import {createProgramAgentState,observeProgramStep,decideProgramNext,summarizeProgramAgent,PROGRAM_AGENT_LIMITS} from './programAgent.js';
import { getDb } from '../db/connection.js';
import { runTool } from '../tools/toolRunner.js';
import { reactDecide, determineEngineType } from './reactEngine.js';
import { buildAppContextForStep } from './knowledgeEnricher.js';
import { validateInsertion, recordBlock, getTelemetry } from './reactRuntimeGuard.js';
import { applyBlueTeamPreExec, applyBlueTeamPostProcess } from './interventionGuards.js';
import { extractEvidence, evalAllRules } from './rulesEngine.js';
import { runPreflightChecks } from './preflightGate.js';
import { compilePlaybook } from './playbookCompiler.js';
import { detectMappings } from './mappingDetector.js';
import { buildContextForTarget } from './targetAdapters/index.js';
import { renderCommand, replaceTargetPlaceholder } from './commandTemplateRenderer.js';
import { getWsManager } from './wsManager.js';
import { createStepIndexAllocator, buildExecutionSummary } from './executionState.js';
import { validateExecutionScope } from './executionScope.js';
import { taskScope } from './taskScope.js';
import { normalizeToolArgs, redactToolArgs } from '../tools/toolContracts.js';
import { getEngine } from '../tools/containerEngine.js';
import { establishDvwaSession } from './dvwaSession.js';
import { validateStepVariables, isDvwaSessionProducer } from './executionVariables.js';
import {evaluateEvidenceCriteria,sameComparisonRequest} from './sourceEvidenceCriteria.js';
import {parseSourceDiagnostics} from './sourceDiagnostics.js';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const runControllers = new Map();

// ── Module-level abort flags ───────────────────────────────────────────
// Allows external API (POST /api/runs/:runId/abort) to cancel a running execution.
const abortFlags = new Map();

export function requestAbort(runId) {
  abortFlags.set(runId, true);
  runControllers.get(runId)?.abort();
}

const MAX_OUTPUT_LENGTH = 4096;

// Generic Nuclei scans need more time because they evaluate many templates.
// Keep the longer timeout scoped to Nuclei so other tools retain their limit.
export function getToolTimeout(toolId) {
  if (toolId !== 'nuclei') return 300_000;
  const configured = Number(process.env.NUCLEI_TIMEOUT_MS);
  return Number.isSafeInteger(configured) && configured >= 300_000 && configured <= 2_147_483_647
    ? configured : 900_000;
}

// Track running executions to prevent duplicates
const runningRuns = new Set();

// ── Evidence type mapping ──────────────────────────────────────────────
const EVIDENCE_TYPE_MAP = {
  nmap: 'open_port', whatweb: 'web_fingerprint', gobuster: 'dir_enum',
  ffuf: 'fuzz_result', httpx: 'web_probe', amass: 'subdomain',
  nuclei: 'vulnerability', nikto: 'vulnerability', sqlmap: 'vulnerability',
  hydra: 'credential_access', john: 'credential_access', hashcat: 'credential_access',
  netexec: 'lateral_movement', 'evil-winrm': 'lateral_movement',
  'ssh-exec': 'lateral_movement', rpcclient: 'lateral_movement',
  arjun: 'param_discovery', 'web-brute': 'param_discovery',
  'system-tools': 'command_execution',
  'target-request': 'application_observation',
};

// ── Recommendation builder ─────────────────────────────────────────────
function buildRecommendations(evidenceType, success) {
  const recs = [];
  if (evidenceType === 'open_port') recs.push('Review exposed services and close unnecessary ports');
  if (evidenceType === 'vulnerability') recs.push('Patch identified vulnerabilities and verify remediation');
  if (evidenceType === 'dir_enum') recs.push('Restrict access to sensitive directories');
  if (evidenceType === 'credential_access') recs.push('Rotate compromised credentials and enforce strong passwords');
  if (evidenceType === 'web_fingerprint') recs.push('Update server software and remove version headers');
  if (evidenceType === 'lateral_movement') recs.push('Segment network and review access controls');
  if (evidenceType === 'command_execution') recs.push('Review command execution results for security implications');
  if (!success) recs.push('Step failed — check tool configuration and target availability');
  return recs;
}

// ── Record evidence for a step ─────────────────────────────────────────
function recordEvidence(db, runId, stepIndex, toolId, result, target, expectedMitre, payloadInfo, attemptId, sourceLinkage, findingLinkage) {
  const evidenceType = EVIDENCE_TYPE_MAP[toolId] || 'tool_output';
  const mitreHits = [];

  const dataSummary = (result.stdout || '').split('\n')[0]?.slice(0, 200) || '';
  const recommendations = buildRecommendations(evidenceType, result.success);
  const now = new Date().toISOString();

  // ── Structured evidence via rules engine ──────────────────────────────
  let structuredEvidence = null;
  let ruleMatchResult = null;
  try {
    structuredEvidence = extractEvidence({
      toolId,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      target
    });
    ruleMatchResult = evalAllRules({
      toolId,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      target
    });
    if (!result.success) ruleMatchResult = { matches: [] };
    for (const match of ruleMatchResult.matches) {
      const ruleMitre = (match.then?.mitre || []);
      for (const m of ruleMitre) {
        if (!mitreHits.some(h => h.id === m.id)) {
          mitreHits.push(m);
        }
      }
      // Merge rule-based recommendations
      const ruleRecs = (match.then?.recommendations || []);
      for (const r of ruleRecs) {
        if (!recommendations.some(er => er === r.title)) {
          recommendations.push(r.title);
        }
      }
    }
  } catch (e) {
    console.warn(`[executionEngine] Rules engine failed for ${toolId}: ${e.message}`);
  }

  let comparison=null;
  let diagnostics=[];
  if(sourceLinkage && toolId==='target-request') {
    try {const observation=JSON.parse(result.stdout || '{}');diagnostics=parseSourceDiagnostics(observation.response,
      (sourceLinkage.source_versions || []).filter(version=>version.file).map(version=>({...version,path:version.file})));
    } catch { /* Non-JSON failures retain their raw output. */ }
  }
  if(sourceLinkage?.criteria && toolId==='target-request') {
    const previous=db.prepare("SELECT id,evidence_data,raw_stdout FROM evidence_records WHERE run_id=? AND tool_id='target-request' ORDER BY id DESC").all(runId);
    let currentObservation;
    try {currentObservation=JSON.parse(result.stdout || '{}');} catch {}
    const baseline=previous.find(row=>{
      try {const linked=JSON.parse(row.evidence_data).source_verification;
        return linked?.phase==='baseline' && linked.scan_task_id===sourceLinkage.scan_task_id
          && linked.finding_ids?.length===1 && sourceLinkage.finding_ids?.length===1 && linked.finding_ids[0]===sourceLinkage.finding_ids[0]
          && (sourceLinkage.criteria.kind!=='response_differs' || sameComparisonRequest(JSON.parse(row.raw_stdout),currentObservation));
      } catch {return false;}
    });
    let observation;
    try {observation=baseline ? {...JSON.parse(baseline.raw_stdout),success:JSON.parse(baseline.evidence_data).success} : null;} catch {}
    comparison=evaluateEvidenceCriteria(sourceLinkage.criteria,result,observation);
    if(comparison && baseline) comparison.baseline_evidence_id=baseline.id;
  }

  const insertedEvidence=db.prepare(`
    INSERT INTO evidence_records
      (run_id, step_index, tool_id, evidence_type, evidence_data, raw_stdout, raw_stderr,
       target, mitre_hits, recommendations, rule_matches, structured_type, structured_data, recorded_at, attempt_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    runId, stepIndex, toolId, structuredEvidence?.type || evidenceType,
    JSON.stringify({
      ...(structuredEvidence?.data || { summary: dataSummary, success: result.success }),
      success: result.success, exit_code: result.exitCode, error: result.error || null,
      ...(sourceLinkage ? {source_verification:sourceLinkage} : {}),
      ...(findingLinkage ? {finding_verification:findingLinkage} : {}),
      ...(comparison ? {source_comparison:comparison} : {}),
      ...(diagnostics.length ? {source_diagnostics:{provenance:'untrusted_target_response',items:diagnostics,
        note:'响应中的诊断文本需核对目标日志、构建版本及源码关联，不能单独证明漏洞'}} : {}),
      planned_mitre: tryJsonArr(expectedMitre),
      ...(payloadInfo ? { payload_id: payloadInfo.id, payload_name: payloadInfo.name,
        payload_version: payloadInfo.version, payload_source: payloadInfo.source,
        payload_consumption: payloadInfo.consumption } : {}),
    }),
    (result.stdout || '').slice(0, toolId==='target-request' ? 524288 : MAX_OUTPUT_LENGTH),
    (result.stderr || '').slice(0, MAX_OUTPUT_LENGTH),
    target || null,
    JSON.stringify(mitreHits),
    JSON.stringify(recommendations),
    ruleMatchResult ? JSON.stringify(ruleMatchResult.matches) : null,
    structuredEvidence?.type || null,
    structuredEvidence ? JSON.stringify(structuredEvidence.data) : null,
    now, attemptId
  );

  return { structuredEvidence, ruleMatchResult, evidenceId:Number(insertedEvidence.lastInsertRowid) };
}

// ── Main entry: execute a run ──────────────────────────────────────────

export async function executeRun(runId) {
  if (runningRuns.has(runId)) {
    return { ok: false, error: 'Run is already executing' };
  }

  const db = getDb();

  // Get run record
  const run = db.prepare(
    'SELECT run_id, playbook_id, target, status, engine_type, plan_data, user_sub, user_role, scan_task_id FROM execution_runs WHERE run_id = ?'
  ).get(runId);
  if (!run) return { ok: false, error: 'Run not found' };
  if (run.status !== 'PENDING') return { ok: false, error: `Run status is ${run.status}, expected PENDING` };
  let findingVerification;
  try { findingVerification=JSON.parse(run.plan_data || '{}').finding_verification; } catch {}
  const pipeline=findingVerification
    ? db.prepare('SELECT * FROM pipelines WHERE pipeline_id=? AND created_by=?').get(findingVerification.pipeline_id,run.user_sub)
    : db.prepare('SELECT * FROM pipelines WHERE run_id=? AND target=? AND created_by=?').get(runId,run.target,run.user_sub);
  if (findingVerification && !pipeline) return {ok:false,error:'验证任务归属失效',processStopped:true};
  const scope=pipeline ? taskScope(pipeline) : null;

  let sourceVerification;
  try {sourceVerification=JSON.parse(db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(run.playbook_id)?.metadata || '{}').source_verification;} catch {}
  const programAgent=sourceVerification?.agent?.enabled === true && run.engine_type!=='mechanical'
    ? createProgramAgentState(sourceVerification.context) : null;
  // Program testing uses typed JSON decisions; the generic XML ReAct path is separate.
  let engineType = findingVerification ? 'mechanical' : sourceVerification ? (programAgent ? 'react' : 'mechanical') : run.engine_type;
  if (!engineType || engineType === 'auto' || engineType === 'playbook') {
    engineType = determineEngineType(db);
  }
  if (!['mechanical', 'react'].includes(engineType)) return { ok: false, error: `Invalid engine type: ${engineType}` };

  // Get playbook steps (include payload_id and payload_variables for compiler)
  const steps = db.prepare(
    `SELECT step_index, step_id, name, tool_id, args_template, optional, expected_mitre,
            payload_id, payload_variables, input_variables, output_variables, description, evidence_config
     FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index`
  ).all(run.playbook_id);
  if (!steps.length) return { ok: false, error: 'Playbook has no steps' };

  // ── Preflight checks ──────────────────────────────────────────────
  runningRuns.add(runId);
  const controller = new AbortController();
  runControllers.set(runId, controller);
  let deadlineTimer;
  let verificationStopConfirmed = true;
  try {
  db.prepare("UPDATE execution_runs SET status = 'RUNNING', engine_type = ?, stop_reason = NULL, updated_at = datetime('now') WHERE run_id = ?")
    .run(engineType, runId);
  run.status = 'RUNNING';
  let scanTaskIds = run.scan_task_id ? [run.scan_task_id] : [];
  try { scanTaskIds = JSON.parse(run.plan_data || '{}')._scan_task_ids || scanTaskIds; } catch {}
  const preflight = await runPreflightChecks({ playbookId: run.playbook_id, target: run.target, db, scanTaskIds, runId, signal: controller.signal });
  if (abortFlags.get(runId)) {
    db.prepare("UPDATE execution_runs SET status = 'ABORTED', stop_reason = '操作员手动中止', updated_at = datetime('now') WHERE run_id = ?").run(runId);
    return { ok: true, runId, status: 'ABORTED', completed: 0, failed: 0 };
  }
  if (!preflight.passed) {
    const failedChecks = preflight.checks.filter(c => !c.passed).map(c => `${c.name}: ${c.message}`);
    const error = `预检失败：${failedChecks.join('; ')}`;
    db.prepare(
      "UPDATE execution_runs SET status = 'FAILED', final_summary = ?, preflight_status = 'FAILED', preflight_data = ?, stop_reason = ?, updated_at = datetime('now') WHERE run_id = ?"
    ).run(
      JSON.stringify({ preflightFailed: failedChecks }),
      JSON.stringify(preflight.checks),
      error,
      runId
    );
    return { ok: false, runId, status: 'FAILED', error, checks: preflight.checks };
  }

  // Persist preflight data
  db.prepare(
    "UPDATE execution_runs SET preflight_status = 'PASSED', preflight_data = ?, updated_at = datetime('now') WHERE run_id = ?"
  ).run(JSON.stringify(preflight.checks), runId);

  // ── Target resolution ──────────────────────────────────────────────
  let targetProfile = null;
  let targetContext = null;
  let disableAutoInsert = false;
  {
    const pbRow = db.prepare('SELECT target_type, metadata, disable_auto_insert FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    if (pbRow) {
      disableAutoInsert = !!pbRow.disable_auto_insert;
      targetProfile = preflight.checks.find(check => check.name === 'target_class_compatibility').target_profile;
      let metadata = {};
      try { metadata = JSON.parse(pbRow.metadata || '{}'); } catch {}
      const profile = { ...metadata.dvwa_profile };
      delete profile.host;
      delete profile.port;
      delete profile.base_url;
      delete profile.login_url;
      delete profile.sqli_url;
      delete profile.scheme;
      delete profile.dvwa_cookie;
      targetContext = buildContextForTarget(targetProfile, profile);
    } else {
      targetProfile = preflight.checks.find(check => check.name === 'target_class_compatibility').target_profile;
      targetContext = buildContextForTarget(targetProfile);
    }
    // Persist target info to execution_runs
    try {
      db.prepare("UPDATE execution_runs SET target_class = ?, target_profile = ? WHERE run_id = ?")
        .run(targetProfile.target_class, JSON.stringify(targetProfile), runId);
    } catch {
      // Columns may not exist yet (pre-migration)
    }
  }

  // ── Campaign artifact injection ─────────────────────────────────────
  // If this run was spawned by the campaign engine, plan_data contains
  // resolved args_template per step (with {{artifact.xxx}} replaced).
  // Merge those resolved templates into the steps so they take effect.
  if (run.plan_data) {
    try {
      const planData = JSON.parse(run.plan_data);
      if (planData._campaignArtifacts) {
        for (const step of steps) {
          if (planData._campaignArtifacts[step.step_index] !== undefined) {
            step.args_template = planData._campaignArtifacts[step.step_index];
          }
        }
      }
    } catch { /* not campaign context, ignore */ }
  }

  // ── Playbook compilation ────────────────────────────────────────────
  const compiled = sourceVerification
    ? {ok:true,warnings:[],errors:[],compiledSteps:steps.map(step=>({...step,compile_status:'READY',resolved_args:JSON.parse(step.args_template)}))}
    : compilePlaybook({ steps, target: run.target, db, context: targetContext });
  if (!compiled.ok) {
    console.warn(`[executionEngine] Playbook compilation warnings: ${compiled.warnings.join('; ')}`);
  }
  if (compiled.errors.length > 0) {
    for (const err of compiled.errors) {
      console.warn(`[executionEngine] Compilation error: ${err}`);
    }
  }
  if (findingVerification && !compiled.ok) throw new Error('验证计划编译失败，未执行任何步骤');
  // Use compiled steps (even with warnings, non-BLOCKED steps can still run)
  const runnableSteps = compiled.compiledSteps.filter(s => !s.compile_status.startsWith('BLOCKED'));
  const blockedCount = compiled.compiledSteps.length - runnableSteps.length;
  if (blockedCount > 0) {
    console.warn(`[executionEngine] ${blockedCount} steps are BLOCKED and will be skipped`);
  }

  let completedSteps = 0;
  let failedSteps = 0;
  let aborted = false;
  let stopReason = null;
  let manualAbort = false;   // operator-initiated abort (vs ReAct "stop" / timeout)
  let timeoutAbort = false;  // global run deadline exceeded

  // ReAct state (only used when engineType === 'react')
  const evidenceHistory = [];
  let reactCallCount = 0;

  // B5.3: Inject pipeline analysis results into ReAct initial evidence
  // When a run originates from a pipeline, plan_data may contain _pipeline_analysis
  // which provides scan analysis context so ReAct doesn't start "blind"
  let pipelineAnalysis = null;
  if (run.plan_data) {
    try {
      const planData = typeof run.plan_data === 'string' ? JSON.parse(run.plan_data) : run.plan_data;
      if (planData._pipeline_analysis) {
        const analysis = planData._pipeline_analysis;
        pipelineAnalysis = analysis;  // Store for ReAct appContext enrichment
        const summaryParts = [];
        if (Array.isArray(analysis.tech_stack) && analysis.tech_stack.length) summaryParts.push(`Tech stack: ${analysis.tech_stack.map(tech => typeof tech === 'string' ? tech : tech.name).join(', ')}`);
        if (analysis.attack_surface?.length) {
          summaryParts.push(`Attack surface: ${analysis.attack_surface.slice(0, 5).map(a => a.type + ':' + (a.detail || a.path || a.port || '?')).join(', ')}`);
        }
        if (analysis.risk_assessment?.length) {
          summaryParts.push(`Risks: ${analysis.risk_assessment.slice(0, 5).map(r => r.category || r.owasp_id || '?').join(', ')}`);
        }
        if (summaryParts.length) {
          evidenceHistory.push({
            stepIndex: -1,  // Virtual step: pipeline analysis
            toolId: 'pipeline_analyzer',
            success: true,
            output: `[Pipeline Scan Analysis] ${summaryParts.join(' | ')}`,
          });
          console.log(`[executionEngine] Injected pipeline analysis into ReAct evidence (${summaryParts.length} parts)`);
        }
      }
    } catch (e) {
      console.warn('[executionEngine] Failed to parse plan_data for pipeline analysis injection:', e.message);
    }
  }
  const reactThoughts = [];
  const failedToolCounts = [];  // [{ toolId, count }] — blacklist for 3+ failures
  const stepRetryCount = new Map();  // stepIndex → retry count (max 2 per step)
  const failedNonOptionalSteps = new Set();  // step_index values of non-optional failures
  let attempts = 0;
  let reactStopped = false;
  const sessionDirectory = resolve(PROJECT_ROOT, 'data/output', `run-${Buffer.from(runId).toString('hex')}`);

    const executionEnvironment = sourceVerification || (findingVerification && runnableSteps.every(s=>s.tool_id==='target-request')) ? 'builtin' : await getEngine();
    // Use mutable steps array (ReAct may insert new steps)
    const mutableSteps = runnableSteps.map(step => ({ ...step, source: 'playbook' }));
    const removedSteps = compiled.compiledSteps.filter(step => step.compile_status.startsWith('BLOCKED'));
    const allocateStepIndex = createStepIndexAllocator(steps);

    // Global run deadline — prevents runaway execution from hanging forever.
    // Default 4h, configurable via RUN_TIMEOUT_MS env var (min 1 minute).
    const _parsedDeadline = parseInt(process.env.RUN_TIMEOUT_MS || '', 10);
    const RUN_DEADLINE_MS = findingVerification ? Math.min(findingVerification.duration_ms || 300000,900000) : sourceVerification ? Math.min(_parsedDeadline>=60000 ? _parsedDeadline : PROGRAM_AGENT_LIMITS.duration_ms,PROGRAM_AGENT_LIMITS.duration_ms)
      : _parsedDeadline >= 60_000 ? _parsedDeadline : (4 * 60 * 60 * 1000);
    const runStartTime = Date.now();
    deadlineTimer = setTimeout(() => { timeoutAbort = true; controller.abort(); }, RUN_DEADLINE_MS);

    for (let i = 0; i < mutableSteps.length; i++) {
      if (aborted) break;

      // Check for external abort request (POST /api/runs/:runId/abort)
      if (abortFlags.get(runId)) {
        aborted = true;
        manualAbort = true;
        stopReason = '操作员手动中止';
        console.log(`[executionEngine] Run ${runId} aborted by operator`);
        break;
      }

      // Global run deadline — stop runaway executions
      if (timeoutAbort || Date.now() - runStartTime > RUN_DEADLINE_MS) {
        aborted = true;
        timeoutAbort = true;
        stopReason = `运行超时（${Math.round(RUN_DEADLINE_MS / 60000)}分钟）`;
        console.warn(`[executionEngine] Run ${runId} exceeded deadline (${RUN_DEADLINE_MS}ms), aborting`);
        break;
      }

      const step = mutableSteps[i];
      const startedAt = new Date().toISOString();
      const startedMs = Date.now();
      let preparationError = step.compile_status?.startsWith('BLOCKED') ? step.compile_reason : null;
      const isSessionProducer = isDvwaSessionProducer(step, targetContext);
      if (isSessionProducer) {
        targetContext.dvwa_cookie = '';
        targetContext.auth_cookie = '';
        targetContext.dvwa_session_verified = false;
      }
      if(!sourceVerification) preparationError ||= validateStepVariables(step, targetContext);

      // Resolve args: use compiler-resolved args if available, otherwise parse args_template
      let args = [];
      if (step.resolved_args && Array.isArray(step.resolved_args) && step.resolved_args.length > 0) {
        // Use compiler-resolved args (includes payload_variables substitution and <target> replacement)
        args = step.resolved_args;
      } else {
        try {
          args = JSON.parse(step.args_template || '[]');
        } catch {}
        // Simple <target> replacement (backward compat)
        args = args.map(a => (typeof a === 'string' ? a.replace(/<target>/g, run.target || '') : a));
      }
      // Always apply full context rendering via commandTemplateRenderer
      // (handles {{host}}, {{base_url}}, {{domain}}, etc. from targetAdapters)
      if (targetContext && !sourceVerification) {
        const { rendered, unresolvedTokens } = renderCommand(args, targetContext);
        args = rendered;
        if (unresolvedTokens.length > 0) {
          console.warn(`[executionEngine] Step ${step.step_index} has unresolved tokens: ${unresolvedTokens.join(', ')}`);
          preparationError = `Unresolved tokens: ${unresolvedTokens.join(', ')}`;
        }
      }
      try {
        args = normalizeToolArgs(step.tool_id, args, { projectRoot: PROJECT_ROOT, engine: executionEnvironment, scheme: targetContext?.scheme, target: run.target });
        const scopeCheck = validateExecutionScope({ target: run.target, toolId: step.tool_id, args, scope });
        if (!scopeCheck.allowed) preparationError = scopeCheck.reason;
        if (targetProfile?.target_class === 'dvwa' && step.tool_id === 'sqlmap') {
          const cookieIndex = args.indexOf('--cookie');
          if (!targetContext.dvwa_session_verified || !targetContext.dvwa_cookie) {
            preparationError = 'DVWA SQLMap requires a verified session; run the login step first';
          } else if (cookieIndex >= 0) args[cookieIndex + 1] = targetContext.dvwa_cookie;
          else args.push('--cookie', targetContext.dvwa_cookie);
        }
      } catch (error) { preparationError = error.message; }

      // ── Blue team pre-exec check ────────────────────────────────────
      const preExecResult = applyBlueTeamPreExec({
        runId,
        toolId: step.tool_id,
        args,
        target: run.target,
      });

      let result, toolStarted=false;
      if (preparationError || !preExecResult.allowed) {
        // Blocked by blue team — skip execution entirely
        result = {
          success: false,
          exitCode: -2,
          stdout: '',
          stderr: preparationError || preExecResult.deniedReason || 'Blocked by blue team intervention',
          executionMode: 'blocked',
        };
      } else {
        // Use adjusted args if blue team modified them
        if (preExecResult.adjustedArgs) {
          if(findingVerification && JSON.stringify(args)!==JSON.stringify(preExecResult.adjustedArgs)) throw new Error('冻结验证计划不允许运行时改写参数');
          args = preExecResult.adjustedArgs;
        }

        // Execute tool
        try {
          toolStarted=true;
          const isDvwaLogin = isSessionProducer;
          if (isDvwaLogin) {
            targetContext.dvwa_cookie = '';
            targetContext.dvwa_session_verified = false;
            const dataIndex = args.findIndex(arg => ['--data', '-d', '--data-raw'].includes(arg));
            const credentials = new URLSearchParams(args[dataIndex + 1] || '');
            result = await establishDvwaSession({ baseUrl: targetContext.base_url,
              username: credentials.get('username') || '', password: credentials.get('password') || '',
              securityLevel: targetContext.security_level, outputDirectory: sessionDirectory,
              signal: controller.signal,
            });
            if (result.success) {
              targetContext.dvwa_cookie = result.cookie;
              targetContext.auth_cookie = result.cookie;
            }
            targetContext.dvwa_session_verified = result.success;
          } else {
            result = await runTool(step.tool_id, args, { timeout: getToolTimeout(step.tool_id), signal: controller.signal, target: run.target });
          }
        } catch (err) {
          result = { success: false, exitCode: -1, stdout: '', stderr: err.message, executionMode: 'error', processStopped: findingVerification ? false : undefined };
        }
      }

      // Record step result
      // (DELETE first to handle retry case — adjust action may re-execute a step)
      if (abortFlags.get(runId)) { aborted = true; manualAbort = true; stopReason = '操作员手动中止'; }
      if (findingVerification && result.processStopped === false) verificationStopConfirmed = false;
      if (timeoutAbort) { aborted = true; stopReason = '运行超时'; }
      const output = [result.stdout, result.stderr, result.error].filter(Boolean).join('\n').slice(0, MAX_OUTPUT_LENGTH);
      const source = step.source || 'react';
      const durationMs = Date.now() - startedMs;
      const attemptId = Number(db.prepare(`INSERT INTO execution_attempts
        (run_id, step_index, step_id, source, tool_id, args, started_at, completed_at, success, exit_code, stdout, stderr, execution_mode, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        runId, step.step_index, step.step_id, source, step.tool_id, JSON.stringify(redactToolArgs(args, step.tool_id)),
        startedAt, new Date().toISOString(), result.success ? 1 : 0, result.exitCode ?? -1,
        (result.stdout || '').slice(0, step.tool_id==='target-request' ? 524288 : MAX_OUTPUT_LENGTH), (result.stderr || '').slice(0, MAX_OUTPUT_LENGTH), result.executionMode || null, durationMs,
      ).lastInsertRowid);
      attempts++;
      step.execution_finished = true;
      step.execution_success = !!result.success;
      step.execution_error = result.success ? null : result.error || result.stderr?.trim().slice(0, 1000) || `Tool exited with code ${result.exitCode ?? -1}`;
      db.prepare('DELETE FROM execution_steps WHERE run_id = ? AND step_index = ?')
        .run(runId, step.step_index);
      db.prepare(`
        INSERT INTO execution_steps (run_id, step_index, tool_id, args, success, exit_code, notes, step_id, source, attempt_id, executed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        runId, step.step_index, step.tool_id,
        JSON.stringify(redactToolArgs(args, step.tool_id)), result.success ? 1 : 0, result.exitCode ?? -1, output,
        step.step_id, source, attemptId, startedAt
      );

      // Record evidence (with structured parsing + rules engine)
      const evidenceResult = recordEvidence(db, runId, step.step_index, step.tool_id, result, run.target, step.expected_mitre,
        toolStarted && result.toolStarted!==false && step.payload_data && !['blocked','error'].includes(result.executionMode) ? { id: step.payload_data.id, name: step.payload_data.name,
          version: step.payload_data.version, source: step.payload_data.source,
          consumption: step.payload_data.consumption?.type } : null, attemptId,
        sourceVerification ? {...JSON.parse(step.evidence_config || '{"finding_ids":[]}'),scan_task_id:sourceVerification.scan_task_id,
          source_versions:sourceVerification.reproducibility?.source_versions || [],deployment_version_verified:false} : null,
        findingVerification ? {...findingVerification, tool_started:toolStarted && result.toolStarted!==false && !['blocked','error'].includes(result.executionMode),payload_consumed:!!(toolStarted && result.toolStarted!==false && step.payload_data && !['blocked','error'].includes(result.executionMode)),consumption:JSON.parse(step.evidence_config || '{}').consumption,
          payload_version:JSON.parse(step.evidence_config || '{}').payload_version} : null);
      db.prepare(`INSERT INTO audit_log (type, execution_id, run_id, tool_id, args, user_role, target, execution_mode, success, exit_code, duration_ms, output_size, reasons, timestamp)
        VALUES ('tool_execution', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        String(attemptId), runId, step.tool_id, JSON.stringify(redactToolArgs(args, step.tool_id)), run.user_role || null, run.target,
        result.executionMode || null, result.success ? 1 : 0, result.exitCode ?? -1, durationMs,
        Buffer.byteLength((result.stdout || '') + (result.stderr || '')), JSON.stringify({ error: result.error || (result.success ? null : 'Tool execution failed') }), new Date().toISOString(),
      );

      // ── Detect candidate tool-to-technique mappings ──────────────────
      let detectedTechniques = [];
      if (result.success) {
        try {
          const { candidates } = detectMappings({ toolId: step.tool_id, stdout: result.stdout, success: true });
          if (candidates.length > 0) {
            const insertStmt = db.prepare(
              `INSERT INTO candidate_mappings (run_id, tool_id, technique_id, confidence, signal, snippet) VALUES (?, ?, ?, ?, ?, ?)`
            );
            const mappingInsert = db.transaction((mappings) => {
              for (const c of mappings) {
                insertStmt.run(runId, c.toolId, c.techniqueId, c.confidence, c.signal, c.snippet);
              }
            });
            mappingInsert(candidates);
            // Capture detected technique IDs for ReAct prompt enrichment
            detectedTechniques = candidates.map(c => ({
              techniqueId: c.techniqueId,
              confidence: c.confidence,
              signal: c.signal,
            }));
          }
        } catch (e) {
          console.warn(`[executionEngine] Mapping detection failed: ${e.message}`);
        }
      }

      // ── Blue team post-process filtering ────────────────────────────
      const postProcessResult = applyBlueTeamPostProcess({
        runId,
        findings: evidenceResult?.structuredEvidence?.data?.findings || [],
        evidence: evidenceResult?.structuredEvidence?.data || null,
      });
      if (postProcessResult.notes.length > 0) {
        // Annotate step notes with blue-team filter info
        const filterNote = postProcessResult.notes.join('; ');
        db.prepare(
          "UPDATE execution_steps SET notes = CASE WHEN notes IS NULL OR notes = '' THEN ? ELSE notes || ' | ' || ? END WHERE run_id = ? AND step_index = ?"
        ).run(filterNote, filterNote, runId, step.step_index);
      }

      if (result.success) {
        completedSteps++;
      } else {
        failedSteps++;
        // Track failed tool counts for ReAct blacklist (always track —
        // even without LLM, the blacklist is useful for reporting)
        const existing = failedToolCounts.find(f => f.toolId === step.tool_id);
        if (existing) { existing.count++; } else { failedToolCounts.push({ toolId: step.tool_id, count: 1 }); }
        // Track non-optional failures for final status determination
        if (!step.optional) failedNonOptionalSteps.add(step.step_index);
        // In mechanical mode (no LLM), abort on non-optional step failures.
        // In ReAct mode, let the LLM decide whether to continue or stop.
        if (engineType === 'mechanical' && !step.optional) {
          aborted = true;
          stopReason = `非可选步骤失败: ${step.tool_id}`;
          console.log(`[executionEngine] Mechanical mode: aborting due to non-optional step failure (${step.tool_id})`);
        }
      }

      // ── WebSocket broadcast: step completed ──────────────────────────
      const ws = getWsManager();
      const runInfo = ws ? db.prepare('SELECT user_sub FROM execution_runs WHERE run_id = ?').get(runId) : null;
      if (ws) {
        const broadcast = sourceVerification ? (event,data) => ws.broadcastProgram(run.user_sub,event,data) : (event,data) => ws.broadcast(event,data);
        broadcast('run:step', {
          run_id: runId,
          step_index: step.step_index,
          tool_id: step.tool_id,
          success: result.success,
          exit_code: result.exitCode,
          running_status: aborted ? 'ABORTED' : 'RUNNING',
          completed_steps: completedSteps,
          failed_steps: failedSteps,
          total_steps: mutableSteps.length,
          userId: runInfo?.user_sub || null,
          username: runInfo?.user_sub || null,
        });
      }

      // ── ReAct: LLM-in-the-loop analysis ────────────────────────────
      // Only run when LLM is available (engineType === 'react').
      // In mechanical mode, the abort logic above already handles failures
      // (non-optional → abort, optional → continue), so ReAct is unnecessary
      // and would waste time building prompts just to get a 'continue' fallback.
      evidenceHistory.push({ stepIndex: step.step_index, attemptId, toolId: step.tool_id, success: result.success,
        output: output.slice(0, 2500), stderr: (result.stderr || '').slice(0, 1500), exitCode: result.exitCode });
      if(programAgent) {
        const linkage=JSON.parse(step.evidence_config || '{"finding_ids":[]}');
        observeProgramStep(programAgent,{evidenceId:evidenceResult.evidenceId,stepIndex:step.step_index,
          findingIds:linkage.finding_ids || [],request:JSON.parse(args[0]),result});
        if(!aborted) {
          const decision=await decideProgramNext({target:run.target,findingIds:sourceVerification.finding_ids || [],
            state:programAgent,remainingSteps:mutableSteps.slice(i+1),signal:controller.signal});
          reactCallCount=programAgent.decisions;
          if(abortFlags.get(runId) || timeoutAbort) {
            aborted=true;manualAbort=!!abortFlags.get(runId);
            stopReason=manualAbort?'操作员手动中止':'运行超时';
          } else if(decision) {
            const publicDecision={...decision,...(decision.request ? {request:JSON.parse(redactToolArgs([JSON.stringify(decision.request)],'target-request')[0])} : {})};
            const actionData=JSON.stringify({type:decision.action,...publicDecision});
            db.prepare('UPDATE execution_steps SET react_thought=?,react_action=? WHERE attempt_id=?').run(decision.summary,actionData,attemptId);
            db.prepare('UPDATE execution_attempts SET react_thought=?,react_action=? WHERE id=?').run(decision.summary,actionData,attemptId);
            reactThoughts.push({stepIndex:step.step_index,attemptId,toolId:step.tool_id,
              thought:decision.summary,action:decision.action,decision:publicDecision,timestamp:new Date().toISOString()});
            getWsManager()?.broadcastProgram(run.user_sub,'run:react',{run_id:runId,step_index:step.step_index,
              thought:decision.summary,action:decision.action,userId:run.user_sub || null});
            if(decision.action==='request') {
              const newStepIndex=allocateStepIndex();
              mutableSteps.splice(i+1,0,{step_index:newStepIndex,step_id:'program_agent_'+newStepIndex,
                name:'Agent 补充验证',tool_id:'target-request',source:'react',
                args_template:JSON.stringify([JSON.stringify(decision.request)]),
                resolved_args:[JSON.stringify(decision.request)],optional:false,expected_mitre:'[]',
                evidence_config:JSON.stringify({finding_ids:decision.finding_ids,expected_evidence:decision.expected_evidence,
                  based_on_evidence_ids:decision.evidence_ids})});
            } else if(decision.action==='stop') {
              aborted=true;reactStopped=true;stopReason=decision.summary;
            }
          }
        }
        db.prepare('UPDATE execution_runs SET evidence_history=?,react_thoughts=? WHERE run_id=?')
          .run(JSON.stringify(evidenceHistory),JSON.stringify(reactThoughts),runId);
      }
      if (!aborted && engineType === 'react' && !programAgent) {
        // Accumulate evidence

        // Get remaining steps
        const remainingSteps = mutableSteps.slice(i + 1).map(s => ({
          step_index: s.step_index,
          step_id: s.step_id,
          name: s.name,
          tool_id: s.tool_id,
          args_template: s.args_template,
        }));

        // Build rule match context for ReAct prompt
        let ruleMatchContext = '';
        if (evidenceResult?.ruleMatchResult?.matches?.length > 0) {
          const matchLines = evidenceResult.ruleMatchResult.matches.map(m => {
            const mitreIds = (m.then?.mitre || []).map(t => t.id).join(', ');
            const recs = (m.then?.recommendations || []).map(r => `${r.suggestedTool || '?'}: ${r.title}`).join('; ');
            return `- 规则[${m.ruleId}]: MITRE ${mitreIds || 'N/A'} | 推荐: ${recs || '无'}`;
          });
          ruleMatchContext = `本次步骤触发了 ${matchLines.length} 条规则匹配：\n${matchLines.join('\n')}`;
        }

        // Build app context from pipeline analysis (OWASP + tech stack)
        let appContext = '';
        if (pipelineAnalysis) {
          try {
            appContext = buildAppContextForStep(step.tool_id, pipelineAnalysis);
          } catch (e) {
            console.warn('[executionEngine] buildAppContextForStep failed:', e.message);
          }
        }

        // Call ReAct engine
        // Dynamic explorationMode: first half of steps uses exploration mode
        // (encourages insert/pivot for attack surface discovery), second half
        // uses auto-pilot (focuses on completing the playbook).
        const explorationMode = completedSteps < mutableSteps.length * 0.5;

        const decision = await reactDecide({
          runId,
          stepIndex: step.step_index,
          toolId: step.tool_id,
          stepName: step.name,
          stepResult: result,
          evidenceHistory,
          remainingSteps,
          target: run.target,
          targetClass: targetProfile?.target_class || null,
          reactCallCount,
          guardState: { steps: mutableSteps, status: run.status, stopReason },
          ruleMatchContext,
          payloadContext: step.payload_context || null,
          failedToolCounts,
          totalSteps: mutableSteps.length,
          completedSteps,
          detectedTechniques,
          appContext,
          explorationMode,
          signal: controller.signal,
        });

        if (abortFlags.get(runId) || timeoutAbort) {
          aborted = true;
          manualAbort = !!abortFlags.get(runId);
          stopReason = manualAbort ? '操作员手动中止' : '运行超时';
          break;
        }
        reactCallCount++;

        // Record thought in DB
        db.prepare("UPDATE execution_steps SET react_thought = ?, react_action = ? WHERE run_id = ? AND step_index = ?")
          .run(decision.thought, JSON.stringify({ type: decision.action }), runId, step.step_index);

        const thoughtRecord = {
          stepIndex: step.step_index,
          toolId: step.tool_id, attemptId, callIndex: reactCallCount,
          source, timestamp: new Date().toISOString(), observation: output.slice(0, 200),
          thought: decision.thought,
          action: decision.action,
          decision, guardBlocks: [],
        };
        reactThoughts.push(thoughtRecord);

        const validateDynamicArgs = (toolId, dynamicArgs) => {
          try {
            if (!Array.isArray(dynamicArgs) || dynamicArgs.some(argument => typeof argument !== 'string')) {
              throw new Error('工具参数必须为字符串数组');
            }
            const rendered = renderCommand(dynamicArgs.map(argument => replaceTargetPlaceholder(argument, run.target || '')), targetContext || {});
            if (rendered.unresolvedTokens.length) throw new Error('工具目标或参数仍含未解析变量');
            const normalized = normalizeToolArgs(toolId, rendered.rendered,
              { projectRoot: PROJECT_ROOT, engine: executionEnvironment, scheme: targetContext?.scheme });
            const scopeCheck = validateExecutionScope({ target: run.target, toolId, args: normalized, scope });
            if (scopeCheck.allowed) return true;
            throw new Error(scopeCheck.reason);
          } catch (error) {
            thoughtRecord.guardBlocks.push({ allowed: false, category: 'target_scope', toolId, reason: error.message });
            console.warn(`[ReAct Guard] ${error.message}`);
            return false;
          }
        };

        // ── WebSocket broadcast: ReAct reasoning (real-time) ──────────
        // Push the AI's thought + action to the frontend so the user can
        // see the reasoning chain as it happens, not just after completion.
        if (ws) {
          ws.broadcast('run:react', {
            run_id: runId,
            step_index: step.step_index,
            tool_id: step.tool_id,
            thought: decision.thought,
            action: decision.action,
            reason: decision.reason || null,
            react_call_count: reactCallCount,
            attempt_id: attemptId,
            source, timestamp: thoughtRecord.timestamp, observation: thoughtRecord.observation,
            completed_steps: completedSteps,
            failed_steps: failedSteps,
            total_steps: mutableSteps.length,
            userId: runInfo?.user_sub || null,
            username: runInfo?.user_sub || null,
          });
        }

        // Handle action
        switch (decision.action) {
          case 'stop':
            aborted = true;
            reactStopped = true;
            stopReason = decision.reason || 'LLM决定终止';
            console.log(`[ReAct] Run stopped: ${stopReason}`);
            break;

          case 'adjust': {
            // Default to current step if stepIndex not provided by LLM
            const adjustTargetIdx = typeof decision.stepIndex === 'number'
              ? decision.stepIndex
              : step.step_index;
            const targetStep = mutableSteps.find(s => s.step_index === adjustTargetIdx);

            if (!targetStep) {
              console.warn(`[ReAct] adjust: step ${adjustTargetIdx} not found, skipping`);
              break;
            }

            if (decision.newArgs && !validateDynamicArgs(targetStep.tool_id, decision.newArgs)) break;

            // Apply new args if provided; otherwise keep existing (simple retry)
            if (decision.newArgs) {
              targetStep.args_template = JSON.stringify(decision.newArgs);
              targetStep.resolved_args = [];
            }

            // If target is the current step → re-execute (retry)
            if (adjustTargetIdx === step.step_index) {
              const retries = (stepRetryCount.get(adjustTargetIdx) || 0) + 1;
              stepRetryCount.set(adjustTargetIdx, retries);
              if (retries <= 2) {
                // Undo the counter from this attempt so re-execution re-counts
                if (result.success) completedSteps--; else failedSteps--;
                targetStep.execution_finished = false;
                targetStep.execution_success = false;
                targetStep.execution_error = null;
                failedNonOptionalSteps.delete(adjustTargetIdx);  // clear this step's failure, re-eval on retry
                i--;  // loop will i++ and re-execute this step
                console.log(`[ReAct] Retrying step ${adjustTargetIdx} (attempt ${retries}/2)${decision.newArgs ? ' with adjusted args' : ''}`);
              } else {
                console.warn(`[ReAct] Step ${adjustTargetIdx} retry limit (2) reached, continuing`);
              }
            } else {
              // Adjusting a future step — just modify args, no retry needed
              console.log(`[ReAct] Adjusted future step ${adjustTargetIdx}: ${decision.newArgs ? JSON.stringify(decision.newArgs) : 'keep existing args'}`);
            }
            break;
          }

          case 'insert':
            if (decision.toolId && decision.args) {
              if (!validateDynamicArgs(decision.toolId, decision.args)) break;
              // Guard: validate insertion before proceeding
              const guardState = { steps: mutableSteps, status: run.status, stopReason };
              const guardResult = validateInsertion(guardState, 'insert', decision.toolId, disableAutoInsert);
              if (!guardResult.allowed) {
                recordBlock(guardState, guardResult.category, decision.toolId);
                thoughtRecord.guardBlocks.push(guardResult);
                console.warn(`[ReAct Guard] ${guardResult.reason}`);
                break;  // Skip insertion, continue to next step
              }
              // Insert new step after current position
              const newStepIndex = allocateStepIndex();
              const newStep = {
                step_index: newStepIndex,
                step_id: `react_insert_${newStepIndex}`,
                name: `ReAct插入: ${decision.toolId}`,
                tool_id: decision.toolId,
                args_template: JSON.stringify(decision.args),
                optional: true,
                expected_mitre: '[]',
              };
              mutableSteps.splice(i + 1, 0, newStep);
              console.log(`[ReAct] Inserted step: ${decision.toolId} ${JSON.stringify(decision.args)}`);

              // B5.5: Record discovered sub-targets for evidence-driven target expansion
              if (decision.newTarget) {
                try {
                  db.prepare(`
                    INSERT INTO evidence_records (run_id, step_index, tool_id, evidence_type, evidence_data, target, recorded_at, attempt_id)
                    VALUES (?, ?, ?, 'discovered_target', ?, ?, ?, ?)
                  `).run(
                    run.run_id, step.step_index, decision.toolId,
                    JSON.stringify({ target: decision.newTarget, source: 'react_insert' }),
                    decision.newTarget, new Date().toISOString(), attemptId
                  );
                  console.log(`[ReAct] Discovered new target: ${decision.newTarget}`);
                } catch (e) {
                  console.warn('[ReAct] Failed to record discovered target:', e.message);
                }
              }
            }
            break;

          case 'pivot':
            if (decision.toolId && decision.args) {
              if (!validateDynamicArgs(decision.toolId, decision.args)) break;
              // Guard: validate insertion before proceeding
              const guardState = { steps: mutableSteps, status: run.status, stopReason };
              const guardResult = validateInsertion(guardState, 'pivot', decision.toolId, disableAutoInsert);
              if (!guardResult.allowed) {
                recordBlock(guardState, guardResult.category, decision.toolId);
                thoughtRecord.guardBlocks.push(guardResult);
                console.warn(`[ReAct Guard] ${guardResult.reason}`);
                break;
              }
              // Remove all remaining steps after current position
              removedSteps.push(...mutableSteps.splice(i + 1));
              // Insert new pivot step
              const newStepIndex = allocateStepIndex();
              const newStep = {
                step_index: newStepIndex,
                step_id: `react_pivot_${newStepIndex}`,
                name: `ReAct转向: ${decision.toolId}`,
                tool_id: decision.toolId,
                args_template: JSON.stringify(decision.args),
                optional: true,
                expected_mitre: '[]',
              };
              mutableSteps.push(newStep);
              console.log(`[ReAct] Pivoted to: ${decision.toolId} ${JSON.stringify(decision.args)}`);
            }
            break;

          case 'parallel':
            if (decision.toolIds && decision.argsList) {
              const guardState = { steps: mutableSteps, status: run.status, stopReason };
              let insertOffset = 1;
              for (let pi = 0; pi < decision.toolIds.length; pi++) {
                const pToolId = decision.toolIds[pi];
                const pArgs = decision.argsList[pi] || [];
                if (!validateDynamicArgs(pToolId, pArgs)) continue;
                // Guard: validate each parallel insertion
                const pGuard = validateInsertion(guardState, 'parallel', pToolId, disableAutoInsert);
                if (!pGuard.allowed) {
                  recordBlock(guardState, pGuard.category, pToolId);
                  thoughtRecord.guardBlocks.push({ ...pGuard, toolId: pToolId });
                  console.warn(`[ReAct Guard] ${pGuard.reason}`);
                  continue;  // Skip this tool in the parallel group
                }
                const newStepIndex = allocateStepIndex();
                const newStep = {
                  step_index: newStepIndex,
                  step_id: `react_parallel_${newStepIndex}_${pi}`,
                  name: `ReAct并行: ${pToolId}`,
                  tool_id: pToolId,
                  args_template: JSON.stringify(pArgs),
                  optional: true,
                  expected_mitre: '[]',
                };
                mutableSteps.splice(i + insertOffset, 0, newStep);
                insertOffset++;
                console.log(`[ReAct] Parallel inserted step: ${pToolId} ${JSON.stringify(pArgs)}`);
              }
            }
            break;

          // 'continue' — no action needed
        }
        const actionData = JSON.stringify({ type: decision.action, ...decision, guardBlocks: thoughtRecord.guardBlocks });
        db.prepare('UPDATE execution_steps SET react_action = ? WHERE attempt_id = ?').run(actionData, attemptId);
        db.prepare('UPDATE execution_attempts SET react_thought = ?, react_action = ? WHERE id = ?').run(decision.thought, actionData, attemptId);
        db.prepare('UPDATE execution_runs SET evidence_history = ?, react_thoughts = ? WHERE run_id = ?')
          .run(JSON.stringify(evidenceHistory), JSON.stringify(reactThoughts), runId);
      }
    }

    if (abortFlags.get(runId)) { manualAbort = true; stopReason = '操作员手动中止'; }
    else if (timeoutAbort) stopReason = '运行超时';
    const final = buildExecutionSummary({ steps: [...mutableSteps, ...removedSteps], completed: completedSteps,
      failed: failedSteps, manualAbort, timeoutAbort, reactStopped, stopReason, engineType, reactCallCount, attempts });
    const finalStatus = final.status;
    if(programAgent) {
      if(manualAbort || timeoutAbort) {programAgent.status=manualAbort?'cancelled':'timed_out';programAgent.reason=stopReason;}
      final.summary.program_agent=summarizeProgramAgent(programAgent);
    }
    const summary = JSON.stringify(final.summary);
    db.prepare(`UPDATE execution_runs SET status = ?, final_summary = ?, stop_reason = ?,
      evidence_history = ?, react_thoughts = ?, updated_at = datetime('now') WHERE run_id = ?`)
      .run(finalStatus, summary, stopReason, JSON.stringify(evidenceHistory), JSON.stringify(reactThoughts), runId);

    return { ok: true, runId, status: finalStatus, error: final.error, completed: final.summary.completed,
      failed: final.summary.failed, engineType, stopReason };

  } catch (err) {
    const wasAborted = !!abortFlags.get(runId);
    const status = wasAborted ? 'ABORTED' : 'FAILED';
    const reason = wasAborted ? '操作员手动中止' : err.message;
    db.prepare(`
      UPDATE execution_runs SET status = ?, final_summary = ?, stop_reason = ?, updated_at = datetime('now')
      WHERE run_id = ?
    `).run(status, JSON.stringify({ error: err.message, aborted: wasAborted, stopReason: reason }), reason, runId);

    return { ok: false, error: err.message, status, stopReason: reason };
  } finally {
    clearTimeout(deadlineTimer);
    runControllers.delete(runId);
    runningRuns.delete(runId);
    abortFlags.delete(runId);
    if (findingVerification) {
      let summary = {};
      try {summary=JSON.parse(db.prepare('SELECT final_summary FROM execution_runs WHERE run_id=?').get(runId)?.final_summary || '{}');} catch {}
      summary.verification_stop_confirmed = verificationStopConfirmed;
      db.prepare('UPDATE execution_runs SET final_summary=? WHERE run_id=?').run(JSON.stringify(summary),runId);
    }
    const finalRun = db.prepare('SELECT status, final_summary, stop_reason, user_sub FROM execution_runs WHERE run_id = ?').get(runId);
    const wsEnd = getWsManager();
    if (wsEnd && finalRun && ['COMPLETED', 'FAILED', 'ABORTED'].includes(finalRun.status)) {
      let summary = {};
      try { summary = JSON.parse(finalRun.final_summary || '{}'); } catch {}
      const broadcast = sourceVerification ? (event,data) => wsEnd.broadcastProgram(run.user_sub,event,data) : (event,data) => wsEnd.broadcast(event,data);
      broadcast('run:complete', {
        run_id: runId, status: finalRun.status,
        completed_steps: summary.completed || 0, failed_steps: summary.failed || 0,
        total_steps: summary.total ?? steps.length, stop_reason: finalRun.stop_reason,
        userId: finalRun.user_sub || null, username: finalRun.user_sub || null,
      });
    }
  }
}

function tryJsonArr(str) {
  try { const v = JSON.parse(str || '[]'); return Array.isArray(v) ? v : []; } catch { return []; }
}
