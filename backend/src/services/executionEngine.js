import { getDb } from '../db/connection.js';
import { runTool } from '../tools/toolRunner.js';
import { reactDecide, isReactEngine, determineEngineType } from './reactEngine.js';
import { validateInsertion, recordBlock, getTelemetry } from './reactRuntimeGuard.js';
import { applyBlueTeamPreExec, applyBlueTeamPostProcess } from './interventionGuards.js';
import { extractEvidence, evalAllRules } from './rulesEngine.js';
import { runPreflightChecks } from './preflightGate.js';
import { compilePlaybook } from './playbookCompiler.js';
import { detectMappings } from './mappingDetector.js';
import { resolveTargetProfile, derivePreferredClass } from './targetProfileResolver.js';
import { buildContextForTarget } from './targetAdapters/index.js';
import { renderCommand } from './commandTemplateRenderer.js';
import { getWsManager } from './wsManager.js';

const MAX_OUTPUT_LENGTH = 4096;

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
function recordEvidence(db, runId, stepIndex, toolId, result, target, expectedMitre, payloadInfo) {
  const evidenceType = EVIDENCE_TYPE_MAP[toolId] || 'tool_output';
  let mitreHits = [];
  try { mitreHits = JSON.parse(expectedMitre || '[]'); } catch {}
  if (!Array.isArray(mitreHits)) mitreHits = [];

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
    // Merge rule-based MITRE hits with expected MITRE
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

  db.prepare(`
    INSERT INTO evidence_records
      (run_id, step_index, tool_id, evidence_type, evidence_data, raw_stdout, raw_stderr,
       target, mitre_hits, recommendations, rule_matches, structured_type, structured_data, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    runId, stepIndex, toolId, structuredEvidence?.type || evidenceType,
    JSON.stringify({
      ...(structuredEvidence?.data || { summary: dataSummary, success: result.success }),
      ...(payloadInfo ? { payload_id: payloadInfo.id, payload_name: payloadInfo.name } : {}),
    }),
    (result.stdout || '').slice(0, MAX_OUTPUT_LENGTH),
    (result.stderr || '').slice(0, MAX_OUTPUT_LENGTH),
    target || null,
    JSON.stringify(mitreHits),
    JSON.stringify(recommendations),
    ruleMatchResult ? JSON.stringify(ruleMatchResult.matches) : null,
    structuredEvidence?.type || null,
    structuredEvidence ? JSON.stringify(structuredEvidence.data) : null,
    now
  );

  return { structuredEvidence, ruleMatchResult };
}

// ── Main entry: execute a run ──────────────────────────────────────────

export async function executeRun(runId) {
  if (runningRuns.has(runId)) {
    return { ok: false, error: 'Run is already executing' };
  }

  const db = getDb();

  // Get run record
  const run = db.prepare(
    'SELECT run_id, playbook_id, target, status, engine_type FROM execution_runs WHERE run_id = ?'
  ).get(runId);
  if (!run) return { ok: false, error: 'Run not found' };
  if (run.status !== 'PENDING') return { ok: false, error: `Run status is ${run.status}, expected PENDING` };

  // Determine engine type: use stored value, or auto-detect
  let engineType = run.engine_type;
  if (!engineType || engineType === 'mechanical' || engineType === 'playbook') {
    // Auto-detect: if LLM is available, upgrade to react
    engineType = determineEngineType(db);
  }

  // Get playbook steps (include payload_id and payload_variables for compiler)
  const steps = db.prepare(
    `SELECT step_index, step_id, name, tool_id, args_template, optional, expected_mitre,
            payload_id, payload_variables
     FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index`
  ).all(run.playbook_id);
  if (!steps.length) return { ok: false, error: 'Playbook has no steps' };

  // ── Preflight checks ──────────────────────────────────────────────
  const preflight = await runPreflightChecks({ playbookId: run.playbook_id, target: run.target, db });
  if (!preflight.passed) {
    const failedChecks = preflight.checks.filter(c => !c.passed).map(c => `${c.name}: ${c.message}`);
    db.prepare(
      "UPDATE execution_runs SET status = 'FAILED', final_summary = ?, preflight_status = 'FAILED', preflight_data = ?, updated_at = datetime('now') WHERE run_id = ?"
    ).run(
      JSON.stringify({ preflightFailed: failedChecks }),
      JSON.stringify(preflight.checks),
      runId
    );
    return { ok: false, error: 'Preflight checks failed', checks: preflight.checks };
  }

  // Persist preflight data
  db.prepare(
    "UPDATE execution_runs SET preflight_status = 'PASSED', preflight_data = ?, updated_at = datetime('now') WHERE run_id = ?"
  ).run(JSON.stringify(preflight.checks), runId);

  runningRuns.add(runId);

  // Mark as RUNNING, set engine_type
  db.prepare("UPDATE execution_runs SET status = 'RUNNING', engine_type = ?, updated_at = datetime('now') WHERE run_id = ?")
    .run(engineType, runId);

  // ── Target resolution ──────────────────────────────────────────────
  let targetProfile = null;
  let targetContext = null;
  {
    const pbRow = db.prepare('SELECT target_type FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    if (pbRow) {
      const targetTypes = tryJsonArr(pbRow.target_type);
      const preferredClass = derivePreferredClass(targetTypes);
      targetProfile = resolveTargetProfile(run.target, { preferredTargetClass: preferredClass });
      targetContext = buildContextForTarget(targetProfile);
    } else {
      targetProfile = resolveTargetProfile(run.target);
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
  const compiled = compilePlaybook({ steps, target: run.target, db });
  if (!compiled.ok) {
    console.warn(`[executionEngine] Playbook compilation warnings: ${compiled.warnings.join('; ')}`);
  }
  if (compiled.errors.length > 0) {
    for (const err of compiled.errors) {
      console.warn(`[executionEngine] Compilation error: ${err}`);
    }
  }
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

  // ReAct state (only used when engineType === 'react')
  const evidenceHistory = [];
  let reactCallCount = 0;

  // B5.3: Inject pipeline analysis results into ReAct initial evidence
  // When a run originates from a pipeline, plan_data may contain _pipeline_analysis
  // which provides scan analysis context so ReAct doesn't start "blind"
  if (engineType === 'react' && run.plan_data) {
    try {
      const planData = typeof run.plan_data === 'string' ? JSON.parse(run.plan_data) : run.plan_data;
      if (planData._pipeline_analysis) {
        const analysis = planData._pipeline_analysis;
        const summaryParts = [];
        if (analysis.tech_stack?.length) summaryParts.push(`Tech stack: ${analysis.tech_stack.join(', ')}`);
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

  try {
    // Use mutable steps array (ReAct may insert new steps)
    const mutableSteps = [...runnableSteps];

    for (let i = 0; i < mutableSteps.length; i++) {
      if (aborted) break;

      const step = mutableSteps[i];

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
      if (targetContext) {
        const { rendered, unresolvedTokens } = renderCommand(args, targetContext);
        args = rendered;
        if (unresolvedTokens.length > 0) {
          console.warn(`[executionEngine] Step ${step.step_index} has unresolved tokens: ${unresolvedTokens.join(', ')}`);
        }
      }

      // ── Blue team pre-exec check ────────────────────────────────────
      const preExecResult = applyBlueTeamPreExec({
        runId,
        toolId: step.tool_id,
        args,
        target: run.target,
      });

      let result;
      if (!preExecResult.allowed) {
        // Blocked by blue team — skip execution entirely
        result = {
          success: false,
          exitCode: -2,
          stdout: '',
          stderr: preExecResult.deniedReason || 'Blocked by blue team intervention',
          executionMode: 'blocked',
        };
      } else {
        // Use adjusted args if blue team modified them
        if (preExecResult.adjustedArgs) {
          args = preExecResult.adjustedArgs;
        }

        // Execute tool
        try {
          result = await runTool(step.tool_id, args, { timeout: 300 });
        } catch (err) {
          result = { success: false, exitCode: -1, stdout: '', stderr: err.message, executionMode: 'error' };
        }
      }

      // Record step result
      const output = (result.stdout || result.stderr || '').slice(0, MAX_OUTPUT_LENGTH);
      db.prepare(`
        INSERT INTO execution_steps (run_id, step_index, tool_id, args, success, exit_code, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        runId, step.step_index, step.tool_id,
        JSON.stringify(args), result.success ? 1 : 0, result.exitCode ?? -1, output
      );

      // Record evidence (with structured parsing + rules engine)
      const evidenceResult = recordEvidence(db, runId, step.step_index, step.tool_id, result, run.target, step.expected_mitre,
        step.payload_data ? { id: step.payload_data.id, name: step.payload_data.name } : null);

      // ── Detect candidate tool-to-technique mappings ──────────────────
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
        // Track failed tool counts for ReAct blacklist
        if (engineType === 'react') {
          const existing = failedToolCounts.find(f => f.toolId === step.tool_id);
          if (existing) { existing.count++; } else { failedToolCounts.push({ toolId: step.tool_id, count: 1 }); }
        }
        // In mechanical mode, non-optional step failure aborts immediately.
        // In react mode, we let ReAct analyze the failure and decide
        // (continue / adjust / insert / stop) — don't preempt the AI.
        if (!step.optional && engineType !== 'react') {
          aborted = true;
        }
      }

      // ── WebSocket broadcast: step completed ──────────────────────────
      const ws = getWsManager();
      if (ws) {
        const runInfo = db.prepare('SELECT user_sub FROM execution_runs WHERE run_id = ?').get(runId);
        ws.broadcast('run:step', {
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
      // Run on EVERY step (including failed ones and the last step) so
      // the AI can analyze results and decide next action. The only
      // exception is when a prior ReAct call already decided to stop.
      if (engineType === 'react' && !aborted) {
        // Accumulate evidence
        evidenceHistory.push({
          stepIndex: step.step_index,
          toolId: step.tool_id,
          success: result.success,
          output: output.slice(0, 300),
        });

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

        // Call ReAct engine
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
        });

        reactCallCount++;

        // Record thought in DB
        db.prepare("UPDATE execution_steps SET react_thought = ?, react_action = ? WHERE run_id = ? AND step_index = ?")
          .run(decision.thought, JSON.stringify({ type: decision.action }), runId, step.step_index);

        reactThoughts.push({
          stepIndex: step.step_index,
          thought: decision.thought,
          action: decision.action,
        });

        // Handle action
        switch (decision.action) {
          case 'stop':
            aborted = true;
            stopReason = decision.reason || 'LLM决定终止';
            console.log(`[ReAct] Run stopped: ${stopReason}`);
            break;

          case 'adjust':
            if (decision.newArgs && typeof decision.stepIndex === 'number') {
              // Find and modify the target step
              const targetStep = mutableSteps.find(s => s.step_index === decision.stepIndex);
              if (targetStep) {
                targetStep.args_template = JSON.stringify(decision.newArgs);
                console.log(`[ReAct] Adjusted step ${decision.stepIndex}: ${JSON.stringify(decision.newArgs)}`);
              }
            }
            break;

          case 'insert':
            if (decision.toolId && decision.args) {
              // Guard: validate insertion before proceeding
              const guardState = { steps: mutableSteps, status: run.status, stopReason };
              const guardResult = validateInsertion(guardState, 'insert', decision.toolId);
              if (!guardResult.allowed) {
                recordBlock(guardState, guardResult.category, decision.toolId);
                console.warn(`[ReAct Guard] ${guardResult.reason}`);
                break;  // Skip insertion, continue to next step
              }
              // Insert new step after current position
              const newStepIndex = mutableSteps[mutableSteps.length - 1].step_index + 1;
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
                    INSERT INTO evidence_records (record_id, run_id, step_index, tool_id, result_type, result_data, created_at)
                    VALUES (?, ?, ?, ?, 'discovered_target', ?, ?)
                  `).run(
                    `dt_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
                    run.run_id, step.step_index, decision.toolId,
                    JSON.stringify({ target: decision.newTarget, source: 'react_insert' }),
                    new Date().toISOString()
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
              // Guard: validate insertion before proceeding
              const guardState = { steps: mutableSteps, status: run.status, stopReason };
              const guardResult = validateInsertion(guardState, 'pivot', decision.toolId);
              if (!guardResult.allowed) {
                recordBlock(guardState, guardResult.category, decision.toolId);
                console.warn(`[ReAct Guard] ${guardResult.reason}`);
                break;
              }
              // Remove all remaining steps after current position
              mutableSteps.splice(i + 1);
              // Insert new pivot step
              const newStepIndex = mutableSteps[mutableSteps.length - 1].step_index + 1;
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
                // Guard: validate each parallel insertion
                const pGuard = validateInsertion(guardState, 'parallel', pToolId);
                if (!pGuard.allowed) {
                  recordBlock(guardState, pGuard.category, pToolId);
                  console.warn(`[ReAct Guard] ${pGuard.reason}`);
                  continue;  // Skip this tool in the parallel group
                }
                const newStepIndex = mutableSteps[mutableSteps.length - 1].step_index + 1;
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
      }
    }

    // Update run status
    const finalStatus = aborted ? (stopReason ? 'COMPLETED' : 'FAILED') : 'COMPLETED';
    const summary = JSON.stringify({
      total: mutableSteps.length,
      completed: completedSteps,
      failed: failedSteps,
      aborted,
      stopReason,
      engineType,
      reactCallCount,
    });

    // ── WebSocket broadcast: run completed ────────────────────────────
    const wsEnd = getWsManager();
    if (wsEnd) {
      const runInfo = db.prepare('SELECT user_sub FROM execution_runs WHERE run_id = ?').get(runId);
      wsEnd.broadcast('run:complete', {
        run_id: runId,
        status: finalStatus,
        completed_steps: completedSteps,
        failed_steps: failedSteps,
        total_steps: mutableSteps.length,
        stop_reason: stopReason,
        userId: runInfo?.user_sub || null,
        username: runInfo?.user_sub || null,
      });
    }

    // Persist ReAct state
    if (engineType === 'react') {
      db.prepare(`
        UPDATE execution_runs SET status = ?, final_summary = ?, stop_reason = ?,
          evidence_history = ?, react_thoughts = ?, updated_at = datetime('now')
        WHERE run_id = ?
      `).run(
        finalStatus, summary, stopReason,
        JSON.stringify(evidenceHistory),
        JSON.stringify(reactThoughts),
        runId
      );
    } else {
      db.prepare(`
        UPDATE execution_runs SET status = ?, final_summary = ?, updated_at = datetime('now')
        WHERE run_id = ?
      `).run(finalStatus, summary, runId);
    }

    return { ok: true, runId, status: finalStatus, completed: completedSteps, failed: failedSteps, engineType, stopReason };

  } catch (err) {
    db.prepare(`
      UPDATE execution_runs SET status = 'FAILED', final_summary = ?, updated_at = datetime('now')
      WHERE run_id = ?
    `).run(JSON.stringify({ error: err.message }), runId);

    return { ok: false, error: err.message };
  } finally {
    runningRuns.delete(runId);
  }
}

function tryJsonArr(str) {
  try { const v = JSON.parse(str || '[]'); return Array.isArray(v) ? v : []; } catch { return []; }
}
