import { getDb } from '../db/connection.js';
import { randomUUID } from 'crypto';
import { getWsManager } from './wsManager.js';
import { resolveTargetProfile } from './targetProfileResolver.js';
import { analyzeScanResults } from './scanAnalyzer.js';

// ── Track running pipelines for cancellation ──────────────────────────────
const runningPipelines = new Set();

// ── Step type constants ───────────────────────────────────────────────────
const STEP_SCAN     = 'scan';
const STEP_ANALYZE  = 'analyze';
const STEP_GENERATE = 'generate';
const STEP_EXECUTE  = 'execute';

// ── WebSocket event names ─────────────────────────────────────────────────
const WS_PIPELINE_STATUS   = 'pipeline:status';
const WS_PIPELINE_STEP     = 'pipeline:step';
const WS_PIPELINE_LOG      = 'pipeline:log';

// ── Internal helpers ──────────────────────────────────────────────────────

/** Broadcast a pipeline-level event to all connected clients. */
function broadcastPipelineEvent(event, data) {
  const ws = getWsManager();
  if (ws) ws.broadcast(event, data);
}

/** Update pipeline status in DB and broadcast. */
function updateStatus(db, pipelineId, status, extra = {}) {
  const now = new Date().toISOString();
  const sets = ["status = ?", "updated_at = ?"];
  const params = [status, now];

  if (extra.error_message !== undefined) {
    sets.push("error_message = ?");
    params.push(extra.error_message);
  }
  if (extra.result !== undefined) {
    sets.push("result = ?");
    params.push(JSON.stringify(extra.result));
  }
  if (extra.scan_task_id !== undefined) {
    sets.push("scan_task_id = ?");
    params.push(extra.scan_task_id);
  }
  if (extra.generated_playbook_id !== undefined) {
    sets.push("generated_playbook_id = ?");
    params.push(extra.generated_playbook_id);
  }
  if (extra.run_id !== undefined) {
    sets.push("run_id = ?");
    params.push(extra.run_id);
  }
  if (extra.analysis_result !== undefined) {
    sets.push("analysis_result = ?");
    params.push(JSON.stringify(extra.analysis_result));
  }

  params.push(pipelineId);
  db.prepare(`UPDATE pipelines SET ${sets.join(', ')} WHERE pipeline_id = ?`).run(...params);

  broadcastPipelineEvent(WS_PIPELINE_STATUS, { pipeline_id: pipelineId, status, ...extra });
}

/** Update a pipeline step status in DB and broadcast. */
function updateStep(db, pipelineId, stepOrder, status, data = {}) {
  const now = new Date().toISOString();
  const sets = ["status = ?"];
  const params = [status];

  if (status === 'running' && !data.started_at) {
    sets.push("started_at = ?");
    params.push(now);
  }
  if (['completed', 'failed', 'skipped', 'cancelled'].includes(status) && !data.completed_at) {
    sets.push("completed_at = ?");
    params.push(now);
  }
  if (data.output_data !== undefined) {
    sets.push("output_data = ?");
    params.push(typeof data.output_data === 'string' ? data.output_data : JSON.stringify(data.output_data));
  }
  if (data.input_data !== undefined) {
    sets.push("input_data = ?");
    params.push(typeof data.input_data === 'string' ? data.input_data : JSON.stringify(data.input_data));
  }
  if (data.error_message !== undefined) {
    sets.push("error_message = ?");
    params.push(data.error_message);
  }

  params.push(pipelineId, stepOrder);
  db.prepare(
    `UPDATE pipeline_steps SET ${sets.join(', ')} WHERE pipeline_id = ? AND step_order = ?`
  ).run(...params);

  broadcastPipelineEvent(WS_PIPELINE_STEP, {
    pipeline_id: pipelineId, step_order: stepOrder, step_type: data.step_type, status, ...data,
  });
}

/** Log a pipeline message (for debugging / real-time UI). */
function pipelineLog(pipelineId, message, level = 'info') {
  broadcastPipelineEvent(WS_PIPELINE_LOG, { pipeline_id: pipelineId, message, level, timestamp: Date.now() });
}

/** Ensure step record exists in pipeline_steps. */
function ensureStep(db, pipelineId, stepOrder, stepType) {
  const existing = db.prepare(
    'SELECT id FROM pipeline_steps WHERE pipeline_id = ? AND step_order = ?'
  ).get(pipelineId, stepOrder);
  if (!existing) {
    db.prepare(
      `INSERT INTO pipeline_steps (pipeline_id, step_order, step_type, status)
       VALUES (?, ?, ?, 'pending')`
    ).run(pipelineId, stepOrder, stepType);
  }
}

/** Mark a pipeline as failed with an error. */
function failPipeline(db, pipelineId, errorMessage) {
  updateStatus(db, pipelineId, 'failed', { error_message: errorMessage });
  runningPipelines.delete(pipelineId);
}

/** Check if pipeline was cancelled mid-run. */
function isCancelled(pipelineId) {
  if (!runningPipelines.has(pipelineId)) return true; // removed from set = cancelled
  const db = getDb();
  const row = db.prepare('SELECT status FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
  return !row || row.status === 'cancelled';
}

// ── Step 1: Scan ──────────────────────────────────────────────────────────

async function runPipelineScan(db, pipeline) {
  const pipelineId = pipeline.pipeline_id;
  const target = pipeline.target;

  pipelineLog(pipelineId, `开始扫描目标: ${target}`);

  // Resolve target profile to determine scan types
  const profile = resolveTargetProfile(target);
  const isWebLike = ['dvwa', 'local_ip', 'web_url'].includes(profile.target_class);

  // Determine scan types to run
  const scanTypes = isWebLike ? ['port_scan', 'web_scan'] : ['port_scan'];

  // Insert step record
  ensureStep(db, pipelineId, 0, STEP_SCAN);
  updateStep(db, pipelineId, 0, 'running', { step_type: STEP_SCAN, input_data: { target, scan_types: scanTypes } });

  const scanTaskIds = [];

  try {
    for (const scanType of scanTypes) {
      if (isCancelled(pipelineId)) {
        updateStep(db, pipelineId, 0, 'cancelled', { step_type: STEP_SCAN });
        return { ok: false, cancelled: true };
      }

      pipelineLog(pipelineId, `创建扫描任务: ${scanType}`);

      // Create scan task
      const scanTaskId = `scan_${randomUUID().slice(0, 12)}`;
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO scan_tasks (scan_task_id, target, scan_type, target_class, parameters, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(scanTaskId, target, scanType, profile.target_class, JSON.stringify({}), pipeline.created_by || 'pipeline', now);

      scanTaskIds.push(scanTaskId);

      // Execute the scan
      pipelineLog(pipelineId, `执行扫描: ${scanType} (${scanTaskId})`);
      const { executeScan } = await import('./scanExecutor.js');
      const scanResult = await executeScan(scanTaskId);

      if (isCancelled(pipelineId)) {
        updateStep(db, pipelineId, 0, 'cancelled', { step_type: STEP_SCAN });
        return { ok: false, cancelled: true };
      }

      if (!scanResult.ok) {
        pipelineLog(pipelineId, `扫描 ${scanType} 失败: ${scanResult.error}`, 'warn');
      } else {
        pipelineLog(pipelineId, `扫描 ${scanType} 完成，发现 ${scanResult.resultsCount || 0} 条结果`);
      }
    }

    // Store all scan task IDs in the pipeline record (comma-separated)
    updateStatus(db, pipelineId, 'running', { scan_task_id: scanTaskIds.join(',') });

    // Count total results
    const placeholders = scanTaskIds.map(() => '?').join(',');
    const totalResults = db.prepare(
      `SELECT COUNT(*) AS n FROM scan_results WHERE scan_task_id IN (${placeholders})`
    ).get(...scanTaskIds).n;

    const stepOutput = {
      scan_task_ids: scanTaskIds,
      scan_types_run: scanTypes,
      total_results: totalResults,
    };

    updateStep(db, pipelineId, 0, 'completed', {
      step_type: STEP_SCAN,
      output_data: stepOutput,
    });

    pipelineLog(pipelineId, `扫描阶段完成，共 ${totalResults} 条发现`);

    return { ok: true, scanTaskIds, totalResults };
  } catch (err) {
    updateStep(db, pipelineId, 0, 'failed', {
      step_type: STEP_SCAN,
      error_message: err.message,
    });
    pipelineLog(pipelineId, `扫描阶段异常: ${err.message}`, 'error');
    return { ok: false, error: err.message };
  }
}

// ── Step 2: Analyze ───────────────────────────────────────────────────────

async function runPipelineAnalysis(db, pipeline, scanTaskIds) {
  const pipelineId = pipeline.pipeline_id;
  pipelineLog(pipelineId, '开始分析扫描结果');

  ensureStep(db, pipelineId, 1, STEP_ANALYZE);
  updateStep(db, pipelineId, 1, 'running', {
    step_type: STEP_ANALYZE,
    input_data: { scan_task_ids: scanTaskIds },
  });

  try {
    if (isCancelled(pipelineId)) {
      updateStep(db, pipelineId, 1, 'cancelled', { step_type: STEP_ANALYZE });
      return { ok: false, cancelled: true };
    }

    const analysisResult = await analyzeScanResults(scanTaskIds, { target: pipeline.target });

    if (isCancelled(pipelineId)) {
      updateStep(db, pipelineId, 1, 'cancelled', { step_type: STEP_ANALYZE });
      return { ok: false, cancelled: true };
    }

    if (!analysisResult.ok) {
      // If analysis fails (e.g. LLM not configured), create a minimal fallback analysis
      const fallback = createFallbackAnalysis(db, pipeline.target, scanTaskIds);
      updateStatus(db, pipelineId, 'running', { analysis_result: fallback });
      updateStep(db, pipelineId, 1, 'completed', {
        step_type: STEP_ANALYZE,
        output_data: { fallback: true, ...fallback },
        error_message: analysisResult.error,
      });
      pipelineLog(pipelineId, `分析使用降级结果（${analysisResult.error}）`, 'warn');
      return { ok: true, data: fallback, fallback: true };
    }

    // Store analysis result in pipeline record
    updateStatus(db, pipelineId, 'running', { analysis_result: analysisResult.data });

    updateStep(db, pipelineId, 1, 'completed', {
      step_type: STEP_ANALYZE,
      output_data: analysisResult.data,
    });

    pipelineLog(pipelineId, '分析阶段完成');
    return { ok: true, data: analysisResult.data };
  } catch (err) {
    // Fallback on error too
    const fallback = createFallbackAnalysis(db, pipeline.target, scanTaskIds);
    updateStatus(db, pipelineId, 'running', { analysis_result: fallback });
    updateStep(db, pipelineId, 1, 'completed', {
      step_type: STEP_ANALYZE,
      output_data: { fallback: true, ...fallback },
      error_message: err.message,
    });
    pipelineLog(pipelineId, `分析异常，使用降级结果: ${err.message}`, 'warn');
    return { ok: true, data: fallback, fallback: true };
  }
}

/** Create a fallback analysis when LLM is unavailable. */
function createFallbackAnalysis(db, target, scanTaskIds) {
  const ids = Array.isArray(scanTaskIds) ? scanTaskIds : [scanTaskIds];
  const placeholders = ids.map(() => '?').join(',');

  // Group findings by type
  const findings = db.prepare(
    `SELECT result_type, severity, COUNT(*) AS cnt
     FROM scan_results WHERE scan_task_id IN (${placeholders})
     GROUP BY result_type, severity ORDER BY cnt DESC`
  ).all(...ids);

  const profile = resolveTargetProfile(target);

  return {
    tech_stack: {
      note: 'LLM 不可用，基于扫描类型推断',
      detected_class: profile.target_class,
    },
    attack_surface: findings.map(f => ({
      type: f.result_type,
      count: f.cnt,
      max_severity: f.severity,
    })),
    risk_assessment: findings
      .filter(f => ['critical', 'high', 'medium'].includes(f.severity))
      .map(f => ({
        category: f.result_type,
        level: f.severity,
        finding_count: f.cnt,
      })),
    recommended_strategy: [
      { priority: 1, strategy: '根据发现类型选择对应 Playbook', description: `共 ${findings.length} 类发现，优先处理 high/critical 项` },
    ],
  };
}

// ── Step 3: Generate / Match Playbook ─────────────────────────────────────

async function runPipelineGeneration(db, pipeline, analysisData, scanTaskIds) {
  const pipelineId = pipeline.pipeline_id;
  pipelineLog(pipelineId, '开始生成/匹配 Playbook');

  ensureStep(db, pipelineId, 2, STEP_GENERATE);
  updateStep(db, pipelineId, 2, 'running', {
    step_type: STEP_GENERATE,
    input_data: { analysis_summary: analysisData, scan_task_ids: scanTaskIds },
  });

  try {
    if (isCancelled(pipelineId)) {
      updateStep(db, pipelineId, 2, 'cancelled', { step_type: STEP_GENERATE });
      return { ok: false, cancelled: true };
    }

    let playbookId = null;
    let generationMethod = null;
    let playbookName = null;

    // Strategy 1: Try AI generation from the primary scan task
    const primaryScanId = Array.isArray(scanTaskIds) ? scanTaskIds[0] : scanTaskIds;
    if (primaryScanId) {
      pipelineLog(pipelineId, '尝试 AI 生成 Playbook');
      try {
        const { generatePlaybook } = await import('./playbookGenerator.js');
        const genResult = await generatePlaybook(primaryScanId);

        if (isCancelled(pipelineId)) {
          updateStep(db, pipelineId, 2, 'cancelled', { step_type: STEP_GENERATE });
          return { ok: false, cancelled: true };
        }

        if (genResult.ok) {
          playbookId = genResult.playbook_id;
          generationMethod = 'ai_generated';
          playbookName = genResult.name;
          pipelineLog(pipelineId, `AI 生成成功: ${playbookName} (${playbookId})`);
        } else {
          pipelineLog(pipelineId, `AI 生成失败: ${genResult.error}，尝试匹配已有 Playbook`, 'warn');
        }
      } catch (err) {
        pipelineLog(pipelineId, `AI 生成异常: ${err.message}，尝试匹配已有 Playbook`, 'warn');
      }
    }

    // Strategy 2: Fall back to playbook matching if generation failed
    if (!playbookId) {
      pipelineLog(pipelineId, '尝试匹配已有 Playbook');
      const { matchPlaybooks } = await import('./playbookMatcher.js');

      // Get all scan results for matching
      const ids = Array.isArray(scanTaskIds) ? scanTaskIds : [scanTaskIds];
      const placeholders = ids.map(() => '?').join(',');
      const allResults = db.prepare(
        `SELECT result_type, result_data, severity, mitre_technique_id, source_tool
         FROM scan_results WHERE scan_task_id IN (${placeholders})`
      ).all(...ids);

      const profile = resolveTargetProfile(pipeline.target);
      const ranked = matchPlaybooks(allResults, profile.target_class);

      if (ranked.length > 0) {
        const bestMatch = ranked[0];
        playbookId = bestMatch.playbook_id;
        generationMethod = 'matched';
        playbookName = bestMatch.name;
        pipelineLog(pipelineId, `匹配成功: ${playbookName} (${playbookId})，评分: ${bestMatch.match_score}`);
      } else {
        pipelineLog(pipelineId, '未匹配到任何 Playbook', 'error');
        updateStep(db, pipelineId, 2, 'failed', {
          step_type: STEP_GENERATE,
          error_message: 'AI 生成和已有 Playbook 匹配均失败',
        });
        return { ok: false, error: '无法生成或匹配 Playbook' };
      }
    }

    // Store playbook ID in pipeline record
    updateStatus(db, pipelineId, 'running', { generated_playbook_id: playbookId });

    const stepOutput = {
      playbook_id: playbookId,
      name: playbookName,
      method: generationMethod,
    };

    updateStep(db, pipelineId, 2, 'completed', {
      step_type: STEP_GENERATE,
      output_data: stepOutput,
    });

    pipelineLog(pipelineId, `生成阶段完成: ${generationMethod} → ${playbookName}`);
    return { ok: true, playbookId, method: generationMethod, name: playbookName };
  } catch (err) {
    updateStep(db, pipelineId, 2, 'failed', {
      step_type: STEP_GENERATE,
      error_message: err.message,
    });
    pipelineLog(pipelineId, `生成阶段异常: ${err.message}`, 'error');
    return { ok: false, error: err.message };
  }
}

// ── Step 4: Execute ───────────────────────────────────────────────────────

async function runPipelineExecution(db, pipeline, playbookId, analysisData) {
  const pipelineId = pipeline.pipeline_id;
  pipelineLog(pipelineId, `开始执行 Playbook: ${playbookId}`);

  ensureStep(db, pipelineId, 3, STEP_EXECUTE);

  // Build execution config from pipeline config and analysis data
  let pipelineConfig = {};
  try { pipelineConfig = JSON.parse(pipeline.config || '{}'); } catch {}

  // Determine execution mode
  const autoExecute = pipelineConfig.auto_execute !== false; // default: true

  if (!autoExecute) {
    pipelineLog(pipelineId, 'auto_execute 为 false，跳过执行阶段', 'info');
    updateStep(db, pipelineId, 3, 'skipped', {
      step_type: STEP_EXECUTE,
      output_data: { note: 'auto_execute 配置为 false，跳过执行' },
    });
    return { ok: true, skipped: true };
  }

  updateStep(db, pipelineId, 3, 'running', {
    step_type: STEP_EXECUTE,
    input_data: { playbook_id: playbookId, target: pipeline.target },
  });

  try {
    if (isCancelled(pipelineId)) {
      updateStep(db, pipelineId, 3, 'cancelled', { step_type: STEP_EXECUTE });
      return { ok: false, cancelled: true };
    }

    // Create an execution run
    const runId = `run_${randomUUID().slice(0, 12)}`;
    const now = new Date().toISOString();
    const userSub = pipeline.created_by || 'pipeline';
    const userRole = 'student'; // pipelines run with student-level privileges

    const planData = {
      _pipeline_source: pipelineId,
      _pipeline_analysis: analysisData ? {
        tech_stack: analysisData.tech_stack,
        recommended_strategy: analysisData.recommended_strategy,
      } : null,
    };

    db.prepare(
      `INSERT INTO execution_runs (run_id, playbook_id, user_sub, user_role, target, status, plan_data, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)`
    ).run(runId, playbookId, userSub, userRole, pipeline.target, JSON.stringify(planData), now, now);

    // Store run_id in pipeline record
    updateStatus(db, pipelineId, 'running', { run_id: runId });

    pipelineLog(pipelineId, `执行运行创建: ${runId}`);

    // Execute the run
    const { executeRun } = await import('./executionEngine.js');
    const execResult = await executeRun(runId);

    if (isCancelled(pipelineId)) {
      updateStep(db, pipelineId, 3, 'cancelled', { step_type: STEP_EXECUTE });
      return { ok: false, cancelled: true };
    }

    // Get final run status
    const runRecord = db.prepare(
      'SELECT status, final_summary, stop_reason FROM execution_runs WHERE run_id = ?'
    ).get(runId);

    const execSuccess = execResult.ok && runRecord && runRecord.status === 'COMPLETED';
    const stepStatus = execSuccess ? 'completed' : 'failed';

    const stepOutput = {
      run_id: runId,
      status: runRecord?.status || 'UNKNOWN',
      final_summary: runRecord?.final_summary || null,
      stop_reason: runRecord?.stop_reason || null,
    };

    updateStep(db, pipelineId, 3, stepStatus, {
      step_type: STEP_EXECUTE,
      output_data: stepOutput,
      error_message: execResult.ok ? null : (execResult.error || 'Execution failed'),
    });

    pipelineLog(pipelineId, `执行阶段${execSuccess ? '完成' : '失败'} (${runRecord?.status || 'ERROR'})`);

    return { ok: execSuccess, runId, status: runRecord?.status };
  } catch (err) {
    updateStep(db, pipelineId, 3, 'failed', {
      step_type: STEP_EXECUTE,
      error_message: err.message,
    });
    pipelineLog(pipelineId, `执行阶段异常: ${err.message}`, 'error');
    return { ok: false, error: err.message };
  }
}

// ── Main entry point ──────────────────────────────────────────────────────

/**
 * Run a pipeline through all steps: scan → analyze → generate → execute.
 *
 * @param {string} pipelineId
 * @returns {Promise<{ok: boolean, pipeline_id: string, status?: string, error?: string}>}
 */
export async function runPipeline(pipelineId) {
  const db = getDb();

  // Get pipeline from DB
  const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
  if (!pipeline) {
    return { ok: false, error: `Pipeline ${pipelineId} not found` };
  }

  // Validate current status
  // Note: the start route sets status to 'running' before calling runPipeline,
  // so we accept 'running' as a valid starting state too.
  if (!['created', 'paused', 'running'].includes(pipeline.status)) {
    return { ok: false, error: `Pipeline status is "${pipeline.status}", expected "created", "paused", or "running"` };
  }

  if (runningPipelines.has(pipelineId)) {
    return { ok: false, error: 'Pipeline is already running' };
  }

  // Mark as running (if not already set by the start route)
  runningPipelines.add(pipelineId);
  if (pipeline.status !== 'running') {
    updateStatus(db, pipelineId, 'running', { error_message: null });
  }

  pipelineLog(pipelineId, `流水线启动: target=${pipeline.target}`);

  try {
    // Parse config
    let pipelineConfig = {};
    try { pipelineConfig = JSON.parse(pipeline.config || '{}'); } catch {}

    // ── Step 0: Scan ────────────────────────────────────────────────────
    pipelineLog(pipelineId, '=== 步骤 0: 扫描 ===');
    const scanResult = await runPipelineScan(db, pipeline);
    if (!scanResult.ok) {
      if (scanResult.cancelled) {
        updateStatus(db, pipelineId, 'cancelled', { result: { stopped_at: 'scan' } });
      } else {
        failPipeline(db, pipelineId, `扫描阶段失败: ${scanResult.error}`);
      }
      return { ok: scanResult.ok !== false, pipeline_id: pipelineId, status: 'failed', error: scanResult.error };
    }

    // ── Step 1: Analyze ─────────────────────────────────────────────────
    pipelineLog(pipelineId, '=== 步骤 1: 分析 ===');
    const analysisResult = await runPipelineAnalysis(db, pipeline, scanResult.scanTaskIds);
    if (!analysisResult.ok) {
      if (analysisResult.cancelled) {
        updateStatus(db, pipelineId, 'cancelled', { result: { stopped_at: 'analyze' } });
      } else {
        failPipeline(db, pipelineId, `分析阶段失败: ${analysisResult.error}`);
      }
      return { ok: false, pipeline_id: pipelineId, status: 'failed', error: analysisResult.error };
    }

    // ── Step 2: Generate ────────────────────────────────────────────────
    pipelineLog(pipelineId, '=== 步骤 2: 生成 Playbook ===');
    const generateResult = await runPipelineGeneration(db, pipeline, analysisResult.data, scanResult.scanTaskIds);
    if (!generateResult.ok) {
      if (generateResult.cancelled) {
        updateStatus(db, pipelineId, 'cancelled', { result: { stopped_at: 'generate' } });
      } else {
        failPipeline(db, pipelineId, `生成阶段失败: ${generateResult.error}`);
      }
      return { ok: false, pipeline_id: pipelineId, status: 'failed', error: generateResult.error };
    }

    // ── Step 3: Execute ─────────────────────────────────────────────────
    pipelineLog(pipelineId, '=== 步骤 3: 执行 ===');
    const executeResult = await runPipelineExecution(db, pipeline, generateResult.playbookId, analysisResult.data);

    if (!executeResult.ok) {
      if (executeResult.cancelled) {
        updateStatus(db, pipelineId, 'cancelled', { result: { stopped_at: 'execute' } });
      } else {
        failPipeline(db, pipelineId, `执行阶段失败: ${executeResult.error}`);
      }
      return { ok: false, pipeline_id: pipelineId, status: 'failed', error: executeResult.error };
    }

    // ── All steps completed ─────────────────────────────────────────────
    const finalResult = {
      scan_task_ids: scanResult.scanTaskIds,
      analysis: {
        tech_stack: analysisResult.data?.tech_stack,
        attack_surface_count: Array.isArray(analysisResult.data?.attack_surface) ? analysisResult.data.attack_surface.length : 0,
        risk_count: Array.isArray(analysisResult.data?.risk_assessment) ? analysisResult.data.risk_assessment.length : 0,
        strategy_count: Array.isArray(analysisResult.data?.recommended_strategy) ? analysisResult.data.recommended_strategy.length : 0,
      },
      playbook: {
        id: generateResult.playbookId,
        name: generateResult.name,
        method: generateResult.method,
      },
      execution: executeResult.skipped
        ? { skipped: true }
        : { run_id: executeResult.runId, status: executeResult.status },
      pipeline_completed_at: new Date().toISOString(),
    };

    updateStatus(db, pipelineId, 'completed', { result: finalResult });
    runningPipelines.delete(pipelineId);

    pipelineLog(pipelineId, '流水线全部完成');
    return { ok: true, pipeline_id: pipelineId, status: 'completed' };
  } catch (err) {
    failPipeline(db, pipelineId, `流水线异常: ${err.message}`);
    pipelineLog(pipelineId, `流水线异常: ${err.message}`, 'error');
    return { ok: false, pipeline_id: pipelineId, status: 'failed', error: err.message };
  }
}

// ── Cancel a running pipeline ─────────────────────────────────────────────

/**
 * Cancel a running pipeline.
 * @param {string} pipelineId
 * @returns {{ok: boolean, error?: string}}
 */
export function cancelPipeline(pipelineId) {
  const db = getDb();
  const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
  if (!pipeline) return { ok: false, error: 'Pipeline not found' };
  if (pipeline.status !== 'running') return { ok: false, error: `Pipeline is "${pipeline.status}", not running` };

  // Remove from running set — step functions check this to abort
  runningPipelines.delete(pipelineId);

  const now = new Date().toISOString();
  db.prepare("UPDATE pipelines SET status = 'cancelled', updated_at = ? WHERE pipeline_id = ?").run(now, pipelineId);

  // Mark all pending/running steps as cancelled
  db.prepare(
    "UPDATE pipeline_steps SET status = 'cancelled', completed_at = ? WHERE pipeline_id = ? AND status IN ('pending', 'running')"
  ).run(now, pipelineId);

  broadcastPipelineEvent(WS_PIPELINE_STATUS, { pipeline_id: pipelineId, status: 'cancelled' });

  return { ok: true };
}

// ── Status check ──────────────────────────────────────────────────────────

/**
 * Check if a pipeline is currently running.
 * @param {string} pipelineId
 * @returns {boolean}
 */
export function isPipelineRunning(pipelineId) {
  return runningPipelines.has(pipelineId);
}

/**
 * Get the count of currently running pipelines.
 * @returns {number}
 */
export function runningPipelineCount() {
  return runningPipelines.size;
}

export default {
  runPipeline,
  cancelPipeline,
  isPipelineRunning,
  runningPipelineCount,
};
