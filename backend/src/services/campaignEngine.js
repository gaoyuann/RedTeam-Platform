import { randomUUID } from 'crypto';
import { getWsManager } from './wsManager.js';

// ── Safe template variable replacement ──────────────────────────────────
// Replaces {{artifact.xxx}} placeholders with artifact values, shell-escaped.
function safeTemplateReplace(template, artifactsMap) {
  if (!template || typeof template !== 'string') return template;
  return template.replace(/\{\{(\w[\w.]*)\}\}/g, (match, key) => {
    const value = artifactsMap[key];
    if (value === undefined) return match; // unresolved variable stays as-is
    return String(value).replace(/[^\w\-.,:/@]/g, '\\$&');
  });
}

// ── Build artifacts map from previous phases ────────────────────────────
function buildArtifactsMap(db, campaignId, currentPhaseOrderIndex) {
  const artifacts = db.prepare(`
    SELECT ca.artifact_type, ca.artifact_key, ca.artifact_value, cp.order_index
    FROM campaign_artifacts ca
    JOIN campaign_phases cp ON cp.phase_id = ca.phase_id
    WHERE ca.campaign_id = ? AND cp.order_index < ?
    ORDER BY cp.order_index DESC, ca.created_at DESC
  `).all(campaignId, currentPhaseOrderIndex);

  const map = {};
  for (const a of artifacts) {
    const prefix = `artifact.${a.artifact_key}`;
    try {
      map[prefix] = a.artifact_value; // raw JSON string
      // Also parse and expose individual fields
      const parsed = JSON.parse(a.artifact_value);
      if (typeof parsed === 'object' && parsed !== null) {
        for (const [k, v] of Object.entries(parsed)) {
          map[`${prefix}.${k}`] = String(v);
        }
      }
    } catch {
      map[prefix] = a.artifact_value;
    }
  }
  return map;
}

// ── Extract artifacts from evidence records ─────────────────────────────
function extractArtifactsFromEvidence(db, runId, campaignId, phaseId) {
  const evidence = db.prepare(
    'SELECT * FROM evidence_records WHERE run_id = ? ORDER BY recorded_at'
  ).all(runId);

  const insertArtifact = db.prepare(`
    INSERT INTO campaign_artifacts (campaign_id, phase_id, artifact_type, artifact_key, artifact_value, source_run_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
  `);

  for (const e of evidence) {
    let artifactType = 'custom';
    let artifactKey = '';
    let artifactValue = '';

    if (e.evidence_type === 'credential_access') {
      artifactType = 'credential';
      artifactKey = 'cracked_credential';
      try {
        const data = e.evidence_data ? JSON.parse(e.evidence_data) : {};
        artifactValue = JSON.stringify({ type: 'credential', source: e.tool_id, ...data });
      } catch {
        artifactValue = JSON.stringify({ type: 'credential', source: e.tool_id, raw: (e.evidence_data || '').slice(0, 500) });
      }
    } else if (e.evidence_type === 'open_port') {
      artifactType = 'ip_list';
      artifactKey = 'discovered_hosts';
      try {
        const existing = db.prepare(
          "SELECT artifact_value FROM campaign_artifacts WHERE campaign_id = ? AND phase_id = ? AND artifact_key = 'discovered_hosts' ORDER BY id DESC LIMIT 1"
        ).get(campaignId, phaseId);
        const hosts = existing ? JSON.parse(existing.artifact_value) : [];
        const data = e.evidence_data ? JSON.parse(e.evidence_data) : {};
        if (e.target && !hosts.includes(e.target)) hosts.push(e.target);
        artifactValue = JSON.stringify(hosts);
        // Update existing instead of inserting duplicate
        if (existing) {
          db.prepare("UPDATE campaign_artifacts SET artifact_value = ? WHERE campaign_id = ? AND phase_id = ? AND artifact_key = 'discovered_hosts' AND id = (SELECT id FROM campaign_artifacts WHERE campaign_id = ? AND phase_id = ? AND artifact_key = 'discovered_hosts' ORDER BY id DESC LIMIT 1)")
            .run(artifactValue, campaignId, phaseId, campaignId, phaseId);
          continue; // skip insert
        }
      } catch {
        artifactValue = JSON.stringify([e.target].filter(Boolean));
      }
    } else {
      // Generic artifact
      artifactKey = `${e.evidence_type}_${e.step_index || 0}`;
      artifactValue = JSON.stringify({ type: e.evidence_type, tool: e.tool_id, summary: (e.evidence_data || '').slice(0, 500) });
    }

    try {
      insertArtifact.run(campaignId, phaseId, artifactType, artifactKey, artifactValue, runId);
    } catch (err) {
      console.error(`[CampaignEngine] Failed to insert artifact:`, err.message);
    }
  }
}

// ── Execute a single playbook within a campaign ─────────────────────────
async function executePlaybookInCampaign(db, campaignId, phaseId, cpRow, target, artifactsMap) {
  const now = new Date().toISOString();

  // Update campaign_playbooks status
  db.prepare("UPDATE campaign_playbooks SET status = 'running' WHERE id = ?").run(cpRow.id);

  // Create an execution_run
  const runId = `run_${randomUUID().slice(0, 12)}`;
  const effectiveTarget = cpRow.target_override || target;

  // Resolve artifact template variables in playbook steps
  const steps = db.prepare(
    'SELECT step_index, args_template FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index'
  ).all(cpRow.playbook_id);

  // Build resolved args map: for each step, apply safeTemplateReplace to args_template
  const resolvedSteps = {};
  for (const step of steps) {
    if (step.args_template && Object.keys(artifactsMap).length > 0) {
      resolvedSteps[step.step_index] = safeTemplateReplace(step.args_template, artifactsMap);
    }
  }

  db.prepare(`INSERT INTO execution_runs (run_id, playbook_id, user_sub, user_role, target, status, plan_data, created_at, updated_at)
    VALUES (?, ?, 'campaign', 'system', ?, 'PENDING', ?, ?, ?)`).run(
      runId, cpRow.playbook_id, effectiveTarget,
      Object.keys(resolvedSteps).length > 0 ? JSON.stringify({ _campaignArtifacts: resolvedSteps }) : null,
      now, now);

  // Update campaign_playbooks with run_id
  db.prepare('UPDATE campaign_playbooks SET run_id = ? WHERE id = ?').run(runId, cpRow.id);

  // Broadcast
  const ws = getWsManager();
  if (ws) ws.broadcast('campaign:playbook_started', { campaign_id: campaignId, phase_id: phaseId, run_id: runId, playbook_id: cpRow.playbook_id });

  try {
    // Import and call the existing execution engine
    const { executeRun } = await import('./executionEngine.js');
    await executeRun(runId);

    // Check run result
    const run = db.prepare('SELECT status, final_summary FROM execution_runs WHERE run_id = ?').get(runId);
    const success = run && run.status === 'COMPLETED';

    db.prepare("UPDATE campaign_playbooks SET status = ? WHERE id = ?").run(success ? 'completed' : 'failed', cpRow.id);

    // Extract artifacts from evidence
    extractArtifactsFromEvidence(db, runId, campaignId, phaseId);

    return { runId, success };
  } catch (err) {
    db.prepare("UPDATE campaign_playbooks SET status = 'failed' WHERE id = ?").run(cpRow.id);
    console.error(`[CampaignEngine] Playbook ${cpRow.playbook_id} failed:`, err.message);
    return { runId, success: false, error: err.message };
  }
}

// ── Execute a single phase ──────────────────────────────────────────────
async function executePhase(db, campaignId, phase, target) {
  const now = new Date().toISOString();
  db.prepare("UPDATE campaign_phases SET status = 'running', started_at = ? WHERE phase_id = ?").run(now, phase.phase_id);

  const ws = getWsManager();
  if (ws) ws.broadcast('phase:started', { campaign_id: campaignId, phase_id: phase.phase_id, phase_type: phase.phase_type });

  // Get playbooks in this phase
  const playbooks = db.prepare(
    'SELECT * FROM campaign_playbooks WHERE phase_id = ? ORDER BY execution_order'
  ).all(phase.phase_id);

  if (playbooks.length === 0) {
    // Empty phase — mark as skipped (not completed, since nothing was actually done)
    console.warn(`[CampaignEngine] Phase ${phase.phase_id} (${phase.phase_type}) has no playbooks, marking as skipped`);
    db.prepare("UPDATE campaign_phases SET status = 'skipped', completed_at = datetime('now'), summary = ? WHERE phase_id = ?")
      .run(JSON.stringify({ note: '无Playbook，自动跳过' }), phase.phase_id);
    if (ws) ws.broadcast('phase:skipped', { campaign_id: campaignId, phase_id: phase.phase_id });
    return true;
  }

  // Build artifacts map from previous phases
  const artifactsMap = buildArtifactsMap(db, campaignId, phase.order_index);

  // Execute playbooks
  const parallelGroups = [];
  let currentParallelGroup = [];

  for (const pb of playbooks) {
    if (pb.execution_mode === 'parallel') {
      currentParallelGroup.push(pb);
    } else {
      // Flush current parallel group
      if (currentParallelGroup.length > 0) {
        parallelGroups.push({ mode: 'parallel', items: currentParallelGroup });
        currentParallelGroup = [];
      }
      parallelGroups.push({ mode: 'sequential', items: [pb] });
    }
  }
  if (currentParallelGroup.length > 0) {
    parallelGroups.push({ mode: 'parallel', items: currentParallelGroup });
  }

  let allSuccess = true;
  for (const group of parallelGroups) {
    if (group.mode === 'parallel') {
      const results = await Promise.all(
        group.items.map(pb => executePlaybookInCampaign(db, campaignId, phase.phase_id, pb, target, artifactsMap))
      );
      if (results.some(r => !r.success)) allSuccess = false;
    } else {
      for (const pb of group.items) {
        const result = await executePlaybookInCampaign(db, campaignId, phase.phase_id, pb, target, artifactsMap);
        if (!result.success) { allSuccess = false; break; } // sequential: stop on failure
      }
    }
  }

  // Update phase status
  const completedNow = new Date().toISOString();
  const phaseStatus = allSuccess ? 'completed' : 'failed';
  const phaseSummary = JSON.stringify({
    playbooks_total: playbooks.length,
    playbooks_completed: playbooks.filter(p => p.status === 'completed').length,
    playbooks_failed: playbooks.filter(p => p.status === 'failed').length,
  });
  db.prepare("UPDATE campaign_phases SET status = ?, completed_at = ?, summary = ? WHERE phase_id = ?")
    .run(phaseStatus, completedNow, phaseSummary, phase.phase_id);

  if (ws) ws.broadcast('phase:completed', { campaign_id: campaignId, phase_id: phase.phase_id, status: phaseStatus });

  return allSuccess;
}

// ── Main: Start campaign execution ──────────────────────────────────────
export async function startCampaign(db, campaignId, userSub) {
  console.log(`[CampaignEngine] Starting campaign ${campaignId}`);

  const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(campaignId);
  if (!campaign || campaign.status !== 'running') {
    console.error(`[CampaignEngine] Campaign ${campaignId} not in running state`);
    return;
  }

  // Get phases in order
  const phases = db.prepare(
    'SELECT * FROM campaign_phases WHERE campaign_id = ? ORDER BY order_index'
  ).all(campaignId);

  for (const phase of phases) {
    // Re-check campaign status (may have been paused/aborted)
    const current = db.prepare('SELECT status FROM campaigns WHERE campaign_id = ?').get(campaignId);
    if (current.status !== 'running') {
      console.log(`[CampaignEngine] Campaign ${campaignId} ${current.status}, stopping`);
      return;
    }

    // Skip already-skipped or completed phases
    if (phase.status === 'skipped' || phase.status === 'completed') continue;

    // Check if phase is enabled
    let phaseConfig = {};
    try { phaseConfig = JSON.parse(phase.config || '{}'); } catch {}
    if (phaseConfig.enabled === false) {
      db.prepare("UPDATE campaign_phases SET status = 'skipped', completed_at = datetime('now') WHERE phase_id = ?").run(phase.phase_id);
      const ws = getWsManager();
      if (ws) ws.broadcast('phase:skipped', { campaign_id: campaignId, phase_id: phase.phase_id });
      continue;
    }

    // Execute the phase
    const success = await executePhase(db, campaignId, phase, campaign.target);

    if (!success) {
      // Check auto_advance config
      if (!phaseConfig.auto_advance) {
        // Pause campaign on phase failure
        db.prepare("UPDATE campaigns SET status = 'paused', updated_at = datetime('now') WHERE campaign_id = ?").run(campaignId);
        const ws = getWsManager();
        if (ws) ws.broadcast('campaign:paused', { campaign_id: campaignId, reason: 'phase_failed' });
        return;
      }
      // auto_advance: continue to next phase even on failure
    }
  }

  // All phases done
  const now = new Date().toISOString();
  db.prepare("UPDATE campaigns SET status = 'completed', updated_at = ? WHERE campaign_id = ?").run(now, campaignId);

  const ws = getWsManager();
  if (ws) ws.broadcast('campaign:completed', { campaign_id: campaignId });

  console.log(`[CampaignEngine] Campaign ${campaignId} completed`);
}

// ── Pause campaign ──────────────────────────────────────────────────────
export function pauseCampaign(db, campaignId) {
  db.prepare("UPDATE campaigns SET status = 'paused', updated_at = datetime('now') WHERE campaign_id = ?").run(campaignId);
}

// ── Abort campaign ──────────────────────────────────────────────────────
export function abortCampaign(db, campaignId) {
  const now = new Date().toISOString();
  db.prepare("UPDATE campaigns SET status = 'aborted', updated_at = ? WHERE campaign_id = ?").run(now, campaignId);
  db.prepare("UPDATE campaign_phases SET status = 'failed', completed_at = ? WHERE campaign_id = ? AND status = 'running'").run(now, campaignId);
}
