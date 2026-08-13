/**
 * Evidence Serializer for ReAct Engine
 *
 * Converts in-memory evidence history and remaining plan into text
 * suitable for inclusion in LLM prompts.
 *
 * Ported from RedTeam-Edu: backend/src/utils/evidenceSerializer.js
 */

const MAX_EVIDENCE_LENGTH = 6000;  // Total cap for evidence text
const MAX_STEP_OUTPUT = 300;       // Truncate per-step output

/**
 * Serialize evidence history into ReAct prompt text.
 *
 * @param {Array<{stepIndex, toolId, success, output, evidence}>} history
 * @returns {string}
 */
export function serializeEvidenceHistory(history) {
  if (!history || history.length === 0) {
    return '(无历史证据)';
  }

  const lines = [];
  let totalLen = 0;

  for (const entry of history) {
    const idx = entry.stepIndex ?? '?';
    const tool = entry.toolId || '?';
    const status = entry.success ? '✅' : '❌';

    let output = '';
    if (entry.output) {
      output = typeof entry.output === 'string'
        ? entry.output
        : JSON.stringify(entry.output);
      // Take only first line or first MAX_STEP_OUTPUT chars
      const firstLine = output.split('\n')[0] || '';
      output = firstLine.length > MAX_STEP_OUTPUT
        ? firstLine.slice(0, MAX_STEP_OUTPUT) + '…'
        : firstLine;
    }

    let evidenceStr = '';
    if (entry.evidence) {
      evidenceStr = typeof entry.evidence === 'string'
        ? entry.evidence
        : JSON.stringify(entry.evidence);
      if (evidenceStr.length > MAX_STEP_OUTPUT) {
        evidenceStr = evidenceStr.slice(0, MAX_STEP_OUTPUT) + '…';
      }
    }

    let line = `步骤${idx} [${tool}] ${status}`;
    if (output) line += `: ${output}`;
    if (evidenceStr && evidenceStr !== output) line += ` | 证据: ${evidenceStr}`;

    if (totalLen + line.length > MAX_EVIDENCE_LENGTH) {
      lines.push('…(更早的证据已截断)');
      break;
    }

    lines.push(line);
    totalLen += line.length;
  }

  return lines.join('\n');
}

/**
 * Serialize remaining plan steps into ReAct prompt text.
 *
 * @param {Array<{step_index, step_id, name, tool_id, args_template}>} steps
 * @returns {string}
 */
export function serializeCurrentPlan(steps) {
  if (!steps || steps.length === 0) {
    return '(无剩余步骤)';
  }

  const lines = [];
  for (const step of steps) {
    const idx = step.step_index ?? '?';
    const tool = step.tool_id || '?';
    const name = step.name || step.step_id || '';

    let argsStr = '';
    try {
      const args = JSON.parse(step.args_template || '[]');
      if (Array.isArray(args) && args.length > 0) {
        argsStr = ' ' + args.join(' ');
        if (argsStr.length > 80) argsStr = argsStr.slice(0, 80) + '…';
      }
    } catch {}

    lines.push(`步骤${idx} [${tool}] ${name}${argsStr}`);
  }

  return lines.join('\n');
}
