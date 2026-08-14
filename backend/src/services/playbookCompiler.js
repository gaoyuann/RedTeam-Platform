/**
 * PlaybookCompiler - Compiles raw playbook steps into executable plans
 * Ported from RedTeam-Edu: backend/src/runtime/playbookCompiler.js
 * With full Payloader support: payload_id resolution, template rendering, context injection
 */

import { IMAGE_MAP, VIRTUAL_TOOLS } from '../tools/toolRunner.js';
import { buildKGContextForStep } from './knowledgeEnricher.js';
import {
  getPayloadById,
  extractPayloadData,
  buildPayloadContext,
} from './payloadLoader.js';

/**
 * Compile a playbook for execution.
 * Checks: toolspec existence, payload resolution, template variable resolution, target compatibility.
 *
 * @param {object} params
 * @param {Array} params.steps - playbook steps from DB
 * @param {string} params.target - execution target
 * @param {object} params.db - better-sqlite3 Database
 * @returns {{ ok: boolean, compiledSteps: Array, warnings: Array, errors: Array }}
 */
export function compilePlaybook({ steps, target, db }) {
  const compiledSteps = [];
  const warnings = [];
  const errors = [];

  if (!steps || !Array.isArray(steps)) {
    return { ok: false, compiledSteps: [], warnings, errors: ['No steps provided'] };
  }

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const compiled = {
      ...step,
      compile_status: 'READY',
      compile_reason: null,
      resolved_args: [],
      payload_id: step.payload_id || null,
      payload_data: null,
      payload_context: null,
    };

    // 1. Toolspec existence check
    if (!IMAGE_MAP[step.tool_id]) {
      if (!VIRTUAL_TOOLS.has(step.tool_id)) {
        compiled.compile_status = 'BLOCKED_MISSING_TOOLSPEC';
        compiled.compile_reason = `Tool '${step.tool_id}' not found in IMAGE_MAP`;
        errors.push(compiled.compile_reason);
      } else {
        warnings.push(`Tool '${step.tool_id}' is virtual — may require HTTP handler`);
      }
    }

    // 2. Payloader 载荷解析 (在模板渲染之前)
    if (step.payload_id && !compiled.compile_status.startsWith('BLOCKED')) {
      const payload = getPayloadById(step.payload_id, db);

      if (!payload) {
        compiled.compile_status = 'BLOCKED_PAYLOAD_NOT_FOUND';
        compiled.compile_reason = `payload_id '${step.payload_id}' not found in payloader data`;
        errors.push(compiled.compile_reason);
      } else {
        // 提取结构化载荷数据
        compiled.payload_data = extractPayloadData(payload);

        // 构建载荷上下文（用于 LLM 注入和前端展示）
        compiled.payload_context = buildPayloadContext(payload, compiled.payload_data);

        // 用载荷的 primary command 增强 args_template
        const primaryContent = compiled.payload_data.primary_content;
        if (primaryContent && !step.args_template) {
          // 如果步骤没有 args_template，用载荷的 primary command 作为模板
          try {
            compiled.resolved_args = JSON.parse(JSON.stringify(primaryContent.split('\n')[0].split(' ').filter(Boolean)));
          } catch {
            compiled.resolved_args = [];
          }
        }

        warnings.push(`Step '${step.name || i}' enriched with payload '${step.payload_id}'`);
      }
    }

    // 3. Template variable check - look for unresolved {{var}} patterns
    if (!compiled.compile_status.startsWith('BLOCKED')) {
      const argsStr = step.args_template || '';
      const unresolvedVars = argsStr.match(/\{\{[^}]+\}\}/g);
      if (unresolvedVars) {
        // Variables resolved at runtime by commandTemplateRenderer + targetAdapters
        const RUNTIME_RESOLVABLE = new Set([
          'host', 'port', 'base_url', 'target_url', 'login_url',
          'dvwa_login_url', 'sqli_url', 'dvwa_sqli_url', 'dvwa_cookie',
          'wordlist_small', 'wordlist_small_users', 'wordlist_small_passwords',
          'nuclei_template_dir', 'evidence_dir', 'domain', 'scheme',
          'target_class', 'username', 'password', 'smb_port',
          'winrm_port', 'aws_region', 'aws_profile', 's3_bucket',
          'ad_domain',
        ]);
        // Filter out <target>, runtime-resolvable {{var}}, and cross-step evidence refs ({{stepN_...}})
        // which will be resolved at execution time
        const realUnresolved = unresolvedVars.filter(v => {
          if (v === '<target>' || v.startsWith('{{target')) return false;
          const varName = v.replace(/\{\{|\}\}/g, '');
          if (RUNTIME_RESOLVABLE.has(varName)) return false;
          // Cross-step evidence references: {{stepN_name.evidence.data.xxx}}
          if (/^step\d+_/.test(varName)) return false;
          return true;
        });
        if (realUnresolved.length > 0) {
          // If payload_variables are provided, they may resolve some vars
          let payloadVars = {};
          try {
            payloadVars = step.payload_variables ? (typeof step.payload_variables === 'string' ? JSON.parse(step.payload_variables) : step.payload_variables) : {};
          } catch { /* malformed JSON — treat as empty */ }
          const stillUnresolved = realUnresolved.filter(v => {
            const varName = v.replace(/\{\{|\}\}/g, '');
            return !(varName in payloadVars);
          });
          if (stillUnresolved.length > 0) {
            compiled.compile_status = 'BLOCKED_TEMPLATE_UNRESOLVED';
            compiled.compile_reason = `Unresolved template variables: ${stillUnresolved.join(', ')}`;
            errors.push(compiled.compile_reason);
          } else {
            warnings.push(`Step '${step.name || i}' template vars resolved via payload_variables`);
          }
        } else {
          warnings.push(`Step '${step.name || i}' has <target> placeholder — will be resolved at runtime`);
        }
      }
    }

    // 4. Replace <target> placeholder in args (skip if payload already set resolved_args)
    if (!compiled.compile_status.startsWith('BLOCKED') && !(step.payload_id && compiled.resolved_args.length > 0)) {
      let args = [];
      try {
        args = JSON.parse(step.args_template || '[]');
      } catch {
        args = [];
      }
      // Merge payload_variables into rendering context
      let payloadVars = {};
      try {
        payloadVars = step.payload_variables ? (typeof step.payload_variables === 'string' ? JSON.parse(step.payload_variables) : step.payload_variables) : {};
      } catch { /* ignore parse errors */ }

      args = args.map(a => {
        if (typeof a !== 'string') return a;
        let result = a.replace(/<target>/g, target || '');
        // Replace payload_variables in template (escape key for regex safety)
        for (const [key, value] of Object.entries(payloadVars)) {
          const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          result = result.replace(new RegExp(`\\{\\{${escapedKey}\\}\\}`, 'g'), value);
        }
        return result;
      });
      compiled.resolved_args = args;
    }

    // 5. Build KG context for the step
    try {
      const kgContext = buildKGContextForStep(step.tool_id);
      if (kgContext) {
        compiled.kg_context = kgContext;
      }
    } catch {
      // Non-fatal
    }

    compiledSteps.push(compiled);
  }

  const ok = errors.length === 0;
  const totalSteps = compiledSteps.length;
  const blockedSteps = compiledSteps.filter(s => s.compile_status.startsWith('BLOCKED')).length;
  const payloadEnriched = compiledSteps.filter(s => s.payload_id && s.payload_data).length;

  if (blockedSteps > 0) {
    warnings.push(`${blockedSteps} of ${totalSteps} steps are blocked and will not execute`);
  }
  if (payloadEnriched > 0) {
    warnings.push(`${payloadEnriched} steps enriched with payload data`);
  }

  return { ok, compiledSteps, warnings, errors };
}

/**
 * Quick helper to check if a compiled step is safe to run.
 */
export function isStepRunnable(compiledStep) {
  return compiledStep && compiledStep.compile_status === 'READY';
}

/**
 * Get non-blocked (runnable) steps from a compilation result.
 */
export function getRunnableSteps(compiledSteps) {
  return compiledSteps.filter(s => s.compile_status === 'READY');
}
