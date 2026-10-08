import { renderCommand } from './commandTemplateRenderer.js';

export function parseVariableContract(value) {
  const parsed = typeof value === 'string' ? JSON.parse(value || '[]') : value || [];
  if (!Array.isArray(parsed) || parsed.some(name => typeof name !== 'string' || !/^[a-z_]+$/.test(name))) {
    throw new Error('Variable contracts must be arrays of variable names');
  }
  return parsed;
}

function argsForStep(step) {
  const args = typeof step.args_template === 'string' ? JSON.parse(step.args_template || '[]') : step.args_template || [];
  if (!Array.isArray(args) || args.some(arg => typeof arg !== 'string')) throw new Error('Argument template must be an array of strings');
  return args;
}

export function isContextControlledVariable(name, context) {
  return ['dvwa_cookie', 'auth_cookie', 'dvwa_session_verified'].includes(name) ||
    Object.hasOwn(context, name) && ['host', 'port', 'scheme', 'domain', 'target_class', 'base_url', 'target_url',
      'login_url', 'dvwa_login_url', 'sqli_url', 'dvwa_sqli_url', 'api_base_url', 'graphql_endpoint',
      'auth_endpoint', 'admin_url', 'signup_url', 'reset_password_url', 'swagger_url', 'openapi_url'].includes(name);
}

function contextForStep(step, context) {
  const payload = typeof step.payload_variables === 'string' ? JSON.parse(step.payload_variables || '{}') : step.payload_variables || {};
  const values = Object.fromEntries(Object.entries(payload).filter(([name]) => !isContextControlledVariable(name, context)));
  return { ...context, ...values };
}

export function getStepInputs(step, context = {}) {
  const referenced = argsForStep(step).flatMap(arg => [...arg.matchAll(/\{\{([^}]+)\}\}/g)].map(match => match[1]));
  const implicit = context.target_class === 'dvwa' && step.tool_id === 'sqlmap' ? ['dvwa_cookie'] : [];
  return [...new Set([...parseVariableContract(step.input_variables), ...referenced, ...implicit])];
}

export function getStepOutputs(step) {
  return parseVariableContract(step.output_variables);
}

export function isUsableVariable(value) {
  return value !== undefined && value !== null && String(value).trim() !== '' &&
    !/\b(?:placeholder|CHANGE_ME|REPLACE_ME)\b|dvwa_sess/i.test(String(value));
}

export function isDvwaSessionProducer(step, context) {
  if (context.target_class !== 'dvwa' || step.tool_id !== 'curl') return false;
  try {
    const args = renderCommand(argsForStep(step), contextForStep(step, context)).rendered;
    return args.includes(context.login_url) && args.some(arg => /username=/.test(arg)) &&
      args.some(arg => ['--data', '-d', '--data-raw'].includes(arg));
  } catch { return false; }
}

export function validateVariablePlan(steps, context) {
  const produced = new Set();
  const issues = [];
  const deferred = [];
  for (const step of steps) {
    try {
      const values = contextForStep(step, context);
      if (isDvwaSessionProducer(step, context)) {
        produced.delete('dvwa_cookie');
        produced.delete('auth_cookie');
      }
      for (const name of getStepInputs(step, context)) {
        if (!/^[a-z_]+$/.test(name)) issues.push(`{{${name}}} (step ${step.step_index}): invalid variable name`);
        else if (!isUsableVariable(values[name]) || context.target_class === 'dvwa' && ['dvwa_cookie', 'auth_cookie'].includes(name) && !context.dvwa_session_verified) {
          if (produced.has(name)) deferred.push({ variable: name, step_index: step.step_index });
          else issues.push(`{{${name}}} (step ${step.step_index}): no value or preceding producer`);
        }
      }
      const outputs = getStepOutputs(step);
      if (outputs.length && (!isDvwaSessionProducer(step, context) || outputs.some(name => !['dvwa_cookie', 'auth_cookie'].includes(name)))) {
        issues.push(`step ${step.step_index}: unsupported variable producer`);
      } else for (const name of outputs) produced.add(name);
    } catch (error) { issues.push(`step ${step.step_index}: ${error.message}`); }
  }
  return { passed: issues.length === 0, issues, deferred };
}

export function validateStepVariables(step, context) {
  try {
    const values = contextForStep(step, context);
    const missing = getStepInputs(step, context).filter(name => !isUsableVariable(values[name]) ||
      context.target_class === 'dvwa' && ['dvwa_cookie', 'auth_cookie'].includes(name) && !context.dvwa_session_verified);
    return missing.length ? `Runtime dependencies unavailable: ${missing.join(', ')}` : null;
  } catch (error) { return error.message; }
}
