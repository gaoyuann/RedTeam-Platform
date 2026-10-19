// Providers sometimes wrap a concrete response in the output schema requested by
// the prompt. Recognize that one unambiguous envelope, then run the normal plan
// validation; never search arbitrary nested objects for executable instructions.
export function parseVerificationGeneration(response) {
  if (typeof response !== 'string' || response.length > 65536) throw new Error('模型方案内容为空或超过长度限制');
  let plan = JSON.parse(response.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, ''));
  if (plan && typeof plan === 'object' && !Array.isArray(plan) && plan.schema
      && !Object.hasOwn(plan, 'steps') && !Object.hasOwn(plan, 'missing_conditions')
      && Object.keys(plan).every(key => ['type', 'schema'].includes(key))) {
    const candidate = plan.schema;
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)
        && (Object.hasOwn(candidate, 'steps') || Object.hasOwn(candidate, 'missing_conditions'))) plan = candidate;
  }
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) throw new Error('方案格式无效');
  return plan;
}
