export const SCAN_BUDGET_DEFAULTS=Object.freeze({decisions:24,checks:16,pages:60,tools:24,sql_checks:5,model_ms:30000,tool_ms:120000,duration_ms:600000});
export class ScanBudgetExceeded extends Error {constructor(dimension){super('扫描预算耗尽：'+dimension);this.dimension=dimension;this.code='SCAN_BUDGET_EXHAUSTED';}}
export function createScanBudget(overrides={},clock=Date.now){
 const limits={...SCAN_BUDGET_DEFAULTS,...overrides};
 for(const [key,value] of Object.entries(limits))if(!Number.isSafeInteger(value)||value<0)throw Error('无效扫描预算：'+key);
 const started=clock(),used={decisions:0,checks:0,pages:0,tools:0,sql_checks:0};let exhausted=null;
 const ensure=()=>{if(clock()-started>=limits.duration_ms){exhausted='duration_ms';throw new ScanBudgetExceeded(exhausted);}};
 const consumeMany=keys=>{
  ensure();const costs={};for(const key of keys){if(!(key in used))throw Error('未知预算维度');costs[key]=(costs[key]||0)+1;}
  for(const [key,cost] of Object.entries(costs))if(used[key]+cost>limits[key]){exhausted=key;throw new ScanBudgetExceeded(key);}
  for(const [key,cost] of Object.entries(costs))used[key]+=cost;
 };
 return {limits,consume:key=>consumeMany([key]),consumeMany,
 timeout(key){ensure();return Math.max(1,Math.min(limits[key],limits.duration_ms-(clock()-started)));},
 snapshot(){if(clock()-started>=limits.duration_ms)exhausted='duration_ms';return {limits:{...limits},used:{...used},remaining:Object.fromEntries(Object.keys(used).map(k=>[k,Math.max(0,limits[k]-used[k])])),exhausted,elapsed_ms:Math.max(0,clock()-started)};}};
}

export function remainingScanBudget(budget,local) {
 const remaining=budget?.snapshot().remaining;
 return Object.fromEntries(Object.entries(local).map(([key,value])=>[key,Math.max(0,Math.min(value,remaining?.[key]??value))]));
}
