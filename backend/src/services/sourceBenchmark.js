export function scoreSourceBenchmark(findings,cases) {
  const results=cases.map(item=>{
    const alerts=findings.filter(finding=>finding.file===item.file);
    const expected=item.expected_cwes || (item.cwe ? [item.cwe] : []);
    const localized=alerts.filter(finding=>{
      const actual=[...String(finding.cwe || '').matchAll(/\b(?:CWE-)?(\d+)\b/g)].map(match=>'CWE-'+match[1]);
      return Math.abs((finding.start_line ?? finding.line)-item.line)<=1 && (!expected.length || expected.some(cwe=>actual.includes(cwe)));
    });
    return {...item,alerts:alerts.length,localized_alerts:localized.length,detected:item.vulnerable?localized.length>0:alerts.length>0};
  });
  const tp=results.filter(item=>item.vulnerable && item.detected).length,fn=results.filter(item=>item.vulnerable && !item.detected).length;
  const fp=results.filter(item=>!item.vulnerable && item.detected).length,tn=results.filter(item=>!item.vulnerable && !item.detected).length;
  return {scope:'fixture_case_classification',true_positive:tp,false_negative:fn,false_positive:fp,true_negative:tn,
    precision:tp+fp ? tp/(tp+fp):null,recall:tp+fn ? tp/(tp+fn):null,
    localization_hits:results.filter(item=>item.vulnerable && item.localized_alerts>0).length,
    total_alerts:findings.length,cases:results};
}
