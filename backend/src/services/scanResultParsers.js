import { ordinaryHttpMethods } from './scanResultCatalog.js';
import { parseCppcheck, parseFlawfinder } from './sourceToolParsers.js';
import { parseNmapResults } from './nmapTopology.js';
const SCAN_TOOL_MAP = {port_scan:'nmap',topology_scan:'nmap',vuln_scan:'nuclei',auth_audit:'nuclei',web_scan_nikto:'nikto',web_scan_sqlmap:'sqlmap',api_fuzz_ffuf:'ffuf',api_fuzz_arjun:'arjun'};
// ── Simple result parsers per scan type ────────────────────────────────
function legacyParseResults(scanType, stdout) {
  const results = [];
  const lines = stdout.split('\n').filter(l => l.trim());

  switch (scanType) {
    case 'port_scan':
    case 'topology_scan':
      results.push(...parseNmapResults(stdout, { assumedUp: scanType === 'port_scan' }));
      break;

    case 'vuln_scan': {
      // Parse nuclei v3 output: [template-id] [protocol] [severity] URL [extra]
      // Strip ANSI escape codes as safety net
      const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
      // nuclei v3 -no-color format: [template-id] [protocol] [severity] URL [extra]
      const nucleiV3 = /^\[([^\]]+)\]\s+\[(\w+)\]\s+\[(\w+)\]\s+(.+)/;
      // nuclei v2 legacy format: [severity] [template-id] detail
      const nucleiV2 = /^\[(\w+)\]\s+\[([^\]]+)\]\s+(.+)/;
      for (const line of lines) {
        const clean = stripAnsi(line);
        let match = clean.match(nucleiV3);
        if (match) {
          // [template-id] [protocol] [severity] detail
          const templateId = match[1];
          const protocol = match[2];
          const sev = match[3].toLowerCase();
          const detail = match[4];
          if (!['info','inf','low','medium','high','critical','unknown'].includes(sev)) continue;
          results.push({
            result_type: 'vulnerability',
            result_data: { template: templateId, protocol, detail },
            severity: sev,
            source_tool: 'nuclei',
          });
        } else {
          // Try legacy format: [severity] [template-id] detail
          match = clean.match(nucleiV2);
          if (match) {
            const sev = match[1].toLowerCase();
            if (!['info','inf','low','medium','high','critical','unknown'].includes(sev)) continue;
            results.push({
              result_type: 'vulnerability',
              result_data: { template: match[2], detail: match[3] },
              severity: sev,
              source_tool: 'nuclei',
            });
          }
        }
      }
      break;
    }

    case 'web_scan_nikto': {
      // Parse nikto text output:
      //   + OSVDB-3268: /config/: Directory indexing found.
      //   + /config/: Configuration information may be available remotely.
      //   + The anti-clickjacking X-Frame-Options header is not present.
      // Skip: lines starting with "-", "-----", "Nikto v", "Target", "Start", "End", "requests"
      const osvdbLine = /^\+\s+(OSVDB-\d+):\s+(\S+)\s+(.+)/;   // + OSVDB-XXX: /path/: finding
      const pathLine  = /^\+\s+(\/\S+):\s+(.+)/;                 // + /path: finding
      const infoLine  = /^\+\s+(The\s+.+|Cookie\s+.+|Allowed\s+.+|Server\s+.+)/i;  // + The X-Frame...

      for (const line of lines) {
        // Skip header/footer lines
        if (line.startsWith('-') || line.startsWith('---') || line.includes('Nikto v') ||
            line.includes('Target IP') || line.includes('Start Time') || line.includes('End Time') ||
            line.includes('requests:') || line.includes('host(s) tested') ||
            line.includes('submit this') || line.includes('CIRT.net')) continue;

        let osvdbId = '', path = '', finding = '';

        // Pattern 1: + OSVDB-XXXX: /path/: finding
        const m1 = line.match(osvdbLine);
        if (m1) {
          osvdbId = m1[1];
          path = m1[2];
          finding = m1[3].trim();
        } else {
          // Pattern 2: + /path: finding
          const m2 = line.match(pathLine);
          if (m2) {
            path = m2[1];
            finding = m2[2].trim();
          } else {
            // Pattern 3: + The X-Frame... / + Cookie ... / + Allowed ...
            const m3 = line.match(infoLine);
            if (m3) {
              finding = m3[1].trim();
            } else {
              continue; // skip unrecognized lines
            }
          }
        }

        if (!finding) continue;

        // Determine severity from finding content
        let sev = 'low';
        const fl = finding.toLowerCase();
        if (fl.includes('admin') || fl.includes('login') || fl.includes('config')) sev = 'medium';
        if (fl.includes('x-frame') || fl.includes('x-xss') || fl.includes('x-content-type')) sev = 'medium';
        if (fl.includes('httponly') || fl.includes('directory indexing') || fl.includes('default file')) sev = 'medium';
        if (fl.includes('sql') || fl.includes('inject') || fl.includes('exec') || fl.includes('vulnerable')) sev = 'high';
        if (fl.includes('leak') || fl.includes('expos')) sev = 'medium';

        const informational=ordinaryHttpMethods({result_type:'web_vuln',source_tool:'nikto',result_data:{finding}});
        results.push({
          result_type: informational ? 'information' : 'web_vuln',
          result_data: { finding, ...(path && { path }), ...(osvdbId && { osvdb_id: osvdbId }) },
          severity: informational ? 'info' : sev,
          source_tool: 'nikto',
        });
      }
      break;
    }

    case 'web_scan_sqlmap': {
      // Enhanced sqlmap output parsing
      // Pattern 1: "is vulnerable"
      if (stdout.includes('is vulnerable')) {
        // Try to extract more detail
        let param = '', technique = '', dbms = '';
        const paramMatch = stdout.match(/Parameter:\s*(\S+)/i);
        if (paramMatch) param = paramMatch[1];
        const techMatch = stdout.match(/Type:\s*(.+)/i);
        if (techMatch) technique = techMatch[1].trim();
        const dbmsMatch = stdout.match(/back-end DBMS:\s*(.+)/i);
        if (dbmsMatch) dbms = dbmsMatch[1].trim();

        results.push({
          result_type: 'sql_injection',
          result_data: {
            detail: 'Target is vulnerable to SQL injection',
            ...(param && { parameter: param }),
            ...(technique && { technique }),
            ...(dbms && { dbms }),
          },
          severity: 'critical',
          source_tool: 'sqlmap',
        });
      }
      // Pattern 2: "Parameter: X appears to be injectable"
      const injectablePattern = /Parameter:\s*'([^']+)'.*appears to be ('[^']+' )?injectable/gi;
      let injectMatch;
      while ((injectMatch = injectablePattern.exec(stdout)) !== null) {
        const param = injectMatch[1];
        // Avoid duplicate if already captured by "is vulnerable"
        if (!results.some(r => r.result_data?.parameter === param)) {
          results.push({
            result_type: 'sql_injection',
            result_data: { detail: `Parameter '${param}' is injectable`, parameter: param },
            severity: 'critical',
            source_tool: 'sqlmap',
          });
        }
      }
      break;
    }

    case 'brute_force': {
      // Parse hydra output:
      //   [80][http-post-form] host: 172.17.0.2   login: admin   password: password
      //   [22][ssh] host: 192.168.1.1   login: root   password: toor
      const hydraLine = /\[(\d+)\]\[([^\]]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)/;
      for (const line of lines) {
        const match = line.match(hydraLine);
        if (match) {
          const [, port, service, host, login, password] = match;
          results.push({
            result_type: 'credential',
            result_data: { login, password, host, port: Number(port), service },
            severity: 'critical',
            source_tool: 'hydra',
          });
        }
      }
      break;
    }

    case 'ad_scan': {
      // Parse netexec SMB output
      // Patterns:
      //   [+] 192.168.1.10    445    HOSTNAME   Windows Server 2019 ...
      //   SMB    192.168.1.10    445    HOSTNAME   ...
      const netexecLine = /(?:\[?\+?\]?\s*)?(\S+)\s+(\d+)\s+(\S+)\s+(.+)/;
      for (const line of lines) {
        const match = line.match(netexecLine);
        if (match && (line.startsWith('[+]') || !line.startsWith('['))) {
          const [, host, portStr, hostname, detail] = match;
          if (host && portStr && hostname) {
            results.push({
              result_type: 'service_info',
              result_data: { host, port: Number(portStr), hostname, os: detail.trim() },
              severity: 'medium',
              source_tool: 'netexec',
            });
          }
        }
      }
      break;
    }

    case 'cloud_scan': {
      // Parse cloudmapper audit output (may be JSON or text)
      try {
        const auditResults = JSON.parse(stdout);
        const findings = Array.isArray(auditResults) ? auditResults : (auditResults.findings || []);
        for (const finding of findings) {
          results.push({
            result_type: 'misconfiguration',
            result_data: { ...finding },
            severity: finding.severity || 'medium',
            source_tool: 'cloudmapper',
          });
        }
      } catch {
        // Unknown cloud text, including tool failures, is evidence rather than a vulnerability.
      }
      break;
    }

    // ── Application target scan type parsers ─────────────────────────

    case 'app_discovery_whatweb': {
      // Parse whatweb output: "URL [Title] ..."
      // Lines: "http://host.domain.com [200 OK] Apache[2.4.41], PHP[7.4], HTML5"
      const whatwebLine = /^(\S+)\s+(.+)$/;
      for (const line of lines) {
        const match = line.match(whatwebLine);
        if (!match) continue;
        const [, url, techStr] = match;
        const status = techStr.match(/^\[(\d{3})(?:\s[^\]]*)?\]/);
        if (!/^https?:\/\//i.test(url) || !status) continue;
        // Extract individual technologies: "Apache[2.4.41]" or just "PHP"
        const techs = [];
        const techPattern = /([A-Za-z0-9_/.-]+)(?:\[([^\]]*)\])?/g;
        let techMatch;
        while ((techMatch = techPattern.exec(techStr.slice(status[0].length))) !== null) {
          const name = techMatch[1].trim();
          const version = techMatch[2] || '';
          if (name && name !== url) {
            techs.push({ name, version });
          }
        }
        if (techs.length > 0) {
          results.push({
            result_type: 'technology_detection',
            result_data: { url, status_code: Number(status[1]), technologies: techs, raw: techStr },
            severity: 'info',
            source_tool: 'whatweb',
          });
        }
      }
      break;
    }

    case 'app_discovery_httpx': {
      // Parse httpx output:
      // "http://host.domain.com [200] [Page Title] [Apache/PHP]"
      // or JSON output if -json flag used
      for (const line of lines) {
        // Try JSON first
        try {
          const json = JSON.parse(line);
          if (json.url) {
            results.push({
              result_type: 'http_probe',
              result_data: {
                url: json.url,
                status_code: json.status_code || json['status-code'],
                title: json.title,
                technologies: json.tech || json.technologies,
                content_length: json.content_length || json['content-length'],
                webserver: json.webserver,
              },
              severity: 'info',
              source_tool: 'httpx',
            });
          }
          continue;
        } catch { /* not JSON, try text parsing */ }

        // Text format: URL [status] [title] [technologies]
        const textMatch = line.match(/^(\S+)\s+\[(\d+)\]\s+\[([^\]]*)\]\s+\[([^\]]*)\]/);
        if (textMatch) {
          const [, url, statusCode, title, technologies] = textMatch;
          results.push({
            result_type: 'http_probe',
            result_data: { url, status_code: parseInt(statusCode), title, technologies: technologies || '' },
            severity: 'info',
            source_tool: 'httpx',
          });
        }
      }
      break;
    }

    case 'api_fuzz_arjun': {
      // Parse arjun output for discovered parameters
      // arjun shows: [+] Parameter: id found in URL query
      //              [+] Parameter: token found in POST body
      const paramPattern = /\[\+\]\s*Parameter:\s*(\S+)\s+found\s+in\s+(.+)/i;
      for (const line of lines) {
        const match = line.match(paramPattern);
        if (match) {
          const [, paramName, location] = match;
          results.push({
            result_type: 'api_parameter',
            result_data: { parameter: paramName, location: location.trim() },
            severity: 'low',
            source_tool: 'arjun',
          });
        }
      }
      break;
    }

    case 'api_fuzz_ffuf': {
      // Parse ffuf JSON output lines (when using -json flag)
      // Otherwise parse text lines: "200 123 http://host/api/FUZZ"
      for (const line of lines) {
        // Try JSON format first
        try {
          const json = JSON.parse(line);
          if (json.url) {
            results.push({
              result_type: 'api_endpoint',
              result_data: {
                url: json.url,
                status_code: json.status || json.status_code,
                length: json.length || json.content_length,
                words: json.words,
              },
              severity: 'info',
              source_tool: 'ffuf',
            });
          }
          continue;
        } catch { /* not JSON */ }

        // Text format: status_code size url
        const textMatch = line.match(/^(\d+)\s+(\d+)\s+(\S+)/);
        if (textMatch) {
          const [, statusCode, size, url] = textMatch;
          results.push({
            result_type: 'api_endpoint',
            result_data: { url, status_code: parseInt(statusCode), length: parseInt(size) },
            severity: 'info',
            source_tool: 'ffuf',
          });
        }
      }
      break;
    }

    case 'auth_audit': {
      // Parse nuclei auth template output (same JSON-lines format as vuln_scan)
      for (const line of lines) {
        try {
          const finding = JSON.parse(line);
          if (finding.type === 'finding' || finding.templateID) {
            results.push({
              result_type: 'auth_finding',
              result_data: {
                template_id: finding.templateID || finding.template_id || '',
                template_name: finding.info?.name || finding.name || '',
                severity: finding.info?.severity || finding.severity || 'info',
                host: finding.host || finding.matched || '',
                type: finding.type || '',
                extracted: finding.extracted || finding.matcher_name || '',
              },
              severity: finding.info?.severity || finding.severity || 'info',
              source_tool: 'nuclei',
            });
          }
        } catch {
          // Non-JSON line — try text format: "[template] http://host"
          const textMatch = line.match(/\[([^\]]+)\]\s+(https?:\/\/\S+)/);
          if (textMatch) {
            results.push({
              result_type: 'auth_finding',
              result_data: { template: textMatch[1], host: textMatch[2] },
              severity: 'info',
              source_tool: 'nuclei',
            });
          }
        }
      }
      break;
    }

    case 'source_scan_cppcheck':
      results.push(...parseCppcheck(stdout));
      break;
    case 'source_scan_flawfinder':
      results.push(...parseFlawfinder(stdout));
      break;
  }

  if (results.length === 0 && stdout.length > 0) {
    results.push({
      result_type: 'raw_output',
      result_data: { output: stdout },
      severity: 'info',
      source_tool: SCAN_TOOL_MAP[scanType] || 'unknown',
    });
  }

  return results;
}


export function parseResults(scanType, output = '') {
  if (['vuln_scan','auth_audit'].includes(scanType)) {
    const records=[];
    for (const raw of output.split(/\r?\n/)) {
      const line=raw.replace(/\x1b\[[0-9;]*m/g,'').trim();
      let json; try { json=JSON.parse(line); } catch {}
      const template=json?.['template-id'] || json?.templateID || json?.template_id;
      if (template) {
        records.push({result_type:scanType==='auth_audit'?'auth_finding':'vulnerability',source_tool:'nuclei',
          severity:json.info?.severity || json.severity || 'unknown',result_data:{...json,template,matched_at:json['matched-at'] || json.matched || json.host || null}});
        continue;
      }
      const parsed=legacyParseResults('vuln_scan',line).filter(r=>r.result_type!=='raw_output');
      records.push(...parsed.map(row=>({...row,result_type:scanType==='auth_audit'?'auth_finding':row.result_type,
        result_data:{...row.result_data,matched_at:row.result_data.detail?.match(/^https?:\/\/\S+/)?.[0] || null}})));
    }
    return records.length?records:output.trim()?[{result_type:'raw_output',result_data:{output},severity:'info',source_tool:'nuclei'}]:[];
  }
  if (scanType==='web_scan_sqlmap') {
    // Match each parameter report independently; a Type alone is not a finding.
    const parts=output.split(/^Parameter:\s*/m).slice(1);
    const records=parts.flatMap(part=>{
      const parameter=part.split(/\r?\n/)[0].trim();
      const types=[...part.matchAll(/^\s*Type:\s*(.+)\r?\n\s*Title:\s*(.+)/gm)];
      return types.map(m=>({result_type:'sql_injection',source_tool:'sqlmap',severity:'critical',
        result_data:{parameter,technique:m[1].trim(),title:m[2].trim()}}));
    });
    if(records.length) return records;
  }
  if(scanType==='api_fuzz_arjun') {
    const found=output.match(/Parameters? found:\s*([^\n]+)/i);
    if(found) return found[1].split(/[,\s]+/).filter(Boolean).map(parameter=>({result_type:'api_parameter',severity:'info',source_tool:'arjun',result_data:{parameter}}));
  }
  return legacyParseResults(scanType,output);
}

const isToolProgressLine = line => /^(?:\s*$|[-=]{3,}|Nikto v|Starting Nmap|\[INF\]|\[WRN\])/.test(line);

// Diagnostics never pretend that log lines are tool-reported vulnerabilities.
export function parseScanOutput(scanType, stdout='', stderr='') {
  const records=parseResults(scanType,stdout).filter(r=>r.result_type!=='raw_output');
  const lines=stdout.split(/\r?\n/).filter(l=>l.trim());
  const lineTypes=new Set(['vuln_scan','auth_audit','web_scan_nikto','app_discovery_httpx','app_discovery_whatweb','api_fuzz_arjun','api_fuzz_ffuf','brute_force','ad_scan']);
  let unparsed=null, ignored=null;
  if(lineTypes.has(scanType)) {
    unparsed=0;ignored=0;
    for(const line of lines) {
      if(parseResults(scanType,line).some(r=>r.result_type!=='raw_output')) continue;
      if (isToolProgressLine(line)) ignored++;
      else unparsed++;
    }
  }
  if(stdout || stderr) records.push({result_type:'scan_evidence',source_tool:SCAN_TOOL_MAP[scanType] || null,severity:'info',
    result_data:{stdout,stderr,output:stdout,parser_version:1,unparsed_lines:unparsed,
      note:'工具输出证据；未识别内容不视为漏洞，日志行数不是发现数'}});
  return {records,diagnostics:{parser_version:1,tool_reported_count:null,output_lines:lines.length,
    parsed_records:records.filter(r=>r.result_type!=='scan_evidence').length,unparsed_lines:unparsed,
    ignored_lines:ignored,ignored_reason:ignored?'recognized tool banners/progress':null,merged_records:0}};
}

// Receives every observed byte before the runner's evidence buffer is capped.
// Line formats are parsed incrementally; multiline formats retain their complete
// observed stream until the runner terminates on its existing output limit.
export function createScanOutputCollector(scanType) {
  const decoder={stdout:new TextDecoder(),stderr:new TextDecoder()};
  const lineMode=new Set(['vuln_scan','auth_audit','web_scan_nikto','app_discovery_httpx','app_discovery_whatweb','api_fuzz_arjun','api_fuzz_ffuf','brute_force','ad_scan']).has(scanType);
  const chunks={stdout:[],stderr:[]};
  let observed=false,pending='',bytes=0,truncated=false,lines=0,unparsed=0,ignored=0;
  const streamed=[];
  const accept=line=>{
    if(!line.trim()) return;
    lines++;
    const rows=parseResults(scanType,line).filter(r=>r.result_type!=='raw_output');
    if(!rows.length) { if(isToolProgressLine(line)) ignored++; else unparsed++; }
    streamed.push(...rows);
  };
  return {
    push(data, channel='stdout') {
      observed=true;
      const text=decoder[channel].decode(data,{stream:true});
      if(lineMode && channel==='stdout') {
        const parts=(pending+text).split('\n'); pending=parts.pop();
        for(const line of parts) accept(line);
      }
      // Bounded raw evidence for line formats; recognized records are retained independently.
      const remaining=Math.max(0,2*1024*1024-bytes);
      chunks[channel].push(lineMode?text.slice(0,remaining):text);
      bytes+=text.length; if(bytes>2*1024*1024) truncated=true;
    },
    finish(result) {
      if(!observed) return parseScanOutput(scanType,result.stdout || '',result.stderr || '');
      for(const channel of ['stdout','stderr']) {
        const tail=decoder[channel].decode(); chunks[channel].push(tail);
        if(channel==='stdout') pending+=tail;
      }
      const parsed=parseScanOutput(scanType,chunks.stdout.join(''),chunks.stderr.join(''));
      if(lineMode) {
        if(pending) accept(pending);
        parsed.records=[...streamed,...parsed.records.filter(r=>r.result_type==='scan_evidence')];
        parsed.diagnostics={...parsed.diagnostics,parsed_records:streamed.length,output_lines:lines,unparsed_lines:unparsed,ignored_lines:ignored,ignored_reason:ignored?'recognized tool banners/progress':null};
      }
      parsed.diagnostics.evidence_truncated=truncated;
      return parsed;
    },
  };
}
