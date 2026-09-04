/**
 * reportHtml.js — HTML 报告生成服务
 * 生成带内联 CSS 的 HTML 报告，用于前端 QTextBrowser 预览
 */
import { getDb } from '../db/connection.js';
import { computeGrade } from './gradingEngine.js';

export function generateHtml(runId, options = {}) {
  const db = getDb();

  // 1. 查询数据
  const run = db.prepare(
    `SELECT run_id, playbook_id, target, status, engine_type, final_summary, created_at, updated_at
     FROM execution_runs WHERE run_id = ?`
  ).get(runId);
  if (!run) return { ok: false, error: 'Run not found' };

  const grade = computeGrade(runId);
  const steps = db.prepare(
    `SELECT step_index, tool_id, args, success, exit_code, notes
     FROM execution_steps WHERE run_id = ? ORDER BY step_index`
  ).all(runId);
  const evidence = db.prepare(
    `SELECT step_index, tool_id, evidence_type, evidence_data, mitre_hits, recommendations
     FROM evidence_records WHERE run_id = ? ORDER BY step_index`
  ).all(runId);
  const interventions = db.prepare(
    `SELECT type, target, port, created_at
     FROM blue_team_interventions WHERE run_id = ?`
  ).all(runId);

  let playbookName = null;
  if (run.playbook_id) {
    const pb = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    playbookName = pb?.name || run.playbook_id;
  }

  // 2. 构建 HTML
  const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const css = `
    body { font-family: 'SimSun', '宋体', serif; font-size: 14px; color: #333; margin: 40px; line-height: 1.8; }
    h1 { font-family: 'SimHei', '黑体', sans-serif; font-size: 22px; color: #1a3a6a; border-bottom: 2px solid #2a5daa; padding-bottom: 6px; margin-top: 30px; }
    h2 { font-family: 'SimHei', '黑体', sans-serif; font-size: 18px; color: #333; margin-top: 20px; }
    .cover { text-align: center; margin: 60px 0; }
    .cover h1 { font-size: 32px; border: none; color: #1a3a6a; }
    .cover .subtitle { font-size: 16px; color: #666; margin: 10px 0 30px; }
    .cover .meta { font-size: 16px; margin: 8px 0; }
    table { border-collapse: collapse; width: 100%; margin: 10px 0 20px; }
    th { background: #2a5daa; color: #fff; font-weight: bold; padding: 8px 12px; text-align: left; font-size: 13px; }
    td { border: 1px solid #ddd; padding: 6px 12px; font-size: 13px; }
    tr:nth-child(even) td { background: #f5f7fa; }
    .success { color: #228b22; font-weight: bold; }
    .fail { color: #cc0000; font-weight: bold; }
    .grade { font-size: 24px; font-weight: bold; }
    .grade-a { color: #228b22; } .grade-b { color: #2a5daa; } .grade-c { color: #ff8c00; } .grade-d { color: #cc6600; } .grade-f { color: #cc0000; }
    .mitre-badge { display: inline-block; background: #8b45a6; color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin: 2px 4px; }
    .progress-bar { background: #e0e0e0; height: 20px; border-radius: 4px; overflow: hidden; margin: 10px 0; }
    .progress-fill { height: 100%; background: #2a5daa; }
    .label { font-weight: bold; }
    .indent { margin-left: 20px; }
    .signature { margin-top: 60px; }
    .evidence-detail { background: #f5f7fa; padding: 10px; margin: 8px 0; border-left: 3px solid #2a5daa; }
  `;

  let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${css}</style></head><body>`;

  // 封面
  html += `<div class="cover">
    <h1>渗透测试评估报告</h1>
    <div class="subtitle">基于红蓝实装对抗的智能化系统安全测试平台</div>
    <hr style="border:1px solid #2a5daa;width:60%">
    <div class="meta"><span class="label">测试目标：</span>${esc(run.target)}</div>
    <div class="meta"><span class="label">测试方案：</span>${esc(playbookName)}</div>
    <div class="meta"><span class="label">报告日期：</span>${new Date().toISOString().slice(0, 10)}</div>
  </div>`;

  // 一、测试概述
  html += `<h1>一、测试概述</h1>
    <p><span class="label">运行 ID：</span>${esc(run.run_id)}</p>
    <p><span class="label">测试目标：</span>${esc(run.target)}</p>
    <p><span class="label">测试方案：</span>${esc(playbookName || run.playbook_id)}</p>
    <p><span class="label">引擎类型：</span>${esc(run.engine_type === 'react' ? 'ReAct 智能引擎' : '机械执行引擎')}</p>
    <p><span class="label">运行状态：</span>${esc(run.status === 'COMPLETED' ? '已完成' : run.status === 'FAILED' ? '失败' : run.status)}</p>
    <p><span class="label">开始时间：</span>${esc(run.created_at)}</p>`;

  // 二、测试环境
  const uniqueTools = [...new Set(steps.map(s => s.tool_id))];
  const TOOL_CATS = {
    nmap: '侦察扫描', masscan: '侦察扫描', nuclei: '脆弱性扫描', nikto: '脆弱性扫描',
    sqlmap: '漏洞利用', hydra: '暴力破解', john: '密码破解', hashcat: '密码破解',
    metasploit: '漏洞利用', crackmapexec: '横向移动', smbclient: '横向移动',
    evilwinrm: '远程执行', wpscan: 'Web扫描', dirsearch: 'Web扫描', gobuster: 'Web扫描',
    responder: '网络攻击', mitm6: '网络攻击', ntlmrelayx: '网络攻击',
    ping: '连通性检测', curl: '连通性检测',
  };
  html += `<h1>二、测试环境</h1>
    <p>本次测试共使用 ${uniqueTools.length} 个工具，执行 ${steps.length} 个步骤。</p>`;
  if (uniqueTools.length > 0) {
    html += `<table><tr><th>序号</th><th>工具名称</th><th>工具类别</th></tr>`;
    uniqueTools.forEach((t, i) => {
      const cat = TOOL_CATS[t] || '其他';
      html += `<tr><td>${i + 1}</td><td>${esc(t)}</td><td>${esc(cat)}</td></tr>`;
    });
    html += `</table>`;
  }

  // 三、测试结果总评
  html += `<h1>三、测试结果总评</h1>`;
  if (grade.ok) {
    const gradeClass = grade.grade ? `grade-${grade.grade.toLowerCase()}` : '';
    html += `<div class="progress-bar"><div class="progress-fill" style="width:${grade.percent}%"></div></div>
      <p><span class="label">总分：</span>${grade.earned} / ${grade.total} 分 &nbsp;&nbsp;
         <span class="label">得分率：</span>${grade.percent}% &nbsp;&nbsp;
         <span class="label">等级：</span><span class="grade ${gradeClass}">${esc(grade.grade)}</span></p>
      <p><span class="label">步骤得分：</span>${grade.stepScore.earned} / ${grade.stepScore.total} 分</p>
      <p><span class="label">MITRE 覆盖：</span>${grade.mitre.covered} / ${grade.mitre.total} 项技术 (${grade.mitre.percent}%) &nbsp; 加分：+${grade.mitre.score} 分</p>`;
  } else {
    html += `<p>评分数据不可用</p>`;
  }

  // 四、MITRE ATT&CK
  html += `<h1>四、MITRE ATT&CK 技术覆盖</h1>`;
  if (grade.ok && grade.mitre.techniques.length > 0) {
    html += `<p>`;
    grade.mitre.techniques.forEach(t => {
      html += `<span class="mitre-badge">${esc(typeof t === 'string' ? t : t.id || '?')}</span>`;
    });
    html += `</p>`;
  } else {
    html += `<p>暂未检测到 MITRE ATT&CK 技术命中。</p>`;
  }

  // 五、步骤执行明细
  html += `<h1>五、步骤执行明细</h1>`;
  if (steps.length > 0) {
    html += `<table><tr><th>步骤</th><th>工具</th><th>参数</th><th>结果</th><th>得分</th></tr>`;
    steps.forEach(s => {
      const success = s.success === 1;
      const sg = grade.ok ? grade.breakdown.find(b => b.stepIndex === s.step_index) : null;
      const earned = sg ? `${sg.earned}/${sg.score}` : '-';
      html += `<tr>
        <td>${s.step_index + 1}</td>
        <td>${esc(s.tool_id)}</td>
        <td>${esc((s.args || '').slice(0, 80))}</td>
        <td class="${success ? 'success' : 'fail'}">${success ? '成功' : '失败'}</td>
        <td>${earned}</td>
      </tr>`;
    });
    html += `</table>`;
  }

  // 六、攻击证据
  html += `<h1>六、攻击证据</h1>`;
  if (evidence.length > 0) {
    html += `<table><tr><th>步骤</th><th>工具</th><th>类型</th><th>MITRE 命中</th></tr>`;
    evidence.forEach(e => {
      let hits = '';
      try { hits = JSON.parse(e.mitre_hits || '[]').join(', '); } catch {}
      html += `<tr><td>${e.step_index + 1}</td><td>${esc(e.tool_id)}</td><td>${esc(e.evidence_type)}</td><td>${esc(hits.slice(0, 60))}</td></tr>`;
    });
    html += `</table>`;

    const detailCount = Math.min(evidence.length, 10);
    for (let i = 0; i < detailCount; i++) {
      const e = evidence[i];
      html += `<h2>证据 #${i + 1}（步骤 ${e.step_index + 1} · ${esc(e.tool_id)}）</h2>`;
      html += `<div class="evidence-detail">
        <p><span class="label">类型：</span>${esc(e.evidence_type)}</p>`;
      if (e.evidence_data) {
        html += `<p><span class="label">数据：</span></p><pre class="indent">${esc(e.evidence_data.slice(0, 2000))}</pre>`;
      }
      let recs = '';
      try { recs = JSON.parse(e.recommendations || '[]').map(r => typeof r === 'string' ? r : r.title || '').filter(Boolean).join('；'); } catch {}
      if (recs) html += `<p><span class="label">建议：</span>${esc(recs)}</p>`;
      html += `</div>`;
    }
    if (evidence.length > 10) html += `<p>（共 ${evidence.length} 条证据，仅展示前 10 条）</p>`;
  } else {
    html += `<p>无攻击证据记录。</p>`;
  }

  // 七、蓝队干预
  html += `<h1>七、蓝队干预记录</h1>`;
  if (interventions.length > 0) {
    html += `<table><tr><th>类型</th><th>目标</th><th>端口</th></tr>`;
    interventions.forEach(intv => {
      html += `<tr><td>${esc(intv.type)}</td><td>${esc(intv.target)}</td><td>${intv.port || '-'}</td></tr>`;
    });
    html += `</table>`;
  } else {
    html += `<p>本次测试未触发蓝队防御干预。</p>`;
  }

  // 八、风险评估
  html += `<h1>八、风险评估与建议</h1>`;
  const allRecs = [];
  for (const e of evidence) {
    try {
      const recs = JSON.parse(e.recommendations || '[]');
      for (const r of recs) {
        const title = typeof r === 'string' ? r : r.title || '';
        if (title) allRecs.push({ step: e.step_index, tool: e.tool_id, title });
      }
    } catch {}
  }
  if (allRecs.length > 0) {
    html += `<p>基于攻击证据分析，共发现 ${allRecs.length} 条修复建议：</p><ol>`;
    allRecs.slice(0, 20).forEach(r => {
      html += `<li>[步骤${r.step + 1}/${esc(r.tool)}] ${esc(r.title)}</li>`;
    });
    html += `</ol>`;
  } else {
    html += `<p>暂无自动生成的修复建议。</p>`;
  }
  if (grade.ok) {
    const riskLevel = grade.percent >= 80 ? '高风险' : grade.percent >= 50 ? '中风险' : '低风险';
    const riskColor = grade.percent >= 80 ? '#cc0000' : grade.percent >= 50 ? '#ff8c00' : '#228b22';
    html += `<p><span class="label">综合风险评级：</span><span style="color:${riskColor};font-weight:bold;font-size:18px">${esc(riskLevel)}</span></p>`;
  }

  // 签名
  html += `<div class="signature">
    <h1>签名</h1>
    <p>被测试单位签名：________________________</p>
    <p>测试人员签名：________________________</p>
    <p>日期：${new Date().toISOString().slice(0, 10)}</p>
  </div>`;

  html += `</body></html>`;

  return { ok: true, html };
}
