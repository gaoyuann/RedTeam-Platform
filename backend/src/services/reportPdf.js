/**
 * reportPdf.js — PDF 报告生成服务
 * 从 RedTeam-Edu 的 grading.js 移植，适配 SQLite 数据源
 * 使用 pdf-lib + Noto Sans CJK 中文字体
 */
import { getDb } from '../db/connection.js';
import { computeGrade } from './gradingEngine.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.resolve(__dirname, '..', '..', '..', 'data', 'reports');
const FONT_PATH = path.resolve(__dirname, '..', '..', 'assets', 'fonts', 'NotoSansSC-Regular.ttf');

export async function generatePdf(runId, options = {}) {
  const { PDFDocument, rgb, StandardFonts } = await import('pdf-lib');
  const fontkit = (await import('@pdf-lib/fontkit')).default;

  const db = getDb();

  // 1. 查询数据
  const run = db.prepare(
    `SELECT run_id, playbook_id, target, status, engine_type, final_summary, created_at
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

  // 2. 创建 PDF
  const pdfDoc = await PDFDocument.create();
  pdfDoc.registerFontkit(fontkit);

  // 嵌入中文字体
  let cnFont;
  let fontFallback = false;
  try {
    const fontBytes = fs.readFileSync(FONT_PATH);
    cnFont = await pdfDoc.embedFont(fontBytes, { subset: false });
  } catch (e) {
    console.warn('[reportPdf] 中文字体加载失败，回退到 Helvetica（中文将显示为 ?）:', e.message);
    cnFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
    fontFallback = true;
  }

  // 添加第一页
  let page = pdfDoc.addPage([595, 842]); // A4
  let { width, height } = page.getSize();
  let y = height - 50;

  // ── 辅助函数 ──────────────────────────────────────────────────────
  const drawText = (text, x, yPos, size = 11, fontObj = cnFont, color = rgb(0, 0, 0)) => {
    const safe = String(text);
    // Estimate max chars: CJK chars are ~2x wider than ASCII.
    // Use a conservative average width factor of 0.8 to handle mixed content.
    const maxLen = Math.max(4, Math.floor((width - x - 50) / (size * 0.8)));
    const truncated = safe.length > maxLen ? safe.slice(0, maxLen - 3) + '...' : safe;
    try {
      page.drawText(truncated, { x, y: yPos, size, font: fontObj, color });
    } catch {
      const ascii = truncated.replace(/[^\x00-\x7F]/g, '?');
      page.drawText(ascii, { x, y: yPos, size, font: fontObj, color });
    }
  };

  const drawLine = (yPos) => {
    page.drawLine({
      start: { x: 50, y: yPos }, end: { x: width - 50, y: yPos },
      thickness: 0.5, color: rgb(0.7, 0.7, 0.7),
    });
  };

  const ensureSpace = (needed = 80) => {
    if (y < needed) {
      page = pdfDoc.addPage([595, 842]);
      ({ width, height } = page.getSize());
      y = height - 50;
    }
  };

  // ── 标题 ──────────────────────────────────────────────────────────
  drawText('渗透测试评估报告', 50, y, 22, cnFont, rgb(0.1, 0.2, 0.5));
  y -= 8; drawLine(y); y -= 25;

  drawText('基于红蓝实装对抗的智能化系统安全测试平台', 50, y, 12, cnFont, rgb(0.4, 0.4, 0.4));
  y -= 8; drawLine(y); y -= 25;

  if (fontFallback) {
    drawText('[警告] 中文字体加载失败，中文内容可能无法正常显示。请检查字体文件。', 50, y, 10, cnFont, rgb(0.8, 0.1, 0.1));
    y -= 18;
  }

  // ── 运行信息 ──────────────────────────────────────────────────────
  drawText('一、测试概述', 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
  const infoRows = [
    ['运行 ID', run.run_id],
    ['目标', run.target || 'N/A'],
    ['Playbook', playbookName || run.playbook_id || 'N/A'],
    ['引擎', run.engine_type === 'react' ? 'ReAct 智能引擎' : '机械执行引擎'],
    ['开始时间', run.created_at || 'N/A'],
    ['状态', run.status === 'COMPLETED' ? '已完成' : run.status === 'FAILED' ? '失败' : run.status],
  ];
  for (const [label, value] of infoRows) {
    drawText(`${label}:`, 60, y, 11, cnFont);
    drawText(value, 200, y, 11, cnFont);
    y -= 18;
  }
  y -= 10; drawLine(y); y -= 20;

  // ── 评估概要 ──────────────────────────────────────────────────────
  const CN_NUM = ['一', '二', '三', '四', '五', '六', '七', '八', '九'];
  let sectionIdx = 1; // 一 is already used for 测试概述

  if (grade.ok) {
    sectionIdx++;
    drawText(`${CN_NUM[sectionIdx - 1]}、测试结果总评`, 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;

    // 进度条
    const barWidth = 300;
    const filledWidth = Math.round((grade.percent / 100) * barWidth);
    page.drawRectangle({ x: 60, y: y - 4, width: barWidth, height: 12, color: rgb(0.9, 0.9, 0.9) });
    page.drawRectangle({ x: 60, y: y - 4, width: filledWidth, height: 12, color: rgb(0.2, 0.5, 0.9) });
    drawText(`${grade.percent}%`, 60 + barWidth + 8, y, 11, cnFont, rgb(0.2, 0.5, 0.9));
    y -= 22;

    const scoreRows = [
      ['总分', `${grade.total} 分`],
      ['得分', `${grade.earned} 分 (${grade.percent}%)`],
      ['等级', grade.grade],
      ['MITRE 覆盖率', `${grade.mitre.percent}% (${grade.mitre.covered} / ${grade.mitre.total} 项技术)`],
      ['MITRE 加分', `+${grade.mitre.score} 分 (满分 20)`],
    ];
    for (const [label, value] of scoreRows) {
      drawText(`${label}:`, 60, y, 11, cnFont);
      drawText(value, 200, y, 11, cnFont);
      y -= 18;
    }
    y -= 10; drawLine(y); y -= 20;

    // ── MITRE 技术覆盖 ──────────────────────────────────────────────
    sectionIdx++;
    drawText(`${CN_NUM[sectionIdx - 1]}、MITRE ATT&CK 技术覆盖`, 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
    if (grade.mitre.techniques.length === 0) {
      drawText('暂未检测到 MITRE 技术命中。', 60, y, 11, cnFont, rgb(0.5, 0.5, 0.5)); y -= 18;
    } else {
      for (const t of grade.mitre.techniques) {
        ensureSpace(25);
        const tid = typeof t === 'string' ? t : (t.id || '?');
        const tname = typeof t === 'string' ? '' : (t.name || '');
        page.drawRectangle({ x: 58, y: y - 3, width: 80, height: 14, color: rgb(0.55, 0.27, 0.68) });
        drawText(tid, 62, y, 10, cnFont, rgb(1, 1, 1));
        if (tname) drawText(tname, 148, y, 11, cnFont);
        y -= 20;
      }
    }
    y -= 10; drawLine(y); y -= 20;
  }

  // ── 步骤得分明细 ──────────────────────────────────────────────────
  sectionIdx++;
  drawText(`${CN_NUM[sectionIdx - 1]}、步骤执行明细`, 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
  for (let i = 0; i < steps.length; i++) {
    ensureSpace(40);
    const s = steps[i];
    const success = s.success === 1;
    const statusColor = success ? rgb(0.1, 0.6, 0.1) : rgb(0.8, 0.1, 0.1);
    const stepGrade = grade.ok ? grade.breakdown.find(b => b.stepIndex === s.step_index) : null;

    drawText(`步骤 ${i + 1}: ${s.tool_id}`, 60, y, 11, cnFont);
    const statusText = success ? '通过' : '失败';
    const scoreText = stepGrade ? ` ${stepGrade.earned}/${stepGrade.score}分` : '';
    drawText(`[${statusText}]${scoreText}`, 300, y, 11, cnFont, statusColor);
    y -= 16;

    if (s.args) {
      drawText(`参数: ${(s.args || '').slice(0, 80)}`, 80, y, 9, cnFont, rgb(0.5, 0.5, 0.5));
      y -= 14;
    }
    y -= 6;
  }
  y -= 10; drawLine(y); y -= 20;

  // ── 证据记录 ──────────────────────────────────────────────────────
  if (evidence.length > 0) {
    ensureSpace(60);
    sectionIdx++;
    drawText(`${CN_NUM[sectionIdx - 1]}、攻击证据`, 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
    const showCount = Math.min(evidence.length, 10);
    for (let i = 0; i < showCount; i++) {
      ensureSpace(40);
      const e = evidence[i];
      drawText(`[${e.evidence_type}] 工具: ${e.tool_id}  步骤: ${e.step_index + 1}`, 60, y, 10, cnFont);
      y -= 16;
      if (e.mitre_hits) {
        let hits = '';
        try { hits = JSON.parse(e.mitre_hits).join(', '); } catch {}
        if (hits) { drawText(`MITRE: ${hits.slice(0, 80)}`, 80, y, 9, cnFont, rgb(0.4, 0.2, 0.6)); y -= 14; }
      }
      y -= 6;
    }
    if (evidence.length > 10) {
      drawText(`（共 ${evidence.length} 条，仅展示前 10 条）`, 60, y, 10, cnFont, rgb(0.5, 0.5, 0.5));
      y -= 18;
    }
    y -= 10; drawLine(y); y -= 20;
  }

  // ── 蓝队干预记录 ──────────────────────────────────────────────────
  ensureSpace(60);
  sectionIdx++;
  drawText(`${CN_NUM[sectionIdx - 1]}、蓝队干预记录`, 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
  if (interventions.length > 0) {
    for (const intv of interventions) {
      ensureSpace(25);
      drawText(`[${intv.type}] 目标: ${intv.target}  端口: ${intv.port || '-'}`, 60, y, 11, cnFont);
      y -= 18;
    }
  } else {
    drawText('本次测试未触发蓝队防御干预。', 60, y, 11, cnFont, rgb(0.5, 0.5, 0.5)); y -= 18;
  }
  y -= 10; drawLine(y); y -= 20;

  // ── 风险评估与建议 ────────────────────────────────────────────────
  ensureSpace(60);
  sectionIdx++;
  drawText(`${CN_NUM[sectionIdx - 1]}、风险评估与建议`, 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
  const allRecs = [];
  for (const e of evidence) {
    try {
      const recs = JSON.parse(e.recommendations || '[]');
      for (const r of recs) {
        const title = typeof r === 'string' ? r : r.title || '';
        if (title) allRecs.push(title);
      }
    } catch {}
  }
  if (allRecs.length > 0) {
    for (let i = 0; i < Math.min(allRecs.length, 10); i++) {
      ensureSpace(25);
      drawText(`${i + 1}. ${allRecs[i].slice(0, 80)}`, 60, y, 11, cnFont);
      y -= 18;
    }
    if (allRecs.length > 10) {
      drawText(`（共 ${allRecs.length} 条，仅展示前 10 条）`, 60, y, 10, cnFont, rgb(0.5, 0.5, 0.5)); y -= 18;
    }
  } else {
    drawText('暂无自动生成的修复建议。', 60, y, 11, cnFont, rgb(0.5, 0.5, 0.5)); y -= 18;
  }
  if (grade.ok) {
    ensureSpace(25);
    const riskLevel = grade.percent >= 80 ? '高风险' : grade.percent >= 50 ? '中风险' : '低风险';
    drawText(`综合风险评级: ${riskLevel}`, 60, y, 12, cnFont, rgb(0.8, 0.1, 0.1)); y -= 18;
  }
  y -= 10; drawLine(y); y -= 20;

  // ── 签名 ──────────────────────────────────────────────────────────
  ensureSpace(80);
  drawText('签名', 50, y, 14, cnFont, rgb(0.1, 0.2, 0.5)); y -= 22;
  drawText('被测试单位签名: ________________________', 60, y, 11, cnFont); y -= 20;
  drawText('测试人员签名: ________________________', 60, y, 11, cnFont); y -= 20;
  drawText(`日期: ${new Date().toISOString().slice(0, 10)}`, 60, y, 11, cnFont);

  // ── 导出 ──────────────────────────────────────────────────────────
  const pdfBytes = await pdfDoc.save();
  const buffer = Buffer.from(pdfBytes);

  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const fileName = `report_${runId}.pdf`;
  const filePath = path.join(REPORTS_DIR, fileName);
  fs.writeFileSync(filePath, buffer);

  return { ok: true, filePath, fileName, buffer };
}
