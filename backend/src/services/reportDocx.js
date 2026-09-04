/**
 * reportDocx.js — DOCX 报告生成服务
 * 使用 docx npm 包生成结构化 .docx 报告，可用 WPS/Word 打开编辑
 */
import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType,
  Header, Footer, PageNumber, PageBreak, ShadingType,
  VerticalAlign,
} from 'docx';
import { getDb } from '../db/connection.js';
import { computeGrade } from './gradingEngine.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.resolve(__dirname, '..', '..', '..', 'data', 'reports');

// ── 工具类别映射 ──────────────────────────────────────────────────────
const TOOL_CATEGORIES = {
  nmap: '侦察扫描', masscan: '侦察扫描', nuclei: '脆弱性扫描', nikto: '脆弱性扫描',
  sqlmap: '漏洞利用', hydra: '暴力破解', john: '密码破解', hashcat: '密码破解',
  metasploit: '漏洞利用', crackmapexec: '横向移动', smbclient: '横向移动',
  evilwinrm: '远程执行', wpscan: 'Web扫描', dirsearch: 'Web扫描', gobuster: 'Web扫描',
  responder: '网络攻击', mitm6: '网络攻击', ntlmrelayx: '网络攻击',
  ping: '连通性检测', curl: '连通性检测',
};

function toolCategory(toolId) {
  return TOOL_CATEGORIES[toolId] || '其他';
}

// ── 表格边框样式 ──────────────────────────────────────────────────────
const TABLE_BORDERS = {
  top: { style: BorderStyle.SINGLE, size: 1, color: '999999' },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: '999999' },
  left: { style: BorderStyle.SINGLE, size: 1, color: '999999' },
  right: { style: BorderStyle.SINGLE, size: 1, color: '999999' },
  insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
  insideVertical: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
};

// ── 辅助函数 ──────────────────────────────────────────────────────────
function cn(text, opts = {}) {
  return new TextRun({ text: String(text ?? ''), font: '宋体', size: 24, ...opts });
}

function cnBold(text, opts = {}) {
  return cn(text, { bold: true, ...opts });
}

function heading1(text) {
  return new Paragraph({
    children: [new TextRun({ text, font: '黑体', size: 32, bold: true })],
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 400, after: 200 },
  });
}

function heading2(text) {
  return new Paragraph({
    children: [new TextRun({ text, font: '黑体', size: 28, bold: true })],
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 300, after: 150 },
  });
}

function bodyPara(runs) {
  return new Paragraph({
    children: Array.isArray(runs) ? runs : [cn(runs)],
    spacing: { after: 80 },
  });
}

function labelValue(label, value) {
  return bodyPara([cnBold(`${label}：`), cn(value || 'N/A')]);
}

function makeCell(runs, opts = {}) {
  const children = Array.isArray(runs) ? runs : [cn(runs)];
  return new TableCell({
    children: [new Paragraph({ children, spacing: { before: 40, after: 40 } })],
    verticalAlign: VerticalAlign.CENTER,
    ...opts,
  });
}

function headerCell(text, width) {
  return new TableCell({
    children: [new Paragraph({
      children: [cnBold(text, { color: 'FFFFFF' })],
      spacing: { before: 40, after: 40 },
      alignment: AlignmentType.CENTER,
    })],
    shading: { type: ShadingType.SOLID, color: '2A5DAA' },
    verticalAlign: VerticalAlign.CENTER,
    width: width ? { size: width, type: WidthType.DXA } : undefined,
  });
}

// ── 主生成函数 ────────────────────────────────────────────────────────
export async function generateDocx(runId, options = {}) {
  const db = getDb();

  // 1. 查询执行记录
  const run = db.prepare(
    `SELECT run_id, playbook_id, target, status, engine_type, final_summary, created_at, updated_at
     FROM execution_runs WHERE run_id = ?`
  ).get(runId);
  if (!run) return { ok: false, error: 'Run not found' };

  // 2. 计算评分
  const grade = computeGrade(runId);

  // 3. 查询执行步骤
  const steps = db.prepare(
    `SELECT step_index, tool_id, args, success, exit_code, notes
     FROM execution_steps WHERE run_id = ? ORDER BY step_index`
  ).all(runId);

  // 4. 查询证据记录
  const evidence = db.prepare(
    `SELECT step_index, tool_id, evidence_type, evidence_data, mitre_hits, recommendations
     FROM evidence_records WHERE run_id = ? ORDER BY step_index`
  ).all(runId);

  // 5. 查询蓝队干预
  const interventions = db.prepare(
    `SELECT type, target, port, created_at
     FROM blue_team_interventions WHERE run_id = ?`
  ).all(runId);

  // 6. (candidate_mappings query removed — data not used in report)

  // 7. 查询 Playbook 信息
  let playbookName = null;
  if (run.playbook_id) {
    const pb = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    playbookName = pb?.name || run.playbook_id;
  }

  // 8. 构建报告章节
  const sections = [];

  // ── 封面 ─────────────────────────────────────────────────────────
  sections.push(
    new Paragraph({ spacing: { before: 3000 } }),
    new Paragraph({
      children: [new TextRun({ text: '渗透测试评估报告', font: '黑体', size: 52, bold: true, color: '1A3A6A' })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 200 },
    }),
    new Paragraph({
      children: [new TextRun({
        text: '基于红蓝实装对抗的智能化系统安全测试平台',
        font: '宋体', size: 28, color: '666666',
      })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 600 },
    }),
    new Paragraph({
      children: [cn('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', { color: '2A5DAA', size: 20 })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 600 },
    }),
    new Paragraph({
      children: [cnBold('测试目标：', { size: 28 }), cn(run.target || 'N/A', { size: 28 })],
      alignment: AlignmentType.CENTER, spacing: { after: 200 },
    }),
    new Paragraph({
      children: [cnBold('测试方案：', { size: 28 }), cn(playbookName || 'N/A', { size: 28 })],
      alignment: AlignmentType.CENTER, spacing: { after: 200 },
    }),
    new Paragraph({
      children: [cnBold('报告日期：', { size: 28 }), cn(new Date().toISOString().slice(0, 10), { size: 28 })],
      alignment: AlignmentType.CENTER, spacing: { after: 200 },
    }),
    new Paragraph({ children: [new PageBreak()] }),
  );

  // ── 一、测试概述 ──────────────────────────────────────────────────
  sections.push(heading1('一、测试概述'));
  sections.push(labelValue('运行 ID', run.run_id));
  sections.push(labelValue('测试目标', run.target));
  sections.push(labelValue('测试方案', playbookName || run.playbook_id));
  sections.push(labelValue('引擎类型', run.engine_type === 'react' ? 'ReAct 智能引擎' : '机械执行引擎'));
  sections.push(labelValue('运行状态', run.status === 'COMPLETED' ? '已完成' : run.status === 'FAILED' ? '失败' : run.status));
  sections.push(labelValue('开始时间', run.created_at));
  sections.push(labelValue('结束时间', run.updated_at));

  // ── 二、测试环境 ──────────────────────────────────────────────────
  const uniqueTools = [...new Set(steps.map(s => s.tool_id))];
  sections.push(heading1('二、测试环境'));
  sections.push(bodyPara(`本次测试共使用 ${uniqueTools.length} 个工具，执行 ${steps.length} 个步骤。`));

  if (uniqueTools.length > 0) {
    const toolRows = [
      new TableRow({
        children: [headerCell('序号', 800), headerCell('工具名称', 2500), headerCell('工具类别', 2500)],
        tableHeader: true,
      }),
      ...uniqueTools.map((t, i) => new TableRow({
        children: [
          makeCell(String(i + 1), { width: { size: 800, type: WidthType.DXA } }),
          makeCell(t, { width: { size: 2500, type: WidthType.DXA } }),
          makeCell(toolCategory(t), { width: { size: 2500, type: WidthType.DXA } }),
        ],
      })),
    ];
    sections.push(new Table({
      rows: toolRows, borders: TABLE_BORDERS, width: { size: 5800, type: WidthType.DXA },
    }));
  }

  // ── 三、测试结果总评 ──────────────────────────────────────────────
  sections.push(heading1('三、测试结果总评'));
  if (grade.ok) {
    sections.push(bodyPara([
      cnBold('总分：'), cn(`${grade.earned} / ${grade.total} 分`),
      cnBold('  得分率：'), cn(`${grade.percent}%`),
      cnBold('  等级：'), cn(grade.grade, { bold: true, size: 28, color: grade.grade === 'A' ? '228B22' : grade.grade === 'F' ? 'CC0000' : '333333' }),
    ]));
    sections.push(bodyPara([
      cnBold('步骤得分：'), cn(`${grade.stepScore.earned} / ${grade.stepScore.total} 分`),
    ]));
    sections.push(bodyPara([
      cnBold('MITRE 覆盖：'), cn(`${grade.mitre.covered} / ${grade.mitre.total} 项技术 (${grade.mitre.percent}%)  加分：+${grade.mitre.score} 分`),
    ]));
  } else {
    sections.push(bodyPara('评分数据不可用'));
  }

  // ── 四、MITRE ATT&CK 覆盖 ─────────────────────────────────────────
  sections.push(heading1('四、MITRE ATT&CK 技术覆盖'));
  if (grade.ok && grade.mitre.techniques.length > 0) {
    const mitreRows = [
      new TableRow({
        children: [headerCell('序号', 800), headerCell('技术 ID', 2000), headerCell('来源', 3000)],
        tableHeader: true,
      }),
      ...grade.mitre.techniques.map((t, i) => {
        const tid = typeof t === 'string' ? t : (t.id || '?');
        const tname = typeof t === 'string' ? '' : (t.name || '');
        return new TableRow({
          children: [
            makeCell(String(i + 1), { width: { size: 800, type: WidthType.DXA } }),
            makeCell(tid, { width: { size: 2000, type: WidthType.DXA } }),
            makeCell(tname || '证据命中', { width: { size: 3000, type: WidthType.DXA } }),
          ],
        });
      }),
    ];
    sections.push(new Table({
      rows: mitreRows, borders: TABLE_BORDERS, width: { size: 5800, type: WidthType.DXA },
    }));
  } else {
    sections.push(bodyPara('暂未检测到 MITRE ATT&CK 技术命中。'));
  }

  // ── 五、步骤执行明细 ──────────────────────────────────────────────
  sections.push(heading1('五、步骤执行明细'));
  if (steps.length > 0) {
    const stepRows = [
      new TableRow({
        children: [
          headerCell('步骤', 700), headerCell('工具', 1500), headerCell('参数', 2000),
          headerCell('结果', 800), headerCell('得分', 800),
        ],
        tableHeader: true,
      }),
      ...steps.map((s, i) => {
        const success = s.success === 1;
        const stepGrade = grade.ok && Array.isArray(grade.breakdown) ? grade.breakdown.find(b => b.stepIndex === s.step_index) : null;
        const earned = stepGrade ? `${stepGrade.earned}/${stepGrade.score}` : '-';
        return new TableRow({
          children: [
            makeCell(String(s.step_index + 1), { width: { size: 700, type: WidthType.DXA } }),
            makeCell(s.tool_id, { width: { size: 1500, type: WidthType.DXA } }),
            makeCell((s.args || '').slice(0, 80), { width: { size: 2000, type: WidthType.DXA } }),
            makeCell(success ? '成功' : '失败', {
              width: { size: 800, type: WidthType.DXA },
              shading: success
                ? { type: ShadingType.SOLID, color: 'E8F5E9' }
                : { type: ShadingType.SOLID, color: 'FFEBEE' },
            }),
            makeCell(earned, { width: { size: 800, type: WidthType.DXA } }),
          ],
        });
      }),
    ];
    sections.push(new Table({
      rows: stepRows, borders: TABLE_BORDERS, width: { size: 5800, type: WidthType.DXA },
    }));
  } else {
    sections.push(bodyPara('无执行步骤记录。'));
  }

  // ── 六、攻击证据 ──────────────────────────────────────────────────
  sections.push(heading1('六、攻击证据'));
  if (evidence.length > 0) {
    // 证据概要表
    const evRows = [
      new TableRow({
        children: [
          headerCell('步骤', 700), headerCell('工具', 1200), headerCell('类型', 1500),
          headerCell('MITRE 命中', 1400), headerCell('数据摘要', 1000),
        ],
        tableHeader: true,
      }),
      ...evidence.map(e => {
        let mitreHits = '';
        try { mitreHits = JSON.parse(e.mitre_hits || '[]').join(', '); } catch {}
        return new TableRow({
          children: [
            makeCell(String(e.step_index + 1), { width: { size: 700, type: WidthType.DXA } }),
            makeCell(e.tool_id, { width: { size: 1200, type: WidthType.DXA } }),
            makeCell(e.evidence_type, { width: { size: 1500, type: WidthType.DXA } }),
            makeCell(mitreHits.slice(0, 50), { width: { size: 1400, type: WidthType.DXA } }),
            makeCell((e.evidence_data || '').slice(0, 60), { width: { size: 1000, type: WidthType.DXA } }),
          ],
        });
      }),
    ];
    sections.push(new Table({
      rows: evRows, borders: TABLE_BORDERS, width: { size: 5800, type: WidthType.DXA },
    }));

    // 详细证据（前 10 条）
    const detailCount = Math.min(evidence.length, 10);
    for (let i = 0; i < detailCount; i++) {
      const e = evidence[i];
      sections.push(heading2(`证据 #${i + 1}（步骤 ${e.step_index + 1} · ${e.tool_id}）`));
      sections.push(labelValue('证据类型', e.evidence_type));
      if (e.evidence_data) {
        sections.push(bodyPara([cnBold('证据数据：')]));
        const dataPreview = e.evidence_data.slice(0, 1000);
        sections.push(new Paragraph({
          children: [cn(dataPreview, { size: 20 })],
          spacing: { after: 80 },
          indent: { left: 400 },
        }));
      }
      let mitreHits = '';
      try { mitreHits = JSON.parse(e.mitre_hits || '[]').join(', '); } catch {}
      if (mitreHits) sections.push(labelValue('MITRE 命中', mitreHits));
      let recs = '';
      try { recs = JSON.parse(e.recommendations || '[]').map(r => typeof r === 'string' ? r : r.title || '').filter(Boolean).join('；'); } catch {}
      if (recs) sections.push(labelValue('修复建议', recs));
    }
    if (evidence.length > 10) {
      sections.push(bodyPara(`（共 ${evidence.length} 条证据，仅展示前 10 条）`));
    }
  } else {
    sections.push(bodyPara('无攻击证据记录。'));
  }

  // ── 七、蓝队干预记录 ──────────────────────────────────────────────
  sections.push(heading1('七、蓝队干预记录'));
  if (interventions.length > 0) {
    const intRows = [
      new TableRow({
        children: [headerCell('序号', 800), headerCell('类型', 2000), headerCell('目标', 2000), headerCell('端口', 1000)],
        tableHeader: true,
      }),
      ...interventions.map((intv, i) => new TableRow({
        children: [
          makeCell(String(i + 1), { width: { size: 800, type: WidthType.DXA } }),
          makeCell(intv.type, { width: { size: 2000, type: WidthType.DXA } }),
          makeCell(intv.target, { width: { size: 2000, type: WidthType.DXA } }),
          makeCell(String(intv.port || '-'), { width: { size: 1000, type: WidthType.DXA } }),
        ],
      })),
    ];
    sections.push(new Table({
      rows: intRows, borders: TABLE_BORDERS, width: { size: 5800, type: WidthType.DXA },
    }));
  } else {
    sections.push(bodyPara('本次测试未触发蓝队防御干预。'));
  }

  // ── 八、风险评估与建议 ─────────────────────────────────────────────
  sections.push(heading1('八、风险评估与建议'));

  // 汇总所有修复建议
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
    sections.push(bodyPara(`基于攻击证据分析，共发现 ${allRecs.length} 条修复建议：`));
    const recRows = [
      new TableRow({
        children: [headerCell('序号', 800), headerCell('来源步骤', 1500), headerCell('来源工具', 1500), headerCell('建议', 2000)],
        tableHeader: true,
      }),
      ...allRecs.slice(0, 20).map((r, i) => new TableRow({
        children: [
          makeCell(String(i + 1), { width: { size: 800, type: WidthType.DXA } }),
          makeCell(String(r.step + 1), { width: { size: 1500, type: WidthType.DXA } }),
          makeCell(r.tool, { width: { size: 1500, type: WidthType.DXA } }),
          makeCell(r.title.slice(0, 80), { width: { size: 2000, type: WidthType.DXA } }),
        ],
      })),
    ];
    sections.push(new Table({
      rows: recRows, borders: TABLE_BORDERS, width: { size: 5800, type: WidthType.DXA },
    }));
  } else {
    sections.push(bodyPara('暂无自动生成的修复建议。'));
  }

  // 综合风险评级
  if (grade.ok) {
    const riskLevel = grade.percent >= 80 ? '高风险' : grade.percent >= 50 ? '中风险' : '低风险';
    const riskColor = grade.percent >= 80 ? 'CC0000' : grade.percent >= 50 ? 'FF8C00' : '228B22';
    sections.push(bodyPara([
      cnBold('综合风险评级：'), cn(riskLevel, { bold: true, size: 28, color: riskColor }),
    ]));
    sections.push(bodyPara(
      `目标系统 ${run.target} 在本次渗透测试中得分 ${grade.percent}%，` +
      `覆盖 ${grade.mitre.covered} 项 MITRE ATT&CK 技术。` +
      (grade.percent >= 80 ? '系统存在严重安全隐患，建议立即整改。' :
       grade.percent >= 50 ? '系统存在一定安全隐患，建议尽快修复。' :
       '系统安全状况较好，建议持续监测。')
    ));
  }

  // ── 签名栏 ────────────────────────────────────────────────────────
  sections.push(new Paragraph({ spacing: { before: 800 } }));
  sections.push(heading1('签名'));
  sections.push(bodyPara('被测试单位签名：________________________'));
  sections.push(bodyPara('测试人员签名：________________________'));
  sections.push(bodyPara(`日期：${new Date().toISOString().slice(0, 10)}`));

  // ── 构建 Document ──────────────────────────────────────────────────
  const doc = new Document({
    creator: 'RedTeam-Platform',
    title: `渗透测试评估报告 - ${run.target}`,
    description: '自动生成的渗透测试评估报告',
    styles: {
      default: {
        document: {
          run: { font: '宋体', size: 24 },  // 小四号 = 12pt = 24 half-pt
        },
        heading1: {
          run: { font: '黑体', size: 32, bold: true, color: '1A3A6A' },
        },
        heading2: {
          run: { font: '黑体', size: 28, bold: true, color: '333333' },
        },
      },
    },
    sections: [{
      properties: {
        page: {
          size: { width: 11906, height: 16838 },  // A4 (twips)
          margin: { top: 1440, bottom: 1440, left: 1800, right: 1800 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            children: [new TextRun({ text: '渗透测试评估报告', font: '宋体', size: 18, color: '999999' })],
            alignment: AlignmentType.RIGHT,
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            children: [
              new TextRun({ text: '第 ', font: '宋体', size: 18, color: '999999' }),
              new TextRun({ children: [PageNumber.CURRENT], font: '宋体', size: 18, color: '999999' }),
              new TextRun({ text: ' 页', font: '宋体', size: 18, color: '999999' }),
            ],
            alignment: AlignmentType.CENTER,
          })],
        }),
      },
      children: sections,
    }],
  });

  // ── 导出 ──────────────────────────────────────────────────────────
  const buffer = await Packer.toBuffer(doc);

  // 保存到文件
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const fileName = `report_${runId}.docx`;
  const filePath = path.join(REPORTS_DIR, fileName);
  fs.writeFileSync(filePath, buffer);

  return { ok: true, filePath, fileName, buffer };
}
