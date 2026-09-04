/**
 * reportTemplate.js — 模板化报告生成服务
 * 使用 carbone 库渲染 DOCX 模板
 */
import carbone from 'carbone';
import { getDb } from '../db/connection.js';
import { computeGrade } from './gradingEngine.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.resolve(__dirname, '..', '..', '..', 'data', 'reports');
const TEMPLATES_DIR = path.resolve(__dirname, '..', '..', '..', 'data', 'report-templates');
const DEFAULT_TEMPLATE = path.join(TEMPLATES_DIR, 'standard.docx');

/**
 * 收集报告数据（供模板填充使用）
 */
function collectReportData(runId) {
  const db = getDb();

  const run = db.prepare(
    `SELECT run_id, playbook_id, target, status, engine_type, final_summary, created_at, updated_at
     FROM execution_runs WHERE run_id = ?`
  ).get(runId);
  if (!run) return null;

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
    `SELECT type, target, port FROM blue_team_interventions WHERE run_id = ?`
  ).all(runId);

  let playbookName = null;
  if (run.playbook_id) {
    const pb = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    playbookName = pb?.name || run.playbook_id;
  }

  // Build flat data object for template
  const data = {
    title: `渗透测试评估报告 - ${run.target}`,
    target: run.target || 'N/A',
    playbook_name: playbookName || 'N/A',
    playbook_id: run.playbook_id || 'N/A',
    run_id: run.run_id,
    run_status: run.status === 'COMPLETED' ? '已完成' : run.status === 'FAILED' ? '失败' : run.status,
    engine_type: run.engine_type === 'react' ? 'ReAct 智能引擎' : '机械执行引擎',
    created_at: run.created_at,
    updated_at: run.updated_at,
    date: new Date().toISOString().slice(0, 10),

    // Score
    score_total: grade.ok ? grade.total : 0,
    score_earned: grade.ok ? grade.earned : 0,
    score_percent: grade.ok ? grade.percent : 0,
    grade: grade.ok ? grade.grade : 'N/A',
    step_score_total: grade.ok ? grade.stepScore.total : 0,
    step_score_earned: grade.ok ? grade.stepScore.earned : 0,

    // MITRE
    mitre_covered: grade.ok ? grade.mitre.covered : 0,
    mitre_total: grade.ok ? grade.mitre.total : 0,
    mitre_percent: grade.ok ? grade.mitre.percent : 0,
    mitre_score: grade.ok ? grade.mitre.score : 0,

    // Risk
    risk_level: grade.ok ? (grade.percent >= 80 ? '高风险' : grade.percent >= 50 ? '中风险' : '低风险') : 'N/A',

    // Arrays for table rendering
    steps: steps.map((s, i) => ({
      index: i + 1,
      tool_id: s.tool_id,
      args: (s.args || '').slice(0, 100),
      result: s.success === 1 ? '成功' : '失败',
      exit_code: s.exit_code,
      notes: (s.notes || '').slice(0, 200),
    })),

    evidence: evidence.map((e, i) => {
      let mitreHits = '';
      try { mitreHits = JSON.parse(e.mitre_hits || '[]').join(', '); } catch {}
      let recs = '';
      try { recs = JSON.parse(e.recommendations || '[]').map(r => typeof r === 'string' ? r : r.title || '').filter(Boolean).join('；'); } catch {}
      return {
        index: i + 1,
        tool_id: e.tool_id,
        type: e.evidence_type,
        data: (e.evidence_data || '').slice(0, 500),
        mitre_hits: mitreHits,
        recommendations: recs,
      };
    }),

    interventions: interventions.map((intv, i) => ({
      index: i + 1,
      type: intv.type,
      target: intv.target,
      port: intv.port || '-',
    })),

    mitre_techniques: grade.ok ? grade.mitre.techniques.map(t => ({
      id: typeof t === 'string' ? t : (t.id || '?'),
      name: typeof t === 'string' ? '' : (t.name || ''),
    })) : [],
  };

  return data;
}

/**
 * 使用模板生成 DOCX 报告
 * @param {string} runId - 执行记录 ID
 * @param {string} templatePath - 模板文件路径（可选，默认使用 standard.docx）
 * @returns {Promise<{ok: boolean, filePath?: string, buffer?: Buffer, error?: string}>}
 */
export async function generateDocxFromTemplate(runId, templatePath) {
  const data = collectReportData(runId);
  if (!data) return { ok: false, error: 'Run not found' };

  const tplPath = templatePath || DEFAULT_TEMPLATE;
  if (!fs.existsSync(tplPath)) {
    return { ok: false, error: `Template not found: ${tplPath}` };
  }

  return new Promise((resolve, reject) => {
    carbone.render(tplPath, data, { convertTo: 'docx' }, (err, result) => {
      if (err) {
        return resolve({ ok: false, error: err.message || String(err) });
      }

      const buffer = Buffer.from(result);
      fs.mkdirSync(REPORTS_DIR, { recursive: true });
      const fileName = `report_${runId}_tpl.docx`;
      const filePath = path.join(REPORTS_DIR, fileName);
      fs.writeFileSync(filePath, buffer);

      resolve({ ok: true, filePath, fileName, buffer });
    });
  });
}

/**
 * 列出可用模板
 */
export function listTemplates() {
  if (!fs.existsSync(TEMPLATES_DIR)) return [];
  return fs.readdirSync(TEMPLATES_DIR)
    .filter(f => f.endsWith('.docx') || f.endsWith('.xlsx'))
    .map(f => ({
      name: f,
      path: path.join(TEMPLATES_DIR, f),
      size: fs.statSync(path.join(TEMPLATES_DIR, f)).size,
    }));
}
