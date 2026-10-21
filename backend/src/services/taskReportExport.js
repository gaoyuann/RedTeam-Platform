import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { buildTaskAttackReport, taskAttackReportHtml, TASK_ATTACK_REPORT_TITLE } from './taskAttackReport.js';

export const MAX_TASK_REPORT_EXPORT_BYTES = 16 * 1024 * 1024;
const FONT_PATH = fileURLToPath(new URL('../../assets/fonts/NotoSansSC-Regular.ttf', import.meta.url));
const TYPES = {
  json: 'application/json; charset=utf-8', html: 'text/html; charset=utf-8',
  pdf: 'application/pdf', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
};
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const value = (item, fallback = '未记录') => item === undefined || item === null || item === '' ? fallback
  : typeof item === 'object' ? JSON.stringify(item, null, 2) : String(item);

function assertSnapshot(document) {
  if (document?.report?.kind !== 'trace_snapshot' || ![1, 2].includes(document.report.content?.schema_version)
      || !document.report.content.results?.execution || !document.report.content.results?.assessment)
    fail(409, '旧报告缺少完整来源，请生成新的追溯报告');
}

// Derive the same short presentation for Office files, HTML and the API.
// A caller-supplied presentation is never trusted over the saved content.
export function buildTaskReportSections(document) {
  assertSnapshot(document);
  return buildTaskAttackReport(document).sections;
}

function columnFractions(count) {
  if (count === 5) return [20, 17, 21, 30, 12];
  if (count === 2) return [30, 70];
  if (count === 3) return [24, 26, 50];
  return Array.from({ length: count }, () => 100 / count);
}

function binaryText(item) {
  return value(item).replace(/\r\n?/g, '\n').replace(/\t/g, '    ').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]/g, '');
}

async function renderDocx(document, sections) {
  const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType,
    WidthType, Header, Footer, PageNumber, ShadingType } = await import('docx');
  const run = (text, extra = {}) => new TextRun({ text: binaryText(text), font: '宋体', size: 21, ...extra });
  const paragraphs = (text, extra = {}) => binaryText(text).split('\n').map(line => new Paragraph({
    children: [run(line)], spacing: { after: 60 }, ...extra,
  }));
  const children = [new Paragraph({ children: [run(TASK_ATTACK_REPORT_TITLE, { bold: true, size: 36, color: '1A3A6A' })],
    alignment: AlignmentType.CENTER, spacing: { after: 320 } })];
  for (const section of sections) {
    children.push(new Paragraph({ children: [run(section.title, { bold: true, size: 28, color: '1A3A6A' })],
      heading: HeadingLevel.HEADING_1, keepNext: true, spacing: { before: 240, after: 160 } }));
    for (const text of section.paragraphs || []) children.push(...paragraphs(text));
    if (!section.headers) continue;
    if (!section.rows.length) { children.push(...paragraphs('未记录')); continue; }
    const fractions = columnFractions(section.headers.length);
    const makeRow = (cells, header = false) => new TableRow({ tableHeader: header, cantSplit: header,
      children: cells.map((text, index) => new TableCell({
        width: { size: fractions[index], type: WidthType.PERCENTAGE },
        shading: header ? { type: ShadingType.CLEAR, fill: 'EAF1FA' } : undefined,
        children: header ? [new Paragraph({ children: [run(text, { bold: true })] })] : paragraphs(text),
      })),
    });
    children.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE },
      columnWidths: fractions.map(fraction => Math.round(14638 * fraction / 100)),
      rows: [makeRow(section.headers, true), ...section.rows.map(row => makeRow(row))] }));
  }
  const doc = new Document({ title: TASK_ATTACK_REPORT_TITLE, creator: 'RedTeam-Platform',
    styles: { default: { document: { run: { font: '宋体', size: 21 } } } },
    sections: [{ properties: { page: { size: { width: 11906, height: 16838, orientation: 'landscape' }, margin: { top: 1100, bottom: 1100, left: 1100, right: 1100 } } },
      headers: { default: new Header({ children: [new Paragraph({ children: [run('RedTeam-Platform 测试报告', { size: 18, color: '777777' })], alignment: AlignmentType.RIGHT })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ children: [run('第 '), new TextRun({ children: [PageNumber.CURRENT], font: '宋体', size: 18 }), run(' 页')], alignment: AlignmentType.CENTER })] }) },
      children }],
  });
  return Packer.toBuffer(doc);
}

async function renderPdf(document, sections, options) {
  const { PDFDocument, rgb } = await import('pdf-lib');
  const fontkit = (await import('@pdf-lib/fontkit')).default;
  const pdf = await PDFDocument.create();
  pdf.registerFontkit(fontkit);
  let font;
  try {
    // Keep the bundled CJK font intact: its subset can retain Unicode mappings
    // while losing glyph outlines, producing extractable but unreadable PDFs.
    font = await pdf.embedFont(await readFile(options.fontPath || FONT_PATH), {
      subset: false,
      // Avoid localized alternate glyphs without a Unicode entry in the full
      // font's cmap (e.g. the final digit in a wrapped "attack-1" URL).
      features: { locl: false },
    });
  } catch { fail(500, 'PDF 中文字体加载失败，请检查报告字体文件后重试'); }
  const supported = new Set(font.getCharacterSet());
  if (Array.from('测试报告').some(character => !supported.has(character.codePointAt(0))))
    fail(500, 'PDF 中文字体加载失败，请检查报告字体文件后重试');
  const missingCharacters = new Set();
  const text = item => Array.from(binaryText(item)).map(character => {
    if (character === '\n' || supported.has(character.codePointAt(0))) return character;
    missingCharacters.add(character.codePointAt(0));
    return `[U+${character.codePointAt(0).toString(16).toUpperCase()}]`;
  }).join('');
  const widths = new Map();
  const measure = (character, size) => {
    const key = `${size}:${character}`;
    if (!widths.has(key)) widths.set(key, font.widthOfTextAtSize(character, size));
    return widths.get(key);
  };
  const wrap = (item, width, size) => {
    const output = [];
    for (const source of text(item).split('\n')) {
      let line = '', used = 0;
      for (const character of source) {
        const length = measure(character, size);
        if (line && used + length > width) { output.push(line); line = ''; used = 0; }
        line += character; used += length;
      }
      output.push(line);
    }
    return output;
  };
  const pageWidth = 841.89, pageHeight = 595.28, left = 36, right = pageWidth - 36, bottom = 42;
  let page, y;
  const newPage = () => {
    page = pdf.addPage([pageWidth, pageHeight]); y = pageHeight - 66;
    page.drawText('RedTeam-Platform 测试报告', { x: left, y: pageHeight - 33, size: 9, font, color: rgb(0.4, 0.4, 0.4) });
    page.drawLine({ start: { x: left, y: pageHeight - 42 }, end: { x: right, y: pageHeight - 42 }, thickness: 0.5, color: rgb(0.7, 0.75, 0.8) });
  };
  const paragraph = (item, size = 10, color = rgb(0.1, 0.13, 0.18)) => {
    for (const line of wrap(item, right - left, size)) {
      if (y - size * 1.5 < bottom) newPage();
      page.drawText(line, { x: left, y, size, font, color }); y -= size * 1.5;
    }
    y -= 5;
  };
  newPage();
  paragraph(TASK_ATTACK_REPORT_TITLE, 20, rgb(0.1, 0.2, 0.4));
  for (const section of sections) {
    if (y < bottom + 90) newPage();
    y -= 9; paragraph(section.title, 13, rgb(0.1, 0.2, 0.4));
    for (const item of section.paragraphs || []) paragraph(item);
    if (!section.headers) continue;
    if (!section.rows.length) { paragraph('未记录'); continue; }
    const fractions = columnFractions(section.headers.length).map(fraction => fraction / 100);
    const cellWidths = fractions.map(fraction => (right - left) * fraction), size = 9, height = 14, padding = 5;
    const paint = (cells, offset, count, header) => {
      const rowHeight = count * height + padding * 2;
      let x = left;
      for (let column = 0; column < cells.length; column++) {
        page.drawRectangle({ x, y: y - rowHeight, width: cellWidths[column], height: rowHeight,
          borderWidth: 0.5, borderColor: rgb(0.75, 0.8, 0.85), ...(header ? { color: rgb(0.92, 0.95, 0.98) } : {}) });
        const end = Math.min(offset + count, cells[column].length);
        for (let index = offset; index < end; index++) page.drawText(cells[column][index], {
          x: x + padding, y: y - padding - size - (index - offset) * height, size, font,
        });
        x += cellWidths[column];
      }
      y -= rowHeight;
    };
    const headerCells = section.headers.map((item, index) => wrap(item, cellWidths[index] - padding * 2, size));
    const headerCount = Math.max(...headerCells.map(cell => cell.length));
    const headerHeight = headerCount * height + padding * 2;
    const paintHeader = () => paint(headerCells, 0, headerCount, true);
    if (y < bottom + headerHeight + height + padding * 2) newPage();
    paintHeader();
    for (const row of section.rows) {
      const cells = row.map((item, index) => wrap(item, cellWidths[index] - padding * 2, size));
      const count = Math.max(...cells.map(cell => cell.length));
      let offset = 0;
      while (offset < count) {
        let available = Math.floor((y - bottom - padding * 2) / height);
        if (available < 1) { newPage(); paintHeader(); available = Math.floor((y - bottom - padding * 2) / height); }
        const take = Math.min(count - offset, available);
        paint(cells, offset, take, false); offset += take;
      }
    }
    y -= 8;
  }
  if (missingCharacters.size) paragraph('字体未包含的字符以 Unicode 码点 [U+XXXX] 标注；完整保存字符可通过 JSON 导出查看。');
  pdf.setTitle(TASK_ATTACK_REPORT_TITLE); pdf.setCreator('RedTeam-Platform');
  const pages = pdf.getPages();
  pages.forEach((current, index) => current.drawText(`第 ${index + 1} / ${pages.length} 页`, {
    x: left, y: 25, size: 9, font, color: rgb(0.4, 0.4, 0.4),
  }));
  return Buffer.from(await pdf.save());
}

export async function exportTaskReport(document, format, options = {}) {
  if (typeof format !== 'string' || !Object.hasOwn(TYPES, format)) fail(400, '不支持的报告格式，请选择 JSON、HTML、PDF 或 DOCX');
  assertSnapshot(document);
  const maximum = Number.isSafeInteger(options.maxBytes) && options.maxBytes > 0
    ? Math.min(options.maxBytes, MAX_TASK_REPORT_EXPORT_BYTES) : MAX_TASK_REPORT_EXPORT_BYTES;
  let buffer;
  try {
    if (format === 'json') buffer = Buffer.from(JSON.stringify(document, null, 2), 'utf8');
    else if (format === 'html') buffer = Buffer.from(taskAttackReportHtml(document), 'utf8');
    else {
      const sections = buildTaskReportSections(document);
      buffer = format === 'docx' ? await renderDocx(document, sections) : await renderPdf(document, sections, options);
    }
  } catch (error) {
    if (error.status) throw error;
    fail(500, '报告文件生成失败，请稍后重试');
  }
  if (buffer.length > maximum) fail(413, '报告文件超过 16 MiB 导出上限，未生成下载文件；请尝试其他导出格式');
  const id = String(document.report.report_id).replace(/[^a-z0-9_-]/gi, '_');
  return { buffer, contentType: TYPES[format], filename: `report_${id}.${format}` };
}
