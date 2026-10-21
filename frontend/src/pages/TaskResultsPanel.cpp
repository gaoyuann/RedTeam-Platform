#include "TaskStatisticsPanel.h"
#include "ScanPage.h"
#include "TaskResultsPanel.h"
#include "../ApiClient.h"
#include "../ReportFileActions.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/MetricCard.h"
#include "../widgets/WorkbenchTabs.h"
#include <QDateTime>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDir>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QShowEvent>
#include <QSplitter>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTimer>
#include <QTemporaryDir>
#include <QUrl>
#include <QVBoxLayout>
#include <memory>

namespace {
QString number(const QJsonValue &value)
{
  return value.isDouble() ? QString::number(value.toVariant().toLongLong()) : QStringLiteral("—");
}

QString state(const QString &value)
{
  const QMap<QString, QString> labels{{"PENDING", "待执行"}, {"RUNNING", "运行中"}, {"COMPLETED", "已完成"},
    {"FAILED", "失败"}, {"ABORTED", "已中止"}, {"SUCCEEDED", "工具成功"}, {"WAITING", "尚无结果"},
    {"NOT_RECORDED", "未记录结果"}, {"draft", "草稿"}, {"submitted", "待审阅"}, {"rejected", "已退回"}, {"reviewed", "已审阅"}, {"published", "已发布"}};
  return labels.value(value, value.isEmpty() ? QStringLiteral("未记录") : value);
}

QString sourceState(const QString &value)
{
  return value == "linked" ? QStringLiteral("尝试已关联") : value == "legacy" ? QStringLiteral("旧记录 / 缺尝试来源")
    : value == "target_mismatch" ? QStringLiteral("目标不匹配") : QStringLiteral("尝试不匹配");
}

QString kind(const QString &value)
{
  return value == "trace_snapshot" ? QStringLiteral("任务追溯快照") : value == "legacy" ? QStringLiteral("旧报告 / 来源不完整") : QStringLiteral("来源无效 / 待核对");
}

QString findingSystemResult(const QJsonObject &finding)
{
  const auto verification=finding.value("verification").toObject();
  if(verification.isEmpty())return QStringLiteral("未开展适用验证");
  const auto result=verification.value("result").toObject();
  if(result.value("schema_version").toInt()!=1)return QStringLiteral("证据不足（旧版接口）");
  const QMap<QString,QString> labels{{"achieved","目标已达成"},{"not_achieved","目标未达成"},{"inconclusive","证据不足"},{"not_performed","未开展适用验证"},{"pending","等待结果"}};
  return labels.value(result.value("status").toString(),QStringLiteral("证据不足（未知结果状态）"));
}

QString time(const QString &value)
{
  auto parsed = QDateTime::fromString(value, Qt::ISODateWithMs);
  if (!parsed.isValid()) parsed = QDateTime::fromString(value, Qt::ISODate);
  if (!parsed.isValid()) { parsed = QDateTime::fromString(value, "yyyy-MM-dd HH:mm:ss"); parsed.setTimeSpec(Qt::UTC); }
  return parsed.isValid() ? parsed.toLocalTime().toString("yyyy-MM-dd HH:mm:ss") : value.isEmpty() ? QStringLiteral("—") : value;
}

QString pretty(const QJsonObject &value) { return QString::fromUtf8(QJsonDocument(value).toJson(QJsonDocument::Indented)); }

QLabel *plainLabel(QWidget *parent)
{
  auto *label = new QLabel(parent);
  label->setTextFormat(Qt::PlainText);
  label->setWordWrap(true);
  label->setTextInteractionFlags(Qt::TextSelectableByMouse);
  return label;
}

bool identifier(const QJsonValue &value)
{
  return value.isDouble() && value.toDouble() >= 1 && value.toDouble() <= 9007199254740991.0
      && value.toDouble() == value.toVariant().toLongLong();
}

QString presentationText(const QJsonObject &presentation)
{
  if (presentation.value("schema_version").toInt() != 1 || !presentation.value("title").isString()
      || !presentation.value("sections").isArray() || presentation.value("sections").toArray().isEmpty()) return {};
  QStringList parts{presentation.value("title").toString()};
  for (const auto &sectionValue : presentation.value("sections").toArray()) {
    if (!sectionValue.isObject()) return {};
    const auto section = sectionValue.toObject();
    if (!section.value("title").isString()) return {};
    parts.append(section.value("title").toString());
    if (section.contains("paragraphs")) {
      if (!section.value("paragraphs").isArray()) return {};
      for (const auto &paragraph : section.value("paragraphs").toArray()) {
        if (!paragraph.isString()) return {};
        parts.append(paragraph.toString());
      }
    }
    QStringList headers;
    if (section.contains("headers")) {
      if (!section.value("headers").isArray()) return {};
      for (const auto &header : section.value("headers").toArray()) {
        if (!header.isString()) return {};
        headers.append(header.toString());
      }
    }
    if (section.contains("rows")) {
      if (!section.value("rows").isArray() || headers.isEmpty()) return {};
      for (const auto &rowValue : section.value("rows").toArray()) {
        if (!rowValue.isArray() || rowValue.toArray().size() != headers.size()) return {};
        QStringList cells;
        for (const auto &cell : rowValue.toArray()) {
          if (!cell.isString()) return {};
          cells.append(cell.toString());
        }
        if (cells.size() == 2) parts.append(cells[0] + QStringLiteral("：") + cells[1]);
        else {
          QStringList record;
          for (int index = 0; index < cells.size(); ++index) record.append(headers[index] + QStringLiteral("：") + cells[index]);
          parts.append(record.join('\n'));
        }
      }
    }
  }
  return parts.join(QStringLiteral("\n\n"));
}
}

TaskResultsPanel::TaskResultsPanel(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username)
{
  setObjectName("taskResultsPanel");
  setStyleSheet(Theme::PageStyle);
  auto *outer = new QVBoxLayout(this);
  outer->setContentsMargins(8, 8, 8, 8);
  auto *heading = new QHBoxLayout;
  auto *title = plainLabel(this);
  title->setText(QStringLiteral("任务结果与报告"));
  title->setStyleSheet(Theme::SectionStyle);
  heading->addWidget(title, 1);
  m_refresh = new QPushButton(QStringLiteral("刷新来源"), this);
  heading->addWidget(m_refresh);
  outer->addLayout(heading);
  m_state = plainLabel(this);
  m_identity = plainLabel(this);
  m_assessment = plainLabel(this);
  outer->addWidget(m_state);
  outer->addWidget(m_identity);
  auto *metrics = new QHBoxLayout;
  const QStringList titles{"发现候选（未复核）", "已返回 / 已知步骤", "证据记录", "历史教学得分（非风险）"};
  for (int index = 0; index < 4; ++index) {
    m_metrics[index] = new MetricCard(titles[index], Theme::Primary, this);
    m_metrics[index]->setObjectName("resultsMetric" + QString::number(index));
    metrics->addWidget(m_metrics[index]);
  }
  outer->addLayout(metrics);
  m_assessment->setStyleSheet("color:#64748b;font-size:12px;");
  outer->addWidget(m_assessment);
  auto *splitter = new QSplitter(Qt::Horizontal, this);
  m_tabs = new WorkbenchTabs(splitter);
  m_statistics = new TaskStatisticsPanel(api, m_tabs);
  m_statistics->changed = [this]{ refresh(); };
  m_tabs->addTab(m_statistics, QStringLiteral("统一统计"));
  auto makeTable = [this](const QString &title, const QStringList &headers, const QString &hint) {
    auto *table = new QTableWidget(0, headers.size(), m_tabs);
    table->setHorizontalHeaderLabels(headers);
    table->setAlternatingRowColors(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setWordWrap(false);
    table->setShowGrid(false);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setStyleSheet(Theme::ItemViewStyle);
    UiUtil::EmptyHint::attach(table, hint);
    m_tabs->addTab(table, title);
    connect(table, &QTableWidget::itemSelectionChanged, this, &TaskResultsPanel::showSelection);
    return table;
  };
  m_findings = makeTable("候选摘要（限量）", {"类别", "名称", "风险标签", "复核状态", "来源"}, "暂无扫描或分析候选；不表示目标安全");
  m_steps = makeTable("工具结果", {"步骤", "工具", "工具状态", "尝试编号", "来源", "退出码"}, "暂无执行结果，不自动计算评分或判定验证成功");
  m_evidence = makeTable("证据清单", {"证据编号", "步骤", "工具", "尝试编号", "来源校验", "采集时间"}, "暂无本任务证据记录");
  m_reports = makeTable("报告记录", {"报告编号", "标题", "来源完整性", "状态", "创建时间"}, "暂无当前任务报告；生成操作需单独确认");
  m_findings->setColumnWidth(0, 130);
  m_findings->setColumnWidth(1, 260);
  m_steps->setColumnWidth(1, 170);
  m_evidence->setColumnWidth(2, 170);
  m_evidence->setColumnWidth(4, 200);
  m_reports->setColumnWidth(0, 220);
  m_reports->setColumnWidth(1, 230);
  m_reports->setColumnWidth(2, 200);
  m_reports->setColumnWidth(3, 190);
  m_trace = new QPlainTextEdit(m_tabs);
  m_trace->setReadOnly(true);
  m_tabs->addTab(m_trace, QStringLiteral("来源链"));
  m_scanRecords = new ScanPage(m_api, m_role, m_username, m_tabs);
  m_tabs->addTab(m_scanRecords, QStringLiteral("全部扫描记录"));
  auto *detailCard = new QFrame(splitter);
  detailCard->setProperty("softCard", true);
  auto *detailLayout = new QVBoxLayout(detailCard);
  detailLayout->setContentsMargins(12, 10, 12, 10);
  auto *detailTitle = new QLabel(QStringLiteral("候选 / 证据 / 报告详情"), detailCard);
  detailTitle->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(detailTitle);
  m_detail = new QPlainTextEdit(detailCard);
  detailLayout->addWidget(m_detail, 1);
  m_detail->setObjectName("taskResultDetail");
  m_detail->setReadOnly(true);
  splitter->addWidget(m_tabs);
  splitter->addWidget(detailCard);
  splitter->setChildrenCollapsible(false);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 2);
  splitter->setSizes({680, 360});
  outer->addWidget(splitter, 1);
  auto *actions = new QHBoxLayout;
  m_generate = new QPushButton(QStringLiteral("生成报告"), this);
  m_formatCombo = new QComboBox(this);
  m_formatCombo->setObjectName("taskReportExportFormat");
  for (const auto &format : {QStringLiteral("docx"), QStringLiteral("pdf"), QStringLiteral("html"), QStringLiteral("json")})
    m_formatCombo->addItem(format.toUpper() + (format == "json" ? QStringLiteral("（完整快照）") : QString()), format);
  m_formatCombo->setToolTip(QStringLiteral("DOCX / PDF / HTML 导出攻击测试简报；JSON 保留完整保存快照"));
  m_export = new QPushButton(QStringLiteral("导出报告"), this);
  m_export->setObjectName("taskReportExport");
  m_openWps = new QPushButton(QStringLiteral("在 WPS 中打开"), this);
  m_openWps->setObjectName("taskReportOpenWps");
  m_openWps->setToolTip(QStringLiteral("下载所选报告的攻击测试简报后打开，支持 DOCX 和 PDF"));
  actions->addWidget(m_generate);
  actions->addStretch();
  actions->addWidget(m_formatCombo);
  actions->addWidget(m_export);
  actions->addWidget(m_openWps);
  outer->addLayout(actions);
  m_exportResult = plainLabel(this);
  m_exportResult->setObjectName("taskReportExportResult");
  outer->addWidget(m_exportResult);
  m_updated = plainLabel(this);
  m_updated->setStyleSheet("color:#64748b;font-size:12px;");
  outer->addWidget(m_updated);
  m_timer = new QTimer(this);
  m_timer->setInterval(5000);
  connect(m_timer, &QTimer::timeout, this, [this]() { if (isVisible()) refresh(); });
  connect(m_tabs, &QTabWidget::currentChanged, this, &TaskResultsPanel::showSelection);
  connect(m_refresh, &QPushButton::clicked, this, &TaskResultsPanel::refresh);
  connect(m_generate, &QPushButton::clicked, this, &TaskResultsPanel::generateReport);
  connect(m_export, &QPushButton::clicked, this, [this]() { exportReport(m_formatCombo->currentData().toString()); });
  connect(m_openWps, &QPushButton::clicked, this, &TaskResultsPanel::openInWps);
  connect(m_formatCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() {
    ++m_exportVersion; m_exporting = false; m_exportResult->clear(); updateButtons();
  });
  clearTaskContext();
}

QString TaskResultsPanel::apiPath() const
{
  return "/api/pipelines/" + QString::fromLatin1(QUrl::toPercentEncoding(m_pipelineId)) + "/results";
}

void TaskResultsPanel::setTaskContext(const QString &pipelineId, const QString &runId, const QString &target)
{
  if (pipelineId == m_pipelineId && runId == m_expectedRunId && target == m_target) return;
  clearTaskContext();
  m_pipelineId = pipelineId;
  m_expectedRunId = runId;
  m_target = target;
  if (!pipelineId.isEmpty()) m_scanRecords->setPipelineScope(pipelineId, {});
  m_refresh->setEnabled(!pipelineId.isEmpty());
  if (!pipelineId.isEmpty()) { m_state->setText(QStringLiteral("正在读取本任务结果来源…")); m_timer->start(); refresh(); }
}

void TaskResultsPanel::clearTaskContext()
{
  m_scanRecords->clearTaskScope();
  ++m_contextVersion;
  ++m_requestVersion;
  ++m_selectionVersion;
  ++m_exportVersion;
  m_pipelineId.clear(); m_expectedRunId.clear(); m_target.clear();
  m_selectedReportId.clear(); m_pendingReportId.clear();
  m_snapshot = {};
  m_statistics->setSnapshot({}); m_report = {}; m_reportMetadata = {};
  m_linkedReportMetadata = {}; m_linkedBusy = false;
  m_busy = false; m_fresh = false; m_generating = false; m_exporting = false;
  m_timer->stop(); m_refresh->setEnabled(false);
  for (auto *table : {m_findings, m_steps, m_evidence, m_reports}) table->setRowCount(0);
  for (auto *metric : m_metrics) metric->setValue(QStringLiteral("—"));
  m_state->setText(QStringLiteral("选择任务后查看结果与报告"));
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_identity->clear(); m_assessment->clear(); m_updated->clear(); m_trace->clear();
  m_exportResult->clear();
  m_detail->setPlainText(QStringLiteral("发现候选、工具结果、系统验证结论与人工意见分开处理；选择记录查看来源。"));
  updateButtons();
}

bool TaskResultsPanel::validSnapshot(const QJsonObject &snapshot) const
{
  if (snapshot.value("version").toInt() != 1 || snapshot.value("pipeline_id").toString() != m_pipelineId
      || snapshot.value("owner").toString().isEmpty() || (m_role != "admin" && snapshot.value("owner").toString() != m_username)
      || !snapshot.value("target").isString()
      || (!m_target.isEmpty() && snapshot.value("target").toString() != m_target)
      || !QRegularExpression("^[a-f0-9]{64}$").match(snapshot.value("source_fingerprint").toString()).hasMatch()) return false;
  const auto execution = snapshot.value("execution").toObject();
  if (execution.value("version").toInt() != 1 || execution.value("pipeline_id") != snapshot.value("pipeline_id") || execution.value("owner") != snapshot.value("owner")
      || execution.value("target") != snapshot.value("target")) return false;
  for (const QString key : {"findings", "reports"})
    if (!snapshot.value(key).isArray() || snapshot.value(key).toArray().size() > (key == "reports" ? 50 : 200)) return false;
  for (const QString key : {"steps", "evidence", "attempts"})
    if (!execution.value(key).isArray() || execution.value(key).toArray().size() > 200) return false;
  const auto runValue = execution.value("run");
  const auto run = runValue.toObject();
  const QString runId = run.value("run_id").toString();
  if (runValue.isNull()) {
    if (!m_expectedRunId.isEmpty() || !execution.value("steps").toArray().isEmpty() || !execution.value("evidence").toArray().isEmpty()
        || !execution.value("attempts").toArray().isEmpty()) return false;
  } else if (!runValue.isObject() || runId.isEmpty() || (!m_expectedRunId.isEmpty() && runId != m_expectedRunId)
      || !QStringList{"PENDING", "RUNNING", "COMPLETED", "FAILED", "ABORTED"}.contains(run.value("status").toString())) return false;
  if (runValue.isObject()) {
    const auto counts = run.value("counts").toObject();
    for (const QString key : {"steps", "returned", "succeeded", "failed", "attempts", "evidence"}) {
      const auto value = counts.value(key);
      if (!value.isDouble() || value.toDouble(-1) < 0 || value.toDouble() > 9007199254740991.0
          || value.toDouble() != value.toVariant().toLongLong()) return false;
    }
  }
  QSet<QString> findingIds;
  for (const auto &value : snapshot.value("findings").toArray()) {
    const auto row = value.toObject();
    const QString id = row.value("id").toString();
    if (!value.isObject() || id.isEmpty() || findingIds.contains(id) || row.value("state").toString() != "unreviewed") return false;
    findingIds.insert(id);
  }
  QSet<QString> reportIds;
  for (const auto &value : snapshot.value("reports").toArray()) {
    const QString id = value.toObject().value("report_id").toString();
    if (!value.isObject() || id.isEmpty() || reportIds.contains(id)) return false;
    reportIds.insert(id);
  }
  for (const QString key : {"evidence", "attempts"}) {
    QSet<qint64> ids;
    for (const auto &value : execution.value(key).toArray()) {
      const auto row = value.toObject();
      const auto id = row.value("id");
      if (!identifier(id) || row.value("run_id").toString() != runId || ids.contains(id.toVariant().toLongLong())) return false;
      ids.insert(id.toVariant().toLongLong());
    }
  }
  return snapshot.value("assessment").isObject() && snapshot.value("trace").isObject();
}

bool TaskResultsPanel::validReport(const QJsonObject &document, const QString &reportId, bool linked) const
{
  if (document.value("pipeline_id").toString() != m_pipelineId || document.value("owner") != m_snapshot.value("owner")
      || document.value("target") != m_snapshot.value("target")) return false;
  const auto report = document.value("report").toObject();
  if (report.value("report_id").toString() != reportId || !report.value("content").isObject()
      || (!linked && (report.value("kind") != m_reportMetadata.value("kind") || report.value("run_id") != m_reportMetadata.value("run_id")))) return false;
  if (report.value("kind").toString() == "legacy") return report.value("run_id").toString() == m_expectedRunId
    && report.value("content").toObject().value("schema_version").toInt(-1) == 0;
  const auto content = report.value("content").toObject();
  const auto source = content.value("provenance").toObject();
  const auto results = content.value("results").toObject();
  return report.value("kind").toString() == "trace_snapshot" && QList<int>{1,2}.contains(content.value("schema_version").toInt())
    && content.value("type").toString() == "task_result_report"
    && source.value("pipeline_id").toString() == m_pipelineId && source.value("owner") == m_snapshot.value("owner")
    && source.value("target") == m_snapshot.value("target") && source.value("run_id") == report.value("run_id")
    && results.value("pipeline_id").toString() == m_pipelineId && results.value("owner") == m_snapshot.value("owner")
    && results.value("target") == m_snapshot.value("target") && results.value("execution").toObject().value("run").toObject().value("run_id").toString() == report.value("run_id").toString()
    && results.value("source_fingerprint") == source.value("source_fingerprint")
    && QRegularExpression("^[a-f0-9]{64}$").match(source.value("source_fingerprint").toString()).hasMatch()
    && source.value("source_fingerprint") == report.value("source_fingerprint")
    && (linked || source.value("source_fingerprint") == m_reportMetadata.value("source_fingerprint"));
}

void TaskResultsPanel::refresh()
{
  if (m_pipelineId.isEmpty() || m_busy) return;
  m_busy = true; updateButtons();
  const int context = m_contextVersion;
  const int request = ++m_requestVersion;
  QPointer<TaskResultsPanel> guard(this);
  m_api->get(apiPath(), 5000, [guard, context, request](const QJsonObject &response) {
    if (!guard || context != guard->m_contextVersion || request != guard->m_requestVersion) return;
    guard->m_busy = false;
    const auto snapshot = response.value("data").toObject();
    if (response.value("status").toString() != "ok" || !guard->validSnapshot(snapshot)) {
      guard->m_fresh = false; guard->m_statistics->invalidate();
      const QString error = response.value("error").toObject().value("message").toString();
      guard->m_state->setText(QStringLiteral("读取失败，保留旧快照并禁用生成/导出：") + (error.isEmpty() ? QStringLiteral("响应来源或格式不匹配") : error));
      guard->m_state->setStyleSheet(Theme::StatusErrorStyle);
      guard->updateButtons(); return;
    }
    guard->m_fresh = true; guard->m_snapshot = snapshot; guard->render();
  });
}

void TaskResultsPanel::showEvent(QShowEvent *event) { QWidget::showEvent(event); refresh(); }

void TaskResultsPanel::showReport(const QString &reportId)
{
  ++m_selectionVersion; m_linkedBusy = false;
  m_exportResult->clear();
  m_linkedReportMetadata = {}; m_selectedReportId.clear(); m_report = {}; m_reportMetadata = {};
  m_pendingReportId = reportId;
  m_tabs->setCurrentWidget(m_reports);
  if (m_fresh && !m_busy) render();
  else refresh();
}

void TaskResultsPanel::loadLinkedReport()
{
  if (!m_fresh || m_pendingReportId.isEmpty() || m_linkedBusy) return;
  m_linkedBusy = true;
  const int context = m_contextVersion;
  const int selection = ++m_selectionVersion;
  const QString reportId = m_pendingReportId;
  QPointer<TaskResultsPanel> guard(this);
  m_api->get(apiPath() + "/reports/" + QString::fromLatin1(QUrl::toPercentEncoding(reportId)), 5000,
    [guard, context, selection, reportId](const QJsonObject &response) {
      if (!guard || context != guard->m_contextVersion || selection != guard->m_selectionVersion || reportId != guard->m_pendingReportId) return;
      guard->m_linkedBusy = false;
      const auto document = response.value("data").toObject();
      if (response.value("status").toString() != "ok" || !guard->validReport(document, reportId, true)) {
        guard->m_pendingReportId.clear();
        guard->m_detail->setPlainText(QStringLiteral("指定报告不存在、权限不足或来源不匹配；未改为打开其他报告。"));
        guard->updateButtons(); return;
      }
      guard->m_linkedReportMetadata = document.value("report").toObject();
      guard->m_linkedReportMetadata.remove("content");
      guard->render();
    });
}

void TaskResultsPanel::render()
{
  m_statistics->setSnapshot(m_snapshot);
  QStringList scanIds;
  for (const auto &value : m_snapshot.value("trace").toObject().value("scan_sources").toArray())
    scanIds.append(value.toObject().value("scan_task_id").toString());
  if (!m_pipelineId.isEmpty()) m_scanRecords->setPipelineScope(m_pipelineId, scanIds, m_snapshot.value("pipeline_status").toString());
  const auto execution = m_snapshot.value("execution").toObject();
  const auto run = execution.value("run").toObject();
  const auto counts = run.value("counts").toObject();
  const auto assessment = m_snapshot.value("assessment").toObject();
  const auto score = assessment.value("teaching_score").toObject();
  m_identity->setText(QStringLiteral("任务：%1 · %2  ·  目标：%3\nRun：%4  ·  预案：%5")
      .arg(m_snapshot.value("task_name").toString(), m_pipelineId, m_snapshot.value("target").toString(),
        run.value("run_id").toString().isEmpty() ? QStringLiteral("尚未生成") : run.value("run_id").toString(), run.value("playbook_name").toString()));
  m_state->setText(run.isEmpty() ? QStringLiteral("暂无执行结果；可以查看已有候选，但不能生成执行结果报告。")
      : QStringLiteral("Run %1 · %2").arg(state(run.value("status").toString()), run.value("stop_reason").toString()));
  m_state->setStyleSheet(run.value("status").toString() == "FAILED" ? Theme::StatusErrorStyle : Theme::StatusInfoStyle);
  m_assessment->setText(assessment.value("risk_level").toString() + "\n" + assessment.value("notice").toString()
      + QStringLiteral(" 教学分仅展示历史存储值，本页不会自动评分；系统结论由适用判据和证据决定，人工意见单独保留。"));
  m_metrics[0]->setValue(number(m_snapshot.value("finding_count")));
  m_metrics[0]->setToolTip(QStringLiteral("当前候选摘要中的记录数，包含 AI 候选；不是去重漏洞数。完整扫描记录见同名标签。"));
  m_metrics[1]->setValue(run.isEmpty() ? QStringLiteral("—") : number(counts.value("returned")) + " / " + number(counts.value("steps")));
  m_metrics[2]->setValue(run.isEmpty() ? QStringLiteral("—") : number(counts.value("evidence")));
  m_metrics[3]->setValue(score.value("percent").isDouble() ? QString::number(score.value("percent").toDouble(), 'f', 1) + "%" : QStringLiteral("—"));
  const QList<QTableWidget *> tables{m_findings, m_steps, m_evidence, m_reports};
  auto reports = m_snapshot.value("reports").toArray();
  bool linkedPresent = false;
  for (const auto &value : reports) if (value.toObject().value("report_id") == m_linkedReportMetadata.value("report_id")) linkedPresent = true;
  if (!m_linkedReportMetadata.isEmpty() && !linkedPresent) reports.append(m_linkedReportMetadata);
  const QList<QJsonArray> arrays{m_snapshot.value("findings").toArray(), execution.value("steps").toArray(), execution.value("evidence").toArray(), reports};
  bool pendingFound = false;
  for (int tableIndex = 0; tableIndex < tables.size(); ++tableIndex) {
    auto *table = tables[tableIndex];
    const auto *selected = table->item(table->currentRow(), 0);
    const auto old = selected ? selected->data(Qt::UserRole).toJsonObject() : QJsonObject();
    const QString key = tableIndex == 1 ? "step_index" : tableIndex == 3 ? "report_id" : "id";
    const auto identity = tableIndex == 3 && !m_pendingReportId.isEmpty() ? QJsonValue(m_pendingReportId) : old.value(key);
    table->blockSignals(true); table->setRowCount(arrays[tableIndex].size());
    int selectedRow = -1;
    for (int rowIndex = 0; rowIndex < arrays[tableIndex].size(); ++rowIndex) {
      const auto row = arrays[tableIndex][rowIndex].toObject();
      QStringList cells;
      if (tableIndex == 0) cells = QStringList{row.value("category").toString() == "scan_candidate" ? "扫描候选" : "分析候选", row.value("name").toString(),
        row.value("severity").toString(), findingSystemResult(row), row.value("source").toString() == "structured_scan" ? "结构化扫描结果" : "任务 AI 分析"};
      else if (tableIndex == 1) cells = QStringList{number(row.value("step_index")), row.value("tool_id").toString(), state(row.value("state").toString()),
        number(row.value("attempt_id")), row.value("source").toString() == "playbook" ? "预案" : "动态 / 来源待核对", number(row.value("exit_code"))};
      else if (tableIndex == 2) cells = QStringList{number(row.value("id")), number(row.value("step_index")), row.value("tool_id").toString(),
        number(row.value("attempt_id")), sourceState(row.value("source_state").toString()), time(row.value("recorded_at").toString())};
      else cells = QStringList{row.value("report_id").toString(), row.value("title").toString(), kind(row.value("kind").toString()),
        row.value("kind").toString() == "trace_snapshot" ? QStringLiteral("已生成") : state(row.value("status").toString()), time(row.value("created_at").toString())};
      for (int column = 0; column < cells.size(); ++column) {
        auto *item = new QTableWidgetItem(cells[column]); item->setToolTip(cells[column].toHtmlEscaped());
        if (column == 0) item->setData(Qt::UserRole, row);
        table->setItem(rowIndex, column, item);
      }
      if (!identity.isUndefined() && row.value(key) == identity) selectedRow = rowIndex;
    }
    if (selectedRow >= 0) { table->selectRow(selectedRow); if (tableIndex == 3) pendingFound = true; }
    else { table->clearSelection(); table->setCurrentCell(-1, -1); }
    table->blockSignals(false);
  }
  if (pendingFound) m_pendingReportId.clear();
  const QString traceText = QStringLiteral("任务—预案—Run—证据来源链\n批准来源 verified 仅表示预案与批准记录一致，不表示漏洞已验证。\n预案内容版本与批准操作后的记录版本分开保存；旧任务缺来源时保持 incomplete。\n\n")
      + pretty(QJsonObject{{"pipeline_id", m_pipelineId}, {"owner", m_snapshot.value("owner")}, {"target", m_snapshot.value("target")},
        {"run_id", run.value("run_id")}, {"playbook_id", run.value("playbook_id")}, {"trace", m_snapshot.value("trace")},
        {"source_fingerprint", m_snapshot.value("source_fingerprint")}, {"limits", m_snapshot.value("limits")}});
  if (m_trace->toPlainText() != traceText) m_trace->setPlainText(traceText);
  m_updated->setText(QStringLiteral("来源快照：%1 · 最多 150 个扫描候选 + 50 个分析候选、200 条步骤/证据、最新 50 份报告；可额外定位 1 份历史报告。单字段限长并脱敏，不是原始取证材料。")
      .arg(time(m_snapshot.value("captured_at").toString())));
  showSelection();
  loadLinkedReport();
}

void TaskResultsPanel::showSelection()
{
  if (m_tabs->currentWidget() != m_reports && m_exporting) {
    ++m_exportVersion; m_exporting = false;
  }
  if (m_linkedBusy && m_tabs->currentWidget() != m_reports) {
    ++m_selectionVersion; m_linkedBusy = false; m_pendingReportId.clear();
  }
  if (m_tabs->currentWidget() == m_reports) {
    const auto *item = m_reports->item(m_reports->currentRow(), 0);
    const auto metadata = item && m_reports->selectionModel()->hasSelection() ? item->data(Qt::UserRole).toJsonObject() : QJsonObject();
    const QString reportId = metadata.value("report_id").toString();
    if (m_linkedBusy && !reportId.isEmpty() && reportId != m_pendingReportId) {
      ++m_selectionVersion; m_linkedBusy = false; m_pendingReportId.clear();
    }
    if (reportId != m_selectedReportId || metadata != m_reportMetadata) {
      m_exportResult->clear();
      ++m_selectionVersion; m_exporting = false; m_report = {}; m_reportMetadata = metadata; m_selectedReportId = reportId;
      if (!reportId.isEmpty()) {
        const int context = m_contextVersion; const int selection = m_selectionVersion;
        QPointer<TaskResultsPanel> guard(this);
        m_api->get(apiPath() + "/reports/" + QString::fromLatin1(QUrl::toPercentEncoding(reportId)), 5000,
          [guard, context, selection, reportId](const QJsonObject &response) {
            if (!guard || context != guard->m_contextVersion || selection != guard->m_selectionVersion || reportId != guard->m_selectedReportId) return;
            const auto document = response.value("data").toObject();
            if (response.value("status").toString() != "ok" || !guard->validReport(document, reportId)) {
              guard->m_detail->setPlainText(QStringLiteral("报告读取失败或来源不匹配；请重新选择或刷新，导出保持禁用。"));
              guard->m_selectedReportId.clear(); guard->m_report = {}; guard->updateButtons(); return;
            }
            guard->m_report = document; guard->renderDetail(); guard->updateButtons();
          });
      }
    }
  }
  renderDetail(); updateButtons();
}

void TaskResultsPanel::renderDetail()
{
  if (m_tabs->currentWidget() == m_reports) {
    QString detail;
    if (m_selectedReportId.isEmpty()) detail = QStringLiteral("选择报告查看保存时的攻击测试简报；JSON 可导出完整保存快照。");
    else if (m_report.isEmpty()) detail = QStringLiteral("正在读取所选报告…");
    else {
      const auto report = m_report.value("report").toObject();
      const auto content = report.value("content").toObject();
      detail = QStringLiteral("报告：%1\n编号：%2 · %3 · %4\n")
        .arg(report.value("title").toString(), report.value("report_id").toString(), state(report.value("status").toString()),
          time(report.value("created_at").toString()));
      if (report.value("kind").toString() == "trace_snapshot") {
        const QString brief = presentationText(m_report.value("presentation").toObject());
        detail += brief.isEmpty() ? QStringLiteral("\n详细攻击效果未提供，请刷新或更新后端。") : "\n" + brief;
        detail += QStringLiteral("\n\nDOCX / PDF / HTML 导出简报；JSON 导出完整保存快照。");
      } else detail += content.value("notice").toString() + "\n\n" + pretty(content);
    }
    if (m_detail->toPlainText() != detail) m_detail->setPlainText(detail);
    return;
  }
  auto *table = qobject_cast<QTableWidget *>(m_tabs->currentWidget());
  const auto *item = table ? table->item(table->currentRow(), 0) : nullptr;
  if (!item || !table->selectionModel()->hasSelection()) {
    m_detail->setPlainText(QStringLiteral("选择一条候选、工具结果或证据记录查看来源；缺少记录不能推断为安全或验证成功。")); return;
  }
  const QString detail = QStringLiteral("任务：%1\n候选和工具结果不自动代表目标达成，source_state 只校验记录关联。\n\n").arg(m_pipelineId) + pretty(item->data(Qt::UserRole).toJsonObject());
  if (m_detail->toPlainText() != detail) m_detail->setPlainText(detail);
}

void TaskResultsPanel::updateButtons()
{
  const QString runState = m_snapshot.value("execution").toObject().value("run").toObject().value("status").toString();
  m_generate->setEnabled(m_fresh && !m_busy && !m_generating && (m_snapshot.contains("statistics") ? m_snapshot.value("statistics").toObject().value("report_ready").toBool() : QStringList{"COMPLETED", "FAILED", "ABORTED"}.contains(runState)));
  m_generate->setText(m_generating ? QStringLiteral("生成报告中…") : QStringLiteral("生成报告"));
  const bool canExport = canExportReport();
  m_formatCombo->setEnabled(m_fresh && m_tabs->currentWidget() == m_reports && !m_report.isEmpty());
  m_export->setEnabled(canExport);
  m_export->setText(m_exporting ? QStringLiteral("下载报告中…") : QStringLiteral("导出报告"));
  m_openWps->setEnabled(canExport && QStringList{"docx", "pdf"}.contains(m_formatCombo->currentData().toString()));
}

bool TaskResultsPanel::canExportReport() const
{
  return m_fresh && !m_exporting && m_tabs->currentWidget() == m_reports && !m_selectedReportId.isEmpty()
      && !m_report.isEmpty() && m_report.value("report").toObject().value("kind").toString() == "trace_snapshot";
}

void TaskResultsPanel::generateReport()
{
  if (!m_generate->isEnabled()) return;
  const int context = m_contextVersion;
  const auto run = m_snapshot.value("execution").toObject().value("run").toObject();
  const QString fingerprint = m_snapshot.value("source_fingerprint").toString();
  QMessageBox confirmation(QMessageBox::Question, QStringLiteral("生成结果报告"),
    QStringLiteral("将保存任务 %1 / Run %2 的脱敏、限长来源快照。\n不会重新执行、评分或判定漏洞；同一来源重复生成会复用已有报告。\n是否继续？").arg(m_pipelineId, run.value("run_id").toString()),
    QMessageBox::Yes | QMessageBox::No, this);
  confirmation.setTextFormat(Qt::PlainText); confirmation.setDefaultButton(QMessageBox::No);
  if (confirmation.exec() != QMessageBox::Yes || context != m_contextVersion || !m_fresh) return;
  m_generating = true; updateButtons();
  const QString runId = run.value("run_id").toString();
  QPointer<TaskResultsPanel> guard(this);
  m_api->post(apiPath() + "/reports", QJsonObject{{"run_id", runId}, {"source_fingerprint", fingerprint}}, 10000,
    [guard, context, runId, fingerprint](const QJsonObject &response) {
      if (!guard || context != guard->m_contextVersion) return;
      guard->m_generating = false;
      const auto data = response.value("data").toObject(); const auto report = data.value("report").toObject();
      if (response.value("status").toString() != "ok" || data.value("pipeline_id").toString() != guard->m_pipelineId
          || data.value("run_id").toString() != runId || report.value("report_id").toString().isEmpty()
          || report.value("source_fingerprint").toString() != fingerprint || report.value("kind").toString() != "trace_snapshot") {
        guard->m_fresh = false;
        guard->m_state->setText(QStringLiteral("报告生成失败；请刷新来源后重新确认：") + response.value("error").toObject().value("message").toString());
        guard->m_state->setStyleSheet(Theme::StatusErrorStyle); guard->updateButtons(); return;
      }
      guard->m_pendingReportId = report.value("report_id").toString(); guard->m_tabs->setCurrentWidget(guard->m_reports);
      guard->refresh(); guard->updateButtons();
    });
}

void TaskResultsPanel::exportReport(const QString &format)
{
  if (!canExportReport() || !QStringList{"docx", "pdf", "json", "html"}.contains(format)
      || m_formatCombo->currentData().toString() != format) return;
  m_exportResult->clear();
  const int context = m_contextVersion; const int selection = m_selectionVersion;
  const int exportVersion = m_exportVersion;
  const QString reportId = m_selectedReportId;
  QString safeName = reportId; safeName.replace(QRegularExpression("[^a-zA-Z0-9_-]"), "_");
  const QString filename = "report_" + safeName + "." + format;
  QPointer<TaskResultsPanel> guard(this);
  const QString path = QFileDialog::getSaveFileName(this,
      format == "json" ? QStringLiteral("导出完整保存快照") : QStringLiteral("导出攻击测试简报"), filename,
      format.toUpper() + " (*." + format + ")");
  if (!guard || path.isEmpty() || context != guard->m_contextVersion || selection != guard->m_selectionVersion
      || exportVersion != guard->m_exportVersion || guard->m_formatCombo->currentData().toString() != format) return;
  guard->downloadReport(format, path, false);
}

void TaskResultsPanel::openInWps()
{
  const QString format = m_formatCombo->currentData().toString();
  if (!canExportReport() || !QStringList{"docx", "pdf"}.contains(format)) return;
  downloadReport(format, {}, true);
}

void TaskResultsPanel::downloadReport(const QString &format, const QString &path, bool openWps)
{
  if (!canExportReport() || m_formatCombo->currentData().toString() != format
      || !QStringList{"docx", "pdf", "json", "html"}.contains(format)
      || (openWps && !QStringList{"docx", "pdf"}.contains(format)) || (!openWps && path.isEmpty())) return;
  const int context = m_contextVersion; const int selection = m_selectionVersion;
  const int exportVersion = ++m_exportVersion;
  const QString reportId = m_selectedReportId;
  QString safeName = reportId; safeName.replace(QRegularExpression("[^a-zA-Z0-9_-]"), "_");
  const QString filename = "report_" + safeName + "." + format;
  const QString fingerprint = m_report.value("report").toObject().value("source_fingerprint").toString();
  m_exportResult->clear();
  m_exporting = true; updateButtons();
  QPointer<TaskResultsPanel> guard(this);
  m_api->downloadWithError(apiPath() + "/reports/" + QString::fromLatin1(QUrl::toPercentEncoding(reportId)) + "/export?format=" + format, 30000,
    [guard, context, selection, exportVersion, reportId, fingerprint, format, filename, path, openWps]
    (bool ok, const QByteArray &bytes, const QString &receivedName, const QString &errorMessage) {
      if (!guard || context != guard->m_contextVersion || selection != guard->m_selectionVersion
          || exportVersion != guard->m_exportVersion || reportId != guard->m_selectedReportId
          || guard->m_formatCombo->currentData().toString() != format) return;
      guard->m_exporting = false;
      if (!ok) {
        guard->m_exportResult->setText(QStringLiteral("报告下载失败：")
            + (errorMessage.isEmpty() ? QStringLiteral("请检查后端服务和网络后重试。") : errorMessage)
            + QStringLiteral("\n未写入文件。"));
        guard->updateButtons(); return;
      }
      if (bytes.size() > 16 * 1024 * 1024) {
        guard->m_exportResult->setText(QStringLiteral("报告文件超过 16 MiB 导出上限，未写入文件；请尝试其他导出格式。"));
        guard->updateButtons(); return;
      }
      bool valid = !bytes.isEmpty() && receivedName == filename;
      if (valid && format == "json") valid = guard->validReport(QJsonDocument::fromJson(bytes).object(), reportId);
      if (valid && format == "pdf") valid = bytes.startsWith("%PDF-");
      if (valid && format == "docx") valid = bytes.startsWith(QByteArray::fromHex("504b0304"));
      if (!valid) guard->m_exportResult->setText(QStringLiteral("报告文件内容或响应来源校验失败，未写入文件；请重新选择报告后重试。"));
      else {
        QString savePath = path;
        std::unique_ptr<QTemporaryDir> temporary;
        if (openWps) {
          const QString cache = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
          const QString cacheRoot = QDir(cache).filePath("report-exports");
          const auto identity = QJsonDocument(QJsonObject{{"owner", guard->m_snapshot.value("owner")},
            {"pipeline_id", guard->m_pipelineId}, {"report_id", reportId}, {"format", format}, {"source_fingerprint", fingerprint}}).toJson(QJsonDocument::Compact);
          const QString key = QString::fromLatin1(QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex().left(20));
          if (cache.isEmpty() || !QDir().mkpath(cacheRoot)) {
            guard->m_exportResult->setText(QStringLiteral("无法创建报告缓存目录，请使用导出报告选择保存位置。"));
            guard->updateButtons(); return;
          }
          // Each click receives a fresh copy; WPS edits never become another report's cache.
          temporary = std::make_unique<QTemporaryDir>(QDir(cacheRoot).filePath(key + "-XXXXXX"));
          if (!temporary->isValid()) {
            guard->m_exportResult->setText(QStringLiteral("无法创建报告缓存目录，请使用导出报告选择保存位置。"));
            guard->updateButtons(); return;
          }
          savePath = QDir(temporary->path()).filePath(filename);
        }
        QSaveFile file(savePath);
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
          guard->m_exportResult->setText(QStringLiteral("无法写入导出文件，请检查保存目录。"));
        else if (openWps) {
          // Keep the file after page/client exit so the detached editor can keep reading it.
          temporary->setAutoRemove(false);
          const auto result = ReportFileActions::openInWps(savePath);
          guard->m_exportResult->setText(result.status == ReportFileActions::OpenStatus::Started
              ? QStringLiteral("已在 WPS 中打开攻击测试简报：") + savePath : result.message);
        } else guard->m_exportResult->setText((format == "json"
              ? QStringLiteral("已导出完整保存快照：") : QStringLiteral("已导出攻击测试简报：")) + savePath);
      }
      guard->updateButtons();
    });
}
