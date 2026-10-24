#include "TaskPlanPage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/WorkbenchTabs.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTabWidget>
#include <QVBoxLayout>

namespace {
QString jsonText(const QJsonValue &value)
{
  if (value.isString()) return value.toString();
  if (value.isArray()) return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Indented));
  if (value.isObject()) return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Indented));
  return {};
}

QString planState(const QString &state)
{
  if (state == "draft") return QStringLiteral("编辑中");
  if (state == "submitted") return QStringLiteral("已提审 · 等待管理员审批");
  if (state == "rejected") return QStringLiteral("已驳回 · 可返回编辑");
  if (state == "approved") return QStringLiteral("审批通过 · 执行按审批快照启动");
  return QStringLiteral("尚未建立任务草稿");
}

QString actionText(const QString &action)
{
  if (action == "create") return QStringLiteral("建立草稿");
  if (action == "save") return QStringLiteral("保存编辑");
  if (action == "add_suggestion") return QStringLiteral("加入候选");
  if (action == "submit") return QStringLiteral("提交审批");
  if (action == "reopen") return QStringLiteral("返回编辑");
  if (action == "reject") return QStringLiteral("驳回");
  if (action == "approve") return QStringLiteral("审批通过");
  return action;
}

void setupTable(QTableWidget *table, const QStringList &headers)
{
  table->setColumnCount(headers.size());
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->verticalHeader()->hide();
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  table->setAlternatingRowColors(true);
  table->setWordWrap(false);
  table->setShowGrid(false);
  table->setTextElideMode(Qt::ElideRight);
  table->verticalHeader()->setDefaultSectionSize(36);
}
}

TaskPlanPage::TaskPlanPage(ApiClient *api, const QString &role, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role)
{
  setObjectName(QStringLiteral("taskPlanPage"));
  setStyleSheet(Theme::PageStyle);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(16, 14, 16, 14);
  layout->setSpacing(8);
  auto *header = new QHBoxLayout;
  auto *title = new QLabel(QStringLiteral("任务预案 · 编辑与审阅"), this);
  title->setStyleSheet(QStringLiteral("font-size:20px; font-weight:700; color:#172033;"));
  header->addWidget(title, 1);
  m_refresh = new QPushButton(QStringLiteral("刷新预案"), this);
  m_refresh->setObjectName(QStringLiteral("planRefreshButton"));
  header->addWidget(m_refresh);
  layout->addLayout(header);
  auto *optional = new QLabel(QStringLiteral("可选，用于批量编排；逐漏洞测试可直接从漏洞列表开始。"), this);
  optional->setObjectName("optionalPlanHint");
  optional->setWordWrap(true);
  optional->setStyleSheet(Theme::StatusInfoStyle);
  layout->addWidget(optional);
  m_status = new QLabel(this);
  m_status->setObjectName(QStringLiteral("planStatusLabel"));
  m_status->setTextFormat(Qt::PlainText);
  m_status->setWordWrap(true);
  layout->addWidget(m_status);
  m_scope = new QLabel(this);
  m_scope->setTextFormat(Qt::PlainText);
  m_scope->setWordWrap(true);
  m_scope->setStyleSheet(QStringLiteral("color:#64748b; font-size:12px;"));
  layout->addWidget(m_scope);
  auto *sourceRow = new QHBoxLayout;
  sourceRow->addWidget(new QLabel(QStringLiteral("来源预案："), this));
  m_source = new QComboBox(this);
  m_source->setObjectName(QStringLiteral("planSourceCombo"));
  m_source->setMinimumWidth(160);
  m_source->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  sourceRow->addWidget(m_source, 1);
  m_create = new QPushButton(QStringLiteral("建立任务草稿"), this);
  m_create->setObjectName(QStringLiteral("planCreateButton"));
  sourceRow->addWidget(m_create);
  layout->addLayout(sourceRow);
  m_generateSource = new QPushButton(QStringLiteral("生成攻击测试预案"), this);
  m_generateSource->setObjectName(QStringLiteral("planGenerateSourceButton"));
  m_generateSource->setProperty("primary", true);
  m_generateSource->hide();
  layout->addWidget(m_generateSource);
  connect(m_generateSource, &QPushButton::clicked, this, &TaskPlanPage::sourceVerificationRequested);

  auto *form = new QFormLayout;
  m_name = new QLineEdit(this);
  m_name->setObjectName(QStringLiteral("planNameEdit"));
  m_name->setMaxLength(200);
  form->addRow(QStringLiteral("预案名称："), m_name);
  m_notes = new QPlainTextEdit(this);
  m_notes->setObjectName(QStringLiteral("planNotesEdit"));
  m_notes->setMaximumHeight(64);
  m_notes->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  m_notes->setPlaceholderText(QStringLiteral("填写验证目标、人工确认点和停止条件；备注不作为自动执行规则。"));
  form->addRow(QStringLiteral("约束 / 备注："), m_notes);
  layout->addLayout(form);

  auto *tabs = new WorkbenchTabs(this);
  auto *stepsPage = new QWidget(tabs);
  auto *stepsLayout = new QVBoxLayout(stepsPage);
  auto *splitter = new QSplitter(Qt::Horizontal, stepsPage);
  m_steps = new QTableWidget(splitter);
  m_steps->setObjectName(QStringLiteral("planStepsTable"));
  setupTable(m_steps, {QStringLiteral("步骤"), QStringLiteral("工具"), QStringLiteral("参数摘要"), QStringLiteral("失败策略")});
  UiUtil::EmptyHint::attach(m_steps, QStringLiteral("暂无预案步骤；建立或读取任务草稿后显示"));
  auto *editor = new QFrame(splitter);
  editor->setProperty("softCard", true);
  auto *editorLayout = new QVBoxLayout(editor);
  auto *editorTitle = new QLabel(QStringLiteral("步骤详情"), editor);
  editorTitle->setStyleSheet(Theme::SectionStyle);
  editorLayout->addWidget(editorTitle);
  editorLayout->addWidget(new QLabel(QStringLiteral("步骤名称"), editor));
  m_stepName = new QLineEdit(editor);
  m_stepName->setObjectName(QStringLiteral("planStepNameEdit"));
  m_stepName->setMaxLength(200);
  editorLayout->addWidget(m_stepName);
  auto *advanced = new QPushButton(QStringLiteral("展开高级参数"), editor);
  advanced->setObjectName(QStringLiteral("planAdvancedToggle"));
  advanced->setCheckable(true);
  advanced->setProperty("quiet", true);
  advanced->setToolTip(QStringLiteral("查看或编辑现有 JSON 参数模板；收起不会清除参数。"));
  editorLayout->addWidget(advanced);
  m_args = new QPlainTextEdit(editor);
  m_args->setObjectName(QStringLiteral("planArgsEdit"));
  m_args->setPlaceholderText(QStringLiteral("JSON 字符串数组"));
  m_args->hide();
  connect(advanced, &QPushButton::toggled, this, [this, advanced](bool expanded) {
    m_args->setVisible(expanded);
    advanced->setText(expanded ? QStringLiteral("收起高级参数") : QStringLiteral("展开高级参数"));
  });
  editorLayout->addWidget(m_args, 1);
  m_optional = new QCheckBox(QStringLiteral("可选步骤：失败时允许继续"), editor);
  editorLayout->addWidget(m_optional);
  auto *ordering = new QHBoxLayout;
  m_up = new QPushButton(QStringLiteral("上移"), editor);
  m_down = new QPushButton(QStringLiteral("下移"), editor);
  m_remove = new QPushButton(QStringLiteral("移除步骤"), editor);
  ordering->addWidget(m_up);
  ordering->addWidget(m_down);
  ordering->addWidget(m_remove);
  editorLayout->addLayout(ordering);
  splitter->setChildrenCollapsible(false);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 2);
  splitter->setSizes({500, 320});
  stepsLayout->addWidget(splitter);
  tabs->addTab(stepsPage, QStringLiteral("执行步骤"));

  auto *suggestionPage = new QWidget(tabs);
  auto *suggestionLayout = new QVBoxLayout(suggestionPage);
  auto *hint = new QLabel(QStringLiteral("在“智能分析”中选择候选并加入草稿。接受仅表示纳入审阅备注，不自动生成步骤或执行工具。"), suggestionPage);
  hint->setWordWrap(true);
  suggestionLayout->addWidget(hint);
  m_suggestions = new QTableWidget(suggestionPage);
  m_suggestions->setObjectName(QStringLiteral("planSuggestionsTable"));
  setupTable(m_suggestions, {QStringLiteral("来源"), QStringLiteral("候选内容"), QStringLiteral("人工处置")});
  UiUtil::EmptyHint::attach(m_suggestions, QStringLiteral("暂无候选建议；从智能分析中选择后加入"));
  suggestionLayout->addWidget(m_suggestions, 2);
  m_suggestionDetail = new QPlainTextEdit(suggestionPage);
  m_suggestionDetail->setReadOnly(true);
  suggestionLayout->addWidget(m_suggestionDetail, 1);
  tabs->addTab(suggestionPage, QStringLiteral("候选建议"));
  m_history = new QTableWidget(tabs);
  m_history->setObjectName(QStringLiteral("planHistoryTable"));
  setupTable(m_history, {QStringLiteral("时间（UTC）"), QStringLiteral("操作"), QStringLiteral("记录版本"), QStringLiteral("操作人"), QStringLiteral("意见")});
  tabs->addTab(m_history, QStringLiteral("提审 / 审批记录"));
  layout->addWidget(tabs, 1);

  auto *actions = new QHBoxLayout;
  m_save = new QPushButton(QStringLiteral("保存草稿"), this);
  m_save->setObjectName(QStringLiteral("planSaveButton"));
  m_submit = new QPushButton(QStringLiteral("提交审批"), this);
  m_submit->setObjectName(QStringLiteral("planSubmitButton"));
  m_reopen = new QPushButton(QStringLiteral("返回编辑"), this);
  m_reject = new QPushButton(QStringLiteral("驳回"), this);
  m_reject->setObjectName(QStringLiteral("planRejectButton"));
  m_approve = new QPushButton(QStringLiteral("批准此版本并执行"), this);
  m_approve->setObjectName(QStringLiteral("planApproveButton"));
  m_submit->setProperty("primary", true);
  m_approve->setProperty("primary", true);
  actions->addWidget(m_save);
  actions->addWidget(m_submit);
  actions->addWidget(m_reopen);
  actions->addStretch();
  actions->addWidget(m_reject);
  actions->addWidget(m_approve);
  layout->addLayout(actions);
  auto *footer = new QLabel(QStringLiteral("草稿只修改当前任务，来源预案保持原样。提审后锁定编辑，修改须返回编辑并重新提审；批准的执行版本仅保存在所属任务，执行前检查仍需通过。"), this);
  footer->setWordWrap(true);
  footer->setStyleSheet(QStringLiteral("font-size:12px; color:#64748b;"));
  layout->addWidget(footer);

  connect(m_refresh, &QPushButton::clicked, this, [this]() { refresh(true); });
  connect(m_create, &QPushButton::clicked, this, [this]() {
    mutate({}, {{"playbook_id", m_source->currentData().toString()}});
  });
  connect(m_name, &QLineEdit::textChanged, this, [this](const QString &name) {
    if (m_rendering) return;
    m_content["name"] = name;
    markDirty();
  });
  connect(m_notes, &QPlainTextEdit::textChanged, this, [this]() {
    if (m_rendering) return;
    m_content["notes"] = m_notes->toPlainText();
    markDirty();
  });
  connect(m_steps, &QTableWidget::itemSelectionChanged, this, &TaskPlanPage::showStep);
  connect(m_stepName, &QLineEdit::textChanged, this, &TaskPlanPage::editStep);
  connect(m_args, &QPlainTextEdit::textChanged, this, &TaskPlanPage::editStep);
  connect(m_optional, &QCheckBox::toggled, this, &TaskPlanPage::editStep);
  connect(m_up, &QPushButton::clicked, this, [this]() { moveStep(-1); });
  connect(m_down, &QPushButton::clicked, this, [this]() { moveStep(1); });
  connect(m_remove, &QPushButton::clicked, this, [this]() {
    const int row = m_steps->currentRow();
    auto steps = m_content["steps"].toArray();
    if (row < 0 || row >= steps.size() || steps.size() <= 1) return;
    steps.removeAt(row);
    m_content["steps"] = steps;
    markDirty();
    render();
  });
  connect(m_suggestions, &QTableWidget::itemSelectionChanged, this, [this]() {
    if (m_rendering) return;
    const int row = m_suggestions->currentRow();
    const auto suggestions = m_content["suggestions"].toArray();
    m_suggestionDetail->setPlainText(row >= 0 && row < suggestions.size()
        ? jsonText(suggestions.at(row)) : QStringLiteral("选择候选项查看来源快照；候选不是已验证结论。"));
  });
  connect(m_save, &QPushButton::clicked, this, &TaskPlanPage::save);
  connect(m_submit, &QPushButton::clicked, this, [this]() { transition("submit"); });
  connect(m_reopen, &QPushButton::clicked, this, [this]() { transition("reopen"); });
  connect(m_reject, &QPushButton::clicked, this, [this]() { transition("reject"); });
  connect(m_approve, &QPushButton::clicked, this, [this]() { transition("approve"); });
  clearTaskContext();
}

void TaskPlanPage::message(const QString &text, bool error)
{
  m_status->setText(text);
  m_status->setStyleSheet(error ? Theme::StatusErrorStyle : Theme::StatusInfoStyle);
}

void TaskPlanPage::clearTaskContext()
{
  ++m_contextVersion;
  ++m_requestVersion;
  m_pipeline = {};
  m_plan = {};
  m_content = {};
  m_busy = false;
  m_dirty = false;
  m_pendingSourcePlaybookId.clear();
  m_source->clear();
  render();
  message(QStringLiteral("请选择任务；预案生成后可建立草稿并提交审批。"));
}

void TaskPlanPage::setTaskContext(const QJsonObject &pipeline)
{
  const bool changed = pipeline["pipeline_id"] != m_pipeline.value("pipeline_id");
  const bool statusChanged = pipeline["status"] != m_pipeline.value("status");
  if (changed) clearTaskContext();
  m_pipeline = pipeline;
  updateControls();
  if (changed || (statusChanged && !m_busy && !m_dirty)) refresh();
  if (!changed && statusChanged && m_dirty)
    message(QStringLiteral("任务状态已变化；保留未保存编辑，但当前状态可能不再允许保存。"), true);
}

void TaskPlanPage::refresh(bool discard)
{
  if (m_busy || m_pipeline.value("pipeline_id").toString().isEmpty()) return;
  if (m_dirty) {
    if (!discard) return;
    if (QMessageBox::question(this, QStringLiteral("刷新预案"), QStringLiteral("刷新会丢弃未保存修改，是否继续？")) != QMessageBox::Yes) return;
  }
  m_busy = true;
  updateControls();
  message(QStringLiteral("正在加载任务预案…"));
  const int context = m_contextVersion;
  const int request = ++m_requestVersion;
  QPointer<TaskPlanPage> guard(this);
  m_api->get(QStringLiteral("/api/pipelines/%1/plan").arg(m_pipeline.value("pipeline_id").toString()), 8000,
      [guard, context, request](const QJsonObject &response) {
    if (!guard || context != guard->m_contextVersion || request != guard->m_requestVersion) return;
    guard->m_busy = false;
    if (response["status"].toString() != "ok") {
      guard->message(response["error"].toObject()["message"].toString(QStringLiteral("预案加载失败，请刷新重试")), true);
      guard->updateControls();
      return;
    }
    const auto data = response["data"].toObject();
    if (!response["data"].isNull() && (!response["data"].isObject()
        || data["pipeline_id"] != guard->m_pipeline.value("pipeline_id") || !data["content"].isObject())) {
      guard->message(QStringLiteral("预案响应任务标识或内容格式不匹配，请刷新重试。"), true);
      guard->updateControls();
      return;
    }
    guard->m_plan = response["data"].toObject();
    guard->m_content = guard->m_plan.value("content").toObject();
    guard->m_dirty = false;
    guard->render();
    if (!guard->m_pendingSourcePlaybookId.isEmpty()) {
      const QString pending = guard->m_pendingSourcePlaybookId;
      guard->m_pendingSourcePlaybookId.clear();
      guard->useSourcePlaybook(pending);
      return;
    }
    if (guard->m_plan.isEmpty()) guard->loadSources(request);
  });
}

void TaskPlanPage::loadSources(int requestVersion)
{
  const int context = m_contextVersion;
  QPointer<TaskPlanPage> guard(this);
  m_api->get(QStringLiteral("/api/pipelines/%1/plan/sources").arg(m_pipeline.value("pipeline_id").toString()), 8000, [guard, context, requestVersion](const QJsonObject &response) {
    if (!guard || context != guard->m_contextVersion || requestVersion != guard->m_requestVersion || !guard->m_plan.isEmpty()) return;
    guard->m_source->clear();
    if (response["status"].toString() != "ok") {
      guard->message(QStringLiteral("来源预案加载失败，请点击刷新重试。"), true);
      guard->updateControls();
      return;
    }
    for (const auto &value : response["data"].toArray()) {
      const auto playbook = value.toObject();
      guard->m_source->addItem(playbook["name"].toString(), playbook["playbook_id"].toString());
    }
    const int selected = guard->m_source->findData(guard->m_pipeline.value("generated_playbook_id").toString());
    if (selected >= 0) guard->m_source->setCurrentIndex(selected);
    const auto config = QJsonDocument::fromJson(guard->m_pipeline["config"].toString().toUtf8()).object();
    const bool sourceMode =QStringList{"source_assisted","program_dynamic"}.contains( (guard->m_pipeline["config"].isObject() ? guard->m_pipeline["config"].toObject() : config)["scan_mode"].toString());
    if (sourceMode) guard->message(guard->m_source->count() == 0
        ? QStringLiteral("尚未生成本任务的验证预案。点击“生成攻击测试预案”，选定对象后会生成步骤并自动建立草稿。")
        : QStringLiteral("已找到本任务生成的验证预案；选择来源并建立草稿即可查看执行步骤。"));
    guard->updateControls();
  });
}

void TaskPlanPage::render()
{
  m_rendering = true;
  const int selected = m_steps->currentRow();
  m_name->setText(m_content["name"].toString());
  m_notes->setPlainText(m_content["notes"].toString());
  if (!m_plan.isEmpty()) {
    m_source->clear();
    m_source->addItem(m_content["source_playbook"].toObject()["name"].toString(m_content["source_playbook_id"].toString()), m_content["source_playbook_id"].toString());
  }
  const auto steps = m_content["steps"].toArray();
  m_steps->setRowCount(steps.size());
  for (int row = 0; row < steps.size(); ++row) {
    const auto step = steps.at(row).toObject();
    m_steps->setItem(row, 0, new QTableWidgetItem(step["name"].toString()));
    m_steps->setItem(row, 1, new QTableWidgetItem(step["tool_id"].toString()));
    m_steps->setItem(row, 2, new QTableWidgetItem(jsonText(step["args_template"]).simplified().left(100)));
    m_steps->setItem(row, 3, new QTableWidgetItem(step["optional"].toBool() ? QStringLiteral("可选") : QStringLiteral("失败停止")));
  }
  if (!steps.isEmpty()) m_steps->selectRow(qBound(0, selected, steps.size() - 1));
  const auto suggestions = m_content["suggestions"].toArray();
  m_suggestions->setRowCount(0);
  m_suggestions->setRowCount(suggestions.size());
  for (int row = 0; row < suggestions.size(); ++row) {
    const auto item = suggestions.at(row).toObject();
    m_suggestions->setItem(row, 0, new QTableWidgetItem(QStringLiteral("%1 / 第 %2 项").arg(item["category"].toString()).arg(item["index"].toInt() + 1)));
    auto *summary = new QTableWidgetItem(jsonText(item["source"]).simplified().left(150));
    summary->setToolTip(jsonText(item["source"]).toHtmlEscaped());
    m_suggestions->setItem(row, 1, summary);
    auto *disposition = new QComboBox(m_suggestions);
    disposition->addItem(QStringLiteral("待处置"), "pending");
    disposition->addItem(QStringLiteral("接受（仅备注）"), "accepted");
    disposition->addItem(QStringLiteral("拒绝"), "rejected");
    disposition->setCurrentIndex(disposition->findData(item["status"].toString()));
    m_suggestions->setCellWidget(row, 2, disposition);
    connect(disposition, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this, row, disposition]() {
      if (m_rendering || m_busy || m_plan.value("state").toString() != "draft") return;
      auto items = m_content["suggestions"].toArray();
      if (row >= items.size()) return;
      auto suggestion = items.at(row).toObject();
      suggestion["status"] = disposition->currentData().toString();
      items[row] = suggestion;
      m_content["suggestions"] = items;
      markDirty();
    });
  }
  m_suggestionDetail->setPlainText(QStringLiteral("选择候选项查看来源快照；候选不是已验证结论。"));
  const auto history = m_plan.value("history").toArray();
  m_history->setRowCount(history.size());
  for (int row = 0; row < history.size(); ++row) {
    const auto item = history.at(row).toObject();
    const QStringList values = {item["created_at"].toString(), actionText(item["action"].toString()), QString::number(item["revision"].toInt()),
      QStringLiteral("%1 (%2)").arg(item["actor"].toString(), item["actor_role"].toString()), item["note"].toString()};
    for (int column = 0; column < values.size(); ++column) {
      auto *cell = new QTableWidgetItem(values.at(column));
      cell->setToolTip(values.at(column).toHtmlEscaped());
      m_history->setItem(row, column, cell);
    }
  }
  m_rendering = false;
  showStep();
  const auto config = m_pipeline.value("config").isObject() ? m_pipeline.value("config").toObject()
      : QJsonDocument::fromJson(m_pipeline.value("config").toString().toUtf8()).object();
  m_scope->setText(QStringLiteral("任务：%1 · 目标：%2\n任务ID：%4\n授权范围记录：%3（授权需人工核验；后端使用结构化范围限制调用）")
      .arg(config["task_name"].toString(m_pipeline.value("pipeline_id").toString()), m_pipeline.value("target").toString(), config["authorization_scope"].toString(QStringLiteral("未填写")), UiUtil::taskIdentifier(m_pipeline)));
  if (!m_content.isEmpty()) {
    const QString sourceName = m_content["source_playbook"].toObject()["name"].toString(m_content["source_playbook_id"].toString());
    m_scope->setText(m_scope->text() + QStringLiteral("\n来源预案：%1 · 当前任务独立审阅，批准后保留本任务执行版本。").arg(sourceName));
  }
  message(QStringLiteral("%1%2%3").arg(planState(m_plan.value("state").toString()),
      m_plan.isEmpty() ? QString() : QStringLiteral(" · v%1").arg(m_plan.value("revision").toInt()),
      m_dirty ? QStringLiteral(" · 未保存") : QString()));
  if (m_plan.value("state").toString() == "approved")
    message(QStringLiteral("审批通过 · 提审版本 v%1 · 当前记录 v%2；执行状态请查看任务头部。")
        .arg(m_plan.value("revision").toInt() - 1).arg(m_plan.value("revision").toInt()));
  if (m_plan.isEmpty() && m_pipeline.value("status").toString() != "awaiting_approval")
    message(QStringLiteral("当前任务不在待审批阶段；等待预案生成并进入待审批后再建立草稿。"));
  updateControls();
}

void TaskPlanPage::updateControls()
{
  const bool waiting = m_pipeline.value("status").toString() == "awaiting_approval";
  const QString state = m_plan.value("state").toString();
  const bool editable = waiting && state == "draft" && !m_busy;
  bool resolved = true;
  for (const auto &value : m_content["suggestions"].toArray())
    resolved = resolved && value.toObject()["status"].toString() != "pending";
  const auto config = m_pipeline.value("config").isObject() ? m_pipeline.value("config").toObject()
      : QJsonDocument::fromJson(m_pipeline.value("config").toString().toUtf8()).object();
  const bool selected = m_steps->currentRow() >= 0;
  const bool sourceMode =QStringList{"source_assisted","program_dynamic"}.contains( config["scan_mode"].toString());
  m_generateSource->setVisible(sourceMode && m_plan.isEmpty());
  m_generateSource->setEnabled(waiting && !m_busy && !m_dirty);
  m_refresh->setEnabled(!m_busy && !m_pipeline.isEmpty());
  m_source->setEnabled(waiting && m_plan.isEmpty() && !m_busy);
  m_create->setEnabled(waiting && m_plan.isEmpty() && !m_busy && m_source->count() > 0);
  m_name->setEnabled(editable);
  m_notes->setReadOnly(!editable);
  m_stepName->setEnabled(editable && selected);
  m_args->setReadOnly(!editable || !selected);
  m_optional->setEnabled(editable && selected);
  m_up->setEnabled(editable && m_steps->currentRow() > 0);
  m_down->setEnabled(editable && selected && m_steps->currentRow() < m_steps->rowCount() - 1);
  m_remove->setEnabled(editable && selected && m_steps->rowCount() > 1);
  m_save->setEnabled(editable && m_dirty);
  m_submit->setEnabled(editable && !m_dirty && resolved && config["authorization_confirmed"].toBool());
  m_submit->setToolTip(QStringLiteral("请先保存编辑、处置所有候选建议，并确认任务已有授权记录。"));
  m_reopen->setEnabled(waiting && !m_busy && (state == "submitted" || state == "rejected"));
  m_approve->setVisible(m_role == "admin");
  m_reject->setVisible(m_role == "admin");
  m_approve->setEnabled(m_role == "admin" && waiting && state == "submitted" && !m_busy);
  m_reject->setEnabled(m_role == "admin" && waiting && state == "submitted" && !m_busy);
  for (int row = 0; row < m_suggestions->rowCount(); ++row)
    if (auto *widget = m_suggestions->cellWidget(row, 2)) widget->setEnabled(editable);
}

void TaskPlanPage::markDirty()
{
  if (m_rendering) return;
  m_dirty = true;
  message(QStringLiteral("编辑中 · v%1 · 未保存；保存后才能提审").arg(m_plan.value("revision").toInt()));
  updateControls();
}

void TaskPlanPage::showStep()
{
  if (m_rendering) return;
  m_rendering = true;
  const int row = m_steps->currentRow();
  const auto steps = m_content["steps"].toArray();
  const auto step = row >= 0 && row < steps.size() ? steps.at(row).toObject() : QJsonObject{};
  m_stepName->setText(step["name"].toString());
  m_args->setPlainText(jsonText(step["args_template"]));
  m_optional->setChecked(step["optional"].toBool());
  m_rendering = false;
  updateControls();
}

void TaskPlanPage::editStep()
{
  if (m_rendering) return;
  const int row = m_steps->currentRow();
  auto steps = m_content["steps"].toArray();
  if (row < 0 || row >= steps.size()) return;
  auto step = steps.at(row).toObject();
  step["name"] = m_stepName->text();
  step["args_template"] = m_args->toPlainText();
  step["optional"] = m_optional->isChecked();
  steps[row] = step;
  m_content["steps"] = steps;
  m_steps->item(row, 0)->setText(m_stepName->text());
  m_steps->item(row, 2)->setText(m_args->toPlainText().simplified().left(100));
  m_steps->item(row, 3)->setText(m_optional->isChecked() ? QStringLiteral("可选") : QStringLiteral("失败停止"));
  markDirty();
}

void TaskPlanPage::moveStep(int direction)
{
  const int row = m_steps->currentRow();
  auto steps = m_content["steps"].toArray();
  const int next = row + direction;
  if (row < 0 || next < 0 || next >= steps.size()) return;
  const QJsonValue previous = steps.at(row);
  steps[row] = steps.at(next);
  steps[next] = previous;
  m_content["steps"] = steps;
  markDirty();
  render();
  m_steps->selectRow(next);
}

void TaskPlanPage::save()
{
  if (m_busy || !m_dirty) return;
  for (const auto &value : m_content["steps"].toArray()) {
    const auto step = value.toObject();
    const auto raw = step["args_template"];
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(jsonText(raw).toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isArray()) {
      message(QStringLiteral("步骤“%1”的参数必须是合法 JSON 字符串数组。").arg(step["name"].toString()), true);
      return;
    }
    for (const auto &arg : doc.array()) if (!arg.isString()) {
      message(QStringLiteral("步骤“%1”包含非字符串参数，请修改。").arg(step["name"].toString()), true);
      return;
    }
  }
  mutate({}, {{"revision", m_plan.value("revision")}, {"content", m_content}}, true);
}

void TaskPlanPage::transition(const QString &action)
{
  if (m_busy || m_dirty || m_plan.isEmpty()) return;
  QString note;
  const int context = m_contextVersion;
  const auto revision = m_plan.value("revision");
  if (action == "reject") {
    bool accepted = false;
    note = QInputDialog::getMultiLineText(this, QStringLiteral("驳回预案"), QStringLiteral("请填写驳回原因："), {}, &accepted);
    if (!accepted || note.trimmed().isEmpty()) return;
  }
  if (action == "approve") {
    const auto prompt = QStringLiteral("批准任务 %1 的预案 v%2 并启动执行？\n目标：%3\n执行采用已提审步骤的独立快照；不会接受模型临时新增步骤。")
        .arg(UiUtil::taskIdentifier(m_pipeline)).arg(m_plan.value("revision").toInt()).arg(m_pipeline.value("target").toString());
    if (QMessageBox::question(this, QStringLiteral("确认批准并执行"), prompt,
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
  }
  if (context != m_contextVersion || revision != m_plan.value("revision")) return;
  mutate('/' + action, {{"revision", revision}, {"note", note}}, false,
      action == "approve" ? std::function<void()>([this]() { emit executionStarted(); }) : nullptr);
}

void TaskPlanPage::mutate(const QString &suffix, const QJsonObject &body, bool put, std::function<void()> after)
{
  if (m_busy || m_pipeline.value("pipeline_id").toString().isEmpty()) return;
  m_busy = true;
  updateControls();
  const int context = m_contextVersion;
  const int request = ++m_requestVersion;
  QPointer<TaskPlanPage> guard(this);
  auto callback = [guard, context, request, after](const QJsonObject &response) {
    if (!guard || context != guard->m_contextVersion || request != guard->m_requestVersion) return;
    guard->m_busy = false;
    if (response["status"].toString() != "ok") {
      guard->message(response["error"].toObject()["message"].toString(QStringLiteral("操作失败，请刷新重试")), true);
      guard->updateControls();
      return;
    }
    const auto data = response["data"].toObject();
    if (data["pipeline_id"] != guard->m_pipeline.value("pipeline_id") || !data["content"].isObject()) {
      guard->message(QStringLiteral("操作响应任务标识或内容格式不匹配，请刷新核对服务端记录。"), true);
      guard->updateControls();
      return;
    }
    guard->m_plan = response["data"].toObject();
    guard->m_content = guard->m_plan.value("content").toObject();
    guard->m_dirty = false;
    guard->render();
    emit guard->planChanged();
    if (after && guard && context == guard->m_contextVersion) after();
    if (guard && context == guard->m_contextVersion && !guard->m_pendingSourcePlaybookId.isEmpty()) {
      const QString pending = guard->m_pendingSourcePlaybookId;
      guard->m_pendingSourcePlaybookId.clear();
      guard->useSourcePlaybook(pending);
    }
  };
  const auto path = QStringLiteral("/api/pipelines/%1/plan%2").arg(m_pipeline.value("pipeline_id").toString(), suffix);
  if (put) m_api->put(path, body, 12000, callback);
  else m_api->post(path, body, 12000, callback);
}

void TaskPlanPage::addCandidate(const QString &category, int index, const QJsonValue &source)
{
  if (m_busy || m_dirty || m_pipeline.value("status").toString() != "awaiting_approval") {
    message(QStringLiteral("请等待预案加载并先保存编辑；仅待审批任务可加入候选建议。"), true);
    return;
  }
  const QJsonObject candidate{{"category", category}, {"index", index}, {"source", source}};
  if (m_plan.isEmpty()) {
    const auto config = m_pipeline["config"].isObject() ? m_pipeline["config"].toObject()
        : QJsonDocument::fromJson(m_pipeline["config"].toString().toUtf8()).object();
    if (QStringList{"source_assisted","program_dynamic"}.contains(config["scan_mode"].toString())) {
      message(QStringLiteral("请先根据本任务漏洞发现生成预案；分析备注不会生成执行步骤。"), true);
      emit sourceVerificationRequested();
      return;
    }
    const QString playbookId = m_source->currentData().toString();
    if (playbookId.isEmpty()) {
      message(QStringLiteral("请先选择来源预案并建立草稿，再加入候选。"), true);
      return;
    }
    mutate({}, {{"playbook_id", playbookId}}, false, [this, candidate]() { sendCandidate(candidate); });
  } else sendCandidate(candidate);
}

void TaskPlanPage::useSourcePlaybook(const QString &playbookId)
{
  if (m_dirty || m_pipeline.value("status").toString() != "awaiting_approval") {
    message(QStringLiteral("仅待审批任务可建立演示草稿；请等待加载并先保存现有编辑。"), true);
    return;
  }
  if (m_busy) {
    m_pendingSourcePlaybookId = playbookId;
    message(QStringLiteral("验证预案已生成，任务草稿加载完成后会自动加入。"));
    return;
  }
  if (!m_plan.isEmpty()) {
    if (m_content["source_playbook_id"].toString() == playbookId) render();
    else message(QStringLiteral("当前任务已有草稿，已保留。新预案已保存，可在扫描页预览；现有草稿不会自动替换。"), true);
    return;
  }
  mutate({}, {{"playbook_id", playbookId}});
}

void TaskPlanPage::sendCandidate(const QJsonObject &candidate)
{
  auto body = candidate;
  body["revision"] = m_plan.value("revision");
  mutate("/suggestions", body);
}
