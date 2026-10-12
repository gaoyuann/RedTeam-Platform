#include "FlowPage.h"
#include "TaskAiPanel.h"
#include "AnalysisPage.h"
#include "TaskPlanPage.h"
#include "TaskOverviewPage.h"
#include "TaskLogPanel.h"
#include "StepIndicator.h"
#include "TopologyPage.h"
#include "ScanPage.h"
#include "ExecutionPage.h"
#include "EvaluatePage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/MetricCard.h"
#include "../widgets/WorkbenchTabs.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QTabWidget>
#include <QMenu>
#include <QAction>
#include <QDialog>
#include <QDialogButtonBox>
#include <QSplitter>
#include <QScrollArea>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonDocument>
#include <QDateTime>
#include <QTimer>
#include <QPointer>
#include <cmath>

// ── Step metadata ──────────────────────────────────────────────────────
static const QStringList STEP_NAMES = {
  QStringLiteral("任务准备"), QStringLiteral("扫描发现"),
  QStringLiteral("智能分析"), QStringLiteral("预案制定"),
  QStringLiteral("执行验证"), QStringLiteral("结果评估"),
};

static QJsonObject parseJsonObject(const QJsonValue &value)
{
  if (value.isObject()) return value.toObject();
  if (!value.isString()) return {};
  QJsonParseError error;
  const auto document = QJsonDocument::fromJson(value.toString().toUtf8(), &error);
  return error.error == QJsonParseError::NoError && document.isObject()
      ? document.object() : QJsonObject{};
}

static QString pipelineTaskName(const QJsonObject &pipeline)
{
  const auto config = parseJsonObject(pipeline.value(QStringLiteral("config")));
  const auto name = config.value(QStringLiteral("task_name")).toString().trimmed();
  return name.isEmpty()
      ? QStringLiteral("%1 安全测试").arg(pipeline.value(QStringLiteral("target")).toString())
      : name;
}

static QString pipelineTypeText(const QJsonObject &pipeline)
{
  const auto config = parseJsonObject(pipeline.value(QStringLiteral("config")));
  const auto type = config.value(QStringLiteral("test_type")).toString();
  if (type == QStringLiteral("web")) return QStringLiteral("Web 安全测试");
  if (type == QStringLiteral("host")) return QStringLiteral("主机安全测试");
  if (type == QStringLiteral("internal")) return QStringLiteral("内网渗透测试");
  return QStringLiteral("综合测试");
}

static QString pipelineProgressText(const QJsonObject &pipeline)
{
  const auto value = pipeline.value(QStringLiteral("progress"));
  if (!value.isDouble()) return QStringLiteral("未提供");
  const double progress = value.toDouble();
  if (!std::isfinite(progress) || progress < 0.0 || progress > 100.0)
    return QStringLiteral("未提供");
  const int decimals = std::floor(progress) == progress ? 0 : 1;
  return QStringLiteral("%1%").arg(QString::number(progress, 'f', decimals));
}

// Status is informational: a small pill rather than a full-height action.
static QString statusBadgeStyle(const QString &status)
{
  QString text = "#64748b", background = "#f1f5f9", border = "#e2e8f0";
  if (status == "completed") {
    text = "#15803d"; background = "#ecfdf3"; border = "#d1fadf";
  } else if (status == "running") {
    text = "#1d4ed8"; background = "#eff6ff"; border = "#dbeafe";
  } else if (status == "awaiting_approval" || status == "paused") {
    text = "#a16207"; background = "#fffbeb"; border = "#fef0c7";
  } else if (status == "failed") {
    text = "#b42318"; background = "#fef3f2"; border = "#fee4e2";
  }
  return QString("QLabel { color:%1; background:%2; border:1px solid %3; "
                 "border-radius:13px; padding:0 10px; font-size:12px; font-weight:500; }")
      .arg(text, background, border);
}

// ── FlowPage ───────────────────────────────────────────────────────────

FlowPage::FlowPage(ApiClient *api, const QString &role,
                   const QString &username, QWidget *parent)
    : QWidget(parent)
    , m_api(api)
    , m_role(role)
    , m_username(username)
    , m_stack(nullptr)
    , m_listView(nullptr)
    , m_flowTable(nullptr)
    , m_newBtn(nullptr)
    , m_refreshBtn(nullptr)
    , m_quickBtn(nullptr)
    , m_searchInput(nullptr)
    , m_filterCombo(nullptr)
    , m_totalCard(nullptr)
    , m_runningCard(nullptr)
    , m_pendingCard(nullptr)
    , m_completedCard(nullptr)
    , m_workbenchView(nullptr)
    , m_backBtn(nullptr)
    , m_targetLabel(nullptr)
    , m_statusLabel(nullptr)
    , m_startBtn(nullptr)
    , m_approveBtn(nullptr)
    , m_moreBtn(nullptr)
    , m_aiToggleBtn(nullptr)
    , m_logToggleBtn(nullptr)
    , m_cancelAction(nullptr)
    , m_deleteAction(nullptr)
    , m_reportAction(nullptr)
    , m_stepIndicator(nullptr)
    , m_stageTabs(nullptr)
    , m_topoTab(nullptr)
    , m_scanTab(nullptr)
    , m_execTab(nullptr)
    , m_evalTab(nullptr)
    , m_analysisTab(nullptr)
    , m_planTab(nullptr)
    , m_overviewTab(nullptr)
    , m_logPanel(nullptr)
    , m_aiPanel(nullptr)
{
  setupUI();

  // Auto-refresh every 5s: flow list + workbench detail (if visible).
  // The workbench detail poll is a fallback for WS events, which may not
  // always arrive promptly — without it the user has to exit and re-enter
  // to see pipeline progress.
  auto *timer = new QTimer(this);
  timer->setInterval(5000);
  connect(timer, &QTimer::timeout, this, [this]() {
    if (!isVisible()) return;
    if (m_stack->currentIndex() == 0) {
      refreshFlows();
    } else if (!m_selectedPipelineId.isEmpty()) {
      loadFlowDetail(m_selectedPipelineId);
      if (m_logPanel->isVisible()) m_logPanel->refresh();
    }
  });
  timer->start();
  refreshFlows();
}

void FlowPage::setupUI()
{
  setStyleSheet(Theme::PageStyle);

  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(0);

  m_stack = new QStackedWidget(this);
  layout->addWidget(m_stack);

  setupListView();
  setupWorkbenchView();

  m_stack->setCurrentIndex(0);
}

// ── List View ──────────────────────────────────────────────────────────

void FlowPage::setupListView()
{
  m_listView = new QWidget(this);
  auto *layout = new QVBoxLayout(m_listView);
  layout->setContentsMargins(24, 20, 24, 20);
  layout->setSpacing(14);

  auto *headerLayout = new QHBoxLayout;
  auto *titleLayout = new QVBoxLayout;
  titleLayout->setSpacing(3);
  auto *header = new QLabel(QStringLiteral("测试任务"), m_listView);
  header->setStyleSheet(QStringLiteral("font-size:24px; font-weight:700; color:#12213c;"));
  auto *subtitle = new QLabel(
      QStringLiteral("管理和执行安全测试任务，支持快速测试和完整任务流程。"), m_listView);
  subtitle->setStyleSheet(QStringLiteral("font-size:13px; color:#64748b;"));
  titleLayout->addWidget(header);
  titleLayout->addWidget(subtitle);
  headerLayout->addLayout(titleLayout);
  headerLayout->addStretch();

  m_quickBtn = new QPushButton(QStringLiteral("⚡ 快速测试"), m_listView);
  m_quickBtn->setProperty("primary", true);
  connect(m_quickBtn, &QPushButton::clicked, this, [this]() { createFlow(true); });
  headerLayout->addWidget(m_quickBtn);
  layout->addLayout(headerLayout);

  auto *metrics = new QHBoxLayout;
  metrics->setSpacing(12);
  m_totalCard = new MetricCard(QStringLiteral("任务总数"), QStringLiteral("#2563eb"), m_listView);
  m_runningCard = new MetricCard(QStringLiteral("进行中"), QStringLiteral("#0f766e"), m_listView);
  m_pendingCard = new MetricCard(QStringLiteral("待确认"), QStringLiteral("#d97706"), m_listView);
  m_completedCard = new MetricCard(QStringLiteral("已完成"), QStringLiteral("#16a34a"), m_listView);
  for (auto *card : {m_totalCard, m_runningCard, m_pendingCard, m_completedCard}) {
    metrics->addWidget(card, 1);
  }
  layout->addLayout(metrics);

  auto *toolbar = new QHBoxLayout;
  m_newBtn = new QPushButton(QStringLiteral("＋ 完整任务配置"), m_listView);
  m_newBtn->setProperty("primary", true);
  connect(m_newBtn, &QPushButton::clicked, this, [this]() { createFlow(false); });

  m_refreshBtn = new QPushButton(QStringLiteral("刷新"), m_listView);
  connect(m_refreshBtn, &QPushButton::clicked, this, &FlowPage::refreshFlows);

  m_searchInput = new QLineEdit(m_listView);
  m_searchInput->setPlaceholderText(QStringLiteral("搜索任务名称、目标、负责人…"));
  m_searchInput->setMinimumWidth(120);
  m_searchInput->setMaximumWidth(270);

  m_filterCombo = new QComboBox(m_listView);
  m_filterCombo->addItem(QStringLiteral("全部状态"), QString());
  m_filterCombo->addItem(QStringLiteral("待运行"), QStringLiteral("created"));
  m_filterCombo->addItem(QStringLiteral("进行中"), QStringLiteral("running"));
  m_filterCombo->addItem(QStringLiteral("已暂停"), QStringLiteral("paused"));
  m_filterCombo->addItem(QStringLiteral("待确认"), QStringLiteral("awaiting_approval"));
  m_filterCombo->addItem(QStringLiteral("已完成"), QStringLiteral("completed"));
  m_filterCombo->addItem(QStringLiteral("失败"), QStringLiteral("failed"));
  m_filterCombo->addItem(QStringLiteral("已取消"), QStringLiteral("cancelled"));
  m_filterCombo->setFixedWidth(140);
  connect(m_filterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
          this, &FlowPage::onFilterChanged);

  toolbar->addWidget(m_newBtn);
  toolbar->addSpacing(8);
  toolbar->addWidget(m_refreshBtn);
  toolbar->addWidget(m_searchInput, 1);
  toolbar->addWidget(new QLabel(QStringLiteral("状态:")));
  toolbar->addWidget(m_filterCombo);
  layout->addLayout(toolbar);

  connect(m_searchInput, &QLineEdit::textChanged, this, [this]() { loadFlows(); });

  // Hint label
  m_listState = new QLabel(
    QStringLiteral("双击打开任务 · 任务状态、进度和负责人来自后端真实记录"), m_listView);
  m_listState->setTextFormat(Qt::PlainText);
  m_listState->setWordWrap(true);
  m_listState->setStyleSheet(Theme::StatusInfoStyle);
  layout->addWidget(m_listState);

  // Flow table
  m_flowTable = new QTableWidget(0, 8, m_listView);
  UiUtil::EmptyHint::attach(m_flowTable, QStringLiteral("暂无测试任务"));
  m_flowTable->setHorizontalHeaderLabels(
    { QStringLiteral("任务名称"), QStringLiteral("目标范围"), QStringLiteral("任务类型"),
      QStringLiteral("状态"), QStringLiteral("进度"), QStringLiteral("创建时间"),
      QStringLiteral("负责人"), QStringLiteral("操作") });
  m_flowTable->setColumnWidth(0, 220);
  m_flowTable->setColumnWidth(1, 180);
  m_flowTable->setColumnWidth(2, 130);
  m_flowTable->setColumnWidth(3, 100);
  m_flowTable->setColumnWidth(4, 100);
  m_flowTable->setColumnWidth(5, 150);
  m_flowTable->setColumnWidth(6, 100);
  m_flowTable->setColumnWidth(7, 70);
  m_flowTable->horizontalHeader()->setStretchLastSection(false);
  m_flowTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_flowTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_flowTable->verticalHeader()->setVisible(false);
  m_flowTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_flowTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_flowTable->setAlternatingRowColors(true);
  m_flowTable->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_flowTable, &QTableWidget::cellDoubleClicked,
          this, &FlowPage::onFlowDoubleClicked);
  connect(m_flowTable, &QTableWidget::customContextMenuRequested,
          this, &FlowPage::onFlowContextMenu);
  layout->addWidget(m_flowTable, 1);

  m_stack->addWidget(m_listView);
}

// ── Workbench View ─────────────────────────────────────────────────────

void FlowPage::setupWorkbenchView()
{
  m_workbenchView = new QWidget(this);
  auto *layout = new QVBoxLayout(m_workbenchView);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(0);

  // Top bar
  auto *topBar = new QFrame(m_workbenchView);
  topBar->setObjectName("flowToolbar");
  topBar->setStyleSheet("QFrame#flowToolbar { background:#ffffff; border-bottom:1px solid #dbe3ef; }");
  auto *toolbarLayout = new QVBoxLayout(topBar);
  toolbarLayout->setContentsMargins(0, 8, 0, 8);
  toolbarLayout->setSpacing(6);
  auto *topLayout = new QHBoxLayout;
  toolbarLayout->addLayout(topLayout);
  topLayout->setContentsMargins(14, 0, 14, 0);
  topLayout->setSpacing(8);

  m_backBtn = new QPushButton(QStringLiteral("← 返回列表"), topBar);
  m_backBtn->setProperty("quiet", true);
  UiUtil::styleToolbarButton(m_backBtn);
  connect(m_backBtn, &QPushButton::clicked, this, &FlowPage::onBackToList);
  topLayout->addWidget(m_backBtn);

  auto *sep1 = new QFrame(topBar);
  sep1->setFrameShape(QFrame::VLine);
  sep1->setFixedHeight(22);
  sep1->setStyleSheet("color:#dbe3ef;");
  topLayout->addWidget(sep1);

  m_targetLabel = new QLabel(topBar);
  m_targetLabel->setTextFormat(Qt::PlainText);
  m_targetLabel->setStyleSheet("font-size:15px; font-weight:600; color:#1e293b;");
  m_targetLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
  m_targetLabel->setMinimumWidth(80);
  topLayout->addWidget(m_targetLabel, 1);

  m_statusLabel = new QLabel(topBar);
  m_statusLabel->setObjectName("flowStatusBadge");
  m_statusLabel->setFixedHeight(26);
  m_statusLabel->setAlignment(Qt::AlignCenter);
  m_statusLabel->setStyleSheet(statusBadgeStyle({}));
  topLayout->addWidget(m_statusLabel);

  auto *actionLayout = new QHBoxLayout;
  actionLayout->setContentsMargins(14, 0, 14, 0);
  actionLayout->setSpacing(8);
  toolbarLayout->addLayout(actionLayout);

  m_startBtn = new QPushButton(QStringLiteral("▶ 启动任务"), topBar);
  m_startBtn->setProperty("primary", true);
  UiUtil::styleToolbarButton(m_startBtn);
  m_startBtn->setVisible(false);
  connect(m_startBtn, &QPushButton::clicked, this, &FlowPage::onStartFlow);
  actionLayout->addWidget(m_startBtn);

  // Approve button (visible only when awaiting_approval)
  m_approveBtn = new QPushButton(QStringLiteral("审阅任务预案"), topBar);
  m_approveBtn->setProperty("primary", true);
  UiUtil::styleToolbarButton(m_approveBtn);
  m_approveBtn->setVisible(false);
  connect(m_approveBtn, &QPushButton::clicked, this, &FlowPage::onApproveFlow);
  actionLayout->addWidget(m_approveBtn);
  m_resultBtn = new QPushButton(QStringLiteral("查看结果"), topBar);
  m_resultBtn->setObjectName("flowResultButton");
  m_resultBtn->setProperty("primary", true);
  UiUtil::styleToolbarButton(m_resultBtn);
  m_resultBtn->hide();
  actionLayout->addWidget(m_resultBtn);
  connect(m_resultBtn, &QPushButton::clicked, this, [this]() {
    m_stageTabs->setCurrentWidget(m_evalTab);
    if (!m_lastLoadedRunId.isEmpty()) m_evalTab->showRun(m_lastLoadedRunId);
  });

  // ⋯ dropdown menu for secondary actions (cancel / delete / report)
  m_moreBtn = new QPushButton(QStringLiteral("⋯"), topBar);
  m_moreBtn->setObjectName("flowMoreButton");
  m_moreBtn->setProperty("iconOnly", true);
  m_moreBtn->setToolTip(QStringLiteral("更多操作"));
  m_moreBtn->setAccessibleName(QStringLiteral("更多任务操作"));
  UiUtil::styleToolbarButton(m_moreBtn);
  m_moreBtn->setFixedWidth(36);
  auto *moreMenu = new QMenu(m_moreBtn);
  moreMenu->setStyleSheet("QMenu { font-size:13px; padding:4px; }");
  m_cancelAction = moreMenu->addAction(QStringLiteral("取消任务"));
  m_deleteAction = moreMenu->addAction(QStringLiteral("删除任务"));
  m_reportAction = moreMenu->addAction(QStringLiteral("查看报告"));
  m_moreBtn->setMenu(moreMenu);
  connect(m_cancelAction, &QAction::triggered, this, &FlowPage::onCancelFlow);
  connect(m_deleteAction, &QAction::triggered, this, &FlowPage::onDeleteFlow);
  connect(m_reportAction, &QAction::triggered, [this]() {
    m_stageTabs->setCurrentWidget(m_evalTab);
    m_evalTab->showReports();         // 切到"测试报告"子页 + 刷新
  });
  actionLayout->addWidget(m_moreBtn);
  actionLayout->addStretch();

  m_aiToggleBtn = new QPushButton(QStringLiteral("AI 协作"), topBar);
  m_aiToggleBtn->setObjectName(QStringLiteral("taskAiToggleButton"));
  m_aiToggleBtn->setCheckable(true);
  m_aiToggleBtn->setChecked(true);
  m_aiToggleBtn->setToolTip(QStringLiteral("显示或收起任务级 AI 协作面板"));
  UiUtil::styleToolbarButton(m_aiToggleBtn);
  actionLayout->addWidget(m_aiToggleBtn);

  m_logToggleBtn = new QPushButton(QStringLiteral("任务日志"), topBar);
  m_logToggleBtn->setObjectName(QStringLiteral("taskLogToggleButton"));
  m_logToggleBtn->setCheckable(true);
  m_logToggleBtn->setEnabled(false);
  UiUtil::styleToolbarButton(m_logToggleBtn);
  actionLayout->addWidget(m_logToggleBtn);

  layout->addWidget(topBar);

  // Six user-facing phases map to the existing four backend execution steps.
  auto *progressFrame = new QFrame(m_workbenchView);
  progressFrame->setStyleSheet("background:#f8fbff;");
  auto *progressLayout = new QHBoxLayout(progressFrame);
  progressLayout->setContentsMargins(14, 6, 14, 6);
  m_stepIndicator = new StepIndicator(progressFrame);
  QVector<PhaseStep> initialPhases;
  for (int i = 0; i < STEP_NAMES.size(); ++i) {
    PhaseStep step;
    step.displayName = STEP_NAMES[i];
    step.status = QStringLiteral("pending");
    initialPhases.append(step);
  }
  m_stepIndicator->setPhases(initialPhases);
  progressLayout->addWidget(m_stepIndicator, 1);
  layout->addWidget(progressFrame);

  // Task workbench tabs preserve the selected pipeline context.
  m_stageTabs = new WorkbenchTabs(m_workbenchView, false);
  m_topoTab = new TopologyPage(m_api, m_role, m_username, m_stageTabs);
  m_scanTab = new ScanPage(m_api, m_role, m_username, m_stageTabs);
  m_scanTab->setTaskScope({});
  // 攻击 Tab：快速执行（原"多阶段战役"子 Tab 已移除）
  m_execTab = new ExecutionPage(m_api, m_role, m_username, m_stageTabs);
  m_evalTab = new EvaluatePage(m_api, m_role, m_username, m_stageTabs);
  m_overviewTab = new TaskOverviewPage(m_stageTabs);
  m_stageTabs->addTab(m_overviewTab, QStringLiteral("任务概况"));
  m_stageTabs->addTab(m_scanTab, QStringLiteral("扫描发现"));
  m_analysisTab = new AnalysisPage(m_stageTabs);
  m_stageTabs->addTab(m_analysisTab, QStringLiteral("智能分析"));
  m_stageTabs->addTab(m_topoTab, QStringLiteral("资产与拓扑"));
  m_planTab = new TaskPlanPage(m_api, m_role, m_stageTabs);
  m_stageTabs->addTab(m_planTab, QStringLiteral("任务预案"));
  m_stageTabs->addTab(m_execTab, QStringLiteral("执行验证"));
  m_stageTabs->addTab(m_evalTab, QStringLiteral("结果评估"));

  connect(m_execTab, &ExecutionPage::runSelected, this, [this](const QString &runId) {
    if (!m_selectedPipelineId.isEmpty() || m_stack->currentIndex() != 1) return;
    if (runId == m_workbenchRunId) return;
    m_workbenchRunId = runId;
    m_lastLoadedEvalRunId.clear();
    m_evalTab->clearRun();
  });
  connect(m_execTab, &ExecutionPage::runCompleted, this, &FlowPage::onRunCompleted);
  connect(m_stageTabs, &QTabWidget::currentChanged, this, [this](int index) {
    if (m_stageTabs->widget(index) == m_evalTab && m_stack->currentIndex() == 1 && !m_lastLoadedEvalRunId.isEmpty())
      m_evalTab->retryRun(m_lastLoadedEvalRunId);
  });

  // 演示动线：扫描结果漏洞 → 一键转入漏洞攻击 Tab（目标预填 + 预案匹配）
  connect(m_scanTab, &ScanPage::attackRequested, this, [this](const QString &target, const QString &vulnText, const QString &resultType) {
    m_execTab->attackFromVuln(target, vulnText, resultType);
    m_stageTabs->setCurrentWidget(m_execTab);
  });

  auto *workspace = new QSplitter(Qt::Horizontal, m_workbenchView);
  workspace->setObjectName(QStringLiteral("taskWorkspaceSplitter"));
  workspace->addWidget(m_stageTabs);
  m_aiPanel = new TaskAiPanel(m_api, workspace);
  workspace->addWidget(m_aiPanel);
  workspace->setChildrenCollapsible(false);
  workspace->setStretchFactor(0, 4);
  workspace->setStretchFactor(1, 1);
  workspace->setSizes({900, 330});
  auto *workspaceScroll = new QScrollArea(m_workbenchView);
  workspaceScroll->setObjectName(QStringLiteral("taskWorkspaceScroll"));
  workspaceScroll->setWidgetResizable(true);
  workspaceScroll->setFrameShape(QFrame::NoFrame);
  workspaceScroll->setWidget(workspace);
  auto *verticalWorkspace = new QSplitter(Qt::Vertical, m_workbenchView);
  verticalWorkspace->setObjectName(QStringLiteral("taskActivitySplitter"));
  verticalWorkspace->addWidget(workspaceScroll);
  m_logPanel = new TaskLogPanel(m_api, verticalWorkspace);
  verticalWorkspace->addWidget(m_logPanel);
  verticalWorkspace->setChildrenCollapsible(false);
  verticalWorkspace->setStretchFactor(0, 4);
  verticalWorkspace->setStretchFactor(1, 1);
  verticalWorkspace->setSizes({650, 220});
  m_logPanel->hide();
  connect(m_logToggleBtn, &QPushButton::toggled, m_logPanel, &QWidget::setVisible);
  layout->addWidget(verticalWorkspace, 1);
  m_aiPanel->setStage(m_stageTabs->tabText(m_stageTabs->currentIndex()));
  connect(m_aiToggleBtn, &QPushButton::toggled, m_aiPanel, &QWidget::setVisible);
  connect(m_stageTabs, &QTabWidget::currentChanged, this, [this](int index) {
    m_aiPanel->setStage(m_stageTabs->tabText(index));
  });
  connect(m_analysisTab, &AnalysisPage::refreshRequested, this, [this]() {
    if (!m_selectedPipelineId.isEmpty()) {
      m_lastDisplayedDetail = {};
      loadFlowDetail(m_selectedPipelineId);
    }
  });
  connect(m_overviewTab, &TaskOverviewPage::refreshRequested, this, [this]() {
    if (!m_selectedPipelineId.isEmpty()) {
      m_lastDisplayedDetail = {};
      loadFlowDetail(m_selectedPipelineId);
    }
  });
  connect(m_overviewTab, &TaskOverviewPage::stageRequested, this, &FlowPage::switchToStageTab);
  connect(m_analysisTab, &AnalysisPage::scanRequested, this, [this]() {
    m_stageTabs->setCurrentIndex(1);
  });
  connect(m_analysisTab, &AnalysisPage::assistantRequested, this, [this](const QString &question) {
    m_aiToggleBtn->setChecked(true);
    m_aiPanel->setQuestion(question);
  });
  connect(m_analysisTab, &AnalysisPage::planCandidateRequested, this,
      [this](const QString &category, int index, const QJsonValue &source) {
    m_stageTabs->setCurrentWidget(m_planTab);
    m_planTab->addCandidate(category, index, source);
  });
  connect(m_planTab, &TaskPlanPage::planChanged, this, [this]() {
    if (!m_selectedPipelineId.isEmpty()) loadFlowDetail(m_selectedPipelineId);
    refreshFlows();
  });
  connect(m_planTab, &TaskPlanPage::executionStarted, this, [this]() {
    if (m_stageTabs->currentWidget() == m_planTab) m_stageTabs->setCurrentWidget(m_execTab);
  });

  m_stack->addWidget(m_workbenchView);
}

// ── Status helpers ─────────────────────────────────────────────────────

QString FlowPage::statusIcon(const QString &status) const
{
  if (status == "running") return "●";
  if (status == "awaiting_approval") return QString();
  if (status == "completed") return "✓";
  if (status == "failed") return "✗";
  if (status == "cancelled") return "⊘";
  return "○";
}

QString FlowPage::statusText(const QString &status) const
{
  return UiUtil::taskStatusText(status);
}

QColor FlowPage::statusColor(const QString &status) const
{
  if (status == "running") return QColor("#2563eb");
  if (status == "awaiting_approval") return QColor("#8b5cf6");
  if (status == "completed") return QColor("#22c55e");
  if (status == "failed") return QColor("#ef4444");
  if (status == "cancelled") return QColor("#94a3b8");
  return QColor("#64748b");
}

QString FlowPage::flowIdAtRow(int row) const
{
  if (row < 0 || row >= m_flowTable->rowCount()) return QString();
  auto *item = m_flowTable->item(row, 3);
  return item ? item->data(Qt::UserRole).toString() : QString();
}

// ── Load flow list ─────────────────────────────────────────────────────

void FlowPage::refreshFlows()
{
  loadFlows();
}

void FlowPage::loadFlows()
{
  const int revision = ++m_flowListRequestRevision;
  m_flowListFresh = false;
  m_listState->setStyleSheet(Theme::StatusInfoStyle);
  m_listState->setText(QStringLiteral("正在读取任务列表…已有行暂不可打开，等待本次刷新。"));
  UiUtil::EmptyHint::setState(m_flowTable, QStringLiteral("正在读取任务列表…"));
  QPointer<FlowPage> guard(this);
  m_api->get("/api/pipelines", 5000, [this, guard, revision](const QJsonObject &res) {
    if (!guard || revision != m_flowListRequestRevision) return;
    if (res["status"].toString() != "ok" || !res["data"].isArray()) {
      m_flowTable->setRowCount(0);
      for (auto *card : {m_totalCard, m_runningCard, m_pendingCard, m_completedCard}) card->setValue(QStringLiteral("—"));
      m_listState->setStyleSheet(Theme::StatusErrorStyle);
      m_listState->setText(QStringLiteral("任务列表读取失败：%1。请刷新重试，不把失败当作没有任务。")
          .arg(res["error"].toObject()["message"].toString(QStringLiteral("任务列表格式无效"))));
      UiUtil::EmptyHint::setState(m_flowTable, QStringLiteral("任务列表读取失败，请刷新重试"), true);
      return;
    }

    auto arr = res["data"].toArray();
    QString filter = m_filterCombo ? m_filterCombo->currentData().toString() : QString();
    QString search = m_searchInput ? m_searchInput->text().trimmed() : QString();

    int runningCount = 0;
    int pendingCount = 0;
    int completedCount = 0;
    for (const auto &value : arr) {
      const auto pipeline = value.toObject();
      const auto status = pipeline["status"].toString();
      if (status == "running") ++runningCount;
      if (status == "awaiting_approval") ++pendingCount;
      if (status == "completed") ++completedCount;
    }
    m_totalCard->setValue(QString::number(arr.size()));
    m_runningCard->setValue(QString::number(runningCount));
    m_pendingCard->setValue(QString::number(pendingCount));
    m_completedCard->setValue(QString::number(completedCount));

    m_flowTable->setRowCount(0);
    int row = 0;
    for (int i = 0; i < arr.size(); i++) {
      auto p = arr[i].toObject();
      QString status = p["status"].toString();
      if (!filter.isEmpty() && status != filter) continue;

      QString pid = p["pipeline_id"].toString();
      QString target = p["target"].toString();
      QString created = p["created_at"].toString();
      QString taskName = pipelineTaskName(p);
      QString type = pipelineTypeText(p);
      QString owner = p["created_by"].toString();
      if (!search.isEmpty()) {
        const QString haystack = taskName + " " + target + " " + type + " " + owner;
        if (!haystack.contains(search, Qt::CaseInsensitive)) continue;
      }

      m_flowTable->insertRow(row);

      auto *nameItem = new QTableWidgetItem(taskName);
      nameItem->setToolTip(taskName);
      m_flowTable->setItem(row, 0, nameItem);

      auto *targetItem = new QTableWidgetItem(target);
      targetItem->setToolTip(target);
      m_flowTable->setItem(row, 1, targetItem);

      m_flowTable->setItem(row, 2, new QTableWidgetItem(type));

      // Status column stores pipeline_id in UserRole for row actions.
      auto *statusItem = new QTableWidgetItem(
        QStringLiteral("%1  %2").arg(statusIcon(status), statusText(status)));
      statusItem->setData(Qt::UserRole, pid);
      QColor sc = statusColor(status);
      statusItem->setForeground(sc);
      statusItem->setTextAlignment(Qt::AlignCenter);
      m_flowTable->setItem(row, 3, statusItem);

      const QString progressText = pipelineProgressText(p);
      auto *progressItem = new QTableWidgetItem(progressText);
      progressItem->setTextAlignment(Qt::AlignCenter);
      const bool progressKnown = progressText != QStringLiteral("未提供");
      progressItem->setForeground(progressKnown && status == "completed" ? QColor("#16a34a")
          : progressKnown ? QColor("#2563eb") : QColor("#64748b"));
      m_flowTable->setItem(row, 4, progressItem);

      auto dt = QDateTime::fromString(created, Qt::ISODate);
      QString displayTime = dt.isValid()
        ? dt.toString("MM-dd HH:mm:ss") : created.left(19);
      auto *timeItem = new QTableWidgetItem(displayTime);
      timeItem->setTextAlignment(Qt::AlignCenter);
      m_flowTable->setItem(row, 5, timeItem);

      m_flowTable->setItem(row, 6, new QTableWidgetItem(owner.isEmpty() ? QStringLiteral("—") : owner));
      auto *openItem = new QTableWidgetItem(QStringLiteral("进入"));
      openItem->setForeground(QColor("#2563eb"));
      openItem->setTextAlignment(Qt::AlignCenter);
      m_flowTable->setItem(row, 7, openItem);

      row++;
    }
    m_flowListFresh = true;
    UiUtil::EmptyHint::reset(m_flowTable);
    m_listState->setText(QStringLiteral("读取 %1 个可见任务，当前匹配 %2 个 · 双击打开任务；统计不是漏洞数量。")
        .arg(arr.size()).arg(row));
  });
}

// ── Load flow detail (workbench) ───────────────────────────────────────

void FlowPage::loadFlowDetail(const QString &pipelineId)
{
  const int contextRevision = m_taskContextRevision;
  const int requestRevision = ++m_taskDetailRequestRevision;
  QPointer<FlowPage> guard(this);
  m_api->get(QStringLiteral("/api/pipelines/%1").arg(pipelineId), 5000,
    [this, guard, pipelineId, contextRevision, requestRevision](const QJsonObject &res) {
    // Stale-response guard: if the user switched to a different flow while
    // this GET was in flight, skip the update to avoid overwriting the UI
    // with the wrong flow's data.
    if (!guard || pipelineId != m_selectedPipelineId || contextRevision != m_taskContextRevision ||
        requestRevision != m_taskDetailRequestRevision) return;
    if (res["status"].toString() != "ok") {
      m_lastDisplayedDetail = {};
      showTaskDetailError(res["error"].toObject()["message"].toString(QStringLiteral("后端未返回有效数据")));
      return;
    }

    auto p = res["data"].toObject();
    if (p.value("pipeline_id").toString() != pipelineId) {
      showTaskDetailError(QStringLiteral("响应任务标识不匹配"));
      m_lastDisplayedDetail = {};
      return;
    }
    m_logPanel->setTaskContext(pipelineId);
    m_logToggleBtn->setEnabled(true);
    QString target = p["target"].toString();
    QString status = p["status"].toString();
    // Still poll for changes, but stable completed/approval views need no rebuild.
    if (m_lastDetailPipelineId == pipelineId && m_lastDisplayedDetail == p
        && status != "running") return;
    m_lastDetailPipelineId = pipelineId;
    m_lastDisplayedDetail = p;
    m_aiPanel->setTaskContext(p);
    m_analysisTab->setTaskContext(p);
    m_overviewTab->setTaskContext(p);
    m_planTab->setTaskContext(p);

    // Sync target to all embedded stage tabs
    bool scanFinished = false;
    for (const auto &value : p["steps"].toArray()) {
      const auto step = value.toObject();
      if (step["step_type"].toString() == "scan")
        scanFinished = step["status"].toString() == "completed"
            || step["status"].toString() == "failed"
            || step["status"].toString() == "cancelled";
    }
    QStringList scopedScanIds;
    const auto summary = p.value("summary").toObject();
    if (summary.contains("scan_task_ids")) {
      for (const auto &value : summary.value("scan_task_ids").toArray()) scopedScanIds.append(value.toString());
    } else scopedScanIds = p.value("scan_task_id").toString().split(',', Qt::SkipEmptyParts);
    m_topoTab->setPipelineContext(pipelineId, target, scopedScanIds, scanFinished);
    m_scanTab->setTaskScope(scopedScanIds);
    m_scanTab->setTarget(target);
    m_execTab->setPipelineContext(pipelineId, status, p["run_id"].toString(), target);
    m_evalTab->setPipelineContext(pipelineId, p["run_id"].toString(), target);
    m_execTab->setTarget(target);
    m_evalTab->setTarget(target);

    // Header
    const QString taskTitle = pipelineTaskName(p);
    m_targetLabel->setText(QStringLiteral("%1 · %2").arg(taskTitle, target));
    m_targetLabel->setToolTip(QStringLiteral("任务：%1\n目标：%2").arg(taskTitle, target));
    m_statusLabel->setText(QStringLiteral("%1  %2").arg(statusIcon(status), statusText(status)));
    m_statusLabel->setStyleSheet(statusBadgeStyle(status));

    // 从 pipeline 数据提取 run_id 和 playbook_id，自动加载到攻击 Tab.
    // Guard against repeated events: only drive selectPlaybook/showRun when
    // the ID actually changes, so we don't reset the user's manual combo
    // selection or yank the sub-tab on every status tick.
    QString runId = p["run_id"].toString();
    m_workbenchRunId = runId;
    QString playbookId = p["generated_playbook_id"].toString();
    m_generatedPlaybookId = playbookId;
    if (!playbookId.isEmpty() && playbookId != m_lastLoadedPlaybookId) {
      m_lastLoadedPlaybookId = playbookId;
      m_execTab->selectPlaybook(playbookId, target);
    }
    if (!runId.isEmpty() && runId != m_lastLoadedRunId) {
      m_lastLoadedRunId = runId;
      m_execTab->showRun(runId, false);
    }

    // 评估 Tab：pipeline 完成后预加载该 run 的评分（兜底，不切 stage tab —
    // stage tab 的切换由 onPipelineStatus 在完成事件到达时驱动，避免打开已
    // 完成的流水线时强制跳到评估 Tab）
    if (!runId.isEmpty() && (status == "completed" || status == "failed") && runId != m_lastLoadedEvalRunId) {
      onRunCompleted(runId);
    }
    if (!m_pendingTaskReportId.isEmpty()) {
      const QString reportId = m_pendingTaskReportId;
      m_pendingTaskReportId.clear();
      m_evalTab->showReport(reportId);
    }

    // Step progress → StepIndicator
    auto steps = p["steps"].toArray();
    QVector<PhaseStep> phaseSteps;
    for (int i = 0; i < STEP_NAMES.size(); i++) {
      PhaseStep ps;
      ps.displayName = STEP_NAMES[i];
      ps.phaseId = QStringLiteral("step_%1").arg(i + 1);
      ps.status = QStringLiteral("pending");
      if (i == 0) {
        ps.phaseType = QStringLiteral("prepare");
        const auto recordedConfig = p.value("config").isObject() ? p.value("config").toObject()
            : QJsonDocument::fromJson(p.value("config").toString().toUtf8()).object();
        const bool recordedAuthorization = recordedConfig.value("authorization_confirmed").toBool();
        ps.status = recordedAuthorization ? QStringLiteral("completed") : QStringLiteral("pending");
        ps.summary = recordedAuthorization ? QStringLiteral("用户已记录授权确认") : QStringLiteral("授权确认记录未提供");
      } else if (i == 1 && steps.size() > 0) {
        auto step = steps[0].toObject();
        ps.phaseType = step["step_type"].toString();
        ps.status = step["status"].toString();

        // Summary from output_data
        const auto output = step["output_data"].toObject();
        if (ps.status == "completed") {
          if (ps.phaseType == "scan") {
            int totalResults = output["total_results"].toInt(0);
            ps.summary = output.contains("total_results") ? QStringLiteral("发现 %1 条结果").arg(totalResults) : QStringLiteral("发现统计未提供");
          } else if (ps.phaseType == "analyze") {
            auto attackSurface = output["attack_surface"].toArray();
            ps.summary = output.contains("attack_surface") ? QStringLiteral("攻击面 %1 项").arg(attackSurface.size()) : QStringLiteral("攻击面统计未提供");
          } else if (ps.phaseType == "generate") {
            QString method = output["method"].toString();
            QString name = output["name"].toString();
            ps.summary = QStringLiteral("%1: %2").arg(
              method == "ai_generated" ? "AI生成" : "匹配", name);
          } else if (ps.phaseType == "execute") {
            QString runId = output["run_id"].toString();
            ps.summary = QStringLiteral("执行已结束，可查看结果");
          }
        } else if (ps.status == "failed") {
          ps.summary = step["error_message"].toString();
        }
      } else if (i == 2 && steps.size() > 1) {
        auto step = steps[1].toObject();
        ps.phaseType = step["step_type"].toString();
        ps.status = step["status"].toString();
        const auto output = step["output_data"].toObject();
        if (ps.status == "completed") {
          auto attackSurface = output["attack_surface"].toArray();
          ps.summary = output.contains("attack_surface") ? QStringLiteral("攻击面 %1 项").arg(attackSurface.size()) : QStringLiteral("攻击面统计未提供");
        } else if (ps.status == "failed") {
          ps.summary = step["error_message"].toString();
        }
      } else if (i == 3 && steps.size() > 2) {
        auto step = steps[2].toObject();
        ps.phaseType = step["step_type"].toString();
        ps.status = step["status"].toString();
        const auto output = step["output_data"].toObject();
        if (ps.status == "completed") {
          QString method = output["method"].toString();
          QString name = output["name"].toString();
          ps.summary = QStringLiteral("%1: %2").arg(
              method == "ai_generated" ? "AI生成" : "匹配", name);
        } else if (ps.status == "failed") {
          ps.summary = step["error_message"].toString();
        }
      } else if (i == 4 && steps.size() > 3) {
        auto step = steps[3].toObject();
        ps.phaseType = step["step_type"].toString();
        ps.status = step["status"].toString();
        const auto output = step["output_data"].toObject();
        if (ps.status == "completed") {
          ps.summary = QStringLiteral("执行已结束，可查看证据");
        } else if (ps.status == "failed") {
          ps.summary = step["error_message"].toString();
        }
      }
      if (i == 5 && status == "completed") {
        ps.status = "completed";
        ps.summary = QStringLiteral("结果已生成，可进行核验");
      } else if (i == 5 && status == "failed") {
        ps.status = "failed";
        ps.summary = QStringLiteral("任务执行失败，请查看日志");
      } else if (i == 3 && status == "awaiting_approval") {
        ps.status = "awaiting_approval";
        ps.summary = QStringLiteral("预案已就绪，等待人工审批");
      }
      if (ps.phaseType == "execute" && status == "awaiting_approval") {
        ps.status = "awaiting_approval";
        ps.summary = QStringLiteral("预案已就绪，等待确认");
      }
      phaseSteps.append(ps);
    }
    m_stepIndicator->setPhases(phaseSteps);

    // Refresh the embedded scan tab while the scan phase is active, so it
    // picks up new tasks / results (loadFlowDetail is called by the 5s poll
    // timer and WS events, not just on entry).
    for (int i = 0; i < steps.size(); i++) {
      auto step = steps[i].toObject();
      if (step["step_type"].toString() == "scan") {
        QString sStatus = step["status"].toString();
        if (sStatus == "running" || sStatus == "completed") {
          m_scanTab->onRefreshTasks();
          break;
        }
      }
    }


    // Action visibility based on status
    bool isAwaiting = (status == "awaiting_approval");
    bool isActive = (status == "running" || status == "awaiting_approval");
    bool isDeletable = !isActive;  // backend refuses delete on running/awaiting
    m_startBtn->setVisible(status == "created");
    m_approveBtn->setVisible(isAwaiting);
    m_resultBtn->setVisible((status == "completed" || status == "failed") && !runId.isEmpty());
    m_cancelAction->setVisible(isActive);
    m_deleteAction->setVisible(isDeletable);
    m_reportAction->setVisible((status == "completed" || status == "failed") && !runId.isEmpty());
    // Hide ⋯ button entirely if no actions are available
    m_moreBtn->setVisible(isActive || isDeletable || status == "completed");
  });
}

// ── Create flow ────────────────────────────────────────────────────────

void FlowPage::onCreateFlow()
{
  createFlow(false);
}

void FlowPage::createFlow(bool quickMode)
{
  QDialog dlg(this);
  dlg.setWindowTitle(QStringLiteral("新建测试任务"));
  dlg.setMinimumWidth(quickMode ? 480 : 560);
  auto *l = new QVBoxLayout(&dlg);
  l->setSpacing(12);
  l->setContentsMargins(20, 20, 20, 20);

  if (quickMode) {
    auto *intro = new QLabel(QStringLiteral("快速测试会创建正式测试任务并启动基础扫描。"), &dlg);
    intro->setWordWrap(true);
    intro->setStyleSheet(QStringLiteral("color:#64748b;"));
    l->addWidget(intro);
  }

  auto *form = new QFormLayout;
  QLineEdit *nameInput = nullptr;
  if (!quickMode) {
    nameInput = new QLineEdit(&dlg);
    nameInput->setPlaceholderText(QStringLiteral("例如：本地测试环境安全验证"));
    form->addRow(QStringLiteral("任务名称"), nameInput);
  }

  auto *targetInput = new QLineEdit(&dlg);
  targetInput->setPlaceholderText(QStringLiteral("例: 192.168.1.0/24 或 http://172.17.0.2"));
  form->addRow(QStringLiteral("测试目标"), targetInput);

  auto *testType = new QComboBox(&dlg);
  testType->addItem(QStringLiteral("综合测试"), QStringLiteral("comprehensive"));
  testType->addItem(QStringLiteral("Web 安全测试"), QStringLiteral("web"));
  testType->addItem(QStringLiteral("主机安全测试"), QStringLiteral("host"));
  testType->addItem(QStringLiteral("内网渗透测试"), QStringLiteral("internal"));
  if (!quickMode) form->addRow(QStringLiteral("任务类型"), testType);

  QLineEdit *scopeInput = nullptr;
  if (!quickMode) {
    scopeInput = new QLineEdit(&dlg);
    scopeInput->setPlaceholderText(QStringLiteral("仅填写已获得授权的目标或范围"));
    form->addRow(QStringLiteral("授权范围"), scopeInput);
  }
  l->addLayout(form);

  auto *authorizationCheck = new QCheckBox(QStringLiteral("我确认已获得对上述目标开展测试的授权"), &dlg);
  authorizationCheck->setChecked(false);
  l->addWidget(authorizationCheck);

  auto *approvalCheck = new QCheckBox(QStringLiteral("执行验证前需人工确认"), &dlg);
  approvalCheck->setChecked(true);
  l->addWidget(approvalCheck);

  auto *btns = new QDialogButtonBox(
    QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);

  UiUtil::styleDialogButtons(btns);
  auto *confirmButton = btns->button(QDialogButtonBox::Ok);
  confirmButton->setText(quickMode ? QStringLiteral("授权并开始快速测试")
                                   : QStringLiteral("创建任务"));
  confirmButton->setEnabled(false);
  connect(authorizationCheck, &QCheckBox::toggled, confirmButton, &QPushButton::setEnabled);
  connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  l->addWidget(btns);

  if (dlg.exec() != QDialog::Accepted) return;

  QString target = targetInput->text().trimmed();
  if (target.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("无法创建任务"), QStringLiteral("请先填写测试目标。"));
    return;
  }
  const QString taskName = nameInput ? nameInput->text().trimmed()
      : QStringLiteral("%1 快速测试").arg(target);
  if (taskName.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("无法创建任务"), QStringLiteral("请填写任务名称。"));
    return;
  }
  if (scopeInput && scopeInput->text().trimmed().isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("无法创建任务"), QStringLiteral("请填写已获授权的测试范围。"));
    return;
  }

  QJsonObject config;
  config["require_approval"] = approvalCheck->isChecked();
  config["auto_execute"] = true;
  config["task_name"] = taskName;
  config["test_type"] = testType->currentData().toString();
  config["authorization_confirmed"] = authorizationCheck->isChecked();
  config["authorization_scope"] = scopeInput ? scopeInput->text().trimmed() : target;
  config["creation_mode"] = quickMode ? QStringLiteral("quick") : QStringLiteral("full");
  config["created_by_label"] = m_username;
  QJsonObject body;
  body["target"] = target;
  body["config"] = config;

  m_newBtn->setEnabled(false);
  m_quickBtn->setEnabled(false);

  m_api->post("/api/pipelines", body, 10000, [this, quickMode](const QJsonObject &res) {
    m_newBtn->setEnabled(true);
    m_quickBtn->setEnabled(true);
    if (res["status"].toString() != "ok") {
      QMessageBox::warning(this, QStringLiteral("任务创建失败"),
          res["error"].toObject()["message"].toString());
      return;
    }

    QString pipelineId = res["data"].toObject()["pipeline_id"].toString();
    refreshFlows();
    if (!quickMode) return;
    m_api->post(QStringLiteral("/api/pipelines/%1/start").arg(pipelineId),
                QJsonObject{}, 10000, [this, pipelineId](const QJsonObject &startResponse) {
      if (startResponse["status"].toString() != "ok") {
        QMessageBox::warning(this, QStringLiteral("任务已创建"),
            QStringLiteral("任务已保存，但启动失败：%1")
                .arg(startResponse["error"].toObject()["message"].toString()));
      }
      refreshFlows();
      const int row = [&]() {
        for (int index = 0; index < m_flowTable->rowCount(); ++index) {
          if (flowIdAtRow(index) == pipelineId) return index;
        }
        return -1;
      }();
      if (row >= 0) onFlowDoubleClicked(row);
    });
  });
}

// ── Flow selection & navigation ────────────────────────────────────────

void FlowPage::onFlowDoubleClicked(int row)
{
  if (!m_flowListFresh) return;
  QString pid = flowIdAtRow(row);
  if (pid.isEmpty()) return;
  m_selectedPipelineId = pid;
  clearRunContext();
  m_lastDisplayedDetail = {};
  m_resultBtn->hide();
  m_execTab->setPipelineContext(pid, "loading", {});
  m_evalTab->setPipelineContext(pid, {});
  m_analysisTab->setLoading();
  m_overviewTab->setLoading();
  m_topoTab->setPipelineContext(pid, {}, {}, false);
  loadFlowDetail(pid);
  m_stack->setCurrentIndex(1);
  // Refresh the embedded scan tab so it picks up any new scan tasks
  m_scanTab->onRefreshTasks();
}

void FlowPage::onFlowContextMenu(const QPoint &pos)
{
  if (!m_flowListFresh) return;
  int row = m_flowTable->rowAt(pos.y());
  if (row < 0) return;
  QString pid = flowIdAtRow(row);
  if (pid.isEmpty()) return;

  // Read status from the item text (stored as "icon  text")
  QString statusText = m_flowTable->item(row, 3)->text();
  bool isActive = statusText.contains("进行中") || statusText.contains("待确认");

  auto *menu = new QMenu(this);
  menu->addAction(QStringLiteral("打开"), [this, pid]() {
    m_selectedPipelineId = pid;
    clearRunContext();
    m_resultBtn->hide();
    m_execTab->setPipelineContext(pid, "loading", {});
    m_evalTab->setPipelineContext(pid, {});
    m_analysisTab->setLoading();
    m_overviewTab->setLoading();
    m_topoTab->setPipelineContext(pid, {}, {}, false);
    loadFlowDetail(pid);
    m_stack->setCurrentIndex(1);
  });
  if (isActive) {
    menu->addAction(QStringLiteral("取消"), [this, pid]() {
      m_api->post(QStringLiteral("/api/pipelines/%1/cancel").arg(pid),
                  QJsonObject{}, 5000, [this](const QJsonObject &) {
        refreshFlows();
      });
    });
  } else {
    menu->addAction(QStringLiteral("删除"), [this, pid]() {
      if (QMessageBox::question(this, QStringLiteral("删除任务"),
            QStringLiteral("确定删除此测试任务？此操作不可撤销。"),
            QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        m_api->del(QStringLiteral("/api/pipelines/%1").arg(pid), 5000,
                   [this](const QJsonObject &) {
          refreshFlows();
        });
      }
    });
  }
  menu->exec(m_flowTable->viewport()->mapToGlobal(pos));
}

void FlowPage::onOpenFlow()
{
  int row = m_flowTable->currentRow();
  if (row < 0) return;
  onFlowDoubleClicked(row);
}

void FlowPage::onBackToList()
{
  const int returnPage = m_returnPage;
  m_selectedPipelineId.clear();
  clearRunContext();
  m_stack->setCurrentIndex(0);
  if (returnPage >= 0) emit returnPageRequested(returnPage);
  else refreshFlows();
}

void FlowPage::setReturnPage(int page, const QString &title)
{
  m_returnPage = page;
  m_backBtn->setText(QStringLiteral("← 返回%1").arg(title));
  m_backBtn->setToolTip(QStringLiteral("返回来源页面；保留其筛选和分页条件，不取消后台任务。"));
}

void FlowPage::onFilterChanged(int)
{
  loadFlows();
}

// ── Workbench actions ──────────────────────────────────────────────────

void FlowPage::onCancelFlow()
{
  if (m_selectedPipelineId.isEmpty()) return;
  QString pid = m_selectedPipelineId;
  m_api->post(QStringLiteral("/api/pipelines/%1/cancel").arg(pid),
              QJsonObject{}, 5000, [this, pid](const QJsonObject &) {
    refreshFlows();
    loadFlowDetail(pid);
  });
}

void FlowPage::onDeleteFlow()
{
  if (m_selectedPipelineId.isEmpty()) return;
  QString pid = m_selectedPipelineId;
  if (QMessageBox::question(this, QStringLiteral("删除任务"),
        QStringLiteral("确定删除此测试任务？此操作不可撤销。"),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;

  m_api->del(QStringLiteral("/api/pipelines/%1").arg(pid), 5000,
             [this](const QJsonObject &) {
    m_stack->setCurrentIndex(0);
    refreshFlows();
  });
}

void FlowPage::onApproveFlow()
{
  m_stageTabs->setCurrentWidget(m_planTab);
}

void FlowPage::onStartFlow()
{
  if (m_selectedPipelineId.isEmpty()) return;
  const QString pipelineId = m_selectedPipelineId;
  m_startBtn->setEnabled(false);
  m_startBtn->setText(QStringLiteral("启动中…"));
  m_api->post(QStringLiteral("/api/pipelines/%1/start").arg(pipelineId),
              QJsonObject{}, 10000, [this, pipelineId](const QJsonObject &response) {
    m_startBtn->setEnabled(true);
    m_startBtn->setText(QStringLiteral("▶ 启动任务"));
    if (response.value(QStringLiteral("status")).toString() != QStringLiteral("ok")) {
      QMessageBox::warning(this, QStringLiteral("任务启动失败"),
          response.value(QStringLiteral("error")).toObject()
              .value(QStringLiteral("message")).toString());
    }
    refreshFlows();
    if (pipelineId == m_selectedPipelineId) loadFlowDetail(pipelineId);
  });
}


void FlowPage::onPipelineCreated(const QJsonObject &)
{
  refreshFlows();
}

void FlowPage::onPipelineStatus(const QJsonObject &data)
{
  const QString pipelineId = data["pipeline_id"].toString();
  if (pipelineId == m_selectedPipelineId && m_stack->currentIndex() == 1)
    loadFlowDetail(pipelineId);
  refreshFlows();
}

void FlowPage::onPipelineStep(const QJsonObject &data)
{
  const QString pipelineId = data["pipeline_id"].toString();
  if (pipelineId == m_selectedPipelineId && m_stack->currentIndex() == 1)
    loadFlowDetail(pipelineId);
}

void FlowPage::onPipelineLog(const QJsonObject &data)
{
  if (data.value("pipeline_id").toString() == m_selectedPipelineId && m_stack->currentIndex() == 1
      && m_logPanel->isVisible()) m_logPanel->refresh();
}

TopologyPage *FlowPage::topoTab() const
{
  return m_topoTab;
}

ScanPage *FlowPage::scanTab() const
{
  return m_scanTab;
}

ExecutionPage *FlowPage::execTab() const
{
  return m_execTab;
}

EvaluatePage *FlowPage::evalTab() const
{
  return m_evalTab;
}

void FlowPage::clearRunContext()
{
  m_returnPage = -1;
  m_backBtn->setText(QStringLiteral("← 返回列表"));
  m_backBtn->setToolTip(QStringLiteral("返回任务列表，不取消后台任务。"));
  m_pendingTaskReportId.clear();
  ++m_taskContextRevision;
  ++m_taskDetailRequestRevision;
  m_aiPanel->clearTaskContext();
  m_analysisTab->clearTaskContext();
  m_planTab->clearTaskContext();
  m_overviewTab->clearTaskContext();
  m_logPanel->clearTaskContext();
  m_topoTab->setPipelineContext({}, {}, {}, false);
  m_scanTab->clearTaskScope();
  m_logToggleBtn->setChecked(false);
  m_logToggleBtn->setEnabled(false);
  m_lastDisplayedDetail = {};
  m_lastDetailPipelineId.clear();
  m_workbenchRunId.clear();
  m_lastLoadedRunId.clear();
  m_lastLoadedPlaybookId.clear();
  m_lastLoadedEvalRunId.clear();
  m_generatedPlaybookId.clear();
  m_execTab->clearRunContext();
  m_evalTab->clearRun();
  m_targetLabel->setText(QStringLiteral("任务详情加载中…"));
  m_targetLabel->setToolTip(QString());
  m_statusLabel->setText(QStringLiteral("等待任务数据"));
  m_statusLabel->setStyleSheet(statusBadgeStyle({}));
  QVector<PhaseStep> pendingPhases;
  for (const auto &name : STEP_NAMES) {
    PhaseStep phase;
    phase.displayName = name;
    phase.status = QStringLiteral("pending");
    pendingPhases.append(phase);
  }
  m_stepIndicator->setPhases(pendingPhases);
  m_startBtn->setVisible(false);
  m_startBtn->setEnabled(true);
  m_startBtn->setText(QStringLiteral("▶ 启动任务"));
  m_approveBtn->setVisible(false);
  m_resultBtn->setVisible(false);
  m_moreBtn->setVisible(false);
  m_cancelAction->setVisible(false);
  m_deleteAction->setVisible(false);
  m_reportAction->setVisible(false);
}

void FlowPage::showTaskDetailError(const QString &message)
{
  m_targetLabel->setText(QStringLiteral("任务详情加载失败"));
  m_targetLabel->setToolTip(message);
  m_statusLabel->setText(QStringLiteral("加载失败"));
  m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
  m_analysisTab->showError(message);
  m_overviewTab->showError(message);
  m_scanTab->showTaskContextError(message);
}

void FlowPage::onRunCompleted(const QString &runId)
{
  if (m_stack->currentIndex() != 1 || runId.isEmpty() || runId != m_workbenchRunId) return;
  if (runId == m_lastLoadedEvalRunId) return;
  m_lastLoadedEvalRunId = runId;
  m_evalTab->showRun(runId, false);
}

void FlowPage::switchToStageTab(int idx)
{
  if (m_stageTabs && idx >= 0 && idx < m_stageTabs->count())
    m_stageTabs->setCurrentIndex(idx);
}

void FlowPage::openTaskAnalysis(const QString &pipelineId)
{
  if (pipelineId.isEmpty()) return;
  clearRunContext();
  m_selectedPipelineId = pipelineId;
  m_resultBtn->hide();
  m_execTab->setPipelineContext(pipelineId, "loading", {});
  m_evalTab->setPipelineContext(pipelineId, {});
  m_analysisTab->setLoading();
  m_overviewTab->setLoading();
  m_topoTab->setPipelineContext(pipelineId, {}, {}, false);
  m_stack->setCurrentIndex(1);
  m_stageTabs->setCurrentWidget(m_analysisTab);
  loadFlowDetail(pipelineId);
}

void FlowPage::openTaskReport(const QString &pipelineId, const QString &reportId)
{
  if (pipelineId.isEmpty() || reportId.isEmpty()) return;
  clearRunContext();
  m_selectedPipelineId = pipelineId;
  m_pendingTaskReportId = reportId;
  m_resultBtn->hide();
  m_execTab->setPipelineContext(pipelineId, "loading", {});
  m_evalTab->setPipelineContext(pipelineId, {});
  m_analysisTab->setLoading();
  m_overviewTab->setLoading();
  m_topoTab->setPipelineContext(pipelineId, {}, {}, false);
  m_stack->setCurrentIndex(1);
  m_stageTabs->setCurrentWidget(m_evalTab);
  loadFlowDetail(pipelineId);
}

void FlowPage::jumpToExecution(const QString &playbookId, const QString &target)
{
  // Clear pipeline context — this is a direct execution, not a pipeline view
  m_selectedPipelineId.clear();
  clearRunContext();
  m_execTab->setPipelineContext({}, {}, {});
  m_evalTab->setPipelineContext({}, {});

  // Show "direct execution" in the workbench header
  m_targetLabel->setText(QStringLiteral("直接执行: %1").arg(
    target.isEmpty() ? QStringLiteral("(未指定)") : target));
  m_statusLabel->setText(QStringLiteral(" 直接执行模式 "));
  m_statusLabel->setStyleSheet(statusBadgeStyle({}));

  // Hide pipeline-specific action buttons
  m_startBtn->setVisible(false);
  m_approveBtn->setVisible(false);
  m_resultBtn->hide();
  m_moreBtn->setVisible(false);

  // Switch to workbench + attack tab
  m_stack->setCurrentIndex(1);
  m_stageTabs->setCurrentWidget(m_execTab);

  // Pre-select the playbook
  if (!playbookId.isEmpty())
    m_execTab->selectPlaybook(playbookId, target);
}
