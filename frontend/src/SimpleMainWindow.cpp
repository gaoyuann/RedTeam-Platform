#include "SimpleMainWindow.h"
#include "ApiClient.h"
#include "LoginDialog.h"
#include "Theme.h"
#include "WsClient.h"
#include "LiveActivityPanel.h"
#include "ToastOverlay.h"
#include "pages/DashboardPage.h"
#include "pages/ScanPage.h"
#include "pages/ExecutionPage.h"
#include "pages/EvaluatePage.h"
#include "pages/PayloadPage.h"
#include "pages/PlaybookPage.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFrame>
#include <QScrollArea>
#include <QSplitter>
#include <QStatusBar>
#include <QMessageBox>
#include <QApplication>
#include <QSettings>
#include <QCompleter>
#include <QStringListModel>
#include <QHeaderView>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonDocument>
#include <QTextEdit>
#include <QUuid>
#include <QResizeEvent>

// ── Formatting helpers ────────────────────────────────────────────────

static QString formatSeverity(const QString &s) {
  QString sl = s.toLower();
  if (sl == "critical") return QStringLiteral("严重");
  if (sl == "high")     return QStringLiteral("高危");
  if (sl == "medium")   return QStringLiteral("中危");
  if (sl == "low")      return QStringLiteral("低危");
  if (sl == "info" || sl == "inf") return QStringLiteral("信息");
  return s;
}

static QString formatTime(const QString &iso) {
  if (iso.isEmpty()) return "";
  auto dt = QDateTime::fromString(iso, Qt::ISODate);
  if (!dt.isValid()) return iso.left(16);
  return dt.toString("MM-dd HH:mm");
}

// ── SimpleMainWindow ──────────────────────────────────────────────────

SimpleMainWindow::SimpleMainWindow(ApiClient *api, const QString &role,
                                   const QString &username,
                                   QWidget *parent)
    : QMainWindow(parent)
    , m_api(api)
    , m_role(role)
    , m_username(username)
    , m_ws(nullptr)
    , m_activityPanel(nullptr)
    , m_toastOverlay(nullptr)
{
  setupUI();
  setupWebSocket();
  loadHistory();
}

void SimpleMainWindow::setupUI()
{
  setWindowTitle(QStringLiteral("信息系统渗透智能化测试平台"));
  resize(1280, 800);
  setMinimumSize(1024, 600);

  auto *centralWidget = new QWidget(this);
  centralWidget->setObjectName("contentArea");
  auto *mainLayout = new QHBoxLayout(centralWidget);

  // ── Left: navigation ───────────────────────────────────────────────
  // Build module list based on role
  if (m_role == "admin" || m_role == "teacher") {
    m_modules = QStringList({
      QStringLiteral("总览大屏"),
      QStringLiteral("快速测试"),
      QStringLiteral("扫描任务"),
      QStringLiteral("载荷库"),
      QStringLiteral("想定预案"),
      QStringLiteral("攻击执行"),
      QStringLiteral("测试评估")
    });
  } else {
    m_modules = QStringList({
      QStringLiteral("快速测试"),
      QStringLiteral("扫描任务"),
      QStringLiteral("载荷库"),
      QStringLiteral("想定预案"),
      QStringLiteral("攻击执行"),
      QStringLiteral("测试评估")
    });
  }

  m_navList = new QListWidget(this);
  m_navList->setObjectName("navList");
  m_navList->setFixedWidth(220);
  for (const auto &name : m_modules) {
    m_navList->addItem(name);
  }
  m_navList->setCurrentRow(0);

  // ── Right: stacked pages ───────────────────────────────────────────
  m_stackWidget = new QStackedWidget(this);

  int pageIdx = 0;

  // Page: Dashboard (总览大屏) — admin only
  if (m_role == "admin" || m_role == "teacher") {
    m_dashboardPage = new DashboardPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(m_dashboardPage);
    m_dashboardPageIndex = pageIdx++;
  } else {
    m_dashboardPage = nullptr;
    m_dashboardPageIndex = -1;
  }

  // Page: Quick test (custom page)
  auto *quickPage = new QWidget;
  setupQuickTestPage(quickPage);
  m_stackWidget->addWidget(quickPage);
  pageIdx++;

  // Page: Scan tasks (reuse ScanPage)
  m_scanPage = new ScanPage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_scanPage);
  pageIdx++;

  // Page: Payload library
  m_stackWidget->addWidget(new PayloadPage(m_api, m_role, m_username, this));
  pageIdx++;

  // Page: Playbook (想定预案)
  m_playbookPage = new PlaybookPage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_playbookPage);
  pageIdx++;

  // Page: Execution (攻击执行)
  m_executionPage = new ExecutionPage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_executionPage);
  pageIdx++;

  // Page: Evaluate (测试评估)
  m_stackWidget->addWidget(new EvaluatePage(m_api, m_role, m_username, this));
  pageIdx++;

  // Cross-page navigation: ScanPage → ExecutionPage (select playbook)
  connect(m_scanPage, &ScanPage::playbookNavigateRequested, this, [this](const QString &playbookId) {
    m_executionPage->selectPlaybook(playbookId, QString());
    int execRow = m_modules.indexOf(QStringLiteral("攻击执行"));
    if (execRow >= 0) m_navList->setCurrentRow(execRow);
  });

  // Cross-page navigation: PlaybookPage → ExecutionPage (go execute)
  // Primary: direct callback (most reliable)
  m_playbookPage->setGoExecuteCallback([this](const QString &playbookId) {
    m_executionPage->selectPlaybook(playbookId, QString());
    int execRow = m_modules.indexOf(QStringLiteral("攻击执行"));
    if (execRow >= 0) m_navList->setCurrentRow(execRow);
    statusBar()->showMessage(QString("已跳转到攻击执行，预填 Playbook: %1").arg(playbookId), 3000);
  });
  // Secondary: Qt signal (for any other listeners)
  connect(m_playbookPage, &PlaybookPage::executeRequested, this, [this](const QString &playbookId) {
    // Navigation already handled by callback above; this is for extensibility
    Q_UNUSED(playbookId);
  });

  mainLayout->addWidget(m_navList);

  // Right column: pages + activity panel
  auto *rightColumn = new QVBoxLayout();
  rightColumn->setSpacing(0);
  rightColumn->addWidget(m_stackWidget, 1);

  // Bottom: LiveActivityPanel (compact mode)
  m_activityPanel = new LiveActivityPanel(m_role, m_username, this);
  m_activityPanel->setCompact(true);
  // For student, default collapsed
  if (m_role != "admin" && m_role != "teacher") {
    m_activityPanel->onToggleCollapse();  // start collapsed
  }
  rightColumn->addWidget(m_activityPanel);

  mainLayout->addLayout(rightColumn, 1);
  setCentralWidget(centralWidget);

  // Toast overlay (positioned in top-right corner)
  m_toastOverlay = new ToastOverlay(this);
  // Only show toasts for admin/teacher
  if (m_role != "admin" && m_role != "teacher") {
    m_toastOverlay->hide();
  }

  // ── Status bar ─────────────────────────────────────────────────────
  auto *checkBtn = new QPushButton(QStringLiteral("检测连接"), this);
  checkBtn->setObjectName("checkBtn");
  checkBtn->setFixedWidth(90);
  statusBar()->addWidget(checkBtn);

  auto *statusLabel = new QLabel(QStringLiteral("未检测"), this);
  statusLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
  statusBar()->addWidget(statusLabel);

  // User info label
  auto *userLabel = new QLabel(
    QString("%1 [%2]").arg(m_username, m_role), this);
  userLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
  statusBar()->addWidget(userLabel);

  // Logout button
  auto *logoutBtn = new QPushButton(QStringLiteral("退出登录"), this);
  logoutBtn->setObjectName("checkBtn");
  logoutBtn->setFixedWidth(90);
  statusBar()->addPermanentWidget(logoutBtn);

  // Signals
  connect(m_navList, &QListWidget::currentRowChanged,
          this, &SimpleMainWindow::onModuleChanged);
  connect(checkBtn, &QPushButton::clicked, this, [this, checkBtn, statusLabel]() {
    checkBtn->setEnabled(false);
    statusLabel->setText(QStringLiteral("检测中..."));
    m_api->get("/api/health", 3000, [this, checkBtn, statusLabel](const QJsonObject &res) {
      checkBtn->setEnabled(true);
      if (res["status"].toString() == "ok") {
        statusLabel->setText(QStringLiteral("已连接"));
        statusLabel->setStyleSheet("color: #27ae60; font-weight: bold; padding: 0 10px; font-size: 13px;");
      } else {
        statusLabel->setText(QStringLiteral("未连接"));
        statusLabel->setStyleSheet("color: #e74c3c; font-weight: bold; padding: 0 10px; font-size: 13px;");
      }
    });
  });
  connect(logoutBtn, &QPushButton::clicked, this, &SimpleMainWindow::onLogout);

  // Global API error → status bar
  connect(m_api, &ApiClient::apiError, this, [this](const QString &path, const QString &msg) {
    statusBar()->showMessage(QString("API 错误: %1 -- %2").arg(path, msg), 5000);
  });

  // ── Poll timer ─────────────────────────────────────────────────────
  m_pollTimer = new QTimer(this);
  m_pollTimer->setInterval(3000);
  connect(m_pollTimer, &QTimer::timeout, this, [this]() {
    if (m_currentStage == PortScan || m_currentStage == VulnScan) {
      onPollScan();
    } else if (m_currentStage == ExecAttack) {
      onPollRun();
    }
  });
}

// ── WebSocket setup ────────────────────────────────────────────────────

void SimpleMainWindow::setupWebSocket()
{
  m_ws = new WsClient(m_api, this);
  m_ws->connectToServer();

  // ── Wire to LiveActivityPanel ──────────────────────────────────────
  connect(m_ws, &WsClient::scanCreated, m_activityPanel, &LiveActivityPanel::onScanCreated);
  connect(m_ws, &WsClient::scanStarted, m_activityPanel, &LiveActivityPanel::onScanStarted);
  connect(m_ws, &WsClient::scanCompleted, m_activityPanel, &LiveActivityPanel::onScanCompleted);
  connect(m_ws, &WsClient::runCreated, m_activityPanel, &LiveActivityPanel::onRunCreated);
  connect(m_ws, &WsClient::runStarted, m_activityPanel, &LiveActivityPanel::onRunStarted);
  connect(m_ws, &WsClient::runStepComplete, m_activityPanel, &LiveActivityPanel::onRunStepComplete);
  connect(m_ws, &WsClient::runCompleted, m_activityPanel, &LiveActivityPanel::onRunCompleted);

  // ── Wire to DashboardPage's activity panel ─────────────────────────
  if (m_dashboardPage) {
    auto *dashPanel = m_dashboardPage->activityPanel();
    if (dashPanel) {
      connect(m_ws, &WsClient::scanCreated, dashPanel, &LiveActivityPanel::onScanCreated);
      connect(m_ws, &WsClient::scanStarted, dashPanel, &LiveActivityPanel::onScanStarted);
      connect(m_ws, &WsClient::scanCompleted, dashPanel, &LiveActivityPanel::onScanCompleted);
      connect(m_ws, &WsClient::runCreated, dashPanel, &LiveActivityPanel::onRunCreated);
      connect(m_ws, &WsClient::runStarted, dashPanel, &LiveActivityPanel::onRunStarted);
      connect(m_ws, &WsClient::runStepComplete, dashPanel, &LiveActivityPanel::onRunStepComplete);
      connect(m_ws, &WsClient::runCompleted, dashPanel, &LiveActivityPanel::onRunCompleted);
    }
  }

  // ── Wire to ToastOverlay (admin only) ──────────────────────────────
  if (m_role == "admin" || m_role == "teacher") {
    connect(m_ws, &WsClient::scanCompleted, m_toastOverlay, &ToastOverlay::onScanCompleted);
    connect(m_ws, &WsClient::runStepComplete, m_toastOverlay, &ToastOverlay::onRunStepComplete);
    connect(m_ws, &WsClient::runCompleted, m_toastOverlay, &ToastOverlay::onRunCompleted);
  }

  // ── Wire to ScanPage: auto-refresh on events from other users ─────
  connect(m_ws, &WsClient::scanCompleted, m_scanPage, [this](const QJsonObject &data) {
    Q_UNUSED(data);
    // Refresh task list when any scan completes (especially from other users)
    m_scanPage->onRefreshTasks();
  });
  connect(m_ws, &WsClient::scanCreated, m_scanPage, [this](const QJsonObject &data) {
    // Only refresh if the event is from a different user
    QString eventUser = data["userId"].toString();
    if (eventUser != m_username) {
      m_scanPage->onRefreshTasks();
    }
  });

  // ── Wire to ExecutionPage: auto-refresh on run events ──────────────
  connect(m_ws, &WsClient::runStepComplete, m_executionPage, [this](const QJsonObject &data) {
    Q_UNUSED(data);
    // Trigger a refresh of the currently viewed run if it matches
    // ExecutionPage will check internally
    m_executionPage->onRefreshRuns();
  });
  connect(m_ws, &WsClient::runCompleted, m_executionPage, [this](const QJsonObject &data) {
    Q_UNUSED(data);
    m_executionPage->onRefreshRuns();
  });

  // ── WebSocket connection status in status bar ──────────────────────
  connect(m_ws, &WsClient::connected, this, [this]() {
    statusBar()->showMessage(QStringLiteral("WebSocket 已连接"), 3000);
  });
  connect(m_ws, &WsClient::disconnected, this, [this]() {
    statusBar()->showMessage(QStringLiteral("WebSocket 断开"), 3000);
  });
  connect(m_ws, &WsClient::connectionError, this, [this](const QString &err) {
    statusBar()->showMessage(QString("WebSocket 错误: %1").arg(err), 5000);
  });
}

// ── Resize event: reposition toast overlay ─────────────────────────────

void SimpleMainWindow::resizeEvent(QResizeEvent *event)
{
  QMainWindow::resizeEvent(event);
  if (m_toastOverlay && m_toastOverlay->isVisible()) {
    m_toastOverlay->reposition();
  }
}

// ── Quick test page ───────────────────────────────────────────────────

void SimpleMainWindow::setupQuickTestPage(QWidget *page)
{
  page->setStyleSheet(Theme::PageStyle);

  auto *scrollArea = new QScrollArea(page);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);
  layout->setSpacing(20);
  layout->setContentsMargins(28, 24, 28, 24);

  // ══ Quick test card ═══════════════════════════════════════════════
  auto *testCard = new QFrame;
  testCard->setProperty("card", true);
  auto *testLayout = new QVBoxLayout(testCard);
  testLayout->setContentsMargins(32, 28, 32, 28);
  testLayout->setSpacing(18);

  auto *testTitle = new QLabel(QStringLiteral("快速渗透测试"));
  testTitle->setStyleSheet(Theme::SectionStyle);
  testLayout->addWidget(testTitle);

  auto *descLabel = new QLabel(
    QStringLiteral("输入目标地址，一键完成：扫描 → 生成攻击方案（执行攻击和报告需手动操作）"));
  descLabel->setStyleSheet("font-size: 13px; color: #64748b;");
  descLabel->setWordWrap(true);
  testLayout->addWidget(descLabel);

  // Input row
  auto *inputRow = new QHBoxLayout;
  inputRow->setSpacing(20);

  auto *targetLabel = new QLabel(QStringLiteral("目标地址:"));
  targetLabel->setStyleSheet("font-size: 15px; font-weight: bold;");
  inputRow->addWidget(targetLabel);

  m_targetInput = new QLineEdit;
  m_targetInput->setPlaceholderText(QStringLiteral("例: 192.168.1.1"));
  m_targetInput->setMinimumHeight(36);
  m_targetInput->setMinimumWidth(280);
  QSettings settings("RedTeam", "RedTeam-Platform");
  QStringList history = settings.value("history/targets").toStringList();
  auto *completer = new QCompleter(history, this);
  completer->setCaseSensitivity(Qt::CaseInsensitive);
  m_targetInput->setCompleter(completer);
  inputRow->addWidget(m_targetInput, 2);

  auto *portsLabel = new QLabel(QStringLiteral("端口:"));
  portsLabel->setStyleSheet("font-size: 15px; font-weight: bold;");
  inputRow->addWidget(portsLabel);

  m_portsInput = new QLineEdit;
  m_portsInput->setPlaceholderText(QStringLiteral("22,80,443"));
  m_portsInput->setMinimumHeight(36);
  m_portsInput->setMaximumWidth(180);
  inputRow->addWidget(m_portsInput);

  testLayout->addLayout(inputRow);

  // Button row
  auto *btnRow = new QHBoxLayout;
  btnRow->setSpacing(16);
  btnRow->addStretch();

  m_startBtn = new QPushButton(QStringLiteral("一键开始测试"));
  m_startBtn->setProperty("primary", true);
  m_startBtn->setFixedSize(220, 52);
  m_startBtn->setStyleSheet(
    "QPushButton { background: #2563eb; color: #ffffff; border: none; "
    "border-radius: 10px; font-size: 17px; font-weight: bold; }"
    "QPushButton:hover { background: #1d4ed8; }"
    "QPushButton:pressed { background: #1e40af; }"
    "QPushButton:disabled { background: #94a3b8; color: #ffffff; }");
  btnRow->addWidget(m_startBtn);

  m_retryBtn = new QPushButton(QStringLiteral("重试当前阶段"));
  m_retryBtn->setVisible(false);
  m_retryBtn->setFixedSize(180, 52);
  m_retryBtn->setStyleSheet(
    "QPushButton { background: #f59e0b; color: #ffffff; border: none; "
    "border-radius: 10px; font-size: 15px; font-weight: bold; }"
    "QPushButton:hover { background: #d97706; }");
  btnRow->addWidget(m_retryBtn);

  btnRow->addStretch();
  testLayout->addLayout(btnRow);

  connect(m_startBtn, &QPushButton::clicked, this, &SimpleMainWindow::onStartTest);
  connect(m_retryBtn, &QPushButton::clicked, this, &SimpleMainWindow::onRetryStage);

  layout->addWidget(testCard);

  // ══ Progress card ═════════════════════════════════════════════════
  auto *progressCard = new QFrame;
  progressCard->setProperty("card", true);
  auto *progressLayout = new QVBoxLayout(progressCard);
  progressLayout->setContentsMargins(32, 24, 32, 24);
  progressLayout->setSpacing(14);

  auto *progressTitle = new QLabel(QStringLiteral("执行进度"));
  progressTitle->setStyleSheet(Theme::SectionStyle);
  progressLayout->addWidget(progressTitle);

  const QStringList stageNames = {
    QStringLiteral("端口扫描"),
    QStringLiteral("漏洞扫描"),
    QStringLiteral("生成攻击方案"),
    QStringLiteral("执行攻击"),
    QStringLiteral("生成报告")
  };

  for (int i = 0; i < 5; i++) {
    auto *row = new QHBoxLayout;
    row->setSpacing(16);

    m_stages[i].iconLabel = new QLabel(QStringLiteral("--"));
    m_stages[i].iconLabel->setFixedWidth(40);
    m_stages[i].iconLabel->setAlignment(Qt::AlignCenter);
    m_stages[i].iconLabel->setStyleSheet("font-size: 15px; color: #94a3b8;");

    m_stages[i].nameLabel = new QLabel(stageNames[i]);
    m_stages[i].nameLabel->setFixedWidth(130);
    m_stages[i].nameLabel->setStyleSheet("font-size: 15px; color: #475569; font-weight: bold;");

    m_stages[i].progress = new QProgressBar;
    m_stages[i].progress->setRange(0, 100);
    m_stages[i].progress->setValue(0);
    m_stages[i].progress->setFixedHeight(18);
    m_stages[i].progress->setTextVisible(false);
    m_stages[i].progress->setStyleSheet(
      "QProgressBar { background: #e2e8f0; border: none; border-radius: 9px; }"
      "QProgressBar::chunk { background: #94a3b8; border-radius: 9px; }");

    m_stages[i].statusLabel = new QLabel(QStringLiteral("等待中"));
    m_stages[i].statusLabel->setMinimumWidth(120);
    m_stages[i].statusLabel->setStyleSheet("font-size: 14px; color: #94a3b8;");

    m_stages[i].thoughtLabel = new QLabel;
    m_stages[i].thoughtLabel->setStyleSheet("font-size: 12px; color: #6366f1; padding-left: 56px;");
    m_stages[i].thoughtLabel->setWordWrap(true);
    m_stages[i].thoughtLabel->hide();

    row->addWidget(m_stages[i].iconLabel);
    row->addWidget(m_stages[i].nameLabel);
    row->addWidget(m_stages[i].progress, 1);
    row->addWidget(m_stages[i].statusLabel);
    progressLayout->addLayout(row);
    progressLayout->addWidget(m_stages[i].thoughtLabel);
  }

  layout->addWidget(progressCard);

  // ══ Discovery summary card ════════════════════════════════════════
  m_summaryFrame = new QFrame;
  m_summaryFrame->setProperty("card", true);
  auto *summaryLayout = new QVBoxLayout(m_summaryFrame);
  summaryLayout->setContentsMargins(32, 24, 32, 24);
  summaryLayout->setSpacing(12);

  auto *summaryTitle = new QLabel(QStringLiteral("发现摘要"));
  summaryTitle->setStyleSheet(Theme::SectionStyle);
  summaryLayout->addWidget(summaryTitle);

  m_portsLabel = new QLabel(QStringLiteral("开放端口: --"));
  m_portsLabel->setStyleSheet("font-size: 15px; color: #475569;");
  m_portsLabel->setWordWrap(true);
  summaryLayout->addWidget(m_portsLabel);

  m_vulnLabel = new QLabel(QStringLiteral("漏洞发现: --"));
  m_vulnLabel->setStyleSheet("font-size: 15px; color: #475569;");
  m_vulnLabel->setWordWrap(true);
  summaryLayout->addWidget(m_vulnLabel);

  m_playbookLabel = new QLabel(QStringLiteral("攻击方案: --"));
  m_playbookLabel->setStyleSheet("font-size: 15px; color: #475569;");
  m_playbookLabel->setWordWrap(true);

  auto *pbRow = new QHBoxLayout;
  pbRow->addWidget(m_playbookLabel, 1);
  m_viewPlaybookBtn = new QPushButton(QStringLiteral("查看方案"));
  m_viewPlaybookBtn->setFixedSize(80, 28);
  m_viewPlaybookBtn->setStyleSheet(
    "QPushButton { background: #3a8fd6; color: #fff; border: none; border-radius: 4px; font-size: 13px; }"
    "QPushButton:hover { background: #4da3e8; }");
  m_viewPlaybookBtn->setVisible(false);
  pbRow->addWidget(m_viewPlaybookBtn);

  m_gotoExecBtn = new QPushButton(QStringLiteral("前往执行"));
  m_gotoExecBtn->setFixedSize(80, 28);
  m_gotoExecBtn->setStyleSheet(
    "QPushButton { background: #22c55e; color: #fff; border: none; border-radius: 4px; font-size: 13px; font-weight: bold; }"
    "QPushButton:hover { background: #16a34a; }");
  m_gotoExecBtn->setVisible(false);
  pbRow->addWidget(m_gotoExecBtn);

  summaryLayout->addLayout(pbRow);

  connect(m_viewPlaybookBtn, &QPushButton::clicked, this, &SimpleMainWindow::onViewPlaybook);
  connect(m_gotoExecBtn, &QPushButton::clicked, this, [this]() {
    if (!m_playbookId.isEmpty() && m_executionPage) {
      m_executionPage->selectPlaybook(m_playbookId, m_target);
      int execRow = m_modules.indexOf(QStringLiteral("攻击执行"));
      if (execRow >= 0) m_navList->setCurrentRow(execRow);
    }
  });

  layout->addWidget(m_summaryFrame);

  // ══ Playbook detail (expandable, initially hidden) ═════════════════
  m_playbookDetailFrame = new QFrame;
  m_playbookDetailFrame->setProperty("card", true);
  m_playbookDetailLayout = new QVBoxLayout(m_playbookDetailFrame);
  m_playbookDetailLayout->setContentsMargins(32, 20, 32, 20);
  m_playbookDetailLayout->setSpacing(8);
  m_playbookDetailFrame->setVisible(false);
  layout->addWidget(m_playbookDetailFrame);

  // ══ Report card ═══════════════════════════════════════════════════
  m_reportFrame = new QFrame;
  m_reportFrame->setProperty("card", true);
  auto *reportLayout = new QVBoxLayout(m_reportFrame);
  reportLayout->setContentsMargins(32, 24, 32, 24);
  reportLayout->setSpacing(12);

  auto *reportTitle = new QLabel(QStringLiteral("测试报告"));
  reportTitle->setStyleSheet(Theme::SectionStyle);
  reportLayout->addWidget(reportTitle);

  auto *reportRow = new QHBoxLayout;
  reportRow->setSpacing(16);
  m_reportTitleLabel = new QLabel(QStringLiteral("尚未生成"));
  m_reportTitleLabel->setStyleSheet("font-size: 15px; color: #94a3b8;");
  reportRow->addWidget(m_reportTitleLabel, 1);

  m_viewReportBtn = new QPushButton(QStringLiteral("查看报告"));
  m_viewReportBtn->setVisible(false);
  m_viewReportBtn->setFixedWidth(100);
  m_viewReportBtn->setProperty("primary", true);
  reportRow->addWidget(m_viewReportBtn);
  reportLayout->addLayout(reportRow);

  connect(m_viewReportBtn, &QPushButton::clicked, this, &SimpleMainWindow::onViewReport);

  layout->addWidget(m_reportFrame);

  // ══ History card ══════════════════════════════════════════════════
  auto *historyCard = new QFrame;
  historyCard->setProperty("card", true);
  auto *historyLayout = new QVBoxLayout(historyCard);
  historyLayout->setContentsMargins(32, 24, 32, 24);
  historyLayout->setSpacing(12);

  auto *historyTitle = new QLabel(QStringLiteral("历史记录"));
  historyTitle->setStyleSheet(Theme::SectionStyle);
  historyLayout->addWidget(historyTitle);

  m_historyTable = new QTableWidget(0, 4);
  m_historyTable->setHorizontalHeaderLabels({
    QStringLiteral("目标"), QStringLiteral("时间"),
    QStringLiteral("状态"), QStringLiteral("操作")
  });
  m_historyTable->setAlternatingRowColors(true);
  m_historyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_historyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_historyTable->setSelectionMode(QAbstractItemView::SingleSelection);
  m_historyTable->horizontalHeader()->setStretchLastSection(true);
  m_historyTable->setColumnWidth(0, 220);
  m_historyTable->setColumnWidth(1, 160);
  m_historyTable->setColumnWidth(2, 100);
  m_historyTable->verticalHeader()->setVisible(false);
  m_historyTable->setMinimumHeight(120);
  historyLayout->addWidget(m_historyTable);

  connect(m_historyTable, &QTableWidget::cellClicked, this, &SimpleMainWindow::onViewHistoryReport);

  layout->addWidget(historyCard, 1);

  // Finalize scroll area
  scrollArea->setWidget(container);
  auto *pageLayout = new QVBoxLayout(page);
  pageLayout->setContentsMargins(0, 0, 0, 0);
  pageLayout->addWidget(scrollArea);
}

// ── Module navigation ─────────────────────────────────────────────────

void SimpleMainWindow::onModuleChanged(int row)
{
  if (row >= 0 && row < m_stackWidget->count()) {
    m_stackWidget->setCurrentIndex(row);
  }
}

// ── Stage management ──────────────────────────────────────────────────

void SimpleMainWindow::setStage(Stage s)
{
  m_currentStage = s;
  updateStageUI();
}

void SimpleMainWindow::updateStageUI()
{
  for (int i = 0; i < 5; i++) {
    m_stages[i].iconLabel->setText(QStringLiteral("--"));
    m_stages[i].iconLabel->setStyleSheet("font-size: 15px; color: #94a3b8;");
    m_stages[i].progress->setValue(0);
    m_stages[i].progress->setStyleSheet(
      "QProgressBar { background: #e2e8f0; border: none; border-radius: 9px; }"
      "QProgressBar::chunk { background: #94a3b8; border-radius: 9px; }");
    m_stages[i].statusLabel->setText(QStringLiteral("等待中"));
    m_stages[i].statusLabel->setStyleSheet("font-size: 14px; color: #94a3b8;");
    m_stages[i].thoughtLabel->clear();
    m_stages[i].thoughtLabel->hide();
  }

  int completedUpTo = 0;
  if (m_currentStage == Done) {
    // Only stages 0-2 actually ran (port scan, vuln scan, gen playbook)
    // Stages 3-4 (exec attack, gen report) are manual — mark them specially
    completedUpTo = 3;
  } else if (m_currentStage == Failed) {
    return;
  } else if (m_currentStage > Idle) {
    completedUpTo = static_cast<int>(m_currentStage) - 1;
  }

  for (int i = 0; i < completedUpTo && i < 5; i++) {
    m_stages[i].iconLabel->setText(QStringLiteral("[OK]"));
    m_stages[i].iconLabel->setStyleSheet("font-size: 15px; color: #22c55e; font-weight: bold;");
    m_stages[i].progress->setValue(100);
    m_stages[i].progress->setStyleSheet(
      "QProgressBar { background: #e2e8f0; border: none; border-radius: 9px; }"
      "QProgressBar::chunk { background: #22c55e; border-radius: 9px; }");
    m_stages[i].statusLabel->setText(QStringLiteral("已完成"));
    m_stages[i].statusLabel->setStyleSheet("font-size: 14px; color: #22c55e;");
  }

  // Mark stages 3-4 as "待手动" when Done (they weren't auto-executed)
  if (m_currentStage == Done) {
    for (int i = 3; i < 5; i++) {
      m_stages[i].iconLabel->setText(QStringLiteral("[–]"));
      m_stages[i].iconLabel->setStyleSheet("font-size: 15px; color: #f59e0b; font-weight: bold;");
      m_stages[i].progress->setValue(0);
      m_stages[i].progress->setStyleSheet(
        "QProgressBar { background: #e2e8f0; border: none; border-radius: 9px; }"
        "QProgressBar::chunk { background: #f59e0b; border-radius: 9px; }");
      m_stages[i].statusLabel->setText(QStringLiteral("待手动执行"));
      m_stages[i].statusLabel->setStyleSheet("font-size: 14px; color: #f59e0b;");
    }
  }

  int runningIndex = static_cast<int>(m_currentStage) - 1;
  if (runningIndex >= 0 && runningIndex < 5) {
    m_stages[runningIndex].iconLabel->setText(QStringLiteral(">>"));
    m_stages[runningIndex].iconLabel->setStyleSheet("font-size: 15px; color: #2563eb; font-weight: bold;");
    m_stages[runningIndex].progress->setStyleSheet(
      "QProgressBar { background: #e2e8f0; border: none; border-radius: 9px; }"
      "QProgressBar::chunk { background: #2563eb; border-radius: 9px; }");
  }

  m_startBtn->setEnabled(m_currentStage == Idle || m_currentStage == Done);
  if (m_currentStage != Idle && m_currentStage != Done) {
    m_startBtn->setText(QStringLiteral("测试进行中..."));
  } else {
    m_startBtn->setText(QStringLiteral("一键开始测试"));
  }

  m_retryBtn->setVisible(m_currentStage == Failed);
}

void SimpleMainWindow::updateStageRow(int index, const QString &icon,
                                       int percent, const QString &status,
                                       const QString &color)
{
  if (index < 0 || index >= 5) return;
  m_stages[index].iconLabel->setText(icon);
  m_stages[index].iconLabel->setStyleSheet(
    QString("font-size: 15px; color: %1; font-weight: bold;").arg(color));
  m_stages[index].progress->setValue(percent);
  m_stages[index].statusLabel->setText(status);
  m_stages[index].statusLabel->setStyleSheet(
    QString("font-size: 14px; color: %1;").arg(color));
}

// ── One-click start ───────────────────────────────────────────────────

void SimpleMainWindow::onStartTest()
{
  QString target = m_targetInput->text().trimmed();
  if (target.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("提示"),
                         QStringLiteral("请输入目标地址"));
    return;
  }

  m_target = target;

  // Save to history
  {
    QSettings settings("RedTeam", "RedTeam-Platform");
    QStringList history = settings.value("history/targets").toStringList();
    history.removeAll(target);
    history.prepend(target);
    while (history.size() > 20) history.removeLast();
    settings.setValue("history/targets", history);
    if (auto *c = m_targetInput->completer()) {
      auto *m = qobject_cast<QStringListModel*>(c->model());
      if (m) m->setStringList(history);
    }
  }

  // Reset UI
  m_portScanTaskId.clear();
  m_vulnScanTaskId.clear();
  m_playbookId.clear();
  m_runId.clear();
  m_portResults = QJsonArray();
  m_vulnResults = QJsonArray();
  m_portScanDone = false;
  m_vulnScanDone = false;
  m_portsLabel->setText(QStringLiteral("开放端口: --"));
  m_portsLabel->setStyleSheet("font-size: 15px; color: #475569;");
  m_vulnLabel->setText(QStringLiteral("漏洞发现: --"));
  m_vulnLabel->setStyleSheet("font-size: 15px; color: #475569;");
  m_playbookLabel->setText(QStringLiteral("攻击方案: --"));
  m_playbookLabel->setStyleSheet("font-size: 15px; color: #475569;");
  m_viewPlaybookBtn->setVisible(false);
  m_viewPlaybookBtn->setText(QStringLiteral("查看方案"));
  m_gotoExecBtn->setVisible(false);
  m_playbookDetailFrame->setVisible(false);
  // Clear old detail content
  QLayoutItem *ci;
  while ((ci = m_playbookDetailLayout->takeAt(0)) != nullptr) {
    delete ci->widget();
    delete ci;
  }
  m_reportTitleLabel->setText(QStringLiteral("尚未生成"));
  m_reportTitleLabel->setStyleSheet("font-size: 15px; color: #94a3b8;");
  m_viewReportBtn->setVisible(false);
  m_latestReportId.clear();

  // Start stage 1: port scan
  setStage(PortScan);
  updateStageRow(0, ">>", 10, QStringLiteral("创建中..."), "#2563eb");

  QJsonObject body;
  body["target"] = target;
  body["scan_type"] = QStringLiteral("port_scan");
  QString ports = m_portsInput->text().trimmed();
  if (!ports.isEmpty()) {
    QJsonObject params;
    params["ports"] = ports;
    body["parameters"] = params;
  }

  m_api->post("/api/scan-tasks", body, 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      updateStageRow(0, "[X]", 0, QStringLiteral("创建失败"), "#ef4444");
      m_portScanDone = true;
      checkBothScansDone();
      return;
    }
    m_portScanTaskId = res["data"].toObject()["scan_task_id"].toString();
    updateStageRow(0, ">>", 20, QStringLiteral("已创建，执行中..."), "#2563eb");

    QJsonObject empty;
    m_api->post("/api/scan-tasks/" + m_portScanTaskId + "/execute", empty, 5000,
      [this](const QJsonObject &execRes) {
        if (execRes["status"].toString() != "ok") {
          updateStageRow(0, "[X]", 0, QStringLiteral("执行失败"), "#ef4444");
          m_portScanDone = true;
          checkBothScansDone();
          return;
        }
        updateStageRow(0, ">>", 30, QStringLiteral("扫描中..."), "#2563eb");
        if (!m_pollTimer->isActive()) m_pollTimer->start();
      });
  });

  // Also start vuln scan in parallel
  updateStageRow(1, ">>", 10, QStringLiteral("创建中..."), "#2563eb");

  QJsonObject vulnBody;
  vulnBody["target"] = target;
  vulnBody["scan_type"] = QStringLiteral("vuln_scan");
  if (!ports.isEmpty()) {
    QJsonObject params;
    params["ports"] = ports;
    vulnBody["parameters"] = params;
  }

  m_api->post("/api/scan-tasks", vulnBody, 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      updateStageRow(1, "[X]", 0, QStringLiteral("创建失败"), "#ef4444");
      m_vulnScanDone = true;
      checkBothScansDone();
      return;
    }
    m_vulnScanTaskId = res["data"].toObject()["scan_task_id"].toString();
    updateStageRow(1, ">>", 20, QStringLiteral("已创建，执行中..."), "#2563eb");

    QJsonObject empty;
    m_api->post("/api/scan-tasks/" + m_vulnScanTaskId + "/execute", empty, 5000,
      [this](const QJsonObject &execRes) {
        if (execRes["status"].toString() != "ok") {
          updateStageRow(1, "[X]", 0, QStringLiteral("执行失败"), "#ef4444");
          m_vulnScanDone = true;
          checkBothScansDone();
          return;
        }
        updateStageRow(1, ">>", 30, QStringLiteral("扫描中..."), "#2563eb");
        if (!m_pollTimer->isActive()) m_pollTimer->start();
      });
  });
}

// ── Poll scan status ──────────────────────────────────────────────────

void SimpleMainWindow::onPollScan()
{
  if (!m_portScanDone && !m_portScanTaskId.isEmpty()) {
    m_api->get("/api/scan-tasks/" + m_portScanTaskId, 5000,
      [this](const QJsonObject &res) {
        if (res["status"].toString() != "ok") {
          // API error — treat as failed
          updateStageRow(0, "[X]", 0, QStringLiteral("查询失败"), "#ef4444");
          m_portScanDone = true;
          checkBothScansDone();
          return;
        }
        auto d = res["data"].toObject();
        QString status = d["status"].toString();
        if (status == "COMPLETED") {
          updateStageRow(0, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
          m_portResults = d["results"].toArray();
          QStringList ports;
          for (const auto &r : m_portResults) {
            auto obj = r.toObject();
            if (obj["result_type"].toString() == "open_port") {
              auto data = QJsonDocument::fromJson(obj["result_data"].toString().toUtf8()).object();
              int port = data["port"].toInt();
              QString service = data["service"].toString();
              if (port > 0) {
                QString text = QString::number(port);
                if (!service.isEmpty()) text += "/" + service;
                ports << text;
              }
            }
          }
          if (!ports.isEmpty()) {
            m_portsLabel->setText(QStringLiteral("开放端口: ") + ports.join("  "));
            m_portsLabel->setStyleSheet("font-size: 15px; color: #1a2a3a;");
          }
          m_portScanDone = true;
          checkBothScansDone();
        } else if (status == "FAILED" || status == "CANCELLED") {
          updateStageRow(0, "[X]", 0, QStringLiteral("失败"), "#ef4444");
          m_portScanDone = true;
          checkBothScansDone();
        } else if (status == "RUNNING") {
          updateStageRow(0, ">>", 50, QStringLiteral("扫描中..."), "#2563eb");
        } else if (status == "PENDING") {
          updateStageRow(0, ">>", 20, QStringLiteral("等待执行..."), "#f59e0b");
        }
      });
  }

  if (!m_vulnScanDone && !m_vulnScanTaskId.isEmpty()) {
    m_api->get("/api/scan-tasks/" + m_vulnScanTaskId, 5000,
      [this](const QJsonObject &res) {
        if (res["status"].toString() != "ok") {
          updateStageRow(1, "[X]", 0, QStringLiteral("查询失败"), "#ef4444");
          m_vulnScanDone = true;
          checkBothScansDone();
          return;
        }
        auto d = res["data"].toObject();
        QString status = d["status"].toString();
        if (status == "COMPLETED") {
          updateStageRow(1, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
          m_vulnResults = d["results"].toArray();
          QMap<QString, int> counts;
          for (const auto &r : m_vulnResults) {
            QString sev = r.toObject()["severity"].toString();
            if (!sev.isEmpty()) counts[sev]++;
          }
          QStringList parts;
          for (const auto &sev : {"critical", "high", "medium", "low"}) {
            if (counts.contains(sev) && counts[sev] > 0)
              parts << QString("%1x%2").arg(counts[sev]).arg(formatSeverity(sev));
          }
          if (!parts.isEmpty()) {
            m_vulnLabel->setText(QStringLiteral("漏洞发现: ") + parts.join("  "));
            m_vulnLabel->setStyleSheet("font-size: 15px; color: #1a2a3a;");
          } else {
            m_vulnLabel->setText(QStringLiteral("漏洞发现: 未发现"));
            m_vulnLabel->setStyleSheet("font-size: 15px; color: #22c55e;");
          }
          m_vulnScanDone = true;
          checkBothScansDone();
        } else if (status == "FAILED" || status == "CANCELLED") {
          updateStageRow(1, "[X]", 0, QStringLiteral("失败"), "#ef4444");
          m_vulnScanDone = true;
          checkBothScansDone();
        } else if (status == "RUNNING") {
          updateStageRow(1, ">>", 50, QStringLiteral("扫描中..."), "#2563eb");
        } else if (status == "PENDING") {
          updateStageRow(1, ">>", 20, QStringLiteral("等待执行..."), "#f59e0b");
        }
      });
  }
}

void SimpleMainWindow::checkBothScansDone()
{
  if (m_portScanDone && m_vulnScanDone) {
    m_pollTimer->stop();
    advanceStage();
  }
}

// ── Start playbook execution (called after playbook is ready) ─────────

void SimpleMainWindow::startExecution()
{
  if (m_playbookId.isEmpty()) {
    updateStageRow(3, "[X]", 0, QStringLiteral("无攻击方案"), "#ef4444");
    setStage(Failed);
    return;
  }

  setStage(ExecAttack);
  updateStageRow(3, ">>", 10, QStringLiteral("创建执行..."), "#2563eb");

  QJsonObject runBody;
  runBody["playbook_id"] = m_playbookId;
  runBody["target"] = m_target;
  runBody["user_sub"] = m_username;
  runBody["user_role"] = m_role;

  m_api->post("/api/runs", runBody, 10000,
    [this](const QJsonObject &runRes) {
      if (runRes["status"].toString() != "ok") {
        updateStageRow(3, "[X]", 0, QStringLiteral("创建失败"), "#ef4444");
        setStage(Failed);
        return;
      }
      m_runId = runRes["data"].toObject()["run_id"].toString();
      updateStageRow(3, ">>", 20, QStringLiteral("执行中..."), "#2563eb");

      QJsonObject empty;
      m_api->post("/api/runs/" + m_runId + "/execute", empty, 5000,
        [this](const QJsonObject &execRes) {
          if (execRes["status"].toString() != "ok") {
            updateStageRow(3, "[X]", 0, QStringLiteral("启动失败"), "#ef4444");
            setStage(Failed);
            return;
          }
          updateStageRow(3, ">>", 30, QStringLiteral("执行中..."), "#2563eb");
          if (!m_pollTimer->isActive()) m_pollTimer->start();
        });
    });
}

// ── Advance to next stage ─────────────────────────────────────────────

void SimpleMainWindow::advanceStage()
{
  if (m_currentStage == PortScan || m_currentStage == VulnScan) {
    setStage(GenPlaybook);
    updateStageRow(2, ">>", 30, QStringLiteral("AI生成中..."), "#2563eb");

    QString scanId = m_vulnScanTaskId.isEmpty() ? m_portScanTaskId : m_vulnScanTaskId;
    if (scanId.isEmpty()) {
      updateStageRow(2, "[X]", 0, QStringLiteral("无扫描结果"), "#ef4444");
      setStage(Failed);
      return;
    }

    // Try AI generate-playbook first (30s timeout); on failure, fall back to
    // playbook matcher recommendations (no LLM needed)
    QJsonObject empty;
    m_api->post("/api/scan-tasks/" + scanId + "/generate-playbook", empty, 30000,
      [this, scanId](const QJsonObject &res) {
        if (res["status"].toString() != "ok") {
          // AI generation failed — fall back to playbook matcher
          updateStageRow(2, ">>", 50, QStringLiteral("匹配已有方案..."), "#f59e0b");
          m_api->get("/api/scan-tasks/" + scanId + "/recommendations", 10000,
            [this](const QJsonObject &recRes) {
              if (recRes["status"].toString() != "ok" ||
                  recRes["data"].toArray().isEmpty()) {
                updateStageRow(2, "[X]", 0, QStringLiteral("无可用方案"), "#ef4444");
                setStage(Failed);
                return;
              }
              // Use the top-recommended playbook
              auto rec = recRes["data"].toArray()[0].toObject();
              m_playbookId = rec["playbook_id"].toString();
              QString pbName = rec["name"].toString();

              updateStageRow(2, "[OK]", 100, QStringLiteral("已匹配"), "#22c55e");
              m_playbookLabel->setText(QStringLiteral("攻击方案: ") + pbName);
              m_playbookLabel->setStyleSheet("font-size: 15px; color: #1a2a3a;");
              m_viewPlaybookBtn->setVisible(true);
              m_gotoExecBtn->setVisible(true);

              // Done — stop here, user can view the playbook
              setStage(Done);
            });
          return;
          }
        auto data = res["data"].toObject();
        m_playbookId = data["playbook_id"].toString();
        QString pbName = data["name"].toString();
        int steps = data["steps_count"].toInt();

        updateStageRow(2, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
        m_playbookLabel->setText(QStringLiteral("攻击方案: ") + pbName +
          QString(" (%1步)").arg(steps));
        m_playbookLabel->setStyleSheet("font-size: 15px; color: #1a2a3a;");
        m_viewPlaybookBtn->setVisible(true);

        // Done — stop here, user can view the playbook
        setStage(Done);
      });
  }
  else if (m_currentStage == ExecAttack) {
    setStage(GenReport);
    updateStageRow(4, ">>", 30, QStringLiteral("生成中..."), "#2563eb");

    QString reportId = "rpt_" + QUuid::createUuid().toString(QUuid::Id128).left(12);
    QString title = m_target + QStringLiteral(" 渗透测试报告");

    QJsonObject genBody;
    genBody["run_id"] = m_runId;
    genBody["title"] = title;

    m_api->post("/api/reports/generate", genBody, 30000,
      [this, reportId, title](const QJsonObject &res) {
        QString rid = reportId;
        if (res["status"].toString() == "ok") {
          rid = res["data"].toObject()["report_id"].toString(rid);
        }
        if (res["status"].toString() != "ok") {
          QJsonObject manualBody;
          manualBody["report_id"] = reportId;
          manualBody["title"] = title;
          manualBody["run_id"] = m_runId;
          manualBody["generated_by"] = m_username;

          m_api->post("/api/reports", manualBody, 10000,
            [this, reportId, title](const QJsonObject &r2) {
              if (r2["status"].toString() == "ok") {
                m_latestReportId = r2["data"].toObject()["report_id"].toString(reportId);
              }
              updateStageRow(4, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
              setStage(Done);
              m_reportTitleLabel->setText(title);
              m_reportTitleLabel->setStyleSheet("font-size: 15px; color: #1a2a3a;");
              m_viewReportBtn->setVisible(true);
              loadHistory();
            });
          return;
        }

        m_latestReportId = rid;
        updateStageRow(4, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
        setStage(Done);
        m_reportTitleLabel->setText(title);
        m_reportTitleLabel->setStyleSheet("font-size: 15px; color: #1a2a3a;");
        m_viewReportBtn->setVisible(true);
        loadHistory();
      });
  }
}

// ── Poll run status ───────────────────────────────────────────────────

void SimpleMainWindow::onPollRun()
{
  if (m_runId.isEmpty()) return;

  m_api->get("/api/runs/" + m_runId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    if (status == "COMPLETED") {
      updateStageRow(3, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
      m_pollTimer->stop();
      advanceStage();
    } else if (status == "FAILED" || status == "ABORTED") {
      updateStageRow(3, "[X]", 0, QStringLiteral("失败"), "#ef4444");
      m_pollTimer->stop();
      setStage(Failed);
    } else if (status == "RUNNING") {
      auto steps = d["steps"].toArray();
      int totalSteps = steps.size();
      int completedSteps = 0;
      for (const auto &s : steps) {
        if (s.toObject()["success"].toInt() == 1) completedSteps++;
      }
      if (totalSteps > 0) {
        int pct = 30 + (completedSteps * 70 / totalSteps);
        QString stepInfo = QString("步骤 %1/%2").arg(completedSteps).arg(totalSteps);
        updateStageRow(3, ">>", pct, stepInfo, "#2563eb");
      } else {
        updateStageRow(3, ">>", 40, QStringLiteral("执行中..."), "#2563eb");
      }

      // Show ReAct thoughts from step data
      for (const auto &s : steps) {
        auto stepObj = s.toObject();
        QString thought = stepObj["react_thought"].toString();
        int stepIdx = stepObj["step_index"].toInt();
        if (!thought.isEmpty() && stepIdx >= 0 && stepIdx < 5) {
          m_stages[3].thoughtLabel->setText(QStringLiteral("💭 ") + thought);
          m_stages[3].thoughtLabel->show();
        }
      }
    }
  });
}

// ── Retry current stage ───────────────────────────────────────────────

void SimpleMainWindow::onRetryStage()
{
  if (m_currentStage == Failed) {
    m_startBtn->setEnabled(true);
    m_startBtn->setText(QStringLiteral("一键开始测试"));
    m_retryBtn->setVisible(false);
    setStage(Idle);

    for (int i = 0; i < 5; i++) {
      m_stages[i].iconLabel->setText(QStringLiteral("--"));
      m_stages[i].iconLabel->setStyleSheet("font-size: 15px; color: #94a3b8;");
      m_stages[i].progress->setValue(0);
      m_stages[i].progress->setStyleSheet(
        "QProgressBar { background: #e2e8f0; border: none; border-radius: 9px; }"
        "QProgressBar::chunk { background: #94a3b8; border-radius: 9px; }");
      m_stages[i].statusLabel->setText(QStringLiteral("等待中"));
      m_stages[i].statusLabel->setStyleSheet("font-size: 14px; color: #94a3b8;");
      m_stages[i].thoughtLabel->clear();
      m_stages[i].thoughtLabel->hide();
    }

    onStartTest();
  }
}

// ── View playbook details (inline expand/collapse) ───────────────────

void SimpleMainWindow::onViewPlaybook()
{
  // Toggle: if already visible, collapse
  if (m_playbookDetailFrame->isVisible()) {
    m_playbookDetailFrame->setVisible(false);
    m_viewPlaybookBtn->setText(QStringLiteral("查看方案"));
    return;
  }

  if (m_playbookId.isEmpty()) return;

  m_viewPlaybookBtn->setText(QStringLiteral("收起方案"));

  m_api->get("/api/playbooks/" + m_playbookId, 10000,
    [this](const QJsonObject &res) {
      if (res["status"].toString() != "ok") {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("获取方案详情失败"));
        m_viewPlaybookBtn->setText(QStringLiteral("查看方案"));
        return;
      }

      auto data = res["data"].toObject();
      QString name = data["name"].toString();
      QString desc = data["description"].toString();
      QString difficulty = data["difficulty"].toString();
      QString group = data["baseline_group"].toString();
      auto steps = data["steps"].toArray();

      // Clear old content
      QLayoutItem *child;
      while ((child = m_playbookDetailLayout->takeAt(0)) != nullptr) {
        delete child->widget();
        delete child;
      }

      // Header row: name + meta
      auto *headerRow = new QHBoxLayout;
      auto *headerLabel = new QLabel(QString("<b>%1</b>").arg(name));
      headerLabel->setStyleSheet("font-size: 16px; color: #1a2a3a;");
      headerRow->addWidget(headerLabel, 1);

      // Difficulty badge
      QString diffColor = difficulty == "advanced" ? "#ef4444" :
                          difficulty == "intermediate" ? "#f59e0b" : "#22c55e";
      auto *diffBadge = new QLabel(difficulty);
      diffBadge->setStyleSheet(
        QString("font-size: 12px; color: %1; border: 1px solid %1; "
                "border-radius: 10px; padding: 2px 10px; font-weight: bold;").arg(diffColor));
      headerRow->addWidget(diffBadge);

      auto *groupLabel = new QLabel(group);
      groupLabel->setStyleSheet("font-size: 12px; color: #64748b; border: 1px solid #cbd5e1; border-radius: 10px; padding: 2px 10px;");
      headerRow->addWidget(groupLabel);

      m_playbookDetailLayout->addLayout(headerRow);

      // Description
      if (!desc.isEmpty()) {
        auto *descLabel = new QLabel(desc);
        descLabel->setWordWrap(true);
        descLabel->setStyleSheet("font-size: 13px; color: #64748b; margin-top: 4px;");
        m_playbookDetailLayout->addWidget(descLabel);
      }

      // Separator
      auto *sep = new QFrame;
      sep->setFrameShape(QFrame::HLine);
      sep->setStyleSheet("color: #e2e8f0; margin-top: 8px;");
      m_playbookDetailLayout->addWidget(sep);

      // Step count
      auto *stepCount = new QLabel(QStringLiteral("共 %1 步").arg(steps.size()));
      stepCount->setStyleSheet("font-size: 13px; color: #94a3b8; margin-bottom: 4px;");
      m_playbookDetailLayout->addWidget(stepCount);

      // Step cards
      for (int i = 0; i < steps.size(); i++) {
        auto s = steps[i].toObject();
        QString toolId = s["tool_id"].toString();
        QString stepName = s["name"].toString();
        QString stepDesc = s["description"].toString();
        int score = s["score"].toInt();

        // Build command string from args_template
        QString cmdStr;
        QString argsStr = s["args_template"].toString();
        if (!argsStr.isEmpty()) {
          QJsonDocument argsDoc = QJsonDocument::fromJson(argsStr.toUtf8());
          if (argsDoc.isArray()) {
            QStringList argList;
            for (const auto &a : argsDoc.array()) argList << a.toString();
            if (!argList.isEmpty())
              cmdStr = toolId + " " + argList.join(" ");
          }
        }
        if (cmdStr.isEmpty()) cmdStr = toolId;

        // Card frame
        auto *card = new QFrame;
        card->setStyleSheet(
          "QFrame { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; }");
        auto *cardLayout = new QVBoxLayout(card);
        cardLayout->setContentsMargins(12, 8, 12, 8);
        cardLayout->setSpacing(4);

        // Row 1: step number + tool badge + name
        auto *row1 = new QHBoxLayout;
        auto *numLabel = new QLabel(QString("#%1").arg(i + 1));
        numLabel->setStyleSheet("font-size: 13px; color: #94a3b8; font-weight: bold; font-family: monospace;");
        row1->addWidget(numLabel);

        auto *toolBadge = new QLabel(toolId);
        toolBadge->setStyleSheet(
          "font-size: 11px; color: #fff; background: #3a8fd6; "
          "border-radius: 8px; padding: 1px 8px; font-family: monospace;");
        row1->addWidget(toolBadge);

        auto *nameLabel = new QLabel(stepName);
        nameLabel->setStyleSheet("font-size: 14px; color: #1a2a3a; font-weight: bold;");
        row1->addWidget(nameLabel, 1);

        if (score > 0) {
          auto *scoreLabel = new QLabel(QString("+%1分").arg(score));
          scoreLabel->setStyleSheet("font-size: 12px; color: #f59e0b; font-weight: bold;");
          row1->addWidget(scoreLabel);
        }
        cardLayout->addLayout(row1);

        // Row 2: description
        if (!stepDesc.isEmpty()) {
          auto *descL = new QLabel(stepDesc);
          descL->setWordWrap(true);
          descL->setStyleSheet("font-size: 12px; color: #64748b;");
          cardLayout->addWidget(descL);
        }

        // Row 3: command (monospace)
        auto *cmdLabel = new QLabel(cmdStr);
        cmdLabel->setStyleSheet(
          "font-size: 12px; color: #334155; background: #e2e8f0; "
          "border-radius: 3px; padding: 3px 8px; font-family: monospace;");
        cmdLabel->setWordWrap(true);
        cardLayout->addWidget(cmdLabel);

        m_playbookDetailLayout->addWidget(card);
      }

      m_playbookDetailFrame->setVisible(true);
    });
}

// ── View report ───────────────────────────────────────────────────────

void SimpleMainWindow::onViewReport()
{
  if (m_latestReportId.isEmpty()) return;

  m_api->get("/api/reports/" + m_latestReportId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("无法加载报告"));
      return;
    }

    auto data = res["data"].toObject();
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("测试报告"));
    dlg.resize(750, 550);
    auto *layout = new QVBoxLayout(&dlg);
    layout->setSpacing(16);
    layout->setContentsMargins(28, 24, 28, 24);

    auto *title = new QLabel(data["title"].toString());
    title->setStyleSheet("font-size: 20px; font-weight: bold; color: #1a2a3a;");
    title->setWordWrap(true);
    layout->addWidget(title);

    auto *timeLabel = new QLabel(QStringLiteral("生成时间: ") + data["created_at"].toString());
    timeLabel->setStyleSheet("font-size: 14px; color: #64748b;");
    layout->addWidget(timeLabel);

    auto *sep = new QFrame;
    sep->setFixedHeight(1);
    sep->setStyleSheet("background: #dce1e8;");
    layout->addWidget(sep);

    auto *content = new QTextEdit;
    content->setReadOnly(true);
    content->setStyleSheet(
      "QTextEdit { font-size: 14px; background: #fafbfc; "
      "border: 1px solid #dce1e8; border-radius: 8px; padding: 16px; }");

    QString contentStr = data["content"].toString();
    if (!contentStr.isEmpty()) {
      QJsonParseError err;
      auto doc = QJsonDocument::fromJson(contentStr.toUtf8(), &err);
      if (err.error == QJsonParseError::NoError) {
        content->setText(doc.toJson(QJsonDocument::Indented));
      } else {
        content->setText(contentStr);
      }
    } else {
      content->setText(
        QStringLiteral("目标: ") + m_target + "\n" +
        QStringLiteral("报告ID: ") + m_latestReportId + "\n" +
        QStringLiteral("运行ID: ") + data["run_id"].toString() + "\n" +
        QStringLiteral("状态: ") + data["status"].toString());
    }
    layout->addWidget(content, 1);

    auto *closeBtn = new QPushButton(QStringLiteral("关闭"));
    closeBtn->setProperty("primary", true);
    closeBtn->setFixedSize(120, 40);
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    auto *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    dlg.exec();
  });
}

// ── View history report ───────────────────────────────────────────────

void SimpleMainWindow::onViewHistoryReport(int row, int col)
{
  if (col != 3) return;
  auto *item = m_historyTable->item(row, 3);
  if (!item) return;
  QString reportId = item->data(Qt::UserRole).toString();
  if (reportId.isEmpty()) return;

  m_api->get("/api/reports/" + reportId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("无法加载报告"));
      return;
    }

    auto data = res["data"].toObject();
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("测试报告"));
    dlg.resize(750, 550);
    auto *layout = new QVBoxLayout(&dlg);
    layout->setSpacing(16);
    layout->setContentsMargins(28, 24, 28, 24);

    auto *title = new QLabel(data["title"].toString());
    title->setStyleSheet("font-size: 20px; font-weight: bold; color: #1a2a3a;");
    title->setWordWrap(true);
    layout->addWidget(title);

    auto *timeLabel = new QLabel(QStringLiteral("生成时间: ") + data["created_at"].toString());
    timeLabel->setStyleSheet("font-size: 14px; color: #64748b;");
    layout->addWidget(timeLabel);

    auto *sep = new QFrame;
    sep->setFixedHeight(1);
    sep->setStyleSheet("background: #dce1e8;");
    layout->addWidget(sep);

    auto *content = new QTextEdit;
    content->setReadOnly(true);
    content->setStyleSheet(
      "QTextEdit { font-size: 14px; background: #fafbfc; "
      "border: 1px solid #dce1e8; border-radius: 8px; padding: 16px; }");

    QString contentStr = data["content"].toString();
    if (!contentStr.isEmpty()) {
      QJsonParseError err;
      auto doc = QJsonDocument::fromJson(contentStr.toUtf8(), &err);
      if (err.error == QJsonParseError::NoError) {
        content->setText(doc.toJson(QJsonDocument::Indented));
      } else {
        content->setText(contentStr);
      }
    } else {
      content->setText(
        QStringLiteral("报告ID: ") + data["report_id"].toString() + "\n" +
        QStringLiteral("运行ID: ") + data["run_id"].toString() + "\n" +
        QStringLiteral("状态: ") + data["status"].toString());
    }
    layout->addWidget(content, 1);

    auto *closeBtn = new QPushButton(QStringLiteral("关闭"));
    closeBtn->setProperty("primary", true);
    closeBtn->setFixedSize(120, 40);
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    auto *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    dlg.exec();
  });
}

// ── Load history ──────────────────────────────────────────────────────

void SimpleMainWindow::loadHistory()
{
  m_api->get("/api/reports", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_historyTable->setRowCount(arr.size());

    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString title = r["title"].toString();
      QString reportId = r["report_id"].toString();

      QString target = title;
      int idx = target.indexOf(QStringLiteral(" 渗透测试报告"));
      if (idx > 0) target = target.left(idx);

      m_historyTable->setItem(i, 0, new QTableWidgetItem(target));
      m_historyTable->setItem(i, 1, new QTableWidgetItem(formatTime(r["created_at"].toString())));

      QString status = r["status"].toString();
      if (status.isEmpty()) status = QStringLiteral("已完成");
      auto *statusItem = new QTableWidgetItem(status);
      if (status == QStringLiteral("已完成")) {
        statusItem->setForeground(QColor("#22c55e"));
      }
      m_historyTable->setItem(i, 2, statusItem);

      auto *viewItem = new QTableWidgetItem(QStringLiteral("查看"));
      viewItem->setData(Qt::UserRole, reportId);
      viewItem->setForeground(QColor("#2563eb"));
      m_historyTable->setItem(i, 3, viewItem);
    }
    m_historyTable->resizeColumnsToContents();
    m_historyTable->horizontalHeader()->setStretchLastSection(true);
  });
}

// ── Logout ────────────────────────────────────────────────────────────

void SimpleMainWindow::onLogout()
{
  QMessageBox msgBox(this);
  msgBox.setWindowTitle(QStringLiteral("退出登录"));
  msgBox.setText(QStringLiteral("确定要退出登录吗？"));
  msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
  msgBox.setDefaultButton(QMessageBox::No);
  if (msgBox.exec() != QMessageBox::Yes) return;

  m_pollTimer->stop();

  // Disconnect WebSocket
  if (m_ws) m_ws->disconnectFromServer();

  // Exit the event loop — main.cpp's loop will delete this window
  // and show the login dialog again.
  QApplication::quit();
}
