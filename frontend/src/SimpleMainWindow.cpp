#include "SimpleMainWindow.h"
#include "ApiClient.h"
#include "LoginDialog.h"
#include "Theme.h"
#include "WsClient.h"
#include "pages/ScanPage.h"
#include "pages/ExecutionPage.h"
#include "pages/EvaluatePage.h"
#include "pages/PayloadPage.h"
#include "pages/PlaybookPage.h"
#include "pages/DongleLockPage.h"
#include "services/dongle/DongleService.h"
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
#include <QPointer>
#include <QDialogButtonBox>
#include <QTextBrowser>
#include "UiUtil.h"

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
{
  setupUI();
  auto *wsClient = new WsClient(m_api, this);
  connect(wsClient, &WsClient::runReact, m_executionPage, &ExecutionPage::onRunReact);
  connect(wsClient, &WsClient::runCompleted, m_executionPage, &ExecutionPage::onRefreshRuns);
  wsClient->connectToServer();
  updateStageUI();
  loadHistory();

  // 加密锁运行时心跳：每 5s 校验一次策略，失败则锁屏，恢复则回到原页面。
  m_dongleTimer = new QTimer(this);
  m_dongleTimer->setInterval(5000);
  connect(m_dongleTimer, &QTimer::timeout, this, &SimpleMainWindow::verifyDongleHeartbeat);
  m_dongleTimer->start();
}

void SimpleMainWindow::setupUI()
{
  setWindowTitle(QStringLiteral("信息系统渗透智能化测试平台"));
  resize(1280, 800);
  setMinimumSize(1024, 600);

  auto *centralWidget = new QWidget(this);
  centralWidget->setObjectName("contentArea");
  auto *mainLayout = new QHBoxLayout(centralWidget);

  // Shared visual language with the administrator workspace.
  auto *sidebar = new QFrame(centralWidget);
  sidebar->setObjectName("sidebar");
  sidebar->setFixedWidth(224);
  sidebar->setStyleSheet(
    "QFrame#sidebar { background:#10243e; border:none; }"
    "QListWidget#navList { background:transparent; color:#a8bdd5; border:none; outline:none; }"
    "QListWidget#navList::item { padding:12px 10px; margin:2px 0; border-radius:8px; }"
    "QListWidget#navList::item:selected { background:#2563eb; color:white; }"
    "QListWidget#navList::item:hover:!selected { background:#1d3655; color:white; }");
  auto *sidebarLayout = new QVBoxLayout(sidebar);
  sidebarLayout->setContentsMargins(16, 22, 16, 16);
  sidebarLayout->setSpacing(14);
  auto *brand = new QLabel(QStringLiteral("红队安全测试"), sidebar);
  brand->setStyleSheet("color:#ffffff; font-size:19px; font-weight:700;");
  sidebarLayout->addWidget(brand);
  auto *identity = new QLabel(QStringLiteral("普通用户工作区"), sidebar);
  identity->setStyleSheet("color:#93b4d5; font-size:12px;");
  sidebarLayout->addWidget(identity);
  auto *divider = new QFrame(sidebar);
  divider->setFixedHeight(1);
  divider->setStyleSheet("background:#294667;");
  sidebarLayout->addWidget(divider);
  m_navList = new QListWidget(sidebar);
  m_navList->setObjectName("navList");
  for (const auto &name : m_modules) m_navList->addItem(name);
  m_navList->setCurrentRow(0);
  sidebarLayout->addWidget(m_navList, 1);
  auto *guide = new QLabel(QStringLiteral("扫描目标 → 确认方案\n执行测试 → 查看报告"), sidebar);
  guide->setStyleSheet("color:#93b4d5; font-size:12px;");
  guide->setWordWrap(true);
  sidebarLayout->addWidget(guide);

  // ── Right: stacked pages ───────────────────────────────────────────
  m_stackWidget = new QStackedWidget(this);

  // Page 0: Quick test (custom page)
  auto *quickPage = new QWidget;
  setupQuickTestPage(quickPage);
  m_stackWidget->addWidget(quickPage);

  // Page 1: Scan tasks (reuse ScanPage)
  m_scanPage = new ScanPage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_scanPage);

  // Page 2: Payload library
  m_stackWidget->addWidget(new PayloadPage(m_api, m_role, m_username, this));

  // Page 3: Playbook (想定预案)
  m_playbookPage = new PlaybookPage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_playbookPage);

  // Page 4: Execution (攻击执行)
  m_executionPage = new ExecutionPage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_executionPage);

  // Page 5: Evaluate (测试评估)
  m_evaluatePage = new EvaluatePage(m_api, m_role, m_username, this);
  m_stackWidget->addWidget(m_evaluatePage);

  // 加密锁锁屏页（不占导航行，仅在校验失败时显示）
  m_dongleLockPage = new DongleLockPage(this);
  m_stackWidget->addWidget(m_dongleLockPage);

  // Cross-page navigation: ScanPage → ExecutionPage (select playbook)
  connect(m_scanPage, &ScanPage::playbookNavigateRequested, this, [this](const QString &playbookId, const QString &target) {
    m_executionPage->selectPlaybook(playbookId, target);
    m_navList->setCurrentRow(4);  // switch to "攻击执行" page
  });

  connect(m_scanPage, &ScanPage::attackRequested, this,
    [this](const QString &target, const QString &vulnText, const QString &resultType) {
      m_executionPage->attackFromVuln(target, vulnText, resultType);
      m_navList->setCurrentRow(4);
    });

  // Cross-page navigation: PlaybookPage → ExecutionPage (go execute)
  // Primary: direct callback (most reliable)
  m_playbookPage->setGoExecuteCallback([this](const QString &playbookId) {
    m_executionPage->selectPlaybook(playbookId, QString());
    m_navList->setCurrentRow(4);  // switch to "攻击执行" page
    statusBar()->showMessage(QString("已跳转到攻击执行，已预填预案：%1").arg(playbookId), 3000);
  });
  // Secondary: Qt signal (for any other listeners)
  connect(m_playbookPage, &PlaybookPage::executeRequested, this, [this](const QString &playbookId) {
    // Navigation already handled by callback above; this is for extensibility
    Q_UNUSED(playbookId);
  });

  mainLayout->setContentsMargins(0, 0, 0, 0);
  mainLayout->setSpacing(0);
  mainLayout->addWidget(sidebar);
  mainLayout->addWidget(m_stackWidget, 1);
  setCentralWidget(centralWidget);

  // ── Status bar ─────────────────────────────────────────────────────
  auto *checkBtn = new QPushButton(QStringLiteral("检测连接"), this);
  checkBtn->setObjectName("checkBtn");
  checkBtn->setFixedWidth(90);
  statusBar()->addWidget(checkBtn);

  auto *statusLabel = new QLabel(QStringLiteral("未检测"), this);
  statusLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
  statusBar()->addWidget(statusLabel);

  // User info label
  QString roleLabel = m_role;
  if (m_role == "admin") roleLabel = "管理员";
  else if (m_role == "user") roleLabel = "普通用户";
  auto *userLabel = new QLabel(
    QString("%1 [%2]").arg(m_username, roleLabel), this);
  userLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
  statusBar()->addWidget(userLabel);

  m_currentTaskBtn = new QPushButton(QStringLiteral("返回当前任务"), this);
  m_currentTaskBtn->setObjectName("checkBtn");
  m_currentTaskBtn->hide();
  statusBar()->addPermanentWidget(m_currentTaskBtn);
  connect(m_currentTaskBtn, &QPushButton::clicked, this, [this]() {
    m_navList->setCurrentRow(0);
  });
  m_currentReportBtn = new QPushButton(QStringLiteral("查看本次报告"), this);
  m_currentReportBtn->setObjectName("checkBtn");
  m_currentReportBtn->hide();
  statusBar()->addPermanentWidget(m_currentReportBtn);
  connect(m_currentReportBtn, &QPushButton::clicked, this, &SimpleMainWindow::onViewReport);

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
    statusBar()->showMessage(QString("接口错误: %1 -- %2").arg(path, msg), 5000);
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

// ── Quick test page ───────────────────────────────────────────────────

void SimpleMainWindow::setupQuickTestPage(QWidget *page)
{
  page->setStyleSheet(Theme::PageStyle);

  auto *scrollArea = new QScrollArea(page);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);
  layout->setSpacing(16);
  layout->setContentsMargins(24, 20, 24, 20);
  auto *heading = new QLabel(QStringLiteral("测试工作台"));
  heading->setStyleSheet("font-size:24px; font-weight:700; color:#172033;");
  layout->addWidget(heading);
  auto *intro = new QLabel(QStringLiteral("从目标扫描开始，逐步完成方案确认、执行和评估。"));
  intro->setWordWrap(true);
  intro->setStyleSheet("font-size:13px; color:#64748b;");
  layout->addWidget(intro);
  m_workflowHint = new QLabel(QStringLiteral("第一步：填写目标地址，开始扫描并生成方案。"));
  m_workflowHint->setObjectName("workflowHint");
  m_workflowHint->setWordWrap(true);
  m_workflowHint->setTextFormat(Qt::PlainText);
  m_workflowHint->setStyleSheet(Theme::StatusInfoStyle);
  layout->addWidget(m_workflowHint);

  // ══ Quick test card ═══════════════════════════════════════════════
  auto *testCard = new QFrame;
  testCard->setProperty("card", true);
  auto *testLayout = new QVBoxLayout(testCard);
  testLayout->setContentsMargins(24, 20, 24, 20);
  testLayout->setSpacing(18);

  auto *testTitle = new QLabel(QStringLiteral("新建测试"));
  testTitle->setStyleSheet(Theme::SectionStyle);
  testLayout->addWidget(testTitle);

  auto *descLabel = new QLabel(
    QStringLiteral("扫描并生成方案后，由你审阅确认；执行结束后自动生成本次报告。"));
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
  m_targetInput->setMinimumWidth(150);
  m_targetInput->setObjectName("quickTestTarget");
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

  m_startBtn = new QPushButton(QStringLiteral("开始扫描并生成方案"));
  m_startBtn->setProperty("primary", true);
  m_startBtn->setProperty("large", true);
  m_startBtn->setMinimumSize(210, 42);
  m_startBtn->setObjectName("quickTestStart");
  btnRow->addWidget(m_startBtn);

  m_retryBtn = new QPushButton(QStringLiteral("重新开始扫描"));
  m_retryBtn->setVisible(false);
  m_retryBtn->setMinimumHeight(42);
  m_retryBtn->setObjectName("quickTestRetry");
  m_retryBtn->setProperty("warning", true);
  m_retryBtn->setProperty("large", true);
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
  progressLayout->setContentsMargins(24, 18, 24, 18);
  progressLayout->setSpacing(14);

  auto *progressTitle = new QLabel(QStringLiteral("任务进度"));
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
    m_stages[i].statusLabel->setObjectName(QString("quickStageStatus%1").arg(i));
    m_stages[i].statusLabel->setWordWrap(true);
    m_stages[i].statusLabel->setStyleSheet("font-size: 14px; color: #94a3b8;");

    m_stages[i].thoughtLabel = new QLabel;
    m_stages[i].thoughtLabel->setTextFormat(Qt::PlainText);
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
  summaryLayout->setContentsMargins(24, 18, 24, 18);
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
  m_viewPlaybookBtn->setFixedSize(84, 28);
  m_viewPlaybookBtn->setProperty("compact", true);
  m_viewPlaybookBtn->setProperty("primary", true);
  m_viewPlaybookBtn->setVisible(false);
  pbRow->addWidget(m_viewPlaybookBtn);

  m_gotoExecBtn = new QPushButton(QStringLiteral("审阅方案 →"));
  m_gotoExecBtn->setObjectName("quickTestContinue");
  m_gotoExecBtn->setProperty("primary", true);
  m_gotoExecBtn->setMinimumHeight(38);
  m_gotoExecBtn->setVisible(false);
  btnRow->insertWidget(2, m_gotoExecBtn);

  summaryLayout->addLayout(pbRow);

  connect(m_viewPlaybookBtn, &QPushButton::clicked, this, &SimpleMainWindow::onViewPlaybook);
  connect(m_gotoExecBtn, &QPushButton::clicked, this, &SimpleMainWindow::onReviewPlan);

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
  reportLayout->setContentsMargins(24, 18, 24, 18);
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
  m_generateReportBtn = new QPushButton(QStringLiteral("生成本次结果报告"));
  m_generateReportBtn->setObjectName("generateCurrentReport");
  m_generateReportBtn->setProperty("primary", true);
  m_generateReportBtn->hide();
  reportRow->addWidget(m_generateReportBtn);
  connect(m_generateReportBtn, &QPushButton::clicked, this, &SimpleMainWindow::onGenerateCurrentReport);
  reportLayout->addLayout(reportRow);

  connect(m_viewReportBtn, &QPushButton::clicked, this, &SimpleMainWindow::onViewReport);

  layout->addWidget(m_reportFrame);

  // ══ History card ══════════════════════════════════════════════════
  auto *historyCard = new QFrame;
  historyCard->setProperty("card", true);
  auto *historyLayout = new QVBoxLayout(historyCard);
  historyLayout->setContentsMargins(24, 18, 24, 18);
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
  UiUtil::EmptyHint::attach(m_historyTable, QStringLiteral("暂无报告 · 完成执行后可生成并查看报告"));
  historyLayout->addWidget(m_historyTable);

  connect(m_historyTable, &QTableWidget::cellClicked, this, &SimpleMainWindow::onViewHistoryReport);

  layout->addWidget(historyCard, 1);

  // Finalize scroll area
  scrollArea->setWidget(container);
  auto *pageLayout = new QVBoxLayout(page);
  pageLayout->setContentsMargins(0, 0, 0, 0);
  pageLayout->addWidget(scrollArea);
  resetStageRows();
}

// ── Module navigation ─────────────────────────────────────────────────

void SimpleMainWindow::onModuleChanged(int row)
{
  if (m_dongleLocked) return;
  if (row >= 0 && row < m_stackWidget->count()) {
    m_stackWidget->setCurrentIndex(row);
  }
}

void SimpleMainWindow::verifyDongleHeartbeat()
{
  QString error;
  const bool valid = DongleService::verifyPolicy(DongleService::policyDir(), &error);
  if (!valid) {
    setDongleLocked(true, error);
  } else if (m_dongleLocked) {
    setDongleLocked(false);
  }
}

void SimpleMainWindow::setDongleLocked(bool locked, const QString &errorMessage)
{
  if (locked == m_dongleLocked && locked) {
    if (m_dongleLockPage) {
      m_dongleLockPage->setErrorMessage(errorMessage);
    }
    return;
  }

  if (locked) {
    const int current = m_stackWidget ? m_stackWidget->currentIndex() : -1;
    if (current >= 0 && m_dongleLockPage && m_stackWidget->widget(current) != m_dongleLockPage) {
      m_pageBeforeDongleLock = current;
    }
    m_dongleLocked = true;
    if (m_dongleLockPage && m_stackWidget) {
      m_dongleLockPage->setErrorMessage(errorMessage);
      m_stackWidget->setCurrentWidget(m_dongleLockPage);
    }
    if (m_navList) {
      m_navList->setEnabled(false);
    }
    return;
  }

  m_dongleLocked = false;
  if (m_navList) {
    m_navList->setEnabled(true);
  }
  if (m_pageBeforeDongleLock >= 0 && m_pageBeforeDongleLock < m_stackWidget->count()) {
    m_stackWidget->setCurrentIndex(m_pageBeforeDongleLock);
    m_navList->setCurrentRow(m_pageBeforeDongleLock);
  }
}

// ── Stage management ──────────────────────────────────────────────────

void SimpleMainWindow::setStage(Stage s)
{
  if (s == Failed && m_currentStage != Failed) m_failedStage = m_currentStage;
  m_currentStage = s;
  updateStageUI();
}

void SimpleMainWindow::resetStageRows()
{
  for (int i = 0; i < 5; ++i) {
    updateStageRow(i, QStringLiteral("—"), 0,
      i < 3 ? QStringLiteral("等待开始") : QStringLiteral("待确认方案"), "#94a3b8");
    m_stages[i].thoughtLabel->clear();
    m_stages[i].thoughtLabel->hide();
  }
}

void SimpleMainWindow::showStageError(int index, const QString &message)
{
  updateStageRow(index, QStringLiteral("!"), 0, QStringLiteral("未完成"), "#b42318");
  m_stages[index].thoughtLabel->setText(message);
  m_stages[index].thoughtLabel->setStyleSheet("font-size:12px; color:#b42318; padding-left:56px;");
  m_stages[index].thoughtLabel->show();
}

void SimpleMainWindow::updateStageUI()
{
  // Rows follow actual results, not the overall stage.
  const bool busy = m_currentStage == PortScan || m_currentStage == VulnScan ||
                    m_currentStage == GenPlaybook || m_currentStage == ExecAttack ||
                    m_currentStage == GenReport;
  m_startBtn->setEnabled(!busy && !m_reviewPending && (m_currentStage != Failed || m_failedStage == ExecAttack));
  const bool planReady = m_currentStage == PlanReady;
  m_startBtn->setProperty("primary", !planReady);
  m_startBtn->style()->unpolish(m_startBtn);
  m_startBtn->style()->polish(m_startBtn);
  m_startBtn->update();
  m_targetInput->setEnabled(!busy && !m_reviewPending);
  m_portsInput->setEnabled(!busy && !m_reviewPending);
  m_retryBtn->setVisible(m_currentStage == Failed && m_failedStage != ExecAttack);
  m_retryBtn->setText(m_failedStage == GenPlaybook ? QStringLiteral("重试方案生成")
    : m_failedStage == GenReport ? QStringLiteral("重试生成报告") : QStringLiteral("重新开始扫描"));
  m_gotoExecBtn->setVisible(planReady);
  m_gotoExecBtn->setEnabled(planReady && !m_reviewPending);
  m_currentTaskBtn->setVisible(m_currentStage != Idle);
  m_currentReportBtn->setVisible(!m_latestReportId.isEmpty());
  m_generateReportBtn->setVisible(!m_runTerminalStatus.isEmpty() && m_latestReportId.isEmpty()
                                  && m_currentStage != GenReport);
  m_startBtn->setText(busy ? QStringLiteral("正在处理…") :
    m_currentStage == PlanReady || m_currentStage == Done
      ? QStringLiteral("开始新的扫描") : QStringLiteral("开始扫描并生成方案"));
  m_workflowHint->setStyleSheet(m_currentStage == Failed
    ? Theme::StatusErrorStyle : Theme::StatusInfoStyle);
  switch (m_currentStage) {
    case Idle:
      m_workflowHint->setText(QStringLiteral("第一步：填写目标地址，开始扫描并生成方案。"));
      break;
    case PortScan:
    case VulnScan:
      m_workflowHint->setText(QStringLiteral("正在扫描 %1；结果会自动更新，可切换页面查看其他任务。").arg(m_target));
      break;
    case GenPlaybook:
      m_workflowHint->setText(QStringLiteral("扫描已完成，正在生成方案；暂未执行攻击。"));
      break;
    case PlanReady:
      m_workflowHint->setText(QStringLiteral("方案已就绪。下一步：审阅目标与方案步骤，确认后开始执行；完成后自动生成报告。"));
      updateStageRow(3, QStringLiteral("→"), 0, QStringLiteral("待确认并执行"), "#b45309");
      updateStageRow(4, QStringLiteral("—"), 0, QStringLiteral("执行后生成"), "#64748b");
      break;
    case Failed:
      m_workflowHint->setText(QStringLiteral("任务未完成，已保留各阶段结果。请查看下方原因后重试；不会自动继续执行。"));
      break;
    case Done:
      m_workflowHint->setStyleSheet(Theme::StatusSuccessStyle);
      m_workflowHint->setText(m_runTerminalStatus == "COMPLETED"
        ? QStringLiteral("本次测试与报告已完成。可直接查看报告，或在执行页检查证据。")
        : QStringLiteral("本次结果报告已生成，包含执行失败或中止的情况；不代表测试全部成功。"));
      break;
    case ExecAttack:
      m_workflowHint->setText(QStringLiteral("正在执行 %1，可查看实时步骤或停止执行；完成后自动生成报告。").arg(m_target));
      break;
    case GenReport:
      m_workflowHint->setText(QStringLiteral("正在整理本次执行结果并生成报告，请稍候。"));
      break;
    default:
      m_workflowHint->setText(QStringLiteral("正在处理当前阶段，请稍候。"));
      break;
  }
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
  m_stages[index].progress->setStyleSheet(
    QString("QProgressBar { background:#e2e8f0; border:none; border-radius:5px; }"
            "QProgressBar::chunk { background:%1; border-radius:5px; }").arg(color));
  m_stages[index].statusLabel->setText(status);
  m_stages[index].statusLabel->setStyleSheet(
    QString("font-size: 14px; color: %1;").arg(color));
}

// ── One-click start ───────────────────────────────────────────────────

void SimpleMainWindow::onStartTest()
{
  if (m_reviewPending || m_currentStage == PortScan || m_currentStage == VulnScan ||
      m_currentStage == GenPlaybook || m_currentStage == ExecAttack || m_currentStage == GenReport) return;
  QString target = m_targetInput->text().trimmed();
  if (target.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("提示"),
                         QStringLiteral("请输入目标地址"));
    return;
  }

  ++m_workflowRevision;
  m_runPollInFlight = false;
  m_runTerminalStatus.clear();
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

  resetStageRows();
  m_portScanSucceeded = m_vulnScanSucceeded = false;
  m_portPollInFlight = m_vulnPollInFlight = false;
  m_failedStage = Idle;
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
      showStageError(0, res["error"].toObject()["message"].toString(QStringLiteral("创建失败，请检查服务连接")));
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
          showStageError(0, execRes["error"].toObject()["message"].toString(QStringLiteral("执行失败，请检查服务连接")));
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
      showStageError(1, res["error"].toObject()["message"].toString(QStringLiteral("创建失败，请检查服务连接")));
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
          showStageError(1, execRes["error"].toObject()["message"].toString(QStringLiteral("执行失败，请检查服务连接")));
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
  QPointer<SimpleMainWindow> self(this);
  if (!m_portScanDone && !m_portScanTaskId.isEmpty() && !m_portPollInFlight) {
    m_portPollInFlight = true;
    const QString taskId = m_portScanTaskId;
    m_api->get("/api/scan-tasks/" + taskId, 5000,
      [this, self, taskId](const QJsonObject &res) {
        if (!self || taskId != m_portScanTaskId) return;
        m_portPollInFlight = false;
        if (m_portScanDone) return;
        if (res["status"].toString() != "ok") {
          updateStageRow(0, "…", m_stages[0].progress->value(), QStringLiteral("连接中断，重试中"), "#b45309");
          return;
        }
        auto d = res["data"].toObject();
        QString status = d["status"].toString();
        if (status == "COMPLETED") {
          updateStageRow(0, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
          m_portScanSucceeded = true;
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
          } else {
            m_portsLabel->setText(QStringLiteral("开放端口: 未发现"));
          }
          m_portScanDone = true;
          checkBothScansDone();
        } else if (status == "FAILED" || status == "CANCELLED") {
          showStageError(0, d["error_message"].toString(QStringLiteral("扫描失败或已取消，请检查扫描任务详情")));
          m_portScanDone = true;
          checkBothScansDone();
        } else if (status == "RUNNING") {
          updateStageRow(0, ">>", 50, QStringLiteral("扫描中..."), "#2563eb");
        } else if (status == "PENDING") {
          updateStageRow(0, ">>", 20, QStringLiteral("等待执行..."), "#f59e0b");
        }
      });
  }

  if (!m_vulnScanDone && !m_vulnScanTaskId.isEmpty() && !m_vulnPollInFlight) {
    m_vulnPollInFlight = true;
    const QString taskId = m_vulnScanTaskId;
    m_api->get("/api/scan-tasks/" + taskId, 5000,
      [this, self, taskId](const QJsonObject &res) {
        if (!self || taskId != m_vulnScanTaskId) return;
        m_vulnPollInFlight = false;
        if (m_vulnScanDone) return;
        if (res["status"].toString() != "ok") {
          updateStageRow(1, "…", m_stages[1].progress->value(), QStringLiteral("连接中断，重试中"), "#b45309");
          return;
        }
        auto d = res["data"].toObject();
        QString status = d["status"].toString();
        if (status == "COMPLETED") {
          updateStageRow(1, "[OK]", 100, QStringLiteral("已完成"), "#22c55e");
          m_vulnScanSucceeded = true;
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
          showStageError(1, d["error_message"].toString(QStringLiteral("扫描失败或已取消，请检查扫描任务详情")));
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
  if (m_currentStage != PortScan && m_currentStage != VulnScan) return;
  if (m_portScanDone && m_vulnScanDone) {
    m_pollTimer->stop();
    if (!m_portScanSucceeded || !m_vulnScanSucceeded) {
      updateStageRow(2, "—", 0, QStringLiteral("等待扫描完成"), "#64748b");
      setStage(Failed);
      return;
    }
    advanceStage();
  }
}

// ── Start playbook execution (called after playbook is ready) ─────────

void SimpleMainWindow::onReviewPlan()
{
  if (m_currentStage != PlanReady || m_playbookId.isEmpty() || m_reviewPending) return;
  m_reviewPending = true;
  updateStageUI();
  const int revision = m_workflowRevision;
  const QString playbookId = m_playbookId;
  QPointer<SimpleMainWindow> self(this);
  m_api->get("/api/playbooks/" + playbookId, 10000,
    [this, self, revision, playbookId](const QJsonObject &res) {
      if (!self || revision != m_workflowRevision) return;
      m_reviewPending = false;
      updateStageUI();
      const auto plan = res["data"].toObject();
      const auto steps = plan["steps"].toArray();
      if (res["status"].toString() != "ok" || steps.isEmpty()) {
        m_workflowHint->setText(QStringLiteral("无法审阅方案：详情加载失败或没有可执行步骤。请重试或选择其他方案。"));
        m_workflowHint->setStyleSheet(Theme::StatusErrorStyle);
        return;
      }
      QDialog dialog(this);
      dialog.setObjectName("workflowReviewDialog");
      dialog.setWindowTitle(QStringLiteral("审阅本次测试方案"));
      dialog.resize(760, 560);
      auto *layout = new QVBoxLayout(&dialog);
      auto *content = new QTextBrowser(&dialog);
      content->setOpenExternalLinks(false);
      QString html = QString("<h2>%1</h2><p><b>本次目标：</b>%2</p>"
        "<p><b>扫描来源：</b>%3 / %4</p><p>%5</p><h3>计划执行 %6 个步骤</h3><ol>")
        .arg(plan["name"].toString().toHtmlEscaped(), m_target.toHtmlEscaped(),
             m_portScanTaskId.toHtmlEscaped(), m_vulnScanTaskId.toHtmlEscaped(),
             plan["description"].toString().toHtmlEscaped()).arg(steps.size());
      for (const auto &value : steps) {
        const auto step = value.toObject();
        html += QString("<li><b>%1</b> · 工具：%2<p>%3</p></li>")
          .arg(step["name"].toString(step["step_id"].toString()).toHtmlEscaped(),
               step["tool_id"].toString().toHtmlEscaped(),
               step["description"].toString().toHtmlEscaped());
      }
      html += QStringLiteral("</ol><p>确认后开始执行以上方案，执行结束后自动生成本次结果报告。</p>");
      content->setHtml(html);
      layout->addWidget(content);
      auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
      UiUtil::styleDialogButtons(buttons);
      buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("确认并开始执行"));
      buttons->button(QDialogButtonBox::Ok)->setObjectName("confirmWorkflowExecution");
      buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("返回修改"));
      connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
      connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
      layout->addWidget(buttons);
      if (dialog.exec() != QDialog::Accepted) return;
      if (!self || revision != m_workflowRevision || m_playbookId != playbookId ||
          m_currentStage != PlanReady) return;
      startExecution();
    });
}

void SimpleMainWindow::startExecution()
{
  if (m_currentStage != PlanReady || m_playbookId.isEmpty() || !m_runId.isEmpty()) return;
  setStage(ExecAttack);
  updateStageRow(3, "…", 0, QStringLiteral("创建执行记录…"), "#2563eb");
  m_navList->setCurrentRow(4);
  m_executionPage->focusDetails();
  const int revision = m_workflowRevision;
  QPointer<SimpleMainWindow> self(this);
  QJsonObject body{{"playbook_id", m_playbookId}, {"target", m_target},
                   {"scan_task_id", m_vulnScanTaskId}, {"user_sub", m_username}, {"user_role", m_role}};
  m_api->post("/api/runs", body, 10000, [this, self, revision](const QJsonObject &res) {
    if (!self || revision != m_workflowRevision) return;
    m_runId = res["data"].toObject()["run_id"].toString();
    if (res["status"].toString() != "ok" || m_runId.isEmpty()) {
      const QString message = res["error"].toObject()["message"].toString(
          QStringLiteral("未取得执行编号，请检查执行记录后再开始新任务"));
      showStageError(3, message);
      m_executionPage->showExecutionError(message);
      statusBar()->showMessage(message, 10000);
      setStage(Failed);
      return;
    }
    const QString runId = m_runId;
    m_api->post("/api/runs/" + runId + "/execute", {}, 10000,
      [this, self, revision, runId](const QJsonObject &started) {
        if (!self || revision != m_workflowRevision || runId != m_runId) return;
        m_executionPage->showRun(runId, false);
        if (started["status"].toString() != "ok") {
          // A timeout does not prove that the server failed to start.
          m_workflowHint->setText(QStringLiteral("启动响应异常，正在核对本次执行状态；请勿重复启动。"));
        }
        m_pollTimer->start();
        onPollRun();
      });
  });
}

// ── Advance to next stage ─────────────────────────────────────────────

void SimpleMainWindow::advanceStage()
{
  if (m_currentStage == PortScan || m_currentStage == VulnScan) {
    setStage(GenPlaybook);
    updateStageRow(2, ">>", 30, QStringLiteral("智能生成中..."), "#2563eb");

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
                showStageError(2, recRes["error"].toObject()["message"].toString(QStringLiteral("未找到可用方案，可重试生成或在预案库中选择")));
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

              // Plan ready; execution still requires the user.
              setStage(PlanReady);
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
        m_gotoExecBtn->setVisible(true);

        // Plan ready; execution still requires the user.
        setStage(PlanReady);
      });
  }
}

// ── Poll run status ───────────────────────────────────────────────────

void SimpleMainWindow::onPollRun()
{
  if (m_currentStage != ExecAttack || m_runId.isEmpty() || m_runPollInFlight) return;
  m_runPollInFlight = true;
  const int revision = m_workflowRevision;
  const QString runId = m_runId;
  QPointer<SimpleMainWindow> self(this);
  m_api->get("/api/runs/" + runId, 5000, [this, self, revision, runId](const QJsonObject &res) {
    if (!self || revision != m_workflowRevision || runId != m_runId) return;
    m_runPollInFlight = false;
    if (m_currentStage != ExecAttack) return;
    if (res["status"].toString() != "ok") {
      updateStageRow(3, "…", 0, QStringLiteral("连接中断，重试中"), "#b45309");
      return;
    }
    const auto data = res["data"].toObject();
    const QString status = data["status"].toString();
    if (status == "COMPLETED" || status == "FAILED" || status == "ABORTED" || status == "CANCELLED") {
      m_pollTimer->stop();
      m_runTerminalStatus = status;
      if (status == "COMPLETED") {
        updateStageRow(3, "✓", 100, QStringLiteral("已完成"), "#22c55e");
        onGenerateCurrentReport();
      } else {
        showStageError(3, data["final_summary"].toString(QStringLiteral("执行失败或已中止，可查看执行详情并生成本次结果报告")));
        updateStageRow(4, "—", 0, QStringLiteral("可生成结果报告"), "#b45309");
        setStage(Failed);
        statusBar()->showMessage(QStringLiteral("本次执行失败或已中止，可点击“返回当前任务”查看详情。"), 10000);
      }
      return;
    }
    const auto steps = data["steps"].toArray();
    int finished = 0;
    for (const auto &step : steps) {
      const auto success = step.toObject()["success"];
      if (success.isBool() || success.isDouble()) ++finished;
    }
    updateStageRow(3, "…", steps.isEmpty() ? 0 : finished * 100 / steps.size(),
      status == "PENDING" ? QStringLiteral("等待执行") :
      steps.isEmpty() ? QStringLiteral("执行中…") : QStringLiteral("已结束 %1/%2 步").arg(finished).arg(steps.size()), "#2563eb");
  });
}

void SimpleMainWindow::onGenerateCurrentReport()
{
  if (m_runId.isEmpty() || m_runTerminalStatus.isEmpty() || m_currentStage == GenReport) return;
  if (!m_latestReportId.isEmpty()) { onViewReport(); return; }
  setStage(GenReport);
  m_stages[4].thoughtLabel->hide();
  updateStageRow(4, "…", 0, QStringLiteral("正在生成报告…"), "#2563eb");
  const int revision = m_workflowRevision;
  const QString runId = m_runId;
  const QString title = m_target + QStringLiteral(" 渗透测试报告");
  QPointer<SimpleMainWindow> self(this);
  // Reconcile an earlier timed-out request before creating another report.
  m_api->get("/api/reports", 5000, [this, self, revision, runId, title](const QJsonObject &list) {
    if (!self || revision != m_workflowRevision || runId != m_runId) return;
    if (list["status"].toString() != "ok") {
      showStageError(4, QStringLiteral("无法核对已有报告，请恢复连接后重试；不会重复执行测试。"));
      setStage(Failed);
      return;
    }
    for (const auto &value : list["data"].toArray()) {
      const auto report = value.toObject();
      if (report["run_id"].toString() == runId && !report["report_id"].toString().isEmpty()) {
        finishReport(report["report_id"].toString(), report["title"].toString(title));
        return;
      }
    }
    m_api->post("/api/reports/generate", {{"run_id", runId}, {"title", title}}, 30000,
      [this, self, revision, runId, title](const QJsonObject &res) {
        if (!self || revision != m_workflowRevision || runId != m_runId) return;
        const QString id = res["data"].toObject()["report_id"].toString();
        if (res["status"].toString() != "ok" || id.isEmpty()) {
          showStageError(4, res["error"].toObject()["message"].toString(QStringLiteral("报告未生成，请重试；本次执行结果已保留")));
          setStage(Failed);
          statusBar()->showMessage(QStringLiteral("本次报告生成失败，可点击“返回当前任务”重试。"), 10000);
          return;
        }
        finishReport(id, title);
      });
  });
}

void SimpleMainWindow::finishReport(const QString &reportId, const QString &title)
{
  m_latestReportId = reportId;
  updateStageRow(4, "✓", 100, QStringLiteral("报告已生成"), "#22c55e");
  m_reportTitleLabel->setText(title);
  m_reportTitleLabel->setStyleSheet("font-size:15px; color:#1a2a3a;");
  m_viewReportBtn->show();
  setStage(Done);
  loadHistory();
  statusBar()->showMessage(QStringLiteral("本次报告已生成，点击“查看本次报告”直接预览或导出。"), 10000);
}

// ── Retry current stage ───────────────────────────────────────────────

void SimpleMainWindow::onRetryStage()
{
  if (m_currentStage != Failed) return;
  if (m_failedStage == GenReport) { onGenerateCurrentReport(); return; }
  if (m_failedStage == ExecAttack) return;
  if (m_failedStage == GenPlaybook) {
    m_stages[2].thoughtLabel->clear();
    m_stages[2].thoughtLabel->hide();
    // Reuse completed scans rather than creating duplicates.
    m_currentStage = PortScan;
    advanceStage();
    return;
  }
  onStartTest();
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
  m_navList->setCurrentRow(5);
  m_evaluatePage->showReport(m_latestReportId);
}

void SimpleMainWindow::onViewHistoryReport(int row, int col)
{
  if (col != 3) return;
  const auto *item = m_historyTable->item(row, 3);
  if (!item || item->data(Qt::UserRole).toString().isEmpty()) return;
  m_navList->setCurrentRow(5);
  m_evaluatePage->showReport(item->data(Qt::UserRole).toString());
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

  // Exit the event loop — main.cpp's loop will delete this window
  // and show the login dialog again.
  QApplication::quit();
}
