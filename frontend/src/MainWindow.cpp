#include "MainWindow.h"
#include "widgets/ModuleRibbon.h"
#include "pages/DeployConfigPage.h"
#include "ApiClient.h"
#include "LoginDialog.h"
#include "Theme.h"
#include "WsClient.h"
#include "ToastOverlay.h"
#include "pages/BasePage.h"
#include "pages/DashboardPage.h"
#include "pages/FlowPage.h"
#include "pages/TopologyPage.h"
#include "pages/PlaybookPage.h"
#include "pages/ScanPage.h"
#include "pages/ExecutionPage.h"
#include "pages/EvaluatePage.h"
#include "pages/ResultsPage.h"
#include "pages/AnalysisHubPage.h"
#include "pages/SystemPage.h"
#include "pages/DongleLockPage.h"
#include "services/dongle/DongleService.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QStatusBar>
#include <QMessageBox>
#include <QApplication>
#include <QFrame>
#include <QResizeEvent>
#include <QTimer>
#include <QPixmap>
#include <QIcon>
#include <QMenu>
#include <QSignalBlocker>
#include <QScopedValueRollback>
#include <QScrollArea>

namespace {
QString displayRole(const QString &role)
{
    if (role == QStringLiteral("admin")) return QStringLiteral("管理员");
    if (role == QStringLiteral("user")) return QStringLiteral("普通用户");
    return role;
}
}

MainWindow::MainWindow(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QMainWindow(parent)
    , m_api(api)
    , m_role(role)
    , m_username(username)
{
    setupUI();
    setupWebSocket();
    openRibbonFeature(QStringLiteral("resources.discovery"));

    // 加密锁运行时心跳：每 5s 校验一次策略，失败则锁屏，恢复则回到原页面。
    m_dongleTimer = new QTimer(this);
    m_dongleTimer->setInterval(5000);
    connect(m_dongleTimer, &QTimer::timeout, this, &MainWindow::verifyDongleHeartbeat);
    m_dongleTimer->start();
}

void MainWindow::setupUI()
{
    setWindowTitle(QStringLiteral("信息系统安全智能化测试平台"));
    resize(1360, 860);
    setMinimumSize(1024, 600);

    auto *centralWidget = new QWidget(this);
    centralWidget->setObjectName("contentArea");
    auto *rootLayout = new QVBoxLayout(centralWidget);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    centralWidget->setStyleSheet(QStringLiteral("QWidget#contentArea { background:#f3f5f9; }"));
    auto *topBar = new QFrame(centralWidget);
    topBar->setObjectName("appTopBar");
    topBar->setStyleSheet(QStringLiteral("QFrame#appTopBar { background:#eaf0fb; border-bottom:1px solid #dbe4f4; }"));
    auto *headerLayout = new QHBoxLayout(topBar);
    headerLayout->setContentsMargins(16, 4, 16, 4);
    headerLayout->setSpacing(8);
    auto *mark = new QLabel(QStringLiteral("安全测试"), topBar);
    mark->setStyleSheet("font-size:12px;font-weight:600;color:#6280a9;padding-left:4px;");
    headerLayout->addWidget(mark);
    headerLayout->addStretch();
    auto *title = new QLabel(QStringLiteral("信息系统安全智能化测试平台"), topBar);
    title->setObjectName("platformTitle");
    title->setStyleSheet(QStringLiteral("font-size:17px; font-weight:700; color:#244b82; padding:0 6px;"));
    headerLayout->addWidget(title);
    auto *collapse = new QPushButton(QStringLiteral("收起功能区"), topBar);
    m_navigationToggle = collapse;
    collapse->setObjectName("navigationToggle");
    collapse->setProperty("quiet", true);
    collapse->setCheckable(true);
    headerLayout->addWidget(collapse);
    rootLayout->addWidget(topBar);

    m_modules = QStringList{QStringLiteral("工作台"), QStringLiteral("测试任务"), QStringLiteral("资产与拓扑"),
        QStringLiteral("智能分析"), QStringLiteral("预案与知识库"), QStringLiteral("结果与报告"), QStringLiteral("系统管理")};
    m_navList = new QListWidget(centralWidget);
    m_navList->setObjectName("ribbonModuleTabs");
    QFont moduleFont = m_navList->font();
    moduleFont.setPixelSize(13);
    m_navList->setFont(moduleFont);
    m_navList->setTextElideMode(Qt::ElideNone);
    m_navList->setStyleSheet(QStringLiteral(
        "QListWidget#ribbonModuleTabs { background:white; border:none; border-bottom:1px solid #dfe5ef; outline:none; }"
        "QListWidget#ribbonModuleTabs::item { padding:4px 12px; margin:0 2px; color:#526984; border-bottom:3px solid transparent; }"
        "QListWidget#ribbonModuleTabs::item:selected { background:#f1f5ff; color:#245fd6; border-bottom:3px solid #2862d7; }"
        "QListWidget#ribbonModuleTabs::item:hover { background:#f6f8fc; }"));
    m_navList->setFlow(QListView::LeftToRight);
    m_navList->setWrapping(false);
    m_navList->setResizeMode(QListView::Adjust);
    m_navList->setMovement(QListView::Static);
    m_navList->setSpacing(0);
    m_navList->setFixedHeight(47);
    m_navList->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_navList->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_navList->setAccessibleName(QStringLiteral("功能模块"));
    for (const auto &name : ModuleRibbon::moduleNames()) {
        auto *item = new QListWidgetItem(name, m_navList);
        item->setToolTip(name);
        item->setSizeHint(QSize(m_navList->fontMetrics().horizontalAdvance(name) + 48, 35));
    }
    rootLayout->addWidget(m_navList);
    m_ribbon = new ModuleRibbon(m_role == QStringLiteral("admin"), centralWidget);
    rootLayout->addWidget(m_ribbon);
    m_contextBar = new QFrame(centralWidget);
    m_contextBar->setObjectName("ribbonTaskContext");
    m_contextBar->setStyleSheet(QStringLiteral("QFrame#ribbonTaskContext { background:#f7faff; border-bottom:1px solid #dfe5ef; }"));
    auto *contextLayout = new QHBoxLayout(m_contextBar);
    contextLayout->setContentsMargins(18, 3, 18, 3);
    m_contextLabel = new QLabel(QStringLiteral("工作台 · 从上方选择功能；任务中心保留测试流程与历史记录"), m_contextBar);
    m_contextLabel->setTextFormat(Qt::PlainText);
    m_contextLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_contextLabel->setMinimumWidth(0);
    m_contextLabel->setStyleSheet(QStringLiteral("font-size:12px; color:#5e7596;"));
    contextLayout->addWidget(m_contextLabel, 1);
    m_overviewButton = new QPushButton(QStringLiteral("任务概况"), m_contextBar);
    m_overviewButton->setObjectName("ribbonTaskOverview");
    m_overviewButton->setProperty("compact", true);
    m_resultsButton = new QPushButton(QStringLiteral("测试结果"), m_contextBar);
    m_resultsButton->setObjectName("ribbonTaskResults");
    m_resultsButton->setProperty("compact", true);
    m_overviewButton->setEnabled(false);
    m_resultsButton->setEnabled(false);
    contextLayout->addWidget(m_overviewButton);
    contextLayout->addWidget(m_resultsButton);
    rootLayout->addWidget(m_contextBar);
    connect(m_overviewButton, &QPushButton::clicked, this, [this]() { openTaskStage(0); });
    connect(m_resultsButton, &QPushButton::clicked, this, [this]() { openTaskStage(6); });
    connect(m_ribbon, &ModuleRibbon::featureRequested, this, &MainWindow::openRibbonFeature);
    connect(collapse, &QPushButton::toggled, this, [this, collapse](bool collapsed) {
        m_ribbon->setVisible(!collapsed);
        collapse->setText(collapsed ? QStringLiteral("展开功能区") : QStringLiteral("收起功能区"));
        collapse->setAccessibleName(collapse->text());
    });

    // Right: stacked pages
    m_stackWidget = new QStackedWidget(this);

    // Page 0: global dashboard
    m_dashboardPage = new DashboardPage(m_api, this);
    m_stackWidget->addWidget(m_dashboardPage);

    // Keep navigation indices stable while deferring unused module construction.
    for (int index = 1; index < m_modules.size(); ++index) {
        auto *placeholder = new QWidget(m_stackWidget);
        placeholder->setProperty("deferredModule", true);
        m_stackWidget->addWidget(placeholder);
    }

    // 加密锁锁屏页（不占导航行，仅在校验失败时显示）
    m_dongleLockPage = new DongleLockPage(this);
    m_stackWidget->addWidget(m_dongleLockPage);

    // Extra hosts are lazy; resource configuration never constructs user administration.
    for (int extra = 0; extra < 4; ++extra) {
        auto *placeholder = new QWidget(m_stackWidget);
        placeholder->setProperty("deferredModule", true);
        m_stackWidget->addWidget(placeholder);
    }
    m_navList->setCurrentRow(0);
    m_ribbon->setModule(0);

    m_featureHeader = new QWidget(centralWidget);
    m_featureHeader->setObjectName("featurePageHeader");
    auto *featureLayout = new QVBoxLayout(m_featureHeader);
    featureLayout->setContentsMargins(24, 16, 24, 12);
    featureLayout->setSpacing(5);
    m_featurePath = new QLabel(m_featureHeader);
    m_featurePath->setStyleSheet("font-size:11px;color:#8a99ae;");
    m_featureTitle = new QLabel(m_featureHeader);
    m_featureTitle->setObjectName("featurePageTitle");
    m_featureTitle->setTextFormat(Qt::PlainText);
    m_featureTitle->setStyleSheet("font-size:22px;font-weight:700;color:#203b60;");
    m_featureDescription = new QLabel(m_featureHeader);
    m_featureDescription->setTextFormat(Qt::PlainText);
    m_featureDescription->setWordWrap(true);
    m_featureDescription->setStyleSheet("font-size:12px;color:#7b8fa9;");
    featureLayout->addWidget(m_featurePath);
    featureLayout->addWidget(m_featureTitle);
    featureLayout->addWidget(m_featureDescription);
    rootLayout->addWidget(m_featureHeader);
    m_featureHeader->hide();
    m_taskGate = new QWidget(centralWidget);
    m_taskGate->setObjectName("featureTaskGate");
    auto *gateLayout = new QVBoxLayout(m_taskGate);
    gateLayout->setContentsMargins(40, 35, 40, 35);
    gateLayout->setSpacing(18);
    m_taskGateMessage = new QLabel(m_taskGate);
    m_taskGateMessage->setWordWrap(true);
    m_taskGateMessage->setStyleSheet("font-size:14px;color:#7c90ac;");
    m_chooseTaskButton = new QPushButton(QStringLiteral("选择测试任务"), m_taskGate);
    m_chooseTaskButton->setProperty("primary", true);
    m_chooseTaskButton->setFixedWidth(155);
    gateLayout->addWidget(m_taskGateMessage);
    gateLayout->addWidget(m_chooseTaskButton, 0, Qt::AlignLeft);
    gateLayout->addStretch();
    connect(m_chooseTaskButton, &QPushButton::clicked, this, &MainWindow::chooseTaskForFeature);
    rootLayout->addWidget(m_taskGate, 1);
    m_taskGate->hide();
    m_stackWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    rootLayout->addWidget(m_stackWidget, 1);
    setCentralWidget(centralWidget);

    // Toast overlay (positioned in top-right corner)
    m_toastOverlay = new ToastOverlay(this);

    // Status bar: backend check button + status label + logout
    m_checkBackendBtn = new QPushButton(QStringLiteral("检测连接"), this);
    m_checkBackendBtn->setObjectName("checkBtn");
    m_checkBackendBtn->setFixedWidth(90);
    statusBar()->addWidget(m_checkBackendBtn);

    m_backendStatusLabel = new QLabel(QStringLiteral("未检测"), this);
    m_backendStatusLabel->setStyleSheet("color: #64748b; padding: 0 10px; font-size: 13px;");
    statusBar()->addWidget(m_backendStatusLabel);

    // User info label in status bar
    m_userInfoLabel = new QLabel(QStringLiteral("%1 [%2]").arg(m_username, displayRole(m_role)), this);
    m_userInfoLabel->setTextFormat(Qt::PlainText);
    m_userInfoLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    m_userInfoLabel->setMaximumWidth(240);
    m_userInfoLabel->setToolTip(m_userInfoLabel->text().toHtmlEscaped());
    m_userInfoLabel->setStyleSheet("color: #64748b; padding: 0 10px; font-size: 13px;");
    statusBar()->addWidget(m_userInfoLabel);

    m_logoutBtn = new QPushButton(QStringLiteral("退出登录"), this);
    m_logoutBtn->setObjectName("checkBtn");
    m_logoutBtn->setFixedWidth(90);
    statusBar()->addPermanentWidget(m_logoutBtn);

    // Signals
    connect(m_navList, &QListWidget::currentRowChanged,
            this, &MainWindow::selectRibbonModule);
    // The home dashboard initially shares the first module row without opening it.
    connect(m_navList, &QListWidget::itemClicked, this, [this](QListWidgetItem *item) {
        if (m_navigationToggle->isChecked()) m_navigationToggle->setChecked(false);
        if (m_activeFeature.isEmpty()) selectRibbonModule(m_navList->row(item));
    });
    connect(m_checkBackendBtn, &QPushButton::clicked,
            this, &MainWindow::onCheckBackend);

    // Global API error → status bar
    connect(m_api, &ApiClient::apiError, this, [this](const QString &path, const QString &msg) {
        statusBar()->showMessage(QString("接口错误: %1 — %2").arg(path, msg), 5000);
    });

    // Logout button
    connect(m_logoutBtn, &QPushButton::clicked, this, &MainWindow::onLogout);

    connect(m_dashboardPage, &DashboardPage::openTasksRequested, this, [this]() {
        switchToPage(1);
    });
}

// ── WebSocket setup ────────────────────────────────────────────────────

void MainWindow::setupWebSocket()
{
    m_ws = new WsClient(m_api, this);
    m_ws->connectToServer();

    connect(m_ws, &WsClient::pipelineCreated, m_dashboardPage, &DashboardPage::scheduleRefresh);
    connect(m_ws, &WsClient::pipelineStatus, m_dashboardPage, &DashboardPage::scheduleRefresh);
    connect(m_ws, &WsClient::runCompleted, m_dashboardPage, &DashboardPage::scheduleRefresh);
    connectFlowWebSocket();

    // Wire to ToastOverlay
    if (m_role == QStringLiteral("admin")) {
        connect(m_ws, &WsClient::scanCompleted, m_toastOverlay, &ToastOverlay::onScanCompleted);
        connect(m_ws, &WsClient::runStepComplete, m_toastOverlay, &ToastOverlay::onRunStepComplete);
        connect(m_ws, &WsClient::runCompleted, m_toastOverlay, &ToastOverlay::onRunCompleted);
    }

    // WebSocket connection status in status bar
    connect(m_ws, &WsClient::connected, this, [this]() {
        statusBar()->showMessage(QStringLiteral("实时通道已连接"), 3000);
    });
    connect(m_ws, &WsClient::disconnected, this, [this]() {
        statusBar()->showMessage(QStringLiteral("实时通道已断开"), 3000);
    });
    connect(m_ws, &WsClient::connectionError, this, [this](const QString &err) {
        statusBar()->showMessage(QString("实时通道错误: %1").arg(err), 5000);
    });
}

QWidget *MainWindow::createModulePage(int index)
{
    switch (index) {
    case 1: {
        m_flowPage = new FlowPage(m_api, m_role, m_username, this);
        connect(m_flowPage, &FlowPage::returnPageRequested, this, &MainWindow::switchToPage);
        connectFlowWebSocket();
        m_flowPage->setRibbonNavigation(true);
        connect(m_flowPage, &FlowPage::taskContextChanged, this, &MainWindow::updateTaskContext);
        connect(m_flowPage, &FlowPage::taskListRequested, this, [this]() { openRibbonFeature("system.tasks"); });
        connect(m_flowPage, &FlowPage::workspaceStageChanged, this, [this](int stage) {
            if (m_routingFeature || !m_pendingTaskFeature.isEmpty() || m_dongleLocked || m_stackWidget->currentWidget() != m_flowPage) return;
            QString id;
            if (stage == 1) id = m_activeFeature.startsWith("scans.") ? m_activeFeature : "scans.system";
            else if (stage == 2) id = "plans.scenario";
            else if (stage == 3) id = m_activeFeature.startsWith("topology.") ? m_activeFeature : "topology.display";
            else if (stage == 4) id = "plans.task";
            else if (stage == 5) id = m_activeFeature.startsWith("attacks.") ? m_activeFeature : "attacks.data";
            else if (stage == 6 && m_activeFeature == "system.generate-report") id = m_activeFeature;
            m_activeFeature = id;
            const auto *entry = ModuleRibbon::feature(id);
            if (entry) {
                m_lastFeatures[entry->module] = id;
                const QSignalBlocker blocker(m_navList);
                m_navList->setCurrentRow(entry->module);
            }
            m_ribbon->setActiveFeature(id);
            updateFeaturePresentation();
            updateTaskContext();
        });
        return m_flowPage;
    }
    case 2: {
        auto *assetTopology=new TopologyPage(m_api,m_role,m_username,this);
        connect(assetTopology,&TopologyPage::testTargetRequested,this,[this,assetTopology](const QString &target) {
            if(m_dongleLocked) return;
            switchToPage(1);
            m_flowPage->createTestForTarget(target,assetTopology->selectedTargetContext());
        });
        connect(assetTopology,&TopologyPage::linkedTaskRequested,this,[this](const QString &pipelineId) {
            if(m_dongleLocked) return;
            switchToPage(1);
            m_flowPage->openTaskAnalysis(pipelineId);
        });

        if (m_ws) {
            connect(m_ws, &WsClient::scanStarted, assetTopology, &TopologyPage::onScanStarted);
            connect(m_ws, &WsClient::scanCompleted, assetTopology, &TopologyPage::onScanCompleted);
        }
        return assetTopology;
    }
    case 3: {
        m_analysisPage = new AnalysisHubPage(m_api, m_role, m_username, this);
        connect(m_analysisPage, &AnalysisHubPage::openTaskAnalysisRequested, this,
            [this](const QString &pipelineId) {
                if (m_dongleLocked) return;
                switchToPage(1);
                m_flowPage->openTaskAnalysis(pipelineId);
                m_flowPage->setReturnPage(3, QStringLiteral("智能分析"));
            });

        return m_analysisPage;
    }
    case 4: {
        auto *playbookPage = new PlaybookPage(m_api, m_role, m_username, this);

        // Cross-page navigation: PlaybookPage → FlowPage workbench (攻击 Tab)
        connect(playbookPage, &PlaybookPage::executeRequested, this,
            [this](const QString &id) {
                if (m_dongleLocked) return;
                switchToPage(1);  // 测试任务
                m_flowPage->jumpToExecution(id, QString());
                m_flowPage->setReturnPage(4, QStringLiteral("预案与知识库"));
            });

        return playbookPage;
    }
    case 5: {
        auto *resultsPage = new ResultsPage(m_api, m_role, m_username, this);
        connect(resultsPage, &ResultsPage::openTaskReportRequested, this,
            [this](const QString &pipelineId, const QString &reportId) {
                if (m_dongleLocked) return;
                switchToPage(1);
                m_flowPage->openTaskReport(pipelineId, reportId);
                m_flowPage->setReturnPage(5, QStringLiteral("结果与报告"));
            });
        return resultsPage;
    }

    case 6: {
        if (m_role == QStringLiteral("admin"))
            return new SystemPage(m_api, m_role, m_username, this);
        auto *restrictedPage = new QWidget(this);
        restrictedPage->setObjectName(QStringLiteral("systemPermissionPage"));
        restrictedPage->setStyleSheet(Theme::PageStyle);
        auto *restrictedLayout = new QVBoxLayout(restrictedPage);
        restrictedLayout->setContentsMargins(28, 24, 28, 24);
        auto *restrictedTitle = new QLabel(QStringLiteral("系统管理 · 权限说明"), restrictedPage);
        restrictedTitle->setStyleSheet(QStringLiteral("font-size:24px; font-weight:700; color:#12213c;"));
        auto *restrictedHint = new QLabel(QStringLiteral("当前账号：%1（普通用户）\n用户、权限、模型和部署配置由管理员维护。\n"
            "你可以在测试任务中创建自己的任务、编辑预案并提审；批准和驳回由管理员操作。\n"
            "此页不会加载管理接口。其他模块操作仍由后端权限校验。 ").arg(m_username), restrictedPage);
        restrictedHint->setTextFormat(Qt::PlainText);
        restrictedHint->setWordWrap(true);
        restrictedLayout->addWidget(restrictedTitle);
        restrictedLayout->addWidget(restrictedHint);
        auto *openTasks = new QPushButton(QStringLiteral("进入我的测试任务"), restrictedPage);
        openTasks->setProperty("primary", true);
        restrictedLayout->addWidget(openTasks, 0, Qt::AlignLeft);
        restrictedLayout->addStretch();
        connect(openTasks, &QPushButton::clicked, this, [this]() { switchToPage(1); });
        return restrictedPage;
    }
    case 8:
        if (m_role != QStringLiteral("admin")) return nullptr;
        m_deployPage = new DeployConfigPage(m_api, m_role, m_username, this);
        return m_deployPage;
    case 10: {
        m_standaloneScan = new ScanPage(m_api, m_role, m_username, this);
        m_standaloneScan->enableRibbonWorkspace();
        connect(m_standaloneScan, &ScanPage::taskSelectionRequested, this, [this]() { openRibbonFeature("system.tasks"); });
        connect(m_standaloneScan, &ScanPage::playbookNavigateRequested, this, [this](const QString &id, const QString &target) {
            switchToPage(1);
            m_flowPage->jumpToExecution(id, target);
        });
        connect(m_standaloneScan, &ScanPage::attackRequested, this, [this](const QString &target, const QString &text, const QString &type) {
            switchToPage(11);
            m_standaloneExecution->attackFromVuln(target, text, type);
        });
        if (m_ws) {
            const auto refresh = [this]() { if (m_standaloneScan->isVisible()) m_standaloneScan->onRefreshTasks(); };
            connect(m_ws, &WsClient::scanCompleted, m_standaloneScan, refresh);
            connect(m_ws, &WsClient::connected, m_standaloneScan, refresh);
        }
        return m_standaloneScan;
    }
    case 11:
        m_standaloneExecution = new ExecutionPage(m_api, m_role, m_username, this);
        if (m_ws) {
            connect(m_ws, &WsClient::runReact, m_standaloneExecution, &ExecutionPage::onRunReact);
            connect(m_ws, &WsClient::runCompleted, m_standaloneExecution, &ExecutionPage::onRefreshRuns);
        }
        return m_standaloneExecution;
    case 9:
        m_capturePage = new EvaluatePage(m_api, m_role, m_username, this);
        return m_capturePage;
    default: return nullptr;
    }
}

void MainWindow::ensureModulePage(int index)
{
    auto *placeholder = m_stackWidget->widget(index);
    if (!placeholder || !placeholder->property("deferredModule").toBool()) return;
    auto *page = createModulePage(index);
    if (!page) return;
    m_stackWidget->insertWidget(index, page);
    m_stackWidget->removeWidget(placeholder);
    delete placeholder;
}

void MainWindow::connectFlowWebSocket()
{
    if (!m_ws || !m_flowPage || m_flowWebSocketConnected) return;
    m_flowWebSocketConnected = true;
    // Refresh task state and results on execution events
    if (m_flowPage) {
        // Pipeline events → FlowPage real-time updates
        connect(m_ws, &WsClient::pipelineCreated, m_flowPage, &FlowPage::onPipelineCreated);
        connect(m_ws, &WsClient::pipelineStatus, m_flowPage, &FlowPage::onPipelineStatus);
        connect(m_ws, &WsClient::pipelineStep, m_flowPage, &FlowPage::onPipelineStep);
        connect(m_ws, &WsClient::pipelineLog, m_flowPage, &FlowPage::onPipelineLog);
        // Scan/run events also refresh flow list (pipeline creates scans/runs internally)
        connect(m_ws, &WsClient::scanCompleted, m_flowPage, &FlowPage::onPipelineCreated);
        connect(m_ws, &WsClient::runCompleted, m_flowPage, &FlowPage::onPipelineCreated);
    }

    // Wire WebSocket to FlowPage's embedded stage-tab pages
    if (m_flowPage) {
        auto *embTopo = m_flowPage->topoTab();
        if (embTopo) {
            connect(m_ws, &WsClient::scanStarted, embTopo, &TopologyPage::onScanStarted);
            connect(m_ws, &WsClient::scanCompleted, embTopo, &TopologyPage::onScanCompleted);
        }
        auto *embScan = m_flowPage->scanTab();
        if (embScan) {
            const auto refreshVisibleScans = [embScan]() {
                if (embScan->isVisible()) embScan->onRefreshTasks();
            };
            connect(m_ws, &WsClient::scanCreated, embScan, refreshVisibleScans);
            connect(m_ws, &WsClient::scanCompleted, embScan, refreshVisibleScans);
            connect(m_ws, &WsClient::scanAgentStep, embScan, refreshVisibleScans);
            connect(m_ws, &WsClient::connected, embScan, refreshVisibleScans);
            // Embedded scan "推荐执行" → switch to attack tab within the workbench
            connect(embScan, &ScanPage::playbookNavigateRequested, this,
                [this](const QString &id, const QString &target) {
                    m_flowPage->switchToStageTab(5);
                    m_flowPage->execTab()->selectPlaybook(id, target);
                });
        }
        auto *embExec = m_flowPage->execTab();
        if (embExec) {
            connect(m_ws, &WsClient::runReact, embExec, &ExecutionPage::onRunReact);
            connect(m_ws, &WsClient::runCompleted, embExec, [embExec]() {
                if (embExec->isVisible()) embExec->onRefreshRuns();
            });
        }
        connect(m_ws, &WsClient::runCompleted, m_flowPage, [this](const QJsonObject &data) {
            m_flowPage->onRunCompleted(data.value(QStringLiteral("run_id")).toString());
        });
    }

}

// ── Resize event: reposition toast overlay ─────────────────────────────

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    if (m_toastOverlay) {
        m_toastOverlay->reposition();
    }
}

void MainWindow::switchToPage(int index)
{
    if (m_dongleLocked || index < 0 || index > 11 || index == 7) return;
    onModuleChanged(index);
    if (!m_routingFeature) syncRibbonForPage(index);
    updateFeaturePresentation();
    updateTaskContext();
}

void MainWindow::onModuleChanged(int row)
{
    if (m_dongleLocked) return;
    if (row >= 0 && row < m_stackWidget->count()) {
        ensureModulePage(row);
        if (m_stackWidget->widget(row)->property("deferredModule").toBool()) return;
        m_stackWidget->setCurrentIndex(row);
        // Trigger page refresh if it's a BasePage subclass
        auto *page = m_stackWidget->widget(row);
        if (auto *basePage = qobject_cast<BasePage*>(page)) {
            basePage->refresh();
        }
        // Also refresh BasePage children inside QTabWidget containers
        auto *tab = page->findChild<QTabWidget*>();
        if (tab) {
            for (int i = 0; i < tab->count(); ++i) {
                if (auto *bp = qobject_cast<BasePage*>(tab->widget(i))) {
                    bp->refresh();
                }
            }
        }

    }
}

void MainWindow::verifyDongleHeartbeat() {
    QString error;
    const bool valid = DongleService::verifyPolicy(DongleService::policyDir(), &error);
    if (!valid) {
        setDongleLocked(true, error);
    } else if (m_dongleLocked) {
        setDongleLocked(false);
    }
}

void MainWindow::setDongleLocked(bool locked, const QString &errorMessage) {
    if (locked == m_dongleLocked && locked) {
        if (m_dongleLockPage) {
            m_dongleLockPage->setErrorMessage(errorMessage);
        }
        return;
    }

    if (locked) {
        m_featureBeforeDongleLock = m_activeFeature;
        const int current = m_stackWidget ? m_stackWidget->currentIndex() : -1;
        if (current >= 0 && m_dongleLockPage && m_stackWidget->widget(current) != m_dongleLockPage) {
            m_pageBeforeDongleLock = current;
        }
        m_dongleLocked = true;
        updateFeaturePresentation();
        if (m_dongleLockPage && m_stackWidget) {
            m_dongleLockPage->setErrorMessage(errorMessage);
            m_stackWidget->setCurrentWidget(m_dongleLockPage);
        }
        if (m_navList) m_navList->setEnabled(false);
        if (m_ribbon) m_ribbon->setEnabled(false);
        if (m_contextBar) m_contextBar->setEnabled(false);
        for (const auto &name : {"ribbonHome", "ribbonTaskCenter", "ribbonKnowledge"})
            if (auto *button = findChild<QPushButton *>(name)) button->setEnabled(false);
        return;
    }

    m_dongleLocked = false;
    if (m_navList) m_navList->setEnabled(true);
    if (m_ribbon) m_ribbon->setEnabled(true);
    if (m_contextBar) m_contextBar->setEnabled(true);
    for (const auto &name : {"ribbonHome", "ribbonTaskCenter", "ribbonKnowledge"})
        if (auto *button = findChild<QPushButton *>(name)) button->setEnabled(true);
    {
        const QScopedValueRollback<bool> routing(m_routingFeature, true);
        switchToPage(m_pageBeforeDongleLock);
    }
    m_activeFeature = m_featureBeforeDongleLock;
    m_ribbon->setActiveFeature(m_activeFeature);
    if (const auto *entry = ModuleRibbon::feature(m_activeFeature)) {
        const QSignalBlocker blocker(m_navList);
        m_navList->setCurrentRow(entry->module);
    }
    updateTaskContext();
    // The selected navigation row normally stays unchanged while locked, so
    // setCurrentRow does not emit currentRowChanged when the dongle returns.
    if (m_stackWidget && m_stackWidget->currentWidget() == m_dongleLockPage) {
        onModuleChanged(m_pageBeforeDongleLock);
    }
}

void MainWindow::onLogout()
{
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("退出登录");
    msgBox.setText("确定要退出登录吗？");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    auto reply = msgBox.exec();
    if (reply != QMessageBox::Yes) return;

    // Disconnect WebSocket
    if (m_ws) m_ws->disconnectFromServer();

    // Exit the event loop — main.cpp's loop will delete this window
    // and show the login dialog again.
    QApplication::quit();
}

void MainWindow::onCheckBackend()
{
    m_checkBackendBtn->setEnabled(false);
    m_backendStatusLabel->setText("检测中...");
    m_backendStatusLabel->setStyleSheet("color: #64748b; padding: 0 10px; font-size: 13px;");

    m_api->get("/api/health", 3000, [this](const QJsonObject &res) {
        m_checkBackendBtn->setEnabled(true);
        if (res["status"].toString() == "ok") {
            m_backendStatusLabel->setText("已连接");
            m_backendStatusLabel->setStyleSheet(
                "color: #16a34a; font-weight: bold; padding: 0 10px; font-size: 13px;");
        } else {
            m_backendStatusLabel->setText("未连接");
            m_backendStatusLabel->setStyleSheet(
                "color: #dc3545; font-weight: bold; padding: 0 10px; font-size: 13px;");
        }
    });
}

void MainWindow::selectRibbonModule(int module)
{
    if (m_dongleLocked || module < 0 || module >= 7) return;
    m_ribbon->setModule(module);
    QString id = m_lastFeatures[module];
    if (!m_ribbon->canOpen(id)) {
        for (const auto &feature : ModuleRibbon::features()) {
            if (feature.module == module && m_ribbon->canOpen(feature.id)) { id = feature.id; break; }
        }
    }
    if (!id.isEmpty()) openRibbonFeature(id);
}

void MainWindow::openRibbonFeature(const QString &id)
{
    if (m_dongleLocked || !m_ribbon->canOpen(id)) return;
    const auto *feature = ModuleRibbon::feature(id);
    m_pendingTaskFeature.clear();
    m_selectingFeatureTask = false;
    m_activeFeature = id;
    m_lastFeatures[feature->module] = id;
    {
        const QSignalBlocker blocker(m_navList);
        m_navList->setCurrentRow(feature->module);
    }
    m_ribbon->setActiveFeature(id);
    const QScopedValueRollback<bool> routing(m_routingFeature, true);
    if (id == "resources.discovery") {
        TopologyPage *topology = nullptr;
        if (m_flowPage && m_flowPage->hasSelectedTask()) {
            openTaskStage(3);
            topology = m_flowPage->topoTab();
        } else {
            switchToPage(2);
            topology = qobject_cast<TopologyPage *>(m_stackWidget->widget(2));
        }
        if (topology) topology->selectWorkspaceMode("assets");
    } else if (id.startsWith("resources.")) {
        switchToPage(8);
        if (m_deployPage) m_deployPage->showSection(id.section('.', 1));
    } else if (id == "plans.library") {
        switchToPage(4);
    } else if (id == "plans.scenario" || id == "plans.task") {
        openTaskStage(id == "plans.scenario" ? 2 : 4);
    } else if (id.startsWith("topology.")) {
        TopologyPage *topology = nullptr;
        if (m_flowPage && m_flowPage->hasSelectedTask()) {
            openTaskStage(3);
            topology = m_flowPage->topoTab();
        } else {
            switchToPage(2);
            topology = qobject_cast<TopologyPage *>(m_stackWidget->widget(2));
        }
        if (topology) topology->selectWorkspaceMode(id.section('.', 1));
    } else if (id.startsWith("scans.")) {
        if (m_flowPage && m_flowPage->hasSelectedTask()) {
            openTaskStage(1);
            m_flowPage->scanTab()->selectScanType(id.section('.', 1));
        } else {
            switchToPage(10);
            if (m_standaloneScan) m_standaloneScan->selectScanType(id.section('.', 1));
        }
    } else if (id.startsWith("attacks.")) {
        const int category = id == "attacks.data" ? 1 : id == "attacks.tampering" ? 2 : 3;
        if (m_flowPage && m_flowPage->hasSelectedTask()) {
            openTaskStage(5);
            m_flowPage->execTab()->selectAttackCategory(category);
        } else {
            switchToPage(11);
            if (m_standaloneExecution) m_standaloneExecution->selectAttackCategory(category);
        }
    } else if (id.startsWith("evaluation.")) {
        switchToPage(9);
        if (m_capturePage) m_capturePage->showCaptureWorkspace(id == "evaluation.analysis");
    } else if (id == "system.tasks") {
        showTaskCenter();
    } else if (id == "system.reports") {
        switchToPage(5);
    } else if (id == "system.generate-report") {
        openTaskStage(6);
        if (m_flowPage && m_flowPage->hasSelectedTask()) m_flowPage->evalTab()->showReports();
    } else if (id.startsWith("system.")) {
        switchToPage(6);
        if (auto *system = qobject_cast<SystemPage *>(m_stackWidget->widget(6))) system->selectSection(id.section('.', 1));
    }
    updateFeaturePresentation();
    updateTaskContext();
}

void MainWindow::showTaskCenter()
{
    if (m_dongleLocked) return;
    m_pendingTaskFeature.clear();
    m_selectingFeatureTask = false;
    const QScopedValueRollback<bool> routing(m_routingFeature, true);
    switchToPage(1);
    if (m_flowPage) m_flowPage->showTaskList();
    if (m_activeFeature != "system.tasks") {
        m_activeFeature.clear();
        m_ribbon->setActiveFeature({});
    }
    updateFeaturePresentation();
    updateTaskContext();
}

void MainWindow::openTaskStage(int stage)
{
    if (m_dongleLocked) return;
    const QScopedValueRollback<bool> routing(m_routingFeature, true);
    switchToPage(1);
    if (m_flowPage) {
        if (!m_flowPage->hasSelectedTask() && !m_activeFeature.isEmpty()) m_pendingTaskFeature = m_activeFeature;
        m_flowPage->requestWorkspaceStage(stage);
    }
    updateFeaturePresentation();
    updateTaskContext();
}

void MainWindow::syncRibbonForPage(int page)
{
    QString feature;
    if (page == 0) {
        m_activeFeature.clear();
        m_ribbon->setActiveFeature({});
        return;
    }
    if (page == 1 && m_flowPage) {
        const int stage = m_flowPage->workspaceStage();
        if (stage == 1) feature = m_activeFeature.startsWith("scans.") ? m_activeFeature : "scans.system";
        else if (stage == 2) feature = "plans.scenario";
        else if (stage == 3) feature = m_activeFeature.startsWith("topology.") ? m_activeFeature : "topology.display";
        else if (stage == 4) feature = "plans.task";
        else if (stage == 5) feature = m_activeFeature.startsWith("attacks.") ? m_activeFeature : "attacks.data";
        else if (stage == 6) feature = "system.generate-report";
        else {
            m_activeFeature.clear();
            m_ribbon->setActiveFeature({});
            return;
        }
    }
    else if (page == 2) feature = "topology.display";
    else if (page == 3) feature = "plans.scenario";
    else if (page == 4) feature = "plans.library";
    else if (page == 5) feature = "system.reports";
    else if (page == 6) feature = "system.users";
    else if (page == 8) feature = m_activeFeature.startsWith("resources.") ? m_activeFeature : "resources.runtime";
    else if (page == 9) feature = m_activeFeature.startsWith("evaluation.") ? m_activeFeature : "evaluation.capture";
    else if (page == 10) feature = m_activeFeature.startsWith("scans.") ? m_activeFeature : "scans.system";
    else if (page == 11) feature = m_activeFeature.startsWith("attacks.") ? m_activeFeature : "attacks.data";
    if (feature.isEmpty() || !m_ribbon->canOpen(feature)) return;
    m_activeFeature = feature;
    const auto *entry = ModuleRibbon::feature(feature);
    m_lastFeatures[entry->module] = feature;
    const QSignalBlocker blocker(m_navList);
    m_navList->setCurrentRow(entry->module);
    m_ribbon->setActiveFeature(feature);
}

void MainWindow::updateTaskContext()
{
    const bool selected = m_flowPage && m_flowPage->hasSelectedTask();
    if (selected && !m_pendingTaskFeature.isEmpty() && m_flowPage->taskContextReady() && !m_routingFeature) {
        const QString requested = m_pendingTaskFeature;
        m_pendingTaskFeature.clear();
        openRibbonFeature(requested);
        return;
    }
    const auto *feature = ModuleRibbon::feature(m_activeFeature);
    QString text = selected ? m_flowPage->taskContextSummary() : QStringLiteral("未选择测试任务 · 请在任务中心选择或创建任务");
    if (feature) {
        text += QStringLiteral("  |  %1").arg(feature->title);
        if (feature->id.startsWith("resources.") && feature->id != "resources.discovery") text += QStringLiteral("（全局配置）");
        if (feature->id.startsWith("evaluation.")) text += QStringLiteral("（独立捕获任务，在工作区选择记录）");
        if (selected && feature->id.startsWith("attacks.")) text += QStringLiteral("（查看当前任务执行，沿用现有预案）");
    }
    updateFeaturePresentation();
    m_contextLabel->setText(text);
    m_contextLabel->setToolTip(text.toHtmlEscaped());
    m_overviewButton->setEnabled(selected);
    m_resultsButton->setEnabled(selected);
}

QString MainWindow::featureDescription(const QString &id) const
{
    static const QMap<QString, QString> descriptions{
        {"resources.discovery", "发现主机与服务，建立后续拓扑、扫描和测试使用的资产清单。"},
        {"resources.runtime", "配置现有隔离执行环境，检查容器引擎与依赖镜像。"},
        {"resources.llm", "维护模型服务连接、接口凭据与模型选择。"},
        {"resources.labs", "查看测试靶场，显式启动、停止或检查所选环境。"},
        {"resources.tools", "查看工具与运行镜像映射，核对工具环境就绪状态。"},
        {"plans.scenario", "依据当前任务的资产和扫描结果整理利用思路与候选策略。"},
        {"plans.task", "编排任务预案、检查步骤与变量，并管理审阅和版本。"},
        {"plans.library", "检索漏洞利用战术、预案模板和关联知识资源。"},
        {"topology.discover", "选择探测范围与来源，生成或更新网络拓扑。"},
        {"topology.edit", "在当前画布中编辑节点、连接及对象属性。"},
        {"topology.display", "查看网络区域、主机服务及其连接关系。"},
        {"topology.annotate", "为选中的节点或连接维护备注、服务与证据标注。"},
        {"scans.system", "查看系统与组件漏洞检查记录，保留来源和验证状态。"},
        {"scans.web", "查看 Web 应用检测记录、候选发现和请求依据。"},
        {"scans.ports", "查看端口、服务与主机发现；端口开放本身不等于漏洞。"},
        {"scans.passwords", "查看认证服务检查和弱口令记录，敏感结果按原有规则脱敏。"},
        {"attacks.data", "查看数据抵近窃取场景的预案或已保存分类关联的执行记录。"},
        {"attacks.tampering", "查看信息篡改欺骗场景的预案或已保存分类关联的执行记录。"},
        {"attacks.control", "查看关键设备夺控场景的预案或已保存分类关联的执行记录。"},
        {"evaluation.capture", "配置捕获接口、过滤条件和时长，查看原独立捕获任务。"},
        {"evaluation.analysis", "选择已有捕获记录，查看网络数据分析及证据定位。"},
        {"system.tasks", "管理当前账号可见的测试任务与执行状态。"},
        {"system.users", "维护用户账户与角色，操作仍由后端校验权限。"},
        {"system.permissions", "维护实际支持角色的读取与操作权限。"},
        {"system.license", "查看硬件加密锁、绑定策略及校验状态。"},
        {"system.generate-report", "选择任务结果与证据，显式生成并审阅测试报告。"},
        {"system.reports", "查看报告索引、历史版本及导出记录。"}
    };
    return descriptions.value(id);
}

void MainWindow::updateFeaturePresentation()
{
    if (!m_featureHeader || !m_taskGate) return;
    const auto *feature = ModuleRibbon::feature(m_activeFeature);
    m_featureHeader->setVisible(feature && !m_dongleLocked);
    if (feature) {
        m_featureTitle->setText(feature->title);
        m_featurePath->setText(ModuleRibbon::moduleNames().value(feature->module) + QStringLiteral("  /  ") + feature->title);
        m_featureDescription->setText(featureDescription(feature->id));
    }
    const bool requiresTask = feature && (feature->id == "plans.scenario" || feature->id == "plans.task"
        || feature->id == "system.generate-report");
    const bool gated = requiresTask && (!m_flowPage || !m_flowPage->hasSelectedTask())
        && !m_selectingFeatureTask && !m_dongleLocked;
    if (gated) m_taskGateMessage->setText(QStringLiteral("%1需要关联测试任务。请选择已有任务，或在任务列表中创建任务。\n选择后保留当前功能，继续查看该任务的数据。").arg(feature->title));
    m_taskGate->setVisible(gated);
    m_stackWidget->setVisible(!gated);
}

void MainWindow::chooseTaskForFeature()
{
    if (m_dongleLocked || !m_flowPage) return;
    const QString id = m_activeFeature;
    const int stage = id == "plans.scenario" ? 2 : id == "plans.task" ? 4 : 6;
    m_selectingFeatureTask = true;
    m_pendingTaskFeature = id;
    m_flowPage->showTaskList();
    m_flowPage->requestWorkspaceStage(stage);
    updateFeaturePresentation();
}
