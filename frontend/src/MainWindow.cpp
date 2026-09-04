#include "MainWindow.h"
#include "ApiClient.h"
#include "LoginDialog.h"
#include "WsClient.h"
#include "ToastOverlay.h"
#include "LiveActivityPanel.h"
#include "pages/BasePage.h"
#include "pages/DashboardPage.h"
#include "pages/DeployConfigPage.h"
#include "pages/PlaybookPage.h"
#include "pages/TopologyPage.h"
#include "pages/ScanPage.h"
#include "pages/ExecutionPage.h"
#include "pages/CampaignPage.h"
#include "pages/EvaluatePage.h"
#include "pages/SystemPage.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QStatusBar>
#include <QMessageBox>
#include <QApplication>
#include <QFrame>
#include <QResizeEvent>

namespace {
QString displayRole(const QString &role)
{
    if (role == QStringLiteral("admin")) return QStringLiteral("管理员");
    if (role == QStringLiteral("teacher")) return QStringLiteral("教师");
    if (role == QStringLiteral("student")) return QStringLiteral("学生");
    if (role == QStringLiteral("operator")) return QStringLiteral("操作员");
    if (role == QStringLiteral("viewer")) return QStringLiteral("观察者");
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
}

void MainWindow::setupUI()
{
    setWindowTitle(QStringLiteral("信息系统渗透智能化测试平台"));
    resize(1360, 860);
    setMinimumSize(1024, 600);

    auto *centralWidget = new QWidget(this);
    centralWidget->setObjectName("contentArea");
    auto *mainLayout = new QHBoxLayout(centralWidget);

    // Left: navigation — 总览大屏 as first item
    m_modules = QStringList({
        QStringLiteral("总览大屏"),
        QStringLiteral("渗透测试资源部署配置"),
        QStringLiteral("漏洞利用想定与预案"),
        QStringLiteral("网络拓扑探测与绘制"),
        QStringLiteral("脆弱性扫描"),
        QStringLiteral("漏洞攻击测试"),
        QStringLiteral("测试评估"),
        QStringLiteral("系统管理")
    });

    auto *sidebar = new QFrame(centralWidget);
    sidebar->setObjectName("sidebar");
    sidebar->setFixedWidth(248);
    auto *sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(16, 18, 16, 14);
    sidebarLayout->setSpacing(14);

    auto *brandLabel = new QLabel(QStringLiteral("红队安全运营"), sidebar);
    brandLabel->setObjectName("sidebarBrand");
    sidebarLayout->addWidget(brandLabel);

    auto *brandSubtitle = new QLabel(QStringLiteral("信息系统安全测试平台"), sidebar);
    brandSubtitle->setObjectName("sidebarSubtitle");
    sidebarLayout->addWidget(brandSubtitle);

    auto *brandDivider = new QFrame(sidebar);
    brandDivider->setObjectName("sidebarDivider");
    brandDivider->setFrameShape(QFrame::HLine);
    sidebarLayout->addWidget(brandDivider);

    m_navList = new QListWidget(sidebar);
    m_navList->setObjectName("navList");
    m_navList->setFixedWidth(220);
    for (const auto &name : m_modules) {
        m_navList->addItem(name);
    }
    m_navList->setCurrentRow(0);

    // Right: stacked pages
    m_stackWidget = new QStackedWidget(this);

    // Page 0: Dashboard (总览大屏)
    m_dashboardPage = new DashboardPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(m_dashboardPage);

    // Page 1: Deploy config
    m_stackWidget->addWidget(new DeployConfigPage(m_api, m_role, m_username, this));

    // Page 2: Playbook
    auto *playbookPage = new PlaybookPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(playbookPage);

    // Page 3: Topology
    m_stackWidget->addWidget(new TopologyPage(m_api, m_role, m_username, this));

    // Page 4: Scan (scan→auto-generate→inline-execute workflow)
    m_scanPage = new ScanPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(m_scanPage);

    // Page 5: 漏洞攻击测试 (Tab: 快速执行 + 攻击战役)
    auto *page5 = new QWidget;
    auto *page5Layout = new QVBoxLayout(page5);
    page5Layout->setContentsMargins(0, 0, 0, 0);
    auto *tab5 = new QTabWidget;
    m_executionPage = new ExecutionPage(m_api, m_role, m_username, this);
    tab5->addTab(m_executionPage, QStringLiteral("快速执行"));
    m_campaignPage = new CampaignPage(m_api, m_role, m_username, this);
    tab5->addTab(m_campaignPage, QStringLiteral("攻击战役"));
    page5Layout->addWidget(tab5);
    m_stackWidget->addWidget(page5);

    // Page 6: Evaluate
    m_stackWidget->addWidget(new EvaluatePage(m_api, m_role, m_username, this));

    // Page 7: System
    m_stackWidget->addWidget(new SystemPage(m_api, m_role, m_username, this));

    sidebarLayout->addWidget(m_navList, 1);
    auto *sidebarFooter = new QLabel(QStringLiteral("安全态势 · 实时联动"), sidebar);
    sidebarFooter->setObjectName("sidebarFooter");
    sidebarLayout->addWidget(sidebarFooter);

    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);
    mainLayout->addWidget(sidebar);
    mainLayout->addWidget(m_stackWidget, 1);
    setCentralWidget(centralWidget);

    // Toast overlay (positioned in top-right corner)
    m_toastOverlay = new ToastOverlay(this);

    // Status bar: backend check button + status label + logout
    m_checkBackendBtn = new QPushButton(QStringLiteral("检测连接"), this);
    m_checkBackendBtn->setObjectName("checkBtn");
    m_checkBackendBtn->setFixedWidth(90);
    statusBar()->addWidget(m_checkBackendBtn);

    m_backendStatusLabel = new QLabel(QStringLiteral("未检测"), this);
    m_backendStatusLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
    statusBar()->addWidget(m_backendStatusLabel);

    // User info label in status bar
    m_userInfoLabel = new QLabel(QStringLiteral("%1 [%2]").arg(m_username, displayRole(m_role)), this);
    m_userInfoLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
    statusBar()->addWidget(m_userInfoLabel);

    m_logoutBtn = new QPushButton(QStringLiteral("退出登录"), this);
    m_logoutBtn->setObjectName("checkBtn");
    m_logoutBtn->setFixedWidth(90);
    statusBar()->addPermanentWidget(m_logoutBtn);

    // Signals
    connect(m_navList, &QListWidget::currentRowChanged,
            this, &MainWindow::onModuleChanged);
    connect(m_checkBackendBtn, &QPushButton::clicked,
            this, &MainWindow::onCheckBackend);

    // Global API error → status bar
    connect(m_api, &ApiClient::apiError, this, [this](const QString &path, const QString &msg) {
        statusBar()->showMessage(QString("接口错误: %1 — %2").arg(path, msg), 5000);
    });

    // Logout button
    connect(m_logoutBtn, &QPushButton::clicked, this, &MainWindow::onLogout);

    // Cross-page navigation: ScanPage → ExecutionPage (index 5, 快速执行 tab)
    connect(m_scanPage, &ScanPage::playbookNavigateRequested, this, [this, tab5](const QString &id, const QString &target) {
        switchToPage(5);  // 漏洞攻击测试 is index 5
        tab5->setCurrentIndex(0);  // 切到"快速执行"Tab
        m_executionPage->selectPlaybook(id, target);
    });

    // Cross-page navigation: PlaybookPage → ExecutionPage
    connect(playbookPage, &PlaybookPage::executeRequested, this,
        [this, tab5](const QString &id) {
            switchToPage(5);
            tab5->setCurrentIndex(0);  // 切到"快速执行"Tab
            m_executionPage->selectPlaybook(id, QString());
        });
}

// ── WebSocket setup ────────────────────────────────────────────────────

void MainWindow::setupWebSocket()
{
    m_ws = new WsClient(m_api, this);
    m_ws->connectToServer();

    // Wire to DashboardPage's activity panel + refresh stats on events
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
        // Refresh dashboard stats table when key events arrive
        connect(m_ws, &WsClient::scanCreated, m_dashboardPage, &DashboardPage::refreshStats);
        connect(m_ws, &WsClient::scanCompleted, m_dashboardPage, &DashboardPage::refreshStats);
        connect(m_ws, &WsClient::runCreated, m_dashboardPage, &DashboardPage::refreshStats);
        connect(m_ws, &WsClient::runCompleted, m_dashboardPage, &DashboardPage::refreshStats);
    }

    if (m_campaignPage) {
        auto refreshCampaign = [this](const QJsonObject &) {
            m_campaignPage->refresh();
        };
        connect(m_ws, &WsClient::campaignStarted, this, refreshCampaign);
        connect(m_ws, &WsClient::campaignPaused, this, refreshCampaign);
        connect(m_ws, &WsClient::campaignAborted, this, refreshCampaign);
        connect(m_ws, &WsClient::campaignCompleted, this, refreshCampaign);
        connect(m_ws, &WsClient::phaseStarted, this, refreshCampaign);
        connect(m_ws, &WsClient::phaseCompleted, this, refreshCampaign);
        connect(m_ws, &WsClient::phaseSkipped, this, refreshCampaign);
    }

    // Wire to ToastOverlay
    connect(m_ws, &WsClient::scanCompleted, m_toastOverlay, &ToastOverlay::onScanCompleted);
    connect(m_ws, &WsClient::runStepComplete, m_toastOverlay, &ToastOverlay::onRunStepComplete);
    connect(m_ws, &WsClient::runCompleted, m_toastOverlay, &ToastOverlay::onRunCompleted);

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

// ── Resize event: reposition toast overlay ─────────────────────────────

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    if (m_toastOverlay) {
        m_toastOverlay->reposition();
    }
}

void MainWindow::switchToPage(int index) {
    if (index >= 0 && index < m_modules.size()) {
        m_navList->setCurrentRow(index);
    }
}

void MainWindow::onModuleChanged(int row)
{
    if (row >= 0 && row < m_stackWidget->count()) {
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
        if (row == 4 && m_scanPage) {
            m_scanPage->onRefreshTasks();
        } else if (row == 5 && m_executionPage) {
            m_executionPage->onRefreshRuns();
        }
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
    m_backendStatusLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");

    m_api->get("/api/health", 3000, [this](const QJsonObject &res) {
        m_checkBackendBtn->setEnabled(true);
        if (res["status"].toString() == "ok") {
            m_backendStatusLabel->setText("已连接");
            m_backendStatusLabel->setStyleSheet(
                "color: #27ae60; font-weight: bold; padding: 0 10px; font-size: 13px;");
        } else {
            m_backendStatusLabel->setText("未连接");
            m_backendStatusLabel->setStyleSheet(
                "color: #e74c3c; font-weight: bold; padding: 0 10px; font-size: 13px;");
        }
    });
}
