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
#include "pages/EvaluatePage.h"
#include "pages/SystemPage.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QStatusBar>
#include <QMessageBox>
#include <QApplication>
#include <QResizeEvent>

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
    resize(1280, 800);
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

    m_navList = new QListWidget(this);
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

    // Page 4: Scan
    auto *scanPage = new ScanPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(scanPage);

    // Page 5: Execution
    m_stackWidget->addWidget(new ExecutionPage(m_api, m_role, m_username, this));

    // Page 6: Evaluate
    m_stackWidget->addWidget(new EvaluatePage(m_api, m_role, m_username, this));

    // Page 7: System
    m_stackWidget->addWidget(new SystemPage(m_api, m_role, m_username, this));

    mainLayout->addWidget(m_navList);
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
    m_userInfoLabel = new QLabel(QStringLiteral("%1 [%2]").arg(m_username, m_role), this);
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
        statusBar()->showMessage(QString("API 错误: %1 — %2").arg(path, msg), 5000);
    });

    // Logout button
    connect(m_logoutBtn, &QPushButton::clicked, this, &MainWindow::onLogout);

    // Cross-page navigation: ScanPage → PlaybookPage (index 2)
    connect(scanPage, &ScanPage::playbookNavigateRequested, this, [this, playbookPage](const QString &id) {
        switchToPage(2);  // PlaybookPage is now index 2
        playbookPage->selectPlaybook(id);
    });
}

// ── WebSocket setup ────────────────────────────────────────────────────

void MainWindow::setupWebSocket()
{
    m_ws = new WsClient(m_api, this);
    m_ws->connectToServer();

    // Wire to DashboardPage's activity panel
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

    // Wire to ToastOverlay
    connect(m_ws, &WsClient::scanCompleted, m_toastOverlay, &ToastOverlay::onScanCompleted);
    connect(m_ws, &WsClient::runStepComplete, m_toastOverlay, &ToastOverlay::onRunStepComplete);
    connect(m_ws, &WsClient::runCompleted, m_toastOverlay, &ToastOverlay::onRunCompleted);

    // WebSocket connection status in status bar
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
            QMetaObject::invokeMethod(basePage, "refresh");
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
