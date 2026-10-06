#include "MainWindow.h"
#include "ApiClient.h"
#include "LoginDialog.h"
#include "WsClient.h"
#include "ToastOverlay.h"
#include "LiveActivityPanel.h"
#include "pages/BasePage.h"
#include "pages/FlowPage.h"
#include "pages/PlaybookPage.h"
#include "pages/ScanPage.h"
#include "pages/ExecutionPage.h"
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

    // 加密锁运行时心跳：每 5s 校验一次策略，失败则锁屏，恢复则回到原页面。
    m_dongleTimer = new QTimer(this);
    m_dongleTimer->setInterval(5000);
    connect(m_dongleTimer, &QTimer::timeout, this, &MainWindow::verifyDongleHeartbeat);
    m_dongleTimer->start();
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
    // Note: "资源部署配置" moved to SystemPage sub-tab (P2 optimization)
    m_modules = QStringList({
        QStringLiteral("📋 测试任务"),
        QStringLiteral("📚 预案与知识库"),
        QStringLiteral("⚙️ 系统管理")
    });

    auto *sidebar = new QFrame(centralWidget);
    sidebar->setObjectName("sidebar");
    sidebar->setFixedWidth(186);
    auto *sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(10, 18, 10, 14);
    sidebarLayout->setSpacing(14);

    auto *brandLabel = new QLabel(QStringLiteral("信息系统渗透智能化测试平台"), sidebar);
    brandLabel->setObjectName("sidebarBrand");
    brandLabel->setStyleSheet(QStringLiteral(
        "color: #ffffff; font-size: 14px; font-weight: 800; letter-spacing: 0px;"));
    brandLabel->setWordWrap(true);
    sidebarLayout->addWidget(brandLabel);

    auto *brandDivider = new QFrame(sidebar);
    brandDivider->setObjectName("sidebarDivider");
    brandDivider->setFrameShape(QFrame::HLine);
    sidebarLayout->addWidget(brandDivider);

    m_navList = new QListWidget(sidebar);
    m_navList->setObjectName("navList");
    for (const auto &name : m_modules) {
        m_navList->addItem(name);
    }
    m_navList->setCurrentRow(0);

    // Right: stacked pages
    m_stackWidget = new QStackedWidget(this);

    // Page 0: FlowPage (测试任务 — PentAGI-style flow list + workbench)
    m_flowPage = new FlowPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(m_flowPage);

    // Page 1: Playbook (was page 2 before deploy config removal)
    auto *playbookPage = new PlaybookPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(playbookPage);

    // Page 2: System (includes 资源部署 as sub-tab)
    m_stackWidget->addWidget(new SystemPage(m_api, m_role, m_username, this));

    // 加密锁锁屏页（不占导航行，仅在校验失败时显示）
    m_dongleLockPage = new DongleLockPage(this);
    m_stackWidget->addWidget(m_dongleLockPage);

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

    // Cross-page navigation: PlaybookPage → FlowPage workbench (攻击 Tab)
    connect(playbookPage, &PlaybookPage::executeRequested, this,
        [this](const QString &id) {
            switchToPage(0);  // 测试任务
            m_flowPage->jumpToExecution(id, QString());
        });
}

// ── WebSocket setup ────────────────────────────────────────────────────

void MainWindow::setupWebSocket()
{
    m_ws = new WsClient(m_api, this);
    m_ws->connectToServer();

    // Wire to FlowPage's activity panel + refresh flows on events
    if (m_flowPage) {
        auto *flowPanel = m_flowPage->activityPanel();
        if (flowPanel) {
            connect(m_ws, &WsClient::scanCreated, flowPanel, &LiveActivityPanel::onScanCreated);
            connect(m_ws, &WsClient::scanStarted, flowPanel, &LiveActivityPanel::onScanStarted);
            connect(m_ws, &WsClient::scanCompleted, flowPanel, &LiveActivityPanel::onScanCompleted);
            connect(m_ws, &WsClient::runCreated, flowPanel, &LiveActivityPanel::onRunCreated);
            connect(m_ws, &WsClient::runStarted, flowPanel, &LiveActivityPanel::onRunStarted);
            connect(m_ws, &WsClient::runStepComplete, flowPanel, &LiveActivityPanel::onRunStepComplete);
            connect(m_ws, &WsClient::runCompleted, flowPanel, &LiveActivityPanel::onRunCompleted);
            // Pipeline events → LiveActivityPanel
            connect(m_ws, &WsClient::pipelineCreated, flowPanel, &LiveActivityPanel::onPipelineCreated);
            connect(m_ws, &WsClient::pipelineStatus, flowPanel, &LiveActivityPanel::onPipelineStatus);
            connect(m_ws, &WsClient::pipelineStep, flowPanel, &LiveActivityPanel::onPipelineStep);
        }
        // Pipeline events → FlowPage real-time updates
        connect(m_ws, &WsClient::pipelineCreated, m_flowPage, &FlowPage::onPipelineCreated);
        connect(m_ws, &WsClient::pipelineStatus, m_flowPage, &FlowPage::onPipelineStatus);
        connect(m_ws, &WsClient::pipelineStep, m_flowPage, &FlowPage::onPipelineStep);
        connect(m_ws, &WsClient::pipelineLog, m_flowPage, &FlowPage::onPipelineLog);
        // Scan/run events also refresh flow list (pipeline creates scans/runs internally)
        connect(m_ws, &WsClient::scanCompleted, m_flowPage, &FlowPage::refreshFlows);
        connect(m_ws, &WsClient::runCompleted, m_flowPage, &FlowPage::refreshFlows);
    }

    // Wire WebSocket to FlowPage's embedded stage-tab pages
    if (m_flowPage) {
        auto *embScan = m_flowPage->scanTab();
        if (embScan) {
            connect(m_ws, &WsClient::scanCreated, embScan, &ScanPage::onRefreshTasks);
            connect(m_ws, &WsClient::scanCompleted, embScan, &ScanPage::onRefreshTasks);
            // Embedded scan "推荐执行" → switch to attack tab within the workbench
            connect(embScan, &ScanPage::playbookNavigateRequested, this,
                [this](const QString &id, const QString &target) {
                    m_flowPage->switchToStageTab(2);  // 2 = 漏洞攻击
                    m_flowPage->execTab()->selectPlaybook(id, target);
                });
        }
        auto *embExec = m_flowPage->execTab();
        if (embExec) {
            connect(m_ws, &WsClient::runReact, embExec, &ExecutionPage::onRunReact);
            connect(m_ws, &WsClient::runCompleted, embExec, &ExecutionPage::onRefreshRuns);
        }
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
    if (m_dongleLocked) return;
    if (index >= 0 && index < m_modules.size()) {
        m_navList->setCurrentRow(index);
    }
}

void MainWindow::onModuleChanged(int row)
{
    if (m_dongleLocked) return;
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
        if (row == 0 && m_flowPage) {
            m_flowPage->refreshFlows();
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
    switchToPage(m_pageBeforeDongleLock);
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
