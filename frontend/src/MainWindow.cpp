#include "MainWindow.h"
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
    auto *rootLayout = new QVBoxLayout(centralWidget);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    auto *topBar = new QFrame(centralWidget);
    topBar->setObjectName("appTopBar");
    auto *headerLayout = new QHBoxLayout(topBar);
    headerLayout->setContentsMargins(20, 4, 20, 4);
    headerLayout->setSpacing(14);
    headerLayout->addStretch();
    auto *userIcon = new QLabel(topBar);
    userIcon->setPixmap(QIcon(":/icons/shell/user.svg").pixmap(24, 24));
    headerLayout->addWidget(userIcon);
    auto *topUser = new QLabel(QStringLiteral("%1 (%2)")
        .arg(m_username, displayRole(m_role)), topBar);
    topUser->setTextFormat(Qt::PlainText);
    topUser->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    topUser->setMinimumWidth(120);
    topUser->setMaximumWidth(280);
    topUser->setToolTip(topUser->text().toHtmlEscaped());
    topUser->setStyleSheet(QStringLiteral("color:#1e3a63; font-size:13px; font-weight:600;"));
    headerLayout->addWidget(topUser);
    auto *collapse = new QPushButton(QStringLiteral("收起导航"), topBar);
    collapse->setObjectName("navigationToggle");
    collapse->setProperty("quiet", true);
    collapse->setCheckable(true);
    collapse->setMinimumHeight(34);
    headerLayout->addWidget(collapse);
    rootLayout->addWidget(topBar);

    // Unified horizontal module navigation within the application header.
    m_modules = QStringList({
        QStringLiteral("工作台"),
        QStringLiteral("测试任务"),
        QStringLiteral("资产与拓扑"),
        QStringLiteral("智能分析"),
        QStringLiteral("预案与知识库"),
        QStringLiteral("结果与报告"),
        QStringLiteral("系统管理")
    });

    m_navList = new QListWidget(topBar);
    m_navList->setObjectName("navList");
    m_navList->setMinimumWidth(0);
    m_navList->setFlow(QListView::LeftToRight);
    m_navList->setWrapping(false);
    m_navList->setResizeMode(QListView::Adjust);
    m_navList->setMovement(QListView::Static);
    m_navList->setSpacing(3);
    m_navList->setFixedHeight(58);
    m_navList->setIconSize(QSize(Theme::IconSize, Theme::IconSize));
    m_navList->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_navList->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_navList->setAccessibleName(QStringLiteral("主导航"));
    const QStringList navIcons = {"dashboard", "tasks", "topology", "analysis", "library", "reports", "settings"};
    for (int index = 0; index < m_modules.size(); ++index) {
        auto *item = new QListWidgetItem(m_modules.at(index), m_navList);
        item->setData(Qt::UserRole, m_modules.at(index));
        item->setToolTip(m_modules.at(index));
        QIcon icon(":/icons/shell/" + navIcons.at(index) + ".svg");
        icon.addFile(":/icons/shell/" + navIcons.at(index) + "-selected.svg", QSize(), QIcon::Selected);
        item->setIcon(icon);
        item->setSizeHint(QSize(m_navList->fontMetrics().horizontalAdvance(m_modules.at(index)) + 56, 42));
    }
    m_navList->setCurrentRow(0);
    if (m_role != QStringLiteral("admin")) {
        m_navList->item(6)->setToolTip(QStringLiteral("仅管理员可操作系统管理；当前账号显示权限说明。"));
    }

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

    headerLayout->insertWidget(0, m_navList, 1);
    const auto updateNavigationToggle = [this, collapse]() {
        const bool collapsed = collapse->isChecked();
        collapse->setText(collapsed
            ? QStringLiteral("展开导航 · %1").arg(m_modules.value(m_navList->currentRow()))
            : QStringLiteral("收起导航"));
        collapse->setToolTip(collapsed ? QStringLiteral("展开主导航") : QStringLiteral("收起主导航"));
        collapse->setAccessibleName(collapse->text());
    };
    connect(collapse, &QPushButton::toggled, this, [this, updateNavigationToggle](bool collapsed) {
        m_navList->setVisible(!collapsed);
        updateNavigationToggle();
    });
    connect(m_navList, &QListWidget::currentRowChanged, this, updateNavigationToggle);
    updateNavigationToggle();

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
            this, &MainWindow::onModuleChanged);
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
        return m_flowPage;
    }
    case 2: {
        auto *assetTopology=new TopologyPage(m_api,m_role,m_username,this);
        connect(assetTopology,&TopologyPage::testTargetRequested,this,[this](const QString &target) {
            if(m_dongleLocked) return;
            switchToPage(1);
            m_flowPage->createTestForTarget(target);
        });

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
        ensureModulePage(row);
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
