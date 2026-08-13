#include "MainWindow.h"
#include "ApiClient.h"
#include "LoginDialog.h"
#include "pages/BasePage.h"
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

MainWindow::MainWindow(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QMainWindow(parent)
    , m_api(api)
    , m_role(role)
    , m_username(username)
{
    setupUI();
}

void MainWindow::setupUI()
{
    setWindowTitle(QStringLiteral("信息系统渗透智能化测试平台"));
    resize(1280, 800);
    setMinimumSize(1024, 600);

    auto *centralWidget = new QWidget(this);
    centralWidget->setObjectName("contentArea");
    auto *mainLayout = new QHBoxLayout(centralWidget);

    // Left: navigation
    m_navList = new QListWidget(this);
    m_navList->setObjectName("navList");
    m_navList->setFixedWidth(220);
    for (const auto &name : m_modules) {
        m_navList->addItem(name);
    }
    m_navList->setCurrentRow(0);

    // Right: stacked pages
    m_stackWidget = new QStackedWidget(this);
    m_stackWidget->addWidget(new DeployConfigPage(m_api, m_role, m_username, this));   // 0
    auto *playbookPage = new PlaybookPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(playbookPage);                        // 1
    m_stackWidget->addWidget(new TopologyPage(m_api, m_role, m_username, this)); // 2
    auto *scanPage = new ScanPage(m_api, m_role, m_username, this);
    m_stackWidget->addWidget(scanPage);                            // 3
    m_stackWidget->addWidget(new ExecutionPage(m_api, m_role, m_username, this));      // 4
    m_stackWidget->addWidget(new EvaluatePage(m_api, m_role, m_username, this));       // 5
    m_stackWidget->addWidget(new SystemPage(m_api, m_role, m_username, this));         // 6

    mainLayout->addWidget(m_navList);
    mainLayout->addWidget(m_stackWidget, 1);
    setCentralWidget(centralWidget);

    // Status bar: backend check button + status label + logout
    m_checkBackendBtn = new QPushButton(QStringLiteral("检测连接"), this);
    m_checkBackendBtn->setObjectName("checkBtn");
    m_checkBackendBtn->setFixedWidth(90);
    statusBar()->addWidget(m_checkBackendBtn);

    m_backendStatusLabel = new QLabel(QStringLiteral("未检测"), this);
    m_backendStatusLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
    statusBar()->addWidget(m_backendStatusLabel);

    m_logoutBtn = new QPushButton(QStringLiteral("退出登录"), this);
    m_logoutBtn->setObjectName("checkBtn");
    m_logoutBtn->setFixedWidth(90);
    statusBar()->addPermanentWidget(m_logoutBtn);

    // User info label in status bar
    m_userInfoLabel = new QLabel(QStringLiteral("%1 [%2]").arg(m_username, m_role), this);
    m_userInfoLabel->setStyleSheet("color: #a0aec0; padding: 0 10px; font-size: 13px;");
    statusBar()->addPermanentWidget(m_userInfoLabel);

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

    // Cross-page navigation: ScanPage → PlaybookPage
    connect(scanPage, &ScanPage::playbookNavigateRequested, this, [this, playbookPage](const QString &id) {
        switchToPage(1);  // PlaybookPage is index 1
        playbookPage->selectPlaybook(id);
    });
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
