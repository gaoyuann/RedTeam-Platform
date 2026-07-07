#include "MainWindow.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_networkMgr(new QNetworkAccessManager(this))
{
    setupUI();
}

void MainWindow::setupUI()
{
    setWindowTitle(QStringLiteral("信息系统渗透智能化测试平台"));
    resize(1280, 800);

    auto *centralWidget = new QWidget(this);
    auto *mainLayout = new QHBoxLayout(centralWidget);

    // Left: navigation
    m_navList = new QListWidget(this);
    m_navList->setFixedWidth(220);
    for (const auto &name : m_modules) {
        m_navList->addItem(name);
    }
    m_navList->setCurrentRow(0);

    // Right: stacked pages
    m_stackWidget = new QStackedWidget(this);
    for (const auto &name : m_modules) {
        auto *page = new QWidget(this);
        auto *layout = new QVBoxLayout(page);
        auto *label = new QLabel(
            QStringLiteral("【%1】\n\n模块开发中...").arg(name), page);
        label->setAlignment(Qt::AlignCenter);
        label->setStyleSheet("font-size: 18px; color: #888;");
        layout->addWidget(label);
        m_stackWidget->addWidget(page);
    }

    mainLayout->addWidget(m_navList);
    mainLayout->addWidget(m_stackWidget, 1);
    setCentralWidget(centralWidget);

    // Status bar + backend check button
    m_checkBackendBtn = new QPushButton(
        QStringLiteral("检测后端连接"), this);
    statusBar()->addWidget(m_checkBackendBtn);
    statusBar()->showMessage(QStringLiteral("后端状态：未检测"));

    // Signals
    connect(m_navList, &QListWidget::currentRowChanged,
            this, &MainWindow::onModuleChanged);
    connect(m_checkBackendBtn, &QPushButton::clicked,
            this, &MainWindow::onCheckBackend);
    connect(m_networkMgr, &QNetworkAccessManager::finished,
            this, &MainWindow::onBackendReply);
}

void MainWindow::onModuleChanged(int row)
{
    if (row >= 0 && row < m_stackWidget->count()) {
        m_stackWidget->setCurrentIndex(row);
    }
}

void MainWindow::onCheckBackend()
{
    m_checkBackendBtn->setEnabled(false);
    statusBar()->showMessage(QStringLiteral("正在检测后端..."));

    QUrl url("http://127.0.0.1:3002/api/health");
    QNetworkRequest request(url);
    request.setTransferTimeout(3000);
    m_networkMgr->get(request);
}

void MainWindow::onBackendReply(QNetworkReply *reply)
{
    m_checkBackendBtn->setEnabled(true);

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        statusBar()->showMessage(
            QStringLiteral("后端已连接 — %1").arg(QString::fromUtf8(data)));
    } else {
        statusBar()->showMessage(
            QStringLiteral("后端未连接（%1）").arg(reply->errorString()));
    }

    reply->deleteLater();
}
