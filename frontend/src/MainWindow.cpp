#include "MainWindow.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QMessageBox>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

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
    for (int i = 0; i < m_modules.size(); ++i) {
        auto *page = new QWidget(this);
        if (i == 0) {
            // First module = verification dashboard
            setupVerificationPage(page);
        } else {
            auto *layout = new QVBoxLayout(page);
            auto *label = new QLabel(
                QStringLiteral("【%1】\n\n模块开发中...").arg(m_modules[i]), page);
            label->setAlignment(Qt::AlignCenter);
            label->setStyleSheet("font-size: 18px; color: #888;");
            layout->addWidget(label);
        }
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

void MainWindow::setupVerificationPage(QWidget *page)
{
    auto *layout = new QVBoxLayout(page);
    layout->setSpacing(12);

    // ── Section 1: Backend Status ────────────────────────────────────────
    auto *backendGroup = new QWidget(page);
    auto *backendLayout = new QHBoxLayout(backendGroup);
    backendLayout->setContentsMargins(0, 0, 0, 0);

    auto *backendTitle = new QLabel(QStringLiteral("后端连接："), backendGroup);
    backendTitle->setStyleSheet("font-weight: bold; font-size: 14px;");
    m_backendStatusLabel = new QLabel(QStringLiteral("未检测"), backendGroup);
    m_backendStatusLabel->setStyleSheet("font-size: 14px; color: #888;");

    backendLayout->addWidget(backendTitle);
    backendLayout->addWidget(m_backendStatusLabel);
    backendLayout->addStretch();
    layout->addWidget(backendGroup);

    // ── Section 2: SQLite Data ───────────────────────────────────────────
    auto *dbGroup = new QWidget(page);
    auto *dbLayout = new QVBoxLayout(dbGroup);

    auto *dbHeader = new QWidget(dbGroup);
    auto *dbHeaderLayout = new QHBoxLayout(dbHeader);
    dbHeaderLayout->setContentsMargins(0, 0, 0, 0);

    auto *dbTitle = new QLabel(QStringLiteral("SQLite 数据库验证"), dbHeader);
    dbTitle->setStyleSheet("font-weight: bold; font-size: 14px;");
    m_fetchDbBtn = new QPushButton(QStringLiteral("读取数据库"), dbHeader);
    dbHeaderLayout->addWidget(dbTitle);
    dbHeaderLayout->addStretch();
    dbHeaderLayout->addWidget(m_fetchDbBtn);

    m_dbTable = new QTableWidget(dbGroup);
    m_dbTable->setColumnCount(4);
    m_dbTable->setHorizontalHeaderLabels(
        {QStringLiteral("ID"), QStringLiteral("名称"),
         QStringLiteral("值"), QStringLiteral("创建时间")});
    m_dbTable->horizontalHeader()->setStretchLastSection(true);
    m_dbTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dbTable->setAlternatingRowColors(true);
    m_dbTable->setMaximumHeight(200);

    dbLayout->addWidget(dbHeader);
    dbLayout->addWidget(m_dbTable);
    layout->addWidget(dbGroup);

    // ── Section 3: Container Test ────────────────────────────────────────
    auto *containerGroup = new QWidget(page);
    auto *containerLayout = new QVBoxLayout(containerGroup);

    auto *containerHeader = new QWidget(containerGroup);
    auto *containerHeaderLayout = new QHBoxLayout(containerHeader);
    containerHeaderLayout->setContentsMargins(0, 0, 0, 0);

    auto *containerTitle = new QLabel(QStringLiteral("容器工具验证"), containerHeader);
    containerTitle->setStyleSheet("font-weight: bold; font-size: 14px;");
    m_containerTestBtn = new QPushButton(QStringLiteral("测试 nmap 容器"), containerHeader);
    containerHeaderLayout->addWidget(containerTitle);
    containerHeaderLayout->addStretch();
    containerHeaderLayout->addWidget(m_containerTestBtn);

    m_containerOutput = new QTextEdit(containerGroup);
    m_containerOutput->setReadOnly(true);
    m_containerOutput->setMaximumHeight(120);
    m_containerOutput->setPlaceholderText(
        QStringLiteral("点击「测试 nmap 容器」查看结果..."));

    containerLayout->addWidget(containerHeader);
    containerLayout->addWidget(m_containerOutput);
    layout->addWidget(containerGroup);

    layout->addStretch();

    // ── Signals ──────────────────────────────────────────────────────────
    connect(m_fetchDbBtn, &QPushButton::clicked,
            this, &MainWindow::onFetchDbData);
    connect(m_containerTestBtn, &QPushButton::clicked,
            this, &MainWindow::onContainerTest);
}

void MainWindow::onModuleChanged(int row)
{
    if (row >= 0 && row < m_stackWidget->count()) {
        m_stackWidget->setCurrentIndex(row);
    }
}

// ── Backend Health Check ────────────────────────────────────────────────
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
        m_backendStatusLabel->setText(QStringLiteral("已连接 ✅"));
        m_backendStatusLabel->setStyleSheet("font-size: 14px; color: green;");
        statusBar()->showMessage(
            QStringLiteral("后端已连接 — %1").arg(QString::fromUtf8(data)));
    } else {
        m_backendStatusLabel->setText(QStringLiteral("未连接 ❌"));
        m_backendStatusLabel->setStyleSheet("font-size: 14px; color: red;");
        statusBar()->showMessage(
            QStringLiteral("后端未连接（%1）").arg(reply->errorString()));
    }

    reply->deleteLater();
}

// ── SQLite Data Fetch ───────────────────────────────────────────────────
void MainWindow::onFetchDbData()
{
    m_fetchDbBtn->setEnabled(false);
    m_fetchDbBtn->setText(QStringLiteral("读取中..."));

    QUrl url("http://127.0.0.1:3002/api/db-test");
    QNetworkRequest request(url);
    request.setTransferTimeout(5000);

    auto *reply = m_networkMgr->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        onDbDataReply(reply);
    });
}

void MainWindow::onDbDataReply(QNetworkReply *reply)
{
    m_fetchDbBtn->setEnabled(true);
    m_fetchDbBtn->setText(QStringLiteral("读取数据库"));

    if (reply->error() != QNetworkReply::NoError) {
        m_dbTable->setRowCount(0);
        statusBar()->showMessage(
            QStringLiteral("数据库读取失败：%1").arg(reply->errorString()));
        reply->deleteLater();
        return;
    }

    QByteArray data = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    QJsonObject root = doc.object();
    QJsonArray rows = root[QStringLiteral("data")].toArray();

    m_dbTable->setRowCount(static_cast<int>(rows.size()));
    for (int i = 0; i < rows.size(); ++i) {
        QJsonObject row = rows[i].toObject();
        m_dbTable->setItem(i, 0, new QTableWidgetItem(
            QString::number(row[QStringLiteral("id")].toInt())));
        m_dbTable->setItem(i, 1, new QTableWidgetItem(
            row[QStringLiteral("name")].toString()));
        m_dbTable->setItem(i, 2, new QTableWidgetItem(
            row[QStringLiteral("value")].toString()));
        m_dbTable->setItem(i, 3, new QTableWidgetItem(
            row[QStringLiteral("created_at")].toString()));
    }
    m_dbTable->resizeColumnsToContents();

    statusBar()->showMessage(
        QStringLiteral("数据库读取成功 — %1 条记录").arg(rows.size()));
    reply->deleteLater();
}

// ── Container Tool Test ─────────────────────────────────────────────────
void MainWindow::onContainerTest()
{
    m_containerTestBtn->setEnabled(false);
    m_containerTestBtn->setText(QStringLiteral("测试中..."));
    m_containerOutput->setText(QStringLiteral("正在调用容器..."));

    QUrl url("http://127.0.0.1:3002/api/container-test");
    QNetworkRequest request(url);
    request.setTransferTimeout(20000);

    auto *reply = m_networkMgr->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        onContainerTestReply(reply);
    });
}

void MainWindow::onContainerTestReply(QNetworkReply *reply)
{
    m_containerTestBtn->setEnabled(true);
    m_containerTestBtn->setText(QStringLiteral("测试 nmap 容器"));

    if (reply->error() != QNetworkReply::NoError) {
        m_containerOutput->setText(
            QStringLiteral("请求失败：%1").arg(reply->errorString()));
        reply->deleteLater();
        return;
    }

    QByteArray data = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    QJsonObject root = doc.object();
    QString status = root[QStringLiteral("status")].toString();

    if (status == QStringLiteral("ok")) {
        m_containerOutput->setText(
            QStringLiteral("✅ 容器执行成功\n\n%1")
                .arg(root[QStringLiteral("output")].toString()));
    } else {
        m_containerOutput->setText(
            QStringLiteral("❌ 容器执行失败\n\n%1\n\n提示：%2")
                .arg(root[QStringLiteral("message")].toString())
                .arg(root[QStringLiteral("hint")].toString()));
    }

    reply->deleteLater();
}
