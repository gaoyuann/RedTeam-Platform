#include "DashboardPage.h"
#include "LiveActivityPanel.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QTimer>
#include <QTableWidget>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime>

// ── Dashboard Page ─────────────────────────────────────────────────────

DashboardPage::DashboardPage(ApiClient *api, const QString &role,
                               const QString &username, QWidget *parent)
    : QWidget(parent)
    , m_api(api)
    , m_role(role)
{
  setupUI();

  // Auto-refresh stats every 10 seconds
  auto *timer = new QTimer(this);
  timer->setInterval(10000);
  connect(timer, &QTimer::timeout, this, &DashboardPage::refreshStats);
  timer->start();
  refreshStats();
}

void DashboardPage::setupUI()
{
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(20, 16, 20, 16);
  mainLayout->setSpacing(16);

  // ── Title ──────────────────────────────────────────────────────────
  auto *titleLabel = new QLabel(QStringLiteral("总览大屏"));
  titleLabel->setStyleSheet(Theme::SectionStyle);
  mainLayout->addWidget(titleLabel);

  // ── Stat cards row ─────────────────────────────────────────────────
  // 4 white cards in a horizontal row, matching Theme::PageStyle QFrame[card]
  auto *statsLayout = new QHBoxLayout();
  statsLayout->setSpacing(16);

  auto createCard = [&](const QString &title, const QString &icon,
                        const QString &color) -> QLabel* {
    auto *frame = new QFrame(this);
    frame->setProperty("card", true);
    auto *cardLayout = new QVBoxLayout(frame);
    cardLayout->setContentsMargins(20, 16, 20, 16);
    cardLayout->setSpacing(6);

    // Title line: icon + label
    auto *titleRow = new QHBoxLayout();
    titleRow->setSpacing(6);
    auto *iconLabel = new QLabel(icon, frame);
    iconLabel->setStyleSheet("font-size: 16px; background: transparent;");
    titleRow->addWidget(iconLabel);

    auto *titleLabel = new QLabel(title, frame);
    titleLabel->setStyleSheet(
      QString("color: %1; font-size: 13px; font-weight: bold; background: transparent;").arg(color)
    );
    titleRow->addWidget(titleLabel);
    titleRow->addStretch();
    cardLayout->addLayout(titleRow);

    // Big number
    auto *valueLabel = new QLabel(QStringLiteral("0"), frame);
    valueLabel->setStyleSheet("color: #1a2a3a; font-size: 32px; font-weight: bold; background: transparent;");
    cardLayout->addWidget(valueLabel);

    statsLayout->addWidget(frame, 1);
    return valueLabel;
  };

  m_scanTotalLabel    = createCard(QStringLiteral("扫描总数"), "🔍", "#2563eb");
  m_scanRunningLabel  = createCard(QStringLiteral("扫描进行中"), "⏳", "#f59e0b");
  m_scanCompletedLabel = createCard(QStringLiteral("扫描已完成"), "✅", "#22c55e");
  m_runTotalLabel     = createCard(QStringLiteral("攻击执行总数"), "⚡", "#8b5cf6");

  mainLayout->addLayout(statsLayout);

  // ── Recent activity table ──────────────────────────────────────────
  auto *actLabel = new QLabel(QStringLiteral("最近活动"));
  actLabel->setStyleSheet(Theme::SectionStyle);
  mainLayout->addWidget(actLabel);

  m_activityTable = new QTableWidget(0, 4, this);
  m_activityTable->setHorizontalHeaderLabels({
    QStringLiteral("时间"), QStringLiteral("用户"),
    QStringLiteral("操作"), QStringLiteral("状态")
  });
  m_activityTable->setAlternatingRowColors(true);
  m_activityTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_activityTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_activityTable->setSelectionMode(QAbstractItemView::SingleSelection);
  m_activityTable->horizontalHeader()->setStretchLastSection(true);
  m_activityTable->setColumnWidth(0, 160);
  m_activityTable->setColumnWidth(1, 100);
  m_activityTable->setColumnWidth(2, 280);
  m_activityTable->verticalHeader()->setVisible(false);
  m_activityTable->setMinimumHeight(180);
  m_activityTable->setMaximumHeight(300);
  mainLayout->addWidget(m_activityTable);

  // ── Real-time event stream ─────────────────────────────────────────
  auto *evLabel = new QLabel(QStringLiteral("实时事件"));
  evLabel->setStyleSheet(Theme::SectionStyle);
  mainLayout->addWidget(evLabel);

  m_activityPanel = new LiveActivityPanel(m_role, "", this);
  m_activityPanel->setCompact(false);
  mainLayout->addWidget(m_activityPanel, 1);
}

LiveActivityPanel *DashboardPage::activityPanel() const
{
  return m_activityPanel;
}

void DashboardPage::refreshStats()
{
  // Fetch scan task stats
  m_api->get("/api/scan-tasks", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    int total = arr.size();
    int running = 0, completed = 0;
    for (const auto &item : arr) {
      QString status = item.toObject()["status"].toString();
      if (status == "RUNNING") running++;
      if (status == "COMPLETED") completed++;
    }
    m_scanTotalLabel->setText(QString::number(total));
    m_scanRunningLabel->setText(QString::number(running));
    m_scanCompletedLabel->setText(QString::number(completed));

    // Populate recent activity table (last 20 scans)
    m_activityTable->setRowCount(0);
    int count = qMin(arr.size(), 20);
    for (int i = 0; i < count; i++) {
      auto r = arr[i].toObject();
      int row = m_activityTable->rowCount();
      m_activityTable->insertRow(row);

      QString time = r["created_at"].toString();
      auto dt = QDateTime::fromString(time, Qt::ISODate);
      if (dt.isValid()) time = dt.toString("MM-dd HH:mm:ss");
      m_activityTable->setItem(row, 0, new QTableWidgetItem(time));

      QString user = r["created_by"].toString();
      if (user.isEmpty()) user = QStringLiteral("-");
      m_activityTable->setItem(row, 1, new QTableWidgetItem(user));

      QString scanType = r["scan_type"].toString();
      if (scanType == "port_scan") scanType = QStringLiteral("端口扫描");
      else if (scanType == "vuln_scan") scanType = QStringLiteral("漏洞扫描");
      else if (scanType == "web_scan") scanType = QStringLiteral("Web扫描");
      QString target = r["target"].toString();
      m_activityTable->setItem(row, 2, new QTableWidgetItem(
        QStringLiteral("扫描 %1 → %2").arg(scanType, target)));

      QString status = r["status"].toString();
      auto *statusItem = new QTableWidgetItem(status);
      if (status == "COMPLETED") statusItem->setForeground(QColor("#22c55e"));
      else if (status == "RUNNING") statusItem->setForeground(QColor("#2563eb"));
      else if (status == "FAILED") statusItem->setForeground(QColor("#ef4444"));
      m_activityTable->setItem(row, 3, statusItem);
    }
  });

  // Fetch run stats
  m_api->get("/api/runs", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_runTotalLabel->setText(QString::number(arr.size()));
  });
}
