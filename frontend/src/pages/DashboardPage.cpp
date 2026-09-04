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
#include <algorithm>

// ── Dashboard Page ─────────────────────────────────────────────────────

DashboardPage::DashboardPage(ApiClient *api, const QString &role,
                               const QString &username, QWidget *parent)
    : QWidget(parent)
    , m_api(api)
    , m_role(role)
    , m_scanTotalLabel(nullptr)
    , m_scanRunningLabel(nullptr)
    , m_scanCompletedLabel(nullptr)
    , m_runTotalLabel(nullptr)
    , m_activityTable(nullptr)
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

  // ── Overview header ────────────────────────────────────────────────
  auto *heroCard = new QFrame(this);
  heroCard->setProperty("card", true);
  auto *heroLayout = new QVBoxLayout(heroCard);
  heroLayout->setContentsMargins(22, 18, 22, 18);
  heroLayout->setSpacing(5);

  auto *titleLabel = new QLabel(QStringLiteral("安全运营总览"), heroCard);
  titleLabel->setStyleSheet("font-size:24px; font-weight:800; color:#172033;");
  heroLayout->addWidget(titleLabel);

  auto *subtitleLabel = new QLabel(
      QStringLiteral("集中查看扫描、执行与实时事件，快速掌握当前测试态势。"), heroCard);
  subtitleLabel->setStyleSheet("font-size:13px; color:#64748b;");
  heroLayout->addWidget(subtitleLabel);
  mainLayout->addWidget(heroCard);

  // ── Stat cards row ─────────────────────────────────────────────────
  auto *statsLayout = new QHBoxLayout();
  statsLayout->setSpacing(16);

  auto createCard = [&](const QString &title, const QString &icon,
                        const QString &color) -> QLabel* {
    auto *frame = new QFrame(this);
    frame->setProperty("card", true);
    auto *cardLayout = new QVBoxLayout(frame);
    cardLayout->setContentsMargins(20, 16, 20, 16);
    cardLayout->setSpacing(6);

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

// ── Stats refresh (polling + merge) ───────────────────────────────────

void DashboardPage::refreshStats()
{
  struct ActivityEntry {
    QDateTime dt;
    QString timeStr;
    QString user;
    QString action;
    QString status;
    QColor statusColor;
  };

  auto *scanEntries = new QList<ActivityEntry>();
  auto *runEntries = new QList<ActivityEntry>();
  auto *pending = new int(2);

  auto mergeAndDisplay = [this, scanEntries, runEntries, pending]() {
    (*pending)--;
    if (*pending > 0) return;

    QList<ActivityEntry> all;
    all << *scanEntries << *runEntries;
    std::sort(all.begin(), all.end(),
      [](const ActivityEntry &a, const ActivityEntry &b) {
        return a.dt > b.dt;
      });

    m_activityTable->setRowCount(0);
    int count = qMin(all.size(), 20);
    for (int i = 0; i < count; i++) {
      const auto &e = all[i];
      int row = m_activityTable->rowCount();
      m_activityTable->insertRow(row);
      m_activityTable->setItem(row, 0, new QTableWidgetItem(e.timeStr));
      m_activityTable->setItem(row, 1, new QTableWidgetItem(e.user));
      m_activityTable->setItem(row, 2, new QTableWidgetItem(e.action));
      auto *statusItem = new QTableWidgetItem(e.status);
      statusItem->setForeground(e.statusColor);
      m_activityTable->setItem(row, 3, statusItem);
    }

    delete scanEntries;
    delete runEntries;
    delete pending;
  };

  // Fetch scan task stats
  m_api->get("/api/scan-tasks", 5000, [this, scanEntries, mergeAndDisplay](const QJsonObject &res) {
    if (res["status"].toString() != "ok") { mergeAndDisplay(); return; }
    auto arr = res["data"].toArray();
    int total = arr.size();
    int running = 0, completed = 0;

    for (const auto &item : arr) {
      QString status = item.toObject()["status"].toString();
      if (status == "RUNNING") running++;
      if (status == "COMPLETED") completed++;

      ActivityEntry e;
      QString time = item.toObject()["created_at"].toString();
      e.dt = QDateTime::fromString(time, Qt::ISODate);
      e.timeStr = e.dt.isValid() ? e.dt.toString("MM-dd HH:mm:ss") : time;
      e.user = item.toObject()["created_by"].toString();
      if (e.user.isEmpty()) e.user = QStringLiteral("-");
      QString scanTypeLabel = item.toObject()["scan_type"].toString();
      if (scanTypeLabel == "port_scan") scanTypeLabel = QStringLiteral("端口扫描");
      else if (scanTypeLabel == "vuln_scan") scanTypeLabel = QStringLiteral("漏洞扫描");
      else if (scanTypeLabel == "web_scan") scanTypeLabel = QStringLiteral("网站扫描");
      else if (scanTypeLabel == "topology") scanTypeLabel = QStringLiteral("拓扑探测");
      QString target = item.toObject()["target"].toString();
      e.action = QStringLiteral("扫描 %1 → %2").arg(scanTypeLabel, target);
      e.status = status;
      if (e.status == "COMPLETED") e.statusColor = QColor("#22c55e");
      else if (e.status == "RUNNING") e.statusColor = QColor("#2563eb");
      else if (e.status == "FAILED") e.statusColor = QColor("#ef4444");
      else e.statusColor = QColor("#94a3b8");
      scanEntries->append(e);
    }

    m_scanTotalLabel->setText(QString::number(total));
    m_scanRunningLabel->setText(QString::number(running));
    m_scanCompletedLabel->setText(QString::number(completed));

    mergeAndDisplay();
  });

  // Fetch run stats
  m_api->get("/api/runs", 5000, [this, runEntries, mergeAndDisplay](const QJsonObject &res) {
    if (res["status"].toString() != "ok") { mergeAndDisplay(); return; }
    auto arr = res["data"].toArray();
    m_runTotalLabel->setText(QString::number(arr.size()));

    for (const auto &item : arr) {
      auto r = item.toObject();
      ActivityEntry e;
      QString time = r["created_at"].toString();
      e.dt = QDateTime::fromString(time, Qt::ISODate);
      e.timeStr = e.dt.isValid() ? e.dt.toString("MM-dd HH:mm:ss") : time;
      e.user = r["user_sub"].toString();
      if (e.user.isEmpty()) e.user = r["created_by"].toString();
      if (e.user.isEmpty()) e.user = QStringLiteral("-");
      QString pbName = r["playbook_name"].toString();
      if (pbName.isEmpty()) pbName = r["playbook_id"].toString().left(12);
      QString target = r["target"].toString();
      e.action = QStringLiteral("攻击 %1 → %2").arg(pbName, target);
      e.status = r["status"].toString();
      if (e.status == "COMPLETED") e.statusColor = QColor("#22c55e");
      else if (e.status == "RUNNING") e.statusColor = QColor("#2563eb");
      else if (e.status == "FAILED") e.statusColor = QColor("#ef4444");
      else e.statusColor = QColor("#94a3b8");
      runEntries->append(e);
    }

    mergeAndDisplay();
  });
}
