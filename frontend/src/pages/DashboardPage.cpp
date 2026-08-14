#include "DashboardPage.h"
#include "LiveActivityPanel.h"
#include "ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>

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
  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(20, 16, 20, 16);
  mainLayout->setSpacing(16);

  // ── Title ──────────────────────────────────────────────────────────
  auto *titleLabel = new QLabel(QStringLiteral("📡 总览大屏"), this);
  titleLabel->setStyleSheet("color: #e2e8f0; font-size: 22px; font-weight: bold;");
  mainLayout->addWidget(titleLabel);

  // ── Stat cards row ─────────────────────────────────────────────────
  auto *statsLayout = new QHBoxLayout();
  statsLayout->setSpacing(16);

  auto createCard = [&](const QString &title, const QString &color) -> QLabel* {
    auto *frame = new QFrame(this);
    frame->setObjectName("statCard");
    frame->setStyleSheet(
      QString(
        "QFrame#statCard {"
        "  background: #1a1f2e;"
        "  border: 1px solid %1;"
        "  border-radius: 8px;"
        "  padding: 12px;"
        "}"
      ).arg(color)
    );
    auto *cardLayout = new QVBoxLayout(frame);
    cardLayout->setSpacing(4);

    auto *titleLabel = new QLabel(title, frame);
    titleLabel->setStyleSheet(
      QString("color: %1; font-size: 12px; font-weight: bold;").arg(color)
    );
    cardLayout->addWidget(titleLabel);

    auto *valueLabel = new QLabel(QStringLiteral("0"), frame);
    valueLabel->setStyleSheet("color: #e2e8f0; font-size: 28px; font-weight: bold;");
    cardLayout->addWidget(valueLabel);

    statsLayout->addWidget(frame, 1);
    return valueLabel;
  };

  m_scanTotalLabel    = createCard(QStringLiteral("扫描总数"), "#63b3ed");
  m_scanRunningLabel  = createCard(QStringLiteral("扫描进行中"), "#f6ad55");
  m_scanCompletedLabel = createCard(QStringLiteral("扫描已完成"), "#48bb78");
  m_runTotalLabel     = createCard(QStringLiteral("攻击总数"), "#b794f4");
  m_runRunningLabel   = createCard(QStringLiteral("攻击进行中"), "#f6ad55");
  m_runCompletedLabel = createCard(QStringLiteral("攻击已完成"), "#68d391");

  mainLayout->addLayout(statsLayout);

  // ── Activity panel (full-size) ─────────────────────────────────────
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
  });

  // Fetch run stats
  m_api->get("/api/runs", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    int total = arr.size();
    int running = 0, completed = 0;
    for (const auto &item : arr) {
      QString status = item.toObject()["status"].toString();
      if (status == "RUNNING") running++;
      if (status == "COMPLETED") completed++;
    }
    m_runTotalLabel->setText(QString::number(total));
    m_runRunningLabel->setText(QString::number(running));
    m_runCompletedLabel->setText(QString::number(completed));
  });
}
