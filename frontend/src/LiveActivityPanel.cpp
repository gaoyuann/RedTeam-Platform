#include "LiveActivityPanel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QScrollBar>
#include <QListWidgetItem>

// ── LiveActivityPanel ──────────────────────────────────────────────────

LiveActivityPanel::LiveActivityPanel(const QString &role, const QString &username,
                                       QWidget *parent)
    : QWidget(parent)
    , m_role(role)
    , m_username(username)
{
  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(0, 0, 0, 0);
  mainLayout->setSpacing(0);

  // ── Header bar ─────────────────────────────────────────────────────
  auto *headerFrame = new QFrame(this);
  headerFrame->setObjectName("activityHeader");
  headerFrame->setFixedHeight(32);
  headerFrame->setStyleSheet(
    "QFrame#activityHeader {"
    "  background: #ffffff;"
    "  border-bottom: 1px solid #e2e8f0;"
    "}"
  );
  auto *headerLayout = new QHBoxLayout(headerFrame);
  headerLayout->setContentsMargins(12, 0, 12, 0);

  m_titleLabel = new QLabel(QStringLiteral("📡 实时动态"), this);
  m_titleLabel->setStyleSheet("color: #2563eb; font-size: 13px; font-weight: bold; background: transparent;");
  headerLayout->addWidget(m_titleLabel);

  m_countLabel = new QLabel(QStringLiteral("0 条"), this);
  m_countLabel->setStyleSheet("color: #94a3b8; font-size: 12px; background: transparent;");
  headerLayout->addWidget(m_countLabel);

  headerLayout->addStretch();

  m_collapseBtn = new QPushButton(QStringLiteral("▼"), this);
  m_collapseBtn->setFixedSize(24, 24);
  m_collapseBtn->setStyleSheet(
    "QPushButton { border: none; color: #94a3b8; font-size: 14px; background: transparent; }"
    "QPushButton:hover { color: #64748b; }"
  );
  connect(m_collapseBtn, &QPushButton::clicked, this, &LiveActivityPanel::onToggleCollapse);
  headerLayout->addWidget(m_collapseBtn);

  mainLayout->addWidget(headerFrame);

  // ── Event list ─────────────────────────────────────────────────────
  m_eventList = new QListWidget(this);
  m_eventList->setObjectName("activityList");
  m_eventList->setStyleSheet(
    "QListWidget#activityList {"
    "  background: #ffffff;"
    "  border: none;"
    "  font-family: 'Consolas', 'Monaco', monospace;"
    "  font-size: 12px;"
    "  outline: none;"
    "}"
    "QListWidget#activityList::item {"
    "  padding: 4px 12px;"
    "  border-bottom: 1px solid #f1f5f9;"
    "}"
    "QListWidget#activityList::item:selected {"
    "  background: transparent;"
    "}"
  );
  m_eventList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  m_eventList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
  mainLayout->addWidget(m_eventList, 1);

  setCompact(true);
}

void LiveActivityPanel::setCompact(bool compact)
{
  m_compact = compact;
  if (compact) {
    setFixedHeight(180);
  } else {
    setMinimumHeight(200);
    setMaximumHeight(QWIDGETSIZE_MAX);
  }
}

// ── Event handlers ─────────────────────────────────────────────────────

void LiveActivityPanel::onScanCreated(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString target = data["target"].toString();
  QString scanType = data["scanType"].toString();
  addEvent("🔵",
    QString("%1 创建扫描 [%2] → %3").arg(user, scanType, target),
    "#2563eb");
}

void LiveActivityPanel::onScanStarted(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString id = data["scanTaskId"].toString();
  id = id.left(16);
  addEvent("▶️",
    QString("%1 启动扫描 %2...").arg(user, id),
    "#0891b2");
}

void LiveActivityPanel::onScanCompleted(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString id = data["scanTaskId"].toString();
  id = id.left(16);
  QString status = data["status"].toString();
  if (status == "COMPLETED") {
    int count = data["resultsCount"].toInt(0);
    addEvent("✅",
      QString("%1 扫描完成 %2... (%3 条结果)").arg(user, id).arg(count),
      "#22c55e");
  } else {
    QString error = data["error"].toString();
    if (error.length() > 40) error = error.left(40) + "...";
    addEvent("❌",
      QString("%1 扫描失败 %2... %3").arg(user, id, error),
      "#ef4444");
  }
}

void LiveActivityPanel::onRunCreated(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString target = data["target"].toString();
  addEvent("📋",
    QString("%1 创建攻击执行 → %2").arg(user, target),
    "#8b5cf6");
}

void LiveActivityPanel::onRunStarted(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString id = data["runId"].toString();
  id = id.left(16);
  addEvent("🚀",
    QString("%1 启动攻击 %2...").arg(user, id),
    "#f59e0b");
}

void LiveActivityPanel::onRunStepComplete(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString tool = data["tool_id"].toString();
  int step = data["step_index"].toInt(0) + 1;
  int total = data["total_steps"].toInt(0);
  bool success = data["success"].toBool();
  if (success) {
    addEvent("⚡",
      QString("%1 步骤 %2/%3 [%4] 完成").arg(user).arg(step).arg(total).arg(tool),
      "#f59e0b");
  } else {
    addEvent("⚠️",
      QString("%1 步骤 %2/%3 [%4] 失败").arg(user).arg(step).arg(total).arg(tool),
      "#ef4444");
  }
}

void LiveActivityPanel::onRunCompleted(const QJsonObject &data)
{
  QString user = formatUser(data);
  QString id = data["run_id"].toString();
  id = id.left(16);
  QString status = data["status"].toString();
  int completed = data["completed_steps"].toInt(0);
  int total = data["total_steps"].toInt(0);
  if (status == "COMPLETED") {
    addEvent("🎯",
      QString("%1 攻击完成 %2... (%3/%4 步骤成功)").arg(user, id).arg(completed).arg(total),
      "#22c55e");
  } else {
    addEvent("💥",
      QString("%1 攻击失败 %2...").arg(user, id),
      "#ef4444");
  }
}

// ── Private helpers ────────────────────────────────────────────────────

void LiveActivityPanel::addEvent(const QString &icon, const QString &text, const QString &color)
{
  QString time = nowTime();
  QString html = QString(
    "<span style='color:#94a3b8;'>%1</span> "
    "%2 "
    "<span style='color:%3;'>%4</span>"
  ).arg(time, icon, color, text.toHtmlEscaped());

  auto *item = new QListWidgetItem(m_eventList);
  item->setText(html);
  item->setFlags(item->flags() & ~Qt::ItemIsSelectable);

  // Trim old events
  while (m_eventList->count() > MAX_EVENTS) {
    delete m_eventList->takeItem(0);
  }

  m_eventList->scrollToBottom();
  m_countLabel->setText(QString("%1 条").arg(m_eventList->count()));
}

QString LiveActivityPanel::formatUser(const QJsonObject &data) const
{
  QString username = data["username"].toString();
  QString userId = data["userId"].toString();
  if (!username.isEmpty()) return QStringLiteral("[%1]").arg(username);
  if (!userId.isEmpty()) return QStringLiteral("[%1]").arg(userId.left(8));
  return QStringLiteral("[系统]");
}

QString LiveActivityPanel::nowTime() const
{
  return QDateTime::currentDateTime().toString("HH:mm:ss");
}

void LiveActivityPanel::onToggleCollapse()
{
  m_collapsed = !m_collapsed;
  m_eventList->setVisible(!m_collapsed);
  m_collapseBtn->setText(m_collapsed ? QStringLiteral("▲") : QStringLiteral("▼"));
  if (m_compact) {
    setFixedHeight(m_collapsed ? 32 : 180);
  }
}
