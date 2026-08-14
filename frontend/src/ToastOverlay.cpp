#include "ToastOverlay.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QDateTime>

// ── ToastCard: individual notification card ─────────────────────────────
// No Q_OBJECT needed — uses only base class signals/slots and lambdas.

class ToastCard : public QWidget {
public:
  ToastCard(const QString &icon, const QString &title,
            const QString &message, const QString &color,
            QWidget *parent = nullptr)
      : QWidget(parent)
  {
    setAttribute(Qt::WA_DeleteOnClose);
    setFixedWidth(300);
    setObjectName("toastCard");

    setStyleSheet(
      QString(
        "QWidget#toastCard {"
        "  background: rgba(26, 31, 46, 235);"
        "  border-left: 3px solid %1;"
        "  border-radius: 6px;"
        "  padding: 0px;"
        "}"
      ).arg(color)
    );

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(14, 10, 14, 10);
    layout->setSpacing(3);

    // Title line: icon + title
    auto *titleLine = new QHBoxLayout();
    titleLine->setSpacing(8);
    auto *iconLabel = new QLabel(icon, this);
    iconLabel->setStyleSheet("font-size: 15px; background: transparent;");
    titleLine->addWidget(iconLabel);

    auto *titleLabel = new QLabel(title, this);
    titleLabel->setStyleSheet(
      QString("color: %1; font-size: 13px; font-weight: bold; background: transparent;")
        .arg(color)
    );
    titleLine->addWidget(titleLabel, 1);
    layout->addLayout(titleLine);

    // Message line
    if (!message.isEmpty()) {
      auto *msgLabel = new QLabel(message, this);
      msgLabel->setWordWrap(true);
      msgLabel->setMaximumWidth(280);
      msgLabel->setStyleSheet("color: #a0aec0; font-size: 12px; background: transparent;");
      layout->addWidget(msgLabel);
    }

    // Auto-dismiss with fade-out animation
    auto *timer = new QTimer(this);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, this, [this]() {
      auto *effect = new QGraphicsOpacityEffect(this);
      effect->setOpacity(1.0);
      setGraphicsEffect(effect);

      auto *anim = new QPropertyAnimation(effect, "opacity");
      anim->setDuration(350);
      anim->setStartValue(1.0);
      anim->setEndValue(0.0);
      connect(anim, &QPropertyAnimation::finished, this, [this]() {
        close();
        deleteLater();
      });
      anim->start(QAbstractAnimation::DeleteWhenStopped);
    });
    timer->start(3000);
  }
};

// ── ToastOverlay ───────────────────────────────────────────────────────

ToastOverlay::ToastOverlay(QWidget *parent)
    : QWidget(parent)
{
  setAttribute(Qt::WA_TranslucentBackground);
  setObjectName("toastOverlay");

  m_layout = new QVBoxLayout(this);
  m_layout->setContentsMargins(0, 0, 0, 0);
  m_layout->setSpacing(6);
  m_layout->addStretch();

  setFixedWidth(320);
}

void ToastOverlay::showToast(const QString &icon, const QString &title,
                               const QString &message, const QString &color)
{
  // Limit active toasts
  if (m_activeCount >= MAX_TOASTS) return;

  auto *card = new ToastCard(icon, title, message, color, this);
  connect(card, &QObject::destroyed, this, [this]() {
    if (m_activeCount > 0) m_activeCount--;
  });

  // Insert before the stretch at the bottom
  m_layout->insertWidget(m_layout->count() - 1, card);
  m_activeCount++;

  // Reposition overlay
  reposition();
}

void ToastOverlay::reposition()
{
  QWidget *p = parentWidget();
  if (!p) return;

  // Position in top-right corner of parent, with margin
  int x = p->width() - width() - 16;
  int y = 48;  // below the title bar / menu area
  move(x, y);
  adjustSize();
  raise();
}

// ── Slot implementations ───────────────────────────────────────────────

void ToastOverlay::onScanCompleted(const QJsonObject &data)
{
  QString user = data["username"].toString();
  if (user.isEmpty()) user = data["userId"].toString().left(8);
  if (user.isEmpty()) user = QStringLiteral("未知");

  QString status = data["status"].toString();
  if (status == "COMPLETED") {
    int count = data["resultsCount"].toInt(0);
    showToast("✅", QString("%1 扫描完成").arg(user),
              QString("发现 %1 条结果").arg(count), "#48bb78");
  } else {
    showToast("❌", QString("%1 扫描失败").arg(user),
              data["error"].toString().left(50), "#fc8181");
  }
}

void ToastOverlay::onRunStepComplete(const QJsonObject &data)
{
  QString user = data["username"].toString();
  if (user.isEmpty()) user = data["userId"].toString().left(8);
  if (user.isEmpty()) user = QStringLiteral("未知");

  QString tool = data["tool_id"].toString();
  int step = data["step_index"].toInt(0) + 1;
  int total = data["total_steps"].toInt(0);
  bool success = data["success"].toBool();

  if (success) {
    showToast("⚡", QString("%1 步骤 %2/%3").arg(user).arg(step).arg(total),
              QString("[%1] 执行成功").arg(tool), "#fbd38d");
  }
}

void ToastOverlay::onRunCompleted(const QJsonObject &data)
{
  QString user = data["username"].toString();
  if (user.isEmpty()) user = data["userId"].toString().left(8);
  if (user.isEmpty()) user = QStringLiteral("未知");

  QString status = data["status"].toString();
  int completed = data["completed_steps"].toInt(0);
  int total = data["total_steps"].toInt(0);

  if (status == "COMPLETED") {
    showToast("🎯", QString("%1 攻击完成").arg(user),
              QString("%1/%2 步骤成功").arg(completed).arg(total), "#68d391");
  } else {
    showToast("💥", QString("%1 攻击失败").arg(user), "", "#fc8181");
  }
}
