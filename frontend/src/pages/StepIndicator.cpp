#include "StepIndicator.h"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QHelpEvent>
#include <QToolTip>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static QColor colorForStatus(const QString &status)
{
  if (status == "awaiting_approval") return QColor("#b45309");
  if (status == "running")    return QColor("#2a7dd6");
  if (status == "completed")  return QColor("#27ae60");
  if (status == "skipped")    return QColor("#b45309");
  if (status == "failed")     return QColor("#e74c3c");
  if (status == "cancelled")  return QColor("#94a3b8");
  /* pending  */              return QColor("#a0aec0");
}

static QString labelForStatus(const QString &status)
{
  if (status == "running") return QStringLiteral("进行中");
  if (status == "awaiting_approval") return QStringLiteral("待确认");
  if (status == "completed") return QStringLiteral("已完成");
  if (status == "failed") return QStringLiteral("失败");
  if (status == "cancelled") return QStringLiteral("已取消");
  if (status == "skipped") return QStringLiteral("已跳过");
  return QStringLiteral("待开始");
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

StepIndicator::StepIndicator(QWidget *parent)
    : QWidget(parent)
{
  setMouseTracking(true);
  setFixedHeight(78);
  setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

  // Default three campaign phases (in order)
  m_phases = {
    { QStringLiteral("data-exfiltration"),
      QStringLiteral("数据窃取"),    QStringLiteral("phase_1"), QStringLiteral("pending") },
    { QStringLiteral("tampering-deception"),
      QStringLiteral("信息篡改"),    QStringLiteral("phase_2"), QStringLiteral("pending") },
    { QStringLiteral("device-control"),
      QStringLiteral("设备夺控"),    QStringLiteral("phase_3"), QStringLiteral("pending") },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void StepIndicator::setPhases(const QVector<PhaseStep> &phases)
{
  m_phases = phases;
  update();
}

QVector<PhaseStep> StepIndicator::phases() const
{
  return m_phases;
}

// ---------------------------------------------------------------------------
// Size hints
// ---------------------------------------------------------------------------

QSize StepIndicator::minimumSizeHint() const
{
  return QSize(300, 78);
}

QSize StepIndicator::sizeHint() const
{
  return QSize(600, 78);
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

QRect StepIndicator::nodeRect(int index) const
{
  if (index < 0 || index >= m_phases.size()) return {};
  const int gap = 8;
  const int cardWidth = (width() - gap * (m_phases.size() - 1)) / m_phases.size();
  return QRect(index * (cardWidth + gap), 2, cardWidth, height() - 4);
}

int StepIndicator::nodeAtPos(const QPoint &pos) const
{
  for (int i = 0; i < m_phases.size(); ++i) {
    if (nodeRect(i).contains(pos))
      return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------

void StepIndicator::paintEvent(QPaintEvent *)
{
  QPainter p(this);
  p.setRenderHint(QPainter::Antialiasing);
  for (int i = 0; i < m_phases.size(); ++i) {
    const auto &phase = m_phases[i];
    const auto rect = nodeRect(i);
    const auto color = colorForStatus(phase.status);
    const bool active = phase.status == "running" || phase.status == "awaiting_approval";
    p.setPen(QPen(active ? color : QColor("#dbe3ef"), active ? 1.5 : 1));
    p.setBrush(active ? (phase.status == "running" ? QColor("#eff6ff") : QColor("#fffbeb")) : QColor("#ffffff"));
    p.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 8, 8);
    const QRect badge(rect.left() + 10, rect.top() + 12, 25, 25);
    p.setPen(Qt::NoPen); p.setBrush(color); p.drawEllipse(badge);
    QFont font = p.font(); font.setPixelSize(12); font.setBold(true);
    p.setFont(font); p.setPen(Qt::white);
    const QString icon = phase.status == "completed" ? QStringLiteral("✓") :
                         phase.status == "failed" ? QStringLiteral("×") : QString::number(i + 1);
    p.drawText(badge, Qt::AlignCenter, icon);
    p.setPen(QColor("#172033")); font.setPixelSize(13); p.setFont(font);
    const QRect title(rect.left() + 43, rect.top() + 10, rect.width() - 98, 24);
    p.drawText(title, Qt::AlignLeft | Qt::AlignVCenter,
               QFontMetrics(font).elidedText(phase.displayName, Qt::ElideRight, title.width()));
    font.setPixelSize(10); font.setBold(false); p.setFont(font); p.setPen(color);
    p.drawText(QRect(rect.right() - 52, rect.top() + 13, 42, 20), Qt::AlignRight | Qt::AlignVCenter,
               labelForStatus(phase.status));
    const QString summary = phase.summary.isEmpty()
        ? (active ? QStringLiteral("正在处理，请稍候") : labelForStatus(phase.status)) : phase.summary;
    font.setPixelSize(12); p.setFont(font); p.setPen(QColor("#52637a"));
    const QRect summaryRect(rect.left() + 11, rect.top() + 46, rect.width() - 22, 19);
    p.drawText(summaryRect, Qt::AlignLeft | Qt::AlignVCenter,
               QFontMetrics(font).elidedText(summary, Qt::ElideRight, summaryRect.width()));
  }
}

// ---------------------------------------------------------------------------
// Mouse interaction
// ---------------------------------------------------------------------------

void StepIndicator::mousePressEvent(QMouseEvent *event)
{
  const int idx = nodeAtPos(event->pos());
  if (idx >= 0)
    emit phaseClicked(idx);

  QWidget::mousePressEvent(event);
}


bool StepIndicator::event(QEvent *event)
{
  if (event->type() == QEvent::ToolTip) {
    auto *help = static_cast<QHelpEvent*>(event);
    const int index = nodeAtPos(help->pos());
    if (index >= 0) {
      const auto &phase = m_phases[index];
      QToolTip::showText(help->globalPos(), phase.displayName + " · " + labelForStatus(phase.status)
                        + "\n" + phase.summary, this);
      return true;
    }
  }
  return QWidget::event(event);
}
