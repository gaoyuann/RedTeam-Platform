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
  if (status == "running")    return QColor("#2563eb");
  if (status == "completed")  return QColor("#16a36b");
  if (status == "skipped")    return QColor("#b45309");
  if (status == "failed")     return QColor("#dc4b4b");
  if (status == "cancelled")  return QColor("#94a3b8");
  /* pending  */              return QColor("#78879c");
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
    const QRectF card = nodeRect(i).adjusted(1, 1, -1, -1);
    const QColor color = colorForStatus(phase.status);
    const bool active = phase.status == "running" || phase.status == "awaiting_approval";
    const bool completed = phase.status == "completed";
    const bool failed = phase.status == "failed";
    const bool waiting = phase.status == "awaiting_approval";
    const QColor border = waiting ? QColor("#f0d7a6")
                                  : active ? QColor("#b9d2fc") : QColor("#e0e7f0");
    const QColor surface = waiting ? QColor("#fffcf5")
                                   : active ? QColor("#f5f9ff") : QColor("#ffffff");
    p.setPen(QPen(border, 1));
    p.setBrush(surface);
    p.drawRoundedRect(card, 10, 10);

    // Small, lightly tinted status tile with vector marks at any display scale.
    const QRectF tile(card.left() + 11, card.top() + 11, 28, 28);
    QColor tint = color; tint.setAlpha(24);
    p.setPen(Qt::NoPen); p.setBrush(tint); p.drawRoundedRect(tile, 8, 8);
    p.setPen(QPen(color, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    if (completed) {
      QPainterPath check;
      check.moveTo(tile.left()+8, tile.top()+14);
      check.lineTo(tile.left()+12, tile.top()+18);
      check.lineTo(tile.left()+20, tile.top()+10);
      p.drawPath(check);
    } else if (failed) {
      p.drawLine(tile.topLeft()+QPointF(10,10), tile.topLeft()+QPointF(18,18));
      p.drawLine(tile.topLeft()+QPointF(18,10), tile.topLeft()+QPointF(10,18));
    } else {
      QFont number = font(); number.setPixelSize(12); number.setBold(true);
      p.setFont(number); p.drawText(tile, Qt::AlignCenter, QString::number(i+1));
    }

    QFont label = font(); label.setPixelSize(13); label.setBold(true);
    p.setFont(label); p.setPen(QColor("#243247"));
    const QRectF title(card.left()+48, card.top()+10, qMax(0.0,card.width()-108), 24);
    p.drawText(title, Qt::AlignLeft|Qt::AlignVCenter,
               QFontMetrics(label).elidedText(phase.displayName, Qt::ElideRight, int(title.width())));
    label.setPixelSize(11); label.setBold(false); p.setFont(label);
    p.setPen(color);
    p.drawText(QRectF(card.right()-56, card.top()+12, 46, 20),
               Qt::AlignRight|Qt::AlignVCenter, labelForStatus(phase.status));

    const QString summary = phase.summary.isEmpty()
        ? (active ? QStringLiteral("正在处理，请稍候") : labelForStatus(phase.status))
        : phase.summary;
    label.setPixelSize(12); p.setFont(label); p.setPen(QColor("#718096"));
    const QRectF detail(card.left()+12, card.top()+45, card.width()-24, 20);
    p.drawText(detail, Qt::AlignLeft|Qt::AlignVCenter,
               QFontMetrics(label).elidedText(summary, Qt::ElideRight, int(detail.width())));
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
