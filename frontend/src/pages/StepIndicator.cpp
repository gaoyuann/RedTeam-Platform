#include "StepIndicator.h"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static QColor colorForStatus(const QString &status)
{
  if (status == "running")    return QColor("#2a7dd6");
  if (status == "completed")  return QColor("#27ae60");
  if (status == "skipped")    return QColor("#b45309");
  if (status == "failed")     return QColor("#e74c3c");
  /* pending  */              return QColor("#a0aec0");
}

static QString iconForStatus(const QString &status)
{
  if (status == "running")    return QStringLiteral("\U0001F504");  // 🔄
  if (status == "completed")  return QStringLiteral("✅");      // ✅
  if (status == "skipped")    return QStringLiteral("⏭");      // ⏭
  if (status == "failed")     return QStringLiteral("❌");      // ❌
  /* pending  */              return QStringLiteral("⬜");      // ⬜
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

StepIndicator::StepIndicator(QWidget *parent)
    : QWidget(parent)
{
  setMouseTracking(true);
  setMinimumHeight(80);
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
  return QSize(300, 80);
}

QSize StepIndicator::sizeHint() const
{
  return QSize(600, 80);
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

static constexpr int kRadius   = 18;   // circle radius (px)
static constexpr int kDiameter = 36;   // 2 * radius

// Returns the bounding rect for the hit-test / hover region around node `index`.
QRect StepIndicator::nodeRect(int index) const
{
  if (index < 0 || index >= m_phases.size())
    return {};

  const int count = m_phases.size();
  const int w     = width();
  const int gap   = qMax(8, (w - count * kDiameter) / (count + 1));

  const int cx    = gap + index * (kDiameter + gap) + kRadius;
  const int cy    = height() / 2 - 5;   // same Y as paintEvent uses

  // Slightly larger than the visual circle for easier clicking
  const int margin = 6;
  return QRect(cx - kRadius - margin,
               cy - kRadius - margin,
               kDiameter + 2 * margin,
               kDiameter + 2 * margin);
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

void StepIndicator::paintEvent(QPaintEvent * /*event*/)
{
  QPainter p(this);
  p.setRenderHint(QPainter::Antialiasing);

  const int count = m_phases.size();
  if (count == 0)
    return;

  const int w   = width();
  const int gap = qMax(8, (w - count * kDiameter) / (count + 1));

  // Vertical centres
  const int circleY = height() / 2 - 5;    // centre of each circle
  const int iconY   = circleY - kRadius - 18;  // status icon above
  const int nameY   = circleY + kRadius + 6;   // display name below

  // ---------- 1. arrows between nodes ----------
  // No horizontal connector line — just a prominent chevron arrow centered
  // between the two nodes so the flow direction stays clear.
  QColor arrowColor("#4a5568");
  QPen arrowPen(arrowColor, 3);
  arrowPen.setCapStyle(Qt::RoundCap);
  arrowPen.setJoinStyle(Qt::RoundJoin);
  p.setPen(arrowPen);
  p.setBrush(Qt::NoBrush);

  for (int i = 0; i < count - 1; ++i) {
    const int cx1 = gap + i * (kDiameter + gap) + kRadius;
    const int cx2 = gap + (i + 1) * (kDiameter + gap) + kRadius;

    if (cx2 - cx1 < 2 * kDiameter)
      continue;   // too narrow, skip arrow

    const int midX  = (cx1 + cx2) / 2;
    const int aSize = 9;   // chevron half-size

    QPainterPath chevron;
    chevron.moveTo(midX - aSize, circleY - aSize);   // top-left
    chevron.lineTo(midX,           circleY);          // right tip
    chevron.lineTo(midX - aSize, circleY + aSize);   // bottom-left
    p.drawPath(chevron);
  }

  // ---------- 2. nodes ----------
  for (int i = 0; i < count; ++i) {
    const PhaseStep &ps = m_phases[i];
    const QColor col    = colorForStatus(ps.status);
    const int cx = gap + i * (kDiameter + gap) + kRadius;

    // -- status icon (above circle) --
    {
      p.setPen(col);
      QFont f = p.font();
      f.setPixelSize(16);
      p.setFont(f);
      QRect iconRect(cx - kRadius, iconY, kDiameter, 18);
      p.drawText(iconRect, Qt::AlignCenter, iconForStatus(ps.status));
    }

    // -- circle --
    {
      p.setPen(QPen(col, 2));
      p.setBrush(Qt::white);
      p.drawEllipse(QPointF(cx, circleY), kRadius, kRadius);
    }

    // -- number inside circle --
    {
      p.setPen(col);
      QFont f = p.font();
      f.setPixelSize(14);
      f.setBold(true);
      p.setFont(f);
      QRect numRect(cx - kRadius, circleY - kRadius, kDiameter, kDiameter);
      p.drawText(numRect, Qt::AlignCenter, QString::number(i + 1));
    }

    // -- Chinese name below --
    {
      p.setPen(QColor("#4a5568"));
      QFont f = p.font();
      f.setPixelSize(11);
      p.setFont(f);
      QRect nameRect(cx - kRadius - 8, nameY, kDiameter + 16, 18);
      p.drawText(nameRect, Qt::AlignCenter, ps.displayName);
    }
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
