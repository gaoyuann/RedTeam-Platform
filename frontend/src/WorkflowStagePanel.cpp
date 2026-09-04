#include "WorkflowStagePanel.h"
#include "OverviewCircleButton.h"

#include <QPainter>
#include <QPainterPath>
#include <QPaintEvent>
#include <QTimer>
#include <QtMath>

// ── Stage visual states ─────────────────────────────────────────────────
// Must stay in sync with DashboardPage's state constants.
namespace {
// State indices — used by both WorkflowStagePanel and DashboardPage
constexpr int StageIdle     = 0;
constexpr int StageReady    = 1;
constexpr int StageRunning  = 2;
constexpr int StageWaiting  = 3;
constexpr int StageFinished = 4;
constexpr int StageFailed   = 5;
}

WorkflowStagePanel::WorkflowStagePanel(QWidget *parent)
    : QFrame(parent),
      m_topologyButton(nullptr),
      m_scanButton(nullptr),
      m_targetButton(nullptr),
      m_methodsButton(nullptr),
      m_topologyState(StageIdle),
      m_scanState(StageIdle),
      m_targetState(StageIdle),
      m_methodsState(StageIdle),
      m_phase(0),
      m_timer(new QTimer(this)) {
    setObjectName(QStringLiteral("workflowStagePanel"));
    setFrameShape(QFrame::NoFrame);
    setAutoFillBackground(false);
    setAttribute(Qt::WA_TranslucentBackground, true);
    setStyleSheet(QStringLiteral("QFrame#workflowStagePanel { background:transparent; border:none; }"));
    m_timer->setInterval(90);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        m_phase = (m_phase + 7) % 360;
        update();
    });
    m_timer->start();
}

void WorkflowStagePanel::setButtons(OverviewCircleButton *topologyButton,
                                    OverviewCircleButton *scanButton,
                                    OverviewCircleButton *targetButton,
                                    OverviewCircleButton *methodsButton) {
    m_topologyButton = topologyButton;
    m_scanButton = scanButton;
    m_targetButton = targetButton;
    m_methodsButton = methodsButton;
}

void WorkflowStagePanel::setStageState(const QString &pageId, int state) {
    if (pageId == QStringLiteral("topology")) {
        m_topologyState = state;
    } else if (pageId == QStringLiteral("scan")) {
        m_scanState = state;
    } else if (pageId == QStringLiteral("attack.target")) {
        m_targetState = state;
    } else if (pageId == QStringLiteral("attack.methods")) {
        m_methodsState = state;
    }
    update();
}

void WorkflowStagePanel::paintEvent(QPaintEvent *event) {
    QFrame::paintEvent(event);
    if (!m_topologyButton || !m_scanButton || !m_targetButton || !m_methodsButton) {
        return;
    }

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    // Arrow: topology → scan
    drawArrow(&painter,
              mapPoint(m_topologyButton, QPoint(m_topologyButton->width(), m_topologyButton->height() / 2)),
              mapPoint(m_scanButton, QPoint(0, m_scanButton->height() / 2)),
              m_topologyState,
              m_scanState,
              0.0);

    // Arrow: scan → target (upper)
    const QPointF scanOut = mapPoint(m_scanButton, QPoint(m_scanButton->width(), m_scanButton->height() / 2));
    drawArrow(&painter,
              scanOut,
              mapPoint(m_targetButton, QPoint(0, m_targetButton->height() / 2)),
              m_scanState,
              m_targetState,
              -48.0);

    // Arrow: scan → methods (lower)
    drawArrow(&painter,
              scanOut,
              mapPoint(m_methodsButton, QPoint(0, m_methodsButton->height() / 2)),
              m_scanState,
              m_methodsState,
              48.0);
}

QPointF WorkflowStagePanel::mapPoint(QWidget *widget, const QPoint &point) const {
    return mapFromGlobal(widget->mapToGlobal(point));
}

bool WorkflowStagePanel::isArrowActive(int fromState, int toState) const {
    return fromState == StageRunning
           || fromState == StageWaiting
           || fromState == StageFinished
           || toState == StageReady
           || toState == StageRunning
           || toState == StageWaiting;
}

QColor WorkflowStagePanel::colorForState(int state) const {
    switch (state) {
    case StageRunning:  return QColor(QStringLiteral("#2563eb"));
    case StageWaiting:  return QColor(QStringLiteral("#f59e0b"));
    case StageFinished: return QColor(QStringLiteral("#16a34a"));
    case StageFailed:   return QColor(QStringLiteral("#dc2626"));
    case StageReady:    return QColor(QStringLiteral("#0891b2"));
    case StageIdle:
    default:            return QColor(QStringLiteral("#94a3b8"));
    }
}

void WorkflowStagePanel::drawArrow(QPainter *painter,
                                   const QPointF &start,
                                   const QPointF &end,
                                   int fromState,
                                   int toState,
                                   qreal curveOffset) {
    const bool active = isArrowActive(fromState, toState);
    const QColor baseColor = active ? colorForState(toState == StageIdle ? fromState : toState)
                                    : QColor(QStringLiteral("#cbd5e1"));
    const qreal midX = (start.x() + end.x()) * 0.5;
    QPainterPath path(start);
    path.cubicTo(QPointF(midX, start.y() + curveOffset),
                 QPointF(midX, end.y() + curveOffset),
                 end);

    // Shadow line
    QPen shadowPen(QColor(15, 23, 42, active ? 36 : 18), active ? 8 : 5);
    shadowPen.setCapStyle(Qt::RoundCap);
    painter->setPen(shadowPen);
    painter->drawPath(path);

    // Main line
    QPen pen(baseColor, active ? 4.5 : 3.0);
    pen.setCapStyle(Qt::RoundCap);
    painter->setPen(pen);
    painter->drawPath(path);

    // Flowing dot (only when active)
    if (active) {
        const qreal t = static_cast<qreal>(m_phase) / 360.0;
        const QPointF dot = path.pointAtPercent(t);
        painter->setPen(Qt::NoPen);
        painter->setBrush(QColor(255, 255, 255, 230));
        painter->drawEllipse(dot, 5.0, 5.0);
        painter->setBrush(QColor(baseColor.red(), baseColor.green(), baseColor.blue(), 120));
        painter->drawEllipse(dot, 10.0, 10.0);
    }

    // Arrow head
    const qreal angle = qAtan2(end.y() - start.y(), end.x() - start.x());
    const qreal size = active ? 15.0 : 12.0;
    QPolygonF arrowHead;
    arrowHead << end
              << QPointF(end.x() - qCos(angle - M_PI / 7.0) * size,
                         end.y() - qSin(angle - M_PI / 7.0) * size)
              << QPointF(end.x() - qCos(angle + M_PI / 7.0) * size,
                         end.y() - qSin(angle + M_PI / 7.0) * size);
    painter->setPen(Qt::NoPen);
    painter->setBrush(baseColor);
    painter->drawPolygon(arrowHead);
}
