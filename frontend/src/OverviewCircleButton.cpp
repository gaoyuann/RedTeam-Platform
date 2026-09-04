#include "OverviewCircleButton.h"

#include <QEvent>
#include <QPainter>
#include <QPaintEvent>
#include <QPen>
#include <QTimer>
#include <QtMath>

namespace {
QColor blendedColor(const QColor &color, int delta) {
    return color.lighter(delta);
}
}

OverviewCircleButton::OverviewCircleButton(const QString &title, QWidget *parent)
    : QPushButton(parent),
      m_title(title),
      m_hintText(QStringLiteral("点击进入")),
      m_statusText(QStringLiteral("待命")),
      m_running(false),
      m_hovered(false),
      m_progressValue(-1),
      m_idleColor(QStringLiteral("#16a34a")),
      m_activeColor(QStringLiteral("#ef4444")),
      m_spinTimer(new QTimer(this)),
      m_spinAngle(0) {
    setCursor(Qt::PointingHandCursor);
    setCheckable(false);
    setFlat(true);
    setMinimumSize(220, 220);
    setFocusPolicy(Qt::NoFocus);
    setAttribute(Qt::WA_Hover, true);
    setAttribute(Qt::WA_TranslucentBackground, true);
    setAttribute(Qt::WA_NoSystemBackground, true);
    setAutoFillBackground(false);
    setStyleSheet(QStringLiteral(
        "QPushButton { background:transparent; border:none; }"
        "QPushButton:hover { background:transparent; border:none; }"
        "QPushButton:pressed { background:transparent; border:none; }"
        "QPushButton:focus { outline:none; }"));
    m_spinTimer->setInterval(80);
    connect(m_spinTimer, &QTimer::timeout, this, [this]() {
        m_spinAngle = (m_spinAngle + 18) % 360;
        update();
    });
}

void OverviewCircleButton::setRunning(bool running) {
    if (m_running == running) {
        return;
    }
    m_running = running;
    if (m_running) {
        m_spinTimer->start();
    } else {
        m_spinTimer->stop();
        m_spinAngle = 0;
    }
    update();
}

bool OverviewCircleButton::isRunning() const {
    return m_running;
}

void OverviewCircleButton::setHintText(const QString &text) {
    m_hintText = text;
    update();
}

void OverviewCircleButton::setStatusText(const QString &text) {
    m_statusText = text;
    update();
}

void OverviewCircleButton::setProgressValue(int value) {
    m_progressValue = value;
    update();
}

void OverviewCircleButton::setIdleColor(const QColor &color) {
    m_idleColor = color;
    update();
}

void OverviewCircleButton::setActiveColor(const QColor &color) {
    m_activeColor = color;
    update();
}

void OverviewCircleButton::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event)

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);

    const QRectF bounds = rect().adjusted(16, 16, -16, -16);
    const QColor baseColor = m_running ? m_activeColor : m_idleColor;
    const QColor fillColor = m_hovered ? blendedColor(baseColor, 112) : baseColor;
    const QColor borderColor = baseColor.darker(132);
    const QColor haloColor = QColor(baseColor.red(), baseColor.green(), baseColor.blue(), m_running ? 56 : 34);
    const qreal pulse = m_running ? (0.5 + 0.5 * qSin(qDegreesToRadians(static_cast<qreal>(m_spinAngle) * 2.0))) : 0.0;
    const qreal pulseRadius = m_running ? (12.0 + pulse * 8.0) : 8.0;

    // Halo
    painter.setBrush(haloColor);
    painter.drawEllipse(bounds.adjusted(-pulseRadius, -pulseRadius, pulseRadius, pulseRadius));

    // Shadow
    QRectF shadowRect = bounds.translated(0, 8);
    painter.setBrush(QColor(15, 23, 42, 24));
    painter.drawEllipse(shadowRect);

    // Main circle fill + border
    painter.setBrush(fillColor);
    painter.setPen(QPen(borderColor, 2));
    painter.drawEllipse(bounds);

    // Running animation: glow + spinning arcs
    if (m_running) {
        const QRectF glowRect = bounds.adjusted(-18, -18, 18, 18);
        QPen glowPen(QColor(255, 247, 181, 110 + static_cast<int>(pulse * 70.0)), 8);
        glowPen.setCapStyle(Qt::RoundCap);
        painter.setPen(glowPen);
        painter.drawEllipse(glowRect);

        const QRectF arcRect = bounds.adjusted(-13, -13, 13, 13);
        for (int index = 0; index < 6; ++index) {
            QColor arcColor = QColor(255, 255, 255, 235 - index * 28);
            QPen arcPen(arcColor, 9 - index);
            arcPen.setCapStyle(Qt::RoundCap);
            painter.setPen(arcPen);
            const int startAngle = (m_spinAngle - index * 22) * 16;
            painter.drawArc(arcRect, startAngle, 42 * 16);
        }
        painter.setPen(Qt::NoPen);
    }

    // Title text — white on colored circle (same as pentagi)
    painter.setPen(QColor(QStringLiteral("#ffffff")));

    QFont titleFont = font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    painter.setFont(titleFont);
    QRectF titleRect(bounds.left() + 28, bounds.top() + 42, bounds.width() - 56, bounds.height() * 0.36);
    painter.drawText(titleRect, Qt::AlignCenter | Qt::TextWordWrap, m_title);

    // Status text
    QFont statusFont = font();
    statusFont.setPointSize(10);
    statusFont.setBold(true);
    painter.setFont(statusFont);
    const QString statusText = m_statusText.trimmed().isEmpty()
                                   ? (m_running ? QStringLiteral("运行中") : QStringLiteral("待命"))
                                   : m_statusText;
    QRectF statusRect(bounds.left() + 24, bounds.center().y() + 6, bounds.width() - 48, 22);
    painter.drawText(statusRect, Qt::AlignCenter, statusText);

    // Progress value
    if (m_progressValue >= 0) {
        QFont progressFont = font();
        progressFont.setPointSize(12);
        progressFont.setBold(true);
        painter.setFont(progressFont);
        QRectF progressRect(bounds.left() + 24, bounds.center().y() + 30, bounds.width() - 48, 22);
        painter.drawText(progressRect, Qt::AlignCenter, QStringLiteral("进度 %1%").arg(m_progressValue));
    }

    // Hint text — white with alpha (same as pentagi)
    QFont hintFont = font();
    hintFont.setPointSize(9);
    painter.setFont(hintFont);
    painter.setPen(QColor(255, 255, 255, 220));
    QRectF hintRect(bounds.left() + 24, bounds.bottom() - 48, bounds.width() - 48, 18);
    painter.drawText(hintRect, Qt::AlignCenter, m_hintText);
}

void OverviewCircleButton::enterEvent(QEvent *event) {
    QPushButton::enterEvent(event);
    m_hovered = true;
    update();
}

void OverviewCircleButton::leaveEvent(QEvent *event) {
    QPushButton::leaveEvent(event);
    m_hovered = false;
    update();
}
