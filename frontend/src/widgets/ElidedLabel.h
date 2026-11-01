#pragma once
#include <QLabel>
#include <QPainter>

// Preserve text()/tooltip/accessibility; only the single-line display is elided.
class ElidedLabel : public QLabel {
public:
  using QLabel::QLabel;
protected:
  void paintEvent(QPaintEvent *) override {
    QPainter painter(this);
    painter.setPen(palette().color(isEnabled() ? QPalette::Active : QPalette::Disabled, QPalette::WindowText));
    const QRect area = contentsRect().adjusted(margin(), margin(), -margin(), -margin());
    painter.drawText(area, Qt::AlignLeft | Qt::AlignVCenter,
      fontMetrics().elidedText(text(), Qt::ElideRight, area.width()));
  }
};
