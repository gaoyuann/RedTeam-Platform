#pragma once
#include <QTabWidget>
#include <QTabBar>
#include <QVariantAnimation>
#include <QPainter>
#include <QResizeEvent>
#include <QShowEvent>

// Native tabs retain keyboard navigation, scrolling and page switching.
// Only the underline is animated; it does not delay the actual selection.
class WorkbenchTabBar : public QTabBar {
public:
  explicit WorkbenchTabBar(QWidget *parent = nullptr, bool compact = true)
      : QTabBar(parent), m_padding(compact ? 16 : 22) {
    setDrawBase(false);
    setExpanding(false);
    setStyleSheet(QStringLiteral(
      "QTabBar::tab { background:transparent; color:#64748b; border:none;"
      " padding:%1px %2px; margin-right:4px; font-size:13px; font-weight:500; }"
      "QTabBar::tab:selected { color:#2563eb; font-weight:600; }"
      "QTabBar::tab:hover:!selected { color:#2563eb; background:#f1f6ff; border-radius:6px; }"
      "QTabBar::tab:disabled { color:#a3afbf; }").arg(compact ? 9 : 12).arg(m_padding));
    m_animation.setDuration(150);
    m_animation.setEasingCurve(QEasingCurve::OutCubic);
    connect(&m_animation, &QVariantAnimation::valueChanged, this, [this](const QVariant &value) {
      m_progress = value.toReal();
      update();
    });
    connect(this, &QTabBar::currentChanged, this, [this](int index) {
      const QRectF next = indicatorRect(index);
      if (!isVisible() || m_line.isEmpty()) {
        m_animation.stop();
        m_line = next;
        m_progress = 1;
        update();
        return;
      }
      m_from = currentLine();
      m_line = next;
      m_animation.stop();
      m_progress = 0;
      m_animation.setStartValue(0.0);
      m_animation.setEndValue(1.0);
      m_animation.start();
    });
  }
protected:
  void paintEvent(QPaintEvent *event) override {
    QTabBar::paintEvent(event);
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor("#2563eb"));
    // Scroll buttons can change tab positions without changing the index.
    m_line = indicatorRect(currentIndex());
    p.drawRoundedRect(currentLine(), 1.5, 1.5);
  }
  void resizeEvent(QResizeEvent *event) override {
    QTabBar::resizeEvent(event);
    settle();
  }
  void showEvent(QShowEvent *event) override {
    QTabBar::showEvent(event);
    settle();
  }
private:
  QRectF indicatorRect(int index) const {
    if (index < 0) return {};
    const QRect tab = tabRect(index);
    const qreal w = qMax(20, tab.width() - 2 * m_padding);
    return QRectF(tab.center().x() - w / 2, height() - 3, w, 3);
  }
  QRectF currentLine() const {
    if (m_progress >= 1 || m_from.isEmpty()) return m_line;
    return QRectF(m_from.x() + (m_line.x() - m_from.x()) * m_progress,
                  m_line.y(), m_from.width() + (m_line.width() - m_from.width()) * m_progress, 3);
  }
  void settle() {
    m_animation.stop();
    m_progress = 1;
    m_line = indicatorRect(currentIndex());
    update();
  }
  int m_padding;
  QVariantAnimation m_animation;
  QRectF m_from, m_line;
  qreal m_progress = 1;
};

class WorkbenchTabs : public QTabWidget {
public:
  explicit WorkbenchTabs(QWidget *parent = nullptr, bool compact = true) : QTabWidget(parent) {
    setTabBar(new WorkbenchTabBar(this, compact));
    setDocumentMode(true);
    setStyleSheet("QTabWidget::pane { border:none; border-top:1px solid #e2e8f0;"
                  " background:#ffffff; padding:0; }");
  }
};
