#pragma once
#include <QFrame>
#include <QLabel>
#include <QVBoxLayout>

// Presentation only; the caller owns the meaning and source of the value.
class MetricCard : public QFrame {
public:
  MetricCard(const QString &title, const QString &accent, QWidget *parent = nullptr)
      : QFrame(parent) {
    setProperty("metricCard", true);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    setStyleSheet(QStringLiteral(
        "QFrame[metricCard=\"true\"] { background:#f8fbff; border:1px solid #dbe5f0; border-radius:10px; }"
        "QLabel { background:transparent; border:none; }"
        "QLabel#metricTitle { color:#64748b; font-size:12px; }"
        "QLabel#metricValue { color:%1; font-size:26px; font-weight:700; }").arg(accent));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(14, 10, 14, 10);
    layout->setSpacing(2);
    auto *label = new QLabel(title, this);
    label->setObjectName("metricTitle");
    m_value = new QLabel(QStringLiteral("—"), this);
    m_value->setObjectName("metricValue");
    m_value->setTextFormat(Qt::PlainText);
    layout->addWidget(label);
    layout->addWidget(m_value);
  }
  void setValue(const QString &value) { m_value->setText(value); }
private:
  QLabel *m_value;
};