#pragma once
#include <QVariant>
#include <QFrame>
#include "../Theme.h"
#include <QLabel>
#include <QIcon>
#include <QHBoxLayout>
#include <QVBoxLayout>

// Presentation only; the caller owns the meaning and source of the value.
class MetricCard : public QFrame {
public:
  MetricCard(const QString &title, const QString &accent, QWidget *parent = nullptr)
      : QFrame(parent) {
    setProperty("metricCard", true);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    setStyleSheet(QStringLiteral(
        "QFrame[metricCard=\"true\"] { background:%2; border:1px solid %3; border-radius:%4px; }"
        "QLabel { background:transparent; border:none; }"
        "QLabel#metricTitle { color:#64748b; font-size:12px; }"
        "QLabel#metricValue { color:%1; font-size:26px; font-weight:700; }"
        "QLabel#metricCaption { color:#94a3b8; font-size:11px; }").arg(accent, Theme::Card, Theme::Border).arg(Theme::CardRadius));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(14, 10, 14, 10);
    layout->setSpacing(2);
    auto *header = new QHBoxLayout;
    header->setSpacing(7);
    auto *label = new QLabel(title, this);
    label->setObjectName("metricTitle");
    header->addWidget(label);
    header->addStretch();
    m_header = header;
    m_value = new QLabel(QStringLiteral("—"), this);
    m_value->setObjectName("metricValue");
    m_value->setTextFormat(Qt::PlainText);
    m_caption = new QLabel(QStringLiteral("数据加载中"), this);
    m_caption->setObjectName("metricCaption");
    m_caption->setTextFormat(Qt::PlainText);
    m_caption->hide();
    layout->addLayout(header);
    layout->addWidget(m_value);
    layout->addWidget(m_caption);
  }
  void setIcon(const QString &path) {
    auto *icon = new QLabel(this);
    icon->setPixmap(QIcon(path).pixmap(24,24));
    icon->setObjectName(QStringLiteral("metricIcon"));
    icon->setFixedSize(24, 24);
    icon->setAlignment(Qt::AlignCenter);
    if (m_header) m_header->insertWidget(0, icon);
  }
  void setValue(const QString &value) { m_value->setText(value); }
  void setCaption(const QString &caption) { m_caption->setText(caption); m_caption->setVisible(!caption.isEmpty()); }
private:
  QHBoxLayout *m_header = nullptr;
  QLabel *m_value;
  QLabel *m_caption;
};
