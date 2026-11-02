#pragma once

#include <QAction>
#include <QEvent>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>
#include "../Theme.h"

namespace PageComponents {

// The original button still owns validation, permissions and request guards.
// Menus only forward explicit clicks and never submit work while opening.
class ButtonAction final : public QObject {
public:
  ButtonAction(QPushButton *source, QMenu *menu) : QObject(menu), m_source(source), m_action(menu->addAction(source->text())) {
    m_action->setObjectName(source->objectName() + "MenuAction");
    if (!source->parentWidget()) source->setParent(menu);
    source->hide();
    source->installEventFilter(this);
    sync();
    connect(menu, &QMenu::aboutToShow, this, [this] { sync(); });
    connect(source, &QPushButton::toggled, this, [this] { sync(); });
    connect(source, &QObject::destroyed, this, [this] { m_action->setEnabled(false); });
    connect(m_action, &QAction::triggered, this, [this] {
      if (m_source && m_source->isEnabled()) m_source->click();
      sync();
    });
  }
protected:
  bool eventFilter(QObject *, QEvent *event) override {
    if (event->type() == QEvent::EnabledChange || event->type() == QEvent::ToolTipChange) sync();
    return false;
  }
private:
  void sync() {
    if (!m_source) return;
    m_action->setText(m_source->text());
    m_action->setToolTip(m_source->toolTip());
    m_action->setEnabled(m_source->isEnabled());
    m_action->setCheckable(m_source->isCheckable());
    m_action->setChecked(m_source->isChecked());
  }
  QPointer<QPushButton> m_source;
  QAction *m_action;
};

inline QPushButton *actionMenu(const QString &text, const QList<QPushButton *> &sources, QWidget *parent) {
  auto *button = new QPushButton(text, parent);
  button->setAutoDefault(false);
  button->setProperty("quiet", true);
  auto *menu = new QMenu(button);
  for (auto *source : sources) {
    if (source) new ButtonAction(source, menu);
    else menu->addSeparator();
  }
  button->setMenu(menu);
  return button;
}

class Disclosure final : public QWidget {
public:
  Disclosure(const QString &title, QWidget *content, QWidget *parent = nullptr) : QWidget(parent), m_content(content) {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    m_toggle = new QToolButton(this);
    m_toggle->setText(title);
    m_toggle->setCheckable(true);
    m_toggle->setArrowType(Qt::RightArrow);
    m_toggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_toggle->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_toggle->setStyleSheet(QStringLiteral("QToolButton { text-align:left; border:0; padding:5px 0; background:transparent; color:%1; }"
      "QToolButton:hover { color:%2; }").arg(Theme::TextSecondary, Theme::Primary));
    layout->addWidget(m_toggle);
    layout->addWidget(content);
    content->hide();
    connect(m_toggle, &QToolButton::toggled, this, [this](bool expanded) {
      m_toggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
      m_content->setVisible(expanded);
      updateGeometry();
    });
  }
  QToolButton *toggle() const { return m_toggle; }
private:
  QWidget *m_content;
  QToolButton *m_toggle;
};

}
