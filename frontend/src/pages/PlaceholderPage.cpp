#include "PlaceholderPage.h"
#include <QVBoxLayout>

PlaceholderPage::PlaceholderPage(const QString &title, QWidget *parent)
    : QWidget(parent) {
  auto *layout = new QVBoxLayout(this);
  auto *label = new QLabel(title + "\n\n模块开发中，敬请期待...");
  label->setAlignment(Qt::AlignCenter);
  label->setStyleSheet("color: #888; font-size: 20px;");
  layout->addWidget(label);
}
