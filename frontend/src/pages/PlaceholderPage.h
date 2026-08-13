#pragma once
#include <QWidget>
#include <QLabel>

class PlaceholderPage : public QWidget {
public:
  explicit PlaceholderPage(const QString &title, QWidget *parent = nullptr);
};
