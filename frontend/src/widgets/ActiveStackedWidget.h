#pragma once
#include <QStackedWidget>

// Hidden workspaces must not impose their minimum size on the current page.
class ActiveStackedWidget : public QStackedWidget {
public:
    explicit ActiveStackedWidget(QWidget *parent = nullptr) : QStackedWidget(parent) {
        connect(this, &QStackedWidget::currentChanged, this, [this]() { updateGeometry(); });
    }
    QSize minimumSizeHint() const override {
        return currentWidget() ? currentWidget()->minimumSizeHint().expandedTo(currentWidget()->minimumSize()) : QSize(0, 0);
    }
    QSize sizeHint() const override {
        return currentWidget() ? currentWidget()->sizeHint().expandedTo(minimumSizeHint()) : QSize(0, 0);
    }
};
