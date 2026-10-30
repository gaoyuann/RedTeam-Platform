#pragma once

#include <QWidget>
#include <QVector>
#include <QStringList>

class QStackedWidget;
class QToolButton;

// Stable feature IDs route to existing Qt pages; unavailable features have no action.
struct RibbonFeature {
    QString id;
    QString title;
    QString group;
    QString icon;
    int module;
    bool implemented = true;
    bool adminOnly = false;
};

class ModuleRibbon : public QWidget {
    Q_OBJECT
public:
    explicit ModuleRibbon(bool administrator, QWidget *parent = nullptr);
    static QStringList moduleNames();
    static const QVector<RibbonFeature> &features();
    static const RibbonFeature *feature(const QString &id);
    bool canOpen(const QString &id) const;
    void setModule(int module);
    void setActiveFeature(const QString &id);

signals:
    void featureRequested(const QString &id);

private:
    bool m_administrator;
    QStackedWidget *m_pages;
    QVector<QToolButton *> m_buttons;
};
