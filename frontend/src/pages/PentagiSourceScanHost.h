#pragma once
#include <QWidget>
#include <QString>
#include <QStringList>
#include <QPointer>
class ApiClient;
class QLineEdit;
class QLabel;
class QCheckBox;
class QPushButton;
class QTableWidget;
class SourceScanDetailDialog;

// Platform adapter for PentAGI's target -> Flow -> findings workflow.
class PentagiSourceScanHost : public QWidget {
public:
    explicit PentagiSourceScanHost(ApiClient *api, QWidget *parent = nullptr);
    void showScanDetails(const QStringList &ids, const QString &target, const QString &pipeline);
private:
    void reload();
    void create();
    void openTask(int row);
    ApiClient *m_api;
    QLineEdit *m_target, *m_runtime;
    QCheckBox *m_authorized;
    QPushButton *m_create;
    QLabel *m_notice;
    QTableWidget *m_tasks;
    QPointer<SourceScanDetailDialog> m_detail;
    QString m_requestId, m_requestContent, m_currentScan;
};
