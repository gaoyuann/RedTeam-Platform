#pragma once
#include <QDialog>
#include <QJsonObject>
#include <QSet>
#include <QStringList>
class ApiClient;
class QLineEdit;
class QListWidget;
class QLabel;
class QPushButton;
class QTimer;

class GlobalSearchDialog : public QDialog {
    Q_OBJECT
public:
    GlobalSearchDialog(ApiClient *api, const QStringList &modules, const QString &role,
                       const QString &username, QWidget *parent = nullptr);
    void search(const QString &text);
signals:
    void resultActivated(int page, const QString &pipelineId, const QString &reportId);
private:
    void restart();
    void fetch();
    void updateState();
    ApiClient *m_api;
    QStringList m_modules;
    QString m_role, m_username, m_query;
    QLineEdit *m_input;
    QListWidget *m_results;
    QLabel *m_state;
    QPushButton *m_more;
    QTimer *m_timer;
    int m_revision = 0, m_pending = 0;
    int m_offsets[2] = {0, 0};
    bool m_hasMore[2] = {true, true};
    QStringList m_errors;
    QSet<QString> m_seen[2];
};
