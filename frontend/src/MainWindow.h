#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QPushButton>
#include <QLabel>

class ApiClient;
class LoginDialog;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(ApiClient *api, const QString &role = "admin",
                        const QString &username = "", QWidget *parent = nullptr);
    void switchToPage(int index);

signals:
    void navigateToExecution(const QString &runId);
    void roleSwitchRequested(const QString &role, const QString &username);

private slots:
    void onModuleChanged(int row);
    void onCheckBackend();
    void onLogout();

private:
    void setupUI();

    QListWidget *m_navList;
    QStackedWidget *m_stackWidget;
    QPushButton *m_checkBackendBtn;
    QPushButton *m_logoutBtn;
    QLabel *m_backendStatusLabel;
    QLabel *m_userInfoLabel;
    ApiClient *m_api;
    QString m_role;
    QString m_username;

    const QStringList m_modules = {
        QStringLiteral("渗透测试资源部署配置"),
        QStringLiteral("漏洞利用想定与预案"),
        QStringLiteral("网络拓扑探测与绘制"),
        QStringLiteral("脆弱性扫描"),
        QStringLiteral("漏洞攻击测试"),
        QStringLiteral("测试评估"),
        QStringLiteral("系统管理")
    };
};

#endif // MAINWINDOW_H
