#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QTabWidget>
#include <QPushButton>
#include <QLabel>

class ApiClient;
class LoginDialog;
class FlowPage;
class WsClient;
class ToastOverlay;
class DongleLockPage;
class QTimer;

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
    void setupWebSocket();

    // 加密锁运行时心跳与锁屏
    void verifyDongleHeartbeat();
    void setDongleLocked(bool locked, const QString &errorMessage = QString());

    // Keep toast overlay positioned in top-right on resize
    void resizeEvent(QResizeEvent *event) override;

    QListWidget *m_navList;
    QStackedWidget *m_stackWidget;
    QPushButton *m_checkBackendBtn;
    QPushButton *m_logoutBtn;
    QLabel *m_backendStatusLabel;
    QLabel *m_userInfoLabel;
    ApiClient *m_api;
    QString m_role;
    QString m_username;

    // Dashboard + WebSocket + Toast
    FlowPage *m_flowPage = nullptr;
    WsClient *m_ws = nullptr;
    ToastOverlay *m_toastOverlay = nullptr;

    // Module names (built dynamically, first item is 总览大屏 for admin)
    QStringList m_modules;

    // 加密锁运行时锁
    DongleLockPage *m_dongleLockPage = nullptr;
    QTimer *m_dongleTimer = nullptr;
    bool m_dongleLocked = false;
    int m_pageBeforeDongleLock = 0;
};

#endif // MAINWINDOW_H
