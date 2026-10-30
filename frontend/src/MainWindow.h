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
class DashboardPage;
class AnalysisHubPage;
class QTimer;
class ModuleRibbon;
class DeployConfigPage;
class EvaluatePage;
class QFrame;
class ScanPage;
class ExecutionPage;

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
    QWidget *createModulePage(int index);
    void ensureModulePage(int index);
    void connectFlowWebSocket();
    void selectRibbonModule(int module);
    void openRibbonFeature(const QString &id);
    void syncRibbonForPage(int page);
    void showTaskCenter();
    void openTaskStage(int stage);
    void updateTaskContext();
    void updateFeaturePresentation();
    void chooseTaskForFeature();
    QString featureDescription(const QString &id) const;
    QWidget *m_featureHeader = nullptr;
    QLabel *m_featureTitle = nullptr;
    QLabel *m_featureDescription = nullptr;
    QLabel *m_featurePath = nullptr;
    QWidget *m_taskGate = nullptr;
    QLabel *m_taskGateMessage = nullptr;
    QPushButton *m_chooseTaskButton = nullptr;
    ScanPage *m_standaloneScan = nullptr;
    ExecutionPage *m_standaloneExecution = nullptr;
    QString m_pendingTaskFeature;
    bool m_selectingFeatureTask = false;
    ModuleRibbon *m_ribbon = nullptr;
    QFrame *m_contextBar = nullptr;
    QLabel *m_contextLabel = nullptr;
    QPushButton *m_overviewButton = nullptr;
    QPushButton *m_resultsButton = nullptr;
    QPushButton *m_navigationToggle = nullptr;
    DeployConfigPage *m_deployPage = nullptr;
    EvaluatePage *m_capturePage = nullptr;
    QString m_activeFeature;
    QString m_featureBeforeDongleLock;
    QString m_lastFeatures[7];
    bool m_routingFeature = false;
    bool m_flowWebSocketConnected = false;

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
    DashboardPage *m_dashboardPage = nullptr;
    FlowPage *m_flowPage = nullptr;
    AnalysisHubPage *m_analysisPage = nullptr;
    WsClient *m_ws = nullptr;
    ToastOverlay *m_toastOverlay = nullptr;

    // Legacy page IDs remain stable for existing task/report callbacks.
    // The visible module names are provided by ModuleRibbon.
    QStringList m_modules;

    // 加密锁运行时锁
    DongleLockPage *m_dongleLockPage = nullptr;
    QTimer *m_dongleTimer = nullptr;
    bool m_dongleLocked = false;
    int m_pageBeforeDongleLock = 0;
};

#endif // MAINWINDOW_H
