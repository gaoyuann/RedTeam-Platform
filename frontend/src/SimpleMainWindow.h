#pragma once

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTableWidget>
#include <QTimer>
#include <QJsonArray>

class QVBoxLayout;
class ApiClient;
class ExecutionPage;
class ScanPage;
class PlaybookPage;
class WsClient;
class LiveActivityPanel;
class ToastOverlay;
class DashboardPage;

class SimpleMainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit SimpleMainWindow(ApiClient *api, const QString &role,
                              const QString &username,
                              QWidget *parent = nullptr);

signals:
    void roleSwitchRequested(const QString &role, const QString &username);

private slots:
    void onModuleChanged(int row);
    void onStartTest();
    void onRetryStage();
    void onViewReport();
    void onViewHistoryReport(int row, int col);
    void onLogout();
    void onViewPlaybook();    void onPollScan();
    void onPollRun();

private:
    void setupUI();
    void setupQuickTestPage(QWidget *page);
    void setupWebSocket();
    void loadHistory();
    void advanceStage();
    void checkBothScansDone();
    void startExecution();

    // Keep toast overlay positioned in top-right on resize
    void resizeEvent(QResizeEvent *event) override;

    // Stage management
    enum Stage {
        Idle = 0,
        PortScan = 1,
        VulnScan = 2,
        GenPlaybook = 3,
        ExecAttack = 4,
        GenReport = 5,
        Done = 6,
        Failed = 7
    };
    void setStage(Stage s);
    void updateStageUI();
    void updateStageRow(int index, const QString &icon, int percent,
                        const QString &status, const QString &color);

    ApiClient *m_api;
    QString m_role;
    QString m_username;

    // Navigation
    QListWidget *m_navList;
    QStackedWidget *m_stackWidget;
    DashboardPage *m_dashboardPage;
    ScanPage *m_scanPage;
    PlaybookPage *m_playbookPage;
    ExecutionPage *m_executionPage;

    // Quick test page — target input area
    QLineEdit *m_targetInput;
    QLineEdit *m_portsInput;
    QPushButton *m_startBtn;
    QPushButton *m_retryBtn;
    QPushButton *m_viewPlaybookBtn;
    QPushButton *m_gotoExecBtn;

    // Progress area — 5 stage rows
    struct StageRow {
        QLabel *iconLabel;
        QLabel *nameLabel;
        QProgressBar *progress;
        QLabel *statusLabel;
        QLabel *thoughtLabel;  // ReAct thought display
    };
    StageRow m_stages[5];

    // Discovery summary area
    QFrame *m_summaryFrame;
    QLabel *m_portsLabel;
    QLabel *m_vulnLabel;
    QLabel *m_playbookLabel;
    QFrame *m_playbookDetailFrame;   // expandable step cards
    QVBoxLayout *m_playbookDetailLayout;

    // Report area
    QFrame *m_reportFrame;
    QLabel *m_reportTitleLabel;
    QPushButton *m_viewReportBtn;
    QString m_latestReportId;

    // History area
    QTableWidget *m_historyTable;

    // Flow state
    Stage m_currentStage = Idle;
    QString m_portScanTaskId;
    QString m_vulnScanTaskId;
    QString m_playbookId;
    QString m_runId;
    QString m_target;
    QTimer *m_pollTimer;
    bool m_portScanDone = false;
    bool m_vulnScanDone = false;

    // Scan result cache for summary
    QJsonArray m_portResults;
    QJsonArray m_vulnResults;

    // ── WebSocket + Real-time ──────────────────────────────────────────
    WsClient *m_ws;
    LiveActivityPanel *m_activityPanel;
    ToastOverlay *m_toastOverlay;
    int m_dashboardPageIndex = -1;  // index in stack widget (-1 if not added)

    // Module names (built dynamically based on role)
    QStringList m_modules;
};
