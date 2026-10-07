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
class EvaluatePage;
class ScanPage;
class PlaybookPage;
class DongleLockPage;

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
    void onViewPlaybook();
    void onReviewPlan();
    void onGenerateCurrentReport();
    void onPollScan();
    void onPollRun();

private:
    void setupUI();
    void setupQuickTestPage(QWidget *page);
    void loadHistory();
    void advanceStage();
    void checkBothScansDone();
    void startExecution();
    void finishReport(const QString &reportId, const QString &title);

    // 加密锁运行时心跳与锁屏
    void verifyDongleHeartbeat();
    void setDongleLocked(bool locked, const QString &errorMessage = QString());

    // Stage management
    enum Stage {
        Idle = 0,
        PortScan = 1,
        VulnScan = 2,
        GenPlaybook = 3,
        ExecAttack = 4,
        GenReport = 5,
        Done = 6,
        Failed = 7,
        PlanReady = 8
    };
    void setStage(Stage s);
    void updateStageUI();
    void resetStageRows();
    void showStageError(int index, const QString &message);
    void updateStageRow(int index, const QString &icon, int percent,
                        const QString &status, const QString &color);

    ApiClient *m_api;
    QString m_role;
    QString m_username;

    // Navigation
    QListWidget *m_navList;
    QStackedWidget *m_stackWidget;
    ScanPage *m_scanPage;
    PlaybookPage *m_playbookPage;
    ExecutionPage *m_executionPage;
    EvaluatePage *m_evaluatePage;
    QPushButton *m_currentTaskBtn;
    QPushButton *m_currentReportBtn;

    // Quick test page — target input area
    QLineEdit *m_targetInput;
    QLineEdit *m_portsInput;
    QPushButton *m_startBtn;
    QPushButton *m_retryBtn;
    QPushButton *m_viewPlaybookBtn;
    QPushButton *m_gotoExecBtn;
    QLabel *m_workflowHint;

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
    QPushButton *m_generateReportBtn;
    QString m_latestReportId;

    // History area
    QTableWidget *m_historyTable;

    // Flow state
    Stage m_currentStage = Idle;
    Stage m_failedStage = Idle;
    QString m_portScanTaskId;
    QString m_vulnScanTaskId;
    QString m_playbookId;
    QString m_runId;
    QString m_target;
    QTimer *m_pollTimer;
    bool m_portScanDone = false;
    bool m_vulnScanDone = false;
    bool m_portScanSucceeded = false;
    bool m_vulnScanSucceeded = false;
    bool m_portPollInFlight = false;
    bool m_vulnPollInFlight = false;
    bool m_runPollInFlight = false;
    bool m_reviewPending = false;
    int m_workflowRevision = 0;
    QString m_runTerminalStatus;

    // Scan result cache for summary
    QJsonArray m_portResults;
    QJsonArray m_vulnResults;

    // Module names
    const QStringList m_modules = {
        QStringLiteral("测试工作台"),
        QStringLiteral("扫描任务"),
        QStringLiteral("载荷库"),
        QStringLiteral("想定预案"),
        QStringLiteral("攻击执行"),
        QStringLiteral("测试评估")
    };

    // 加密锁运行时锁
    DongleLockPage *m_dongleLockPage = nullptr;
    QTimer *m_dongleTimer = nullptr;
    bool m_dongleLocked = false;
    int m_pageBeforeDongleLock = 0;
};
