#ifndef FLOWPAGE_H
#define FLOWPAGE_H

#include <QWidget>
#include <QStackedWidget>
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QJsonObject>

class ApiClient;
class QAction;
class QTabWidget;
class StepIndicator;
class TopologyPage;
class ScanPage;
class ExecutionPage;
class EvaluatePage;
class MetricCard;
class QLineEdit;
class TaskAiPanel;
class AnalysisPage;
class TaskPlanPage;
class TaskOverviewPage;
class TaskLogPanel;
class QTimer;

// ── FlowPage ───────────────────────────────────────────────────────────
// PentAGI-inspired task entry: internal QStackedWidget switches between
// [0] flow list (landing) and [1] flow workbench (detail).
// A "flow" maps 1:1 to a backend pipeline (scan→analyze→generate→execute).

class FlowPage : public QWidget {
  Q_OBJECT
public:
  explicit FlowPage(ApiClient *api, const QString &role = "admin",
                    const QString &username = "", QWidget *parent = nullptr);

  /// Expose embedded stage-tab pages for WebSocket wiring in MainWindow.
  TopologyPage *topoTab() const;
  ScanPage *scanTab() const;
  ExecutionPage *execTab() const;
  EvaluatePage *evalTab() const;  // 评估页（用于 run:complete 时预加载评分）

  /// Switch to a task workbench tab by index.
  void switchToStageTab(int idx);

  /// Open the workbench in "direct execution" mode — no pipeline selected,
  /// jump straight to the attack tab with a playbook pre-selected.
  /// Used when PlaybookPage::executeRequested fires.
  void jumpToExecution(const QString &playbookId, const QString &target);
  void openTaskReport(const QString &pipelineId, const QString &reportId);
  void openTaskAnalysis(const QString &pipelineId);
  void setReturnPage(int page, const QString &title);
  void createTestForTarget(const QString &target);

signals:
  void returnPageRequested(int page);

public slots:
  void refreshFlows();
  void onPipelineCreated(const QJsonObject &data);
  void onPipelineStatus(const QJsonObject &data);
  void onPipelineStep(const QJsonObject &data);
  void onPipelineLog(const QJsonObject &data);
  void onRunCompleted(const QString &runId);

private slots:
  void onCreateFlow();
  void onFlowDoubleClicked(int row);
  void onFlowContextMenu(const QPoint &pos);
  void onOpenFlow();
  void onCancelFlow();
  void onDeleteFlow();
  void onApproveFlow();
  void createFlow(bool quickMode, const QString &initialTarget = {});
  void onStartFlow();
  void onBackToList();
  void onFilterChanged(int index);

private:
  bool eventFilter(QObject *watched, QEvent *event) override;
  void setupUI();
  void setupListView();
  void setupWorkbenchView();
  void loadFlows();
  void resizeFlowColumns();
  void submitTaskCreation(const QJsonObject &body, bool startAfterCreate);
  void loadFlowDetail(const QString &pipelineId);
  void clearRunContext();
  void showTaskDetailError(const QString &message);

  QString statusText(const QString &status) const;
  QString statusIcon(const QString &status) const;
  QColor statusColor(const QString &status) const;
  QString flowIdAtRow(int row) const;

  ApiClient *m_api;
  QString m_role;
  QString m_username;

  // Internal stack: [0]=list, [1]=workbench
  QStackedWidget *m_stack;

  // List view
  QWidget *m_listView;
  QTableWidget *m_flowTable;
  QPushButton *m_newBtn;
  QPushButton *m_refreshBtn;
  QPushButton *m_quickBtn;
  QLineEdit *m_searchInput;
  QComboBox *m_filterCombo;
  QLabel *m_listState;
  QTimer *m_searchTimer = nullptr;
  QTimer *m_flowResizeTimer = nullptr;
  bool m_searchOpenRequested = false;
  QWidget *m_creationNotice = nullptr;
  QLabel *m_creationLabel = nullptr;
  QPushButton *m_creationOpen = nullptr;
  QPushButton *m_creationCopy = nullptr;
  QPushButton *m_retryCreate = nullptr;
  QJsonObject m_pendingCreateBody;
  bool m_pendingCreateStart = false;
  bool m_taskIdentitySupported = false;
  bool m_pendingCreateCanRetry = false;
  int m_flowListRequestRevision = 0;
  bool m_flowListFresh = false;
  MetricCard *m_totalCard;
  MetricCard *m_runningCard;
  MetricCard *m_pendingCard;
  MetricCard *m_completedCard;

  // Workbench view
  QWidget *m_workbenchView;
  QPushButton *m_backBtn;
  QLabel *m_targetLabel;
  QLabel *m_taskIdLabel = nullptr;
  QPushButton *m_copyTaskId = nullptr;
  QLabel *m_statusLabel;
  QPushButton *m_startBtn;
  QPushButton *m_approveBtn;
  QPushButton *m_resultBtn;
  QPushButton *m_moreBtn;       // ⋯ dropdown (cancel / delete / report)
  QPushButton *m_aiToggleBtn;
  QPushButton *m_logToggleBtn;
  QAction *m_cancelAction;
  QAction *m_deleteAction;
  QAction *m_reportAction;
  StepIndicator *m_stepIndicator;   // 六阶段任务进度（后端四步骤映射到用户流程）

  // Stage tabs (拓扑/扫描/攻击/评估) embedded in the workbench
  QTabWidget *m_stageTabs;
  TopologyPage *m_topoTab;
  ScanPage *m_scanTab;
  ExecutionPage *m_execTab;
  EvaluatePage *m_evalTab;
  AnalysisPage *m_analysisTab;
  TaskPlanPage *m_planTab;
  TaskOverviewPage *m_overviewTab;
  TaskLogPanel *m_logPanel;
  TaskAiPanel *m_aiPanel;

  QString m_selectedPipelineId;
  int m_returnPage = -1;
  QString m_pendingTaskReportId;
  QString m_lastDetailPipelineId;
  int m_taskContextRevision = 0;
  int m_taskDetailRequestRevision = 0;
  QJsonObject m_lastDisplayedDetail;
  QString m_workbenchRunId;
  // Dedup guards: track the last run/playbook loaded into the attack tab,
  // so repeated pipeline events don't re-call selectPlaybook/showRun (which
  // would reset the user's manual combo selection and yank the sub-tab).
  QString m_lastLoadedRunId;
  QString m_lastLoadedPlaybookId;
  QString m_lastLoadedEvalRunId;
  QString m_generatedPlaybookId;  // cached from loadFlowDetail for the approve dialog
};

#endif // FLOWPAGE_H
