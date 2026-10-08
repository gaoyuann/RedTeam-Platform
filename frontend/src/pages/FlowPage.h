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

  /// Switch to a stage tab by index (0=拓扑, 1=扫描, 2=攻击, 3=评估)
  void switchToStageTab(int idx);

  /// Open the workbench in "direct execution" mode — no pipeline selected,
  /// jump straight to the attack tab with a playbook pre-selected.
  /// Used when PlaybookPage::executeRequested fires.
  void jumpToExecution(const QString &playbookId, const QString &target);

public slots:
  void refreshFlows();
  void onPipelineCreated(const QJsonObject &data);
  void onPipelineStatus(const QJsonObject &data);
  void onPipelineStep(const QJsonObject &data);
  void onRunCompleted(const QString &runId);

private slots:
  void onCreateFlow();
  void onFlowDoubleClicked(int row);
  void onFlowContextMenu(const QPoint &pos);
  void onOpenFlow();
  void onCancelFlow();
  void onDeleteFlow();
  void onApproveFlow();
  void onBackToList();
  void onFilterChanged(int index);

private:
  void setupUI();
  void setupListView();
  void setupWorkbenchView();
  void loadFlows();
  void loadFlowDetail(const QString &pipelineId);
  void approveFlow(const QString &preferredPlaybookId);
  bool m_approvalInFlight = false;
  void clearRunContext();

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
  QComboBox *m_filterCombo;

  // Workbench view
  QWidget *m_workbenchView;
  QPushButton *m_backBtn;
  QLabel *m_targetLabel;
  QLabel *m_statusLabel;
  QPushButton *m_approveBtn;
  QPushButton *m_resultBtn;
  QPushButton *m_moreBtn;       // ⋯ dropdown (cancel / delete / report)
  QAction *m_cancelAction;
  QAction *m_deleteAction;
  QAction *m_reportAction;
  StepIndicator *m_stepIndicator;   // pipeline 四阶段进度（自绘节点+连线+摘要）

  // Stage tabs (拓扑/扫描/攻击/评估) embedded in the workbench
  QTabWidget *m_stageTabs;
  TopologyPage *m_topoTab;
  ScanPage *m_scanTab;
  ExecutionPage *m_execTab;
  EvaluatePage *m_evalTab;

  QString m_selectedPipelineId;
  QString m_lastDetailPipelineId;
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
