#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QButtonGroup>
#include <QTimer>
#include <QJsonArray>
#include <QTabWidget>
#include <QSet>

class ApiClient;
class CortexPanel;

class ExecutionPage : public QWidget {
  Q_OBJECT
public:
  explicit ExecutionPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

  /// Select a playbook by ID and pre-fill the target, for cross-page navigation
  void selectPlaybook(const QString &playbookId, const QString &target);

  /// Pre-fill the target input (used when embedded in FlowPage workbench)
  void setTarget(const QString &target);

  /// Load and display a specific run by ID (used by FlowPage workbench
  /// when a pipeline's execute step produces a run).
  void showRun(const QString &runId);
  void clearRunContext();

signals:
  /// Emitted when a run reaches a terminal state (COMPLETED/FAILED/ABORTED).
  /// Carries the run_id so listeners (e.g. EvaluatePage) can focus it.
  void runCompleted(const QString &runId);
  void runSelected(const QString &runId);

public slots:
  void onRefreshRuns();
  void onRunReact(const QJsonObject &data);  // run:react — real-time AI reasoning

private slots:
  void onRunClicked(int row, int col);
  void onExecute();
  void onAttackCategoryChanged(int id);
  void onPollRunning();

private:
  void setupUI();
  void loadPlaybooks();
  void loadPlaybooksByGroup(const QStringList &groups);
  void loadRunDetails(const QString &runId);
  void showCellDetail(const QString &title, const QString &content);

  ApiClient *m_api;
  QTabWidget *m_tabWidget;
  QComboBox *m_playbookCombo;
  QLineEdit *m_targetInput;
  QPushButton *m_execBtn;
  QTableWidget *m_runTable;
  QTableWidget *m_stepTable;
  QLabel *m_statusLabel;
  QPushButton *m_stopBtn;

  // Attack category filter
  QRadioButton *m_catAll;
  QRadioButton *m_catDataTheft;
  QRadioButton *m_catTamper;
  QRadioButton *m_catDeviceCtrl;
  QButtonGroup *m_catGroup;

  // Evidence display
  QLabel *m_evidenceLabel;
  QTableWidget *m_evidenceTable;

  // Cortex decision panel (replaces m_reactPanel + m_payloadPanel)
  CortexPanel *m_cortexPanel;
  QSet<QString> m_injectedPayloadSteps;  // track which steps already injected payload cards
  QSet<QString> m_injectedReactSteps;    // track which steps already injected react thoughts
  QString m_lastReactAction;             // track previous step's react action for dynamic detection

  // Real-time polling for running executions
  QString m_runningRunId;       // currently running run (auto-highlighted)
  QString m_runningPlaybookId;  // playbook of the running run
  QString m_loadedRunId;        // run currently rendered in the detail tab
  QTimer *m_pollTimer;          // polls every 2s while a run is RUNNING
  int m_pollErrorCount = 0;     // consecutive poll failures (stop after threshold)
  int m_contextRevision = 0;

  // Cached playbook data
  QJsonArray m_allPlaybooks;
};
