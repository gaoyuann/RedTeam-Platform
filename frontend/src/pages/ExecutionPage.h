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

class ApiClient;

class ExecutionPage : public QWidget {
  Q_OBJECT
public:
  explicit ExecutionPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

  /// Select a playbook by ID and pre-fill the target, for cross-page navigation
  void selectPlaybook(const QString &playbookId, const QString &target);

  /// 演示动线：从扫描漏洞一键发起攻击 — 目标预填 + 关键词匹配预案
  void attackFromVuln(const QString &target, const QString &vulnText, const QString &resultType);

  /// Pre-fill the target input (used when embedded in FlowPage workbench)
  void setTarget(const QString &target);

  /// Load and display a specific run by ID (used by FlowPage workbench
  /// when a pipeline's execute step produces a run).
  void showRun(const QString &runId);
  void setPipelineContext(const QString &pipelineId, const QString &status, const QString &runId);

  void clearRunContext();

signals:
  /// Emitted when a run reaches a terminal state (COMPLETED/FAILED/ABORTED).
  /// Carries the run_id so listeners (e.g. EvaluatePage) can focus it.
  void runCompleted(const QString &runId);
  void runSelected(const QString &runId);

public slots:
  void onRefreshRuns();

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

  QString m_pipelineId;
  QString m_pipelineStatus;
  QString m_pipelineRunId;
  ApiClient *m_api;
  QTabWidget *m_tabWidget;
  QWidget *m_standaloneControls;
  QLabel *m_pipelineHint;
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
