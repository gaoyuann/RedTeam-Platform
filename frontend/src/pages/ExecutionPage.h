#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QButtonGroup>
#include <QTextEdit>
#include <QTimer>
#include <QJsonArray>

class ApiClient;

class ExecutionPage : public QWidget {
  Q_OBJECT
public:
  explicit ExecutionPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

  /// Select a playbook by ID and pre-fill the target, for cross-page navigation
  void selectPlaybook(const QString &playbookId, const QString &target);

private slots:
  void onRefreshRuns();
  void onRunClicked(int row, int col);
  void onExecute();
  void onAttackCategoryChanged(int id);
  void onPollRunning();

private:
  void setupUI();
  void loadPlaybooks();
  void loadPlaybooksByGroup(const QStringList &groups);

  ApiClient *m_api;
  QComboBox *m_playbookCombo;
  QLineEdit *m_targetInput;
  QPushButton *m_execBtn;
  QTableWidget *m_runTable;
  QTableWidget *m_stepTable;
  QLabel *m_statusLabel;

  // Attack category filter
  QRadioButton *m_catAll;
  QRadioButton *m_catDataTheft;
  QRadioButton *m_catTamper;
  QRadioButton *m_catDeviceCtrl;
  QButtonGroup *m_catGroup;

  // Evidence display
  QLabel *m_evidenceLabel;
  QTableWidget *m_evidenceTable;
  QTextEdit *m_evidenceDetail;

  // ReAct reasoning panel
  QWidget *m_reactPanel;
  QLabel *m_engineLabel;
  QTextEdit *m_reactThoughtView;

  // Payload info panel
  QWidget *m_payloadPanel;
  QLabel *m_payloadLabel;
  QTextEdit *m_payloadDetailView;

  // Real-time polling for running executions
  QString m_runningRunId;       // currently running run (auto-highlighted)
  QTimer *m_pollTimer;          // polls every 2s while a run is RUNNING

  // Cached playbook data
  QJsonArray m_allPlaybooks;
};
