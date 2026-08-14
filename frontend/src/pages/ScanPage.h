#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QJsonArray>

class ApiClient;

class ScanPage : public QWidget {
  Q_OBJECT
public:
  explicit ScanPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

signals:
  void playbookNavigateRequested(const QString &playbookId);

public slots:
  void onRefreshTasks();

private slots:
  void onCreateScan();
  void onTaskClicked(int row, int col);
  void onGeneratePlaybook();
  void onPollStatus();
  void onDeleteTask();
  void onReexecScan();
  void onRecommendationClicked(int row, int col);
  void onViewGeneratedPlaybook();

private:
  void setupUI();
  void loadResults(const QString &taskId);
  void loadRecommendations(const QString &taskId);
  void clearDetailPanel();
  void updateStatusLabel(const QJsonObject &d);

  // Formatting helpers
  static QString formatScanType(const QString &type);
  static QString formatStatus(const QString &s, bool hasStructured = true);
  static QString formatSeverity(const QString &s);
  static QString formatDifficulty(const QString &s);
  static QString formatBaselineGroup(const QString &s);
  static QString formatTime(const QString &iso);
  static QString formatResultData(const QString &json, const QString &resultType = "");
  static QColor severityColor(const QString &sev);
  static QString formatDuration(const QString &started, const QString &completed);
  static QString buildResultSummary(const QJsonArray &results, const QString &scanType);
  static bool hasStructuredResults(const QJsonArray &results);

  ApiClient *m_api;
  QLineEdit *m_targetInput;
  QLineEdit *m_portsInput;
  QLineEdit *m_cookieInput;
  QComboBox *m_scanTypeCombo;
  QComboBox *m_serviceCombo;   // brute_force service selector (ssh, http-post-form, etc.)
  QLineEdit *m_formDefInput;   // http-post-form definition
  QTableWidget *m_taskTable;
  QTableWidget *m_resultTable;
  QLabel *m_statusLabel;
  QLabel *m_taskCountLabel;

  // Recommendations
  QTableWidget *m_recTable;
  QPushButton *m_genBtn;
  QPushButton *m_viewGenBtn;      // "查看生成的 Playbook" button
  QString m_selectedTaskId;
  QString m_lastGeneratedId;      // playbook_id of last AI-generated playbook

  // Left-panel buttons
  QPushButton *m_delBtn;

  // Right-panel: re-execute for FAILED/CANCELLED
  QPushButton *m_reexecBtn;

  // Polling
  QTimer *m_pollTimer;
  QStringList m_runningTaskIds;   // track all RUNNING task IDs for polling
  void startPollingIfNeeded();
};
