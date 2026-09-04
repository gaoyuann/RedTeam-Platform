#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QTextBrowser>
#include <QLineEdit>
#include <QSpinBox>
#include <QTimer>
#include <QSplitter>
#include <QStackedWidget>
#include <QJsonArray>

class ApiClient;

class EvaluatePage : public QWidget {
  Q_OBJECT
public:
  explicit EvaluatePage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

private slots:
  void onLoadRuns();
  void onGradeRun();
  void onGenerateReport();
  void onRefreshReports();
  void onReportClicked(int row, int col);
  void onDeleteReport();
  void onLoadEvidenceRuns();
  void onEvidenceRunSelected(int index);
  void onEvidenceClicked(int row, int col);
  void onExportReport();
  void onOpenInWps();
  void onPreviewReport();

  // Capture + Analysis (merged)
  void onLoadCaptureTasks();
  void onLoadInterfaces();
  void onCreateCapture();
  void onStartCapture();
  void onStopCapture();
  void onCaptureTaskClicked(int row, int col);
  void onDeleteCaptureTask();
  void onCapturePollStatus();
  void onRunAnalysis();
  void onAnalysisResultClicked(int row, int col);
  void onPollAnalysisResults();

private:
  void setupUI();
  void loadAnalysisForCapture(const QString &captureTaskId);
  void populateAnalysisTable(const QJsonArray &arr);
  QString formatAnalysisType(const QString &type) const;
  QString formatSeverity(const QString &sev) const;
  QString findWpsExecutable();
  void openFileInWps(const QString &filePath);

  ApiClient *m_api;
  QTabWidget *m_tabs;

  // Grade tab
  QComboBox *m_runCombo;
  QLabel *m_scoreLabel;
  QLabel *m_mitreLabel;
  QTableWidget *m_stepTable;
  QPushButton *m_gradeBtn;
  QPushButton *m_genReportBtn;
  QString m_selectedRunId;

  // Reports tab
  QTableWidget *m_reportTable;
  QTextEdit *m_reportDetail;
  QTextBrowser *m_reportPreview;
  QPushButton *m_delReportBtn;
  QPushButton *m_exportBtn;
  QPushButton *m_openWpsBtn;
  QPushButton *m_previewBtn;
  QComboBox *m_formatCombo;
  QStackedWidget *m_reportStack;
  QString m_selectedReportId;
  QString m_lastExportPath;
  QString m_lastExportFormat;
  bool m_previewMode;  // true = HTML preview, false = JSON source

  // Evidence tab
  QComboBox *m_evidenceRunCombo;
  QTableWidget *m_evidenceTable;
  QTextEdit *m_evidenceDetail;

  // ── Capture + Analysis (merged single tab) ─────────────────────────────
  // Left panel: task list
  QTableWidget *m_captureTaskTable;
  QPushButton *m_createCaptureBtn;
  QPushButton *m_delCaptureBtn;
  QString m_selectedCaptureTaskId;
  QTimer *m_capturePollTimer;

  // Right panel: config + status + analysis results
  QComboBox *m_interfaceCombo;
  QLineEdit *m_bpfInput;
  QSpinBox *m_durationSpin;
  QComboBox *m_captureTypeCombo;
  QPushButton *m_startCaptureBtn;
  QPushButton *m_stopCaptureBtn;
  QLabel *m_captureStatusLabel;
  QPushButton *m_runAnalysisBtn;
  QTableWidget *m_analysisResultTable;
  QTextEdit *m_analysisDetail;
  QTimer *m_analysisPollTimer;
  QString m_analysisPollCaptureId;
  int m_analysisPollCount = 0;
};
