#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>

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

private:
  void setupUI();

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
  QPushButton *m_delReportBtn;
  QString m_selectedReportId;

  // Evidence tab
  QComboBox *m_evidenceRunCombo;
  QTableWidget *m_evidenceTable;
  QTextEdit *m_evidenceDetail;
};
