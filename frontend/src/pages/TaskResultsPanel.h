#pragma once

#include <QJsonObject>
#include <QWidget>

class ApiClient;
class TaskStatisticsPanel;
class ScanPage;
class QLabel;
class QComboBox;
class QPushButton;
class QPlainTextEdit;
class QTabWidget;
class QTableWidget;
class QTimer;
class MetricCard;

class TaskResultsPanel : public QWidget {
  Q_OBJECT
public:
  explicit TaskResultsPanel(ApiClient *api, const QString &role, const QString &username, QWidget *parent = nullptr);
  void setTaskContext(const QString &pipelineId, const QString &runId, const QString &target = {});
  void clearTaskContext();
  void showReport(const QString &reportId = {});

public slots:
  void refresh();

protected:
  void showEvent(QShowEvent *event) override;

private:
  bool validSnapshot(const QJsonObject &snapshot) const;
  bool validReport(const QJsonObject &document, const QString &reportId, bool linked = false) const;
  void loadLinkedReport();
  void render();
  void showSelection();
  void renderDetail();
  void updateButtons();
  void generateReport();
  void exportReport(const QString &format);
  void openInWps();
  void downloadReport(const QString &format, const QString &path, bool openWps);
  bool canExportReport() const;
  QString apiPath() const;
  ApiClient *m_api;
  QString m_role;
  QString m_username;
  QString m_pipelineId;
  QString m_expectedRunId;
  QString m_target;
  QString m_selectedReportId;
  QString m_pendingReportId;
  QJsonObject m_snapshot;
  QJsonObject m_report;
  QJsonObject m_reportMetadata;
  QJsonObject m_linkedReportMetadata;
  bool m_linkedBusy = false;
  int m_contextVersion = 0;
  int m_requestVersion = 0;
  int m_selectionVersion = 0;
  int m_exportVersion = 0;
  bool m_busy = false;
  bool m_fresh = false;
  bool m_generating = false;
  bool m_exporting = false;
  QLabel *m_state;
  QLabel *m_identity;
  QLabel *m_assessment;
  QLabel *m_updated;
  QLabel *m_exportResult;
  QPushButton *m_refresh;
  QPushButton *m_generate;
  QComboBox *m_formatCombo;
  QPushButton *m_export;
  QPushButton *m_openWps;
  MetricCard *m_metrics[4];
  QTabWidget *m_tabs;
  ScanPage *m_scanRecords;
  TaskStatisticsPanel *m_statistics;
  QTableWidget *m_findings;
  QTableWidget *m_steps;
  QTableWidget *m_evidence;
  QTableWidget *m_reports;
  QPlainTextEdit *m_trace;
  QPlainTextEdit *m_detail;
  QTimer *m_timer;
};
