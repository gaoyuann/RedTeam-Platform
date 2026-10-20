#pragma once

#include <QJsonObject>
#include <QWidget>

class ApiClient;
class QLabel;
class QGroupBox;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QTextEdit;
class QTimer;
class MetricCard;

class TaskExecutionPanel : public QWidget {
  Q_OBJECT
public:
  explicit TaskExecutionPanel(ApiClient *api, const QString &role, const QString &username, QWidget *parent = nullptr);
  void setTaskContext(const QString &pipelineId, const QString &runId, const QString &target = {});
  void clearTaskContext();

public slots:
  void refresh();

signals:
  void runSelected(const QString &runId);
  void runCompleted(const QString &runId);
  void findingVerificationChanged(const QString &pipelineId);

protected:
  void showEvent(QShowEvent *event) override;

private:
  void render();
  void renderDetail();
  void openVerificationHistory(int row);
  bool validSnapshot(const QJsonObject &snapshot) const;
  ApiClient *m_api;
  QString m_role;
  QString m_username;
  QString m_pipelineId;
  QString m_expectedRunId;
  QString m_expectedTarget;
  QString m_notifiedRunId;
  QString m_completedRunId;
  QString m_detailKey;
  QJsonObject m_snapshot;
  int m_contextVersion = 0;
  int m_requestVersion = 0;
  bool m_busy = false;
  QLabel *m_title;
  QLabel *m_state;
  QLabel *m_parentState;
  QGroupBox *m_parentDetails;
  QLabel *m_identity;
  QLabel *m_gate;
  QLabel *m_updated;
  QPushButton *m_refresh;
  MetricCard *m_metrics[4];
  QTabWidget *m_tabs;
  QTableWidget *m_steps;
  QTableWidget *m_attempts;
  QTableWidget *m_evidence;
  QTableWidget *m_preflight;
  QTableWidget *m_verifications;
  QTextEdit *m_detail;
  QTimer *m_timer;
};
