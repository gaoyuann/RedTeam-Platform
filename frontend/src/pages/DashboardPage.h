#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QWidget>

class ApiClient;
class QLabel;
class QListWidget;
class QTableWidget;
class MetricCard;
class DistributionPanel;
class QTimer;

class DashboardPage : public QWidget {
  Q_OBJECT
public:
  explicit DashboardPage(ApiClient *api, QWidget *parent = nullptr);
  void refresh();
  void scheduleRefresh();

signals:
  void openTasksRequested();

private:
  void showEvent(QShowEvent *event) override;
  void responseFinished();
  void setupUI();
  void loadPipelines();
  void loadReports();
  void loadKnowledge();
  void loadHealth();
  void showPipelineLoading();
  void showPipelineError(const QString &message);
  void renderPipelineData(const QJsonArray &pipelines);
  void setState(QLabel *label, const QString &text, const QString &color);

  quint64 m_revision = 0;
  QTimer *m_refreshTimer = nullptr;
  int m_pendingResponses = 0;
  bool m_refreshPending = false;
  bool m_dirty = false;
  bool m_hasBeenShown = false;
  ApiClient *m_api;
  MetricCard *m_taskCard = nullptr;
  MetricCard *m_assetCard = nullptr;
  MetricCard *m_findingCard = nullptr;
  MetricCard *m_reportCard = nullptr;
  DistributionPanel *m_statusDistribution = nullptr;
  DistributionPanel *m_riskDistribution = nullptr;
  DistributionPanel *m_typeDistribution = nullptr;
  QTableWidget *m_recentTable = nullptr;
  QListWidget *m_todoList = nullptr;
  QLabel *m_apiStatusLabel = nullptr;
  QLabel *m_dataStatusLabel = nullptr;
  QLabel *m_knowledgeStatusLabel = nullptr;
  QLabel *m_knowledgeSummaryLabel = nullptr;
  QLabel *m_healthHintLabel = nullptr;
};
