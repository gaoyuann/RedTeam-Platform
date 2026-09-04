#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QJsonObject>
#include <QJsonArray>

class ApiClient;

class PhasePanel : public QWidget {
  Q_OBJECT
public:
  explicit PhasePanel(ApiClient *api, QWidget *parent = nullptr);

  void setPhase(const QJsonObject &phase, const QString &campaignId);
  void clear();
  QJsonObject currentPhase() const;

signals:
  void phaseChanged();

private slots:
  void onAddPlaybook();
  void onRemovePlaybook();
  void onSkipPhase();

private:
  void setupUI();
  void loadPlaybooksForPhase();
  void loadArtifactsForPhase();

  ApiClient *m_api;
  QString m_campaignId;
  QJsonObject m_phase;

  QLabel *m_phaseTitle;
  QTableWidget *m_playbookTable;  // 顺序/名称/模式/状态
  QTableWidget *m_artifactTable;  // 类型/键/值摘要
  QPushButton *m_addPbBtn;
  QPushButton *m_removePbBtn;
  QPushButton *m_skipBtn;
};
