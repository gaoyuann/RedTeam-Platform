#pragma once
#include "BasePage.h"
#include "StepIndicator.h"
#include "PhasePanel.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QCheckBox>
#include <QJsonObject>
#include <QJsonArray>

class CampaignPage : public BasePage {
  Q_OBJECT
public:
  explicit CampaignPage(ApiClient *api, const QString &role = "",
                        const QString &username = "", QWidget *parent = nullptr);

  void refresh() override;

private slots:
  void onRefreshList();
  void onCampaignClicked(int row, int col);
  void onNewCampaign();
  void onDeleteCampaign();
  void onStartCampaign();
  void onPauseCampaign();
  void onAbortCampaign();
  void onViewReport();
  void onPhaseClicked(int index);
  void onPhaseChanged();

private:
  void setupUI();
  void loadCampaignDetail(const QString &campaignId);
  void updateActionButtons();

  // Left panel
  QTableWidget *m_listTable;   // 名称/目标/状态/创建时间
  QPushButton *m_newBtn;
  QPushButton *m_delBtn;

  // Right panel
  QLabel *m_nameLabel;
  QLabel *m_targetLabel;
  QLabel *m_statusLabel;
  StepIndicator *m_stepIndicator;
  PhasePanel *m_phasePanel;
  QPushButton *m_startBtn;
  QPushButton *m_pauseBtn;
  QPushButton *m_abortBtn;
  QPushButton *m_reportBtn;

  // State
  QString m_selectedId;
  QJsonObject m_currentCampaign;  // full campaign detail
  int m_activePhaseIndex = 0;
};
