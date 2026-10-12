#pragma once

#include <QJsonObject>
#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;

class TaskOverviewPage : public QWidget {
  Q_OBJECT
public:
  explicit TaskOverviewPage(QWidget *parent = nullptr);
  void setTaskContext(const QJsonObject &pipeline);
  void clearTaskContext();
  void setLoading();
  void showError(const QString &message);

signals:
  void refreshRequested();
  void stageRequested(int index);

private:
  QLabel *m_state;
  QLabel *m_identity;
  QLabel *m_authorization;
  QLabel *m_policy;
  QLabel *m_sources;
  QLabel *m_scanCount;
  QLabel *m_riskCount;
  QLabel *m_evidenceCount;
  QLabel *m_reportCount;
  QTableWidget *m_steps;
  QList<QPushButton *> m_stageButtons;
};
