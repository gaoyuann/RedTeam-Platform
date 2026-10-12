#pragma once

#include <QJsonArray>
#include <QWidget>

class ApiClient;
class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;

class TaskLogPanel : public QWidget {
  Q_OBJECT
public:
  explicit TaskLogPanel(ApiClient *api, QWidget *parent = nullptr);
  void setTaskContext(const QString &pipelineId);
  void clearTaskContext();

public slots:
  void refresh();

protected:
  void showEvent(QShowEvent *event) override;

private:
  void render();
  ApiClient *m_api;
  QString m_pipelineId;
  QJsonArray m_rows;
  qint64 m_cursor = 0;
  int m_contextVersion = 0;
  int m_requestVersion = 0;
  bool m_loaded = false;
  bool m_busy = false;
  QLabel *m_state;
  QLabel *m_detail;
  QPushButton *m_refresh;
  QComboBox *m_level;
  QCheckBox *m_follow;
  QTableWidget *m_table;
};
