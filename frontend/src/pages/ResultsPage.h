#pragma once

#include <QWidget>
#include <QJsonObject>

class ApiClient;
class EvaluatePage;
class QLabel;
class QLineEdit;
class QComboBox;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QTimer;

class ResultsPage : public QWidget {
  Q_OBJECT
public:
  explicit ResultsPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent = nullptr);
signals:
  void openTaskReportRequested(const QString &pipelineId, const QString &reportId);
protected:
  void showEvent(QShowEvent *event) override;
private:
  void refresh();
  void resetFilter();
  void updateButtons();
  void openSelected();
  ApiClient *m_api;
  QString m_role;
  QString m_username;
  QTabWidget *m_tabs;
  EvaluatePage *m_legacy;
  QLineEdit *m_search;
  QComboBox *m_kind;
  QLabel *m_state;
  QTableWidget *m_table;
  QPushButton *m_open;
  QPushButton *m_previous;
  QPushButton *m_next;
  QPushButton *m_refresh;
  QTimer *m_timer;
  int m_revision = 0;
  int m_offset = 0;
  int m_total = 0;
  bool m_busy = false;
  bool m_fresh = false;
};
