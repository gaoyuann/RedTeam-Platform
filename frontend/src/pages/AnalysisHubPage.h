#pragma once

#include <QJsonArray>
#include <QWidget>

class ApiClient;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;

class AnalysisHubPage : public QWidget {
  Q_OBJECT
public:
  explicit AnalysisHubPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent = nullptr);

signals:
  void openTaskAnalysisRequested(const QString &pipelineId);

protected:
  void showEvent(QShowEvent *event) override;

private:
  void refresh();
  void showSelection();
  void openSelected();
  void fail(const QString &message);
  bool validIndex(const QJsonObject &data, const QString &search, const QString &state, int offset) const;

  ApiClient *m_api;
  QString m_role;
  QString m_username;
  QLineEdit *m_search;
  QComboBox *m_filter;
  QLabel *m_state;
  QTableWidget *m_table;
  QPlainTextEdit *m_detail;
  QPushButton *m_open;
  QPushButton *m_previous;
  QPushButton *m_next;
  QLabel *m_pagination;
  QJsonArray m_records;
  int m_offset = 0;
  int m_requestRevision = 0;
  bool m_fresh = false;
};
