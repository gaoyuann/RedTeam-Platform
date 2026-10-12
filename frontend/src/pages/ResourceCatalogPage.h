#pragma once

#include <QJsonArray>
#include <QWidget>

class ApiClient;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;

class ResourceCatalogPage : public QWidget {
  Q_OBJECT
public:
  enum class Kind { Tools, Vulnerabilities };
  explicit ResourceCatalogPage(ApiClient *api, Kind kind, QWidget *parent = nullptr);

protected:
  void showEvent(QShowEvent *event) override;

private:
  void refresh();
  void search();
  void render(const QJsonArray &records);
  void showSelection();
  void fail(const QString &message);

  ApiClient *m_api;
  Kind m_kind;
  QLabel *m_state;
  QLineEdit *m_search;
  QPushButton *m_searchButton;
  QTableWidget *m_table;
  QPlainTextEdit *m_detail;
  QJsonArray m_records;
  QJsonArray m_tools;
  int m_requestRevision = 0;
  bool m_supported = false;
};
