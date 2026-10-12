#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QWidget>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;

class AnalysisPage : public QWidget {
  Q_OBJECT
public:
  explicit AnalysisPage(QWidget *parent = nullptr);
  void setTaskContext(const QJsonObject &pipeline);
  void clearTaskContext();
  void setLoading();
  void showError(const QString &message);

signals:
  void refreshRequested();
  void scanRequested();
  void assistantRequested(const QString &question);
  void planCandidateRequested(const QString &category, int index, const QJsonValue &source);

private:
  void rebuildTable();
  void showSelection();

  QJsonObject m_pipeline;
  QJsonObject m_analysis;
  QJsonArray m_items;
  QLabel *m_stateLabel;
  QLabel *m_sourceLabel;
  QComboBox *m_categoryCombo;
  QTableWidget *m_table;
  QPlainTextEdit *m_detail;
  QPushButton *m_askButton;
  QPushButton *m_refreshButton;
  QPushButton *m_planButton;
};
