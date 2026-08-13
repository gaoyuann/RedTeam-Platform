#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QDialog>
#include <QTextEdit>
#include <functional>

class ApiClient;

class PlaybookPage : public QWidget {
  Q_OBJECT
public:
  explicit PlaybookPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);
  void selectPlaybook(const QString &playbookId);

  /// Set a callback for "go execute" navigation. Called instead of (or in addition to) the signal.
  void setGoExecuteCallback(std::function<void(const QString &)> cb) { m_goExecuteCb = std::move(cb); }

signals:
  void executeRequested(const QString &playbookId);

private slots:
  void onLoadList();
  void onPlaybookClicked(int row, int col);
  void onDeletePlaybook();
  void onNewPlaybook();
  void onGoExecute();

private:
  void setupUI();
  void loadPlaybookDetail(const QString &id);
  static QString formatDifficulty(const QString &s);
  static QString formatBaselineGroup(const QString &s);

  ApiClient *m_api;
  QComboBox *m_groupFilter;
  QCheckBox *m_showGenerated;
  QTableWidget *m_listTable;
  QTreeWidget *m_detailTree;
  QLabel *m_detailLabel;
  QString m_selectedId;

  // Go to execute button
  QPushButton *m_goExecBtn;
  std::function<void(const QString &)> m_goExecuteCb;  // direct callback for navigation

  // New playbook
  QPushButton *m_newBtn;
};
