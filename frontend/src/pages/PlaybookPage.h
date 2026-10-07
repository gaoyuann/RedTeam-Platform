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
#include <QTextBrowser>
#include <QTabWidget>
#include <QSplitter>
#include <functional>

class ApiClient;
class KnowledgeGraphPage;
class PayloadPage;

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
  void onStepSelected();

protected:
  bool eventFilter(QObject *watched, QEvent *ev) override;
  void showEvent(QShowEvent *event) override;

private:
  void setupUI();
  void refreshPermissions();
  void loadPlaybookDetail(const QString &id);
  void fitDetailTreeHeight();
  void compressListColumns();
  static QString formatDifficulty(const QString &s);
  static QString formatBaselineGroup(const QString &s);

  ApiClient *m_api;
  QString m_role;
  QString m_username;

  // Sub-tab container (Playbook 库 / 知识图谱 / 载荷样本库)
  QTabWidget *m_tabs;
  QWidget *m_playbookTab;
  KnowledgeGraphPage *m_kgTab;
  PayloadPage *m_payloadTab;

  QComboBox *m_groupFilter;
  QCheckBox *m_showGenerated;
  QSplitter *m_splitter;
  QTableWidget *m_listTable;
  QTreeWidget *m_detailTree;
  QLabel *m_detailLabel;
  QLabel *m_detailMeta;
  QLabel *m_detailDesc;
  QTextBrowser *m_stepDetail;   // 步骤详情卡片（描述/参数模板完整展示）
  QPushButton *m_copyArgsBtn;
  QString m_selectedId;

  // Go to execute button
  QPushButton *m_goExecBtn;
  std::function<void(const QString &)> m_goExecuteCb;  // direct callback for navigation

  // New playbook
  QPushButton *m_newBtn;
  QPushButton *m_deleteBtn;
  QLabel *m_permissionHint;
  bool m_canWrite = false;
  bool m_permissionRequestPending = false;
  bool m_compressPending = false;  // 防抖：一轮布局结束再压缩列宽
};
