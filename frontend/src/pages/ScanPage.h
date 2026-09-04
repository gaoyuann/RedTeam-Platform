#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QJsonArray>
#include <QTabWidget>

class ApiClient;

class ScanPage : public QWidget {
  Q_OBJECT
public:
  explicit ScanPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

signals:
  void playbookNavigateRequested(const QString &playbookId, const QString &target = "");

public slots:
  void onRefreshTasks();

private slots:
  void onCreateScan();
  void onTaskClicked(int row, int col);
  void onGeneratePlaybook();
  void onDeleteTask();
  void onReexecScan();
  void onRecommendationClicked(int row, int col);
  void onRecExecClicked();
  void onGenExecClicked();
  void onPollStatus();

private:
  void setupUI();
  void loadResults(const QString &taskId);
  void loadRecommendations(const QString &taskId);
  void clearDetailPanel();
  void updateStatusLabel(const QJsonObject &d);
  void startPollingIfNeeded();
  void renderGroupedResults(const QJsonArray &results);
  void enableCurrentTabDelBtn(bool enabled);

  // Formatting helpers
  static QString formatScanType(const QString &type);
  static QString formatStatus(const QString &s, bool hasStructured = true);
  static QString formatSeverity(const QString &s);
  static QString formatDifficulty(const QString &s);
  static QString formatBaselineGroup(const QString &s);
  static QString formatTime(const QString &iso);
  static QString formatResultData(const QString &json, const QString &resultType = "");
  static QColor severityColor(const QString &sev);
  static QString formatDuration(const QString &started, const QString &completed);
  static QString buildResultSummary(const QJsonArray &results, const QString &scanType);
  static bool hasStructuredResults(const QJsonArray &results);

  ApiClient *m_api;

  // ── Left panel: 4-Tab scan type layout ──
  QTabWidget *m_scanTypeTabs;
  QTableWidget *m_portScanTable;
  QTableWidget *m_vulnScanTable;
  QTableWidget *m_webScanTable;
  QTableWidget *m_bruteForceTable;
  QLineEdit *m_portTargetInput;
  QLineEdit *m_vulnTargetInput;
  QLineEdit *m_webTargetInput;
  QLineEdit *m_bruteTargetInput;
  QLineEdit *m_portsInput;         // port_scan specific
  QLineEdit *m_cookieInput;        // web_scan specific
  QComboBox *m_serviceCombo;       // brute_force service selector
  QLineEdit *m_formDefInput;       // http-post-form definition
  QLabel *m_portScanCount;
  QLabel *m_vulnScanCount;
  QLabel *m_webScanCount;
  QLabel *m_bruteForceCount;

  // ── Right panel ──
  QTreeWidget *m_resultTree;       // grouped results by result_type
  QLabel *m_statusLabel;

  // ── Per-tab delete buttons (need to enable/disable the one in the active tab) ──
  QPushButton *m_portDelBtn;
  QPushButton *m_vulnDelBtn;
  QPushButton *m_webDelBtn;
  QPushButton *m_bruteDelBtn;

  // Recommendations
  QTableWidget *m_recTable;
  QPushButton *m_genBtn;
  QString m_selectedRecPlaybookId;   // 当前选中的推荐预案ID
  QString m_selectedRecPlaybookName; // 当前选中的推荐预案名称
  QPushButton *m_recExecBtn;         // 推荐预案的"前往执行→"按钮

  // AI 生成预案预览区
  QWidget *m_genPreviewWidget;      // 预览区容器（可整体显示/隐藏）
  QLabel *m_genPreviewTitle;        // "AI 生成预案: xxx (N步)"
  QTableWidget *m_genStepTable;     // 步骤预览表格
  QPushButton *m_genExecBtn;        // "前往执行→"按钮

  QString m_selectedTaskId;
  QString m_lastGeneratedId;       // playbook_id of last AI-generated playbook
  QString m_currentTarget;         // current selected task's target, for cross-page navigation

  // Right-panel: re-execute for FAILED/CANCELLED
  QPushButton *m_reexecBtn;

  // Polling
  QTimer *m_pollTimer;
  QStringList m_runningTaskIds;   // track all RUNNING task IDs for polling
};
