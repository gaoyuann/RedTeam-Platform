#pragma once
#include <QWidget>
#include <QSet>
#include <QSpinBox>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QTabWidget>
#include <QPointer>

class QCheckBox;
class QPlainTextEdit;
class ApiClient;
class RemoteSourcePicker;
class ScanResultOverview;
class SourceScanDetailDialog;

class ScanPage : public QWidget {
  Q_OBJECT
public:
  explicit ScanPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

  /// Pre-fill all 4 target inputs (used when embedded in FlowPage workbench)
  void setTarget(const QString &target);
  void setPipelineScope(const QString &pipelineId, const QStringList &taskIds, const QString &state = {});
  void setTaskScope(const QStringList &taskIds);
  void clearTaskScope();
  void showTaskContextError(const QString &message);

signals:
  void sourceGenerationStatus(const QString &message, bool error);
  void sourcePlaybookGenerated(const QString &playbookId);
  void playbookNavigateRequested(const QString &playbookId, const QString &target = "");
  /// 从扫描结果漏洞一键发起攻击（演示动线：扫描 → 漏洞列表 → 攻击）
  void attackRequested(const QString &target, const QString &vulnText, const QString &resultType);
  void findingVerificationChanged(const QString &pipelineId);

public slots:
  void onRefreshTasks();
  void beginSourceVerification();

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
  void showEvent(QShowEvent *event) override;
  void setupUI();
  void setStatusText(const QString &text);
  void openRecordDetails(QTreeWidgetItem *item);
  void openSourceScanDetails();
  QPointer<SourceScanDetailDialog> m_sourceDetail;
  QPushButton *m_sourceDetailButton = nullptr;
  QStringList m_sourceTaskIds;
  QString m_sourceViewTarget;
  bool m_openSourceDetailsRequested = false;
  void resizeResultColumns();
  bool eventFilter(QObject *object, QEvent *event) override;
  QPlainTextEdit *m_webScanProcess = nullptr;
  QLabel *m_compactStatus = nullptr;
  QLabel *m_listTitle = nullptr;
  QPushButton *m_showAllRecords = nullptr;
  void openFindingVerification(const QList<qint64> &ids);
  QSet<qint64> m_checkedFindings;
  QList<QTreeWidgetItem*> selectableFindingItems() const;
  void updateFindingSelection();
  void setCurrentFindingsChecked(bool checked);
  QCheckBox *m_selectAllFindings = nullptr;
  QLabel *m_findingSelectionCount = nullptr;
  QPushButton *m_openCheckedFindings = nullptr;
  void loadPipelineResults(bool append = false);
  void renderCoverage(const QJsonObject &coverage);
  QString m_pipelineId;
  QString m_pipelineScanState;
  QString m_retryRequestId;
  QString m_retryRequestSource;
  bool m_allScanResults = false;
  bool m_scanPageBusy = false;
  int m_scanPageRequest = 0;
  qint64 m_scanCursor = 0;
  qint64 m_scanThrough = 0;
  QJsonArray m_aggregateRecords;
  bool m_sourceResultsView = false;
  bool m_sourceResultsPending = false;
  bool m_sourceRecordsMode = false;
  QJsonArray m_sourceRecords;
  QString m_sourceProgressText;
  QWidget *m_aggregateControls;
  QPushButton *m_allResultsButton;
  QPushButton *m_moreResultsButton;
  QComboBox *m_resultCategory;
  QComboBox *m_resultSource;

  void loadResults(const QString &taskId);
  void loadRecommendations(const QString &taskId);
  void clearDetailPanel();
  void updateStatusLabel(const QJsonObject &d);
  void startPollingIfNeeded();
  void renderGroupedResults(const QJsonArray &results);
  void showPayloadMatches(QTreeWidgetItem *item);
  void decorateResultRow(QTreeWidgetItem *item, const QJsonObject &record);
  void enableCurrentTabDelBtn(bool enabled);
  void showSourceEvidence(QTreeWidgetItem *item);
  void showPayloadForFinding(int findingId);
  void reviewSourceFinding(int findingId);
  void selectSourceDemonstration();
  void generatePlaybook(const QJsonArray &findingIds = QJsonArray());

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

  QJsonArray m_lastSourceSelection;
  QString m_lastSourceSelectionTask;
  ApiClient *m_api;

  // ── Left panel: 5-Tab scan type layout ──
  QTabWidget *m_scanTypeTabs;
  QTableWidget *m_portScanTable;
  QTableWidget *m_vulnScanTable;
  QTableWidget *m_webScanTable;
  QTableWidget *m_bruteForceTable;
  QTableWidget *m_sourceScanTable;
  QLineEdit *m_portTargetInput;
  QLineEdit *m_vulnTargetInput;
  QLineEdit *m_webTargetInput;
  QLineEdit *m_bruteTargetInput;
  QLineEdit *m_sourceTargetInput;
  QLineEdit *m_sourceNotesInput;
  QComboBox *m_programInputKind;
  RemoteSourcePicker *m_remoteSourcePicker;
  QLineEdit *m_programRuntimeInput;
  QCheckBox *m_sourceAdaptiveCheck;
  QLineEdit *m_portsInput;         // port_scan specific
  QLineEdit *m_cookieInput;        // web_scan specific
  QComboBox *m_serviceCombo;       // brute_force service selector
  QLineEdit *m_formDefInput;       // http-post-form definition
  QLabel *m_portScanCount;
  QLabel *m_vulnScanCount;
  QLabel *m_webScanCount;
  QLabel *m_bruteForceCount;
  QLabel *m_sourceScanCount;

  // ── Right panel ──
  ScanResultOverview *m_resultOverview;
  QTreeWidget *m_resultTree;       // grouped results by result_type
  QTreeWidget *m_coverageTree;     // task assets, services, entries and check states
  QTabWidget *m_detailTabs;
  QLabel *m_statusLabel;
  QLabel *m_resultHint;
  QPushButton *m_sourceDemoBtn;
  QString m_currentTaskTarget;     // 当前选中任务的目标（供"发起攻击"使用）
  QString m_currentScanType;

  // ── Per-tab delete buttons (need to enable/disable the one in the active tab) ──
  QPushButton *m_portDelBtn;
  QPushButton *m_vulnDelBtn;
  QPushButton *m_webDelBtn;
  QPushButton *m_bruteDelBtn;
  QPushButton *m_sourceDelBtn;

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

  bool m_scopedTasks = false;
  bool m_selectInitialScopeTask = false;
  QStringList m_scopeTaskIds;
  int m_scopeRevision = 0;
  QString m_selectedTaskId;
  QString m_lastGeneratedId;       // playbook_id of last AI-generated playbook
  bool m_generationInProgress = false;
  bool m_pendingSourceVerification = false;
  int m_generationRevision = 0;
  QString m_currentTarget;         // current selected task's target, for cross-page navigation

  // Right-panel: re-execute for FAILED/CANCELLED
  QPushButton *m_reexecBtn;
  bool m_canReparseReport = false;

  // Polling
  QTimer *m_pollTimer;
  QStringList m_runningTaskIds;   // track all RUNNING task IDs for polling
  int m_pollErrorCount = 0;       // consecutive poll failures (stop after threshold)
};
