#include "FlowPage.h"
#include "LiveActivityPanel.h"
#include "StepIndicator.h"
#include "TopologyPage.h"
#include "ScanPage.h"
#include "ExecutionPage.h"
#include "EvaluatePage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QSplitter>
#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QComboBox>
#include <QTabWidget>
#include <QTextBrowser>
#include <QMenu>
#include <QAction>
#include <QDialog>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonDocument>
#include <QDateTime>
#include <QTimer>

// ── Step metadata ──────────────────────────────────────────────────────
static const QStringList STEP_NAMES = {
  QStringLiteral("扫描"), QStringLiteral("分析"),
  QStringLiteral("生成"), QStringLiteral("执行"),
};

// ── FlowPage ───────────────────────────────────────────────────────────

FlowPage::FlowPage(ApiClient *api, const QString &role,
                   const QString &username, QWidget *parent)
    : QWidget(parent)
    , m_api(api)
    , m_role(role)
    , m_username(username)
    , m_stack(nullptr)
    , m_listView(nullptr)
    , m_flowTable(nullptr)
    , m_newBtn(nullptr)
    , m_refreshBtn(nullptr)
    , m_filterCombo(nullptr)
    , m_workbenchView(nullptr)
    , m_backBtn(nullptr)
    , m_targetLabel(nullptr)
    , m_statusLabel(nullptr)
    , m_approveBtn(nullptr)
    , m_moreBtn(nullptr)
    , m_cancelAction(nullptr)
    , m_deleteAction(nullptr)
    , m_reportAction(nullptr)
    , m_stepIndicator(nullptr)
    , m_activityPanel(nullptr)
    , m_stageTabs(nullptr)
    , m_contentSplitter(nullptr)
    , m_reasoningPanel(nullptr)
    , m_topoTab(nullptr)
    , m_scanTab(nullptr)
    , m_execTab(nullptr)
    , m_evalTab(nullptr)
{
  setupUI();

  // Auto-refresh every 5s: flow list + workbench detail (if visible).
  // The workbench detail poll is a fallback for WS events, which may not
  // always arrive promptly — without it the user has to exit and re-enter
  // to see pipeline progress.
  auto *timer = new QTimer(this);
  timer->setInterval(5000);
  connect(timer, &QTimer::timeout, this, [this]() {
    refreshFlows();
    if (m_stack->currentIndex() == 1 && !m_selectedPipelineId.isEmpty()) {
      loadFlowDetail(m_selectedPipelineId);
    }
  });
  timer->start();
  refreshFlows();
}

void FlowPage::setupUI()
{
  setStyleSheet(Theme::PageStyle);

  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(0);

  m_stack = new QStackedWidget(this);
  layout->addWidget(m_stack);

  setupListView();
  setupWorkbenchView();

  m_stack->setCurrentIndex(0);
}

// ── List View ──────────────────────────────────────────────────────────

void FlowPage::setupListView()
{
  m_listView = new QWidget(this);
  auto *layout = new QVBoxLayout(m_listView);
  layout->setContentsMargins(20, 18, 20, 18);
  layout->setSpacing(14);

  // Header
  auto *header = new QLabel(QStringLiteral("测试任务"), m_listView);
  header->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(header);

  // Toolbar
  auto *toolbar = new QHBoxLayout;
  m_newBtn = new QPushButton(QStringLiteral("＋ 新建任务"), m_listView);
  m_newBtn->setProperty("primary", true);
  connect(m_newBtn, &QPushButton::clicked, this, &FlowPage::onCreateFlow);

  m_refreshBtn = new QPushButton(QStringLiteral("刷新"), m_listView);
  connect(m_refreshBtn, &QPushButton::clicked, this, &FlowPage::refreshFlows);

  m_filterCombo = new QComboBox(m_listView);
  m_filterCombo->addItem(QStringLiteral("全部状态"), QString());
  m_filterCombo->addItem(QStringLiteral("进行中"), QStringLiteral("running"));
  m_filterCombo->addItem(QStringLiteral("待确认"), QStringLiteral("awaiting_approval"));
  m_filterCombo->addItem(QStringLiteral("已完成"), QStringLiteral("completed"));
  m_filterCombo->addItem(QStringLiteral("已取消"), QStringLiteral("cancelled"));
  m_filterCombo->setFixedWidth(140);
  connect(m_filterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
          this, &FlowPage::onFilterChanged);

  toolbar->addWidget(m_newBtn);
  toolbar->addSpacing(8);
  toolbar->addWidget(m_refreshBtn);
  toolbar->addStretch();
  toolbar->addWidget(new QLabel(QStringLiteral("筛选:")));
  toolbar->addWidget(m_filterCombo);
  layout->addLayout(toolbar);

  // Hint label
  auto *hint = new QLabel(
    QStringLiteral("  双击打开任务  ·  右键菜单可取消 / 删除"), m_listView);
  hint->setStyleSheet("font-size:12px; color:#94a3b8; padding:2px 0;");
  layout->addWidget(hint);

  // Flow table
  m_flowTable = new QTableWidget(0, 3, m_listView);
  UiUtil::EmptyHint::attach(m_flowTable, QStringLiteral("暂无测试任务"));
  m_flowTable->setHorizontalHeaderLabels(
    { QStringLiteral("状态"), QStringLiteral("目标"),
      QStringLiteral("创建时间") });
  m_flowTable->setColumnWidth(0, 160);
  m_flowTable->setColumnWidth(2, 180);
  m_flowTable->horizontalHeader()->setStretchLastSection(false);
  m_flowTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_flowTable->verticalHeader()->setVisible(false);
  m_flowTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_flowTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_flowTable->setAlternatingRowColors(true);
  m_flowTable->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_flowTable, &QTableWidget::cellDoubleClicked,
          this, &FlowPage::onFlowDoubleClicked);
  connect(m_flowTable, &QTableWidget::customContextMenuRequested,
          this, &FlowPage::onFlowContextMenu);
  layout->addWidget(m_flowTable, 1);

  m_stack->addWidget(m_listView);
}

// ── Workbench View ─────────────────────────────────────────────────────

void FlowPage::setupWorkbenchView()
{
  m_workbenchView = new QWidget(this);
  auto *layout = new QVBoxLayout(m_workbenchView);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(0);

  // Top bar
  auto *topBar = new QFrame(m_workbenchView);
  topBar->setStyleSheet("background:#ffffff; border-bottom:1px solid #dbe3ef;");
  topBar->setFixedHeight(60);
  auto *topLayout = new QHBoxLayout(topBar);
  topLayout->setContentsMargins(20, 0, 20, 0);
  topLayout->setSpacing(14);

  m_backBtn = new QPushButton(QStringLiteral("← 返回列表"), topBar);
  connect(m_backBtn, &QPushButton::clicked, this, &FlowPage::onBackToList);
  topLayout->addWidget(m_backBtn);

  auto *sep1 = new QFrame(topBar);
  sep1->setFrameShape(QFrame::VLine);
  sep1->setStyleSheet("color:#dbe3ef;");
  topLayout->addWidget(sep1);

  m_targetLabel = new QLabel(topBar);
  m_targetLabel->setStyleSheet("font-size:15px; font-weight:600; color:#1e293b;");
  topLayout->addWidget(m_targetLabel, 1);

  m_statusLabel = new QLabel(topBar);
  m_statusLabel->setStyleSheet(
    "font-size:13px; font-weight:600; padding:4px 12px; border-radius:8px;");
  topLayout->addWidget(m_statusLabel);

  topLayout->addSpacing(8);

  // Approve button (visible only when awaiting_approval)
  m_approveBtn = new QPushButton(QStringLiteral("选择预案并执行"), topBar);
  m_approveBtn->setStyleSheet(
    "QPushButton { background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; "
    "border-radius:8px; padding:7px 16px; font-size:13px; font-weight:600; }"
    "QPushButton:hover { background:#1d4ed8; border:1px solid #1e40af; }"
    "QPushButton:disabled { background:#93c5fd; color:#ffffff; border:1px solid #60a5fa; }");
  m_approveBtn->setVisible(false);
  connect(m_approveBtn, &QPushButton::clicked, this, &FlowPage::onApproveFlow);
  topLayout->addWidget(m_approveBtn);

  // ⋯ dropdown menu for secondary actions (cancel / delete / report)
  m_moreBtn = new QPushButton(QStringLiteral("⋯"), topBar);
  m_moreBtn->setFixedWidth(40);
  m_moreBtn->setStyleSheet(
    "QPushButton { font-size:18px; font-weight:700; color:#475569; "
    "background:#f1f5f9; border:1px solid #e2e8f0; border-radius:8px; padding:6px; }"
    "QPushButton:hover { background:#e2e8f0; }");
  auto *moreMenu = new QMenu(m_moreBtn);
  moreMenu->setStyleSheet("QMenu { font-size:13px; padding:4px; }");
  m_cancelAction = moreMenu->addAction(QStringLiteral("取消任务"));
  m_deleteAction = moreMenu->addAction(QStringLiteral("删除任务"));
  m_reportAction = moreMenu->addAction(QStringLiteral("查看报告"));
  m_moreBtn->setMenu(moreMenu);
  connect(m_cancelAction, &QAction::triggered, this, &FlowPage::onCancelFlow);
  connect(m_deleteAction, &QAction::triggered, this, &FlowPage::onDeleteFlow);
  connect(m_reportAction, &QAction::triggered, [this]() {
    m_stageTabs->setCurrentIndex(3);  // 测试评估
    m_evalTab->showReports();         // 切到"测试报告"子页 + 刷新
  });
  topLayout->addWidget(m_moreBtn);

  layout->addWidget(topBar);

  // 4-step progress — StepIndicator 自绘（节点+连线+状态，摘要显示在节点名下方）
  auto *progressFrame = new QFrame(m_workbenchView);
  progressFrame->setStyleSheet("background:#f8fbff; border-bottom:1px solid #dbe3ef;");
  auto *progressLayout = new QHBoxLayout(progressFrame);
  progressLayout->setContentsMargins(24, 8, 24, 4);
  m_stepIndicator = new StepIndicator(progressFrame);
  progressLayout->addWidget(m_stepIndicator, 1);
  layout->addWidget(progressFrame);

  // Stage tabs (拓扑/扫描/攻击/评估) — full width, starting from the left edge
  m_stageTabs = new QTabWidget(m_workbenchView);
  m_stageTabs->setStyleSheet(
    "QTabWidget::pane { border:none; background:#ffffff; }"
    "QTabBar::tab { padding:8px 20px; font-size:13px; font-weight:600; color:#475569; "
    "  border:1px solid #dbe3ef; border-bottom:none; border-top-left-radius:6px; border-top-right-radius:6px; "
    "  background:#f8fafc; margin-right:2px; }"
    "QTabBar::tab:selected { color:#1e40af; background:#ffffff; border-color:#dbe3ef; }"
    "QTabBar::tab:hover:!selected { background:#eff6ff; }"
  );
  m_topoTab = new TopologyPage(m_api, m_role, m_username, m_stageTabs);
  m_scanTab = new ScanPage(m_api, m_role, m_username, m_stageTabs);
  // 攻击 Tab：快速执行（原"多阶段战役"子 Tab 已移除）
  m_execTab = new ExecutionPage(m_api, m_role, m_username, m_stageTabs);
  m_evalTab = new EvaluatePage(m_api, m_role, m_username, m_stageTabs);
  m_stageTabs->addTab(m_topoTab, QStringLiteral("网络拓扑"));
  m_stageTabs->addTab(m_scanTab, QStringLiteral("脆弱性扫描"));
  m_stageTabs->addTab(m_execTab, QStringLiteral("漏洞攻击"));
  m_stageTabs->addTab(m_evalTab, QStringLiteral("测试评估"));

  // AI 推理流（左）+ 阶段 Tab（右）— runReact/pipelineLog 事件写入推理流
  m_contentSplitter = new QSplitter(Qt::Horizontal, m_workbenchView);
  m_contentSplitter->setChildrenCollapsible(false);
  auto *reasoningPane = new QWidget(m_contentSplitter);
  auto *reasoningLayout = new QVBoxLayout(reasoningPane);
  reasoningLayout->setContentsMargins(8, 8, 0, 8);
  reasoningLayout->setSpacing(6);
  auto *reasoningTitle = new QLabel(QStringLiteral("AI 推理流"), reasoningPane);
  reasoningTitle->setStyleSheet("font-size:13px; font-weight:600; color:#475569; padding:2px 4px;");
  m_reasoningPanel = new QTextBrowser(reasoningPane);
  m_reasoningPanel->setStyleSheet(
    "QTextBrowser { background:#ffffff; border:1px solid #dbe3ef; border-radius:8px; "
    "padding:8px; font-size:12px; color:#334155; }");
  m_reasoningPanel->setOpenExternalLinks(true);
  reasoningLayout->addWidget(reasoningTitle);
  reasoningLayout->addWidget(m_reasoningPanel, 1);
  m_contentSplitter->addWidget(reasoningPane);
  m_contentSplitter->addWidget(m_stageTabs);
  m_contentSplitter->setStretchFactor(0, 0);
  m_contentSplitter->setStretchFactor(1, 1);
  m_contentSplitter->setSizes({240, 960});
  layout->addWidget(m_contentSplitter, 1);

  // 实时动态（底部，可折叠）— MainWindow 将 WS 事件接入 activityPanel()
  m_activityPanel = new LiveActivityPanel(m_role, m_username, m_workbenchView);
  m_activityPanel->setCompact(true);
  layout->addWidget(m_activityPanel);

  m_stack->addWidget(m_workbenchView);
}

// ── Status helpers ─────────────────────────────────────────────────────

QString FlowPage::statusIcon(const QString &status) const
{
  if (status == "running") return "●";
  if (status == "awaiting_approval") return "⏸";
  if (status == "completed") return "✓";
  if (status == "failed") return "✗";
  if (status == "cancelled") return "⊘";
  return "○";
}

QString FlowPage::statusText(const QString &status) const
{
  static const QHash<QString, QString> map = {
    {"created", "待运行"}, {"running", "进行中"}, {"paused", "已暂停"},
    {"awaiting_approval", "待确认"}, {"completed", "已完成"},
    {"failed", "失败"}, {"cancelled", "已取消"},
  };
  return map.value(status, status);
}

QColor FlowPage::statusColor(const QString &status) const
{
  if (status == "running") return QColor("#2563eb");
  if (status == "awaiting_approval") return QColor("#8b5cf6");
  if (status == "completed") return QColor("#22c55e");
  if (status == "failed") return QColor("#ef4444");
  if (status == "cancelled") return QColor("#94a3b8");
  return QColor("#64748b");
}

QString FlowPage::flowIdAtRow(int row) const
{
  if (row < 0 || row >= m_flowTable->rowCount()) return QString();
  auto *item = m_flowTable->item(row, 0);
  return item ? item->data(Qt::UserRole).toString() : QString();
}

// ── Load flow list ─────────────────────────────────────────────────────

void FlowPage::refreshFlows()
{
  loadFlows();
}

void FlowPage::loadFlows()
{
  m_api->get("/api/pipelines", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;

    auto arr = res["data"].toArray();
    QString filter = m_filterCombo ? m_filterCombo->currentData().toString() : QString();

    m_flowTable->setRowCount(0);
    int row = 0;
    for (int i = 0; i < arr.size(); i++) {
      auto p = arr[i].toObject();
      QString status = p["status"].toString();
      if (!filter.isEmpty() && status != filter) continue;

      QString pid = p["pipeline_id"].toString();
      QString target = p["target"].toString();
      QString created = p["created_at"].toString();

      m_flowTable->insertRow(row);

      // Status column (col 0) — colored dot + text, stores pipeline_id in UserRole
      auto *statusItem = new QTableWidgetItem(
        QStringLiteral("%1  %2").arg(statusIcon(status), statusText(status)));
      statusItem->setData(Qt::UserRole, pid);
      QColor sc = statusColor(status);
      statusItem->setForeground(sc);
      statusItem->setTextAlignment(Qt::AlignCenter);
      m_flowTable->setItem(row, 0, statusItem);

      // Target column (col 1)
      auto *targetItem = new QTableWidgetItem(target);
      m_flowTable->setItem(row, 1, targetItem);

      // Created column (col 2)
      auto dt = QDateTime::fromString(created, Qt::ISODate);
      QString displayTime = dt.isValid()
        ? dt.toString("MM-dd HH:mm:ss") : created.left(19);
      auto *timeItem = new QTableWidgetItem(displayTime);
      timeItem->setTextAlignment(Qt::AlignCenter);
      m_flowTable->setItem(row, 2, timeItem);

      row++;
    }
  });
}

// ── Load flow detail (workbench) ───────────────────────────────────────

void FlowPage::loadFlowDetail(const QString &pipelineId)
{
  m_api->get(QStringLiteral("/api/pipelines/%1").arg(pipelineId), 5000,
    [this, pipelineId](const QJsonObject &res) {
    // Stale-response guard: if the user switched to a different flow while
    // this GET was in flight, skip the update to avoid overwriting the UI
    // with the wrong flow's data.
    if (pipelineId != m_selectedPipelineId) return;
    if (res["status"].toString() != "ok") return;

    auto p = res["data"].toObject();
    QString target = p["target"].toString();
    QString status = p["status"].toString();

    // Sync target to all embedded stage tabs
    m_topoTab->setTarget(target);
    m_scanTab->setTarget(target);
    m_execTab->setTarget(target);
    m_evalTab->setTarget(target);

    // Header
    m_targetLabel->setText(QStringLiteral("目标: %1").arg(target));
    QColor sc = statusColor(status);
    m_statusLabel->setText(QStringLiteral(" %1 %2 ").arg(statusIcon(status), statusText(status)));
    // Qt 的 8 位十六进制是 #AARRGGBB（alpha 在前），拼 #RRGGBBAA 会被误解析，须用 rgba()
    auto rgba = [](const QColor &c, int a) {
      return QString("rgba(%1,%2,%3,%4)").arg(c.red()).arg(c.green()).arg(c.blue())
              .arg(a / 255.0, 0, 'f', 2);
    };
    m_statusLabel->setStyleSheet(
      QString("font-size:12px; font-weight:700; color:%1; background:%2; "
              "padding:5px 14px; border-radius:11px; border:1px solid %3;")
        .arg(sc.name(), rgba(sc, 26), rgba(sc, 102)));

    // 从 pipeline 数据提取 run_id 和 playbook_id，自动加载到攻击 Tab.
    // Guard against repeated events: only drive selectPlaybook/showRun when
    // the ID actually changes, so we don't reset the user's manual combo
    // selection or yank the sub-tab on every status tick.
    QString runId = p["run_id"].toString();
    QString playbookId = p["generated_playbook_id"].toString();
    m_generatedPlaybookId = playbookId;
    if (!playbookId.isEmpty() && playbookId != m_lastLoadedPlaybookId) {
      m_lastLoadedPlaybookId = playbookId;
      m_execTab->selectPlaybook(playbookId, target);
    }
    if (!runId.isEmpty() && runId != m_lastLoadedRunId) {
      m_lastLoadedRunId = runId;
      m_execTab->showRun(runId);
    }

    // 评估 Tab：pipeline 完成后预加载该 run 的评分（兜底，不切 stage tab —
    // stage tab 的切换由 onPipelineStatus 在完成事件到达时驱动，避免打开已
    // 完成的流水线时强制跳到评估 Tab）
    if (!runId.isEmpty() && status == "completed" && runId != m_lastLoadedEvalRunId) {
      m_lastLoadedEvalRunId = runId;
      m_evalTab->showRun(runId);
    }

    // Step progress → StepIndicator
    auto steps = p["steps"].toArray();
    QVector<PhaseStep> phaseSteps;
    for (int i = 0; i < 4; i++) {
      PhaseStep ps;
      ps.displayName = STEP_NAMES[i];
      ps.phaseId = QStringLiteral("step_%1").arg(i + 1);
      ps.status = QStringLiteral("pending");
      if (i < steps.size()) {
        auto step = steps[i].toObject();
        ps.phaseType = step["step_type"].toString();
        ps.status = step["status"].toString();

        // Summary from output_data
        auto output = step["output_data"].toObject();
        if (ps.status == "completed") {
          if (ps.phaseType == "scan") {
            int totalResults = output["total_results"].toInt(0);
            ps.summary = QStringLiteral("发现 %1 条结果").arg(totalResults);
          } else if (ps.phaseType == "analyze") {
            auto attackSurface = output["attack_surface"].toArray();
            ps.summary = QStringLiteral("攻击面 %1 项").arg(attackSurface.size());
          } else if (ps.phaseType == "generate") {
            QString method = output["method"].toString();
            QString name = output["name"].toString();
            ps.summary = QStringLiteral("%1: %2").arg(
              method == "ai_generated" ? "AI生成" : "匹配", name);
          } else if (ps.phaseType == "execute") {
            QString runId = output["run_id"].toString();
            ps.summary = QStringLiteral("Run: %1").arg(runId.left(16));
          }
        } else if (ps.status == "failed") {
          ps.summary = step["error_message"].toString();
        }
      }
      phaseSteps.append(ps);
    }
    m_stepIndicator->setPhases(phaseSteps);

    // Refresh the embedded scan tab while the scan phase is active, so it
    // picks up new tasks / results (loadFlowDetail is called by the 5s poll
    // timer and WS events, not just on entry).
    for (int i = 0; i < steps.size(); i++) {
      auto step = steps[i].toObject();
      if (step["step_type"].toString() == "scan") {
        QString sStatus = step["status"].toString();
        if (sStatus == "running" || sStatus == "completed") {
          m_scanTab->onRefreshTasks();
          break;
        }
      }
    }

    // execute 阶段运行中时自动切到攻击 Tab（不含 completed——完成后让用户
    // 自行决定落点，避免打开已完成的流水线时永远到不了"测试评估"Tab）
    for (int i = 0; i < steps.size(); i++) {
      auto step = steps[i].toObject();
      if (step["step_type"].toString() == "execute") {
        QString sStatus = step["status"].toString();
        if (sStatus == "running") {
          m_stageTabs->setCurrentIndex(2);  // 漏洞攻击
        }
      }
    }

    // Action visibility based on status
    bool isAwaiting = (status == "awaiting_approval");
    bool isActive = (status == "running" || status == "awaiting_approval");
    bool isDeletable = !isActive;  // backend refuses delete on running/awaiting
    m_approveBtn->setVisible(isAwaiting);
    m_cancelAction->setVisible(isActive);
    m_deleteAction->setVisible(isDeletable);
    m_reportAction->setVisible(status == "completed");
    // Hide ⋯ button entirely if no actions are available
    m_moreBtn->setVisible(isActive || isDeletable || status == "completed");
  });
}

// ── Create flow ────────────────────────────────────────────────────────

void FlowPage::onCreateFlow()
{
  // Dialog: target input + approval checkbox
  QDialog dlg(this);
  dlg.setWindowTitle(QStringLiteral("新建测试任务"));
  dlg.setMinimumWidth(420);
  auto *l = new QVBoxLayout(&dlg);
  l->setSpacing(12);
  l->setContentsMargins(20, 20, 20, 20);

  l->addWidget(new QLabel(QStringLiteral("目标 IP / 网段 / URL:")));
  auto *targetInput = new QLineEdit(&dlg);
  targetInput->setPlaceholderText(QStringLiteral("例: 192.168.1.0/24 或 http://172.17.0.2"));
  l->addWidget(targetInput);

  auto *approvalCheck = new QCheckBox(QStringLiteral("攻击前需人工确认（推荐）"), &dlg);
  approvalCheck->setChecked(true);
  l->addWidget(approvalCheck);

  auto *btns = new QDialogButtonBox(
    QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
  btns->button(QDialogButtonBox::Ok)->setText(QStringLiteral("创建并开始"));
  connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  l->addWidget(btns);

  if (dlg.exec() != QDialog::Accepted) return;

  QString target = targetInput->text().trimmed();
  if (target.isEmpty()) return;

  QJsonObject config;
  config["require_approval"] = approvalCheck->isChecked();
  QJsonObject body;
  body["target"] = target;
  body["config"] = config;

  m_newBtn->setEnabled(false);
  m_newBtn->setText(QStringLiteral("创建中..."));

  m_api->post("/api/pipelines", body, 10000, [this](const QJsonObject &res) {
    m_newBtn->setEnabled(true);
    m_newBtn->setText(QStringLiteral("＋ 新建任务"));
    if (res["status"].toString() != "ok") return;

    QString pipelineId = res["data"].toObject()["pipeline_id"].toString();
    // Auto-start
    m_api->post(QStringLiteral("/api/pipelines/%1/start").arg(pipelineId),
                QJsonObject{}, 10000, [this](const QJsonObject &) {
      refreshFlows();
    });
  });
}

// ── Flow selection & navigation ────────────────────────────────────────

void FlowPage::onFlowDoubleClicked(int row)
{
  QString pid = flowIdAtRow(row);
  if (pid.isEmpty()) return;
  m_selectedPipelineId = pid;
  if (m_reasoningPanel) m_reasoningPanel->clear();
  m_lastLoadedRunId.clear();
  m_lastLoadedPlaybookId.clear();
  m_lastLoadedEvalRunId.clear();
  loadFlowDetail(pid);
  m_stack->setCurrentIndex(1);
  // Refresh the embedded scan tab so it picks up any new scan tasks
  m_scanTab->onRefreshTasks();
}

void FlowPage::onFlowContextMenu(const QPoint &pos)
{
  int row = m_flowTable->rowAt(pos.y());
  if (row < 0) return;
  QString pid = flowIdAtRow(row);
  if (pid.isEmpty()) return;

  // Read status from the item text (stored as "icon  text")
  QString statusText = m_flowTable->item(row, 0)->text();
  bool isActive = statusText.contains("进行中") || statusText.contains("待确认");

  auto *menu = new QMenu(this);
  menu->addAction(QStringLiteral("打开"), [this, pid]() {
    m_selectedPipelineId = pid;
    if (m_reasoningPanel) m_reasoningPanel->clear();
    m_lastLoadedRunId.clear();
    m_lastLoadedPlaybookId.clear();
    m_lastLoadedEvalRunId.clear();
    loadFlowDetail(pid);
    m_stack->setCurrentIndex(1);
  });
  if (isActive) {
    menu->addAction(QStringLiteral("取消"), [this, pid]() {
      m_api->post(QStringLiteral("/api/pipelines/%1/cancel").arg(pid),
                  QJsonObject{}, 5000, [this](const QJsonObject &) {
        refreshFlows();
      });
    });
  } else {
    menu->addAction(QStringLiteral("删除"), [this, pid]() {
      if (QMessageBox::question(this, QStringLiteral("删除任务"),
            QStringLiteral("确定删除此测试任务？此操作不可撤销。"),
            QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        m_api->del(QStringLiteral("/api/pipelines/%1").arg(pid), 5000,
                   [this](const QJsonObject &) {
          refreshFlows();
        });
      }
    });
  }
  menu->exec(m_flowTable->viewport()->mapToGlobal(pos));
}

void FlowPage::onOpenFlow()
{
  int row = m_flowTable->currentRow();
  if (row < 0) return;
  onFlowDoubleClicked(row);
}

void FlowPage::onBackToList()
{
  m_stack->setCurrentIndex(0);
  refreshFlows();
}

void FlowPage::onFilterChanged(int)
{
  loadFlows();
}

// ── Workbench actions ──────────────────────────────────────────────────

void FlowPage::onCancelFlow()
{
  if (m_selectedPipelineId.isEmpty()) return;
  QString pid = m_selectedPipelineId;
  m_api->post(QStringLiteral("/api/pipelines/%1/cancel").arg(pid),
              QJsonObject{}, 5000, [this, pid](const QJsonObject &) {
    refreshFlows();
    loadFlowDetail(pid);
  });
}

void FlowPage::onDeleteFlow()
{
  if (m_selectedPipelineId.isEmpty()) return;
  QString pid = m_selectedPipelineId;
  if (QMessageBox::question(this, QStringLiteral("删除任务"),
        QStringLiteral("确定删除此测试任务？此操作不可撤销。"),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;

  m_api->del(QStringLiteral("/api/pipelines/%1").arg(pid), 5000,
             [this](const QJsonObject &) {
    m_stack->setCurrentIndex(0);
    refreshFlows();
  });
}

void FlowPage::onApproveFlow()
{
  if (m_selectedPipelineId.isEmpty()) return;
  QString pid = m_selectedPipelineId;

  m_approveBtn->setEnabled(false);
  m_approveBtn->setText(QStringLiteral("加载预案..."));

  // Fetch playbooks for the selection dialog
  m_api->get("/api/playbooks?includeGenerated=true", 5000, [this, pid](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      m_approveBtn->setEnabled(true);
      m_approveBtn->setText(QStringLiteral("选择预案并执行"));
      return;
    }
    auto playbooks = res["data"].toArray();

    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("审批执行"));
    dlg.setMinimumWidth(500);
    auto *l = new QVBoxLayout(&dlg);
    l->setSpacing(12);
    l->setContentsMargins(20, 20, 20, 20);

    l->addWidget(new QLabel(m_targetLabel->text()));
    l->addWidget(new QLabel(QStringLiteral("选择攻击预案:")));

    auto *combo = new QComboBox(&dlg);
    int defaultIndex = 0;
    for (int i = 0; i < playbooks.size(); i++) {
      auto pb = playbooks[i].toObject();
      QString pbId = pb["playbook_id"].toString();
      QString name = pb["name"].toString();
      QString label = name + " [" + pbId + "]";
      if (pbId == m_generatedPlaybookId) {
        label = QStringLiteral("★ ") + label + QStringLiteral("  (AI生成)");
        defaultIndex = i;
      }
      combo->addItem(label, pbId);
    }
    if (combo->count() > 0) combo->setCurrentIndex(defaultIndex);
    l->addWidget(combo);

    auto *btns = new QDialogButtonBox(
      QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    btns->button(QDialogButtonBox::Ok)->setText(QStringLiteral("批准并执行"));
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    l->addWidget(btns);

    if (dlg.exec() != QDialog::Accepted) {
      m_approveBtn->setEnabled(true);
      m_approveBtn->setText(QStringLiteral("选择预案并执行"));
      return;
    }

    QString selectedPlaybookId = combo->currentData().toString();

    m_approveBtn->setText(QStringLiteral("审批中..."));

    QJsonObject body;
    body["playbook_id"] = selectedPlaybookId;
    m_api->post(QStringLiteral("/api/pipelines/%1/approve").arg(pid),
                body, 10000, [this, pid](const QJsonObject &approveRes) {
      m_approveBtn->setEnabled(true);
      m_approveBtn->setText(QStringLiteral("选择预案并执行"));
      if (approveRes["status"].toString() == "ok") {
        refreshFlows();
        loadFlowDetail(pid);
      }
    });
  });
}

// ── WebSocket slots ────────────────────────────────────────────────────

void FlowPage::onPipelineCreated(const QJsonObject &)
{
  refreshFlows();
}

void FlowPage::onPipelineStatus(const QJsonObject &data)
{
  QString pid = data["pipeline_id"].toString();
  if (pid == m_selectedPipelineId && m_stack->currentIndex() == 1) {
    loadFlowDetail(pid);

    // pipeline 完成时自动切到评估 Tab 并加载评分
    if (data["status"].toString() == "completed") {
      QString runId = data["run_id"].toString();
      if (runId.isEmpty()) {
        // 兜底：completed 事件可能不含顶层 run_id，从 result.execution 取
        runId = data["result"].toObject()["execution"].toObject()["run_id"].toString();
      }
      if (!runId.isEmpty() && runId != m_lastLoadedEvalRunId) {
        m_lastLoadedEvalRunId = runId;
        m_stageTabs->setCurrentIndex(3);  // 测试评估
        m_evalTab->showRun(runId);
      }
    }
  }
  refreshFlows();
}

void FlowPage::onPipelineStep(const QJsonObject &data)
{
  QString pid = data["pipeline_id"].toString();
  if (pid == m_selectedPipelineId && m_stack->currentIndex() == 1) {
    loadFlowDetail(pid);
    // execute 步骤开始时自动切到攻击 Tab
    if (data["step_type"].toString() == "execute" &&
        data["status"].toString() == "running") {
      m_stageTabs->setCurrentIndex(2);
    }
    // Append to reasoning stream
    QString stepType = data["step_type"].toString();
    QString status = data["status"].toString();
    QString timeStr = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString icon = (status == "completed") ? "✓" :
                   (status == "failed")   ? "✗" :
                   (status == "running")   ? "▶" : "○";
    if (m_reasoningPanel)
      m_reasoningPanel->append(
        QString("<span style='color:#94a3b8;font-size:11px;'>[%1]</span> "
                "<b>%2</b> 阶段 %3")
          .arg(timeStr, icon, stepType.toHtmlEscaped()));
  }
}

void FlowPage::onPipelineLog(const QJsonObject &data)
{
  QString pid = data["pipeline_id"].toString();
  if (pid != m_selectedPipelineId) return;
  if (m_stack->currentIndex() != 1) return;
  if (!m_reasoningPanel) return;

  QString msg = data["message"].toString();
  QString level = data["level"].toString();
  qint64 ts = data["timestamp"].toVariant().toLongLong();
  QString timeStr = ts > 0
    ? QDateTime::fromMSecsSinceEpoch(ts).toString("HH:mm:ss")
    : QDateTime::currentDateTime().toString("HH:mm:ss");

  QString color = "#64748b";  // info
  if (level == "warn")  color = "#d97706";
  if (level == "error") color = "#dc2626";
  m_reasoningPanel->append(
    QString("<span style='color:#94a3b8;font-size:11px;'>[%1]</span> "
            "<span style='color:%2;'>%3</span>")
      .arg(timeStr, color, msg.toHtmlEscaped()));
}

LiveActivityPanel *FlowPage::activityPanel() const
{
  return m_activityPanel;
}

ScanPage *FlowPage::scanTab() const
{
  return m_scanTab;
}

ExecutionPage *FlowPage::execTab() const
{
  return m_execTab;
}

void FlowPage::switchToStageTab(int idx)
{
  if (m_stageTabs && idx >= 0 && idx < m_stageTabs->count())
    m_stageTabs->setCurrentIndex(idx);
}

void FlowPage::jumpToExecution(const QString &playbookId, const QString &target)
{
  // Clear pipeline context — this is a direct execution, not a pipeline view
  m_selectedPipelineId.clear();
  m_lastLoadedRunId.clear();
  m_lastLoadedPlaybookId.clear();
  m_lastLoadedEvalRunId.clear();

  // Show "direct execution" in the workbench header
  m_targetLabel->setText(QStringLiteral("直接执行: %1").arg(
    target.isEmpty() ? QStringLiteral("(未指定)") : target));
  m_statusLabel->setText(QStringLiteral(" 直接执行模式 "));
  m_statusLabel->setStyleSheet(
    "font-size:13px; font-weight:600; color:#64748b; background:#f1f5f9; "
    "padding:4px 12px; border-radius:8px; border:1px solid #cbd5e1;");

  // Hide pipeline-specific action buttons
  m_approveBtn->setVisible(false);
  m_moreBtn->setVisible(false);

  // Switch to workbench + attack tab
  m_stack->setCurrentIndex(1);
  m_stageTabs->setCurrentIndex(2);  // 漏洞攻击

  // Pre-select the playbook
  if (!playbookId.isEmpty())
    m_execTab->selectPlaybook(playbookId, target);

  // Clear reasoning panel
  if (m_reasoningPanel) m_reasoningPanel->clear();
}

void FlowPage::appendThought(const QString &text)
{
  if (!m_reasoningPanel || text.isEmpty()) return;
  // Only append when the workbench is visible — run:react events lack
  // pipeline_id, so we can't filter by pipeline.  This guard at least
  // prevents appending thoughts when nobody is looking at the panel.
  if (m_stack->currentIndex() != 1) return;
  QString timeStr = QDateTime::currentDateTime().toString("HH:mm:ss");
  m_reasoningPanel->append(
    QString("<span style='color:#94a3b8;font-size:11px;'>[%1]</span> "
            "<i style='color:#7c3aed;'>%2</i>")
      .arg(timeStr, text.toHtmlEscaped()));
}
