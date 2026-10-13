#include "../widgets/WorkbenchTabs.h"
#include "ExecutionPage.h"
#include "TaskExecutionPanel.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../ApiClient.h"
#include "../CortexPanel.h"
#include <QScrollArea>
#include <QSplitter>
#include <QFrame>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMap>
#include <QSettings>
#include <QCompleter>
#include <QStringListModel>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QMessageBox>
#include <QShowEvent>

// ── Helper: create a table item with truncated display text and the full
//    text stored in Qt::UserRole for double-click expansion. ─────────────
static QTableWidgetItem *truncItem(const QString &full, int maxChars) {
  QString display = full.length() > maxChars ? full.left(maxChars) + QStringLiteral("…") : full;
  auto *item = new QTableWidgetItem(display);
  item->setData(Qt::UserRole, full);  // always store full text for popup
  return item;
}

// ── Helper: wrap text as an HTML tooltip with a max width so long content
//    wraps instead of stretching across the screen. ──────────────────────
static QString wrapToolTip(const QString &text) {
  if (text.isEmpty()) return {};
  return QStringLiteral("<div style=\"max-width: 500px; white-space: pre-wrap;\">") +
         text.toHtmlEscaped() + QStringLiteral("</div>");
}

ExecutionPage::ExecutionPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
  m_taskMonitor = new TaskExecutionPanel(api, role, username, this);
  layout()->addWidget(m_taskMonitor);
  m_taskMonitor->hide();
  connect(m_taskMonitor, &TaskExecutionPanel::runSelected, this, &ExecutionPage::runSelected);
  connect(m_taskMonitor, &TaskExecutionPanel::runCompleted, this, &ExecutionPage::runCompleted);
  loadPlaybooks();

  // Poll timer for real-time execution updates
  m_pollTimer = new QTimer(this);
  m_pollTimer->setInterval(2000);
  connect(m_pollTimer, &QTimer::timeout, this, &ExecutionPage::onPollRunning);
}

void ExecutionPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(12, 8, 12, 8);

  // ── Tab widget ─────────────────────────────────────────────────────
  m_tabWidget = new WorkbenchTabs(this);

  // ── Tab 1: 执行记录 ────────────────────────────────────────────────
  auto *tab1 = new QWidget;
  auto *tab1Layout = new QVBoxLayout(tab1);
  tab1Layout->setContentsMargins(8, 8, 8, 8);

  m_standaloneControls = new QWidget(tab1);
  m_standaloneControls->setObjectName("standaloneExecutionControls");
  auto *standaloneLayout = new QVBoxLayout(m_standaloneControls);
  standaloneLayout->setContentsMargins(0, 0, 0, 0);
  tab1Layout->addWidget(m_standaloneControls);
  m_pipelineHint = new QLabel(tab1);
  m_pipelineHint->setWordWrap(true);
  m_pipelineHint->setStyleSheet("color:#64748b;padding:4px 0;");
  m_pipelineHint->hide();
  tab1Layout->addWidget(m_pipelineHint);

  // ── Attack category filter ─────────────────────────────────────────
  auto *catH = new QHBoxLayout;
  catH->addWidget(new QLabel("攻击类型:"));
  m_catAll = new QRadioButton("全部");
  m_catDataTheft = new QRadioButton("数据窃取");
  m_catTamper = new QRadioButton("信息篡改");
  m_catDeviceCtrl = new QRadioButton("设备夺控");
  m_catAll->setChecked(true);
  m_catGroup = new QButtonGroup(this);
  m_catGroup->addButton(m_catAll, 0);
  m_catGroup->addButton(m_catDataTheft, 1);
  m_catGroup->addButton(m_catTamper, 2);
  m_catGroup->addButton(m_catDeviceCtrl, 3);
  catH->addWidget(m_catAll);
  catH->addWidget(m_catDataTheft);
  catH->addWidget(m_catTamper);
  catH->addWidget(m_catDeviceCtrl);
  catH->addStretch();
  standaloneLayout->addLayout(catH);
  connect(m_catGroup, QOverload<int>::of(&QButtonGroup::buttonClicked),
          this, &ExecutionPage::onAttackCategoryChanged);

  // ── Top: select playbook + target + execute ────────────────────────
  auto *h1 = new QHBoxLayout;
  h1->addWidget(new QLabel("预案:"));
  m_playbookCombo = new QComboBox;
  m_playbookCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
  m_playbookCombo->setMinimumContentsLength(12);
  h1->addWidget(m_playbookCombo, 1);
  h1->addWidget(new QLabel("目标:"));
  m_targetInput = new QLineEdit;
  m_targetInput->setPlaceholderText("例: 192.168.1.1");
  m_targetInput->setMinimumWidth(130);
  // Input history via QCompleter
  QSettings settings("RedTeam", "RedTeam-Platform");
  QStringList history = settings.value("history/targets").toStringList();
  auto *completer = new QCompleter(history, this);
  completer->setCaseSensitivity(Qt::CaseInsensitive);
  m_targetInput->setCompleter(completer);
  // Note: No QRegularExpressionValidator — it blocks intermediate typing.
  h1->addWidget(m_targetInput);
  m_execBtn = new QPushButton("执行");
  m_execBtn->setProperty("primary", true);
  h1->addWidget(m_execBtn);
  standaloneLayout->addLayout(h1);
  connect(m_execBtn, &QPushButton::clicked, this, &ExecutionPage::onExecute);

  // ── Run list ──────────────────────────────────────────────────────
  auto *runLabel = new QLabel("执行记录"); runLabel->setStyleSheet(Theme::SectionStyle);
  tab1Layout->addWidget(runLabel);
  m_runTable = new QTableWidget(0, 5);
  UiUtil::EmptyHint::attach(m_runTable, QStringLiteral("暂无攻击执行记录"));
  m_runTable->setHorizontalHeaderLabels({"执行编号", "预案", "目标", "状态", "创建时间"});
  m_runTable->setAlternatingRowColors(true);
  m_runTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_runTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_runTable->setSortingEnabled(true);
  m_runTable->setContextMenuPolicy(Qt::CustomContextMenu);
  tab1Layout->addWidget(m_runTable, 1);
  connect(m_runTable, &QTableWidget::cellClicked, this, &ExecutionPage::onRunClicked);

  // ── Refresh ───────────────────────────────────────────────────────
  auto *refreshBtn = new QPushButton("刷新");
  tab1Layout->addWidget(refreshBtn);
  connect(refreshBtn, &QPushButton::clicked, this, &ExecutionPage::onRefreshRuns);

  m_tabWidget->addTab(tab1, QStringLiteral("执行记录"));

  // ── Tab 2: 执行详情（步骤 / 证据） ─────────────────────────────
  auto *tab2 = new QWidget;
  auto *tab2Layout = new QHBoxLayout(tab2);
  tab2Layout->setContentsMargins(0, 0, 0, 0);
  tab2Layout->setSpacing(0);

  m_cortexPanel = new CortexPanel(m_api);
  m_cortexPanel->setObjectName(QStringLiteral("aiExecutionAnalysisPanel"));

  // ── Right: Step details + Evidence ─────────────────────────────────
  auto *rightWidget = new QWidget;
  auto *rightInner = new QWidget;
  auto *rightLayout = new QVBoxLayout(rightInner);
  rightLayout->setContentsMargins(8, 8, 8, 8);

  // Status + stop button row
  auto *statusRow = new QHBoxLayout;
  statusRow->setSpacing(8);
  m_statusLabel = new QLabel;
  m_statusLabel->setWordWrap(true);
  statusRow->addWidget(m_statusLabel, 1);

  m_stopBtn = new QPushButton(QStringLiteral("🛑 停止执行"));
  m_stopBtn->setMinimumWidth(110);
  m_stopBtn->setCursor(Qt::PointingHandCursor);
  m_stopBtn->setProperty("danger", true);
  m_stopBtn->setEnabled(false);  // disabled until a running run is loaded
  m_stopBtn->setToolTip(QStringLiteral("中止当前工具进程，并停止后续步骤"));
  statusRow->addWidget(m_stopBtn);
  rightLayout->addLayout(statusRow);

  connect(m_stopBtn, &QPushButton::clicked, this, [this]() {
    if (m_runningRunId.isEmpty()) return;
    m_stopBtn->setEnabled(false);
    m_stopBtn->setText("停止中...");
    m_api->post("/api/runs/" + m_runningRunId + "/abort", {}, 5000,
      [this](const QJsonObject &res) {
        if (res["status"].toString() == "ok") {
          m_stopBtn->setText(QStringLiteral("🛑 已中止"));
        } else {
          m_stopBtn->setEnabled(true);
          m_stopBtn->setText(QStringLiteral("🛑 停止执行"));
        }
      });
  });

  // Step table
  auto *stepLabel = new QLabel("步骤执行详情"); stepLabel->setStyleSheet(Theme::SectionStyle);
  rightLayout->addWidget(stepLabel);
  m_stepTable = new QTableWidget(0, 7);
  UiUtil::EmptyHint::attach(m_stepTable, QStringLiteral("选择执行记录后展示步骤"));
  m_stepTable->setHorizontalHeaderLabels({"步骤", "工具", "参数", "工具结果", "来源", "输出摘要", "载荷"});
  m_stepTable->setAlternatingRowColors(true);
  m_stepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_stepTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_stepTable->setWordWrap(false);
  m_stepTable->setTextElideMode(Qt::ElideRight);
  m_stepTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
  m_stepTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
  rightLayout->addWidget(m_stepTable, 1);

  // Evidence
  m_evidenceLabel = new QLabel;
  rightLayout->addWidget(m_evidenceLabel);
  auto *evLabel = new QLabel("攻击证据"); evLabel->setStyleSheet(Theme::SectionStyle);
  rightLayout->addWidget(evLabel);
  m_evidenceTable = new QTableWidget(0, 5);
  UiUtil::EmptyHint::attach(m_evidenceTable, QStringLiteral("暂无取证数据"));
  m_evidenceTable->setHorizontalHeaderLabels({"步骤", "类型", "数据摘要", "MITRE命中", "建议"});
  m_evidenceTable->setAlternatingRowColors(true);
  m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_evidenceTable->setWordWrap(false);
  m_evidenceTable->setTextElideMode(Qt::ElideRight);
  m_evidenceTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  rightLayout->addWidget(m_evidenceTable, 1);

  auto *detailTabs = new WorkbenchTabs;
  detailTabs->setObjectName("executionDetailTabs");
  auto *stepsPage = new QWidget;
  auto *stepsLayout = new QVBoxLayout(stepsPage);
  stepLabel->hide();
  auto *stepHint = new QLabel;
  stepHint->setStyleSheet("color:#64748b;");
  stepHint->setText(QStringLiteral("双击查看完整输出；工具执行成功不代表已确认漏洞，请结合证据判断。"));
  stepHint->setWordWrap(true);
  stepsLayout->addWidget(stepHint);
  m_stepTable->setToolTip(stepHint->text());
  stepsLayout->addWidget(m_stepTable, 1);
  auto *evidencePage = new QWidget;
  auto *evidenceLayout = new QVBoxLayout(evidencePage);
  evidenceLayout->addWidget(m_evidenceLabel);
  evLabel->hide();
  evidenceLayout->addWidget(m_evidenceTable, 1);
  detailTabs->addTab(stepsPage, QStringLiteral("执行步骤"));
  detailTabs->addTab(evidencePage, QStringLiteral("证据"));
  m_programReport=new QPlainTextEdit;
  m_programReport->setReadOnly(true);
  m_programReport->setPlaceholderText("程序测试结束后显示 Agent 观察、证据引用和待复核评估");
  detailTabs->addTab(m_programReport,QStringLiteral("程序测试报告"));
  rightLayout->addWidget(detailTabs, 1);
  auto *rightOuterLayout = new QVBoxLayout(rightWidget);
  rightOuterLayout->setContentsMargins(0, 0, 0, 0);
  rightOuterLayout->addWidget(rightInner);
  auto *splitter = new QSplitter(Qt::Horizontal);
  splitter->addWidget(m_cortexPanel);
  splitter->addWidget(rightWidget);
  splitter->setStretchFactor(0, 2);
  splitter->setStretchFactor(1, 3);
  splitter->setSizes({380, 570});
  tab2Layout->addWidget(splitter);

  for (auto *table : {m_runTable, m_stepTable, m_evidenceTable}) {
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->setWordWrap(false);
    table->setTextElideMode(Qt::ElideRight);
  }
  for (int col : {2, 4, 6}) m_stepTable->setColumnHidden(col, true);
  m_stepTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
  m_stepTable->setColumnWidth(0, 60);
  m_stepTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);
  m_stepTable->setColumnWidth(3, 100);
  m_tabWidget->addTab(tab2, QStringLiteral("执行详情"));

  mainLayout->addWidget(m_tabWidget, 1);

  // ── Right-click menus ────────────────────────────────────────────────
  connect(m_runTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_runTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_runTable->viewport()->mapToGlobal(pos));
  });
  connect(m_stepTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_stepTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_stepTable->viewport()->mapToGlobal(pos));
  });
  connect(m_evidenceTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_evidenceTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_evidenceTable->viewport()->mapToGlobal(pos));
  });

  // ── Double-click to expand truncated cells in a popup ───────────────
  connect(m_stepTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
    QStringList lines;
    for (int col = 0; col < m_stepTable->columnCount(); ++col) {
      const auto *item = m_stepTable->item(row, col);
      if (!item) continue;
      QString full = item->data(Qt::UserRole).toString();
      if (full.isEmpty()) full = item->text();
      lines << m_stepTable->horizontalHeaderItem(col)->text() + ":\n" + full;
    }
    showCellDetail(QStringLiteral("步骤 %1 · 完整详情").arg(row + 1), lines.join("\n\n"));
  });
  connect(m_evidenceTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int col) {
    auto *item = m_evidenceTable->item(row, col);
    if (!item) return;
    QString full = item->data(Qt::UserRole).toString();
    if (full.isEmpty()) full = item->text();
    if (full.isEmpty() || full == QStringLiteral("-")) return;
    QString colTitle = m_evidenceTable->horizontalHeaderItem(col)->text();
    showCellDetail(QStringLiteral("证据 %1 — %2").arg(row + 1).arg(colTitle), full);
  });
}

// ── Load all playbooks ───────────────────────────────────────────────
void ExecutionPage::loadPlaybooks() {
  m_api->get("/api/playbooks?includeGenerated=true", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    m_allPlaybooks = res["data"].toArray();
    // Populate combo with all
    loadPlaybooksByGroup(QStringList());
  });
}

// ── Select playbook by ID (cross-page navigation) ────────────────────
void ExecutionPage::setTarget(const QString &target) {
  m_targetInput->setText(target);
}

void ExecutionPage::selectPlaybook(const QString &playbookId, const QString &target) {
  // Pre-fill target
  m_targetInput->setText(target);

  // Try to find in combo box (may already be loaded)
  for (int i = 0; i < m_playbookCombo->count(); i++) {
    if (m_playbookCombo->itemData(i).toString() == playbookId) {
      m_playbookCombo->setCurrentIndex(i);
      // Reset category filter to "All" so the item is visible
      m_catAll->setChecked(true);
      return;
    }
  }

  // Not found — reload playbooks then select
  m_api->get("/api/playbooks?includeGenerated=true", 5000,
    [this, playbookId](const QJsonObject &res) {
      if (res["status"].toString() != "ok") return;
      m_allPlaybooks = res["data"].toArray();
      m_catAll->setChecked(true);
      loadPlaybooksByGroup(QStringList());

      // Now find it
      for (int i = 0; i < m_playbookCombo->count(); i++) {
        if (m_playbookCombo->itemData(i).toString() == playbookId) {
          m_playbookCombo->setCurrentIndex(i);
          return;
        }
      }
    });
}

// ── 演示动线：从扫描漏洞一键发起攻击 ──────────────────────────────────
void ExecutionPage::attackFromVuln(const QString &target, const QString &vulnText, const QString &resultType) {
  setTarget(target);

  // 关键词 → 预案规则（按优先级，首个命中即用）
  const QString hay = (vulnText + " " + resultType).toLower();
  const QList<QPair<QStringList, QString>> rules = {
    {{"sql", "注入", "sqlmap", "sqli"}, "sqli_exploit_sqlmap_basic"},
    {{"upload", "上传"}, "web_file_upload_exploit"},
    {{"password", "credential", "弱口令", "爆破", "brute"}, "brute_force_hydra"},
    {{"nikto", "cgi", "xss", "web_vuln"}, "web_vuln_exploit"},
  };
  QString matched;
  for (const auto &rule : rules) {
    for (const auto &kw : rule.first) {
      if (hay.contains(kw)) { matched = rule.second; break; }
    }
    if (!matched.isEmpty()) break;
  }
  if (resultType == "source_vuln" || resultType == "source_finding" || resultType == "program_finding") {
    m_statusLabel->setText("请从程序测试任务根据具体发现生成攻击预案，并按实际证据查看攻击效果。");
    return;
  }
  if (matched.isEmpty()) matched = "web_vuln_exploit";

  selectPlaybook(matched, target);
  m_statusLabel->setText(QString("已从扫描漏洞转入攻击：目标 %1 · 匹配预案 %2（可手动调整后执行）")
                             .arg(target, matched));
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
}

// ── Show a specific run (public, used by FlowPage workbench) ──────────
void ExecutionPage::showRun(const QString &runId, bool focus)
{
  if (!m_pipelineId.isEmpty() && runId != m_pipelineRunId) return;
  if (runId.isEmpty()) return;
  if (!m_pipelineId.isEmpty()) {
    m_taskMonitor->setTaskContext(m_pipelineId, runId, m_targetInput->text());
    m_taskMonitor->refresh();
    return;
  }
  // Track as the running run so the poll timer keeps the step table, evidence,
  // and status label live.  onPollRunning stops automatically at a terminal
  // state, so a completed run costs at most one extra GET.
  m_runningRunId = runId;
  m_pollErrorCount = 0;
  if (!m_pollTimer->isActive()) m_pollTimer->start();
  // Refresh the run table so the target run appears, then load its details
  onRefreshRuns();
  loadRunDetails(runId);
  if (focus) focusDetails();
}

void ExecutionPage::focusDetails() {
  m_tabWidget->setCurrentIndex(1);
}

void ExecutionPage::showExecutionError(const QString &message) {
  m_statusLabel->setTextFormat(Qt::PlainText);
  m_statusLabel->setText(message);
  m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
  m_stopBtn->setEnabled(false);
  m_cortexPanel->setStatus(QStringLiteral("FAILED"));
}

void ExecutionPage::clearRunContext() {
  m_taskMonitor->clearTaskContext();
  ++m_contextRevision;
  m_pollTimer->stop();
  m_runningRunId.clear();
  m_runningPlaybookId.clear();
  m_loadedRunId.clear();
  ++m_runSelectionRevision;
  ++m_runDetailsRequestRevision;
  ++m_pollRequestRevision;
  m_pollRequestInFlight = false;
  m_cortexPanel->clearMessages();
  m_cortexPanel->setEngineInfo({});
  m_cortexPanel->setStatus({});
  m_reactEventIds.clear();
  m_payloadCardIds.clear();
  m_lastReactAction.clear();
  m_pollErrorCount = 0;
  m_stopBtn->setEnabled(false);
  m_execBtn->setEnabled(m_pipelineId.isEmpty());
  m_execBtn->setText(QStringLiteral("执行"));
  m_stepTable->setRowCount(0);
  m_evidenceTable->setRowCount(0);
  m_programReport->clear();
  m_runTable->setRowCount(0);
  m_evidenceLabel->setText(QStringLiteral("暂无执行证据"));
  m_stopBtn->hide();
  m_statusLabel->setText(QStringLiteral("选择执行记录查看详情"));
}

// ── Load playbooks filtered by baseline_group ───────────────────────
void ExecutionPage::loadPlaybooksByGroup(const QStringList &groups) {
  m_playbookCombo->clear();
  for (int i = 0; i < m_allPlaybooks.size(); i++) {
    auto pb = m_allPlaybooks[i].toObject();
    QString group = pb["baseline_group"].toString();
    if (!groups.isEmpty() && !groups.contains(group)) continue;
    QString label = pb["name"].toString() + " [" + pb["playbook_id"].toString() + "]";
    m_playbookCombo->addItem(label, pb["playbook_id"].toString());
  }
}

// ── Attack category changed ─────────────────────────────────────────
void ExecutionPage::onAttackCategoryChanged(int id) {
  switch (id) {
    case 0: loadPlaybooksByGroup(QStringList()); break;
    case 1: loadPlaybooksByGroup({"data-exfiltration", "credential-access"}); break;
    case 2: loadPlaybooksByGroup({"tampering-deception"}); break;
    case 3: loadPlaybooksByGroup({"device-control", "internal-network-exploitation", "impact-demonstration"}); break;
  }
}

// A pipeline owns its execution; independent runs remain in the standalone view.
void ExecutionPage::setPipelineContext(const QString &pipelineId, const QString &status, const QString &runId, const QString &target) {
  const bool changed = pipelineId != m_pipelineId || runId != m_pipelineRunId;
  m_pipelineId = pipelineId;
  m_pipelineStatus = status;
  m_pipelineRunId = runId;
  const bool scoped = !pipelineId.isEmpty();
  if (scoped) m_targetInput->setText(target);
  m_tabWidget->setVisible(!scoped);
  m_taskMonitor->setTaskContext(pipelineId, runId, target);
  m_taskMonitor->setVisible(scoped);
  m_targetInput->setReadOnly(scoped);
  m_standaloneControls->setVisible(!scoped);
  m_pipelineHint->setVisible(scoped);
  m_execBtn->setEnabled(!scoped);
  m_execBtn->setText(QStringLiteral("执行"));
  m_pipelineHint->setText(status == "awaiting_approval"
      ? QStringLiteral("当前任务待确认。请使用顶部“确认预案并执行”；本页展示执行过程与结果。")
      : runId.isEmpty() ? QStringLiteral("当前任务尚无执行记录，请查看顶部任务进度。")
      : QStringLiteral("仅显示当前任务关联的执行记录。点击记录可查看执行步骤与证据。"));
  if (changed) {
    ++m_contextRevision;
    ++m_runSelectionRevision;
    ++m_runDetailsRequestRevision;
    ++m_pollRequestRevision;
    m_pollRequestInFlight = false;
    m_pollErrorCount = 0;
    m_pollTimer->stop();
    m_runningRunId.clear();
    m_loadedRunId.clear();
    m_runningPlaybookId.clear();
    m_stepTable->setRowCount(0);
    m_evidenceTable->setRowCount(0);
    m_runTable->setRowCount(0);
    m_evidenceLabel->setText(QStringLiteral("暂无执行证据"));
    m_cortexPanel->clearMessages();
    m_cortexPanel->setEngineInfo({});
    m_cortexPanel->setStatus({});
    m_reactEventIds.clear();
    m_payloadCardIds.clear();
    m_lastReactAction.clear();
    m_stopBtn->hide();
    m_statusLabel->setText(QStringLiteral("选择执行记录查看详情"));
    onRefreshRuns();
  }
  if (scoped && runId.isEmpty()) {
    m_statusLabel->setText(status == "awaiting_approval"
        ? QStringLiteral("当前任务尚未确认执行。使用顶部“确认预案并执行”审阅预案；此处仅显示本任务关联的执行记录。")
        : QStringLiteral("当前任务尚无关联执行记录，请查看上方任务进度。"));
    m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  }
}

// ── Execute ─────────────────────────────────────────────────────────
void ExecutionPage::onExecute() {
  if (!m_pipelineId.isEmpty()) return;
  QString playbookId = m_playbookCombo->currentData().toString();
  QString target = m_targetInput->text().trimmed();
  if (playbookId.isEmpty() || target.isEmpty()) {
    m_statusLabel->setText("请选择预案并填写目标地址后再执行。");
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
    m_tabWidget->setCurrentIndex(1);
    return;
  }

  // ── 执行前展示 playbook 计划，让用户了解要做什么、有哪些步骤 ──
  QJsonObject selPlaybook;
  for (int i = 0; i < m_allPlaybooks.size(); ++i) {
    auto p = m_allPlaybooks[i].toObject();
    if (p["playbook_id"].toString() == playbookId) { selPlaybook = p; break; }
  }
  if (!selPlaybook.isEmpty()) {
    QString pbName = selPlaybook["name"].toString();
    QString pbDesc = selPlaybook["description"].toString();
    QString pbDiff = selPlaybook["difficulty"].toString();
    auto ttArr = selPlaybook["target_type"].toArray();
    QStringList ttList;
    for (const auto &v : ttArr) ttList << v.toString();
    auto mitreArr = selPlaybook["mitre_techniques"].toArray();
    QStringList mitreList;
    for (const auto &v : mitreArr) mitreList << v.toString();
    QString teaching = selPlaybook["teaching_objective"].toString();

    // 基于 target_type 推断预期流程
    QString flow;
    if (ttList.contains("dvwa") || ttList.contains("web_url") || ttList.contains("web")) {
      flow = "1. 侦察 (whatweb)：识别 Web 服务、框架、版本\n"
             "2. 目录枚举 (gobuster/ffuf)：发现隐藏路径和攻击面\n"
             "3. 漏洞扫描 (nikto/nuclei)：检测已知漏洞和配置问题\n"
             "4. 注入测试 (sqlmap)：验证 SQL 注入等注入点\n"
             "5. 认证测试 (hydra)：暴力破解弱密码\n"
             "6. 利用验证：基于发现验证攻击路径";
    } else {
      flow = "1. 端口扫描 (nmap)：发现开放端口和服务\n"
             "2. 服务识别：指纹识别运行的服务\n"
             "3. 漏洞扫描：检测已知漏洞\n"
             "4. 利用：基于发现验证攻击路径";
    }

    QString planHtml = QString(
      "<h3>%1</h3>"
      "<p><b>描述：</b>%2</p>"
      "<p><b>目标：</b>%3 &nbsp;&nbsp; <b>难度：</b>%4 &nbsp;&nbsp; <b>目标类型：</b>%5</p>"
      "<p><b>MITRE 技术：</b>%6</p>"
      "%7"
      "<p><b>预期执行流程：</b></p>"
      "<pre style='font-family:monospace;background:#f5f5f5;padding:8px;'>%8</pre>"
      "<p style='color:#888;font-size:11px;'>⚠ ReAct 引擎会根据每步结果动态调整后续步骤，实际执行可能与此计划不同。</p>"
      "<p><b>是否开始执行？</b></p>")
      .arg(pbName, pbDesc.isEmpty() ? QStringLiteral("（无描述）") : pbDesc,
           target, pbDiff.isEmpty() ? QStringLiteral("未标注") : pbDiff,
           ttList.isEmpty() ? QStringLiteral("未指定") : ttList.join(", "),
           mitreList.isEmpty() ? QStringLiteral("未标注") : mitreList.join(", "),
           teaching.isEmpty() ? QString() : QString("<p><b>教学目标：</b>%1</p>").arg(teaching),
           flow);

    auto *msg = new QMessageBox(this);
    msg->setIcon(QMessageBox::Question);
    msg->setWindowTitle(QStringLiteral("执行计划确认"));
    msg->setText(planHtml);
    msg->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msg->button(QMessageBox::Yes)->setText(QStringLiteral("开始执行"));
    msg->button(QMessageBox::No)->setText(QStringLiteral("取消"));
    if (msg->exec() != QMessageBox::Yes) {
      return;  // 用户取消
    }
  }

  m_execBtn->setEnabled(false);
  m_execBtn->setText("创建中...");
  m_tabWidget->setCurrentIndex(1);

  // Save to history
  {
    QSettings settings("RedTeam", "RedTeam-Platform");
    QStringList history = settings.value("history/targets").toStringList();
    history.removeAll(target);
    history.prepend(target);
    while (history.size() > 20) history.removeLast();
    settings.setValue("history/targets", history);
    if (auto *c = m_targetInput->completer()) {
      auto *m = qobject_cast<QStringListModel*>(c->model());
      if (m) m->setStringList(history);
    }
  }

  QJsonObject body;
  body["playbook_id"] = playbookId;
  body["target"] = target;
  const int contextRevision = m_contextRevision;
  m_api->post("/api/runs", body, 5000, [this, playbookId, contextRevision](const QJsonObject &res) {
    if (contextRevision != m_contextRevision) return;
    if (res["status"].toString() != "ok") {
      m_execBtn->setEnabled(true);
      m_execBtn->setText("执行");
      m_statusLabel->setText("创建执行任务失败：" + res["error"].toObject()["message"].toString());
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }
    QString runId = res["data"].toObject()["run_id"].toString();
    if (runId.isEmpty()) {
      m_execBtn->setEnabled(true);
      m_execBtn->setText("执行");
      m_statusLabel->setText("创建执行任务失败：服务端未返回执行编号。");
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }

    QJsonObject empty;
    m_api->post("/api/runs/" + runId + "/execute", empty, 5000, [this, runId, playbookId, contextRevision](const QJsonObject &execRes) {
      if (contextRevision != m_contextRevision) return;
      m_execBtn->setEnabled(true);
      m_execBtn->setText("执行");
      if (execRes["status"].toString() != "ok") {
        m_statusLabel->setText("启动执行失败：" + execRes["error"].toObject()["message"].toString());
        m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
        onRefreshRuns();
        return;
      }
      m_targetInput->clear();
      // Track this run for real-time polling + auto-highlight
      m_runningRunId = runId;
      m_runningPlaybookId = playbookId;
      m_pollErrorCount = 0;
      m_pollTimer->start();
      // Immediately load this run's details (don't wait for full refresh)
      loadRunDetails(runId);
      // Refresh run list in background
      onRefreshRuns();
    });
  });
}

// ── Refresh runs ─────────────────────────────────────────────────────
void ExecutionPage::showEvent(QShowEvent *event) {
  QWidget::showEvent(event);
  onRefreshRuns();
}

void ExecutionPage::onRefreshRuns() {
  if (!m_pipelineId.isEmpty()) {
    m_taskMonitor->refresh();
    return;
  }
  const int contextRevision = m_contextRevision;
  m_api->get("/api/runs", 5000, [this, contextRevision](const QJsonObject &res) {
    if (contextRevision != m_contextRevision || res["status"].toString() != "ok") return;
    QJsonArray arr;
    for (const auto &value : res["data"].toArray()) {
      if (m_pipelineId.isEmpty() || value.toObject()["run_id"].toString() == m_pipelineRunId)
        arr.append(value);
    }
    const bool sortingEnabled = m_runTable->isSortingEnabled();
    m_runTable->setSortingEnabled(false);
    m_runTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      m_runTable->setItem(i, 0, new QTableWidgetItem(r["run_id"].toString()));
      m_runTable->setItem(i, 1, new QTableWidgetItem(r["playbook_id"].toString()));
      m_runTable->setItem(i, 2, new QTableWidgetItem(r["target"].toString()));
      QString runStatus = r["status"].toString();
      if (runStatus == "RUNNING") runStatus = "运行中";
      else if (runStatus == "PENDING") runStatus = "待执行";
      else if (runStatus == "COMPLETED") runStatus = "已完成";
      else if (runStatus == "FAILED") runStatus = "失败";
      else if (runStatus == "ABORTED") runStatus = "已中止";
      m_runTable->setItem(i, 3, new QTableWidgetItem(runStatus));
      m_runTable->setItem(i, 4, new QTableWidgetItem(r["created_at"].toString()));

      // Highlight running record
      if (!m_runningRunId.isEmpty() && r["run_id"].toString() == m_runningRunId) {
        QColor highlightBg(41, 121, 255, 40);  // semi-transparent blue
        for (int col = 0; col < m_runTable->columnCount(); col++) {
          if (auto *item = m_runTable->item(i, col)) {
            item->setBackground(highlightBg);
          }
        }
      }
    }


    m_runTable->setSortingEnabled(sortingEnabled);

    // Auto-select and show details for the running run
    const QString selectedRunId = m_loadedRunId.isEmpty() ? m_runningRunId : m_loadedRunId;
    for (int row = 0; row < m_runTable->rowCount(); ++row) {
      auto *item = m_runTable->item(row, 0);
      if (!selectedRunId.isEmpty() && item && item->text() == selectedRunId) {
        m_runTable->selectRow(row);
        m_runTable->scrollToItem(item);
        break;
      }
    }
  });
}

// ── Run clicked: load steps + evidence ──────────────────────────────
void ExecutionPage::onRunClicked(int row, int) {
  auto *runItem = m_runTable->item(row, 0);
  if (!runItem) return;
  QString runId = runItem->text();
  if (runId != m_runningRunId) {
    m_pollTimer->stop();
    m_runningRunId.clear();
    m_runningPlaybookId.clear();
    m_pollErrorCount = 0;
  }
  loadRunDetails(runId);
  // Auto-switch to detail tab
  m_tabWidget->setCurrentIndex(1);
}

// ── Load run details by ID (shared by onRunClicked and onExecute) ────
void ExecutionPage::onRunReact(const QJsonObject &data) {
  const QString runId = data.value(QStringLiteral("run_id")).toString();
  if (!m_pipelineId.isEmpty()) {
    if (!runId.isEmpty() && runId == m_pipelineRunId) m_taskMonitor->refresh();
    return;
  }
  if (runId.isEmpty() || runId != m_loadedRunId) return;
  const QString thought = data.value(QStringLiteral("thought")).toString();
  if (thought.isEmpty()) return;
  const int callIndex = data.value(QStringLiteral("react_call_count")).toInt();
  const int stepIndex = data.value(QStringLiteral("step_index")).toInt();
  const QString attemptId = data.value(QStringLiteral("attempt_id")).toVariant().toString();
  const QString toolId = data.value(QStringLiteral("tool_id")).toString();
  const QString action = data.value(QStringLiteral("action")).toString();
  const bool hasStableId = callIndex > 0 && !attemptId.isEmpty();
  const QString contentId = QStringLiteral("%1:%2:%3:%4")
      .arg(stepIndex).arg(toolId, action, thought);
  const QString eventId = hasStableId
      ? QStringLiteral("event:%1:%2").arg(attemptId).arg(callIndex)
      : QStringLiteral("legacy:%1").arg(contentId);
  const QString oppositeContentId = (hasStableId ? QStringLiteral("legacy-content:")
                                                 : QStringLiteral("stable-content:")) + contentId;
  if (m_reactEventIds.contains(eventId) || m_reactEventIds.contains(oppositeContentId)) return;
  m_reactEventIds.insert(eventId);
  m_reactEventIds.insert((hasStableId ? QStringLiteral("stable-content:")
                                     : QStringLiteral("legacy-content:")) + contentId);
  const QMap<QString, QString> actionLabels{
    {QStringLiteral("insert"), QStringLiteral("插入")},
    {QStringLiteral("adjust"), QStringLiteral("调整")},
    {QStringLiteral("parallel"), QStringLiteral("工具组插入（顺序执行）")},
    {QStringLiteral("pivot"), QStringLiteral("转向")},
    {QStringLiteral("stop"), QStringLiteral("终止")},
    {QStringLiteral("continue"), QStringLiteral("继续")}
  };
  QString observation = data.value(QStringLiteral("observation")).toString();
  if (observation.isEmpty()) observation = data.value(QStringLiteral("reason")).toString();
  const QString source = data.value(QStringLiteral("source")).toString();
  const bool isDynamic = source == QStringLiteral("react") ||
      (source.isEmpty() && (m_lastReactAction == QStringLiteral("insert") ||
       m_lastReactAction == QStringLiteral("parallel") ||
       m_lastReactAction == QStringLiteral("pivot")));
  m_cortexPanel->addReactThought(observation, thought,
      actionLabels.value(action, action.isEmpty() ? QStringLiteral("继续") : action),
      data.value(QStringLiteral("timestamp")).toString(), stepIndex,
      toolId, isDynamic, callIndex);
  m_lastReactAction = action;
}

void ExecutionPage::loadRunDetails(const QString &runId) {
  if (!m_pipelineId.isEmpty() && runId != m_pipelineRunId) return;
  if (!m_pipelineId.isEmpty()) {
    m_taskMonitor->refresh();
    return;
  }
  if (runId != m_loadedRunId) {
    ++m_runSelectionRevision;
    ++m_pollRequestRevision;
    m_pollRequestInFlight = false;
    m_cortexPanel->clearMessages();
    m_reactEventIds.clear();
    m_payloadCardIds.clear();
    m_lastReactAction.clear();
    m_loadedRunId = runId;
    emit runSelected(runId);
  }

  const int selectionRevision = m_runSelectionRevision;
  const int requestRevision = ++m_runDetailsRequestRevision;
  m_api->get("/api/runs/" + runId, 5000,
    [this, runId, selectionRevision, requestRevision](const QJsonObject &res) {
    if (selectionRevision != m_runSelectionRevision ||
        requestRevision != m_runDetailsRequestRevision ||
        runId != m_loadedRunId || res["status"].toString() != "ok") return;
    applyRunDetails(runId, res["data"].toObject(), selectionRevision);
  });
}

void ExecutionPage::applyRunDetails(const QString &runId, const QJsonObject &data,
                                    int selectionRevision) {
    if (selectionRevision != m_runSelectionRevision || runId != m_loadedRunId) return;
    const auto d = data;
    QJsonArray thoughts;
    const auto thoughtsValue = d.value(QStringLiteral("react_thoughts"));
    if (thoughtsValue.isArray()) {
      thoughts = thoughtsValue.toArray();
    } else if (thoughtsValue.isString()) {
      const auto thoughtsDocument = QJsonDocument::fromJson(thoughtsValue.toString().toUtf8());
      if (thoughtsDocument.isArray()) thoughts = thoughtsDocument.array();
    }
    for (int thoughtIndex = 0; thoughtIndex < thoughts.size(); ++thoughtIndex) {
      const auto thought = thoughts[thoughtIndex].toObject();
      onRunReact(QJsonObject{
        {QStringLiteral("run_id"), runId},
        {QStringLiteral("step_index"), thought.value(QStringLiteral("stepIndex"))},
        {QStringLiteral("tool_id"), thought.value(QStringLiteral("toolId"))},
        {QStringLiteral("attempt_id"), thought.value(QStringLiteral("attemptId"))},
        {QStringLiteral("react_call_count"), thought.value(QStringLiteral("callIndex")).toInt(thoughtIndex + 1)},
        {QStringLiteral("thought"), thought.value(QStringLiteral("thought"))},
        {QStringLiteral("action"), thought.value(QStringLiteral("action"))},
        {QStringLiteral("source"), thought.value(QStringLiteral("source"))},
        {QStringLiteral("timestamp"), thought.value(QStringLiteral("timestamp"))},
        {QStringLiteral("observation"), thought.value(QStringLiteral("observation"))},
        {QStringLiteral("reason"), thought.value(QStringLiteral("decision")).toObject().value(QStringLiteral("reason"))},
      });
    }

    // ── Status line with engine type ────────────────────────────────
    QString engineType = d["engine_type"].toString();
    QString stopReason = d["stop_reason"].toString();
    QString statusVal = d["status"].toString();
    m_cortexPanel->setEngineInfo(engineType.isEmpty() ? QStringLiteral("mechanical") : engineType);
    m_cortexPanel->setStatus(statusVal);
    // If this run is still running, ensure polling is active for live updates.
    // This covers onRunClicked (user clicking a running run in the list) —
    // without this, the detail page would freeze at the initial snapshot.
    if (statusVal == "RUNNING" || statusVal == "PENDING") {
      m_runningRunId = runId;
      if (!m_pollTimer->isActive()) m_pollTimer->start();
    }
    if (statusVal == "RUNNING") statusVal = "运行中";
    else if (statusVal == "PENDING") statusVal = "待执行";
    else if (statusVal == "COMPLETED") statusVal = "已完成";
    else if (statusVal == "FAILED") statusVal = "失败";
    else if (statusVal == "ABORTED") statusVal = "已中止";
    // Show playbook name (not just ID) in status line
    QString pbId = d["playbook_id"].toString();
    QString pbName = d["playbook_name"].toString();
    if (pbName.isEmpty()) pbName = pbId;
    const auto allSteps = d["steps"].toArray();
    int succeeded = 0, failed = 0;
    for (const auto &value : allSteps) {
      const auto outcome = value.toObject()["success"];
      if (!outcome.isBool() && !outcome.isDouble()) continue;
      if (outcome.toBool() || outcome.toInt() != 0) ++succeeded; else ++failed;
    }
    const auto resultCounts = d["result_counts"].toObject();
    const bool hasCanonicalCounts = resultCounts.value("known").isDouble()
        && resultCounts.value("returned").isDouble()
        && resultCounts.value("succeeded").isDouble()
        && resultCounts.value("failed").isDouble()
        && resultCounts.value("pending").isDouble();
    const int known = hasCanonicalCounts ? resultCounts.value("known").toInt() : allSteps.size();
    const int returned = hasCanonicalCounts ? resultCounts.value("returned").toInt() : succeeded + failed;
    succeeded = hasCanonicalCounts ? resultCounts.value("succeeded").toInt() : succeeded;
    failed = hasCanonicalCounts ? resultCounts.value("failed").toInt() : failed;
    const int pending = hasCanonicalCounts ? resultCounts.value("pending").toInt() : qMax(0, known - returned);
    const bool requiresAttention = hasCanonicalCounts && resultCounts.value("requires_attention").toBool();
    const bool terminalPending = hasCanonicalCounts && resultCounts.value("terminal_pending").toBool();
    QString statusText = QString("%1 · %2\n已返回 %3/%4 步结果  ·  成功 %5  ·  失败 %6  ·  证据 %7 条")
        .arg(pbName, statusVal).arg(returned).arg(known)
        .arg(succeeded).arg(failed).arg(d["evidence"].toArray().size());
    if (pending > 0) statusText += QString("  ·  待返回 %1").arg(pending);
    if (terminalPending) statusText += QStringLiteral("\n统计校验：任务已结束，但仍有步骤没有结果记录，请查看执行尝试。");
    else if (requiresAttention) statusText += QStringLiteral("\n统计校验：存在重复或缺失的步骤结果，请查看执行尝试。");
    if (!stopReason.isEmpty()) statusText += "\n停止原因：" + stopReason;
    const auto finalSummary=d["final_summary"].isObject() ? d["final_summary"].toObject()
      : QJsonDocument::fromJson(d["final_summary"].toString().toUtf8()).object();
    const auto agent=finalSummary["program_agent"].toObject();
    QString agentText;
    if(!agent.isEmpty()) {
      const QString state=agent["status"].toString();
      QString stateText=state;
      if(state=="evidence_collected") stateText="已收集证据，结论待复核";
      else if(state=="plan_finished") stateText="预定步骤已结束";
      else if(state=="unavailable") stateText="模型不可用，仅执行已有预案";
      else if(state=="invalid_decision") stateText="无效决策已拒绝，仅执行已有预案";
      else if(state=="budget_exhausted") stateText="已达到分析预算";
      else if(state=="needs_information") stateText="缺少验证条件";
      else if(state=="no_progress") stateText="没有更多有效进展";
      agentText=QString("测试端集中执行 · %1\n请求 %2 次，Agent 决策 %3 次\n%4\n\n")
        .arg(stateText).arg(agent["requests"].toInt()).arg(agent["decisions"].toInt()).arg(agent["reason"].toString());
      agentText+="执行成功不等于漏洞成立。以下内容为 Agent 观察和待复核评估。\n\n";
      auto appendItems=[&agentText](const QJsonArray &items,bool finding) {
        for(const auto &value:items) {
          const auto item=value.toObject();
          QStringList ids;for(const auto &id:item["evidence_ids"].toArray()) ids<<QString::number(id.toInt());
          agentText+=(finding ? QString("源码发现 #%1 · %2").arg(item["finding_id"].toInt()).arg(item["status"].toString())
                             : item["title"].toString())
            +"\n"+item["reason"].toString()+"\n引用证据 ID："+ids.join(", ")+"\n\n";
        }
      };
      appendItems(agent["observations"].toArray(),false);
      appendItems(agent["assessments"].toArray(),true);
      statusText+="\nAgent："+stateText+"；漏洞结论请复核证据。";
    } else agentText="本次执行按预案步骤运行，未启用动态追加请求。请在“执行步骤”和“证据”中查看结果；源码分析依据和复核结论在扫描结果中查看。执行完成不等于漏洞成立。";
    if(m_programReport->toPlainText()!=agentText) m_programReport->setPlainText(agentText);

    m_statusLabel->setTextFormat(Qt::PlainText);
    m_statusLabel->setToolTip(QString("执行编号：%1\n引擎：%2").arg(runId, engineType));
    m_statusLabel->setText(statusText);
    m_statusLabel->setStyleSheet(d["status"] == "FAILED" ? Theme::StatusErrorStyle :
        failed > 0 || requiresAttention ? Theme::StatusWarningStyle :
        d["status"] == "COMPLETED" ? Theme::StatusSuccessStyle : Theme::StatusInfoStyle);

    // ── Build evidence lookup: step_index → payload info ────────────
    auto evidence = d["evidence"].toArray();
    QMap<int, QJsonObject> evidenceByStep;
    for (int i = 0; i < evidence.size(); i++) {
      auto e = evidence[i].toObject();
      int stepIdx = e["step_index"].toInt();
      evidenceByStep.insert(stepIdx, e);
    }

    // ── Steps (7 columns: 步骤/工具/参数/成功/来源/输出摘要/载荷) ──
    auto steps = d["steps"].toArray();
    m_stepTable->setRowCount(steps.size());
    QString prevActionType;  // track previous step's react_action to detect dynamic inserts

    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      int stepIdx = s["step_index"].toInt();
      m_stepTable->setItem(i, 0, new QTableWidgetItem(QString::number(stepIdx)));
      m_stepTable->setItem(i, 1, new QTableWidgetItem(s["tool_id"].toString()));
      m_stepTable->setItem(i, 2, truncItem(s["args"].toString(), 40));
      const auto outcome = s["success"];
      const bool reported = outcome.isBool() || outcome.isDouble();
      const bool success = reported && (outcome.toBool() || outcome.toInt() != 0);
      const bool terminal = QStringList{"COMPLETED", "FAILED", "ABORTED"}.contains(d["status"].toString());
      auto *resultItem = new QTableWidgetItem(!reported ? (terminal ? QStringLiteral("结果未返回") : QStringLiteral("等待结果")) :
                                             success ? QStringLiteral("✓ 成功") : QStringLiteral("✕ 失败"));
      resultItem->setForeground(QColor(!reported ? "#64748b" : success ? "#15803d" : "#b91c1c"));
      resultItem->setBackground(QColor(!reported ? "#f8fafc" : success ? "#f0fdf4" : "#fff1f2"));
      resultItem->setTextAlignment(Qt::AlignCenter);
      m_stepTable->setItem(i, 3, resultItem);

      // Column 4: 来源 — mark dynamic steps inserted by ReAct
      bool isDynamic = s["source"].toString() == QStringLiteral("react") ||
                       (s["source"].toString().isEmpty() && (prevActionType == QStringLiteral("insert") ||
                        prevActionType == QStringLiteral("parallel") ||
                        prevActionType == QStringLiteral("pivot")));
      auto *sourceItem = new QTableWidgetItem(isDynamic ? QStringLiteral("AI 插入") : QStringLiteral("预案"));
      if (isDynamic) {
        sourceItem->setForeground(QColor("#7c3aed"));
        QFont f = sourceItem->font(); f.setBold(true); sourceItem->setFont(f);
      } else {
        sourceItem->setForeground(QColor("#64748b"));
      }
      m_stepTable->setItem(i, 4, sourceItem);

      {
        QString notesFull = s["notes"].toString();
        QString summary = s["description"].toString().simplified();
        if (summary.isEmpty()) {
          const auto lines = notesFull.split('\n');
          const QRegularExpression meaningful(QStringLiteral("[\\p{L}\\p{N}]{2,}"));
          for (const auto &line : lines) {
            if (meaningful.match(line).hasMatch()) { summary = line.simplified(); break; }
          }
        }
        if (summary.isEmpty()) summary = notesFull.isEmpty() ? QStringLiteral("暂无输出") : QStringLiteral("双击查看完整输出");
        auto *notesItem = truncItem(notesFull, 60);
        notesItem->setText(summary.left(120));
        notesItem->setToolTip(wrapToolTip(notesFull));
        m_stepTable->setItem(i, 5, notesItem);
      }

      // Column 6: Payload — only show when a real payload binding exists
      // in evidence_data; otherwise show "—" (the command is already in 参数).
      QString payloadDisplay = QStringLiteral("—");
      if (evidenceByStep.contains(stepIdx)) {
        auto evObj = evidenceByStep.value(stepIdx);
        QJsonDocument evDoc = QJsonDocument::fromJson(evObj["evidence_data"].toString().toUtf8());
        if (evDoc.isObject()) {
          auto evData = evDoc.object();
          if (evData.contains("payload_id")) {
            payloadDisplay = evData["payload_name"].toString();
            if (payloadDisplay.isEmpty()) payloadDisplay = evData["payload_id"].toString();
          }
        }
      }
      auto *payloadItem = new QTableWidgetItem(payloadDisplay);
      if (payloadDisplay == QStringLiteral("—"))
        payloadItem->setForeground(QColor("#94a3b8"));  // muted gray for no payload
      m_stepTable->setItem(i, 6, payloadItem);

      // Track this step's action type for next iteration's dynamic detection
      QString actionJson = s["react_action"].toString();
      if (!actionJson.isEmpty()) {
        QJsonDocument actDoc = QJsonDocument::fromJson(actionJson.toUtf8());
        if (actDoc.isObject()) {
          prevActionType = actDoc.object()["type"].toString();
        } else {
          prevActionType.clear();
        }
      } else {
        prevActionType.clear();
      }
      if (thoughts.isEmpty()) {
        onRunReact(QJsonObject{
          {QStringLiteral("run_id"), runId},
          {QStringLiteral("step_index"), stepIdx},
          {QStringLiteral("tool_id"), s["tool_id"]},
          {QStringLiteral("thought"), s["react_thought"]},
          {QStringLiteral("action"), prevActionType},
          {QStringLiteral("observation"), s["notes"].toString().left(200)},
          {QStringLiteral("source"), isDynamic ? QStringLiteral("react") : QStringLiteral("playbook")}
        });
      }
    }



    // ── Evidence ────────────────────────────────────────────────────
    m_evidenceLabel->setText(QString("攻击证据: %1 条").arg(evidence.size()));
    m_evidenceTable->setRowCount(evidence.size());
    for (int i = 0; i < evidence.size(); i++) {
      auto e = evidence[i].toObject();
      m_evidenceTable->setItem(i, 0, new QTableWidgetItem(QString::number(e["step_index"].toInt())));
      m_evidenceTable->setItem(i, 1, new QTableWidgetItem(e["evidence_type"].toString()));

      // 数据摘要: parse evidence_data JSON → readable summary; full JSON in UserRole
      QString evDataRaw = e["evidence_data"].toString();
      QString evSummary;
      QString evFull = evDataRaw;
      QJsonDocument evDoc = QJsonDocument::fromJson(evDataRaw.toUtf8());
      if (evDoc.isObject()) {
        auto evObj = evDoc.object();
        evSummary = evObj["summary"].toString();
        const auto comparison=evObj["source_comparison"].toObject();
        if(!comparison.isEmpty()) evSummary=comparison["status"].toString()=="matched" ? "观察符合预案条件，待复核" : comparison["status"].toString()=="not_matched" ? "本次观察未符合条件" : "判定条件不足";
        if (evSummary.isEmpty()) {
          QStringList parts;
          if (evObj.contains("success"))
            parts << (evObj["success"].toBool() ? QStringLiteral("成功") : QStringLiteral("失败"));
          if (evObj.contains("payload_name"))
            parts << QStringLiteral("载荷: ") + evObj["payload_name"].toString();
          evSummary = parts.join(QStringLiteral(" | "));
        }
        evFull = QString::fromUtf8(QJsonDocument(evObj).toJson(QJsonDocument::Indented));
      }
      if (evSummary.isEmpty()) evSummary = QStringLiteral("(无摘要)");
      auto *evItem = new QTableWidgetItem(evSummary.length() > 50 ? evSummary.left(50) + QStringLiteral("…") : evSummary);
      evItem->setData(Qt::UserRole, evFull);
      evItem->setToolTip(wrapToolTip(evFull));
      m_evidenceTable->setItem(i, 2, evItem);

      // MITRE命中: parse array → "T1110, T1046"; full "ID — name" list in UserRole
      QString mitreRaw = e["mitre_hits"].toString();
      QString mitreDisplay;
      QString mitreFull;
      QJsonDocument mitreDoc = QJsonDocument::fromJson(mitreRaw.toUtf8());
      if (mitreDoc.isArray()) {
        QStringList ids, fullLines;
        for (const auto &m : mitreDoc.array()) {
          if (m.isString()) {
            ids << m.toString();
            fullLines << m.toString();
          } else if (m.isObject()) {
            auto mo = m.toObject();
            QString id = mo["id"].toString();
            ids << id;
            fullLines << id + (mo.contains("name") ? QStringLiteral(" — ") + mo["name"].toString() : QString());
          }
        }
        mitreDisplay = ids.join(QStringLiteral(", "));
        mitreFull = fullLines.join(QStringLiteral("\n"));
      }
      if (mitreDisplay.isEmpty()) mitreDisplay = QStringLiteral("—");
      auto *mitreItem = new QTableWidgetItem(mitreDisplay.length() > 30 ? mitreDisplay.left(30) + QStringLiteral("…") : mitreDisplay);
      mitreItem->setData(Qt::UserRole, mitreFull.isEmpty() ? mitreDisplay : mitreFull);
      m_evidenceTable->setItem(i, 3, mitreItem);

      // 建议: parse array → joined strings; full bullet list in UserRole
      QString recRaw = e["recommendations"].toString();
      QString recDisplay;
      QString recFull;
      QJsonDocument recDoc = QJsonDocument::fromJson(recRaw.toUtf8());
      if (recDoc.isArray()) {
        QStringList recs, fullRecs;
        for (const auto &r : recDoc.array()) {
          if (r.isString()) {
            recs << r.toString();
            fullRecs << QStringLiteral("• ") + r.toString();
          }
        }
        recDisplay = recs.join(QStringLiteral("; "));
        recFull = fullRecs.join(QStringLiteral("\n"));
      }
      if (recDisplay.isEmpty()) recDisplay = QStringLiteral("—");
      auto *recItem = new QTableWidgetItem(recDisplay.length() > 40 ? recDisplay.left(40) + QStringLiteral("…") : recDisplay);
      recItem->setData(Qt::UserRole, recFull.isEmpty() ? recDisplay : recFull);
      m_evidenceTable->setItem(i, 4, recItem);

      const QString payloadId = evDoc.object()["payload_id"].toString();
      const int stepIndex = e["step_index"].toInt();
      const QString cardId = QStringLiteral("%1:%2").arg(stepIndex).arg(payloadId);
      if (payloadId.isEmpty() || m_payloadCardIds.contains(cardId)) continue;
      m_payloadCardIds.insert(cardId);
      const int revision = m_contextRevision;
      m_api->get("/api/payloads/" + payloadId, 5000,
        [this, runId, payloadId, stepIndex, cardId, revision, selectionRevision](const QJsonObject &payloadResponse) {
          if (runId != m_loadedRunId || revision != m_contextRevision ||
              selectionRevision != m_runSelectionRevision) return;
          if (payloadResponse["status"].toString() != "ok") {
            m_payloadCardIds.remove(cardId);
            return;
          }
          const auto payload = payloadResponse["data"].toObject();
          const auto payloadData = payload["payload_data"].toObject();
          const auto localizedText = [](const QJsonValue &value) {
            if (value.isString()) return value.toString();
            const auto object = value.toObject();
            return object["zh"].toString(object["en"].toString());
          };
          QString name = localizedText(payload["name"]);
          if (name.isEmpty()) name = payloadId;
          QStringList context;
          const QString principle = localizedText(payload["description"]);
          const QString defense = localizedText(payloadData["defense"]);
          if (!principle.isEmpty()) context << QStringLiteral("【载荷原理】") + principle;
          if (!defense.isEmpty()) context << QStringLiteral("【防御手段】") + defense;
          QStringList bypasses;
          for (const auto &value : payloadData["bypass_variants"].toArray()) {
            const auto variant = value.toObject();
            bypasses << QStringLiteral("%1: %2")
                .arg(localizedText(variant["title"]), variant["command"].toString());
          }
          if (!bypasses.isEmpty()) context << QStringLiteral("【绕过变体】\n") + bypasses.join('\n');
          QStringList tips;
          for (const auto &value : payloadData["opsec_tips"].toArray()) {
            const QString tip = localizedText(value);
            if (!tip.isEmpty()) tips << tip;
          }
          if (!tips.isEmpty()) context << QStringLiteral("【OPSEC建议】\n") + tips.join('\n');
          m_cortexPanel->addPayloadCard(name, context.join(QStringLiteral("\n\n")), {}, stepIndex);
        });
    }



    // Stop button: visible and enabled only for active runs.
    // NOTE: statusVal has been converted to Chinese above (e.g. "运行中"),
    // so use the original raw status from the API for button logic.
    {
      QString rawStatus = d["status"].toString();
      bool canStop = (rawStatus == "RUNNING" || rawStatus == "PENDING");
      m_stopBtn->setEnabled(canStop);
      m_stopBtn->setVisible(canStop);
      if (canStop)
        m_stopBtn->setText(QStringLiteral("🛑 停止执行"));
      else if (rawStatus == "ABORTED")
        m_stopBtn->setText(QStringLiteral("🛑 已中止"));
      else if (rawStatus == "COMPLETED")
        m_stopBtn->setText(QStringLiteral("✓ 已完成"));
      else if (rawStatus == "FAILED")
        m_stopBtn->setText(QStringLiteral("✗ 已失败"));
      else
        m_stopBtn->setText(QStringLiteral("🛑 停止执行"));
    }

}

// ── Poll running execution for real-time updates ─────────────────────
void ExecutionPage::onPollRunning() {
  if (m_runningRunId.isEmpty()) {
    m_pollTimer->stop();
    return;
  }
  if (m_pollRequestInFlight) return;

  const QString runId = m_runningRunId;
  const int contextRevision = m_contextRevision;
  const int selectionRevision = m_runSelectionRevision;
  const int pollRequestRevision = ++m_pollRequestRevision;
  m_pollRequestInFlight = true;
  m_api->get("/api/runs/" + runId, 5000,
    [this, runId, contextRevision, selectionRevision, pollRequestRevision](const QJsonObject &res) {
    if (pollRequestRevision != m_pollRequestRevision) return;
    m_pollRequestInFlight = false;
    if (contextRevision != m_contextRevision ||
        selectionRevision != m_runSelectionRevision ||
        m_runningRunId != runId) return;
    if (res["status"].toString() != "ok") {
      // API error — tolerate transient failures, then stop polling to avoid spin
      if (++m_pollErrorCount >= 10) {
        m_pollTimer->stop();
        m_runningRunId.clear();
        m_runningPlaybookId.clear();
        m_statusLabel->setText(QStringLiteral("轮询失败：无法获取执行状态（已连续失败 10 次）"));
        m_stopBtn->setEnabled(false);
      }
      return;
    }
    m_pollErrorCount = 0;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    // The polling response already contains the full run details. Render it
    // directly so terminal handling cannot race with a second GET.
    ++m_runDetailsRequestRevision;
    applyRunDetails(runId, d, selectionRevision);


    // Stop button: always visible, enabled only for active runs
    {
      bool canStop = (status == "RUNNING" || status == "PENDING");
      m_stopBtn->setEnabled(canStop);
      m_stopBtn->setVisible(canStop);
      if (canStop)
        m_stopBtn->setText(QStringLiteral("🛑 停止执行"));
      else if (status == "ABORTED")
        m_stopBtn->setText(QStringLiteral("🛑 已中止"));
      else if (status == "COMPLETED")
        m_stopBtn->setText(QStringLiteral("✓ 已完成"));
      else if (status == "FAILED")
        m_stopBtn->setText(QStringLiteral("✗ 已失败"));
    }

    // loadRunDetails renders the same summary for initial load and polling.

    // Terminal state — stop polling
    if (status != "RUNNING" && status != "PENDING") {
      m_pollTimer->stop();
      QString finishedRunId = m_runningRunId;
      m_runningRunId.clear();
      m_runningPlaybookId.clear();
      // Full refresh to update final state
      onRefreshRuns();
      // Notify listeners (e.g. EvaluatePage) to focus this run
      if (!finishedRunId.isEmpty()) {
        emit runCompleted(finishedRunId);
      }
    }
  });
}

// ── Popup dialog for expanded cell content (double-click) ──────────────
void ExecutionPage::showCellDetail(const QString &title, const QString &content) {
  if (content.isEmpty()) return;
  auto *dlg = new QDialog(this);
  dlg->setWindowTitle(title);
  dlg->setMinimumSize(600, 400);
  auto *l = new QVBoxLayout(dlg);
  l->setContentsMargins(12, 12, 12, 12);
  auto *te = new QTextEdit(dlg);
  te->setPlainText(content);
  te->setReadOnly(true);
  te->setStyleSheet("QTextEdit { font-size: 13px; font-family: 'Monospace'; "
                    "background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; }");
  l->addWidget(te);
  auto *btn = new QPushButton(QStringLiteral("关闭"), dlg);
  btn->setProperty("primary", true);
  btn->setFixedWidth(100);
  auto *btnL = new QHBoxLayout;
  btnL->addStretch();
  btnL->addWidget(btn);
  btnL->addStretch();
  l->addLayout(btnL);
  connect(btn, &QPushButton::clicked, dlg, &QDialog::accept);
  dlg->exec();
  dlg->deleteLater();
}
