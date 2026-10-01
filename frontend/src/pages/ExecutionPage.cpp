#include "ExecutionPage.h"
#include "../Theme.h"
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
  loadPlaybooks();
  onRefreshRuns();

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
  m_tabWidget = new QTabWidget(this);

  // ── Tab 1: 执行记录 ────────────────────────────────────────────────
  auto *tab1 = new QWidget;
  auto *tab1Layout = new QVBoxLayout(tab1);
  tab1Layout->setContentsMargins(8, 8, 8, 8);

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
  tab1Layout->addLayout(catH);
  connect(m_catGroup, QOverload<int>::of(&QButtonGroup::buttonClicked),
          this, &ExecutionPage::onAttackCategoryChanged);

  // ── Top: select playbook + target + execute ────────────────────────
  auto *h1 = new QHBoxLayout;
  h1->addWidget(new QLabel("预案:"));
  m_playbookCombo = new QComboBox;
  h1->addWidget(m_playbookCombo, 1);
  h1->addWidget(new QLabel("目标:"));
  m_targetInput = new QLineEdit;
  m_targetInput->setPlaceholderText("例: 192.168.1.1");
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
  tab1Layout->addLayout(h1);
  connect(m_execBtn, &QPushButton::clicked, this, &ExecutionPage::onExecute);

  // ── Run list ──────────────────────────────────────────────────────
  auto *runLabel = new QLabel("执行记录"); runLabel->setStyleSheet(Theme::SectionStyle);
  tab1Layout->addWidget(runLabel);
  m_runTable = new QTableWidget(0, 5);
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

  // ── Tab 2: 执行详情 (左右分栏: Cortex + 步骤/证据) ─────────────────
  auto *tab2 = new QWidget;
  auto *tab2Layout = new QHBoxLayout(tab2);
  tab2Layout->setContentsMargins(0, 0, 0, 0);
  tab2Layout->setSpacing(0);

  // ── Left: Cortex decision panel ────────────────────────────────────
  m_cortexPanel = new CortexPanel(m_api);

  // ── Right: Step details + Evidence ─────────────────────────────────
  auto *rightWidget = new QWidget;
  auto *rightScroll = new QScrollArea;
  rightScroll->setWidgetResizable(true);
  rightScroll->setFrameShape(QFrame::NoFrame);
  auto *rightInner = new QWidget;
  auto *rightLayout = new QVBoxLayout(rightInner);
  rightLayout->setContentsMargins(8, 8, 8, 8);

  // Status + stop button row
  auto *statusRow = new QHBoxLayout;
  statusRow->setSpacing(8);
  m_statusLabel = new QLabel;
  statusRow->addWidget(m_statusLabel, 1);

  m_stopBtn = new QPushButton(QStringLiteral("🛑 停止执行"));
  m_stopBtn->setFixedSize(110, 32);
  m_stopBtn->setCursor(Qt::PointingHandCursor);
  m_stopBtn->setStyleSheet(
    "QPushButton { background: #ef4444; color: #ffffff; border: none; "
    "border-radius: 6px; font-size: 12px; font-weight: bold; }"
    "QPushButton:hover { background: #dc2626; }"
    "QPushButton:pressed { background: #b91c1c; }"
    "QPushButton:disabled { background: #fca5a5; color: #fef2f2; }");
  m_stopBtn->setEnabled(false);  // disabled until a running run is loaded
  m_stopBtn->setToolTip(QStringLiteral("点击中止当前执行\n当前步骤完成后不再执行后续步骤"));
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
  m_stepTable = new QTableWidget(0, 8);
  m_stepTable->setHorizontalHeaderLabels({"步骤", "工具", "参数", "成功", "来源", "输出摘要", "载荷", "推理"});
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
  m_stepTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
  rightLayout->addWidget(m_stepTable, 1);

  // Evidence
  m_evidenceLabel = new QLabel;
  rightLayout->addWidget(m_evidenceLabel);
  auto *evLabel = new QLabel("攻击证据"); evLabel->setStyleSheet(Theme::SectionStyle);
  rightLayout->addWidget(evLabel);
  m_evidenceTable = new QTableWidget(0, 5);
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

  rightScroll->setWidget(rightInner);
  auto *rightOuterLayout = new QVBoxLayout(rightWidget);
  rightOuterLayout->setContentsMargins(0, 0, 0, 0);
  rightOuterLayout->addWidget(rightScroll);

  // ── Splitter: Cortex (left) | Details (right) ──────────────────────
  auto *splitter = new QSplitter(Qt::Horizontal);
  splitter->addWidget(m_cortexPanel);
  splitter->addWidget(rightWidget);
  splitter->setStretchFactor(0, 2);  // Cortex: 40%
  splitter->setStretchFactor(1, 3);  // Details: 60%
  splitter->setSizes({380, 570});
  tab2Layout->addWidget(splitter);

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
  connect(m_stepTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int col) {
    auto *item = m_stepTable->item(row, col);
    if (!item) return;
    QString full = item->data(Qt::UserRole).toString();
    if (full.isEmpty()) full = item->text();
    if (full.isEmpty() || full == QStringLiteral("-")) return;
    QString colTitle = m_stepTable->horizontalHeaderItem(col)->text();
    showCellDetail(QStringLiteral("步骤 %1 — %2").arg(row + 1).arg(colTitle), full);
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

// ── Show a specific run (public, used by FlowPage workbench) ──────────
void ExecutionPage::showRun(const QString &runId)
{
  if (runId.isEmpty()) return;
  // Track as the running run so the poll timer keeps the step table, evidence,
  // and status label live.  onPollRunning stops automatically at a terminal
  // state, so a completed run costs at most one extra GET.
  m_runningRunId = runId;
  if (!m_pollTimer->isActive()) m_pollTimer->start();
  // Refresh the run table so the target run appears, then load its details
  onRefreshRuns();
  loadRunDetails(runId);
  // Switch to the detail tab so step progress / evidence / Cortex are visible
  m_tabWidget->setCurrentIndex(1);
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

// ── Execute ─────────────────────────────────────────────────────────
void ExecutionPage::onExecute() {
  QString playbookId = m_playbookCombo->currentData().toString();
  QString target = m_targetInput->text().trimmed();
  if (playbookId.isEmpty() || target.isEmpty()) {
    m_statusLabel->setText("请选择预案并填写目标地址后再执行。");
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
    m_tabWidget->setCurrentIndex(1);
    return;
  }

  m_execBtn->setEnabled(false);
  m_execBtn->setText("创建中...");

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
  m_api->post("/api/runs", body, 5000, [this, playbookId](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      m_execBtn->setEnabled(true);
      m_execBtn->setText("执行");
      m_statusLabel->setText("创建执行任务失败：" + res["error"].toObject()["message"].toString());
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      m_tabWidget->setCurrentIndex(1);
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
    m_api->post("/api/runs/" + runId + "/execute", empty, 5000, [this, runId, playbookId](const QJsonObject &execRes) {
      m_execBtn->setEnabled(true);
      m_execBtn->setText("执行");
      if (execRes["status"].toString() != "ok") {
        m_statusLabel->setText("启动执行失败：" + execRes["error"].toObject()["message"].toString());
        m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
        m_tabWidget->setCurrentIndex(1);
        onRefreshRuns();
        return;
      }
      m_targetInput->clear();
      // Track this run for real-time polling + auto-highlight
      m_runningRunId = runId;
      m_runningPlaybookId = playbookId;
      // Clear Cortex for new execution
      m_cortexPanel->clearMessages();
      m_injectedReactSteps.clear();
      m_injectedPayloadSteps.clear();
      m_pollTimer->start();
      // Immediately load this run's details (don't wait for full refresh)
      loadRunDetails(runId);
      // Switch to detail tab to show execution progress
      m_tabWidget->setCurrentIndex(1);
      // Refresh run list in background
      onRefreshRuns();
    });
  });
}

// ── Refresh runs ─────────────────────────────────────────────────────
void ExecutionPage::onRefreshRuns() {
  m_api->get("/api/runs", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    const bool sortingEnabled = m_runTable->isSortingEnabled();
    m_runTable->setSortingEnabled(false);
    m_runTable->setRowCount(arr.size());
    int highlightRow = -1;
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
        highlightRow = i;
        QColor highlightBg(41, 121, 255, 40);  // semi-transparent blue
        for (int col = 0; col < m_runTable->columnCount(); col++) {
          if (auto *item = m_runTable->item(i, col)) {
            item->setBackground(highlightBg);
          }
        }
      }
    }
    m_runTable->resizeColumnsToContents();
    m_runTable->horizontalHeader()->setStretchLastSection(true);
    m_runTable->setSortingEnabled(sortingEnabled);

    // Auto-select and show details for the running run
    if (highlightRow >= 0) {
      m_runTable->selectRow(highlightRow);
      m_runTable->scrollToItem(m_runTable->item(highlightRow, 0));
      onRunClicked(highlightRow, 0);
    }
  });
}

// ── Real-time ReAct reasoning from WebSocket (run:react) ─────────────
void ExecutionPage::onRunReact(const QJsonObject &data) {
  QString runId = data["run_id"].toString();
  // Only display if this is the currently loaded/running run
  if (runId != m_loadedRunId && runId != m_runningRunId) return;

  int stepIdx = data["step_index"].toInt();
  QString stepKey = QStringLiteral("react_%1").arg(stepIdx);
  if (m_injectedReactSteps.contains(stepKey)) return;  // dedup
  m_injectedReactSteps.insert(stepKey);

  QString thought = data["thought"].toString();
  if (thought.isEmpty()) return;

  // Parse action
  QString actionStr = data["action"].toString();
  if (actionStr.isEmpty()) actionStr = QStringLiteral("continue");

  // Map action to Chinese label
  QString actionLabel;
  if (actionStr == QStringLiteral("insert")) actionLabel = QStringLiteral("🔀 插入");
  else if (actionStr == QStringLiteral("adjust")) actionLabel = QStringLiteral("🔧 调整");
  else if (actionStr == QStringLiteral("parallel")) actionLabel = QStringLiteral("⚡ 并行");
  else if (actionStr == QStringLiteral("pivot")) actionLabel = QStringLiteral("🔄 转向");
  else if (actionStr == QStringLiteral("stop")) actionLabel = QStringLiteral("🛑 终止");
  else actionLabel = QStringLiteral("▶ 继续");

  // Observation = tool_id + step info
  QString observation = QStringLiteral("Step %1 [%2]").arg(stepIdx).arg(data["tool_id"].toString());

  // Determine if this step was dynamically inserted by ReAct
  bool isDynamic = (m_lastReactAction == QStringLiteral("insert") ||
                    m_lastReactAction == QStringLiteral("parallel") ||
                    m_lastReactAction == QStringLiteral("pivot"));

  m_cortexPanel->addReactThought(observation, thought, actionLabel, {},
                                  stepIdx, data["tool_id"].toString(), isDynamic);
  m_lastReactAction = actionStr;
}

// ── Run clicked: load steps + evidence ──────────────────────────────
void ExecutionPage::onRunClicked(int row, int) {
  auto *runItem = m_runTable->item(row, 0);
  if (!runItem) return;
  QString runId = runItem->text();
  loadRunDetails(runId);
  // Auto-switch to detail tab
  m_tabWidget->setCurrentIndex(1);
}

// ── Load run details by ID (shared by onRunClicked and onExecute) ────
void ExecutionPage::loadRunDetails(const QString &runId) {
  if (runId != m_loadedRunId) {
    m_cortexPanel->clearMessages();
    m_injectedReactSteps.clear();
    m_injectedPayloadSteps.clear();
    m_lastReactAction.clear();
    m_loadedRunId = runId;
  }

  m_api->get("/api/runs/" + runId, 5000, [this, runId](const QJsonObject &res) {
    if (runId != m_loadedRunId || res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();

    // ── Status line with engine type ────────────────────────────────
    QString engineType = d["engine_type"].toString();
    QString stopReason = d["stop_reason"].toString();
    QString statusVal = d["status"].toString();
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
    QString statusText = QString("执行: %1 | 预案: %2 | 状态: %3 | 引擎: %4")
        .arg(d["run_id"].toString(), pbName, statusVal,
             engineType.isEmpty() ? "机械" : engineType);
    if (!stopReason.isEmpty()) {
      statusText += " | 停止原因: " + stopReason;
    }
    m_statusLabel->setText(statusText);
    m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);

    // ── Build evidence lookup: step_index → payload info ────────────
    auto evidence = d["evidence"].toArray();
    QMap<int, QJsonObject> evidenceByStep;
    for (int i = 0; i < evidence.size(); i++) {
      auto e = evidence[i].toObject();
      int stepIdx = e["step_index"].toInt();
      evidenceByStep.insert(stepIdx, e);
    }

    // ── Steps (8 columns: 步骤/工具/参数/成功/来源/输出摘要/载荷/推理) ──
    auto steps = d["steps"].toArray();
    m_stepTable->setRowCount(steps.size());
    QString prevActionType;  // track previous step's react_action to detect dynamic inserts

    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      int stepIdx = s["step_index"].toInt();
      m_stepTable->setItem(i, 0, new QTableWidgetItem(QString::number(stepIdx)));
      m_stepTable->setItem(i, 1, new QTableWidgetItem(s["tool_id"].toString()));
      m_stepTable->setItem(i, 2, truncItem(s["args"].toString(), 40));
      m_stepTable->setItem(i, 3, new QTableWidgetItem(s["success"].toInt() ? "✓ 成功" : "✗ 失败"));

      // Column 4: 来源 — mark dynamic steps inserted by ReAct
      bool isDynamic = (prevActionType == QStringLiteral("insert") ||
                        prevActionType == QStringLiteral("parallel") ||
                        prevActionType == QStringLiteral("pivot"));
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
        auto *notesItem = truncItem(notesFull, 60);
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

      // Column 7: ReAct thought summary, or step description as fallback
      QString thought = s["react_thought"].toString();
      if (!thought.isEmpty()) {
        m_stepTable->setItem(i, 7, truncItem(thought, 40));
      } else {
        // Fallback: show step description as "reasoning"
        QString stepDesc = s["description"].toString();
        if (stepDesc.isEmpty()) stepDesc = s["notes"].toString();
        if (!stepDesc.isEmpty()) {
          m_stepTable->setItem(i, 7, truncItem(stepDesc, 40));
        } else {
          m_stepTable->setItem(i, 7, new QTableWidgetItem("—"));
        }
      }

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
    }
    m_stepTable->resizeColumnsToContents();
    m_stepTable->horizontalHeader()->setStretchLastSection(true);

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
    }
    m_evidenceTable->resizeColumnsToContents();
    m_evidenceTable->horizontalHeader()->setStretchLastSection(true);

    // ── Cortex panel: ReAct thoughts + Payload cards ──────────────────
    // Update engine info and status in Cortex header
    m_cortexPanel->setEngineInfo(engineType.isEmpty() ? QStringLiteral("mechanical") : engineType);
    m_cortexPanel->setStatus(statusVal);
    // Stop button: always visible, but only enabled for active runs.
    // NOTE: statusVal has been converted to Chinese above (e.g. "运行中"),
    // so use the original raw status from the API for button logic.
    {
      QString rawStatus = d["status"].toString();
      bool canStop = (rawStatus == "RUNNING" || rawStatus == "PENDING");
      m_stopBtn->setEnabled(canStop);
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

    // Inject ReAct thoughts as structured cards (only new ones)
    QString cortexPrevAction;  // track for dynamic step detection
    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      int stepIdx = s["step_index"].toInt();
      QString thought = s["react_thought"].toString();
      if (thought.isEmpty()) {
        // Still track action for dynamic detection even if no thought
        QString aj = s["react_action"].toString();
        if (!aj.isEmpty()) {
          QJsonDocument ad = QJsonDocument::fromJson(aj.toUtf8());
          if (ad.isObject()) cortexPrevAction = ad.object()["type"].toString();
        }
        continue;
      }

      QString stepKey = QStringLiteral("react_%1").arg(stepIdx);

      // Parse action (needed for both dynamic detection and display)
      QString actionStr;
      QString actionJson = s["react_action"].toString();
      if (!actionJson.isEmpty()) {
        QJsonDocument actDoc = QJsonDocument::fromJson(actionJson.toUtf8());
        if (actDoc.isObject()) {
          actionStr = actDoc.object()["type"].toString();
        }
      }
      if (actionStr.isEmpty()) actionStr = QStringLiteral("continue");

      // Skip if already injected, but still update cortexPrevAction for dynamic detection
      if (m_injectedReactSteps.contains(stepKey)) {
        cortexPrevAction = actionStr;
        continue;
      }
      m_injectedReactSteps.insert(stepKey);

      // Map action to Chinese label
      QString actionLabel;
      if (actionStr == QStringLiteral("insert")) actionLabel = QStringLiteral("🔀 插入");
      else if (actionStr == QStringLiteral("adjust")) actionLabel = QStringLiteral("🔧 调整");
      else if (actionStr == QStringLiteral("parallel")) actionLabel = QStringLiteral("⚡ 并行");
      else if (actionStr == QStringLiteral("stop")) actionLabel = QStringLiteral("🛑 终止");
      else actionLabel = QStringLiteral("▶ 继续");

      // Extract observation from step notes (first line of output)
      QString observation = s["notes"].toString().left(200);

      // Determine if this step was dynamically inserted
      bool isDynamic = (cortexPrevAction == QStringLiteral("insert") ||
                        cortexPrevAction == QStringLiteral("parallel") ||
                        cortexPrevAction == QStringLiteral("pivot"));

      m_cortexPanel->addReactThought(observation, thought, actionLabel, {},
                                      stepIdx, s["tool_id"].toString(), isDynamic);
      cortexPrevAction = actionStr;
    }

    // Inject payload cards (only new ones, fetch details from API)
    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      int stepIdx = s["step_index"].toInt();

      // Check evidence for payload_id
      if (!evidenceByStep.contains(stepIdx)) continue;
      auto evObj = evidenceByStep.value(stepIdx);
      QString evDataStr = evObj["evidence_data"].toString();
      QJsonDocument evDoc = QJsonDocument::fromJson(evDataStr.toUtf8());
      if (!evDoc.isObject()) continue;

      QString pId = evDoc.object()["payload_id"].toString();
      if (pId.isEmpty()) continue;

      QString stepKey = QStringLiteral("payload_%1_%2").arg(stepIdx).arg(pId);
      if (m_injectedPayloadSteps.contains(stepKey)) continue;
      m_injectedPayloadSteps.insert(stepKey);

      // Fetch payload details and inject as card
      m_api->get("/api/payloads/" + pId, 5000,
        [this, pId, runId, stepIdx](const QJsonObject &pRes) {
          if (runId != m_loadedRunId || pRes["status"].toString() != "ok") return;
          auto pData = pRes["data"].toObject();
          auto payloadData = pData["payload_data"].toObject();

          // Build payload context text (same format as backend buildPayloadContext)
          QString name = pData["name"].toObject()["zh"].toString();
          if (name.isEmpty()) name = pData["name"].toString();
          if (name.isEmpty()) name = pId;

          QStringList contextLines;
          QString principle = pData["description"].toObject()["zh"].toString();
          if (principle.isEmpty()) principle = pData["description"].toString();
          if (!principle.isEmpty()) contextLines << QStringLiteral("【载荷原理】") + principle;

          QString defense = payloadData["defense"].toObject()["zh"].toString();
          if (defense.isEmpty()) defense = payloadData["defense"].toString();
          if (!defense.isEmpty()) contextLines << QStringLiteral("【防御手段】") + defense;

          auto bypasses = payloadData["bypass_variants"].toArray();
          if (bypasses.size() > 0) {
            QStringList bypassLines;
            for (const auto &b : bypasses) {
              auto bo = b.toObject();
              bypassLines << QStringLiteral("  - %1: %2")
                .arg(bo["title"].toString())
                .arg(bo["command"].toString().left(120));
            }
            contextLines << QStringLiteral("【绕过变体(WAF/EDR Bypass)】\n") + bypassLines.join("\n");
          }

          auto opsec = payloadData["opsec_tips"].toArray();
          if (opsec.size() > 0) {
            QStringList opsecLines;
            for (const auto &tip : opsec) {
              if (tip.isObject()) {
                opsecLines << QStringLiteral("  - ") + (tip.toObject()["zh"].toString().isEmpty()
                  ? tip.toObject()["en"].toString() : tip.toObject()["zh"].toString());
              } else {
                opsecLines << QStringLiteral("  - ") + tip.toString();
              }
            }
            contextLines << QStringLiteral("【OPSEC建议】\n") + opsecLines.join("\n");
          }

          m_cortexPanel->addPayloadCard(name, contextLines.join("\n\n"), {}, stepIdx);
        });
    }
  });
}

// ── Poll running execution for real-time updates ─────────────────────
void ExecutionPage::onPollRunning() {
  if (m_runningRunId.isEmpty()) {
    m_pollTimer->stop();
    return;
  }

  const QString runId = m_runningRunId;
  m_api->get("/api/runs/" + runId, 5000, [this, runId](const QJsonObject &res) {
    if (m_runningRunId != runId) return;
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

    // Full reload of run details to keep step table, evidence, etc. in sync
    loadRunDetails(runId);

    // Update Cortex status dot in real-time
    m_cortexPanel->setStatus(status);

    // Stop button: always visible, enabled only for active runs
    {
      bool canStop = (status == "RUNNING" || status == "PENDING");
      m_stopBtn->setEnabled(canStop);
      if (canStop)
        m_stopBtn->setText(QStringLiteral("🛑 停止执行"));
      else if (status == "ABORTED")
        m_stopBtn->setText(QStringLiteral("🛑 已中止"));
      else if (status == "COMPLETED")
        m_stopBtn->setText(QStringLiteral("✓ 已完成"));
      else if (status == "FAILED")
        m_stopBtn->setText(QStringLiteral("✗ 已失败"));
    }

    // Update status label with progress
    auto steps = d["steps"].toArray();
    int done = 0, total = steps.size();
    for (const auto &s : steps) {
      const QJsonValue success = s.toObject()["success"];
      if (success.isBool() || success.isDouble()) done++;
    }
    QString statusCn;
    if (status == "RUNNING") statusCn = "运行中";
    else if (status == "PENDING") statusCn = "待执行";
    else if (status == "COMPLETED") statusCn = "已完成";
    else if (status == "FAILED") statusCn = "失败";
    else if (status == "ABORTED") statusCn = "已中止";
    else statusCn = status;

    // Show playbook name in status
    QString pbName = d["playbook_name"].toString();
    if (pbName.isEmpty()) pbName = d["playbook_id"].toString();
    m_statusLabel->setText(QString("执行: %1 | 预案: %2 | 状态: %3 (%4/%5步)")
        .arg(runId, pbName, statusCn)
        .arg(done).arg(total));
    m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);

    // Terminal state — stop polling
    if (status != "RUNNING" && status != "PENDING") {
      m_pollTimer->stop();
      m_runningRunId.clear();
      m_runningPlaybookId.clear();
      // Full refresh to update final state
      onRefreshRuns();
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
