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

  // Status
  m_statusLabel = new QLabel;
  rightLayout->addWidget(m_statusLabel);

  // Step table
  auto *stepLabel = new QLabel("步骤执行详情"); stepLabel->setStyleSheet(Theme::SectionStyle);
  rightLayout->addWidget(stepLabel);
  m_stepTable = new QTableWidget(0, 7);
  m_stepTable->setHorizontalHeaderLabels({"步骤", "工具", "参数", "成功", "输出摘要", "载荷", "推理"});
  m_stepTable->setAlternatingRowColors(true);
  m_stepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_stepTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_stepTable->setWordWrap(true);
  m_stepTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
  m_stepTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
  m_stepTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
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
  m_evidenceTable->setWordWrap(true);
  m_evidenceTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
  rightLayout->addWidget(m_evidenceTable, 1);

  m_evidenceDetail = new QTextEdit;
  m_evidenceDetail->setReadOnly(true);
  m_evidenceDetail->setPlaceholderText("点击证据行查看详情");
  rightLayout->addWidget(m_evidenceDetail, 1);

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
    m_loadedRunId = runId;
  }

  m_api->get("/api/runs/" + runId, 5000, [this, runId](const QJsonObject &res) {
    if (runId != m_loadedRunId || res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();

    // ── Status line with engine type ────────────────────────────────
    QString engineType = d["engine_type"].toString();
    QString stopReason = d["stop_reason"].toString();
    QString statusVal = d["status"].toString();
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

    // ── Steps (7 columns: 步骤/工具/参数/成功/输出摘要/载荷/推理) ──
    auto steps = d["steps"].toArray();
    m_stepTable->setRowCount(steps.size());
    bool hasReactThoughts = false;
    bool hasPayloadBindings = false;
    QStringList reactLines;
    QStringList payloadLines;

    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      int stepIdx = s["step_index"].toInt();
      m_stepTable->setItem(i, 0, new QTableWidgetItem(QString::number(stepIdx)));
      m_stepTable->setItem(i, 1, new QTableWidgetItem(s["tool_id"].toString()));
      m_stepTable->setItem(i, 2, new QTableWidgetItem(s["args"].toString().left(200)));
      m_stepTable->setItem(i, 3, new QTableWidgetItem(s["success"].toInt() ? "✓ 成功" : "✗ 失败"));
      m_stepTable->setItem(i, 4, new QTableWidgetItem(s["notes"].toString().left(500)));

      // Column 5: Payload — extract from evidence_data JSON, or show tool+args as fallback
      QString payloadDisplay = "-";
      if (evidenceByStep.contains(stepIdx)) {
        auto evObj = evidenceByStep.value(stepIdx);
        QString evDataStr = evObj["evidence_data"].toString();
        if (evDataStr.isEmpty()) {
          // evidence_data might already be a QJsonObject
          auto evData = evObj["evidence_data"].toObject();
          if (evData.contains("payload_id")) {
            payloadDisplay = evData["payload_name"].toString();
            if (payloadDisplay.isEmpty()) payloadDisplay = evData["payload_id"].toString();
            hasPayloadBindings = true;
            payloadLines << QString("步骤 %1 [%2] → 载荷: %3 (%4)")
                .arg(stepIdx).arg(s["tool_id"].toString())
                .arg(evData["payload_name"].toString())
                .arg(evData["payload_id"].toString());
          }
        } else {
          // Parse JSON string
          QJsonDocument evDoc = QJsonDocument::fromJson(evDataStr.toUtf8());
          if (evDoc.isObject()) {
            auto evData = evDoc.object();
            if (evData.contains("payload_id")) {
              payloadDisplay = evData["payload_name"].toString();
              if (payloadDisplay.isEmpty()) payloadDisplay = evData["payload_id"].toString();
              hasPayloadBindings = true;
              payloadLines << QString("步骤 %1 [%2] → 载荷: %3 (%4)")
                  .arg(stepIdx).arg(s["tool_id"].toString())
                  .arg(evData["payload_name"].toString())
                  .arg(evData["payload_id"].toString());
            }
          }
        }
      }
      // Fallback: show tool + truncated args as payload info
      if (payloadDisplay == "-") {
        QString toolId = s["tool_id"].toString();
        QString argsStr = s["args"].toString();
        if (!toolId.isEmpty()) {
          payloadDisplay = toolId;
          if (!argsStr.isEmpty()) {
            payloadDisplay += " " + argsStr.left(30);
            if (argsStr.length() > 30) payloadDisplay += "...";
          }
          hasPayloadBindings = true;
          payloadLines << QString("步骤 %1 [%2] → 命令: %3 %4")
              .arg(stepIdx).arg(toolId).arg(toolId).arg(argsStr.left(80));
        }
      }
      m_stepTable->setItem(i, 5, new QTableWidgetItem(payloadDisplay));

      // Column 6: ReAct thought summary, or step description as fallback
      QString thought = s["react_thought"].toString();
      if (!thought.isEmpty()) {
        hasReactThoughts = true;
        m_stepTable->setItem(i, 6, new QTableWidgetItem(thought.left(100) + (thought.length() > 100 ? "..." : "")));
        // Build detailed ReAct view
        reactLines << QString("━━ 步骤 %1 [%2] ━━").arg(stepIdx).arg(s["tool_id"].toString());
        reactLines << "  💭 思考: " + thought;
        QString action = s["react_action"].toString();
        if (!action.isEmpty()) {
          reactLines << "  🎯 动作: " + action.left(300);
        }
        reactLines << "";
      } else {
        // Fallback: show step description as "reasoning"
        QString stepDesc = s["description"].toString();
        if (stepDesc.isEmpty()) stepDesc = s["notes"].toString().left(100);
        if (!stepDesc.isEmpty()) {
          hasReactThoughts = true;
          m_stepTable->setItem(i, 6, new QTableWidgetItem(stepDesc.left(100) + (stepDesc.length() > 100 ? "..." : "")));
          reactLines << QString("━━ 步骤 %1 [%2] ━━").arg(stepIdx).arg(s["tool_id"].toString());
          reactLines << "  📋 " + stepDesc.left(300);
          reactLines << "";
        } else {
          m_stepTable->setItem(i, 6, new QTableWidgetItem("-"));
        }
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
      m_evidenceTable->setItem(i, 2, new QTableWidgetItem(e["evidence_data"].toString().left(200)));
      m_evidenceTable->setItem(i, 3, new QTableWidgetItem(e["mitre_hits"].toString().left(150)));
      m_evidenceTable->setItem(i, 4, new QTableWidgetItem(e["recommendations"].toString().left(200)));
    }
    m_evidenceTable->resizeColumnsToContents();
    m_evidenceTable->horizontalHeader()->setStretchLastSection(true);

    // If evidence is empty, show summary from final_summary
    if (evidence.isEmpty()) {
      QString summary = d["final_summary"].toString();
      if (!summary.isEmpty()) {
        m_evidenceDetail->setText("执行摘要: " + summary);
      } else {
        m_evidenceDetail->clear();
      }
    } else {
      // Show first evidence detail
      m_evidenceDetail->setText(evidence[0].toObject()["evidence_data"].toString().left(2000));
    }

    // ── Cortex panel: ReAct thoughts + Payload cards ──────────────────
    // Update engine info in Cortex header
    m_cortexPanel->setEngineInfo(engineType.isEmpty() ? QStringLiteral("mechanical") : engineType);

    // Inject ReAct thoughts as structured cards (only new ones)
    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      int stepIdx = s["step_index"].toInt();
      QString thought = s["react_thought"].toString();
      if (thought.isEmpty()) continue;

      QString stepKey = QStringLiteral("react_%1").arg(stepIdx);
      if (m_injectedReactSteps.contains(stepKey)) continue;
      m_injectedReactSteps.insert(stepKey);

      // Parse action
      QString actionStr;
      QString actionJson = s["react_action"].toString();
      if (!actionJson.isEmpty()) {
        QJsonDocument actDoc = QJsonDocument::fromJson(actionJson.toUtf8());
        if (actDoc.isObject()) {
          actionStr = actDoc.object()["type"].toString();
        }
      }
      if (actionStr.isEmpty()) actionStr = QStringLiteral("continue");

      // Map action to Chinese label
      QString actionLabel;
      if (actionStr == QStringLiteral("insert")) actionLabel = QStringLiteral("🔀 插入");
      else if (actionStr == QStringLiteral("adjust")) actionLabel = QStringLiteral("🔧 调整");
      else if (actionStr == QStringLiteral("parallel")) actionLabel = QStringLiteral("⚡ 并行");
      else if (actionStr == QStringLiteral("stop")) actionLabel = QStringLiteral("🛑 终止");
      else actionLabel = QStringLiteral("▶ 继续");

      // Extract observation from step notes (first line of output)
      QString observation = s["notes"].toString().left(200);

      m_cortexPanel->addReactThought(observation, thought, actionLabel);
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
        [this, pId, runId](const QJsonObject &pRes) {
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

          m_cortexPanel->addPayloadCard(name, contextLines.join("\n\n"));
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
    if (res["status"].toString() != "ok" || m_runningRunId != runId) return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    // Full reload of run details to keep step table, evidence, etc. in sync
    loadRunDetails(runId);

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
