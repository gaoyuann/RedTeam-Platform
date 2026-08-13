#include "ExecutionPage.h"
#include "../Theme.h"
#include "../ApiClient.h"
#include <QScrollArea>
#include <QFrame>
#include <QSplitter>
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

  auto *scrollArea = new QScrollArea(this);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);

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
  layout->addLayout(catH);
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
  layout->addLayout(h1);
  connect(m_execBtn, &QPushButton::clicked, this, &ExecutionPage::onExecute);

  // ── Main vertical splitter (draggable sections) ───────────────────
  auto *mainSplitter = new QSplitter(Qt::Vertical);

  // ── Run list (top section) ────────────────────────────────────────
  auto *runW = new QWidget;
  auto *runL = new QVBoxLayout(runW);
  runL->setContentsMargins(0, 0, 0, 0);
  auto *runLabel = new QLabel("执行记录"); runLabel->setStyleSheet(Theme::SectionStyle);
  runL->addWidget(runLabel);
  m_runTable = new QTableWidget(0, 5);
  m_runTable->setHorizontalHeaderLabels({"执行ID", "预案", "目标", "状态", "创建时间"});
  m_runTable->setAlternatingRowColors(true);
  m_runTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_runTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_runTable->setSortingEnabled(true);
  m_runTable->setContextMenuPolicy(Qt::CustomContextMenu);
  runL->addWidget(m_runTable, 1);
  mainSplitter->addWidget(runW);
  connect(m_runTable, &QTableWidget::cellClicked, this, &ExecutionPage::onRunClicked);

  // ── Step details (middle section) ─────────────────────────────────
  auto *stepW = new QWidget;
  auto *stepL = new QVBoxLayout(stepW);
  stepL->setContentsMargins(0, 0, 0, 0);
  m_statusLabel = new QLabel;
  stepL->addWidget(m_statusLabel);
  auto *stepLabel = new QLabel("步骤执行详情"); stepLabel->setStyleSheet(Theme::SectionStyle);
  stepL->addWidget(stepLabel);
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
  stepL->addWidget(m_stepTable, 1);
  mainSplitter->addWidget(stepW);

  // ── Evidence display (bottom section) ─────────────────────────────
  auto *evW = new QWidget;
  auto *evL = new QVBoxLayout(evW);
  evL->setContentsMargins(0, 0, 0, 0);
  m_evidenceLabel = new QLabel;
  evL->addWidget(m_evidenceLabel);
  auto *evLabel = new QLabel("攻击证据"); evLabel->setStyleSheet(Theme::SectionStyle);
  evL->addWidget(evLabel);
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
  evL->addWidget(m_evidenceTable, 1);

  m_evidenceDetail = new QTextEdit;
  m_evidenceDetail->setReadOnly(true);
  m_evidenceDetail->setPlaceholderText("点击证据行查看详情");
  evL->addWidget(m_evidenceDetail, 1);
  mainSplitter->addWidget(evW);

  // ── ReAct reasoning panel ────────────────────────────────────────
  m_reactPanel = new QWidget;
  auto *reactL = new QVBoxLayout(m_reactPanel);
  reactL->setContentsMargins(0, 0, 0, 0);
  m_engineLabel = new QLabel;
  m_engineLabel->setStyleSheet("font-weight: bold; color: #2196F3; padding: 4px;");
  reactL->addWidget(m_engineLabel);
  auto *reactSectionLabel = new QLabel("ReAct 推理过程");
  reactSectionLabel->setStyleSheet(Theme::SectionStyle);
  reactL->addWidget(reactSectionLabel);
  m_reactThoughtView = new QTextEdit;
  m_reactThoughtView->setReadOnly(true);
  m_reactThoughtView->setPlaceholderText("执行使用 ReAct 引擎时，此处显示 LLM 推理过程...");
  m_reactThoughtView->setMaximumHeight(200);
  reactL->addWidget(m_reactThoughtView, 1);
  m_reactPanel->hide();  // shown only when ReAct data exists
  mainSplitter->addWidget(m_reactPanel);

  // ── Payload info panel ───────────────────────────────────────────
  m_payloadPanel = new QWidget;
  auto *payloadL = new QVBoxLayout(m_payloadPanel);
  payloadL->setContentsMargins(0, 0, 0, 0);
  m_payloadLabel = new QLabel;
  m_payloadLabel->setStyleSheet("font-weight: bold; color: #FF9800; padding: 4px;");
  payloadL->addWidget(m_payloadLabel);
  auto *payloadSectionLabel = new QLabel("载荷信息");
  payloadSectionLabel->setStyleSheet(Theme::SectionStyle);
  payloadL->addWidget(payloadSectionLabel);
  m_payloadDetailView = new QTextEdit;
  m_payloadDetailView->setReadOnly(true);
  m_payloadDetailView->setPlaceholderText("步骤绑定载荷时，此处显示载荷详情（命令、绕过变体、防御建议）...");
  m_payloadDetailView->setMaximumHeight(200);
  payloadL->addWidget(m_payloadDetailView, 1);
  m_payloadPanel->hide();  // shown only when payload data exists
  mainSplitter->addWidget(m_payloadPanel);

  // Set proportional sizes for the 5 sections
  mainSplitter->setStretchFactor(0, 2);  // run list
  mainSplitter->setStretchFactor(1, 3);  // step details
  mainSplitter->setStretchFactor(2, 3);  // evidence
  mainSplitter->setStretchFactor(3, 1);  // ReAct reasoning
  mainSplitter->setStretchFactor(4, 1);  // Payload info
  mainSplitter->setSizes({200, 300, 300, 150, 150});
  layout->addWidget(mainSplitter, 1);

  // ── Refresh ───────────────────────────────────────────────────────
  auto *refreshBtn = new QPushButton("刷新");
  layout->addWidget(refreshBtn);
  connect(refreshBtn, &QPushButton::clicked, this, &ExecutionPage::onRefreshRuns);

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

  scrollArea->setWidget(container);
  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->addWidget(scrollArea);
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
    case 1: loadPlaybooksByGroup({"brute", "credential", "brute_force"}); break;
    case 2: loadPlaybooksByGroup({"web-vuln-scan", "exploit", "vuln_scan"}); break;
    case 3: loadPlaybooksByGroup({"windows-exploitation", "internal-network-exploitation", "impact-demonstration"}); break;
  }
}

// ── Execute ─────────────────────────────────────────────────────────
void ExecutionPage::onExecute() {
  QString playbookId = m_playbookCombo->currentData().toString();
  QString target = m_targetInput->text().trimmed();
  if (playbookId.isEmpty() || target.isEmpty()) return;

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
  m_api->post("/api/runs", body, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    QString runId = res["data"].toObject()["run_id"].toString();

    QJsonObject empty;
    m_api->post("/api/runs/" + runId + "/execute", empty, 5000, [this, runId](const QJsonObject &) {
      m_targetInput->clear();
      // Track this run for real-time polling + auto-highlight
      m_runningRunId = runId;
      m_pollTimer->start();
      // Refresh and auto-select the new run
      onRefreshRuns();
    });
  });
}

// ── Refresh runs ─────────────────────────────────────────────────────
void ExecutionPage::onRefreshRuns() {
  m_api->get("/api/runs", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
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
  m_api->get("/api/runs/" + runId, 5000, [this, runId](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
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
    QString statusText = QString("执行: %1 | 预案: %2 | 状态: %3 | 引擎: %4")
        .arg(d["run_id"].toString(), d["playbook_id"].toString(), statusVal,
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

      // Column 5: Payload — extract from evidence_data JSON
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
      m_stepTable->setItem(i, 5, new QTableWidgetItem(payloadDisplay));

      // Column 6: ReAct thought summary
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
        m_stepTable->setItem(i, 6, new QTableWidgetItem("-"));
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

    // ── ReAct reasoning panel ───────────────────────────────────────
    if (hasReactThoughts || engineType == "react") {
      m_reactPanel->show();
      m_engineLabel->setText(QString("🧠 引擎: %1").arg(engineType.isEmpty() ? "mechanical" : engineType));
      if (!stopReason.isEmpty()) {
        m_engineLabel->setText(m_engineLabel->text() + " | 停止: " + stopReason);
      }
      if (reactLines.isEmpty()) {
        m_reactThoughtView->setText("ReAct 引擎已启用，但本次执行未产生推理记录。\n（可能所有步骤均直接执行，无需 LLM 介入）");
      } else {
        m_reactThoughtView->setText(reactLines.join("\n"));
      }
    } else {
      m_reactPanel->hide();
    }

    // ── Payload info panel ──────────────────────────────────────────
    if (hasPayloadBindings) {
      m_payloadPanel->show();
      m_payloadLabel->setText(QString("📦 载荷绑定: %1 个步骤").arg(payloadLines.size()));
      m_payloadDetailView->setText(payloadLines.join("\n"));

      // Fetch detailed payload info for each bound payload
      // (async, best-effort — enrich the display after initial render)
      for (int i = 0; i < steps.size(); i++) {
        auto s = steps[i].toObject();
        int stepIdx = s["step_index"].toInt();
        if (evidenceByStep.contains(stepIdx)) {
          auto evObj = evidenceByStep.value(stepIdx);
          QString evDataStr = evObj["evidence_data"].toString();
          QJsonDocument evDoc = QJsonDocument::fromJson(evDataStr.toUtf8());
          if (evDoc.isObject()) {
            QString pId = evDoc.object()["payload_id"].toString();
            if (!pId.isEmpty()) {
              m_api->get("/api/payloads/" + pId, 5000,
                [this, stepIdx, pId](const QJsonObject &pRes) {
                  if (pRes["status"].toString() != "ok") return;
                  auto pData = pRes["data"].toObject();
                  auto payloadData = pData["payload_data"].toObject();
                  QString primary = payloadData["primary_content"].toString();
                  int bypassCount = payloadData["bypass_variants"].toArray().size();
                  int execCount = payloadData["all_executions"].toArray().size();

                  // Append details to existing text
                  QString current = m_payloadDetailView->toPlainText();
                  QString detail = QString("\n  └ 步骤 %1 载荷详情 [%2]:\n"
                                          "     命令: %3\n"
                                          "     执行步骤: %4 | 绕过变体: %5")
                      .arg(stepIdx).arg(pId)
                      .arg(primary.left(150))
                      .arg(execCount).arg(bypassCount);
                  m_payloadDetailView->setText(current + detail);
                });
            }
          }
        }
      }
    } else {
      m_payloadPanel->hide();
    }
  });
}

// ── Poll running execution for real-time updates ─────────────────────
void ExecutionPage::onPollRunning() {
  if (m_runningRunId.isEmpty()) {
    m_pollTimer->stop();
    return;
  }

  m_api->get("/api/runs/" + m_runningRunId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    if (m_runningRunId.isEmpty()) return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    // Update step table in-place with latest data
    auto steps = d["steps"].toArray();
    if (steps.size() > 0 && m_stepTable->rowCount() > 0) {
      for (int i = 0; i < steps.size() && i < m_stepTable->rowCount(); i++) {
        auto s = steps[i].toObject();
        m_stepTable->setItem(i, 3, new QTableWidgetItem(s["success"].toInt() ? "✓ 成功" : "✗ 失败"));
        m_stepTable->setItem(i, 4, new QTableWidgetItem(s["notes"].toString().left(500)));
      }
    }

    // Update status label with progress
    int done = 0, total = steps.size();
    for (const auto &s : steps) {
      if (s.toObject()["success"].toInt() == 1 || s.toObject()["success"].toInt() == 0) done++;
    }
    QString statusCn;
    if (status == "RUNNING") statusCn = "运行中";
    else if (status == "PENDING") statusCn = "待执行";
    else if (status == "COMPLETED") statusCn = "已完成";
    else if (status == "FAILED") statusCn = "失败";
    else if (status == "ABORTED") statusCn = "已中止";
    else statusCn = status;
    m_statusLabel->setText(m_statusLabel->text().split(" | ").first() +
      QString(" | 状态: %1 (%2/%3步)").arg(statusCn).arg(done).arg(total));

    // Terminal state — stop polling
    if (status != "RUNNING" && status != "PENDING") {
      m_pollTimer->stop();
      m_runningRunId.clear();
      // Full refresh to update final state
      onRefreshRuns();
    }
  });
}
