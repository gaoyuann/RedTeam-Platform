#include "../widgets/WorkbenchTabs.h"
#include "EvaluatePage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "StatsSummaryCard.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QMessageBox>
#include <QScrollArea>
#include <QFrame>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QSplitter>
#include <QDateTime>
#include <QFileDialog>
#include <QFile>
#include <QProcess>
#include <QFileInfo>
#include <QStackedWidget>
#include <QDir>
#include <QPointer>
#include <QDialog>
#include <QGridLayout>

EvaluatePage::EvaluatePage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_previewMode(false) {
  setupUI();
  onLoadRuns();
  onRefreshReports();
  onLoadEvidenceRuns();
  onLoadCaptureTasks();
}

void EvaluatePage::setTarget(const QString &target) {
  // TODO: 按 pipeline run 过滤 — EvaluatePage 按 run_id 工作，暂无 target 输入框
  (void)target;
}

void EvaluatePage::showRun(const QString &runId, bool focus) {
  if (runId.isEmpty()) return;
  if (focus) m_tabs->setCurrentIndex(0);
  if (runId == m_requestedRunId &&
      (m_runLoadPending || runId == m_gradingRunId || runId == m_gradedRunId)) return;
  clearRun();
  m_requestedRunId = runId;
  m_runLoadPending = true;
  const int revision = ++m_runRequestRevision;
  m_scoreLabel->setText(QStringLiteral("正在加载执行记录：%1").arg(runId));
  m_api->get("/api/runs", 5000, [this, runId, revision, focus](const QJsonObject &res) {
    if (revision != m_runRequestRevision) return;
    m_runLoadPending = false;
    if (res["status"].toString() != "ok") {
      m_scoreLabel->setText(QStringLiteral("加载执行记录失败，请切换评估页重试。"));
      return;
    }
    m_runCombo->clear();
    auto arr = res["data"].toArray();
    int targetIndex = -1;
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString status = r["status"].toString();
      if (status == "COMPLETED") status = "已完成";
      else if (status == "RUNNING") status = "运行中";
      else if (status == "PENDING") status = "待执行";
      else if (status == "FAILED") status = "失败";
      QString label = QString("%1 | %2 | %3")
          .arg(r["run_id"].toString(),
               r["playbook_id"].toString(),
               status);
      QString rid = r["run_id"].toString();
      m_runCombo->addItem(label, rid);
      if (rid == runId) targetIndex = i;
    }
    // Select the pipeline's run and trigger grading
    if (targetIndex >= 0) {
      m_runCombo->setCurrentIndex(targetIndex);
      if (focus) m_tabs->setCurrentIndex(0);  // Only explicit navigation changes tabs.
      onGradeRun();
    } else {
      m_runCombo->setCurrentIndex(-1);
      m_scoreLabel->setText(QStringLiteral("执行记录不可用：%1").arg(runId));
    }
  });
}

void EvaluatePage::clearRun() {
  ++m_runRequestRevision;
  ++m_gradeRequestRevision;
  ++m_reportRequestRevision;
  m_requestedRunId.clear();
  m_selectedRunId.clear();
  m_gradedRunId.clear();
  m_gradingRunId.clear();
  m_runLoadPending = false;
  m_runCombo->setCurrentIndex(-1);
  m_scoreLabel->setText(QStringLiteral("选择执行记录后点击评分"));
  m_mitreLabel->clear();
  m_stepTable->setRowCount(0);
  m_gradeBtn->setEnabled(true);
  m_genReportBtn->setEnabled(false);
  m_genReportBtn->setText(QStringLiteral("生成测试报告"));
}

void EvaluatePage::retryRun(const QString &runId) {
  if (runId == m_requestedRunId) showRun(runId, false);
}

void EvaluatePage::showReports() {
  m_tabs->setCurrentIndex(1);  // 切到"测试报告"子页
  onRefreshReports();
}

void EvaluatePage::showReport(const QString &reportId) {
  if (reportId.isEmpty()) return;
  m_pendingReportId = reportId;
  m_tabs->setCurrentIndex(1);
  onRefreshReports();
}

void EvaluatePage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(12, 8, 12, 8);
  m_tabs = new WorkbenchTabs;

  // ── Tab 1: Grading ────────────────────────────────────────────────
  auto *gradeW = new QWidget;
  auto *gradeL = new QVBoxLayout(gradeW);

  // 攻击结果统计卡（自绘）— 演示④
  m_statsCard = new StatsSummaryCard(gradeW);
  auto *statsDialog = new QDialog(this);
  statsDialog->setObjectName("evaluationStats");
  statsDialog->setWindowTitle(QStringLiteral("执行状态统计"));
  statsDialog->resize(820, 280);
  auto *statsLayout = new QVBoxLayout(statsDialog);
  statsLayout->addWidget(m_statsCard);
  auto *statsButton = new QPushButton(QStringLiteral("执行统计"));
  connect(statsButton, &QPushButton::clicked, this, [statsDialog]() {
    statsDialog->show(); statsDialog->raise();
  });

  auto *selectH = new QHBoxLayout;
  selectH->addWidget(new QLabel("执行记录:"));
  m_runCombo = new QComboBox;
  m_runCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
  m_runCombo->setMinimumContentsLength(16);
  selectH->addWidget(m_runCombo, 1);
  m_gradeBtn = new QPushButton("评分");
  m_gradeBtn->setProperty("primary", true);
  selectH->addWidget(m_gradeBtn);
  selectH->addWidget(statsButton);
  gradeL->addLayout(selectH);
  connect(m_gradeBtn, &QPushButton::clicked, this, &EvaluatePage::onGradeRun);
  connect(m_runCombo, QOverload<int>::of(&QComboBox::activated), this, [this](int) {
    ++m_runRequestRevision;
    ++m_gradeRequestRevision;
    ++m_reportRequestRevision;
    m_requestedRunId = m_runCombo->currentData().toString();
    m_selectedRunId.clear();
    m_gradedRunId.clear();
    m_gradingRunId.clear();
    m_runLoadPending = false;
    m_scoreLabel->setText(QStringLiteral("选择执行记录后点击评分"));
    m_mitreLabel->clear();
    m_stepTable->setRowCount(0);
    m_gradeBtn->setEnabled(true);
    m_genReportBtn->setEnabled(false);
    m_genReportBtn->setText(QStringLiteral("生成测试报告"));
  });

  m_scoreLabel = new QLabel("选择执行记录后点击评分");
  m_scoreLabel->setStyleSheet(Theme::SectionStyle);
  m_scoreLabel->setWordWrap(true);
  gradeL->addWidget(m_scoreLabel);

  m_mitreLabel = new QLabel;
  m_mitreLabel->setWordWrap(true);
  gradeL->addWidget(m_mitreLabel);

  m_stepTable = new QTableWidget(0, 5);
  UiUtil::EmptyHint::attach(m_stepTable, QStringLiteral("选择评分记录后展示步骤得分"));
  m_stepTable->setHorizontalHeaderLabels({"步骤", "工具", "满分", "得分", "状态"});
  m_stepTable->setAlternatingRowColors(true);
  m_stepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_stepTable->setSortingEnabled(true);
  m_stepTable->setContextMenuPolicy(Qt::CustomContextMenu);
  gradeL->addWidget(m_stepTable, 1);

  m_genReportBtn = new QPushButton("生成测试报告");
  m_genReportBtn->setProperty("primary", true);
  m_genReportBtn->setEnabled(false);
  gradeL->addWidget(m_genReportBtn);
  connect(m_genReportBtn, &QPushButton::clicked, this, &EvaluatePage::onGenerateReport);

  m_tabs->addTab(gradeW, "执行评分");

  // ── Tab 2: Reports ────────────────────────────────────────────────
  auto *rptW = new QWidget;
  auto *rptL = new QVBoxLayout(rptW);

  m_reportTable = new QTableWidget(0, 5);
  UiUtil::EmptyHint::attach(m_reportTable, QStringLiteral("暂无评分报告"));
  m_reportTable->setHorizontalHeaderLabels({"报告编号", "标题", "关联执行", "状态", "创建时间"});
  m_reportTable->setAlternatingRowColors(true);
  m_reportTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_reportTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_reportTable->setSortingEnabled(true);
  m_reportTable->setContextMenuPolicy(Qt::CustomContextMenu);

  connect(m_reportTable, &QTableWidget::cellClicked, this, &EvaluatePage::onReportClicked);

  // Report detail: stacked widget with JSON source and HTML preview
  m_reportStack = new QStackedWidget;
  m_reportDetail = new QTextEdit;
  m_reportDetail->setReadOnly(true);
  m_reportDetail->setPlaceholderText("选择上方报告，查看报告内容；可切换预览或导出。");
  m_reportStack->addWidget(m_reportDetail);  // index 0 = JSON source

  m_reportPreview = new QTextBrowser;
  m_reportStack->addWidget(m_reportPreview);  // index 1 = HTML preview
  auto *reportSplit = new QSplitter(Qt::Vertical);
  reportSplit->setChildrenCollapsible(false);
  reportSplit->addWidget(m_reportTable);
  reportSplit->addWidget(m_reportStack);
  m_reportTable->setMinimumHeight(96);
  m_reportStack->setMinimumHeight(100);
  reportSplit->setSizes({140, 240});
  rptL->addWidget(reportSplit, 1);

  // Report action buttons
  auto *rptBtnH = new QHBoxLayout;

  // Export format selector
  m_formatCombo = new QComboBox;
  m_formatCombo->addItems({"DOCX", "PDF", "HTML"});
  m_formatCombo->setToolTip("选择导出格式");
  rptBtnH->addWidget(m_formatCombo);

  m_exportBtn = new QPushButton("导出报告");
  m_exportBtn->setProperty("primary", true);
  m_exportBtn->setEnabled(false);
  rptBtnH->addWidget(m_exportBtn);
  connect(m_exportBtn, &QPushButton::clicked, this, &EvaluatePage::onExportReport);

  m_openWpsBtn = new QPushButton("在 WPS 中打开");
  m_openWpsBtn->setEnabled(false);
  rptBtnH->addWidget(m_openWpsBtn);
  connect(m_openWpsBtn, &QPushButton::clicked, this, &EvaluatePage::onOpenInWps);

  m_previewBtn = new QPushButton("预览报告");
  m_previewBtn->setEnabled(false);
  rptBtnH->addWidget(m_previewBtn);
  connect(m_previewBtn, &QPushButton::clicked, this, &EvaluatePage::onPreviewReport);

  rptBtnH->addStretch();

  m_delReportBtn = new QPushButton("删除选中报告");
  m_delReportBtn->setProperty("danger", true);
  m_delReportBtn->setEnabled(false);
  rptBtnH->addWidget(m_delReportBtn);

  auto *rptRefresh = new QPushButton("刷新");
  rptBtnH->addWidget(rptRefresh);
  rptL->addLayout(rptBtnH);
  connect(m_delReportBtn, &QPushButton::clicked, this, &EvaluatePage::onDeleteReport);
  connect(rptRefresh, &QPushButton::clicked, this, &EvaluatePage::onRefreshReports);

  // Store stacked widget reference for toggle
  m_reportStack->setCurrentIndex(0);

  m_tabs->addTab(rptW, "测试报告");

  // ── Tab 3: Evidence ────────────────────────────────────────────────
  auto *evW = new QWidget;
  auto *evL = new QVBoxLayout(evW);

  auto *evSelectH = new QHBoxLayout;
  evSelectH->addWidget(new QLabel("执行记录:"));
  m_evidenceRunCombo = new QComboBox;
  m_evidenceRunCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
  m_evidenceRunCombo->setMinimumContentsLength(16);
  evSelectH->addWidget(m_evidenceRunCombo, 1);
  evL->addLayout(evSelectH);
  connect(m_evidenceRunCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
          this, &EvaluatePage::onEvidenceRunSelected);

  m_evidenceTable = new QTableWidget(0, 5);
  UiUtil::EmptyHint::attach(m_evidenceTable, QStringLiteral("暂无取证数据"));
  m_evidenceTable->setHorizontalHeaderLabels({"步骤", "类型", "数据摘要", "MITRE命中", "建议"});
  m_evidenceTable->setAlternatingRowColors(true);
  m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_evidenceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_evidenceTable->setSortingEnabled(true);
  m_evidenceTable->setContextMenuPolicy(Qt::CustomContextMenu);

  connect(m_evidenceTable, &QTableWidget::cellClicked, this, &EvaluatePage::onEvidenceClicked);

  m_evidenceDetail = new QTextEdit;
  m_evidenceDetail->setReadOnly(true);
  m_evidenceDetail->setPlaceholderText("点击证据行查看完整数据");
  auto *evidenceSplit = new QSplitter(Qt::Vertical);
  evidenceSplit->setChildrenCollapsible(false);
  evidenceSplit->addWidget(m_evidenceTable);
  evidenceSplit->addWidget(m_evidenceDetail);
  evL->addWidget(evidenceSplit, 1);

  m_tabs->addTab(evW, "攻击证据");

  // ── Tab 4: Network Data Capture + Analysis (merged) ──────────────────
  auto *capW = new QWidget;
  auto *capOuterL = new QVBoxLayout(capW);

  auto *capSplitter = new QSplitter(Qt::Horizontal);

  // ── Left: capture task list ───────────────────────────────────────
  auto *capLeftW = new QWidget;
  auto *capLeftL = new QVBoxLayout(capLeftW);

  auto *capBtnH = new QHBoxLayout;
  m_createCaptureBtn = new QPushButton("+ 新建捕获");
  m_createCaptureBtn->setProperty("primary", true);
  auto *capRefreshBtn = new QPushButton("刷新");
  m_delCaptureBtn = new QPushButton("删除");
  m_delCaptureBtn->setProperty("danger", true);
  m_delCaptureBtn->setEnabled(false);
  capBtnH->addWidget(m_createCaptureBtn);
  capBtnH->addWidget(capRefreshBtn);
  capBtnH->addWidget(m_delCaptureBtn);
  capBtnH->addStretch();
  capLeftL->addLayout(capBtnH);

  m_captureTaskTable = new QTableWidget(0, 5);
  UiUtil::EmptyHint::attach(m_captureTaskTable, QStringLiteral("暂无抓包任务"));
  m_captureTaskTable->setHorizontalHeaderLabels({"编号", "接口", "状态", "包数", "大小"});
  m_captureTaskTable->setAlternatingRowColors(true);
  m_captureTaskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_captureTaskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_captureTaskTable->setSortingEnabled(true);
  capLeftL->addWidget(m_captureTaskTable, 1);
  connect(m_captureTaskTable, &QTableWidget::cellClicked, this, &EvaluatePage::onCaptureTaskClicked);
  connect(m_createCaptureBtn, &QPushButton::clicked, this, &EvaluatePage::onCreateCapture);
  connect(capRefreshBtn, &QPushButton::clicked, this, &EvaluatePage::onLoadCaptureTasks);
  connect(m_delCaptureBtn, &QPushButton::clicked, this, &EvaluatePage::onDeleteCaptureTask);

  // ── Right: config + status + analysis results ─────────────────────
  auto *capRightW = new QWidget;
  auto *capRightOuter = new QVBoxLayout(capRightW);
  capRightOuter->setContentsMargins(0, 0, 0, 0);
  auto *captureDetails = new WorkbenchTabs;
  captureDetails->setObjectName("captureDetails");
  capRightOuter->addWidget(captureDetails);
  auto *captureConfig = new QWidget;
  auto *capRightL = new QVBoxLayout(captureConfig);
  auto *captureAnalysis = new QWidget;
  auto *analysisLayout = new QVBoxLayout(captureAnalysis);

  auto *configGrid = new QGridLayout;
  configGrid->setVerticalSpacing(4);
  configGrid->addWidget(new QLabel("网络接口"), 0, 0);
  configGrid->addWidget(new QLabel("模式"), 0, 1);
  m_interfaceCombo = new QComboBox;
  m_interfaceCombo->addItem("任意接口", "any");
  m_interfaceCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
  m_interfaceCombo->setMinimumContentsLength(8);
  onLoadInterfaces();
  m_captureTypeCombo = new QComboBox;
  m_captureTypeCombo->addItems({"定时", "手动停止"});
  configGrid->addWidget(m_interfaceCombo, 1, 0);
  configGrid->addWidget(m_captureTypeCombo, 1, 1);
  configGrid->addWidget(new QLabel("BPF 过滤"), 2, 0);
  configGrid->addWidget(new QLabel("时长（秒）"), 2, 1);
  m_bpfInput = new QLineEdit;
  m_bpfInput->setPlaceholderText("例: port 443");
  m_durationSpin = new QSpinBox;
  m_durationSpin->setRange(5, 3600);
  m_durationSpin->setValue(60);
  configGrid->addWidget(m_bpfInput, 3, 0);
  configGrid->addWidget(m_durationSpin, 3, 1);
  configGrid->setColumnStretch(0, 1);
  configGrid->setColumnStretch(1, 1);
  capRightL->setSpacing(6);
  capRightL->addLayout(configGrid);

  auto *actH = new QHBoxLayout;
  m_startCaptureBtn = new QPushButton("▶ 开始捕获");
  m_startCaptureBtn->setProperty("primary", true);
  m_stopCaptureBtn = new QPushButton("■ 停止捕获");
  m_stopCaptureBtn->setProperty("danger", true);
  m_stopCaptureBtn->setEnabled(false);
  actH->addWidget(m_startCaptureBtn);
  actH->addWidget(m_stopCaptureBtn);
  capRightL->addLayout(actH);
  connect(m_startCaptureBtn, &QPushButton::clicked, this, &EvaluatePage::onStartCapture);
  connect(m_stopCaptureBtn, &QPushButton::clicked, this, &EvaluatePage::onStopCapture);

  m_captureStatusLabel = new QLabel("选择左侧捕获任务查看详情");
  m_captureStatusLabel->setWordWrap(true);
  m_captureStatusLabel->setStyleSheet("font-size: 13px; padding: 8px;");
  capRightL->addWidget(m_captureStatusLabel);

  auto *anaBtnH = new QHBoxLayout;
  m_runAnalysisBtn = new QPushButton("🔍 分析");
  m_runAnalysisBtn->setProperty("primary", true);
  m_runAnalysisBtn->setEnabled(false);
  anaBtnH->addWidget(m_runAnalysisBtn);
  anaBtnH->addStretch();
  analysisLayout->addLayout(anaBtnH);
  connect(m_runAnalysisBtn, &QPushButton::clicked, this, &EvaluatePage::onRunAnalysis);

  m_analysisResultTable = new QTableWidget(0, 4);
  UiUtil::EmptyHint::attach(m_analysisResultTable, QStringLiteral("暂无流量分析结果"));
  m_analysisResultTable->setHorizontalHeaderLabels({"分析类型", "严重度", "摘要", "时间"});
  m_analysisResultTable->setAlternatingRowColors(true);
  m_analysisResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_analysisResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_analysisResultTable->setSortingEnabled(true);
  m_analysisResultTable->setMinimumHeight(100);
  analysisLayout->addWidget(m_analysisResultTable, 1);
  connect(m_analysisResultTable, &QTableWidget::cellClicked, this, &EvaluatePage::onAnalysisResultClicked);

  m_analysisDetail = new QTextEdit;
  m_analysisDetail->setReadOnly(true);
  m_analysisDetail->setPlaceholderText("点击分析结果行查看详情");
  m_analysisDetail->setMinimumHeight(70);
  analysisLayout->addWidget(m_analysisDetail, 1);

  capRightL->addStretch();
  captureDetails->addTab(captureConfig, QStringLiteral("捕获配置"));
  captureDetails->addTab(captureAnalysis, QStringLiteral("分析结果"));

  capSplitter->addWidget(capLeftW);
  capSplitter->addWidget(capRightW);
  capSplitter->setChildrenCollapsible(false);
  capSplitter->setStretchFactor(0, 1);
  capSplitter->setStretchFactor(1, 1);
  capSplitter->setSizes({330, 470});
  capOuterL->addWidget(capSplitter, 1);

  // Poll timer for capture status
  m_capturePollTimer = new QTimer(this);
  m_capturePollTimer->setInterval(3000);
  connect(m_capturePollTimer, &QTimer::timeout, this, &EvaluatePage::onCapturePollStatus);

  // Analysis poll timer (used after triggering analyze to wait for results)
  m_analysisPollTimer = new QTimer(this);
  m_analysisPollTimer->setSingleShot(true);
  connect(m_analysisPollTimer, &QTimer::timeout, this, &EvaluatePage::onPollAnalysisResults);

  m_tabs->addTab(capW, "网络数据捕获");

  // ── Right-click menus ────────────────────────────────────────────────
  connect(m_stepTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_stepTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_stepTable->viewport()->mapToGlobal(pos));
  });
  connect(m_reportTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_reportTable->itemAt(pos);
    if (!item) return;
    int row = item->row();
    auto *idItem = m_reportTable->item(row, 0);
    auto *statusItem = m_reportTable->item(row, 3);
    if (!idItem) return;

    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });

    // Status transition actions
    QString currentStatus = statusItem ? statusItem->text() : "";
    QString reportId = idItem->text();
    if (currentStatus == "草稿") {
      menu.addSeparator();
      menu.addAction("标记为已审核", [this, reportId]() {
        QJsonObject body;
        body["status"] = "reviewed";
        m_api->patch("/api/reports/" + reportId + "/status", body, 5000, [this](const QJsonObject &) {
          onRefreshReports();
        });
      });
    } else if (currentStatus == "已审核") {
      menu.addSeparator();
      menu.addAction("发布报告", [this, reportId]() {
        QJsonObject body;
        body["status"] = "published";
        m_api->patch("/api/reports/" + reportId + "/status", body, 5000, [this](const QJsonObject &) {
          onRefreshReports();
        });
      });
    }

    menu.exec(m_reportTable->viewport()->mapToGlobal(pos));
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

  layout->addWidget(m_tabs);

  for (auto *table : {m_stepTable, m_reportTable, m_evidenceTable,
                      m_captureTaskTable, m_analysisResultTable}) {
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->horizontalHeader()->setMinimumSectionSize(42);
    table->setWordWrap(false);
    table->setTextElideMode(Qt::ElideRight);
  }
  m_captureTaskTable->setColumnHidden(0, true);
}

// ════════════════════════════════════════════════════════════════════════
// Tab 1: Grading
// ════════════════════════════════════════════════════════════════════════

void EvaluatePage::onLoadRuns() {
  const int revision = ++m_runRequestRevision;
  m_api->get("/api/runs", 5000, [this, revision](const QJsonObject &res) {
    if (revision != m_runRequestRevision || res["status"].toString() != "ok") return;
    m_runCombo->clear();
    auto arr = res["data"].toArray();
    m_statsCard->setRuns(arr);  // 统计卡与下拉框共用同一份记录
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString status = r["status"].toString();
      if (status == "COMPLETED") status = "已完成";
      else if (status == "RUNNING") status = "运行中";
      else if (status == "PENDING") status = "待执行";
      else if (status == "FAILED") status = "失败";
      QString label = QString("%1 | %2 | %3")
          .arg(r["run_id"].toString(),
               r["playbook_id"].toString(),
               status);
      m_runCombo->addItem(label, r["run_id"].toString());
    }
    m_runCombo->setCurrentIndex(-1);
  });
}

void EvaluatePage::onGradeRun() {
  QString runId = m_runCombo->currentData().toString();
  if (runId.isEmpty()) return;
  if (runId == m_gradingRunId) return;
  m_selectedRunId = runId;
  m_requestedRunId = runId;
  m_gradingRunId = runId;
  m_gradedRunId.clear();
  const int revision = ++m_gradeRequestRevision;
  ++m_reportRequestRevision;
  m_gradeBtn->setEnabled(false);
  m_genReportBtn->setEnabled(false);
  m_genReportBtn->setText(QStringLiteral("生成测试报告"));

  m_api->post("/api/runs/" + runId + "/grade", QJsonObject(), 5000, [this, runId, revision](const QJsonObject &res) {
    if (revision != m_gradeRequestRevision || runId != m_runCombo->currentData().toString()) return;
    m_gradingRunId.clear();
    m_gradeBtn->setEnabled(true);
    if (res["status"].toString() != "ok") {
      m_scoreLabel->setText(QStringLiteral("评分失败，请重试。"));
      return;
    }
    m_gradedRunId = runId;
    auto d = res["data"].toObject();

    QString grade = d["grade"].toString();
    double percent = d["percent"].toDouble();
    int earned = d["earned"].toInt();
    int total = d["total"].toInt();
    m_scoreLabel->setText(QString("总分: %1/%2 (%3%) 等级: %4")
        .arg(earned).arg(total).arg(percent, 0, 'f', 1).arg(grade));

    auto mitre = d["mitre"].toObject();
    m_mitreLabel->setText(QString("MITRE 覆盖: %1/%2 (%3%) 加分: %4")
        .arg(mitre["covered"].toInt())
        .arg(mitre["total"].toInt())
        .arg(mitre["percent"].toDouble(), 0, 'f', 1)
        .arg(mitre["score"].toInt()));

    auto breakdown = d["breakdown"].toArray();
    const bool sorting = m_stepTable->isSortingEnabled();
    m_stepTable->setSortingEnabled(false);
    m_stepTable->setRowCount(breakdown.size());
    for (int i = 0; i < breakdown.size(); i++) {
      auto s = breakdown[i].toObject();
      m_stepTable->setItem(i, 0, new QTableWidgetItem(QString::number(s["stepIndex"].toInt())));
      m_stepTable->setItem(i, 1, new QTableWidgetItem(s["toolId"].toString()));
      m_stepTable->setItem(i, 2, new QTableWidgetItem(QString::number(s["score"].toInt())));
      m_stepTable->setItem(i, 3, new QTableWidgetItem(QString::number(s["earned"].toInt())));
      m_stepTable->setItem(i, 4, new QTableWidgetItem(s["success"].toBool() ? "通过" : "失败"));
    }


    m_stepTable->setSortingEnabled(sorting);
    m_genReportBtn->setEnabled(true);
  });
}

void EvaluatePage::onGenerateReport() {
  const QString runId = m_selectedRunId;
  if (runId.isEmpty() || runId != m_gradedRunId || runId != m_runCombo->currentData().toString()
      || !m_genReportBtn->isEnabled()) return;
  QJsonObject body;
  body["run_id"] = runId;
  const int revision = ++m_reportRequestRevision;
  QPointer<EvaluatePage> page(this);
  m_genReportBtn->setEnabled(false);
  m_genReportBtn->setText("生成中...");
  m_api->post("/api/reports/generate", body, 5000, [this, page, runId, revision](const QJsonObject &res) {
    if (!page || revision != m_reportRequestRevision || runId != m_gradedRunId
        || runId != m_runCombo->currentData().toString()) return;
    m_genReportBtn->setEnabled(true);
    m_genReportBtn->setText("生成测试报告");
    if (res["status"].toString() == "ok") {
      QMessageBox::information(this, "生成成功", "测试报告已生成，可在「测试报告」标签页查看。");
    } else {
      auto err = res["error"].toObject()["message"].toString();
      QMessageBox::warning(this, "生成失败", QString("报告生成失败：%1").arg(err));
    }
    onRefreshReports();
  });
}

// ════════════════════════════════════════════════════════════════════════
// Tab 2: Reports
// ════════════════════════════════════════════════════════════════════════

void EvaluatePage::onRefreshReports() {
  const int revision = ++m_reportListRevision;
  QPointer<EvaluatePage> self(this);
  m_api->get("/api/reports", 5000, [this, self, revision](const QJsonObject &res) {
    if (!self || revision != m_reportListRevision) return;
    if (res["status"].toString() != "ok") {
      m_reportDetail->setPlainText(QStringLiteral("报告列表加载失败，请刷新后重试。"));
      return;
    }
    auto arr = res["data"].toArray();
    const bool sorting = m_reportTable->isSortingEnabled();
    m_reportTable->setSortingEnabled(false);
    m_reportTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      m_reportTable->setItem(i, 0, new QTableWidgetItem(r["report_id"].toString()));
      m_reportTable->setItem(i, 1, new QTableWidgetItem(r["title"].toString()));
      m_reportTable->setItem(i, 2, new QTableWidgetItem(r["run_id"].toString()));
      QString rptStatus = r["status"].toString();
      if (rptStatus == "draft") rptStatus = "草稿";
      else if (rptStatus == "reviewed") rptStatus = "已审核";
      else if (rptStatus == "published") rptStatus = "已发布";
      else if (rptStatus == "COMPLETED") rptStatus = "已完成";
      else if (rptStatus == "PENDING") rptStatus = "待生成";
      else if (rptStatus == "FAILED") rptStatus = "生成失败";
      m_reportTable->setItem(i, 3, new QTableWidgetItem(rptStatus));
      m_reportTable->setItem(i, 4, new QTableWidgetItem(r["created_at"].toString()));
    }
    m_reportTable->setSortingEnabled(sorting);


    if (!m_pendingReportId.isEmpty()) {
      const QString requested = m_pendingReportId;
      m_pendingReportId.clear();
      for (int row = 0; row < m_reportTable->rowCount(); ++row) {
        if (m_reportTable->item(row, 0)->text() != requested) continue;
        m_reportTable->selectRow(row);
        m_reportTable->scrollToItem(m_reportTable->item(row, 0));
        onReportClicked(row, 0);
        onPreviewReport();
        return;
      }
      m_reportDetail->setPlainText(QStringLiteral("未找到本次报告，可能已被删除。请刷新后重试。"));
    }
  });
}

void EvaluatePage::onReportClicked(int row, int) {
  auto *idItem = m_reportTable->item(row, 0);
  if (!idItem) return;
  QString id = idItem->text();
  m_selectedReportId = id;
  m_delReportBtn->setEnabled(true);
  m_exportBtn->setEnabled(true);
  m_openWpsBtn->setEnabled(true);
  m_previewBtn->setEnabled(true);

  // Reset to JSON source mode when selecting a new report
  if (m_previewMode) {
    m_previewMode = false;
    m_reportStack->setCurrentIndex(0);
    m_previewBtn->setText("预览报告");
  }

  QPointer<EvaluatePage> self(this);
  m_api->get("/api/reports/" + id, 5000, [this, self, id](const QJsonObject &res) {
    if (!self || m_selectedReportId != id) return;
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString content = d["content"].toString();
    if (content.isEmpty()) {
      m_reportDetail->setText("（报告内容为空）");
    } else {
      QJsonDocument doc = QJsonDocument::fromJson(content.toUtf8());
      if (!doc.isNull()) {
        m_reportDetail->setText(QString::fromUtf8(doc.toJson(QJsonDocument::Indented)));
      } else {
        m_reportDetail->setText(content);
      }
    }
  });
}

void EvaluatePage::onDeleteReport() {
  if (m_selectedReportId.isEmpty()) return;
  auto reply = QMessageBox::question(this->window(), "确认删除",
    QString("确定要删除此报告吗？此操作不可撤销。"),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;
  m_api->del("/api/reports/" + m_selectedReportId, 5000, [this](const QJsonObject &) {
    m_selectedReportId.clear();
    m_delReportBtn->setEnabled(false);
    m_exportBtn->setEnabled(false);
    m_openWpsBtn->setEnabled(false);
    m_previewBtn->setEnabled(false);
    m_reportDetail->clear();
    m_reportPreview->clear();
    onRefreshReports();
  });
}

// ── Export Report ─────────────────────────────────────────────────────

void EvaluatePage::onExportReport() {
  if (m_selectedReportId.isEmpty()) return;
  const QString reportId = m_selectedReportId;  // 快照：避免异步下载期间切换报告导致缓存错位

  QString format = m_formatCombo->currentText().toLower();
  QString url = QString("/api/reports/%1/export?format=%2").arg(reportId, format);

  // Determine file filter and default extension
  QString filter;
  QString defaultExt;
  if (format == "docx") {
    filter = "Word 文档 (*.docx);;所有文件 (*)";
    defaultExt = ".docx";
  } else if (format == "pdf") {
    filter = "PDF 文档 (*.pdf);;所有文件 (*)";
    defaultExt = ".pdf";
  } else {
    filter = "HTML 文档 (*.html);;所有文件 (*)";
    defaultExt = ".html";
  }

  QString defaultName = QString("report_%1%2").arg(reportId, defaultExt);
  QString savePath = QFileDialog::getSaveFileName(this, "保存报告", defaultName, filter);
  if (savePath.isEmpty()) return;

  m_exportBtn->setEnabled(false);
  m_exportBtn->setText("导出中...");

  m_api->download(url, 30000, [this, savePath, format, reportId](bool ok, const QByteArray &data, const QString &) {
    m_exportBtn->setEnabled(true);
    m_exportBtn->setText("导出报告");

    if (!ok || data.isEmpty()) {
      QMessageBox::warning(this, "导出失败", "无法下载报告文件，请检查后端服务是否正常运行。");
      return;
    }

    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
      QMessageBox::warning(this, "保存失败", QString("无法写入文件：%1").arg(savePath));
      return;
    }
    file.write(data);
    file.close();

    // 仅当用户未在下载期间切换报告时才更新缓存，否则丢弃以免缓存指向错误的报告
    if (m_selectedReportId == reportId) {
      m_lastExportPath = savePath;
      m_lastExportFormat = format;
      m_lastExportReportId = reportId;
    }
    QMessageBox::information(this, "导出成功", QString("报告已保存至：\n%1").arg(savePath));
  });
}

// ── Open in WPS ──────────────────────────────────────────────────────

void EvaluatePage::onOpenInWps() {
  if (m_selectedReportId.isEmpty()) return;
  const QString reportId = m_selectedReportId;  // 快照：避免异步下载期间切换报告导致缓存错位

  // Use the format selected in the combo box
  QString format = m_formatCombo->currentText().toLower();

  // Re-export if: no previous export, file deleted, format changed, or selected report changed
  bool needExport = m_lastExportPath.isEmpty()
    || !QFileInfo::exists(m_lastExportPath)
    || m_lastExportFormat != format
    || m_lastExportReportId != reportId;

  if (needExport) {
    QString url = QString("/api/reports/%1/export?format=%2").arg(reportId, format);

    m_openWpsBtn->setEnabled(false);
    m_openWpsBtn->setText("导出中...");

    m_api->download(url, 30000, [this, format, reportId](bool ok, const QByteArray &data, const QString &filename) {
      m_openWpsBtn->setEnabled(true);
      m_openWpsBtn->setText("在 WPS 中打开");

      if (!ok || data.isEmpty()) {
        QMessageBox::warning(this, "导出失败", "无法下载报告文件。");
        return;
      }

      // 下载期间用户切换了报告：不写缓存、不打开，交给当前选中报告的状态
      if (m_selectedReportId != reportId) return;

      // Save to temp location (sanitize filename to prevent path traversal)
      QString tempDir = QDir::tempPath();
      QString defaultName = QString("report_temp.%1").arg(format);
      QString saveName = filename.isEmpty() ? defaultName : QFileInfo(filename).fileName();
      QString savePath = tempDir + "/" + saveName;
      QFile file(savePath);
      if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, "保存失败", QString("无法写入临时文件：%1").arg(savePath));
        return;
      }
      file.write(data);
      file.close();
      m_lastExportPath = savePath;
      m_lastExportFormat = format;
      m_lastExportReportId = reportId;

      // Now open in WPS
      openFileInWps(savePath);
    });
  } else {
    openFileInWps(m_lastExportPath);
  }
}

void EvaluatePage::openFileInWps(const QString &filePath) {
  QString wpsPath = findWpsExecutable();
  if (wpsPath.isEmpty()) {
    // Fallback: in WSL2, try opening via Windows default handler (cmd.exe /c start)
    if (QFileInfo::exists("/mnt/c/Windows/System32/cmd.exe")) {
      // Convert WSL path to Windows path: /home/xxx → \\wsl$\Ubuntu\home\xxx
      QString winPath = filePath;
      if (winPath.startsWith("/")) {
        QString distro = qgetenv("WSL_DISTRO_NAME");
        if (distro.isEmpty()) distro = "Ubuntu";
        winPath = "\\\\wsl$\\" + distro + filePath;
      }
      bool started = QProcess::startDetached("/mnt/c/Windows/System32/cmd.exe",
        { "/c", "start", "", winPath });
      if (started) return;
    }
    QMessageBox::information(this, "未找到 WPS",
      QString("未检测到 WPS Office，请手动打开文件：\n%1\n\n"
              "提示：可设置环境变量 WPS_PATH 指向 WPS 可执行文件路径。").arg(filePath));
    return;
  }

  bool started = QProcess::startDetached(wpsPath, { filePath });
  if (!started) {
    QMessageBox::warning(this, "启动失败", QString("无法启动 WPS：%1").arg(wpsPath));
  }
}

QString EvaluatePage::findWpsExecutable() {
  // 1. Environment variable
  QByteArray envPath = qgetenv("WPS_PATH");
  if (!envPath.isEmpty() && QFileInfo::exists(QString::fromUtf8(envPath))) {
    return QString::fromUtf8(envPath);
  }

  // 2. Common installation paths (银河麒麟/统信UOS Linux)
  const QStringList candidates = {
    "/usr/bin/wps-office",
    "/opt/apps/cn.wps.wps-office-pro/files/wps-office/office6/wps",
    "/opt/wps-office/office6/wps",
    "/usr/local/bin/wps",
    "/usr/bin/wps",
  };
  for (const auto &p : candidates) {
    if (QFileInfo::exists(p)) return p;
  }

  // 3. which lookup
  for (const auto &cmd : {"wps-office", "wps"}) {
    QProcess which;
    which.start("which", {cmd});
    if (which.waitForFinished(2000)) {
      QString result = QString::fromUtf8(which.readAllStandardOutput()).trimmed();
      if (!result.isEmpty() && QFileInfo::exists(result)) return result;
    }
  }

  return {};
}

// ── Preview Report (HTML) ────────────────────────────────────────────

void EvaluatePage::onPreviewReport() {
  // Toggle between preview and source mode
  if (m_previewMode) {
    // Switch back to JSON source
    m_previewMode = false;
    m_reportStack->setCurrentIndex(0);
    m_previewBtn->setText("预览报告");
    return;
  }

  if (m_selectedReportId.isEmpty()) return;
  const QString reportId = m_selectedReportId;  // 快照：加载期间切换报告则丢弃过期结果

  m_previewBtn->setEnabled(false);
  m_previewBtn->setText("加载中...");

  QString url = QString("/api/reports/%1/export?format=html").arg(reportId);
  QPointer<EvaluatePage> self(this);
  m_api->download(url, 15000, [this, self, reportId](bool ok, const QByteArray &data, const QString &) {
    if (!self) return;
    // 用户在加载期间切换了报告，丢弃这次过期结果，不触碰 UI（由当前选中报告的决定生效）
    if (m_selectedReportId != reportId) return;

    m_previewBtn->setEnabled(true);

    if (!ok || data.isEmpty()) {
      m_previewBtn->setText("预览报告");
      QMessageBox::warning(this, "预览失败", "无法获取报告 HTML 预览。");
      return;
    }

    m_reportPreview->setHtml(QString::fromUtf8(data));
    m_previewMode = true;
    m_reportStack->setCurrentIndex(1);  // HTML preview
    m_previewBtn->setText("查看源码");
  });
}

// ════════════════════════════════════════════════════════════════════════
// Tab 3: Evidence
// ════════════════════════════════════════════════════════════════════════

void EvaluatePage::onLoadEvidenceRuns() {
  m_api->get("/api/runs", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    m_evidenceRunCombo->clear();
    auto arr = res["data"].toArray();
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString status = r["status"].toString();
      if (status == "COMPLETED") status = "已完成";
      else if (status == "RUNNING") status = "运行中";
      else if (status == "PENDING") status = "待执行";
      else if (status == "FAILED") status = "失败";
      QString label = QString("%1 | %2 | %3")
          .arg(r["run_id"].toString(),
               r["playbook_id"].toString(),
               status);
      m_evidenceRunCombo->addItem(label, r["run_id"].toString());
    }
    if (m_evidenceRunCombo->count() > 0) {
      onEvidenceRunSelected(0);
    }
  });
}

void EvaluatePage::onEvidenceRunSelected(int index) {
  if (index < 0) return;
  QString runId = m_evidenceRunCombo->currentData().toString();
  if (runId.isEmpty()) return;

  m_api->get("/api/runs/" + runId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    auto evidence = d["evidence"].toArray();

    const bool sorting = m_evidenceTable->isSortingEnabled();
    m_evidenceTable->setSortingEnabled(false);
    m_evidenceTable->setRowCount(evidence.size());
    for (int i = 0; i < evidence.size(); i++) {
      auto e = evidence[i].toObject();
      m_evidenceTable->setItem(i, 0, new QTableWidgetItem(QString::number(e["step_index"].toInt())));
      m_evidenceTable->item(i, 0)->setData(Qt::UserRole, e);
      m_evidenceTable->setItem(i, 1, new QTableWidgetItem(e["evidence_type"].toString()));
      m_evidenceTable->setItem(i, 2, new QTableWidgetItem(e["evidence_data"].toString().left(200)));
      m_evidenceTable->setItem(i, 3, new QTableWidgetItem(e["mitre_hits"].toString().left(150)));
      m_evidenceTable->setItem(i, 4, new QTableWidgetItem(e["recommendations"].toString().left(200)));
    }



    m_evidenceTable->setSortingEnabled(sorting);
    if (evidence.isEmpty()) {
      m_evidenceDetail->setText("该执行记录无攻击证据数据");
    } else {
      m_evidenceDetail->clear();
    }
  });
}

void EvaluatePage::onEvidenceClicked(int row, int) {
  auto *item = m_evidenceTable->item(row, 0);
  if (!item) return;
  const auto e = item->data(Qt::UserRole).toJsonObject();
    QStringList lines;
    lines << "=== 攻击证据详情 ===";
    lines << QString("步骤: %1").arg(e["step_index"].toInt());
    lines << QString("工具: %1").arg(e["tool_id"].toString());
    lines << QString("类型: %1").arg(e["evidence_type"].toString());
    lines << "";
    lines << "--- 证据数据 ---";
    lines << e["evidence_data"].toString();
    lines << "";
    if (!e["mitre_hits"].toString().isEmpty()) {
      lines << "--- MITRE 命中 ---";
      lines << e["mitre_hits"].toString();
    }
    if (!e["recommendations"].toString().isEmpty()) {
      lines << "--- 修复建议 ---";
      lines << e["recommendations"].toString();
    }
    if (!e["raw_stdout"].toString().isEmpty()) {
      lines << "--- 工具原始输出 (stdout) ---";
      lines << e["raw_stdout"].toString().left(3000);
    }
    m_evidenceDetail->setPlainText(lines.join("\n"));
}


// ════════════════════════════════════════════════════════════════════════
// Tab 4: Network Data Capture + Analysis (merged)
// ════════════════════════════════════════════════════════════════════════

void EvaluatePage::onLoadCaptureTasks() {
  m_api->get("/api/capture-tasks", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    const bool sorting = m_captureTaskTable->isSortingEnabled();
    m_captureTaskTable->setSortingEnabled(false);
    m_captureTaskTable->setRowCount(arr.size());
    bool hasRunning = false;
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString id = r["capture_task_id"].toString();
      m_captureTaskTable->setItem(i, 0, new QTableWidgetItem(id));
      m_captureTaskTable->setItem(i, 1, new QTableWidgetItem(r["interface"].toString()));

      QString status = r["status"].toString();
      QString errMsg = r["error_message"].toString();
      if (status == "RUNNING") { status = "运行中"; hasRunning = true; }
      else if (status == "COMPLETED") status = "已完成";
      else if (status == "PENDING") status = "待执行";
      else if (status == "FAILED") status = errMsg.isEmpty() ? "失败" : QString("失败: %1").arg(errMsg.left(40));
      else if (status == "STOPPED") status = "已停止";
      m_captureTaskTable->setItem(i, 2, new QTableWidgetItem(status));
      m_captureTaskTable->setItem(i, 3, new QTableWidgetItem(QString::number(r["packet_count"].toInt())));
      qint64 sizeBytes = r["file_size_bytes"].toInt();
      QString sizeStr = sizeBytes > 1048576 ? QString("%1 MB").arg(sizeBytes / 1048576.0, 0, 'f', 1)
                       : sizeBytes > 1024 ? QString("%1 KB").arg(sizeBytes / 1024.0, 0, 'f', 1)
                       : QString("%1 B").arg(sizeBytes);
      m_captureTaskTable->setItem(i, 4, new QTableWidgetItem(sizeStr));
    }



    m_captureTaskTable->setSortingEnabled(sorting);
    // Start/stop polling based on running tasks
    if (hasRunning && !m_capturePollTimer->isActive()) {
      m_capturePollTimer->start();
    } else if (!hasRunning && m_capturePollTimer->isActive()) {
      m_capturePollTimer->stop();
    }
  });
}

void EvaluatePage::onLoadInterfaces() {
  m_api->get("/api/capture-tasks/interfaces/list", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    if (arr.isEmpty()) return;
    QString current = m_interfaceCombo->currentData().toString();
    if (current.isEmpty()) current = m_interfaceCombo->currentText();
    m_interfaceCombo->clear();
    for (int i = 0; i < arr.size(); i++) {
      const QString interfaceName = arr[i].toString();
      if (interfaceName == "any") {
        m_interfaceCombo->addItem("任意接口", interfaceName);
      } else {
        m_interfaceCombo->addItem(interfaceName, interfaceName);
      }
    }
    // Restore previous selection if still available
    int idx = m_interfaceCombo->findData(current);
    if (idx >= 0) m_interfaceCombo->setCurrentIndex(idx);
  });
}

void EvaluatePage::onCreateCapture() {
  if (!m_createCaptureBtn->isEnabled()) return;

  QJsonObject body;
  QString interfaceName = m_interfaceCombo->currentData().toString();
  body["interface"] = interfaceName.isEmpty() ? m_interfaceCombo->currentText() : interfaceName;
  body["bpf_filter"] = m_bpfInput->text();
  body["capture_type"] = m_captureTypeCombo->currentIndex() == 0 ? "timed" : "manual";
  body["duration_sec"] = m_durationSpin->value();

  m_createCaptureBtn->setEnabled(false);
  m_createCaptureBtn->setText("创建中...");
  m_startCaptureBtn->setEnabled(false);
  m_captureStatusLabel->setText("正在创建捕获任务...");

  m_api->post("/api/capture-tasks", body, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      m_createCaptureBtn->setEnabled(true);
      m_createCaptureBtn->setText("+ 新建捕获");
      m_startCaptureBtn->setEnabled(true);
      m_captureStatusLabel->setText("创建捕获任务失败：" + res["error"].toObject()["message"].toString());
      return;
    }
    auto d = res["data"].toObject();
    QString taskId = d["capture_task_id"].toString();
    if (taskId.isEmpty()) {
      m_createCaptureBtn->setEnabled(true);
      m_createCaptureBtn->setText("+ 新建捕获");
      m_startCaptureBtn->setEnabled(true);
      m_captureStatusLabel->setText("创建捕获任务失败：服务端未返回任务编号。");
      return;
    }
    // Auto-start the capture
    m_api->post("/api/capture-tasks/" + taskId + "/start", QJsonObject(), 5000, [this](const QJsonObject &startRes) {
      m_createCaptureBtn->setEnabled(true);
      m_createCaptureBtn->setText("+ 新建捕获");
      if (startRes["status"].toString() != "ok") {
        m_startCaptureBtn->setEnabled(true);
        m_stopCaptureBtn->setEnabled(false);
        QMessageBox::warning(this->window(), "启动失败",
          QString("捕获任务已创建但启动失败：%1").arg(startRes["error"].toObject()["message"].toString()));
      } else {
        m_startCaptureBtn->setEnabled(false);
        m_stopCaptureBtn->setEnabled(true);
        m_captureStatusLabel->setText("捕获任务已启动。");
      }
      onLoadCaptureTasks();
    });
  });
}

void EvaluatePage::onStartCapture() {
  // Create and start in one flow
  onCreateCapture();
}

void EvaluatePage::onStopCapture() {
  if (m_selectedCaptureTaskId.isEmpty()) return;
  const QString taskId = m_selectedCaptureTaskId;
  m_stopCaptureBtn->setEnabled(false);
  m_captureStatusLabel->setText("正在停止捕获任务...");
  m_api->post("/api/capture-tasks/" + taskId + "/stop", QJsonObject(), 5000, [this, taskId](const QJsonObject &res) {
    if (taskId != m_selectedCaptureTaskId) return;
    if (res["status"].toString() != "ok") {
      m_stopCaptureBtn->setEnabled(true);
      m_captureStatusLabel->setText("停止捕获失败：" + res["error"].toObject()["message"].toString());
      return;
    }
    m_stopCaptureBtn->setEnabled(false);
    m_startCaptureBtn->setEnabled(true);
    m_captureStatusLabel->setText("捕获任务已停止。");
    onLoadCaptureTasks();
  });
}

void EvaluatePage::onCaptureTaskClicked(int row, int) {
  auto *idItem = m_captureTaskTable->item(row, 0);
  if (!idItem) return;
  m_selectedCaptureTaskId = idItem->text();
  m_delCaptureBtn->setEnabled(true);

  // Check if this task is running
  auto *statusItem = m_captureTaskTable->item(row, 2);
  bool isRunning = statusItem && statusItem->text() == "运行中";
  m_stopCaptureBtn->setEnabled(isRunning);

  // Fetch full task detail and update status label
  const QString taskId = m_selectedCaptureTaskId;
  m_api->get("/api/capture-tasks/" + taskId, 5000, [this, taskId](const QJsonObject &res) {
    if (taskId != m_selectedCaptureTaskId || res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();
    int packets = d["packet_count"].toInt();
    qint64 sizeBytes = d["file_size_bytes"].toInt();
    QString sizeStr = sizeBytes > 1048576 ? QString("%1 MB").arg(sizeBytes / 1048576.0, 0, 'f', 1)
                     : sizeBytes > 1024 ? QString("%1 KB").arg(sizeBytes / 1024.0, 0, 'f', 1)
                     : QString("%1 B").arg(sizeBytes);
    QString statusCn;
    if (status == "RUNNING") statusCn = "运行中";
    else if (status == "COMPLETED") statusCn = "已完成";
    else if (status == "STOPPED") statusCn = "已停止";
    else if (status == "FAILED") statusCn = "失败";
    else if (status == "PENDING") statusCn = "待执行";
    else statusCn = status;
    QString errMsg = d["error_message"].toString();
    m_captureStatusLabel->setText(
      QString("状态: %1 | 数据包: %2 | PCAP: %3%4")
        .arg(statusCn)
        .arg(packets)
        .arg(sizeStr)
        .arg(errMsg.isEmpty() ? "" : QString("\n错误: %1").arg(errMsg)));

    // Enable/disable analysis button based on status
    bool canAnalyze = (status == "COMPLETED" || status == "STOPPED");
    m_runAnalysisBtn->setEnabled(canAnalyze);

    // Auto-load existing analysis results for this capture
    if (canAnalyze) {
      loadAnalysisForCapture(m_selectedCaptureTaskId);
    } else {
      // Clear analysis area
      m_analysisResultTable->setRowCount(0);
      m_analysisDetail->clear();
      if (status == "RUNNING") {
        m_analysisDetail->setPlaceholderText("捕获进行中，完成后可分析");
      } else {
        m_analysisDetail->setPlaceholderText("点击分析结果行查看详情");
      }
    }
  });
}

void EvaluatePage::onDeleteCaptureTask() {
  if (m_selectedCaptureTaskId.isEmpty()) return;
  auto reply = QMessageBox::question(this->window(), "确认删除",
    QString("确定要删除此捕获任务及其 PCAP 文件吗？"),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;
  m_api->del("/api/capture-tasks/" + m_selectedCaptureTaskId, 5000, [this](const QJsonObject &) {
    m_selectedCaptureTaskId.clear();
    m_delCaptureBtn->setEnabled(false);
    m_runAnalysisBtn->setEnabled(false);
    m_analysisResultTable->setRowCount(0);
    m_analysisDetail->clear();
    m_captureStatusLabel->setText("选择左侧捕获任务查看详情");
    onLoadCaptureTasks();
  });
}

void EvaluatePage::onCapturePollStatus() {
  onLoadCaptureTasks();
  // If a capture was selected and is now complete, refresh its analysis
  if (!m_selectedCaptureTaskId.isEmpty()) {
    loadAnalysisForCapture(m_selectedCaptureTaskId);
  }
}

// ── Analysis (integrated into capture tab) ────────────────────────────

void EvaluatePage::onRunAnalysis() {
  if (m_selectedCaptureTaskId.isEmpty()) return;

  m_runAnalysisBtn->setEnabled(false);
  m_runAnalysisBtn->setText("分析中...");
  m_api->post("/api/capture-tasks/" + m_selectedCaptureTaskId + "/analyze", QJsonObject(), 10000,
    [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      m_runAnalysisBtn->setEnabled(true);
      m_runAnalysisBtn->setText("🔍 分析");
      return;
    }
    // Analysis is async on the backend — start polling for results
    m_analysisPollCaptureId = m_selectedCaptureTaskId;
    m_analysisPollCount = 0;
    m_analysisPollTimer->start(2000);  // first poll after 2s
  });
}

void EvaluatePage::onPollAnalysisResults() {
  if (m_analysisPollCaptureId.isEmpty()) {
    m_runAnalysisBtn->setEnabled(true);
    m_runAnalysisBtn->setText("🔍 分析");
    return;
  }

  m_api->get("/api/capture-tasks/" + m_analysisPollCaptureId + "/analysis", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      m_runAnalysisBtn->setEnabled(true);
      m_runAnalysisBtn->setText("🔍 分析");
      m_analysisPollCaptureId.clear();
      m_analysisPollCount = 0;
      return;
    }
    auto arr = res["data"].toArray();

    // If no results yet, keep polling (max ~30s via 15 polls × 2s)
    if (arr.isEmpty()) {
      if (++m_analysisPollCount < 15) {
        m_analysisPollTimer->start(2000);
        return;
      }
      // Timed out waiting for results
      m_runAnalysisBtn->setEnabled(true);
      m_runAnalysisBtn->setText("🔍 分析");
      m_analysisPollCaptureId.clear();
      m_analysisPollCount = 0;
      return;
    }

    // Got results — reset and display
    m_analysisPollCount = 0;
    m_runAnalysisBtn->setEnabled(true);
    m_runAnalysisBtn->setText("🔍 重新分析");
    m_analysisPollCaptureId.clear();

    populateAnalysisTable(arr);
  });
}

void EvaluatePage::onAnalysisResultClicked(int row, int) {
  auto *item = m_analysisResultTable->item(row, 0);
  if (!item) return;
  const auto r = item->data(Qt::UserRole).toJsonObject();
    QString dataStr = r["analysis_data"].toString();
    QJsonDocument doc = QJsonDocument::fromJson(dataStr.toUtf8());

    QStringList lines;
    lines << QString("=== %1 ===").arg(formatAnalysisType(r["analysis_type"].toString()));
    lines << QString("严重度: %1").arg(formatSeverity(r["severity"].toString()));
    lines << "";

    if (!doc.isNull()) {
      lines << QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
    } else {
      lines << dataStr;
    }
    m_analysisDetail->setPlainText(lines.join("\n"));
}


// ── Helper: load analysis results for a capture task ─────────────────
void EvaluatePage::loadAnalysisForCapture(const QString &captureTaskId) {
  m_api->get("/api/capture-tasks/" + captureTaskId + "/analysis", 5000, [this, captureTaskId](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();

    if (arr.isEmpty()) {
      m_analysisResultTable->setRowCount(0);
      m_analysisDetail->clear();
      m_runAnalysisBtn->setText("🔍 分析");
      return;
    }

    // Has existing analysis — show results, button becomes "重新分析"
    m_runAnalysisBtn->setText("🔍 重新分析");
    populateAnalysisTable(arr);
  });
}

// ── Helper: populate analysis result table ───────────────────────────
void EvaluatePage::populateAnalysisTable(const QJsonArray &arr) {
  const bool sorting = m_analysisResultTable->isSortingEnabled();
    m_analysisResultTable->setSortingEnabled(false);
    m_analysisResultTable->setRowCount(arr.size());
  for (int i = 0; i < arr.size(); i++) {
    auto r = arr[i].toObject();
    m_analysisResultTable->setItem(i, 0, new QTableWidgetItem(formatAnalysisType(r["analysis_type"].toString())));
    m_analysisResultTable->item(i, 0)->setData(Qt::UserRole, r);
    m_analysisResultTable->setItem(i, 1, new QTableWidgetItem(formatSeverity(r["severity"].toString())));

    // Extract a summary from analysis_data JSON
    QString dataStr = r["analysis_data"].toString();
    QJsonDocument dataDoc = QJsonDocument::fromJson(dataStr.toUtf8());
    QString summary;
    if (!dataDoc.isNull()) {
      QJsonObject dataObj = dataDoc.object();
      if (dataObj.contains("protocols")) summary = QString("%1 种协议").arg(dataObj["protocols"].toArray().size());
      else if (dataObj.contains("conversations")) summary = QString("%1 条会话").arg(dataObj["conversations"].toArray().size());
      else if (dataObj.contains("credentials")) summary = QString("%1 条凭据").arg(dataObj["credentials"].toArray().size());
      else if (dataObj.contains("anomalies")) summary = QString("%1 条异常").arg(dataObj["anomalies"].toArray().size());
      else if (dataObj.contains("mappings")) summary = QString("%1 项映射").arg(dataObj["mappings"].toArray().size());
      else summary = dataStr.left(100);
    } else {
      summary = dataStr.left(100);
    }
    m_analysisResultTable->setItem(i, 2, new QTableWidgetItem(summary));
    m_analysisResultTable->setItem(i, 3, new QTableWidgetItem(r["created_at"].toString()));
  }    m_analysisResultTable->setSortingEnabled(sorting);



}

// ── Helper: format analysis type ─────────────────────────────────────
QString EvaluatePage::formatAnalysisType(const QString &type) const {
  if (type == "protocol_breakdown") return "协议分布";
  if (type == "conversation") return "会话统计";
  if (type == "credential") return "凭据发现";
  if (type == "anomaly") return "异常检测";
  if (type == "mitre_mapping") return "MITRE映射";
  return type;
}

// ── Helper: format severity ──────────────────────────────────────────
QString EvaluatePage::formatSeverity(const QString &sev) const {
  if (sev == "critical") return "严重";
  if (sev == "high") return "高危";
  if (sev == "medium") return "中危";
  if (sev == "low") return "低危";
  return sev;
}
