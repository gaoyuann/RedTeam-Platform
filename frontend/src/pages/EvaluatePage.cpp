#include "EvaluatePage.h"
#include "../ApiClient.h"
#include "../Theme.h"
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

EvaluatePage::EvaluatePage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
  onLoadRuns();
  onRefreshReports();
  onLoadEvidenceRuns();
}

void EvaluatePage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *scrollArea = new QScrollArea(this);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);
  m_tabs = new QTabWidget;

  // ── Tab 1: Grading ────────────────────────────────────────────────
  auto *gradeW = new QWidget;
  auto *gradeL = new QVBoxLayout(gradeW);

  auto *selectH = new QHBoxLayout;
  selectH->addWidget(new QLabel("执行记录:"));
  m_runCombo = new QComboBox;
  selectH->addWidget(m_runCombo, 1);
  m_gradeBtn = new QPushButton("评分");
  m_gradeBtn->setProperty("primary", true);
  selectH->addWidget(m_gradeBtn);
  gradeL->addLayout(selectH);
  connect(m_gradeBtn, &QPushButton::clicked, this, &EvaluatePage::onGradeRun);

  m_scoreLabel = new QLabel("选择执行记录后点击评分");
  m_scoreLabel->setStyleSheet(Theme::SectionStyle);
  gradeL->addWidget(m_scoreLabel);

  m_mitreLabel = new QLabel;
  gradeL->addWidget(m_mitreLabel);

  m_stepTable = new QTableWidget(0, 5);
  m_stepTable->setHorizontalHeaderLabels({"步骤", "工具", "满分", "得分", "状态"});
  m_stepTable->setAlternatingRowColors(true);
  m_stepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_stepTable->setSortingEnabled(true);
  m_stepTable->setContextMenuPolicy(Qt::CustomContextMenu);
  gradeL->addWidget(m_stepTable);

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
  m_reportTable->setHorizontalHeaderLabels({"报告ID", "标题", "关联Run", "状态", "创建时间"});
  m_reportTable->setAlternatingRowColors(true);
  m_reportTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_reportTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_reportTable->setSortingEnabled(true);
  m_reportTable->setContextMenuPolicy(Qt::CustomContextMenu);
  rptL->addWidget(m_reportTable, 1);
  connect(m_reportTable, &QTableWidget::cellClicked, this, &EvaluatePage::onReportClicked);

  m_reportDetail = new QTextEdit;
  m_reportDetail->setReadOnly(true);
  rptL->addWidget(m_reportDetail);

  auto *rptBtnH = new QHBoxLayout;
  m_delReportBtn = new QPushButton("删除选中报告");
  m_delReportBtn->setProperty("danger", true);
  m_delReportBtn->setEnabled(false);
  auto *rptRefresh = new QPushButton("刷新");
  rptBtnH->addWidget(m_delReportBtn);
  rptBtnH->addStretch();
  rptBtnH->addWidget(rptRefresh);
  rptL->addLayout(rptBtnH);
  connect(m_delReportBtn, &QPushButton::clicked, this, &EvaluatePage::onDeleteReport);
  connect(rptRefresh, &QPushButton::clicked, this, &EvaluatePage::onRefreshReports);

  m_tabs->addTab(rptW, "测试报告");

  // ── Tab 3: Evidence ────────────────────────────────────────────────
  auto *evW = new QWidget;
  auto *evL = new QVBoxLayout(evW);

  auto *evSelectH = new QHBoxLayout;
  evSelectH->addWidget(new QLabel("执行记录:"));
  m_evidenceRunCombo = new QComboBox;
  evSelectH->addWidget(m_evidenceRunCombo, 1);
  evL->addLayout(evSelectH);
  connect(m_evidenceRunCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
          this, &EvaluatePage::onEvidenceRunSelected);

  m_evidenceTable = new QTableWidget(0, 5);
  m_evidenceTable->setHorizontalHeaderLabels({"步骤", "类型", "数据摘要", "MITRE命中", "建议"});
  m_evidenceTable->setAlternatingRowColors(true);
  m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_evidenceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_evidenceTable->setSortingEnabled(true);
  m_evidenceTable->setContextMenuPolicy(Qt::CustomContextMenu);
  evL->addWidget(m_evidenceTable, 1);
  connect(m_evidenceTable, &QTableWidget::cellClicked, this, &EvaluatePage::onEvidenceClicked);

  m_evidenceDetail = new QTextEdit;
  m_evidenceDetail->setReadOnly(true);
  m_evidenceDetail->setPlaceholderText("点击证据行查看完整数据");
  evL->addWidget(m_evidenceDetail, 1);

  m_tabs->addTab(evW, "攻击证据");

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
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
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

  scrollArea->setWidget(container);
  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->addWidget(scrollArea);
}

void EvaluatePage::onLoadRuns() {
  m_api->get("/api/runs", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    m_runCombo->clear();
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
      m_runCombo->addItem(label, r["run_id"].toString());
    }
    // Pre-select the first (newest) run and auto-grade
    if (m_runCombo->count() > 0) {
      onGradeRun();
    }
  });
}

void EvaluatePage::onGradeRun() {
  QString runId = m_runCombo->currentData().toString();
  if (runId.isEmpty()) return;
  m_selectedRunId = runId;
  m_gradeBtn->setEnabled(false);

  m_api->post("/api/runs/" + runId + "/grade", QJsonObject(), 5000, [this](const QJsonObject &res) {
    m_gradeBtn->setEnabled(true);
    if (res["status"].toString() != "ok") return;
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
    m_stepTable->setRowCount(breakdown.size());
    for (int i = 0; i < breakdown.size(); i++) {
      auto s = breakdown[i].toObject();
      m_stepTable->setItem(i, 0, new QTableWidgetItem(QString::number(s["stepIndex"].toInt())));
      m_stepTable->setItem(i, 1, new QTableWidgetItem(s["toolId"].toString()));
      m_stepTable->setItem(i, 2, new QTableWidgetItem(QString::number(s["score"].toInt())));
      m_stepTable->setItem(i, 3, new QTableWidgetItem(QString::number(s["earned"].toInt())));
      m_stepTable->setItem(i, 4, new QTableWidgetItem(s["success"].toBool() ? "通过" : "失败"));
    }
    m_stepTable->resizeColumnsToContents();
    m_stepTable->horizontalHeader()->setStretchLastSection(true);
    m_genReportBtn->setEnabled(true);
  });
}

void EvaluatePage::onGenerateReport() {
  if (m_selectedRunId.isEmpty()) return;
  QJsonObject body;
  body["run_id"] = m_selectedRunId;
  m_api->post("/api/reports/generate", body, 5000, [this](const QJsonObject &) {
    onRefreshReports();
  });
}

void EvaluatePage::onRefreshReports() {
  m_api->get("/api/reports", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_reportTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      m_reportTable->setItem(i, 0, new QTableWidgetItem(r["report_id"].toString()));
      m_reportTable->setItem(i, 1, new QTableWidgetItem(r["title"].toString()));
      m_reportTable->setItem(i, 2, new QTableWidgetItem(r["run_id"].toString()));
      QString rptStatus = r["status"].toString();
      if (rptStatus == "COMPLETED") rptStatus = "已完成";
      else if (rptStatus == "PENDING") rptStatus = "待生成";
      else if (rptStatus == "FAILED") rptStatus = "生成失败";
      m_reportTable->setItem(i, 3, new QTableWidgetItem(rptStatus));
      m_reportTable->setItem(i, 4, new QTableWidgetItem(r["created_at"].toString()));
    }
    m_reportTable->resizeColumnsToContents();
    m_reportTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void EvaluatePage::onReportClicked(int row, int) {
  auto *idItem = m_reportTable->item(row, 0);
  if (!idItem) return;
  QString id = idItem->text();
  m_selectedReportId = id;
  m_delReportBtn->setEnabled(true);

  m_api->get("/api/reports/" + id, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString content = d["content"].toString();
    if (content.isEmpty()) {
      m_reportDetail->setText("（报告内容为空）");
    } else {
      // Try to pretty-print JSON
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
    m_reportDetail->clear();
    onRefreshReports();
  });
}

// ── Evidence Tab ─────────────────────────────────────────────────────
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
    // Auto-select first run to show evidence
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

    if (evidence.isEmpty()) {
      m_evidenceDetail->setText("该执行记录无攻击证据数据");
    } else {
      m_evidenceDetail->clear();
    }
  });
}

void EvaluatePage::onEvidenceClicked(int row, int) {
  if (row < 0) return;
  // Store full evidence data in the detail view
  QString runId = m_evidenceRunCombo->currentData().toString();
  if (runId.isEmpty()) return;

  m_api->get("/api/runs/" + runId, 5000, [this, row](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto evidence = res["data"].toObject()["evidence"].toArray();
    if (row >= evidence.size()) return;

    auto e = evidence[row].toObject();
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
    m_evidenceDetail->setText(lines.join("\n"));
  });
}
