#pragma once

#include "../ApiClient.h"
#include "../UiUtil.h"
#include "FindingVerificationDialog.h"
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QSignalBlocker>
#include <QShowEvent>
#include <QTableWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <functional>
#include <algorithm>

// A read-only index over the existing scan findings and verification plans.
// Opening an editor reuses the same verification, revision and execution history.
class FindingPlanPanel : public QWidget {
public:
  explicit FindingPlanPanel(ApiClient *api, QWidget *parent = nullptr) : QWidget(parent), m_api(api) {
    setObjectName("findingPlanPanel");
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    auto *actions = new QHBoxLayout;
    m_status = new QLabel(QStringLiteral("选择测试任务后查看漏洞预案"), this);
    m_status->setTextFormat(Qt::PlainText); m_status->setWordWrap(true);
    actions->addWidget(m_status, 1);
    m_refresh = new QPushButton(QStringLiteral("刷新预案列表"), this);
    m_refresh->setObjectName("findingPlanRefresh"); actions->addWidget(m_refresh);
    m_scan = new QPushButton(QStringLiteral("返回扫描发现"), this);
    m_scan->setObjectName("findingPlanScan"); actions->addWidget(m_scan);
    m_global = new QPushButton(QStringLiteral("查看整体编排预案"), this);
    m_global->setObjectName("findingPlanGlobal"); m_global->hide(); actions->addWidget(m_global);
    layout->addLayout(actions);
    m_table = new QTableWidget(0, 8, this);
    m_table->setObjectName("findingPlanTable");
    m_table->setHorizontalHeaderLabels({"发现编号", "漏洞", "目标 / 位置", "来源扫描", "预案版本", "预案状态", "最近执行", "验证结论"});
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_table->verticalHeader()->hide();
    m_table->setWordWrap(false); m_table->setTextElideMode(Qt::ElideMiddle);
    UiUtil::EmptyHint::attach(m_table, QStringLiteral("尚无漏洞候选，请先扫描目标；打开本页不会创建预案或执行攻击。"));
    layout->addWidget(m_table, 2);
    m_detail = new QPlainTextEdit(this); m_detail->setReadOnly(true);
    m_detail->setObjectName("findingPlanDetail"); m_detail->setMinimumHeight(100);
    layout->addWidget(m_detail, 1);
    auto *footer = new QHBoxLayout;
    m_more = new QPushButton(QStringLiteral("加载更多漏洞"), this);
    m_more->setObjectName("findingPlanMore"); footer->addWidget(m_more); footer->addStretch();
    m_open = new QPushButton(QStringLiteral("编制 / 查看所选预案"), this);
    m_open->setObjectName("findingPlanOpen"); m_open->setProperty("primary", true); footer->addWidget(m_open);
    layout->addLayout(footer);
    connect(m_refresh, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(m_more, &QPushButton::clicked, this, [this]() { refresh(true); });
    connect(m_scan, &QPushButton::clicked, this, [this]() { if (scanRequested) scanRequested(); });
    connect(m_global, &QPushButton::clicked, this, [this]() { if (globalPlanRequested) globalPlanRequested(); });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() { updateControls(); showSelection(); });
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this]() { openSelection(); });
    connect(m_open, &QPushButton::clicked, this, [this]() { openSelection(); });
    updateControls();
  }

  std::function<void()> changed, scanRequested, globalPlanRequested;
  std::function<void(const QString &)> executionStarted, assessmentRequested;

  void setGlobalPlanAvailable(bool available) { m_global->setVisible(available); }

  void setTask(const QString &pipeline) {
    if (pipeline == m_pipeline) return;
    ++m_generation; ++m_request; ++m_selection;
    m_pipeline = pipeline; m_busy = false; m_fresh = false; m_hasMore = false;
    m_cursor = m_through = 0;
    if (m_editor) m_editor->close();
    m_editor.clear(); m_editorIds.clear();
    m_table->setRowCount(0); m_detail->clear(); updateControls();
    if (!pipeline.isEmpty()) refresh();
    else m_status->setText(QStringLiteral("选择测试任务后查看漏洞预案"));
  }

  void refresh(bool append = false) {
    if (m_pipeline.isEmpty() || m_busy || (append && !m_hasMore)) return;
    m_busy = true; m_fresh = false; updateControls();
    ++m_selection;
    const auto generation = m_generation, request = ++m_request;
    const QString pipeline = m_pipeline;
    const auto selected = selectedIds();
    QString path = "/api/pipelines/" + QString::fromLatin1(QUrl::toPercentEncoding(pipeline))
      + "/results?view=scans&category=vulnerability&limit=100&after=" + QString::number(append ? m_cursor : 0);
    if (append) path += "&through=" + QString::number(m_through);
    m_status->setText(QStringLiteral("正在读取本次测试的漏洞与预案…"));
    QPointer<FindingPlanPanel> guard(this);
    m_api->get(path, 10000, [guard,generation,request,append,selected](const QJsonObject &response) {
      if (!guard || generation != guard->m_generation || request != guard->m_request) return;
      guard->m_busy = false;
      const auto data = response["data"].toObject(), page = data["page"].toObject();
      const qint64 next = page["next_after"].toVariant().toLongLong();
      const qint64 through = page["through"].toVariant().toLongLong();
      if (response["status"] != "ok" || !data["scan_records"].isArray() || !data["page"].isObject()
          || (page["has_more"].toBool() && next <= (append ? guard->m_cursor : 0))
          || (append && through != guard->m_through)) {
        guard->m_status->setText(QStringLiteral("预案列表读取失败，保留已有内容；请刷新重试。")
          + response["error"].toObject()["message"].toString());
        guard->m_detail->setPlainText(QStringLiteral("列表尚未核实，暂不能打开旧记录；已打开的预案草稿保持不变。"));
        guard->updateControls(); return;
      }
      const QSignalBlocker block(guard->m_table);
      if (!append) guard->m_table->setRowCount(0);
      QSet<qint64> known;
      for (int row = 0; row < guard->m_table->rowCount(); ++row) known.insert(guard->record(row)["id"].toVariant().toLongLong());
      for (const auto &value : data["scan_records"].toArray()) {
        const auto record = value.toObject(); const qint64 id = record["id"].toVariant().toLongLong();
        if (id <= 0 || record["category"] != "vulnerability" || known.contains(id)) continue;
        known.insert(id);
        const auto finding = object(record["result_data"]), verification = record["verification"].toObject();
        const int revision = verification["revision"].toInt();
        const auto result = verification["result"].toObject();
        const QStringList cells{QString::number(id), finding["title"].toString(finding["name"].toString(finding["finding"].toString(record["result_type"].toString()))),
          finding["url"].toString(finding["host"].toString(finding["file"].toString(finding["path"].toString()))), record["scan_task_id"].toString(),
          revision > 0 ? "v" + QString::number(revision) : QStringLiteral("未编制"),
          revision > 0 ? state(verification["state"].toString()) : QStringLiteral("待引用 / 编制"),
          verification["attempt_id"].toString().isEmpty() ? QStringLiteral("尚未执行")
            : verification["run_id"].toString(QStringLiteral("已有记录 · 查看历史")),
          result.isEmpty() ? QStringLiteral("尚无验证结论") : state(result["status"].toString())};
        const int row = guard->m_table->rowCount(); guard->m_table->insertRow(row);
        for (int col = 0; col < cells.size(); ++col) {
          auto *item = new QTableWidgetItem(cells[col]); item->setToolTip(cells[col]);
          if (!col) item->setData(Qt::UserRole, record);
          guard->m_table->setItem(row, col, item);
        }
      }
      guard->m_cursor = next; guard->m_through = through;
      guard->m_hasMore = page["has_more"].toBool(); guard->m_fresh = true;
      const auto restore = selected.isEmpty() ? guard->m_editorIds : selected;
      bool currentSet = false;
      for (int row = 0; row < guard->m_table->rowCount(); ++row)
        if (restore.contains(guard->record(row)["id"].toVariant().toLongLong())) {
          if (!currentSet) { guard->m_table->setCurrentCell(row,0); currentSet = true; }
          for (int col = 0; col < guard->m_table->columnCount(); ++col) guard->m_table->item(row,col)->setSelected(true);
        }
      guard->m_status->setText(QStringLiteral("本次测试 · 已加载 %1 个漏洞；预案版本与实际验证结论分别保留。%2")
        .arg(guard->m_table->rowCount()).arg(guard->m_hasMore ? QStringLiteral("还有更多记录。") : QString()));
      guard->updateControls(); guard->showSelection();
    });
  }

  void openFindings(QList<qint64> ids) {
    if (m_pipeline.isEmpty() || ids.isEmpty()) return;
    std::sort(ids.begin(), ids.end()); ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    if (ids.first() <= 0) return;
    if (m_editor && m_editorIds == ids) { m_editor->show(); m_editor->raise(); m_editor->activateWindow(); return; }
    if (m_editor) {
      m_editor->show(); m_editor->raise();
      m_status->setText(QStringLiteral("请先保存并关闭当前预案，再编制其他漏洞；已有草稿已保留。")); return;
    }
    const auto generation = m_generation;
    const QString pipeline = m_pipeline;
    QString existing;
    if (ids.size() == 1) for (int row = 0; row < m_table->rowCount(); ++row)
      if (record(row)["id"].toVariant().toLongLong() == ids.first()) existing = record(row)["verification"].toObject()["id"].toString();
    auto *editor = new FindingVerificationDialog(m_api,pipeline,ids,this,existing);
    m_editor = editor; m_editorIds = ids;
    editor->setObjectName("findingPlanEditor"); editor->setAttribute(Qt::WA_DeleteOnClose);
    connect(editor, &FindingVerificationDialog::verificationStarted, this, [this,generation,pipeline](const QString &id) {
      if (generation != m_generation || pipeline != m_pipeline || id != pipeline) return;
      if (executionStarted) executionStarted(pipeline);
    });
    connect(editor, &FindingVerificationDialog::assessmentRequested, this, [this,generation,pipeline](const QString &id) {
      if (generation == m_generation && pipeline == m_pipeline && id == pipeline && assessmentRequested) assessmentRequested(pipeline);
    });
    connect(editor, &QDialog::finished, this, [this,generation,pipeline,editor]() {
      if (m_editor == editor) { m_editor.clear(); m_editorIds.clear(); }
      if (generation != m_generation || pipeline != m_pipeline) return;
      refresh(); if (changed) changed();
    });
    editor->showPlanWorkspace(); editor->show();
  }

protected:
  void showEvent(QShowEvent *event) override {
    QWidget::showEvent(event);
    if (!m_busy && !m_editor) refresh();
  }

private:
  static QJsonObject object(const QJsonValue &value) {
    return value.isObject() ? value.toObject() : QJsonDocument::fromJson(value.toString().toUtf8()).object();
  }
  static QString state(const QString &value) {
    const QMap<QString,QString> labels{{"draft","已编制 · 待确认"},{"ready","已确认"},{"needs_conditions","待补条件"},
      {"preparation_failed","编制失败"},{"queued","已保存 · 排队中"},{"running","已保存 · 执行中"},{"cancelling","已保存 · 取消中"},
      {"unknown","停止待核查"},{"completed","已保存"},{"failed","已保存 · 执行异常"},{"aborted","已保存 · 已中止"},
      {"achieved","目标已达成"},{"not_achieved","目标未达成"},{"not_performed","未开展适用验证"},{"inconclusive","证据不足"},{"pending","等待验证结果"}};
    return labels.value(value,QStringLiteral("未知 / 待核对"));
  }
  QJsonObject record(int row) const {
    return m_table->item(row,0) ? m_table->item(row,0)->data(Qt::UserRole).toJsonObject() : QJsonObject{};
  }
  QList<qint64> selectedIds() const {
    QList<qint64> ids;
    for (const auto &index : m_table->selectionModel()->selectedRows()) ids << record(index.row())["id"].toVariant().toLongLong();
    return ids;
  }
  void openSelection() { if (m_fresh && !m_busy) openFindings(selectedIds()); }
  void updateControls() {
    m_refresh->setEnabled(!m_pipeline.isEmpty() && !m_busy);
    m_scan->setEnabled(!m_pipeline.isEmpty());
    m_more->setVisible(m_hasMore); m_more->setEnabled(!m_busy && m_fresh);
    m_open->setEnabled(m_fresh && !m_busy && !selectedIds().isEmpty());
  }
  void showSelection() {
    ++m_selection;
    if (m_busy || !m_fresh) return;
    const int row = m_table->currentRow(); const auto found = record(row);
    if (found.isEmpty()) { m_detail->setPlainText(QStringLiteral("选择漏洞编制或引用预案；确认预案版本后再执行攻击测试。")); return; }
    const auto summary = found["verification"].toObject();
    m_detail->setPlainText(QStringLiteral("发现 #%1\n来源扫描：%2\n扫描证据：\n%3")
      .arg(found["id"].toVariant().toString(),found["scan_task_id"].toString(),found["result_data"].toString()));
    const QString id = summary["id"].toString(); if (id.isEmpty()) return;
    const auto generation = m_generation, selection = m_selection;
    QPointer<FindingPlanPanel> guard(this);
    m_api->get("/api/pipelines/" + QString::fromLatin1(QUrl::toPercentEncoding(m_pipeline)) + "/verifications/" + QString::fromLatin1(QUrl::toPercentEncoding(id)),10000,
      [guard,generation,selection,id,found](const QJsonObject &response) {
        if (!guard || generation != guard->m_generation || selection != guard->m_selection) return;
        const auto detail = response["data"].toObject();
        if (response["status"] != "ok" || detail["id"] != id || detail["finding_id"] != found["id"]) {
          guard->m_detail->appendPlainText(QStringLiteral("\n预案详情读取失败或来源不符，请刷新重试。")); return;
        }
        const auto plan = detail["plans"].toArray().isEmpty() ? QJsonObject{} : detail["plans"].toArray().first().toObject();
        const auto content = plan["content"].toObject(), provenance = content["provenance"].toObject();
        QString text = QStringLiteral("发现 #%1 · 来源扫描 %2\n预案：%3 · v%4\n实际入口：%5\n来源预案：%6\n成功判据：%7\n清理要求：%8\n\n步骤、参数与预期证据：\n%9")
          .arg(found["id"].toVariant().toString(),found["scan_task_id"].toString(),content["name"].toString(QStringLiteral("尚未编制")),QString::number(plan["revision"].toInt()),
            content["target"].toString(detail["default_target"].toString()),provenance["label"].toString() + " · " + content["source_playbook_id"].toString(),
            content["success_criteria"].toString(),content["cleanup"].toString(),QString::fromUtf8(QJsonDocument(content["steps"].toArray()).toJson(QJsonDocument::Indented)));
        const auto attempts = detail["attempts"].toArray();
        if (!attempts.isEmpty()) {
          const auto attempt = attempts.first().toObject();
          text += QStringLiteral("\n最近执行：%1 · 使用预案 v%2\n验证结论：%3\n失败 / 停止原因：%4")
            .arg(attempt["run_id"].toString(),QString::number(attempt["revision"].toInt()),
              state(attempt["summary"].toObject()["result"].toObject()["status"].toString()),attempt["reason"].toString());
        }
        guard->m_detail->setPlainText(text);
      });
  }
  ApiClient *m_api;
  QString m_pipeline;
  int m_generation = 0, m_request = 0, m_selection = 0;
  qint64 m_cursor = 0, m_through = 0;
  bool m_busy = false, m_fresh = false, m_hasMore = false;
  QLabel *m_status;
  QTableWidget *m_table;
  QPlainTextEdit *m_detail;
  QPushButton *m_refresh, *m_scan, *m_more, *m_open, *m_global;
  QPointer<FindingVerificationDialog> m_editor;
  QList<qint64> m_editorIds;
};
