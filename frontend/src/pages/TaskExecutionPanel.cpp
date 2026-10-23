#include "TaskExecutionPanel.h"
#include "FindingVerificationDialog.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/MetricCard.h"
#include "../widgets/WorkbenchTabs.h"
#include <QDateTime>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QGroupBox>
#include <QMap>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QScrollBar>
#include <QSet>
#include <QSplitter>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

namespace {
QString stateText(const QString &state)
{
  const QMap<QString, QString> labels{{"PENDING", "待执行"}, {"RUNNING", "运行中"}, {"COMPLETED", "已完成"},
    {"FAILED", "失败"}, {"ABORTED", "已中止"}, {"SUCCEEDED", "工具成功"}, {"WAITING", "尚无结果"},
    {"NOT_RECORDED", "未记录结果"}, {"PASSED", "通过"}, {"SKIPPED", "已跳过"},
    {"draft", "草稿"}, {"submitted", "待审批"}, {"rejected", "已退回"}, {"approved", "已批准"},
    {"created", "已创建"}, {"running", "运行中"}, {"awaiting_approval", "待审批"}, {"paused", "已暂停"},
    {"completed", "执行结束"}, {"failed", "执行失败"}, {"cancelled", "已取消"},
    {"queued", "排队中"}, {"cancelling", "取消中"}, {"aborted", "已中止"}, {"unknown", "停止未确认"}};
  return labels.value(state, QStringLiteral("未知 / 未记录"));
}

QString verificationResultText(const QJsonObject &result)
{
  if(result.value("schema_version").toInt()!=1)return QStringLiteral("证据不足（旧版结果）");
  const QMap<QString,QString> labels{{"achieved","目标已达成"},{"not_achieved","目标未达成"},
    {"inconclusive","证据不足"},{"not_performed","未开展适用验证"},{"pending","等待结果"}};
  return labels.value(result.value("status").toString(),QStringLiteral("证据不足（未知状态）"));
}

QString sourceText(const QString &source)
{
  return source == "playbook" ? QStringLiteral("预案") : source == "react" ? QStringLiteral("AI 动态步骤") : QStringLiteral("来源未记录");
}

QString sourceStateText(const QString &state)
{
  return state == "linked" ? QStringLiteral("尝试已关联") : state == "legacy" ? QStringLiteral("旧记录 / 缺尝试编号")
    : state == "target_mismatch" ? QStringLiteral("目标不匹配 / 待核对") : QStringLiteral("尝试不匹配 / 待核对");
}

QString numberText(const QJsonValue &value)
{
  return value.isDouble() ? QString::number(value.toVariant().toLongLong()) : QStringLiteral("—");
}

QString timeText(const QString &value)
{
  auto time = QDateTime::fromString(value, Qt::ISODateWithMs);
  if (!time.isValid()) time = QDateTime::fromString(value, Qt::ISODate);
  if (!time.isValid()) {
    time = QDateTime::fromString(value, "yyyy-MM-dd HH:mm:ss");
    time.setTimeSpec(Qt::UTC);
  }
  return time.isValid() ? time.toLocalTime().toString("yyyy-MM-dd HH:mm:ss") : value.isEmpty() ? QStringLiteral("—") : value;
}

QLabel *label(QWidget *parent)
{
  auto *result = new QLabel(parent);
  result->setTextFormat(Qt::PlainText);
  result->setWordWrap(true);
  result->setTextInteractionFlags(Qt::TextSelectableByMouse);
  return result;
}

void setRow(QTableWidget *table, int row, const QStringList &values, const QJsonObject &record)
{
  for (int column = 0; column < values.size(); ++column) {
    auto *item = new QTableWidgetItem(values[column]);
    item->setToolTip(values[column].toHtmlEscaped());
    if (column == 0) item->setData(Qt::UserRole, record);
    table->setItem(row, column, item);
  }
}

bool safeId(const QJsonValue &value)
{
  const double number = value.toDouble(-1);
  return value.isDouble() && number >= 1 && number <= 9007199254740991.0 && number == value.toVariant().toLongLong();
}
}

TaskExecutionPanel::TaskExecutionPanel(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username)
{
  setObjectName("taskExecutionPanel");
  setStyleSheet(Theme::PageStyle);
  auto *outer = new QVBoxLayout(this);
  outer->setContentsMargins(8, 8, 8, 8);
  auto *heading = new QHBoxLayout;
  m_title = label(this);
  m_title->setText(QStringLiteral("执行记录：主预案与逐漏洞"));
  m_title->setStyleSheet(Theme::SectionStyle);
  heading->addWidget(m_title, 1);
  m_refresh = new QPushButton(QStringLiteral("刷新记录"), this);
  heading->addWidget(m_refresh);
  outer->addLayout(heading);
  m_state = label(this);
  m_identity = label(this);
  m_gate = label(this);
  outer->addWidget(m_state);
  m_parentDetails = new QGroupBox(QStringLiteral("主预案详情（可选批量编排，展开查看）"), this);
  m_parentDetails->setCheckable(true);
  m_parentDetails->setChecked(false);
  auto *parentLayout = new QVBoxLayout(m_parentDetails);
  auto *parentBody = new QWidget(m_parentDetails);
  auto *parentContent = new QVBoxLayout(parentBody);
  parentContent->setContentsMargins(0, 0, 0, 0);
  m_parentState = label(parentBody);
  parentContent->addWidget(m_parentState);
  parentContent->addWidget(m_identity);
  parentLayout->addWidget(parentBody);
  parentBody->hide();
  connect(m_parentDetails, &QGroupBox::toggled, parentBody, &QWidget::setVisible);
  outer->addWidget(m_parentDetails);
  auto *metrics = new QHBoxLayout;
  const QStringList titles{QStringLiteral("主预案 Run 状态"), QStringLiteral("主预案已返回 / 步骤"), QStringLiteral("主预案工具调用"), QStringLiteral("主预案证据")};
  for (int index = 0; index < 4; ++index) {
    m_metrics[index] = new MetricCard(titles[index], Theme::Primary, this);
    m_metrics[index]->setObjectName("executionMetric" + QString::number(index));
    metrics->addWidget(m_metrics[index]);
  }
  parentContent->addLayout(metrics);
  m_gate->setStyleSheet("color:#475569;padding:4px 0;");
  parentContent->addWidget(m_gate);
  auto *notice = label(this);
  notice->setText(QStringLiteral("只读监控；取消任务请使用工作台顶部按钮。后端暂无可靠的暂停/恢复/手动重试接口，本页不提供这些操作。工具成功、规则命中和 MITRE 标签不等于漏洞已验证；模拟模式必须另行核验。"));
  notice->setStyleSheet("color:#64748b;font-size:12px;");
  outer->addWidget(notice);
  auto *splitter = new QSplitter(Qt::Horizontal, this);
  m_tabs = new WorkbenchTabs(splitter);
  auto makeTable = [this](const QString &title, const QStringList &headers, const QString &hint) {
    auto *table = new QTableWidget(0, headers.size(), m_tabs);
    table->setHorizontalHeaderLabels(headers);
    table->setAlternatingRowColors(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setWordWrap(false);
    table->setShowGrid(false);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setStyleSheet(Theme::ItemViewStyle);
    UiUtil::EmptyHint::attach(table, hint);
    m_tabs->addTab(table, title);
    connect(table, &QTableWidget::itemSelectionChanged, this, &TaskExecutionPanel::renderDetail);
    return table;
  };
  m_verifications = makeTable("逐漏洞执行记录", {"漏洞", "方案", "版本", "执行状态", "系统结果", "执行时间", "目标", "调用 / 证据"}, "暂无逐漏洞执行记录；查看历史不要求填写人工意见");
  m_verifications->setObjectName("findingVerificationRuns");
  m_verifications->setToolTip("双击打开已保存的同次历史与证据，不会重新执行。");
  connect(m_verifications,&QTableWidget::cellDoubleClicked,this,[this](int row,int){openVerificationHistory(row);});
  m_steps = makeTable("主预案步骤", {"步骤", "工具", "结果", "来源", "尝试编号", "退出码", "记录时间"}, "暂无主预案步骤结果；逐漏洞记录在单独页签展示");
  m_attempts = makeTable("执行尝试", {"尝试编号", "步骤", "工具", "结果", "执行模式", "耗时(ms)", "完成时间"}, "暂无执行尝试记录");
  m_evidence = makeTable("证据来源", {"证据编号", "步骤", "工具", "尝试编号", "类型", "来源校验", "采集时间"}, "暂无本任务证据记录");
  m_preflight = makeTable("执行预检", {"检查项", "结果", "说明"}, "预检尚无记录；不表示已通过");
  m_steps->setColumnWidth(1, 160);
  m_steps->setColumnWidth(3, 130);
  m_attempts->setColumnWidth(2, 160);
  m_attempts->setColumnWidth(4, 130);
  m_evidence->setColumnWidth(2, 160);
  m_evidence->setColumnWidth(4, 130);
  m_evidence->setColumnWidth(5, 200);
  m_verifications->setColumnWidth(0,140);
  m_verifications->setColumnWidth(1,110);
  m_verifications->setColumnWidth(2,45);
  m_verifications->setColumnWidth(3,75);
  m_verifications->setColumnWidth(4,125);
  m_verifications->setColumnWidth(5,185);
  m_verifications->setColumnWidth(6,190);
  auto *detailCard = new QFrame(splitter);
  detailCard->setProperty("softCard", true);
  auto *detailLayout = new QVBoxLayout(detailCard);
  detailLayout->setContentsMargins(12, 10, 12, 10);
  auto *detailTitle = new QLabel(QStringLiteral("执行记录与来源"), detailCard);
  detailTitle->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(detailTitle);
  m_detail = new QTextEdit(detailCard);
  detailLayout->addWidget(m_detail, 1);
  m_detail->setObjectName("executionRecordDetail");
  m_detail->setReadOnly(true);
  m_detail->setAcceptRichText(false);
  splitter->addWidget(m_tabs);
  splitter->addWidget(detailCard);
  splitter->setChildrenCollapsible(false);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 2);
  splitter->setSizes({680, 360});
  outer->addWidget(splitter, 1);
  m_updated = label(this);
  m_updated->setStyleSheet("color:#64748b;font-size:12px;");
  outer->addWidget(m_updated);
  m_timer = new QTimer(this);
  m_timer->setInterval(2000);
  connect(m_timer, &QTimer::timeout, this, [this]() {
    const QString state = m_snapshot.value("run").toObject().value("status").toString();
    if (isVisible() && (state.isEmpty() || state == "RUNNING" || state == "PENDING"
        || m_snapshot.value("verification_runs").toObject().value("active").toInt()>0)) refresh();
  });
  connect(m_refresh, &QPushButton::clicked, this, &TaskExecutionPanel::refresh);
  connect(m_tabs, &QTabWidget::currentChanged, this, &TaskExecutionPanel::renderDetail);
  clearTaskContext();
}

void TaskExecutionPanel::setTaskContext(const QString &pipelineId, const QString &runId, const QString &target)
{
  if (m_pipelineId == pipelineId && m_expectedRunId == runId && m_expectedTarget == target) return;
  clearTaskContext();
  m_pipelineId = pipelineId;
  m_expectedRunId = runId;
  m_expectedTarget = target;
  m_refresh->setEnabled(!pipelineId.isEmpty());
  if (!pipelineId.isEmpty()) {
    m_state->setText(QStringLiteral("正在读取本任务执行记录…"));
    m_timer->start();
    refresh();
  }
}

void TaskExecutionPanel::clearTaskContext()
{
  ++m_contextVersion;
  ++m_requestVersion;
  m_pipelineId.clear();
  m_expectedRunId.clear();
  m_expectedTarget.clear();
  m_notifiedRunId.clear();
  m_completedRunId.clear();
  m_detailKey.clear();
  m_snapshot = {};
  m_busy = false;
  m_refreshFailed = false;
  m_timer->stop();
  m_refresh->setEnabled(false);
  for (auto *table : {m_steps, m_attempts, m_evidence, m_preflight, m_verifications}) table->setRowCount(0);
  for (auto *metric : m_metrics) metric->setValue(QStringLiteral("—"));
  m_state->setText(QStringLiteral("选择任务后查看执行监控"));
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_identity->clear();
  m_parentState->clear();
  m_parentDetails->setChecked(false);
  m_tabs->setCurrentWidget(m_verifications);
  m_gate->clear();
  m_updated->clear();
  m_detail->setPlainText(QStringLiteral("选择步骤、尝试、证据或预检项查看来源与详情。"));
}

bool TaskExecutionPanel::validSnapshot(const QJsonObject &snapshot) const
{
  if (snapshot.value("version").toInt() != 1 || snapshot.value("pipeline_id").toString() != m_pipelineId
      || !snapshot.value("owner").isString() || snapshot.value("owner").toString().isEmpty()
      || (m_role != "admin" && snapshot.value("owner").toString() != m_username)
      || !snapshot.value("target").isString()
      || (!m_expectedTarget.isEmpty() && snapshot.value("target").toString() != m_expectedTarget)) return false;
  for (const QString key : {"steps", "attempts", "evidence", "preflight"})
    if (!snapshot.value(key).isArray() || snapshot.value(key).toArray().size() > (key == "preflight" ? 50 : 200)) return false;
  if(snapshot.contains("verification_runs")) {
    const auto child=snapshot.value("verification_runs").toObject();
    if(child.value("schema_version").toInt()!=1 || !child.value("items").isArray()
        || child.value("items").toArray().size()>200 || !child.value("has_more").isBool())return false;
    for(const QString key:{"total","returned","active","completed","failed","aborted","unknown","invalid_source_count"}) {
      const auto value=child.value(key);
      if(!value.isDouble() || value.toDouble(-1)<0 || value.toDouble()>9007199254740991.0
          || value.toDouble()!=value.toVariant().toLongLong())return false;
    }
    if(child.value("returned").toInt()!=child.value("items").toArray().size()
        || child.value("total").toDouble()<child.value("returned").toDouble())return false;
    QSet<QString> seen;
    for(const auto &value:child.value("items").toArray()) {
      const auto row=value.toObject();
      const auto id=row.value("attempt_id").toString();
      if(!value.isObject() || id.isEmpty() || seen.contains(id) || row.value("verification_id").toString().isEmpty()
          || row.value("run_id").toString().isEmpty() || !safeId(row.value("finding_id")) || !safeId(row.value("revision"))
          || !QStringList{"queued","running","cancelling","completed","failed","aborted","unknown"}.contains(row.value("state").toString())
          || !row.value("stop_confirmed").isBool() || !row.value("result").isObject())return false;
      seen.insert(id);
    }
  }
  const auto runValue = snapshot.value("run");
  if (runValue.isNull()) return m_expectedRunId.isEmpty() && snapshot.value("steps").toArray().isEmpty()
      && snapshot.value("attempts").toArray().isEmpty() && snapshot.value("evidence").toArray().isEmpty();
  if (!runValue.isObject()) return false;
  const auto run = runValue.toObject();
  const QString runId = run.value("run_id").toString();
  if (runId.isEmpty() || (!m_expectedRunId.isEmpty() && runId != m_expectedRunId)
      || !QStringList{"PENDING", "RUNNING", "COMPLETED", "FAILED", "ABORTED"}.contains(run.value("status").toString())
      || !run.value("counts").isObject()) return false;
  const auto counts = run.value("counts").toObject();
  for (const QString key : {"steps", "returned", "succeeded", "failed", "attempts", "evidence"}) {
    const auto value = counts.value(key);
    const double number = value.toDouble(-1);
    if (!value.isDouble() || number < 0 || number > 9007199254740991.0 || number != value.toVariant().toLongLong()) return false;
  }
  QSet<qint64> indices;
  for (const auto &value : snapshot.value("steps").toArray()) {
    const auto row = value.toObject();
    const auto index = row.value("step_index");
    if (!value.isObject() || !index.isDouble() || index.toDouble(-1) < 0
        || index.toDouble() != index.toVariant().toLongLong() || indices.contains(index.toVariant().toLongLong())) return false;
    indices.insert(index.toVariant().toLongLong());
  }
  for (const QString key : {"attempts", "evidence"}) {
    QSet<qint64> identifiers;
    for (const auto &value : snapshot.value(key).toArray()) {
      const auto row = value.toObject();
      if (!value.isObject() || !safeId(row.value("id")) || row.value("run_id").toString() != runId
          || identifiers.contains(row.value("id").toVariant().toLongLong())) return false;
      identifiers.insert(row.value("id").toVariant().toLongLong());
    }
  }
  return true;
}

void TaskExecutionPanel::refresh()
{
  if (m_pipelineId.isEmpty() || m_busy) return;
  m_busy = true;
  const int context = m_contextVersion;
  const int request = ++m_requestVersion;
  const QString pipelineId = m_pipelineId;
  QPointer<TaskExecutionPanel> guard(this);
  m_api->get("/api/pipelines/" + QString::fromLatin1(QUrl::toPercentEncoding(pipelineId)) + "/execution", 5000,
    [guard, context, request, pipelineId](const QJsonObject &response) {
      if (!guard || context != guard->m_contextVersion || request != guard->m_requestVersion || pipelineId != guard->m_pipelineId) return;
      guard->m_busy = false;
      const auto snapshot = response.value("data").toObject();
      if (response.value("status").toString() != "ok" || !guard->validSnapshot(snapshot)) {
        guard->m_refreshFailed = true;
        const QString error = response.value("error").toObject().value("message").toString();
        guard->m_state->setText(QStringLiteral("读取失败，保留上次快照（不是实时状态）：")
            + (error.isEmpty() ? QStringLiteral("响应身份或格式不匹配") : error));
        guard->m_state->setStyleSheet(Theme::StatusErrorStyle);
        return;
      }
      auto previousContent = guard->m_snapshot;
      auto nextContent = snapshot;
      previousContent.remove("captured_at");
      nextContent.remove("captured_at");
      const bool needsRender = guard->m_refreshFailed || previousContent != nextContent;
      guard->m_snapshot = snapshot;
      guard->m_refreshFailed = false;
      if (needsRender) guard->render();
      const auto run = snapshot.value("run").toObject();
      const QString runId = run.value("run_id").toString();
      if (!runId.isEmpty() && guard->m_notifiedRunId != runId) {
        guard->m_notifiedRunId = runId;
        emit guard->runSelected(runId);
      }
      if (!guard || context != guard->m_contextVersion || pipelineId != guard->m_pipelineId) return;
      const bool childActive=snapshot.value("verification_runs").toObject().value("active").toInt()>0;
      if(childActive)guard->m_timer->start();
      if (!childActive && runId.isEmpty() && QStringList{"completed", "failed", "cancelled"}.contains(snapshot.value("pipeline_status").toString()))
        guard->m_timer->stop();
      if (!runId.isEmpty() && QStringList{"COMPLETED", "FAILED", "ABORTED"}.contains(run.value("status").toString())) {
        if(!childActive)guard->m_timer->stop();
        if (guard->m_completedRunId != runId) {
          guard->m_completedRunId = runId;
          emit guard->runCompleted(runId);
        }
      }
    });
}

void TaskExecutionPanel::showEvent(QShowEvent *event)
{
  QWidget::showEvent(event);
  refresh();
}

void TaskExecutionPanel::render()
{
  const auto run = m_snapshot.value("run").toObject();
  const auto counts = run.value("counts").toObject();
  const auto plan = m_snapshot.value("plan").toObject();
  const QString runId = run.value("run_id").toString();
  m_identity->setText(QStringLiteral("任务：%1  ·  目标：%2  ·  创建人：%3\nRun：%4  ·  预案：%5  ·  引擎：%6")
      .arg(m_pipelineId, m_snapshot.value("target").toString(), m_snapshot.value("owner").toString(),
        runId.isEmpty() ? QStringLiteral("尚未生成") : runId, run.value("playbook_name").toString(), run.value("engine_type").toString()));
  const auto verifications=m_snapshot.value("verification_runs").toObject();
  QString status = runId.isEmpty() ? QStringLiteral("主预案尚未执行 · 任务%1").arg(stateText(m_snapshot.value("pipeline_status").toString()))
    : QStringLiteral("%1 · 工具成功 %2，失败 %3，待返回 %4。")
      .arg(stateText(run.value("status").toString()), numberText(counts.value("succeeded")),
        numberText(counts.value("failed")), numberText(counts.value("pending")));
  if (counts.value("terminal_pending").toBool())
    status += QStringLiteral("\n统计校验：任务已结束，但仍有步骤没有结果记录，请查看执行尝试。");
  else if (counts.value("requires_attention").toBool())
    status += QStringLiteral("\n统计校验：存在重复或缺失的步骤结果，请查看执行尝试。");
  if (!run.value("stop_reason").toString().isEmpty()) status += "\n停止/失败原因：" + run.value("stop_reason").toString();
  m_parentState->setText(status);
  m_parentState->setStyleSheet(run.value("status").toString() == "FAILED" ? Theme::StatusErrorStyle
    : counts.value("failed").toInt() > 0 ? Theme::StatusWarningStyle : Theme::StatusInfoStyle);
  if(verifications.value("schema_version").toInt()==1) {
    const int total=verifications.value("total").toInt(), active=verifications.value("active").toInt();
    status=active>0 ? QStringLiteral("逐漏洞测试进行中 · %1 次活动测试").arg(active)
      : total>0 ? QStringLiteral("已有 %1 次逐漏洞测试记录").arg(total)
      : runId.isEmpty() ? QStringLiteral("待执行验证；可从漏洞列表开始逐漏洞测试。")
      : QStringLiteral("已有主预案执行记录；展开主预案详情查看状态及步骤。");
    if(total>0) status+=QStringLiteral("\n执行结束 %1 · 失败 %2 · 中止 %3 · 停止未确认 %4。已有记录不表示任务完成或全部目标达成。")
      .arg(verifications.value("completed").toInt()).arg(verifications.value("failed").toInt())
      .arg(verifications.value("aborted").toInt()).arg(verifications.value("unknown").toInt());
    if(verifications.value("invalid_source_count").toInt()>0)status+=QStringLiteral("\n另有 %1 条记录来源不匹配，未展示内容。请核对来源。").arg(verifications.value("invalid_source_count").toInt());
  } else status=QStringLiteral("当前接口未提供逐漏洞执行列表，请使用配套后端版本查看；主预案状态见详情。");
  m_state->setText(status);
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_metrics[0]->setValue(runId.isEmpty() ? QStringLiteral("—") : stateText(run.value("status").toString()));
  m_metrics[1]->setValue(runId.isEmpty() ? QStringLiteral("—") : numberText(counts.value("returned")) + " / " + numberText(counts.value("steps")));
  m_metrics[2]->setValue(runId.isEmpty() ? QStringLiteral("—") : numberText(counts.value("attempts")));
  m_metrics[3]->setValue(runId.isEmpty() ? QStringLiteral("—") : numberText(counts.value("evidence")));
  m_gate->setText(plan.isEmpty() ? QStringLiteral("未记录版本化预案；是否需审批遵循现有任务配置（%1），不代表已授权。")
      .arg(!m_snapshot.value("requires_approval").isBool() ? QStringLiteral("审批要求未提供") :
           m_snapshot.value("requires_approval").toBool() ? QStringLiteral("需审批") : QStringLiteral("无需审批"))
    : QStringLiteral("预案版本 r%1 · %2 · %3")
      .arg(numberText(plan.value("revision")), stateText(plan.value("state").toString()), runId.isEmpty() ? QStringLiteral("未开始执行")
        : run.value("approved_snapshot").toBool() ? QStringLiteral("Run 使用该批准快照") : QStringLiteral("未确认 Run 与批准快照一致，请核对")));
  const QStringList keys{"steps", "attempts", "evidence", "preflight"};
  const QList<QTableWidget *> tables{m_steps, m_attempts, m_evidence, m_preflight};
  for (int tableIndex = 0; tableIndex < tables.size(); ++tableIndex) {
    auto *table = tables[tableIndex];
    const auto *selected = table->item(table->currentRow(), 0);
    const auto old = selected ? selected->data(Qt::UserRole).toJsonObject() : QJsonObject();
    const QString identityKey = tableIndex == 0 ? "step_index" : tableIndex == 3 ? "name" : "id";
    const auto identity = old.value(identityKey);
    const auto rows = m_snapshot.value(keys[tableIndex]).toArray();
    table->blockSignals(true);
    table->setRowCount(rows.size());
    int selectedRow = -1;
    for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex) {
      const auto row = rows[rowIndex].toObject();
      QStringList cells;
      if (tableIndex == 0) cells = QStringList{numberText(row.value("step_index")), row.value("tool_id").toString(), stateText(row.value("state").toString()),
        sourceText(row.value("source").toString()), numberText(row.value("attempt_id")), numberText(row.value("exit_code")), timeText(row.value("executed_at").toString())};
      else if (tableIndex == 1) cells = QStringList{numberText(row.value("id")), numberText(row.value("step_index")), row.value("tool_id").toString(),
        stateText(row.value("state").toString()), row.value("execution_mode").toString().isEmpty() ? QStringLiteral("未记录") : row.value("execution_mode").toString(),
        numberText(row.value("duration_ms")), timeText(row.value("completed_at").toString())};
      else if (tableIndex == 2) cells = QStringList{numberText(row.value("id")), numberText(row.value("step_index")), row.value("tool_id").toString(),
        numberText(row.value("attempt_id")), row.value("evidence_type").toString(), sourceStateText(row.value("source_state").toString()), timeText(row.value("recorded_at").toString())};
      else cells = QStringList{row.value("name").toString(), stateText(row.value("state").toString()), row.value("message").toString()};
      setRow(table, rowIndex, cells, row);
      if (!identity.isUndefined() && row.value(identityKey) == identity) selectedRow = rowIndex;
    }
    if (selectedRow >= 0) table->selectRow(selectedRow);
    else { table->clearSelection(); table->setCurrentCell(-1, -1); }
    table->blockSignals(false);
  }
  m_updated->setText(QStringLiteral("快照时间：%1 · 步骤展示前 200 项，尝试/证据展示最新 200 项（当前 %2 / %3 条）；文本最多 2000 字符并脱敏，可能省略内容，不作为完整原始证据。")
      .arg(timeText(m_snapshot.value("captured_at").toString())).arg(m_attempts->rowCount()).arg(m_evidence->rowCount()));
  const auto childRows=verifications.value("items").toArray();
  const auto *selected=m_verifications->item(m_verifications->currentRow(),0);
  const QString selectedId=selected?selected->data(Qt::UserRole).toJsonObject().value("attempt_id").toString():QString();
  {const QSignalBlocker block(m_verifications);m_verifications->setRowCount(childRows.size());int selectedRow=-1;
    for(int index=0;index<childRows.size();++index) {
      const auto row=childRows[index].toObject();const auto result=row.value("result").toObject();
      const QString target=result.value("object").toObject().value("target").toString();
      setRow(m_verifications,index,{row.value("finding_name").toString(),row.value("plan_name").toString(),
        "r"+numberText(row.value("revision")),stateText(row.value("state").toString()),verificationResultText(result),
        timeText(row.value("created_at").toString()),target,numberText(row.value("tool_calls"))+" / "+numberText(row.value("evidence_count"))},row);
      if(row.value("attempt_id").toString()==selectedId)selectedRow=index;
    }
    if(selectedRow>=0)m_verifications->selectRow(selectedRow);
    else {m_verifications->clearSelection();m_verifications->setCurrentCell(-1,-1);}
  }
  if(verifications.value("schema_version").toInt()==1)m_updated->setText(m_updated->text()+QStringLiteral("\n逐漏洞记录：显示最新 %1 / %2 次%3；双击只查看历史，不重新执行。")
    .arg(verifications.value("returned").toInt()).arg(verifications.value("total").toInt()).arg(verifications.value("has_more").toBool()?QStringLiteral("（较早记录可从扫描发现打开）"):QString()));
  renderDetail();
}

void TaskExecutionPanel::renderDetail()
{
  auto *table = qobject_cast<QTableWidget *>(m_tabs->currentWidget());
  const auto *item = table ? table->item(table->currentRow(), 0) : nullptr;
  if (!item || !table->selectionModel()->hasSelection()) {
    m_detailKey.clear();
    m_detail->setPlainText(QStringLiteral("选择当前页的一条记录查看输入、输出和来源；这里没有原始流式工具日志。"));
    return;
  }
  const auto row = item->data(Qt::UserRole).toJsonObject();
  QStringList lines{QStringLiteral("任务：%1\nRun：%2").arg(m_pipelineId, table==m_verifications?row.value("run_id").toString():m_snapshot.value("run").toObject().value("run_id").toString())};
  if(table==m_verifications) {
    const auto result=row.value("result").toObject();
    lines<<QStringLiteral("漏洞：%1\n方案：%2 · r%3\n执行状态：%4\n系统结果：%5\n目标：%6")
      .arg(row.value("finding_name").toString(),row.value("plan_name").toString(),numberText(row.value("revision")),
        stateText(row.value("state").toString()),verificationResultText(result),result.value("objective").toObject().value("label").toString())
      <<QStringLiteral("尝试：%1\n创建时间：%2\n完成时间：%3\n停止确认：%4\n工具调用：%5 · 证据：%6")
        .arg(row.value("attempt_id").toString(),timeText(row.value("created_at").toString()),timeText(row.value("completed_at").toString()),
          row.value("stop_confirmed").toBool()?QStringLiteral("已确认"):QStringLiteral("未确认"),numberText(row.value("tool_calls")),numberText(row.value("evidence_count")))
      <<"系统依据："+result.value("reason").toString()<<QStringLiteral("双击记录查看该次历史与证据；人工意见为可选补充，不改变系统结果。");
  } else if (table == m_steps) {
    lines << QStringLiteral("步骤索引：%1（数据库原始索引）\n名称：%2\n工具：%3\n结果：%4\n来源：%5\n尝试编号：%6\n退出码：%7")
      .arg(numberText(row.value("step_index")), row.value("name").toString(), row.value("tool_id").toString(), stateText(row.value("state").toString()),
        sourceText(row.value("source").toString()), numberText(row.value("attempt_id")), numberText(row.value("exit_code")));
    lines << "预案参数模板（不是实际输入）：\n" + row.value("template").toString()
      << "已记录实际输入（脱敏）：\n" + row.value("args").toString()
      << "步骤输出摘要（脱敏）：\n" + row.value("output").toString();
  } else if (table == m_attempts) {
    lines << QStringLiteral("尝试编号：%1\n步骤：%2\n工具：%3\n结果：%4\n执行模式：%5\n开始：%6\n完成：%7\n退出码：%8\n耗时(ms)：%9")
      .arg(numberText(row.value("id")), numberText(row.value("step_index")), row.value("tool_id").toString(), stateText(row.value("state").toString()),
        row.value("execution_mode").toString(), timeText(row.value("started_at").toString()), timeText(row.value("completed_at").toString()),
        numberText(row.value("exit_code")), numberText(row.value("duration_ms")));
    lines << "实际输入（脱敏）：\n" + row.value("args").toString() << "stdout（脱敏/限长）：\n" + row.value("stdout").toString()
      << "stderr（脱敏/限长）：\n" + row.value("stderr").toString();
  } else if (table == m_evidence) {
    lines << QStringLiteral("证据编号：%1\n步骤：%2\n工具：%3\n尝试编号：%4\n来源：%5\n目标：%6\n执行模式：%7\n采集时间：%8")
      .arg(numberText(row.value("id")), numberText(row.value("step_index")), row.value("tool_id").toString(), numberText(row.value("attempt_id")),
        sourceStateText(row.value("source_state").toString()), row.value("target").toString(), row.value("execution_mode").toString(), timeText(row.value("recorded_at").toString()));
    lines << "证据数据（不自动判定漏洞成立）：\n" + row.value("data").toString()
      << "stdout（脱敏/限长）：\n" + row.value("stdout").toString() << "stderr（脱敏/限长）：\n" + row.value("stderr").toString()
      << "MITRE 标签（不是验证结论）：\n" + row.value("mitre_hits").toString()
      << "规则匹配：\n" + row.value("rule_matches").toString() << "建议：\n" + row.value("recommendations").toString();
  } else lines << "检查项：" + row.value("name").toString() << "结果：" + stateText(row.value("state").toString()) << row.value("message").toString();
  const QString identityKey = table == m_steps ? "step_index" : table == m_preflight ? "name" : table==m_verifications?"attempt_id":"id";
  const QString detailKey = QString::number(m_tabs->currentIndex()) + ":" + row.value(identityKey).toVariant().toString();
  const int scroll = detailKey == m_detailKey ? m_detail->verticalScrollBar()->value() : 0;
  m_detailKey = detailKey;
  const QString detail = lines.join("\n\n");
  if (m_detail->toPlainText() != detail) {
    m_detail->setPlainText(detail);
    m_detail->verticalScrollBar()->setValue(scroll);
  }
}

void TaskExecutionPanel::openVerificationHistory(int index)
{
  const auto *item=m_verifications->item(index,0);
  if(!item || m_pipelineId.isEmpty())return;
  const auto row=item->data(Qt::UserRole).toJsonObject();
  const auto pipeline=m_pipelineId;
  const int context=m_contextVersion;
  auto *dialog=new FindingVerificationDialog(m_api,pipeline,{row.value("finding_id").toVariant().toLongLong()},this,
      row.value("verification_id").toString(),row.value("attempt_id").toString());
  connect(dialog,&QDialog::finished,this,[this,pipeline,context](){
    if(pipeline!=m_pipelineId || context!=m_contextVersion)return;
    refresh();
    emit findingVerificationChanged(pipeline);
  });
  dialog->setAttribute(Qt::WA_DeleteOnClose);
  dialog->show();
}
