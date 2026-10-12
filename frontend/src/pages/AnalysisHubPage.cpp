#include "AnalysisHubPage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"

#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QShowEvent>
#include <QSplitter>
#include <QTableWidget>
#include <QUrlQuery>
#include <QVBoxLayout>
#include <cmath>

namespace {
const QStringList categories = {"risk_assessment", "tech_stack", "attack_surface", "recommended_strategy"};

bool nonnegativeInteger(const QJsonValue &value)
{
  return value.isDouble() && std::isfinite(value.toDouble()) && value.toDouble() >= 0 &&
      value.toDouble() <= 2147483647 && std::floor(value.toDouble()) == value.toDouble();
}

QString sourceLabel(const QString &source)
{
  if (source == "fallback") return QStringLiteral("扫描规则回退");
  if (source == "structured") return QStringLiteral("结构化候选成果");
  if (source == "unknown") return QStringLiteral("已存储 · 来源未确认");
  return QStringLiteral("暂无候选成果");
}

QString stepLabel(const QString &status)
{
  const QMap<QString, QString> names = {{"pending", "待执行"}, {"running", "分析中"},
      {"completed", "步骤完成"}, {"failed", "分析失败"}, {"skipped", "已跳过"},
      {"cancelled", "已取消"}, {"not_recorded", "无步骤记录"}};
  return names.value(status, status);
}

}

AnalysisHubPage::AnalysisHubPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username)
{
  setObjectName("analysisHubPage");
  setStyleSheet(Theme::PageStyle);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(20, 16, 20, 16);
  auto *title = new QLabel(QStringLiteral("智能分析 · 任务索引"), this);
  title->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(title);
  auto *hint = new QLabel(QStringLiteral("先选定任务，再查看其分析来源和候选成果。此页不合并跨任务结论，不启动模型、扫描或执行；候选不等于已验证漏洞。"), this);
  hint->setTextFormat(Qt::PlainText);
  hint->setWordWrap(true);
  layout->addWidget(hint);
  auto *filters = new QHBoxLayout;
  m_search = new QLineEdit(this);
  m_search->setPlaceholderText(QStringLiteral("任务名称 / 编号 / 目标 / 所有者"));
  m_search->setMaxLength(120);
  m_filter = new QComboBox(this);
  m_filter->addItem(QStringLiteral("全部可见任务"), "all");
  m_filter->addItem(QStringLiteral("已有候选成果"), "available");
  m_filter->addItem(QStringLiteral("尚无候选成果"), "pending");
  auto *searchButton = new QPushButton(QStringLiteral("筛选"), this);
  auto *refreshButton = new QPushButton(QStringLiteral("刷新"), this);
  filters->addWidget(m_search, 1);
  filters->addWidget(m_filter);
  filters->addWidget(searchButton);
  filters->addWidget(refreshButton);
  layout->addLayout(filters);
  m_state = new QLabel(QStringLiteral("打开此页后读取当前账号可见的任务"), this);
  m_state->setTextFormat(Qt::PlainText);
  m_state->setWordWrap(true);
  layout->addWidget(m_state);
  auto *splitter = new QSplitter(Qt::Vertical, this);
  m_table = new QTableWidget(0, 7, splitter);
  m_table->setHorizontalHeaderLabels({"任务名称 / 编号", "目标", "所有者", "任务状态", "分析来源 / 步骤", "候选条目", "更新时间"});
  m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_table->setAlternatingRowColors(true);
  m_table->setWordWrap(false);
  m_table->setShowGrid(false);
  m_table->verticalHeader()->hide();
  m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  m_table->horizontalHeader()->setStretchLastSection(true);
  m_table->setColumnWidth(0, 260);
  m_table->setColumnWidth(1, 210);
  m_table->setColumnWidth(4, 220);
  UiUtil::EmptyHint::attach(m_table, QStringLiteral("暂无匹配的可见任务"));
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("打开此页后读取任务索引"));
  m_detail = new QPlainTextEdit(splitter);
  m_detail->setReadOnly(true);
  m_detail->setPlaceholderText(QStringLiteral("选择任务查看分析来源；候选成果尚未验证。"));
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 1);
  layout->addWidget(splitter, 1);
  auto *footer = new QHBoxLayout;
  m_previous = new QPushButton(QStringLiteral("上一页"), this);
  m_next = new QPushButton(QStringLiteral("下一页"), this);
  m_pagination = new QLabel(this);
  m_open = new QPushButton(QStringLiteral("进入所选任务的分析页"), this);
  m_open->setProperty("primary", true);
  footer->addWidget(m_previous);
  footer->addWidget(m_next);
  footer->addWidget(m_pagination, 1);
  footer->addWidget(m_open);
  layout->addLayout(footer);
  m_previous->setEnabled(false);
  m_next->setEnabled(false);
  connect(m_table, &QTableWidget::itemSelectionChanged, this, &AnalysisHubPage::showSelection);
  connect(m_table, &QTableWidget::cellDoubleClicked, this, [this]() { openSelected(); });
  connect(m_open, &QPushButton::clicked, this, &AnalysisHubPage::openSelected);
  auto filter = [this]() { m_offset = 0; refresh(); };
  connect(searchButton, &QPushButton::clicked, this, filter);
  connect(m_search, &QLineEdit::returnPressed, this, filter);
  connect(m_search, &QLineEdit::textChanged, this, [this]() {
    ++m_requestRevision;
    m_fresh = false;
    m_open->setEnabled(false);
    m_previous->setEnabled(false);
    m_next->setEnabled(false);
    m_state->setText(QStringLiteral("筛选条件已改变，请按回车或点击“筛选”读取匹配任务。"));
    m_state->setStyleSheet(Theme::StatusInfoStyle);
    UiUtil::EmptyHint::setState(m_table, QStringLiteral("筛选条件已修改，请确认筛选后读取新结果"));
  });
  connect(m_filter, QOverload<int>::of(&QComboBox::currentIndexChanged), this, filter);
  connect(refreshButton, &QPushButton::clicked, this, &AnalysisHubPage::refresh);
  connect(m_previous, &QPushButton::clicked, this, [this]() { m_offset = qMax(0, m_offset - 50); refresh(); });
  connect(m_next, &QPushButton::clicked, this, [this]() { m_offset += 50; refresh(); });
  showSelection();
}

void AnalysisHubPage::showEvent(QShowEvent *event)
{
  QWidget::showEvent(event);
  refresh();
}

bool AnalysisHubPage::validIndex(const QJsonObject &data, const QString &search, const QString &state, int offset) const
{
  if (data["schema_version"] != QJsonValue(1) || data["limit"] != QJsonValue(50) ||
      !nonnegativeInteger(data["offset"]) || data["offset"].toInt() != offset ||
      !nonnegativeInteger(data["total"]) || !data["search"].isString() || data["search"].toString() != search ||
      !data["state"].isString() || data["state"].toString() != state || !data["records"].isArray()) return false;
  const auto records = data["records"].toArray();
  if (records.size() > 50 || records.size() != qMin(50, qMax(0, data["total"].toInt() - offset))) return false;
  QSet<QString> identifiers;
  for (const auto value : records) {
    if (!value.isObject()) return false;
    const auto row = value.toObject();
    const QString identifier = row["pipeline_id"].toString();
    if (identifier.isEmpty() || identifiers.contains(identifier) || !row["task_name"].isString() ||
        !row["target"].isString() || !row["owner"].isString() || !row["status"].isString() ||
        !row["updated_at"].isString() || (m_role != "admin" && row["owner"].toString() != m_username)) return false;
    identifiers.insert(identifier);
    const auto analysis = row["analysis"].toObject();
    const auto counts = analysis["counts"].toObject();
    double total = 0;
    for (const auto &category : categories) {
      if (!nonnegativeInteger(counts[category])) return false;
      total += counts[category].toDouble();
    }
    if (!analysis["available"].isBool() || !nonnegativeInteger(analysis["total_entries"]) ||
        analysis["total_entries"].toDouble() != total || analysis["available"].toBool() != (total > 0) ||
        !QStringList{"none", "fallback", "structured", "unknown"}.contains(analysis["source"].toString()) ||
        ((analysis["source"].toString() == "none") != (total == 0)) ||
        !QStringList{"pending", "running", "completed", "failed", "skipped", "cancelled", "not_recorded"}.contains(analysis["step_status"].toString()) ||
        (state == "available" && total == 0) || (state == "pending" && total > 0)) return false;
  }
  return true;
}

void AnalysisHubPage::refresh()
{
  const int revision = ++m_requestRevision;
  const int offset = m_offset;
  const QString search = m_search->text();
  const QString state = m_filter->currentData().toString();
  QString selected;
  if (m_table->currentRow() >= 0 && m_table->currentRow() < m_records.size())
    selected = m_records.at(m_table->currentRow()).toObject()["pipeline_id"].toString();
  m_fresh = false;
  m_open->setEnabled(false);
  m_previous->setEnabled(false);
  m_next->setEnabled(false);
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_state->setText(QStringLiteral("正在读取任务索引…仅获取元数据，不运行分析。"));
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("正在读取任务索引…"));
  QUrlQuery query;
  query.addQueryItem("limit", "50");
  query.addQueryItem("offset", QString::number(offset));
  query.addQueryItem("state", state);
  query.addQueryItem("search", QString::fromLatin1(QUrl::toPercentEncoding(search)));
  QPointer<AnalysisHubPage> guard(this);
  m_api->get("/api/pipelines/analysis-index?" + query.toString(QUrl::FullyEncoded), 5000,
      [this, guard, revision, offset, search, state, selected](const QJsonObject &response) {
    if (!guard || revision != m_requestRevision) return;
    if (response["status"].toString() != "ok") {
      fail(response["error"].toObject()["message"].toString(QStringLiteral("后端未返回有效索引")));
      return;
    }
    const auto data = response["data"].toObject();
    if (!validIndex(data, search, state, offset)) {
      fail(QStringLiteral("任务索引身份、分页或候选计数不匹配"));
      return;
    }
    m_records = data["records"].toArray();
    m_table->clearSelection();
    m_table->setCurrentCell(-1, -1);
    m_table->setRowCount(m_records.size());
    int selectedRow = -1;
    for (int index = 0; index < m_records.size(); ++index) {
      const auto row = m_records.at(index).toObject();
      const auto analysis = row["analysis"].toObject();
      const QString identifier = row["pipeline_id"].toString();
      const QStringList cells = {row["task_name"].toString() + " · " + identifier, row["target"].toString(),
          row["owner"].toString(), UiUtil::taskStatusText(row["status"].toString()),
          sourceLabel(analysis["source"].toString()) + " / " + stepLabel(analysis["step_status"].toString()),
          QString::number(analysis["total_entries"].toInt()), row["updated_at"].toString()};
      for (int column = 0; column < cells.size(); ++column) {
        auto *item = new QTableWidgetItem(cells.at(column));
        item->setToolTip(cells.at(column).toHtmlEscaped());
        m_table->setItem(index, column, item);
      }
      m_table->setRowHeight(index, 44);
      if (identifier == selected) selectedRow = index;
    }
    m_fresh = true;
    UiUtil::EmptyHint::reset(m_table);
    const int total = data["total"].toInt();
    m_previous->setEnabled(offset > 0);
    m_next->setEnabled(offset + m_records.size() < total);
    m_pagination->setText(QStringLiteral("共 %1 个任务 · 当前 %2–%3 · 每页 50 条").arg(total)
        .arg(m_records.isEmpty() ? 0 : offset + 1).arg(m_records.isEmpty() ? 0 : offset + m_records.size()));
    m_state->setText(QStringLiteral("已读取当前账号可见任务。候选条目按四类成果展示单元计数，不是漏洞数量；无成果也不代表目标安全。"));
    if (selectedRow >= 0) m_table->selectRow(selectedRow);
    showSelection();
  });
}

void AnalysisHubPage::fail(const QString &message)
{
  m_fresh = false;
  m_records = {};
  m_table->setRowCount(0);
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("任务索引读取失败，请刷新重试"), true);
  m_pagination->clear();
  m_state->setStyleSheet(Theme::StatusErrorStyle);
  m_state->setText(QStringLiteral("读取失败：%1。请刷新重试；当前不允许进入旧记录。").arg(message));
  showSelection();
}

void AnalysisHubPage::showSelection()
{
  const int index = m_table->currentRow();
  const bool selected = m_fresh && index >= 0 && index < m_records.size();
  m_open->setEnabled(selected);
  if (!selected) {
    m_detail->setPlainText(QStringLiteral("选择一个任务查看来源摘要，再进入任务工作台。尚无成果的任务也可打开分析页查看真实空态；此入口不会启动任务。"));
    return;
  }
  const auto row = m_records.at(index).toObject();
  const auto analysis = row["analysis"].toObject();
  const auto counts = analysis["counts"].toObject();
  m_detail->setPlainText(QStringLiteral("任务：%1\n编号：%2\n目标：%3\n所有者：%4\n来源：%5；分析步骤：%6\n候选风险 %7 / 技术栈 %8 / 攻击面 %9 / 建议策略 %10\n\n这里只展示已存储分析的索引；对象或文本算一个展示单元，数组按条目数计数。成果需回到同一任务核对扫描来源；步骤完成、规则回退或候选等级均不代表漏洞成立。")
      .arg(row["task_name"].toString(), row["pipeline_id"].toString(), row["target"].toString(), row["owner"].toString(),
           sourceLabel(analysis["source"].toString()), stepLabel(analysis["step_status"].toString()))
      .arg(counts["risk_assessment"].toInt()).arg(counts["tech_stack"].toInt())
      .arg(counts["attack_surface"].toInt()).arg(counts["recommended_strategy"].toInt()));
}

void AnalysisHubPage::openSelected()
{
  const int index = m_table->currentRow();
  if (!m_fresh || index < 0 || index >= m_records.size()) return;
  emit openTaskAnalysisRequested(m_records.at(index).toObject()["pipeline_id"].toString());
}
