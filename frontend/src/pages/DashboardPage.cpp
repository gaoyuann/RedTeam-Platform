#include "DashboardPage.h"

#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/MetricCard.h"

#include <QColor>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QLabel>
#include <QListWidget>
#include <QMap>
#include <QPointer>
#include <QPainter>
#include <algorithm>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {
QJsonObject objectValue(const QJsonValue &value)
{
  if (value.isObject()) return value.toObject();
  if (!value.isString()) return {};
  QJsonParseError error;
  const auto document = QJsonDocument::fromJson(value.toString().toUtf8(), &error);
  return error.error == QJsonParseError::NoError && document.isObject()
      ? document.object() : QJsonObject{};
}

QJsonObject pipelineConfig(const QJsonObject &pipeline)
{
  return objectValue(pipeline.value(QStringLiteral("config")));
}

QJsonObject pipelineAnalysis(const QJsonObject &pipeline)
{
  return objectValue(pipeline.value(QStringLiteral("analysis_result")));
}

QString pipelineName(const QJsonObject &pipeline)
{
  const auto name = pipelineConfig(pipeline).value(QStringLiteral("task_name")).toString().trimmed();
  return name.isEmpty() ? QStringLiteral("%1 安全测试").arg(pipeline.value(QStringLiteral("target")).toString()) : name;
}

QString pipelineType(const QJsonObject &pipeline)
{
  const auto type = pipelineConfig(pipeline).value(QStringLiteral("test_type")).toString();
  if (type == QStringLiteral("web")) return QStringLiteral("Web 安全测试");
  if (type == QStringLiteral("host")) return QStringLiteral("主机安全测试");
  if (type == QStringLiteral("internal")) return QStringLiteral("内网渗透测试");
  if (type == "comprehensive" || type == "full") return QStringLiteral("综合测试");
  return QStringLiteral("未注明类型");
}

QString displayTime(const QString &value)
{
  const auto dateTime = QDateTime::fromString(value, Qt::ISODate);
  return dateTime.isValid() ? dateTime.toString(QStringLiteral("yyyy-MM-dd HH:mm")) : value.left(16);
}

QString riskLevel(const QJsonValue &value)
{
  const auto object = objectValue(value);
  const auto raw = object.value(QStringLiteral("severity")).toString(
      object.value(QStringLiteral("risk_level")).toString(
          object.value(QStringLiteral("level")).toString())).toLower();
  if (raw.contains(QStringLiteral("critical")) || raw.contains(QStringLiteral("严重"))) return QStringLiteral("严重");
  if (raw.contains(QStringLiteral("high")) || raw.contains(QStringLiteral("高"))) return QStringLiteral("高危");
  if (raw.contains(QStringLiteral("medium")) || raw.contains(QStringLiteral("中"))) return QStringLiteral("中危");
  if (raw.contains(QStringLiteral("low")) || raw.contains(QStringLiteral("低"))) return QStringLiteral("低危");
  if (raw == "info" || raw == "informational" || raw == QStringLiteral("信息")) return QStringLiteral("信息");
  return QStringLiteral("未分级");
}

QString statusColor(const QString &status)
{
  if (status == QStringLiteral("completed")) return QStringLiteral("#16a34a");
  if (status == QStringLiteral("failed") || status == QStringLiteral("cancelled")) return QStringLiteral("#dc3545");
  if (status == QStringLiteral("awaiting_approval") || status == QStringLiteral("paused")) return QStringLiteral("#f59e0b");
  return QStringLiteral("#2563eb");
}

QString statusLabel(const QString &status)
{
  return UiUtil::taskStatusText(status);
}

} // namespace

// Lightweight Qt painter chart; no additional chart runtime is required.
class DashboardChart : public QWidget {
public:
  QList<QPair<QString, QPair<int, QString>>> rows;
  int total = 0;
  bool bars = false;
  explicit DashboardChart(QWidget *parent) : QWidget(parent) { setMinimumHeight(166); }
protected:
  void paintEvent(QPaintEvent *) override {
    QPainter p(this); p.setRenderHint(QPainter::Antialiasing);
    QFont f = font(); f.setPixelSize(12); p.setFont(f);
    const bool compact = width() < 320;
    if (bars) {
      const int baseline = height() - 28;
      const int step = width() / qMax(1, rows.size());
      int maximum = 1; for (const auto &r : rows) maximum = qMax(maximum, r.second.first);
      p.setPen(QColor(Theme::Border)); p.drawLine(6, baseline, width()-6, baseline);
      for (int i=0; i<rows.size(); ++i) {
        const auto &r = rows[i]; int h = (baseline-32)*r.second.first/maximum;
        QRect bar(i*step+step/4, baseline-h, step/2, h);
        p.setPen(Qt::NoPen); p.setBrush(QColor(r.second.second)); p.drawRoundedRect(bar,3,3);
        p.setPen(QColor(Theme::TextSecondary));
        p.drawText(QRect(i*step,baseline+6,step,20),Qt::AlignCenter,r.first);
        p.drawText(QRect(i*step,baseline-h-24,step,20),Qt::AlignCenter,QString::number(r.second.first));
      }
      return;
    }
    const int size = compact ? 78 : qMin(136, height()-20);
    QRectF ring(2,(height()-size)/2,size,size);
    p.setPen(Qt::NoPen); double start = 90*16;
    for (const auto &r : rows) { double span = 360.0*16*r.second.first/qMax(1,total); p.setBrush(QColor(r.second.second)); p.drawPie(ring,qRound(start),-qRound(span)); start -= span; }
    p.setBrush(QColor(Theme::Card)); p.drawEllipse(ring.adjusted(size*.18,size*.18,-size*.18,-size*.18));
    p.setPen(QColor(Theme::Text)); QFont number = f; number.setPixelSize(compact?20:28); number.setBold(true); p.setFont(number); p.drawText(ring,Qt::AlignCenter,QString::number(total)); p.setFont(f);
    const int x = size + (compact?12:24); const int rowHeight = qMin(25,height()/qMax(1,rows.size()));
    for (int i=0;i<rows.size();++i) { const auto &r=rows[i]; int y=(height()-rows.size()*rowHeight)/2+i*rowHeight;
      p.setPen(Qt::NoPen);p.setBrush(QColor(r.second.second));p.drawRoundedRect(QRect(x,y+6,8,8),2,2);
      p.setPen(QColor(Theme::TextSecondary));
      QString label=QString("%1  %2").arg(r.first).arg(r.second.first);
      if (!compact) label+=QString(" (%1%)").arg(qRound(r.second.first*100.0/qMax(1,total)));
      p.drawText(QRect(x+14,y,width()-x-14,rowHeight),Qt::AlignVCenter,p.fontMetrics().elidedText(label,Qt::ElideRight,width()-x-14));
    }
  }
};

class DistributionPanel : public QFrame {
public:
  explicit DistributionPanel(const QString &title, QWidget *parent = nullptr)
      : QFrame(parent), m_rows(new QVBoxLayout(this))
  {
    setProperty("card", true);
    m_rows->setContentsMargins(16, 13, 16, 13);
    m_rows->setSpacing(7);
    auto *header = new QLabel(title, this);
    header->setObjectName(QStringLiteral("dashboardSectionTitle"));
    header->setProperty("riskChart", title.contains(QStringLiteral("等级")));
    m_rows->addWidget(header);
  }

  void setData(const QList<QPair<QString, QPair<int, QString>>> &data,
               int total, const QString &emptyText)
  {
    while (m_rows->count() > 1) {
      auto *item = m_rows->takeAt(1);
      if (auto *child = item->layout()) {
        while (auto *entry = child->takeAt(0)) { delete entry->widget(); delete entry; }
      }
      delete item->widget();
      delete item;
    }
    if (data.isEmpty() || total <= 0) {
      auto *empty = new QLabel(emptyText, this);
      empty->setObjectName(QStringLiteral("dashboardEmpty"));
      empty->setAlignment(Qt::AlignCenter);
      empty->setWordWrap(true);
      m_rows->addWidget(empty, 1);
      return;
    }
    auto *chart = new DashboardChart(this);
    chart->rows = data;
    chart->total = total;
    chart->bars = m_rows->itemAt(0)->widget()->property("riskChart").toBool();
    m_rows->addWidget(chart, 1);
  }

private:
  QVBoxLayout *m_rows;
};

DashboardPage::DashboardPage(ApiClient *api, QWidget *parent)
    : QWidget(parent), m_api(api)
{
  setupUI();
  refresh();
}

void DashboardPage::setupUI()
{
  setStyleSheet(Theme::PageStyle + QStringLiteral(
      "QLabel#dashboardSectionTitle{font-size:16px;font-weight:700;color:%1;}"
      "QLabel#dashboardEmpty{color:#94a3b8;padding:12px;}"
      "QLabel#dashboardMeta{color:#64748b;font-size:12px;}"
      "QListWidget#todoList{border:none;background:transparent;}"
      "QListWidget#todoList::item{padding:8px 3px;border-bottom:1px solid #edf2f7;}"
      "QProgressBar{min-height:8px;}").arg(Theme::Text));

  auto *root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);
  root->setSpacing(0);
  auto *scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  auto *page = new QWidget;
  page->setObjectName("dashboardCanvas");
  page->setStyleSheet(QString("QWidget#dashboardCanvas{background:%1;}").arg(Theme::Background));
  auto *layout = new QVBoxLayout(page);
  layout->setContentsMargins(18, 16, 18, 18);
  layout->setSpacing(12);

  auto *header = new QHBoxLayout;
  auto *heading = new QVBoxLayout;
  heading->setSpacing(2);
  auto *title = new QLabel(QStringLiteral("工作台"), page);
  title->setStyleSheet(QStringLiteral("font-size:24px;font-weight:700;color:#12213c;"));
  auto *subtitle = new QLabel(QStringLiteral("全局掌握测试任务进展，快速进入扫描、分析与结果核验。"), page);
  subtitle->setObjectName(QStringLiteral("dashboardMeta"));
  heading->addWidget(title);
  heading->addWidget(subtitle);
  header->addLayout(heading);
  header->addStretch();
  auto *newTask = new QPushButton(QStringLiteral("＋ 新建测试任务"), page);
  newTask->setProperty("primary", true);
  connect(newTask, &QPushButton::clicked, this, &DashboardPage::openTasksRequested);
  auto *retry = new QPushButton(QStringLiteral("刷新"), page);
  retry->setObjectName("dashboardRefresh");
  connect(retry, &QPushButton::clicked, this, &DashboardPage::refresh);
  header->addWidget(retry);
  header->addWidget(newTask);
  layout->addLayout(header);

  auto *metrics = new QHBoxLayout;
  metrics->setSpacing(12);
  m_taskCard = new MetricCard(QStringLiteral("测试任务总数"), Theme::Primary, page);
  m_assetCard = new MetricCard(QStringLiteral("任务目标（去重）"), QStringLiteral("#0f766e"), page);
  m_findingCard = new MetricCard(QStringLiteral("分析候选（未复核）"), QStringLiteral("#f59e0b"), page);
  m_reportCard = new MetricCard(QStringLiteral("报告总数"), QStringLiteral("#7c3aed"), page);
  m_taskCard->setIcon(":/icons/shell/tasks.svg");
  m_assetCard->setIcon(":/icons/shell/topology.svg");
  m_findingCard->setIcon(":/icons/shell/analysis.svg");
  m_reportCard->setIcon(":/icons/shell/reports.svg");
  for (auto *card : {m_taskCard, m_assetCard, m_findingCard, m_reportCard}) {
    card->setMinimumHeight(102);
    metrics->addWidget(card, 1);
  }
  layout->addLayout(metrics);

  auto *distributions = new QHBoxLayout;
  distributions->setSpacing(12);
  m_statusDistribution = new DistributionPanel(QStringLiteral("任务状态分布"), page);
  m_riskDistribution = new DistributionPanel(QStringLiteral("分析候选等级分布"), page);
  m_typeDistribution = new DistributionPanel(QStringLiteral("任务类型分布"), page);
  distributions->addWidget(m_statusDistribution, 1);
  distributions->addWidget(m_riskDistribution, 1);
  distributions->addWidget(m_typeDistribution, 1);
  layout->addLayout(distributions);

  auto *middle = new QHBoxLayout;
  middle->setSpacing(12);
  auto *recent = new QFrame(page);
  recent->setProperty("card", true);
  auto *recentLayout = new QVBoxLayout(recent);
  recentLayout->setContentsMargins(14, 12, 14, 14);
  auto *recentHead = new QHBoxLayout;
  auto *recentTitle = new QLabel(QStringLiteral("最近任务"), recent);
  recentTitle->setObjectName(QStringLiteral("dashboardSectionTitle"));
  recentHead->addWidget(recentTitle);
  recentHead->addStretch();
  auto *all = new QPushButton(QStringLiteral("查看全部 →"), recent);
  all->setProperty("quiet", true);
  connect(all, &QPushButton::clicked, this, &DashboardPage::openTasksRequested);
  recentHead->addWidget(all);
  recentLayout->addLayout(recentHead);
  m_recentTable = new QTableWidget(0, 6, recent);
  m_recentTable->setHorizontalHeaderLabels({QStringLiteral("任务名称"), QStringLiteral("目标范围"), QStringLiteral("任务类型"), QStringLiteral("状态"), QStringLiteral("更新时间"), QStringLiteral("来源")});
  m_recentTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_recentTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  for (int i = 2; i < 6; ++i) m_recentTable->horizontalHeader()->setSectionResizeMode(i, QHeaderView::ResizeToContents);
  m_recentTable->verticalHeader()->setVisible(false);
  m_recentTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_recentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_recentTable->setMinimumHeight(228);
  m_recentTable->horizontalHeader()->setMinimumSectionSize(85);
  m_recentTable->setShowGrid(false);
  UiUtil::EmptyHint::attach(m_recentTable, QStringLiteral("暂无测试任务，请先创建一个任务"));
  recentLayout->addWidget(m_recentTable, 1);
  middle->addWidget(recent, 3);

  auto *todo = new QFrame(page);
  todo->setProperty("card", true);
  auto *todoLayout = new QVBoxLayout(todo);
  todoLayout->setContentsMargins(14, 12, 14, 14);
  auto *todoHead = new QHBoxLayout;
  auto *todoTitle = new QLabel(QStringLiteral("待办事项"), todo);
  todoTitle->setObjectName(QStringLiteral("dashboardSectionTitle"));
  todoHead->addWidget(todoTitle);
  todoHead->addStretch();
  auto *todoHint = new QLabel(QStringLiteral("来自当前任务状态"), todo);
  todoHint->setObjectName(QStringLiteral("dashboardMeta"));
  todoHint->setWordWrap(true);
  todoHead->addWidget(todoHint);
  todoLayout->addLayout(todoHead);
  m_todoList = new QListWidget(todo);
  m_todoList->setObjectName(QStringLiteral("todoList"));
  todoLayout->addWidget(m_todoList, 1);
  middle->addWidget(todo, 1);
  layout->addLayout(middle);

  auto *bottom = new QHBoxLayout;
  bottom->setSpacing(12);
  auto *health = new QFrame(page);
  health->setProperty("card", true);
  auto *healthLayout = new QVBoxLayout(health);
  healthLayout->setContentsMargins(14, 12, 14, 14);
  auto *healthTitle = new QLabel(QStringLiteral("系统运行状态"), health);
  healthTitle->setObjectName(QStringLiteral("dashboardSectionTitle"));
  healthLayout->addWidget(healthTitle);
  auto addHealth = [healthLayout, health](const QString &name, QLabel **value) {
    auto *row = new QHBoxLayout;
    auto *label = new QLabel(name, health);
    label->setObjectName(QStringLiteral("dashboardMeta"));
    *value = new QLabel(QStringLiteral("检测中"), health);
    (*value)->setAlignment(Qt::AlignRight);
    row->addWidget(label);
    row->addStretch();
    row->addWidget(*value);
    healthLayout->addLayout(row);
  };
  addHealth(QStringLiteral("后端 API"), &m_apiStatusLabel);
  addHealth(QStringLiteral("任务数据"), &m_dataStatusLabel);
  addHealth(QStringLiteral("扫描引擎 / AI 模型"), &m_healthHintLabel);
  auto *healthNote = new QLabel(QStringLiteral("仅显示已接入的健康检查；未接入项不会填入示例状态。"), health);
  healthNote->setObjectName(QStringLiteral("dashboardMeta"));
  healthNote->setWordWrap(true);
  healthLayout->addWidget(healthNote);
  bottom->addWidget(health, 3);

  auto *knowledge = new QFrame(page);
  knowledge->setProperty("card", true);
  auto *knowledgeLayout = new QVBoxLayout(knowledge);
  knowledgeLayout->setContentsMargins(14, 12, 14, 14);
  auto *knowledgeTitle = new QLabel(QStringLiteral("安全资讯与知识更新"), knowledge);
  knowledgeTitle->setObjectName(QStringLiteral("dashboardSectionTitle"));
  knowledgeLayout->addWidget(knowledgeTitle);
  m_knowledgeSummaryLabel = new QLabel(QStringLiteral("知识库统计加载中"), knowledge);
  m_knowledgeSummaryLabel->setWordWrap(true);
  m_knowledgeSummaryLabel->setStyleSheet(QStringLiteral("font-size:14px;color:%1;").arg(Theme::DarkLighter));
  knowledgeLayout->addWidget(m_knowledgeSummaryLabel);
  m_knowledgeStatusLabel = new QLabel(QStringLiteral("加载中"), knowledge);
  m_knowledgeStatusLabel->setObjectName(QStringLiteral("dashboardMeta"));
  knowledgeLayout->addWidget(m_knowledgeStatusLabel);
  auto *knowledgeNote = new QLabel(QStringLiteral("资讯订阅和漏洞情报更新未接入；此处只展示知识图谱真实规模。"), knowledge);
  knowledgeNote->setObjectName(QStringLiteral("dashboardMeta"));
  knowledgeNote->setWordWrap(true);
  knowledgeLayout->addWidget(knowledgeNote);
  knowledgeLayout->addStretch();
  bottom->addWidget(knowledge, 2);
  layout->addLayout(bottom);

  scroll->setWidget(page);
  root->addWidget(scroll);
}

void DashboardPage::setState(QLabel *label, const QString &text, const QString &color)
{
  if (!label) return;
  label->setText(text);
  label->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(color));
}

void DashboardPage::refresh()
{
  ++m_revision;
  m_reportCard->setValue("—"); m_reportCard->setCaption(QStringLiteral("加载中"));
  m_knowledgeSummaryLabel->setText(QStringLiteral("知识统计加载中"));
  setState(m_knowledgeStatusLabel, QStringLiteral("加载中"), Theme::TextSecondary);
  setState(m_apiStatusLabel, QStringLiteral("检测中"), Theme::TextSecondary);
  m_healthHintLabel->setText(QStringLiteral("未接入健康检查"));
  showPipelineLoading();
  loadPipelines();
  loadReports();
  loadKnowledge();
  loadHealth();
}

void DashboardPage::showPipelineLoading()
{
  for (auto *card : {m_taskCard, m_assetCard, m_findingCard}) {
    card->setValue(QStringLiteral("—"));
    card->setCaption(QStringLiteral("加载中"));
  }
  m_statusDistribution->setData({}, 0, QStringLiteral("任务数据加载中"));
  m_riskDistribution->setData({}, 0, QStringLiteral("候选风险数据加载中"));
  m_typeDistribution->setData({}, 0, QStringLiteral("任务数据加载中"));
  m_recentTable->setRowCount(0);
  UiUtil::EmptyHint::setState(m_recentTable, QStringLiteral("任务数据加载中…"));
  m_todoList->clear();
  m_todoList->addItem(QStringLiteral("待办数据加载中…"));
  setState(m_dataStatusLabel, QStringLiteral("加载中"), Theme::TextSecondary);
}

void DashboardPage::renderPipelineData(const QJsonArray &pipelines)
{
  QSet<QString> targets;
  QMap<QString, int> statuses;
  QMap<QString, int> types;
  QMap<QString, int> risks;
  int candidates = 0;
  bool incompleteAnalysis = false;
  for (const auto &value : pipelines) {
    const auto pipeline = value.toObject();
    const auto status = pipeline.value(QStringLiteral("status")).toString();
    statuses[status]++;
    const auto target = pipeline.value("target").toString().trimmed();
    if (!target.isEmpty()) targets.insert(target);
    types[pipelineType(pipeline)]++;
    const auto analysis = pipeline.value("analysis_result");
    if (analysis.isString() && !analysis.toString().trimmed().isEmpty()) {
      QJsonParseError error;
      const auto document = QJsonDocument::fromJson(analysis.toString().toUtf8(), &error);
      if (error.error != QJsonParseError::NoError || (!document.isObject() && analysis.toString() != "null")) incompleteAnalysis = true;
    }
    const auto riskValue = pipelineAnalysis(pipeline).value(QStringLiteral("risk_assessment"));
    const auto riskArray = riskValue.isArray() ? riskValue.toArray()
        : (riskValue.isObject() && !riskValue.toObject().isEmpty()) || (riskValue.isString() && !riskValue.toString().trimmed().isEmpty())
          ? QJsonArray{riskValue} : QJsonArray{};
    for (const auto &risk : riskArray) {
      if (risk.isNull() || (risk.isObject() && risk.toObject().isEmpty()) || (risk.isString() && risk.toString().trimmed().isEmpty())) continue;
      ++candidates;
      ++risks[riskLevel(risk)];
    }
  }
  m_taskCard->setValue(QString::number(pipelines.size()));
  m_taskCard->setCaption(QStringLiteral("当前账号可见"));
  m_assetCard->setValue(QString::number(targets.size()));
  m_assetCard->setCaption(QStringLiteral("不等于已发现资产数"));
  m_findingCard->setValue(QString::number(candidates));
  m_findingCard->setCaption(candidates ? QStringLiteral("分析记录条数 · 未复核") : QStringLiteral("暂无候选风险"));

  QList<QPair<QString, QPair<int, QString>>> statusRows;
  const QList<QPair<QString, QString>> statusOrder = {{"running", "进行中"}, {"completed", "已完成"}, {"awaiting_approval", "待确认"}, {"failed", "失败"}, {"created", "待运行"}, {"paused", "已暂停"}, {"cancelled", "已取消"}};
  for (const auto &item : statusOrder) if (statuses.value(item.first) > 0) statusRows.append({item.second, {statuses.value(item.first), statusColor(item.first)}});
  int knownStates = 0; for (const auto &row : statusRows) knownStates += row.second.first;
  if (knownStates < pipelines.size()) statusRows.append({QStringLiteral("未知状态"), {pipelines.size() - knownStates, "#94a3b8"}});
  m_statusDistribution->setData(statusRows, pipelines.size(), QStringLiteral("暂无任务状态数据"));

  QList<QPair<QString, QPair<int, QString>>> riskRows;
  const QList<QPair<QString, QString>> riskOrder = {{"信息", "#0f766e"}, {"严重", "#dc3545"}, {"高危", "#f59e0b"}, {"中危", "#3b82f6"}, {"低危", "#16a34a"}, {"未分级", "#94a3b8"}};
  for (const auto &item : riskOrder) if (risks.value(item.first) > 0) riskRows.append({item.first, {risks.value(item.first), item.second}});
  m_riskDistribution->setData(riskRows, candidates, QStringLiteral("暂无分析候选"));
  if (incompleteAnalysis) {
    m_findingCard->setValue(QStringLiteral("—"));
    m_findingCard->setCaption(QStringLiteral("部分分析记录无法解析"));
    m_riskDistribution->setData({}, 0, QStringLiteral("分析数据不完整，暂不汇总"));
  }

  QList<QPair<QString, QPair<int, QString>>> typeRows;
  const QList<QPair<QString, QString>> typeOrder = {{"未注明类型", "#94a3b8"}, {"综合测试", "#3b82f6"}, {"Web 安全测试", "#14b8a6"}, {"主机安全测试", "#f59e0b"}, {"内网渗透测试", "#7c3aed"}};
  for (const auto &item : typeOrder) if (types.value(item.first) > 0) typeRows.append({item.first, {types.value(item.first), item.second}});
  m_typeDistribution->setData(typeRows, pipelines.size(), QStringLiteral("暂无任务类型数据"));

  m_recentTable->setRowCount(0);
  UiUtil::EmptyHint::reset(m_recentTable);
  QList<QJsonObject> recent;
  for (const auto &value : pipelines) recent.append(value.toObject());
  std::stable_sort(recent.begin(), recent.end(), [](const QJsonObject &a, const QJsonObject &b) { return a.value("updated_at").toString() > b.value("updated_at").toString(); });
  const int count = qMin(6, recent.size());
  for (int index = 0; index < count; ++index) {
    const auto pipeline = recent.at(index);
    const int row = m_recentTable->rowCount();
    m_recentTable->insertRow(row);
    m_recentTable->setItem(row, 0, new QTableWidgetItem(pipelineName(pipeline)));
    m_recentTable->setItem(row, 1, new QTableWidgetItem(pipeline.value(QStringLiteral("target")).toString()));
    m_recentTable->setItem(row, 2, new QTableWidgetItem(pipelineType(pipeline)));
    const auto status = pipeline.value(QStringLiteral("status")).toString();
    auto *statusItem = new QTableWidgetItem(statusLabel(status));
    statusItem->setForeground(QColor(statusColor(status)));
    m_recentTable->setItem(row, 3, statusItem);
    m_recentTable->setItem(row, 4, new QTableWidgetItem(displayTime(pipeline.value(QStringLiteral("updated_at")).toString())));
    m_recentTable->setItem(row, 5, new QTableWidgetItem(QStringLiteral("任务记录")));
  }

  m_todoList->clear();
  for (const auto &value : pipelines) {
    const auto pipeline = value.toObject();
    const auto status = pipeline.value(QStringLiteral("status")).toString();
    if (status == QStringLiteral("awaiting_approval") || status == QStringLiteral("running") || status == QStringLiteral("failed")) {
      auto *item = new QListWidgetItem(QStringLiteral("%1\n%2 · %3")
          .arg(pipelineName(pipeline), statusLabel(status), pipeline.value(QStringLiteral("target")).toString()), m_todoList);
      item->setToolTip(item->text());
    }
  }
  if (m_todoList->count() == 0) m_todoList->addItem(QStringLiteral("暂无待处理任务"));
  setState(m_dataStatusLabel, QStringLiteral("已更新"), Theme::Success);
}

void DashboardPage::loadPipelines()
{
  if (!m_api) return;
  m_api->get(QStringLiteral("/api/pipelines"), 5000, [this, guard = QPointer<DashboardPage>(this), revision = m_revision](const QJsonObject &response) {
    if (!guard || revision != m_revision) return;
    if (response.value(QStringLiteral("status")).toString() != QStringLiteral("ok") || !response.value("data").isArray()) {
      showPipelineError(response.value(QStringLiteral("error")).toObject().value(QStringLiteral("message")).toString());
      return;
    }
    renderPipelineData(response.value(QStringLiteral("data")).toArray());
  });
}

void DashboardPage::loadReports()
{
  if (!m_api) return;
  m_api->get(QStringLiteral("/api/reports/index?limit=1&offset=0"), 5000, [this, guard = QPointer<DashboardPage>(this), revision = m_revision](const QJsonObject &response) {
    if (!guard || revision != m_revision) return;
    if (response.value(QStringLiteral("status")).toString() != QStringLiteral("ok")) {
      m_reportCard->setValue(QStringLiteral("—"));
      m_reportCard->setCaption(QStringLiteral("加载失败"));

      return;
    }
    const auto data = response.value(QStringLiteral("data")).toObject();
    if (!data.value("total").isDouble() || data.value("total").toDouble() < 0) { m_reportCard->setValue("—"); m_reportCard->setCaption(QStringLiteral("数据不可用")); return; }
    m_reportCard->setValue(QString::number(data.value(QStringLiteral("total")).toInt()));
    m_reportCard->setCaption(QStringLiteral("当前账号可见"));
  });
}

void DashboardPage::loadKnowledge()
{
  if (!m_api) return;
  m_api->get(QStringLiteral("/api/kg/stats"), 5000, [this, guard = QPointer<DashboardPage>(this), revision = m_revision](const QJsonObject &response) {
    if (!guard || revision != m_revision) return;
    if (response.value(QStringLiteral("status")).toString() != QStringLiteral("ok")) {
      m_knowledgeSummaryLabel->setText(QStringLiteral("知识图谱不可用"));
      setState(m_knowledgeStatusLabel, QStringLiteral("加载失败"), Theme::Error);
      return;
    }
    const auto data = response.value(QStringLiteral("data")).toObject();
    if (!data.value("node_count").isDouble() || !data.value("edge_count").isDouble()) { m_knowledgeSummaryLabel->setText(QStringLiteral("知识统计不可用")); setState(m_knowledgeStatusLabel, QStringLiteral("数据格式异常"), Theme::Error); return; }
    m_knowledgeSummaryLabel->setText(QStringLiteral("知识节点 %1 · 关系 %2")
        .arg(data.value(QStringLiteral("node_count")).toInt())
        .arg(data.value(QStringLiteral("edge_count")).toInt()));
    setState(m_knowledgeStatusLabel, QStringLiteral("知识图谱统计已更新"), Theme::Success);
  });
}

void DashboardPage::loadHealth()
{
  if (!m_api) return;
  m_api->get(QStringLiteral("/api/health"), 3000, [this, guard = QPointer<DashboardPage>(this), revision = m_revision](const QJsonObject &response) {
    if (!guard || revision != m_revision) return;
    const bool ok = response.value(QStringLiteral("status")).toString() == QStringLiteral("ok");
    setState(m_apiStatusLabel, ok ? QStringLiteral("正常") : QStringLiteral("异常"), ok ? Theme::Success : Theme::Error);
    m_healthHintLabel->setText(QStringLiteral("未接入健康检查"));
    m_healthHintLabel->setStyleSheet(QStringLiteral("color:%1;font-size:12px;").arg(Theme::TextSecondary));
  });
}

void DashboardPage::showPipelineError(const QString &)
{
  for (auto *card : {m_taskCard, m_assetCard, m_findingCard}) {
    card->setValue(QStringLiteral("—"));
    card->setCaption(QStringLiteral("加载失败"));
  }
  m_statusDistribution->setData({}, 0, QStringLiteral("任务数据加载失败，请重试"));
  m_riskDistribution->setData({}, 0, QStringLiteral("任务数据加载失败"));
  m_typeDistribution->setData({}, 0, QStringLiteral("任务数据加载失败"));
  m_recentTable->setRowCount(0);
  UiUtil::EmptyHint::setState(m_recentTable, QStringLiteral("任务数据加载失败，请重试"), true);
  m_todoList->clear();
  m_todoList->addItem(QStringLiteral("任务数据加载失败，请重试"));
  setState(m_dataStatusLabel, QStringLiteral("加载失败"), Theme::Error);
}
