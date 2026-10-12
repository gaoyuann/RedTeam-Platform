#include "TaskOverviewPage.h"
#include "../Theme.h"
#include "../widgets/MetricCard.h"

#include <QDateTime>
#include <QGridLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QMap>
#include <QPushButton>
#include <QScrollArea>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {
QString stateName(const QString &state)
{
  const QMap<QString, QString> names{{"created", "待启动"}, {"running", "进行中"}, {"awaiting_approval", "待审批"},
    {"paused", "已暂停"}, {"completed", "已完成"}, {"failed", "失败"}, {"cancelled", "已取消"},
    {"pending", "待开始"}, {"skipped", "已跳过"}, {"draft", "编辑中"}, {"submitted", "已提审"},
    {"approved", "审批通过"}, {"rejected", "已驳回"}};
  return names.value(state, state.isEmpty() ? QStringLiteral("未提供") : state);
}

QString timeText(const QString &value)
{
  if (value.isEmpty()) return QStringLiteral("未提供");
  auto time = QDateTime::fromString(value, Qt::ISODate);
  if (!time.isValid()) {
    time = QDateTime::fromString(value, "yyyy-MM-dd HH:mm:ss");
    time.setTimeSpec(Qt::UTC);
  }
  return time.isValid() ? time.toLocalTime().toString("yyyy-MM-dd HH:mm:ss") : value;
}

QLabel *plainLabel(QWidget *parent)
{
  auto *label = new QLabel(parent);
  label->setTextFormat(Qt::PlainText);
  label->setWordWrap(true);
  label->setTextInteractionFlags(Qt::TextSelectableByMouse);
  return label;
}
}

TaskOverviewPage::TaskOverviewPage(QWidget *parent) : QWidget(parent)
{
  setObjectName(QStringLiteral("taskOverviewPage"));
  setStyleSheet(Theme::PageStyle);
  auto *outer = new QVBoxLayout(this);
  outer->setContentsMargins(0, 0, 0, 0);
  auto *scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto *body = new QWidget(scroll);
  auto *layout = new QVBoxLayout(body);
  layout->setContentsMargins(16, 14, 16, 14);
  layout->setSpacing(12);
  auto *header = new QHBoxLayout;
  auto *title = new QLabel(QStringLiteral("任务概况"), body);
  title->setStyleSheet(QStringLiteral("font-size:20px; font-weight:700; color:#172033;"));
  header->addWidget(title, 1);
  auto *refresh = new QPushButton(QStringLiteral("刷新任务"), body);
  refresh->setObjectName(QStringLiteral("overviewRefreshButton"));
  header->addWidget(refresh);
  connect(refresh, &QPushButton::clicked, this, &TaskOverviewPage::refreshRequested);
  layout->addLayout(header);
  m_state = plainLabel(body);
  m_state->setObjectName(QStringLiteral("overviewStateLabel"));
  layout->addWidget(m_state);

  auto *contextTitle = new QLabel(QStringLiteral("任务上下文"), body);
  contextTitle->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(contextTitle);
  auto *facts = new QFrame(body);
  facts->setObjectName(QStringLiteral("overviewContextCards"));
  auto *factsLayout = new QGridLayout(facts);
  factsLayout->setContentsMargins(0, 0, 0, 0);
  factsLayout->setHorizontalSpacing(24);
  factsLayout->setVerticalSpacing(12);
  m_identity = plainLabel(facts);
  m_identity->setObjectName(QStringLiteral("overviewIdentityLabel"));
  m_authorization = plainLabel(facts);
  m_authorization->setObjectName(QStringLiteral("overviewAuthorizationLabel"));
  m_policy = plainLabel(facts);
  m_policy->setObjectName(QStringLiteral("overviewPolicyLabel"));
  m_sources = plainLabel(facts);
  m_sources->setObjectName(QStringLiteral("overviewSourcesLabel"));
  const QStringList factTitles{QStringLiteral("任务信息"), QStringLiteral("授权范围"),
      QStringLiteral("执行策略"), QStringLiteral("数据来源")};
  const QList<QLabel *> factValues{m_identity, m_authorization, m_policy, m_sources};
  for (int index = 0; index < factValues.size(); ++index) {
    auto *section = new QFrame(facts);
    section->setProperty("softCard", true);
    auto *sectionLayout = new QVBoxLayout(section);
    sectionLayout->setContentsMargins(12, 10, 12, 10);
    auto *heading = new QLabel(factTitles.at(index), section);
    heading->setStyleSheet(QStringLiteral("color:%1;font-size:13px;font-weight:600;").arg(Theme::Primary));
    sectionLayout->addWidget(heading);
    sectionLayout->addWidget(factValues.at(index));
    factsLayout->addWidget(section, index / 2, index % 2);
  }
  factsLayout->setColumnStretch(0, 1);
  factsLayout->setColumnStretch(1, 1);
  layout->addWidget(facts);

  auto *metrics = new QHBoxLayout;
  const QStringList titles{QStringLiteral("扫描发现记录"), QStringLiteral("候选风险（待验证）"), QStringLiteral("执行证据记录"), QStringLiteral("关联报告")};
  QList<QLabel *> values;
  for (int index = 0; index < titles.size(); ++index) {
    const char *colors[] = {Theme::Info, Theme::Warning, Theme::Info, Theme::Success};
    auto *card = new MetricCard(titles.at(index), colors[index], body);
    auto *value = card->findChild<QLabel *>(QStringLiteral("metricValue"));
    card->setObjectName(QStringLiteral("overviewMetric%1").arg(index));
    values.append(value);
    metrics->addWidget(card, 1);
  }
  m_scanCount = values.at(0);
  m_riskCount = values.at(1);
  m_evidenceCount = values.at(2);
  m_reportCount = values.at(3);
  layout->addLayout(metrics);
  auto *boundary = plainLabel(body);
  boundary->setText(QStringLiteral("扫描计数不含原始输出/扫描错误；证据条数不等于已验证漏洞，报告数量不等于正式结论。仅统计当前任务关联的扫描与执行。"));
  boundary->setStyleSheet(QStringLiteral("font-size:12px; color:#64748b;"));
  layout->addWidget(boundary);

  auto *timelineTitle = new QLabel(QStringLiteral("任务进展"), body);
  timelineTitle->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(timelineTitle);
  m_steps = new QTableWidget(0, 5, body);
  m_steps->setObjectName(QStringLiteral("overviewStepsTable"));
  m_steps->setHorizontalHeaderLabels({QStringLiteral("后端阶段"), QStringLiteral("状态"), QStringLiteral("开始时间（本地）"), QStringLiteral("结束时间（本地）"), QStringLiteral("异常摘要")});
  m_steps->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_steps->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_steps->setWordWrap(false);
  m_steps->setShowGrid(false);
  m_steps->verticalHeader()->hide();
  m_steps->verticalHeader()->setDefaultSectionSize(36);
  m_steps->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  m_steps->setMinimumHeight(156);
  layout->addWidget(m_steps);
  auto *actions = new QHBoxLayout;
  const QList<int> stages{1, 2, 4, 5, 6};
  const QStringList texts{QStringLiteral("扫描发现"), QStringLiteral("智能分析"), QStringLiteral("审阅预案"), QStringLiteral("执行验证"), QStringLiteral("结果评估")};
  for (int index = 0; index < stages.size(); ++index) {
    auto *button = new QPushButton(texts.at(index), body);
    button->setObjectName(QStringLiteral("overviewStage%1").arg(stages.at(index)));
    connect(button, &QPushButton::clicked, this, [this, stages, index]() { emit stageRequested(stages.at(index)); });
    actions->addWidget(button);
    m_stageButtons.append(button);
  }
  actions->addStretch();
  layout->addLayout(actions);
  layout->addStretch();
  scroll->setWidget(body);
  outer->addWidget(scroll);
  clearTaskContext();
}

void TaskOverviewPage::clearTaskContext()
{
  m_state->setText(QStringLiteral("请选择测试任务；这里不生成示例数据。"));
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_identity->setText(QStringLiteral("任务信息：未选择任务"));
  m_authorization->setText(QStringLiteral("授权记录：未提供"));
  m_policy->clear();
  m_sources->clear();
  for (auto *label : {m_scanCount, m_riskCount, m_evidenceCount, m_reportCount}) label->setText(QStringLiteral("—"));
  m_steps->setRowCount(0);
  for (auto *button : m_stageButtons) button->setEnabled(false);
}

void TaskOverviewPage::setLoading()
{
  clearTaskContext();
  m_state->setText(QStringLiteral("正在加载当前任务数据…"));
}

void TaskOverviewPage::showError(const QString &message)
{
  m_state->setText(QStringLiteral("任务数据刷新失败：%1。已展示数据可能过期，请刷新重试。").arg(message));
  m_state->setStyleSheet(Theme::StatusErrorStyle);
}

void TaskOverviewPage::setTaskContext(const QJsonObject &pipeline)
{
  if (pipeline.value("pipeline_id").toString().isEmpty()) { clearTaskContext(); return; }
  const auto config = pipeline.value("config").isObject() ? pipeline.value("config").toObject()
      : QJsonDocument::fromJson(pipeline.value("config").toString().toUtf8()).object();
  const auto summary = pipeline.value("summary").toObject();
  const auto plan = summary.value("plan").toObject();
  const auto execution = summary.value("execution").toObject();
  const auto authorization = config.value("authorization_confirmed");
  const auto approval = config.value("require_approval");
  const auto autoExecute = config.value("auto_execute");
  const QString taskName = config.value("task_name").toString().trimmed();
  const QString target = pipeline.value("target").toString().trimmed();
  const QString executionStatus = execution.value("status").toString().trimmed();
  m_state->setText(QStringLiteral("任务状态：%1 · 预案状态：%2 · 执行状态：%3\n%4")
      .arg(stateName(pipeline.value("status").toString()), plan.isEmpty() ? QStringLiteral("尚无独立草稿") : stateName(plan.value("state").toString()),
           executionStatus.isEmpty() ? QStringLiteral("尚无关联执行") : stateName(executionStatus),
           pipeline.value("error_message").toString().isEmpty() ? QStringLiteral("数据来源：当前任务详情及后端关联统计。") : pipeline.value("error_message").toString()));
  m_state->setStyleSheet(pipeline.value("status").toString() == "failed" ? Theme::StatusErrorStyle : Theme::StatusInfoStyle);
  m_identity->setText(QStringLiteral("任务：%1\n任务 ID：%2\n目标：%3\n创建人：%4\n创建时间（本地）：%5")
      .arg(taskName.isEmpty() ? QStringLiteral("未提供") : taskName, pipeline.value("pipeline_id").toString(),
           target.isEmpty() ? QStringLiteral("未提供") : target,
           pipeline.value("created_by").toString().trimmed().isEmpty() ? QStringLiteral("未提供") : pipeline.value("created_by").toString(), timeText(pipeline.value("created_at").toString())));
  m_authorization->setText(QStringLiteral("授权确认记录：%1\n授权范围记录：%2\n授权为用户记录，不代表后端已经核验目标范围。")
      .arg(!authorization.isBool() ? QStringLiteral("未提供") : authorization.toBool() ? QStringLiteral("已确认") : QStringLiteral("未确认"),
           config.value("authorization_scope").toString().trimmed().isEmpty() ? QStringLiteral("未提供") : config.value("authorization_scope").toString()));
  m_policy->setText(QStringLiteral("测试类型：%1\n创建方式：%2\n执行前人工审批：%3\n执行策略：%4")
      .arg(config.value("test_type").toString().trimmed().isEmpty() ? QStringLiteral("未提供") : config.value("test_type").toString(),
           config.value("creation_mode").toString().trimmed().isEmpty() ? QStringLiteral("未提供") : config.value("creation_mode").toString(),
           !approval.isBool() ? QStringLiteral("未提供") : approval.toBool() ? QStringLiteral("需要") : QStringLiteral("未启用"),
           !autoExecute.isBool() ? QStringLiteral("未提供") : autoExecute.toBool() ? QStringLiteral("允许执行（仍需满足审批/预检）") : QStringLiteral("不自动执行")));
  QStringList scanIds;
  for (const auto &value : summary.value("scan_task_ids").toArray()) scanIds.append(value.toString());
  if (!summary.contains("scan_task_ids")) scanIds = pipeline.value("scan_task_id").toString().split(',', QString::SkipEmptyParts);
  m_sources->setText(QStringLiteral("关联扫描：%1\n来源预案 / 执行快照：%2\n关联执行：%3%4")
      .arg(scanIds.isEmpty() ? QStringLiteral("尚无") : scanIds.join(", "),
           pipeline.value("generated_playbook_id").toString(QStringLiteral("尚无")),
           pipeline.value("run_id").toString(QStringLiteral("尚无")),
           plan.isEmpty() ? QString() : QStringLiteral("\n预案记录版本：v%1").arg(plan.value("revision").toInt())));
  const QStringList keys{"scan_findings", "candidate_risks", "evidence_records", "reports"};
  const QList<QLabel *> labels{m_scanCount, m_riskCount, m_evidenceCount, m_reportCount};
  for (int index = 0; index < keys.size(); ++index) labels.at(index)->setText(summary.contains(keys.at(index))
      ? QString::number(summary.value(keys.at(index)).toInt()) : QStringLiteral("—"));
  const auto steps = pipeline.value("steps").toArray();
  m_steps->setRowCount(steps.size());
  const QMap<QString, QString> names{{"scan", "扫描发现"}, {"analyze", "智能分析"}, {"generate", "预案生成"}, {"execute", "执行验证"}};
  for (int row = 0; row < steps.size(); ++row) {
    const auto step = steps.at(row).toObject();
    const QStringList values{names.value(step.value("step_type").toString(), step.value("step_type").toString()), stateName(step.value("status").toString()),
      timeText(step.value("started_at").toString()), timeText(step.value("completed_at").toString()), step.value("error_message").toString()};
    for (int column = 0; column < values.size(); ++column) {
      auto *item = new QTableWidgetItem(values.at(column));
      item->setToolTip(values.at(column).toHtmlEscaped());
      if (column == 1) {
        const auto status = step.value("status").toString();
        const bool failed = status == "failed";
        const bool completed = status == "completed";
        const bool waiting = status == "awaiting_approval";
        item->setForeground(QColor(failed ? Theme::Error : completed ? Theme::Success
            : waiting ? Theme::Warning : Theme::Info));
        item->setBackground(QColor(failed ? Theme::ErrorBg : completed ? Theme::SuccessBg
            : waiting ? Theme::WarningBg : Theme::InfoBg));
        item->setFont(QFont(QString(), 10, QFont::DemiBold));
      }
      m_steps->setItem(row, column, item);
    }
  }
  for (auto *button : m_stageButtons) button->setEnabled(true);
}
