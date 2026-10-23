#include "TaskAiPanel.h"

#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QTimer>
#include <QVBoxLayout>
#include <functional>

namespace {

QString parseStatus(const QJsonObject &pipeline)
{
  const QString status = pipeline.value(QStringLiteral("status_cn")).toString();
  return status.isEmpty() ? UiUtil::taskStatusText(pipeline.value(QStringLiteral("status")).toString()) : status;
}

QJsonObject parseObject(const QJsonValue &value)
{
  if (value.isObject()) return value.toObject();
  if (!value.isString()) return {};

  QJsonParseError error;
  const auto document = QJsonDocument::fromJson(value.toString().toUtf8(), &error);
  return error.error == QJsonParseError::NoError && document.isObject()
      ? document.object() : QJsonObject{};
}

QString configValue(const QJsonObject &pipeline, const QString &key)
{
  return parseObject(pipeline.value(QStringLiteral("config"))).value(key).toString().trimmed();
}

QString valueText(const QJsonValue &value)
{
  if (value.isString()) return value.toString();
  if (value.isBool()) return value.toBool() ? QStringLiteral("是") : QStringLiteral("否");
  if (value.isDouble()) return QString::number(value.toDouble());
  if (value.isObject()) return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
  return {};
}

QString levelText(const QString &level)
{
  if (level == QStringLiteral("critical")) return QStringLiteral("严重");
  if (level == QStringLiteral("high")) return QStringLiteral("高");
  if (level == QStringLiteral("medium")) return QStringLiteral("中");
  if (level == QStringLiteral("low")) return QStringLiteral("低");
  return level;
}

QString formatAnalysisList(const QJsonArray &items, int limit,
                           const std::function<QString(const QJsonObject &)> &formatter)
{
  QStringList lines;
  const int count = qMin(items.size(), limit);
  for (int index = 0; index < count; ++index) {
    const auto object = items.at(index).toObject();
    const QString line = formatter(object).trimmed();
    if (!line.isEmpty()) lines << QStringLiteral("• ") + line;
  }
  if (items.size() > count) {
    lines << QStringLiteral("• 其余 %1 项已折叠，可在智能分析页查看完整结果").arg(items.size() - count);
  }
  return lines.join(QStringLiteral("\n"));
}

}

TaskAiPanel::TaskAiPanel(ApiClient *api, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
}

void TaskAiPanel::setupUI()
{
  setObjectName(QStringLiteral("taskAiPanel"));
  setMinimumWidth(290);
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(0, 0, 0, 0);
  mainLayout->setSpacing(0);

  auto *header = new QFrame(this);
  header->setObjectName(QStringLiteral("taskAiHeader"));
  header->setStyleSheet(QStringLiteral(
      "QFrame#taskAiHeader { background:#ffffff; border-bottom:1px solid #dbe5f0; }"));
  auto *headerLayout = new QHBoxLayout(header);
  headerLayout->setContentsMargins(12, 9, 12, 9);
  headerLayout->setSpacing(8);

  auto *title = new QLabel(QStringLiteral("任务 AI 协作"), header);
  title->setStyleSheet(QStringLiteral("font-size:14px; font-weight:700; color:#172033;"));
  headerLayout->addWidget(title);
  headerLayout->addStretch();

  m_stageLabel = new QLabel(QStringLiteral("未选择阶段"), header);
  m_stageLabel->setStyleSheet(QStringLiteral(
      "font-size:11px; color:#2563eb; background:#eff6ff; border:1px solid #bfdbfe;"
      " border-radius:4px; padding:2px 7px;"));
  headerLayout->addWidget(m_stageLabel);
  mainLayout->addWidget(header);

  m_contextStateLabel = new QLabel(this);
  m_contextStateLabel->setObjectName(QStringLiteral("taskAiContextState"));
  m_contextStateLabel->setWordWrap(true);
  m_contextStateLabel->setStyleSheet(QStringLiteral(
      "font-size:11px; color:#64748b; background:#f8fafc; border-bottom:1px solid #e2e8f0;"
      " padding:7px 12px;"));
  mainLayout->addWidget(m_contextStateLabel);

  m_contentWidget = new QWidget;
  m_contentLayout = new QVBoxLayout(m_contentWidget);
  m_contentLayout->setContentsMargins(10, 10, 10, 10);
  m_contentLayout->setSpacing(9);

  m_emptyLabel = new QLabel;
  m_emptyLabel->setWordWrap(true);
  m_emptyLabel->setStyleSheet(QStringLiteral("color:#64748b; padding:12px 4px;"));
  m_contentLayout->addWidget(m_emptyLabel);
  m_contentLayout->addStretch();

  m_scrollArea = new QScrollArea(this);
  m_scrollArea->setWidgetResizable(true);
  m_scrollArea->setFrameShape(QFrame::NoFrame);
  m_scrollArea->setWidget(m_contentWidget);
  m_scrollArea->setStyleSheet(QStringLiteral("QScrollArea { background:#f5f7fa; border:0; }"));
  mainLayout->addWidget(m_scrollArea, 1);

  auto *composer = new QFrame(this);
  composer->setObjectName(QStringLiteral("taskAiComposer"));
  composer->setStyleSheet(QStringLiteral(
      "QFrame#taskAiComposer { background:#ffffff; border-top:1px solid #dbe5f0; }"));
  auto *composerLayout = new QVBoxLayout(composer);
  composerLayout->setContentsMargins(10, 8, 10, 9);
  composerLayout->setSpacing(6);

  auto *hint = new QLabel(QStringLiteral("仅引用当前任务上下文，不会直接触发执行。"), composer);
  hint->setWordWrap(true);
  hint->setToolTip(QStringLiteral("问答会把当前任务摘要及部分扫描发现发送至系统配置的模型服务。"));
  hint->setStyleSheet(QStringLiteral("font-size:11px; color:#64748b;"));
  composerLayout->addWidget(hint);

  auto *inputLayout = new QHBoxLayout;
  inputLayout->setSpacing(6);
  m_promptEdit = new QPlainTextEdit(composer);
  m_promptEdit->setObjectName(QStringLiteral("taskAiPromptEdit"));
  m_promptEdit->setPlaceholderText(QStringLiteral("询问当前任务的风险、证据缺口或下一步建议…"));
  m_promptEdit->setFixedHeight(66);
  m_promptEdit->setTabChangesFocus(true);
  inputLayout->addWidget(m_promptEdit, 1);

  m_askButton = new QPushButton(QStringLiteral("询问"), composer);
  m_askButton->setObjectName(QStringLiteral("taskAiAskButton"));
  m_askButton->setProperty("primary", true);
  m_askButton->setFixedWidth(58);
  m_askButton->setEnabled(false);
  inputLayout->addWidget(m_askButton, 0, Qt::AlignBottom);
  composerLayout->addLayout(inputLayout);
  mainLayout->addWidget(composer);

  connect(m_askButton, &QPushButton::clicked, this, &TaskAiPanel::onAsk);
  connect(m_promptEdit, &QPlainTextEdit::textChanged, this, [this]() {
    m_askButton->setEnabled(!m_requestInFlight && !m_pipelineId.isEmpty() &&
                           !m_promptEdit->toPlainText().trimmed().isEmpty());
  });

  clearTaskContext();
}

void TaskAiPanel::setTaskContext(const QJsonObject &pipeline)
{
  const QString pipelineId = pipeline.value(QStringLiteral("pipeline_id")).toString();
  if (pipelineId != m_pipelineId) {
    m_messages.clear();
    m_promptEdit->clear();
    m_requestInFlight = false;
    m_askButton->setText(QStringLiteral("询问"));
    ++m_contextRevision;
  }
  if (pipeline == m_pipeline) return;
  m_pipeline = pipeline;
  m_pipelineId = pipelineId;
  rebuildContext();
}

void TaskAiPanel::clearTaskContext()
{
  ++m_contextRevision;
  m_pipeline = {};
  m_pipelineId.clear();
  m_messages.clear();
  m_promptEdit->clear();
  m_requestInFlight = false;
  m_askButton->setText(QStringLiteral("询问"));
  rebuildContext();
}

void TaskAiPanel::setStage(const QString &stage)
{
  m_stage = stage;
  m_stageLabel->setText(stage.isEmpty() ? QStringLiteral("未选择阶段") : stage);
  if (!m_pipelineId.isEmpty())
    m_contextStateLabel->setText(QStringLiteral("上下文已绑定任务 %1 · %2").arg(UiUtil::taskIdentifier(m_pipeline), stage));
}

void TaskAiPanel::setQuestion(const QString &question)
{
  m_promptEdit->setPlainText(question);
  m_promptEdit->setFocus();
  m_promptEdit->moveCursor(QTextCursor::End);
  m_askButton->setEnabled(!m_requestInFlight && !m_pipelineId.isEmpty() && !question.trimmed().isEmpty());
}

void TaskAiPanel::rebuildContext()
{
  while (m_contentLayout->count() > 0) {
    auto *item = m_contentLayout->takeAt(0);
    if (item->widget()) {
      item->widget()->hide();
      item->widget()->deleteLater();
    }
    delete item;
  }

  if (m_pipelineId.isEmpty()) {
    m_contextStateLabel->setText(QStringLiteral("尚未进入正式测试任务；直接执行模式不会混入任务级上下文。"));
    m_emptyLabel = new QLabel(QStringLiteral("打开一个测试任务后，这里会展示任务摘要、扫描事实、候选风险和 AI 协作记录。"));
    m_emptyLabel->setWordWrap(true);
    m_emptyLabel->setStyleSheet(QStringLiteral("color:#64748b; padding:12px 4px;"));
    m_contentLayout->addWidget(m_emptyLabel);
    m_contentLayout->addStretch();
    m_askButton->setEnabled(false);
    return;
  }

  const QString status = parseStatus(m_pipeline);
  const QString taskName = configValue(m_pipeline, QStringLiteral("task_name"));
  const QString type = configValue(m_pipeline, QStringLiteral("test_type"));
  const QString target = m_pipeline.value(QStringLiteral("target")).toString();
  const QString scope = configValue(m_pipeline, QStringLiteral("authorization_scope"));
  const auto config = parseObject(m_pipeline.value(QStringLiteral("config")));
  const auto analysis = parseObject(m_pipeline.value(QStringLiteral("analysis_result")));
  const auto steps = m_pipeline.value(QStringLiteral("steps")).toArray();
  bool fallback = analysis["tech_stack"].isObject() &&
      analysis["tech_stack"].toObject()["note"].toString().contains(QStringLiteral("LLM"));
  for (const auto &value : steps) {
    const auto step = value.toObject();
    if (step["step_type"].toString() == QStringLiteral("analyze"))
      fallback = fallback || parseObject(step["output_data"])["fallback"].toBool();
  }

  QStringList summary;
  summary << QStringLiteral("任务：%1").arg(taskName.isEmpty() ? QStringLiteral("未命名任务") : taskName);
  summary << QStringLiteral("任务ID：%1").arg(UiUtil::taskIdentifier(m_pipeline));
  summary << QStringLiteral("目标：%1").arg(target.isEmpty() ? QStringLiteral("未提供") : target);
  if (!type.isEmpty()) summary << QStringLiteral("类型：%1").arg(type);
  summary << QStringLiteral("状态：%1").arg(status.isEmpty() ? QStringLiteral("未知") : status);
  summary << QStringLiteral("授权记录：%1").arg(config.value(QStringLiteral("authorization_confirmed")).toBool()
      ? QStringLiteral("用户已确认（不等于范围已自动校验）") : QStringLiteral("未确认 / 无记录"));
  if (!scope.isEmpty()) summary << QStringLiteral("授权范围：%1").arg(scope);
  m_contextStateLabel->setText(QStringLiteral("上下文已绑定任务 %1 · %2").arg(
      UiUtil::taskIdentifier(m_pipeline), m_stage.isEmpty() ? QStringLiteral("任务工作台") : m_stage));
  addCard(QStringLiteral("任务摘要"), summary.join(QStringLiteral("\n")), QStringLiteral("#2563eb"));

  QStringList sources;
  const auto scanIds = m_pipeline.value(QStringLiteral("scan_task_id")).toString().split(',', QString::SkipEmptyParts);
  if (!scanIds.isEmpty()) {
    sources << QStringLiteral("扫描来源：%1 个扫描作业（%2）").arg(scanIds.size()).arg(scanIds.join(QStringLiteral(", ")));
  } else {
    sources << QStringLiteral("扫描事实：尚未关联扫描作业");
  }
  sources << QStringLiteral("任务状态：%1").arg(status.isEmpty() ? QStringLiteral("未知") : status);
  if (analysis.isEmpty()) {
    sources << QStringLiteral("分析结果：尚未生成，不能把 AI 候选风险当作正式结论");
  } else {
    sources << QStringLiteral("分析结果：%1，来自当前任务 analysis_result")
        .arg(fallback ? QStringLiteral("规则降级（非 AI 回答）") : QStringLiteral("结构化分析候选"));
  }
  if (!m_pipeline.value(QStringLiteral("generated_playbook_id")).toString().isEmpty())
    sources << QStringLiteral("预案：%1").arg(m_pipeline.value(QStringLiteral("generated_playbook_id")).toString());
  if (!m_pipeline.value(QStringLiteral("run_id")).toString().isEmpty())
    sources << QStringLiteral("执行记录：%1").arg(m_pipeline.value(QStringLiteral("run_id")).toString());
  sources << QStringLiteral("会话仅当前查看期间保留，切换任务后清空。");
  addCard(QStringLiteral("当前引用数据"), sources.join(QStringLiteral("\n")), QStringLiteral("#64748b"));

  if (analysis.isEmpty()) {
    addCard(QStringLiteral("分析摘要"),
            QStringLiteral("当前任务还没有结构化分析结果。请先完成扫描与分析阶段；此面板不会生成固定示例数据。"),
            QStringLiteral("#f59e0b"));
  } else {
    const auto techStack = analysis.value(QStringLiteral("tech_stack")).toArray();
    const QString techText = formatAnalysisList(techStack, 5, [](const QJsonObject &item) {
      const QString name = item.value(QStringLiteral("name")).toString();
      const QString category = item.value(QStringLiteral("category")).toString();
      const QString confidence = item.value(QStringLiteral("confidence")).toString();
      return QStringLiteral("%1%2%3").arg(name,
          category.isEmpty() ? QString() : QStringLiteral("（%1）").arg(category),
          confidence.isEmpty() ? QString() : QStringLiteral(" · 置信度 %1").arg(confidence));
    });
    if (!techText.isEmpty()) addCard(QStringLiteral("技术栈识别"), techText, QStringLiteral("#2563eb"));

    const auto attackSurface = analysis.value(QStringLiteral("attack_surface")).toArray();
    const QString surfaceText = formatAnalysisList(attackSurface, 5, [](const QJsonObject &item) {
      const QString type = item.value(QStringLiteral("type")).toString();
      const QString detail = item.value(QStringLiteral("detail")).toString();
      const QString severity = item.value(QStringLiteral("severity")).toString();
      const QString count = valueText(item.value(QStringLiteral("count")));
      return QStringLiteral("%1：%2%3%4").arg(type,
          detail.isEmpty() ? QStringLiteral("未提供详情") : detail,
          severity.isEmpty() ? QString() : QStringLiteral(" · %1").arg(levelText(severity)),
          count.isEmpty() ? QString() : QStringLiteral(" · %1 项").arg(count));
    });
    if (!surfaceText.isEmpty()) addCard(QStringLiteral("攻击面候选"), surfaceText, QStringLiteral("#0f766e"));

    const auto risks = analysis.value(QStringLiteral("risk_assessment")).toArray();
    const QString riskText = formatAnalysisList(risks, 6, [](const QJsonObject &item) {
      const QString category = item.value(QStringLiteral("category")).toString();
      const QString description = item.value(QStringLiteral("description")).toString();
      const QString level = levelText(item.value(QStringLiteral("level")).toString());
      return QStringLiteral("[%1] %2%3").arg(level.isEmpty() ? QStringLiteral("未分级") : level,
          category, description.isEmpty() ? QString() : QStringLiteral("：%1").arg(description));
    });
    addCard(QStringLiteral("候选风险（非已验证漏洞）"),
            riskText.isEmpty() ? QStringLiteral("暂无候选风险") : riskText,
            QStringLiteral("#f59e0b"));

    const auto strategies = analysis.value(QStringLiteral("recommended_strategy")).toArray();
    const QString strategyText = formatAnalysisList(strategies, 4, [](const QJsonObject &item) {
      const QString priority = valueText(item.value(QStringLiteral("priority")));
      const QString name = item.value(QStringLiteral("strategy")).toString();
      const QString description = item.value(QStringLiteral("description")).toString();
      return QStringLiteral("P%1 %2%3").arg(priority.isEmpty() ? QStringLiteral("?") : priority,
          name, description.isEmpty() ? QString() : QStringLiteral("：%1").arg(description));
    });
    if (!strategyText.isEmpty()) addCard(QStringLiteral("建议操作（待审核）"), strategyText, QStringLiteral("#7c3aed"));
  }

  for (const auto &message : m_messages) addConversationCard(message);
  if (m_messages.isEmpty()) {
    auto *hint = new QLabel(QStringLiteral("可以询问：当前有哪些证据缺口？下一步应优先验证什么？"));
    hint->setWordWrap(true);
    hint->setStyleSheet(QStringLiteral("color:#94a3b8; font-size:11px; padding:2px 4px;"));
    m_contentLayout->addWidget(hint);
  }
  m_contentLayout->addStretch();
  m_askButton->setEnabled(!m_requestInFlight && !m_promptEdit->toPlainText().trimmed().isEmpty());
}

void TaskAiPanel::addCard(const QString &title, const QString &text, const QString &accent)
{
  auto *card = new QFrame(m_contentWidget);
  card->setObjectName(QStringLiteral("taskAiCard"));
  card->setStyleSheet(QStringLiteral(
      "QFrame#taskAiCard { background:#ffffff; border:1px solid #dbe5f0; border-left:3px solid %1;"
      " border-radius:6px; }").arg(accent));
  auto *layout = new QVBoxLayout(card);
  layout->setContentsMargins(10, 8, 10, 9);
  layout->setSpacing(5);

  auto *titleLabel = new QLabel(title, card);
  titleLabel->setStyleSheet(QStringLiteral("font-size:12px; font-weight:700; color:#334155;"));
  titleLabel->setWordWrap(true);
  titleLabel->setTextFormat(Qt::PlainText);
  layout->addWidget(titleLabel);
  auto *body = new QLabel(text, card);
  body->setWordWrap(true);
  body->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
  body->setTextFormat(Qt::PlainText);
  body->setTextInteractionFlags(Qt::TextSelectableByMouse);
  body->setStyleSheet(QStringLiteral("font-size:12px; color:#475569;"));
  layout->addWidget(body);
  m_contentLayout->addWidget(card);
}

void TaskAiPanel::addConversationCard(const ConversationMessage &message)
{
  const bool user = message.role == QStringLiteral("user");
  auto *card = new QFrame(m_contentWidget);
  card->setObjectName(QStringLiteral("taskAiMessage"));
  const QString background = user ? QStringLiteral("#eff6ff") : QStringLiteral("#ffffff");
  const QString border = user ? QStringLiteral("#bfdbfe") : QStringLiteral("#dbe5f0");
  card->setStyleSheet(QStringLiteral(
      "QFrame#taskAiMessage { background:%1; border:1px solid %2; border-radius:6px; }").arg(background, border));
  auto *layout = new QVBoxLayout(card);
  layout->setContentsMargins(10, 8, 10, 9);
  layout->setSpacing(4);
  auto *roleLabel = new QLabel(user ? QStringLiteral("你") : message.role == QStringLiteral("error")
      ? QStringLiteral("服务提示（非 AI 回答）") : QStringLiteral("AI 助手 · 候选解释"), card);
  roleLabel->setStyleSheet(QStringLiteral("font-size:11px; font-weight:700; color:%1;")
      .arg(user ? QStringLiteral("#2563eb") : QStringLiteral("#0f766e")));
  layout->addWidget(roleLabel);
  auto *body = new QLabel(message.text, card);
  body->setWordWrap(true);
  body->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
  body->setTextFormat(Qt::PlainText);
  body->setTextInteractionFlags(Qt::TextSelectableByMouse);
  body->setStyleSheet(QStringLiteral("font-size:12px; color:#334155;"));
  layout->addWidget(body);
  m_contentLayout->addWidget(card);
}

void TaskAiPanel::onAsk()
{
  if (m_pipelineId.isEmpty() || !m_api || m_requestInFlight) return;
  const QString message = m_promptEdit->toPlainText().trimmed();
  if (message.isEmpty()) return;

  const QString pipelineId = m_pipelineId;
  const int revision = m_contextRevision;
  m_requestInFlight = true;
  QJsonArray history;
  const int first = qMax(0, m_messages.size() - 6);
  for (int index = first; index < m_messages.size(); ++index) {
    const auto &entry = m_messages.at(index);
    if (entry.role == QStringLiteral("error")) continue;
    history.append(QJsonObject{{QStringLiteral("role"), entry.role},
                               {QStringLiteral("content"), entry.text.left(800)}});
  }
  while (m_messages.size() >= 20) m_messages.removeFirst();
  m_messages.append({QStringLiteral("user"), message});
  m_promptEdit->clear();
  m_askButton->setEnabled(false);
  m_askButton->setText(QStringLiteral("分析中"));
  rebuildContext();
  scrollToBottom();

  const QJsonObject body{{QStringLiteral("message"), message},
                         {QStringLiteral("history"), history},
                         {QStringLiteral("stage"), m_stage}};
  const QPointer<TaskAiPanel> guard(this);
  m_api->post(QStringLiteral("/api/pipelines/%1/assistant").arg(pipelineId), body, 65000,
      [this, guard, pipelineId, revision](const QJsonObject &response) {
    if (!guard) return;
    if (pipelineId != m_pipelineId || revision != m_contextRevision) return;
    m_requestInFlight = false;
    m_askButton->setText(QStringLiteral("询问"));
    if (response.value(QStringLiteral("status")).toString() == QStringLiteral("ok")) {
      const auto data = response.value(QStringLiteral("data")).toObject();
      QString answer = data.value(QStringLiteral("answer")).toString().trimmed().left(10000);
      if (data["task_id"].toString() != pipelineId || answer.isEmpty()) {
        m_messages.append({QStringLiteral("error"), QStringLiteral("回答的任务标识不匹配或内容为空，请重试。")});
      } else {
        m_messages.append({QStringLiteral("assistant"), answer});
      }
    } else {
      const auto error = response.value(QStringLiteral("error")).toObject();
      const QString reason = error.value(QStringLiteral("message")).toString(
          QStringLiteral("AI 服务暂时不可用，请检查模型配置或稍后重试。"));
      m_messages.append({QStringLiteral("error"), QStringLiteral("未获得 AI 回答：%1。可重新输入问题重试。").arg(reason)});
    }
    rebuildContext();
    scrollToBottom();
  });
}

void TaskAiPanel::scrollToBottom()
{
  QTimer::singleShot(50, this, [this]() {
    if (m_scrollArea) {
      m_scrollArea->verticalScrollBar()->setValue(m_scrollArea->verticalScrollBar()->maximum());
    }
  });
}
