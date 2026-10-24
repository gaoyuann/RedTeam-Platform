#include "AnalysisPage.h"
#include "../Theme.h"
#include "../UiUtil.h"

#include <QComboBox>
#include <QFrame>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {
QString analysisText(const QJsonValue &value)
{
  if (value.isString()) return value.toString();
  if (value.isObject()) return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Indented));
  if (value.isArray()) return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Indented));
  return {};
}

QJsonObject analysisObject(const QJsonValue &value)
{
  return value.isObject() ? value.toObject() : QJsonDocument::fromJson(value.toString().toUtf8()).object();
}
}

AnalysisPage::AnalysisPage(QWidget *parent) : QWidget(parent)
{
  setObjectName(QStringLiteral("taskAnalysisPage"));
  setStyleSheet(Theme::PageStyle);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(16, 14, 16, 14);
  layout->setSpacing(10);

  auto *header = new QHBoxLayout;
  auto *title = new QLabel(QStringLiteral("智能分析 · 候选成果"), this);
  title->setStyleSheet(QStringLiteral("font-size:20px; font-weight:700; color:#172033;"));
  header->addWidget(title, 1);
  m_refreshButton = new QPushButton(QStringLiteral("刷新结果"), this);
  m_refreshButton->setObjectName(QStringLiteral("analysisRefreshButton"));
  header->addWidget(m_refreshButton);
  auto *scanButton = new QPushButton(QStringLiteral("查看扫描来源"), this);
  header->addWidget(scanButton);
  layout->addLayout(header);
  connect(m_refreshButton, &QPushButton::clicked, this, &AnalysisPage::refreshRequested);
  connect(scanButton, &QPushButton::clicked, this, &AnalysisPage::scanRequested);

  m_stateLabel = new QLabel(this);
  m_stateLabel->setTextFormat(Qt::PlainText);
  m_stateLabel->setWordWrap(true);
  m_stateLabel->setStyleSheet(Theme::StatusInfoStyle);
  layout->addWidget(m_stateLabel);
  m_sourceLabel = new QLabel(this);
  m_sourceLabel->setTextFormat(Qt::PlainText);
  m_sourceLabel->setWordWrap(true);
  m_sourceLabel->setStyleSheet(QStringLiteral("font-size:12px; color:#64748b;"));
  layout->addWidget(m_sourceLabel);

  auto *categoryRow = new QHBoxLayout;
  categoryRow->addWidget(new QLabel(QStringLiteral("成果类型："), this));
  m_categoryCombo = new QComboBox(this);
  m_categoryCombo->setObjectName(QStringLiteral("analysisCategoryCombo"));
  m_categoryCombo->addItem(QStringLiteral("候选风险"), QStringLiteral("risk_assessment"));
  m_categoryCombo->addItem(QStringLiteral("技术栈识别"), QStringLiteral("tech_stack"));
  m_categoryCombo->addItem(QStringLiteral("攻击面候选"), QStringLiteral("attack_surface"));
  m_categoryCombo->addItem(QStringLiteral("建议策略"), QStringLiteral("recommended_strategy"));
  categoryRow->addWidget(m_categoryCombo);
  categoryRow->addStretch();
  layout->addLayout(categoryRow);
  connect(m_categoryCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
          [this]() { rebuildTable(); });

  auto *splitter = new QSplitter(Qt::Horizontal, this);
  m_table = new QTableWidget(0, 4, splitter);
  m_table->setObjectName(QStringLiteral("analysisResultTable"));
  m_table->setHorizontalHeaderLabels({QStringLiteral("条目"), QStringLiteral("摘要"),
                                      QStringLiteral("等级 / 置信度"), QStringLiteral("判定状态")});
  m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_table->setAlternatingRowColors(true);
  m_table->setWordWrap(false);
  m_table->setShowGrid(false);
  m_table->setTextElideMode(Qt::ElideRight);
  m_table->verticalHeader()->hide();
  m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  UiUtil::EmptyHint::attach(m_table, QStringLiteral("当前任务暂无此类分析成果"));
  connect(m_table, &QTableWidget::itemSelectionChanged, this, &AnalysisPage::showSelection);

  auto *detailWidget = new QFrame(splitter);
  detailWidget->setProperty("softCard", true);
  auto *detailLayout = new QVBoxLayout(detailWidget);
  detailLayout->setContentsMargins(14, 12, 14, 12);
  auto *detailHeader = new QHBoxLayout;
  auto *detailTitle = new QLabel(QStringLiteral("来源与证据边界"), detailWidget);
  detailTitle->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(detailTitle);
  m_askButton = new QPushButton(QStringLiteral("请 AI 解释此项"), detailWidget);
  m_askButton->setObjectName(QStringLiteral("analysisAskButton"));
  detailHeader->addWidget(m_askButton);
  m_planButton = new QPushButton(QStringLiteral("加入预案草稿"), detailWidget);
  m_planButton->setObjectName(QStringLiteral("analysisPlanButton"));
  detailHeader->addWidget(m_planButton);
  connect(m_planButton, &QPushButton::clicked, this, [this]() {
    if (QStringList{"source_assisted","program_dynamic"}.contains(analysisObject(m_pipeline["config"])["scan_mode"].toString())) {
      emit sourceVerificationRequested();
      return;
    }
    const int row = m_table->currentRow();
    if (row >= 0 && row < m_items.size())
      emit planCandidateRequested(m_categoryCombo->currentData().toString(), row, m_items.at(row));
  });
  detailLayout->addLayout(detailHeader);
  m_detail = new QPlainTextEdit(detailWidget);
  m_detail->setObjectName(QStringLiteral("analysisItemDetail"));
  m_detail->setReadOnly(true);
  detailLayout->addWidget(m_detail, 1);
  splitter->setChildrenCollapsible(false);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 2);
  splitter->setSizes({560, 360});
  layout->addWidget(splitter, 1);
  connect(m_askButton, &QPushButton::clicked, this, [this]() {
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_items.size()) return;
    emit assistantRequested(QStringLiteral("请解释当前任务 %1 的 %2 第 %3 项，说明依据和证据缺口，不要将其当作已验证漏洞。\n%4")
        .arg(m_pipeline["pipeline_id"].toString(), m_categoryCombo->currentText())
        .arg(row + 1).arg(analysisText(m_items.at(row)).left(1200)));
  });
  clearTaskContext();
}

void AnalysisPage::setTaskContext(const QJsonObject &pipeline)
{
  UiUtil::EmptyHint::reset(m_table);
  m_refreshButton->setEnabled(true);
  const bool changed = pipeline["pipeline_id"] != m_pipeline["pipeline_id"];
  m_pipeline = pipeline;
  m_analysis = analysisObject(pipeline["analysis_result"]);
  if (changed) m_table->clearSelection();
  QString state = QStringLiteral("当前尚未生成结构化分析；请先完成扫描与分析阶段。");
  bool fallback = m_analysis["tech_stack"].isObject() &&
                  m_analysis["tech_stack"].toObject()["note"].toString().contains(QStringLiteral("LLM"));
  for (const auto &value : pipeline["steps"].toArray()) {
    const auto step = value.toObject();
    if (step["step_type"].toString() != QStringLiteral("analyze")) continue;
    fallback = fallback || analysisObject(step["output_data"])["fallback"].toBool();
    if (step["status"].toString() == QStringLiteral("running"))
      state = QStringLiteral("分析进行中；结果尚未产生，不代表已验证风险。");
    else if (step["status"].toString() == QStringLiteral("failed"))
      state = QStringLiteral("分析失败：%1").arg(step["error_message"].toString());
  }
  if (!m_analysis.isEmpty()) {
    state = fallback ? QStringLiteral("来源：规则降级分析（模型不可用）；以下均为待验证候选项。")
                     : QStringLiteral("来源：任务结构化分析；以下均为待验证候选项，不是正式漏洞结论。");
  }
  const auto coverage = m_analysis.value("analysis_scope").toObject();
  if (!coverage.isEmpty()) state += QStringLiteral("\nAI 输入 %1 / %2 条记录（最多 %3 条，单条最多 %4 字符）；完整发现请查看扫描结果。")
      .arg(coverage.value("input_records").toInt()).arg(coverage.value("eligible_records").toInt())
      .arg(coverage.value("record_limit").toInt()).arg(coverage.value("per_record_char_limit").toInt());
  m_stateLabel->setText(state);
  m_stateLabel->setStyleSheet(fallback ? Theme::StatusWarningStyle : Theme::StatusInfoStyle);
  m_sourceLabel->setText(QStringLiteral("任务：%1 · 扫描作业：%2\n仅列出任务级来源；后端尚未提供逐条风险与证据的映射。")
      .arg(UiUtil::taskIdentifier(pipeline), pipeline["scan_task_id"].toString().isEmpty()
          ? QStringLiteral("未关联") : pipeline["scan_task_id"].toString()));
  rebuildTable();
}

void AnalysisPage::clearTaskContext()
{
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("请选择一个正式测试任务查看分析成果"));
  m_pipeline = {};
  m_analysis = {};
  m_table->clearSelection();
  m_stateLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_stateLabel->setText(QStringLiteral("请选择一个正式测试任务查看分析成果。"));
  m_sourceLabel->clear();
  m_refreshButton->setEnabled(false);
  rebuildTable();
}

void AnalysisPage::setLoading()
{
  clearTaskContext();
  m_stateLabel->setText(QStringLiteral("正在加载当前任务的分析数据…"));
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("正在加载当前任务的分析数据…"));
}

void AnalysisPage::showError(const QString &message)
{
  m_stateLabel->setText(QStringLiteral("任务数据加载失败：%1。可点击“刷新结果”重试。").arg(message));
  m_stateLabel->setStyleSheet(Theme::StatusErrorStyle);
  m_refreshButton->setEnabled(true);
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("任务分析数据加载失败，请刷新重试"), true);
}

void AnalysisPage::rebuildTable()
{
  const int previousRow = m_table->currentRow();
  const QString key = m_categoryCombo->currentData().toString();
  const auto value = m_analysis[key];
  m_items = value.isArray() ? value.toArray() : QJsonArray{};
  if (value.isObject() && !value.toObject().isEmpty()) m_items.append(value);
  if (value.isString() && !value.toString().isEmpty()) m_items.append(value);
  m_table->setRowCount(m_items.size());
  for (int index = 0; index < m_items.size(); ++index) {
    const auto item = m_items.at(index).toObject();
    QString title = item["category"].toString(item["name"].toString(item["type"].toString(item["strategy"].toString())));
    if (title.isEmpty()) title = QStringLiteral("条目 %1").arg(index + 1);
    QString summary = item["description"].toString(item["detail"].toString(item["evidence"].toString(item["note"].toString())));
    if (summary.isEmpty()) summary = analysisText(m_items.at(index)).simplified();
    const QString level = item["level"].toString(item["severity"].toString(item["max_severity"].toString(item["confidence"].toString())));
    m_table->setItem(index, 0, new QTableWidgetItem(title));
    auto *summaryItem = new QTableWidgetItem(summary.left(180));
    summaryItem->setToolTip(summary.left(1000).toHtmlEscaped());
    m_table->setItem(index, 1, summaryItem);
    m_table->setItem(index, 2, new QTableWidgetItem(level.isEmpty() ? QStringLiteral("未提供") : level));
    m_table->setItem(index, 3, new QTableWidgetItem(key == QStringLiteral("recommended_strategy")
        ? QStringLiteral("建议 · 未执行") : QStringLiteral("候选 · 待验证")));
  }
  if (!m_items.isEmpty()) m_table->selectRow(qBound(0, previousRow, m_items.size() - 1));
  showSelection();
}

void AnalysisPage::showSelection()
{
  const int row = m_table->currentRow();
  const bool selected = row >= 0 && row < m_items.size();
  m_askButton->setEnabled(selected);
  const bool sourceMode =QStringList{"source_assisted","program_dynamic"}.contains( analysisObject(m_pipeline["config"])["scan_mode"].toString());
  m_planButton->setText(sourceMode ? QStringLiteral("生成攻击测试预案") : QStringLiteral("加入草稿候选备注"));
  m_planButton->setToolTip(sourceMode
      ? QStringLiteral("根据本任务实际漏洞发现生成预案，执行后查看攻击效果。")
      : QStringLiteral("仅加入审阅备注，不新增执行步骤。"));
  m_planButton->setEnabled((selected || sourceMode) && m_pipeline["status"].toString() == QStringLiteral("awaiting_approval"));
  if (!selected) {
    m_detail->setPlainText(QStringLiteral("选择分析条目查看完整数据。候选风险需要独立核验和原始证据才能成为正式结论。"));
    return;
  }
  m_detail->setPlainText(QStringLiteral("来源：任务 %1 / analysis_result / %2 / 第 %3 项\n关联扫描作业：%4\n判定：候选内容，尚未核验；没有逐条证据映射。\n\n%5")
      .arg(m_pipeline["pipeline_id"].toString(), m_categoryCombo->currentData().toString())
      .arg(row + 1).arg(m_pipeline["scan_task_id"].toString(), analysisText(m_items.at(row))));
}
