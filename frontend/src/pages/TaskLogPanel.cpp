#include "TaskLogPanel.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <cmath>
#include <QHeaderView>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QScrollBar>
#include <QShowEvent>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

TaskLogPanel::TaskLogPanel(ApiClient *api, QWidget *parent) : QWidget(parent), m_api(api)
{
  setObjectName(QStringLiteral("taskLogPanel"));
  setStyleSheet(Theme::PageStyle);
  setMinimumHeight(180);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(12, 8, 12, 8);
  layout->setSpacing(5);
  auto *header = new QHBoxLayout;
  auto *title = new QLabel(QStringLiteral("任务活动日志"), this);
  title->setStyleSheet(QStringLiteral("font-weight:700; color:#172033;"));
  header->addWidget(title);
  m_level = new QComboBox(this);
  m_level->setObjectName(QStringLiteral("taskLogLevelCombo"));
  m_level->addItem(QStringLiteral("全部级别"), "");
  m_level->addItem(QStringLiteral("信息"), "info");
  m_level->addItem(QStringLiteral("警告"), "warn");
  m_level->addItem(QStringLiteral("错误"), "error");
  header->addWidget(m_level);
  m_follow = new QCheckBox(QStringLiteral("跟随最新"), this);
  m_follow->setChecked(true);
  header->addWidget(m_follow);
  header->addStretch();
  m_refresh = new QPushButton(QStringLiteral("刷新日志"), this);
  m_refresh->setObjectName(QStringLiteral("taskLogRefreshButton"));
  header->addWidget(m_refresh);
  layout->addLayout(header);
  m_state = new QLabel(this);
  m_state->setTextFormat(Qt::PlainText);
  m_state->setWordWrap(true);
  m_state->setStyleSheet(QStringLiteral("color:#64748b; font-size:12px;"));
  layout->addWidget(m_state);
  m_table = new QTableWidget(0, 3, this);
  m_table->setObjectName(QStringLiteral("taskLogTable"));
  m_table->setHorizontalHeaderLabels({QStringLiteral("时间（本地）"), QStringLiteral("级别"), QStringLiteral("活动摘要")});
  m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_table->setWordWrap(false);
  m_table->verticalHeader()->hide();
  m_table->verticalHeader()->setDefaultSectionSize(36);
  m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  UiUtil::EmptyHint::attach(m_table, QStringLiteral("当前任务暂无已保存活动日志"));
  layout->addWidget(m_table, 1);
  m_detail = new QLabel(this);
  m_detail->setTextFormat(Qt::PlainText);
  m_detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
  m_detail->setWordWrap(true);
  m_detail->setMaximumHeight(45);
  layout->addWidget(m_detail);
  connect(m_refresh, &QPushButton::clicked, this, &TaskLogPanel::refresh);
  connect(m_level, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TaskLogPanel::render);
  connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() {
    const auto *item = m_table->item(m_table->currentRow(), 2);
    m_detail->setText(item ? item->text() : QString());
    m_detail->setToolTip(item ? item->text().toHtmlEscaped() : QString());
  });
  clearTaskContext();
}

void TaskLogPanel::clearTaskContext()
{
  ++m_contextVersion;
  ++m_requestVersion;
  m_pipelineId.clear();
  m_rows = {};
  m_cursor = 0;
  m_loaded = false;
  m_busy = false;
  m_table->setRowCount(0);
  m_detail->clear();
  m_state->setText(QStringLiteral("未选择任务；活动日志不是工具原始输出或验证证据。"));
  m_refresh->setEnabled(false);
}

void TaskLogPanel::setTaskContext(const QString &pipelineId)
{
  if (pipelineId == m_pipelineId) return;
  clearTaskContext();
  m_pipelineId = pipelineId;
  m_refresh->setEnabled(!pipelineId.isEmpty());
  if (isVisible()) refresh();
}

void TaskLogPanel::showEvent(QShowEvent *event)
{
  QWidget::showEvent(event);
  refresh();
}

void TaskLogPanel::refresh()
{
  if (m_busy || m_pipelineId.isEmpty()) return;
  m_busy = true;
  m_refresh->setEnabled(false);
  const int context = m_contextVersion;
  const int request = ++m_requestVersion;
  const auto identifier = m_pipelineId;
  const auto path = QStringLiteral("/api/pipelines/%1/logs?limit=100%2").arg(identifier,
      m_loaded ? QStringLiteral("&after=%1").arg(m_cursor) : QString());
  QPointer<TaskLogPanel> guard(this);
  m_api->get(path, 8000, [guard, context, request, identifier](const QJsonObject &response) {
    if (!guard || context != guard->m_contextVersion || request != guard->m_requestVersion) return;
    guard->m_busy = false;
    guard->m_refresh->setEnabled(true);
    if (response.value("status").toString() != "ok") {
      guard->m_state->setText(QStringLiteral("日志刷新失败：%1；保留已加载记录，可重试。")
          .arg(response.value("error").toObject().value("message").toString(QStringLiteral("服务未返回有效数据"))));
      return;
    }
    if (response.value("pipeline_id").toString() != identifier || !response.value("data").isArray()) {
      guard->m_state->setText(QStringLiteral("日志响应任务标识或格式不匹配，未更新当前记录。"));
      return;
    }
    const auto incoming = response.value("data").toArray();
    qint64 previous = guard->m_cursor;
    for (const auto &value : incoming) {
      const auto row = value.toObject();
      const auto identifierValue = row.value("id").toDouble();
      if (!row.value("id").isDouble() || !std::isfinite(identifierValue) || identifierValue < 1
          || identifierValue > 9007199254740991.0 || std::floor(identifierValue) != identifierValue) {
        guard->m_state->setText(QStringLiteral("日志记录标识无效，未更新当前记录。"));
        return;
      }
      const auto rowId = static_cast<qint64>(identifierValue);
      if (row.value("pipeline_id").toString() != identifier || rowId <= previous || identifierValue != rowId
          || !row.value("message").isString() || !row.value("created_at").isString()
          || !QStringList{QStringLiteral("info"), QStringLiteral("warn"), QStringLiteral("error")}.contains(row.value("level").toString())) {
        guard->m_state->setText(QStringLiteral("日志记录来源或顺序无效，未更新当前记录。"));
        return;
      }
      previous = rowId;
    }
    for (const auto &value : incoming) guard->m_rows.append(value);
    while (guard->m_rows.size() > 500) guard->m_rows.removeAt(0);
    guard->m_cursor = previous;
    guard->m_loaded = true;
    guard->render();
    guard->m_state->setText(QStringLiteral("任务：%1 · 本页保留最近 %2 条；后端最多保存 2000 条。旧任务不会补造历史，日志不是验证证据。")
        .arg(identifier).arg(guard->m_rows.size()));
    if (response.value("meta").toObject().value("has_more").toBool() && !incoming.isEmpty() && guard->isVisible())
      QTimer::singleShot(0, guard, [guard, context]() { if (guard && context == guard->m_contextVersion) guard->refresh(); });
  });
}

void TaskLogPanel::render()
{
  const qint64 selected = m_table->currentRow() >= 0 ? m_table->item(m_table->currentRow(), 0)->data(Qt::UserRole).toLongLong() : 0;
  const int scrollPosition = m_table->verticalScrollBar()->value();
  const QString level = m_level->currentData().toString();
  m_table->setRowCount(0);
  int selectedRow = -1;
  for (const auto &value : m_rows) {
    const auto entry = value.toObject();
    if (!level.isEmpty() && entry.value("level").toString() != level) continue;
    const int row = m_table->rowCount();
    m_table->insertRow(row);
    const auto time = QDateTime::fromString(entry.value("created_at").toString(), Qt::ISODate);
    auto *timeItem = new QTableWidgetItem(time.isValid() ? time.toLocalTime().toString("MM-dd HH:mm:ss") : entry.value("created_at").toString());
    timeItem->setData(Qt::UserRole, entry.value("id").toVariant());
    m_table->setItem(row, 0, timeItem);
    const QString severity = entry.value("level").toString();
    m_table->setItem(row, 1, new QTableWidgetItem(severity == "error" ? QStringLiteral("错误") : severity == "warn" ? QStringLiteral("警告") : QStringLiteral("信息")));
    auto *message = new QTableWidgetItem(entry.value("message").toString());
    message->setToolTip(message->text().toHtmlEscaped());
    message->setForeground(severity == "error" ? QColor("#991b1b") : severity == "warn" ? QColor("#b45309") : QColor("#334155"));
    m_table->setItem(row, 2, message);
    if (entry.value("id").toVariant().toLongLong() == selected) selectedRow = row;
  }
  if (selectedRow >= 0) m_table->selectRow(selectedRow);
  if (m_follow->isChecked()) m_table->scrollToBottom();
  else m_table->verticalScrollBar()->setValue(scrollPosition);
}
