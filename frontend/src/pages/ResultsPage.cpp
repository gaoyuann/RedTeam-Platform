#include "ResultsPage.h"
#include "EvaluatePage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/WorkbenchTabs.h"
#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QShowEvent>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QUrlQuery>
#include <QVBoxLayout>

ResultsPage::ResultsPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username)
{
  setObjectName("resultsPage");
  setStyleSheet(Theme::PageStyle);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(24, 20, 24, 20);
  auto *title = new QLabel(QStringLiteral("结果与报告"), this);
  title->setStyleSheet("font-size:24px; font-weight:700; color:#12213c;");
  layout->addWidget(title);
  auto *hint = new QLabel(QStringLiteral("任务追溯报告按明确来源定位；历史报告不按同目标猜测任务归属。草稿、工具结果和人工复核结论分开处理。"), this);
  hint->setWordWrap(true);
  layout->addWidget(hint);
  m_tabs = new WorkbenchTabs(this);
  layout->addWidget(m_tabs, 1);
  auto *index = new QWidget(m_tabs);
  auto *indexLayout = new QVBoxLayout(index);
  auto *filters = new QHBoxLayout;
  m_search = new QLineEdit(index);
  m_search->setMaxLength(120);
  m_search->setPlaceholderText(QStringLiteral("报告编号 / 标题 / 任务编号 / 目标"));
  m_kind = new QComboBox(index);
  m_kind->addItem(QStringLiteral("全部报告"), "all");
  m_kind->addItem(QStringLiteral("任务追溯快照"), "trace_snapshot");
  m_kind->addItem(QStringLiteral("历史报告（来源不完整）"), "legacy");
  auto *searchButton = new QPushButton(QStringLiteral("筛选"), index);
  m_refresh = new QPushButton(QStringLiteral("刷新"), index);
  filters->addWidget(m_search, 1); filters->addWidget(m_kind); filters->addWidget(searchButton); filters->addWidget(m_refresh);
  indexLayout->addLayout(filters);
  m_state = new QLabel(QStringLiteral("打开报告索引后读取当前账号可见的记录"), index);
  m_state->setTextFormat(Qt::PlainText);
  m_state->setWordWrap(true);
  indexLayout->addWidget(m_state);
  m_table = new QTableWidget(index);
  m_table->setColumnCount(7);
  m_table->setHorizontalHeaderLabels({"报告编号 / 标题", "来源类型", "任务编号", "Run", "所有者 / 目标", "存储状态", "创建时间"});
  m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_table->setAlternatingRowColors(true);
  m_table->setWordWrap(false);
  m_table->setShowGrid(false);
  m_table->verticalHeader()->hide();
  m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  m_table->horizontalHeader()->setStretchLastSection(true);
  m_table->setColumnWidth(0, 250); m_table->setColumnWidth(2, 180); m_table->setColumnWidth(4, 230);
  UiUtil::EmptyHint::attach(m_table, QStringLiteral("暂无匹配的可见报告"));
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("打开报告索引后读取记录"));
  indexLayout->addWidget(m_table, 1);
  auto *actions = new QHBoxLayout;
  m_open = new QPushButton(QStringLiteral("打开所属任务报告"), index);
  m_open->setProperty("primary", true);
  m_previous = new QPushButton(QStringLiteral("上一页"), index);
  m_next = new QPushButton(QStringLiteral("下一页"), index);
  actions->addWidget(m_open); actions->addStretch(); actions->addWidget(m_previous); actions->addWidget(m_next);
  indexLayout->addLayout(actions);
  m_tabs->addTab(index, QStringLiteral("报告索引"));
  m_legacy = nullptr;
  auto *legacyContainer = new QWidget(m_tabs);
  auto *legacyLayout = new QVBoxLayout(legacyContainer);
  legacyLayout->setContentsMargins(0, 0, 0, 0);
  m_tabs->addTab(legacyContainer, QStringLiteral("历史评估与报告（兼容入口）"));
  connect(m_refresh, &QPushButton::clicked, this, &ResultsPage::refresh);
  connect(searchButton, &QPushButton::clicked, this, &ResultsPage::resetFilter);
  connect(m_search, &QLineEdit::returnPressed, this, &ResultsPage::resetFilter);
  connect(m_search, &QLineEdit::textChanged, this, [this]() {
    ++m_revision; m_busy = false; m_fresh = false;
    m_state->setStyleSheet(Theme::StatusInfoStyle);
    m_state->setText(QStringLiteral("筛选条件已修改，按回车或点击“筛选”读取新结果。"));
    UiUtil::EmptyHint::setState(m_table, QStringLiteral("筛选条件已修改，请确认筛选后读取新结果"));
    updateButtons();
  });
  connect(m_kind, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ResultsPage::resetFilter);
  connect(m_previous, &QPushButton::clicked, this, [this]() { m_offset = qMax(0, m_offset - 50); refresh(); });
  connect(m_next, &QPushButton::clicked, this, [this]() { m_offset += 50; refresh(); });
  connect(m_open, &QPushButton::clicked, this, &ResultsPage::openSelected);
  connect(m_table, &QTableWidget::itemSelectionChanged, this, &ResultsPage::updateButtons);
  connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int, int) { openSelected(); });
  connect(m_tabs, &QTabWidget::currentChanged, this, [this, legacyLayout, legacyContainer](int tab) {
    ++m_revision; m_busy = false; m_fresh = false; updateButtons();
    if (tab == 0) refresh();
    else if (!m_legacy) {
      m_legacy = new EvaluatePage(m_api, m_role, m_username, legacyContainer);
      legacyLayout->addWidget(m_legacy);
    }
  });
  m_timer = new QTimer(this);
  m_timer->setInterval(15000);
  connect(m_timer, &QTimer::timeout, this, [this]() { if (isVisible() && m_tabs->currentIndex() == 0) refresh(); });
  m_timer->start();
  updateButtons();
}

void ResultsPage::showEvent(QShowEvent *event) { QWidget::showEvent(event); if (m_tabs->currentIndex() == 0) refresh(); }

void ResultsPage::resetFilter()
{
  ++m_revision; m_busy = false; m_offset = 0; m_fresh = false; refresh();
}

void ResultsPage::refresh()
{
  if (m_busy || m_tabs->currentIndex() != 0) return;
  m_busy = true; m_fresh = false; updateButtons();
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_state->setText(QStringLiteral("正在读取报告索引…不评分、生成或导出报告。"));
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("正在读取报告索引…"));
  const int revision = ++m_revision;
  const int offset = m_offset;
  const QString kind = m_kind->currentData().toString();
  const QString search = m_search->text().trimmed();
  QUrlQuery query;
  query.addQueryItem("limit", "50"); query.addQueryItem("offset", QString::number(offset));
  query.addQueryItem("kind", kind); query.addQueryItem("search", QString::fromLatin1(QUrl::toPercentEncoding(search)));
  QPointer<ResultsPage> guard(this);
  m_api->get("/api/reports/index?" + query.toString(QUrl::FullyEncoded), 5000,
    [guard, revision, offset, kind, search](const QJsonObject &response) {
      if (!guard || revision != guard->m_revision) return;
      guard->m_busy = false;
      const auto data = response.value("data").toObject();
      const auto rows = data.value("records").toArray();
      const int total = data.value("total").toInt(-1);
      bool valid = response.value("status").toString() == "ok" && data.value("schema_version").toInt() == 1
        && data.value("records").isArray() && rows.size() <= 50 && total >= rows.size()
        && data.value("limit").toInt() == 50 && data.value("offset").toInt(-1) == offset
        && data.value("kind").toString() == kind && data.value("search").toString() == search;
      QSet<QString> identities;
      for (const auto &value : rows) {
        const auto row = value.toObject();
        const QString id = row.value("report_id").toString();
        const QString rowKind = row.value("kind").toString();
        valid = valid && !id.isEmpty() && !identities.contains(id) && row.value("title").isString()
          && (rowKind == "trace_snapshot" || rowKind == "legacy") && (kind == "all" || rowKind == kind)
          && (guard->m_role == "admin" || row.value("owner").toString() == guard->m_username)
          && (rowKind != "trace_snapshot" || !row.value("pipeline_id").toString().isEmpty());
        identities.insert(id);
      }
      const auto *selected = guard->m_table->item(guard->m_table->currentRow(), 0);
      const QString oldId = selected ? selected->data(Qt::UserRole).toJsonObject().value("report_id").toString() : QString();
      guard->m_table->blockSignals(true);
      guard->m_table->setRowCount(valid ? rows.size() : 0);
      int selectedRow = -1;
      if (valid) for (int index = 0; index < rows.size(); ++index) {
        const auto row = rows[index].toObject();
        const bool trace = row.value("kind").toString() == "trace_snapshot";
        const auto review = row.value("review").toObject();
        const QMap<QString, QString> reviewStates{{"draft", "草稿 / 未审阅"}, {"submitted", "待审阅"}, {"rejected", "已退回"}, {"reviewed", "已审阅（非漏洞验证）"}};
        const QStringList cells{row.value("report_id").toString() + " · " + row.value("title").toString(),
          trace ? QStringLiteral("任务追溯快照") : QStringLiteral("历史 / 来源不完整"),
          trace ? row.value("pipeline_id").toString() : QStringLiteral("不推断归属"), row.value("run_id").toString(),
          row.value("owner").toString() + " · " + row.value("target").toString(),
          trace ? review.value("available").toBool() ? reviewStates.value(review.value("state").toString(), QStringLiteral("审阅状态不可用"))
            : QStringLiteral("审阅状态不可用") : row.value("status").toString(), row.value("created_at").toString()};
        for (int column = 0; column < cells.size(); ++column) {
          auto *item = new QTableWidgetItem(cells[column]);
          item->setToolTip(cells[column].toHtmlEscaped());
          if (column == 0) item->setData(Qt::UserRole, row);
          guard->m_table->setItem(index, column, item);
        }
        if (row.value("report_id").toString() == oldId) selectedRow = index;
      }
      if (selectedRow >= 0) guard->m_table->selectRow(selectedRow);
      else { guard->m_table->clearSelection(); guard->m_table->setCurrentCell(-1, -1); }
      guard->m_table->blockSignals(false);
      guard->m_fresh = valid; guard->m_total = valid ? total : 0;
      if (valid) UiUtil::EmptyHint::reset(guard->m_table);
      else UiUtil::EmptyHint::setState(guard->m_table, QStringLiteral("报告索引读取失败，请刷新重试"), true);
      guard->m_state->setText(valid ? QStringLiteral("当前账号可见 %1 份报告 · 本页 %2 份 · 第 %3 页；索引只读，不自动评分、生成或导出。%4")
        .arg(total).arg(rows.size()).arg(offset / 50 + 1).arg(rows.isEmpty() ? QStringLiteral(" 暂无匹配记录。") : QString())
        : QStringLiteral("报告索引读取失败或来源不匹配，打开操作已禁用。") + response.value("error").toObject().value("message").toString());
      guard->m_state->setStyleSheet(valid ? Theme::StatusInfoStyle : Theme::StatusErrorStyle);
      guard->updateButtons();
    });
}

void ResultsPage::updateButtons()
{
  const bool selected = m_table->selectionModel()->hasSelection();
  const auto *item = selected ? m_table->item(m_table->currentRow(), 0) : nullptr;
  const bool legacy = item && item->data(Qt::UserRole).toJsonObject().value("kind").toString() == "legacy";
  m_open->setText(legacy ? QStringLiteral("打开历史报告（兼容入口）") : QStringLiteral("打开所属任务报告"));
  m_open->setEnabled(m_fresh && !m_busy && item);
  m_refresh->setEnabled(!m_busy);
  m_previous->setEnabled(m_fresh && !m_busy && m_offset > 0);
  m_next->setEnabled(m_fresh && !m_busy && m_offset + 50 < m_total);
}

void ResultsPage::openSelected()
{
  if (!m_open->isEnabled()) return;
  const auto *item = m_table->item(m_table->currentRow(), 0);
  if (!item) return;
  const auto record = item->data(Qt::UserRole).toJsonObject();
  if (record.value("kind").toString() == "trace_snapshot")
    emit openTaskReportRequested(record.value("pipeline_id").toString(), record.value("report_id").toString());
  else { m_tabs->setCurrentIndex(1); m_legacy->showReport(record.value("report_id").toString()); }
}
