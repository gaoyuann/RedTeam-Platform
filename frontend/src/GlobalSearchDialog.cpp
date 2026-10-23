#include "GlobalSearchDialog.h"
#include "ApiClient.h"
#include "UiUtil.h"
#include <QLineEdit>
#include <QListWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QPointer>
#include <QUrlQuery>

GlobalSearchDialog::GlobalSearchDialog(ApiClient *api, const QStringList &modules,
        const QString &role, const QString &username, QWidget *parent)
    : QDialog(parent), m_api(api), m_modules(modules), m_role(role), m_username(username)
{
    setWindowTitle(QStringLiteral("全局搜索"));
    resize(720, 520);
    auto *layout = new QVBoxLayout(this);
    m_input = new QLineEdit(this);
    m_input->setObjectName("searchQuery");
    m_input->setMaxLength(120);
    m_input->setClearButtonEnabled(true);
    m_input->setPlaceholderText(QStringLiteral("搜索任务ID、模块、名称、目标或报告编号"));
    layout->addWidget(m_input);
    auto *hint = new QLabel(QStringLiteral("搜索范围：模块入口、当前账号可见任务和报告。双击或选中后按回车打开。"), this);
    hint->setWordWrap(true);
    layout->addWidget(hint);
    m_results = new QListWidget(this);
    m_results->setObjectName("searchResults");
    layout->addWidget(m_results, 1);
    m_state = new QLabel(this);
    m_state->setObjectName("searchState");
    m_state->setTextFormat(Qt::PlainText);
    m_state->setWordWrap(true);
    layout->addWidget(m_state);
    m_more = new QPushButton(QStringLiteral("加载更多 / 重试失败项"), this);
    m_more->setAutoDefault(false);
    layout->addWidget(m_more);
    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    m_timer->setInterval(300);
    connect(m_input, &QLineEdit::textChanged, this, [this]() {
        ++m_revision; // Invalidate responses immediately, before the debounce expires.
        m_results->clear();
        m_more->setEnabled(false);
        m_state->setText(QStringLiteral("等待输入…"));
        m_timer->start();
    });
    connect(m_timer, &QTimer::timeout, this, &GlobalSearchDialog::restart);
    connect(m_input, &QLineEdit::returnPressed, this, [this]() { m_timer->stop(); restart(); });
    connect(m_more, &QPushButton::clicked, this, &GlobalSearchDialog::fetch);
    connect(m_results, &QListWidget::itemActivated, this, [this](QListWidgetItem *item) {
        const auto data = item->data(Qt::UserRole).toJsonObject();
        emit resultActivated(data["page"].toInt(), data["pipeline_id"].toString(), data["report_id"].toString());
        accept();
    });
    connect(this, &QDialog::finished, this, [this]() { ++m_revision; m_timer->stop(); });
}

void GlobalSearchDialog::search(const QString &text)
{
    m_input->setText(text);
    m_timer->stop();
    restart();
    m_input->setFocus();
    m_input->selectAll();
}

void GlobalSearchDialog::restart()
{
    ++m_revision;
    m_pending = 0;
    m_offsets[0] = m_offsets[1] = 0;
    m_seen[0].clear();
    m_seen[1].clear();
    m_hasMore[0] = m_hasMore[1] = true;
    m_errors.clear();
    m_results->clear();
    m_query = m_input->text().trimmed();
    for (int i = 0; i < m_modules.size(); ++i) {
        if (i == 6 && m_role != "admin") continue;
        if (!m_query.isEmpty() && !m_modules[i].contains(m_query, Qt::CaseInsensitive)) continue;
        auto *item = new QListWidgetItem(QStringLiteral("模块 · ") + m_modules[i], m_results);
        item->setData(Qt::UserRole, QJsonObject{{"page", i}});
    }
    if (m_query.isEmpty()) {
        m_more->setEnabled(false);
        m_state->setText(QStringLiteral("输入关键词查找任务和报告，或直接选择模块。"));
        return;
    }
    fetch();
}

void GlobalSearchDialog::fetch()
{
    if (m_pending || m_query.isEmpty()) return;
    m_errors.clear();
    m_pending = int(m_hasMore[0]) + int(m_hasMore[1]);
    updateState();
    const int revision = m_revision;
    for (int type = 0; type < 2; ++type) {
        if (!m_hasMore[type]) continue;
        QUrlQuery query;
        query.addQueryItem("limit", "50");
        query.addQueryItem("offset", QString::number(m_offsets[type]));
        query.addQueryItem(type == 0 ? "state" : "kind", "all");
        query.addQueryItem("search", QString::fromLatin1(QUrl::toPercentEncoding(m_query)));
        QPointer<GlobalSearchDialog> guard(this);
        m_api->get((type == 0 ? QStringLiteral("/api/pipelines/analysis-index?") : QStringLiteral("/api/reports/index?"))
            + query.toString(QUrl::FullyEncoded), 5000, [guard, revision, type](const QJsonObject &response) {
            if (!guard || guard->m_revision != revision) return;
            auto *self = guard.data();
            const auto data = response["data"].toObject();
            const auto rows = data["records"].toArray();
            const int total = data["total"].toInt(-1);
            bool valid = response["status"].toString() == "ok" && data["schema_version"].toInt() == 1
                && data["records"].isArray() && rows.size() <= 50 && total >= 0
                && (rows.isEmpty() ? total <= self->m_offsets[type] : total >= self->m_offsets[type] + rows.size())
                && data["offset"].toInt(-1) == self->m_offsets[type] && data["limit"].toInt() == 50
                && data["search"].toString() == self->m_query
                && data[type == 0 ? "state" : "kind"].toString() == "all";
            for (const auto &value : rows) {
                const auto row = value.toObject();
                valid = valid && !row[type == 0 ? "pipeline_id" : "report_id"].toString().isEmpty()
                    && row[type == 0 ? "task_name" : "title"].isString()
                    && (self->m_role == "admin" || row["owner"].toString() == self->m_username);
                if (type == 1) {
                    const auto kind = row["kind"].toString();
                    valid = valid && (kind == "legacy" || (kind == "trace_snapshot" && !row["pipeline_id"].toString().isEmpty()));
                }
            }
            if (valid) {
                for (const auto &value : rows) {
                    auto row = value.toObject();
                    const QString id = row[type == 0 ? "pipeline_id" : "report_id"].toString();
                    if (self->m_seen[type].contains(id)) continue;
                    self->m_seen[type].insert(id);
                    const QString title = row[type == 0 ? "task_name" : "title"].toString();
                    auto *item = new QListWidgetItem(QStringLiteral("%1 · %2\n%3 · %4")
                        .arg(type == 0 ? QStringLiteral("任务") : QStringLiteral("报告"), title, type == 0 ? UiUtil::taskIdentifier(row) : id, row["target"].toString()), self->m_results);
                    // Legacy reports have no reliable task association.
                    if (type == 1 && row["kind"].toString() != "trace_snapshot") {
                        row.remove("pipeline_id");
                        item->setText(item->text() + QStringLiteral("（打开报告列表）"));
                    }
                    // Navigation uses only fields belonging to this result type.
                    item->setData(Qt::UserRole, QJsonObject{{"page", type == 0 ? 1 : 5},
                        {"pipeline_id", row["pipeline_id"].toString()},
                        {"report_id", type == 1 ? id : QString()}});
                }
                self->m_offsets[type] += rows.size();
                self->m_hasMore[type] = self->m_offsets[type] < total;
            } else {
                self->m_errors.append(type == 0 ? QStringLiteral("任务读取失败") : QStringLiteral("报告读取失败"));
            }
            --self->m_pending;
            self->updateState();
        });
    }
}

void GlobalSearchDialog::updateState()
{
    m_more->setEnabled(!m_pending && (m_hasMore[0] || m_hasMore[1]));
    QString text = m_pending ? QStringLiteral("正在搜索…")
        : m_results->count() ? QStringLiteral("已显示 %1 条结果").arg(m_results->count()) : QStringLiteral("未找到匹配结果");
    if (!m_errors.isEmpty()) text += QStringLiteral("；%1，请重试（结果不完整）").arg(m_errors.join(QStringLiteral("、")));
    m_state->setText(text);
}
