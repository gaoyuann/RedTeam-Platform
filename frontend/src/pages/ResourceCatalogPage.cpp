#include "ResourceCatalogPage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"

#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonDocument>
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
bool validCount(const QJsonValue &value)
{
  return value.isDouble() && std::isfinite(value.toDouble()) && value.toDouble() >= 0 &&
      value.toDouble() <= 2147483647 && std::floor(value.toDouble()) == value.toDouble();
}
}

ResourceCatalogPage::ResourceCatalogPage(ApiClient *api, Kind kind, QWidget *parent)
    : QWidget(parent), m_api(api), m_kind(kind)
{
  const bool tools = kind == Kind::Tools;
  setObjectName(tools ? "toolLibraryPage" : "vulnerabilityLibraryPage");
  setStyleSheet(Theme::PageStyle);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(16, 14, 16, 14);
  auto *title = new QLabel(tools ? QStringLiteral("工具库 · 注册目录") : QStringLiteral("漏洞知识 · 数据接入状态"), this);
  title->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(title);
  auto *hint = new QLabel(tools
      ? QStringLiteral("只读展示后端已注册的工具和运行方式。注册不代表镜像已部署、容器健康或工具执行成功；执行仍须进入授权任务。")
      : QStringLiteral("仅检索知识文件中的 Vulnerability 实体。不把 ATT&CK 技术、工具映射或分析候选冒充 CVE / 已验证漏洞；当前任务发现请到任务结果页核对。"), this);
  hint->setTextFormat(Qt::PlainText);
  hint->setWordWrap(true);
  layout->addWidget(hint);
  auto *filters = new QHBoxLayout;
  m_search = new QLineEdit(this);
  m_search->setMaxLength(120);
  m_search->setPlaceholderText(tools ? QStringLiteral("按工具编号或镜像名称过滤") : QStringLiteral("CVE / 漏洞名称 / 描述关键词（需数据接入）"));
  m_searchButton = new QPushButton(tools ? QStringLiteral("过滤") : QStringLiteral("检索"), this);
  auto *refreshButton = new QPushButton(QStringLiteral("刷新目录状态"), this);
  filters->addWidget(m_search, 1);
  filters->addWidget(m_searchButton);
  filters->addWidget(refreshButton);
  layout->addLayout(filters);
  m_state = new QLabel(QStringLiteral("打开此入口后读取真实目录状态"), this);
  m_state->setTextFormat(Qt::PlainText);
  m_state->setWordWrap(true);
  layout->addWidget(m_state);
  auto *splitter = new QSplitter(Qt::Vertical, this);
  m_table = new QTableWidget(0, 4, splitter);
  m_table->setHorizontalHeaderLabels(tools ? QStringList{"工具编号", "注册镜像", "运行方式", "能力边界"}
                                        : QStringList{"知识编号", "名称", "来源系统", "参考风险（非任务评级）"});
  m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_table->setAlternatingRowColors(true);
  m_table->setWordWrap(false);
  m_table->verticalHeader()->hide();
  m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  m_table->horizontalHeader()->setStretchLastSection(true);
  m_table->setColumnWidth(0, 240);
  m_table->setColumnWidth(1, 330);
  UiUtil::EmptyHint::attach(m_table, tools ? QStringLiteral("暂无匹配的注册工具") : QStringLiteral("尚未接入漏洞实体，或暂无检索结果"));
  m_detail = new QPlainTextEdit(splitter);
  m_detail->setReadOnly(true);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 1);
  layout->addWidget(splitter, 1);
  connect(m_table, &QTableWidget::itemSelectionChanged, this, &ResourceCatalogPage::showSelection);
  connect(m_searchButton, &QPushButton::clicked, this, &ResourceCatalogPage::search);
  connect(m_search, &QLineEdit::returnPressed, this, &ResourceCatalogPage::search);
  connect(m_search, &QLineEdit::textChanged, this, [this]() {
    if (m_kind == Kind::Tools) search();
    else {
      ++m_requestRevision;
      render({});
      if (m_supported) {
        m_state->setText(QStringLiteral("请输入关键词并检索；尚未读取此关键词的结果。"));
        UiUtil::EmptyHint::setState(m_table, QStringLiteral("检索条件已修改，请确认关键词后检索"));
      }
    }
  });
  connect(refreshButton, &QPushButton::clicked, this, &ResourceCatalogPage::refresh);
  m_searchButton->setEnabled(tools);
  m_search->setEnabled(tools);
  showSelection();
}

void ResourceCatalogPage::showEvent(QShowEvent *event)
{
  QWidget::showEvent(event);
  refresh();
}

void ResourceCatalogPage::refresh()
{
  const int revision = ++m_requestRevision;
  m_supported = false;
  m_tools = {};
  render({});
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("正在读取资源目录及接入状态…"));
  m_searchButton->setEnabled(false);
  m_search->setEnabled(false);
  m_state->setStyleSheet(Theme::StatusInfoStyle);
  m_state->setText(QStringLiteral("正在读取真实资源目录…不执行工具或生成样本。"));
  QPointer<ResourceCatalogPage> guard(this);
  m_api->get(m_kind == Kind::Tools ? "/api/tools/list" : "/api/kg/stats", 5000,
      [this, guard, revision](const QJsonObject &response) {
    if (!guard || revision != m_requestRevision) return;
    if (response["status"].toString() != "ok") {
      fail(response["error"].toObject()["message"].toString(QStringLiteral("未返回有效目录")));
      return;
    }
    if (m_kind == Kind::Tools) {
      const auto rows = response["data"].toArray();
      const QJsonValue total = response["meta"].toObject().value("total");
      if (!response["data"].isArray() || !validCount(total) || total.toInt() != rows.size() || rows.size() > 500) {
        fail(QStringLiteral("工具目录数量无效或超过展示上限 500"));
        return;
      }
      QSet<QString> identifiers;
      for (const auto value : rows) {
        const auto row = value.toObject();
        const QString identifier = row["toolId"].toString();
        if (!value.isObject() || identifier.isEmpty() || identifiers.contains(identifier) ||
            !row["virtual"].isBool() || !(row["image"].isString() || row["image"].isNull()) ||
            (!row["virtual"].toBool() && row["image"].toString().isEmpty())) {
          fail(QStringLiteral("工具目录标识或运行方式无效"));
          return;
        }
        identifiers.insert(identifier);
      }
      m_tools = rows;
      m_supported = true;
      m_searchButton->setEnabled(true);
      m_search->setEnabled(true);
      search();
    } else {
      const auto data = response["data"].toObject();
      const auto counts = data["node_type_counts"].toObject();
      if (!data["node_type_counts"].isObject() || !validCount(data["node_count"]) ||
          (counts.contains("Vulnerability") && !validCount(counts["Vulnerability"]))) {
        fail(QStringLiteral("知识实体统计无效，无法判断接入状态"));
        return;
      }
      m_supported = counts["Vulnerability"].toInt() > 0;
      m_searchButton->setEnabled(m_supported);
      m_search->setEnabled(m_supported);
      m_state->setText(m_supported
          ? QStringLiteral("知识文件声明 %1 个漏洞实体。请输入关键词检索，最多展示 50 条；这些是参考知识，不是任务漏洞结论。").arg(counts["Vulnerability"].toInt())
          : QStringLiteral("未接入：当前知识文件未包含 Vulnerability / CVE 实体。该入口仅保留接入状态，不展示模拟漏洞数据；已有攻击技术和工具关系请查看“知识图谱”。"));
      UiUtil::EmptyHint::setState(m_table, m_supported ? QStringLiteral("请输入关键词检索漏洞参考知识")
          : QStringLiteral("漏洞知识未接入，不展示模拟数据"));
    }
  });
}

void ResourceCatalogPage::search()
{
  if (!m_supported) return;
  const QString queryText = m_search->text().trimmed();
  if (m_kind == Kind::Tools) {
    QJsonArray rows;
    for (const auto value : m_tools) {
      const auto row = value.toObject();
      if (queryText.isEmpty() || row["toolId"].toString().contains(queryText, Qt::CaseInsensitive) ||
          row["image"].toString().contains(queryText, Qt::CaseInsensitive)) rows.append(value);
    }
    render(rows);
    UiUtil::EmptyHint::reset(m_table);
    m_state->setText(QStringLiteral("后端注册 %1 个工具，当前匹配 %2 个。虚拟工具不使用容器镜像；本页不检查部署状态，也不提供执行按钮。").arg(m_tools.size()).arg(rows.size()));
    return;
  }
  const int revision = ++m_requestRevision;
  render({});
  if (queryText.isEmpty()) {
    m_state->setText(QStringLiteral("请先输入关键词；空关键词不会发送检索请求。"));
    UiUtil::EmptyHint::setState(m_table, QStringLiteral("请输入关键词后检索漏洞参考知识"));
    return;
  }
  QUrlQuery query;
  query.addQueryItem("q", QString::fromLatin1(QUrl::toPercentEncoding(queryText)));
  query.addQueryItem("type", "Vulnerability");
  query.addQueryItem("limit", "50");
  m_state->setText(QStringLiteral("正在检索漏洞参考知识…"));
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("正在检索漏洞参考知识…"));
  QPointer<ResourceCatalogPage> guard(this);
  m_api->get("/api/kg/search?" + query.toString(QUrl::FullyEncoded), 5000,
      [this, guard, revision](const QJsonObject &response) {
    if (!guard || revision != m_requestRevision) return;
    if (response["status"].toString() != "ok") {
      fail(response["error"].toObject()["message"].toString(QStringLiteral("检索失败")));
      return;
    }
    const auto data = response["data"].toObject();
    const auto rows = data["results"].toArray();
    if (!data["results"].isArray() || !validCount(data["total"]) || rows.size() != qMin(50, data["total"].toInt())) {
      fail(QStringLiteral("检索结果数量不匹配"));
      return;
    }
    QSet<QString> identifiers;
    for (const auto value : rows) {
      const auto row = value.toObject();
      const QString identifier = row["id"].toString();
      if (identifier.isEmpty() || identifiers.contains(identifier) || row["type"].toString() != "Vulnerability" ||
          !row["name"].isString() || !row["description"].isString()) {
        fail(QStringLiteral("检索返回非漏洞实体或重复标识"));
        return;
      }
      identifiers.insert(identifier);
    }
    render(rows);
    UiUtil::EmptyHint::reset(m_table);
    m_state->setText(QStringLiteral("匹配 %1 条，展示前 %2 条。描述由现有接口截取最多 150 字符；参考风险不等于当前任务评级。").arg(data["total"].toInt()).arg(rows.size()));
  });
}

void ResourceCatalogPage::render(const QJsonArray &records)
{
  m_records = records;
  m_table->clearSelection();
  m_table->setCurrentCell(-1, -1);
  m_table->setRowCount(records.size());
  for (int index = 0; index < records.size(); ++index) {
    const auto row = records.at(index).toObject();
    const QStringList cells = m_kind == Kind::Tools
        ? QStringList{row["toolId"].toString(), row["image"].toString(QStringLiteral("不使用镜像")),
            row["virtual"].toBool() ? QStringLiteral("虚拟工具") : QStringLiteral("容器工具"), QStringLiteral("已注册 · 未检查部署")}
        : QStringList{row["id"].toString(), row["name"].toString(), row["source_system"].toString(), row["risk_level"].toString()};
    for (int column = 0; column < cells.size(); ++column) {
      auto *item = new QTableWidgetItem(cells.at(column));
      item->setToolTip(cells.at(column).toHtmlEscaped());
      m_table->setItem(index, column, item);
    }
  }
  showSelection();
}

void ResourceCatalogPage::showSelection()
{
  const int index = m_table->currentRow();
  m_detail->setPlainText(index >= 0 && index < m_records.size()
      ? QStringLiteral("来源：%1\n只读参考；不绑定任务、不执行工具、不确认漏洞。\n\n%2")
          .arg(m_kind == Kind::Tools ? QStringLiteral("后端工具注册表 /api/tools/list") : QStringLiteral("知识文件 /api/kg/search，类型 Vulnerability"),
               QString::fromUtf8(QJsonDocument(m_records.at(index).toObject()).toJson(QJsonDocument::Indented)))
      : QStringLiteral("选择条目查看接口返回的原始目录字段；此页没有执行或编辑操作。"));
}

void ResourceCatalogPage::fail(const QString &message)
{
  m_tools = {};
  m_supported = false;
  render({});
  UiUtil::EmptyHint::setState(m_table, QStringLiteral("资源目录读取失败，请刷新重试"), true);
  m_searchButton->setEnabled(false);
  m_search->setEnabled(false);
  m_state->setStyleSheet(Theme::StatusErrorStyle);
  m_state->setText(QStringLiteral("读取失败：%1。可刷新目录状态重试，不使用旧结果。").arg(message));
}
