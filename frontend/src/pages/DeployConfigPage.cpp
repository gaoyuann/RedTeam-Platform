#include "DeployConfigPage.h"
#include "../ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QScrollArea>
#include <QFrame>
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/WorkbenchTabs.h"
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QPointer>
#include <QUrl>
#include <QSet>
#include <QTabBar>

namespace {
QString compactStatusStyle(const char *style)
{
  return QString::fromLatin1(style) + QStringLiteral(" font-size:14px; padding:4px 8px; border-radius:5px;");
}

void styleResourceTable(QTableWidget *table)
{
  table->setShowGrid(false);
  table->verticalHeader()->hide();
  table->verticalHeader()->setDefaultSectionSize(38);
  table->horizontalHeader()->setFixedHeight(36);
  table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  table->horizontalHeader()->setMinimumSectionSize(72);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setWordWrap(false);
  table->setTextElideMode(Qt::ElideRight);
  table->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
  table->setMinimumHeight(150);
  table->setStyleSheet(QStringLiteral(
    "QTableWidget { background:white; alternate-background-color:#f8fafc; border:1px solid #e2e8f0;"
    " border-radius:6px; color:#26364b; selection-background-color:#eaf2ff; selection-color:#1d4ed8; }"
    "QTableWidget::item { padding:0 10px; border-bottom:1px solid #edf1f6; }"
    "QTableWidget::item:hover { background:#f1f6ff; }"
    "QHeaderView::section { background:#f5f7fb; color:#526174; font-size:15px; font-weight:600;"
    " padding:0 10px; border:none; border-bottom:1px solid #e2e8f0; }"));
}

QTableWidgetItem *resourceItem(const QString &text)
{
  auto *item = new QTableWidgetItem(text);
  item->setToolTip(text.toHtmlEscaped());
  return item;
}

// Compare the tag separator after the last slash so registry ports stay intact.
QPair<QString, QString> imageParts(const QString &image)
{
  const int colon = image.lastIndexOf(':');
  if (colon > image.lastIndexOf('/')) return {image.left(colon), image.mid(colon + 1)};
  return {image, QStringLiteral("latest")};
}
}

DeployConfigPage::DeployConfigPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
  onRefresh();
}

void DeployConfigPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *scrollArea = new QScrollArea(this);
  m_formScroll = scrollArea;
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);

  // ── 1. Platform Status ─────────────────────────────────────────────
  auto *platLabel = new QLabel("平台状态"); platLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(platLabel);

  auto *platH = new QHBoxLayout;
  m_checkBtn = new QPushButton("检测后端连接");
  m_engineLabel = new QLabel("未检测");
  m_engineLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
  platH->addWidget(m_checkBtn);
  platH->addWidget(m_engineLabel);
  platH->addStretch();
  layout->addLayout(platH);
  connect(m_checkBtn, &QPushButton::clicked, this, &DeployConfigPage::onCheckBackend);

  // 平台状态数据行：三个指标块（启动/运行/数据库）+ 表行数芯片网格。
  // 原先三个 QLabel 挤一行，表行数 wordWrap 成大块文字，很乱
  auto *statCard = new QFrame;
  statCard->setProperty("softCard", true);
  auto *statL = new QHBoxLayout(statCard);
  statL->setContentsMargins(14, 8, 14, 8);
  statL->setSpacing(36);
  auto makeStat = [statL](const QString &caption) {
    auto *box = new QVBoxLayout;
    box->setSpacing(1);
    auto *cap = new QLabel(caption);
    cap->setStyleSheet("font-size:13px; color:#7f8c8d;");
    auto *val = new QLabel("-");
    val->setStyleSheet("font-size:16px; font-weight:600; color:#172033;");
    box->addWidget(cap);
    box->addWidget(val);
    statL->addLayout(box);
    return val;
  };
  m_versionLabel = makeStat("启动时间");
  m_uptimeLabel = makeStat("运行时长");
  m_dbSizeLabel = makeStat("数据库大小");
  statL->addStretch();
  layout->addWidget(statCard);

  m_dbTablesCaption = new QLabel("数据库表行数 · 点击「检测后端连接」获取");
  m_dbTablesCaption->setStyleSheet("font-size:14px; color:#7f8c8d;");
  layout->addWidget(m_dbTablesCaption);
  auto *tablesFlow = new QWidget;
  m_dbTablesGrid = new QGridLayout(tablesFlow);
  m_dbTablesGrid->setContentsMargins(0, 0, 0, 0);
  m_dbTablesGrid->setHorizontalSpacing(8);
  m_dbTablesGrid->setVerticalSpacing(6);
  layout->addWidget(tablesFlow);

  // ── 2. LLM Config ─────────────────────────────────────────────────
  auto *llmLabel = new QLabel("大语言模型配置"); llmLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(llmLabel);

  auto *llmH1 = new QHBoxLayout;
  llmH1->addWidget(new QLabel("接口密钥："));
  m_llmApiKey = new QLineEdit;
  m_llmApiKey->setEchoMode(QLineEdit::Password);
  m_llmApiKey->setPlaceholderText("sk-...");
  llmH1->addWidget(m_llmApiKey, 1);
  layout->addLayout(llmH1);

  auto *llmH2 = new QHBoxLayout;
  llmH2->addWidget(new QLabel("服务地址："));
  m_llmBaseUrl = new QLineEdit;
  m_llmBaseUrl->setPlaceholderText("https://api.deepseek.com/v1");
  llmH2->addWidget(m_llmBaseUrl, 1);
  llmH2->addWidget(new QLabel("模型:"));
  m_llmModel = new QLineEdit;
  m_llmModel->setPlaceholderText("deepseek-chat");
  m_llmModel->setMaximumWidth(200);
  llmH2->addWidget(m_llmModel);
  layout->addLayout(llmH2);

  auto *llmBtnH = new QHBoxLayout;
  m_llmSaveBtn = new QPushButton("保存模型配置");
  m_llmSaveBtn->setProperty("primary", true);
  m_llmTestBtn = new QPushButton("保存并测试连接");
  m_llmTestBtn->setToolTip(QStringLiteral("先保存当前模型配置，再使用该配置检查连接。"));
  m_llmStatusLabel = new QLabel;
  llmBtnH->addWidget(m_llmSaveBtn);
  llmBtnH->addWidget(m_llmTestBtn);
  llmBtnH->addWidget(m_llmStatusLabel);
  llmBtnH->addStretch();
  layout->addLayout(llmBtnH);
  connect(m_llmSaveBtn, &QPushButton::clicked, this, &DeployConfigPage::onSaveLlmConfig);
  connect(m_llmTestBtn, &QPushButton::clicked, this, &DeployConfigPage::onTestLlmConnection);

  // ── 3. Sandbox Config ─────────────────────────────────────────────
  auto *sbLabel = new QLabel("沙箱运行环境");
  sbLabel->setStyleSheet("font-size:18px; font-weight:600; color:#172033;");
  layout->addWidget(sbLabel);

  auto *sbH = new QHBoxLayout;
  sbH->setSpacing(12);
  m_sandboxEnabled = new QCheckBox("启用沙箱");
  sbH->addWidget(m_sandboxEnabled);
  sbH->addSpacing(12);
  sbH->addWidget(new QLabel("容器引擎:"));
  m_sandboxType = new QComboBox;
  m_sandboxType->addItem("自动", "auto");
  m_sandboxType->addItem("Podman", "podman");
  m_sandboxType->addItem("Docker", "docker");
  m_sandboxType->addItem("无", "none");
  m_sandboxType->setMinimumWidth(140);
  sbH->addWidget(m_sandboxType);
  sbH->addStretch();
  m_sandboxSaveBtn = new QPushButton("保存沙箱配置");
  m_sandboxSaveBtn->setProperty("primary", true);
  sbH->addWidget(m_sandboxSaveBtn);
  layout->addLayout(sbH);
  m_sandboxStatusLabel = new QLabel;
  m_sandboxStatusLabel->setWordWrap(true);
  m_sandboxStatusLabel->setTextFormat(Qt::PlainText);
  m_sandboxStatusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
  layout->addWidget(m_sandboxStatusLabel);
  connect(m_sandboxSaveBtn, &QPushButton::clicked, this, &DeployConfigPage::onSaveSandboxConfig);

  // ── 4. Container Images (existing) ────────────────────────────────
  auto *imgLabel = new QLabel("容器镜像"); imgLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(imgLabel);
  m_imageTable = new QTableWidget(0, 6);
  m_imageTable->setObjectName("deploymentImages");
  UiUtil::EmptyHint::attach(m_imageTable, QStringLiteral("暂无镜像 · 点击刷新获取"));
  m_imageTable->setHorizontalHeaderLabels({"镜像名称", "标签", "本地状态", "大小", "关联工具", "适用能力（按需）"});
  m_imageTable->setAlternatingRowColors(true);
  m_imageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_imageTable->setSortingEnabled(true);
  m_imageTable->setContextMenuPolicy(Qt::CustomContextMenu);
  styleResourceTable(m_imageTable);
  m_imageTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  m_imageTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_imageTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
  m_imageTable->setColumnWidth(1, 100);
  m_imageTable->setColumnWidth(2, 110);
  m_imageTable->setColumnWidth(3, 100);
  m_imageTable->setColumnWidth(4, 100);
  m_imageTable->horizontalHeaderItem(5)->setToolTip(QStringLiteral("按实际测试内容选择镜像；清单中的镜像无需全部安装。"));
  m_imageTable->horizontalHeaderItem(3)->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
  m_imageTable->sortItems(0, Qt::AscendingOrder);
  layout->addWidget(m_imageTable);

  // ── 5. Tool List (existing) ───────────────────────────────────────
  auto *toolLabel = new QLabel("工具列表"); toolLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(toolLabel);
  m_toolTable = new QTableWidget(0, 5);
  m_toolTable->setObjectName("deploymentTools");
  UiUtil::EmptyHint::attach(m_toolTable, QStringLiteral("暂无工具"));
  m_toolTable->setHorizontalHeaderLabels({"工具编号", "用途", "运行方式", "依赖镜像", "镜像状态"});
  m_toolTable->setAlternatingRowColors(true);
  m_toolTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_toolTable->setSortingEnabled(true);
  m_toolTable->setContextMenuPolicy(Qt::CustomContextMenu);
  styleResourceTable(m_toolTable);
  m_toolTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  m_toolTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_toolTable->setColumnWidth(0, 180);
  m_toolTable->setColumnWidth(2, 120);
  m_toolTable->setColumnWidth(3, 165);
  m_toolTable->setColumnWidth(4, 110);
  m_toolTable->sortItems(0, Qt::AscendingOrder);
  layout->addWidget(m_toolTable);

  // ── 6. System Config (existing) ───────────────────────────────────
  auto *cfgLabel = new QLabel("系统配置"); cfgLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(cfgLabel);
  m_configTable = new QTableWidget(0, 3);
  UiUtil::EmptyHint::attach(m_configTable, QStringLiteral("暂无配置项"));
  m_configTable->setHorizontalHeaderLabels({"配置项", "值", "类别"});
  m_configTable->setAlternatingRowColors(true);
  m_configTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_configTable->setSortingEnabled(true);
  m_configTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_configTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_configTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_configTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  layout->addWidget(m_configTable);

  // ── 7. Test Labs (测试靶场) ────────────────────────────────────────
  auto *labHeader = new QWidget;
  auto *labHeaderH = new QHBoxLayout(labHeader);
  labHeaderH->setContentsMargins(0, 0, 0, 0);
  auto *labLabel = new QLabel("测试靶场"); labLabel->setStyleSheet(Theme::SectionStyle);
  m_labRefreshBtn = new QPushButton("刷新列表");
  m_labStatusLabel = new QLabel;
  labHeaderH->addWidget(labLabel);
  labHeaderH->addStretch();
  labHeaderH->addWidget(m_labRefreshBtn);
  labHeaderH->addWidget(m_labStatusLabel);
  layout->addWidget(labHeader);

  m_labTable = new QTableWidget(0, 3);
  UiUtil::EmptyHint::attach(m_labTable, QStringLiteral("暂无靶场环境"));
  m_labTable->setHorizontalHeaderLabels({"靶场名称", "状态", "操作"});
  m_labTable->verticalHeader()->setDefaultSectionSize(44);
  m_labTable->setAlternatingRowColors(true);
  m_labTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_labTable->setSortingEnabled(true);
  m_labTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_labTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_labTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  // 操作列固定宽：按钮是 setCellWidget，ResizeToContents 测不到会被压瘪
  m_labTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);
  m_labTable->setColumnWidth(2, 170);
  layout->addWidget(m_labTable);


  connect(m_labRefreshBtn, &QPushButton::clicked, this, &DeployConfigPage::loadLabList);

  // ── Right-click menus ────────────────────────────────────────────────
  connect(m_imageTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_imageTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_imageTable->viewport()->mapToGlobal(pos));
  });
  connect(m_toolTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_toolTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_toolTable->viewport()->mapToGlobal(pos));
  });
  connect(m_configTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_configTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_configTable->viewport()->mapToGlobal(pos));
  });
  connect(m_labTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_labTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_labTable->viewport()->mapToGlobal(pos));
  });

  // ── Refresh ───────────────────────────────────────────────────────
  m_refreshBtn = new QPushButton("刷新配置状态");
  m_refreshBtn->setFixedWidth(132);
  layout->addWidget(m_refreshBtn, 0, Qt::AlignLeft);
  connect(m_refreshBtn, &QPushButton::clicked, this, &DeployConfigPage::onRefresh);

  // Reuse each existing form as a section, without duplicating API or submit logic.
  const QMap<QWidget *, QString> anchors{{platLabel, "status"}, {llmLabel, "llm"},
    {sbLabel, "runtime"}, {imgLabel, "images"}, {toolLabel, "tools"},
    {cfgLabel, "config"}, {labHeader, "labs"}, {m_refreshBtn, "refresh"}};
  const int originalCount = layout->count();
  QList<QLayoutItem *> originalItems;
  for (int i = 0; i < originalCount; ++i) originalItems << layout->takeAt(0);
  QString sectionId;
  QVBoxLayout *sectionLayout = nullptr;
  QMap<QString, QVBoxLayout *> sectionLayouts;
  for (auto *item : originalItems) {
    if (anchors.contains(item->widget())) {
      sectionId = anchors.value(item->widget());
      auto *section = new QWidget(container);
      section->setObjectName(QStringLiteral("deploySection.%1").arg(sectionId));
      sectionLayout = new QVBoxLayout;
      sectionLayout->setContentsMargins(0, 0, 0, 0);
      sectionLayouts.insert(sectionId, sectionLayout);
      m_sections.insert(sectionId, section);
      layout->addWidget(section);
    }
    if (!sectionLayout) { layout->addItem(item); continue; }
    if (auto *nested = item->layout()) {
      nested->setParent(nullptr);
      sectionLayout->addLayout(nested);
    } else {
      sectionLayout->addItem(item);
    }
  }
  // setLayout reparents all existing controls, including those in nested forms.
  for (auto it = sectionLayouts.cbegin(); it != sectionLayouts.cend(); ++it)
    m_sections.value(it.key())->setLayout(it.value());

  // Runtime settings occupy their natural height, independently of the forms
  // scroll area. The image inventory receives all remaining workspace height.
  auto *runtimeCard = m_sections.value("runtime");
  layout->removeWidget(runtimeCard);
  runtimeCard->setParent(this);
  runtimeCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  runtimeCard->setAttribute(Qt::WA_StyledBackground, true);
  runtimeCard->setStyleSheet("QWidget[objectName=\"deploySection.runtime\"] { background:white; border:1px solid #e2e8f0; border-radius:8px; }");
  runtimeCard->layout()->setContentsMargins(16, 8, 16, 8);
  runtimeCard->layout()->setSpacing(6);
  runtimeCard->hide();

  // Resource pages share a full-height table; forms keep their existing scroll area.
  m_resourceTabs = new WorkbenchTabs(this);
  m_resourceTabs->setObjectName("deploymentResourceTabs");
  for (const auto &id : {QStringLiteral("tools"), QStringLiteral("images")}) {
    auto *section = m_sections.value(id);
    layout->removeWidget(section);
    section->layout()->itemAt(0)->widget()->hide();
    qobject_cast<QVBoxLayout *>(section->layout())->setStretch(1, 1);
    m_resourceTabs->addTab(section, id == "tools" ? QStringLiteral("工具列表") : QStringLiteral("容器镜像"));
  }
  auto *refresh = m_sections.value("refresh");
  layout->removeWidget(refresh);
  refresh->hide();
  m_resourceToolbar = new QWidget(this);
  auto *toolbar = new QHBoxLayout(m_resourceToolbar);
  toolbar->setContentsMargins(0, 0, 0, 0);
  toolbar->setSpacing(10);
  m_resourceHeading = new QLabel(QStringLiteral("容器镜像"), m_resourceToolbar);
  m_resourceHeading->setStyleSheet("font-size:17px; font-weight:600; color:#172033;");
  m_resourceHeading->hide();
  m_resourceSearch = new QLineEdit(m_resourceToolbar);
  m_resourceSearch->setClearButtonEnabled(true);
  m_resourceSearch->setMaxLength(120);
  m_resourceSearch->setPlaceholderText(QStringLiteral("搜索工具、用途或镜像"));
  m_resourceType = new QComboBox(m_resourceToolbar);
  m_resourceType->addItem(QStringLiteral("全部运行方式"), "all");
  m_resourceType->addItem(QStringLiteral("容器工具"), "container");
  m_resourceType->addItem(QStringLiteral("内置处理器"), "builtin");
  m_resourceType->addItem(QStringLiteral("虚拟工具"), "virtual");
  m_resourceSummary = new QLabel(m_resourceToolbar);
  m_resourceSummary->setStyleSheet("color:#526174; font-size:15px;");
  toolbar->addWidget(m_resourceHeading);
  toolbar->addWidget(m_resourceSummary);
  toolbar->addStretch();
  toolbar->addWidget(m_resourceSearch, 1);
  toolbar->addWidget(m_resourceType);
  toolbar->addWidget(m_refreshBtn);
  m_refreshBtn->setText(QStringLiteral("刷新"));
  m_refreshBtn->setFixedWidth(76);
  connect(m_resourceSearch, &QLineEdit::textChanged, this, &DeployConfigPage::filterResources);
  connect(m_resourceType, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &DeployConfigPage::filterResources);
  connect(m_resourceTabs, &QTabWidget::currentChanged, this, &DeployConfigPage::filterResources);
  layout->addStretch();
  container->setMaximumWidth(1120);
  scrollArea->setAlignment(Qt::AlignTop | Qt::AlignLeft);
  scrollArea->setStyleSheet("QScrollArea { background:#f3f5f9; border:0; }");
  container->setObjectName("deploymentFormCard");
  container->setStyleSheet("QWidget#deploymentFormCard { background:white; }");
  container->setAttribute(Qt::WA_StyledBackground, true);
  scrollArea->setWidget(container);
  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->setContentsMargins(24, 0, 24, 20);
  outerLayout->setSpacing(12);
  outerLayout->addWidget(runtimeCard);
  outerLayout->addWidget(m_resourceToolbar);
  outerLayout->addWidget(scrollArea);
  outerLayout->addWidget(m_resourceTabs, 1);
  m_resourceTabs->hide();
  m_resourceSearch->hide();
  m_resourceType->hide();
  m_resourceSummary->hide();
}

// ── Slot: Refresh all ────────────────────────────────────────────────
void DeployConfigPage::onRefresh() {
  onCheckBackend();       // merged: also loads platform status
  loadLlmConfig();
  loadSandboxConfig();    // merged: also loads container status
  loadToolList();
  loadConfig();
  loadLabList();
}

// 表单中的配置与靶场表格随内容收紧，行多时在 cap 上限内滚动。
void DeployConfigPage::fitTableHeight(QTableWidget *t, int cap) {
  const int h = t->horizontalHeader()->height() +
                qMax(t->rowCount(), 1) * t->verticalHeader()->defaultSectionSize() + 10;
  t->setFixedHeight(qBound(110, h, cap));
}

// ── Slot: Check backend (merged with loadPlatformStatus) ─────────────
void DeployConfigPage::onCheckBackend() {
  const QPointer<DeployConfigPage> guard(this);
  m_checkBtn->setEnabled(false);
  m_api->get("/api/health", 3000, [this, guard](const QJsonObject &res) {
    if (!guard) return;
    m_checkBtn->setEnabled(true);
    if (res["status"].toString() == "ok") {
      m_engineLabel->setText("已连接");
      m_engineLabel->setStyleSheet(Theme::StatusSuccessStyle);

      // Also update platform status (was separate loadPlatformStatus)
      QString ts = res["timestamp"].toString();
      double uptime = res["uptime"].toDouble();
      QString uptimeStr = uptime > 3600 ? QString("%1h").arg(int(uptime / 3600))
                       : uptime > 60   ? QString("%1m").arg(int(uptime / 60))
                       :                  QString("%1s").arg(int(uptime));
      m_versionLabel->setText(ts.left(19).replace('T', ' '));
      m_uptimeLabel->setText(uptimeStr);
    } else {
      m_engineLabel->setText("未连接");
      m_engineLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });

  // DB stats (separate endpoint, keep as-is)
  m_api->get("/api/db/stats", 3000, [this, guard](const QJsonObject &res) {
    if (!guard) return;
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    qint64 size = d["dbSizeBytes"].toVariant().toLongLong();
    QString sizeStr = size > 1048576 ? QString("%1 MB").arg(size / 1048576.0, 0, 'f', 1)
                   : size > 1024   ? QString("%1 KB").arg(size / 1024.0, 0, 'f', 0)
                   :                  QString("%1 B").arg(size);
    m_dbSizeLabel->setText(sizeStr);

    // 表行数芯片网格重建：非 0 表高亮蓝色，空表灰色，按表名排序便于扫读
    auto tables = d["tableRowCounts"].toObject();
    while (m_dbTablesGrid->count() > 0) {
      auto *it = m_dbTablesGrid->takeAt(0);
      if (it->widget()) it->widget()->deleteLater();
      delete it;
    }
    const QString chipZero =
      "background:#f1f5f9; color:#94a3b8; border:1px solid #e2e8f0; "
      "border-radius:7px; padding:3px 10px; font-size:14px;";
    const QString chipData =
      "background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; "
      "border-radius:7px; padding:3px 10px; font-size:14px; font-weight:600;";
    QStringList names = tables.keys();
    names.sort();
    const int cols = 5;
    int nonZero = 0;
    for (int i = 0; i < names.size(); i++) {
      const int n = tables.value(names[i]).toInt();
      if (n > 0) nonZero++;
      auto *chip = new QLabel(QString("%1 · %2").arg(names[i], QString::number(n)));
      chip->setStyleSheet(n > 0 ? chipData : chipZero);
      m_dbTablesGrid->addWidget(chip, i / cols, i % cols);
    }
    m_dbTablesCaption->setText(QString("数据库表行数 · 共 %1 张表，%2 张有数据")
                                 .arg(names.size()).arg(nonZero));
  });
}

// ── Load LLM config ──────────────────────────────────────────────────
void DeployConfigPage::loadLlmConfig() {
  const QPointer<DeployConfigPage> guard(this);
  const int version = ++m_readVersions["loadLlmConfig"];
  if (m_llmBusy) return;
  m_llmLoaded = false; setLlmControlsEnabled(false);
  m_llmStatusLabel->setText(QStringLiteral("正在读取模型配置…")); m_llmStatusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_api->get("/api/config/llm", 3000, [this, guard, version](const QJsonObject &res) {
    if (!guard || version != m_readVersions["loadLlmConfig"]) return;
    if (res["status"] != "ok" || !res["data"].isArray()) {
      m_llmStatusLabel->setText(QStringLiteral("模型配置读取失败，已有输入保留；请刷新后再保存或测试。"));
      m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle); return;
    }
    m_llmLoaded = true; setLlmControlsEnabled(true);
    m_llmStatusLabel->setText(QStringLiteral("配置已读取")); m_llmStatusLabel->setStyleSheet(Theme::StatusInfoStyle);
    auto arr = res["data"].toArray();
    // Look for the 'default' entry or first entry
    QJsonObject defaultEntry;
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      if (c["config_key"].toString() == "default") {
        tryParseLlmValue(c["config_value"].toString(), defaultEntry);
        break;
      }
    }
    // If no 'default', try first entry
    if (defaultEntry.isEmpty() && arr.size() > 0) {
      tryParseLlmValue(arr[0].toObject()["config_value"].toString(), defaultEntry);
    }
    if (!defaultEntry.isEmpty()) {
      m_llmApiKey->setText(defaultEntry["key"].toString());
      m_llmBaseUrl->setText(defaultEntry["url"].toString());
      m_llmModel->setText(defaultEntry["model"].toString());
    }
  });
}

// ── Save LLM config ──────────────────────────────────────────────────
void DeployConfigPage::onSaveLlmConfig() {
  if (!m_llmLoaded || m_llmBusy || !validateLlmConfiguration()) return;
  m_llmBusy = true;
  QJsonObject entry;
  entry["key"] = m_llmApiKey->text();
  entry["url"] = m_llmBaseUrl->text();
  entry["model"] = m_llmModel->text();

  QJsonObject body;
  body["config_value"] = entry;
  body["description"] = "LLM model: default";

  setLlmControlsEnabled(false);
  const QPointer<DeployConfigPage> guard(this);
  m_api->put("/api/config/llm/default", body, 5000, [this, guard](const QJsonObject &res) {
    if (!guard) return;
    m_llmBusy = false; setLlmControlsEnabled(true);
    if (res["status"].toString() == "ok") {
      m_llmStatusLabel->setText("已保存");
      m_llmStatusLabel->setStyleSheet(Theme::StatusSuccessStyle);
    } else {
      m_llmStatusLabel->setText("保存失败");
      m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });
}

// ── Test LLM connection ──────────────────────────────────────────────
void DeployConfigPage::onTestLlmConnection() {
  if (!m_llmLoaded || m_llmBusy || !validateLlmConfiguration()) return;
  m_llmBusy = true;
  // Save first, then test in the save callback (fixes async race)
  QJsonObject entry;
  entry["key"] = m_llmApiKey->text();
  entry["url"] = m_llmBaseUrl->text();
  entry["model"] = m_llmModel->text();

  QJsonObject body;
  body["config_value"] = entry;
  body["description"] = "LLM model: default";

  setLlmControlsEnabled(false);
  m_llmTestBtn->setEnabled(false);
  m_llmStatusLabel->setText("保存并测试中...");
  m_llmStatusLabel->setStyleSheet(Theme::StatusInfoStyle);

  QPointer<DeployConfigPage> guard(this);
  m_api->put("/api/config/llm/default", body, 5000, [this, guard](const QJsonObject &saveRes) {
    if (!guard) return;
    if (saveRes["status"].toString() != "ok") {
      m_llmBusy = false;
      setLlmControlsEnabled(true);
      m_llmTestBtn->setEnabled(true);
      m_llmStatusLabel->setText("保存失败");
      m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }
    m_llmStatusLabel->setText("正在请求模型服务...");
    m_api->post("/api/config/llm/test-connection", QJsonObject{}, 25000, [this, guard](const QJsonObject &res) {
      if (!guard) return;
      m_llmBusy = false;
      setLlmControlsEnabled(true);
      m_llmTestBtn->setEnabled(true);
      if (res["status"].toString() == "ok") {
        m_llmStatusLabel->setText(res["data"].toObject()["message"].toString("模型连接测试通过"));
        m_llmStatusLabel->setStyleSheet(Theme::StatusSuccessStyle);
      } else {
        const QString error = res["error"].toObject()["message"].toString("未知错误");
        m_llmStatusLabel->setText(QString("连接测试失败：%1").arg(error.left(120)));
        m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
      }
    });
  });
}

// ── Load sandbox config (merged with loadContainerStatus) ────────────
void DeployConfigPage::loadSandboxConfig() {
  const QPointer<DeployConfigPage> guard(this);
  const int version = ++m_readVersions["loadSandboxConfig"];
  if (m_sandboxBusy) return;
  m_sandboxLoaded = false; setSandboxControlsEnabled(false);
  m_sandboxStatusLabel->setText(QStringLiteral("正在读取运行环境配置…")); m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusInfoStyle));
  m_api->get("/api/config/sandbox", 3000, [this, guard, version](const QJsonObject &res) {
    if (!guard || version != m_readVersions["loadSandboxConfig"]) return;
    if (res["status"] != "ok" || !res["data"].isArray()) {
      m_sandboxStatusLabel->setText(QStringLiteral("运行环境配置读取失败，已有输入保留；请刷新重试。"));
      m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusErrorStyle)); return;
    }
    m_sandboxLoaded = true; setSandboxControlsEnabled(true);
    m_sandboxStatusLabel->setText(QStringLiteral("配置已读取")); m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusInfoStyle));
    auto arr = res["data"].toArray();
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      QString key = c["config_key"].toString();
      if (key == "enabled") {
        m_sandboxEnabled->setChecked(c["config_value"].toString() == "true");
      } else if (key == "engine") {
        QString val = c["config_value"].toString();
        int idx = m_sandboxType->findData(val);
        if (idx >= 0) m_sandboxType->setCurrentIndex(idx);
      }
    }
  });

  m_imagesLoaded = false;
  m_imagesLoading = true;
  m_containerStatus = {};
  renderResourceTables();
  m_api->get("/api/tools/containers/status", 5000, [this, guard, version](const QJsonObject &res) {
    if (!guard || version != m_readVersions["loadSandboxConfig"]) return;
    m_imagesLoading = false;
    m_imagesLoaded = res["status"] == "ok" && res["data"].isObject()
        && res["data"].toObject()["images"].isArray();
    m_containerStatus = m_imagesLoaded ? res["data"].toObject() : QJsonObject();
    renderResourceTables();
  });
}

// ── Save sandbox config ──────────────────────────────────────────────
void DeployConfigPage::onSaveSandboxConfig() {
  if (!m_sandboxLoaded || m_sandboxBusy) return;
  m_sandboxBusy = true;
  const QPointer<DeployConfigPage> guard(this);
  QJsonObject bodyEnabled;
  bodyEnabled["config_value"] = m_sandboxEnabled->isChecked();
  bodyEnabled["description"] = "Sandbox enabled toggle";

  QJsonObject bodyEngine;
  bodyEngine["config_value"] = m_sandboxType->currentData().toString();
  bodyEngine["description"] = "Sandbox container engine";

  setSandboxControlsEnabled(false);
  m_sandboxStatusLabel->setText("保存中...");
  m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusInfoStyle));
  m_api->put("/api/config/sandbox/enabled", bodyEnabled, 3000, [this, guard, bodyEngine](const QJsonObject &enabledRes) {
    if (!guard) return;
    if (enabledRes["status"].toString() != "ok") {
      m_sandboxBusy = false;
      setSandboxControlsEnabled(true);
      m_sandboxStatusLabel->setText("保存失败");
      m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusErrorStyle));
      return;
    }
    m_api->put("/api/config/sandbox/engine", bodyEngine, 3000, [this, guard](const QJsonObject &engineRes) {
      if (!guard) return;
      m_sandboxBusy = false;
      setSandboxControlsEnabled(true);
      if (engineRes["status"].toString() == "ok") {
        m_sandboxStatusLabel->setText("已保存");
        m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusSuccessStyle));
      } else {
        m_sandboxStatusLabel->setText(QStringLiteral("启用状态已保存，但引擎配置保存失败；请刷新核对。"));
        m_sandboxStatusLabel->setStyleSheet(compactStatusStyle(Theme::StatusErrorStyle));
      }
    });
  });
}

// ── Load tool list (existing) ────────────────────────────────────────
void DeployConfigPage::loadToolList() {
  const QPointer<DeployConfigPage> guard(this);
  const int version = ++m_readVersions["loadToolList"];
  m_toolsLoaded = false;
  m_toolsLoading = true;
  m_tools = {};
  renderResourceTables();
  m_api->get("/api/tools/list", 5000, [this, guard, version](const QJsonObject &res) {
    if (!guard || version != m_readVersions["loadToolList"]) return;
    m_toolsLoading = false;
    m_toolsLoaded = res["status"] == "ok" && res["data"].isArray();
    m_tools = m_toolsLoaded ? res["data"].toArray() : QJsonArray();
    renderResourceTables();
  });
}

// ── Load system config (existing) ────────────────────────────────────
void DeployConfigPage::loadConfig() {
  const QPointer<DeployConfigPage> guard(this);
  const int version = ++m_readVersions["loadConfig"];
  m_api->get("/api/config", 5000, [this, guard, version](const QJsonObject &res) {
    if (!guard || version != m_readVersions["loadConfig"]) return;
    if (res["status"] != "ok" || !res["data"].isArray()) {
      UiUtil::EmptyHint::setState(m_configTable, QStringLiteral("配置列表读取失败，请刷新重试"), true); return;
    }
    UiUtil::EmptyHint::setState(m_configTable, QStringLiteral("暂无配置列表记录"));
    auto arr = res["data"].toArray();
    m_configTable->setSortingEnabled(false);
    m_configTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      m_configTable->setItem(i, 0, new QTableWidgetItem(c["config_key"].toString()));
      m_configTable->setItem(i, 1, new QTableWidgetItem(c["config_value"].toString()));
      m_configTable->setItem(i, 2, new QTableWidgetItem(c["category"].toString()));
    }
    m_configTable->setSortingEnabled(true);
    fitTableHeight(m_configTable, 300);
  });
}

// ── Load lab list ──────────────────────────────────────────────────────
void DeployConfigPage::loadLabList() {
  const QPointer<DeployConfigPage> guard(this);
  const int version = ++m_readVersions["loadLabList"];
  m_api->get("/api/labs", 5000, [this, guard, version](const QJsonObject &res) {
    if (!guard || version != m_readVersions["loadLabList"]) return;
    if (res["status"] != "ok" || !res["data"].isArray()) {
      UiUtil::EmptyHint::setState(m_labTable, QStringLiteral("靶场列表读取失败，请刷新重试"), true); return;
    }
    UiUtil::EmptyHint::setState(m_labTable, QStringLiteral("暂无靶场列表记录"));
    auto data = res["data"].toArray();
    // 排序开启时逐行 setItem 会边填边重排，行错位（状态/操作列空白的根因）
    m_labTable->setSortingEnabled(false);
    m_labTable->setRowCount(data.size());
    for (int i = 0; i < data.size(); i++) {
      auto lab = data[i].toObject();
      QString name = lab["name"].toString();
      // Backend returns "name" only, no "display_name" — capitalize for display
      QString displayName = name;
      if (!displayName.isEmpty()) displayName[0] = displayName[0].toUpper();
      QString status = lab["status"].toString();

      // Column 0: display name (store API name as UserRole data)
      auto *nameItem = new QTableWidgetItem(displayName);
      nameItem->setData(Qt::UserRole, name);
      m_labTable->setItem(i, 0, nameItem);

      // Column 1: status
      QString statusDisplay = (status == "running") ? "运行中" : "已停止";
      auto *statusItem = new QTableWidgetItem(statusDisplay);
      m_labTable->setItem(i, 1, statusItem);

      // Column 2: action buttons
      auto *btnWidget = new QWidget;
      auto *btnLayout = new QHBoxLayout(btnWidget);
      btnLayout->setContentsMargins(4, 2, 4, 2);

      // 紧凑按钮：默认按钮 + 单元行高会被裁切
      auto *startBtn = new QPushButton("启动");
      auto *stopBtn = new QPushButton("停止");
      auto *verifyBtn = new QPushButton("自检");
      startBtn->setProperty("compact", true);
      stopBtn->setProperty("compact", true);
      verifyBtn->setProperty("compact", true);
      verifyBtn->setToolTip(QStringLiteral("检查靶场运行与测试链路；检查过程使用所选靶场环境。"));

      stopBtn->setProperty("danger", true);
      if (status == "running") {
        startBtn->hide();
      } else {
        stopBtn->hide();
      }

      connect(startBtn, &QPushButton::clicked, this, [this, name]() { onLabAction("start", name); });
      connect(stopBtn, &QPushButton::clicked, this, [this, name]() { onLabAction("stop", name); });
      connect(verifyBtn, &QPushButton::clicked, this, [this, name]() { onLabVerify(name); });

      btnLayout->addWidget(startBtn);
      btnLayout->addWidget(stopBtn);
      btnLayout->addWidget(verifyBtn);
      m_labTable->setCellWidget(i, 2, btnWidget);
    }
    m_labTable->setSortingEnabled(true);
    fitTableHeight(m_labTable, 380);
  });
}

// ── Lab action (start / stop) ─────────────────────────────────────────
void DeployConfigPage::onLabAction(const QString &action, const QString &name) {
  if (!m_labTable->isEnabled() || name.isEmpty()) return;
  const QPointer<DeployConfigPage> guard(this);
  QString actionLabel = (action == "start") ? "启动" : "停止";
  m_labStatusLabel->setText(QString("%1 %2...").arg(actionLabel, name));
  m_labStatusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_labTable->setEnabled(false);
  m_api->post("/api/labs/" + name + "/" + action, QJsonObject(), 30000,
              [this, guard, name](const QJsonObject &res) {
    if (!guard) return;
    m_labTable->setEnabled(true);
    if (res["status"].toString() == "ok") {
      m_labStatusLabel->setText(name + " 操作成功");
      m_labStatusLabel->setStyleSheet(Theme::StatusSuccessStyle);
      loadLabList();
    } else {
      // Backend returns errors as {status:"error", error:{message:"..."}}
      QString errMsg = res["error"].toObject()["message"].toString();
      if (errMsg.isEmpty()) errMsg = res["message"].toString();
      m_labStatusLabel->setText("操作失败: " + errMsg);
      m_labStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });
}

// ── Lab verify ─────────────────────────────────────────────────────────
void DeployConfigPage::onLabVerify(const QString &name) {
  if (!m_labTable->isEnabled() || name.isEmpty()) return;
  const QPointer<DeployConfigPage> guard(this);
  m_labStatusLabel->setText(QString("正在自检 %1...").arg(name));
  m_labStatusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_labTable->setEnabled(false);
  m_api->post("/api/labs/" + name + "/verify", QJsonObject(), 180000,
              [this, guard, name](const QJsonObject &res) {
    if (!guard) return;
    m_labTable->setEnabled(true);
    if (res["status"].toString() == "ok") {
      auto data = res["data"].toObject();
      // Backend returns {ok, checks, duration, name}
      bool ok = data["ok"].toBool();
      double duration = data["duration"].toDouble();
      auto checks = data["checks"].toArray();
      int passCount = 0;
      for (const auto &c : checks) {
        const auto check = c.toObject();
        if (check["passed"].toBool() || check["ok"].toBool()) passCount++;
      }
      QString result = ok ? QString("✅ 通过 (%1/%2 检查项, 耗时%3s)")
                                .arg(passCount).arg(checks.size()).arg(duration, 0, 'f', 1)
                          : QString("❌ 失败 (%1/%2 检查项通过)")
                                .arg(passCount).arg(checks.size());
      m_labStatusLabel->setText(QString("自检 %1: %2").arg(name, result));
      m_labStatusLabel->setStyleSheet(ok ? Theme::StatusSuccessStyle : Theme::StatusErrorStyle);
    } else {
      m_labStatusLabel->setText(QString("自检 %1 失败: %2").arg(name, res["error"].toObject()["message"].toString()));
      m_labStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });
}

// ── Helper: parse LLM config_value JSON ──────────────────────────────
void DeployConfigPage::tryParseLlmValue(const QString &jsonStr, QJsonObject &out) {
  QJsonParseError err;
  auto doc = QJsonDocument::fromJson(jsonStr.toUtf8(), &err);
  if (err.error == QJsonParseError::NoError && doc.isObject()) {
    out = doc.object();
  }
}

void DeployConfigPage::showSection(const QString &section)
{
  if (!m_sections.contains(section)) return;
  const bool resources = section == "tools" || section == "images";
  const bool runtime = section == "runtime";
  setProperty("activeSection", section);
  for (auto it = m_sections.cbegin(); it != m_sections.cend(); ++it) {
    if (it.key() == "images" || it.key() == "tools" || it.key() == "refresh") continue;
    it.value()->setVisible(it.key() == section);
    if (it.key() == section && it.value()->layout()->count() > 0)
      if (auto *heading = qobject_cast<QLabel *>(it.value()->layout()->itemAt(0)->widget())) heading->setVisible(section != "llm");
  }
  m_formScroll->setVisible(!resources && !runtime);
  m_resourceHeading->setVisible(runtime);
  m_resourceSearch->setMaximumWidth(runtime ? 420 : QWIDGETSIZE_MAX);
  m_resourceTabs->setVisible(resources || runtime);
  m_resourceTabs->tabBar()->setVisible(!runtime);
  m_resourceTabs->setCurrentIndex(runtime || section == "images" ? 1 : 0);
  m_resourceSearch->setVisible(resources || runtime);
  m_resourceSummary->setVisible(resources || runtime);
  filterResources();
}

void DeployConfigPage::renderResourceTables()
{
  const QString engine = m_containerStatus["engine"].toString();
  const QString inventoryStatus = m_containerStatus["imageInventoryStatus"].toString();
  const bool known = m_imagesLoaded && (inventoryStatus == "ok"
      || (inventoryStatus.isEmpty() && (engine == "docker" || engine == "podman")));
  QSet<QString> loaded;
  for (const auto &value : m_containerStatus["images"].toArray()) loaded.insert(value.toString());
  const auto sizes = m_containerStatus["imageSizes"].toObject();
  QMap<QString, QStringList> dependents;
  m_toolTable->setSortingEnabled(false);
  m_toolTable->setRowCount(m_tools.size());
  for (int row = 0; row < m_tools.size(); ++row) {
    const auto tool = m_tools[row].toObject();
    const QString id = tool["toolId"].toString();
    const QString image = tool["image"].toString();
    // Older servers return only virtual/image; preserve those records too.
    const QString mode = tool["virtual"].toBool() ? "virtual" : image == "builtin" ? "builtin" : "container";
    const QString reference = imageParts(image).first + ':' + imageParts(image).second;
    if (mode == "container" && !image.isEmpty()) dependents[reference] << id;
    const QString state = mode != "container" ? QStringLiteral("不适用")
        : image.isEmpty() ? QStringLiteral("未配置")
        : !known ? QStringLiteral("未确认") : loaded.contains(reference) ? QStringLiteral("已加载") : QStringLiteral("未安装");
    const QStringList cells{id, tool["purpose"].toString(QStringLiteral("—")),
      mode == "virtual" ? QStringLiteral("虚拟工具") : mode == "builtin" ? QStringLiteral("内置处理器") : QStringLiteral("容器工具"),
      mode != "container" ? QStringLiteral("—") : image.isEmpty() ? QStringLiteral("未配置") : image, state};
    for (int col = 0; col < cells.size(); ++col) m_toolTable->setItem(row, col, resourceItem(cells[col]));
    m_toolTable->item(row, 0)->setData(Qt::UserRole, mode);
    auto *status = m_toolTable->item(row, 4);
    status->setForeground(QColor(state == QStringLiteral("已加载") ? Theme::Success
        : state == QStringLiteral("未配置") ? Theme::Warning : Theme::TextSecondary));
    status->setToolTip(state == QStringLiteral("已加载")
        ? QStringLiteral("本地存在依赖镜像；工具执行状态需在任务中核实。")
        : state == QStringLiteral("未安装") ? QStringLiteral("使用此工具时需要安装对应镜像；可按实际测试内容选择工具，无需全部安装。")
        : state == QStringLiteral("未确认") ? QStringLiteral("尚未取得有效的容器镜像清单，请刷新重试。") : state);
  }
  m_toolTable->setSortingEnabled(true);
  QSet<QString> references = loaded;
  for (const auto &value : m_containerStatus["expectedImages"].toArray())
    if (value.toString() != "builtin:latest") references.insert(value.toString());
  for (auto it = dependents.cbegin(); it != dependents.cend(); ++it)
    references.insert(it.key());
  QStringList sorted = references.values(); sorted.sort();
  m_imageTable->setSortingEnabled(false);
  m_imageTable->setRowCount(sorted.size());
  const auto capabilities = m_containerStatus["imageCapabilities"].toObject();
  for (int row = 0; row < sorted.size(); ++row) {
    const auto parts = imageParts(sorted[row]);
    const auto tools = dependents.value(sorted[row]);
    const QString state = !known ? QStringLiteral("未确认") : loaded.contains(sorted[row]) ? QStringLiteral("已加载") : QStringLiteral("未安装");
    const QString size = sizes[sorted[row]].toString(sizes[parts.first].toString(QStringLiteral("—")));
    const QStringList cells{parts.first, parts.second, state, loaded.contains(sorted[row]) ? size : QStringLiteral("—"),
      m_toolsLoaded ? QStringLiteral("%1 个工具").arg(tools.size()) : QStringLiteral("未确认"),
      capabilities[parts.first].toString(QStringLiteral("—"))};
    for (int col = 0; col < cells.size(); ++col) m_imageTable->setItem(row, col, resourceItem(cells[col]));
    m_imageTable->item(row, 2)->setForeground(QColor(known && loaded.contains(sorted[row]) ? Theme::Success : Theme::TextSecondary));
    m_imageTable->item(row, 2)->setToolTip(state == QStringLiteral("未安装")
        ? QStringLiteral("本地未安装此标签的镜像；使用关联工具时按需安装。")
        : state == QStringLiteral("已加载") ? QStringLiteral("本地存在此镜像，不代表容器正在运行或工具已通过检查。")
        : QStringLiteral("尚未取得有效的容器镜像清单，请刷新重试。"));
    m_imageTable->item(row, 3)->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_imageTable->item(row, 4)->setToolTip(tools.join(QStringLiteral("、")).toHtmlEscaped());
    m_imageTable->item(row, 4)->setData(Qt::UserRole, tools.join(' '));
    m_imageTable->item(row, 5)->setToolTip(capabilities[parts.first].isString()
        ? QStringLiteral("用于%1；使用关联工具时需要对应镜像，按实际测试内容选择安装。")
            .arg(capabilities[parts.first].toString())
        : QStringLiteral("当前服务未提供此镜像的适用能力信息。"));
  }
  m_imageTable->setSortingEnabled(true);
  UiUtil::EmptyHint::setState(m_toolTable, m_toolsLoading ? QStringLiteral("正在读取工具列表…")
      : m_toolsLoaded ? QStringLiteral("暂无匹配工具") : QStringLiteral("工具列表读取失败，请刷新重试"), !m_toolsLoaded && !m_toolsLoading);
  UiUtil::EmptyHint::setState(m_imageTable, m_imagesLoading ? QStringLiteral("正在读取镜像清单…")
      : known ? QStringLiteral("暂无匹配镜像") : QStringLiteral("镜像清单未确认，请刷新重试"), !known && !m_imagesLoading);
  filterResources();
}

void DeployConfigPage::filterResources()
{
  const bool tools = m_resourceTabs->currentIndex() == 0;
  m_resourceType->setVisible(tools && property("activeSection").toString() == "tools");
  m_resourceSearch->setPlaceholderText(tools ? QStringLiteral("搜索工具、用途或镜像") : QStringLiteral("搜索镜像、适用能力或关联工具"));
  const QString query = m_resourceSearch->text().trimmed();
  auto *table = tools ? m_toolTable : m_imageTable;
  int visible = 0;
  for (int row = 0; row < table->rowCount(); ++row) {
    bool matches = query.isEmpty();
    for (int col = 0; col < table->columnCount(); ++col) {
      const auto *item = table->item(row, col);
      if (item && (item->text().contains(query, Qt::CaseInsensitive)
          || (!tools && col == 4 && item->data(Qt::UserRole).toString().contains(query, Qt::CaseInsensitive)))) matches = true;
    }
    if (tools && m_resourceType->currentData().toString() != "all")
      matches = matches && table->item(row, 0)->data(Qt::UserRole).toString() == m_resourceType->currentData().toString();
    table->setRowHidden(row, !matches);
    if (matches) ++visible;
  }
  const bool known = tools ? m_toolsLoaded : m_imagesLoaded
      && (m_containerStatus["imageInventoryStatus"].toString() == "ok"
          || (m_containerStatus["imageInventoryStatus"].toString().isEmpty()
              && QStringList{"docker", "podman"}.contains(m_containerStatus["engine"].toString())));
  const bool loading = tools ? m_toolsLoading : m_imagesLoading;
  m_resourceSummary->setText(loading ? QStringLiteral("正在读取…")
      : known ? QStringLiteral("%1 / %2 项").arg(visible).arg(table->rowCount()) : QStringLiteral("状态未确认"));
  if (auto *hint = table->viewport()->findChild<QLabel *>("itemViewEmptyHint", Qt::FindDirectChildrenOnly))
    hint->setVisible(visible == 0);
}

void DeployConfigPage::setLlmControlsEnabled(bool enabled)
{
  for (auto *field : {m_llmApiKey, m_llmBaseUrl, m_llmModel}) field->setEnabled(enabled);
  m_llmSaveBtn->setEnabled(enabled); m_llmTestBtn->setEnabled(enabled);
}

void DeployConfigPage::setSandboxControlsEnabled(bool enabled)
{
  m_sandboxEnabled->setEnabled(enabled); m_sandboxType->setEnabled(enabled); m_sandboxSaveBtn->setEnabled(enabled);
}

bool DeployConfigPage::validateLlmConfiguration()
{
  const QUrl url(m_llmBaseUrl->text().trimmed());
  if (!url.isValid() || url.host().isEmpty() || !QStringList{"http", "https"}.contains(url.scheme().toLower())) {
    m_llmStatusLabel->setText(QStringLiteral("请填写有效的 HTTP/HTTPS 模型服务地址。"));
    m_llmStatusLabel->setStyleSheet(Theme::StatusWarningStyle); m_llmBaseUrl->setFocus(); return false;
  }
  if (m_llmModel->text().trimmed().isEmpty()) {
    m_llmStatusLabel->setText(QStringLiteral("请填写模型名称。"));
    m_llmStatusLabel->setStyleSheet(Theme::StatusWarningStyle); m_llmModel->setFocus(); return false;
  }
  return true;
}
