#include "../widgets/WorkbenchTabs.h"
#include "KnowledgeGraphPage.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QSplitter>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsSimpleTextItem>
#include <QWheelEvent>
#include <QCheckBox>
#include <QGraphicsItem>
#include <QPainter>
#include <QBrush>
#include <QColor>
#include <QPen>
#include <QFont>
#include <QtMath>

namespace {

class KgGraphicsView : public QGraphicsView {
public:
  explicit KgGraphicsView(QWidget *parent = nullptr) : QGraphicsView(parent) {}
protected:
  void wheelEvent(QWheelEvent *event) override {
    if (event->modifiers() & Qt::ControlModifier) {
      const qreal factor = event->angleDelta().y() > 0 ? 1.12 : (1.0 / 1.12);
      scale(factor, factor);
      event->accept();
      return;
    }
    QGraphicsView::wheelEvent(event);
  }
};

} // anonymous namespace

KnowledgeGraphPage::KnowledgeGraphPage(ApiClient *api, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
  refresh();
}

void KnowledgeGraphPage::setupUI() {
  setStyleSheet(Theme::PageStyle);
  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(16, 12, 16, 16);
  layout->setSpacing(12);

  auto *header = new QHBoxLayout;
  auto *title = new QLabel("攻防知识图谱");
  title->setStyleSheet("font-size:17px; font-weight:700; color:#172033;");
  header->addWidget(title);
  auto *refreshBtn = new QPushButton("刷新");
  header->addStretch();
  header->addWidget(refreshBtn);
  layout->addLayout(header);
  connect(refreshBtn, &QPushButton::clicked, this, &KnowledgeGraphPage::refresh);

  m_subTabs = new WorkbenchTabs;

  // Sub-tab 1: Stats
  auto *statsW = new QWidget;
  setupStatsTab(statsW);
  m_subTabs->addTab(statsW, "统计");

  // Sub-tab 2: Graph
  auto *graphW = new QWidget;
  setupGraphTab(graphW);
  m_subTabs->addTab(graphW, "图谱");

  // Sub-tab 3: Tactic tree (战术→技术层级浏览)
  auto *tacticW = new QWidget;
  setupTacticTreeTab(tacticW);
  m_subTabs->addTab(tacticW, "战术浏览");

  // Sub-tab 4: Mappings
  auto *mapW = new QWidget;
  setupMappingsTab(mapW);
  m_subTabs->addTab(mapW, "映射关系");

  // Sub-tab 5: Node search
  auto *nodesW = new QWidget;
  setupNodesTab(nodesW);
  m_subTabs->addTab(nodesW, "节点搜索");

  layout->addWidget(m_subTabs);
  connect(m_subTabs, &QTabWidget::currentChanged, this, &KnowledgeGraphPage::onSubTabChanged);
}

void KnowledgeGraphPage::refresh() {
  loadStats();
}

void KnowledgeGraphPage::onSubTabChanged(int index) {
  if (index == 0) loadStats();
  else if (index == 1) loadGraph();
  else if (index == 2) loadTacticTree();
  else if (index == 3) loadMappings();
  // tab 4 (search) loads on demand
}

QString KnowledgeGraphPage::nodeTypeColor(const QString &type) const {
  static const QMap<QString, QString> colors = {
    {"HexToolWrapper", "#3b82f6"}, {"AttackTechnique", "#ef4444"},
    {"AttackTactic", "#f59e0b"}, {"AttackSoftware", "#8b5cf6"},
    {"AttackGroup", "#ec4899"}, {"HexEndpoint", "#06b6d4"},
    {"AttackMitigation", "#22c55e"}, {"AttackDataComponent", "#14b8a6"},
    {"AttackCampaign", "#f97316"}, {"HexPayload", "#6366f1"},
    {"HexDecisionRule", "#a855f7"}, {"HexParameterRule", "#d946ef"},
    {"HexRecoveryRule", "#84cc16"},
  };
  return colors.value(type, "#94a3b8");
}

QString KnowledgeGraphPage::nodeTypeLabel(const QString &type) const {
  static const QMap<QString, QString> labels = {
    {"HexToolWrapper", "工具"}, {"AttackTechnique", "攻防技术"},
    {"AttackTactic", "战术"}, {"AttackSoftware", "软件"},
    {"AttackGroup", "攻击组织"}, {"HexEndpoint", "端点"},
    {"AttackMitigation", "缓解措施"}, {"AttackDataComponent", "数据组件"},
    {"AttackCampaign", "攻击活动"}, {"HexPayload", "载荷"},
    {"HexDecisionRule", "决策规则"}, {"HexParameterRule", "参数规则"},
    {"HexRecoveryRule", "恢复规则"},
  };
  return labels.value(type, type);
}

QString KnowledgeGraphPage::edgeTypeLabel(const QString &type) const {
  static const QMap<QString, QString> labels = {
    {"MAPS_TO_TECHNIQUE", "映射到技术"},
    {"BELONGS_TO_TACTIC", "属于战术"},
    {"USES_TECHNIQUE", "使用技术"},
    {"SUBTECHNIQUE_OF", "子技术"},
    {"MITIGATES", "缓解"},
    {"MITIGATED_BY", "被缓解"},
    {"RELATES_TO", "关联"},
    {"TARGETS", "针对"},
    {"USES_SOFTWARE", "使用软件"},
    {"USES", "使用"},
    {"SUPPORTS", "支撑"},
    {"SUPPORT_UTILITY_ONLY", "仅辅助支撑"},
    {"REQUIRES", "需要"},
    {"REQUIRES_REVIEW", "需人工审核"},
    {"IMPLIES", "蕴含"},
    {"DEPENDS_ON", "依赖"},
    {"HAS_SUBTECHNIQUE", "包含子技术"},
    {"REVOKED_BY", "被撤销"},
    {"DETECTS", "检测"},
    {"EXECUTED_BY_TOOL", "由工具执行"},
  };
  return labels.value(type, type);
}

QString KnowledgeGraphPage::zhOrDefault(const QJsonObject &obj, const QString &field) const {
  QString zhKey = "zh_" + field;
  QString zh = obj[zhKey].toString();
  if (!zh.isEmpty()) return zh;
  return obj[field].toString();
}

// ── Sub-tab setup ────────────────────────────────────────────────────

void KnowledgeGraphPage::setupStatsTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);

  // Stat cards row
  auto *cardsH = new QHBoxLayout;
  m_nodeCountLabel = new QLabel("节点: -");
  m_nodeCountLabel->setStyleSheet("font-size:18px; font-weight:bold; color:#3b82f6; padding:12px; background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px;");
  m_edgeCountLabel = new QLabel("边: -");
  m_edgeCountLabel->setStyleSheet("font-size:18px; font-weight:bold; color:#8b5cf6; padding:12px; background:#f5f3ff; border:1px solid #c4b5fd; border-radius:10px;");
  m_versionLabel = new QLabel("版本：-");
  m_versionLabel->setStyleSheet("font-size:14px; color:#64748b; padding:12px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;");
  cardsH->addWidget(m_nodeCountLabel);
  cardsH->addWidget(m_edgeCountLabel);
  cardsH->addWidget(m_versionLabel);
  cardsH->addStretch();
  l->addLayout(cardsH);

  // 两张分布表并排铺满行宽，不再上下堆叠留白
  auto *distH = new QHBoxLayout;

  auto *ntW = new QWidget;
  auto *ntL = new QVBoxLayout(ntW);
  ntL->setContentsMargins(0, 0, 0, 0);
  auto *ntLabel = new QLabel("节点类型分布"); ntLabel->setStyleSheet(Theme::SectionStyle);
  ntL->addWidget(ntLabel);
  m_nodeTypeTable = new QTableWidget(0, 3);
  UiUtil::EmptyHint::attach(m_nodeTypeTable, QStringLiteral("暂无节点统计"));
  m_nodeTypeTable->setHorizontalHeaderLabels({"类型", "数量", "占比"});
  m_nodeTypeTable->setAlternatingRowColors(true);
  m_nodeTypeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_nodeTypeTable->setSortingEnabled(true);
  m_nodeTypeTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_nodeTypeTable->verticalHeader()->setDefaultSectionSize(36);
  ntL->addWidget(m_nodeTypeTable, 1);
  distH->addWidget(ntW, 1);

  auto *etW = new QWidget;
  auto *etL = new QVBoxLayout(etW);
  etL->setContentsMargins(0, 0, 0, 0);
  auto *etLabel = new QLabel("边类型分布"); etLabel->setStyleSheet(Theme::SectionStyle);
  etL->addWidget(etLabel);
  m_edgeTypeTable = new QTableWidget(0, 2);
  UiUtil::EmptyHint::attach(m_edgeTypeTable, QStringLiteral("暂无关系统计"));
  m_edgeTypeTable->setHorizontalHeaderLabels({"类型", "数量"});
  m_edgeTypeTable->setAlternatingRowColors(true);
  m_edgeTypeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_edgeTypeTable->setSortingEnabled(true);
  m_edgeTypeTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_edgeTypeTable->verticalHeader()->setDefaultSectionSize(36);
  etL->addWidget(m_edgeTypeTable, 1);
  distH->addWidget(etW, 1);

  l->addLayout(distH, 1);
}

void KnowledgeGraphPage::setupGraphTab(QWidget *parent) {
  auto *splitter = new QSplitter(Qt::Horizontal, parent);

  // Left: graph + controls
  auto *leftW = new QWidget;
  auto *leftL = new QVBoxLayout(leftW);
  leftL->setContentsMargins(4, 4, 4, 4);

  // Type filter checkboxes
  auto *filterH = new QHBoxLayout;
  m_showTactics = new QCheckBox("战术"); m_showTactics->setChecked(true);
  m_showTechniques = new QCheckBox("技术"); m_showTechniques->setChecked(true);
  m_showWrappers = new QCheckBox("工具"); m_showWrappers->setChecked(false);
  m_showGroups = new QCheckBox("组织"); m_showGroups->setChecked(false);
  m_showSoftware = new QCheckBox("软件"); m_showSoftware->setChecked(false);
  filterH->addWidget(m_showTactics);
  filterH->addWidget(m_showTechniques);
  filterH->addWidget(m_showWrappers);
  filterH->addWidget(m_showGroups);
  filterH->addWidget(m_showSoftware);
  filterH->addStretch();
  auto *zoomInBtn = new QPushButton("放大");
  auto *zoomOutBtn = new QPushButton("缩小");
  auto *resetBtn = new QPushButton("重置");
  leftL->addLayout(filterH);
  auto *zoomRow = new QHBoxLayout;
  zoomRow->addStretch();
  zoomRow->addWidget(zoomInBtn);
  zoomRow->addWidget(zoomOutBtn);
  zoomRow->addWidget(resetBtn);
  leftL->addLayout(zoomRow);

  // Graphics scene + view
  m_scene = new QGraphicsScene(this);
  m_view = new KgGraphicsView;
  m_view->setScene(m_scene);
  m_view->setRenderHint(QPainter::Antialiasing, true);
  m_view->setDragMode(QGraphicsView::ScrollHandDrag);
  m_view->setBackgroundBrush(QColor("#0f172a"));
  m_view->setViewportUpdateMode(QGraphicsView::SmartViewportUpdate);
  leftL->addWidget(m_view, 1);

  // Legend
  auto *legendH = new QHBoxLayout;
  for (const auto &pair : QList<QPair<QString,QString>>({
    {"工具","#3b82f6"}, {"技术","#ef4444"}, {"战术","#f59e0b"},
    {"软件","#8b5cf6"}, {"组织","#ec4899"}, {"端点","#06b6d4"}, {"缓解","#22c55e"}
  })) {
    auto *dot = new QLabel("●");
    dot->setStyleSheet(QString("color:%1; font-size:14px;").arg(pair.second));
    auto *lbl = new QLabel(pair.first);
    lbl->setStyleSheet("color:#94a3b8; font-size:11px;");
    legendH->addWidget(dot);
    legendH->addWidget(lbl);
  }
  legendH->addStretch();
  leftL->addLayout(legendH);

  // Click handler for node selection
  connect(m_scene, &QGraphicsScene::selectionChanged, this, [this]() {
    auto sel = m_scene->selectedItems();
    if (sel.isEmpty()) return;
    auto *item = sel.first();
    QString nodeId = item->data(0).toString();
    if (!nodeId.isEmpty()) onNodeClicked(nodeId);
  });

  // Zoom signals
  connect(zoomInBtn, &QPushButton::clicked, this, [this]() { m_view->scale(1.2, 1.2); });
  connect(zoomOutBtn, &QPushButton::clicked, this, [this]() { m_view->scale(1.0/1.2, 1.0/1.2); });
  connect(resetBtn, &QPushButton::clicked, this, [this]() {
    m_view->resetTransform();
    m_view->fitInView(m_scene->itemsBoundingRect(), Qt::KeepAspectRatio);
  });

  // Re-render on filter change
  connect(m_showTactics, &QCheckBox::stateChanged, this, [this]() { loadGraph(); });
  connect(m_showTechniques, &QCheckBox::stateChanged, this, [this]() { loadGraph(); });
  connect(m_showWrappers, &QCheckBox::stateChanged, this, [this]() { loadGraph(); });
  connect(m_showGroups, &QCheckBox::stateChanged, this, [this]() { loadGraph(); });
  connect(m_showSoftware, &QCheckBox::stateChanged, this, [this]() { loadGraph(); });

  // Right: detail panel
  auto *rightW = new QWidget;
  auto *rightL = new QVBoxLayout(rightW);
  rightL->setContentsMargins(8, 8, 8, 8);
  rightW->setMaximumWidth(320);
  m_detailTitle = new QLabel("点击节点查看详情");
  m_detailTitle->setStyleSheet("font-size:14px; font-weight:bold; color:#1e293b;");
  m_detailTitle->setWordWrap(true);
  rightL->addWidget(m_detailTitle);
  m_detailText = new QTextEdit;
  m_detailText->setReadOnly(true);
  m_detailText->setPlaceholderText("选择图谱中的节点以查看详情...");
  rightL->addWidget(m_detailText, 1);

  splitter->addWidget(leftW);
  splitter->addWidget(rightW);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 1);

  auto *outerL = new QVBoxLayout(parent);
  outerL->addWidget(splitter);
}

void KnowledgeGraphPage::setupMappingsTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);

  auto *filterH = new QHBoxLayout;
  m_mappingSearchEdit = new QLineEdit;
  m_mappingSearchEdit->setPlaceholderText("搜索工具或技术...");
  filterH->addWidget(m_mappingSearchEdit, 1);
  m_mappingConfidenceFilter = new QComboBox;
  m_mappingConfidenceFilter->addItems({"全部", "高", "中", "低"});
  filterH->addWidget(m_mappingConfidenceFilter);
  l->addLayout(filterH);

  m_mappingTable = new QTableWidget(0, 4);
  UiUtil::EmptyHint::attach(m_mappingTable, QStringLiteral("暂无映射记录"));
  m_mappingTable->setHorizontalHeaderLabels({"工具名称", "技术编号", "技术名称", "置信度"});
  m_mappingTable->setAlternatingRowColors(true);
  m_mappingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_mappingTable->setSortingEnabled(true);
  m_mappingTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_mappingTable->horizontalHeader()->setStretchLastSection(false);
  m_mappingTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  m_mappingTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_mappingTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  m_mappingTable->horizontalHeader()->setMinimumSectionSize(80);
  m_mappingTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  l->addWidget(m_mappingTable, 1);

  connect(m_mappingSearchEdit, &QLineEdit::textChanged, this, &KnowledgeGraphPage::onMappingSearch);
  connect(m_mappingConfidenceFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &KnowledgeGraphPage::onMappingSearch);

  // Right-click copy
  connect(m_mappingTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_mappingTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_mappingTable->viewport()->mapToGlobal(pos));
  });
}

void KnowledgeGraphPage::setupNodesTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);

  auto *filterH = new QHBoxLayout;
  m_searchEdit = new QLineEdit;
  m_searchEdit->setPlaceholderText("搜索节点名称或编号...");
  filterH->addWidget(m_searchEdit, 1);
  m_searchTypeFilter = new QComboBox;
  m_searchTypeFilter->addItem("全部", "");
  m_searchTypeFilter->addItem("工具", "HexToolWrapper");
  m_searchTypeFilter->addItem("攻防技术", "AttackTechnique");
  m_searchTypeFilter->addItem("战术", "AttackTactic");
  m_searchTypeFilter->addItem("软件", "AttackSoftware");
  m_searchTypeFilter->addItem("攻击组织", "AttackGroup");
  m_searchTypeFilter->addItem("端点", "HexEndpoint");
  m_searchTypeFilter->addItem("缓解措施", "AttackMitigation");
  filterH->addWidget(m_searchTypeFilter);
  auto *searchBtn = new QPushButton("搜索");
  searchBtn->setProperty("primary", true);
  filterH->addWidget(searchBtn);
  l->addLayout(filterH);

  m_searchTable = new QTableWidget(0, 4);
  m_searchTable->setObjectName("kgSearchTable");
  UiUtil::EmptyHint::attach(m_searchTable, QStringLiteral("暂无搜索结果 · 输入节点名称或编号后点击搜索"));
  m_searchTable->setHorizontalHeaderLabels({"名称", "类型", "来源", "风险"});
  m_searchTable->setAlternatingRowColors(true);
  m_searchTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_searchTable->setSortingEnabled(true);
  m_searchTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_searchTable->setSelectionMode(QAbstractItemView::SingleSelection);
  m_searchTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_searchTable->horizontalHeader()->setStretchLastSection(false);
  m_searchTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  m_searchTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_searchTable->horizontalHeader()->setMinimumSectionSize(80);
  m_searchTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  auto *split = new QSplitter(Qt::Vertical);
  split->setObjectName("kgSearchSplit");
  split->setChildrenCollapsible(false);
  split->addWidget(m_searchTable);
  auto *detailPanel = new QWidget;
  auto *detailLayout = new QVBoxLayout(detailPanel);
  detailLayout->setContentsMargins(0, 6, 0, 0);
  auto *detailTitle = new QLabel("节点详情");
  detailTitle->setStyleSheet("font-size:13px; font-weight:600; color:#475569;");
  detailLayout->addWidget(detailTitle);
  m_searchDetail = new QTextEdit;
  m_searchDetail->setObjectName("kgSearchDetail");
  m_searchDetail->setReadOnly(true);
  m_searchDetail->setPlaceholderText("选择上方搜索结果，查看节点说明和关联关系。");
  m_searchDetail->setMinimumHeight(72);
  detailLayout->addWidget(m_searchDetail);
  split->addWidget(detailPanel);
  split->setStretchFactor(0, 1);
  split->setStretchFactor(1, 0);
  split->setSizes({480, 130});
  l->addWidget(split, 1);

  connect(searchBtn, &QPushButton::clicked, this, &KnowledgeGraphPage::onSearch);
  connect(m_searchEdit, &QLineEdit::returnPressed, this, &KnowledgeGraphPage::onSearch);

  connect(m_searchTable, &QTableWidget::cellClicked, this, [this](int row, int) {
    auto *item = m_searchTable->item(row, 0);
    if (!item) return;
    onNodeClicked(item->data(Qt::UserRole).toString());
  });

  // Right-click copy
  connect(m_searchTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_searchTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_searchTable->viewport()->mapToGlobal(pos));
  });
}

// ── KG data loading ──────────────────────────────────────────────────

void KnowledgeGraphPage::loadStats() {
  m_api->get("/api/kg/stats", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();

    m_nodeCountLabel->setText(QString("节点: %1").arg(d["node_count"].toInt()));
    m_edgeCountLabel->setText(QString("边: %1").arg(d["edge_count"].toInt()));
    m_versionLabel->setText(QString("版本：%1").arg(d["kg_version"].toString()));

    // 排序开启时逐行 setItem 会边填边重排，后两列 item 落错行 → 数字错位/丢失
    m_nodeTypeTable->setSortingEnabled(false);
    auto ntc = d["node_type_counts"].toObject();
    m_nodeTypeTable->setRowCount(ntc.size());
    int i = 0;
    for (auto it = ntc.begin(); it != ntc.end(); ++it, ++i) {
      int count = it.value().toInt();
      double pct = d["node_count"].toInt() > 0 ? (count * 100.0 / d["node_count"].toInt()) : 0;
      m_nodeTypeTable->setItem(i, 0, new QTableWidgetItem(nodeTypeLabel(it.key())));
      m_nodeTypeTable->setItem(i, 1, new QTableWidgetItem(QString::number(count)));
      m_nodeTypeTable->setItem(i, 2, new QTableWidgetItem(QString("%1%").arg(pct, 0, 'f', 1)));
    }
    m_nodeTypeTable->setSortingEnabled(true);
    m_nodeTypeTable->resizeColumnsToContents();

    // Edge type distribution
    m_edgeTypeTable->setSortingEnabled(false);
    auto etc = d["edge_type_counts"].toObject();
    m_edgeTypeTable->setRowCount(etc.size());
    i = 0;
    for (auto it = etc.begin(); it != etc.end(); ++it, ++i) {
      m_edgeTypeTable->setItem(i, 0, new QTableWidgetItem(edgeTypeLabel(it.key())));
      m_edgeTypeTable->setItem(i, 1, new QTableWidgetItem(QString::number(it.value().toInt())));
    }
    m_edgeTypeTable->setSortingEnabled(true);
    m_edgeTypeTable->resizeColumnsToContents();
  });
}

void KnowledgeGraphPage::setupTacticTreeTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);
  l->setContentsMargins(8, 8, 8, 8);

  auto *header = new QLabel("战术 → 技术层级浏览（点击技术节点查看关联工具与缓解措施）");
  header->setStyleSheet("color: #6b7280; font-size: 13px; padding: 4px;");
  l->addWidget(header);

  auto *splitter = new QSplitter(Qt::Horizontal, parent);
  l->addWidget(splitter, 1);

  // Left: tactic→technique tree
  m_tacticTree = new QTreeWidget;
  UiUtil::EmptyHint::attach(m_tacticTree, QStringLiteral("暂无战术技术数据"));
  m_tacticTree->setHeaderLabels(QStringList{QStringLiteral("名称"), QStringLiteral("ID")});
  m_tacticTree->setColumnWidth(0, 280);
  m_tacticTree->setColumnWidth(1, 100);
  m_tacticTree->setStyleSheet("QTreeWidget { font-size: 13px; }");
  splitter->addWidget(m_tacticTree);

  // Right: detail panel
  m_tacticDetail = new QTextEdit;
  m_tacticDetail->setReadOnly(true);
  m_tacticDetail->setPlaceholderText("选择左侧技术，查看关联工具与缓解措施。");
  m_tacticDetail->setStyleSheet("QTextEdit { font-size: 13px; padding: 8px; }");
  splitter->addWidget(m_tacticDetail);

  splitter->setStretchFactor(0, 2);
  splitter->setStretchFactor(1, 3);

  connect(m_tacticTree, &QTreeWidget::itemClicked,
          this, &KnowledgeGraphPage::onTacticItemClicked);
}

void KnowledgeGraphPage::loadTacticTree() {
  if (!m_tacticTree) return;
  m_tacticTree->clear();
  m_tacticDetail->clear();

  // Load tactics
  m_api->get("/api/kg/tactics", 5000, [this](const QJsonObject &res) {
    const auto tactics = res["data"].toObject()["tactics"].toArray();
    if (tactics.isEmpty()) return;

    for (const auto &t : tactics) {
      const auto tac = t.toObject();
      const QString tacId = tac["id"].toString().replace("tactic:", "");
      const QString tacName = tac["zh_name"].toString().isEmpty()
          ? tac["name"].toString()
          : tac["zh_name"].toString();

      auto *tacItem = new QTreeWidgetItem(QStringList{
          QStringLiteral("%1 [%2]").arg(tacName, tacId), tacId});
      tacItem->setData(0, Qt::UserRole, QStringLiteral("tactic"));
      tacItem->setData(1, Qt::UserRole, tacId);
      tacItem->setForeground(0, QBrush(QColor("#3b82f6")));
      m_tacticTree->addTopLevelItem(tacItem);

      // Load techniques for this tactic (async, lazy expand)
      // Note: capture tacticId by value, NOT tacItem by pointer —
      // the tree may be cleared before the API call returns, dangling the pointer.
      const QString tacticId = tacId;
      m_api->get(QStringLiteral("/api/kg/techniques?tactic=%1&limit=200").arg(tacticId), 5000,
          [this, tacticId](const QJsonObject &techRes) {
            // Look up the tactic item by ID (safe if tree was cleared)
            QTreeWidgetItem *tacItem = nullptr;
            for (int i = 0; i < m_tacticTree->topLevelItemCount(); i++) {
              auto *item = m_tacticTree->topLevelItem(i);
              if (item && item->data(1, Qt::UserRole).toString() == tacticId) {
                tacItem = item;
                break;
              }
            }
            if (!tacItem) return;  // tree was cleared

            const auto techs = techRes["data"].toObject()["techniques"].toArray();
            for (const auto &tech : techs) {
              const auto tObj = tech.toObject();
              const QString techId = tObj["external_id"].toString();
              const QString techName = tObj["zh_name"].toString().isEmpty()
                  ? tObj["name"].toString()
                  : tObj["zh_name"].toString();

              auto *techItem = new QTreeWidgetItem(tacItem, QStringList{
                  QStringLiteral("%1 [%2]").arg(techName, techId), techId});
              techItem->setData(0, Qt::UserRole, QStringLiteral("technique"));
              techItem->setData(1, Qt::UserRole, techId);
              techItem->setForeground(0, QBrush(QColor("#ef4444")));
            }
          });
    }
  });
}

void KnowledgeGraphPage::onTacticItemClicked(QTreeWidgetItem *item, int /*column*/) {
  if (!item || !m_tacticDetail) return;
  const QString type = item->data(0, Qt::UserRole).toString();
  const QString nodeId = item->data(1, Qt::UserRole).toString();
  if (type != QStringLiteral("technique")) return;

  // Fetch technique node detail (includes edges: tools, mitigations, groups)
  m_api->get(QStringLiteral("/api/kg/node/technique:%1").arg(nodeId), 5000, [this, nodeId](const QJsonObject &res) {
    const auto data = res["data"].toObject();
    const auto node = data["node"].toObject();
    const auto outEdges = data["out_edges"].toArray();
    const auto inEdges = data["in_edges"].toArray();

    QString html = QStringLiteral("<h3 style='color:#ef4444;'>%1 [%2]</h3>")
        .arg(node["zh_name"].toString().isEmpty() ? node["name"].toString() : node["zh_name"].toString(), nodeId);

    if (!node["zh_desc"].toString().isEmpty()) {
      html += QStringLiteral("<p style='color:#6b7280;'>%1</p>").arg(node["zh_desc"].toString());
    } else if (!node["description"].toString().isEmpty()) {
      html += QStringLiteral("<p style='color:#6b7280;'>%1</p>").arg(node["description"].toString());
    }

    // Categorize edges
    QStringList tools, mitigations, groups, software;
    for (const auto &e : outEdges) {
      const auto edge = e.toObject();
      const QString eType = edge["type"].toString();
      const QString targetName = edge["target_zh_name"].toString().isEmpty()
          ? edge["target_name"].toString()
          : edge["target_zh_name"].toString();
      if (eType == QStringLiteral("MITIGATED_BY")) {
        mitigations << targetName;
      }
    }
    for (const auto &e : inEdges) {
      const auto edge = e.toObject();
      const QString eType = edge["type"].toString();
      const QString sourceName = edge["source_zh_name"].toString().isEmpty()
          ? edge["source_name"].toString()
          : edge["source_zh_name"].toString();
      const QString sourceType = edge["source_type"].toString();
      if (eType == QStringLiteral("MAPS_TO_TECHNIQUE") && sourceType == QStringLiteral("HexToolWrapper")) {
        tools << sourceName;
      } else if (eType == QStringLiteral("USES_TECHNIQUE")) {
        if (sourceType == QStringLiteral("AttackGroup")) groups << sourceName;
        else if (sourceType == QStringLiteral("AttackSoftware")) software << sourceName;
      }
    }

    if (!tools.isEmpty()) {
      html += QStringLiteral("<h4 style='color:#3b82f6;'>关联工具 (%1)</h4><ul>").arg(tools.size());
      for (const auto &t : tools) html += QStringLiteral("<li>%1</li>").arg(t);
      html += QStringLiteral("</ul>");
    }
    if (!mitigations.isEmpty()) {
      html += QStringLiteral("<h4 style='color:#22c55e;'>缓解措施 (%1)</h4><ul>").arg(mitigations.size());
      for (const auto &m : mitigations) html += QStringLiteral("<li>%1</li>").arg(m);
      html += QStringLiteral("</ul>");
    }
    if (!groups.isEmpty()) {
      html += QStringLiteral("<h4 style='color:#f59e0b;'>攻击组织 (%1)</h4><ul>").arg(groups.size());
      for (const auto &g : groups) html += QStringLiteral("<li>%1</li>").arg(g);
      html += QStringLiteral("</ul>");
    }
    if (!software.isEmpty()) {
      html += QStringLiteral("<h4 style='color:#8b5cf6;'>相关软件 (%1)</h4><ul>").arg(software.size());
      for (const auto &s : software) html += QStringLiteral("<li>%1</li>").arg(s);
      html += QStringLiteral("</ul>");
    }

    m_tacticDetail->setHtml(html);
  });
}

void KnowledgeGraphPage::loadGraph() {
  // Build types filter from checkboxes
  QStringList types;
  if (m_showTactics->isChecked()) types << "AttackTactic";
  if (m_showTechniques->isChecked()) types << "AttackTechnique";
  if (m_showWrappers->isChecked()) types << "HexToolWrapper";
  if (m_showGroups->isChecked()) types << "AttackGroup";
  if (m_showSoftware->isChecked()) types << "AttackSoftware";
  if (types.isEmpty()) types << "AttackTactic" << "AttackTechnique";

  // Limit nodes to keep force-directed layout fast (O(N²) per iteration)
  QString path = QString("/api/kg/graph?types=%1&limit=300").arg(types.join(","));
  m_api->get(path, 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    m_nodesCache = res["data"].toObject()["nodes"].toArray();
    m_edgesCache = res["data"].toObject()["edges"].toArray();
    renderGraph();
  });
}

void KnowledgeGraphPage::renderGraph() {
  m_scene->clear();
  m_nodeItems.clear();

  if (m_nodesCache.isEmpty()) return;

  const int N = m_nodesCache.size();

  // ── Build adjacency list for force-directed layout ────────────────
  QMap<QString, int> idToIdx;
  for (int i = 0; i < N; i++) {
    idToIdx[m_nodesCache[i].toObject()["id"].toString()] = i;
  }
  QVector<QVector<int>> adj(N);
  for (int i = 0; i < m_edgesCache.size(); i++) {
    auto e = m_edgesCache[i].toObject();
    int si = idToIdx.value(e["source"].toString(), -1);
    int ti = idToIdx.value(e["target"].toString(), -1);
    if (si >= 0 && ti >= 0) { adj[si].append(ti); adj[ti].append(si); }
  }

  // ── Fruchterman-Reingold force-directed layout ────────────────────
  // Initialize positions: group by type in concentric rings
  QMap<QString, QList<int>> typeGroups;
  for (int i = 0; i < N; i++) {
    typeGroups[m_nodesCache[i].toObject()["type"].toString()].append(i);
  }

  const double area = qMax(800.0 * 800.0, static_cast<double>(N) * 8000.0);
  const double optLen = qSqrt(area / N) * 0.8;  // optimal spring length
  const double initRadius = optLen * 1.5;

  QVector<QPointF> pos(N), disp(N);
  // Initial placement: spread by type in sectors
  double angleOff = 0.0;
  for (auto it = typeGroups.begin(); it != typeGroups.end(); ++it) {
    const auto &idxs = it.value();
    double sector = 360.0 * idxs.size() / N;
    for (int j = 0; j < idxs.size(); j++) {
      double angle = qDegreesToRadians(angleOff + sector * (j + 0.5) / idxs.size());
      // Slight randomness to break symmetry
      double r = initRadius * (0.7 + 0.6 * (j % 3) / 2.0);
      pos[idxs[j]] = QPointF(r * qCos(angle), r * qSin(angle));
    }
    angleOff += sector;
  }

  // Iterative force simulation with grid-accelerated repulsion
  // Adaptive iterations: fewer for large graphs
  const int iterations = N > 200 ? 60 : (N > 100 ? 80 : 120);
  double temperature = optLen * 2.0;
  const double cooling = temperature / (iterations + 1);
  const double gridCellSize = optLen * 1.5;  // grid cell = 1.5× optimal length

  for (int iter = 0; iter < iterations; iter++) {
    for (int i = 0; i < N; i++) disp[i] = QPointF(0, 0);

    // ── Grid-accelerated repulsive forces ────────────────────────────
    // Build spatial grid
    QMap<QPair<int,int>, QVector<int>> grid;
    for (int i = 0; i < N; i++) {
      int gx = static_cast<int>(pos[i].x() / gridCellSize);
      int gy = static_cast<int>(pos[i].y() / gridCellSize);
      grid[{gx, gy}].append(i);
    }
    // For each node, check own cell + 8 neighbors
    for (int i = 0; i < N; i++) {
      int gx = static_cast<int>(pos[i].x() / gridCellSize);
      int gy = static_cast<int>(pos[i].y() / gridCellSize);
      for (int dx = -1; dx <= 1; dx++) {
        for (int dy = -1; dy <= 1; dy++) {
          auto it = grid.find({gx + dx, gy + dy});
          if (it == grid.end()) continue;
          for (int j : it.value()) {
            if (j <= i) continue;
            double ddx = pos[i].x() - pos[j].x();
            double ddy = pos[i].y() - pos[j].y();
            double dist = qMax(1.0, qSqrt(ddx * ddx + ddy * ddy));
            double force = (optLen * optLen) / dist;
            double fx = (ddx / dist) * force;
            double fy = (ddy / dist) * force;
            disp[i] += QPointF(fx, fy);
            disp[j] -= QPointF(fx, fy);
          }
        }
      }
    }

    // Attractive forces along edges
    for (int i = 0; i < N; i++) {
      for (int j : adj[i]) {
        if (j <= i) continue;
        double dx = pos[i].x() - pos[j].x();
        double dy = pos[i].y() - pos[j].y();
        double dist = qMax(1.0, qSqrt(dx * dx + dy * dy));
        double force = (dist * dist) / optLen;
        double fx = (dx / dist) * force;
        double fy = (dy / dist) * force;
        disp[i] -= QPointF(fx, fy);
        disp[j] += QPointF(fx, fy);
      }
    }
    // Apply displacement capped by temperature
    for (int i = 0; i < N; i++) {
      double d = qMax(1.0, qSqrt(disp[i].x() * disp[i].x() + disp[i].y() * disp[i].y()));
      double cap = qMin(d, temperature);
      pos[i] += QPointF(disp[i].x() / d * cap, disp[i].y() / d * cap);
    }
    temperature -= cooling;
  }

  // Build position map
  QMap<QString, QPointF> nodePositions;
  for (int i = 0; i < N; i++) {
    nodePositions[m_nodesCache[i].toObject()["id"].toString()] = pos[i];
  }

  // ── Draw edges first (below nodes) ────────────────────────────────
  for (int i = 0; i < m_edgesCache.size(); i++) {
    auto e = m_edgesCache[i].toObject();
    QString src = e["source"].toString();
    QString tgt = e["target"].toString();
    if (!nodePositions.contains(src) || !nodePositions.contains(tgt)) continue;

    auto *line = new QGraphicsLineItem(
      nodePositions[src].x(), nodePositions[src].y(),
      nodePositions[tgt].x(), nodePositions[tgt].y());

    QString edgeType = e["type"].toString();
    QColor edgeColor = (edgeType == "MAPS_TO_TECHNIQUE") ? QColor(239, 68, 68, 50) :
                       (edgeType == "BELONGS_TO_TACTIC") ? QColor(245, 158, 11, 50) :
                       QColor(148, 163, 184, 30);
    line->setPen(QPen(edgeColor, 1.2));
    line->setZValue(0.5);
    m_scene->addItem(line);
  }

  // ── Draw nodes ────────────────────────────────────────────────────
  for (int i = 0; i < m_nodesCache.size(); i++) {
    auto n = m_nodesCache[i].toObject();
    QString id = n["id"].toString();
    if (!nodePositions.contains(id)) continue;

    QPointF p = nodePositions[id];
    QString type = n["type"].toString();
    QColor color(nodeTypeColor(type));

    // Larger nodes for tactics, smaller for tools
    double nodeSize = (type == "AttackTactic") ? 14.0 :
                      (type == "AttackTechnique") ? 10.0 :
                      (type == "HexToolWrapper") ? 8.0 : 9.0;
    auto *ellipse = new QGraphicsEllipseItem(-nodeSize, -nodeSize, nodeSize * 2, nodeSize * 2);
    ellipse->setPos(p);
    ellipse->setBrush(QBrush(color));
    ellipse->setPen(QPen(color.darker(120), 1.5));
    ellipse->setToolTip(QString("%1\n类型: %2\nID: %3")
      .arg(zhOrDefault(n, "name"), nodeTypeLabel(type), id));
    ellipse->setData(0, id);
    ellipse->setFlag(QGraphicsItem::ItemIsSelectable);
    ellipse->setZValue(2.0);
    m_scene->addItem(ellipse);
    m_nodeItems[id] = ellipse;

    // Label — offset to avoid overlap with node
    auto *label = new QGraphicsSimpleTextItem(zhOrDefault(n, "name"));
    label->setPos(p.x() + nodeSize + 4, p.y() - 6);
    label->setBrush(QBrush(QColor("#e2e8f0")));
    QFont f = label->font();
    f.setPointSize(7);
    label->setFont(f);
    label->setZValue(2.5);
    m_scene->addItem(label);
  }

  m_scene->setSceneRect(m_scene->itemsBoundingRect().adjusted(-80, -80, 80, 80));
  m_view->fitInView(m_scene->sceneRect(), Qt::KeepAspectRatio);
}

void KnowledgeGraphPage::onNodeClicked(const QString &nodeId) {
  if (nodeId.isEmpty()) return;
  const bool forSearch = m_subTabs->currentIndex() == 4;
  m_api->get("/api/kg/node/" + nodeId, 5000, [this, forSearch](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    showNodeDetail(res["data"].toObject(), forSearch);
  });
}

void KnowledgeGraphPage::showNodeDetail(const QJsonObject &detail, bool forSearch) {
  auto node = detail["node"].toObject();
  QString type = node["type"].toString();
  QString color = nodeTypeColor(type);

  if (!forSearch) m_detailTitle->setText(QString("<span style='color:%1'>%2</span> — %3")
    .arg(color, nodeTypeLabel(type), zhOrDefault(node, "name")));

  QStringList lines;
  lines << QString("编号：%1").arg(node["id"].toString());
  lines << QString("来源: %1").arg(node["source_system"].toString());
  if (!node["risk_level"].toString().isEmpty()) {
    QString risk = node["risk_level"].toString();
    if (risk == "high") risk = "高";
    else if (risk == "medium") risk = "中";
    else if (risk == "low") risk = "低";
    else if (risk == "critical") risk = "严重";
    lines << QString("风险: %1").arg(risk);
  }
  // Prefer Chinese description, fall back to English
  QString desc = node["zh_desc"].toString().isEmpty()
    ? node["description"].toString()
    : node["zh_desc"].toString();
  if (!desc.isEmpty())
    lines << "" << desc.left(500);

  auto outEdges = detail["out_edges"].toArray();
  if (!outEdges.isEmpty()) {
    lines << "" << QString("出边 (%1):").arg(outEdges.size());
    for (int i = 0; i < qMin(outEdges.size(), 20); i++) {
      auto e = outEdges[i].toObject();
      QString targetDisplay = e["target_zh_name"].toString().isEmpty()
        ? e["target_name"].toString()
        : e["target_zh_name"].toString();
      lines << QString("  → %1 [%2]").arg(targetDisplay, edgeTypeLabel(e["type"].toString()));
    }
  }

  auto inEdges = detail["in_edges"].toArray();
  if (!inEdges.isEmpty()) {
    lines << "" << QString("入边 (%1):").arg(inEdges.size());
    for (int i = 0; i < qMin(inEdges.size(), 20); i++) {
      auto e = inEdges[i].toObject();
      QString sourceDisplay = e["source_zh_name"].toString().isEmpty()
        ? e["source_name"].toString()
        : e["source_zh_name"].toString();
      lines << QString("  ← %1 [%2]").arg(sourceDisplay, edgeTypeLabel(e["type"].toString()));
    }
  }

  if (forSearch) {
    m_searchDetail->setPlainText(zhOrDefault(node, "name") + "\n" + lines.join("\n"));
  } else {
    m_detailText->setPlainText(lines.join("\n"));
  }
}

void KnowledgeGraphPage::loadMappings() {
  m_api->get("/api/kg/mappings?limit=1000", 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto mappings = res["data"].toObject()["mappings"].toArray();
    m_mappingTable->setSortingEnabled(false);
    m_mappingTable->setRowCount(mappings.size());
    for (int i = 0; i < mappings.size(); i++) {
      auto m = mappings[i].toObject();
      m_mappingTable->setItem(i, 0, new QTableWidgetItem(
        m["source_zh_name"].toString().isEmpty() ? m["source_name"].toString() : m["source_zh_name"].toString()));
      m_mappingTable->setItem(i, 1, new QTableWidgetItem(m["target_external_id"].toString()));
      m_mappingTable->setItem(i, 2, new QTableWidgetItem(
        m["target_zh_name"].toString().isEmpty() ? m["target_name"].toString() : m["target_zh_name"].toString()));
      QString conf = m["confidence"].toString();
      if (conf == "high") conf = "高";
      else if (conf == "medium") conf = "中";
      else if (conf == "low") conf = "低";
      m_mappingTable->setItem(i, 3, new QTableWidgetItem(conf));
    }
    m_mappingTable->setSortingEnabled(true);
  });
}

void KnowledgeGraphPage::onMappingSearch() {
  QString q = m_mappingSearchEdit->text().trimmed().toLower();
  QString conf = m_mappingConfidenceFilter->currentText();
  if (conf == "全部") conf = "";
  else if (conf == "高") conf = "high";
  else if (conf == "中") conf = "medium";
  else if (conf == "低") conf = "low";

  QString path = "/api/kg/mappings?limit=1000";
  if (!conf.isEmpty()) path += "&confidence=" + conf;
  m_api->get(path, 10000, [this, q](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto mappings = res["data"].toObject()["mappings"].toArray();

    // Client-side text filter
    QJsonArray filtered;
    for (int i = 0; i < mappings.size(); i++) {
      auto m = mappings[i].toObject();
      if (q.isEmpty() ||
          m["source_name"].toString().toLower().contains(q) ||
          m["target_name"].toString().toLower().contains(q) ||
          m["target_external_id"].toString().toLower().contains(q)) {
        filtered.append(m);
      }
    }

    m_mappingTable->setSortingEnabled(false);
    m_mappingTable->setRowCount(filtered.size());
    for (int i = 0; i < filtered.size(); i++) {
      auto m = filtered[i].toObject();
      m_mappingTable->setItem(i, 0, new QTableWidgetItem(
        m["source_zh_name"].toString().isEmpty() ? m["source_name"].toString() : m["source_zh_name"].toString()));
      m_mappingTable->setItem(i, 1, new QTableWidgetItem(m["target_external_id"].toString()));
      m_mappingTable->setItem(i, 2, new QTableWidgetItem(
        m["target_zh_name"].toString().isEmpty() ? m["target_name"].toString() : m["target_zh_name"].toString()));
      QString conf = m["confidence"].toString();
      if (conf == "high") conf = "高";
      else if (conf == "medium") conf = "中";
      else if (conf == "low") conf = "低";
      m_mappingTable->setItem(i, 3, new QTableWidgetItem(conf));
    }
    m_mappingTable->setSortingEnabled(true);
  });
}

void KnowledgeGraphPage::onSearch() {
  QString q = m_searchEdit->text().trimmed();
  if (q.isEmpty()) return;
  QString type = m_searchTypeFilter->currentData().toString();
  QString path = QString("/api/kg/search?q=%1&limit=100").arg(q);
  if (!type.isEmpty()) path += "&type=" + type;

  m_api->get(path, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto results = res["data"].toObject()["results"].toArray();
    m_searchDetail->clear();
    m_searchTable->setSortingEnabled(false);
    m_searchTable->setRowCount(results.size());
    for (int i = 0; i < results.size(); i++) {
      auto r = results[i].toObject();
      auto *nameItem = new QTableWidgetItem(zhOrDefault(r, "name"));
      nameItem->setData(Qt::UserRole, r["id"].toString());
      m_searchTable->setItem(i, 0, nameItem);
      m_searchTable->setItem(i, 1, new QTableWidgetItem(nodeTypeLabel(r["type"].toString())));
      m_searchTable->setItem(i, 2, new QTableWidgetItem(r["source_system"].toString()));
      QString risk = r["risk_level"].toString();
      if (risk == "high") risk = "高";
      else if (risk == "medium") risk = "中";
      else if (risk == "low") risk = "低";
      else if (risk == "critical") risk = "严重";
      m_searchTable->setItem(i, 3, new QTableWidgetItem(risk));
    }
    m_searchTable->setSortingEnabled(true);
  });
}
