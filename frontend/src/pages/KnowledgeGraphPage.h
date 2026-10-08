#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QTextEdit>
#include <QCheckBox>
#include <QGraphicsScene>
#include <QGraphicsView>
#include <QGraphicsItem>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>

class ApiClient;

class KnowledgeGraphPage : public QWidget {
  Q_OBJECT
public:
  explicit KnowledgeGraphPage(ApiClient *api, QWidget *parent = nullptr);

public slots:
  void refresh();

private slots:
  void onSubTabChanged(int index);
  void onNodeClicked(const QString &nodeId);
  void onSearch();
  void onMappingSearch();
  void onTacticItemClicked(QTreeWidgetItem *item, int column);

private:
  void setupUI();
  void setupStatsTab(QWidget *parent);
  void setupGraphTab(QWidget *parent);
  void setupMappingsTab(QWidget *parent);
  void setupNodesTab(QWidget *parent);
  void setupTacticTreeTab(QWidget *parent);
  void loadStats();
  void loadGraph();
  void loadMappings();
  void loadTacticTree();
  void renderGraph();
  void showNodeDetail(const QJsonObject &detail, bool forSearch);
  QString nodeTypeColor(const QString &type) const;
  QString nodeTypeLabel(const QString &type) const;
  QString edgeTypeLabel(const QString &type) const;
  QString zhOrDefault(const QJsonObject &obj, const QString &field) const;

  ApiClient *m_api;

  // Sub-tabs container
  QTabWidget *m_subTabs;

  // Tactic tree sub-tab
  QTreeWidget *m_tacticTree = nullptr;
  QTextEdit *m_tacticDetail = nullptr;

  // Stats sub-tab
  QLabel *m_nodeCountLabel;
  QLabel *m_edgeCountLabel;
  QLabel *m_versionLabel;
  QTableWidget *m_nodeTypeTable;
  QTableWidget *m_edgeTypeTable;

  // Graph sub-tab
  QGraphicsScene *m_scene;
  QGraphicsView *m_view;
  QCheckBox *m_showTactics;
  QCheckBox *m_showTechniques;
  QCheckBox *m_showWrappers;
  QCheckBox *m_showGroups;
  QCheckBox *m_showSoftware;
  QLabel *m_detailTitle;
  QTextEdit *m_detailText;
  QJsonArray m_nodesCache;
  QJsonArray m_edgesCache;
  QMap<QString, QGraphicsItem*> m_nodeItems;

  // Mappings sub-tab
  QLineEdit *m_mappingSearchEdit;
  QComboBox *m_mappingConfidenceFilter;
  QTableWidget *m_mappingTable;

  // Nodes search sub-tab
  QLineEdit *m_searchEdit;
  QComboBox *m_searchTypeFilter;
  QTableWidget *m_searchTable;
  QTextEdit *m_searchDetail;
};
