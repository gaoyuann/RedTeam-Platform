#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QGraphicsScene>
#include <QGraphicsView>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QCheckBox>
#include <QTextEdit>
#include <QJsonArray>
#include <QJsonObject>

class ApiClient;

class SystemPage : public QWidget {
  Q_OBJECT
public:
  explicit SystemPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

private slots:
  void onRefreshUsers();
  void onAddUser();
  void onDeleteUser();
  void onRefreshClasses();
  void onAddClass();
  void onDeleteClass();
  void onRefreshConfig();
  void onSaveConfig();
  void onConfigDoubleClicked(int row, int col);
  void onRefreshAssignments();
  void onRefreshSubmissions();
  void onRefreshKnowledgeGraph();
  void onKgSubTabChanged(int index);
  void onKgNodeClicked(const QString &nodeId);
  void onKgSearch();
  void onKgMappingSearch();

private:
  void setupUI();
  void setupKgStatsTab(QWidget *parent);
  void setupKgGraphTab(QWidget *parent);
  void setupKgMappingsTab(QWidget *parent);
  void setupKgNodesTab(QWidget *parent);
  void loadKgStats();
  void loadKgGraph();
  void loadKgMappings();
  void renderKgGraph();
  void showKgNodeDetail(const QJsonObject &detail);
  QString kgNodeTypeColor(const QString &type) const;
  QString kgNodeTypeLabel(const QString &type) const;
  QString kgEdgeTypeLabel(const QString &type) const;
  QString zhOrDefault(const QJsonObject &obj, const QString &field) const;

  ApiClient *m_api;
  QTabWidget *m_tabs;

  // Users tab
  QTableWidget *m_userTable;
  QLineEdit *m_newUsername;
  QLineEdit *m_newPassword;
  QComboBox *m_newRole;

  // Classes tab
  QTableWidget *m_classTable;
  QLineEdit *m_newClassName;
  QLineEdit *m_newClassTeacher;
  QPushButton *m_addClassBtn;
  QPushButton *m_delClassBtn;

  // Config tab
  QTableWidget *m_configTable;
  QPushButton *m_configSaveBtn;

  // Assignments tab
  QTableWidget *m_assignmentTable;

  // Submissions tab
  QTableWidget *m_submissionTable;

  // ── Knowledge Graph sub-tabs ─────────────────────────────────────
  QTabWidget *m_kgSubTabs;

  // Stats sub-tab
  QLabel *m_kgNodeCountLabel;
  QLabel *m_kgEdgeCountLabel;
  QLabel *m_kgVersionLabel;
  QTableWidget *m_kgNodeTypeTable;
  QTableWidget *m_kgEdgeTypeTable;

  // Graph sub-tab
  QGraphicsScene *m_kgScene;
  QGraphicsView *m_kgView;
  QCheckBox *m_kgShowTactics;
  QCheckBox *m_kgShowTechniques;
  QCheckBox *m_kgShowWrappers;
  QCheckBox *m_kgShowGroups;
  QCheckBox *m_kgShowSoftware;
  QLabel *m_kgDetailTitle;
  QTextEdit *m_kgDetailText;
  QJsonArray m_kgNodesCache;
  QJsonArray m_kgEdgesCache;
  QMap<QString, QGraphicsItem*> m_kgNodeItems;

  // Mappings sub-tab
  QLineEdit *m_kgMappingSearchEdit;
  QComboBox *m_kgMappingConfidenceFilter;
  QTableWidget *m_kgMappingTable;

  // Nodes search sub-tab
  QLineEdit *m_kgSearchEdit;
  QComboBox *m_kgSearchTypeFilter;
  QTableWidget *m_kgSearchTable;
  QTextEdit *m_kgSearchDetail;
};
