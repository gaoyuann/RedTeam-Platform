#include "SystemPage.h"
#include "../Theme.h"
#include "../ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QHeaderView>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QScrollArea>
#include <QFrame>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QSplitter>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QWheelEvent>
#include <QCheckBox>
#include <QGraphicsItem>
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

SystemPage::SystemPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent) : QWidget(parent), m_api(api) {
  setupUI();
  onRefreshUsers();
  onRefreshClasses();
  onRefreshConfig();
  onRefreshAssignments();
  onRefreshSubmissions();
  onRefreshKnowledgeGraph();
}

void SystemPage::setupUI() {
  setStyleSheet(Theme::PageStyle);
  auto *scrollArea = new QScrollArea(this);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);
  m_tabs = new QTabWidget;

  // ── Users tab ─────────────────────────────────────────────────────
  auto *userW = new QWidget;
  auto *userL = new QVBoxLayout(userW);
  m_userTable = new QTableWidget(0, 5);
  m_userTable->setHorizontalHeaderLabels({"用户名", "显示名", "角色", "状态", "创建时间"});
  m_userTable->setAlternatingRowColors(true);
  m_userTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_userTable->setSortingEnabled(true);
  m_userTable->setContextMenuPolicy(Qt::CustomContextMenu);
  userL->addWidget(m_userTable);

  auto *addH = new QHBoxLayout;
  m_newUsername = new QLineEdit;
  m_newUsername->setPlaceholderText("用户名");
  m_newPassword = new QLineEdit;
  m_newPassword->setPlaceholderText("密码");
  m_newPassword->setEchoMode(QLineEdit::Password);
  m_newRole = new QComboBox;
  m_newRole->addItem("管理员", "admin");
  m_newRole->addItem("教师", "teacher");
  m_newRole->addItem("学生", "student");
  m_newRole->addItem("操作员", "operator");
  m_newRole->addItem("观察者", "viewer");
  auto *addBtn = new QPushButton("添加");
  addBtn->setProperty("primary", true);
  auto *delBtn = new QPushButton("删除选中");
  delBtn->setProperty("danger", true);
  addH->addWidget(m_newUsername);
  addH->addWidget(m_newPassword);
  addH->addWidget(m_newRole);
  addH->addWidget(addBtn);
  addH->addWidget(delBtn);
  userL->addLayout(addH);
  connect(addBtn, &QPushButton::clicked, this, &SystemPage::onAddUser);
  connect(delBtn, &QPushButton::clicked, this, &SystemPage::onDeleteUser);

  m_tabs->addTab(userW, "用户管理");

  // ── Classes tab (now with CRUD) ──────────────────────────────────
  auto *classW = new QWidget;
  auto *classL = new QVBoxLayout(classW);
  m_classTable = new QTableWidget(0, 5);
  m_classTable->setHorizontalHeaderLabels({"班级ID", "名称", "教师", "加入码", "创建时间"});
  m_classTable->setAlternatingRowColors(true);
  m_classTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_classTable->setSortingEnabled(true);
  m_classTable->setContextMenuPolicy(Qt::CustomContextMenu);
  classL->addWidget(m_classTable);

  auto *classAddH = new QHBoxLayout;
  m_newClassName = new QLineEdit;
  m_newClassName->setPlaceholderText("班级名称");
  m_newClassTeacher = new QLineEdit;
  m_newClassTeacher->setPlaceholderText("教师用户名");
  m_addClassBtn = new QPushButton("添加班级");
  m_addClassBtn->setProperty("primary", true);
  m_delClassBtn = new QPushButton("删除选中");
  m_delClassBtn->setProperty("danger", true);
  classAddH->addWidget(m_newClassName);
  classAddH->addWidget(m_newClassTeacher);
  classAddH->addWidget(m_addClassBtn);
  classAddH->addWidget(m_delClassBtn);
  classL->addLayout(classAddH);
  connect(m_addClassBtn, &QPushButton::clicked, this, &SystemPage::onAddClass);
  connect(m_delClassBtn, &QPushButton::clicked, this, &SystemPage::onDeleteClass);

  auto *classRefresh = new QPushButton("刷新");
  classL->addWidget(classRefresh);
  connect(classRefresh, &QPushButton::clicked, this, &SystemPage::onRefreshClasses);
  m_tabs->addTab(classW, "班级管理");

  // ── Config tab (now editable) ────────────────────────────────────
  auto *cfgW = new QWidget;
  auto *cfgL = new QVBoxLayout(cfgW);
  auto *cfgHint = new QLabel("双击配置值可编辑，编辑后点击保存");
  cfgHint->setStyleSheet("color:#64748b; font-size:13px;");
  cfgL->addWidget(cfgHint);
  m_configTable = new QTableWidget(0, 3);
  m_configTable->setHorizontalHeaderLabels({"配置项", "值", "类别"});
  m_configTable->setAlternatingRowColors(true);
  m_configTable->setSortingEnabled(true);
  m_configTable->setContextMenuPolicy(Qt::CustomContextMenu);
  cfgL->addWidget(m_configTable);
  m_configSaveBtn = new QPushButton("保存修改");
  m_configSaveBtn->setProperty("primary", true);
  cfgL->addWidget(m_configSaveBtn);
  connect(m_configSaveBtn, &QPushButton::clicked, this, &SystemPage::onSaveConfig);
  auto *cfgRefresh = new QPushButton("刷新");
  cfgL->addWidget(cfgRefresh);
  connect(cfgRefresh, &QPushButton::clicked, this, &SystemPage::onRefreshConfig);
  connect(m_configTable, &QTableWidget::cellDoubleClicked, this, &SystemPage::onConfigDoubleClicked);
  m_tabs->addTab(cfgW, "系统配置");

  // ── Assignments tab ──────────────────────────────────────────────
  auto *asgnW = new QWidget;
  auto *asgnL = new QVBoxLayout(asgnW);
  auto *asgnLabel = new QLabel("任务管理"); asgnLabel->setStyleSheet(Theme::SectionStyle);
  asgnL->addWidget(asgnLabel);
  m_assignmentTable = new QTableWidget(0, 6);
  m_assignmentTable->setHorizontalHeaderLabels({"任务ID", "班级", "标题", "Playbook", "截止时间", "创建时间"});
  m_assignmentTable->setAlternatingRowColors(true);
  m_assignmentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_assignmentTable->setSortingEnabled(true);
  m_assignmentTable->setContextMenuPolicy(Qt::CustomContextMenu);
  asgnL->addWidget(m_assignmentTable);

  auto *asgnSubLabel = new QLabel("提交记录"); asgnSubLabel->setStyleSheet(Theme::SectionStyle);
  asgnL->addWidget(asgnSubLabel);
  m_submissionTable = new QTableWidget(0, 6);
  m_submissionTable->setHorizontalHeaderLabels({"提交ID", "任务", "学生", "Run ID", "成绩", "提交时间"});
  m_submissionTable->setAlternatingRowColors(true);
  m_submissionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_submissionTable->setSortingEnabled(true);
  m_submissionTable->setContextMenuPolicy(Qt::CustomContextMenu);
  asgnL->addWidget(m_submissionTable);

  auto *asgnRefresh = new QPushButton("刷新");
  asgnL->addWidget(asgnRefresh);
  connect(asgnRefresh, &QPushButton::clicked, this, [this]() { onRefreshAssignments(); onRefreshSubmissions(); });
  m_tabs->addTab(asgnW, "任务管理");

  // ── Knowledge Graph tab (4 sub-views) ───────────────────────────
  auto *kgW = new QWidget;
  auto *kgL = new QVBoxLayout(kgW);
  kgL->setContentsMargins(0, 0, 0, 0);

  auto *kgHeader = new QHBoxLayout;
  auto *kgTitle = new QLabel("攻防知识图谱");
  kgTitle->setStyleSheet(Theme::SectionStyle);
  kgHeader->addWidget(kgTitle);
  auto *kgRefresh = new QPushButton("刷新");
  kgHeader->addStretch();
  kgHeader->addWidget(kgRefresh);
  kgL->addLayout(kgHeader);
  connect(kgRefresh, &QPushButton::clicked, this, &SystemPage::onRefreshKnowledgeGraph);

  m_kgSubTabs = new QTabWidget;

  // Sub-tab 1: Stats
  auto *statsW = new QWidget;
  setupKgStatsTab(statsW);
  m_kgSubTabs->addTab(statsW, "统计");

  // Sub-tab 2: Graph
  auto *graphW = new QWidget;
  setupKgGraphTab(graphW);
  m_kgSubTabs->addTab(graphW, "图谱");

  // Sub-tab 3: Mappings
  auto *mapW = new QWidget;
  setupKgMappingsTab(mapW);
  m_kgSubTabs->addTab(mapW, "映射关系");

  // Sub-tab 4: Node search
  auto *nodesW = new QWidget;
  setupKgNodesTab(nodesW);
  m_kgSubTabs->addTab(nodesW, "节点搜索");

  kgL->addWidget(m_kgSubTabs);
  connect(m_kgSubTabs, &QTabWidget::currentChanged, this, &SystemPage::onKgSubTabChanged);
  m_tabs->addTab(kgW, "知识图谱");

  // ── Right-click menus ────────────────────────────────────────────────
  connect(m_userTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_userTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_userTable->viewport()->mapToGlobal(pos));
  });
  connect(m_classTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_classTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_classTable->viewport()->mapToGlobal(pos));
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
  connect(m_assignmentTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_assignmentTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_assignmentTable->viewport()->mapToGlobal(pos));
  });
  connect(m_submissionTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_submissionTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_submissionTable->viewport()->mapToGlobal(pos));
  });

  layout->addWidget(m_tabs);

  scrollArea->setWidget(container);
  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->addWidget(scrollArea);
}

// ── Users ────────────────────────────────────────────────────────────
void SystemPage::onRefreshUsers() {
  m_api->get("/api/users", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_userTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto u = arr[i].toObject();
      m_userTable->setItem(i, 0, new QTableWidgetItem(u["username"].toString()));
      m_userTable->setItem(i, 1, new QTableWidgetItem(u["display_name"].toString()));
      // Translate role to Chinese
      QString role = u["role"].toString();
      QString roleCn;
      if (role == "admin") roleCn = "管理员";
      else if (role == "teacher") roleCn = "教师";
      else if (role == "student") roleCn = "学生";
      else if (role == "operator") roleCn = "操作员";
      else if (role == "viewer") roleCn = "观察者";
      else roleCn = role;
      auto *roleItem = new QTableWidgetItem(roleCn);
      roleItem->setData(Qt::UserRole, role);  // keep original for editing
      m_userTable->setItem(i, 2, roleItem);
      m_userTable->setItem(i, 3, new QTableWidgetItem(u["is_active"].toInt() ? "活跃" : "禁用"));
      m_userTable->setItem(i, 4, new QTableWidgetItem(u["created_at"].toString()));
    }
    m_userTable->resizeColumnsToContents();
    m_userTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void SystemPage::onAddUser() {
  QString user = m_newUsername->text().trimmed();
  QString pass = m_newPassword->text().trimmed();
  if (user.isEmpty() || pass.isEmpty()) return;
  QJsonObject body;
  body["username"] = user;
  body["password"] = pass;
  body["role"] = m_newRole->currentData().toString();
  m_api->post("/api/users", body, 5000, [this](const QJsonObject &) {
    m_newUsername->clear();
    m_newPassword->clear();
    onRefreshUsers();
  });
}

void SystemPage::onDeleteUser() {
  int row = m_userTable->currentRow();
  if (row < 0) return;
  auto *item = m_userTable->item(row, 0);
  if (!item) return;
  QString username = item->text();
  auto reply = QMessageBox::question(this->window(), "确认删除",
    QString("确定要删除用户 \"%1\" 吗？此操作不可撤销。").arg(username),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;
  m_api->del("/api/users/" + username, 5000, [this](const QJsonObject &) {
    onRefreshUsers();
  });
}

// ── Classes (now with CRUD) ─────────────────────────────────────────
void SystemPage::onRefreshClasses() {
  m_api->get("/api/classes", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_classTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      m_classTable->setItem(i, 0, new QTableWidgetItem(c["class_id"].toString()));
      m_classTable->setItem(i, 1, new QTableWidgetItem(c["name"].toString()));
      m_classTable->setItem(i, 2, new QTableWidgetItem(c["teacher_sub"].toString()));
      m_classTable->setItem(i, 3, new QTableWidgetItem(c["join_code"].toString().isEmpty() ? "—" : c["join_code"].toString()));
      m_classTable->setItem(i, 4, new QTableWidgetItem(c["created_at"].toString()));
    }
    m_classTable->resizeColumnsToContents();
    m_classTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void SystemPage::onAddClass() {
  QString name = m_newClassName->text().trimmed();
  if (name.isEmpty()) return;
  QJsonObject body;
  body["name"] = name;
  body["teacher_sub"] = m_newClassTeacher->text().trimmed();
  m_api->post("/api/classes", body, 5000, [this](const QJsonObject &) {
    m_newClassName->clear();
    m_newClassTeacher->clear();
    onRefreshClasses();
  });
}

void SystemPage::onDeleteClass() {
  int row = m_classTable->currentRow();
  if (row < 0) return;
  auto *item = m_classTable->item(row, 0);
  if (!item) return;
  QString classId = item->text();
  auto reply = QMessageBox::question(this->window(), "确认删除",
    QString("确定要删除班级 \"%1\" 吗？此操作不可撤销。").arg(classId),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;
  m_api->del("/api/classes/" + classId, 5000, [this](const QJsonObject &) {
    onRefreshClasses();
  });
}

// ── Config (now editable) ────────────────────────────────────────────
void SystemPage::onSaveConfig() {
  // Save all modified config rows
  m_configSaveBtn->setEnabled(false);
  int rows = m_configTable->rowCount();
  for (int i = 0; i < rows; i++) {
    auto *keyItem = m_configTable->item(i, 0);
    auto *valueItem = m_configTable->item(i, 1);
    auto *catItem = m_configTable->item(i, 2);
    if (!keyItem || !valueItem || !catItem) continue;

    QString category = catItem->text();
    QString key = keyItem->text();
    QString value = valueItem->text();

    QJsonObject body;
    QJsonParseError err;
    auto doc = QJsonDocument::fromJson(value.toUtf8(), &err);
    if (err.error == QJsonParseError::NoError) {
      body["config_value"] = doc.isArray() ? QJsonValue(doc.array()) : QJsonValue(doc.object());
    } else {
      body["config_value"] = value;
    }
    body["description"] = "Updated via SystemPage save";

    m_api->put("/api/config/" + category + "/" + key, body, 5000, nullptr);
  }
  // Refresh after all saves dispatched
  QTimer::singleShot(500, this, [this]() {
    m_configSaveBtn->setEnabled(true);
    onRefreshConfig();
  });
}

void SystemPage::onRefreshConfig() {
  m_api->get("/api/config", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_configTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      m_configTable->setItem(i, 0, new QTableWidgetItem(c["config_key"].toString()));
      // Format config_value: if it's a JSON object, show key fields; otherwise show as-is
      QString valStr = c["config_value"].toString();
      if (!valStr.isEmpty()) {
        QJsonParseError err;
        auto doc = QJsonDocument::fromJson(valStr.toUtf8(), &err);
        if (err.error == QJsonParseError::NoError) {
          if (doc.isObject()) {
            // For LLM config, show key fields in one line
            auto obj = doc.object();
            QStringList parts;
            if (obj.contains("key")) parts << QString("key=%1****").arg(obj["key"].toString().left(8));
            if (obj.contains("url")) parts << QString("url=%1").arg(obj["url"].toString());
            if (obj.contains("model")) parts << QString("model=%1").arg(obj["model"].toString());
            if (!parts.isEmpty()) {
              valStr = parts.join(", ");
            } else {
              valStr = QString::fromUtf8(doc.toJson(QJsonDocument::Indented)).left(200);
            }
          } else if (doc.isArray()) {
            valStr = QString("[%1 items]").arg(doc.array().size());
          }
        }
      }
      m_configTable->setItem(i, 1, new QTableWidgetItem(valStr));
      m_configTable->setItem(i, 2, new QTableWidgetItem(c["category"].toString()));
    }
    m_configTable->resizeColumnsToContents();
    m_configTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void SystemPage::onConfigDoubleClicked(int row, int col) {
  if (col != 1) return;  // Only allow editing the "value" column
  QString category = m_configTable->item(row, 2)->text();
  QString key = m_configTable->item(row, 0)->text();
  QString value = m_configTable->item(row, 1)->text();

  QJsonObject body;
  // Try to preserve JSON type
  QJsonParseError err;
  auto doc = QJsonDocument::fromJson(value.toUtf8(), &err);
  if (err.error == QJsonParseError::NoError) {
    body["config_value"] = doc.isArray() ? QJsonValue(doc.array()) : QJsonValue(doc.object());
  } else {
    body["config_value"] = value;
  }
  body["description"] = "Updated via SystemPage";

  m_api->put("/api/config/" + category + "/" + key, body, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      onRefreshConfig();
    }
  });
}

// ── Assignments ──────────────────────────────────────────────────────
void SystemPage::onRefreshAssignments() {
  m_api->get("/api/assignments", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_assignmentTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto a = arr[i].toObject();
      m_assignmentTable->setItem(i, 0, new QTableWidgetItem(a["assignment_id"].toString()));
      m_assignmentTable->setItem(i, 1, new QTableWidgetItem(a["class_id"].toString()));
      m_assignmentTable->setItem(i, 2, new QTableWidgetItem(a["title"].toString()));
      m_assignmentTable->setItem(i, 3, new QTableWidgetItem(a["playbook_id"].toString()));
      m_assignmentTable->setItem(i, 4, new QTableWidgetItem(a["due_at"].toString().isEmpty() ? "无" : a["due_at"].toString()));
      m_assignmentTable->setItem(i, 5, new QTableWidgetItem(a["created_at"].toString()));
    }
    m_assignmentTable->resizeColumnsToContents();
    m_assignmentTable->horizontalHeader()->setStretchLastSection(true);
  });
}

// ── Submissions ──────────────────────────────────────────────────────
void SystemPage::onRefreshSubmissions() {
  m_api->get("/api/submissions", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_submissionTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto s = arr[i].toObject();
      m_submissionTable->setItem(i, 0, new QTableWidgetItem(s["submission_id"].toString()));
      m_submissionTable->setItem(i, 1, new QTableWidgetItem(s["assignment_id"].toString()));
      m_submissionTable->setItem(i, 2, new QTableWidgetItem(s["student_sub"].toString()));
      m_submissionTable->setItem(i, 3, new QTableWidgetItem(s["run_id"].toString().isEmpty() ? "—" : s["run_id"].toString()));
      // Parse final_grade - may be JSON object or string
      QString gradeStr = s["final_grade"].toString();
      if (!gradeStr.isEmpty()) {
        QJsonParseError err;
        auto doc = QJsonDocument::fromJson(gradeStr.toUtf8(), &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) {
          auto g = doc.object();
          gradeStr = QString("%1/%2 (%3%)")
              .arg(g["earned"].toInt())
              .arg(g["total"].toInt())
              .arg(g["percent"].toDouble(), 0, 'f', 1);
        }
      } else {
        gradeStr = "未评分";
      }
      m_submissionTable->setItem(i, 4, new QTableWidgetItem(gradeStr));
      m_submissionTable->setItem(i, 5, new QTableWidgetItem(s["submitted_at"].toString()));
    }
    m_submissionTable->resizeColumnsToContents();
    m_submissionTable->horizontalHeader()->setStretchLastSection(true);
  });
}

// ── Knowledge Graph ──────────────────────────────────────────────────

void SystemPage::onRefreshKnowledgeGraph() {
  loadKgStats();
}

void SystemPage::onKgSubTabChanged(int index) {
  if (index == 0) loadKgStats();
  else if (index == 1) loadKgGraph();
  else if (index == 2) loadKgMappings();
  // tab 3 (search) loads on demand
}

QString SystemPage::kgNodeTypeColor(const QString &type) const {
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

QString SystemPage::kgNodeTypeLabel(const QString &type) const {
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

QString SystemPage::kgEdgeTypeLabel(const QString &type) const {
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

QString SystemPage::zhOrDefault(const QJsonObject &obj, const QString &field) const {
  QString zhKey = "zh_" + field;
  QString zh = obj[zhKey].toString();
  if (!zh.isEmpty()) return zh;
  return obj[field].toString();
}

// ── Sub-tab setup ────────────────────────────────────────────────────

void SystemPage::setupKgStatsTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);

  // Stat cards row
  auto *cardsH = new QHBoxLayout;
  m_kgNodeCountLabel = new QLabel("节点: -");
  m_kgNodeCountLabel->setStyleSheet("font-size:18px; font-weight:bold; color:#3b82f6; padding:12px; background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px;");
  m_kgEdgeCountLabel = new QLabel("边: -");
  m_kgEdgeCountLabel->setStyleSheet("font-size:18px; font-weight:bold; color:#8b5cf6; padding:12px; background:#f5f3ff; border:1px solid #c4b5fd; border-radius:10px;");
  m_kgVersionLabel = new QLabel("v-");
  m_kgVersionLabel->setStyleSheet("font-size:14px; color:#64748b; padding:12px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;");
  cardsH->addWidget(m_kgNodeCountLabel);
  cardsH->addWidget(m_kgEdgeCountLabel);
  cardsH->addWidget(m_kgVersionLabel);
  cardsH->addStretch();
  l->addLayout(cardsH);

  // Node type distribution
  auto *ntLabel = new QLabel("节点类型分布"); ntLabel->setStyleSheet(Theme::SectionStyle);
  l->addWidget(ntLabel);
  m_kgNodeTypeTable = new QTableWidget(0, 3);
  m_kgNodeTypeTable->setHorizontalHeaderLabels({"类型", "数量", "占比"});
  m_kgNodeTypeTable->setAlternatingRowColors(true);
  m_kgNodeTypeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_kgNodeTypeTable->setSortingEnabled(true);
  l->addWidget(m_kgNodeTypeTable, 1);

  // Edge type distribution
  auto *etLabel = new QLabel("边类型分布"); etLabel->setStyleSheet(Theme::SectionStyle);
  l->addWidget(etLabel);
  m_kgEdgeTypeTable = new QTableWidget(0, 2);
  m_kgEdgeTypeTable->setHorizontalHeaderLabels({"类型", "数量"});
  m_kgEdgeTypeTable->setAlternatingRowColors(true);
  m_kgEdgeTypeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_kgEdgeTypeTable->setSortingEnabled(true);
  l->addWidget(m_kgEdgeTypeTable, 1);
}

void SystemPage::setupKgGraphTab(QWidget *parent) {
  auto *splitter = new QSplitter(Qt::Horizontal, parent);

  // Left: graph + controls
  auto *leftW = new QWidget;
  auto *leftL = new QVBoxLayout(leftW);
  leftL->setContentsMargins(4, 4, 4, 4);

  // Type filter checkboxes
  auto *filterH = new QHBoxLayout;
  m_kgShowTactics = new QCheckBox("战术"); m_kgShowTactics->setChecked(true);
  m_kgShowTechniques = new QCheckBox("技术"); m_kgShowTechniques->setChecked(true);
  m_kgShowWrappers = new QCheckBox("工具"); m_kgShowWrappers->setChecked(false);
  m_kgShowGroups = new QCheckBox("组织"); m_kgShowGroups->setChecked(false);
  m_kgShowSoftware = new QCheckBox("软件"); m_kgShowSoftware->setChecked(false);
  filterH->addWidget(m_kgShowTactics);
  filterH->addWidget(m_kgShowTechniques);
  filterH->addWidget(m_kgShowWrappers);
  filterH->addWidget(m_kgShowGroups);
  filterH->addWidget(m_kgShowSoftware);
  filterH->addStretch();
  auto *zoomInBtn = new QPushButton("放大");
  zoomInBtn->setProperty("primary", true);
  auto *zoomOutBtn = new QPushButton("缩小");
  zoomOutBtn->setProperty("primary", true);
  auto *resetBtn = new QPushButton("重置");
  resetBtn->setProperty("primary", true);
  filterH->addWidget(zoomInBtn);
  filterH->addWidget(zoomOutBtn);
  filterH->addWidget(resetBtn);
  leftL->addLayout(filterH);

  // Graphics scene + view
  m_kgScene = new QGraphicsScene(this);
  m_kgView = new KgGraphicsView;
  m_kgView->setScene(m_kgScene);
  m_kgView->setRenderHint(QPainter::Antialiasing, true);
  m_kgView->setDragMode(QGraphicsView::ScrollHandDrag);
  m_kgView->setBackgroundBrush(QColor("#0f172a"));
  m_kgView->setViewportUpdateMode(QGraphicsView::SmartViewportUpdate);
  leftL->addWidget(m_kgView, 1);

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
  connect(m_kgScene, &QGraphicsScene::selectionChanged, this, [this]() {
    auto sel = m_kgScene->selectedItems();
    if (sel.isEmpty()) return;
    auto *item = sel.first();
    QString nodeId = item->data(0).toString();
    if (!nodeId.isEmpty()) onKgNodeClicked(nodeId);
  });

  // Zoom signals
  connect(zoomInBtn, &QPushButton::clicked, this, [this]() { m_kgView->scale(1.2, 1.2); });
  connect(zoomOutBtn, &QPushButton::clicked, this, [this]() { m_kgView->scale(1.0/1.2, 1.0/1.2); });
  connect(resetBtn, &QPushButton::clicked, this, [this]() {
    m_kgView->resetTransform();
    m_kgView->fitInView(m_kgScene->itemsBoundingRect(), Qt::KeepAspectRatio);
  });

  // Re-render on filter change
  connect(m_kgShowTactics, &QCheckBox::stateChanged, this, [this]() { loadKgGraph(); });
  connect(m_kgShowTechniques, &QCheckBox::stateChanged, this, [this]() { loadKgGraph(); });
  connect(m_kgShowWrappers, &QCheckBox::stateChanged, this, [this]() { loadKgGraph(); });
  connect(m_kgShowGroups, &QCheckBox::stateChanged, this, [this]() { loadKgGraph(); });
  connect(m_kgShowSoftware, &QCheckBox::stateChanged, this, [this]() { loadKgGraph(); });

  // Right: detail panel
  auto *rightW = new QWidget;
  auto *rightL = new QVBoxLayout(rightW);
  rightL->setContentsMargins(8, 8, 8, 8);
  rightW->setMaximumWidth(320);
  m_kgDetailTitle = new QLabel("点击节点查看详情");
  m_kgDetailTitle->setStyleSheet("font-size:14px; font-weight:bold; color:#1e293b;");
  m_kgDetailTitle->setWordWrap(true);
  rightL->addWidget(m_kgDetailTitle);
  m_kgDetailText = new QTextEdit;
  m_kgDetailText->setReadOnly(true);
  m_kgDetailText->setPlaceholderText("选择图谱中的节点以查看详情...");
  rightL->addWidget(m_kgDetailText, 1);

  splitter->addWidget(leftW);
  splitter->addWidget(rightW);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 1);

  auto *outerL = new QVBoxLayout(parent);
  outerL->addWidget(splitter);
}

void SystemPage::setupKgMappingsTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);

  auto *filterH = new QHBoxLayout;
  m_kgMappingSearchEdit = new QLineEdit;
  m_kgMappingSearchEdit->setPlaceholderText("搜索工具或技术...");
  filterH->addWidget(m_kgMappingSearchEdit, 1);
  m_kgMappingConfidenceFilter = new QComboBox;
  m_kgMappingConfidenceFilter->addItems({"全部", "高", "中", "低"});
  filterH->addWidget(m_kgMappingConfidenceFilter);
  l->addLayout(filterH);

  m_kgMappingTable = new QTableWidget(0, 4);
  m_kgMappingTable->setHorizontalHeaderLabels({"工具名称", "技术ID", "技术名称", "置信度"});
  m_kgMappingTable->setAlternatingRowColors(true);
  m_kgMappingTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_kgMappingTable->setSortingEnabled(true);
  m_kgMappingTable->setContextMenuPolicy(Qt::CustomContextMenu);
  l->addWidget(m_kgMappingTable, 1);

  connect(m_kgMappingSearchEdit, &QLineEdit::textChanged, this, &SystemPage::onKgMappingSearch);
  connect(m_kgMappingConfidenceFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SystemPage::onKgMappingSearch);

  // Right-click copy
  connect(m_kgMappingTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_kgMappingTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_kgMappingTable->viewport()->mapToGlobal(pos));
  });
}

void SystemPage::setupKgNodesTab(QWidget *parent) {
  auto *l = new QVBoxLayout(parent);

  auto *filterH = new QHBoxLayout;
  m_kgSearchEdit = new QLineEdit;
  m_kgSearchEdit->setPlaceholderText("搜索节点名称或ID...");
  filterH->addWidget(m_kgSearchEdit, 1);
  m_kgSearchTypeFilter = new QComboBox;
  m_kgSearchTypeFilter->addItem("全部", "");
  m_kgSearchTypeFilter->addItem("工具", "HexToolWrapper");
  m_kgSearchTypeFilter->addItem("攻防技术", "AttackTechnique");
  m_kgSearchTypeFilter->addItem("战术", "AttackTactic");
  m_kgSearchTypeFilter->addItem("软件", "AttackSoftware");
  m_kgSearchTypeFilter->addItem("攻击组织", "AttackGroup");
  m_kgSearchTypeFilter->addItem("端点", "HexEndpoint");
  m_kgSearchTypeFilter->addItem("缓解措施", "AttackMitigation");
  filterH->addWidget(m_kgSearchTypeFilter);
  auto *searchBtn = new QPushButton("搜索");
  searchBtn->setProperty("primary", true);
  filterH->addWidget(searchBtn);
  l->addLayout(filterH);

  m_kgSearchTable = new QTableWidget(0, 4);
  m_kgSearchTable->setHorizontalHeaderLabels({"名称", "类型", "来源", "风险"});
  m_kgSearchTable->setAlternatingRowColors(true);
  m_kgSearchTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_kgSearchTable->setSortingEnabled(true);
  m_kgSearchTable->setContextMenuPolicy(Qt::CustomContextMenu);
  l->addWidget(m_kgSearchTable, 1);

  m_kgSearchDetail = new QTextEdit;
  m_kgSearchDetail->setReadOnly(true);
  m_kgSearchDetail->setMaximumHeight(180);
  l->addWidget(m_kgSearchDetail);

  connect(searchBtn, &QPushButton::clicked, this, &SystemPage::onKgSearch);
  connect(m_kgSearchEdit, &QLineEdit::returnPressed, this, &SystemPage::onKgSearch);

  connect(m_kgSearchTable, &QTableWidget::cellClicked, this, [this](int row, int) {
    auto *item = m_kgSearchTable->item(row, 0);
    if (!item) return;
    onKgNodeClicked(item->data(Qt::UserRole).toString());
  });

  // Right-click copy
  connect(m_kgSearchTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_kgSearchTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_kgSearchTable->viewport()->mapToGlobal(pos));
  });
}

// ── KG data loading ──────────────────────────────────────────────────

void SystemPage::loadKgStats() {
  m_api->get("/api/kg/stats", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();

    m_kgNodeCountLabel->setText(QString("节点: %1").arg(d["node_count"].toInt()));
    m_kgEdgeCountLabel->setText(QString("边: %1").arg(d["edge_count"].toInt()));
    m_kgVersionLabel->setText(QString("v%1").arg(d["kg_version"].toString()));

    // Node type distribution
    auto ntc = d["node_type_counts"].toObject();
    m_kgNodeTypeTable->setRowCount(ntc.size());
    int i = 0;
    for (auto it = ntc.begin(); it != ntc.end(); ++it, ++i) {
      int count = it.value().toInt();
      double pct = d["node_count"].toInt() > 0 ? (count * 100.0 / d["node_count"].toInt()) : 0;
      m_kgNodeTypeTable->setItem(i, 0, new QTableWidgetItem(kgNodeTypeLabel(it.key())));
      m_kgNodeTypeTable->setItem(i, 1, new QTableWidgetItem(QString::number(count)));
      m_kgNodeTypeTable->setItem(i, 2, new QTableWidgetItem(QString("%1%").arg(pct, 0, 'f', 1)));
    }
    m_kgNodeTypeTable->resizeColumnsToContents();
    m_kgNodeTypeTable->horizontalHeader()->setStretchLastSection(true);

    // Edge type distribution
    auto etc = d["edge_type_counts"].toObject();
    m_kgEdgeTypeTable->setRowCount(etc.size());
    i = 0;
    for (auto it = etc.begin(); it != etc.end(); ++it, ++i) {
      m_kgEdgeTypeTable->setItem(i, 0, new QTableWidgetItem(kgEdgeTypeLabel(it.key())));
      m_kgEdgeTypeTable->setItem(i, 1, new QTableWidgetItem(QString::number(it.value().toInt())));
    }
    m_kgEdgeTypeTable->resizeColumnsToContents();
    m_kgEdgeTypeTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void SystemPage::loadKgGraph() {
  // Build types filter from checkboxes
  QStringList types;
  if (m_kgShowTactics->isChecked()) types << "AttackTactic";
  if (m_kgShowTechniques->isChecked()) types << "AttackTechnique";
  if (m_kgShowWrappers->isChecked()) types << "HexToolWrapper";
  if (m_kgShowGroups->isChecked()) types << "AttackGroup";
  if (m_kgShowSoftware->isChecked()) types << "AttackSoftware";
  if (types.isEmpty()) types << "AttackTactic" << "AttackTechnique";

  // Limit nodes to keep force-directed layout fast (O(N²) per iteration)
  QString path = QString("/api/kg/graph?types=%1&limit=300").arg(types.join(","));
  m_api->get(path, 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    m_kgNodesCache = res["data"].toObject()["nodes"].toArray();
    m_kgEdgesCache = res["data"].toObject()["edges"].toArray();
    renderKgGraph();
  });
}

void SystemPage::renderKgGraph() {
  m_kgScene->clear();
  m_kgNodeItems.clear();

  if (m_kgNodesCache.isEmpty()) return;

  const int N = m_kgNodesCache.size();

  // ── Build adjacency list for force-directed layout ────────────────
  QMap<QString, int> idToIdx;
  for (int i = 0; i < N; i++) {
    idToIdx[m_kgNodesCache[i].toObject()["id"].toString()] = i;
  }
  QVector<QVector<int>> adj(N);
  for (int i = 0; i < m_kgEdgesCache.size(); i++) {
    auto e = m_kgEdgesCache[i].toObject();
    int si = idToIdx.value(e["source"].toString(), -1);
    int ti = idToIdx.value(e["target"].toString(), -1);
    if (si >= 0 && ti >= 0) { adj[si].append(ti); adj[ti].append(si); }
  }

  // ── Fruchterman-Reingold force-directed layout ────────────────────
  // Initialize positions: group by type in concentric rings
  QMap<QString, QList<int>> typeGroups;
  for (int i = 0; i < N; i++) {
    typeGroups[m_kgNodesCache[i].toObject()["type"].toString()].append(i);
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
    nodePositions[m_kgNodesCache[i].toObject()["id"].toString()] = pos[i];
  }

  // ── Draw edges first (below nodes) ────────────────────────────────
  for (int i = 0; i < m_kgEdgesCache.size(); i++) {
    auto e = m_kgEdgesCache[i].toObject();
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
    m_kgScene->addItem(line);
  }

  // ── Draw nodes ────────────────────────────────────────────────────
  for (int i = 0; i < m_kgNodesCache.size(); i++) {
    auto n = m_kgNodesCache[i].toObject();
    QString id = n["id"].toString();
    if (!nodePositions.contains(id)) continue;

    QPointF p = nodePositions[id];
    QString type = n["type"].toString();
    QColor color(kgNodeTypeColor(type));

    // Larger nodes for tactics, smaller for tools
    double nodeSize = (type == "AttackTactic") ? 14.0 :
                      (type == "AttackTechnique") ? 10.0 :
                      (type == "HexToolWrapper") ? 8.0 : 9.0;
    auto *ellipse = new QGraphicsEllipseItem(-nodeSize, -nodeSize, nodeSize * 2, nodeSize * 2);
    ellipse->setPos(p);
    ellipse->setBrush(QBrush(color));
    ellipse->setPen(QPen(color.darker(120), 1.5));
    ellipse->setToolTip(QString("%1\n类型: %2\nID: %3")
      .arg(zhOrDefault(n, "name"), kgNodeTypeLabel(type), id));
    ellipse->setData(0, id);
    ellipse->setFlag(QGraphicsItem::ItemIsSelectable);
    ellipse->setZValue(2.0);
    m_kgScene->addItem(ellipse);
    m_kgNodeItems[id] = ellipse;

    // Label — offset to avoid overlap with node
    auto *label = new QGraphicsSimpleTextItem(zhOrDefault(n, "name"));
    label->setPos(p.x() + nodeSize + 4, p.y() - 6);
    label->setBrush(QBrush(QColor("#e2e8f0")));
    QFont f = label->font();
    f.setPointSize(7);
    label->setFont(f);
    label->setZValue(2.5);
    m_kgScene->addItem(label);
  }

  m_kgScene->setSceneRect(m_kgScene->itemsBoundingRect().adjusted(-80, -80, 80, 80));
  m_kgView->fitInView(m_kgScene->sceneRect(), Qt::KeepAspectRatio);
}

void SystemPage::onKgNodeClicked(const QString &nodeId) {
  if (nodeId.isEmpty()) return;
  m_api->get("/api/kg/node/" + nodeId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    showKgNodeDetail(res["data"].toObject());
  });
}

void SystemPage::showKgNodeDetail(const QJsonObject &detail) {
  auto node = detail["node"].toObject();
  QString type = node["type"].toString();
  QString color = kgNodeTypeColor(type);

  m_kgDetailTitle->setText(QString("<span style='color:%1'>%2</span> — %3")
    .arg(color, kgNodeTypeLabel(type), zhOrDefault(node, "name")));

  QStringList lines;
  lines << QString("ID: %1").arg(node["id"].toString());
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
      lines << QString("  → %1 [%2]").arg(targetDisplay, kgEdgeTypeLabel(e["type"].toString()));
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
      lines << QString("  ← %1 [%2]").arg(sourceDisplay, kgEdgeTypeLabel(e["type"].toString()));
    }
  }

  m_kgDetailText->setText(lines.join("\n"));
}

void SystemPage::loadKgMappings() {
  m_api->get("/api/kg/mappings?limit=1000", 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto mappings = res["data"].toObject()["mappings"].toArray();
    m_kgMappingTable->setRowCount(mappings.size());
    for (int i = 0; i < mappings.size(); i++) {
      auto m = mappings[i].toObject();
      m_kgMappingTable->setItem(i, 0, new QTableWidgetItem(
        m["source_zh_name"].toString().isEmpty() ? m["source_name"].toString() : m["source_zh_name"].toString()));
      m_kgMappingTable->setItem(i, 1, new QTableWidgetItem(m["target_external_id"].toString()));
      m_kgMappingTable->setItem(i, 2, new QTableWidgetItem(
        m["target_zh_name"].toString().isEmpty() ? m["target_name"].toString() : m["target_zh_name"].toString()));
      QString conf = m["confidence"].toString();
      if (conf == "high") conf = "高";
      else if (conf == "medium") conf = "中";
      else if (conf == "low") conf = "低";
      m_kgMappingTable->setItem(i, 3, new QTableWidgetItem(conf));
    }
    m_kgMappingTable->resizeColumnsToContents();
    m_kgMappingTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void SystemPage::onKgMappingSearch() {
  QString q = m_kgMappingSearchEdit->text().trimmed().toLower();
  QString conf = m_kgMappingConfidenceFilter->currentText();
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

    m_kgMappingTable->setRowCount(filtered.size());
    for (int i = 0; i < filtered.size(); i++) {
      auto m = filtered[i].toObject();
      m_kgMappingTable->setItem(i, 0, new QTableWidgetItem(
        m["source_zh_name"].toString().isEmpty() ? m["source_name"].toString() : m["source_zh_name"].toString()));
      m_kgMappingTable->setItem(i, 1, new QTableWidgetItem(m["target_external_id"].toString()));
      m_kgMappingTable->setItem(i, 2, new QTableWidgetItem(
        m["target_zh_name"].toString().isEmpty() ? m["target_name"].toString() : m["target_zh_name"].toString()));
      QString conf = m["confidence"].toString();
      if (conf == "high") conf = "高";
      else if (conf == "medium") conf = "中";
      else if (conf == "low") conf = "低";
      m_kgMappingTable->setItem(i, 3, new QTableWidgetItem(conf));
    }
    m_kgMappingTable->resizeColumnsToContents();
    m_kgMappingTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void SystemPage::onKgSearch() {
  QString q = m_kgSearchEdit->text().trimmed();
  if (q.isEmpty()) return;
  QString type = m_kgSearchTypeFilter->currentData().toString();
  QString path = QString("/api/kg/search?q=%1&limit=100").arg(q);
  if (!type.isEmpty()) path += "&type=" + type;

  m_api->get(path, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto results = res["data"].toObject()["results"].toArray();
    m_kgSearchTable->setRowCount(results.size());
    for (int i = 0; i < results.size(); i++) {
      auto r = results[i].toObject();
      auto *nameItem = new QTableWidgetItem(zhOrDefault(r, "name"));
      nameItem->setData(Qt::UserRole, r["id"].toString());
      m_kgSearchTable->setItem(i, 0, nameItem);
      m_kgSearchTable->setItem(i, 1, new QTableWidgetItem(kgNodeTypeLabel(r["type"].toString())));
      m_kgSearchTable->setItem(i, 2, new QTableWidgetItem(r["source_system"].toString()));
      QString risk = r["risk_level"].toString();
      if (risk == "high") risk = "高";
      else if (risk == "medium") risk = "中";
      else if (risk == "low") risk = "低";
      else if (risk == "critical") risk = "严重";
      m_kgSearchTable->setItem(i, 3, new QTableWidgetItem(risk));
    }
    m_kgSearchTable->resizeColumnsToContents();
    m_kgSearchTable->horizontalHeader()->setStretchLastSection(true);
  });
}
