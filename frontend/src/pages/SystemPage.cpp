#include "../widgets/WorkbenchTabs.h"
#include "SystemPage.h"
#include "DeployConfigPage.h"
#include "DongleVerificationPage.h"
#include "services/dongle/DongleService.h"
#include "../Theme.h"
#include "../UiUtil.h"
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

SystemPage::SystemPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent) : QWidget(parent), m_api(api), m_role(role), m_username(username) {
  setupUI();
  onRefreshUsers();
  onRefreshConfig();
  onRefreshAssignments();
  onRefreshSubmissions();
  if (m_role == "admin") onRefreshPermissions();
}

void SystemPage::setupUI() {
  setStyleSheet(Theme::PageStyle);
  auto *scrollArea = new QScrollArea(this);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);
  m_tabs = new WorkbenchTabs;

  // ── Users tab ─────────────────────────────────────────────────────
  auto *userW = new QWidget;
  auto *userL = new QVBoxLayout(userW);
  m_userTable = new QTableWidget(0, 4);
  m_userTable->horizontalHeader()->setStretchLastSection(false);
  m_userTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  UiUtil::EmptyHint::attach(m_userTable, QStringLiteral("暂无用户"));
  m_userTable->setHorizontalHeaderLabels({"用户名", "角色", "状态", "创建时间"});
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
  m_newRole->addItem("普通用户", "user");
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

  // ── Deploy config tab (moved from top-level navigation) ───────────
  // All roles can access (matches old top-level page behavior)
  m_deployTab = new DeployConfigPage(m_api, m_role, m_username, this);
  m_tabs->addTab(m_deployTab, QStringLiteral("资源部署"));

  // ── Permissions tab (admin only) ──────────────────────────────────
  if (m_role == "admin") {
    auto *permW = new QWidget;
    auto *permL = new QVBoxLayout(permW);

    auto *permHint = new QLabel("细粒度权限配置：勾选每个路由组对各角色的读取/写入权限");
    permHint->setStyleSheet("color:#64748b; font-size:13px;");
    permHint->setWordWrap(true);
    permL->addWidget(permHint);

    // Columns: 路由组 | admin R/W | user R/W
    // We use a custom layout: header row + data rows with checkboxes
    m_permTable = new QTableWidget(0, 3);
    UiUtil::EmptyHint::attach(m_permTable, QStringLiteral("暂无权限记录"));
    m_permTable->setHorizontalHeaderLabels({"路由组", "管理员", "普通用户"});
    m_permTable->setAlternatingRowColors(true);
    m_permTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 行高固定留余量：CJK 走字体回退时度量偏高，默认行高会裁掉复选框文字底部
    m_permTable->verticalHeader()->setDefaultSectionSize(38);
    m_permTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    // 权限列固定宽度：QHeaderView 的 ResizeToContents 不测量 setCellWidget
    // 塞入的控件（按空文本算宽），会把列压到只剩表头宽，复选框文字被裁
    for (int c = 1; c <= 2; c++) {
      m_permTable->horizontalHeader()->setSectionResizeMode(c, QHeaderView::Fixed);
      m_permTable->setColumnWidth(c, 116);
    }
    permL->addWidget(m_permTable, 1);

    m_permSaveBtn = new QPushButton("保存权限配置");
    m_permSaveBtn->setProperty("primary", true);
    permL->addWidget(m_permSaveBtn);
    connect(m_permSaveBtn, &QPushButton::clicked, this, &SystemPage::onSavePermissions);

    m_tabs->addTab(permW, "权限管理");
  }

  // ── 加密锁校验 tab ───────────────────────────────────────────────
  m_dongleTab = new DongleVerificationPage(DongleService::policyDir(), this);
  m_tabs->addTab(m_dongleTab, QStringLiteral("加密锁校验"));

  // ── Config tab (now editable) ────────────────────────────────────
  auto *cfgW = new QWidget;
  auto *cfgL = new QVBoxLayout(cfgW);
  auto *cfgHint = new QLabel("双击配置值可编辑，编辑后点击保存");
  cfgHint->setStyleSheet("color:#64748b; font-size:13px;");
  cfgL->addWidget(cfgHint);
  m_configTable = new QTableWidget(0, 3);
  m_configTable->horizontalHeader()->setStretchLastSection(false);
  m_configTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  UiUtil::EmptyHint::attach(m_configTable, QStringLiteral("暂无配置项"));
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
  m_assignmentTable->horizontalHeader()->setStretchLastSection(false);
  m_assignmentTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  UiUtil::EmptyHint::attach(m_assignmentTable, QStringLiteral("暂无任务分配"));
  m_assignmentTable->setHorizontalHeaderLabels({"任务编号", "班级", "标题", "预案", "截止时间", "创建时间"});
  m_assignmentTable->setAlternatingRowColors(true);
  m_assignmentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_assignmentTable->setSortingEnabled(true);
  m_assignmentTable->setContextMenuPolicy(Qt::CustomContextMenu);
  asgnL->addWidget(m_assignmentTable);

  auto *asgnSubLabel = new QLabel("提交记录"); asgnSubLabel->setStyleSheet(Theme::SectionStyle);
  asgnL->addWidget(asgnSubLabel);
  m_submissionTable = new QTableWidget(0, 6);
  m_submissionTable->horizontalHeader()->setStretchLastSection(false);
  m_submissionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  UiUtil::EmptyHint::attach(m_submissionTable, QStringLiteral("暂无提交记录"));
  m_submissionTable->setHorizontalHeaderLabels({"提交编号", "任务", "学生", "执行编号", "成绩", "提交时间"});
  m_submissionTable->setAlternatingRowColors(true);
  m_submissionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_submissionTable->setSortingEnabled(true);
  m_submissionTable->setContextMenuPolicy(Qt::CustomContextMenu);
  asgnL->addWidget(m_submissionTable);

  auto *asgnRefresh = new QPushButton("刷新");
  asgnL->addWidget(asgnRefresh);
  connect(asgnRefresh, &QPushButton::clicked, this, [this]() { onRefreshAssignments(); onRefreshSubmissions(); });
  m_tabs->addTab(asgnW, "任务管理");

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

    // Disable sorting while populating — otherwise Qt re-sorts rows on
    // each setItem(), causing items to land in the wrong rows.
    m_userTable->setSortingEnabled(false);
    m_userTable->setRowCount(0);
    m_userTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto u = arr[i].toObject();
      m_userTable->setItem(i, 0, new QTableWidgetItem(u["username"].toString()));
      // Translate role to Chinese
      QString role = u["role"].toString();
      QString roleCn;
      if (role == "admin") roleCn = "管理员";
      else if (role == "user") roleCn = "普通用户";
      else roleCn = role;
      auto *roleItem = new QTableWidgetItem(roleCn);
      roleItem->setData(Qt::UserRole, role);  // keep original for editing
      m_userTable->setItem(i, 1, roleItem);
      m_userTable->setItem(i, 2, new QTableWidgetItem(u["is_active"].toInt() ? "活跃" : "禁用"));
      m_userTable->setItem(i, 3, new QTableWidgetItem(u["created_at"].toString()));
    }
    m_userTable->setSortingEnabled(true);
    m_userTable->resizeColumnsToContents();
  });
}

void SystemPage::onAddUser() {
  QString user = m_newUsername->text().trimmed();
  QString pass = m_newPassword->text().trimmed();
  if (user.isEmpty() || pass.isEmpty()) return;

  // Client-side duplicate check against the existing table
  for (int i = 0; i < m_userTable->rowCount(); i++) {
    auto *item = m_userTable->item(i, 0);
    if (item && item->text() == user) {
      QMessageBox::warning(this->window(), "用户名已存在",
        QString("用户名 \"%1\" 已存在，请使用其他用户名。").arg(user));
      return;
    }
  }

  QJsonObject body;
  body["username"] = user;
  body["password"] = pass;
  body["role"] = m_newRole->currentData().toString();
  m_api->post("/api/users", body, 5000, [this, user](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      QString msg = res["error"].toObject()["message"].toString();
      if (msg.isEmpty()) msg = "创建用户失败";
      QMessageBox::warning(this->window(), "创建失败", msg);
      return;
    }
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
  });
}

// ── Permissions (RBAC) ────────────────────────────────────────────────

void SystemPage::onRefreshPermissions() {
  if (!m_permTable) return;
  m_api->get("/api/users/permissions", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto rbac = res["data"].toObject();

    QStringList prefixes = rbac.keys();
    std::sort(prefixes.begin(), prefixes.end());
    QStringList roles = {"admin", "user"};

    m_permTable->setRowCount(prefixes.size());
    for (int i = 0; i < prefixes.size(); i++) {
      const QString &prefix = prefixes[i];
      m_permTable->setItem(i, 0, new QTableWidgetItem(prefix));

      auto rules = rbac[prefix].toObject();
      auto readArr = rules["read"].toArray();
      auto writeArr = rules["write"].toArray();
      QSet<QString> readSet, writeSet;
      for (const auto &v : readArr) readSet.insert(v.toString());
      for (const auto &v : writeArr) writeSet.insert(v.toString());

      for (int j = 0; j < roles.size(); j++) {
        const QString &role = roles[j];
        // Create a widget with read and write checkboxes.
        auto *widget = new QWidget;
        auto *layout = new QHBoxLayout(widget);
        layout->setContentsMargins(6, 4, 6, 4);
        layout->setSpacing(2);
        auto *readCb = new QCheckBox("读");
        auto *writeCb = new QCheckBox("写");
        readCb->setChecked(readSet.contains(role));
        writeCb->setChecked(writeSet.contains(role));
        // admin always has full access — disable to prevent lockout
        if (role == "admin") {
          readCb->setChecked(true);
          writeCb->setChecked(true);
          readCb->setEnabled(false);
          writeCb->setEnabled(false);
        }
        layout->addWidget(readCb);
        layout->addWidget(writeCb);
        layout->addStretch();
        m_permTable->setCellWidget(i, j + 1, widget);
      }
    }
    // 不再 resizeColumnsToContents：它不测量 cell widget，会把权限列压瘪
  });
}

void SystemPage::onSavePermissions() {
  if (!m_permTable) return;
  QStringList roles = {"admin", "user"};

  QJsonObject permissions;
  for (int i = 0; i < m_permTable->rowCount(); i++) {
    auto *prefixItem = m_permTable->item(i, 0);
    if (!prefixItem) continue;
    QString prefix = prefixItem->text();

    QJsonArray readArr, writeArr;
    for (int j = 0; j < roles.size(); j++) {
      auto *widget = m_permTable->cellWidget(i, j + 1);
      if (!widget) continue;
      auto *readCb = widget->findChild<QCheckBox*>();
      if (!readCb) continue;
      // Find the second checkbox (W)
      auto cbs = widget->findChildren<QCheckBox*>();
      if (cbs.size() < 2) continue;
      if (cbs[0]->isChecked()) readArr.append(roles[j]);
      if (cbs[1]->isChecked()) writeArr.append(roles[j]);
    }

    QJsonObject rules;
    rules["read"] = readArr;
    rules["write"] = writeArr;
    permissions[prefix] = rules;
  }

  QJsonObject body;
  body["permissions"] = permissions;

  m_permSaveBtn->setEnabled(false);
  m_api->put("/api/users/permissions", body, 5000, [this](const QJsonObject &res) {
    m_permSaveBtn->setEnabled(true);
    if (res["status"].toString() == "ok") {
      // Show success feedback in the table area
      m_permTable->setToolTip("权限配置已保存并立即生效");
    }
  });
}
