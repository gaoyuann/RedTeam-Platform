#include "PayloadPage.h"
#include "../Theme.h"
#include "../ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QScrollArea>
#include <QFrame>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonArray>
#include <QHeaderView>
#include <QDialogButtonBox>
#include <QMap>

PayloadPage::PayloadPage(ApiClient *api, const QString &role,
                         const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username) {
  setupUI();
  onLoadCategories();
  loadPayloadList();
}

void PayloadPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QHBoxLayout(this);

  // ── Left panel: category tree + payload list ────────────────────────
  auto *leftWidget = new QWidget;
  auto *leftLayout = new QVBoxLayout(leftWidget);
  leftLayout->setContentsMargins(0, 0, 0, 0);

  // Filter bar
  auto *filterH = new QHBoxLayout;
  filterH->addWidget(new QLabel(QStringLiteral("类型:")));
  m_typeFilter = new QComboBox;
  m_typeFilter->addItem(QStringLiteral("全部"), QString());
  m_typeFilter->addItem(QStringLiteral("Web攻击"), QStringLiteral("web"));
  m_typeFilter->addItem(QStringLiteral("内网渗透"), QStringLiteral("intranet"));
  m_typeFilter->addItem(QStringLiteral("工具命令"), QStringLiteral("tool"));
  m_typeFilter->addItem(QStringLiteral("AI生成"), QStringLiteral("ai_generated"));
  filterH->addWidget(m_typeFilter);
  filterH->addWidget(new QLabel(QStringLiteral("搜索:")));
  m_searchInput = new QLineEdit;
  m_searchInput->setPlaceholderText(QStringLiteral("载荷ID/名称/标签..."));
  m_searchInput->setClearButtonEnabled(true);
  filterH->addWidget(m_searchInput, 1);
  leftLayout->addLayout(filterH);

  connect(m_typeFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
          this, &PayloadPage::onTypeFilterChanged);
  connect(m_searchInput, &QLineEdit::textChanged, this, &PayloadPage::onSearchChanged);

  // Category tree
  auto *catLabel = new QLabel(QStringLiteral("载荷分类"));
  catLabel->setStyleSheet(Theme::SectionStyle);
  leftLayout->addWidget(catLabel);

  m_categoryTree = new QTreeWidget;
  m_categoryTree->setHeaderLabels({QStringLiteral("分类"), QStringLiteral("数量")});
  m_categoryTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_categoryTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_categoryTree->setMaximumHeight(200);
  leftLayout->addWidget(m_categoryTree);
  connect(m_categoryTree, &QTreeWidget::itemClicked, this, &PayloadPage::onCategoryClicked);

  // Payload list
  auto *listLabel = new QLabel(QStringLiteral("载荷列表"));
  listLabel->setStyleSheet(Theme::SectionStyle);
  leftLayout->addWidget(listLabel);

  m_payloadTable = new QTableWidget(0, 3);
  m_payloadTable->setHorizontalHeaderLabels({
    QStringLiteral("名称"), QStringLiteral("分类"), QStringLiteral("类型")
  });
  m_payloadTable->setAlternatingRowColors(true);
  m_payloadTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_payloadTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_payloadTable->setSortingEnabled(true);
  m_payloadTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  leftLayout->addWidget(m_payloadTable, 1);
  connect(m_payloadTable, &QTableWidget::cellClicked, this, &PayloadPage::onPayloadClicked);

  // ── Right panel: detail ─────────────────────────────────────────────
  auto *rightWidget = new QWidget;
  auto *rightLayout = new QVBoxLayout(rightWidget);
  rightLayout->setContentsMargins(0, 0, 0, 0);

  auto *scrollArea = new QScrollArea;
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *detailContainer = new QWidget;
  auto *detailLayout = new QVBoxLayout(detailContainer);

  // Name + category
  m_nameLabel = new QLabel;
  m_nameLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
  detailLayout->addWidget(m_nameLabel);

  m_categoryLabel = new QLabel;
  m_categoryLabel->setStyleSheet("color: #888;");
  detailLayout->addWidget(m_categoryLabel);

  m_descLabel = new QLabel;
  m_descLabel->setWordWrap(true);
  m_descLabel->setStyleSheet("margin: 8px 0;");
  detailLayout->addWidget(m_descLabel);

  // Commands
  auto *cmdLabel = new QLabel(QStringLiteral("执行命令"));
  cmdLabel->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(cmdLabel);
  m_commandsEdit = new QTextEdit;
  m_commandsEdit->setReadOnly(true);
  m_commandsEdit->setMaximumHeight(150);
  m_commandsEdit->setStyleSheet("font-family: monospace; font-size: 12px;");
  detailLayout->addWidget(m_commandsEdit);

  // Bypass variants
  auto *bypassLabel = new QLabel(QStringLiteral("绕过变体 (WAF/EDR Bypass)"));
  bypassLabel->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(bypassLabel);
  m_bypassEdit = new QTextEdit;
  m_bypassEdit->setReadOnly(true);
  m_bypassEdit->setMaximumHeight(120);
  m_bypassEdit->setStyleSheet("font-family: monospace; font-size: 12px;");
  detailLayout->addWidget(m_bypassEdit);

  // Defense
  auto *defLabel = new QLabel(QStringLiteral("防御方法"));
  defLabel->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(defLabel);
  m_defenseEdit = new QTextEdit;
  m_defenseEdit->setReadOnly(true);
  m_defenseEdit->setMaximumHeight(80);
  detailLayout->addWidget(m_defenseEdit);

  // OPSEC tips
  auto *opsecLabel = new QLabel(QStringLiteral("OPSEC 建议"));
  opsecLabel->setStyleSheet(Theme::SectionStyle);
  detailLayout->addWidget(opsecLabel);
  m_opsecEdit = new QTextEdit;
  m_opsecEdit->setReadOnly(true);
  m_opsecEdit->setMaximumHeight(80);
  detailLayout->addWidget(m_opsecEdit);

  detailLayout->addStretch();

  // Action buttons
  auto *btnH = new QHBoxLayout;
  m_copyBtn = new QPushButton(QStringLiteral("复制载荷命令"));
  m_bindBtn = new QPushButton(QStringLiteral("绑定到 Playbook"));
  m_aiGenBtn = new QPushButton(QStringLiteral("AI 生成载荷"));
  m_aiGenBtn->setProperty("primary", true);
  btnH->addWidget(m_copyBtn);
  btnH->addWidget(m_bindBtn);
  btnH->addStretch();
  btnH->addWidget(m_aiGenBtn);
  detailLayout->addLayout(btnH);

  connect(m_copyBtn, &QPushButton::clicked, this, &PayloadPage::onCopyCommand);
  connect(m_bindBtn, &QPushButton::clicked, this, &PayloadPage::onBindToPlaybook);
  connect(m_aiGenBtn, &QPushButton::clicked, this, &PayloadPage::onAiGenerate);

  scrollArea->setWidget(detailContainer);
  rightLayout->addWidget(scrollArea);

  // Placeholder for when no payload is selected
  m_placeholderLabel = new QLabel(QStringLiteral("选择左侧载荷查看详情"));
  m_placeholderLabel->setAlignment(Qt::AlignCenter);
  m_placeholderLabel->setStyleSheet("color: #888; font-size: 14px;");

  m_detailStack = new QStackedWidget;
  m_detailStack->addWidget(m_placeholderLabel);
  m_detailStack->addWidget(rightWidget);
  m_detailStack->setCurrentIndex(0);

  // ── Splitter ────────────────────────────────────────────────────────
  auto *splitter = new QSplitter(Qt::Horizontal);
  splitter->addWidget(leftWidget);
  splitter->addWidget(m_detailStack);
  splitter->setStretchFactor(0, 1);
  splitter->setStretchFactor(1, 2);
  mainLayout->addWidget(splitter);

  // Hide AI generate for non-admin/teacher
  if (m_role != "admin" && m_role != "teacher") {
    m_aiGenBtn->hide();
  }
}

void PayloadPage::onLoadCategories() {
  QPointer<PayloadPage> self(this);
  m_api->get("/api/payloads/categories", 5000, [this, self](const QJsonObject &res) {
    if (!self) return;
    if (res["status"].toString() != "ok") return;

    const auto data = res["data"].toObject();
    m_categoryTree->clear();

    // Add "全部" root item
    auto *allItem = new QTreeWidgetItem({QStringLiteral("全部载荷"), QString()});
    allItem->setData(0, Qt::UserRole, QStringLiteral(""));
    m_categoryTree->addTopLevelItem(allItem);

    const QStringList typeLabels = {
      QStringLiteral("web"), QStringLiteral("intranet"),
      QStringLiteral("tool"), QStringLiteral("ai_generated")
    };
    const QStringList typeNames = {
      QStringLiteral("Web攻击"), QStringLiteral("内网渗透"),
      QStringLiteral("工具命令"), QStringLiteral("AI生成")
    };

    for (int i = 0; i < typeLabels.size(); i++) {
      const auto cats = data[typeLabels[i]].toArray();
      if (cats.isEmpty()) continue;

      auto *typeItem = new QTreeWidgetItem({typeNames[i], QString()});
      typeItem->setData(0, Qt::UserRole, typeLabels[i]);
      m_categoryTree->addTopLevelItem(typeItem);

      for (const auto &catVal : cats) {
        const auto cat = catVal.toObject();
        auto *catItem = new QTreeWidgetItem({
          cat["category"].toString(),
          QString::number(cat["count"].toInt())
        });
        catItem->setData(0, Qt::UserRole, cat["category"].toString());
        typeItem->addChild(catItem);
      }
      typeItem->setExpanded(true);
    }
    allItem->setExpanded(true);
  });
}

void PayloadPage::onCategoryClicked(QTreeWidgetItem *item, int) {
  // If it's a type-level item (web/intranet/tool), filter by type
  // If it's a category-level item, filter by category
  QString data = item->data(0, Qt::UserRole).toString();

  // Check if this is a type node (web/intranet/tool/ai_generated) or a category node
  if (data == "web" || data == "intranet" || data == "tool" || data == "ai_generated") {
    m_currentType = data;
    m_currentCategory = "";
  } else if (data.isEmpty()) {
    // "全部"
    m_currentType = "";
    m_currentCategory = "";
  } else {
    // Category node
    m_currentCategory = data;
    // Get parent type
    auto *parent = item->parent();
    if (parent) {
      m_currentType = parent->data(0, Qt::UserRole).toString();
    }
  }
  loadPayloadList(m_currentCategory, m_currentType, m_currentKeyword);
}

void PayloadPage::onSearchChanged(const QString &text) {
  m_currentKeyword = text;
  loadPayloadList(m_currentCategory, m_currentType, m_currentKeyword);
}

void PayloadPage::onTypeFilterChanged(int) {
  m_currentType = m_typeFilter->currentData().toString();
  loadPayloadList(m_currentCategory, m_currentType, m_currentKeyword);
}

void PayloadPage::loadPayloadList(const QString &category, const QString &type, const QString &keyword) {
  QString path = "/api/payloads?";
  QStringList params;
  if (!category.isEmpty()) params << QStringLiteral("category=%1").arg(category);
  if (!type.isEmpty()) params << QStringLiteral("type=%1").arg(type);
  if (!keyword.isEmpty()) params << QStringLiteral("keyword=%1").arg(keyword);
  path += params.join("&");

  QPointer<PayloadPage> self(this);
  m_api->get(path, 5000, [this, self](const QJsonObject &res) {
    if (!self) return;
    if (res["status"].toString() != "ok") return;

    const auto data = res["data"].toArray();
    m_payloadTable->setRowCount(data.size());

    // Type label mapping
    QMap<QString, QString> typeLabelMap;
    typeLabelMap["web"] = QStringLiteral("Web");
    typeLabelMap["intranet"] = QStringLiteral("内网");
    typeLabelMap["tool"] = QStringLiteral("工具");
    typeLabelMap["ai_generated"] = QStringLiteral("AI");

    for (int i = 0; i < data.size(); i++) {
      const auto p = data[i].toObject();
      m_payloadTable->setItem(i, 0, new QTableWidgetItem(p["name"].toString()));
      m_payloadTable->setItem(i, 1, new QTableWidgetItem(p["category"].toString()));
      QString typeStr = p["type"].toString();
      if (typeLabelMap.contains(typeStr)) typeStr = typeLabelMap[typeStr];
      m_payloadTable->setItem(i, 2, new QTableWidgetItem(typeStr));
      // Store payload ID in the first column's user data
      m_payloadTable->item(i, 0)->setData(Qt::UserRole, p["id"].toString());
    }
  });
}

void PayloadPage::onPayloadClicked(int row, int) {
  auto *item = m_payloadTable->item(row, 0);
  if (!item) return;
  QString id = item->data(Qt::UserRole).toString();
  loadPayloadDetail(id);
}

void PayloadPage::loadPayloadDetail(const QString &id) {
  m_selectedId = id;
  QPointer<PayloadPage> self(this);
  m_api->get(QStringLiteral("/api/payloads/%1").arg(id), 5000,
    [this, self](const QJsonObject &res) {
      if (!self) return;
      if (res["status"].toString() != "ok") return;
      showPayloadDetail(res["data"].toObject());
    });
}

void PayloadPage::showPayloadDetail(const QJsonObject &payload) {
  m_detailStack->setCurrentIndex(1);

  // Helper: extract zh/en field, fallback to plain string
  auto extractI18n = [](const QJsonObject &obj, const QString &key) -> QString {
    const auto val = obj[key];
    if (val.isObject()) {
      const auto o = val.toObject();
      return o["zh"].toString().isEmpty() ? o["en"].toString() : o["zh"].toString();
    }
    return val.toString();
  };

  m_nameLabel->setText(extractI18n(payload, QStringLiteral("name")));

  const auto catVal = payload["category"];
  QString catDisplay = catVal.isObject()
    ? (catVal.toObject()["zh"].toString().isEmpty() ? catVal.toObject()["en"].toString() : catVal.toObject()["zh"].toString())
    : catVal.toString();
  m_categoryLabel->setText(
    QStringLiteral("分类: %1 | 类型: %2 | ID: %3")
      .arg(catDisplay)
      .arg(payload["_type"].toString())
      .arg(payload["id"].toString())
  );

  m_descLabel->setText(extractI18n(payload, QStringLiteral("description")));

  // Commands
  const auto payloadData = payload["payload_data"].toObject();
  const auto executions = payloadData["all_executions"].toArray();
  QString cmdText;
  for (const auto &execVal : executions) {
    const auto exec = execVal.toObject();
    cmdText += QStringLiteral("▶ %1\n  %2\n\n")
      .arg(exec["title"].toString())
      .arg(exec["command"].toString());
  }
  m_commandsEdit->setText(cmdText);
  m_primaryCommand = payloadData["primary_content"].toString();

  // Bypass variants
  const auto bypasses = payloadData["bypass_variants"].toArray();
  QString bypassText;
  for (const auto &bVal : bypasses) {
    const auto b = bVal.toObject();
    bypassText += QStringLiteral("⚡ %1\n  命令: %2\n  说明: %3\n\n")
      .arg(b["title"].toString())
      .arg(b["command"].toString())
      .arg(b["description"].toString());
  }
  m_bypassEdit->setText(bypassText.isEmpty() ? QStringLiteral("无绕过变体") : bypassText);

  // Defense
  const auto defense = payloadData["defense"].toObject();
  m_defenseEdit->setText(defense["zh"].toString().isEmpty() ? defense["en"].toString() : defense["zh"].toString());

  // OPSEC tips
  const auto opsec = payloadData["opsec_tips"].toArray();
  QString opsecText;
  for (const auto &tip : opsec) {
    if (tip.isObject()) {
      opsecText += QStringLiteral("• %1\n").arg(tip["zh"].toString().isEmpty() ? tip["en"].toString() : tip["zh"].toString());
    } else {
      opsecText += QStringLiteral("• %1\n").arg(tip.toString());
    }
  }
  m_opsecEdit->setText(opsecText.isEmpty() ? QStringLiteral("无OPSEC建议") : opsecText);
}

void PayloadPage::clearDetail() {
  m_detailStack->setCurrentIndex(0);
  m_selectedId.clear();
  m_primaryCommand.clear();
}

void PayloadPage::selectPayload(const QString &payloadId) {
  loadPayloadDetail(payloadId);
}

void PayloadPage::onCopyCommand() {
  if (m_primaryCommand.isEmpty()) {
    QMessageBox::information(this, QStringLiteral("提示"), QStringLiteral("没有可复制的载荷命令"));
    return;
  }
  QApplication::clipboard()->setText(m_primaryCommand);
  QMessageBox::information(this, QStringLiteral("已复制"), QStringLiteral("载荷命令已复制到剪贴板"));
}

void PayloadPage::onBindToPlaybook() {
  if (m_selectedId.isEmpty()) {
    QMessageBox::information(this, QStringLiteral("提示"), QStringLiteral("请先选择一个载荷"));
    return;
  }
  // Simple dialog: enter playbook ID + step index
  QMessageBox::information(this, QStringLiteral("绑定载荷"),
    QStringLiteral("载荷 %1 可在 Playbook 编辑时通过 payload_id 字段绑定到步骤。\n\n"
                   "请前往「战术手册」页面，编辑 Playbook 步骤，在 payload_id 下拉框中选择此载荷。").arg(m_selectedId));
}

void PayloadPage::onAiGenerate() {
  // Dialog for AI payload generation
  auto *dlg = new QDialog(this);
  dlg->setWindowTitle(QStringLiteral("AI 生成载荷"));
  auto *layout = new QVBoxLayout(dlg);

  auto *form = new QFormLayout;
  auto *catInput = new QComboBox;
  catInput->addItems({
    QStringLiteral("SQL/NoSQL注入"), QStringLiteral("XSS跨站脚本"),
    QStringLiteral("RCE远程代码执行"), QStringLiteral("SSRF服务端请求伪造"),
    QStringLiteral("LFI/RFI文件包含"), QStringLiteral("凭证窃取"),
    QStringLiteral("横向移动"), QStringLiteral("权限提升"),
    QStringLiteral("免杀与规避"), QStringLiteral("域渗透攻击"),
  });
  form->addRow(QStringLiteral("载荷分类:"), catInput);

  auto *typeInput = new QComboBox;
  typeInput->addItem(QStringLiteral("Web攻击"), QStringLiteral("web"));
  typeInput->addItem(QStringLiteral("内网渗透"), QStringLiteral("intranet"));
  form->addRow(QStringLiteral("目标类型:"), typeInput);

  auto *techInput = new QLineEdit;
  techInput->setPlaceholderText(QStringLiteral("如 T1190 (可选)"));
  form->addRow(QStringLiteral("MITRE 技术:"), techInput);

  layout->addLayout(form);

  auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  layout->addWidget(buttons);
  connect(buttons, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

  if (dlg->exec() != QDialog::Accepted) {
    delete dlg;
    return;
  }

  // Call API
  QJsonObject body;
  body["category"] = catInput->currentText();
  body["target_type"] = typeInput->currentData().toString();
  body["technique_id"] = techInput->text();

  QPointer<PayloadPage> self(this);
  m_aiGenBtn->setEnabled(false);
  m_aiGenBtn->setText(QStringLiteral("生成中..."));

  m_api->post("/api/payloads/generate", body, 60000,
    [this, self](const QJsonObject &res) {
      if (!self) return;
      m_aiGenBtn->setEnabled(true);
      m_aiGenBtn->setText(QStringLiteral("AI 生成载荷"));

      if (res["status"].toString() != "ok") {
        QString errMsg = res["error"].isObject()
          ? res["error"].toObject()["message"].toString()
          : res["error"].toString();
        if (errMsg.isEmpty()) errMsg = QStringLiteral("未知错误");
        QMessageBox::warning(this, QStringLiteral("生成失败"), errMsg);
        return;
      }

      QMessageBox::information(this, QStringLiteral("生成成功"),
        QStringLiteral("载荷已生成，状态为 candidate，需教师审核后可用。\n\n"
                       "请前往载荷列表查看。"));
      onLoadCategories();
      loadPayloadList();
    });

  delete dlg;
}
