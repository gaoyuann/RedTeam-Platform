#include "PlaybookPage.h"
#include "../ApiClient.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QTreeWidgetItem>
#include <QHeaderView>
#include <QMessageBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QUuid>
#include <QSplitter>
#include "../Theme.h"
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QPointer>

PlaybookPage::PlaybookPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
  onLoadList();
}

void PlaybookPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);

  // Left: list
  auto *left = new QVBoxLayout;
  auto *filterH = new QHBoxLayout;
  m_groupFilter = new QComboBox;
  m_groupFilter->addItem("全部", "");
  m_groupFilter->addItem("侦察", "recon");
  m_groupFilter->addItem("Web漏洞扫描", "web-vuln-scan");
  m_groupFilter->addItem("Windows利用", "windows-exploitation");
  m_groupFilter->addItem("后渗透", "post-exploitation");
  m_groupFilter->addItem("内网横向", "internal-network-exploitation");
  m_groupFilter->addItem("本地安全检查", "local-security-check");
  m_groupFilter->addItem("影响演示", "impact-demonstration");
  m_groupFilter->addItem("域信息收集", "domain-osint");
  m_showGenerated = new QCheckBox("含AI生成");
  filterH->addWidget(new QLabel("基线组:"));
  filterH->addWidget(m_groupFilter);
  filterH->addWidget(m_showGenerated);
  filterH->addStretch();
  left->addLayout(filterH);

  auto *titleLabel = new QLabel("战术手册（预案）");
  titleLabel->setStyleSheet(Theme::SectionStyle);
  left->addWidget(titleLabel);

  m_listTable = new QTableWidget(0, 4);
  m_listTable->setHorizontalHeaderLabels({"名称", "难度", "基线组", "步骤数"});
  m_listTable->setAlternatingRowColors(true);
  m_listTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_listTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_listTable->setSortingEnabled(true);
  m_listTable->setContextMenuPolicy(Qt::CustomContextMenu);
  left->addWidget(m_listTable);

  auto *btnH = new QHBoxLayout;
  m_newBtn = new QPushButton("＋ 新建");
  m_newBtn->setProperty("primary", true);
  auto *delBtn = new QPushButton("删除选中");
  delBtn->setProperty("danger", true);
  btnH->addWidget(m_newBtn);
  btnH->addStretch();
  btnH->addWidget(delBtn);
  left->addLayout(btnH);

  connect(m_newBtn, &QPushButton::clicked, this, &PlaybookPage::onNewPlaybook);
  connect(delBtn, &QPushButton::clicked, this, &PlaybookPage::onDeletePlaybook);

  auto *leftW = new QWidget;
  leftW->setLayout(left);

  // Right: detail
  auto *right = new QVBoxLayout;
  m_detailLabel = new QLabel("选择预案查看详情");
  m_detailLabel->setStyleSheet(Theme::SectionStyle);
  m_detailLabel->setWordWrap(true);
  right->addWidget(m_detailLabel);
  m_detailTree = new QTreeWidget;
  m_detailTree->setHeaderLabels({"步骤", "工具", "载荷", "描述", "参数模板"});
  m_detailTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_detailTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_detailTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  m_detailTree->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  m_detailTree->header()->setSectionResizeMode(4, QHeaderView::Stretch);
  right->addWidget(m_detailTree, 1);

  auto *rightW = new QWidget;
  rightW->setLayout(right);

  auto *splitter = new QSplitter(Qt::Horizontal, this);
  splitter->addWidget(leftW);
  splitter->addWidget(rightW);
  splitter->setStretchFactor(0, 2);
  splitter->setStretchFactor(1, 3);
  splitter->setSizes({400, 600});
  mainLayout->addWidget(splitter, 1);

  // Go to execute button — placed OUTSIDE the splitter for reliable click handling
  auto *execBox = new QHBoxLayout;
  m_goExecBtn = new QPushButton("▶ 前往执行此预案");
  m_goExecBtn->setProperty("primary", true);
  m_goExecBtn->setToolTip("先在左侧列表中选择一个预案，然后点击此按钮跳转到「攻击执行」页面");
  m_goExecBtn->setMinimumHeight(36);
  execBox->addWidget(m_goExecBtn);
  execBox->addStretch();
  mainLayout->addLayout(execBox);
  connect(m_goExecBtn, &QPushButton::clicked, this, &PlaybookPage::onGoExecute);

  // Signals
  connect(m_listTable, &QTableWidget::cellClicked, this, &PlaybookPage::onPlaybookClicked);
  connect(m_groupFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &PlaybookPage::onLoadList);
  connect(m_showGenerated, &QCheckBox::stateChanged, this, &PlaybookPage::onLoadList);
  connect(m_listTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_listTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_listTable->viewport()->mapToGlobal(pos));
  });
}

// ── Formatting helpers ─────────────────────────────────────────────────
QString PlaybookPage::formatDifficulty(const QString &s) {
  if (s.isEmpty()) return "—";
  if (s == "easy" || s == "初级") return "简单";
  if (s == "medium" || s == "中级") return "中等";
  if (s == "hard" || s == "高级") return "困难";
  return s;
}

QString PlaybookPage::formatBaselineGroup(const QString &s) {
  if (s.isEmpty()) return "—";
  if (s == "recon")                           return "侦察";
  if (s == "web-vuln-scan")                   return "Web漏洞扫描";
  if (s == "windows-exploitation")            return "Windows利用";
  if (s == "post-exploitation")               return "后渗透";
  if (s == "internal-network-exploitation")   return "内网横向";
  if (s == "local-security-check")            return "本地安全检查";
  if (s == "impact-demonstration")            return "影响演示";
  if (s == "domain-osint")                    return "域信息收集";
  if (s == "brute")                           return "暴力破解";
  if (s == "exploit")                         return "漏洞利用";
  return s;
}

void PlaybookPage::onLoadList() {
  QString path = QString("/api/playbooks?includeGenerated=") + (m_showGenerated->isChecked() ? "true" : "false");
  QString group = m_groupFilter->currentData().toString();
  if (!group.isEmpty()) path += "&baselineGroup=" + group;

  QPointer<PlaybookPage> self(this);
  m_api->get(path, 5000, [this, self](const QJsonObject &res) {
    if (!self) return;
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_listTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto pb = arr[i].toObject();
      auto *nameItem = new QTableWidgetItem(pb["name"].toString());
      nameItem->setData(Qt::UserRole, pb["playbook_id"].toString());
      m_listTable->setItem(i, 0, nameItem);
      m_listTable->setItem(i, 1, new QTableWidgetItem(formatDifficulty(pb["difficulty"].toString())));
      m_listTable->setItem(i, 2, new QTableWidgetItem(formatBaselineGroup(pb["baseline_group"].toString())));
      m_listTable->setItem(i, 3, new QTableWidgetItem(QString::number(pb["steps_count"].toInt())));
    }
    m_listTable->resizeColumnsToContents();
    m_listTable->horizontalHeader()->setStretchLastSection(true);
  });
}

void PlaybookPage::selectPlaybook(const QString &playbookId) {
  m_showGenerated->blockSignals(true);
  m_groupFilter->blockSignals(true);
  m_showGenerated->setChecked(true);
  m_groupFilter->setCurrentIndex(0);
  m_showGenerated->blockSignals(false);
  m_groupFilter->blockSignals(false);

  QString path = "/api/playbooks?includeGenerated=true";
  QPointer<PlaybookPage> self2(this);
  m_api->get(path, 5000, [this, self2, playbookId](const QJsonObject &res) {
    if (!self2) return;
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();

    m_listTable->setSortingEnabled(false);
    m_listTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto pb = arr[i].toObject();
      auto *nameItem = new QTableWidgetItem(pb["name"].toString());
      nameItem->setData(Qt::UserRole, pb["playbook_id"].toString());
      m_listTable->setItem(i, 0, nameItem);
      m_listTable->setItem(i, 1, new QTableWidgetItem(formatDifficulty(pb["difficulty"].toString())));
      m_listTable->setItem(i, 2, new QTableWidgetItem(formatBaselineGroup(pb["baseline_group"].toString())));
      m_listTable->setItem(i, 3, new QTableWidgetItem(QString::number(pb["steps_count"].toInt())));
    }
    m_listTable->resizeColumnsToContents();
    m_listTable->horizontalHeader()->setStretchLastSection(true);
    m_listTable->setSortingEnabled(true);

    for (int i = 0; i < m_listTable->rowCount(); i++) {
      auto *item = m_listTable->item(i, 0);
      if (item && item->data(Qt::UserRole).toString() == playbookId) {
        m_listTable->selectRow(i);
        m_listTable->scrollToItem(item);
        m_selectedId = playbookId;
        m_goExecBtn->setEnabled(true);
        loadPlaybookDetail(playbookId);
        return;
      }
    }
  });
}

void PlaybookPage::onPlaybookClicked(int row, int) {
  auto *item = m_listTable->item(row, 0);
  if (!item) return;
  auto id = item->data(Qt::UserRole).toString();
  m_selectedId = id;
  m_goExecBtn->setEnabled(!id.isEmpty());
  loadPlaybookDetail(id);
}

void PlaybookPage::loadPlaybookDetail(const QString &id) {
  QPointer<PlaybookPage> self(this);
  m_api->get("/api/playbooks/" + id, 5000, [this, self](const QJsonObject &res) {
    if (!self) return;
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    m_detailLabel->setText(d["name"].toString() + " — " + d["description"].toString());

    m_detailTree->clear();
    auto steps = d["steps"].toArray();
    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      auto *item = new QTreeWidgetItem(m_detailTree);
      item->setText(0, s["step_id"].toString());
      item->setText(1, s["tool_id"].toString());
      // Column 2: payload_id
      item->setText(2, s["payload_id"].toString());
      item->setText(3, s["description"].toString());

      // Show args_template (5th column)
      QString argsStr = s["args_template"].toString();
      if (argsStr.isEmpty()) argsStr = s["args"].toString();
      if (argsStr.length() > 2 && argsStr.startsWith('[')) {
        argsStr = argsStr.mid(1, argsStr.length() - 2);
        argsStr.replace('"', ' ').replace(',', ' ');
      }
      item->setText(4, argsStr.trimmed().left(120));
    }
    // Update step count in list table
    for (int r = 0; r < m_listTable->rowCount(); r++) {
      auto *rItem = m_listTable->item(r, 0);
      if (rItem && rItem->data(Qt::UserRole).toString() == d["playbook_id"].toString()) {
        m_listTable->setItem(r, 3, new QTableWidgetItem(QString::number(steps.size())));
        break;
      }
    }
  });
}

void PlaybookPage::onDeletePlaybook() {
  if (m_selectedId.isEmpty()) return;
  auto reply = QMessageBox::question(this->window(), "确认删除",
    QString("确定要删除此预案吗？此操作不可撤销。"),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;
  m_api->del("/api/playbooks/" + m_selectedId, 5000, [this](const QJsonObject &) {
    m_selectedId.clear();
    m_detailTree->clear();
    m_detailLabel->setText("选择 Playbook 查看详情");
    m_goExecBtn->setEnabled(false);
    onLoadList();
  });
}

// ── Go to Execute ─────────────────────────────────────────────────────
void PlaybookPage::onGoExecute() {
  if (m_selectedId.isEmpty()) {
    QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("请先在左侧列表中选择一个预案，再点击此按钮！"));
    return;
  }
  // Use direct callback for navigation (more reliable than signal across widgets)
  if (m_goExecuteCb) {
    m_goExecuteCb(m_selectedId);
  }
  // Also emit signal for any other listeners
  emit executeRequested(m_selectedId);
}

// ── New Playbook ─────────────────────────────────────────────────────
void PlaybookPage::onNewPlaybook() {
  QDialog dlg(this);
  dlg.setWindowTitle("新建预案");
  dlg.setMinimumWidth(420);

  auto *form = new QFormLayout(&dlg);

  auto *nameEdit = new QLineEdit;
  nameEdit->setPlaceholderText("例: SMB 弱口令检测");
  form->addRow("名称*:", nameEdit);

  auto *descEdit = new QTextEdit;
  descEdit->setMaximumHeight(60);
  descEdit->setPlaceholderText("简要描述此预案的用途");
  form->addRow("描述:", descEdit);

  auto *groupCombo = new QComboBox;
  groupCombo->addItem("侦察", "recon");
  groupCombo->addItem("漏洞扫描", "vuln_scan");
  groupCombo->addItem("暴力破解", "brute");
  groupCombo->addItem("漏洞利用", "exploit");
  form->addRow("基线组:", groupCombo);

  auto *diffCombo = new QComboBox;
  diffCombo->addItem("简单", "easy");
  diffCombo->addItem("中等", "medium");
  diffCombo->addItem("困难", "hard");
  diffCombo->setCurrentIndex(1);
  form->addRow("难度:", diffCombo);

  auto *categoryEdit = new QLineEdit;
  categoryEdit->setPlaceholderText("例: credential_access");
  form->addRow("分类:", categoryEdit);

  auto *targetEdit = new QLineEdit;
  targetEdit->setPlaceholderText("例: windows, linux");
  form->addRow("目标类型:", targetEdit);

  auto *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  form->addRow(btnBox);
  connect(btnBox, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(btnBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

  if (dlg.exec() != QDialog::Accepted) return;

  QString name = nameEdit->text().trimmed();
  if (name.isEmpty()) {
    QMessageBox::warning(this, "提示", "名称不能为空");
    return;
  }

  QString playbookId = "pb_" + QUuid::createUuid().toString(QUuid::Id128).left(12);

  QJsonObject body;
  body["playbook_id"] = playbookId;
  body["name"] = name;
  body["description"] = descEdit->toPlainText().trimmed();
  body["baseline_group"] = groupCombo->currentData().toString();
  body["difficulty"] = diffCombo->currentData().toString();
  body["category"] = categoryEdit->text().trimmed();

  QString targetType = targetEdit->text().trimmed();
  if (!targetType.isEmpty()) {
    QJsonArray arr;
    for (const auto &t : targetType.split(',', Qt::SkipEmptyParts)) {
      arr.append(t.trimmed());
    }
    body["target_type"] = arr;
  }

  body["steps"] = QJsonArray();

  m_newBtn->setEnabled(false);
  m_newBtn->setText("创建中...");

  m_api->post("/api/playbooks", body, 10000, [this](const QJsonObject &res) {
    m_newBtn->setEnabled(true);
    m_newBtn->setText("＋ 新建");

    if (res["status"].toString() == "ok") {
      onLoadList();
    } else {
      QMessageBox::warning(this, "创建失败", res["error"].toObject()["message"].toString());
    }
  });
}
