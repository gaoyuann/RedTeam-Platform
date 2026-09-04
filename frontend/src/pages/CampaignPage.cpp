#include "CampaignPage.h"
#include "../Theme.h"
#include "../ApiClient.h"
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QRegularExpression>
#include <QFormLayout>
#include <QComboBox>
#include <QUuid>

CampaignPage::CampaignPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : BasePage(api, role, username, parent) {
  setupUI();
  onRefreshList();
}

void CampaignPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(12, 8, 12, 8);

  // ── Splitter: left (list) | right (detail) ────────────────────────────
  auto *splitter = new QSplitter(Qt::Horizontal, this);

  // ── Left panel ────────────────────────────────────────────────────────
  auto *leftWidget = new QWidget;
  auto *leftLayout = new QVBoxLayout(leftWidget);
  leftLayout->setContentsMargins(8, 8, 8, 8);

  auto *titleLabel = createSectionHeader(QStringLiteral("攻击战役"));
  leftLayout->addWidget(titleLabel);

  m_listTable = createReadOnlyTable(4, {"名称", "目标", "状态", "创建时间"});
  m_listTable->setSortingEnabled(true);
  leftLayout->addWidget(m_listTable, 1);

  auto *btnRow = new QHBoxLayout;
  m_newBtn = new QPushButton("＋ 新建战役");
  m_newBtn->setProperty("primary", true);
  m_delBtn = new QPushButton("删除");
  m_delBtn->setProperty("danger", true);
  btnRow->addWidget(m_newBtn);
  btnRow->addStretch();
  btnRow->addWidget(m_delBtn);
  leftLayout->addLayout(btnRow);

  // ── Right panel ───────────────────────────────────────────────────────
  auto *rightWidget = new QWidget;
  auto *rightLayout = new QVBoxLayout(rightWidget);
  rightLayout->setContentsMargins(8, 8, 8, 8);

  // Campaign info
  auto *infoRow = new QHBoxLayout;
  m_nameLabel = new QLabel("选择战役查看详情");
  m_nameLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
  infoRow->addWidget(m_nameLabel);
  infoRow->addStretch();
  m_statusLabel = new QLabel;
  m_statusLabel->setStyleSheet("font-size: 14px;");
  infoRow->addWidget(m_statusLabel);
  rightLayout->addLayout(infoRow);

  m_targetLabel = new QLabel;
  m_targetLabel->setStyleSheet("color: #718096; font-size: 13px;");
  rightLayout->addWidget(m_targetLabel);

  // Step indicator (3-phase progress)
  m_stepIndicator = new StepIndicator(this);
  rightLayout->addWidget(m_stepIndicator);

  // Phase panel (playbook orchestration + artifacts)
  m_phasePanel = new PhasePanel(m_api, this);
  rightLayout->addWidget(m_phasePanel, 1);

  // Action buttons
  auto *actionRow = new QHBoxLayout;
  m_startBtn = new QPushButton("▶ 启动战役");
  m_startBtn->setProperty("primary", true);
  m_pauseBtn = new QPushButton("⏸ 暂停");
  m_abortBtn = new QPushButton("⏹ 终止");
  m_abortBtn->setProperty("danger", true);
  m_reportBtn = new QPushButton("查看报告");
  actionRow->addWidget(m_startBtn);
  actionRow->addWidget(m_pauseBtn);
  actionRow->addWidget(m_abortBtn);
  actionRow->addStretch();
  actionRow->addWidget(m_reportBtn);
  rightLayout->addLayout(actionRow);

  // Initially disable action buttons
  m_startBtn->setEnabled(false);
  m_pauseBtn->setEnabled(false);
  m_abortBtn->setEnabled(false);
  m_reportBtn->setEnabled(false);

  splitter->addWidget(leftWidget);
  splitter->addWidget(rightWidget);
  splitter->setStretchFactor(0, 2);
  splitter->setStretchFactor(1, 3);
  splitter->setSizes({350, 600});
  mainLayout->addWidget(splitter, 1);

  // ── Connections ───────────────────────────────────────────────────────
  connect(m_listTable, &QTableWidget::cellClicked, this, &CampaignPage::onCampaignClicked);
  connect(m_newBtn, &QPushButton::clicked, this, &CampaignPage::onNewCampaign);
  connect(m_delBtn, &QPushButton::clicked, this, &CampaignPage::onDeleteCampaign);
  connect(m_startBtn, &QPushButton::clicked, this, &CampaignPage::onStartCampaign);
  connect(m_pauseBtn, &QPushButton::clicked, this, &CampaignPage::onPauseCampaign);
  connect(m_abortBtn, &QPushButton::clicked, this, &CampaignPage::onAbortCampaign);
  connect(m_reportBtn, &QPushButton::clicked, this, &CampaignPage::onViewReport);
  connect(m_stepIndicator, &StepIndicator::phaseClicked, this, &CampaignPage::onPhaseClicked);
  connect(m_phasePanel, &PhasePanel::phaseChanged, this, &CampaignPage::onPhaseChanged);
}

// ── Refresh ─────────────────────────────────────────────────────────────
void CampaignPage::refresh() {
  onRefreshList();
}

void CampaignPage::onRefreshList() {
  apiGet("/api/campaigns", 5000, [this](const QJsonObject &res) {
    auto arr = res["data"].toArray();
    const bool sortingEnabled = m_listTable->isSortingEnabled();
    m_listTable->setSortingEnabled(false);
    m_listTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      auto *nameItem = new QTableWidgetItem(c["name"].toString());
      nameItem->setData(Qt::UserRole, c["campaign_id"].toString());
      m_listTable->setItem(i, 0, nameItem);
      m_listTable->setItem(i, 1, new QTableWidgetItem(c["target"].toString()));
      m_listTable->setItem(i, 2, new QTableWidgetItem(c["status_cn"].toString()));
      m_listTable->setItem(i, 3, new QTableWidgetItem(c["created_at"].toString()));
    }
    m_listTable->resizeColumnsToContents();
    m_listTable->horizontalHeader()->setStretchLastSection(true);
    m_listTable->setSortingEnabled(sortingEnabled);

    for (int row = 0; row < m_listTable->rowCount(); ++row) {
      auto *item = m_listTable->item(row, 0);
      if (item && item->data(Qt::UserRole).toString() == m_selectedId) {
        m_listTable->selectRow(row);
        break;
      }
    }
  });
}

// ── Campaign clicked ────────────────────────────────────────────────────
void CampaignPage::onCampaignClicked(int row, int) {
  auto *item = m_listTable->item(row, 0);
  if (!item) return;
  m_selectedId = item->data(Qt::UserRole).toString();
  loadCampaignDetail(m_selectedId);
}

void CampaignPage::loadCampaignDetail(const QString &campaignId) {
  apiGet("/api/campaigns/" + campaignId, 5000, [this, campaignId](const QJsonObject &res) {
    m_currentCampaign = res["data"].toObject();

    m_nameLabel->setText(m_currentCampaign["name"].toString());
    m_targetLabel->setText("目标: " + m_currentCampaign["target"].toString());

    QString status = m_currentCampaign["status"].toString();
    QString statusCn = m_currentCampaign["status_cn"].toString();
    m_statusLabel->setText("状态: " + statusCn);

    // Color status
    QString color;
    if (status == "running") color = "#2a7dd6";
    else if (status == "completed") color = "#27ae60";
    else if (status == "failed" || status == "aborted") color = "#e74c3c";
    else if (status == "paused") color = "#b45309";
    else color = "#718096";
    m_statusLabel->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: bold;").arg(color));

    // Update step indicator
    QVector<PhaseStep> steps;
    auto phases = m_currentCampaign["phases"].toArray();
    for (const auto &p : phases) {
      auto po = p.toObject();
      PhaseStep step;
      step.phaseType = po["phase_type"].toString();
      step.displayName = po["display_name"].toString();
      step.phaseId = po["phase_id"].toString();
      step.status = po["status"].toString();
      steps.append(step);
    }
    m_stepIndicator->setPhases(steps);

    // Show first non-completed phase, or first phase
    m_activePhaseIndex = 0;
    for (int i = 0; i < steps.size(); i++) {
      if (steps[i].status != "completed" && steps[i].status != "skipped") {
        m_activePhaseIndex = i;
        break;
      }
    }

    // Show phase panel for active phase
    if (m_activePhaseIndex < phases.size()) {
      m_phasePanel->setPhase(phases[m_activePhaseIndex].toObject(), campaignId);
    } else {
      m_phasePanel->clear();
    }

    updateActionButtons();
  });
}

void CampaignPage::updateActionButtons() {
  QString status = m_currentCampaign["status"].toString();
  bool hasSelection = !m_selectedId.isEmpty();

  m_startBtn->setEnabled(hasSelection && (status == "draft" || status == "paused"));
  m_pauseBtn->setEnabled(hasSelection && status == "running");
  m_abortBtn->setEnabled(hasSelection && (status == "running" || status == "paused"));
  m_reportBtn->setEnabled(hasSelection);
}

// ── New campaign ────────────────────────────────────────────────────────
void CampaignPage::onNewCampaign() {
  QDialog dlg(this);
  dlg.setWindowTitle("新建攻击战役");
  dlg.setMinimumWidth(420);

  auto *form = new QFormLayout(&dlg);

  auto *nameEdit = new QLineEdit;
  nameEdit->setPlaceholderText("例: 内网渗透测试-2026");
  nameEdit->setAttribute(Qt::WA_InputMethodEnabled, true);
  form->addRow("名称*:", nameEdit);

  auto *descEdit = new QTextEdit;
  descEdit->setMaximumHeight(60);
  descEdit->setPlaceholderText("战役描述");
  descEdit->setAttribute(Qt::WA_InputMethodEnabled, true);
  form->addRow("描述:", descEdit);

  auto *targetEdit = new QLineEdit;
  targetEdit->setPlaceholderText("例: 192.168.1.0/24");
  targetEdit->setAttribute(Qt::WA_InputMethodEnabled, true);
  targetEdit->setInputMethodHints(Qt::ImhPreferLatin);
  form->addRow("目标*:", targetEdit);

  // Phase checkboxes
  auto *phaseWidget = new QWidget;
  auto *phaseLayout = new QVBoxLayout(phaseWidget);
  phaseLayout->setContentsMargins(0, 0, 0, 0);
  auto *cb1 = new QCheckBox("① 数据抵近窃取"); cb1->setChecked(true);
  auto *cb2 = new QCheckBox("② 信息篡改欺骗"); cb2->setChecked(true);
  auto *cb3 = new QCheckBox("③ 关键设备夺控"); cb3->setChecked(true);
  phaseLayout->addWidget(cb1);
  phaseLayout->addWidget(cb2);
  phaseLayout->addWidget(cb3);
  form->addRow("阶段配置:", phaseWidget);

  auto *autoAdvanceCb = new QCheckBox("阶段完成后自动推进");
  autoAdvanceCb->setChecked(true);
  form->addRow("自动推进:", autoAdvanceCb);

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

  QString target = targetEdit->text().trimmed();
  if (target.isEmpty()) {
    QMessageBox::warning(this, "提示", "目标地址不能为空");
    return;
  }
  // IP/CIDR/主机名格式校验
  QRegularExpression ipCidr(R"(^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$)");
  QRegularExpression hostname(R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$)");
  if (!ipCidr.match(target).hasMatch() && !hostname.match(target).hasMatch()) {
    QMessageBox::warning(this, "提示", "目标地址格式无效，仅支持 IP、网段或主机名");
    return;
  }

  // 至少启用一个阶段
  if (!cb1->isChecked() && !cb2->isChecked() && !cb3->isChecked()) {
    QMessageBox::warning(this, "提示", "至少需要启用一个阶段");
    return;
  }

  QJsonObject body;
  body["name"] = name;
  body["description"] = descEdit->toPlainText().trimmed();
  body["target"] = targetEdit->text().trimmed();
  body["auto_advance"] = autoAdvanceCb->isChecked();

  QJsonObject phases;
  phases["data-exfiltration"] = cb1->isChecked();
  phases["tampering-deception"] = cb2->isChecked();
  phases["device-control"] = cb3->isChecked();
  body["phases"] = phases;

  m_newBtn->setEnabled(false);
  m_newBtn->setText("创建中...");

  apiPost("/api/campaigns", body, 5000, [this](const QJsonObject &res) {
    m_newBtn->setEnabled(true);
    m_newBtn->setText("＋ 新建战役");
    if (res["status"].toString() == "ok") {
      onRefreshList();
    } else {
      QMessageBox::warning(this, "创建失败", res["error"].toObject()["message"].toString());
    }
  }, [this]() {
    m_newBtn->setEnabled(true);
    m_newBtn->setText("＋ 新建战役");
  });
}

// ── Delete campaign ─────────────────────────────────────────────────────
void CampaignPage::onDeleteCampaign() {
  if (m_selectedId.isEmpty()) return;
  if (!confirmDelete("战役")) return;

  apiDel("/api/campaigns/" + m_selectedId, 5000, [this](const QJsonObject &) {
    m_selectedId.clear();
    m_currentCampaign = QJsonObject();
    m_nameLabel->setText("选择战役查看详情");
    m_targetLabel->clear();
    m_statusLabel->clear();
    m_phasePanel->clear();
    m_stepIndicator->setPhases({});
    updateActionButtons();
    onRefreshList();
  });
}

// ── Campaign actions ────────────────────────────────────────────────────
void CampaignPage::onStartCampaign() {
  if (m_selectedId.isEmpty()) return;

  // 前置校验：目标地址
  if (m_currentCampaign["target"].toString().trimmed().isEmpty()) {
    QMessageBox::warning(this, "提示", "战役未设置目标地址，请先编辑战役");
    return;
  }

  // 前置校验：至少有一个 Playbook
  auto phases = m_currentCampaign["phases"].toArray();
  bool hasAnyPlaybook = false;
  for (const auto &p : phases) {
    auto pbs = p.toObject()["playbooks"].toArray();
    if (pbs.size() > 0) { hasAnyPlaybook = true; break; }
  }
  if (!hasAnyPlaybook) {
    QMessageBox::warning(this, "提示", "战役没有任何预案，请先为阶段添加预案");
    return;
  }

  apiPost("/api/campaigns/" + m_selectedId + "/start", QJsonObject(), 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      loadCampaignDetail(m_selectedId);
    } else {
      QMessageBox::warning(this, "启动失败", res["error"].toObject()["message"].toString());
    }
  });
}

void CampaignPage::onPauseCampaign() {
  if (m_selectedId.isEmpty()) return;
  apiPost("/api/campaigns/" + m_selectedId + "/pause", QJsonObject(), 5000, [this](const QJsonObject &) {
    loadCampaignDetail(m_selectedId);
  });
}

void CampaignPage::onAbortCampaign() {
  if (m_selectedId.isEmpty()) return;
  auto reply = QMessageBox::question(this, "终止战役", "确定要终止此战役吗？运行中的预案将被中断。",
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;

  apiPost("/api/campaigns/" + m_selectedId + "/abort", QJsonObject(), 5000, [this](const QJsonObject &) {
    loadCampaignDetail(m_selectedId);
  });
}

void CampaignPage::onViewReport() {
  if (m_selectedId.isEmpty()) return;
  apiGet("/api/campaigns/" + m_selectedId + "/report", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto report = res["data"].toObject();

    QString text = QString("战役: %1\n目标: %2\n状态: %3\n\n")
      .arg(report["name"].toString(), report["target"].toString(), report["status"].toString());

    auto phases = report["phases"].toArray();
    for (const auto &p : phases) {
      auto po = p.toObject();
      text += QString("【%1】状态: %2\n").arg(po["display_name"].toString(), po["status"].toString());
    }

    auto artSummary = report["artifact_summary"].toObject();
    text += QString("\n产物总数: %1").arg(artSummary["total"].toInt());

    QMessageBox::information(this, "战役报告", text);
  });
}

// ── Phase interaction ───────────────────────────────────────────────────
void CampaignPage::onPhaseClicked(int index) {
  m_activePhaseIndex = index;
  auto phases = m_currentCampaign["phases"].toArray();
  if (index >= 0 && index < phases.size()) {
    m_phasePanel->setPhase(phases[index].toObject(), m_selectedId);
  }
}

void CampaignPage::onPhaseChanged() {
  // Refresh campaign detail after phase modification
  if (!m_selectedId.isEmpty()) {
    loadCampaignDetail(m_selectedId);
  }
}
