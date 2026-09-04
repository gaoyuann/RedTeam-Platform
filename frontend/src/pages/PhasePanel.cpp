#include "PhasePanel.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDialog>
#include <QDialogButtonBox>
#include <QMessageBox>

// ── PhasePanel ─────────────────────────────────────────────────────────

PhasePanel::PhasePanel(ApiClient *api, QWidget *parent)
    : QWidget(parent)
    , m_api(api)
{
  setupUI();
  clear();
}

void PhasePanel::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(8, 8, 8, 8);
  mainLayout->setSpacing(8);

  // ── Phase title ──────────────────────────────────────────────────
  m_phaseTitle = new QLabel("阶段: --");
  m_phaseTitle->setStyleSheet("font-size: 14px; font-weight: bold; color: #1a2a3a;");
  mainLayout->addWidget(m_phaseTitle);

  // ── Playbook table ───────────────────────────────────────────────
  auto *pbLabel = new QLabel("阶段预案"); pbLabel->setStyleSheet(Theme::SectionStyle);
  mainLayout->addWidget(pbLabel);

  m_playbookTable = new QTableWidget(0, 4);
  m_playbookTable->setHorizontalHeaderLabels({"顺序", "预案", "模式", "状态"});
  m_playbookTable->setAlternatingRowColors(true);
  m_playbookTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_playbookTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_playbookTable->setSortingEnabled(true);
  m_playbookTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  mainLayout->addWidget(m_playbookTable, 1);

  // ── Buttons row ──────────────────────────────────────────────────
  auto *btnH = new QHBoxLayout;
  m_addPbBtn = new QPushButton("＋ 添加预案");
  m_addPbBtn->setProperty("primary", true);
  m_removePbBtn = new QPushButton("移除");
  m_removePbBtn->setProperty("danger", true);
  m_skipBtn = new QPushButton("跳过此阶段");
  m_skipBtn->setStyleSheet(
    "background:#fff7ed; color:#b45309; border:1px solid #fed7aa; "
    "border-radius:8px; padding:8px 14px; font-weight:600;");
  btnH->addWidget(m_addPbBtn);
  btnH->addWidget(m_removePbBtn);
  btnH->addStretch();
  btnH->addWidget(m_skipBtn);
  mainLayout->addLayout(btnH);

  connect(m_addPbBtn, &QPushButton::clicked, this, &PhasePanel::onAddPlaybook);
  connect(m_removePbBtn, &QPushButton::clicked, this, &PhasePanel::onRemovePlaybook);
  connect(m_skipBtn, &QPushButton::clicked, this, &PhasePanel::onSkipPhase);

  // ── Artifacts section ────────────────────────────────────────────
  auto *artLabel = new QLabel("阶段产物"); artLabel->setStyleSheet(Theme::SectionStyle);
  mainLayout->addWidget(artLabel);

  m_artifactTable = new QTableWidget(0, 3);
  m_artifactTable->setHorizontalHeaderLabels({"类型", "键", "值摘要"});
  m_artifactTable->setAlternatingRowColors(true);
  m_artifactTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_artifactTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_artifactTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  mainLayout->addWidget(m_artifactTable, 1);
}

// ── Set phase data ─────────────────────────────────────────────────────

void PhasePanel::setPhase(const QJsonObject &phase, const QString &campaignId) {
  m_phase = phase;
  m_campaignId = campaignId;

  QString phaseName = phase["name"].toString();
  QString phaseStatus = phase["status"].toString();
  QString statusCn;
  if (phaseStatus == "pending") statusCn = "待执行";
  else if (phaseStatus == "running") statusCn = "运行中";
  else if (phaseStatus == "completed") statusCn = "已完成";
  else if (phaseStatus == "skipped") statusCn = "已跳过";
  else if (phaseStatus == "failed") statusCn = "失败";
  else statusCn = phaseStatus;
  m_phaseTitle->setText(QString("阶段: %1 [%2]").arg(phaseName, statusCn));

  const bool editable = phaseStatus == "pending";
  m_addPbBtn->setEnabled(editable);
  m_removePbBtn->setEnabled(editable);
  m_skipBtn->setEnabled(editable);

  loadPlaybooksForPhase();
  loadArtifactsForPhase();
}

// ── Clear state ───────────────────────────────────────────────────────

void PhasePanel::clear() {
  m_phase = QJsonObject();
  m_campaignId.clear();
  m_phaseTitle->setText("阶段: --");
  m_playbookTable->setRowCount(0);
  m_artifactTable->setRowCount(0);
  m_addPbBtn->setEnabled(false);
  m_removePbBtn->setEnabled(false);
  m_skipBtn->setEnabled(false);
}

QJsonObject PhasePanel::currentPhase() const {
  return m_phase;
}

// ── Load playbooks for this phase ─────────────────────────────────────

void PhasePanel::loadPlaybooksForPhase() {
  QString phaseId = m_phase["phase_id"].toString();
  if (phaseId.isEmpty() || m_campaignId.isEmpty()) return;

  m_api->get("/api/campaigns/" + m_campaignId, 5000, [this, phaseId](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto data = res["data"].toObject();
    auto phases = data["phases"].toArray();

    // Find the phase with matching phase_id
    QJsonArray playbooks;
    for (int i = 0; i < phases.size(); i++) {
      auto p = phases[i].toObject();
      if (p["phase_id"].toString() == phaseId) {
        playbooks = p["playbooks"].toArray();
        break;
      }
    }

    const bool sortingEnabled = m_playbookTable->isSortingEnabled();
    m_playbookTable->setSortingEnabled(false);
    m_playbookTable->setRowCount(playbooks.size());
    for (int i = 0; i < playbooks.size(); i++) {
      auto pb = playbooks[i].toObject();

      // Column 0: execution order
      auto *orderItem = new QTableWidgetItem();
      orderItem->setData(Qt::DisplayRole, pb["execution_order"].toInt());
      m_playbookTable->setItem(i, 0, orderItem);

      // Column 1: playbook name
      QString pbName = pb["playbook_name"].toString();
      if (pbName.isEmpty()) pbName = pb["playbook_id"].toString();
      m_playbookTable->setItem(i, 1, new QTableWidgetItem(pbName));

      // Column 2: execution mode (translate)
      QString mode = pb["execution_mode"].toString();
      QString modeCn;
      if (mode == "sequential") modeCn = "串行";
      else if (mode == "parallel") modeCn = "并行";
      else if (mode == "conditional") modeCn = "条件";
      else modeCn = mode;
      m_playbookTable->setItem(i, 2, new QTableWidgetItem(modeCn));

      // Column 3: status with Chinese translation + icon
      QString st = pb["status"].toString();
      QString statusText;
      if (st == "pending") statusText = "⏳ 待执行";
      else if (st == "running") statusText = "▶ 运行中";
      else if (st == "completed") statusText = "✓ 已完成";
      else if (st == "failed") statusText = "✗ 失败";
      else if (st == "skipped") statusText = "⏭ 已跳过";
      else statusText = st;
      m_playbookTable->setItem(i, 3, new QTableWidgetItem(statusText));

      // Store campaign_playbook id in UserRole for removal
      QString cpId = pb["campaign_playbook_id"].toString();
      if (!cpId.isEmpty()) {
        m_playbookTable->item(i, 0)->setData(Qt::UserRole, cpId);
      }
    }
    m_playbookTable->resizeColumnsToContents();
    m_playbookTable->horizontalHeader()->setStretchLastSection(true);
    m_playbookTable->setSortingEnabled(sortingEnabled);
  });
}

// ── Load artifacts for this phase ─────────────────────────────────────

void PhasePanel::loadArtifactsForPhase() {
  QString phaseId = m_phase["phase_id"].toString();
  if (phaseId.isEmpty() || m_campaignId.isEmpty()) return;

  m_api->get("/api/campaigns/" + m_campaignId + "/artifacts?phase_id=" + phaseId,
    5000, [this](const QJsonObject &res) {
      if (res["status"].toString() != "ok") return;
      auto arr = res["data"].toArray();

      m_artifactTable->setRowCount(arr.size());
      for (int i = 0; i < arr.size(); i++) {
        auto a = arr[i].toObject();
        m_artifactTable->setItem(i, 0, new QTableWidgetItem(a["artifact_type"].toString()));
        m_artifactTable->setItem(i, 1, new QTableWidgetItem(a["artifact_key"].toString()));

        // Truncate value to 100 chars
        QString val = a["artifact_value"].toString();
        if (val.length() > 100) val = val.left(100) + "...";
        m_artifactTable->setItem(i, 2, new QTableWidgetItem(val));
      }
      m_artifactTable->resizeColumnsToContents();
      m_artifactTable->horizontalHeader()->setStretchLastSection(true);
    });
}

// ── Add playbook to phase ─────────────────────────────────────────────

void PhasePanel::onAddPlaybook() {
  QString phaseId = m_phase["phase_id"].toString();
  QString phaseType = m_phase["phase_type"].toString();
  if (phaseId.isEmpty() || m_campaignId.isEmpty()) return;

  // Map campaign phase_type to playbook baseline_group values
  // Campaign phases (data-exfiltration / tampering-deception / device-control)
  // don't directly match existing baseline_group values, so we map them:
  QStringList groups;
  if (phaseType == "data-exfiltration") {
    groups = QStringList() << "recon" << "domain-osint" << "internal-network-exploitation";
  } else if (phaseType == "tampering-deception") {
    groups = QStringList() << "web-vuln-scan" << "local-security-check";
  } else if (phaseType == "device-control") {
    groups = QStringList() << "windows-exploitation" << "post-exploitation" << "impact-demonstration";
  } else {
    groups = QStringList() << phaseType;
  }

  // Fetch all playbooks, then filter client-side by matching baseline_groups
  m_api->get("/api/playbooks", 5000,
    [this, phaseId, groups, phaseType](const QJsonObject &res) {
      if (res["status"].toString() != "ok") {
        QMessageBox::warning(this, "错误", "获取预案列表失败");
        return;
      }

      auto allPlaybooks = res["data"].toArray();
      QJsonArray candidates;
      for (const auto &pb : allPlaybooks) {
        QString bg = pb.toObject()["baseline_group"].toString();
        if (groups.contains(bg)) {
          candidates.append(pb);
        }
      }

      if (candidates.isEmpty()) {
        QString groupNames = groups.join(", ");
        QMessageBox::information(this, "提示",
          QString("当前阶段类型\"%1\"没有匹配的预案\n\n"
                  "匹配的 baseline_group: %2\n\n"
                  "请先在\"漏洞利用想定与预案\"中创建对应类型的预案")
            .arg(phaseType, groupNames));
        return;
      }

      // Build dialog
      QDialog dlg(this);
      dlg.setWindowTitle("添加预案");
      dlg.setMinimumWidth(400);
      auto *dlgLayout = new QVBoxLayout(&dlg);

      auto *combo = new QComboBox(&dlg);
      for (int i = 0; i < candidates.size(); i++) {
        auto pb = candidates[i].toObject();
        QString label = pb["name"].toString() + " [" + pb["playbook_id"].toString() + "]";
        combo->addItem(label, pb["playbook_id"].toString());
      }
      dlgLayout->addWidget(new QLabel("选择预案："));
      dlgLayout->addWidget(combo);

      auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
      dlgLayout->addWidget(buttons);
      connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
      connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

      if (dlg.exec() != QDialog::Accepted) return;

      QString playbookId = combo->currentData().toString();
      if (playbookId.isEmpty()) return;

      // POST to add playbook to phase
      QJsonObject body;
      body["playbook_id"] = playbookId;
      body["execution_mode"] = "sequential";
      m_api->post("/api/campaigns/" + m_campaignId + "/phases/" + phaseId + "/playbooks",
        body, 5000, [this](const QJsonObject &postRes) {
          if (postRes["status"].toString() != "ok") return;
          loadPlaybooksForPhase();
          emit phaseChanged();
        });
    });
}

// ── Remove playbook from phase ────────────────────────────────────────

void PhasePanel::onRemovePlaybook() {
  QString phaseId = m_phase["phase_id"].toString();
  if (phaseId.isEmpty() || m_campaignId.isEmpty()) return;

  int row = m_playbookTable->currentRow();
  if (row < 0) return;

  auto *item = m_playbookTable->item(row, 0);
  if (!item) return;

  QString cpId = item->data(Qt::UserRole).toString();
  if (cpId.isEmpty()) return;

  if (QMessageBox::question(this, "移除预案", "确定要从该阶段移除此预案吗？",
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
      != QMessageBox::Yes) {
    return;
  }

  m_api->del("/api/campaigns/" + m_campaignId + "/phases/" + phaseId + "/playbooks/" + cpId,
    5000, [this](const QJsonObject &res) {
      if (res["status"].toString() != "ok") return;
      loadPlaybooksForPhase();
      emit phaseChanged();
    });
}

// ── Skip this phase ───────────────────────────────────────────────────

void PhasePanel::onSkipPhase() {
  QString phaseId = m_phase["phase_id"].toString();
  if (phaseId.isEmpty() || m_campaignId.isEmpty()) return;

  m_api->put("/api/campaigns/" + m_campaignId + "/phases/" + phaseId + "/skip",
    QJsonObject(), 5000, [this](const QJsonObject &res) {
      if (res["status"].toString() != "ok") return;
      emit phaseChanged();
    });
}
