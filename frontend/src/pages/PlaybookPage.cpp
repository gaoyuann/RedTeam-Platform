#include "../widgets/WorkbenchTabs.h"
#include "PlaybookPage.h"
#include "KnowledgeGraphPage.h"
#include "PayloadPage.h"
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
#include "../UiUtil.h"
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QPointer>
#include <QTimer>
#include <cstdio>
#include <QShowEvent>

PlaybookPage::PlaybookPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username) {
  setupUI();
  onLoadList();
}

void PlaybookPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->setContentsMargins(0, 0, 0, 0);
  outerLayout->setSpacing(0);

  m_tabs = new WorkbenchTabs(this);

  // ── Tab 0: Playbook 库 ───────────────────────────────────────────
  m_playbookTab = new QWidget(m_tabs);
  auto *mainLayout = new QVBoxLayout(m_playbookTab);

  // Left: list
  auto *left = new QVBoxLayout;
  auto *filterH = new QHBoxLayout;
  m_groupFilter = new QComboBox;
  m_groupFilter->addItem("全部", "");
  m_groupFilter->addItem("侦察", "recon");
  m_groupFilter->addItem("网站漏洞扫描", "web-vuln-scan");
  m_groupFilter->addItem("Windows利用", "windows-exploitation");
  m_groupFilter->addItem("后渗透", "post-exploitation");
  m_groupFilter->addItem("内网横向", "internal-network-exploitation");
  m_groupFilter->addItem("本地安全检查", "local-security-check");
  m_groupFilter->addItem("影响演示", "impact-demonstration");
  m_groupFilter->addItem("域信息收集", "domain-osint");
  m_groupFilter->addItem("数据抵近窃取", "data-exfiltration");
  m_groupFilter->addItem("信息篡改欺骗", "tampering-deception");
  m_groupFilter->addItem("关键设备夺控", "device-control");
  m_showGenerated = new QCheckBox("包含智能生成内容");
  filterH->addWidget(new QLabel("基线组:"));
  filterH->addWidget(m_groupFilter);
  filterH->addWidget(m_showGenerated);
  filterH->addStretch();
  left->addLayout(filterH);

  auto *titleLabel = new QLabel("战术手册（预案）");
  titleLabel->setStyleSheet(Theme::SectionStyle);
  left->addWidget(titleLabel);

  m_listTable = new QTableWidget(0, 4);
  m_listTable->setObjectName("playbookListTable");
  UiUtil::EmptyHint::attach(m_listTable, QStringLiteral("暂无预案 · 可从扫描结果智能生成"));
  m_listTable->setHorizontalHeaderLabels({"名称", "难度", "基线组", "步骤数"});
  m_listTable->setAlternatingRowColors(true);
  m_listTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_listTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_listTable->setSortingEnabled(true);
  m_listTable->setContextMenuPolicy(Qt::CustomContextMenu);
  // 名称列单行省略号 + 悬浮提示；窄窗时 compressListColumns 先压元数据列，
  // 极端窄才出横向滚动条
  m_listTable->setWordWrap(false);
  m_listTable->setTextElideMode(Qt::ElideRight);
  m_listTable->verticalHeader()->setDefaultSectionSize(36);
  m_listTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  // 元数据列 Interactive：用户可拖动调宽；初始首选宽在 resizeSection 里给
  m_listTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
  m_listTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
  m_listTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
  m_listTable->horizontalHeader()->resizeSection(1, 88);
  m_listTable->horizontalHeader()->resizeSection(2, 112);
  m_listTable->horizontalHeader()->resizeSection(3, 64);
  m_listTable->installEventFilter(this);
  left->addWidget(m_listTable);

  auto *btnH = new QHBoxLayout;
  m_newBtn = new QPushButton("＋ 新建");
  m_newBtn->setProperty("primary", true);
  m_deleteBtn = new QPushButton("删除选中");
  m_deleteBtn->setProperty("danger", true);
  m_newBtn->setObjectName("playbookNew");
  m_deleteBtn->setObjectName("playbookDelete");
  m_newBtn->setEnabled(false);
  m_deleteBtn->setEnabled(false);
  btnH->addWidget(m_newBtn);
  btnH->addStretch();
  btnH->addWidget(m_deleteBtn);
  left->addLayout(btnH);
  m_permissionHint = new QLabel(QStringLiteral("正在确认预案编辑权限…"));
  m_permissionHint->setObjectName("playbookPermissionHint");
  m_permissionHint->setWordWrap(true);
  m_permissionHint->setStyleSheet(Theme::StatusInfoStyle);
  left->addWidget(m_permissionHint);

  connect(m_newBtn, &QPushButton::clicked, this, &PlaybookPage::onNewPlaybook);
  connect(m_deleteBtn, &QPushButton::clicked, this, &PlaybookPage::onDeletePlaybook);

  auto *leftW = new QWidget;
  leftW->setLayout(left);
  leftW->setMinimumWidth(400);  // splitter 再挤也不能把列表压到不可读

  // Right: detail — 主从式：上表只留短列（步骤/工具/载荷），描述与参数模板
  // 放下方卡片完整换行。5 列硬塞一行是之前横向滚动、信息截断的根因。
  auto *right = new QVBoxLayout;

  // 预案概要卡片：名称做标题 + 元信息行 + 常规字重描述。
  // 原先名称和整段描述一起塞在 17px 粗体 SectionStyle 里，像一堵字墙
  auto *infoCard = new QFrame;
  infoCard->setProperty("softCard", true);
  auto *infoL = new QVBoxLayout(infoCard);
  infoL->setContentsMargins(14, 10, 14, 10);
  infoL->setSpacing(4);
  m_detailLabel = new QLabel("选择预案查看详情");
  m_detailLabel->setStyleSheet("font-size:16px; font-weight:700; color:#172033;");
  m_detailLabel->setWordWrap(true);
  infoL->addWidget(m_detailLabel);
  m_detailMeta = new QLabel;
  m_detailMeta->setStyleSheet("font-size:12px; color:#7f8c8d;");
  m_detailMeta->setVisible(false);
  infoL->addWidget(m_detailMeta);
  m_detailDesc = new QLabel;
  m_detailDesc->setStyleSheet("font-size:13px; color:#51606f;");
  m_detailDesc->setWordWrap(true);
  m_detailDesc->setTextFormat(Qt::RichText);
  // 富文本 QLabel 的 minimumSizeHint 很宽，会把 splitter 右栏撑到挤瘪左栏，取消水平约束
  m_detailDesc->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
  m_detailDesc->setVisible(false);
  infoL->addWidget(m_detailDesc);
  right->addWidget(infoCard);
  m_detailTree = new QTreeWidget;
  UiUtil::EmptyHint::attach(m_detailTree, QStringLiteral("选择预案后展示步骤"));
  m_detailTree->setHeaderLabels({"步骤", "工具", "载荷"});
  m_detailTree->setRootIsDecorated(false);
  m_detailTree->setUniformRowHeights(true);
  m_detailTree->setAlternatingRowColors(true);
  m_detailTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_detailTree->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  m_detailTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_detailTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_detailTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  right->addWidget(m_detailTree, 3);

  // 步骤详情卡片
  auto *detailCard = new QFrame;
  detailCard->setProperty("softCard", true);
  auto *cardL = new QVBoxLayout(detailCard);
  cardL->setContentsMargins(12, 8, 12, 8);
  cardL->setSpacing(4);
  auto *cardHead = new QHBoxLayout;
  auto *cardTitle = new QLabel("步骤详情");
  cardTitle->setStyleSheet("font-weight:700; color:#172033;");
  cardHead->addWidget(cardTitle);
  cardHead->addStretch();
  m_copyArgsBtn = new QPushButton("复制参数");
  m_copyArgsBtn->setToolTip("复制当前步骤的参数模板到剪贴板");
  m_copyArgsBtn->setProperty("compact", true);
  cardHead->addWidget(m_copyArgsBtn);
  cardL->addLayout(cardHead);
  m_stepDetail = new QTextBrowser;
  m_stepDetail->setFrameShape(QFrame::NoFrame);
  m_stepDetail->setOpenExternalLinks(false);
  m_stepDetail->setStyleSheet("QTextBrowser{background:transparent; border:none;}");
  m_stepDetail->setHtml(QStringLiteral(
    "<div style='color:#b6c2d2;'>在上方选择一个步骤，此处显示其描述与参数模板</div>"));
  cardL->addWidget(m_stepDetail);
  right->addWidget(detailCard, 2);

  connect(m_detailTree, &QTreeWidget::currentItemChanged, this, &PlaybookPage::onStepSelected);
  connect(m_copyArgsBtn, &QPushButton::clicked, this, [this]() {
    auto *item = m_detailTree->currentItem();
    if (!item) return;
    QApplication::clipboard()->setText(item->data(0, Qt::UserRole + 1).toString());
    m_copyArgsBtn->setText("✓ 已复制");
    QTimer::singleShot(1200, this, [this]() { m_copyArgsBtn->setText("复制参数"); });
  });

  auto *rightW = new QWidget;
  rightW->setLayout(right);

  m_splitter = new QSplitter(Qt::Horizontal, m_playbookTab);
  m_splitter->addWidget(leftW);
  m_splitter->addWidget(rightW);
  m_splitter->setStretchFactor(0, 2);
  m_splitter->setStretchFactor(1, 3);
  // 左栏给足名称宽度（右栏改主从式后不再需要 5 列宽度）
  m_splitter->setSizes({470, 530});
  mainLayout->addWidget(m_splitter, 1);

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

  m_tabs->addTab(m_playbookTab, QStringLiteral("Playbook 库"));

  // ── Tab 1: 知识图谱 ──────────────────────────────────────────────
  m_kgTab = new KnowledgeGraphPage(m_api, m_tabs);
  m_tabs->addTab(m_kgTab, QStringLiteral("知识图谱"));

  // ── Tab 2: 载荷样本库 ────────────────────────────────────────────
  m_payloadTab = new PayloadPage(m_api, m_role, m_username, m_tabs);
  m_tabs->addTab(m_payloadTab, QStringLiteral("载荷样本库"));

  outerLayout->addWidget(m_tabs);
}

void PlaybookPage::showEvent(QShowEvent *event) {
  QWidget::showEvent(event);
  refreshPermissions();
}

void PlaybookPage::refreshPermissions() {
  if (m_permissionRequestPending) return;
  m_permissionRequestPending = true;
  m_canWrite = false;
  m_newBtn->setEnabled(false);
  m_deleteBtn->setEnabled(false);
  m_permissionHint->setText(QStringLiteral("正在确认预案编辑权限…"));
  m_permissionHint->show();
  QPointer<PlaybookPage> self(this);
  m_api->get("/api/users/me/permissions", 5000, [this, self](const QJsonObject &res) {
    if (!self) return;
    m_permissionRequestPending = false;
    if (res["status"].toString() != "ok") {
      m_permissionHint->setText(QStringLiteral("无法确认编辑权限，暂不可修改。请检查连接后重新进入此页；旧版服务端需先更新。"));
      return;
    }
    const auto permissions = res["data"].toObject()["playbooks"].toObject();
    m_canWrite = permissions["write"].toBool();
    m_newBtn->setEnabled(m_canWrite);
    m_deleteBtn->setEnabled(m_canWrite);
    m_newBtn->setToolTip(m_canWrite ? QString() : QStringLiteral("当前账号没有预案编辑权限"));
    m_deleteBtn->setToolTip(m_newBtn->toolTip());
    m_permissionHint->setText(permissions["read"].toBool()
      ? QStringLiteral("只读预案库 · 可查看方案；新建和删除需要管理员授予编辑权限。")
      : QStringLiteral("当前账号没有预案读取或编辑权限，请联系管理员。"));
    m_permissionHint->setVisible(!m_canWrite);
  });
}

// ── Formatting helpers ─────────────────────────────────────────────────
QString PlaybookPage::formatDifficulty(const QString &s) {
  if (s.isEmpty()) return "—";
  if (s == "easy" || s == "初级") return "简单";
  if (s == "medium" || s == "中级") return "中等";
  if (s == "hard" || s == "高级") return "困难";
  // 智能生成预案用的另一套难度词表
  if (s == "beginner" || s == "entry") return "入门";
  if (s == "intermediate") return "中等";
  if (s == "advanced") return "高级";
  return s;
}

QString PlaybookPage::formatBaselineGroup(const QString &s) {
  if (s.isEmpty()) return "—";
  if (s == "recon")                           return "侦察";
  if (s == "web-vuln-scan")                   return "网站漏洞扫描";
  if (s == "windows-exploitation")            return "Windows利用";
  if (s == "post-exploitation")               return "后渗透";
  if (s == "internal-network-exploitation")   return "内网横向";
  if (s == "local-security-check")            return "本地安全检查";
  if (s == "impact-demonstration")            return "影响演示";
  if (s == "domain-osint")                    return "域信息收集";
  if (s == "data-exfiltration")               return "数据抵近窃取";
  if (s == "tampering-deception")             return "信息篡改欺骗";
  if (s == "device-control")                  return "关键设备夺控";
  if (s == "credential-access")               return "凭据获取";
  if (s == "brute")                           return "暴力破解";
  if (s == "exploit")                         return "漏洞利用";
  return s;
}

// 左表列宽压缩：窗口变窄时先按比例压缩 难度/基线组/步骤数（悬浮提示兜底），
// 名称列保底 150px；再不够就出横向滚动条（Stretch 列自动取最小宽）
void PlaybookPage::compressListColumns() {
  const int pref[3] = {88, 112, 64};
  const int mins[3] = {64, 64, 52};  // 最小宽以表头不省略为准
  const int nameMin = 150;
  const int rowNoCol = m_listTable->verticalHeader()->width();
  const int avail = m_listTable->viewport()->width() - rowNoCol;
  if (avail <= 0) return;
  const int prefSum = pref[0] + pref[1] + pref[2];
  const int minSum = mins[0] + mins[1] + mins[2];
  if (avail - prefSum >= nameMin) {
    for (int i = 0; i < 3; i++) m_listTable->setColumnWidth(i + 1, pref[i]);
    return;  // 宽松：名称列 Stretch 自动吃剩余
  }
  int nameW = avail - minSum;
  if (nameW < nameMin) nameW = nameMin;  // 挤过头：出横向滚动条
  const double f = qBound(0.0, double(avail - nameW - minSum) / double(prefSum - minSum), 1.0);
  for (int i = 0; i < 3; i++)
    m_listTable->setColumnWidth(i + 1, mins[i] + int((pref[i] - mins[i]) * f));
}

bool PlaybookPage::eventFilter(QObject *watched, QEvent *ev) {
  // Resize 期间布局未定稿，延迟到事件循环下一轮再按最终宽度压缩
  if (watched == m_listTable && ev->type() == QEvent::Resize && !m_compressPending) {
    m_compressPending = true;
    QTimer::singleShot(0, this, [this]() {
      m_compressPending = false;
      compressListColumns();
    });
  }
  return QWidget::eventFilter(watched, ev);
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
    m_listTable->setSortingEnabled(false);
    m_listTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto pb = arr[i].toObject();
      auto *nameItem = new QTableWidgetItem(pb["name"].toString());
      nameItem->setData(Qt::UserRole, pb["playbook_id"].toString());
      nameItem->setToolTip(pb["name"].toString());
      m_listTable->setItem(i, 0, nameItem);
      auto *diffItem = new QTableWidgetItem(formatDifficulty(pb["difficulty"].toString()));
      auto *groupItem = new QTableWidgetItem(formatBaselineGroup(pb["baseline_group"].toString()));
      auto *stepsItem = new QTableWidgetItem(QString::number(pb["steps_count"].toInt()));
      // 窄窗压缩后元数据列可能省略号，悬浮提示兜底
      diffItem->setToolTip(diffItem->text());
      groupItem->setToolTip(groupItem->text());
      m_listTable->setItem(i, 1, diffItem);
      m_listTable->setItem(i, 2, groupItem);
      m_listTable->setItem(i, 3, stepsItem);
    }
    m_listTable->setSortingEnabled(true);
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
      nameItem->setToolTip(pb["name"].toString());
      m_listTable->setItem(i, 0, nameItem);
      auto *diffItem = new QTableWidgetItem(formatDifficulty(pb["difficulty"].toString()));
      auto *groupItem = new QTableWidgetItem(formatBaselineGroup(pb["baseline_group"].toString()));
      auto *stepsItem = new QTableWidgetItem(QString::number(pb["steps_count"].toInt()));
      // 窄窗压缩后元数据列可能省略号，悬浮提示兜底
      diffItem->setToolTip(diffItem->text());
      groupItem->setToolTip(groupItem->text());
      m_listTable->setItem(i, 1, diffItem);
      m_listTable->setItem(i, 2, groupItem);
      m_listTable->setItem(i, 3, stepsItem);
    }
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
    m_detailLabel->setText(d["name"].toString());
    m_detailMeta->setText(QString("%1 · %2 · %3 个步骤")
      .arg(formatDifficulty(d["difficulty"].toString()),
           formatBaselineGroup(d["baseline_group"].toString()),
           QString::number(d["steps"].toArray().size())));
    m_detailMeta->setVisible(true);
    const QString desc = d["description"].toString();
    m_detailDesc->setText(desc.isEmpty() ? QString()
      : desc.toHtmlEscaped().replace('\n', QStringLiteral("<br>")));
    m_detailDesc->setVisible(!desc.isEmpty());

    m_detailTree->clear();
    auto steps = d["steps"].toArray();
    for (int i = 0; i < steps.size(); i++) {
      auto s = steps[i].toObject();
      auto *item = new QTreeWidgetItem(m_detailTree);
      item->setText(0, s["step_id"].toString());
      item->setToolTip(0, s["step_id"].toString());
      item->setText(1, s["tool_id"].toString());
      item->setToolTip(1, s["tool_id"].toString());
      item->setText(2, s["payload_id"].toString());
      item->setToolTip(2, s["payload_id"].toString());
      // 描述/参数模板挂 UserRole(+1)，选中行时由 onStepSelected 在下方卡片完整展示
      item->setData(0, Qt::UserRole, s["description"].toString());

      QString argsStr = s["args_template"].toString();
      if (argsStr.isEmpty()) argsStr = s["args"].toString();
      if (argsStr.length() > 2 && argsStr.startsWith('[')) {
        argsStr = argsStr.mid(1, argsStr.length() - 2);
        argsStr.replace('"', ' ').replace(',', ' ');
      }
      item->setData(0, Qt::UserRole + 1, argsStr.trimmed());
    }
    // 默认选中第一步，详情卡片即刻有内容
    if (m_detailTree->topLevelItemCount() > 0)
      m_detailTree->setCurrentItem(m_detailTree->topLevelItem(0));
    fitDetailTreeHeight();
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

// 步骤表高度随内容走：行少时收缩，把竖向空间让给下方详情卡片；行多时上限内滚动
void PlaybookPage::fitDetailTreeHeight() {
  const int rows = m_detailTree->topLevelItemCount();
  if (rows <= 0) { m_detailTree->setMaximumHeight(140); return; }
  const int h = m_detailTree->header()->height() +
                m_detailTree->visualItemRect(m_detailTree->topLevelItem(rows - 1)).bottom() + 14;
  m_detailTree->setMaximumHeight(qBound(140, h, 400));
}

// 步骤详情卡片：描述/参数模板完整换行展示，过长时卡片内纵向滚动
void PlaybookPage::onStepSelected() {
  fitDetailTreeHeight();  // 清空（删除预案）时同步收缩步骤表
  auto *item = m_detailTree->currentItem();
  if (!item) {
    m_stepDetail->setHtml(QStringLiteral(
      "<div style='color:#b6c2d2;'>在上方选择一个步骤，此处显示其描述与参数模板</div>"));
    return;
  }
  const QString stepId = item->text(0);
  const QString desc = item->data(0, Qt::UserRole).toString();
  const QString args = item->data(0, Qt::UserRole + 1).toString();
  const QString stepLine = QStringLiteral("<div style='color:#64748b; font-size:12px;'>%1</div>")
                             .arg(stepId.toHtmlEscaped());
  const QString descHtml = QStringLiteral("<div style='margin-top:6px;'><b>描述</b></div>"
                                          "<div style='color:#475569; margin-top:1px;'>%1</div>")
                             .arg(desc.isEmpty() ? QStringLiteral("—")
                                                 : desc.toHtmlEscaped().replace('\n', QStringLiteral("<br>")));
  const QString argsHtml = QStringLiteral("<div style='margin-top:8px;'><b>参数模板</b></div>"
                                          "<div style='color:#0f766e; font-family:monospace; margin-top:1px;'>%1</div>")
                             .arg(args.isEmpty() ? QStringLiteral("—") : args.toHtmlEscaped());
  m_stepDetail->setHtml(stepLine + descHtml + argsHtml);
}

void PlaybookPage::onDeletePlaybook() {
  if (!m_canWrite) return;
  if (m_selectedId.isEmpty()) return;
  auto reply = QMessageBox::question(this->window(), "确认删除",
    QString("确定要删除此预案吗？此操作不可撤销。"),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  if (reply != QMessageBox::Yes) return;
  QPointer<PlaybookPage> self(this);
  m_api->del("/api/playbooks/" + m_selectedId, 5000, [this, self](const QJsonObject &res) {
    if (!self) return;
    if (res["status"].toString() != "ok") {
      QMessageBox::warning(this, QStringLiteral("删除失败"),
        res["error"].toObject()["message"].toString(QStringLiteral("删除未完成，请重试")));
      refreshPermissions();
      return;
    }
    m_selectedId.clear();
    m_detailTree->clear();
    m_detailLabel->setText("选择预案查看详情");
    m_detailMeta->setVisible(false);
    m_detailDesc->setVisible(false);
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
  if (!m_canWrite) return;
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
  groupCombo->addItem("数据抵近窃取", "data-exfiltration");
  groupCombo->addItem("信息篡改欺骗", "tampering-deception");
  groupCombo->addItem("关键设备夺控", "device-control");
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

  UiUtil::styleDialogButtons(btnBox);
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
    for (const auto &t : targetType.split(',', QString::SkipEmptyParts)) {
      arr.append(t.trimmed());
    }
    body["target_type"] = arr;
  }

  body["steps"] = QJsonArray();

  m_newBtn->setEnabled(false);
  m_newBtn->setText("创建中...");

  QPointer<PlaybookPage> self(this);
  m_api->post("/api/playbooks", body, 10000, [this, self](const QJsonObject &res) {
    if (!self) return;
    m_newBtn->setEnabled(m_canWrite);
    m_newBtn->setText("＋ 新建");

    if (res["status"].toString() == "ok") {
      onLoadList();
    } else {
      QMessageBox::warning(this, "创建失败", res["error"].toObject()["message"].toString());
    }
  });
}
