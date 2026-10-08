#include "../widgets/WorkbenchTabs.h"
#include "ScanPage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/ScanResultOverview.h"
#include <QSplitter>
#include <QGridLayout>
#include <QTabBar>
#include <QDialog>
#include <QDialogButtonBox>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMessageBox>
#include <QSettings>
#include <QCompleter>
#include <QStringListModel>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QDateTime>
#include <QTreeWidgetItem>

// ── Translate nikto finding text to Chinese ───────────────────────────
static QString translateNiktoFinding(const QString &finding) {
  if (finding.contains("X-Frame-Options header is not present"))
    return "缺少 X-Frame-Options 防点击劫持头";
  if (finding.contains("X-XSS-Protection") && finding.contains("not defined"))
    return "缺少 X-XSS-Protection 防XSS头";
  if (finding.contains("X-Content-Type-Options") && finding.contains("not set"))
    return "缺少 X-Content-Type-Options 防MIME嗅探头";
  if (finding.contains("httponly flag"))
    return QString("会话标识未设置 HttpOnly 标志") +
           (finding.contains("PHPSESSID") ? " (PHPSESSID)" :
            finding.contains("security")  ? " (security)" : "");
  if (finding.contains("Directory indexing found"))
    return "目录索引已开启";
  if (finding.contains("Configuration information may be available"))
    return "配置信息可能可远程访问";
  if (finding.contains("Admin login page") || finding.contains("login page/section"))
    return "发现管理员登录页面";
  if (finding.contains("Apache default file found"))
    return "发现 Apache 默认文件";
  if (finding.contains("Server leaks inodes via ETags"))
    return "服务器通过 ETag 泄露 inode 信息";
  if (finding.contains("Allowed HTTP Methods"))
    return "允许的 HTTP 方法";
  if (finding.contains("Help directory should not be accessible"))
    return "Help 目录不应可访问";
  if (finding.contains("No CGI Directories found"))
    return "";
  if (finding.contains("OSVDB-3233") || finding.contains("default file"))
    return "发现默认文件";
  return finding;
}

static QString translateSqlmapDetail(const QString &detail) {
  if (detail.contains("is vulnerable to SQL injection"))
    return "目标存在 SQL 注入漏洞";
  if (detail.contains("is injectable"))
    return "参数存在注入";
  return detail;
}

static QString formatResultType(const QString &type) {
  if (type == "open_port")    return "开放端口";
  if (type == "vulnerability") return "漏洞";
  if (type == "web_vuln")     return "网站漏洞";
  if (type == "sql_injection") return "SQL注入";
  if (type == "credential")   return "凭据";
  if (type == "raw_output")   return "原始输出";
  if (type == "service_info") return "服务信息";
  return type;
}

// ── Formatting helpers ────────────────────────────────────────────────

QString ScanPage::formatScanType(const QString &type) {
  if (type == "port_scan")   return "端口扫描";
  if (type == "vuln_scan")   return "漏洞扫描";
  if (type == "web_scan")    return "网站扫描";
  if (type == "brute_force") return "暴力破解";
  return type;
}

QString ScanPage::formatStatus(const QString &s, bool hasStructured) {
  if (s == "COMPLETED")  return hasStructured ? "已完成" : "无有效结果";
  if (s == "RUNNING")    return "运行中";
  if (s == "PENDING")    return "待执行";
  if (s == "FAILED")     return "失败";
  if (s == "CANCELLED")  return "已取消";
  return s;
}

QString ScanPage::formatSeverity(const QString &s) {
  QString sl = s.toLower();
  if (sl == "critical") return "严重";
  if (sl == "high")     return "高危";
  if (sl == "medium")   return "中危";
  if (sl == "low")      return "低危";
  if (sl == "info" || sl == "inf") return "信息";
  return s;
}

QString ScanPage::formatDifficulty(const QString &s) {
  if (s == "easy")   return "简单";
  if (s == "medium") return "中等";
  if (s == "hard")   return "困难";
  return s;
}

QString ScanPage::formatBaselineGroup(const QString &s) {
  if (s == "recon")                           return "侦察";
  if (s == "web-vuln-scan")                   return "网站漏洞扫描";
  if (s == "windows-exploitation")            return "Windows利用";
  if (s == "post-exploitation")               return "后渗透";
  if (s == "internal-network-exploitation")   return "内网横向";
  if (s == "local-security-check")            return "本地安全检查";
  if (s == "impact-demonstration")            return "影响演示";
  if (s == "domain-osint")                    return "域信息收集";
  if (s == "brute")                           return "暴力破解";
  if (s == "exploit")                         return "漏洞利用";
  if (s == "vuln_scan")                       return "漏洞扫描";
  return s;
}

QString ScanPage::formatTime(const QString &iso) {
  if (iso.isEmpty()) return "";
  auto dt = QDateTime::fromString(iso, Qt::ISODate);
  if (!dt.isValid()) return iso.left(16);
  return dt.toString("MM-dd HH:mm");
}

QString ScanPage::formatResultData(const QString &json, const QString &resultType) {
  if (json.isEmpty()) return "";
  auto doc = QJsonDocument::fromJson(json.toUtf8());
  if (doc.isObject()) {
    auto obj = doc.object();

    if (resultType == "open_port") {
      int port = obj["port"].toInt();
      QString proto = obj["protocol"].toString("tcp");
      QString state = obj["state"].toString();
      QString service = obj["service"].toString();
      if (port > 0) {
        QString text = QString("%1/%2").arg(port).arg(proto);
        if (state == "open") text += " 开放";
        if (!service.isEmpty()) text += QString(" — %1").arg(service);
        return text;
      }
    }

    if (resultType == "credential") {
      QString login = obj["login"].toString();
      QString password = obj["password"].toString();
      QString service = obj["service"].toString();
      int port = obj["port"].toInt();
      if (!login.isEmpty() || !password.isEmpty()) {
        QString text = QString("用户: %1  密码: %2").arg(login, password);
        if (!service.isEmpty()) text += QString("  [%1]").arg(service);
        if (port > 0) text += QString("  端口:%1").arg(port);
        return text;
      }
    }

    if (resultType == "vulnerability") {
      QString title = obj["title"].toString();
      QString tmpl = obj["template"].toString();
      QString protocol = obj["protocol"].toString();
      QString detail = obj["detail"].toString();
      if (!tmpl.isEmpty()) {
        QString text = tmpl;
        if (!protocol.isEmpty()) text += QString(" [%1]").arg(protocol);
        if (!detail.isEmpty()) text += " — " + detail;
        return text;
      }
      if (!title.isEmpty()) return title + (detail.isEmpty() ? "" : " — " + detail);
    }

    if (resultType == "sql_injection") {
      QString detail = obj["detail"].toString();
      if (!detail.isEmpty()) return translateSqlmapDetail(detail);
    }

    if (resultType == "web_vuln") {
      QString finding = obj["finding"].toString();
      QString path = obj["path"].toString();
      QString cn = translateNiktoFinding(finding);
      if (cn.isEmpty()) return "";
      if (!path.isEmpty() && !finding.contains(path)) cn += QString(" — %1").arg(path);
      return cn;
    }

    QStringList parts;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
      QString val = it.value().isString() ? it.value().toString()
                    : it.value().isDouble() ? QString::number(it.value().toDouble())
                    : it.value().toVariant().toString();
      parts << QString("%1=%2").arg(it.key(), val);
    }
    return parts.join(", ");
  }
  return json.length() > 200 ? json.left(200) + "…" : json;
}

QColor ScanPage::severityColor(const QString &sev) {
  QString sl = sev.toLower();
  if (sl == "critical") return QColor("#ef4444");
  if (sl == "high")     return QColor("#f97316");
  if (sl == "medium")   return QColor("#eab308");
  if (sl == "low")      return QColor("#22c55e");
  if (sl == "info" || sl == "inf") return QColor("#94a3b8");
  return QColor("#94a3b8");
}

QString ScanPage::formatDuration(const QString &started, const QString &completed) {
  if (started.isEmpty() || completed.isEmpty()) return "";
  auto s = QDateTime::fromString(started, Qt::ISODate);
  auto c = QDateTime::fromString(completed, Qt::ISODate);
  if (!s.isValid() || !c.isValid()) return "";
  qint64 secs = s.secsTo(c);
  if (secs < 60) return QString("耗时: %1s").arg(secs);
  if (secs < 3600) return QString("耗时: %1m%2s").arg(secs / 60).arg(secs % 60);
  return QString("耗时: %1h%2m").arg(secs / 3600).arg((secs % 3600) / 60);
}

QString ScanPage::buildResultSummary(const QJsonArray &results, const QString &scanType) {
  if (results.isEmpty()) return "";

  if (scanType == "port_scan") {
    QStringList ports;
    for (const auto &r : results) {
      auto obj = r.toObject();
      if (obj["result_type"].toString() == "open_port") {
        QJsonObject data;
        { QJsonParseError err; auto doc = QJsonDocument::fromJson(obj["result_data"].toString().toUtf8(), &err); if (err.error == QJsonParseError::NoError && doc.isObject()) data = doc.object(); }
        int port = data["port"].toInt();
        if (port > 0) ports << QString::number(port);
      }
    }
    if (!ports.isEmpty()) return "开放端口: " + ports.join(", ");
  }
  else if (scanType == "vuln_scan") {
    QMap<QString, int> counts;
    for (const auto &r : results) {
      QString sev = r.toObject()["severity"].toString();
      if (!sev.isEmpty()) counts[sev]++;
    }
    QStringList parts;
    for (const auto &sev : {"critical", "high", "medium", "low"}) {
      if (counts.contains(sev) && counts[sev] > 0)
        parts << QString("%1: %2").arg(formatSeverity(sev)).arg(counts[sev]);
    }
    if (!parts.isEmpty()) return parts.join(", ");
  }
  else if (scanType == "web_scan") {
    int sqli = 0, webVulns = 0;
    for (const auto &r : results) {
      QString type = r.toObject()["result_type"].toString();
      if (type == "sql_injection") sqli++;
      if (type == "web_vuln") webVulns++;
    }
    QStringList parts;
    if (webVulns > 0) parts << QString("网站漏洞：%1").arg(webVulns);
    if (sqli > 0) parts << QString("SQL注入: %1").arg(sqli);
    if (!parts.isEmpty()) return parts.join(", ");
  }
  else if (scanType == "brute_force") {
    int creds = 0;
    for (const auto &r : results) {
      if (r.toObject()["result_type"].toString() == "credential") creds++;
    }
    if (creds > 0) return QString("破解成功: %1").arg(creds);
  }
  return "";
}

static QColor statusColor(const QString &status, bool hasStructured = true) {
  QString sl = status.toLower();
  if (sl == "completed")  return hasStructured ? QColor("#22c55e") : QColor("#f59e0b");
  if (sl == "running")    return QColor("#3b82f6");
  if (sl == "failed")     return QColor("#ef4444");
  if (sl == "pending")    return QColor("#f59e0b");
  if (sl == "cancelled")  return QColor("#94a3b8");
  return QColor("#94a3b8");
}

bool ScanPage::hasStructuredResults(const QJsonArray &results) {
  for (const auto &r : results) {
    QString type = r.toObject()["result_type"].toString();
    if (type != "raw_output") return true;
  }
  return false;
}

// ── Helper: map scan_type string to the corresponding table ───────────
static QTableWidget *tableForScanType(const QString &scanType,
                                       QTableWidget *port, QTableWidget *vuln,
                                       QTableWidget *web, QTableWidget *brute) {
  if (scanType == "port_scan")   return port;
  if (scanType == "vuln_scan")   return vuln;
  if (scanType == "web_scan")    return web;
  if (scanType == "brute_force") return brute;
  return nullptr;
}

// ── Helper: enable/disable the delete button in the currently active tab ─
void ScanPage::enableCurrentTabDelBtn(bool enabled) {
  // A selected task can belong to another tab. Never expose a delete action
  // for it after the user has switched tabs.
  m_portDelBtn->setEnabled(false);
  m_vulnDelBtn->setEnabled(false);
  m_webDelBtn->setEnabled(false);
  m_bruteDelBtn->setEnabled(false);
  if (!enabled || m_selectedTaskId.isEmpty()) return;

  int idx = m_scanTypeTabs->currentIndex();
  QTableWidget *activeTable = idx == 0 ? m_portScanTable
                            : idx == 1 ? m_vulnScanTable
                            : idx == 2 ? m_webScanTable
                                       : m_bruteForceTable;
  bool taskIsInActiveTab = false;
  for (int row = 0; row < activeTable->rowCount(); ++row) {
    auto *item = activeTable->item(row, 0);
    if (item && item->data(Qt::UserRole).toString() == m_selectedTaskId) {
      taskIsInActiveTab = true;
      break;
    }
  }
  if (!taskIsInActiveTab) return;

  switch (idx) {
    case 0: m_portDelBtn->setEnabled(true); break;
    case 1: m_vulnDelBtn->setEnabled(true); break;
    case 2: m_webDelBtn->setEnabled(true); break;
    case 3: m_bruteDelBtn->setEnabled(true); break;
    default: break;
  }
}

// ── Constructor ───────────────────────────────────────────────────────

ScanPage::ScanPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent) : QWidget(parent), m_api(api) {
  (void)role; (void)username;
  setupUI();
  onRefreshTasks();
}

void ScanPage::setTarget(const QString &target)
{
  m_portTargetInput->setText(target);
  m_vulnTargetInput->setText(target);
  m_webTargetInput->setText(target);
  m_bruteTargetInput->setText(target);
}

void ScanPage::setTaskScope(const QStringList &taskIds)
{
  if (m_scopedTasks && taskIds == m_scopeTaskIds) return;
  m_scopedTasks = true;
  m_scopeTaskIds = taskIds;
  m_selectInitialScopeTask = true;
  if (!taskIds.contains(m_selectedTaskId)) {
    m_selectedTaskId.clear();
    clearDetailPanel();
  }
  for (auto *button : findChildren<QPushButton*>("scanCreateToggle")) {
    button->setChecked(false);
    button->hide();
  }
  onRefreshTasks();
}

void ScanPage::setupUI() {
  setObjectName("scanPage");
  // Local styling: do not alter other pages or the application theme.
  setStyleSheet(Theme::PageStyle + QStringLiteral(
      "QWidget#scanPage { background:#f3f6fb; }"
      "QFrame#scanTasksPanel, QFrame#scanDetailsPanel { background:#ffffff; border:1px solid #dbe3ef; border-radius:14px; }"
      "QLabel#scanPanelTitle { color:#172033; font-size:17px; font-weight:700; }"
      "QLabel#scanPanelHint { color:#64748b; font-size:12px; }"
      "QTabWidget#scanDetailTabs::pane { border:none; background:#ffffff; padding:0; }"
      "QTableWidget, QTreeWidget { background:#ffffff; alternate-background-color:#f8fbff; border:1px solid #e2e8f0; border-radius:8px; }"
      "QTableWidget::item, QTreeWidget::item { padding:7px 6px; border:none; }"
      "QTableWidget::item:selected, QTreeWidget::item:selected { background:#dbeafe; color:#1e3a8a; }"
      "QHeaderView::section { background:#f1f5f9; color:#475569; border:none; border-bottom:1px solid #e2e8f0; padding:8px 6px; font-weight:600; }"
      "QSplitter::handle { background:transparent; }"
      "QSplitter::handle:hover { background:#dbeafe; }"));

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(12, 12, 12, 12);
  mainLayout->setSpacing(12);

  // ══ Left Panel ══════════════════════════════════════════════════════
  auto *left = new QVBoxLayout;

  // ── 4-Tab scan type layout ──────────────────────────────────────────
  m_scanTypeTabs = new WorkbenchTabs;

  QSettings settings("RedTeam", "RedTeam-Platform");
  QStringList history = settings.value("history/targets").toStringList();

  // --- Tab: 端口扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    // Input row
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_portTargetInput = new QLineEdit;
    m_portTargetInput->setPlaceholderText("例: 192.168.1.1");
    m_portTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_portTargetInput->setCompleter(completer);
    h->addWidget(m_portTargetInput, 0, 1);
    h->addWidget(new QLabel("端口:"), 1, 0);
    m_portsInput = new QLineEdit;
    m_portsInput->setPlaceholderText("22,80");
    m_portsInput->setMinimumWidth(150);
    h->addWidget(m_portsInput, 1, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    // Task table
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("端口扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_portScanCount = new QLabel;
    m_portScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_portScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_portScanTable = new QTableWidget(0, 3);
    m_portScanTable->setObjectName("scanPortTasks");
    UiUtil::EmptyHint::attach(m_portScanTable, QStringLiteral("暂无端口扫描任务"));
    m_portScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_portScanTable->setAlternatingRowColors(true);
    m_portScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_portScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_portScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_portScanTable->setSortingEnabled(false);
    m_portScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_portScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_portScanTable, 1);
    connect(m_portScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    // Buttons
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    // Store per-tab delete button
    m_portDelBtn = delBtn;
    // Right-click menu
    connect(m_portScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_portScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_portScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("端口扫描"));
  }

  // --- Tab: 系统漏洞扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_vulnTargetInput = new QLineEdit;
    m_vulnTargetInput->setPlaceholderText("例: 192.168.1.1");
    m_vulnTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_vulnTargetInput->setCompleter(completer);
    h->addWidget(m_vulnTargetInput, 0, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("系统漏洞扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_vulnScanCount = new QLabel;
    m_vulnScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_vulnScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_vulnScanTable = new QTableWidget(0, 3);
    m_vulnScanTable->setObjectName("scanVulnTasks");
    UiUtil::EmptyHint::attach(m_vulnScanTable, QStringLiteral("暂无漏洞扫描任务"));
    m_vulnScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_vulnScanTable->setAlternatingRowColors(true);
    m_vulnScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_vulnScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_vulnScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_vulnScanTable->setSortingEnabled(false);
    m_vulnScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_vulnScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_vulnScanTable, 1);
    connect(m_vulnScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_vulnDelBtn = delBtn;
    connect(m_vulnScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_vulnScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_vulnScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("系统漏洞扫描"));
  }

  // --- Tab: Web漏洞扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_webTargetInput = new QLineEdit;
    m_webTargetInput->setPlaceholderText("例: http://target:8080");
    m_webTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_webTargetInput->setCompleter(completer);
    h->addWidget(m_webTargetInput, 0, 1);
    h->addWidget(new QLabel("会话标识："), 1, 0);
    m_cookieInput = new QLineEdit;
    m_cookieInput->setPlaceholderText("PHPSESSID=abc; security=low");
    m_cookieInput->setMinimumWidth(150);
    h->addWidget(m_cookieInput, 1, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("网站漏洞扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_webScanCount = new QLabel;
    m_webScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_webScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_webScanTable = new QTableWidget(0, 3);
    m_webScanTable->setObjectName("scanWebTasks");
    UiUtil::EmptyHint::attach(m_webScanTable, QStringLiteral("暂无网站扫描任务"));
    m_webScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_webScanTable->setAlternatingRowColors(true);
    m_webScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_webScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_webScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_webScanTable->setSortingEnabled(false);
    m_webScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_webScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_webScanTable, 1);
    connect(m_webScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_webDelBtn = delBtn;
    connect(m_webScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_webScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_webScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("网站漏洞扫描"));
  }

  // --- Tab: 弱口令扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_bruteTargetInput = new QLineEdit;
    m_bruteTargetInput->setPlaceholderText("例: 192.168.1.1");
    m_bruteTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_bruteTargetInput->setCompleter(completer);
    h->addWidget(m_bruteTargetInput, 0, 1);
    h->addWidget(new QLabel("服务:"), 1, 0);
    m_serviceCombo = new QComboBox;
    for (const auto &pair : QList<QPair<QString,QString>>{
      {"HTTP表单", "http-post-form"}, {"SSH", "ssh"}, {"FTP", "ftp"},
      {"SMB", "smb"}, {"RDP", "rdp"}, {"MySQL", "mysql"},
      {"PostgreSQL", "postgres"}, {"Telnet", "telnet"}
    }) {
      m_serviceCombo->addItem(pair.first, pair.second);
    }
    h->addWidget(m_serviceCombo, 1, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    // Form definition row (only for http-post-form)
    auto *h2 = new QHBoxLayout;
    auto *formDefLabel = new QLabel("表单:");
    m_formDefInput = new QLineEdit;
    m_formDefInput->setPlaceholderText("/login:user=^USER^&pass=^PASS^:F=Incorrect");
    h2->addWidget(formDefLabel);
    h2->addWidget(m_formDefInput, 1);
    h2->addStretch();
    layout->addLayout(h2);
    const bool needsForm = m_serviceCombo->currentData().toString() == "http-post-form";
    formDefLabel->setVisible(needsForm);
    m_formDefInput->setVisible(needsForm);
    connect(m_serviceCombo, &QComboBox::currentTextChanged, this, [this, formDefLabel]() {
      bool isForm = (m_serviceCombo->currentData().toString() == "http-post-form");
      formDefLabel->setVisible(isForm);
      m_formDefInput->setVisible(isForm);
    });
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("弱口令扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_bruteForceCount = new QLabel;
    m_bruteForceCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_bruteForceCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_bruteForceTable = new QTableWidget(0, 3);
    m_bruteForceTable->setObjectName("scanCredentialTasks");
    UiUtil::EmptyHint::attach(m_bruteForceTable, QStringLiteral("暂无弱口令扫描任务"));
    m_bruteForceTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_bruteForceTable->setAlternatingRowColors(true);
    m_bruteForceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_bruteForceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_bruteForceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_bruteForceTable->setSortingEnabled(false);
    m_bruteForceTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_bruteForceTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_bruteForceTable, 1);
    connect(m_bruteForceTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_bruteDelBtn = delBtn;
    connect(m_bruteForceTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_bruteForceTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_bruteForceTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("弱口令扫描"));
  }

  left->setContentsMargins(14, 14, 14, 14);
  left->setSpacing(10);
  auto *typePicker = new QComboBox(this);
  typePicker->setObjectName("scanTypePicker");
  for (int i = 0; i < m_scanTypeTabs->count(); ++i) {
    typePicker->addItem(m_scanTypeTabs->tabText(i));
    auto *tabLayout = qobject_cast<QVBoxLayout*>(m_scanTypeTabs->widget(i)->layout());
    auto *form = new QWidget;
    auto *formLayout = new QVBoxLayout(form);
    formLayout->setContentsMargins(0, 0, 0, 0);
    auto *inputItem = tabLayout->takeAt(0);
    formLayout->addLayout(inputItem->layout());
    if (i == 3) {
      auto *extraItem = tabLayout->takeAt(0);
      formLayout->addLayout(extraItem->layout());
    }
    auto *formDialog = new QDialog(this);
    formDialog->setObjectName("scanCreateDialog");
    formDialog->setWindowTitle(QStringLiteral("新建") + m_scanTypeTabs->tabText(i));
    formDialog->setWindowModality(Qt::WindowModal);
    formDialog->setMinimumWidth(460);
    auto *dialogLayout = new QVBoxLayout(formDialog);
    dialogLayout->setContentsMargins(20, 20, 20, 20);
    dialogLayout->addWidget(form);
    auto *cancel = new QDialogButtonBox(QDialogButtonBox::Cancel, formDialog);
    UiUtil::styleDialogButtons(cancel);
    cancel->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    connect(cancel, &QDialogButtonBox::rejected, formDialog, &QDialog::reject);
    dialogLayout->addWidget(cancel);
    auto *newScan = new QPushButton(QStringLiteral("＋ 新建扫描"));
    newScan->setObjectName("scanCreateToggle");
    newScan->setProperty("primary", true);
    connect(newScan, &QPushButton::clicked, formDialog, [formDialog]() {
      formDialog->show();
      formDialog->raise();
      formDialog->activateWindow();
    });
    tabLayout->insertWidget(0, newScan);
    tabLayout->setContentsMargins(0, 8, 0, 0);
  }
  m_scanTypeTabs->tabBar()->hide();
  m_scanTypeTabs->setStyleSheet("QTabWidget::pane { border:0; background:transparent; }");
  connect(typePicker, QOverload<int>::of(&QComboBox::currentIndexChanged), m_scanTypeTabs, &QTabWidget::setCurrentIndex);
  connect(m_scanTypeTabs, &QTabWidget::currentChanged, typePicker, &QComboBox::setCurrentIndex);
  auto *taskTitle = new QLabel(QStringLiteral("扫描任务"));
  taskTitle->setObjectName("scanPanelTitle");
  auto *taskHint = new QLabel(QStringLiteral("按类型查看任务与扫描结果"));
  taskHint->setObjectName("scanPanelHint");
  left->addWidget(taskTitle);
  left->addWidget(taskHint);
  left->addWidget(typePicker);
  left->addWidget(m_scanTypeTabs, 1);

  auto *leftW = new QFrame;
  leftW->setObjectName("scanTasksPanel");
  leftW->setLayout(left);
  leftW->setMinimumWidth(310);

  // ══ Right Panel ═════════════════════════════════════════════════════
  auto *detailLayout = new QVBoxLayout;
  detailLayout->setContentsMargins(14, 14, 14, 14);
  detailLayout->setSpacing(10);
  auto *detailTabs = new WorkbenchTabs;
  detailTabs->setObjectName("scanDetailTabs");
  auto *resultsPage = new QWidget;
  auto *right = new QVBoxLayout(resultsPage);
  right->setContentsMargins(0, 12, 0, 0);
  right->setSpacing(10);
  auto *plansPage = new QWidget;
  auto *plansLayout = new QVBoxLayout(plansPage);
  plansLayout->setContentsMargins(0, 12, 0, 0);
  plansLayout->setSpacing(10);

  // ── Status label ──────────────────────────────────────────────────
  m_statusLabel = new QLabel("选择任务查看详情");
  m_statusLabel->setObjectName("scanStatus");
  m_statusLabel->setTextFormat(Qt::PlainText);
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_statusLabel->setWordWrap(true);
  detailLayout->addWidget(m_statusLabel);

  // ── Re-execute button (hidden by default) ─────────────────────────
  auto *reexecH = new QHBoxLayout;
  m_reexecBtn = new QPushButton("重新执行");
  m_reexecBtn->setVisible(false);
  reexecH->addWidget(m_reexecBtn);
  reexecH->addStretch();
  detailLayout->addLayout(reexecH);
  connect(m_reexecBtn, &QPushButton::clicked, this, &ScanPage::onReexecScan);

  // ── Results (QTreeWidget grouped by result_type) ──────────────────
  auto *resLabel = new QLabel(QStringLiteral("结果概览"));
  resLabel->setStyleSheet(Theme::SectionStyle);
  right->addWidget(resLabel);
  m_resultOverview = new ScanResultOverview(resultsPage);
  right->addWidget(m_resultOverview);
  auto *resultHint = new QLabel(QStringLiteral("完整结果  ·  右键复制内容 / 发起攻击，双击漏洞行进入攻击测试"));
  resultHint->setObjectName("scanPanelHint");
  resultHint->setWordWrap(true);
  right->addWidget(resultHint);
  m_resultTree = new QTreeWidget;
  m_resultTree->setMinimumHeight(180);
  m_resultTree->setObjectName("scanResultTree");
  UiUtil::EmptyHint::attach(m_resultTree, QStringLiteral("扫描完成后在此展示结果"));
  m_resultTree->setHeaderLabels({"严重度", "数据", "工具"});
  m_resultTree->setAlternatingRowColors(true);
  m_resultTree->setContextMenuPolicy(Qt::CustomContextMenu);
  m_resultTree->header()->setStretchLastSection(false);
  m_resultTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_resultTree->setColumnWidth(0, 70);
  m_resultTree->setColumnWidth(2, 85);
  m_resultTree->setIndentation(20);
  right->addWidget(m_resultTree, 1);
  connect(m_resultTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_resultTree->itemAt(pos);
    if (!item) return;
    QMenu menu;
    // Copy the most useful column (data column = 1 for child items, 0 for group items)
    QString text = item->text(1).isEmpty() ? item->text(0) : item->text(1);
    menu.addAction("复制内容", [text]() { QApplication::clipboard()->setText(text); });
    // 演示动线：漏洞结果一键发起攻击
    const QString resultType = item->data(0, Qt::UserRole).toString();
    const QStringList attackable = {"vulnerability", "web_vuln", "sql_injection", "credential"};
    if (!m_currentTaskTarget.isEmpty() && attackable.contains(resultType)) {
      menu.addSeparator();
      menu.addAction("⚔ 对此漏洞发起攻击", [this, item, resultType]() {
        const QString raw = item->toolTip(1);  // 优先原始 JSON（关键词更全），展示文本兜底
        emit attackRequested(m_currentTaskTarget, raw.isEmpty() ? item->text(1) : raw, resultType);
      });
    }
    menu.exec(m_resultTree->viewport()->mapToGlobal(pos));
  });
  connect(m_resultTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *item, int) {
    // 双击漏洞行 = 直接发起攻击（分组头/不可攻击类型忽略）
    if (!item || item->parent() == nullptr) return;
    const QString resultType = item->data(0, Qt::UserRole).toString();
    const QStringList attackable = {"vulnerability", "web_vuln", "sql_injection", "credential"};
    if (!attackable.contains(resultType) || m_currentTaskTarget.isEmpty()) return;
    const QString raw = item->toolTip(1);
    emit attackRequested(m_currentTaskTarget, raw.isEmpty() ? item->text(1) : raw, resultType);
  });

  // ── Recommendations ───────────────────────────────────────────────
  auto *recLabel = new QLabel("推荐预案"); recLabel->setStyleSheet(Theme::SectionStyle);
  plansLayout->addWidget(recLabel);
  m_recTable = new QTableWidget(0, 4);
  m_recTable->setMinimumHeight(140);
  m_recTable->setObjectName("scanRecommendations");
  UiUtil::EmptyHint::attach(m_recTable, QStringLiteral("暂无推荐预案 · 先完成扫描"));
  m_recTable->setHorizontalHeaderLabels({"名称", "难度", "基线组", "匹配原因"});
  m_recTable->verticalHeader()->hide();
  m_recTable->horizontalHeader()->setMinimumSectionSize(50);
  m_recTable->setAlternatingRowColors(true);
  m_recTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_recTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_recTable->setSortingEnabled(true);
  m_recTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_recTable->horizontalHeader()->setStretchLastSection(false);
  m_recTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_recTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
  m_recTable->setColumnWidth(1, 60);
  m_recTable->setColumnWidth(2, 90);
  plansLayout->addWidget(m_recTable, 1);
  connect(m_recTable, &QTableWidget::cellClicked, this, &ScanPage::onRecommendationClicked);

  // ── 推荐预案"前往执行→"按钮 ─────────────────────────────────────
  auto *recExecH = new QHBoxLayout;
  m_recExecBtn = new QPushButton("前往执行 →");
  m_recExecBtn->setVisible(false);
  m_recExecBtn->setProperty("primary", true);
  recExecH->addWidget(m_recExecBtn);
  recExecH->addStretch();
  plansLayout->addLayout(recExecH);
  connect(m_recExecBtn, &QPushButton::clicked, this, &ScanPage::onRecExecClicked);

  // ── AI Generate Playbook ──────────────────────────────────────────
  auto *bottomH = new QHBoxLayout;
  m_genBtn = new QPushButton("智能生成预案");
  m_genBtn->setEnabled(false);
  m_genBtn->setProperty("primary", true);
  bottomH->addWidget(m_genBtn);
  bottomH->addStretch();
  plansLayout->addLayout(bottomH);
  connect(m_genBtn, &QPushButton::clicked, this, &ScanPage::onGeneratePlaybook);

  // ── AI 生成预案预览区（初始隐藏）──────────────────────────────────
  m_genPreviewWidget = new QWidget;
  auto *genPreviewLayout = new QVBoxLayout(m_genPreviewWidget);
  genPreviewLayout->setContentsMargins(0, 0, 0, 0);

  m_genPreviewTitle = new QLabel;
  m_genPreviewTitle->setStyleSheet(Theme::SectionStyle);
  genPreviewLayout->addWidget(m_genPreviewTitle);

  m_genStepTable = new QTableWidget(0, 4);
  m_genStepTable->setMinimumHeight(140);
  m_genStepTable->setObjectName("scanGeneratedSteps");
  UiUtil::EmptyHint::attach(m_genStepTable, QStringLiteral("生成预案后展示步骤"));
  m_genStepTable->setHorizontalHeaderLabels({"步骤", "工具", "目标参数", "描述"});
  m_genStepTable->setAlternatingRowColors(true);
  m_genStepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_genStepTable->setSortingEnabled(false);
  m_genStepTable->horizontalHeader()->setStretchLastSection(true);
  m_genStepTable->setContextMenuPolicy(Qt::CustomContextMenu);
  genPreviewLayout->addWidget(m_genStepTable);

  auto *genExecH = new QHBoxLayout;
  m_genExecBtn = new QPushButton("前往执行 →");
  m_genExecBtn->setProperty("primary", true);
  genExecH->addWidget(m_genExecBtn);
  genExecH->addStretch();
  genPreviewLayout->addLayout(genExecH);
  connect(m_genExecBtn, &QPushButton::clicked, this, &ScanPage::onGenExecClicked);

  m_genPreviewWidget->setVisible(false);
  plansLayout->addWidget(m_genPreviewWidget);

  // 步骤表格右键菜单
  connect(m_genStepTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_genStepTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_genStepTable->viewport()->mapToGlobal(pos));
  });

  auto *rightW = new QFrame;
  rightW->setObjectName("scanDetailsPanel");
  auto scrollableDetail = [](QWidget *content) {
    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("QScrollArea { background:#ffffff; border:none; }");
    content->setObjectName("scanScrollableContent");
    content->setStyleSheet("QWidget#scanScrollableContent { background:#ffffff; }");
    scroll->setWidget(content);
    return scroll;
  };
  detailTabs->addTab(scrollableDetail(resultsPage), QStringLiteral("扫描结果"));
  detailTabs->addTab(scrollableDetail(plansPage), QStringLiteral("推荐与生成方案"));
  detailLayout->addWidget(detailTabs, 1);
  rightW->setLayout(detailLayout);
  rightW->setMinimumWidth(350);

  // ══ Splitter ═══════════════════════════════════════════════════════
  auto *splitter = new QSplitter(Qt::Horizontal, this);
  splitter->addWidget(leftW);
  splitter->addWidget(rightW);
  splitter->setChildrenCollapsible(false);
  splitter->setHandleWidth(12);
  splitter->setStretchFactor(0, 0);
  splitter->setStretchFactor(1, 1);
  splitter->setSizes({350, 760});
  mainLayout->addWidget(splitter);

  for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable}) {
    table->verticalHeader()->hide();
    table->verticalHeader()->setDefaultSectionSize(36);
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table->setColumnWidth(1, 76);
    table->setColumnWidth(2, 100);
    table->setTextElideMode(Qt::ElideMiddle);
  }

  // ── Poll timer for running scans ──────────────────────────────────
  m_pollTimer = new QTimer(this);
  m_pollTimer->setInterval(2000);
  connect(m_pollTimer, &QTimer::timeout, this, &ScanPage::onPollStatus);

  // ── Tab switch: update delete button state ────────────────────────
  connect(m_scanTypeTabs, &QTabWidget::currentChanged, this, [this]() {
    m_selectedTaskId.clear();
    clearDetailPanel();
    const QList<QTableWidget*> tables{m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable};
    auto *table = tables.value(m_scanTypeTabs->currentIndex());
    if (table && table->rowCount() > 0) {
      const int row = qMax(0, table->currentRow());
      table->selectRow(row);
      emit table->cellClicked(row, 0);
    } else {
      m_statusLabel->setText(QStringLiteral("当前扫描类型暂无任务"));
    }
  });

  // ── Result tree: 攻击动线入口（右键 / 双击漏洞行）──────────────────
  // ── Right-click menu for rec table ────────────────────────────────
  connect(m_recTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_recTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_recTable->viewport()->mapToGlobal(pos));
  });
}

// ── Update status label from task detail object ───────────────────────
void ScanPage::updateStatusLabel(const QJsonObject &d) {
  QString status = d["status"].toString();
  QString target = d["target"].toString();
  QString scanType = formatScanType(d["scan_type"].toString());
  m_currentTaskTarget = target;              // 供"对此漏洞发起攻击"取目标
  m_currentScanType = d["scan_type"].toString();
  auto arr = d["results"].toArray();
  bool structured = hasStructuredResults(arr);

  QStringList parts;
  parts << QString("目标: %1").arg(target);
  parts << scanType;
  if (status == "RUNNING")
    parts << "⏳ " + formatStatus(status, structured);
  else
    parts << "状态: " + formatStatus(status, structured);
  QString dur = formatDuration(d["started_at"].toString(), d["completed_at"].toString());
  if (!dur.isEmpty()) parts << dur;

  int structuredCount = 0;
  for (const auto &r : arr) {
    if (r.toObject()["result_type"].toString() != "raw_output") structuredCount++;
  }
  if (structuredCount > 0)
    parts << QString("有效结果: %1").arg(structuredCount);
  else if (arr.size() > 0)
    parts << "仅原始输出";

  QString summary = buildResultSummary(arr, d["scan_type"].toString());
  if (!summary.isEmpty()) parts << summary;

  m_statusLabel->setText(parts.join(" | "));
  if (status == "FAILED")
    m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
  else if (status == "COMPLETED" && !structured)
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
  else
    m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
}

// ── Render grouped results in QTreeWidget ─────────────────────────────
void ScanPage::renderGroupedResults(const QJsonArray &results) {
  m_resultOverview->setResults(results);
  m_resultTree->clear();

  // Group by result_type
  QMap<QString, QJsonArray> groups;
  // Define display order
  QStringList order = {"open_port", "vulnerability", "web_vuln", "sql_injection",
                       "credential", "service_info", "raw_output"};

  for (const auto &r : results) {
    QString type = r.toObject()["result_type"].toString();
    groups[type].append(r);
  }

  // Render groups in defined order, then any remaining types
  QStringList renderedTypes;
  for (const auto &type : order) {
    if (!groups.contains(type) || groups[type].isEmpty()) continue;
    renderedTypes << type;

    auto &arr = groups[type];
    QString groupName = formatResultType(type) + QString(" (%1)").arg(arr.size());

    auto *groupItem = new QTreeWidgetItem(m_resultTree, {groupName, "", ""});
    QFont groupFont = groupItem->font(0);
    groupFont.setBold(true);
    groupItem->setFont(0, groupFont);
    groupItem->setFirstColumnSpanned(true);
    // Group header separates result types without competing with severity colors
    for (int col = 0; col < 3; col++) {
      groupItem->setBackground(col, QColor("#eaf1fa"));
      groupItem->setForeground(col, QColor("#334155"));
    }

    for (const auto &r : arr) {
      auto obj = r.toObject();
      QString sev = obj["severity"].toString();
      QString resultType = obj["result_type"].toString();
      QString rawData = obj["result_data"].toString();
      QString tool = obj["source_tool"].toString();

      auto *child = new QTreeWidgetItem(groupItem);
      child->setText(0, formatSeverity(sev));
      child->setForeground(0, severityColor(sev));
      child->setData(0, Qt::UserRole, resultType);  // 供右键"发起攻击"判断类型
      child->setText(1, formatResultData(rawData, resultType));
      child->setToolTip(1, rawData);
      child->setText(2, tool);

      // Dim raw_output items
      if (resultType == "raw_output") {
        child->setForeground(0, QColor("#94a3b8"));
        child->setForeground(1, QColor("#94a3b8"));
      }
    }

    // raw_output group default collapsed, others expanded
    if (type == "raw_output") {
      groupItem->setExpanded(false);
    } else {
      groupItem->setExpanded(true);
    }
  }

  // Render any types not in the predefined order
  for (auto it = groups.begin(); it != groups.end(); ++it) {
    if (renderedTypes.contains(it.key())) continue;
    auto &arr = it.value();
    QString groupName = formatResultType(it.key()) + QString(" (%1)").arg(arr.size());

    auto *groupItem = new QTreeWidgetItem(m_resultTree, {groupName, "", ""});
    QFont groupFont = groupItem->font(0);
    groupFont.setBold(true);
    groupItem->setFont(0, groupFont);
    groupItem->setFirstColumnSpanned(true);
    for (int col = 0; col < 3; col++) {
      groupItem->setBackground(col, QColor("#eaf1fa"));
      groupItem->setForeground(col, QColor("#334155"));
    }

    for (const auto &r : arr) {
      auto obj = r.toObject();
      QString sev = obj["severity"].toString();
      QString resultType = obj["result_type"].toString();
      QString rawData = obj["result_data"].toString();
      QString tool = obj["source_tool"].toString();

      auto *child = new QTreeWidgetItem(groupItem);
      child->setText(0, formatSeverity(sev));
      child->setForeground(0, severityColor(sev));
      child->setData(0, Qt::UserRole, resultType);  // 供右键"发起攻击"判断类型
      child->setText(1, formatResultData(rawData, resultType));
      child->setToolTip(1, rawData);
      child->setText(2, tool);
    }
    groupItem->setExpanded(true);
  }

  m_resultTree->setColumnWidth(0, 90);
  m_resultTree->setColumnWidth(2, 80);
}

// ── Create scan (auto-execute) ───────────────────────────────────────
void ScanPage::onCreateScan() {
  // Determine scan type from current tab
  int tabIdx = m_scanTypeTabs->currentIndex();
  QString scanType;
  QString target;
  switch (tabIdx) {
    case 0: scanType = "port_scan";   target = m_portTargetInput->text().trimmed(); break;
    case 1: scanType = "vuln_scan";   target = m_vulnTargetInput->text().trimmed(); break;
    case 2: scanType = "web_scan";    target = m_webTargetInput->text().trimmed(); break;
    case 3: scanType = "brute_force"; target = m_bruteTargetInput->text().trimmed(); break;
    default: return;
  }

  if (target.isEmpty()) {
    m_statusLabel->setText("请先填写扫描目标。");
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
    return;
  }

  // Save target to history
  {
    QSettings settings("RedTeam", "RedTeam-Platform");
    QStringList history = settings.value("history/targets").toStringList();
    history.removeAll(target);
    history.prepend(target);
    while (history.size() > 20) history.removeLast();
    settings.setValue("history/targets", history);
    // Update completers for all target inputs
    for (auto *input : {m_portTargetInput, m_vulnTargetInput, m_webTargetInput, m_bruteTargetInput}) {
      if (auto *c = input->completer()) {
        auto *m = qobject_cast<QStringListModel*>(c->model());
        if (m) m->setStringList(history);
      }
    }
  }

  QJsonObject body;
  body["target"] = target;
  body["scan_type"] = scanType;

  QJsonObject parameters;
  // Tab-specific parameters
  if (scanType == "port_scan") {
    QString ports = m_portsInput->text().trimmed();
    if (!ports.isEmpty()) parameters["ports"] = ports;
  }
  if (scanType == "web_scan") {
    QString cookie = m_cookieInput->text().trimmed();
    if (!cookie.isEmpty()) parameters["cookie"] = cookie;
  }
  if (scanType == "brute_force") {
    parameters["service"] = m_serviceCombo->currentData().toString();
    QString formDef = m_formDefInput->text().trimmed();
    if (!formDef.isEmpty() && m_serviceCombo->currentData().toString() == "http-post-form") {
      parameters["form_definition"] = formDef;
    }
  }
  if (!parameters.isEmpty()) body["parameters"] = parameters;

  m_api->post("/api/scan-tasks", body, 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      m_statusLabel->setText("创建扫描任务失败");
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }
    for (auto *dialog : findChildren<QDialog*>("scanCreateDialog")) dialog->accept();
    QString taskId = res["data"].toObject()["scan_task_id"].toString();
    m_selectedTaskId = taskId;
    m_statusLabel->setText(QString("已创建: %1 — 正在自动执行...").arg(taskId.left(16)));
    m_statusLabel->setStyleSheet(Theme::StatusSuccessStyle);
    // Clear the target input for the current tab
    int tabIdx = m_scanTypeTabs->currentIndex();
    switch (tabIdx) {
      case 0: m_portTargetInput->clear(); m_portsInput->clear(); break;
      case 1: m_vulnTargetInput->clear(); break;
      case 2: m_webTargetInput->clear(); m_cookieInput->clear(); break;
      case 3: m_bruteTargetInput->clear(); break;
    }
    onRefreshTasks();

    QJsonObject empty;
    m_api->post("/api/scan-tasks/" + taskId + "/execute", empty, 5000, [this, taskId](const QJsonObject &execRes) {
      if (execRes["status"].toString() == "ok") {
        m_reexecBtn->setVisible(false);
        if (!m_runningTaskIds.contains(taskId)) m_runningTaskIds << taskId;
        startPollingIfNeeded();
        onRefreshTasks();
      } else {
        m_statusLabel->setText("创建成功但执行失败，可点击「重新执行」");
        m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
        m_reexecBtn->setVisible(true);
        onRefreshTasks();
      }
    });
  });
}

// ── Start polling ─────────────────────────────────────────────────────
void ScanPage::startPollingIfNeeded() {
  bool needPoll = !m_runningTaskIds.isEmpty();
  if (needPoll && !m_pollTimer->isActive()) {
    m_pollTimer->start();
  } else if (!needPoll && m_pollTimer->isActive()) {
    m_pollTimer->stop();
  }
}

// ── Refresh task list ─────────────────────────────────────────────────
void ScanPage::onRefreshTasks() {
  m_api->get("/api/scan-tasks", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();

    // Clear all 4 tables
    m_portScanTable->setRowCount(0);
    m_vulnScanTable->setRowCount(0);
    m_webScanTable->setRowCount(0);
    m_bruteForceTable->setRowCount(0);

    QMap<QString, int> counts = {{"port_scan", 0}, {"vuln_scan", 0}, {"web_scan", 0}, {"brute_force", 0}};
    QStringList runningIds;
    int selectTabIdx = -1;
    int selectRowInTab = -1;

    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      QString taskId = t["scan_task_id"].toString();
      if (m_scopedTasks && !m_scopeTaskIds.contains(taskId)) continue;
      QString scanType = t["scan_type"].toString();
      QString status = t["status"].toString();

      auto *table = tableForScanType(scanType, m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable);
      if (!table) continue;

      int row = table->rowCount();
      table->setRowCount(row + 1);
      counts[scanType]++;

      auto *targetItem = new QTableWidgetItem(t["target"].toString());
      targetItem->setData(Qt::UserRole, taskId);
      targetItem->setToolTip(t["target"].toString());
      table->setItem(row, 0, targetItem);

      auto *statusItem = new QTableWidgetItem(formatStatus(status));
      statusItem->setForeground(statusColor(status));
      table->setItem(row, 1, statusItem);

      table->setItem(row, 2, new QTableWidgetItem(formatTime(t["created_at"].toString())));

      if (status == "RUNNING" || status == "PENDING") {
        runningIds << taskId;
      }

      // Track selected task
      if (!m_selectedTaskId.isEmpty() && taskId == m_selectedTaskId) {
        selectTabIdx = (scanType == "port_scan") ? 0 :
                       (scanType == "vuln_scan") ? 1 :
                       (scanType == "web_scan") ? 2 :
                       (scanType == "brute_force") ? 3 : -1;
        selectRowInTab = row;
      }
    }

    // Resize columns
    for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable}) {
      table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    }

    // Update count labels
    m_portScanCount->setText(QString("共 %1 个").arg(counts["port_scan"]));
    m_vulnScanCount->setText(QString("共 %1 个").arg(counts["vuln_scan"]));
    m_webScanCount->setText(QString("共 %1 个").arg(counts["web_scan"]));
    m_bruteForceCount->setText(QString("共 %1 个").arg(counts["brute_force"]));

    // Select the previously selected task (only highlight row, don't switch tabs
    // to avoid jarring UX when user is viewing a different tab)
    if (selectTabIdx >= 0 && selectRowInTab >= 0) {
      // Only switch tab if the selected task is in the currently visible tab
      if (m_scanTypeTabs->currentIndex() == selectTabIdx) {
        auto *table = tableForScanType(
          selectTabIdx == 0 ? "port_scan" : selectTabIdx == 1 ? "vuln_scan" : selectTabIdx == 2 ? "web_scan" : "brute_force",
          m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable);
        if (table) {
          table->selectRow(selectRowInTab);
          enableCurrentTabDelBtn(true);
        }
      }
    }

    // Opening a pipeline should show its results, not unrelated global tasks.
    if (m_scopedTasks && m_selectInitialScopeTask && m_selectedTaskId.isEmpty()) {
      const QList<QTableWidget*> tables{m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable};
      for (int tab = 0; tab < tables.size(); ++tab) {
        if (tables[tab]->rowCount() == 0) continue;
        m_scanTypeTabs->setCurrentIndex(tab);
        tables[tab]->selectRow(0);
        emit tables[tab]->cellClicked(0, 0);
        m_selectInitialScopeTask = false;
        break;
      }
    }

    m_runningTaskIds = runningIds;
    startPollingIfNeeded();
  });
}

// ── Task clicked → show detail in right panel ────────────────────────
void ScanPage::onTaskClicked(int row, int) {
  // Determine which table sent the signal
  auto *table = qobject_cast<QTableWidget*>(sender());
  if (!table) return;

  auto *idItem = table->item(row, 0);
  if (!idItem) return;
  QString id = idItem->data(Qt::UserRole).toString();
  if (id.isEmpty()) return;
  m_selectedTaskId = id;
  enableCurrentTabDelBtn(true);

  m_api->get("/api/scan-tasks/" + id, 5000, [this, id](const QJsonObject &res) {
    if (id != m_selectedTaskId) return;
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    // Save current target for cross-page navigation
    m_currentTarget = d["target"].toString();

    // Update status in the originating table (find across all 4 tables)
    for (auto *t : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable}) {
      for (int i = 0; i < t->rowCount(); i++) {
        auto *item = t->item(i, 0);
        if (item && item->data(Qt::UserRole).toString() == id) {
          auto *statusItem = new QTableWidgetItem(formatStatus(status));
          statusItem->setForeground(statusColor(status));
          t->setItem(i, 1, statusItem);
          break;
        }
      }
    }

    updateStatusLabel(d);

    auto arr = d["results"].toArray();
    renderGroupedResults(arr);

    // Clear per-task state
    m_lastGeneratedId.clear();
    m_selectedRecPlaybookId.clear();
    m_selectedRecPlaybookName.clear();
    m_recExecBtn->setVisible(false);
    m_genPreviewWidget->setVisible(false);
    m_genStepTable->setRowCount(0);

    bool structured = hasStructuredResults(arr);
    if (status == "COMPLETED" && structured) {
      m_genBtn->setEnabled(true);
      m_reexecBtn->setVisible(false);
      loadRecommendations(id);
      // 不再自动触发 AI 生成，需用户手动点击
    } else if (status == "COMPLETED" && !structured) {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(true);
      m_recTable->setRowCount(0);
    } else if (status == "PENDING") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
    } else if (status == "RUNNING") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
      if (!m_runningTaskIds.contains(id)) m_runningTaskIds << id;
      startPollingIfNeeded();
    } else if (status == "FAILED" || status == "CANCELLED") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(true);
      m_recTable->setRowCount(0);
    } else {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
    }
  });
}

// ── Load results (used by poll completion) ───────────────────────────
void ScanPage::loadResults(const QString &taskId) {
  m_api->get("/api/scan-tasks/" + taskId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    updateStatusLabel(d);
    m_currentTarget = d["target"].toString();
    auto arr = d["results"].toArray();
    renderGroupedResults(arr);
  });
}

// ── Load recommendations ─────────────────────────────────────────────
void ScanPage::loadRecommendations(const QString &taskId) {
  m_api->get("/api/scan-tasks/" + taskId + "/recommendations", 5000, [this, taskId](const QJsonObject &res) {
    if (taskId != m_selectedTaskId) return;
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    const bool sorting = m_recTable->isSortingEnabled();
    m_recTable->setSortingEnabled(false);
    m_recTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      auto *nameItem = new QTableWidgetItem(r["name"].toString());
      nameItem->setData(Qt::UserRole, r["playbook_id"].toString());
      m_recTable->setItem(i, 0, nameItem);
      m_recTable->setItem(i, 1, new QTableWidgetItem(formatDifficulty(r["difficulty"].toString())));
      m_recTable->setItem(i, 2, new QTableWidgetItem(formatBaselineGroup(r["baseline_group"].toString())));
      auto *reason = new QTableWidgetItem(r["match_reason"].toString());
      reason->setToolTip(reason->text());
      m_recTable->setItem(i, 3, reason);
    }
    m_recTable->setSortingEnabled(sorting);
    m_recTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_recTable->horizontalHeader()->setStretchLastSection(false);
  });
}

// ── AI Generate Playbook ──────────────────────────────────────────────
void ScanPage::onGeneratePlaybook() {
  if (m_selectedTaskId.isEmpty()) return;
  const QString taskId = m_selectedTaskId;
  m_genBtn->setEnabled(false);
  m_genBtn->setText("智能生成中...");
  m_genPreviewWidget->setVisible(false);
  m_genStepTable->setRowCount(0);
  QJsonObject body;
  m_api->post("/api/scan-tasks/" + taskId + "/generate-playbook", body, 60000, [this, taskId](const QJsonObject &res) {
    if (taskId != m_selectedTaskId) return;
    m_genBtn->setEnabled(true);
    m_genBtn->setText("智能生成预案");
    if (res["status"].toString() == "ok") {
      auto data = res["data"].toObject();
      QString pbId = data["playbook_id"].toString();
      QString pbName = data["name"].toString();
      int steps = data["steps_count"].toInt();

      m_lastGeneratedId = pbId;

      // 显示预览区标题
      m_genPreviewTitle->setText(QString("智能生成预案：%1（%2步）").arg(pbName).arg(steps));
      m_genExecBtn->setText(QString("前往执行「%1」→").arg(pbName.left(20)));

      // 加载 Playbook 详情并渲染步骤表格
      m_api->get("/api/playbooks/" + pbId, 5000, [this, taskId](const QJsonObject &pbRes) {
        if (taskId != m_selectedTaskId) return;
        if (pbRes["status"].toString() != "ok") return;
        auto pb = pbRes["data"].toObject();
        auto stepsArr = pb["steps"].toArray();
        m_genStepTable->setRowCount(stepsArr.size());
        for (int i = 0; i < stepsArr.size(); i++) {
          auto s = stepsArr[i].toObject();
          int stepNum = s["step_index"].toInt(i + 1);
          m_genStepTable->setItem(i, 0, new QTableWidgetItem(QString("步骤 %1").arg(stepNum)));
          m_genStepTable->setItem(i, 1, new QTableWidgetItem(s["tool_id"].toString()));
          QStringList args;
          auto at = s["args_template"];
          if (at.isString()) {
            QJsonArray argsArr = QJsonDocument::fromJson(at.toString().toUtf8()).array();
            for (const auto &v : argsArr) args << v.toVariant().toString();
          } else if (at.isArray()) {
            for (const auto &v : at.toArray()) args << v.toVariant().toString();
          }
          m_genStepTable->setItem(i, 2, new QTableWidgetItem(args.join(" ")));
          m_genStepTable->setItem(i, 3, new QTableWidgetItem(s["description"].toString()));
        }
        m_genStepTable->resizeColumnsToContents();
        m_genStepTable->horizontalHeader()->setStretchLastSection(true);
      });

      // 显示预览区
      m_genPreviewWidget->setVisible(true);

      loadRecommendations(m_selectedTaskId);
    } else {
      QString errMsg = res["error"].toObject()["message"].toString();
      if (errMsg.isEmpty()) errMsg = res["data"].toObject()["error"].toString();
      if (errMsg.contains("401") || errMsg.contains("invalid", Qt::CaseInsensitive) || errMsg.contains("authentication", Qt::CaseInsensitive))
        errMsg = "模型服务密钥无效，请在「系统管理→系统配置」中检查模型服务配置";
      else if (errMsg.contains("timed out", Qt::CaseInsensitive))
        errMsg = "模型服务请求超时，请稍后重试";
      else if (errMsg.contains("No LLM API key", Qt::CaseInsensitive))
        errMsg = "未配置模型服务密钥，请在「系统管理→系统配置」中设置模型服务配置";
      else if (errMsg.isEmpty())
        errMsg = "未知错误";
      m_statusLabel->setText(QString("✗ 预案生成失败: %1").arg(errMsg.left(120)));
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });
}

// ── Recommendation clicked → 仅选中，不跳转 ───────────────────────────
void ScanPage::onRecommendationClicked(int row, int) {
  auto *item = m_recTable->item(row, 0);
  if (!item) return;
  QString pbId = item->data(Qt::UserRole).toString();
  if (pbId.isEmpty()) return;
  // 仅选中，不跳转
  m_selectedRecPlaybookId = pbId;
  m_selectedRecPlaybookName = item->text();
  // 显示"前往执行"按钮
  m_recExecBtn->setVisible(true);
  m_recExecBtn->setText(QString("前往执行「%1」→").arg(m_selectedRecPlaybookName.left(20)));
}

// ── 推荐预案"前往执行→"按钮 ──────────────────────────────────────────
void ScanPage::onRecExecClicked() {
  if (m_selectedRecPlaybookId.isEmpty()) return;
  emit playbookNavigateRequested(m_selectedRecPlaybookId, m_currentTarget);
}

// ── AI生成预案"前往执行→"按钮 ────────────────────────────────────────
void ScanPage::onGenExecClicked() {
  if (m_lastGeneratedId.isEmpty()) return;
  emit playbookNavigateRequested(m_lastGeneratedId, m_currentTarget);
}

// ── Re-execute scan ──────────────────────────────────────────────────
void ScanPage::onReexecScan() {
  if (m_selectedTaskId.isEmpty()) return;
  m_reexecBtn->setVisible(false);
  clearDetailPanel();
  m_statusLabel->setText("重新执行中...");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);

  QJsonObject empty;
  m_api->post("/api/scan-tasks/" + m_selectedTaskId + "/execute", empty, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      if (!m_runningTaskIds.contains(m_selectedTaskId)) m_runningTaskIds << m_selectedTaskId;
      startPollingIfNeeded();
      onRefreshTasks();
    } else {
      m_statusLabel->setText("重新执行失败");
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      m_reexecBtn->setVisible(true);
    }
  });
}

// ── Delete task ───────────────────────────────────────────────────────
void ScanPage::onDeleteTask() {
  if (m_selectedTaskId.isEmpty()) return;

  m_api->get("/api/scan-tasks/" + m_selectedTaskId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    if (status == "RUNNING") {
      QMessageBox::warning(this->window(), "无法删除",
        "正在运行的任务无法删除，请先等待完成。");
      return;
    }

    QString target = d["target"].toString();
    QString type = formatScanType(d["scan_type"].toString());
    auto reply = QMessageBox::question(this->window(), "确认删除",
      QString("确定要删除此扫描任务吗？\n目标: %1 | %2\n此操作不可撤销。").arg(target, type),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    m_api->del("/api/scan-tasks/" + m_selectedTaskId, 5000, [this](const QJsonObject &) {
      m_selectedTaskId.clear();
      clearDetailPanel();  // also disables delete button
      onRefreshTasks();
    });
  });
}

// ── Clear detail panel ────────────────────────────────────────────────
void ScanPage::clearDetailPanel() {
  m_resultOverview->clear();
  m_statusLabel->setText("选择任务查看详情");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_resultTree->clear();
  m_recTable->setRowCount(0);
  m_genBtn->setEnabled(false);
  m_reexecBtn->setVisible(false);
  m_selectedRecPlaybookId.clear();
  m_selectedRecPlaybookName.clear();
  m_recExecBtn->setVisible(false);
  m_genPreviewWidget->setVisible(false);
  m_genStepTable->setRowCount(0);
  m_lastGeneratedId.clear();
  m_currentTarget.clear();
  enableCurrentTabDelBtn(false);
}

// ── Poll scan status ──────────────────────────────────────────────────
void ScanPage::onPollStatus() {
  if (m_runningTaskIds.isEmpty()) {
    m_pollTimer->stop();
    return;
  }

  m_api->get("/api/scan-tasks", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      // API error — tolerate transient failures, then stop polling to avoid spin
      if (++m_pollErrorCount >= 10) {
        m_pollTimer->stop();
        m_runningTaskIds.clear();
      }
      return;
    }
    m_pollErrorCount = 0;
    auto arr = res["data"].toArray();

    QStringList stillRunning;
    bool selectedTaskFinished = false;

    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      QString taskId = t["scan_task_id"].toString();
      if (m_scopedTasks && !m_scopeTaskIds.contains(taskId)) continue;
      QString status = t["status"].toString();

      if (m_runningTaskIds.contains(taskId)) {
        // Update status in the corresponding table
        for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable}) {
          for (int row = 0; row < table->rowCount(); row++) {
            auto *idItem = table->item(row, 0);
            if (idItem && idItem->data(Qt::UserRole).toString() == taskId) {
              auto *statusItem = new QTableWidgetItem(formatStatus(status));
              statusItem->setForeground(statusColor(status));
              table->setItem(row, 1, statusItem);
              break;
            }
          }
        }

        if (status == "RUNNING" || status == "PENDING") {
          stillRunning << taskId;
        } else {
          if (taskId == m_selectedTaskId) {
            selectedTaskFinished = true;
          }
        }
      }
    }

    m_runningTaskIds = stillRunning;
    startPollingIfNeeded();

    if (selectedTaskFinished && !m_selectedTaskId.isEmpty()) {
      // Re-trigger task click to load full details
      bool found = false;
      for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable}) {
        if (found) break;
        for (int row = 0; row < table->rowCount(); row++) {
          auto *idItem = table->item(row, 0);
          if (idItem && idItem->data(Qt::UserRole).toString() == m_selectedTaskId) {
            // Directly load the task details
            const QString selectedId = m_selectedTaskId;
      m_api->get("/api/scan-tasks/" + selectedId, 5000, [this, selectedId](const QJsonObject &detailRes) {
        if (selectedId != m_selectedTaskId) return;
              if (detailRes["status"].toString() != "ok") return;
              auto d = detailRes["data"].toObject();
              m_currentTarget = d["target"].toString();
              updateStatusLabel(d);
              renderGroupedResults(d["results"].toArray());
              // Trigger recommendations for completed tasks
              QString status = d["status"].toString();
              auto arr = d["results"].toArray();
              bool structured = hasStructuredResults(arr);
              if (status == "COMPLETED" && structured) {
                m_genBtn->setEnabled(true);
                m_reexecBtn->setVisible(false);
                loadRecommendations(m_selectedTaskId);
                // 不再自动触发 AI 生成
              } else if (status == "COMPLETED" && !structured) {
                m_genBtn->setEnabled(false);
                m_reexecBtn->setVisible(true);
              } else if (status == "FAILED" || status == "CANCELLED") {
                m_genBtn->setEnabled(false);
                m_reexecBtn->setVisible(true);
              }
            });
            found = true;
            break;
          }
        }
      }
    } else if (!m_selectedTaskId.isEmpty() && m_runningTaskIds.contains(m_selectedTaskId)) {
      // Still running — update results incrementally
      const QString selectedId = m_selectedTaskId;
      m_api->get("/api/scan-tasks/" + selectedId, 5000, [this, selectedId](const QJsonObject &detailRes) {
        if (selectedId != m_selectedTaskId) return;
        if (detailRes["status"].toString() != "ok") return;
        auto d = detailRes["data"].toObject();
        m_currentTarget = d["target"].toString();
        updateStatusLabel(d);
        renderGroupedResults(d["results"].toArray());
      });
    }
  });
}
