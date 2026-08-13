#include "ScanPage.h"
#include "../ApiClient.h"
#include "../MainWindow.h"
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMessageBox>
#include "../Theme.h"
#include <QSettings>
#include <QCompleter>
#include <QStringListModel>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QDateTime>
#include <QRegularExpression>

// ── Translate nikto finding text to Chinese ───────────────────────────
static QString translateNiktoFinding(const QString &finding) {
  if (finding.contains("X-Frame-Options header is not present"))
    return "缺少 X-Frame-Options 防点击劫持头";
  if (finding.contains("X-XSS-Protection") && finding.contains("not defined"))
    return "缺少 X-XSS-Protection 防XSS头";
  if (finding.contains("X-Content-Type-Options") && finding.contains("not set"))
    return "缺少 X-Content-Type-Options 防MIME嗅探头";
  if (finding.contains("httponly flag"))
    return QString("Cookie 未设置 HttpOnly 标志") +
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
    return "";  // skip non-finding
  if (finding.contains("OSVDB-3233") || finding.contains("default file"))
    return "发现默认文件";
  return finding;
}

// ── Translate sqlmap detail text to Chinese ───────────────────────────
static QString translateSqlmapDetail(const QString &detail) {
  if (detail.contains("is vulnerable to SQL injection"))
    return "目标存在 SQL 注入漏洞";
  if (detail.contains("is injectable"))
    return "参数存在注入";
  return detail;
}

// ── Format result_type for display ────────────────────────────────────
static QString formatResultType(const QString &type) {
  if (type == "open_port")    return "开放端口";
  if (type == "vulnerability") return "漏洞";
  if (type == "web_vuln")     return "Web漏洞";
  if (type == "sql_injection") return "SQL注入";
  if (type == "credential")   return "凭据";
  if (type == "raw_output")   return "原始输出";
  return type;
}

// ── Formatting helpers ────────────────────────────────────────────────

QString ScanPage::formatScanType(const QString &type) {
  if (type == "port_scan")   return "端口扫描";
  if (type == "vuln_scan")   return "漏洞扫描";
  if (type == "web_scan")    return "Web扫描";
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
  if (s == "web-vuln-scan")                   return "Web漏洞扫描";
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

    // Special formatting for open_port: highlight port and service
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

    // Special formatting for credential: show login/password + service info
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

    // Special formatting for vulnerability: show template + protocol + detail
    if (resultType == "vulnerability") {
      QString title = obj["title"].toString();
      QString tmpl = obj["template"].toString();
      QString protocol = obj["protocol"].toString();
      QString detail = obj["detail"].toString();
      // nuclei format: {template, protocol, detail}
      if (!tmpl.isEmpty()) {
        QString text = tmpl;
        if (!protocol.isEmpty()) text += QString(" [%1]").arg(protocol);
        if (!detail.isEmpty()) text += " — " + detail;
        return text;
      }
      // other format: {title, detail}
      if (!title.isEmpty()) return title + (detail.isEmpty() ? "" : " — " + detail);
    }

    // Special formatting for sql_injection
    if (resultType == "sql_injection") {
      QString detail = obj["detail"].toString();
      if (!detail.isEmpty()) return translateSqlmapDetail(detail);
    }

    // Special formatting for web_vuln (nikto findings)
    if (resultType == "web_vuln") {
      QString finding = obj["finding"].toString();
      QString path = obj["path"].toString();
      QString cn = translateNiktoFinding(finding);
      if (cn.isEmpty()) return "";  // skip non-finding
      if (!path.isEmpty() && !finding.contains(path)) cn += QString(" — %1").arg(path);
      return cn;
    }

    // Generic: key=value format
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
        auto data = obj["result_data"].toObject();
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
    if (webVulns > 0) parts << QString("Web漏洞: %1").arg(webVulns);
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

// ── Status color helper (by raw English status) ───────────────────────
static QColor statusColor(const QString &status, bool hasStructured = true) {
  QString sl = status.toLower();
  if (sl == "completed")  return hasStructured ? QColor("#22c55e") : QColor("#f59e0b");
  if (sl == "running")    return QColor("#3b82f6");
  if (sl == "failed")     return QColor("#ef4444");
  if (sl == "pending")    return QColor("#f59e0b");
  if (sl == "cancelled")  return QColor("#94a3b8");
  return QColor("#94a3b8");
}

// ── Check if results contain structured data (not just raw_output) ────
bool ScanPage::hasStructuredResults(const QJsonArray &results) {
  for (const auto &r : results) {
    QString type = r.toObject()["result_type"].toString();
    if (type != "raw_output") return true;
  }
  return false;
}

// ── Constructor ───────────────────────────────────────────────────────

ScanPage::ScanPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent) : QWidget(parent), m_api(api) {
  setupUI();
  onRefreshTasks();
}

void ScanPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);

  // ══ Left Panel ══════════════════════════════════════════════════════
  auto *left = new QVBoxLayout;

  // ── Create scan (single row: 目标 + 端口 + 类型 + 创建) ──────────
  auto *h1 = new QHBoxLayout;
  h1->addWidget(new QLabel("目标:"));
  m_targetInput = new QLineEdit;
  m_targetInput->setPlaceholderText("例: 192.168.1.1");
  QSettings settings("RedTeam", "RedTeam-Platform");
  QStringList history = settings.value("history/targets").toStringList();
  auto *completer = new QCompleter(history, this);
  completer->setCaseSensitivity(Qt::CaseInsensitive);
  m_targetInput->setCompleter(completer);
  h1->addWidget(m_targetInput, 2);
  h1->addWidget(new QLabel("端口:"));
  m_portsInput = new QLineEdit;
  m_portsInput->setPlaceholderText("22,80");
  m_portsInput->setMaximumWidth(120);
  h1->addWidget(m_portsInput);
  h1->addWidget(new QLabel("类型:"));
  m_scanTypeCombo = new QComboBox;
  for (const auto &pair : QList<QPair<QString,QString>>{
    {"端口扫描", "port_scan"}, {"漏洞扫描", "vuln_scan"},
    {"Web扫描", "web_scan"}, {"暴力破解", "brute_force"}
  }) {
    m_scanTypeCombo->addItem(pair.first, pair.second);
  }
  h1->addWidget(m_scanTypeCombo);
  auto *scanBtn = new QPushButton("创建扫描");
  scanBtn->setProperty("primary", true);
  h1->addWidget(scanBtn);
  left->addLayout(h1);
  connect(scanBtn, &QPushButton::clicked, this, &ScanPage::onCreateScan);

  // ── Cookie input row (shown only for web_scan) ─────────────────────
  auto *h2 = new QHBoxLayout;
  auto *cookieLabel = new QLabel("Cookie:");  // Cookie is a proper noun
  m_cookieInput = new QLineEdit;
  m_cookieInput->setPlaceholderText("可选，例: PHPSESSID=abc123; security=low");
  h2->addWidget(cookieLabel);
  h2->addWidget(m_cookieInput, 1);
  left->addLayout(h2);

  // ── Brute force options row (shown only for brute_force) ───────────
  auto *h3 = new QHBoxLayout;
  auto *serviceLabel = new QLabel("服务:");
  m_serviceCombo = new QComboBox;
  for (const auto &pair : QList<QPair<QString,QString>>{
    {"HTTP表单", "http-post-form"}, {"SSH", "ssh"}, {"FTP", "ftp"},
    {"SMB", "smb"}, {"RDP", "rdp"}, {"MySQL", "mysql"},
    {"PostgreSQL", "postgres"}, {"Telnet", "telnet"}
  }) {
    m_serviceCombo->addItem(pair.first, pair.second);
  }
  auto *formDefLabel = new QLabel("表单:");
  m_formDefInput = new QLineEdit;
  m_formDefInput->setPlaceholderText("/login:user=^USER^&pass=^PASS^:F=Incorrect");
  h3->addWidget(serviceLabel);
  h3->addWidget(m_serviceCombo);
  h3->addWidget(formDefLabel);
  h3->addWidget(m_formDefInput, 1);
  left->addLayout(h3);

  // Initially hidden — show/hide based on scan type
  cookieLabel->setVisible(false);
  m_cookieInput->setVisible(false);
  serviceLabel->setVisible(false);
  m_serviceCombo->setVisible(false);
  formDefLabel->setVisible(false);
  m_formDefInput->setVisible(false);

  connect(m_scanTypeCombo, &QComboBox::currentTextChanged, this, [this, cookieLabel, serviceLabel, formDefLabel](const QString &) {
    QString scanType = m_scanTypeCombo->currentData().toString();
    bool isWeb = (scanType == "web_scan");
    bool isBrute = (scanType == "brute_force");
    cookieLabel->setVisible(isWeb);
    m_cookieInput->setVisible(isWeb);
    serviceLabel->setVisible(isBrute);
    m_serviceCombo->setVisible(isBrute);
    formDefLabel->setVisible(isBrute && m_serviceCombo->currentData().toString() == "http-post-form");
    m_formDefInput->setVisible(isBrute && m_serviceCombo->currentData().toString() == "http-post-form");
  });
  connect(m_serviceCombo, &QComboBox::currentTextChanged, this, [this, formDefLabel]() {
    bool isForm = (m_serviceCombo->currentData().toString() == "http-post-form");
    formDefLabel->setVisible(isForm);
    m_formDefInput->setVisible(isForm);
  });

  // ── Task list ─────────────────────────────────────────────────────
  auto *taskHeaderH = new QHBoxLayout;
  auto *taskLabel = new QLabel("扫描任务"); taskLabel->setStyleSheet(Theme::SectionStyle);
  taskHeaderH->addWidget(taskLabel);
  m_taskCountLabel = new QLabel;
  m_taskCountLabel->setStyleSheet("color:#64748b; font-size:13px;");
  taskHeaderH->addWidget(m_taskCountLabel);
  taskHeaderH->addStretch();
  left->addLayout(taskHeaderH);

  m_taskTable = new QTableWidget(0, 4);
  m_taskTable->setHorizontalHeaderLabels({"目标", "类型", "状态", "时间"});
  m_taskTable->setAlternatingRowColors(true);
  m_taskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_taskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_taskTable->setSelectionMode(QAbstractItemView::SingleSelection);
  m_taskTable->setSortingEnabled(false);
  m_taskTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_taskTable->horizontalHeader()->setStretchLastSection(true);
  left->addWidget(m_taskTable, 1);
  connect(m_taskTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);

  // ── Left-panel buttons ────────────────────────────────────────────
  auto *btnH = new QHBoxLayout;
  m_delBtn = new QPushButton("删除选中");
  m_delBtn->setProperty("danger", true);
  m_delBtn->setEnabled(false);
  auto *refreshBtn = new QPushButton("刷新任务列表");
  btnH->addWidget(m_delBtn);
  btnH->addStretch();
  btnH->addWidget(refreshBtn);
  left->addLayout(btnH);
  connect(m_delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
  connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);

  auto *leftW = new QWidget;
  leftW->setLayout(left);
  leftW->setMinimumWidth(200);

  // ══ Right Panel ═════════════════════════════════════════════════════
  auto *right = new QVBoxLayout;

  // ── Status label ──────────────────────────────────────────────────
  m_statusLabel = new QLabel("选择任务查看详情");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_statusLabel->setWordWrap(true);
  right->addWidget(m_statusLabel);

  // ── Re-execute button (hidden by default) ─────────────────────────
  auto *reexecH = new QHBoxLayout;
  m_reexecBtn = new QPushButton("重新执行");
  m_reexecBtn->setVisible(false);
  reexecH->addWidget(m_reexecBtn);
  reexecH->addStretch();
  right->addLayout(reexecH);
  connect(m_reexecBtn, &QPushButton::clicked, this, &ScanPage::onReexecScan);

  // ── Results ───────────────────────────────────────────────────────
  auto *resLabel = new QLabel("扫描结果"); resLabel->setStyleSheet(Theme::SectionStyle);
  right->addWidget(resLabel);
  m_resultTable = new QTableWidget(0, 4);
  m_resultTable->setHorizontalHeaderLabels({"类型", "严重度", "数据", "工具"});
  m_resultTable->setAlternatingRowColors(true);
  m_resultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_resultTable->setSortingEnabled(true);
  m_resultTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_resultTable->horizontalHeader()->setStretchLastSection(true);
  m_resultTable->setColumnWidth(0, 90);   // 类型
  m_resultTable->setColumnWidth(1, 60);   // 严重度
  m_resultTable->setColumnWidth(3, 70);   // 工具
  right->addWidget(m_resultTable, 1);

  // ── Recommendations ───────────────────────────────────────────────
  auto *recLabel = new QLabel("推荐预案"); recLabel->setStyleSheet(Theme::SectionStyle);
  right->addWidget(recLabel);
  m_recTable = new QTableWidget(0, 4);
  m_recTable->setHorizontalHeaderLabels({"名称", "难度", "基线组", "匹配原因"});
  m_recTable->setAlternatingRowColors(true);
  m_recTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_recTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_recTable->setSortingEnabled(true);
  m_recTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_recTable->horizontalHeader()->setStretchLastSection(true);
  right->addWidget(m_recTable, 1);
  connect(m_recTable, &QTableWidget::cellClicked, this, &ScanPage::onRecommendationClicked);

  // ── AI Generate Playbook ──────────────────────────────────────────
  auto *bottomH = new QHBoxLayout;
  m_genBtn = new QPushButton("AI 生成 Playbook");
  m_genBtn->setEnabled(false);
  m_genBtn->setProperty("primary", true);
  bottomH->addWidget(m_genBtn);
  m_viewGenBtn = new QPushButton("查看生成的 Playbook →");
  m_viewGenBtn->setVisible(false);
  m_viewGenBtn->setProperty("primary", true);
  bottomH->addWidget(m_viewGenBtn);
  bottomH->addStretch();
  right->addLayout(bottomH);
  connect(m_genBtn, &QPushButton::clicked, this, &ScanPage::onGeneratePlaybook);
  connect(m_viewGenBtn, &QPushButton::clicked, this, &ScanPage::onViewGeneratedPlaybook);

  auto *rightW = new QWidget;
  rightW->setLayout(right);
  rightW->setMinimumWidth(200);

  // ══ Splitter ═══════════════════════════════════════════════════════
  auto *splitter = new QSplitter(Qt::Horizontal, this);
  splitter->addWidget(leftW);
  splitter->addWidget(rightW);
  splitter->setStretchFactor(0, 2);
  splitter->setStretchFactor(1, 3);
  splitter->setSizes({400, 600});
  mainLayout->addWidget(splitter);

  // ── Poll timer for running scans ──────────────────────────────────
  m_pollTimer = new QTimer(this);
  m_pollTimer->setInterval(3000);
  connect(m_pollTimer, &QTimer::timeout, this, &ScanPage::onPollStatus);

  // ── Right-click menus ─────────────────────────────────────────────
  connect(m_taskTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_taskTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_taskTable->viewport()->mapToGlobal(pos));
  });
  connect(m_resultTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_resultTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_resultTable->viewport()->mapToGlobal(pos));
  });
  connect(m_recTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_recTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_recTable->viewport()->mapToGlobal(pos));
  });
}

// ── Update status label from task detail object ───────────────────────
void ScanPage::updateStatusLabel(const QJsonObject &d) {
  QString status = d["status"].toString();
  QString target = d["target"].toString();
  QString scanType = formatScanType(d["scan_type"].toString());
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

  // Count structured vs raw results
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
  // Use warning style for completed-but-no-structured-results
  if (status == "COMPLETED" && !structured)
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
  else
    m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
}

// ── Create scan (auto-execute) ───────────────────────────────────────
void ScanPage::onCreateScan() {
  QString target = m_targetInput->text().trimmed();
  if (target.isEmpty()) return;

  // Save to history
  {
    QSettings settings("RedTeam", "RedTeam-Platform");
    QStringList history = settings.value("history/targets").toStringList();
    history.removeAll(target);
    history.prepend(target);
    while (history.size() > 20) history.removeLast();
    settings.setValue("history/targets", history);
    if (auto *c = m_targetInput->completer()) {
      auto *m = qobject_cast<QStringListModel*>(c->model());
      if (m) m->setStringList(history);
    }
  }

  QJsonObject body;
  body["target"] = target;
  body["scan_type"] = m_scanTypeCombo->currentData().toString();

  // Build parameters object (ports + optional cookie/brute-force params)
  QString ports = m_portsInput->text().trimmed();
  QString cookie = m_cookieInput->text().trimmed();
  QString scanType = m_scanTypeCombo->currentData().toString();
  QJsonObject parameters;
  if (!ports.isEmpty()) parameters["ports"] = ports;
  if (!cookie.isEmpty()) parameters["cookie"] = cookie;
  // Brute force: service type + optional form definition
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
    QString taskId = res["data"].toObject()["scan_task_id"].toString();
    m_selectedTaskId = taskId;
    m_statusLabel->setText(QString("已创建: %1 — 正在自动执行...").arg(taskId.left(16)));
    m_statusLabel->setStyleSheet(Theme::StatusSuccessStyle);
    m_targetInput->clear();
    m_portsInput->clear();
    onRefreshTasks();

    // Auto-execute the scan after creation
    QJsonObject empty;
    m_api->post("/api/scan-tasks/" + taskId + "/execute", empty, 5000, [this, taskId](const QJsonObject &execRes) {
      if (execRes["status"].toString() == "ok") {
        m_reexecBtn->setVisible(false);
        // Track this task as running and ensure polling is active
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

// ── Start polling if any tasks are RUNNING ─────────────────────────────
void ScanPage::startPollingIfNeeded() {
  if (!m_runningTaskIds.isEmpty() && !m_pollTimer->isActive()) {
    m_pollTimer->start();
  } else if (m_runningTaskIds.isEmpty() && m_pollTimer->isActive()) {
    m_pollTimer->stop();
  }
}

// ── Refresh task list ─────────────────────────────────────────────────
void ScanPage::onRefreshTasks() {
  m_api->get("/api/scan-tasks", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_taskTable->setRowCount(arr.size());
    m_taskCountLabel->setText(QString("共 %1 个").arg(arr.size()));

    int selectRow = -1;
    QStringList runningIds;
    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      QString taskId = t["scan_task_id"].toString();

      // Target column — store task ID in UserRole
      auto *targetItem = new QTableWidgetItem(t["target"].toString());
      targetItem->setData(Qt::UserRole, taskId);
      m_taskTable->setItem(i, 0, targetItem);

      // Chinese scan type
      m_taskTable->setItem(i, 1, new QTableWidgetItem(formatScanType(t["scan_type"].toString())));

      // Color-coded Chinese status
      QString status = t["status"].toString();
      auto *statusItem = new QTableWidgetItem(formatStatus(status));
      statusItem->setForeground(statusColor(status));
      m_taskTable->setItem(i, 2, statusItem);

      // Formatted time
      m_taskTable->setItem(i, 3, new QTableWidgetItem(formatTime(t["created_at"].toString())));

      // Track running tasks
      if (status == "RUNNING" || status == "PENDING") {
        runningIds << taskId;
      }

      // Track row to select for the currently selected task
      if (!m_selectedTaskId.isEmpty() && taskId == m_selectedTaskId) {
        selectRow = i;
      }
    }
    m_taskTable->resizeColumnsToContents();
    m_taskTable->horizontalHeader()->setStretchLastSection(true);

    // Re-select and highlight the current task row after refresh
    if (selectRow >= 0) {
      m_taskTable->selectRow(selectRow);
      m_delBtn->setEnabled(true);
    }

    // Update running task tracking and auto-start/stop polling
    m_runningTaskIds = runningIds;
    startPollingIfNeeded();
  });
}

// ── Task clicked → show detail in right panel ────────────────────────
void ScanPage::onTaskClicked(int row, int) {
  auto *idItem = m_taskTable->item(row, 0);
  if (!idItem) return;
  QString id = idItem->data(Qt::UserRole).toString();
  if (id.isEmpty()) return;
  m_selectedTaskId = id;
  m_delBtn->setEnabled(true);

  // Fetch real status from API (table may be stale)
  m_api->get("/api/scan-tasks/" + id, 5000, [this, id](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    // Update the status column in the table to keep it in sync
    for (int i = 0; i < m_taskTable->rowCount(); i++) {
      auto *item = m_taskTable->item(i, 0);
      if (item && item->data(Qt::UserRole).toString() == id) {
        auto *statusItem = new QTableWidgetItem(formatStatus(status));
        statusItem->setForeground(statusColor(status));
        m_taskTable->setItem(i, 2, statusItem);
        break;
      }
    }

    // Update status label with target + summary
    updateStatusLabel(d);

    // Populate result table (disable sorting during bulk fill to prevent row shuffling)
    auto arr = d["results"].toArray();
    m_resultTable->setSortingEnabled(false);
    m_resultTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString resultType = r["result_type"].toString();
      bool isRaw = (resultType == "raw_output");

      // Type column: raw_output shown as muted
      auto *typeItem = new QTableWidgetItem(formatResultType(resultType));
      if (isRaw) typeItem->setForeground(QColor("#94a3b8"));
      m_resultTable->setItem(i, 0, typeItem);

      // Severity with color and Chinese label
      QString sev = r["severity"].toString();
      auto *sevItem = new QTableWidgetItem(formatSeverity(sev));
      sevItem->setForeground(severityColor(sev));
      m_resultTable->setItem(i, 1, sevItem);

      // Result data: type-aware formatting + tooltip for full content
      QString rawData = r["result_data"].toString();
      auto *dataItem = new QTableWidgetItem(formatResultData(rawData, resultType));
      dataItem->setToolTip(rawData);
      if (isRaw) dataItem->setForeground(QColor("#94a3b8"));  // muted for raw output
      m_resultTable->setItem(i, 2, dataItem);

      m_resultTable->setItem(i, 3, new QTableWidgetItem(r["source_tool"].toString()));
    }
    m_resultTable->resizeColumnsToContents();
    m_resultTable->horizontalHeader()->setStretchLastSection(true);
    m_resultTable->setSortingEnabled(true);

    // Update buttons based on real API status
    // Always clear per-task state from previous selection
    m_viewGenBtn->setVisible(false);
    m_lastGeneratedId.clear();

    bool structured = hasStructuredResults(arr);
    if (status == "COMPLETED" && structured) {
      m_genBtn->setEnabled(true);
      m_reexecBtn->setVisible(false);
      loadRecommendations(id);
    } else if (status == "COMPLETED" && !structured) {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(true);  // allow re-exec for empty results
      m_recTable->setRowCount(0);
    } else if (status == "PENDING") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
    } else if (status == "RUNNING") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
      // Ensure this task is tracked for polling
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

    // Update status label
    updateStatusLabel(d);

    auto arr = d["results"].toArray();
    m_resultTable->setSortingEnabled(false);
    m_resultTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      QString resultType = r["result_type"].toString();
      bool isRaw = (resultType == "raw_output");

      auto *typeItem = new QTableWidgetItem(formatResultType(resultType));
      if (isRaw) typeItem->setForeground(QColor("#94a3b8"));
      m_resultTable->setItem(i, 0, typeItem);

      QString sev = r["severity"].toString();
      auto *sevItem = new QTableWidgetItem(formatSeverity(sev));
      sevItem->setForeground(severityColor(sev));
      m_resultTable->setItem(i, 1, sevItem);

      QString rawData = r["result_data"].toString();
      auto *dataItem = new QTableWidgetItem(formatResultData(rawData, resultType));
      dataItem->setToolTip(rawData);
      if (isRaw) dataItem->setForeground(QColor("#94a3b8"));
      m_resultTable->setItem(i, 2, dataItem);

      m_resultTable->setItem(i, 3, new QTableWidgetItem(r["source_tool"].toString()));
    }
    m_resultTable->resizeColumnsToContents();
    m_resultTable->horizontalHeader()->setStretchLastSection(true);
    m_resultTable->setSortingEnabled(true);
  });
}

// ── Load recommendations ─────────────────────────────────────────────
void ScanPage::loadRecommendations(const QString &taskId) {
  m_api->get("/api/scan-tasks/" + taskId + "/recommendations", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_recTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      // Store playbook_id in UserRole so click handler can navigate
      auto *nameItem = new QTableWidgetItem(r["name"].toString());
      nameItem->setData(Qt::UserRole, r["playbook_id"].toString());
      m_recTable->setItem(i, 0, nameItem);
      m_recTable->setItem(i, 1, new QTableWidgetItem(formatDifficulty(r["difficulty"].toString())));
      m_recTable->setItem(i, 2, new QTableWidgetItem(formatBaselineGroup(r["baseline_group"].toString())));
      m_recTable->setItem(i, 3, new QTableWidgetItem(r["match_reason"].toString()));
    }
    m_recTable->resizeColumnsToContents();
    m_recTable->horizontalHeader()->setStretchLastSection(true);
  });
}

// ── AI Generate Playbook ──────────────────────────────────────────────
void ScanPage::onGeneratePlaybook() {
  if (m_selectedTaskId.isEmpty()) return;
  m_genBtn->setEnabled(false);
  m_genBtn->setText("AI 生成中...");
  m_viewGenBtn->setVisible(false);
  QJsonObject body;
  m_api->post("/api/scan-tasks/" + m_selectedTaskId + "/generate-playbook", body, 60000, [this](const QJsonObject &res) {
    m_genBtn->setEnabled(true);
    m_genBtn->setText("AI 生成预案");
    if (res["status"].toString() == "ok") {
      auto data = res["data"].toObject();
      QString pbId = data["playbook_id"].toString();
      QString pbName = data["name"].toString();
      int steps = data["steps_count"].toInt();

      m_lastGeneratedId = pbId;
      m_statusLabel->setText(QString("✓ 已生成: %1 (%2步) — 已添加到预案库").arg(pbName).arg(steps));
      m_statusLabel->setStyleSheet(Theme::StatusSuccessStyle);

      // Show "查看生成的 Playbook" button
      m_viewGenBtn->setVisible(true);
      m_viewGenBtn->setText(QString("查看「%1」→").arg(pbName.left(20)));

      loadRecommendations(m_selectedTaskId);
    } else {
      // Show specific error reason from backend
      QString errMsg = res["error"].toObject()["message"].toString();
      if (errMsg.isEmpty()) errMsg = res["data"].toObject()["error"].toString();
      if (errMsg.contains("401") || errMsg.contains("invalid", Qt::CaseInsensitive) || errMsg.contains("authentication", Qt::CaseInsensitive))
        errMsg = "LLM API Key 无效，请在「系统管理→系统配置」中检查 llm 配置的 key 和 url";
      else if (errMsg.contains("timed out", Qt::CaseInsensitive))
        errMsg = "LLM 请求超时，请稍后重试";
      else if (errMsg.contains("No LLM API key", Qt::CaseInsensitive))
        errMsg = "未配置 LLM API Key，请在「系统管理→系统配置」中设置 llm 配置";
      else if (errMsg.isEmpty())
        errMsg = "未知错误";
      m_statusLabel->setText(QString("✗ 预案生成失败: %1").arg(errMsg.left(120)));
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });
}

// ── Recommendation clicked → navigate to PlaybookPage ────────────────
void ScanPage::onRecommendationClicked(int row, int) {
  auto *item = m_recTable->item(row, 0);
  if (!item) return;
  QString pbId = item->data(Qt::UserRole).toString();
  if (pbId.isEmpty()) return;

  // Navigate to PlaybookPage and select this playbook
  emit playbookNavigateRequested(pbId);
}

// ── View generated Playbook → navigate to PlaybookPage ────────────────
void ScanPage::onViewGeneratedPlaybook() {
  if (m_lastGeneratedId.isEmpty()) return;
  emit playbookNavigateRequested(m_lastGeneratedId);
}

// ── Re-execute scan (for FAILED/CANCELLED tasks) ─────────────────────
void ScanPage::onReexecScan() {
  if (m_selectedTaskId.isEmpty()) return;
  m_reexecBtn->setVisible(false);
  clearDetailPanel();  // Clear old results before re-executing
  m_statusLabel->setText("重新执行中...");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);

  QJsonObject empty;
  m_api->post("/api/scan-tasks/" + m_selectedTaskId + "/execute", empty, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      // Track as running and ensure polling is active
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

  // Check if task is RUNNING — cannot delete
  m_api->get("/api/scan-tasks/" + m_selectedTaskId, 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    if (status == "RUNNING") {
      QMessageBox::warning(this->window(), "无法删除",
        "正在运行的任务无法删除，请先等待完成。");
      return;
    }

    // Build readable confirmation text
    QString target = d["target"].toString();
    QString type = formatScanType(d["scan_type"].toString());
    auto reply = QMessageBox::question(this->window(), "确认删除",
      QString("确定要删除此扫描任务吗？\n目标: %1 | %2\n此操作不可撤销。").arg(target, type),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    m_api->del("/api/scan-tasks/" + m_selectedTaskId, 5000, [this](const QJsonObject &) {
      m_selectedTaskId.clear();
      clearDetailPanel();
      m_delBtn->setEnabled(false);
      onRefreshTasks();
    });
  });
}

// ── Clear detail panel ────────────────────────────────────────────────
void ScanPage::clearDetailPanel() {
  m_statusLabel->setText("选择任务查看详情");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_resultTable->setRowCount(0);
  m_recTable->setRowCount(0);
  m_genBtn->setEnabled(false);
  m_reexecBtn->setVisible(false);
  m_viewGenBtn->setVisible(false);
  m_lastGeneratedId.clear();
}

// ── Poll scan status ─────────────────────────────────────────────────
void ScanPage::onPollStatus() {
  // Poll ALL running/pending tasks to keep the task list status in sync.
  // Also update the detail panel if the selected task is among them.
  if (m_runningTaskIds.isEmpty()) {
    m_pollTimer->stop();
    return;
  }

  // Refresh the full task list (lightweight — just the list endpoint)
  // to catch status changes for all running tasks at once
  m_api->get("/api/scan-tasks", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();

    QStringList stillRunning;
    bool selectedTaskFinished = false;
    QString finishedStatus;

    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      QString taskId = t["scan_task_id"].toString();
      QString status = t["status"].toString();

      // Update status column in the table for any task that was running
      if (m_runningTaskIds.contains(taskId)) {
        // Find the row and update status
        for (int row = 0; row < m_taskTable->rowCount(); row++) {
          auto *idItem = m_taskTable->item(row, 0);
          if (idItem && idItem->data(Qt::UserRole).toString() == taskId) {
            auto *statusItem = new QTableWidgetItem(formatStatus(status));
            statusItem->setForeground(statusColor(status));
            m_taskTable->setItem(row, 2, statusItem);
            break;
          }
        }

        if (status == "RUNNING" || status == "PENDING") {
          stillRunning << taskId;
        } else {
          // Task just reached terminal state
          if (taskId == m_selectedTaskId) {
            selectedTaskFinished = true;
            finishedStatus = status;
          }
        }
      }
    }

    m_runningTaskIds = stillRunning;
    startPollingIfNeeded();

    // If the currently selected task just finished, reload its detail
    // (this replaces the old race-prone onRefreshTasks + loadResults combo)
    if (selectedTaskFinished && !m_selectedTaskId.isEmpty()) {
      // Find the row of the selected task and trigger a full detail reload
      for (int row = 0; row < m_taskTable->rowCount(); row++) {
        auto *idItem = m_taskTable->item(row, 0);
        if (idItem && idItem->data(Qt::UserRole).toString() == m_selectedTaskId) {
          onTaskClicked(row, 0);
          break;
        }
      }
    } else if (!m_selectedTaskId.isEmpty() && m_runningTaskIds.contains(m_selectedTaskId)) {
      // Selected task is still running — do a progressive detail update
      m_api->get("/api/scan-tasks/" + m_selectedTaskId, 5000, [this](const QJsonObject &detailRes) {
        if (detailRes["status"].toString() != "ok") return;
        auto d = detailRes["data"].toObject();
        QString status = d["status"].toString();

        // Update status label
        updateStatusLabel(d);

        // Progressive result update
        auto arr = d["results"].toArray();
        m_resultTable->setSortingEnabled(false);
        m_resultTable->setRowCount(arr.size());
        for (int i = 0; i < arr.size(); i++) {
          auto r = arr[i].toObject();
          QString resultType = r["result_type"].toString();
          bool isRaw = (resultType == "raw_output");

          auto *typeItem = new QTableWidgetItem(formatResultType(resultType));
          if (isRaw) typeItem->setForeground(QColor("#94a3b8"));
          m_resultTable->setItem(i, 0, typeItem);

          QString sev = r["severity"].toString();
          auto *sevItem = new QTableWidgetItem(formatSeverity(sev));
          sevItem->setForeground(severityColor(sev));
          m_resultTable->setItem(i, 1, sevItem);

          QString rawData = r["result_data"].toString();
          auto *dataItem = new QTableWidgetItem(formatResultData(rawData, resultType));
          dataItem->setToolTip(rawData);
          if (isRaw) dataItem->setForeground(QColor("#94a3b8"));
          m_resultTable->setItem(i, 2, dataItem);

          m_resultTable->setItem(i, 3, new QTableWidgetItem(r["source_tool"].toString()));
        }
        m_resultTable->resizeColumnsToContents();
        m_resultTable->horizontalHeader()->setStretchLastSection(true);
        m_resultTable->setSortingEnabled(true);
      });
    }
  });
}
