#include "TopologyPage.h"
#include "../ApiClient.h"
#include "../Theme.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsScene>
#include <QGraphicsSimpleTextItem>
#include <QGraphicsView>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProgressDialog>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSet>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QtMath>
#include <QWheelEvent>

// ── Anonymous namespace: helper functions ──────────────────────────────────

namespace {

QString successStatusStyle() {
    return QStringLiteral("color:#166534; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:8px 10px;");
}

QString errorStatusStyle() {
    return QStringLiteral("color:#991b1b; background:#fef2f2; border:1px solid #fecaca; border-radius:8px; padding:8px 10px;");
}

QString infoStatusStyle() {
    return QStringLiteral("color:#1d4ed8; background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; padding:8px 10px;");
}

QString normalizedLine(const QString &text) {
    QString value = text;
    value.replace(QRegularExpression(QStringLiteral("\\s+")), QStringLiteral(" "));
    return value.trimmed();
}

QString firstIpInText(const QString &text) {
    static const QRegularExpression ipPattern(QStringLiteral("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"));
    const QRegularExpressionMatch match = ipPattern.match(text);
    return match.hasMatch() ? match.captured(0) : QString();
}

bool isValidTopologyPortText(const QString &text) {
    bool ok = false;
    const int port = text.trimmed().toInt(&ok);
    return ok && port > 0 && port <= 65535;
}

QString serviceNameFromTopologyContext(const QString &context) {
    static const QList<QPair<QString, QString>> rules{
        {QStringLiteral("jdwp"), QStringLiteral("JDWP")},
        {QStringLiteral("redis"), QStringLiteral("Redis")},
        {QStringLiteral("postgresql"), QStringLiteral("PostgreSQL")},
        {QStringLiteral("postgres"), QStringLiteral("PostgreSQL")},
        {QStringLiteral("mysql"), QStringLiteral("MySQL")},
        {QStringLiteral("grafana"), QStringLiteral("Grafana")},
        {QStringLiteral("prometheus"), QStringLiteral("Prometheus")},
        {QStringLiteral("tomcat"), QStringLiteral("Tomcat")},
        {QStringLiteral("apache"), QStringLiteral("Apache HTTP")},
        {QStringLiteral("nginx"), QStringLiteral("Nginx")},
        {QStringLiteral("ollama"), QStringLiteral("Ollama")},
        {QStringLiteral("langflow"), QStringLiteral("Langflow")},
        {QStringLiteral("dataease"), QStringLiteral("DataEase")},
        {QStringLiteral("vampi"), QStringLiteral("VAmPI")},
        {QStringLiteral("dvwa"), QStringLiteral("DVWA")},
        {QStringLiteral("minio"), QStringLiteral("MinIO")},
        {QStringLiteral("elasticsearch"), QStringLiteral("Elasticsearch")},
        {QStringLiteral("ssh"), QStringLiteral("SSH")},
        {QStringLiteral("rdp"), QStringLiteral("RDP")},
        {QStringLiteral("nfs"), QStringLiteral("NFS")},
        {QStringLiteral("rpcbind"), QStringLiteral("RPCBind")},
        {QStringLiteral("surrealdb"), QStringLiteral("SurrealDB")},
        {QStringLiteral("juice shop"), QStringLiteral("Juice Shop")},
        {QStringLiteral("phpmyadmin"), QStringLiteral("phpMyAdmin")},
        {QStringLiteral("pgadmin"), QStringLiteral("pgAdmin")},
        {QStringLiteral("vite"), QStringLiteral("Vite")},
        {QStringLiteral("next.js"), QStringLiteral("Next.js")},
        {QStringLiteral("nextjs"), QStringLiteral("Next.js")},
        {QStringLiteral("hexstrike"), QStringLiteral("HexStrike")},
        {QStringLiteral("secmanus"), QStringLiteral("SecManus API")},
        {QStringLiteral("open notebook"), QStringLiteral("Open Notebook")},
        {QStringLiteral("open webui"), QStringLiteral("Open WebUI")},
        {QStringLiteral("pentagi"), QStringLiteral("PentAGI")},
    };
    const QString lower = context.toLower();
    for (const QPair<QString, QString> &rule : rules) {
        if (lower.contains(rule.first)) {
            return rule.second;
        }
    }
    return QString();
}

QString protocolFromTopologyContext(const QString &context) {
    const QString lower = context.toLower();
    if (lower.contains(QStringLiteral("/udp")) || lower.contains(QStringLiteral("udp"))) {
        return QStringLiteral("udp");
    }
    return QStringLiteral("tcp");
}

QString compactTopologyNote(const QString &text, int maxLength = 220) {
    QString note = normalizedLine(text);
    if (note.size() > maxLength) {
        note = note.left(maxLength - 1).trimmed() + QStringLiteral("...");
    }
    return note;
}

QString topologyNodeFingerprint(const TopologyNodeRecord &node) {
    const QString stable = !node.ip.trimmed().isEmpty() ? node.ip.trimmed() : node.id.trimmed();
    return stable.toLower();
}

QString topologyServiceFingerprint(const TopologyServiceRecord &service) {
    return service.port.trimmed().toLower() + QLatin1Char('|')
        + service.protocol.trimmed().toLower() + QLatin1Char('|')
        + service.service.trimmed().toLower();
}

void appendUniqueTopologyService(QList<TopologyServiceRecord> *services,
                                  const TopologyServiceRecord &service) {
    if (!services || (service.port.trimmed().isEmpty() && service.service.trimmed().isEmpty())) {
        return;
    }
    const QString fingerprint = topologyServiceFingerprint(service);
    for (const TopologyServiceRecord &existing : *services) {
        if (topologyServiceFingerprint(existing) == fingerprint) {
            return;
        }
    }
    services->append(service);
}

TopologyNodeRecord *findOrCreateTopologyNode(QList<TopologyNodeRecord> *nodes,
                                              const QString &host,
                                              const QString &fallbackTarget) {
    if (!nodes) {
        return nullptr;
    }
    const QString key = host.trimmed().isEmpty() ? fallbackTarget.trimmed() : host.trimmed();
    if (key.isEmpty()) {
        return nullptr;
    }
    for (TopologyNodeRecord &node : *nodes) {
        if (node.ip == key || node.id == key || node.displayName == key) {
            return &node;
        }
    }
    TopologyNodeRecord node;
    node.id = QStringLiteral("host-%1").arg(key);
    node.id.replace(QLatin1Char('.'), QLatin1Char('-'));
    node.displayName = key;
    node.ip = key;
    node.status = QStringLiteral("up");
    node.deviceType = QStringLiteral("host");
    nodes->append(node);
    return &nodes->last();
}

void extractTopologyServicesFromLine(const QString &line, const QString &fallbackTarget,
                                     QList<TopologyNodeRecord> *nodes) {
    if (!nodes) {
        return;
    }
    const QString host = firstIpInText(line);
    TopologyNodeRecord *node = findOrCreateTopologyNode(nodes, host, fallbackTarget);
    if (!node) {
        return;
    }
    auto appendService = [node, &line](const QString &portText, const QString &protocolText) {
        if (!isValidTopologyPortText(portText)) {
            return;
        }
        TopologyServiceRecord service;
        service.port = QString::number(portText.toInt());
        service.protocol = protocolText.trimmed().isEmpty()
                               ? protocolFromTopologyContext(line)
                               : protocolText.trimmed().toLower();
        service.service = serviceNameFromTopologyContext(line);
        service.state = QStringLiteral("open");
        service.note = compactTopologyNote(line);
        appendUniqueTopologyService(&node->services, service);
    };

    static const QRegularExpression slashPattern(
        QStringLiteral("\\b(\\d{1,5})\\s*/\\s*(tcp|udp)\\b"),
        QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator slashIterator = slashPattern.globalMatch(line);
    while (slashIterator.hasNext()) {
        const QRegularExpressionMatch match = slashIterator.next();
        appendService(match.captured(1), match.captured(2));
    }

    static const QRegularExpression labelPattern(
        QStringLiteral("(?:端口|port|ports|:|：|@)\\s*(\\d{1,5})(?![\\.\\d])"),
        QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator labelIterator = labelPattern.globalMatch(line);
    while (labelIterator.hasNext()) {
        const QRegularExpressionMatch match = labelIterator.next();
        appendService(match.captured(1), QString());
    }

    if (!line.contains(QLatin1Char('|'))) {
        return;
    }
    const bool tableLikelyContainsPorts = !serviceNameFromTopologyContext(line).isEmpty()
        || line.contains(QStringLiteral("端口"))
        || line.contains(QStringLiteral("服务"))
        || line.contains(QStringLiteral("port"), Qt::CaseInsensitive)
        || line.contains(QStringLiteral("open"), Qt::CaseInsensitive)
        || line.contains(QStringLiteral("开放"));
    if (!tableLikelyContainsPorts) {
        return;
    }
    static const QRegularExpression tablePortPattern(QStringLiteral("\\b(\\d{1,5})\\+?\\b"));
    const QStringList cells = line.split(QLatin1Char('|'), QString::SkipEmptyParts);
    for (const QString &cell : cells) {
        const QString normalizedCell = cell.trimmed();
        if (normalizedCell.contains(QLatin1Char('.'))) {
            continue;
        }
        QRegularExpressionMatchIterator tableIterator =
            tablePortPattern.globalMatch(normalizedCell);
        while (tableIterator.hasNext()) {
            const QRegularExpressionMatch match = tableIterator.next();
            appendService(match.captured(1),
                          line.contains(QStringLiteral("udp"), Qt::CaseInsensitive)
                              ? QStringLiteral("udp")
                              : QString());
        }
    }
}

// ── Custom QGraphicsView with wheel zoom ──────────────────────────────────

class TopologyGraphicsView : public QGraphicsView {
public:
    explicit TopologyGraphicsView(QWidget *parent = nullptr)
        : QGraphicsView(parent) {}

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

// ── Custom QGraphicsEllipseItem for draggable topology nodes ────────────

class TopologyNodeItem : public QGraphicsEllipseItem {
public:
    explicit TopologyNodeItem(const QString &nodeId, const QRectF &rect)
        : QGraphicsEllipseItem(rect),
          m_nodeId(nodeId) {
        setFlags(QGraphicsItem::ItemIsSelectable | QGraphicsItem::ItemIsMovable);
        setAcceptedMouseButtons(Qt::LeftButton);
        setData(0, nodeId);
        setData(1, QStringLiteral("node"));
        setZValue(2.0);
    }

    std::function<void(const QString &, const QPointF &)> onMoveFinished;

protected:
    void mouseReleaseEvent(QGraphicsSceneMouseEvent *event) override {
        QGraphicsEllipseItem::mouseReleaseEvent(event);
        if (onMoveFinished) {
            onMoveFinished(m_nodeId, sceneBoundingRect().center());
        }
    }

private:
    QString m_nodeId;
};

// ── Custom QGraphicsLineItem for topology edges ─────────────────────────

class TopologyEdgeItem : public QGraphicsLineItem {
public:
    explicit TopologyEdgeItem(const QString &edgeId, const QLineF &line)
        : QGraphicsLineItem(line) {
        setFlags(QGraphicsItem::ItemIsSelectable);
        setAcceptedMouseButtons(Qt::LeftButton);
        setData(0, edgeId);
        setData(1, QStringLiteral("edge"));
        setZValue(0.5);
    }
};

// ── Color helpers ───────────────────────────────────────────────────────

QString nodeStatusColor(const QString &status) {
    if (status == QStringLiteral("up") || status == QStringLiteral("online")) {
        return QStringLiteral("#22c55e");
    }
    if (status == QStringLiteral("warning")) {
        return QStringLiteral("#f59e0b");
    }
    if (status == QStringLiteral("down")) {
        return QStringLiteral("#ef4444");
    }
    return QStringLiteral("#94a3b8");
}

QString nodeStatusLabel(const QString &status) {
    if (status == QStringLiteral("up") || status == QStringLiteral("online")) return QStringLiteral("在线");
    if (status == QStringLiteral("warning")) return QStringLiteral("告警");
    if (status == QStringLiteral("down")) return QStringLiteral("离线");
    if (status == QStringLiteral("unknown")) return QStringLiteral("未知");
    return status;
}

QString edgeColor(const QString &type) {
    if (type == QStringLiteral("gateway") || type == QStringLiteral("route")) {
        return QStringLiteral("#38bdf8");
    }
    if (type == QStringLiteral("uplink") || type == QStringLiteral("trunk")) {
        return QStringLiteral("#f59e0b");
    }
    return QStringLiteral("#64748b");
}

QString edgeTypeLabel(const QString &type) {
    if (type == QStringLiteral("connection")) return QStringLiteral("连接");
    if (type == QStringLiteral("gateway")) return QStringLiteral("网关");
    if (type == QStringLiteral("route")) return QStringLiteral("路由");
    if (type == QStringLiteral("uplink")) return QStringLiteral("上行链路");
    if (type == QStringLiteral("trunk")) return QStringLiteral("主干");
    return type;
}

QString fallbackEdgeLabel(const TopologyEdgeRecord &edge) {
    if (!edge.label.trimmed().isEmpty()) {
        return edge.label.trimmed();
    }
    if (!edge.type.trimmed().isEmpty()) {
        return edgeTypeLabel(edge.type.trimmed());
    }
    return QStringLiteral("连接关系");
}

QString topologyNodeTooltip(const TopologyNodeRecord &node) {
    QStringList lines;
    const QString title = !node.displayName.trimmed().isEmpty()
        ? node.displayName.trimmed()
        : (!node.hostName.trimmed().isEmpty()
               ? node.hostName.trimmed()
               : (!node.ip.trimmed().isEmpty() ? node.ip.trimmed() : node.id.trimmed()));
    lines << (title.isEmpty() ? QStringLiteral("未命名节点") : title)
          << QStringLiteral("主机名：%1").arg(node.hostName.isEmpty() ? QStringLiteral("--") : node.hostName)
          << QStringLiteral("系统：%1 %2")
                 .arg(node.osName.isEmpty() ? QStringLiteral("--") : node.osName)
                 .arg(node.osVersion)
          << QStringLiteral("设备类型：%1").arg(node.deviceType.isEmpty() ? QStringLiteral("--") : node.deviceType)
          << QStringLiteral("状态：%1").arg(node.status.isEmpty() ? QStringLiteral("--") : nodeStatusLabel(node.status));

    const QString ip = node.ip.trimmed();
    if (!ip.isEmpty() && title != ip && !title.contains(ip)) {
        lines.insert(1, QStringLiteral("IP：%1").arg(ip));
    } else if (ip.isEmpty()) {
        lines.insert(1, QStringLiteral("IP：--"));
    }

    if (!node.note.trimmed().isEmpty()) {
        lines << QStringLiteral("备注：%1").arg(node.note.trimmed());
    }

    QStringList tcpServices;
    QStringList udpServices;
    QStringList otherServices;
    for (const TopologyServiceRecord &service : node.services) {
        QStringList parts;
        parts << QStringLiteral("%1/%2")
                     .arg(service.port.isEmpty() ? QStringLiteral("--") : service.port)
                     .arg(service.protocol.isEmpty() ? QStringLiteral("tcp") : service.protocol);
        if (!service.service.trimmed().isEmpty()) {
            parts << service.service.trimmed();
        }
        if (!service.product.trimmed().isEmpty()) {
            parts << service.product.trimmed();
        }
        if (!service.version.trimmed().isEmpty()) {
            parts << service.version.trimmed();
        }
        if (!service.state.trimmed().isEmpty()) {
            parts << QStringLiteral("[%1]").arg(service.state.trimmed());
        }
        if (!service.note.trimmed().isEmpty()) {
            parts << QStringLiteral("备注：%1").arg(service.note.trimmed());
        }

        const QString line = parts.join(QStringLiteral(" "));
        const QString protocol = service.protocol.trimmed().toLower();
        if (protocol == QStringLiteral("udp")) {
            udpServices << line;
        } else if (protocol.isEmpty() || protocol == QStringLiteral("tcp")) {
            tcpServices << line;
        } else {
            otherServices << line;
        }
    }

    auto appendServiceGroup = [&lines](const QString &title, const QStringList &services) {
        lines << QStringLiteral("%1：").arg(title);
        if (services.isEmpty()) {
            lines << QStringLiteral("  --");
            return;
        }
        for (const QString &service : services) {
            lines << QStringLiteral("  - %1").arg(service);
        }
    };

    appendServiceGroup(QStringLiteral("TCP 服务"), tcpServices);
    appendServiceGroup(QStringLiteral("UDP 服务"), udpServices);
    if (!otherServices.isEmpty()) {
        appendServiceGroup(QStringLiteral("其他协议服务"), otherServices);
    }

    return lines.join(QStringLiteral("\n"));
}

QString defaultNodeTitle(const TopologyNodeRecord &node) {
    if (!node.displayName.trimmed().isEmpty()) {
        return node.displayName.trimmed();
    }
    if (!node.hostName.trimmed().isEmpty()) {
        return node.hostName.trimmed();
    }
    if (!node.ip.trimmed().isEmpty()) {
        return node.ip.trimmed();
    }
    return node.id.trimmed();
}

QString topologyNodePrimaryLabel(const TopologyNodeRecord &node) {
    const QString displayName = node.displayName.trimmed();
    const QString hostName = node.hostName.trimmed();
    const QString ip = node.ip.trimmed();

    if (!displayName.isEmpty()) {
        return displayName;
    }
    if (!hostName.isEmpty()) {
        return hostName;
    }
    if (!ip.isEmpty()) {
        return ip;
    }
    return node.id.trimmed();
}

QString topologyNodeSecondaryLabel(const TopologyNodeRecord &node,
                                    const QString &primaryLabel) {
    const QString ip = node.ip.trimmed();
    if (!ip.isEmpty() && primaryLabel != ip && !primaryLabel.contains(ip)) {
        return ip;
    }

    const QStringList details{
        node.deviceType.trimmed(),
        node.osName.trimmed(),
        node.vendor.trimmed(),
    };
    for (const QString &detail : details) {
        if (!detail.isEmpty()
            && detail != primaryLabel
            && !primaryLabel.contains(detail, Qt::CaseInsensitive)) {
            return detail;
        }
    }

    if (!node.services.isEmpty()) {
        return QStringLiteral("%1 个服务").arg(node.services.size());
    }
    return {};
}

QString ensureUniqueId(const QString &baseId, const QSet<QString> &usedIds,
                        const QString &fallbackPrefix) {
    QString normalized = normalizedLine(baseId);
    normalized.replace(QLatin1Char(' '), QLatin1Char('-'));
    if (normalized.isEmpty()) {
        normalized = fallbackPrefix;
    }
    if (!usedIds.contains(normalized)) {
        return normalized;
    }
    int suffix = 2;
    QString candidate;
    do {
        candidate = QStringLiteral("%1-%2").arg(normalized).arg(suffix);
        ++suffix;
    } while (usedIds.contains(candidate));
    return candidate;
}

QString scanStatusLabel(const QString &status) {
    if (status == QStringLiteral("COMPLETED")) return QStringLiteral("已完成");
    if (status == QStringLiteral("RUNNING")) return QStringLiteral("运行中");
    if (status == QStringLiteral("PENDING")) return QStringLiteral("待执行");
    if (status == QStringLiteral("FAILED")) return QStringLiteral("失败");
    return status;
}

} // anonymous namespace

// ── TopologyPage ───────────────────────────────────────────────────────────

TopologyPage::TopologyPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent),
      m_api(api),
      m_currentStatusValueLabel(nullptr),
      m_currentProgressValueLabel(nullptr),
      m_currentTargetValueLabel(nullptr),
      m_currentSourceValueLabel(nullptr),
      m_lastGeneratedValueLabel(nullptr),
      m_summaryLabel(nullptr),
      m_statsLabel(nullptr),
      m_scopeLabel(nullptr),
      m_targetInput(nullptr),
      m_scanTypeCombo(nullptr),
      m_createScanBtn(nullptr),
      m_scanTaskTable(nullptr),
      m_generateBtn(nullptr),
      m_refreshBtn(nullptr),
      m_recentListWidget(nullptr),
      m_removeRecordButton(nullptr),
      m_canvasTitleLabel(nullptr),
      m_canvasSubtitleLabel(nullptr),
      m_statusLabel(nullptr),
      m_graphScene(nullptr),
      m_graphView(nullptr),
      m_nodeListWidget(nullptr),
      m_edgeListWidget(nullptr),
      m_detailStack(nullptr),
      m_addNodeButton(nullptr),
      m_addEdgeButton(nullptr),
      m_deleteNodeButton(nullptr),
      m_deleteEdgeButton(nullptr),
      m_saveTopologyButton(nullptr),
      m_applyDetailButton(nullptr),
      m_detailHintLabel(nullptr),
      m_nodeNameEdit(nullptr),
      m_nodeIpEdit(nullptr),
      m_nodeHostNameEdit(nullptr),
      m_nodeOsEdit(nullptr),
      m_nodeTypeEdit(nullptr),
      m_nodeVendorEdit(nullptr),
      m_nodeStatusCombo(nullptr),
      m_nodeNoteEdit(nullptr),
      m_servicesEdit(nullptr),
      m_edgeSourceCombo(nullptr),
      m_edgeTargetCombo(nullptr),
      m_edgeLabelEdit(nullptr),
      m_edgeTypeCombo(nullptr),
      m_edgeNoteEdit(nullptr) {
    setupUI();
    loadRecentRecords();
    onRefreshScans();

    // Try to load last saved topology
    TopologyDocument doc;
    QString error;
    if (loadTopologyDocumentFromPath(defaultTopologyDocumentPath(), &doc, &error)) {
        m_topologyDocument = doc;
        m_loadedTopologyPath = defaultTopologyDocumentPath();
        m_selectedNodeId.clear();
        m_selectedEdgeId.clear();
        m_documentDirty = false;
        m_editorDirty = false;
        populateTopologyDocument();
    } else {
        populateDocumentPlaceholder(QStringLiteral("等待拓扑文件"),
                                    QStringLiteral("请先执行扫描任务，然后点击\"生成拓扑\"按钮生成网络拓扑图。"));
    }
}

// ── UI Construction ────────────────────────────────────────────────────────

void TopologyPage::setupUI() {
    auto *rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);

    // ── Scroll area wrapper ───────────────────────────────────────────
    auto *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    auto *page = new QWidget(scrollArea);
    page->setStyleSheet(QStringLiteral(
        "QWidget { background:#f3f6fb; color:#0f172a; }"
        "QLabel { background:transparent; border:none; }"
        "QFrame[card=\"true\"] { background:#ffffff; border:1px solid #dbe5f0; border-radius:16px; }"
        "QFrame[softCard=\"true\"] { background:#f8fbff; border:1px solid #dbe5f0; border-radius:12px; }"
        "QLineEdit, QPlainTextEdit, QListWidget, QComboBox { background:#ffffff; border:1px solid #cfd9e6; border-radius:8px; padding:6px 8px; }"
        "QLineEdit:focus, QPlainTextEdit:focus, QListWidget:focus, QComboBox:focus { border:1px solid #60a5fa; }"
        "QListWidget::item { border:1px solid #e5edf6; border-radius:10px; margin:4px 0; padding:6px; background:#ffffff; }"
        "QListWidget::item:selected { background:#eff6ff; color:#0f172a; border:1px solid #60a5fa; }"
        "QPushButton { background:#eef3fb; color:#0f172a; border:1px solid #c7d5ea; border-radius:8px; padding:8px 14px; font-weight:600; }"
        "QPushButton:hover { background:#d9e8ff; border:1px solid #9fc2f7; }"
        "QPushButton[primary=\"true\"] { background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; }"
        "QPushButton[primary=\"true\"]:hover { background:#1d4ed8; border:1px solid #1e40af; }"
        "QPushButton[danger=\"true\"] { background:#fff1f2; color:#b42318; border:1px solid #f3b5bd; }"
        "QPushButton[danger=\"true\"]:hover { background:#ffe4e6; border:1px solid #e58b97; }"
        "QPushButton:disabled { background:#e5e7eb; color:#94a3b8; border:1px solid #d1d5db; }"
    ));

    auto *pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(16, 16, 16, 18);
    pageLayout->setSpacing(12);

    // ── Hero Card with stat tiles ─────────────────────────────────────
    auto *heroCard = new QFrame(page);
    heroCard->setProperty("card", true);
    auto *heroLayout = new QVBoxLayout(heroCard);
    heroLayout->setContentsMargins(18, 16, 18, 16);
    heroLayout->setSpacing(12);

    auto *heroTopRow = new QHBoxLayout();
    auto *titleLabel = new QLabel(QStringLiteral("网络拓扑探测与绘制"), heroCard);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(15);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    m_refreshBtn = new QPushButton(QStringLiteral("刷新"), heroCard);
    m_refreshBtn->setProperty("primary", true);
    heroTopRow->addWidget(titleLabel);
    heroTopRow->addStretch();
    heroTopRow->addWidget(m_refreshBtn);

    auto createStatCard = [heroCard](const QString &title, QLabel **valueLabel) {
        auto *card = new QFrame(heroCard);
        card->setProperty("softCard", true);
        auto *layout = new QVBoxLayout(card);
        layout->setContentsMargins(12, 10, 12, 10);
        layout->setSpacing(4);
        auto *titleWidget = new QLabel(title, card);
        titleWidget->setStyleSheet(QStringLiteral("color:#64748b; font-size:11px;"));
        auto *valueWidget = new QLabel(QStringLiteral("--"), card);
        QFont valueFont = valueWidget->font();
        valueFont.setPointSize(13);
        valueFont.setBold(true);
        valueWidget->setFont(valueFont);
        layout->addWidget(titleWidget);
        layout->addWidget(valueWidget);
        *valueLabel = valueWidget;
        return card;
    };

    auto *heroStatsGrid = new QGridLayout();
    heroStatsGrid->setHorizontalSpacing(10);
    heroStatsGrid->setVerticalSpacing(10);
    heroStatsGrid->addWidget(createStatCard(QStringLiteral("当前状态"), &m_currentStatusValueLabel), 0, 0);
    heroStatsGrid->addWidget(createStatCard(QStringLiteral("当前进度"), &m_currentProgressValueLabel), 0, 1);
    heroStatsGrid->addWidget(createStatCard(QStringLiteral("当前目标"), &m_currentTargetValueLabel), 0, 2);
    heroStatsGrid->addWidget(createStatCard(QStringLiteral("数据来源"), &m_currentSourceValueLabel), 0, 3);
    heroStatsGrid->addWidget(createStatCard(QStringLiteral("最近生成"), &m_lastGeneratedValueLabel), 1, 0);
    for (int column = 0; column < 4; ++column) {
        heroStatsGrid->setColumnStretch(column, 1);
    }

    heroLayout->addLayout(heroTopRow);
    heroLayout->addLayout(heroStatsGrid);

    // ── Main splitter ─────────────────────────────────────────────────
    auto *splitter = new QSplitter(Qt::Horizontal, page);
    splitter->setChildrenCollapsible(false);
    splitter->setHandleWidth(8);

    // ── Left Panel ────────────────────────────────────────────────────
    auto *leftPanel = new QFrame(splitter);
    leftPanel->setProperty("card", true);
    leftPanel->setMaximumWidth(340);
    auto *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(14, 12, 14, 14);
    leftLayout->setSpacing(8);

    auto *sectionLabel = new QLabel(QStringLiteral("拓扑探测"), leftPanel);
    sectionLabel->setStyleSheet(Theme::SectionStyle);
    leftLayout->addWidget(sectionLabel);

    leftLayout->addWidget(new QLabel(QStringLiteral("目标"), leftPanel));
    m_targetInput = new QLineEdit(leftPanel);
    m_targetInput->setPlaceholderText(QStringLiteral("例: 192.168.1.0/24"));
    leftLayout->addWidget(m_targetInput);

    leftLayout->addWidget(new QLabel(QStringLiteral("扫描类型"), leftPanel));
    m_scanTypeCombo = new QComboBox(leftPanel);
    m_scanTypeCombo->addItem(QStringLiteral("端口扫描"), QStringLiteral("port_scan"));
    m_scanTypeCombo->addItem(QStringLiteral("漏洞扫描"), QStringLiteral("vuln_scan"));
    m_scanTypeCombo->addItem(QStringLiteral("Web扫描"), QStringLiteral("web_scan"));
    leftLayout->addWidget(m_scanTypeCombo);

    m_createScanBtn = new QPushButton(QStringLiteral("创建扫描"), leftPanel);
    m_createScanBtn->setProperty("primary", true);
    leftLayout->addWidget(m_createScanBtn);
    connect(m_createScanBtn, &QPushButton::clicked, this, [this]() {
        QString target = m_targetInput->text().trimmed();
        if (target.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("提示"), QStringLiteral("请输入扫描目标。"));
            return;
        }
        QJsonObject body;
        body[QStringLiteral("target")] = target;
        body[QStringLiteral("scan_type")] = m_scanTypeCombo->currentData().toString();
        m_createScanBtn->setEnabled(false);
        m_api->post(QStringLiteral("/api/scan-tasks"), body, 10000,
                    [this, target](const QJsonObject &res) {
                        m_createScanBtn->setEnabled(true);
                        if (res[QStringLiteral("status")].toString() == QStringLiteral("ok")) {
                            m_targetInput->clear();
                            setStatusMessage(QStringLiteral("扫描任务创建成功。"), successStatusStyle());

                            // Persist recent record
                            TopologyScanRecord record;
                            record.scanTaskId = res[QStringLiteral("data")].toObject()[QStringLiteral("scan_task_id")].toString();
                            record.target = target;
                            record.createdAt = QDateTime::currentDateTime().toString(Qt::ISODate);
                            if (!record.scanTaskId.isEmpty()) {
                                upsertRecentRecord(record);
                                saveRecentRecords();
                            }

                            onRefreshScans();
                        } else {
                            setStatusMessage(QStringLiteral("创建扫描失败：%1")
                                                 .arg(res[QStringLiteral("error")].toObject()[QStringLiteral("message")].toString()),
                                             errorStatusStyle());
                        }
                    });
    });

    auto *taskLabel = new QLabel(QStringLiteral("扫描任务"), leftPanel);
    QFont taskFont = taskLabel->font();
    taskFont.setBold(true);
    taskLabel->setFont(taskFont);
    leftLayout->addWidget(taskLabel);

    m_scanTaskTable = new QTableWidget(0, 4, leftPanel);
    m_scanTaskTable->setHorizontalHeaderLabels({QStringLiteral("任务ID"),
                                                  QStringLiteral("目标"),
                                                  QStringLiteral("类型"),
                                                  QStringLiteral("状态")});
    m_scanTaskTable->setAlternatingRowColors(true);
    m_scanTaskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_scanTaskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_scanTaskTable->setMinimumHeight(120);
    m_scanTaskTable->horizontalHeader()->setStretchLastSection(true);
    leftLayout->addWidget(m_scanTaskTable);
    connect(m_scanTaskTable, &QTableWidget::cellClicked,
            this, &TopologyPage::onScanClicked);

    m_generateBtn = new QPushButton(QStringLiteral("生成拓扑"), leftPanel);
    m_generateBtn->setProperty("primary", true);
    m_generateBtn->setEnabled(false);
    leftLayout->addWidget(m_generateBtn);
    connect(m_generateBtn, &QPushButton::clicked,
            this, &TopologyPage::onGenerateTopology);

    // ── Recent records list ───────────────────────────────────────────
    auto *recentLabel = new QLabel(QStringLiteral("最近探测记录"), leftPanel);
    recentLabel->setFont(taskFont);
    leftLayout->addWidget(recentLabel);

    m_recentListWidget = new QListWidget(leftPanel);
    m_recentListWidget->setMinimumHeight(80);
    m_recentListWidget->setMaximumHeight(160);
    leftLayout->addWidget(m_recentListWidget);

    m_removeRecordButton = new QPushButton(QStringLiteral("移除选中记录"), leftPanel);
    m_removeRecordButton->setProperty("danger", true);
    m_removeRecordButton->setEnabled(false);
    leftLayout->addWidget(m_removeRecordButton);
    connect(m_removeRecordButton, &QPushButton::clicked,
            this, &TopologyPage::onRemoveSelectedRecord);
    connect(m_recentListWidget, &QListWidget::itemSelectionChanged, this, [this]() {
        m_removeRecordButton->setEnabled(m_recentListWidget->currentItem() != nullptr);
    });

    leftLayout->addStretch();

    // ── Center Panel ──────────────────────────────────────────────────
    auto *centerCard = new QFrame(splitter);
    centerCard->setProperty("card", true);
    auto *centerLayout = new QVBoxLayout(centerCard);
    centerLayout->setContentsMargins(16, 14, 16, 16);
    centerLayout->setSpacing(10);

    auto *canvasHeader = new QHBoxLayout();
    auto *canvasTextLayout = new QVBoxLayout();
    canvasTextLayout->setSpacing(4);
    m_canvasTitleLabel = new QLabel(QStringLiteral("等待拓扑文件"), centerCard);
    QFont canvasTitleFont = m_canvasTitleLabel->font();
    canvasTitleFont.setPointSize(14);
    canvasTitleFont.setBold(true);
    m_canvasTitleLabel->setFont(canvasTitleFont);
    m_canvasSubtitleLabel = new QLabel(
        QStringLiteral("支持缩放、拖动、编辑节点与连接信息。"), centerCard);
    m_canvasSubtitleLabel->setWordWrap(true);
    m_canvasSubtitleLabel->setStyleSheet(QStringLiteral("color:#475569;"));
    canvasTextLayout->addWidget(m_canvasTitleLabel);
    canvasTextLayout->addWidget(m_canvasSubtitleLabel);

    auto *canvasActionRow = new QHBoxLayout();
    canvasActionRow->setSpacing(6);
    auto *zoomOutButton = new QPushButton(QStringLiteral("缩小"), centerCard);
    auto *resetViewButton = new QPushButton(QStringLiteral("重置视图"), centerCard);
    auto *zoomInButton = new QPushButton(QStringLiteral("放大"), centerCard);
    m_addNodeButton = new QPushButton(QStringLiteral("添加主机"), centerCard);
    m_addEdgeButton = new QPushButton(QStringLiteral("添加连线"), centerCard);
    m_saveTopologyButton = new QPushButton(QStringLiteral("保存"), centerCard);
    m_saveTopologyButton->setProperty("primary", true);
    canvasActionRow->addWidget(zoomOutButton);
    canvasActionRow->addWidget(resetViewButton);
    canvasActionRow->addWidget(zoomInButton);
    canvasActionRow->addWidget(m_addNodeButton);
    canvasActionRow->addWidget(m_addEdgeButton);
    canvasActionRow->addWidget(m_saveTopologyButton);

    canvasHeader->addLayout(canvasTextLayout, 1);
    canvasHeader->addLayout(canvasActionRow);

    m_statusLabel = new QLabel(QStringLiteral("准备就绪。"), centerCard);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(infoStatusStyle());

    // ── Summary / Stats / Scope labels ────────────────────────────────
    m_summaryLabel = new QLabel(QStringLiteral("当前拓扑文件：--"), centerCard);
    m_summaryLabel->setWordWrap(true);
    m_statsLabel = new QLabel(QStringLiteral("节点 -- | 连线 --"), centerCard);
    m_scopeLabel = new QLabel(QStringLiteral("当前未绑定探测记录。"), centerCard);
    m_scopeLabel->setStyleSheet(QStringLiteral("color:#475569;"));

    m_graphScene = new QGraphicsScene(centerCard);
    m_graphView = new TopologyGraphicsView(centerCard);
    m_graphView->setScene(m_graphScene);
    m_graphView->setRenderHint(QPainter::Antialiasing, true);
    m_graphView->setDragMode(QGraphicsView::ScrollHandDrag);
    m_graphView->setBackgroundBrush(QColor(QStringLiteral("#08121a")));
    m_graphView->setMinimumHeight(600);
    m_graphView->setViewportUpdateMode(QGraphicsView::SmartViewportUpdate);

    centerLayout->addLayout(canvasHeader);
    centerLayout->addWidget(m_statusLabel);
    centerLayout->addWidget(m_summaryLabel);
    centerLayout->addWidget(m_statsLabel);
    centerLayout->addWidget(m_scopeLabel);
    centerLayout->addWidget(m_graphView, 1);

    // ── Right Panel ───────────────────────────────────────────────────
    auto *rightPanel = new QFrame(splitter);
    rightPanel->setProperty("card", true);
    rightPanel->setMaximumWidth(300);
    auto *rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(14, 12, 14, 14);
    rightLayout->setSpacing(8);

    auto *nodeListTitle = new QLabel(QStringLiteral("节点列表"), rightPanel);
    nodeListTitle->setStyleSheet(Theme::SectionStyle);
    rightLayout->addWidget(nodeListTitle);
    m_nodeListWidget = new QListWidget(rightPanel);
    m_nodeListWidget->setMinimumHeight(100);
    rightLayout->addWidget(m_nodeListWidget);

    auto *edgeListTitle = new QLabel(QStringLiteral("连接列表"), rightPanel);
    edgeListTitle->setStyleSheet(Theme::SectionStyle);
    rightLayout->addWidget(edgeListTitle);
    m_edgeListWidget = new QListWidget(rightPanel);
    m_edgeListWidget->setMinimumHeight(80);
    rightLayout->addWidget(m_edgeListWidget);

    auto *listActionRow = new QHBoxLayout();
    listActionRow->setSpacing(6);
    m_deleteNodeButton = new QPushButton(QStringLiteral("删除节点"), rightPanel);
    m_deleteNodeButton->setProperty("danger", true);
    m_deleteEdgeButton = new QPushButton(QStringLiteral("删除连线"), rightPanel);
    m_deleteEdgeButton->setProperty("danger", true);
    listActionRow->addWidget(m_deleteNodeButton);
    listActionRow->addWidget(m_deleteEdgeButton);
    rightLayout->addLayout(listActionRow);

    auto *detailTitle = new QLabel(QStringLiteral("详细信息"), rightPanel);
    detailTitle->setStyleSheet(Theme::SectionStyle);
    rightLayout->addWidget(detailTitle);

    m_detailHintLabel = new QLabel(
        QStringLiteral("选择节点或连接后，可在这里编辑信息。"), rightPanel);
    m_detailHintLabel->setWordWrap(true);
    m_detailHintLabel->setStyleSheet(QStringLiteral("color:#475569;"));
    rightLayout->addWidget(m_detailHintLabel);

    m_detailStack = new QStackedWidget(rightPanel);

    // Overview page (index 0)
    auto *overviewPage = new QWidget(m_detailStack);
    auto *overviewLayout = new QVBoxLayout(overviewPage);
    overviewLayout->setContentsMargins(0, 6, 0, 6);
    overviewLayout->addWidget(
        new QLabel(QStringLiteral("请选择一个节点或连接进行编辑。"), overviewPage));
    overviewLayout->addStretch();

    // Node detail page (index 1)
    auto *nodeFormPage = new QWidget(m_detailStack);
    auto *nodeFormLayout = new QFormLayout(nodeFormPage);
    nodeFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    nodeFormLayout->setFormAlignment(Qt::AlignTop);
    nodeFormLayout->setHorizontalSpacing(8);
    nodeFormLayout->setVerticalSpacing(4);
    m_nodeNameEdit = new QLineEdit(nodeFormPage);
    m_nodeIpEdit = new QLineEdit(nodeFormPage);
    m_nodeHostNameEdit = new QLineEdit(nodeFormPage);
    m_nodeOsEdit = new QLineEdit(nodeFormPage);
    m_nodeTypeEdit = new QLineEdit(nodeFormPage);
    m_nodeVendorEdit = new QLineEdit(nodeFormPage);
    m_nodeStatusCombo = new QComboBox(nodeFormPage);
    m_nodeStatusCombo->addItem(QStringLiteral("在线"), QStringLiteral("up"));
    m_nodeStatusCombo->addItem(QStringLiteral("告警"), QStringLiteral("warning"));
    m_nodeStatusCombo->addItem(QStringLiteral("离线"), QStringLiteral("down"));
    m_nodeStatusCombo->addItem(QStringLiteral("未知"), QStringLiteral("unknown"));
    m_nodeNoteEdit = new QPlainTextEdit(nodeFormPage);
    m_nodeNoteEdit->setMinimumHeight(48);
    m_nodeNoteEdit->setMaximumHeight(80);
    m_servicesEdit = new QPlainTextEdit(nodeFormPage);
    m_servicesEdit->setMinimumHeight(72);
    m_servicesEdit->setMaximumHeight(100);
    m_servicesEdit->setPlaceholderText(
        QStringLiteral("每行一个服务：port|protocol|service|product|version|state|note"));
    nodeFormLayout->addRow(QStringLiteral("名称"), m_nodeNameEdit);
    nodeFormLayout->addRow(QStringLiteral("IP"), m_nodeIpEdit);
    nodeFormLayout->addRow(QStringLiteral("主机名"), m_nodeHostNameEdit);
    nodeFormLayout->addRow(QStringLiteral("系统"), m_nodeOsEdit);
    nodeFormLayout->addRow(QStringLiteral("设备类型"), m_nodeTypeEdit);
    nodeFormLayout->addRow(QStringLiteral("厂商"), m_nodeVendorEdit);
    nodeFormLayout->addRow(QStringLiteral("状态"), m_nodeStatusCombo);
    nodeFormLayout->addRow(QStringLiteral("备注"), m_nodeNoteEdit);
    nodeFormLayout->addRow(QStringLiteral("服务"), m_servicesEdit);

    // Edge detail page (index 2)
    auto *edgeFormPage = new QWidget(m_detailStack);
    auto *edgeFormLayout = new QFormLayout(edgeFormPage);
    edgeFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    edgeFormLayout->setFormAlignment(Qt::AlignTop);
    edgeFormLayout->setHorizontalSpacing(8);
    edgeFormLayout->setVerticalSpacing(4);
    m_edgeSourceCombo = new QComboBox(edgeFormPage);
    m_edgeTargetCombo = new QComboBox(edgeFormPage);
    m_edgeLabelEdit = new QLineEdit(edgeFormPage);
    m_edgeTypeCombo = new QComboBox(edgeFormPage);
    m_edgeTypeCombo->setEditable(true);
    m_edgeTypeCombo->addItem(QStringLiteral("连接"), QStringLiteral("connection"));
    m_edgeTypeCombo->addItem(QStringLiteral("网关"), QStringLiteral("gateway"));
    m_edgeTypeCombo->addItem(QStringLiteral("路由"), QStringLiteral("route"));
    m_edgeTypeCombo->addItem(QStringLiteral("上行链路"), QStringLiteral("uplink"));
    m_edgeTypeCombo->addItem(QStringLiteral("主干"), QStringLiteral("trunk"));
    m_edgeNoteEdit = new QPlainTextEdit(edgeFormPage);
    m_edgeNoteEdit->setMinimumHeight(72);
    m_edgeNoteEdit->setMaximumHeight(100);
    edgeFormLayout->addRow(QStringLiteral("源节点"), m_edgeSourceCombo);
    edgeFormLayout->addRow(QStringLiteral("目标节点"), m_edgeTargetCombo);
    edgeFormLayout->addRow(QStringLiteral("标签"), m_edgeLabelEdit);
    edgeFormLayout->addRow(QStringLiteral("类型"), m_edgeTypeCombo);
    edgeFormLayout->addRow(QStringLiteral("说明"), m_edgeNoteEdit);

    m_detailStack->addWidget(overviewPage);   // 0
    m_detailStack->addWidget(nodeFormPage);    // 1
    m_detailStack->addWidget(edgeFormPage);    // 2

    rightLayout->addWidget(m_detailStack, 1);

    m_applyDetailButton = new QPushButton(QStringLiteral("应用"), rightPanel);
    m_applyDetailButton->setObjectName(QStringLiteral("applyBtn"));
    rightLayout->addWidget(m_applyDetailButton);
    connect(m_applyDetailButton, &QPushButton::clicked,
            this, &TopologyPage::onApplyDetailEdits);

    // ── Assemble page layout ──────────────────────────────────────────
    pageLayout->addWidget(heroCard);
    pageLayout->addWidget(splitter, 1);

    // ── Assemble splitter ─────────────────────────────────────────────
    splitter->addWidget(leftPanel);
    splitter->addWidget(centerCard);
    splitter->addWidget(rightPanel);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 7);
    splitter->setStretchFactor(2, 3);
    splitter->setSizes({300, 700, 280});

    scrollArea->setWidget(page);
    rootLayout->addWidget(scrollArea, 1);

    // ── Connect signals ───────────────────────────────────────────────
    connect(m_refreshBtn, &QPushButton::clicked,
            this, &TopologyPage::onRefreshScans);
    connect(m_nodeListWidget, &QListWidget::itemSelectionChanged,
            this, &TopologyPage::onSceneSelectionChanged);
    connect(m_edgeListWidget, &QListWidget::itemSelectionChanged,
            this, &TopologyPage::onSceneSelectionChanged);
    connect(m_graphScene, &QGraphicsScene::selectionChanged,
            this, &TopologyPage::onSceneSelectionChanged);

    connect(zoomInButton, &QPushButton::clicked,
            this, &TopologyPage::onZoomIn);
    connect(zoomOutButton, &QPushButton::clicked,
            this, &TopologyPage::onZoomOut);
    connect(resetViewButton, &QPushButton::clicked,
            this, &TopologyPage::onResetView);
    connect(m_addNodeButton, &QPushButton::clicked,
            this, &TopologyPage::onAddHostNode);
    connect(m_addEdgeButton, &QPushButton::clicked,
            this, &TopologyPage::onAddEdge);
    connect(m_deleteNodeButton, &QPushButton::clicked,
            this, &TopologyPage::onRemoveSelectedNode);
    connect(m_deleteEdgeButton, &QPushButton::clicked,
            this, &TopologyPage::onRemoveSelectedEdge);
    connect(m_saveTopologyButton, &QPushButton::clicked,
            this, &TopologyPage::onSaveTopology);

    auto markEditorDirty = [this]() {
        if (!m_syncingSelection) {
            m_editorDirty = true;
            updateEditorState();
        }
    };
    connect(m_nodeNameEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_nodeIpEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_nodeHostNameEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_nodeOsEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_nodeTypeEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_nodeVendorEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_nodeStatusCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, markEditorDirty);
    connect(m_nodeNoteEdit, &QPlainTextEdit::textChanged, this, markEditorDirty);
    connect(m_servicesEdit, &QPlainTextEdit::textChanged, this, markEditorDirty);
    connect(m_edgeSourceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, markEditorDirty);
    connect(m_edgeTargetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, markEditorDirty);
    connect(m_edgeLabelEdit, &QLineEdit::textChanged, this, markEditorDirty);
    connect(m_edgeTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, markEditorDirty);
    if (m_edgeTypeCombo->lineEdit()) {
        connect(m_edgeTypeCombo->lineEdit(), &QLineEdit::textChanged,
                this, markEditorDirty);
    }
    connect(m_edgeNoteEdit, &QPlainTextEdit::textChanged, this, markEditorDirty);

    // Initial state
    m_addNodeButton->setEnabled(false);
    m_addEdgeButton->setEnabled(false);
    m_deleteNodeButton->setEnabled(false);
    m_deleteEdgeButton->setEnabled(false);
    m_saveTopologyButton->setEnabled(false);
    m_applyDetailButton->setEnabled(false);
    m_detailStack->setCurrentIndex(0);
}

// ── Recent Records Persistence ────────────────────────────────────────────

QString TopologyPage::recentRecordsPath() const {
    return topologyDataDir() + QStringLiteral("/topology_recent.json");
}

void TopologyPage::loadRecentRecords() {
    m_recentRecords.clear();
    QFile file(recentRecordsPath());
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isArray()) {
        return;
    }
    const QJsonArray array = document.array();
    for (const QJsonValue &value : array) {
        const QJsonObject object = value.toObject();
        TopologyScanRecord record;
        record.scanTaskId = object.value(QStringLiteral("scanTaskId")).toString();
        record.target = object.value(QStringLiteral("target")).toString();
        record.createdAt = object.value(QStringLiteral("createdAt")).toString();
        if (!record.scanTaskId.isEmpty() && !record.target.isEmpty()) {
            m_recentRecords.append(record);
        }
    }
}

void TopologyPage::saveRecentRecords() const {
    const QString path = recentRecordsPath();
    const QFileInfo info(path);
    QDir().mkpath(info.dir().absolutePath());
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }
    QJsonArray array;
    for (const TopologyScanRecord &record : m_recentRecords) {
        array.append(QJsonObject{
            {QStringLiteral("scanTaskId"), record.scanTaskId},
            {QStringLiteral("target"), record.target},
            {QStringLiteral("createdAt"), record.createdAt},
        });
    }
    file.write(QJsonDocument(array).toJson(QJsonDocument::Indented));
}

void TopologyPage::upsertRecentRecord(const TopologyScanRecord &record) {
    for (int i = 0; i < m_recentRecords.size(); ++i) {
        if (m_recentRecords.at(i).scanTaskId == record.scanTaskId) {
            m_recentRecords[i] = record;
            populateRecentRecords();
            return;
        }
    }
    m_recentRecords.prepend(record);
    if (m_recentRecords.size() > 8) {
        m_recentRecords.removeLast();
    }
    populateRecentRecords();
}

void TopologyPage::populateRecentRecords() {
    m_recentListWidget->clear();
    for (const TopologyScanRecord &record : m_recentRecords) {
        const QString text = QStringLiteral("目标：%1\n扫描：%2 | 时间：%3")
                                 .arg(record.target)
                                 .arg(record.scanTaskId)
                                 .arg(record.createdAt);
        auto *item = new QListWidgetItem(text, m_recentListWidget);
        item->setData(Qt::UserRole, record.scanTaskId);
        item->setSizeHint(QSize(0, 48));
    }
}

void TopologyPage::onRemoveSelectedRecord() {
    QListWidgetItem *item = m_recentListWidget->currentItem();
    if (!item) {
        QMessageBox::information(this, QStringLiteral("提示"), QStringLiteral("请先选择一条记录。"));
        return;
    }
    const QString scanTaskId = item->data(Qt::UserRole).toString();
    for (int i = 0; i < m_recentRecords.size(); ++i) {
        if (m_recentRecords.at(i).scanTaskId == scanTaskId) {
            m_recentRecords.removeAt(i);
            break;
        }
    }
    saveRecentRecords();
    populateRecentRecords();
}

// ── Scan Task Management ──────────────────────────────────────────────────

void TopologyPage::onRefreshScans() {
    m_api->get(QStringLiteral("/api/scan-tasks"), 5000,
               [this](const QJsonObject &res) {
                   if (res[QStringLiteral("status")].toString() != QStringLiteral("ok")) {
                       setStatusMessage(QStringLiteral("获取扫描列表失败。"), errorStatusStyle());
                       return;
                   }
                   auto arr = res[QStringLiteral("data")].toArray();
                   m_scanTaskTable->setRowCount(arr.size());
                   for (int i = 0; i < arr.size(); ++i) {
                       auto t = arr[i].toObject();
                       m_scanTaskTable->setItem(
                           i, 0,
                           new QTableWidgetItem(t[QStringLiteral("scan_task_id")].toString()));
                       m_scanTaskTable->setItem(
                           i, 1,
                           new QTableWidgetItem(t[QStringLiteral("target")].toString()));
                       m_scanTaskTable->setItem(
                           i, 2,
                           new QTableWidgetItem([&]() {
                               QString st = t[QStringLiteral("scan_type")].toString();
                               if (st == QStringLiteral("port_scan")) return QStringLiteral("端口扫描");
                               if (st == QStringLiteral("vuln_scan")) return QStringLiteral("漏洞扫描");
                               if (st == QStringLiteral("web_scan")) return QStringLiteral("Web扫描");
                               if (st == QStringLiteral("brute_force")) return QStringLiteral("暴力破解");
                               return st;
                           }()));
                       QString statusText = scanStatusLabel(t[QStringLiteral("status")].toString());
                       m_scanTaskTable->setItem(
                           i, 3,
                           new QTableWidgetItem(statusText));
                   }
                   m_scanTaskTable->resizeColumnsToContents();

                   // Update hero stat
                   if (m_currentStatusValueLabel) {
                       m_currentStatusValueLabel->setText(QStringLiteral("%1 条扫描").arg(arr.size()));
                   }

                   setStatusMessage(QStringLiteral("已刷新扫描任务列表，共 %1 条。").arg(arr.size()),
                                    successStatusStyle());
               });
}

void TopologyPage::onScanClicked(int row, int col) {
    Q_UNUSED(col);
    auto idItem = m_scanTaskTable->item(row, 0);
    if (!idItem) {
        return;
    }
    m_selectedScanTaskId = idItem->text();

    // Get target from the table for hero stat
    auto targetItem = m_scanTaskTable->item(row, 1);
    if (m_currentTargetValueLabel && targetItem) {
        m_currentTargetValueLabel->setText(targetItem->text());
    }

    // Check status column for COMPLETED
    auto statusColItem = m_scanTaskTable->item(row, 3);
    if (statusColItem && statusColItem->text() == QStringLiteral("已完成")) {
        m_generateBtn->setEnabled(true);
        if (m_currentStatusValueLabel) {
            m_currentStatusValueLabel->setText(QStringLiteral("已完成"));
        }
        if (m_currentProgressValueLabel) {
            m_currentProgressValueLabel->setText(QStringLiteral("100%"));
        }
        setStatusMessage(QStringLiteral("已选中完成扫描：%1，可点击\"生成拓扑\"。").arg(m_selectedScanTaskId),
                         infoStatusStyle());
    } else {
        m_generateBtn->setEnabled(false);
        if (m_currentStatusValueLabel && statusColItem) {
            m_currentStatusValueLabel->setText(statusColItem->text());
        }
        if (m_currentProgressValueLabel) {
            m_currentProgressValueLabel->setText(QStringLiteral("--"));
        }
        setStatusMessage(QStringLiteral("当前扫描状态为 %1，需要已完成状态才能生成拓扑。")
                             .arg(statusColItem ? statusColItem->text() : QStringLiteral("--")),
                         infoStatusStyle());
    }
}

void TopologyPage::onGenerateTopology() {
    if (m_selectedScanTaskId.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("请先选择一个已完成的扫描任务。"));
        return;
    }

    // ── Progress dialog (heap-allocated, safe for async callback) ────
    if (m_progressDialog) {
        delete m_progressDialog;
    }
    m_progressDialog = new QProgressDialog(QStringLiteral("正在通过 AI 生成拓扑结构..."),
                                            QString(), 0, 0, this);
    m_progressDialog->setWindowTitle(QStringLiteral("生成拓扑"));
    m_progressDialog->setWindowModality(Qt::WindowModal);
    m_progressDialog->setMinimumDuration(0);
    m_progressDialog->setAutoClose(false);
    m_progressDialog->setAutoReset(false);
    m_progressDialog->show();

    m_generateBtn->setEnabled(false);
    m_generateBtn->setText(QStringLiteral("生成中..."));
    qApp->setOverrideCursor(Qt::WaitCursor);
    setStatusMessage(QStringLiteral("正在通过 AI 生成拓扑结构，请稍候..."), infoStatusStyle());

    if (m_currentStatusValueLabel) {
        m_currentStatusValueLabel->setText(QStringLiteral("生成中"));
    }
    if (m_currentProgressValueLabel) {
        m_currentProgressValueLabel->setText(QStringLiteral("..."));
    }

    QJsonObject body;
    body[QStringLiteral("scan_task_id")] = m_selectedScanTaskId;

    m_api->post(QStringLiteral("/api/topology/generate-from-scan"), body, 120000,
                [this](const QJsonObject &res) {
                    // Close and clean up progress dialog
                    if (m_progressDialog) {
                        m_progressDialog->close();
                        delete m_progressDialog;
                        m_progressDialog = nullptr;
                    }
                    m_generateBtn->setEnabled(true);
                    m_generateBtn->setText(QStringLiteral("生成拓扑"));
                    qApp->restoreOverrideCursor();

                    if (res[QStringLiteral("status")].toString() != QStringLiteral("ok")) {
                        QString errMsg = res[QStringLiteral("error")].toObject()[QStringLiteral("message")].toString();
                        setStatusMessage(QStringLiteral("拓扑生成失败：%1").arg(errMsg),
                                         errorStatusStyle());
                        if (m_currentStatusValueLabel) {
                            m_currentStatusValueLabel->setText(QStringLiteral("失败"));
                        }
                        QMessageBox::warning(this, QStringLiteral("生成失败"), errMsg);
                        return;
                    }

                    // Parse the topology from response
                    auto topoObj =
                        res[QStringLiteral("data")].toObject()[QStringLiteral("topology")].toObject();
                    TopologyDocument doc = TopologyDocument::fromJsonObject(topoObj);

                    // Fill in metadata
                    doc.flowId = m_selectedScanTaskId;
                    if (doc.generatedAt.trimmed().isEmpty()) {
                        doc.generatedAt = QDateTime::currentDateTime().toString(Qt::ISODate);
                    }

                    // Ensure unique IDs and positions
                    QSet<QString> usedNodeIds;
                    for (int i = 0; i < doc.nodes.size(); ++i) {
                        auto &node = doc.nodes[i];
                        node.id = ensureUniqueId(
                            node.id.trimmed().isEmpty()
                                ? QStringLiteral("host-%1").arg(i + 1)
                                : node.id,
                            usedNodeIds, QStringLiteral("host"));
                        usedNodeIds.insert(node.id);
                        if (node.displayName.trimmed().isEmpty()) {
                            node.displayName = defaultNodeTitle(node);
                        }
                        if (qFuzzyIsNull(node.x) && qFuzzyIsNull(node.y)) {
                            const double angle = (2.0 * M_PI * i) / qMax(1, doc.nodes.size());
                            node.x = qCos(angle) * 220.0;
                            node.y = qSin(angle) * 220.0;
                        }
                        if (node.status.trimmed().isEmpty()) {
                            node.status = QStringLiteral("unknown");
                        }
                    }

                    QSet<QString> usedEdgeIds;
                    for (int i = 0; i < doc.edges.size(); ++i) {
                        auto &edge = doc.edges[i];
                        edge.id = ensureUniqueId(
                            edge.id.trimmed().isEmpty()
                                ? QStringLiteral("edge-%1").arg(i + 1)
                                : edge.id,
                            usedEdgeIds, QStringLiteral("edge"));
                        usedEdgeIds.insert(edge.id);
                        if (edge.sourceId == edge.targetId) {
                            edge.targetId.clear();
                        }
                    }
                    // Remove edges with invalid node references
                    for (int i = doc.edges.size() - 1; i >= 0; --i) {
                        const auto &e = doc.edges.at(i);
                        if (!usedNodeIds.contains(e.sourceId)
                            || !usedNodeIds.contains(e.targetId)) {
                            doc.edges.removeAt(i);
                        }
                    }

                    // Set the document and populate
                    m_topologyDocument = doc;
                    m_loadedTopologyPath.clear();
                    m_selectedNodeId.clear();
                    m_selectedEdgeId.clear();
                    m_documentDirty = true;
                    m_editorDirty = false;
                    populateTopologyDocument();

                    // Update hero stats
                    if (m_currentStatusValueLabel) {
                        m_currentStatusValueLabel->setText(QStringLiteral("已完成"));
                    }
                    if (m_currentProgressValueLabel) {
                        m_currentProgressValueLabel->setText(QStringLiteral("100%"));
                    }
                    if (m_lastGeneratedValueLabel) {
                        m_lastGeneratedValueLabel->setText(doc.generatedAt);
                    }

                    // Persist recent record
                    TopologyScanRecord record;
                    record.scanTaskId = m_selectedScanTaskId;
                    record.target = m_currentTargetValueLabel ? m_currentTargetValueLabel->text() : QString();
                    record.createdAt = QDateTime::currentDateTime().toString(Qt::ISODate);
                    upsertRecentRecord(record);
                    saveRecentRecords();

                    setStatusMessage(
                        QStringLiteral("拓扑生成成功：%1 个节点，%2 条连线。")
                            .arg(doc.nodes.size())
                            .arg(doc.edges.size()),
                        successStatusStyle());
                });
}

// ── Save Topology ─────────────────────────────────────────────────────────

void TopologyPage::onSaveTopology() {
    applyPendingEditorChanges();
    QString errorMessage;
    if (!saveTopologyDocument(&errorMessage)) {
        QMessageBox::warning(this, QStringLiteral("保存失败"), errorMessage);
        return;
    }
    if (m_loadedTopologyPath.isEmpty()) {
        m_loadedTopologyPath = defaultTopologyDocumentPath();
        if (m_currentSourceValueLabel) {
            m_currentSourceValueLabel->setText(QFileInfo(m_loadedTopologyPath).fileName());
        }
    }
    m_documentDirty = false;
    m_editorDirty = false;
    populateTopologyDocument();
    updateEditorState();
    setStatusMessage(QStringLiteral("拓扑文件已保存。"), successStatusStyle());
}

// ── Document Population ──────────────────────────────────────────────────

void TopologyPage::populateTopologyDocument() {
    if (m_topologyDocument.generatedAt.trimmed().isEmpty()) {
        m_topologyDocument.generatedAt = QDateTime::currentDateTime().toString(Qt::ISODate);
    }
    m_canvasTitleLabel->setText(
        m_topologyDocument.summary.isEmpty()
            ? QStringLiteral("局域网网络拓扑")
            : m_topologyDocument.summary);
    const QString dirtySuffix = m_documentDirty
        ? QStringLiteral("当前有未保存修改。")
        : QStringLiteral("当前拓扑已与本地文件同步。");
    m_canvasSubtitleLabel->setText(
        QStringLiteral("节点 %1 个，连线 %2 条。可直接拖动主机位置，并在下方编辑信息。%3")
            .arg(m_topologyDocument.nodes.size())
            .arg(m_topologyDocument.edges.size())
            .arg(dirtySuffix));

    // Update summary / stats / scope labels
    if (m_summaryLabel) {
        m_summaryLabel->setText(QStringLiteral("当前拓扑文件：%1")
            .arg(m_loadedTopologyPath.isEmpty() ? defaultTopologyDocumentPath() : m_loadedTopologyPath));
    }
    if (m_statsLabel) {
        int serviceCount = 0;
        for (const TopologyNodeRecord &node : m_topologyDocument.nodes) {
            serviceCount += node.services.size();
        }
        m_statsLabel->setText(QStringLiteral("节点 %1 | 连线 %2 | 服务 %3")
            .arg(m_topologyDocument.nodes.size())
            .arg(m_topologyDocument.edges.size())
            .arg(serviceCount));
    }
    if (m_scopeLabel) {
        m_scopeLabel->setText(QStringLiteral("目标：%1 | 扫描：%2 | 生成时间：%3")
            .arg(m_topologyDocument.target.isEmpty() ? QStringLiteral("--") : m_topologyDocument.target)
            .arg(m_topologyDocument.flowId.isEmpty() ? QStringLiteral("--") : m_topologyDocument.flowId)
            .arg(m_topologyDocument.generatedAt.isEmpty() ? QStringLiteral("--") : m_topologyDocument.generatedAt));
    }
    if (m_currentSourceValueLabel) {
        m_currentSourceValueLabel->setText(m_loadedTopologyPath.isEmpty()
            ? QStringLiteral("--")
            : QFileInfo(m_loadedTopologyPath).fileName());
    }
    if (m_lastGeneratedValueLabel) {
        m_lastGeneratedValueLabel->setText(m_topologyDocument.generatedAt.isEmpty()
            ? QStringLiteral("--")
            : m_topologyDocument.generatedAt);
    }

    populateNodeList();
    populateEdgeList();
    refreshEdgeNodeOptions();
    renderTopologyScene();
    if (!m_documentDirty && m_selectedNodeId.isEmpty() && m_selectedEdgeId.isEmpty()) {
        onResetView();
    }
    if (!m_selectedNodeId.isEmpty() && currentSelectedNode()) {
        showNodeDetail(*currentSelectedNode());
    } else if (!m_selectedEdgeId.isEmpty() && currentSelectedEdge()) {
        showEdgeDetail(*currentSelectedEdge());
    } else {
        showOverviewDetail();
    }
    updateEditorState();
}

void TopologyPage::populateDocumentPlaceholder(const QString &title,
                                                const QString &detail) {
    m_topologyDocument = {};
    m_loadedTopologyPath.clear();
    m_selectedNodeId.clear();
    m_selectedEdgeId.clear();
    m_documentDirty = false;
    m_editorDirty = false;
    m_canvasTitleLabel->setText(title);
    m_canvasSubtitleLabel->setText(detail);

    if (m_summaryLabel) m_summaryLabel->setText(QStringLiteral("当前拓扑文件：--"));
    if (m_statsLabel) m_statsLabel->setText(QStringLiteral("节点 -- | 连线 --"));
    if (m_scopeLabel) m_scopeLabel->setText(QStringLiteral("当前未加载任何拓扑文件。"));
    if (m_currentSourceValueLabel) m_currentSourceValueLabel->setText(QStringLiteral("--"));

    m_graphScene->clear();
    m_nodeItems.clear();
    m_edgeItems.clear();
    m_nodeListWidget->clear();
    m_edgeListWidget->clear();
    showOverviewDetail();
    updateEditorState();
}

// ── Render Topology Scene ────────────────────────────────────────────────

void TopologyPage::renderTopologyScene() {
    m_graphScene->clear();
    m_nodeItems.clear();
    m_edgeItems.clear();

    if (m_topologyDocument.nodes.isEmpty()) {
        m_graphScene->addText(QStringLiteral("当前没有可视化主机节点。"));
        return;
    }

    QMap<QString, QPointF> positions;
    bool hasCustomPosition = false;
    for (const TopologyNodeRecord &node : m_topologyDocument.nodes) {
        if (!qFuzzyIsNull(node.x) || !qFuzzyIsNull(node.y)) {
            hasCustomPosition = true;
            break;
        }
    }

    if (hasCustomPosition) {
        for (const TopologyNodeRecord &node : m_topologyDocument.nodes) {
            positions.insert(node.id, QPointF(node.x, node.y));
        }
    } else {
        const int total = m_topologyDocument.nodes.size();
        const double radius = total <= 10 ? 180.0 : 240.0;
        for (int i = 0; i < total; ++i) {
            const double angle = (2.0 * M_PI * i) / qMax(1, total);
            positions.insert(m_topologyDocument.nodes.at(i).id,
                             QPointF(qCos(angle) * radius, qSin(angle) * radius));
        }
    }

    // Draw edges first (below nodes)
    for (const TopologyEdgeRecord &edge : m_topologyDocument.edges) {
        if (!positions.contains(edge.sourceId) || !positions.contains(edge.targetId)) {
            continue;
        }
        const QPointF source = positions.value(edge.sourceId);
        const QPointF target = positions.value(edge.targetId);
        auto *line = new TopologyEdgeItem(edge.id, QLineF(source, target));
        const bool selected = edge.id == m_selectedEdgeId;
        line->setPen(QPen(QColor(selected ? QStringLiteral("#e2e8f0") : edgeColor(edge.type)),
                          selected ? 3.2 : 2.2,
                          Qt::SolidLine,
                          Qt::RoundCap));
        line->setToolTip(QStringLiteral("%1\n%2 -> %3\n%4")
                             .arg(fallbackEdgeLabel(edge))
                             .arg(edge.sourceId)
                             .arg(edge.targetId)
                             .arg(edge.note));
        m_graphScene->addItem(line);
        m_edgeItems.insert(edge.id, line);

        auto *edgeText = m_graphScene->addSimpleText(fallbackEdgeLabel(edge));
        edgeText->setBrush(QColor(selected ? QStringLiteral("#f8fafc") : QStringLiteral("#cbd5e1")));
        edgeText->setPos((source.x() + target.x()) * 0.5,
                         (source.y() + target.y()) * 0.5);
        edgeText->setZValue(1.2);
    }

    // Draw nodes
    for (TopologyNodeRecord &node : m_topologyDocument.nodes) {
        const QPointF pos = positions.value(node.id);
        node.x = pos.x();
        node.y = pos.y();

        auto *ellipse = new TopologyNodeItem(
            node.id, QRectF(pos.x() - 22.0, pos.y() - 22.0, 44.0, 44.0));
        ellipse->setBrush(QColor(nodeStatusColor(node.status)));
        ellipse->setPen(QPen(QColor(node.id == m_selectedNodeId
                                        ? QStringLiteral("#f8fafc")
                                        : QStringLiteral("#e2e8f0")),
                             node.id == m_selectedNodeId ? 3.0 : 2.0));
        ellipse->setToolTip(topologyNodeTooltip(node));
        ellipse->onMoveFinished = [this](const QString &nodeId, const QPointF &center) {
            for (TopologyNodeRecord &record : m_topologyDocument.nodes) {
                if (record.id == nodeId) {
                    record.x = center.x();
                    record.y = center.y();
                    break;
                }
            }
            markDocumentDirty(QStringLiteral("节点位置已更新，记得保存拓扑文件。"));
            QTimer::singleShot(0, this, [this, nodeId]() {
                renderTopologyScene();
                syncSelectionToNode(nodeId);
            });
        };
        m_graphScene->addItem(ellipse);
        m_nodeItems.insert(node.id, ellipse);

        const QString primaryLabel = topologyNodePrimaryLabel(node);
        const QString secondaryLabel = topologyNodeSecondaryLabel(node, primaryLabel);

        auto *text = m_graphScene->addSimpleText(primaryLabel);
        text->setBrush(QColor(QStringLiteral("#e2e8f0")));
        text->setPos(pos.x() + 28.0,
                     secondaryLabel.isEmpty() ? pos.y() - 8.0 : pos.y() - 14.0);
        text->setToolTip(topologyNodeTooltip(node));

        if (!secondaryLabel.isEmpty()) {
            auto *subText = m_graphScene->addSimpleText(secondaryLabel);
            subText->setBrush(QColor(QStringLiteral("#94a3b8")));
            subText->setPos(pos.x() + 28.0, pos.y() + 4.0);
            subText->setToolTip(topologyNodeTooltip(node));
        }
    }

    m_graphScene->setSceneRect(
        m_graphScene->itemsBoundingRect().adjusted(-60, -60, 60, 60));
}

// ── Node / Edge List Population ──────────────────────────────────────────

void TopologyPage::populateNodeList() {
    const QString currentNodeId =
        m_nodeListWidget->currentItem()
            ? m_nodeListWidget->currentItem()->data(Qt::UserRole).toString()
            : m_selectedNodeId;
    m_nodeListWidget->clear();
    int rowToSelect = -1;
    for (int i = 0; i < m_topologyDocument.nodes.size(); ++i) {
        const TopologyNodeRecord &node = m_topologyDocument.nodes.at(i);
        const QString text = QStringLiteral("%1\nIP：%2 | 服务 %3 | 状态 %4")
                                 .arg(nodeDisplayTitle(node))
                                 .arg(node.ip.isEmpty() ? QStringLiteral("--") : node.ip)
                                 .arg(node.services.size())
                                 .arg(node.status.isEmpty() ? QStringLiteral("--") : nodeStatusLabel(node.status));
        auto *item = new QListWidgetItem(text, m_nodeListWidget);
        item->setData(Qt::UserRole, node.id);
        item->setToolTip(text);
        item->setSizeHint(QSize(0, 54));
        if (node.id == currentNodeId) {
            rowToSelect = i;
        }
    }
    if (rowToSelect >= 0) {
        m_nodeListWidget->setCurrentRow(rowToSelect);
    }
}

void TopologyPage::populateEdgeList() {
    const QString currentEdgeId =
        m_edgeListWidget->currentItem()
            ? m_edgeListWidget->currentItem()->data(Qt::UserRole).toString()
            : m_selectedEdgeId;
    m_edgeListWidget->clear();
    int rowToSelect = -1;
    for (int i = 0; i < m_topologyDocument.edges.size(); ++i) {
        const TopologyEdgeRecord &edge = m_topologyDocument.edges.at(i);
        const QString text = QStringLiteral("%1\n%2 -> %3")
                                 .arg(fallbackEdgeLabel(edge))
                                 .arg(edge.sourceId.isEmpty() ? QStringLiteral("--") : edge.sourceId)
                                 .arg(edge.targetId.isEmpty() ? QStringLiteral("--") : edge.targetId);
        auto *item = new QListWidgetItem(text, m_edgeListWidget);
        item->setData(Qt::UserRole, edge.id);
        item->setToolTip(text);
        item->setSizeHint(QSize(0, 50));
        if (edge.id == currentEdgeId) {
            rowToSelect = i;
        }
    }
    if (rowToSelect >= 0) {
        m_edgeListWidget->setCurrentRow(rowToSelect);
    }
}

// ── Detail Form Display ──────────────────────────────────────────────────

void TopologyPage::showNodeDetail(const TopologyNodeRecord &node) {
    m_syncingSelection = true;
    m_detailStack->setCurrentIndex(1);
    m_nodeNameEdit->setText(node.displayName);
    m_nodeIpEdit->setText(node.ip);
    m_nodeHostNameEdit->setText(node.hostName);
    m_nodeOsEdit->setText(QStringLiteral("%1 %2").arg(node.osName, node.osVersion).trimmed());
    m_nodeTypeEdit->setText(node.deviceType);
    m_nodeVendorEdit->setText(node.vendor);
    const int statusIndex = m_nodeStatusCombo->findData(node.status);
    m_nodeStatusCombo->setCurrentIndex(
        statusIndex >= 0 ? statusIndex : m_nodeStatusCombo->findData(QStringLiteral("unknown")));
    m_nodeNoteEdit->setPlainText(node.note);
    QStringList serviceLines;
    for (const TopologyServiceRecord &service : node.services) {
        serviceLines << QStringLiteral("%1|%2|%3|%4|%5|%6|%7")
                            .arg(service.port, service.protocol, service.service,
                                 service.product, service.version, service.state,
                                 service.note);
    }
    m_servicesEdit->setPlainText(serviceLines.join(QStringLiteral("\n")));
    m_detailHintLabel->setText(QStringLiteral("正在编辑：%1").arg(nodeDisplayTitle(node)));
    m_editorDirty = false;
    m_syncingSelection = false;
    updateEditorState();
}

void TopologyPage::showEdgeDetail(const TopologyEdgeRecord &edge) {
    m_syncingSelection = true;
    refreshEdgeNodeOptions();
    m_detailStack->setCurrentIndex(2);
    const int sourceIndex = m_edgeSourceCombo->findData(edge.sourceId);
    const int targetIndex = m_edgeTargetCombo->findData(edge.targetId);
    m_edgeSourceCombo->setCurrentIndex(sourceIndex >= 0 ? sourceIndex : 0);
    m_edgeTargetCombo->setCurrentIndex(targetIndex >= 0 ? targetIndex : 0);
    m_edgeLabelEdit->setText(edge.label);
    const int typeIndex = m_edgeTypeCombo->findData(edge.type);
    if (typeIndex >= 0) {
        m_edgeTypeCombo->setCurrentIndex(typeIndex);
    } else {
        m_edgeTypeCombo->setEditText(edge.type);
    }
    m_edgeNoteEdit->setPlainText(edge.note);
    m_detailHintLabel->setText(
        QStringLiteral("正在编辑连接：%1").arg(fallbackEdgeLabel(edge)));
    m_editorDirty = false;
    m_syncingSelection = false;
    updateEditorState();
}

void TopologyPage::showOverviewDetail() {
    m_syncingSelection = true;
    m_detailStack->setCurrentIndex(0);
    m_nodeNameEdit->clear();
    m_nodeIpEdit->clear();
    m_nodeHostNameEdit->clear();
    m_nodeOsEdit->clear();
    m_nodeTypeEdit->clear();
    m_nodeVendorEdit->clear();
    m_nodeStatusCombo->setCurrentIndex(
        m_nodeStatusCombo->findData(QStringLiteral("unknown")));
    m_nodeNoteEdit->clear();
    m_servicesEdit->clear();
    m_edgeLabelEdit->clear();
    m_edgeTypeCombo->setCurrentIndex(0);
    m_edgeNoteEdit->clear();
    m_detailHintLabel->setText(
        QStringLiteral("选择节点或连接后，可在这里编辑信息。"));
    m_editorDirty = false;
    m_syncingSelection = false;
    updateEditorState();
}

// ── Selection Sync ───────────────────────────────────────────────────────

void TopologyPage::syncSelectionToNode(const QString &nodeId) {
    m_syncingSelection = true;
    for (int row = 0; row < m_nodeListWidget->count(); ++row) {
        QListWidgetItem *item = m_nodeListWidget->item(row);
        if (item && item->data(Qt::UserRole).toString() == nodeId) {
            m_nodeListWidget->setCurrentRow(row);
            break;
        }
    }
    m_edgeListWidget->clearSelection();
    m_graphScene->clearSelection();
    if (m_nodeItems.contains(nodeId) && m_nodeItems.value(nodeId)) {
        m_nodeItems.value(nodeId)->setSelected(true);
        if (m_graphView) {
            m_graphView->centerOn(m_nodeItems.value(nodeId));
        }
    }
    m_syncingSelection = false;
}

void TopologyPage::syncSelectionToEdge(const QString &edgeId) {
    m_syncingSelection = true;
    for (int row = 0; row < m_edgeListWidget->count(); ++row) {
        QListWidgetItem *item = m_edgeListWidget->item(row);
        if (item && item->data(Qt::UserRole).toString() == edgeId) {
            m_edgeListWidget->setCurrentRow(row);
            break;
        }
    }
    m_nodeListWidget->clearSelection();
    m_graphScene->clearSelection();
    if (m_edgeItems.contains(edgeId) && m_edgeItems.value(edgeId)) {
        m_edgeItems.value(edgeId)->setSelected(true);
        if (m_graphView) {
            m_graphView->centerOn(m_edgeItems.value(edgeId));
        }
    }
    m_syncingSelection = false;
}

// ── Scene Selection Changed ─────────────────────────────────────────────

void TopologyPage::onSceneSelectionChanged() {
    if (m_syncingSelection) {
        return;
    }

    applyPendingEditorChanges();

    QString nodeId;
    QString edgeId;
    if (sender() == m_nodeListWidget) {
        QListWidgetItem *item = m_nodeListWidget->currentItem();
        if (item) {
            nodeId = item->data(Qt::UserRole).toString();
        }
    } else if (sender() == m_edgeListWidget) {
        QListWidgetItem *item = m_edgeListWidget->currentItem();
        if (item) {
            edgeId = item->data(Qt::UserRole).toString();
        }
    } else {
        const QList<QGraphicsItem *> items = m_graphScene->selectedItems();
        if (!items.isEmpty()) {
            if (items.first()->data(1).toString() == QStringLiteral("edge")) {
                edgeId = items.first()->data(0).toString();
            } else {
                nodeId = items.first()->data(0).toString();
            }
        }
    }

    if (!edgeId.isEmpty()) {
        m_selectedNodeId.clear();
        m_selectedEdgeId = edgeId;
        syncSelectionToEdge(edgeId);
        if (const TopologyEdgeRecord *edge = currentSelectedEdge()) {
            showEdgeDetail(*edge);
        } else {
            showOverviewDetail();
        }
        updateEditorState();
        return;
    }

    if (nodeId.isEmpty()) {
        m_selectedNodeId.clear();
        m_selectedEdgeId.clear();
        showOverviewDetail();
        updateEditorState();
        return;
    }

    m_selectedNodeId = nodeId;
    m_selectedEdgeId.clear();
    syncSelectionToNode(nodeId);
    if (const TopologyNodeRecord *node = currentSelectedNode()) {
        showNodeDetail(*node);
    } else {
        showOverviewDetail();
    }
    updateEditorState();
}

// ── Zoom / View ──────────────────────────────────────────────────────────

void TopologyPage::onZoomIn() {
    if (m_graphView) {
        m_graphView->scale(1.12, 1.12);
    }
}

void TopologyPage::onZoomOut() {
    if (m_graphView) {
        m_graphView->scale(1.0 / 1.12, 1.0 / 1.12);
    }
}

void TopologyPage::onResetView() {
    if (!m_graphView || !m_graphScene) {
        return;
    }
    m_graphView->resetTransform();
    m_graphView->fitInView(
        m_graphScene->itemsBoundingRect().adjusted(-40, -40, 40, 40),
        Qt::KeepAspectRatio);
}

// ── Add / Remove Nodes & Edges ──────────────────────────────────────────

void TopologyPage::onAddHostNode() {
    applyPendingEditorChanges();
    if (m_topologyDocument.summary.trimmed().isEmpty()) {
        m_topologyDocument.summary = QStringLiteral("手工网络拓扑");
    }
    if (m_topologyDocument.generatedAt.trimmed().isEmpty()) {
        m_topologyDocument.generatedAt = QDateTime::currentDateTime().toString(Qt::ISODate);
    }

    TopologyNodeRecord node;
    QSet<QString> usedIds;
    for (const TopologyNodeRecord &existing : m_topologyDocument.nodes) {
        usedIds.insert(existing.id);
    }
    node.id = ensureUniqueId(
        QStringLiteral("node-%1").arg(QDateTime::currentMSecsSinceEpoch()),
        usedIds, QStringLiteral("node"));
    node.displayName = QStringLiteral("新主机");
    node.status = QStringLiteral("unknown");
    node.x = m_topologyDocument.nodes.size() * 80.0;
    node.y = 0.0;
    m_topologyDocument.nodes.append(node);
    m_selectedNodeId = node.id;
    m_selectedEdgeId.clear();
    markDocumentDirty(QStringLiteral("已添加一个新节点，记得保存拓扑文件。"));
    populateTopologyDocument();
    syncSelectionToNode(node.id);
}

void TopologyPage::onAddEdge() {
    applyPendingEditorChanges();
    if (m_topologyDocument.nodes.size() < 2) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("至少需要两个节点才能创建连接。"));
        return;
    }

    QSet<QString> usedIds;
    for (const TopologyEdgeRecord &existing : m_topologyDocument.edges) {
        usedIds.insert(existing.id);
    }
    TopologyEdgeRecord edge;
    edge.id = ensureUniqueId(
        QStringLiteral("edge-%1").arg(QDateTime::currentMSecsSinceEpoch()),
        usedIds, QStringLiteral("edge"));
    edge.sourceId = m_selectedNodeId.isEmpty()
                        ? m_topologyDocument.nodes.first().id
                        : m_selectedNodeId;
    edge.targetId =
        (m_topologyDocument.nodes.first().id == edge.sourceId
             && m_topologyDocument.nodes.size() > 1)
            ? m_topologyDocument.nodes.at(1).id
            : m_topologyDocument.nodes.first().id;
    edge.label = QStringLiteral("新连接");
    edge.type = QStringLiteral("connection");
    m_topologyDocument.edges.append(edge);
    m_selectedNodeId.clear();
    m_selectedEdgeId = edge.id;
    markDocumentDirty(QStringLiteral("已添加一个新连接，记得保存拓扑文件。"));
    populateTopologyDocument();
    syncSelectionToEdge(edge.id);
}

void TopologyPage::onRemoveSelectedNode() {
    applyPendingEditorChanges();
    TopologyNodeRecord *node = currentSelectedNode();
    if (!node) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("请先选择一个节点。"));
        return;
    }

    const QString nodeId = node->id;
    const QString nodeTitle = nodeDisplayTitle(*node);
    if (QMessageBox::question(this->window(), QStringLiteral("删除节点"),
                              QStringLiteral("确认删除节点\"%1\"及其关联连接吗？").arg(nodeTitle))
        != QMessageBox::Yes) {
        return;
    }

    for (int i = m_topologyDocument.nodes.size() - 1; i >= 0; --i) {
        if (m_topologyDocument.nodes.at(i).id == nodeId) {
            m_topologyDocument.nodes.removeAt(i);
            break;
        }
    }
    for (int i = m_topologyDocument.edges.size() - 1; i >= 0; --i) {
        const TopologyEdgeRecord &edge = m_topologyDocument.edges.at(i);
        if (edge.sourceId == nodeId || edge.targetId == nodeId) {
            m_topologyDocument.edges.removeAt(i);
        }
    }

    m_selectedNodeId.clear();
    m_selectedEdgeId.clear();
    markDocumentDirty(QStringLiteral("已删除节点及相关连接，记得保存拓扑文件。"));
    populateTopologyDocument();

    if (!m_topologyDocument.nodes.isEmpty()) {
        const QString nextNodeId = m_topologyDocument.nodes.first().id;
        m_selectedNodeId = nextNodeId;
        syncSelectionToNode(nextNodeId);
        showNodeDetail(m_topologyDocument.nodes.first());
    } else if (!m_topologyDocument.edges.isEmpty()) {
        const QString nextEdgeId = m_topologyDocument.edges.first().id;
        m_selectedEdgeId = nextEdgeId;
        syncSelectionToEdge(nextEdgeId);
        showEdgeDetail(m_topologyDocument.edges.first());
    } else {
        showOverviewDetail();
    }
    updateEditorState();
}

void TopologyPage::onRemoveSelectedEdge() {
    applyPendingEditorChanges();
    TopologyEdgeRecord *edge = currentSelectedEdge();
    if (!edge) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("请先选择一条连接。"));
        return;
    }

    const QString edgeId = edge->id;
    const QString edgeLabel = fallbackEdgeLabel(*edge);
    if (QMessageBox::question(this->window(), QStringLiteral("删除连接"),
                              QStringLiteral("确认删除连接\"%1\"吗？").arg(edgeLabel))
        != QMessageBox::Yes) {
        return;
    }

    for (int i = m_topologyDocument.edges.size() - 1; i >= 0; --i) {
        if (m_topologyDocument.edges.at(i).id == edgeId) {
            m_topologyDocument.edges.removeAt(i);
            break;
        }
    }

    m_selectedEdgeId.clear();
    markDocumentDirty(QStringLiteral("已删除一条连接，记得保存拓扑文件。"));
    populateTopologyDocument();

    if (!m_topologyDocument.edges.isEmpty()) {
        const QString nextEdgeId = m_topologyDocument.edges.first().id;
        m_selectedEdgeId = nextEdgeId;
        syncSelectionToEdge(nextEdgeId);
        showEdgeDetail(m_topologyDocument.edges.first());
    } else if (!m_topologyDocument.nodes.isEmpty()) {
        const QString nextNodeId = m_topologyDocument.nodes.first().id;
        m_selectedNodeId = nextNodeId;
        syncSelectionToNode(nextNodeId);
        showNodeDetail(m_topologyDocument.nodes.first());
    } else {
        showOverviewDetail();
    }
    updateEditorState();
}

// ── Apply Detail Edits ───────────────────────────────────────────────────

void TopologyPage::onApplyDetailEdits() {
    applyPendingEditorChanges();
}

// ── Apply Node / Edge Edits ──────────────────────────────────────────────

void TopologyPage::applyNodeEdits() {
    if (m_syncingSelection || m_selectedNodeId.isEmpty()) {
        return;
    }
    TopologyNodeRecord *node = currentSelectedNode();
    if (!node) {
        return;
    }

    node->displayName = m_nodeNameEdit->text().trimmed();
    node->ip = m_nodeIpEdit->text().trimmed();
    node->hostName = m_nodeHostNameEdit->text().trimmed();
    const QString osText = m_nodeOsEdit->text().trimmed();
    const QStringList osParts = osText.split(
        QRegularExpression(QStringLiteral("\\s+")), QString::SkipEmptyParts);
    node->osName = osParts.isEmpty() ? QString() : osParts.first();
    node->osVersion = osParts.size() > 1 ? osParts.mid(1).join(QStringLiteral(" ")) : QString();
    node->deviceType = m_nodeTypeEdit->text().trimmed();
    node->vendor = m_nodeVendorEdit->text().trimmed();
    node->status = m_nodeStatusCombo->currentData().toString();
    node->note = m_nodeNoteEdit->toPlainText().trimmed();
    node->services.clear();

    const QStringList lines = m_servicesEdit->toPlainText().split(
        QLatin1Char('\n'), QString::SkipEmptyParts);
    for (const QString &rawLine : lines) {
        const QStringList parts = rawLine.split(QLatin1Char('|'));
        TopologyServiceRecord service;
        service.port = parts.value(0).trimmed();
        service.protocol = parts.value(1).trimmed();
        service.service = parts.value(2).trimmed();
        service.product = parts.value(3).trimmed();
        service.version = parts.value(4).trimmed();
        service.state = parts.value(5).trimmed();
        service.note = parts.value(6).trimmed();
        if (!service.port.isEmpty() || !service.service.isEmpty()) {
            node->services.append(service);
        }
    }

    m_editorDirty = false;
    markDocumentDirty(QStringLiteral("节点信息已更新，记得保存拓扑文件。"));
    const QString nodeId = node->id;
    populateNodeList();
    QTimer::singleShot(0, this, [this, nodeId]() {
        renderTopologyScene();
        syncSelectionToNode(nodeId);
    });
}

void TopologyPage::applyEdgeEdits() {
    if (m_syncingSelection || m_selectedEdgeId.isEmpty()) {
        return;
    }
    TopologyEdgeRecord *edge = currentSelectedEdge();
    if (!edge) {
        return;
    }

    const QString sourceId = m_edgeSourceCombo->currentData().toString();
    const QString targetId = m_edgeTargetCombo->currentData().toString();
    if (sourceId.isEmpty() || targetId.isEmpty() || sourceId == targetId) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("连接的源节点和目标节点必须有效且不能相同。"));
        return;
    }

    edge->sourceId = sourceId;
    edge->targetId = targetId;
    edge->label = m_edgeLabelEdit->text().trimmed();
    edge->type = m_edgeTypeCombo->currentData().toString().isEmpty()
      ? normalizedLine(m_edgeTypeCombo->currentText())
      : m_edgeTypeCombo->currentData().toString();
    edge->note = m_edgeNoteEdit->toPlainText().trimmed();
    m_editorDirty = false;
    markDocumentDirty(QStringLiteral("连接信息已更新，记得保存拓扑文件。"));
    const QString edgeId = edge->id;
    populateEdgeList();
    QTimer::singleShot(0, this, [this, edgeId]() {
        renderTopologyScene();
        syncSelectionToEdge(edgeId);
    });
}

void TopologyPage::applyPendingEditorChanges() {
    if (!m_editorDirty) {
        return;
    }
    if (!m_selectedNodeId.isEmpty()) {
        applyNodeEdits();
    } else if (!m_selectedEdgeId.isEmpty()) {
        applyEdgeEdits();
    }
}

// ── Editor State ─────────────────────────────────────────────────────────

void TopologyPage::updateEditorState() {
    const bool hasDocument = !m_topologyDocument.nodes.isEmpty()
                             || !m_topologyDocument.edges.isEmpty();
    const bool hasNodeSelection = !m_selectedNodeId.isEmpty() && currentSelectedNode();
    const bool hasEdgeSelection = !m_selectedEdgeId.isEmpty() && currentSelectedEdge();

    m_addNodeButton->setEnabled(hasDocument || m_topologyDocument.nodes.isEmpty());
    m_addEdgeButton->setEnabled(m_topologyDocument.nodes.size() >= 2);
    m_deleteNodeButton->setEnabled(hasNodeSelection);
    m_deleteEdgeButton->setEnabled(hasEdgeSelection);
    m_applyDetailButton->setEnabled(
        (hasNodeSelection || hasEdgeSelection) && m_editorDirty);
    m_saveTopologyButton->setEnabled(hasDocument && (m_documentDirty || m_editorDirty));
    m_saveTopologyButton->setText(
        (m_documentDirty || m_editorDirty) ? QStringLiteral("保存 *") : QStringLiteral("保存"));
}

void TopologyPage::refreshEdgeNodeOptions() {
    const QString currentSourceId = m_edgeSourceCombo->currentData().toString();
    const QString currentTargetId = m_edgeTargetCombo->currentData().toString();

    QSignalBlocker sourceBlocker(m_edgeSourceCombo);
    QSignalBlocker targetBlocker(m_edgeTargetCombo);
    m_edgeSourceCombo->clear();
    m_edgeTargetCombo->clear();

    for (const TopologyNodeRecord &node : m_topologyDocument.nodes) {
        const QString title = QStringLiteral("%1 (%2)")
                                  .arg(nodeDisplayTitle(node))
                                  .arg(node.ip.isEmpty() ? node.id : node.ip);
        m_edgeSourceCombo->addItem(title, node.id);
        m_edgeTargetCombo->addItem(title, node.id);
    }

    const int sourceIndex = m_edgeSourceCombo->findData(currentSourceId);
    const int targetIndex = m_edgeTargetCombo->findData(currentTargetId);
    if (sourceIndex >= 0) {
        m_edgeSourceCombo->setCurrentIndex(sourceIndex);
    }
    if (targetIndex >= 0) {
        m_edgeTargetCombo->setCurrentIndex(targetIndex);
    }
}

void TopologyPage::markDocumentDirty(const QString &hint) {
    m_documentDirty = true;
    if (!hint.trimmed().isEmpty()) {
        setStatusMessage(hint, infoStatusStyle());
    }
    updateEditorState();
}

void TopologyPage::setStatusMessage(const QString &text, const QString &style) {
    m_statusLabel->setText(text);
    if (!style.isEmpty()) {
        m_statusLabel->setStyleSheet(style);
    }
}

// ── Current Selection Accessors ──────────────────────────────────────────

TopologyNodeRecord *TopologyPage::currentSelectedNode() {
    for (TopologyNodeRecord &node : m_topologyDocument.nodes) {
        if (node.id == m_selectedNodeId) {
            return &node;
        }
    }
    return nullptr;
}

const TopologyNodeRecord *TopologyPage::currentSelectedNode() const {
    for (const TopologyNodeRecord &node : m_topologyDocument.nodes) {
        if (node.id == m_selectedNodeId) {
            return &node;
        }
    }
    return nullptr;
}

TopologyEdgeRecord *TopologyPage::currentSelectedEdge() {
    for (TopologyEdgeRecord &edge : m_topologyDocument.edges) {
        if (edge.id == m_selectedEdgeId) {
            return &edge;
        }
    }
    return nullptr;
}

const TopologyEdgeRecord *TopologyPage::currentSelectedEdge() const {
    for (const TopologyEdgeRecord &edge : m_topologyDocument.edges) {
        if (edge.id == m_selectedEdgeId) {
            return &edge;
        }
    }
    return nullptr;
}

// ── Document I/O ─────────────────────────────────────────────────────────

QString TopologyPage::topologyDataDir() const {
    return QCoreApplication::applicationDirPath()
           + QStringLiteral("/../data/topology_data");
}

QString TopologyPage::topologyDocumentPath(const QString &scanTaskId) const {
    return topologyDataDir() + QStringLiteral("/%1_topology.json").arg(scanTaskId);
}

QString TopologyPage::defaultTopologyDocumentPath() const {
    return topologyDataDir() + QStringLiteral("/topology_latest.json");
}

bool TopologyPage::saveTopologyDocument(QString *errorMessage) const {
    if (m_topologyDocument.nodes.isEmpty() && m_topologyDocument.edges.isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("当前没有可保存的拓扑内容。");
        }
        return false;
    }

    QDir().mkpath(topologyDataDir());
    const QString targetPath = !m_loadedTopologyPath.isEmpty()
                                   ? m_loadedTopologyPath
                                   : defaultTopologyDocumentPath();

    QFile file(targetPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("无法写入拓扑文件。");
        }
        return false;
    }

    const QByteArray payload =
        QJsonDocument(m_topologyDocument.toJsonObject()).toJson(QJsonDocument::Indented);
    file.write(payload);

    // Also write to latest
    const QString latestPath = defaultTopologyDocumentPath();
    if (targetPath != latestPath) {
        QFile latestFile(latestPath);
        if (latestFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            latestFile.write(payload);
        }
    }
    return true;
}

bool TopologyPage::loadTopologyDocumentFromPath(const QString &path,
                                                  TopologyDocument *document,
                                                  QString *errorMessage) const {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("无法读取拓扑文件：%1").arg(path);
        }
        return false;
    }

    const QJsonDocument json = QJsonDocument::fromJson(file.readAll());
    if (!json.isObject()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("拓扑文件格式无效。");
        }
        return false;
    }

    if (document) {
        *document = TopologyDocument::fromJsonObject(json.object());
    }
    return true;
}

QString TopologyPage::nodeDisplayTitle(const TopologyNodeRecord &node) const {
    return defaultNodeTitle(node);
}
