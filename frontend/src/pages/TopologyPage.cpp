#include "../widgets/WorkbenchTabs.h"
#include <QGraphicsItemGroup>
#include <QStyleOptionGraphicsItem>
#include "TopologyPage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../AuxiliaryPanel.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QMenu>
#include <QTabWidget>
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QCryptographicHash>
#include <QPointer>
#include <QUrl>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGraphicsEllipseItem>
#include <QGraphicsRectItem>
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
#include <QPointer>
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
#include <QVariantAnimation>
#include <QEasingCurve>
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

class TopologyNodeItem : public QGraphicsRectItem {
public:
    explicit TopologyNodeItem(const QString &nodeId, const QRectF &rect)
        : QGraphicsRectItem(rect),
          m_nodeId(nodeId) {
        setFlags(QGraphicsItem::ItemIsSelectable | QGraphicsItem::ItemIsMovable);
        setAcceptedMouseButtons(Qt::LeftButton);
        setData(0, nodeId);
        setData(1, QStringLiteral("node"));
        setZValue(2.0);
        setTransformOriginPoint(rect.center());  // 发现动效缩放以圆心为准
    }

    std::function<void(const QString &, const QPointF &)> onMoveFinished;

protected:
    void paint(QPainter *painter, const QStyleOptionGraphicsItem *option, QWidget *widget) override {
        Q_UNUSED(option);
        Q_UNUSED(widget);
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setPen(QPen(QColor(isSelected() ? Theme::Primary : Theme::Border), isSelected() ? 2.2 : 1.2));
        painter->setBrush(QColor(isSelected() ? Theme::InfoBg : "#ffffff"));
        painter->drawRoundedRect(rect(), 12, 12);
        painter->setPen(Qt::NoPen);
        painter->setBrush(brush());
        painter->drawEllipse(QPointF(99, -29), 4, 4);
        painter->setBrush(QColor(Theme::Surface));
        painter->drawRoundedRect(QRectF(-104, -19, 34, 38), 8, 8);
        painter->setPen(QColor(Theme::MutedText));
        auto roleFont = painter->font();
        roleFont.setPointSize(8);
        painter->setFont(roleFont);
        painter->drawText(QRectF(-60, 14, 165, 20), Qt::AlignLeft | Qt::AlignVCenter, data(3).toString());
        painter->translate(-87, 0);
        painter->setBrush(Qt::NoBrush);
        painter->setPen(QPen(QColor(Theme::Primary), 1.7, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QString kind = data(2).toString().toLower();
        if (kind == QStringLiteral("scanner")) {
            painter->drawEllipse(QPointF(0, 0), 11, 11);
            painter->drawEllipse(QPointF(0, 0), 5, 5);
            painter->drawLine(QPointF(0, 0), QPointF(10, -10));
        } else if (kind == QStringLiteral("network_segment")) {
            for (int x : {-9, 0, 9}) painter->drawRect(QRectF(x - 3, 5, 6, 6));
            painter->drawRect(QRectF(-4, -12, 8, 7));
            painter->drawLine(QPointF(0, -5), QPointF(0, 1));
            painter->drawLine(QPointF(-9, 1), QPointF(9, 1));
            for (int x : {-9, 0, 9}) painter->drawLine(QPointF(x, 1), QPointF(x, 5));
        } else if (kind.contains("router") || kind.contains("gateway") || kind.contains("switch")) {
            painter->drawRoundedRect(QRectF(-12, -5, 24, 12), 2, 2);
            painter->drawLine(QPointF(-8, -5), QPointF(-8, -12));
            painter->drawLine(QPointF(8, -5), QPointF(8, -12));
            for (int x : {-7, -1, 5}) painter->drawLine(QPointF(x, 1), QPointF(x+2, 1));
        } else if (kind.contains("server")) {
            painter->drawRoundedRect(QRectF(-9, -13, 18, 26), 2, 2);
            for (int y : {-5, 4}) painter->drawLine(QPointF(-8, y), QPointF(8, y));
            for (int y : {-9, 0, 9}) painter->drawPoint(QPointF(-5, y));
        } else {
            painter->drawRoundedRect(QRectF(-12, -10, 24, 17), 2, 2);
            painter->drawLine(QPointF(0, 7), QPointF(0, 12));
            painter->drawLine(QPointF(-6, 12), QPointF(6, 12));
        }
        painter->restore();
    }
    void mouseReleaseEvent(QGraphicsSceneMouseEvent *event) override {
        QGraphicsRectItem::mouseReleaseEvent(event);
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
        return QStringLiteral("#2563eb");
    }
    if (type == QStringLiteral("uplink") || type == QStringLiteral("trunk")) {
        return QStringLiteral("#f59e0b");
    }
    return QStringLiteral("#64748b");
}

QString edgeTypeLabel(const QString &type) {
    if (type == QStringLiteral("virtual-link")) return QStringLiteral("逻辑归属");
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
    if (status == QStringLiteral("CANCELLED")) return QStringLiteral("已取消");
    if (status == QStringLiteral("ABORTED")) return QStringLiteral("已中止");
    return status;
}

bool isTopologySourceScanType(const QString &scanType) {
    return scanType == QStringLiteral("topology_scan")
        || scanType == QStringLiteral("port_scan")
        || scanType == QStringLiteral("vuln_scan")
        || scanType == QStringLiteral("web_scan");
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

    auto *scanWatcher = new QTimer(this);
    scanWatcher->setInterval(3000);
    connect(scanWatcher, &QTimer::timeout, this, [this]() {
        if (isVisible()) refreshScans(true);
    });
    scanWatcher->start();

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

void TopologyPage::setTarget(const QString &target)
{
    m_targetInput->setText(target);
}

void TopologyPage::onScanStarted(const QJsonObject &data)
{
    const QString scanTaskId = data[QStringLiteral("scanTaskId")].toString();
    if (!scanTaskId.isEmpty()) {
        m_autoTopologyGenerationIds.remove(scanTaskId);
    }
}

void TopologyPage::onScanCompleted(const QJsonObject &data)
{
    if (data[QStringLiteral("status")].toString() != QStringLiteral("COMPLETED")) {
        return;
    }

    const QString scanTaskId = data[QStringLiteral("scanTaskId")].toString();
    if (scanTaskId.isEmpty()) return;

    if (!m_pipelineId.isEmpty() && !m_scopedTopologyScanIds.contains(scanTaskId)) return;
    if (m_autoTopologyGenerationIds.contains(scanTaskId)) return;

    const QString eventScanType = data[QStringLiteral("scanType")].toString();
    if (!eventScanType.isEmpty() && !isTopologySourceScanType(eventScanType)) {
        return;
    }

    if (m_progressDialog) {
        if (m_selectedScanTaskId == scanTaskId) return;
        refreshScans(true);
        setStatusMessage(QStringLiteral("扫描已完成；当前已有拓扑正在生成，请稍后选择该任务生成。"),
                         infoStatusStyle());
        return;
    }

    m_autoTopologyGenerationIds.insert(scanTaskId);
    QPointer<TopologyPage> page(this);
    const QString pipelineId = m_pipelineId;
    const auto beginGeneration = [this, page, scanTaskId, pipelineId](const QString &target,
                                                           const QString &scanType) {
        if (!page || pipelineId != m_pipelineId) return;
        if (!isTopologySourceScanType(scanType)) {
            m_autoTopologyGenerationIds.remove(scanTaskId);
            return;
        }

        m_selectedScanTaskId = scanTaskId;
        const QString resolvedTarget = target.trimmed().isEmpty()
            ? m_targetInput->text().trimmed()
            : target.trimmed();
        if (m_currentTargetValueLabel && !resolvedTarget.isEmpty()) {
            m_currentTargetValueLabel->setText(resolvedTarget);
        }
        refreshScans(true);

        if (m_documentDirty || m_editorDirty) {
            m_autoTopologyGenerationIds.remove(scanTaskId);
            setStatusMessage(QStringLiteral("扫描已完成；当前拓扑存在未保存修改，请确认后手动生成。"),
                             infoStatusStyle());
            return;
        }

        setStatusMessage(QStringLiteral("扫描已完成，正在自动生成拓扑图…"), infoStatusStyle());
        onGenerateTopology();
    };

    const QString eventTarget = data[QStringLiteral("target")].toString();
    if (!eventScanType.isEmpty()) {
        beginGeneration(eventTarget, eventScanType);
        return;
    }

    m_api->get(QStringLiteral("/api/scan-tasks/") + scanTaskId, 5000,
               [this, page, scanTaskId, beginGeneration](const QJsonObject &res) {
                   if (!page) return;
                   if (res[QStringLiteral("status")].toString() != QStringLiteral("ok")) {
                       m_autoTopologyGenerationIds.remove(scanTaskId);
                       return;
                   }
                   const QJsonObject task = res[QStringLiteral("data")].toObject();
                   if (task[QStringLiteral("status")].toString() != QStringLiteral("COMPLETED")) {
                       m_autoTopologyGenerationIds.remove(scanTaskId);
                       return;
                   }
                   beginGeneration(task[QStringLiteral("target")].toString(),
                                   task[QStringLiteral("scan_type")].toString());
               });
}

void TopologyPage::setPipelineContext(const QString &pipelineId, const QString &target,
                                      const QStringList &scanIds, bool scanFinished)
{
    const bool changed = pipelineId != m_pipelineId;
    if (changed) {
        // Keep unsaved edits when navigating between tasks; polling never replaces them.
        if (!m_pipelineId.isEmpty() && !m_topologyDocument.nodes.isEmpty()) {
            applyPendingEditorChanges();
            m_drafts.insert(m_pipelineId, {m_topologyDocument, m_loadedTopologyPath,
                                          m_selectedScanTaskId, m_documentDirty});
        }
        ++m_contextGeneration;
        ++m_scanRefreshRevision;
        m_scopedTopologyScanIds.clear();
        m_pipelineId = pipelineId;
        m_autoLoadAttempted = false;
        m_scanSnapshotInitialized = false;
        m_observedCompletedScanIds.clear();
        m_selectedScanTaskId.clear();
        m_generateBtn->setEnabled(false);
        populateDocumentPlaceholder(QStringLiteral("正在读取任务拓扑"),
                                     QStringLiteral("优先显示当前任务的归档；扫描结束后自动展示已有结果。"));
        if (m_drafts.contains(pipelineId)) {
            const auto draft = m_drafts.take(pipelineId);
            m_topologyDocument = draft.document;
            m_loadedTopologyPath = draft.path;
            m_selectedScanTaskId = draft.selectedScan;
            m_documentDirty = draft.dirty;
            populateTopologyDocument();
            setStatusMessage(draft.dirty ? QStringLiteral("已恢复当前任务的未保存修改。")
                                        : QStringLiteral("已恢复当前任务的拓扑。"), infoStatusStyle());
        }
    }
    const bool resultsChanged = m_pipelineScanIds != scanIds || (!m_scanFinished && scanFinished);
    if (resultsChanged) m_autoLoadAttempted = false;
    m_pipelineScanIds = scanIds;
    m_scanFinished = scanFinished;
    setTarget(target);
    m_targetInput->setReadOnly(!pipelineId.isEmpty());
    if (!pipelineId.isEmpty()) m_scanTypeCombo->setCurrentIndex(0);
    m_scanTypeCombo->setEnabled(pipelineId.isEmpty());
    m_createScanBtn->setEnabled(pipelineId.isEmpty());
    m_createScanBtn->setVisible(pipelineId.isEmpty());
    m_scanTypeCombo->setVisible(pipelineId.isEmpty());
    if (changed || m_scanTaskTable->rowCount() == 0) {
        // Filter the existing table immediately; a scoped refresh can populate it.
        for (int row = m_scanTaskTable->rowCount() - 1; row >= 0; --row) {
            auto *item = m_scanTaskTable->item(row, 0);
            if (!item || !scanIds.contains(item->text())) m_scanTaskTable->removeRow(row);
        }
    }
    if (!changed && resultsChanged && scanFinished && !m_documentDirty && !m_editorDirty) {
        loadExistingScanTopology(true);
        return;
    }
    if (m_documentDirty || m_editorDirty || !m_topologyDocument.nodes.isEmpty()) return;
    if (restoreCurrentArchive()) return;
    if (scanFinished && !scanIds.isEmpty()) {
        loadExistingScanTopology();
    } else {
        populateDocumentPlaceholder(QStringLiteral("等待扫描结果"),
                                     QStringLiteral("当前任务尚无拓扑归档，扫描结束后会自动展示。"));
        setStatusMessage(QStringLiteral("等待当前任务的扫描结果，无需另行创建扫描。"), infoStatusStyle());
    }
}

QString TopologyPage::archiveDocumentPath() const
{
    if (!m_pipelineId.isEmpty()) {
        const auto key = QCryptographicHash::hash(m_pipelineId.toUtf8(), QCryptographicHash::Sha256).toHex();
        return topologyDataDir() + QStringLiteral("/pipeline_%1_topology.json").arg(QString::fromLatin1(key));
    }
    if (!m_topologyDocument.flowId.isEmpty())
        return topologyDocumentPath(QString::fromLatin1(QUrl::toPercentEncoding(m_topologyDocument.flowId)));
    return defaultTopologyDocumentPath();
}

bool TopologyPage::restoreCurrentArchive()
{
    if (m_pipelineId.isEmpty()) return false;
    QStringList paths{archiveDocumentPath()};
    for (const auto &id : m_pipelineScanIds)
        paths.append(topologyDocumentPath(QString::fromLatin1(QUrl::toPercentEncoding(id))));
    paths.append(defaultTopologyDocumentPath()); // Migrate old saves only when their scan belongs to this task.
    for (const auto &path : paths) {
        TopologyDocument doc;
        if (!loadTopologyDocumentFromPath(path, &doc) || doc.nodes.isEmpty()) continue;
        if (doc.flowId != m_pipelineId && !m_pipelineScanIds.contains(doc.flowId)) continue;
        m_topologyDocument = doc;
        m_loadedTopologyPath = path;
        m_documentDirty = false;
        m_editorDirty = false;
        populateTopologyDocument();
        setStatusMessage(QStringLiteral("已自动加载当前任务的拓扑归档。"), successStatusStyle());
        return true;
    }
    return false;
}

void TopologyPage::loadExistingScanTopology(bool replaceExisting)
{
    if (m_pipelineId.isEmpty() || m_autoLoadAttempted) return;
    m_autoLoadAttempted = true;
    const auto generation = m_contextGeneration;
    const auto scanIds = m_pipelineScanIds;
    QPointer<TopologyPage> guard(this);
    setStatusMessage(QStringLiteral("正在读取已有扫描结果，无需重新扫描…"), infoStatusStyle());
    m_api->get(QStringLiteral("/api/topology/from-pipeline/%1")
                   .arg(QString::fromLatin1(QUrl::toPercentEncoding(m_pipelineId))), 10000,
        [this, guard, generation, scanIds, replaceExisting](const QJsonObject &res) {
        if (!guard || generation != m_contextGeneration || scanIds != m_pipelineScanIds
            || m_documentDirty || m_editorDirty || (!replaceExisting && !m_topologyDocument.nodes.isEmpty())) return;
        if (res["status"].toString() != "ok") {
            setStatusMessage(QStringLiteral("读取已有拓扑结果失败，可在“扫描与记录”中刷新重试。"),
                             errorStatusStyle());
            return;
        }
        auto doc = TopologyDocument::fromJsonObject(res["data"].toObject()["topology"].toObject());
        if (doc.nodes.isEmpty()) {
            populateDocumentPlaceholder(QStringLiteral("暂无可展示的拓扑"),
                                         QStringLiteral("当前任务没有可用于拓扑展示的扫描结果。"));
            setStatusMessage(QStringLiteral("暂无主机数据；不会凭空补充节点或连接。"), infoStatusStyle());
            return;
        }
        doc.flowId = m_pipelineId;
        m_topologyDocument = doc;
        m_discoveryFxPending = true;
        m_loadedTopologyPath.clear();
        m_documentDirty = true;
        m_editorDirty = false;
        archiveGeneratedDocument();
    });
}

void TopologyPage::archiveGeneratedDocument()
{
    QString error;
    if (saveTopologyDocument(&error)) {
        m_loadedTopologyPath = archiveDocumentPath();
        m_documentDirty = false;
        m_editorDirty = false;
        populateTopologyDocument();
        onResetView();
        setStatusMessage(QStringLiteral("拓扑已展示并自动归档：%1 个节点，%2 条连线。")
                         .arg(m_topologyDocument.nodes.size()).arg(m_topologyDocument.edges.size()),
                         successStatusStyle());
    } else {
        populateTopologyDocument();
        onResetView();
        setStatusMessage(QStringLiteral("拓扑已展示，但自动归档失败：%1。请点击“保存”重试。").arg(error),
                         errorStatusStyle());
    }
}

TopologyPage::~TopologyPage() {
    if (m_progressDialog) qApp->restoreOverrideCursor();
}

// ── UI Construction ────────────────────────────────────────────────────────

void TopologyPage::setupUI() {
    setStyleSheet(Theme::PageStyle);
    auto *rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(12, 10, 12, 10);
    rootLayout->setSpacing(8);
    auto openDialog = [](AuxiliaryPanel *dialog) {
        dialog->present();
    };
    auto makeDialog = [this](const QString &name, const QString &title) {
        auto *dialog = new AuxiliaryPanel(this);
        dialog->setObjectName(name);
        dialog->setWindowTitle(title);
        dialog->resize(720, 540);
        return dialog;
    };

    // Scanning and saved records are tools, not permanent columns around the canvas.
    auto *sourceDialog = makeDialog("topologySources", QStringLiteral("扫描与拓扑记录"));
    auto *sourceLayout = new QVBoxLayout(sourceDialog);
    auto *sourceTabs = new WorkbenchTabs;
    sourceLayout->addWidget(sourceTabs);
    auto *scanPage = new QWidget;
    auto *scanLayout = new QVBoxLayout(scanPage);
    auto *form = new QGridLayout;
    m_targetInput = new QLineEdit;
    m_targetInput->setPlaceholderText(QStringLiteral("例: 192.168.1.0/24"));
    m_scanTypeCombo = new QComboBox;
    m_scanTypeCombo->addItem(QStringLiteral("拓扑探测"), "topology_scan");
    m_scanTypeCombo->addItem(QStringLiteral("端口扫描"), "port_scan");
    m_scanTypeCombo->addItem(QStringLiteral("漏洞扫描"), "vuln_scan");
    m_scanTypeCombo->addItem(QStringLiteral("网站扫描"), "web_scan");
    m_createScanBtn = new QPushButton(QStringLiteral("开始探测"));
    form->addWidget(new QLabel(QStringLiteral("目标")), 0, 0);
    form->addWidget(m_targetInput, 0, 1);
    form->addWidget(m_scanTypeCombo, 0, 2);
    form->addWidget(m_createScanBtn, 0, 3);
    form->setColumnStretch(1, 1);
    scanLayout->addLayout(form);
    auto *sourceHint = new QLabel(QStringLiteral("当前任务会随原有扫描自动采集拓扑并展示结果，无需另行启动。此处用于查看记录和必要时重新汇总；单个 IP 不会自动扩展为网段。"));
    sourceHint->setWordWrap(true);
    scanLayout->addWidget(sourceHint);
    m_scanTaskTable = new QTableWidget(0, 4);
    UiUtil::EmptyHint::attach(m_scanTaskTable, QStringLiteral("暂无扫描任务"));
    m_scanTaskTable->setHorizontalHeaderLabels({"任务编号", "目标", "类型", "状态"});
    m_scanTaskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_scanTaskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_scanTaskTable->setAlternatingRowColors(true);
    m_scanTaskTable->verticalHeader()->hide();
    m_scanTaskTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    scanLayout->addWidget(m_scanTaskTable, 1);
    auto *sourceActions = new QHBoxLayout;
    m_refreshBtn = new QPushButton(QStringLiteral("刷新扫描"));
    m_generateBtn = new QPushButton(QStringLiteral("生成拓扑"));
    m_generateBtn->setProperty("primary", true);
    m_generateBtn->setEnabled(false);
    sourceActions->addWidget(m_refreshBtn);
    sourceActions->addStretch();
    sourceActions->addWidget(m_generateBtn);
    scanLayout->addLayout(sourceActions);
    connect(m_scanTaskTable, &QTableWidget::cellClicked, this, &TopologyPage::onScanClicked);
    connect(m_generateBtn, &QPushButton::clicked, this, &TopologyPage::onGenerateTopology);
    sourceTabs->addTab(scanPage, QStringLiteral("扫描任务"));
    connect(m_createScanBtn, &QPushButton::clicked, this, [this]() {
        const QString target = m_targetInput->text().trimmed();
        if (target.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("提示"), QStringLiteral("请输入 IP、主机名或 CIDR 网段。"));
            return;
        }
        const QString pipelineId = m_pipelineId;
        const QString scanType = m_scanTypeCombo->currentData().toString();
        QJsonObject body{{"target", target}, {"scan_type", scanType}};
        if (!pipelineId.isEmpty()) body["parameters"] = QJsonObject{{"pipeline_id", pipelineId}};
        m_createScanBtn->setEnabled(false);
        QPointer<TopologyPage> page(this);
        m_api->post(QStringLiteral("/api/scan-tasks"), body, 10000,
            [this, page, target, pipelineId](const QJsonObject &res) {
                if (!page) return;
                if (pipelineId == m_pipelineId) m_createScanBtn->setEnabled(true);
                if (res["status"].toString() != "ok") {
                    if (pipelineId == m_pipelineId)
                        setStatusMessage(QStringLiteral("创建探测失败：%1").arg(res["error"].toObject()["message"].toString()), errorStatusStyle());
                    return;
                }
                const QString scanId = res["data"].toObject()["scan_task_id"].toString();
                if (scanId.isEmpty()) return;
                if (pipelineId == m_pipelineId) {
                    m_selectedScanTaskId = scanId;
                    if (!pipelineId.isEmpty()) m_scopedTopologyScanIds.insert(scanId);
                    m_currentTargetValueLabel->setText(target);
                    m_generateBtn->setEnabled(false);
                    TopologyScanRecord record{scanId, target, QDateTime::currentDateTime().toString(Qt::ISODate)};
                    upsertRecentRecord(record);
                    saveRecentRecords();
                }
                // Execute even if the user navigates away after submitting.
                m_api->post(QStringLiteral("/api/scan-tasks/") + scanId + QStringLiteral("/execute"), {}, 5000,
                    [this, page, pipelineId](const QJsonObject &result) {
                        if (!page || pipelineId != m_pipelineId) return;
                        if (result["status"].toString() != "ok")
                            setStatusMessage(QStringLiteral("启动失败：%1").arg(result["error"].toObject()["message"].toString()), errorStatusStyle());
                        else
                            setStatusMessage(QStringLiteral("探测已启动，完成后自动汇总拓扑。"), infoStatusStyle());
                        refreshScans(true);
                    });
            });
    });

    auto *recentPage = new QWidget;
    auto *recentLayout = new QVBoxLayout(recentPage);
    m_recentListWidget = new QListWidget;
    UiUtil::EmptyHint::attach(m_recentListWidget, QStringLiteral("暂无历史记录"));
    recentLayout->addWidget(m_recentListWidget, 1);
    m_removeRecordButton = new QPushButton(QStringLiteral("移除选中记录"));
    m_removeRecordButton->setProperty("danger", true);
    m_removeRecordButton->setEnabled(false);
    recentLayout->addWidget(m_removeRecordButton);
    connect(m_removeRecordButton, &QPushButton::clicked, this, &TopologyPage::onRemoveSelectedRecord);
    connect(m_recentListWidget, &QListWidget::itemSelectionChanged, this, [this]() {
        m_removeRecordButton->setEnabled(m_recentListWidget->currentItem() != nullptr);
    });
    sourceTabs->addTab(recentPage, QStringLiteral("最近记录"));

    // Full editors live in a separate inspector with a scrollable property form.
    auto *inspector = makeDialog("topologyInspector", QStringLiteral("节点与连线"));
    auto *inspectorLayout = new QVBoxLayout(inspector);
    auto *inspectorTabs = new WorkbenchTabs;
    inspectorLayout->addWidget(inspectorTabs);
    auto *nodesPage = new QWidget;
    auto *nodesLayout = new QVBoxLayout(nodesPage);
    m_nodeListWidget = new QListWidget;
    m_nodeListWidget->setWordWrap(true);
    UiUtil::EmptyHint::attach(m_nodeListWidget, QStringLiteral("暂无节点"));
    nodesLayout->addWidget(m_nodeListWidget, 1);
    m_deleteNodeButton = new QPushButton(QStringLiteral("删除节点"));
    m_deleteNodeButton->setProperty("danger", true);
    nodesLayout->addWidget(m_deleteNodeButton);
    auto *edgesPage = new QWidget;
    auto *edgesLayout = new QVBoxLayout(edgesPage);
    m_edgeListWidget = new QListWidget;
    m_edgeListWidget->setWordWrap(true);
    UiUtil::EmptyHint::attach(m_edgeListWidget, QStringLiteral("暂无连接"));
    edgesLayout->addWidget(m_edgeListWidget, 1);
    m_deleteEdgeButton = new QPushButton(QStringLiteral("删除连线"));
    m_deleteEdgeButton->setProperty("danger", true);
    edgesLayout->addWidget(m_deleteEdgeButton);
    auto *editorPage = new QWidget;
    auto *editorLayout = new QVBoxLayout(editorPage);
    m_detailHintLabel = new QLabel(QStringLiteral("选择节点或连线，再切换到属性编辑。"));
    m_detailHintLabel->setWordWrap(true);
    editorLayout->addWidget(m_detailHintLabel);
    auto *editorScroll = new QScrollArea;
    editorScroll->setWidgetResizable(true);
    editorScroll->setFrameShape(QFrame::NoFrame);
    m_detailStack = new QStackedWidget;
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
        QStringLiteral("每行一个服务：端口|协议|服务|产品|版本|状态|备注"));
    nodeFormLayout->addRow(QStringLiteral("名称"), m_nodeNameEdit);
    nodeFormLayout->addRow(QStringLiteral("IP 地址"), m_nodeIpEdit);
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
    m_edgeTypeCombo->addItem(QStringLiteral("逻辑归属"), QStringLiteral("virtual-link"));
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


    editorScroll->setWidget(m_detailStack);
    editorLayout->addWidget(editorScroll, 1);
    m_applyDetailButton = new QPushButton(QStringLiteral("应用修改"));
    m_applyDetailButton->setObjectName("applyBtn");
    editorLayout->addWidget(m_applyDetailButton);
    connect(m_applyDetailButton, &QPushButton::clicked, this, &TopologyPage::onApplyDetailEdits);
    inspectorTabs->addTab(nodesPage, QStringLiteral("节点"));
    inspectorTabs->addTab(edgesPage, QStringLiteral("连线"));
    inspectorTabs->addTab(editorPage, QStringLiteral("属性编辑"));
    connect(m_nodeListWidget, &QListWidget::itemDoubleClicked, this, [inspectorTabs]() { inspectorTabs->setCurrentIndex(2); });
    connect(m_edgeListWidget, &QListWidget::itemDoubleClicked, this, [inspectorTabs]() { inspectorTabs->setCurrentIndex(2); });

    auto *infoDialog = makeDialog("topologyInfo", QStringLiteral("拓扑信息"));
    auto *infoLayout = new QFormLayout(infoDialog);
    auto addValue = [infoLayout](const QString &title, QLabel **label) {
        *label = new QLabel("--");
        (*label)->setWordWrap(true);
        (*label)->setTextInteractionFlags(Qt::TextSelectableByMouse);
        infoLayout->addRow(title, *label);
    };
    addValue(QStringLiteral("状态"), &m_currentStatusValueLabel);
    addValue(QStringLiteral("进度"), &m_currentProgressValueLabel);
    addValue(QStringLiteral("目标"), &m_currentTargetValueLabel);
    addValue(QStringLiteral("数据来源"), &m_currentSourceValueLabel);
    addValue(QStringLiteral("生成时间"), &m_lastGeneratedValueLabel);
    addValue(QStringLiteral("文件"), &m_summaryLabel);
    addValue(QStringLiteral("范围"), &m_scopeLabel);
    addValue(QStringLiteral("说明"), &m_canvasSubtitleLabel);

    auto *toolbar = new QHBoxLayout;
    auto *sourcesButton = new QPushButton(QStringLiteral("扫描记录"));
    sourcesButton->setObjectName("topologySourcesButton");
    sourcesButton->setProperty("quiet", true);
    auto *inspectorButton = new QPushButton(QStringLiteral("节点与连线"));
    inspectorButton->setObjectName("topologyInspectorButton");
    auto *infoButton = new QPushButton(QStringLiteral("信息"));
    auto *zoomOutButton = new QPushButton("−");
    auto *resetViewButton = new QPushButton(QStringLiteral("适应画布"));
    auto *zoomInButton = new QPushButton("+");
    zoomOutButton->setToolTip(QStringLiteral("缩小"));
    zoomInButton->setToolTip(QStringLiteral("放大"));
    m_addNodeButton = new QPushButton(QStringLiteral("添加主机"), this);
    m_addEdgeButton = new QPushButton(QStringLiteral("添加连线"), this);
    m_addNodeButton->hide();
    m_addEdgeButton->hide();
    auto *editButton = new QPushButton(QStringLiteral("编辑"));
    auto *editMenu = new QMenu(editButton);
    auto *addNode = editMenu->addAction(QStringLiteral("添加主机"), m_addNodeButton, &QPushButton::click);
    auto *addEdge = editMenu->addAction(QStringLiteral("添加连线"), m_addEdgeButton, &QPushButton::click);
    connect(editMenu, &QMenu::aboutToShow, this, [this, addNode, addEdge]() {
        addNode->setEnabled(m_addNodeButton->isEnabled());
        addEdge->setEnabled(m_addEdgeButton->isEnabled());
    });
    editButton->setMenu(editMenu);
    editButton->setProperty("menuAction", true);
    m_saveTopologyButton = new QPushButton(QStringLiteral("保存"));
    m_saveTopologyButton->setProperty("primary", true);
    for (auto *button : {sourcesButton, inspectorButton, infoButton, zoomOutButton,
                         resetViewButton, zoomInButton, editButton, m_saveTopologyButton})
        UiUtil::styleToolbarButton(button);
    for (auto *button : {zoomOutButton, zoomInButton}) {
        button->setProperty("iconOnly", true);
        UiUtil::styleToolbarButton(button);
        button->setFixedWidth(36);
    }
    toolbar->addWidget(sourcesButton);
    sourcesButton->setToolTip(QStringLiteral("查看自动扫描记录，或重新汇总已有结果"));

    toolbar->addWidget(inspectorButton);
    toolbar->addWidget(infoButton);
    toolbar->addStretch();
    toolbar->addWidget(zoomOutButton);
    toolbar->addWidget(resetViewButton);
    toolbar->addWidget(zoomInButton);
    toolbar->addWidget(editButton);
    toolbar->addWidget(m_saveTopologyButton);
    rootLayout->addLayout(toolbar);
    connect(sourcesButton, &QPushButton::clicked, this, [=]() { openDialog(sourceDialog); });
    connect(inspectorButton, &QPushButton::clicked, this, [=]() { openDialog(inspector); });
    connect(infoButton, &QPushButton::clicked, this, [=]() { openDialog(infoDialog); });

    auto *titleRow = new QHBoxLayout;
    m_canvasTitleLabel = new QLabel(QStringLiteral("等待拓扑文件"));
    m_canvasTitleLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_canvasTitleLabel->setMinimumWidth(0);
    m_canvasTitleLabel->setStyleSheet("font-weight:600;font-size:15px;");
    m_statsLabel = new QLabel(QStringLiteral("节点 -- | 连线 --"));
    titleRow->addWidget(m_canvasTitleLabel, 1);
    titleRow->addWidget(m_statsLabel);
    rootLayout->addLayout(titleRow);
    m_graphScene = new QGraphicsScene(this);
    m_graphView = new TopologyGraphicsView(this);
    m_graphView->setObjectName("topologyCanvas");
    m_graphView->setScene(m_graphScene);
    m_graphView->setRenderHint(QPainter::Antialiasing, true);
    m_graphView->setDragMode(QGraphicsView::ScrollHandDrag);
    m_graphView->setBackgroundBrush(QColor(Theme::Background));
    m_graphView->setMinimumSize(0, 160);
    m_graphView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_graphView->setViewportUpdateMode(QGraphicsView::SmartViewportUpdate);
    rootLayout->addWidget(m_graphView, 1);
    auto *legend = new QLabel(QStringLiteral(
        "<span style='color:#15803d'>● 在线</span>　"
        "<span style='color:#b45309'>● 告警</span>　"
        "<span style='color:#b91c1c'>● 离线</span>　"
        "<span style='color:#64748b'>● 未知</span>　"
        "实线：路由观测/配置 · 虚线：范围归属（逻辑） · 单击查看证据，拖动调整"));
    legend->setObjectName("topologyLegend");
    legend->setWordWrap(true);
    legend->setStyleSheet("color:#52637a;font-size:12px;padding:2px 0;");
    rootLayout->addWidget(legend);
    m_statusLabel = new QLabel(QStringLiteral("准备就绪。"));
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(infoStatusStyle());
    rootLayout->addWidget(m_statusLabel);
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
    if (!m_pipelineId.isEmpty() && m_scanFinished && m_topologyDocument.nodes.isEmpty()) {
        m_autoLoadAttempted = false;
        if (!restoreCurrentArchive()) loadExistingScanTopology();
    }
    refreshScans(false);
}

void TopologyPage::refreshScans(bool preserveStatus) {
    QPointer<TopologyPage> page(this);
    const int revision = ++m_scanRefreshRevision;
    m_api->get(QStringLiteral("/api/scan-tasks"), 5000,
               [this, page, preserveStatus, revision](const QJsonObject &res) {
                   if (!page || revision != m_scanRefreshRevision) return;
                   if (res[QStringLiteral("status")].toString() != QStringLiteral("ok")) {
                       if (!preserveStatus)
                           setStatusMessage(QStringLiteral("获取扫描列表失败。"), errorStatusStyle());
                       return;
                   }
                   auto arr = res[QStringLiteral("data")].toArray();
                   if (!m_pipelineId.isEmpty()) {
                       QJsonArray scoped;
                       for (const auto &value : arr) {
                           const auto task = value.toObject();
                           const auto params = QJsonDocument::fromJson(task["parameters"].toString().toUtf8()).object();
                           const QString id = task["scan_task_id"].toString();
                           const bool discovery = task["scan_type"].toString() == QStringLiteral("topology_scan")
                               && params["pipeline_id"].toString() == m_pipelineId;
                           if (discovery) m_scopedTopologyScanIds.insert(id);
                           if (m_pipelineScanIds.contains(id) || discovery) scoped.append(value);
                       }
                       arr = scoped;
                   }
                   QString selectedStatus;
                   QString newlyCompletedScanId;
                   QJsonObject newlyCompletedScan;
                   QSet<QString> completedScanIds;
                   m_scanTaskTable->setRowCount(arr.size());
                   for (int i = 0; i < arr.size(); ++i) {
                       auto t = arr[i].toObject();
                       const QString scanTaskId = t[QStringLiteral("scan_task_id")].toString();
                       const QString scanType = t[QStringLiteral("scan_type")].toString();
                       const QString scanStatus = t[QStringLiteral("status")].toString();
                       if (scanStatus != QStringLiteral("COMPLETED")) {
                           m_autoTopologyGenerationIds.remove(scanTaskId);
                       }
                       if (scanStatus == QStringLiteral("COMPLETED")) {
                           completedScanIds.insert(scanTaskId);
                           if (m_scanSnapshotInitialized && (m_pipelineId.isEmpty() || m_scopedTopologyScanIds.contains(scanTaskId))
                               && newlyCompletedScanId.isEmpty()
                               && !m_observedCompletedScanIds.contains(scanTaskId)
                               && isTopologySourceScanType(scanType)) {
                               newlyCompletedScanId = scanTaskId;
                               newlyCompletedScan = t;
                           }
                       }
                       if (scanTaskId == m_selectedScanTaskId) {
                           selectedStatus = scanStatus;
                           if (scanStatus == QStringLiteral("FAILED") || scanStatus == QStringLiteral("CANCELLED"))
                               setStatusMessage(QStringLiteral("探测%1：%2").arg(scanStatusLabel(scanStatus),
                                   t["error_message"].toString()), errorStatusStyle());
                       }
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
                               if (st == QStringLiteral("topology_scan")) return QStringLiteral("拓扑探测");
                               if (st == QStringLiteral("port_scan")) return QStringLiteral("端口扫描");
                               if (st == QStringLiteral("vuln_scan")) return QStringLiteral("漏洞扫描");
                               if (st == QStringLiteral("web_scan")) return QStringLiteral("网站扫描");
                               if (st == QStringLiteral("brute_force")) return QStringLiteral("暴力破解");
                               return st;
                           }()));
                       QString statusText = scanStatusLabel(t[QStringLiteral("status")].toString());
                       m_scanTaskTable->setItem(
                           i, 3,
                           new QTableWidgetItem(statusText));
                   }
                   const bool hadScanSnapshot = m_scanSnapshotInitialized;
                   m_observedCompletedScanIds = completedScanIds;
                   m_scanSnapshotInitialized = true;
                   m_scanTaskTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
                   m_generateBtn->setEnabled(!m_progressDialog && selectedStatus == QStringLiteral("COMPLETED"));

                   // Update hero stat
                   if (!preserveStatus && m_currentStatusValueLabel) {
                       m_currentStatusValueLabel->setText(QStringLiteral("%1 条扫描").arg(arr.size()));
                   }

                   if (!preserveStatus && m_pipelineId.isEmpty())
                       setStatusMessage(QStringLiteral("已刷新扫描任务列表，共 %1 条。").arg(arr.size()), successStatusStyle());

                   if (hadScanSnapshot && !newlyCompletedScanId.isEmpty()) {
                       QJsonObject event;
                       event[QStringLiteral("scanTaskId")] = newlyCompletedScanId;
                       event[QStringLiteral("status")] = QStringLiteral("COMPLETED");
                       event[QStringLiteral("scanType")] = newlyCompletedScan[QStringLiteral("scan_type")];
                       event[QStringLiteral("target")] = newlyCompletedScan[QStringLiteral("target")];
                       QTimer::singleShot(0, this, [this, event]() {
                           onScanCompleted(event);
                       });
                   }
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
        m_generateBtn->setEnabled(!m_progressDialog);
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
    if (m_progressDialog) return;
    if (m_selectedScanTaskId.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("请先选择一个已完成的扫描任务。"));
        return;
    }

    if (m_documentDirty || m_editorDirty) {
        if (QMessageBox::question(this, QStringLiteral("重新生成拓扑"),
                QStringLiteral("重新生成会替换当前未保存的修改，是否继续？"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
    }
    const QString scanId = m_selectedScanTaskId;
    const QString target = m_currentTargetValueLabel->text();
    const auto generation = ++m_contextGeneration;
    QPointer<TopologyPage> guard(this);
    // ── Progress dialog (heap-allocated, safe for async callback) ────
    m_progressDialog = new QProgressDialog(QStringLiteral("正在汇总主机与链路证据..."),
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
    setStatusMessage(QStringLiteral("正在汇总主机与链路证据，请稍候..."), infoStatusStyle());

    if (m_currentStatusValueLabel) {
        m_currentStatusValueLabel->setText(QStringLiteral("生成中"));
    }
    if (m_currentProgressValueLabel) {
        m_currentProgressValueLabel->setText(QStringLiteral("..."));
    }

    QJsonObject body;
    body[QStringLiteral("scan_task_id")] = scanId;

    const auto receiveTopology = [this, guard, scanId, target, generation](const QJsonObject &res) {
                    if (!guard) return;
                    // Close and clean up progress dialog
                    if (m_progressDialog) {
                        m_progressDialog->close();
                        delete m_progressDialog;
                        m_progressDialog = nullptr;
                    }
                    m_generateBtn->setEnabled(false);
                    m_generateBtn->setText(QStringLiteral("生成拓扑"));
                    qApp->restoreOverrideCursor();
                    refreshScans(true);
                    if (generation != m_contextGeneration || scanId != m_selectedScanTaskId) {
                        m_autoTopologyGenerationIds.remove(scanId);
                        return;
                    }

                    if (res[QStringLiteral("status")].toString() != QStringLiteral("ok")) {
                        m_autoTopologyGenerationIds.remove(scanId);
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
                    doc.flowId = m_pipelineId.isEmpty() ? scanId : m_pipelineId;
                    doc.target = target;
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
                    m_discoveryFxPending = true;  // 生成完成 → 播放节点发现动效
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
                    record.scanTaskId = scanId;
                    record.target = m_currentTargetValueLabel ? m_currentTargetValueLabel->text() : QString();
                    record.createdAt = QDateTime::currentDateTime().toString(Qt::ISODate);
                    upsertRecentRecord(record);
                    saveRecentRecords();

                    archiveGeneratedDocument();
                };
    if (m_pipelineId.isEmpty()) {
        m_api->post(QStringLiteral("/api/topology/generate-from-scan"), body, 120000, receiveTopology);
    } else {
        m_api->get(QStringLiteral("/api/topology/from-pipeline/%1")
            .arg(QString::fromLatin1(QUrl::toPercentEncoding(m_pipelineId))), 10000, receiveTopology);
    }
}

// ── Save Topology ─────────────────────────────────────────────────────────

void TopologyPage::onSaveTopology() {
    applyPendingEditorChanges();
    QString errorMessage;
    if (!saveTopologyDocument(&errorMessage)) {
        QMessageBox::warning(this, QStringLiteral("保存失败"), errorMessage);
        return;
    }
    {
        m_loadedTopologyPath = archiveDocumentPath();
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
        QStringLiteral("节点 %1 个，连线 %2 条。可直接拖动主机位置，通过“节点与连线”编辑信息。%3")
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

    ++m_sceneGen;
    m_graphScene->clear();
    auto *empty = m_graphScene->addText(title + QStringLiteral("\n\n") + detail);
    empty->setDefaultTextColor(QColor("#a8bdd5"));
    empty->setTextWidth(400);
    m_graphScene->setSceneRect(empty->boundingRect().adjusted(-40, -40, 40, 40));
    m_nodeItems.clear();
    m_edgeItems.clear();
    m_nodeListWidget->clear();
    m_edgeListWidget->clear();
    showOverviewDetail();
    updateEditorState();
}

// ── Render Topology Scene ────────────────────────────────────────────────

void TopologyPage::renderTopologyScene() {
    ++m_sceneGen;  // 场景重建 — 上一轮未完成的动效回调全部失效
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
        auto anchor = [](const QPointF &from, const QPointF &to) {
            const QPointF delta = to - from;
            const qreal scale = qMax(qAbs(delta.x()) / 118.0, qAbs(delta.y()) / 46.0);
            return scale > 1.0 ? from + delta / scale : from;
        };
        auto *line = new TopologyEdgeItem(edge.id, QLineF(anchor(source, target), anchor(target, source)));
        const bool selected = edge.id == m_selectedEdgeId;
        line->setPen(QPen(QColor(selected ? QString(Theme::Primary) : edgeColor(edge.type)),
                          selected ? 3.2 : 2.2,
                          edge.type == QStringLiteral("virtual-link") ? Qt::DashLine : Qt::SolidLine,
                          Qt::RoundCap));
        line->setToolTip(QStringLiteral("%1\n%2 -> %3\n%4")
                             .arg(fallbackEdgeLabel(edge))
                             .arg(edge.sourceId)
                             .arg(edge.targetId)
                             .arg(edge.note));
        m_graphScene->addItem(line);
        m_edgeItems.insert(edge.id, line);

        auto *edgeText = m_graphScene->addSimpleText(fallbackEdgeLabel(edge));
        edgeText->setBrush(QColor(selected ? Theme::Primary : Theme::MutedText));
        edgeText->setPos((source.x() + target.x()) * 0.5 - edgeText->boundingRect().width() * 0.5,
                         (source.y() + target.y()) * 0.5 - edgeText->boundingRect().height() - 4);
        edgeText->setParentItem(line);  // 跟随连线淡入/拖动
        edgeText->setZValue(1.2);
    }

    // Draw nodes
    for (TopologyNodeRecord &node : m_topologyDocument.nodes) {
        const QPointF pos = positions.value(node.id);
        node.x = pos.x();
        node.y = pos.y();

        auto *ellipse = new TopologyNodeItem(
            node.id, QRectF(-116.0, -44.0, 232.0, 88.0));
        ellipse->setPos(pos);
        ellipse->setData(2, node.deviceType);
        const QString role = node.deviceType == QStringLiteral("scanner") ? QStringLiteral("扫描源")
            : node.deviceType == QStringLiteral("router") ? QStringLiteral("路由节点")
            : node.deviceType == QStringLiteral("network_segment") ? QStringLiteral("探测范围 · 逻辑分组")
            : QStringLiteral("目标资产");
        ellipse->setData(3, role + (node.services.isEmpty() ? QString() : QStringLiteral(" · %1 项服务").arg(node.services.size())));
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
        const QString secondaryLabel = node.deviceType == QStringLiteral("network_segment")
            ? QStringLiteral("CIDR 范围")
            : topologyNodeSecondaryLabel(node, primaryLabel);

        // Anchor labels to their host while retaining readable text at overview zoom.
        auto *labels = new QGraphicsItemGroup(ellipse);
        labels->setPos(-60, -27);
        const QString visibleName = QFontMetrics(QApplication::font()).elidedText(primaryLabel, Qt::ElideRight, 155);
        auto *text = new QGraphicsSimpleTextItem(visibleName, labels);
        text->setBrush(QColor(Theme::Dark));
        text->setPos(0, 0);
        text->setToolTip(topologyNodeTooltip(node));

        if (!secondaryLabel.isEmpty()) {
            auto *subText = new QGraphicsSimpleTextItem(QFontMetrics(QApplication::font()).elidedText(secondaryLabel, Qt::ElideRight, 160), labels);
            subText->setBrush(QColor(Theme::MutedText));
            subText->setPos(0, text->boundingRect().height() + 2);
            subText->setToolTip(topologyNodeTooltip(node));
        }
    }

    m_graphScene->setSceneRect(
        m_graphScene->itemsBoundingRect().adjusted(-60, -60, 60, 60));

    // 发现动效：节点逐个弹入，连线随后淡入（仅 generate-from-scan 触发）
    if (m_discoveryFxPending) {
        m_discoveryFxPending = false;
        int delay = 0;
        for (const TopologyNodeRecord &node : m_topologyDocument.nodes) {  // 按文档顺序点亮
            if (auto *item = m_nodeItems.value(node.id, nullptr))
                fxFadeIn(item, m_sceneGen, delay, 0.4);
            delay += 130;
        }
        const int edgeDelay = delay + 100;
        int ei = 0;
        for (auto it = m_edgeItems.constBegin(); it != m_edgeItems.constEnd(); ++it) {
            fxFadeIn(it.value(), m_sceneGen, edgeDelay + ei * 60, 0.0);
            ++ei;
        }
    }
}

// ── 发现动效：单项淡入（fromScale>0 叠加缩放弹入）───────────────────────
void TopologyPage::fxFadeIn(QGraphicsItem *item, quint64 gen, int delayMs, qreal fromScale) {
    item->setOpacity(0.0);
    if (fromScale > 0.0) item->setScale(fromScale);
    auto *anim = new QVariantAnimation(this);
    anim->setDuration(300);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(fromScale > 0.0 ? QEasingCurve::OutBack : QEasingCurve::OutCubic);
    connect(anim, &QVariantAnimation::valueChanged, this, [this, gen, item, fromScale, anim](const QVariant &v) {
        if (gen != m_sceneGen) { anim->stop(); return; }  // 场景已重建，旧项失效
        const qreal t = v.toDouble();
        item->setOpacity(qBound(0.0, t, 1.0));
        if (fromScale > 0.0) item->setScale(fromScale + (1.0 - fromScale) * t);
    });
    QTimer::singleShot(delayMs, this, [anim]() {
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    });
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
        item->setSizeHint(QSize(0, 72));
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
        item->setSizeHint(QSize(0, 72));
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
        m_graphScene->itemsBoundingRect().adjusted(-50, -50, 50, 100),
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
    const QString targetPath = archiveDocumentPath();
    const QByteArray payload =
        QJsonDocument(m_topologyDocument.toJsonObject()).toJson(QJsonDocument::Indented);
    QSaveFile file(targetPath);
    if (!file.open(QIODevice::WriteOnly) || file.write(payload) != payload.size() || !file.commit()) {
        if (errorMessage) *errorMessage = QStringLiteral("无法写入拓扑归档：%1").arg(file.errorString());
        return false;
    }
    // Compatibility snapshot for the standalone page; task pages use their own archive.
    if (targetPath != defaultTopologyDocumentPath()) {
        QSaveFile latest(defaultTopologyDocumentPath());
        if (latest.open(QIODevice::WriteOnly) && latest.write(payload) == payload.size())
            latest.commit();
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
