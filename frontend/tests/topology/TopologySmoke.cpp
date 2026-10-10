#include <QtWidgets>
#include "ApiClient.h"
#include "models/TopologyTypes.h"
// Inspect the actual scene and task controls without adding production test APIs.
#define private public
#include "pages/TopologyPage.h"
#undef private

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setStyle("Fusion");
    ApiClient api("http://127.0.0.1:1");
    TopologyPage page(&api, "admin", "test");
    page.setPipelineContext("visual-fixture", "203.0.113.10", {}, false);
    if (!page.m_createScanBtn->isHidden()) return 1;
    TopologyDocument doc;
    doc.target = "203.0.113.10";
    doc.summary = QStringLiteral("自动采集 · 界面测试示例数据");
    struct Asset { const char *id; const char *ip; const char *kind; const char *name; double x; double y; };
    const Asset assets[] = {
        {"origin","192.0.2.20","client","源主机",-280,0},
        {"scanner","192.0.2.5","scanner","服务器",80,0},
        {"gateway","192.0.2.1","router","192.0.2.1",440,0},
        {"transit","198.51.100.1","router","198.51.100.1",800,0},
        {"web","203.0.113.10","host","任务目标",1160,0},
    };
    for (const auto &asset : assets) {
        TopologyNodeRecord n;
        n.id = asset.id; n.ip = asset.ip; n.deviceType = asset.kind;
        n.displayName = QString::fromUtf8(asset.name);
        n.x = asset.x; n.y = asset.y;
        n.status = "up";
        if (n.id == "web") n.tags.append("target");
        if (n.id == "origin") n.tags.append("source");
        if (n.id == "scanner") n.tags.append("server");
        doc.nodes.append(n);
    }
    auto edge = [&](const char *id, const char *from, const char *to, bool logical) {
        TopologyEdgeRecord e;
        e.id=id; e.sourceId=from; e.targetId=to;
        e.type=logical ? "virtual-link" : "route";
        e.label=logical ? QStringLiteral("范围归属") : QStringLiteral("路由观测");
        doc.edges.append(e);
    };
    edge("request","origin","scanner",false);
    doc.edges.last().type = "task-request";
    doc.edges.last().label = QStringLiteral("任务请求");
    edge("a","scanner","gateway",false);
    edge("b","gateway","transit",false);
    edge("c","transit","web",false);
    page.m_topologyDocument = doc;
    page.m_documentDirty = false;
    page.populateTopologyDocument();
    page.resize(1440, 820);
    page.show();
    app.processEvents();
    page.onResetView();
    if (page.m_nodeItems.size() != 5 || page.m_edgeItems.size() != 4) return 2;
    if (page.m_edgeItems.value("a")->pen().style() != Qt::SolidLine) return 4;
    if (page.m_edgeItems.value("request")->pen().style() != Qt::DashDotLine) return 15;
    if (page.m_graphView->backgroundBrush().color() != QColor("#f3f6fb")) return 5;
    for (auto *node : page.m_nodeItems) {
        if (node->boundingRect().width() < 220) return 6;
    }
    // Existing edits survive automatic task-state refreshes.
    page.m_documentDirty = true;
    page.setPipelineContext("visual-fixture", doc.target, {"completed-scan"}, true);
    if (page.m_topologyDocument.nodes.size() != 5 || !page.m_documentDirty) return 7;
    page.setStatusMessage(QStringLiteral("随任务自动采集与更新 · 示例数据仅用于界面验证"));
    if (argc > 1 && !page.grab().save(QString::fromLocal8Bit(argv[1]) + ".path.png")) return 8;
    // LAN fixture: logical membership branches, while source/server retain roles.
    TopologyDocument lan;
    lan.target = "192.168.1.111";
    lan.summary = QStringLiteral("局域网自动发现 · 虚拟交换机表示逻辑分组 · 界面测试示例数据");
    auto addLanNode = [&](const char *id, const char *ip, const char *kind, const QString &name, int x, int y, const char *tag) {
        TopologyNodeRecord n;
        n.id=id; n.ip=ip; n.deviceType=kind; n.displayName=name;
        n.x=x; n.y=y; n.status="up"; n.tags.append(tag);
        lan.nodes.append(n);
    };
    addLanNode("source","192.168.1.20","client",QStringLiteral("源主机"),80,-85,"source");
    addLanNode("server","192.168.1.5","scanner",QStringLiteral("服务器"),80,85,"server");
    addLanNode("lan","","network_segment",QStringLiteral("虚拟交换机"),440,0,"virtual-switch");
    lan.nodes.last().hostName="192.168.1.0/24";
    lan.nodes.last().status="unknown";
    addLanNode("target","192.168.1.111","host",QStringLiteral("目标主机"),800,-170,"target");
    addLanNode("neighbor1","192.168.1.30","host",QStringLiteral("192.168.1.30"),800,0,"lan-host");
    addLanNode("neighbor2","192.168.1.40","host",QStringLiteral("192.168.1.40"),800,170,"lan-host");
    for (const auto &id : {"source","server","target","neighbor1","neighbor2"}) {
        TopologyEdgeRecord e;
        e.id=QStringLiteral("member-")+id; e.sourceId="lan"; e.targetId=id;
        e.type="virtual-link"; e.label=QStringLiteral("同网段");
        lan.edges.append(e);
    }
    TopologyEdgeRecord request;
    request.id="request"; request.sourceId="source"; request.targetId="server";
    request.type="task-request"; request.label=QStringLiteral("任务请求");
    lan.edges.append(request);
    page.m_topologyDocument=lan;
    page.populateTopologyDocument();
    page.onResetView();
    app.processEvents();
    if (page.m_nodeItems.size()!=6 || page.m_edgeItems.size()!=6) return 16;
    for (auto *line : page.m_edgeItems) {
        if (line == page.m_edgeItems.value("request")) continue;
        if (line->pen().style()!=Qt::DashLine) return 17;
    }
    bool subnetVisible=false;
    for (auto *group : page.m_nodeItems.value("lan")->childItems()) for (auto *child : group->childItems()) {
        auto *text=dynamic_cast<QGraphicsSimpleTextItem *>(child);
        if (text && text->text()=="192.168.1.0/24") subnetVisible=true;
    }
    if (!subnetVisible) return 18;
    if (argc>1 && !page.grab().save(QString::fromLocal8Bit(argv[1]))) return 19;
    // Reproduce the two-node report with generated scanner names and a target
    // that has services. Check real text bounds at normal and enlarged fonts.
    const QFont originalFont = page.font();
    for (int points : {9, 12, 16, 24}) {
        QFont scaledFont = originalFont;
        scaledFont.setPointSize(points);
        page.setFont(scaledFont);
        for (bool namedTarget : {false, true}) {
            TopologyDocument pair;
            TopologyNodeRecord scanner = doc.nodes.at(1);
            scanner.ip = "192.168.1.100";
            scanner.displayName = QStringLiteral("扫描源 ") + scanner.ip;
            TopologyNodeRecord target = doc.nodes.at(4);
            target.ip = "192.168.1.111";
            target.displayName = namedTarget ? QStringLiteral("业务服务器") : target.ip;
            target.y = 0;
            TopologyServiceRecord service;
            service.port = "4280";
            target.services.append(service);
            pair.nodes = {scanner, target};
            TopologyEdgeRecord connection;
            connection.id = "direct";
            connection.sourceId = scanner.id;
            connection.targetId = target.id;
            connection.label = QStringLiteral("目标响应");
            connection.type = "reachability";
            pair.edges.append(connection);
            page.m_topologyDocument = pair;
            page.populateTopologyDocument();
            for (const auto &record : pair.nodes) {
                auto *card = page.m_nodeItems.value(record.id);
                QList<QRectF> rows;
                bool fullAddress = false;
                for (auto *group : card->childItems()) {
                    for (auto *child : group->childItems()) {
                        auto *text = dynamic_cast<QGraphicsSimpleTextItem *>(child);
                        if (!text) continue;
                        if (text->text() == record.ip) fullAddress = true;
                        if (text->text() == "scanner" || text->text() == "host") return 9;
                        const QRectF bounds = text->mapRectToItem(card, text->boundingRect());
                        if (!card->boundingRect().adjusted(8, 8, -8, -8).contains(bounds)) return 10;
                        for (const auto &previous : rows) if (bounds.intersects(previous)) return 11;
                        rows.append(bounds);
                    }
                }
                const int expectedRows = record.id == scanner.id || namedTarget ? 3 : 2;
                if (!fullAddress || rows.size() != expectedRows) return 12;
            }
            auto *line = page.m_edgeItems.value("direct");
            if (line->pen().style() != Qt::DashLine) return 3;
            for (const auto &id : {scanner.id, target.id}) {
                const QRectF interior = page.m_nodeItems.value(id)->sceneBoundingRect().adjusted(1, 1, -1, -1);
                if (interior.contains(line->line().p1()) || interior.contains(line->line().p2())) return 13;
            }
            page.onResetView();
            if (argc > 1 && points == 16 && !namedTarget
                && !page.grab().save(QString::fromLocal8Bit(argv[1]) + ".large-font.png")) return 14;
        }
    }
    return 0;
}
