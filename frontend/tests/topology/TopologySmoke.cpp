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
    page.setPipelineContext("visual-fixture", "198.51.100.0/24", {}, false);
    if (!page.m_createScanBtn->isHidden()) return 1;
    TopologyDocument doc;
    doc.target = "198.51.100.0/24";
    doc.summary = QStringLiteral("自动采集 · 界面测试示例数据");
    struct Asset { const char *id; const char *ip; const char *kind; const char *name; double x; double y; };
    const Asset assets[] = {
        {"scanner","198.51.100.5","scanner","探测节点",80,0},
        {"gateway","198.51.100.1","router","边界路由",440,0},
        {"web","198.51.100.10","host","业务服务",800,-75},
        {"db","198.51.100.20","server","数据库服务",800,75},
        {"scope","","network_segment","198.51.100.0/24",1160,0},
    };
    for (const auto &asset : assets) {
        TopologyNodeRecord n;
        n.id = asset.id; n.ip = asset.ip; n.deviceType = asset.kind;
        n.displayName = QString::fromUtf8(asset.name);
        n.x = asset.x; n.y = asset.y;
        n.status = n.deviceType == "network_segment" ? "unknown" : "up";
        doc.nodes.append(n);
    }
    auto edge = [&](const char *id, const char *from, const char *to, bool logical) {
        TopologyEdgeRecord e;
        e.id=id; e.sourceId=from; e.targetId=to;
        e.type=logical ? "virtual-link" : "route";
        e.label=logical ? QStringLiteral("范围归属") : QStringLiteral("路由观测");
        doc.edges.append(e);
    };
    edge("a","scanner","gateway",false);
    edge("b","gateway","web",false);
    edge("c","gateway","db",false);
    edge("d","scope","web",true);
    edge("e","scope","db",true);
    page.m_topologyDocument = doc;
    page.m_documentDirty = false;
    page.populateTopologyDocument();
    page.resize(1440, 820);
    page.show();
    app.processEvents();
    page.onResetView();
    if (page.m_nodeItems.size() != 5 || page.m_edgeItems.size() != 5) return 2;
    if (page.m_edgeItems.value("d")->pen().style() != Qt::DashLine) return 3;
    if (page.m_edgeItems.value("a")->pen().style() != Qt::SolidLine) return 4;
    if (page.m_graphView->backgroundBrush().color() != QColor("#f3f6fb")) return 5;
    for (auto *node : page.m_nodeItems) {
        if (node->boundingRect().width() < 220) return 6;
    }
    // Existing edits survive automatic task-state refreshes.
    page.m_documentDirty = true;
    page.setPipelineContext("visual-fixture", doc.target, {"completed-scan"}, true);
    if (page.m_topologyDocument.nodes.size() != 5 || !page.m_documentDirty) return 7;
    page.setStatusMessage(QStringLiteral("随任务自动采集与更新 · 示例数据仅用于界面验证"));
    if (argc > 1 && !page.grab().save(QString::fromLocal8Bit(argv[1]))) return 8;
    return 0;
}
