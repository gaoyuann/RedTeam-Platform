#include "TopologyTypes.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QRegExp>

namespace {
QString jsonValueToString(const QJsonValue &value) {
    if (value.isString()) {
        return value.toString().trimmed();
    }
    if (value.isDouble()) {
        const double number = value.toDouble();
        const qint64 integer = static_cast<qint64>(number);
        if (qFuzzyCompare(number + 1.0, static_cast<double>(integer) + 1.0)) {
            return QString::number(integer);
        }
        return QString::number(number);
    }
    if (value.isBool()) {
        return value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    }
    if (value.isArray()) {
        QStringList parts;
        const QJsonArray array = value.toArray();
        for (const QJsonValue &item : array) {
            const QString text = jsonValueToString(item);
            if (!text.isEmpty()) {
                parts.append(text);
            }
        }
        return parts.join(QStringLiteral(", "));
    }
    if (value.isObject()) {
        return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
    }
    return QString();
}

QString firstStringValue(const QJsonObject &object, const QStringList &keys) {
    for (const QString &key : keys) {
        if (!object.contains(key)) {
            continue;
        }
        const QString text = jsonValueToString(object.value(key));
        if (!text.isEmpty()) {
            return text;
        }
    }
    return QString();
}

double firstDoubleValue(const QJsonObject &object, const QStringList &keys) {
    for (const QString &key : keys) {
        const QJsonValue value = object.value(key);
        if (value.isDouble()) {
            return value.toDouble();
        }
        if (value.isString()) {
            bool ok = false;
            const double number = value.toString().trimmed().toDouble(&ok);
            if (ok) {
                return number;
            }
        }
    }
    return 0.0;
}

QJsonArray firstArrayValue(const QJsonObject &object, const QStringList &keys) {
    for (const QString &key : keys) {
        const QJsonValue value = object.value(key);
        if (value.isArray()) {
            return value.toArray();
        }
    }
    return QJsonArray();
}

QJsonObject firstObjectValue(const QJsonObject &object, const QStringList &keys) {
    for (const QString &key : keys) {
        const QJsonValue value = object.value(key);
        if (value.isObject()) {
            return value.toObject();
        }
    }
    return {};
}

QStringList stringListValue(const QJsonValue &value) {
    QStringList items;
    if (value.isArray()) {
        const QJsonArray array = value.toArray();
        for (const QJsonValue &item : array) {
            const QString text = jsonValueToString(item).trimmed();
            if (!text.isEmpty() && !items.contains(text)) {
                items.append(text);
            }
        }
    } else {
        const QString text = jsonValueToString(value).trimmed();
        const QStringList split = text.split(QRegExp(QStringLiteral("[,，;；、]")), QString::SkipEmptyParts);
        for (const QString &item : split) {
            const QString normalized = item.trimmed();
            if (!normalized.isEmpty() && !items.contains(normalized)) {
                items.append(normalized);
            }
        }
    }
    return items;
}

QJsonObject effectiveRootObject(const QJsonObject &object) {
    if (object.contains(QStringLiteral("nodes")) || object.contains(QStringLiteral("hosts")) || object.contains(QStringLiteral("devices"))) {
        return object;
    }
    const QJsonObject topology = firstObjectValue(object, {
        QStringLiteral("topology"), QStringLiteral("networkTopology"), QStringLiteral("network_topology"),
        QStringLiteral("graph"), QStringLiteral("result"), QStringLiteral("data")
    });
    return topology.isEmpty() ? object : topology;
}

QJsonArray topologyNodesArray(const QJsonObject &object) {
    return firstArrayValue(object, {
        QStringLiteral("nodes"), QStringLiteral("hosts"), QStringLiteral("devices"),
        QStringLiteral("assets"), QStringLiteral("endpoints"), QStringLiteral("vertices")
    });
}

QJsonArray topologyEdgesArray(const QJsonObject &object) {
    return firstArrayValue(object, {
        QStringLiteral("edges"), QStringLiteral("links"), QStringLiteral("connections"),
        QStringLiteral("relationships"), QStringLiteral("routes")
    });
}

void appendUniqueService(QList<TopologyServiceRecord> *services, const TopologyServiceRecord &service) {
    if (!services || (service.port.trimmed().isEmpty() && service.service.trimmed().isEmpty())) {
        return;
    }
    const QString fingerprint = service.port.trimmed().toLower() + QLatin1Char('|')
        + service.protocol.trimmed().toLower() + QLatin1Char('|')
        + service.service.trimmed().toLower();
    for (const TopologyServiceRecord &existing : *services) {
        const QString existingFingerprint = existing.port.trimmed().toLower() + QLatin1Char('|')
            + existing.protocol.trimmed().toLower() + QLatin1Char('|')
            + existing.service.trimmed().toLower();
        if (existingFingerprint == fingerprint) {
            return;
        }
    }
    services->append(service);
}
}

QJsonObject TopologyServiceRecord::toJsonObject() const {
    return QJsonObject{
        {QStringLiteral("port"), port},
        {QStringLiteral("protocol"), protocol},
        {QStringLiteral("service"), service},
        {QStringLiteral("product"), product},
        {QStringLiteral("version"), version},
        {QStringLiteral("state"), state},
        {QStringLiteral("note"), note},
    };
}

TopologyServiceRecord TopologyServiceRecord::fromJsonObject(const QJsonObject &object) {
    TopologyServiceRecord record;
    record.port = firstStringValue(object, {
        QStringLiteral("port"), QStringLiteral("portNumber"), QStringLiteral("port_number"), QStringLiteral("openPort")
    });
    record.protocol = firstStringValue(object, {
        QStringLiteral("protocol"), QStringLiteral("proto"), QStringLiteral("transport")
    });
    record.service = firstStringValue(object, {
        QStringLiteral("service"), QStringLiteral("serviceName"), QStringLiteral("service_name"),
        QStringLiteral("name"), QStringLiteral("application"), QStringLiteral("component")
    });
    record.product = firstStringValue(object, {
        QStringLiteral("product"), QStringLiteral("software"), QStringLiteral("app"), QStringLiteral("vendorProduct")
    });
    record.version = firstStringValue(object, {
        QStringLiteral("version"), QStringLiteral("serviceVersion"), QStringLiteral("service_version"), QStringLiteral("banner")
    });
    record.state = firstStringValue(object, {
        QStringLiteral("state"), QStringLiteral("status"), QStringLiteral("portState")
    });
    record.note = firstStringValue(object, {
        QStringLiteral("note"), QStringLiteral("notes"), QStringLiteral("description"),
        QStringLiteral("evidence"), QStringLiteral("summary"), QStringLiteral("details")
    });
    return record;
}

QJsonObject TopologyNodeRecord::toJsonObject() const {
    QJsonArray tagsArray;
    for (const QString &tag : tags) {
        tagsArray.append(tag);
    }
    QJsonArray servicesArray;
    for (const TopologyServiceRecord &serviceRecord : services) {
        servicesArray.append(serviceRecord.toJsonObject());
    }
    return QJsonObject{
        {QStringLiteral("id"), id},
        {QStringLiteral("displayName"), displayName},
        {QStringLiteral("ip"), ip},
        {QStringLiteral("hostName"), hostName},
        {QStringLiteral("osName"), osName},
        {QStringLiteral("osVersion"), osVersion},
        {QStringLiteral("deviceType"), deviceType},
        {QStringLiteral("vendor"), vendor},
        {QStringLiteral("status"), status},
        {QStringLiteral("note"), note},
        {QStringLiteral("tags"), tagsArray},
        {QStringLiteral("x"), x},
        {QStringLiteral("y"), y},
        {QStringLiteral("services"), servicesArray},
    };
}

TopologyNodeRecord TopologyNodeRecord::fromJsonObject(const QJsonObject &object) {
    TopologyNodeRecord record;
    record.id = firstStringValue(object, {
        QStringLiteral("id"), QStringLiteral("nodeId"), QStringLiteral("node_id"), QStringLiteral("uuid")
    });
    record.displayName = firstStringValue(object, {
        QStringLiteral("displayName"), QStringLiteral("display_name"), QStringLiteral("name"),
        QStringLiteral("label"), QStringLiteral("title")
    });
    record.ip = firstStringValue(object, {
        QStringLiteral("ip"), QStringLiteral("host"), QStringLiteral("address"), QStringLiteral("target"),
        QStringLiteral("ipAddress"), QStringLiteral("ip_address")
    });
    record.hostName = firstStringValue(object, {
        QStringLiteral("hostName"), QStringLiteral("hostname"), QStringLiteral("host_name"), QStringLiteral("fqdn")
    });
    record.osName = firstStringValue(object, {
        QStringLiteral("osName"), QStringLiteral("os_name"), QStringLiteral("os"), QStringLiteral("operatingSystem"),
        QStringLiteral("operating_system")
    });
    record.osVersion = firstStringValue(object, {
        QStringLiteral("osVersion"), QStringLiteral("os_version"), QStringLiteral("kernel"), QStringLiteral("kernelVersion"),
        QStringLiteral("kernel_version")
    });
    record.deviceType = firstStringValue(object, {
        QStringLiteral("deviceType"), QStringLiteral("device_type"), QStringLiteral("type"), QStringLiteral("role"),
        QStringLiteral("assetType"), QStringLiteral("asset_type")
    });
    record.vendor = firstStringValue(object, {
        QStringLiteral("vendor"), QStringLiteral("manufacturer"), QStringLiteral("brand")
    });
    record.status = firstStringValue(object, {
        QStringLiteral("status"), QStringLiteral("state"), QStringLiteral("alive"), QStringLiteral("online")
    });
    record.note = firstStringValue(object, {
        QStringLiteral("note"), QStringLiteral("notes"), QStringLiteral("description"), QStringLiteral("summary"),
        QStringLiteral("evidence"), QStringLiteral("details")
    });
    record.x = firstDoubleValue(object, {QStringLiteral("x"), QStringLiteral("posX"), QStringLiteral("pos_x")});
    record.y = firstDoubleValue(object, {QStringLiteral("y"), QStringLiteral("posY"), QStringLiteral("pos_y")});
    const QStringList tags = stringListValue(object.value(QStringLiteral("tags")))
        + stringListValue(object.value(QStringLiteral("labels")));
    for (const QString &tag : tags) {
        if (!tag.isEmpty() && !record.tags.contains(tag)) {
            record.tags.append(tag);
        }
    }
    const QJsonArray servicesArray = firstArrayValue(object, {
        QStringLiteral("services"), QStringLiteral("ports"), QStringLiteral("openPorts"), QStringLiteral("open_ports"),
        QStringLiteral("applications")
    });
    for (const QJsonValue &value : servicesArray) {
        if (value.isObject()) {
            appendUniqueService(&record.services, TopologyServiceRecord::fromJsonObject(value.toObject()));
        }
    }
    return record;
}

QJsonObject TopologyEdgeRecord::toJsonObject() const {
    return QJsonObject{
        {QStringLiteral("id"), id},
        {QStringLiteral("sourceId"), sourceId},
        {QStringLiteral("targetId"), targetId},
        {QStringLiteral("label"), label},
        {QStringLiteral("type"), type},
        {QStringLiteral("note"), note},
    };
}

TopologyEdgeRecord TopologyEdgeRecord::fromJsonObject(const QJsonObject &object) {
    TopologyEdgeRecord record;
    record.id = firstStringValue(object, {
        QStringLiteral("id"), QStringLiteral("edgeId"), QStringLiteral("edge_id"), QStringLiteral("uuid")
    });
    record.sourceId = firstStringValue(object, {
        QStringLiteral("sourceId"), QStringLiteral("source_id"), QStringLiteral("source"),
        QStringLiteral("from"), QStringLiteral("fromId"), QStringLiteral("from_id")
    });
    record.targetId = firstStringValue(object, {
        QStringLiteral("targetId"), QStringLiteral("target_id"), QStringLiteral("target"),
        QStringLiteral("to"), QStringLiteral("toId"), QStringLiteral("to_id"), QStringLiteral("destination")
    });
    record.label = firstStringValue(object, {
        QStringLiteral("label"), QStringLiteral("name"), QStringLiteral("title")
    });
    record.type = firstStringValue(object, {
        QStringLiteral("type"), QStringLiteral("relation"), QStringLiteral("relationship"), QStringLiteral("linkType")
    });
    record.note = firstStringValue(object, {
        QStringLiteral("note"), QStringLiteral("notes"), QStringLiteral("description"), QStringLiteral("summary"),
        QStringLiteral("evidence"), QStringLiteral("details")
    });
    return record;
}

QJsonObject TopologyDocument::toJsonObject() const {
    QJsonArray nodesArray;
    for (const TopologyNodeRecord &node : nodes) {
        nodesArray.append(node.toJsonObject());
    }
    QJsonArray edgesArray;
    for (const TopologyEdgeRecord &edge : edges) {
        edgesArray.append(edge.toJsonObject());
    }
    return QJsonObject{
        {QStringLiteral("flowId"), flowId},
        {QStringLiteral("target"), target},
        {QStringLiteral("generatedAt"), generatedAt},
        {QStringLiteral("summary"), summary},
        {QStringLiteral("nodes"), nodesArray},
        {QStringLiteral("edges"), edgesArray},
    };
}

TopologyDocument TopologyDocument::fromJsonObject(const QJsonObject &object) {
    TopologyDocument document;
    const QJsonObject root = effectiveRootObject(object);
    document.flowId = firstStringValue(root, {
        QStringLiteral("flowId"), QStringLiteral("flow_id"), QStringLiteral("sourceFlowId"), QStringLiteral("source_flow_id")
    });
    document.target = firstStringValue(root, {
        QStringLiteral("target"), QStringLiteral("scope"), QStringLiteral("network"), QStringLiteral("cidr")
    });
    document.generatedAt = firstStringValue(root, {
        QStringLiteral("generatedAt"), QStringLiteral("generated_at"), QStringLiteral("createdAt"), QStringLiteral("created_at")
    });
    document.summary = firstStringValue(root, {
        QStringLiteral("summary"), QStringLiteral("description"), QStringLiteral("overview"), QStringLiteral("title")
    });
    const QJsonArray nodesArray = topologyNodesArray(root);
    for (const QJsonValue &value : nodesArray) {
        if (value.isObject()) {
            document.nodes.append(TopologyNodeRecord::fromJsonObject(value.toObject()));
        }
    }
    const QJsonArray edgesArray = topologyEdgesArray(root);
    for (const QJsonValue &value : edgesArray) {
        if (value.isObject()) {
            document.edges.append(TopologyEdgeRecord::fromJsonObject(value.toObject()));
        }
    }
    return document;
}
