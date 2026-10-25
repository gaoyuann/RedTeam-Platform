#include "AppConfig.h"

namespace {
QVariantMap mapValue(const QVariantMap &map, const QString &key) {
    return map.value(key).toMap();
}
}

AppConfig AppConfig::fromVariantMap(const QVariantMap &map) {
    AppConfig config;

    const QVariantMap pentagiMap = mapValue(map, QStringLiteral("pentagi"));
    config.pentagi.graphqlUrl = pentagiMap.value(
        QStringLiteral("graphqlUrl"),
        QStringLiteral("http://127.0.0.1:8443/api/v1/graphql")).toString();
    config.pentagi.restUrl = pentagiMap.value(
        QStringLiteral("restUrl"),
        QStringLiteral("http://127.0.0.1:8443/api/v1")).toString();
    config.pentagi.apiToken = pentagiMap.value(QStringLiteral("apiToken")).toString();
    config.pentagi.modelProvider = pentagiMap.value(QStringLiteral("modelProvider"), QStringLiteral("openai:default")).toString();

    const QVariantMap graphMap = mapValue(map, QStringLiteral("graphService"));
    config.graphService.baseUrl = graphMap.value(
        QStringLiteral("baseUrl"),
        QStringLiteral("http://127.0.0.1:8013")).toString();

    const QVariantMap openaiMap = mapValue(map, QStringLiteral("openaiCompatible"));
    config.openaiCompatible.baseUrl = openaiMap.value(
        QStringLiteral("baseUrl"),
        QStringLiteral("https://api.openai.com/v1")).toString();
    config.openaiCompatible.model = openaiMap.value(
        QStringLiteral("model"),
        QStringLiteral("gpt-4o-mini")).toString();
    config.openaiCompatible.apiKey = openaiMap.value(QStringLiteral("apiKey")).toString();
    config.openaiCompatible.contextLength = openaiMap.value(QStringLiteral("contextLength"), 8192).toInt();

    const QVariantMap reportMap = mapValue(map, QStringLiteral("reports"));
    config.reports.exportDirectory = reportMap.value(QStringLiteral("exportDirectory"), QStringLiteral("exports")).toString();

    return config;
}

QVariantMap AppConfig::toVariantMap() const {
    QVariantMap map;

    QVariantMap pentagiMap;
    pentagiMap.insert(QStringLiteral("graphqlUrl"), pentagi.graphqlUrl);
    pentagiMap.insert(QStringLiteral("restUrl"), pentagi.restUrl);
    pentagiMap.insert(QStringLiteral("apiToken"), pentagi.apiToken);
    pentagiMap.insert(QStringLiteral("modelProvider"), pentagi.modelProvider);
    map.insert(QStringLiteral("pentagi"), pentagiMap);

    QVariantMap graphMap;
    graphMap.insert(QStringLiteral("baseUrl"), graphService.baseUrl);
    map.insert(QStringLiteral("graphService"), graphMap);

    QVariantMap openaiMap;
    openaiMap.insert(QStringLiteral("baseUrl"), openaiCompatible.baseUrl);
    openaiMap.insert(QStringLiteral("model"), openaiCompatible.model);
    openaiMap.insert(QStringLiteral("apiKey"), openaiCompatible.apiKey);
    openaiMap.insert(QStringLiteral("contextLength"), openaiCompatible.contextLength);
    map.insert(QStringLiteral("openaiCompatible"), openaiMap);

    QVariantMap reportMap;
    reportMap.insert(QStringLiteral("exportDirectory"), reports.exportDirectory);
    map.insert(QStringLiteral("reports"), reportMap);

    return map;
}
