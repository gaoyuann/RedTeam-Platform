#pragma once

#include <QString>
#include <QVariantMap>

struct PentagiConfig {
    QString graphqlUrl;
    QString restUrl;
    QString apiToken;
    QString modelProvider;
};

struct GraphServiceConfig {
    QString baseUrl;
};

struct OpenAiCompatibleConfig {
    QString baseUrl;
    QString model;
    QString apiKey;
    int contextLength;
};

struct ReportConfig {
    QString exportDirectory;
};

struct AppConfig {
    PentagiConfig pentagi;
    GraphServiceConfig graphService;
    OpenAiCompatibleConfig openaiCompatible;
    ReportConfig reports;

    static AppConfig fromVariantMap(const QVariantMap &map);
    QVariantMap toVariantMap() const;
};
