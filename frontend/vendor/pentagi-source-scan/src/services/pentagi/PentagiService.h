#pragma once

#include "config/AppConfig.h"
#include "models/FlowTypes.h"

#include <QObject>

#include <atomic>

class HttpClient;

struct PentagiConnectionInfo {
    bool success = false;
    QString message;
    QString userName;
    QString userRole;
    QString rawResponse;
};

struct PentagiTokenItem {
    QString tokenId;
    QString name;
    int ttl = 0;
    QString status;
    QString createdAt;
};

struct PentagiCreateTokenResult {
    bool success = false;
    QString message;
    QString plainToken;
    PentagiTokenItem token;
};

struct PentagiProviderItem {
    QString id;
    QString name;
    QString type;
    QString model;

    QString providerKey() const {
        return type.trimmed().isEmpty() ? name.trimmed() : QStringLiteral("%1:%2").arg(type.trimmed(), name.trimmed());
    }
};

class PentagiService : public QObject {
    Q_OBJECT

public:
    explicit PentagiService(QObject *parent = nullptr);

    static QString defaultModelProviderValue();

    void setConfig(const PentagiConfig &config);
    void setRequestTimeoutMs(int timeoutMs);
    void setCancellationFlag(const std::atomic_bool *cancelFlag);
    PentagiConnectionInfo testConnection();
    FlowRecord createFlow(const QString &modelProvider, const QString &input, QString *errorMessage = nullptr);
    FlowRecord createFlowWithConfiguredProvider(const QString &input, QString *errorMessage = nullptr);
    bool putUserInput(const QString &flowId, const QString &input, const QString &modelProvider, QString *errorMessage = nullptr);
    bool putUserInputWithConfiguredProvider(const QString &flowId, const QString &input, QString *errorMessage = nullptr);
    QList<FlowRecord> listFlows(QString *errorMessage = nullptr);
    FlowRecord getFlow(const QString &flowId, QString *errorMessage = nullptr);
    QList<PentagiProviderItem> listModelProviders(QString *errorMessage = nullptr);
    QList<FlowAssistantRecord> listAssistants(const QString &flowId, QString *errorMessage = nullptr);
    FlowAssistantRecord createAssistant(const QString &flowId,
                                        const QString &modelProvider,
                                        const QString &input,
                                        bool useAgents,
                                        QString *errorMessage = nullptr,
                                        const std::atomic_bool *cancelFlag = nullptr);
    bool callAssistant(const QString &flowId,
                       const QString &assistantId,
                       const QString &input,
                       bool useAgents,
                       QString *errorMessage = nullptr);
    QList<FlowAssistantLogRecord> listAssistantLogs(const QString &flowId,
                                                    const QString &assistantId,
                                                    QString *errorMessage = nullptr);
    bool stopAssistant(const QString &flowId, const QString &assistantId, QString *errorMessage = nullptr);
    FlowReportRecord fetchFlowReport(const QString &flowId, QString *errorMessage = nullptr);
    bool stopFlow(const QString &flowId, QString *errorMessage = nullptr);
    bool finishFlow(const QString &flowId, QString *errorMessage = nullptr);
    bool deleteFlowById(const QString &flowId, QString *errorMessage = nullptr);
    QList<PentagiTokenItem> listApiTokens(QString *errorMessage = nullptr);
    PentagiCreateTokenResult createApiToken(const QString &name, int ttl);
    bool deleteApiToken(const QString &tokenId, QString *errorMessage = nullptr);
    bool updateApiTokenStatus(const QString &tokenId, const QString &status, QString *errorMessage = nullptr);

private:
    QUrl buildRestUrl(const QString &path) const;
    QUrl buildGraphqlUrl() const;
    QUrl buildApiTokensUrl() const;

    HttpClient *m_httpClient;
    PentagiConfig m_config;
};
