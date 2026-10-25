#pragma once

#include "config/AppConfig.h"
#include "models/OpenAiTypes.h"

#include <QObject>

#include <atomic>

class HttpClient;

class OpenAiCompatibleService : public QObject {
    Q_OBJECT

public:
    explicit OpenAiCompatibleService(QObject *parent = nullptr);

    void setConfig(const OpenAiCompatibleConfig &config);
    void setCancellationFlag(const std::atomic_bool *cancelFlag);
    OpenAiChatResult testChatCompletion(const QString &prompt);
    OpenAiChatResult chatCompletion(const QString &systemPrompt,
                                    const QString &userPrompt,
                                    const std::atomic_bool *cancelFlag = nullptr);

private:
    HttpClient *m_httpClient;
    OpenAiCompatibleConfig m_config;
};
