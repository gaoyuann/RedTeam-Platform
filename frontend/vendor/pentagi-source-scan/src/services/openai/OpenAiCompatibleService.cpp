#include "OpenAiCompatibleService.h"

#include "network/HttpClient.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUrl>

OpenAiCompatibleService::OpenAiCompatibleService(QObject *parent)
    : QObject(parent),
      m_httpClient(new HttpClient(this)) {
    // Local 27B models can need several minutes for a large report, but the
    // client should still stop eventually if the endpoint is unavailable.
    m_httpClient->setTimeoutMs(900000);
}

void OpenAiCompatibleService::setConfig(const OpenAiCompatibleConfig &config) {
    m_config = config;
    m_httpClient->setBearerToken(config.apiKey);
}

void OpenAiCompatibleService::setCancellationFlag(const std::atomic_bool *cancelFlag) {
    m_httpClient->setCancellationFlag(cancelFlag);
}

OpenAiChatResult OpenAiCompatibleService::testChatCompletion(const QString &prompt) {
    return chatCompletion(QString(), prompt);
}

OpenAiChatResult OpenAiCompatibleService::chatCompletion(const QString &systemPrompt,
                                                          const QString &userPrompt,
                                                          const std::atomic_bool *cancelFlag) {
    OpenAiChatResult result;

    const QString baseUrl = m_config.baseUrl.trimmed();
    if (baseUrl.isEmpty() || m_config.model.trimmed().isEmpty() || m_config.apiKey.trimmed().isEmpty()) {
        result.errorMessage = QStringLiteral("请先填写 OpenAI 兼容接口的基础地址、模型名称和接口密钥。");
        return result;
    }

    QUrl url(baseUrl);
    QString normalizedPath = url.path();
    if (!normalizedPath.endsWith(QStringLiteral("/chat/completions"))) {
        normalizedPath = normalizedPath.replace(QRegularExpression("/+$"), QString());
        if (!normalizedPath.endsWith(QStringLiteral("/v1"))) {
            normalizedPath += QStringLiteral("/v1");
        }
        normalizedPath += QStringLiteral("/chat/completions");
        url.setPath(normalizedPath);
    }

    QJsonObject payload;
    payload.insert(QStringLiteral("model"), m_config.model);
    payload.insert(QStringLiteral("stream"), false);
    payload.insert(QStringLiteral("max_tokens"), 8192);
    // This is a llama.cpp-specific option. Keep it local so ordinary OpenAI
    // compatible providers are not sent an unknown request field.
    const QString host = url.host().toLower();
    if (host == QStringLiteral("127.0.0.1")
        || host == QStringLiteral("localhost")
        || host == QStringLiteral("::1")
        || host.startsWith(QStringLiteral("172.20."))) {
        // Disabling hidden chain-of-thought keeps Qwen structured JSON bounded
        // and puts the useful result in message.content.
        payload.insert(QStringLiteral("chat_template_kwargs"), QJsonObject{
            {QStringLiteral("enable_thinking"), false},
        });
    }

    QJsonArray messages;
    if (!systemPrompt.trimmed().isEmpty()) {
        messages.append(QJsonObject{
            {QStringLiteral("role"), QStringLiteral("system")},
            {QStringLiteral("content"), systemPrompt},
        });
    }
    messages.append(QJsonObject{
        {QStringLiteral("role"), QStringLiteral("user")},
        {QStringLiteral("content"), userPrompt},
    });
    payload.insert(QStringLiteral("messages"), messages);

    QString errorMessage;
    const QJsonDocument response = m_httpClient->postJson(url, QJsonDocument(payload), &errorMessage, cancelFlag);
    if (response.isNull()) {
        result.errorMessage = errorMessage;
        return result;
    }

    result.rawResponse = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
    const QJsonObject root = response.object();
    const QJsonArray choices = root.value(QStringLiteral("choices")).toArray();
    if (choices.isEmpty()) {
        result.errorMessage = QStringLiteral("OpenAI 兼容接口未返回 choices。");
        return result;
    }

    const QJsonObject firstChoice = choices.first().toObject();
    const QJsonObject message = firstChoice.value(QStringLiteral("message")).toObject();
    result.content = message.value(QStringLiteral("content")).toString();
    result.model = root.value(QStringLiteral("model")).toString();
    result.success = !result.content.trimmed().isEmpty();
    if (!result.success) {
        result.errorMessage = QStringLiteral("OpenAI 兼容接口返回成功，但消息内容为空。");
    }
    return result;
}
