#include "PentagiService.h"

#include "network/HttpClient.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <algorithm>

namespace {
// Local Qwen inference can take several minutes for a long PentAGI context.
// Keep the HTTP request alive long enough for the backend to finish instead
// of cancelling the worker at the old three-minute limit.
constexpr int kInteractiveRequestTimeoutMs = 600000;

QString ensureLeadingSlash(const QString &path) {
    return path.startsWith('/') ? path : QStringLiteral("/") + path;
}

const char *kFrontendEduDefaultProvider = "openai:default";

PentagiTokenItem parseTokenItem(const QJsonObject &object) {
    PentagiTokenItem item;
    item.tokenId = object.value(QStringLiteral("token_id")).toString(object.value(QStringLiteral("tokenId")).toString());
    item.name = object.value(QStringLiteral("name")).toString();
    item.ttl = object.value(QStringLiteral("ttl")).toInt();
    item.status = object.value(QStringLiteral("status")).toString();
    item.createdAt = object.value(QStringLiteral("created_at")).toString(object.value(QStringLiteral("createdAt")).toString());
    return item;
}

QString firstNonEmptyModel(const QJsonObject &agentsObject) {
    const QStringList agentKeys{
        QStringLiteral("assistant"),
        QStringLiteral("primaryAgent"),
        QStringLiteral("pentester"),
        QStringLiteral("searcher"),
        QStringLiteral("coder"),
        QStringLiteral("installer"),
    };
    for (const QString &key : agentKeys) {
        const QString model = agentsObject.value(key).toObject().value(QStringLiteral("model")).toString().trimmed();
        if (!model.isEmpty()) {
            return model;
        }
    }
    return QString();
}

PentagiProviderItem parseProviderItem(const QJsonObject &object) {
    PentagiProviderItem item;
    item.id = object.value(QStringLiteral("id")).toVariant().toString();
    item.name = object.value(QStringLiteral("name")).toString();
    item.type = object.value(QStringLiteral("type")).toString();
    item.model = firstNonEmptyModel(object.value(QStringLiteral("agents")).toObject());
    return item;
}

FlowRecord parseFlowRecord(const QJsonObject &object) {
    FlowRecord flow;
    flow.id = object.value(QStringLiteral("id")).toVariant().toString();
    flow.title = object.value(QStringLiteral("title")).toString();
    flow.status = object.value(QStringLiteral("status")).toString();
    flow.createdAt = object.value(QStringLiteral("createdAt")).toString();
    flow.updatedAt = object.value(QStringLiteral("updatedAt")).toString();

    const QJsonArray terminals = object.value(QStringLiteral("terminals")).toArray();
    for (const QJsonValue &terminalValue : terminals) {
        const QJsonObject terminalObject = terminalValue.toObject();
        FlowTerminalRecord terminal;
        terminal.id = terminalObject.value(QStringLiteral("id")).toVariant().toString();
        terminal.type = terminalObject.value(QStringLiteral("type")).toString();
        terminal.name = terminalObject.value(QStringLiteral("name")).toString();
        terminal.image = terminalObject.value(QStringLiteral("image")).toString();
        terminal.connected = terminalObject.value(QStringLiteral("connected")).toBool();
        terminal.createdAt = terminalObject.value(QStringLiteral("createdAt")).toString();
        flow.terminals.append(terminal);
    }

    const QJsonObject providerObject = object.value(QStringLiteral("provider")).toObject();
    flow.provider.name = providerObject.value(QStringLiteral("name")).toString();
    flow.provider.type = providerObject.value(QStringLiteral("type")).toString();
    return flow;
}

FlowAssistantRecord parseAssistantRecord(const QJsonObject &object) {
    FlowAssistantRecord assistant;
    assistant.id = object.value(QStringLiteral("id")).toVariant().toString();
    assistant.title = object.value(QStringLiteral("title")).toString();
    assistant.status = object.value(QStringLiteral("status")).toString();
    assistant.flowId = object.value(QStringLiteral("flowId")).toVariant().toString();
    assistant.useAgents = object.value(QStringLiteral("useAgents")).toBool();
    assistant.createdAt = object.value(QStringLiteral("createdAt")).toString();
    assistant.updatedAt = object.value(QStringLiteral("updatedAt")).toString();
    const QJsonObject provider = object.value(QStringLiteral("provider")).toObject();
    assistant.provider.name = provider.value(QStringLiteral("name")).toString();
    assistant.provider.type = provider.value(QStringLiteral("type")).toString();
    return assistant;
}

FlowAssistantLogRecord parseAssistantLogRecord(const QJsonObject &object) {
    FlowAssistantLogRecord log;
    log.id = object.value(QStringLiteral("id")).toVariant().toString();
    log.type = object.value(QStringLiteral("type")).toString();
    log.message = object.value(QStringLiteral("message")).toString();
    log.thinking = object.value(QStringLiteral("thinking")).toString();
    log.result = object.value(QStringLiteral("result")).toString();
    log.resultFormat = object.value(QStringLiteral("resultFormat")).toString();
    log.appendPart = object.value(QStringLiteral("appendPart")).toBool();
    log.flowId = object.value(QStringLiteral("flowId")).toVariant().toString();
    log.assistantId = object.value(QStringLiteral("assistantId")).toVariant().toString();
    log.createdAt = object.value(QStringLiteral("createdAt")).toString();
    return log;
}

FlowSubtaskRecord parseSubtaskRecord(const QJsonObject &object) {
    FlowSubtaskRecord subtask;
    subtask.id = object.value(QStringLiteral("id")).toVariant().toString();
    subtask.status = object.value(QStringLiteral("status")).toString();
    subtask.title = object.value(QStringLiteral("title")).toString();
    subtask.description = object.value(QStringLiteral("description")).toString();
    subtask.result = object.value(QStringLiteral("result")).toString();
    subtask.taskId = object.value(QStringLiteral("taskId")).toVariant().toString();
    subtask.createdAt = object.value(QStringLiteral("createdAt")).toString();
    subtask.updatedAt = object.value(QStringLiteral("updatedAt")).toString();
    return subtask;
}

FlowTaskRecord parseTaskRecord(const QJsonObject &object) {
    FlowTaskRecord task;
    task.id = object.value(QStringLiteral("id")).toVariant().toString();
    task.title = object.value(QStringLiteral("title")).toString();
    task.status = object.value(QStringLiteral("status")).toString();
    task.input = object.value(QStringLiteral("input")).toString();
    task.result = object.value(QStringLiteral("result")).toString();
    task.flowId = object.value(QStringLiteral("flowId")).toVariant().toString();
    task.createdAt = object.value(QStringLiteral("createdAt")).toString();
    task.updatedAt = object.value(QStringLiteral("updatedAt")).toString();

    const QJsonArray subtasks = object.value(QStringLiteral("subtasks")).toArray();
    for (const QJsonValue &subtaskValue : subtasks) {
        task.subtasks.append(parseSubtaskRecord(subtaskValue.toObject()));
    }
    return task;
}

FlowScreenshotRecord parseScreenshotRecord(const QJsonObject &object) {
    FlowScreenshotRecord screenshot;
    screenshot.id = object.value(QStringLiteral("id")).toVariant().toString();
    screenshot.flowId = object.value(QStringLiteral("flowId")).toVariant().toString();
    screenshot.taskId = object.value(QStringLiteral("taskId")).toVariant().toString();
    screenshot.subtaskId = object.value(QStringLiteral("subtaskId")).toVariant().toString();
    screenshot.name = object.value(QStringLiteral("name")).toString();
    screenshot.url = object.value(QStringLiteral("url")).toString();
    screenshot.createdAt = object.value(QStringLiteral("createdAt")).toString();
    return screenshot;
}

int flowStatusRank(const QString &status) {
    if (status == QStringLiteral("running")) {
        return 0;
    }
    if (status == QStringLiteral("waiting")) {
        return 1;
    }
    if (status == QStringLiteral("created")) {
        return 2;
    }
    if (status == QStringLiteral("failed")) {
        return 3;
    }
    if (status == QStringLiteral("finished")) {
        return 4;
    }
    return 5;
}
}

PentagiService::PentagiService(QObject *parent)
    : QObject(parent),
      m_httpClient(new HttpClient(this)) {
}

QString PentagiService::defaultModelProviderValue() {
    return QString::fromLatin1(kFrontendEduDefaultProvider);
}

void PentagiService::setConfig(const PentagiConfig &config) {
    m_config = config;
    m_httpClient->setBearerToken(config.apiToken);
}

void PentagiService::setRequestTimeoutMs(int timeoutMs) {
    m_httpClient->setTimeoutMs(timeoutMs);
}

void PentagiService::setCancellationFlag(const std::atomic_bool *cancelFlag) {
    m_httpClient->setCancellationFlag(cancelFlag);
}

FlowRecord PentagiService::createFlow(const QString &modelProvider, const QString &input, QString *errorMessage) {
    FlowRecord flow;
    if (m_config.graphqlUrl.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("请先填写 PentAGI GraphQL 地址。");
        }
        return flow;
    }
    if (modelProvider.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("模型提供方不能为空。");
        }
        return flow;
    }
    if (input.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("任务输入内容不能为空。");
        }
        return flow;
    }

    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("CreateFlow")},
        {QStringLiteral("query"),
         QStringLiteral("mutation CreateFlow($modelProvider: String!, $input: String!) { createFlow(modelProvider: $modelProvider, input: $input) { id title status createdAt updatedAt terminals { id type name image connected createdAt } provider { name type } } }")},
        {QStringLiteral("variables"),
         QJsonObject{
             {QStringLiteral("modelProvider"), modelProvider.trimmed()},
             {QStringLiteral("input"), input},
         }},
    };
    const int previousTimeoutMs = m_httpClient->timeoutMs();
    // Creating a flow also starts its worker/container on the PentAGI side.
    // Cold starts can take longer than two minutes, so do not cancel the
    // mutation while the backend is still provisioning the worker.
    m_httpClient->setTimeoutMs(qMax(previousTimeoutMs, 300000));
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    m_httpClient->setTimeoutMs(previousTimeoutMs);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage
                            + QStringLiteral("\n提示：PentAGI 创建任务有时会超过默认等待时间。请先点击“刷新任务”确认是否已创建成功；如未创建，可稍后重试。");
        }
        return flow;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return flow;
    }

    flow = parseFlowRecord(root.value(QStringLiteral("data")).toObject().value(QStringLiteral("createFlow")).toObject());
    if (flow.id.isEmpty() && errorMessage) {
        *errorMessage = QStringLiteral("创建任务请求返回成功，但未获得有效的任务编号。");
    }
    return flow;
}

FlowRecord PentagiService::createFlowWithConfiguredProvider(const QString &input, QString *errorMessage) {
    const QString modelProvider = m_config.modelProvider.trimmed().isEmpty()
                                      ? defaultModelProviderValue()
                                      : m_config.modelProvider.trimmed();
    return createFlow(modelProvider, input, errorMessage);
}

bool PentagiService::putUserInput(const QString &flowId, const QString &input, const QString &modelProvider, QString *errorMessage) {
    if (m_config.graphqlUrl.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("请先填写 PentAGI GraphQL 地址。");
        }
        return false;
    }
    if (flowId.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("任务编号不能为空。");
        }
        return false;
    }
    if (input.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("继续输入内容不能为空。");
        }
        return false;
    }

    QString localErrorMessage;
    QJsonObject variables{
        {QStringLiteral("flowId"), flowId.trimmed()},
        {QStringLiteral("input"), input},
    };
    if (!modelProvider.trimmed().isEmpty()) {
        variables.insert(QStringLiteral("modelProvider"), modelProvider.trimmed());
    }

    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("PutUserInput")},
        {QStringLiteral("query"),
         QStringLiteral("mutation PutUserInput($flowId: ID!, $input: String!, $modelProvider: String) { putUserInput(flowId: $flowId, input: $input, modelProvider: $modelProvider) }")},
        {QStringLiteral("variables"), variables},
    };
    const int previousTimeoutMs = m_httpClient->timeoutMs();
    m_httpClient->setTimeoutMs(qMax(previousTimeoutMs, kInteractiveRequestTimeoutMs));
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    m_httpClient->setTimeoutMs(previousTimeoutMs);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return false;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return false;
    }

    const QString result = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("putUserInput")).toString();
    if (result != QStringLiteral("success")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("后端未确认已接收继续指令。");
        }
        return false;
    }
    return true;
}

bool PentagiService::putUserInputWithConfiguredProvider(const QString &flowId, const QString &input, QString *errorMessage) {
    const QString modelProvider = m_config.modelProvider.trimmed().isEmpty()
                                      ? defaultModelProviderValue()
                                      : m_config.modelProvider.trimmed();
    return putUserInput(flowId, input, modelProvider, errorMessage);
}

PentagiConnectionInfo PentagiService::testConnection() {
    PentagiConnectionInfo info;

    const QString graphqlUrl = m_config.graphqlUrl.trimmed();
    if (graphqlUrl.isEmpty()) {
        info.message = QStringLiteral("请先填写 PentAGI GraphQL 地址。");
        return info;
    }

    QString errorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("GetSettings")},
        {QStringLiteral("query"), QStringLiteral("query GetSettings { settings { debug askUser dockerInside assistantUseAgents } }")},
        {QStringLiteral("variables"), QJsonObject()},
    };
    const QJsonDocument graphqlResponse = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &errorMessage);
    if (graphqlResponse.isNull()) {
        info.message = errorMessage;
        return info;
    }

    const QJsonDocument userResponse = m_httpClient->getJson(buildRestUrl(QStringLiteral("/user/")), &errorMessage);
    info.rawResponse = QString::fromUtf8(graphqlResponse.toJson(QJsonDocument::Indented));

    if (!userResponse.isNull()) {
        const QJsonObject userRoot = userResponse.object().value(QStringLiteral("data")).toObject();
        info.userName = userRoot.value(QStringLiteral("name")).toString();
        info.userRole = userRoot.value(QStringLiteral("role")).toObject().value(QStringLiteral("name")).toString();
    }

    const QJsonObject root = graphqlResponse.object();
    if (root.contains(QStringLiteral("errors"))) {
        info.message = QStringLiteral("GraphQL 接口返回错误，请检查地址或接口密钥。");
        return info;
    }

    info.success = true;
    info.message = info.userName.isEmpty()
                       ? QStringLiteral("已成功连接 PentAGI GraphQL。")
                       : QStringLiteral("已连接 PentAGI，当前用户：%1").arg(info.userName);
    return info;
}

QList<FlowRecord> PentagiService::listFlows(QString *errorMessage) {
    QList<FlowRecord> flows;
    if (m_config.graphqlUrl.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("请先填写 PentAGI GraphQL 地址。");
        }
        return flows;
    }

    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("GetFlows")},
        {QStringLiteral("query"),
         QStringLiteral("query GetFlows { flows { id title status createdAt updatedAt terminals { id type name image connected createdAt } provider { name type } } }")},
        {QStringLiteral("variables"), QJsonObject()},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return flows;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return flows;
    }

    const QJsonArray flowArray = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("flows")).toArray();
    for (const QJsonValue &flowValue : flowArray) {
        flows.append(parseFlowRecord(flowValue.toObject()));
    }

    std::sort(flows.begin(), flows.end(), [](const FlowRecord &left, const FlowRecord &right) {
        const int rankDiff = flowStatusRank(left.status) - flowStatusRank(right.status);
        if (rankDiff != 0) {
            return rankDiff < 0;
        }
        return left.updatedAt > right.updatedAt;
    });
    return flows;
}

FlowRecord PentagiService::getFlow(const QString &flowId, QString *errorMessage) {
    if (errorMessage) errorMessage->clear();
    if (m_config.graphqlUrl.trimmed().isEmpty() || flowId.trimmed().isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("请先填写 PentAGI GraphQL 地址和 Flow ID。");
        return {};
    }
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("GetFlow")},
        {QStringLiteral("query"), QStringLiteral("query GetFlow($id: ID!) { flow(flowId: $id) { id title status createdAt updatedAt } }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("id"), flowId}}},
    };
    const auto response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), errorMessage);
    if (response.isNull()) return {};
    const auto root = response.object();
    if (!root.value(QStringLiteral("errors")).toArray().isEmpty()) {
        if (errorMessage) *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        return {};
    }
    const auto data = root.value(QStringLiteral("data")).toObject();
    const auto value = data.value(QStringLiteral("flow"));
    if (!data.contains(QStringLiteral("flow")) || (!value.isNull() && !value.isObject())) {
        if (errorMessage) *errorMessage = QStringLiteral("Flow 查询响应格式异常，无法确认任务状态。");
        return {};
    }
    if (value.isNull()) return {}; // A successful query explicitly returned no accessible Flow.
    const auto flow = parseFlowRecord(value.toObject());
    if (flow.id != flowId && errorMessage)
        *errorMessage = QStringLiteral("Flow 查询返回的 ID 与请求不一致，无法确认任务状态。");
    return flow.id == flowId ? flow : FlowRecord{};
}

QList<PentagiProviderItem> PentagiService::listModelProviders(QString *errorMessage) {
    QList<PentagiProviderItem> providers;
    if (m_config.graphqlUrl.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("请先填写 PentAGI GraphQL 地址。");
        }
        return providers;
    }

    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("GetSettingsProviders")},
        {QStringLiteral("query"),
         QStringLiteral("query GetSettingsProviders { settingsProviders { enabled { openai anthropic gemini bedrock ollama custom deepseek glm kimi qwen } userDefined { id name type agents { assistant { model } primaryAgent { model } pentester { model } searcher { model } coder { model } installer { model } } } } }")},
        {QStringLiteral("variables"), QJsonObject()},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return providers;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return providers;
    }

    const QJsonObject settingsProviders = root.value(QStringLiteral("data"))
                                              .toObject()
                                              .value(QStringLiteral("settingsProviders"))
                                              .toObject();
    const QJsonObject enabledProviders = settingsProviders.value(QStringLiteral("enabled")).toObject();
    const QStringList providerTypes{
        QStringLiteral("openai"), QStringLiteral("anthropic"), QStringLiteral("gemini"),
        QStringLiteral("bedrock"), QStringLiteral("ollama"), QStringLiteral("custom"),
        QStringLiteral("deepseek"), QStringLiteral("glm"), QStringLiteral("kimi"), QStringLiteral("qwen"),
    };
    for (const QString &type : providerTypes) {
        if (!enabledProviders.value(type).toBool()) {
            continue;
        }
        PentagiProviderItem item;
        item.id = QStringLiteral("builtin-default:%1").arg(type);
        item.name = QStringLiteral("default");
        item.type = type;
        providers.append(item);
    }

    const QJsonArray providerArray = settingsProviders.value(QStringLiteral("userDefined")).toArray();
    for (const QJsonValue &providerValue : providerArray) {
        const PentagiProviderItem item = parseProviderItem(providerValue.toObject());
        if (!item.name.trimmed().isEmpty()) {
            for (int index = providers.size() - 1; index >= 0; --index) {
                if (providers.at(index).providerKey() == item.providerKey()) {
                    providers.removeAt(index);
                }
            }
            providers.append(item);
        }
    }

    std::sort(providers.begin(), providers.end(), [](const PentagiProviderItem &left, const PentagiProviderItem &right) {
        if (left.type == right.type) {
            return left.name < right.name;
        }
        return left.type < right.type;
    });
    return providers;
}

QList<FlowAssistantRecord> PentagiService::listAssistants(const QString &flowId, QString *errorMessage) {
    QList<FlowAssistantRecord> assistants;
    if (flowId.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("任务编号不能为空。");
        }
        return assistants;
    }
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("GetAssistants")},
        {QStringLiteral("query"), QStringLiteral("query GetAssistants($flowId: ID!) { assistants(flowId: $flowId) { id title status flowId useAgents createdAt updatedAt provider { name type } } }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId.trimmed()}}},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return assistants;
    }
    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return assistants;
    }
    const QJsonArray values = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("assistants")).toArray();
    for (const QJsonValue &value : values) {
        const FlowAssistantRecord assistant = parseAssistantRecord(value.toObject());
        if (!assistant.id.isEmpty()) {
            assistants.append(assistant);
        }
    }
    return assistants;
}

FlowAssistantRecord PentagiService::createAssistant(const QString &flowId,
                                                    const QString &modelProvider,
                                                    const QString &input,
                                                    bool useAgents,
                                                    QString *errorMessage,
                                                    const std::atomic_bool *cancelFlag) {
    FlowAssistantRecord assistant;
    if (flowId.trimmed().isEmpty() || input.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("任务编号和 Assistant 输入不能为空。");
        }
        return assistant;
    }
    if (modelProvider.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("PentAGI 模型提供方未配置，请先在设置中选择 Provider。");
        }
        return assistant;
    }
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("CreateAssistant")},
        {QStringLiteral("query"), QStringLiteral("mutation CreateAssistant($flowId: ID!, $modelProvider: String!, $input: String!, $useAgents: Boolean!) { createAssistant(flowId: $flowId, modelProvider: $modelProvider, input: $input, useAgents: $useAgents) { assistant { id title status flowId useAgents createdAt updatedAt provider { name type } } } }")},
        {QStringLiteral("variables"), QJsonObject{
            {QStringLiteral("flowId"), flowId.trimmed()},
            {QStringLiteral("modelProvider"), modelProvider.trimmed()},
            {QStringLiteral("input"), input},
            {QStringLiteral("useAgents"), useAgents},
        }},
    };
    const int previousTimeoutMs = m_httpClient->timeoutMs();
    m_httpClient->setTimeoutMs(qMax(previousTimeoutMs, kInteractiveRequestTimeoutMs));
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage, cancelFlag);
    m_httpClient->setTimeoutMs(previousTimeoutMs);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return assistant;
    }
    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return assistant;
    }
    assistant = parseAssistantRecord(root.value(QStringLiteral("data")).toObject()
                                         .value(QStringLiteral("createAssistant")).toObject()
                                         .value(QStringLiteral("assistant")).toObject());
    if (assistant.id.isEmpty() && errorMessage) {
        *errorMessage = QStringLiteral("创建 Assistant 成功但未返回编号。");
    }
    return assistant;
}

bool PentagiService::callAssistant(const QString &flowId,
                                   const QString &assistantId,
                                   const QString &input,
                                   bool useAgents,
                                   QString *errorMessage) {
    if (flowId.trimmed().isEmpty() || assistantId.trimmed().isEmpty() || input.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Flow、Assistant 和输入内容不能为空。");
        }
        return false;
    }
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("CallAssistant")},
        {QStringLiteral("query"), QStringLiteral("mutation CallAssistant($flowId: ID!, $assistantId: ID!, $input: String!, $useAgents: Boolean!) { callAssistant(flowId: $flowId, assistantId: $assistantId, input: $input, useAgents: $useAgents) }")},
        {QStringLiteral("variables"), QJsonObject{
            {QStringLiteral("flowId"), flowId.trimmed()},
            {QStringLiteral("assistantId"), assistantId.trimmed()},
            {QStringLiteral("input"), input},
            {QStringLiteral("useAgents"), useAgents},
        }},
    };
    const int previousTimeoutMs = m_httpClient->timeoutMs();
    m_httpClient->setTimeoutMs(qMax(previousTimeoutMs, kInteractiveRequestTimeoutMs));
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    m_httpClient->setTimeoutMs(previousTimeoutMs);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return false;
    }
    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return false;
    }
    const QString result = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("callAssistant")).toString();
    if (result != QStringLiteral("success")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("后端未确认 Assistant 已接收请求。");
        }
        return false;
    }
    return true;
}

QList<FlowAssistantLogRecord> PentagiService::listAssistantLogs(const QString &flowId,
                                                                const QString &assistantId,
                                                                QString *errorMessage) {
    QList<FlowAssistantLogRecord> logs;
    if (flowId.trimmed().isEmpty() || assistantId.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Flow 和 Assistant 编号不能为空。");
        }
        return logs;
    }
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("GetAssistantLogs")},
        {QStringLiteral("query"), QStringLiteral("query GetAssistantLogs($flowId: ID!, $assistantId: ID!) { assistantLogs(flowId: $flowId, assistantId: $assistantId) { id type message thinking result resultFormat appendPart flowId assistantId createdAt } }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId.trimmed()}, {QStringLiteral("assistantId"), assistantId.trimmed()}}},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return logs;
    }
    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return logs;
    }
    const QJsonArray values = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("assistantLogs")).toArray();
    for (const QJsonValue &value : values) {
        logs.append(parseAssistantLogRecord(value.toObject()));
    }
    return logs;
}

bool PentagiService::stopAssistant(const QString &flowId, const QString &assistantId, QString *errorMessage) {
    if (flowId.trimmed().isEmpty() || assistantId.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Flow 和 Assistant 编号不能为空。");
        }
        return false;
    }
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("StopAssistant")},
        {QStringLiteral("query"), QStringLiteral("mutation StopAssistant($flowId: ID!, $assistantId: ID!) { stopAssistant(flowId: $flowId, assistantId: $assistantId) { id status } }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId.trimmed()}, {QStringLiteral("assistantId"), assistantId.trimmed()}}},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return false;
    }
    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return false;
    }
    const QJsonObject stopped = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("stopAssistant")).toObject();
    if (stopped.isEmpty() && errorMessage) {
        *errorMessage = QStringLiteral("后端未返回 Assistant 停止状态。");
    }
    return !stopped.isEmpty();
}

FlowReportRecord PentagiService::fetchFlowReport(const QString &flowId, QString *errorMessage) {
    FlowReportRecord report;
    if (flowId.trimmed().isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("任务编号不能为空。");
        }
        return report;
    }

    QString localErrorMessage;
    const QJsonObject detailsPayload{
        {QStringLiteral("operationName"), QStringLiteral("GetFlowDetails")},
        {QStringLiteral("query"),
         QStringLiteral("query GetFlowDetails($id: ID!) { flow(flowId: $id) { id title status createdAt updatedAt terminals { id type name image connected createdAt } provider { name type } } tasks(flowId: $id) { id title status input result flowId subtasks { id status title description result taskId createdAt updatedAt } createdAt updatedAt } screenshots(flowId: $id) { id flowId taskId subtaskId name url createdAt } }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("id"), flowId}}},
    };
    const int previousTimeoutMs = m_httpClient->timeoutMs();
    m_httpClient->setTimeoutMs(qMax(previousTimeoutMs, kInteractiveRequestTimeoutMs));
    const QJsonDocument detailsResponse = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(detailsPayload), &localErrorMessage);
    if (detailsResponse.isNull()) {
        m_httpClient->setTimeoutMs(previousTimeoutMs);
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return report;
    }

    const QJsonObject detailsRoot = detailsResponse.object();
    if (detailsRoot.contains(QStringLiteral("errors"))) {
        m_httpClient->setTimeoutMs(previousTimeoutMs);
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(detailsResponse.toJson(QJsonDocument::Indented));
        }
        return report;
    }

    const QJsonObject detailsData = detailsRoot.value(QStringLiteral("data")).toObject();
    report.flow = parseFlowRecord(detailsData.value(QStringLiteral("flow")).toObject());
    const QJsonArray taskArray = detailsData.value(QStringLiteral("tasks")).toArray();
    for (const QJsonValue &taskValue : taskArray) {
        report.tasks.append(parseTaskRecord(taskValue.toObject()));
    }
    const QJsonArray screenshotArray = detailsData.value(QStringLiteral("screenshots")).toArray();
    for (const QJsonValue &screenshotValue : screenshotArray) {
        report.screenshots.append(parseScreenshotRecord(screenshotValue.toObject()));
    }

    const QJsonObject statsPayload{
        {QStringLiteral("operationName"), QStringLiteral("GetFlowStats")},
        {QStringLiteral("query"),
         QStringLiteral("query GetFlowStats($flowId: ID!) { flowStatsByFlow(flowId: $flowId) { totalTasksCount totalSubtasksCount totalAssistantsCount } }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId}}},
    };
    const QJsonDocument statsResponse = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(statsPayload), &localErrorMessage);
    if (!statsResponse.isNull()) {
        const QJsonObject statsRoot = statsResponse.object();
        if (!statsRoot.contains(QStringLiteral("errors"))) {
            const QJsonObject statsObject = statsRoot.value(QStringLiteral("data")).toObject().value(QStringLiteral("flowStatsByFlow")).toObject();
            report.stats.totalTasksCount = statsObject.value(QStringLiteral("totalTasksCount")).toInt();
            report.stats.totalSubtasksCount = statsObject.value(QStringLiteral("totalSubtasksCount")).toInt();
            report.stats.totalAssistantsCount = statsObject.value(QStringLiteral("totalAssistantsCount")).toInt();
        }
    }

    if (report.stats.totalTasksCount <= 0) {
        report.stats.totalTasksCount = report.tasks.size();
    }
    if (report.stats.totalSubtasksCount <= 0) {
        int totalSubtasks = 0;
        for (const FlowTaskRecord &task : report.tasks) {
            totalSubtasks += task.subtasks.size();
        }
        report.stats.totalSubtasksCount = totalSubtasks;
    }
    m_httpClient->setTimeoutMs(previousTimeoutMs);
    return report;
}

bool PentagiService::stopFlow(const QString &flowId, QString *errorMessage) {
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("StopFlow")},
        {QStringLiteral("query"), QStringLiteral("mutation StopFlow($flowId: ID!) { stopFlow(flowId: $flowId) }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId}}},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return false;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return false;
    }
    const QString result = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("stopFlow")).toString();
    if (result != QStringLiteral("success")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("后端未确认停止当前任务。");
        }
        return false;
    }
    return true;
}

bool PentagiService::finishFlow(const QString &flowId, QString *errorMessage) {
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("FinishFlow")},
        {QStringLiteral("query"), QStringLiteral("mutation FinishFlow($flowId: ID!) { finishFlow(flowId: $flowId) }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId}}},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return false;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return false;
    }
    const QString result = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("finishFlow")).toString();
    if (result != QStringLiteral("success")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("后端未确认完成当前任务。");
        }
        return false;
    }
    return true;
}

bool PentagiService::deleteFlowById(const QString &flowId, QString *errorMessage) {
    QString localErrorMessage;
    const QJsonObject payload{
        {QStringLiteral("operationName"), QStringLiteral("DeleteFlow")},
        {QStringLiteral("query"), QStringLiteral("mutation DeleteFlow($flowId: ID!) { deleteFlow(flowId: $flowId) }")},
        {QStringLiteral("variables"), QJsonObject{{QStringLiteral("flowId"), flowId}}},
    };
    const QJsonDocument response = m_httpClient->postJson(buildGraphqlUrl(), QJsonDocument(payload), &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = localErrorMessage;
        }
        return false;
    }

    const QJsonObject root = response.object();
    if (root.contains(QStringLiteral("errors"))) {
        if (errorMessage) {
            *errorMessage = QString::fromUtf8(response.toJson(QJsonDocument::Indented));
        }
        return false;
    }
    const QString result = root.value(QStringLiteral("data")).toObject().value(QStringLiteral("deleteFlow")).toString();
    if (result != QStringLiteral("success")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("后端未确认删除当前任务。");
        }
        return false;
    }
    return true;
}

QList<PentagiTokenItem> PentagiService::listApiTokens(QString *errorMessage) {
    QList<PentagiTokenItem> items;
    const QUrl requestUrl = buildApiTokensUrl();
    QString localErrorMessage;
    const QJsonDocument response = m_httpClient->getJson(requestUrl, &localErrorMessage);
    if (response.isNull()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("密钥列表请求失败。\n请求地址：%1\n%2")
                                .arg(requestUrl.toString(), localErrorMessage);
        }
        return items;
    }

    const QJsonObject root = response.object();
    const QJsonObject dataObject = root.value(QStringLiteral("data")).toObject();
    const QJsonArray tokens = dataObject.value(QStringLiteral("tokens")).toArray();
    for (const QJsonValue &value : tokens) {
        items.append(parseTokenItem(value.toObject()));
    }
    return items;
}

PentagiCreateTokenResult PentagiService::createApiToken(const QString &name, int ttl) {
    PentagiCreateTokenResult result;
    if (ttl <= 0) {
        result.message = QStringLiteral("TTL 必须大于 0。");
        return result;
    }

    const QJsonObject body{
        {QStringLiteral("name"), name},
        {QStringLiteral("ttl"), ttl},
    };
    QString errorMessage;
    const QJsonDocument response = m_httpClient->postJson(
        buildRestUrl(QStringLiteral("/tokens/")),
        QJsonDocument(body),
        &errorMessage);
    if (response.isNull()) {
        result.message = errorMessage;
        return result;
    }

    const QJsonObject tokenObject = response.object().value(QStringLiteral("data")).toObject();
    result.token = parseTokenItem(tokenObject);
    result.plainToken = tokenObject.value(QStringLiteral("token")).toString();
    result.success = !result.plainToken.isEmpty();
    result.message = result.success
                         ? QStringLiteral("密钥创建成功，明文密钥仅会显示这一次。")
                         : QStringLiteral("密钥已创建，但未返回明文密钥。");
    return result;
}

bool PentagiService::deleteApiToken(const QString &tokenId, QString *errorMessage) {
    const QJsonDocument response = m_httpClient->deleteJson(buildRestUrl(QStringLiteral("/tokens/%1").arg(tokenId)), errorMessage);
    return !response.isNull();
}

bool PentagiService::updateApiTokenStatus(const QString &tokenId, const QString &status, QString *errorMessage) {
    const QJsonObject body{
        {QStringLiteral("status"), status},
    };
    const QJsonDocument response = m_httpClient->putJson(
        buildRestUrl(QStringLiteral("/tokens/%1").arg(tokenId)),
        QJsonDocument(body),
        errorMessage);
    return !response.isNull();
}

QUrl PentagiService::buildRestUrl(const QString &path) const {
    QUrl url(m_config.restUrl.trimmed());
    QString pathPart = path;
    QString queryPart;
    const int queryIndex = pathPart.indexOf('?');
    if (queryIndex >= 0) {
        queryPart = pathPart.mid(queryIndex + 1);
        pathPart = pathPart.left(queryIndex);
    }

    QString normalizedPath = url.path();
    normalizedPath = normalizedPath.replace(QRegularExpression("/+$"), QString());
    normalizedPath += ensureLeadingSlash(pathPart);
    url.setPath(normalizedPath);
    if (!queryPart.isEmpty()) {
        url.setQuery(queryPart);
    }
    return url;
}

QUrl PentagiService::buildGraphqlUrl() const {
    return QUrl(m_config.graphqlUrl.trimmed());
}

QUrl PentagiService::buildApiTokensUrl() const {
    return buildRestUrl(QStringLiteral("/tokens/?page=1&pageSize=100&type=init"));
}
