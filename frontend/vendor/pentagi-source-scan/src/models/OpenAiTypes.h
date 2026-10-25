#pragma once

#include <QString>
#include <QStringList>

struct OpenAiChatMessage {
    QString role;
    QString content;
};

struct OpenAiChatResult {
    bool success = false;
    QString model;
    QString content;
    QString rawResponse;
    QString errorMessage;
};
