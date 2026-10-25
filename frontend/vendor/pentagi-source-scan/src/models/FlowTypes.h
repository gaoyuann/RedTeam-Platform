#pragma once

#include <QList>
#include <QString>

struct FlowTerminalRecord {
    QString id;
    QString type;
    QString name;
    QString image;
    bool connected = false;
    QString createdAt;
};

struct FlowProviderRecord {
    QString name;
    QString type;
};

struct FlowRecord {
    QString id;
    QString title;
    QString status;
    QString createdAt;
    QString updatedAt;
    QList<FlowTerminalRecord> terminals;
    FlowProviderRecord provider;
};

struct FlowSubtaskRecord {
    QString id;
    QString status;
    QString title;
    QString description;
    QString result;
    QString taskId;
    QString createdAt;
    QString updatedAt;
};

struct FlowTaskRecord {
    QString id;
    QString title;
    QString status;
    QString input;
    QString result;
    QString flowId;
    QList<FlowSubtaskRecord> subtasks;
    QString createdAt;
    QString updatedAt;
};

struct FlowScreenshotRecord {
    QString id;
    QString flowId;
    QString taskId;
    QString subtaskId;
    QString name;
    QString url;
    QString createdAt;
};

struct FlowStatsRecord {
    int totalTasksCount = 0;
    int totalSubtasksCount = 0;
    int totalAssistantsCount = 0;
};

struct FlowAssistantRecord {
    QString id;
    QString title;
    QString status;
    QString flowId;
    bool useAgents = false;
    QString createdAt;
    QString updatedAt;
    FlowProviderRecord provider;
};

struct FlowAssistantLogRecord {
    QString id;
    QString type;
    QString message;
    QString thinking;
    QString result;
    QString resultFormat;
    bool appendPart = false;
    QString flowId;
    QString assistantId;
    QString createdAt;
};

struct FlowReportRecord {
    FlowRecord flow;
    QList<FlowTaskRecord> tasks;
    QList<FlowScreenshotRecord> screenshots;
    FlowStatsRecord stats;
};
