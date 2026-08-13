#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

struct TopologyServiceRecord {
    QString port;
    QString protocol;
    QString service;
    QString product;
    QString version;
    QString state;
    QString note;

    QJsonObject toJsonObject() const;
    static TopologyServiceRecord fromJsonObject(const QJsonObject &object);
};

struct TopologyNodeRecord {
    QString id;
    QString displayName;
    QString ip;
    QString hostName;
    QString osName;
    QString osVersion;
    QString deviceType;
    QString vendor;
    QString status;
    QString note;
    QStringList tags;
    double x = 0.0;
    double y = 0.0;
    QList<TopologyServiceRecord> services;

    QJsonObject toJsonObject() const;
    static TopologyNodeRecord fromJsonObject(const QJsonObject &object);
};

struct TopologyEdgeRecord {
    QString id;
    QString sourceId;
    QString targetId;
    QString label;
    QString type;
    QString note;

    QJsonObject toJsonObject() const;
    static TopologyEdgeRecord fromJsonObject(const QJsonObject &object);
};

struct TopologyDocument {
    QString flowId;
    QString target;
    QString generatedAt;
    QString summary;
    QList<TopologyNodeRecord> nodes;
    QList<TopologyEdgeRecord> edges;

    QJsonObject toJsonObject() const;
    static TopologyDocument fromJsonObject(const QJsonObject &object);
};
