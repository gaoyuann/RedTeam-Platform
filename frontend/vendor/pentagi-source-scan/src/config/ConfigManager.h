#pragma once

#include "AppConfig.h"

#include <QObject>

class QFileSystemWatcher;

class ConfigManager : public QObject {
    Q_OBJECT

public:
    explicit ConfigManager(QObject *parent = nullptr);

    bool initialize();
    bool initializeAt(const QString &configDir);
    AppConfig currentConfig() const;
    AppConfig defaultConfig() const;
    QString defaultConfigPath() const;
    QString userConfigPath() const;
    QString configDirPath() const;
    QString effectiveConfigPath() const;
    QString lastUpdatedText() const;

    bool saveUserConfig(const AppConfig &config);
    bool reload();

signals:
    void configChanged(const AppConfig &config);

private:
    QVariantMap loadJsonFile(const QString &path) const;
    QVariantMap mergeVariantMaps(const QVariantMap &base, const QVariantMap &overrideMap) const;
    bool ensureUserConfigFileExists();
    void watchConfigFiles();

    QFileSystemWatcher *m_fileWatcher;
    AppConfig m_currentConfig;
    QString m_defaultConfigPath;
    QString m_userConfigPath;
    QString m_configDirPath;
    QString m_lastUpdatedText;
};
