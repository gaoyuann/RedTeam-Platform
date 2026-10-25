#include "ConfigManager.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QJsonDocument>
#include <QJsonObject>

namespace {
QVariantMap jsonObjectToVariantMap(const QJsonObject &object) {
    return object.toVariantMap();
}

bool hasDefaultConfig(const QString &dirPath) {
    return QFileInfo::exists(QDir(dirPath).filePath(QStringLiteral("config/default.json")));
}

QString resolveAppRootDir() {
    const QString currentDir = QDir::currentPath();
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString appParentDir = QDir(appDir).absoluteFilePath(QStringLiteral(".."));
    const QString currentParentDir = QDir(currentDir).absoluteFilePath(QStringLiteral(".."));

    QStringList candidates;
    candidates << currentDir << appDir << appParentDir << currentParentDir;

    QStringList seen;
    for (const QString &candidate : candidates) {
        const QString cleanPath = QDir(candidate).canonicalPath();
        if (cleanPath.isEmpty() || seen.contains(cleanPath)) {
            continue;
        }
        seen << cleanPath;
        if (hasDefaultConfig(cleanPath)) {
            return cleanPath;
        }
    }

    return QDir(appDir).absolutePath();
}
}

ConfigManager::ConfigManager(QObject *parent)
    : QObject(parent),
      m_fileWatcher(new QFileSystemWatcher(this)) {
}

bool ConfigManager::initialize() {
    const QString appRootDir = resolveAppRootDir();
    const QString configDir = QDir(appRootDir).filePath(QStringLiteral("config"));
    return initializeAt(configDir);
}

bool ConfigManager::initializeAt(const QString &configDir) {
    if (!QDir().mkpath(configDir)) return false;

    m_configDirPath = configDir;
    m_defaultConfigPath = QDir(configDir).filePath(QStringLiteral("default.json"));
    m_userConfigPath = QDir(configDir).filePath(QStringLiteral("config.json"));

    ensureUserConfigFileExists();
    watchConfigFiles();

    connect(m_fileWatcher, &QFileSystemWatcher::fileChanged, this, [this](const QString &) {
        reload();
        watchConfigFiles();
    });

    return reload();
}

AppConfig ConfigManager::currentConfig() const {
    return m_currentConfig;
}

AppConfig ConfigManager::defaultConfig() const {
    return AppConfig::fromVariantMap(loadJsonFile(m_defaultConfigPath));
}

QString ConfigManager::defaultConfigPath() const {
    return m_defaultConfigPath;
}

QString ConfigManager::userConfigPath() const {
    return m_userConfigPath;
}

QString ConfigManager::configDirPath() const {
    return m_configDirPath;
}

QString ConfigManager::effectiveConfigPath() const {
    return m_userConfigPath;
}

QString ConfigManager::lastUpdatedText() const {
    return m_lastUpdatedText;
}

bool ConfigManager::saveUserConfig(const AppConfig &config) {
    QFile file(m_userConfigPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }

    const QJsonObject json = QJsonObject::fromVariantMap(config.toVariantMap());
    file.write(QJsonDocument(json).toJson(QJsonDocument::Indented));
    file.close();

    return reload();
}

bool ConfigManager::reload() {
    const QVariantMap defaultMap = loadJsonFile(m_defaultConfigPath);
    const QVariantMap userMap = loadJsonFile(m_userConfigPath);
    const QVariantMap merged = mergeVariantMaps(defaultMap, userMap);

    m_currentConfig = AppConfig::fromVariantMap(merged);
    m_lastUpdatedText = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    emit configChanged(m_currentConfig);
    return true;
}

QVariantMap ConfigManager::loadJsonFile(const QString &path) const {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }

    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        return {};
    }

    return jsonObjectToVariantMap(document.object());
}

QVariantMap ConfigManager::mergeVariantMaps(const QVariantMap &base, const QVariantMap &overrideMap) const {
    QVariantMap result = base;
    for (auto it = overrideMap.constBegin(); it != overrideMap.constEnd(); ++it) {
        if (it.value().type() == QVariant::Map && result.value(it.key()).type() == QVariant::Map) {
            result.insert(it.key(), mergeVariantMaps(result.value(it.key()).toMap(), it.value().toMap()));
        } else {
            result.insert(it.key(), it.value());
        }
    }
    return result;
}

bool ConfigManager::ensureUserConfigFileExists() {
    if (QFileInfo::exists(m_userConfigPath)) {
        return true;
    }

    QFile::copy(m_defaultConfigPath, m_userConfigPath);
    return QFileInfo::exists(m_userConfigPath);
}

void ConfigManager::watchConfigFiles() {
    const QStringList currentFiles = m_fileWatcher->files();
    if (!currentFiles.isEmpty()) {
        m_fileWatcher->removePaths(currentFiles);
    }

    QStringList paths;
    if (QFileInfo::exists(m_defaultConfigPath)) {
        paths << m_defaultConfigPath;
    }
    if (QFileInfo::exists(m_userConfigPath)) {
        paths << m_userConfigPath;
    }
    if (!paths.isEmpty()) {
        m_fileWatcher->addPaths(paths);
    }
}
