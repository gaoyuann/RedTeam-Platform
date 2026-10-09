#include "DongleService.h"

#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLibrary>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStandardPaths>
#include <QSysInfo>
#include <QRegularExpression>
#include <QtGlobal>

#include <algorithm>

namespace {
constexpr unsigned int DongleSuccess = 0;
constexpr quint32 ProtocolHid = 0;
constexpr quint32 ProtocolCcid = 1;
const QByteArray RegistrationMagic("REDTEAM-LOCK-V1");

QString hexHid(const QByteArray &hid) {
    return hid.toHex().toUpper().replace(" ", "");
}

QString protocolText(quint32 protocol) {
    return protocol == ProtocolCcid ? QStringLiteral("CCID") : QStringLiteral("HID");
}
}

struct DongleService::DongleInfoNative {
    quint16 version;
    quint16 type;
    unsigned char birthDay[8];
    quint32 agent;
    quint32 pid;
    quint32 userId;
    unsigned char hid[8];
    quint32 isMother;
    quint32 deviceType;
};

DongleService::DongleService()
    : m_library(new QLibrary()),
      m_enum(nullptr),
      m_open(nullptr),
      m_reset(nullptr),
      m_close(nullptr),
      m_readData(nullptr),
      m_writeData(nullptr) {
}

DongleService::~DongleService() {
    if (m_library) {
        m_library->unload();
        delete m_library;
    }
}

QString DongleService::libraryPath() const {
    return m_loadedLibraryPath;
}

QStringList DongleService::candidateLibraryPaths() const {
    QStringList paths;
    const QString appDir = QCoreApplication::applicationDirPath();
#ifdef Q_OS_WIN
    const QString architecture = QSysInfo::buildCpuArchitecture().toLower();
    QString platformDirectory;
    if (architecture == QStringLiteral("i386") || architecture == QStringLiteral("i686"))
        platformDirectory = QStringLiteral("windows-x86");
    else if (architecture == QStringLiteral("x86_64"))
        platformDirectory = QStringLiteral("windows-x64");
    else
        return paths;
    const QString relativeLibrary = QStringLiteral("third_party/rockey/%1/Dongle_d.dll").arg(platformDirectory);
#elif defined(Q_OS_LINUX)
    const QString architecture = QSysInfo::buildCpuArchitecture().toLower();
    QString platformDirectory;
    if (architecture == QStringLiteral("i386") || architecture == QStringLiteral("i686"))
        platformDirectory = QStringLiteral("linux-x86");
    else if (architecture == QStringLiteral("x86_64"))
        platformDirectory = QStringLiteral("linux-x86_64");
    else if (architecture == QStringLiteral("arm64") || architecture == QStringLiteral("aarch64"))
        platformDirectory = QStringLiteral("linux-aarch64");
    else
        return paths;
    const QString relativeLibrary = QStringLiteral("third_party/rockey/%1/libRockeyARM.so.0.3").arg(platformDirectory);
#else
    return paths;
    const QString relativeLibrary;
#endif
    // SDK 随程序分发；绝不加载用户指定或系统级库。
    // appDir/third_party/rockey 覆盖 dev 构建态（CMake post-build 拷贝）与安装态；
    // appDir/../third_party/rockey 覆盖安装目录布局。
    paths << QDir(appDir).filePath(relativeLibrary);
    paths << QDir(appDir).filePath(QStringLiteral("../") + relativeLibrary);
    return paths;
}

bool DongleService::ensureLoaded(QString *errorMessage) {
    if (m_enum && m_open && m_reset && m_close && m_readData && m_writeData) {
        return true;
    }
    // A failed symbol lookup must never leave callable pointers into an unloaded SDK.
    auto clearFunctions = [this]() {
        m_enum = nullptr; m_open = nullptr; m_reset = nullptr;
        m_close = nullptr; m_readData = nullptr; m_writeData = nullptr;
        m_loadedLibraryPath.clear();
    };
    clearFunctions();
    QStringList attempted;
    QStringList failures;
    for (const QString &path : candidateLibraryPaths()) {
        if (path.isEmpty() || attempted.contains(path)) {
            continue;
        }
        attempted << path;
        m_library->setFileName(path);
        if (!m_library->load()) {
            failures << m_library->errorString();
            continue;
        }
        m_enum = reinterpret_cast<EnumFunction>(m_library->resolve("Dongle_Enum"));
        m_open = reinterpret_cast<OpenFunction>(m_library->resolve("Dongle_Open"));
        m_reset = reinterpret_cast<ResetFunction>(m_library->resolve("Dongle_ResetState"));
        m_close = reinterpret_cast<CloseFunction>(m_library->resolve("Dongle_Close"));
        m_readData = reinterpret_cast<ReadDataFunction>(m_library->resolve("Dongle_ReadData"));
        m_writeData = reinterpret_cast<WriteDataFunction>(m_library->resolve("Dongle_WriteData"));
        if (m_enum && m_open && m_reset && m_close && m_readData && m_writeData) {
            m_loadedLibraryPath = path;
            return true;
        }
        failures << QStringLiteral("SDK 缺少必要接口");
        m_library->unload();
        clearFunctions();
    }
    if (errorMessage) {
        *errorMessage = QStringLiteral("无法加载当前架构（%1）的 ROCKEY ARM SDK。请确认随程序分发的 SDK 与架构匹配。尝试路径：%2。详情：%3")
                            .arg(QSysInfo::buildCpuArchitecture(), attempted.join(QStringLiteral("、")), failures.join(QStringLiteral("；")));
    }
    return false;
}

QString DongleService::formatError(const QString &operation, unsigned int code) const {
    return QStringLiteral("%1失败，SDK 错误码 0x%2。请确认加密狗已插入、权限规则已生效，并检查 PIN/设备状态。")
        .arg(operation)
        .arg(code, 8, 16, QLatin1Char('0')).toUpper();
}

bool DongleService::isLibraryAvailable(QString *errorMessage) {
    return ensureLoaded(errorMessage);
}

QVector<DongleDeviceInfo> DongleService::enumerate(QString *errorMessage) {
    QVector<DongleDeviceInfo> devices;
    if (!ensureLoaded(errorMessage)) {
        return devices;
    }
    int count = 0;
    unsigned int result = m_enum(nullptr, &count);
    if (result != DongleSuccess) {
        if (errorMessage) {
            *errorMessage = formatError(QStringLiteral("枚举加密锁"), result);
        }
        return devices;
    }
    if (count <= 0) {
        return devices;
    }
    QVector<DongleInfoNative> native(count);
    result = m_enum(native.data(), &count);
    if (result != DongleSuccess) {
        if (errorMessage) {
            *errorMessage = formatError(QStringLiteral("读取加密锁列表"), result);
        }
        return devices;
    }
    count = qBound(0, count, native.size());
    for (int i = 0; i < count; ++i) {
        DongleDeviceInfo device;
        device.index = i;
        device.version = native[i].version;
        device.type = native[i].type;
        device.agent = native[i].agent;
        device.pid = native[i].pid;
        device.userId = native[i].userId;
        device.isMother = native[i].isMother;
        device.deviceType = native[i].deviceType;
        device.hid = QByteArray(reinterpret_cast<const char *>(native[i].hid), 8);
        devices.append(device);
    }
    return devices;
}

bool DongleService::openDevice(int index, DongleHandle *handle, QString *errorMessage) {
    if (!handle || !ensureLoaded(errorMessage)) {
        return false;
    }
    const unsigned int result = m_open(handle, index);
    if (result != DongleSuccess) {
        if (errorMessage) {
            *errorMessage = formatError(QStringLiteral("打开加密锁"), result);
        }
        return false;
    }
    return true;
}

bool DongleService::closeDevice(DongleHandle handle, QString *errorMessage) {
    if (!handle || !m_close) {
        return true;
    }
    if (m_reset) {
        m_reset(handle);
    }
    const unsigned int result = m_close(handle);
    if (result != DongleSuccess && errorMessage) {
        *errorMessage = formatError(QStringLiteral("关闭加密锁"), result);
        return false;
    }
    return result == DongleSuccess;
}

bool DongleService::readRecord(int index, QByteArray *record, DongleDeviceInfo *device, QString *errorMessage, const QByteArray &expectedHid) {
    if (!record) {
        return false;
    }
    QString enumerationError;
    const QVector<DongleDeviceInfo> devices = enumerate(&enumerationError);
    if (!enumerationError.isEmpty()) {
        if (errorMessage) *errorMessage = enumerationError;
        return false;
    }
    if (index < 0 || index >= devices.size()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("加密锁索引无效，请先刷新设备列表。");
        }
        return false;
    }
    if (!expectedHid.isEmpty() && devices.at(index).hid != expectedHid) {
        if (errorMessage) *errorMessage = QStringLiteral("设备列表已变化，请刷新后重新选择加密锁。");
        return false;
    }
    if (device) {
        *device = devices.at(index);
    }
    DongleHandle handle = nullptr;
    if (!openDevice(index, &handle, errorMessage)) {
        return false;
    }
    QByteArray data(RegistrationSize, '\0');
    const unsigned int result = m_readData(handle, RegistrationOffset,
                                           reinterpret_cast<unsigned char *>(data.data()), data.size());
    QString closeError;
    const bool closed = closeDevice(handle, &closeError);
    if (result != DongleSuccess) {
        if (errorMessage) {
            *errorMessage = formatError(QStringLiteral("读取校验信息"), result);
        }
        return false;
    }
    if (!closed) {
        if (errorMessage) *errorMessage = closeError;
        return false;
    }
    *record = data;
    return true;
}

bool DongleService::readRegistration(int index, QByteArray *record, DongleDeviceInfo *device, QString *errorMessage) {
    return readRecord(index, record, device, errorMessage);
}

bool DongleService::writeRecord(int index, const QByteArray &record, QString *errorMessage) {
    DongleHandle handle = nullptr;
    if (!openDevice(index, &handle, errorMessage)) {
        return false;
    }
    QByteArray data = record;
    data.resize(RegistrationSize);
    const unsigned int result = m_writeData(handle, RegistrationOffset,
                                            reinterpret_cast<unsigned char *>(data.data()), data.size());
    QString closeError;
    const bool closed = closeDevice(handle, &closeError);
    if (result != DongleSuccess) {
        if (errorMessage) {
            *errorMessage = formatError(QStringLiteral("写入校验信息"), result);
        }
        return false;
    }
    if (!closed) {
        if (errorMessage) *errorMessage = closeError;
        return false;
    }
    return true;
}

bool DongleService::isBlankRecord(const QByteArray &record) const {
    return std::all_of(record.cbegin(), record.cend(), [](char value) { return value == '\0' || value == static_cast<char>(0xFF); });
}

QByteArray DongleService::makeRecord(const DongleDeviceInfo &device) const {
    QByteArray record(RegistrationSize, '\0');
    record.replace(0, RegistrationMagic.size(), RegistrationMagic);
    record[24] = 1;
    record.replace(32, qMin(8, device.hid.size()), device.hid.left(8));
    QByteArray identity = device.hid;
    identity.append(reinterpret_cast<const char *>(&device.pid), sizeof(device.pid));
    identity.append(QByteArrayLiteral("redteam-platform"));
    const QByteArray fingerprint = QCryptographicHash::hash(identity, QCryptographicHash::Sha256);
    record.replace(48, fingerprint.size(), fingerprint);
    const QByteArray checksum = QCryptographicHash::hash(record.left(224), QCryptographicHash::Sha256);
    record.replace(224, checksum.size(), checksum);
    return record;
}

bool DongleService::recordMatchesDevice(const QByteArray &record, const DongleDeviceInfo &device) const {
    // Check version, HID, PID fingerprint and checksum, including reserved bytes.
    return device.hid.size() == 8 && record == makeRecord(device);
}

bool DongleService::registerDevice(int index, bool overwrite, QString *errorMessage, const QByteArray &expectedHid) {
    QByteArray existing;
    DongleDeviceInfo device;
    if (!readRecord(index, &existing, &device, errorMessage, expectedHid)) {
        return false;
    }
    if (!isBlankRecord(existing) && !recordMatchesDevice(existing, device) && !overwrite) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("校验区域已有非本平台数据。为防止覆盖其他应用数据，未执行写入；如确认可覆盖，请再次确认。");
        }
        return false;
    }
    if (!writeRecord(index, makeRecord(device), errorMessage)) return false;
    return verifyDevice(index, errorMessage, device.hid);
}

bool DongleService::destroyRegistration(int index, QString *errorMessage, const QByteArray &expectedHid) {
    QByteArray existing;
    DongleDeviceInfo device;
    if (!readRecord(index, &existing, &device, errorMessage, expectedHid)) {
        return false;
    }
    if (!recordMatchesDevice(existing, device)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("该设备的校验区域不是本平台注册记录，未执行删除。");
        }
        return false;
    }
    return writeRecord(index, QByteArray(RegistrationSize, '\0'), errorMessage);
}

bool DongleService::verifyDevice(int index, QString *errorMessage, const QByteArray &expectedHid) {
    QByteArray record;
    DongleDeviceInfo device;
    if (!readRecord(index, &record, &device, errorMessage, expectedHid)) {
        return false;
    }
    if (!recordMatchesDevice(record, device)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("校验失败：未找到与当前设备匹配的本平台注册记录。");
        }
        return false;
    }
    return true;
}

bool DongleService::verifyDeviceByHid(const QByteArray &expectedHid, QString *errorMessage) {
    QString enumerationError;
    const QVector<DongleDeviceInfo> devices = enumerate(&enumerationError);
    if (!enumerationError.isEmpty()) {
        if (errorMessage) *errorMessage = enumerationError;
        return false;
    }
    for (const DongleDeviceInfo &device : devices) {
        if (device.hid == expectedHid) {
            return verifyDevice(device.index, errorMessage, expectedHid);
        }
    }
    if (errorMessage) {
        *errorMessage = QStringLiteral("校验失败：未检测到已注册的加密锁（HID=%1）。").arg(hexHid(expectedHid));
    }
    return false;
}

QString DongleService::policyDir() {
    // QStandardPaths::AppConfigLocation: Linux ~/.config/RedTeam/RedTeam-Platform/
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (dir.isEmpty()) {
        dir = QDir::homePath() + QStringLiteral("/.config/RedTeam/RedTeam-Platform");
    }
    return dir;
}

QString DongleService::policyPath(const QString &configDir) {
    return QDir(configDir).filePath(QStringLiteral("dongle.json"));
}

bool DongleService::loadPolicy(const QString &configDir, bool *enabled, QString *libraryPath,
                               QByteArray *registeredHid, QString *errorMessage) {
    if (enabled) *enabled = false;
    if (libraryPath) libraryPath->clear();
    if (registeredHid) registeredHid->clear();
    QFile file(policyPath(configDir));
    if (!file.exists()) {
        return true;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        if (errorMessage) *errorMessage = QStringLiteral("无法读取加密锁策略文件：%1").arg(file.errorString());
        return false;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        if (errorMessage) *errorMessage = QStringLiteral("加密锁策略文件不是有效 JSON。");
        return false;
    }
    const QJsonObject object = document.object();
    const QJsonValue enabledValue = object.value(QStringLiteral("enabled"));
    const QJsonValue hidValue = object.value(QStringLiteral("registeredHid"));
    const QString hid = hidValue.toString();
    static const QRegularExpression hidPattern(QStringLiteral("^[0-9a-fA-F]{16}$"));
    if (!enabledValue.isBool() || !hidValue.isString()
        || (!hid.isEmpty() && !hidPattern.match(hid).hasMatch())
        || (enabledValue.toBool() && hid.isEmpty())) {
        if (errorMessage) *errorMessage = QStringLiteral("加密锁策略字段无效：启用状态必须为布尔值，已绑定 HID 必须为 16 位十六进制字符串。");
        return false;
    }
    if (enabled) *enabled = enabledValue.toBool();
    if (libraryPath) *libraryPath = QStringLiteral("bundled");
    if (registeredHid) *registeredHid = QByteArray::fromHex(object.value(QStringLiteral("registeredHid")).toString().toLatin1());
    return true;
}

bool DongleService::savePolicy(const QString &configDir, bool enabled, const QString &libraryPath,
                               const QByteArray &registeredHid, QString *errorMessage) {
    if ((enabled && registeredHid.size() != 8) || (!registeredHid.isEmpty() && registeredHid.size() != 8)) {
        if (errorMessage) *errorMessage = QStringLiteral("无法保存策略：已绑定设备 HID 必须为 8 字节。");
        return false;
    }
    if (!QDir().mkpath(configDir)) {
        if (errorMessage) *errorMessage = QStringLiteral("无法创建加密锁策略目录：%1").arg(configDir);
        return false;
    }
    QJsonObject object;
    object.insert(QStringLiteral("enabled"), enabled);
    Q_UNUSED(libraryPath);
    object.insert(QStringLiteral("libraryPath"), QStringLiteral("bundled"));
    object.insert(QStringLiteral("registeredHid"), QString::fromLatin1(registeredHid.toHex()));
    QSaveFile file(policyPath(configDir));
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(object).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        if (errorMessage) *errorMessage = QStringLiteral("无法保存加密锁策略：%1").arg(file.errorString());
        return false;
    }
    return true;
}

bool DongleService::verifyPolicy(const QString &configDir, QString *errorMessage) {
    bool enabled = false;
    QByteArray registeredHid;
    if (!loadPolicy(configDir, &enabled, nullptr, &registeredHid, errorMessage)) {
        return false;
    }
    if (!enabled) {
        return true;
    }
    if (registeredHid.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("加密锁校验已启用，但尚未注册设备。");
        return false;
    }
    DongleService service;
    return service.verifyDeviceByHid(registeredHid, errorMessage);
}
