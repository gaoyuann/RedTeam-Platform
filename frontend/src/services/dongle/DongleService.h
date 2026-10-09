#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>

class QLibrary;

// 设备信息（枚举一把加密锁时返回）
struct DongleDeviceInfo {
    int index = -1;
    quint16 version = 0;
    quint16 type = 0;
    quint32 agent = 0;
    quint32 pid = 0;
    quint32 userId = 0;
    quint32 isMother = 0;
    quint32 deviceType = 0;
    QByteArray hid;
};

// 飞天 ROCKEY ARM 加密锁服务：加载内置 SDK、枚举/注册/校验/销毁设备、读写本机策略。
// 仅加载项目内置的 SDK 动态库，绝不加载用户指定或系统级库，避免替换攻击。
class DongleService {
public:
    static constexpr int RegistrationOffset = 3840;   // 加密锁数据区写入偏移
    static constexpr int RegistrationSize = 256;       // 校验记录长度

    DongleService();
    ~DongleService();
    DongleService(const DongleService &) = delete;
    DongleService &operator=(const DongleService &) = delete;

    QString libraryPath() const;
    bool isLibraryAvailable(QString *errorMessage = nullptr);
    QVector<DongleDeviceInfo> enumerate(QString *errorMessage = nullptr);
    bool readRegistration(int index, QByteArray *record, DongleDeviceInfo *device, QString *errorMessage = nullptr);
    bool registerDevice(int index, bool overwrite, QString *errorMessage = nullptr, const QByteArray &expectedHid = QByteArray());
    bool destroyRegistration(int index, QString *errorMessage = nullptr, const QByteArray &expectedHid = QByteArray());
    bool verifyDevice(int index, QString *errorMessage = nullptr, const QByteArray &expectedHid = QByteArray());
    bool verifyDeviceByHid(const QByteArray &expectedHid, QString *errorMessage = nullptr);

    // 策略文件（dongle.json）所在目录：QStandardPaths::AppConfigLocation
    // Linux 下为 ~/.config/RedTeam/RedTeam-Platform/，按当前操作系统用户存、升级不丢、不污染仓库。
    static QString policyDir();
    static QString policyPath(const QString &configDir);
    static bool loadPolicy(const QString &configDir, bool *enabled, QString *libraryPath,
                           QByteArray *registeredHid, QString *errorMessage = nullptr);
    static bool savePolicy(const QString &configDir, bool enabled, const QString &libraryPath,
                           const QByteArray &registeredHid, QString *errorMessage = nullptr);
    static bool verifyPolicy(const QString &configDir, QString *errorMessage = nullptr);

private:
    struct DongleInfoNative;
    using DongleHandle = void *;
    using EnumFunction = unsigned int (*)(DongleInfoNative *, int *);
    using OpenFunction = unsigned int (*)(DongleHandle *, int);
    using ResetFunction = unsigned int (*)(DongleHandle);
    using CloseFunction = unsigned int (*)(DongleHandle);
    using ReadDataFunction = unsigned int (*)(DongleHandle, int, unsigned char *, int);
    using WriteDataFunction = unsigned int (*)(DongleHandle, int, unsigned char *, int);

    bool ensureLoaded(QString *errorMessage);
    QStringList candidateLibraryPaths() const;
    QString formatError(const QString &operation, unsigned int code) const;
    bool openDevice(int index, DongleHandle *handle, QString *errorMessage);
    bool closeDevice(DongleHandle handle, QString *errorMessage);
    bool readRecord(int index, QByteArray *record, DongleDeviceInfo *device, QString *errorMessage, const QByteArray &expectedHid = QByteArray());
    bool writeRecord(int index, const QByteArray &record, QString *errorMessage);
    bool recordMatchesDevice(const QByteArray &record, const DongleDeviceInfo &device) const;
    QByteArray makeRecord(const DongleDeviceInfo &device) const;
    bool isBlankRecord(const QByteArray &record) const;

    QString m_loadedLibraryPath;
    QLibrary *m_library;
    EnumFunction m_enum;
    OpenFunction m_open;
    ResetFunction m_reset;
    CloseFunction m_close;
    ReadDataFunction m_readData;
    WriteDataFunction m_writeData;
};
