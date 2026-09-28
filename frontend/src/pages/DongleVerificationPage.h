#pragma once

#include <QByteArray>
#include <QWidget>

#include "services/dongle/DongleService.h"

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

// 系统管理 / 加密锁校验 页：枚举设备、注册/校验/销毁本平台校验记录、开关校验策略。
class DongleVerificationPage : public QWidget {
    Q_OBJECT

public:
    explicit DongleVerificationPage(const QString &configDir, QWidget *parent = nullptr);

private slots:
    void saveEnabledState(bool enabled);
    void refreshDevices();
    void verifySelectedDevice();
    void registerSelectedDevice();
    void destroySelectedRegistration();

private:
    void buildUi();
    void loadPolicy();
    bool savePolicy(QString *errorMessage = nullptr);
    int selectedDeviceIndex() const;
    void setStatus(const QString &text, const QString &color);
    void populateDevices(const QVector<DongleDeviceInfo> &devices);
    QString protocolText(quint32 deviceType) const;

    DongleService m_dongleService;
    QString m_configDir;
    QByteArray m_registeredHid;
    bool m_enabled;

    QCheckBox *m_enabledCheckBox;
    QLabel *m_statusLabel;
    QLabel *m_registeredLabel;
    QTableWidget *m_deviceTable;
    QPushButton *m_refreshButton;
    QPushButton *m_verifyButton;
    QPushButton *m_registerButton;
    QPushButton *m_destroyButton;
};
