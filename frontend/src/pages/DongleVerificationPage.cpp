#include "../Theme.h"
#include "DongleVerificationPage.h"

#include <QCheckBox>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {
QString hidText(const QByteArray &hid) {
    return hid.toHex(' ').toUpper();
}

QFrame *makePanel(QWidget *parent) {
    auto *panel = new QFrame(parent);
    panel->setProperty("donglePanel", true);
    return panel;
}
}

DongleVerificationPage::DongleVerificationPage(const QString &configDir, QWidget *parent)
    : QWidget(parent),
      m_dongleService(),
      m_configDir(configDir),
      m_enabled(false),
      m_enabledCheckBox(nullptr),
      m_statusLabel(nullptr),
      m_registeredLabel(nullptr),
      m_deviceTable(nullptr),
      m_refreshButton(nullptr),
      m_verifyButton(nullptr),
      m_registerButton(nullptr),
      m_destroyButton(nullptr) {
    buildUi();
    refreshDevices();
    loadPolicy();
}

void DongleVerificationPage::buildUi() {
    setStyleSheet(QStringLiteral(
        "QWidget { background:#f3f6fb; color:#0f172a; }"
        "QLabel { background:transparent; border:none; }"
        "QFrame[donglePanel=\"true\"] { background:#ffffff; border:1px solid #dbe5f0; border-radius:12px; }"
        "QLineEdit, QTableWidget { background:#ffffff; color:#0f172a; border:1px solid #cfd9e6; border-radius:8px; padding:6px 8px; }"
        "QLineEdit:focus, QTableWidget:focus { border:1px solid #60a5fa; }"
        "QHeaderView::section { background:#eff4fa; color:#334155; border:none; border-bottom:1px solid #dbe5f0; padding:7px; font-weight:600; }"
        "QTableWidget { gridline-color:#e5edf6; }"
        "QTableWidget::item:selected { background:#dbeafe; color:#0f172a; }") + Theme::ButtonStyle);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto *content = new QWidget(scroll);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(16, 14, 16, 18);
    layout->setSpacing(12);

    auto *header = makePanel(content);
    auto *headerLayout = new QVBoxLayout(header);
    headerLayout->setContentsMargins(18, 16, 18, 16);
    auto *title = new QLabel(QStringLiteral("系统管理 / 加密锁校验"), header);
    QFont titleFont = title->font();
    titleFont.setPointSize(17);
    titleFont.setBold(true);
    title->setFont(titleFont);
    headerLayout->addWidget(title);
    auto *hint = new QLabel(QStringLiteral("将加密锁插入运行客户端的电脑。注册并启用后，登录前和运行期间都会校验设备；拔出后将锁定界面，重新插入后自动恢复。"), header);
    hint->setWordWrap(true);
    headerLayout->addWidget(hint);
    layout->addWidget(header);

    auto *policy = makePanel(content);
    auto *policyLayout = new QVBoxLayout(policy);
    policyLayout->setContentsMargins(16, 14, 16, 16);
    auto *policyTitle = new QLabel(QStringLiteral("校验策略"), policy);
    policyTitle->setStyleSheet(QStringLiteral("font-weight:700; font-size:13px;"));
    policyLayout->addWidget(policyTitle);
    auto *form = new QFormLayout();
    form->setHorizontalSpacing(14);
    form->setVerticalSpacing(10);
    m_enabledCheckBox = new QCheckBox(QStringLiteral("启用加密锁校验策略"), policy);
    connect(m_enabledCheckBox, &QCheckBox::toggled, this, &DongleVerificationPage::saveEnabledState);
    form->addRow(QStringLiteral("校验开关"), m_enabledCheckBox);
    policyLayout->addLayout(form);
    m_registeredLabel = new QLabel(policy);
    m_registeredLabel->setWordWrap(true);
    policyLayout->addWidget(m_registeredLabel);
    layout->addWidget(policy);

    auto *devices = makePanel(content);
    auto *devicesLayout = new QVBoxLayout(devices);
    devicesLayout->setContentsMargins(16, 14, 16, 16);
    auto *deviceHeader = new QHBoxLayout();
    auto *deviceTitle = new QLabel(QStringLiteral("检测到的加密锁"), devices);
    deviceTitle->setStyleSheet(QStringLiteral("font-weight:700; font-size:13px;"));
    deviceHeader->addWidget(deviceTitle);
    deviceHeader->addStretch();
    m_refreshButton = new QPushButton(QStringLiteral("刷新设备"), devices);
    connect(m_refreshButton, &QPushButton::clicked, this, &DongleVerificationPage::refreshDevices);
    deviceHeader->addWidget(m_refreshButton);
    devicesLayout->addLayout(deviceHeader);
    m_deviceTable = new QTableWidget(devices);
    m_deviceTable->setColumnCount(6);
    m_deviceTable->setHorizontalHeaderLabels({QStringLiteral("索引"), QStringLiteral("硬件 ID"), QStringLiteral("PID"), QStringLiteral("协议"), QStringLiteral("版本"), QStringLiteral("当前状态")});
    m_deviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_deviceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_deviceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_deviceTable->verticalHeader()->setVisible(false);
    m_deviceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_deviceTable->setMinimumHeight(150);
    devicesLayout->addWidget(m_deviceTable);
    auto *actions = new QHBoxLayout();
    m_statusLabel = new QLabel(QStringLiteral("尚未检测设备。"), devices);
    m_statusLabel->setObjectName(QStringLiteral("dongleStatus"));
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setTextFormat(Qt::PlainText);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    devicesLayout->addWidget(m_statusLabel);
    actions->addStretch();
    m_verifyButton = new QPushButton(QStringLiteral("校验当前设备"), devices);
    m_registerButton = new QPushButton(QStringLiteral("注册校验"), devices);
    m_destroyButton = new QPushButton(QStringLiteral("销毁校验"), devices);
    m_verifyButton->setProperty("primary", true);
    m_registerButton->setProperty("primary", true);
    m_destroyButton->setProperty("danger", true);
    connect(m_verifyButton, &QPushButton::clicked, this, &DongleVerificationPage::verifySelectedDevice);
    connect(m_registerButton, &QPushButton::clicked, this, &DongleVerificationPage::registerSelectedDevice);
    connect(m_destroyButton, &QPushButton::clicked, this, &DongleVerificationPage::destroySelectedRegistration);
    actions->addWidget(m_verifyButton);
    actions->addWidget(m_registerButton);
    actions->addWidget(m_destroyButton);
    devicesLayout->addLayout(actions);
    layout->addWidget(devices);
    layout->addStretch();
    scroll->setWidget(content);
    root->addWidget(scroll);
}

void DongleVerificationPage::loadPolicy() {
    bool enabled = false;
    QString error;
    if (!DongleService::loadPolicy(m_configDir, &enabled, nullptr, &m_registeredHid, &error)) {
        setStatus(error, QStringLiteral("#b91c1c"));
    }
    m_enabled = enabled;
    if (m_enabledCheckBox) {
        QSignalBlocker blocker(m_enabledCheckBox);
        m_enabledCheckBox->setChecked(m_enabled);
    }
    if (m_registeredLabel) {
        m_registeredLabel->setText(m_registeredHid.isEmpty()
                                        ? QStringLiteral("已注册设备：无")
                                        : QStringLiteral("已注册设备 HID：%1").arg(hidText(m_registeredHid)));
    }
}

bool DongleVerificationPage::savePolicy(QString *errorMessage) {
    return DongleService::savePolicy(m_configDir, m_enabled, QString(), m_registeredHid, errorMessage);
}

void DongleVerificationPage::saveEnabledState(bool enabled) {
    const bool previousEnabled = m_enabled;
    m_enabled = enabled;
    if (enabled && m_registeredHid.isEmpty()) {
        m_enabled = false;
        QSignalBlocker blocker(m_enabledCheckBox);
        m_enabledCheckBox->setChecked(false);
        QMessageBox::information(this, QStringLiteral("尚未注册加密锁"), QStringLiteral("请先选择设备并点击“注册校验”，再启用校验策略。"));
        return;
    }
    QString error;
    if (enabled && !m_dongleService.verifyDeviceByHid(m_registeredHid, &error)) {
        m_enabled = previousEnabled;
        QSignalBlocker blocker(m_enabledCheckBox);
        m_enabledCheckBox->setChecked(m_enabled);
        setStatus(error, QStringLiteral("#b91c1c"));
        return;
    }
    if (!savePolicy(&error)) {
        m_enabled = previousEnabled;
        QSignalBlocker blocker(m_enabledCheckBox);
        m_enabledCheckBox->setChecked(m_enabled);
        setStatus(error, QStringLiteral("#b91c1c"));
        return;
    }
    setStatus(enabled ? QStringLiteral("已启用加密锁校验策略。") : QStringLiteral("已停用加密锁校验策略。"), QStringLiteral("#166534"));
}

int DongleVerificationPage::selectedDeviceIndex() const {
    if (!m_deviceTable || m_deviceTable->currentRow() < 0) {
        return -1;
    }
    QTableWidgetItem *indexItem = m_deviceTable->item(m_deviceTable->currentRow(), 0);
    return indexItem ? indexItem->data(Qt::UserRole).toInt() : -1;
}

QByteArray DongleVerificationPage::selectedDeviceHid() const {
    if (selectedDeviceIndex() < 0) return {};
    return m_deviceTable->item(m_deviceTable->currentRow(), 0)->data(Qt::UserRole + 1).toByteArray();
}

void DongleVerificationPage::refreshDevices() {
    QString error;
    const QVector<DongleDeviceInfo> devices = m_dongleService.enumerate(&error);
    if (!error.isEmpty() && devices.isEmpty()) {
        populateDevices({});
        setStatus(error, QStringLiteral("#b91c1c"));
        return;
    }
    populateDevices(devices);
    if (devices.isEmpty()) {
        setStatus(QStringLiteral("未检测到 ROCKEY ARM。请确认设备已插入并重新插拔，或检查 udev 权限。"), QStringLiteral("#b45309"));
    } else {
        setStatus(QStringLiteral("已检测到 %1 把加密锁。选择一行后可执行校验、注册或销毁。对设备的写入不会自动发生。")
                      .arg(devices.size()), QStringLiteral("#166534"));
        m_deviceTable->selectRow(0);
    }
}

void DongleVerificationPage::populateDevices(const QVector<DongleDeviceInfo> &devices) {
    m_deviceTable->setRowCount(0);
    for (const DongleDeviceInfo &device : devices) {
        const int row = m_deviceTable->rowCount();
        m_deviceTable->insertRow(row);
        auto *index = new QTableWidgetItem(QString::number(device.index));
        index->setData(Qt::UserRole, device.index);
        index->setData(Qt::UserRole + 1, device.hid);
        m_deviceTable->setItem(row, 0, index);
        m_deviceTable->setItem(row, 1, new QTableWidgetItem(hidText(device.hid)));
        m_deviceTable->setItem(row, 2, new QTableWidgetItem(QStringLiteral("0x%1").arg(device.pid, 8, 16, QLatin1Char('0')).toUpper()));
        m_deviceTable->setItem(row, 3, new QTableWidgetItem(protocolText(device.deviceType)));
        m_deviceTable->setItem(row, 4, new QTableWidgetItem(QStringLiteral("%1.%2").arg(device.version >> 8).arg(device.version & 0xff)));
        QString verifyError;
        const bool valid = m_dongleService.verifyDevice(device.index, &verifyError, device.hid);
        auto *state = new QTableWidgetItem(valid ? QStringLiteral("已注册") : QStringLiteral("未通过"));
        state->setToolTip(verifyError);
        m_deviceTable->setItem(row, 5, state);
    }
    m_verifyButton->setEnabled(!devices.isEmpty());
    m_registerButton->setEnabled(!devices.isEmpty());
    m_destroyButton->setEnabled(!devices.isEmpty());
}

void DongleVerificationPage::verifySelectedDevice() {
    const int index = selectedDeviceIndex();
    if (index < 0) {
        setStatus(QStringLiteral("请先选择一把加密锁。"), QStringLiteral("#b45309"));
        return;
    }
    QString error;
    if (m_dongleService.verifyDevice(index, &error, selectedDeviceHid())) {
        setStatus(QStringLiteral("校验成功：当前设备包含有效的本平台注册记录。"), QStringLiteral("#166534"));
    } else {
        setStatus(error, QStringLiteral("#b91c1c"));
    }
}

void DongleVerificationPage::registerSelectedDevice() {
    const int index = selectedDeviceIndex();
    if (index < 0) {
        setStatus(QStringLiteral("请先选择一把加密锁。"), QStringLiteral("#b45309"));
        return;
    }
    const QByteArray selectedHid = selectedDeviceHid();
    if (QMessageBox::warning(this, QStringLiteral("确认注册校验"),
                             QStringLiteral("将在所选设备 %1 上写入本平台校验记录，并启用本机策略。是否继续？").arg(hidText(selectedHid)),
                             QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) return;
    QString error;
    // Retry only when foreign data replacement is explicitly confirmed.
    if (!m_dongleService.registerDevice(index, false, &error, selectedHid)) {
        if (!error.contains(QStringLiteral("已有非本平台数据"))) {
            setStatus(error, QStringLiteral("#b91c1c"));
            return;
        }
        if (QMessageBox::warning(this, QStringLiteral("发现其他数据"),
                                 error + QStringLiteral("\n\n这也可能是 PentAGI 的校验记录。覆盖后该记录将无法用于原应用。确定覆盖吗？"),
                                 QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) return;
        if (!m_dongleService.registerDevice(index, true, &error, selectedHid)) {
            setStatus(error, QStringLiteral("#b91c1c"));
            return;
        }
    }
    const bool saved = DongleService::savePolicy(m_configDir, true, QString(), selectedHid, &error);
    refreshDevices();
    loadPolicy();
    setStatus(saved ? QStringLiteral("注册成功，已启用加密锁校验策略。")
                    : QStringLiteral("设备已注册，但本机策略保存失败，仍沿用原策略：%1").arg(error),
              saved ? QStringLiteral("#166534") : QStringLiteral("#b45309"));
}

void DongleVerificationPage::destroySelectedRegistration() {
    const int index = selectedDeviceIndex();
    if (index < 0) {
        setStatus(QStringLiteral("请先选择一把加密锁。"), QStringLiteral("#b45309"));
        return;
    }
    const QByteArray selectedHid = selectedDeviceHid();
    if (QMessageBox::critical(this, QStringLiteral("确认销毁校验"),
                              QStringLiteral("将清除设备 %1 的本平台注册记录。此操作不可撤销，是否继续？").arg(hidText(selectedHid)),
                              QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) return;
    QString error;
    if (!m_dongleService.destroyRegistration(index, &error, selectedHid)) {
        setStatus(error, QStringLiteral("#b91c1c"));
        return;
    }
    // Deleting another device must not disable the currently bound device.
    const bool wasBound = selectedHid == m_registeredHid;
    const bool saved = !wasBound || DongleService::savePolicy(m_configDir, false, QString(), QByteArray(), &error);
    refreshDevices();
    loadPolicy();
    if (!saved) {
        setStatus(QStringLiteral("设备校验已销毁，但本机策略保存失败；原策略仍生效，请重新注册设备后重试：%1").arg(error), QStringLiteral("#b45309"));
    } else {
        setStatus(wasBound ? QStringLiteral("校验记录已销毁，校验策略已停用。")
                           : QStringLiteral("所选设备记录已销毁，当前绑定设备的策略保持不变。"), QStringLiteral("#166534"));
    }
}

QString DongleVerificationPage::protocolText(quint32 deviceType) const {
    return deviceType == 1 ? QStringLiteral("CCID") : QStringLiteral("HID");
}

void DongleVerificationPage::setStatus(const QString &text, const QString &color) {
    if (!m_statusLabel) {
        return;
    }
    m_statusLabel->setText(text);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;").arg(color));
}
