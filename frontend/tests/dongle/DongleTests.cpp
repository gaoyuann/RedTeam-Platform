#include "services/dongle/DongleService.h"
#include "pages/DongleVerificationPage.h"
#include <QtTest>
#include <QApplication>
#include <QCheckBox>
#include <QFile>
#include <QLabel>
#include <QLibrary>
#include <QMessageBox>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTimer>

class DongleTests : public QObject {
    Q_OBJECT
    QLibrary sdk{QCoreApplication::applicationDirPath() + "/third_party/rockey/linux-x86_64/libRockeyARM.so.0.3"};
    using Reset = void (*)();
    using Set = void (*)(int, int);
    using Writes = int (*)();
    Reset reset = nullptr;
    Set set = nullptr;
    Writes writes = nullptr;
    const QByteArray hid1 = QByteArray(8, '\1'), hid2 = QByteArray(8, '\2');
    void confirm() {
        QTimer::singleShot(0, [] {
            auto *box = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
            if (box) box->button(QMessageBox::Yes)->click();
        });
    }
private slots:
    void initTestCase() {
        QVERIFY(sdk.load());
        reset = reinterpret_cast<Reset>(sdk.resolve("TestReset"));
        set = reinterpret_cast<Set>(sdk.resolve("TestSet"));
        writes = reinterpret_cast<Writes>(sdk.resolve("TestWrites"));
        QVERIFY(reset && set && writes);
    }
    void init() { reset(); }
    void registrationAndIdentity() {
        DongleService service;
        QString error;
        QCOMPARE(service.enumerate(&error).size(), 2);
        QVERIFY(!service.verifyDevice(0));
        QVERIFY(service.registerDevice(0, false, &error, hid1));
        QCOMPARE(writes(), 1);
        QVERIFY(service.verifyDeviceByHid(hid1));
        set(3, 101); // Same HID with a different PID must fail.
        QVERIFY(!service.verifyDevice(0));
        set(3, 100);
        QVERIFY(!service.registerDevice(0, true, &error, hid2));
        QVERIFY(!service.destroyRegistration(0, &error, hid2));
        QCOMPARE(writes(), 1);
        QVERIFY(service.destroyRegistration(0, &error, hid1));
        QVERIFY(!service.verifyDevice(0));
    }
    void foreignDataAndSdkFailures() {
        DongleService service;
        QString error;
        set(4, 65);
        QVERIFY(!service.registerDevice(0, false, &error));
        QVERIFY(!service.destroyRegistration(0, &error));
        QCOMPARE(writes(), 0);
        QVERIFY(service.registerDevice(0, true, &error));
        set(1, 7);
        QVERIFY(!service.verifyDevice(0)); // Failure also propagates with no error pointer.
        QVERIFY(!service.registerDevice(0, false));
        set(1, 0); set(2, 42);
        QVERIFY(!service.verifyDeviceByHid(hid1, &error));
        QVERIFY(error.contains("0000002A"));
    }
    void policyAndHeartbeat() {
        QTemporaryDir dir;
        DongleService service;
        QVERIFY(DongleService::verifyPolicy(dir.path()));
        QVERIFY(!DongleService::savePolicy(dir.path(), true, {}, {}));
        QVERIFY(service.registerDevice(0, false));
        QVERIFY(DongleService::savePolicy(dir.path(), true, {}, hid1));
        QVERIFY(DongleService::verifyPolicy(dir.path()));
        set(0, 0);
        QVERIFY(!DongleService::verifyPolicy(dir.path()));
        set(0, 2);
        QVERIFY(DongleService::verifyPolicy(dir.path()));
        QFile file(DongleService::policyPath(dir.path()));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("{\"enabled\":\"true\",\"registeredHid\":\"0101010101010101\"}");
        file.close();
        QVERIFY(!DongleService::verifyPolicy(dir.path()));
    }
    void pageRegistersOnlyOnce() {
        QTemporaryDir dir;
        DongleVerificationPage page(dir.path());
        confirm();
        QVERIFY(QMetaObject::invokeMethod(&page, "registerSelectedDevice", Qt::DirectConnection));
        QCOMPARE(writes(), 1);
        QVERIFY(DongleService::verifyPolicy(dir.path()));
        QVERIFY(page.findChild<QLabel *>("dongleStatus")->text().contains(QStringLiteral("注册成功")));
    }
    void pageKeepsOtherBinding() {
        QTemporaryDir dir;
        DongleService service;
        QVERIFY(service.registerDevice(0, false));
        QVERIFY(service.registerDevice(1, false));
        QVERIFY(DongleService::savePolicy(dir.path(), true, {}, hid1));
        DongleVerificationPage page(dir.path());
        page.findChild<QTableWidget *>()->selectRow(1);
        confirm();
        QVERIFY(QMetaObject::invokeMethod(&page, "destroySelectedRegistration", Qt::DirectConnection));
        bool enabled = false;
        QByteArray bound;
        QVERIFY(DongleService::loadPolicy(dir.path(), &enabled, nullptr, &bound));
        QVERIFY(enabled);
        QCOMPARE(bound, hid1);
        QVERIFY(DongleService::verifyPolicy(dir.path()));
        QVERIFY(!service.verifyDevice(1));
    }
    void pagePreservesSaveFailure() {
        QTemporaryDir dir;
        QFile blocker(dir.path() + "/not-a-directory");
        QVERIFY(blocker.open(QIODevice::WriteOnly)); blocker.close();
        DongleVerificationPage page(blocker.fileName());
        confirm();
        QVERIFY(QMetaObject::invokeMethod(&page, "registerSelectedDevice", Qt::DirectConnection));
        QCOMPARE(writes(), 1);
        QVERIFY(page.findChild<QLabel *>("dongleStatus")->text().contains(QStringLiteral("策略保存失败")));
        QVERIFY(!page.findChild<QCheckBox *>()->isChecked());
    }
};
QTEST_MAIN(DongleTests)
#include "DongleTests.moc"
