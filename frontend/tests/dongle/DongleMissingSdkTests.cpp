#include "services/dongle/DongleService.h"
#include "pages/DongleVerificationPage.h"
#include <QtTest>
#include <QLabel>
#include <QPushButton>
#include <QTemporaryDir>

class DongleMissingSdkTests : public QObject {
    Q_OBJECT
private slots:
    void missingSdkFailsSafely() {
        DongleService service;
        for (int i = 0; i < 2; ++i) {
            QString error;
            QVERIFY(!service.isLibraryAvailable(&error));
            QVERIFY(!error.isEmpty());
            QVERIFY(service.enumerate().isEmpty());
            QVERIFY(!service.registerDevice(0, false));
            QVERIFY(!service.destroyRegistration(0));
        }
        QTemporaryDir dir;
        QVERIFY(DongleService::verifyPolicy(dir.path())); // Unregistered developers can run.
        QVERIFY(DongleService::savePolicy(dir.path(), true, {}, QByteArray(8, '\1')));
        QVERIFY(!DongleService::verifyPolicy(dir.path()));
        DongleVerificationPage page(dir.path());
        QVERIFY(page.findChild<QLabel *>("dongleStatus")->text().contains(QStringLiteral("缺少")));
        int disabledActions = 0;
        for (auto *button : page.findChildren<QPushButton *>())
            if (!button->isEnabled()) ++disabledActions;
        QCOMPARE(disabledActions, 3);
    }
};
QTEST_MAIN(DongleMissingSdkTests)
#include "DongleMissingSdkTests.moc"
