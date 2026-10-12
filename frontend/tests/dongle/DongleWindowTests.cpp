#include "ApiClient.h"
#include "MainWindow.h"
#include "SimpleMainWindow.h"
#include "pages/DongleLockPage.h"
#include "services/dongle/DongleService.h"
#include <QtTest>
#include <QApplication>
#include <QLibrary>
#include <QListWidget>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QTimer>
#include <memory>

class DongleWindowTests : public QObject {
    Q_OBJECT
private slots:
    void unplugAndRestore_data() {
        QTest::addColumn<bool>("admin");
        QTest::newRow("administrator") << true;
        QTest::newRow("operator") << false;
    }
    void unplugAndRestore() {
        QFETCH(bool, admin);
        QLibrary sdk(QCoreApplication::applicationDirPath() + "/third_party/rockey/linux-x86_64/libRockeyARM.so.0.3");
        QVERIFY(sdk.load());
        auto reset = reinterpret_cast<void (*)()>(sdk.resolve("TestReset"));
        auto set = reinterpret_cast<void (*)(int, int)>(sdk.resolve("TestSet"));
        auto writes = reinterpret_cast<int (*)()>(sdk.resolve("TestWrites"));
        QVERIFY(reset && set && writes);
        reset();
        DongleService service;
        QVERIFY(service.registerDevice(0, false));
        QVERIFY(DongleService::savePolicy(DongleService::policyDir(), true, {}, QByteArray(8, '\1')));
        ApiClient api("http://127.0.0.1:1");
        std::unique_ptr<QMainWindow> window;
        if (admin) window = std::make_unique<MainWindow>(&api, "admin", "dongle-test");
        else window = std::make_unique<SimpleMainWindow>(&api, "user", "dongle-test");
        auto *nav = window->findChild<QListWidget *>("navList");
        auto *lock = window->findChild<DongleLockPage *>();
        QVERIFY(nav && lock);
        QStackedWidget *stack = nullptr;
        for (auto *candidate : window->findChildren<QStackedWidget *>())
            if (candidate->indexOf(lock) >= 0) stack = candidate;
        QVERIFY(stack);
        nav->setCurrentRow(1);
        QWidget *previous = stack->currentWidget();
        QVERIFY(previous != lock);
        QTimer *heartbeat = nullptr;
        for (auto *timer : window->findChildren<QTimer *>(QString(), Qt::FindDirectChildrenOnly))
            if (timer->interval() == 5000) heartbeat = timer;
        QVERIFY(heartbeat && heartbeat->isActive());
        heartbeat->setInterval(20);
        for (int cycle = 0; cycle < 2; ++cycle) {
            set(0, 0);
            QTRY_COMPARE_WITH_TIMEOUT(stack->currentWidget(), lock, 1000);
            QVERIFY(!nav->isEnabled());
            QTest::qWait(60); // Repeated failures must preserve the original page.
            set(0, 2);
            QTRY_COMPARE_WITH_TIMEOUT(stack->currentWidget(), previous, 1000);
            QVERIFY(nav->isEnabled());
            QCOMPARE(nav->currentRow(), 1);
        }
        QCOMPARE(writes(), 1); // Heartbeats must never write to the device.
    }
};

int main(int argc, char **argv) {
    QTemporaryDir config;
    if (!config.isValid()) return 1;
    qputenv("XDG_CONFIG_HOME", config.path().toUtf8());
    QApplication app(argc, argv);
    app.setApplicationName("DongleWindowTests");
    DongleWindowTests tests;
    return QTest::qExec(&tests, argc, argv);
}
#include "DongleWindowTests.moc"
