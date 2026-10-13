#include <QtWidgets>
#include <QtNetwork>
#include <QtTest>
#include "ApiClient.h"
#include "GlobalSearchDialog.h"

class GlobalSearchChecks : public QObject {
    Q_OBJECT
private slots:
    void searchLifecycle() {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));
        bool fail = false, wrongOwner = false, writes = false;
        bool shrink = false, duplicate = false, invalidReport = false, reportFailure = false;
        bool missingPipeline = false, legacy = false;
        QStringList queries;
        connect(&server, &QTcpServer::newConnection, &server, [&]() {
            while (server.hasPendingConnections()) {
                auto *socket = server.nextPendingConnection();
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [&, socket]() {
                    auto buffer = socket->property("buffer").toByteArray() + socket->readAll();
                    socket->setProperty("buffer", buffer);
                    if (!buffer.contains("\r\n\r\n") || socket->property("handled").toBool()) return;
                    socket->setProperty("handled", true);
                    const auto request = buffer.split('\n').first().split(' ');
                    writes |= request[0] != "GET";
                    const QUrl url(QStringLiteral("http://localhost") + QString::fromUtf8(request[1]));
                    const QUrlQuery query(url);
                    const QString search = query.queryItemValue("search", QUrl::FullyDecoded);
                    queries.append(search);
                    const int offset = query.queryItemValue("offset").toInt();
                    const bool task = url.path().contains("pipelines");
                    QJsonArray rows;
                    if (search != "empty" && !(shrink && offset > 0)) rows.append(QJsonObject{{"pipeline_id", missingPipeline && !task ? QString() : "task-" + search + QString::number(duplicate ? 0 : offset)},
                        {"report_id", "report-" + search + QString::number(duplicate ? 0 : offset)}, {"task_name", search}, {"title", search},
                        {"owner", wrongOwner ? "someone-else" : "tester"}, {"kind", invalidReport ? "unknown" : legacy ? "legacy" : "trace_snapshot"}});
                    QJsonObject data{{"schema_version", 1}, {"records", rows}, {"total", search == "empty" || (shrink && offset > 0) ? 0 : 2},
                        {"offset", offset}, {"limit", 50}, {"search", search}, {task ? "state" : "kind", "all"}};
                    const auto bytes = QJsonDocument(QJsonObject{{"status", fail || (reportFailure && !task) ? "error" : "ok"}, {"data", data}}).toJson();
                    QTimer::singleShot(search == "old" ? 180 : 0, socket, [socket, bytes]() {
                        socket->write("HTTP/1.1 200 OK\r\nContent-Length: " + QByteArray::number(bytes.size())
                            + "\r\nConnection: close\r\n\r\n" + bytes);
                        socket->disconnectFromHost();
                    });
                });
            }
        });
        ApiClient api(QString("http://127.0.0.1:%1").arg(server.serverPort()));
        GlobalSearchDialog dialog(&api, {"工作台", "任务", "资产", "分析", "知识", "报告", "系统管理"}, "user", "tester");
        dialog.show();
        auto *list = dialog.findChild<QListWidget*>("searchResults");
        auto *state = dialog.findChild<QLabel*>("searchState");
        auto *more = dialog.findChild<QPushButton*>();
        auto *input = dialog.findChild<QLineEdit*>();
        dialog.search("");
        QCOMPARE(list->count(), 6);
        QCOMPARE(queries.size(), 0);
        const QString special = QStringLiteral("中文 &+#%?");
        dialog.search(special);
        QTRY_COMPARE(list->count(), 2);
        QVERIFY(queries.contains(special));
        QTRY_VERIFY(more->isEnabled());
        QTest::mouseClick(more, Qt::LeftButton);
        QTRY_COMPARE(list->count(), 4);
        QVERIFY(!more->isEnabled());
        shrink = true;
        dialog.search("shrink");
        QTRY_COMPARE(list->count(), 2);
        QTRY_VERIFY(more->isEnabled());
        QTest::mouseClick(more, Qt::LeftButton);
        QTRY_VERIFY(!state->text().contains(QStringLiteral("正在")));
        QVERIFY2(!state->text().contains(QStringLiteral("失败")), "Deletion between pages is a valid empty page");
        QVERIFY(!more->isEnabled());
        shrink = false;
        duplicate = true;
        dialog.search("duplicate");
        QTRY_COMPARE(list->count(), 2);
        QTRY_VERIFY(more->isEnabled());
        QTest::mouseClick(more, Qt::LeftButton);
        QTRY_VERIFY(!state->text().contains(QStringLiteral("正在")));
        QCOMPARE(list->count(), 2);
        duplicate = false;
        invalidReport = true;
        dialog.search("invalid");
        QTRY_VERIFY(state->text().contains(QStringLiteral("报告读取失败")));
        QCOMPARE(list->count(), 1);
        invalidReport = false;
        missingPipeline = true;
        dialog.search("missing");
        QTRY_VERIFY(state->text().contains(QStringLiteral("报告读取失败")));
        QCOMPARE(list->count(), 1);
        missingPipeline = false;
        legacy = true;
        dialog.search("legacy");
        QTRY_COMPARE(list->count(), 2);
        int legacyRow = -1;
        for (int i = 0; i < list->count(); ++i) {
            const auto navigation = list->item(i)->data(Qt::UserRole).toJsonObject();
            if (navigation["page"].toInt() == 5) {
                legacyRow = i;
                QVERIFY(navigation["pipeline_id"].toString().isEmpty());
                QVERIFY(!navigation["report_id"].toString().isEmpty());
            }
        }
        QVERIFY(legacyRow >= 0);
        legacy = false;
        reportFailure = true;
        dialog.search("partial");
        QTRY_VERIFY(state->text().contains(QStringLiteral("报告读取失败")));
        QCOMPARE(list->count(), 1);
        reportFailure = false;
        QTRY_VERIFY(more->isEnabled());
        QTest::mouseClick(more, Qt::LeftButton);
        QTRY_COMPARE(list->count(), 3);
        dialog.search("old");
        QTRY_VERIFY(queries.contains("old"));
        input->setText("empty");
        QTest::qWait(220); // Old response arrives before the new debounced request.
        QCOMPARE(list->count(), 0);
        QTRY_VERIFY(state->text().contains(QStringLiteral("未找到")));
        fail = true;
        dialog.search("retry");
        QTRY_VERIFY(state->text().contains(QStringLiteral("失败")));
        QCOMPARE(list->count(), 0);
        fail = false;
        QTRY_VERIFY(more->isEnabled());
        QTest::mouseClick(more, Qt::LeftButton);
        QTRY_COMPARE(list->count(), 2);
        wrongOwner = true;
        dialog.search("private");
        QTRY_VERIFY(state->text().contains(QStringLiteral("失败")));
        QCOMPARE(list->count(), 0);
        wrongOwner = false;
        dialog.search("activate");
        QTRY_COMPARE(list->count(), 2);
        QSignalSpy activated(&dialog, &GlobalSearchDialog::resultActivated);
        int taskRow = -1;
        for (int i = 0; i < list->count(); ++i)
            if (list->item(i)->data(Qt::UserRole).toJsonObject()["page"].toInt() == 1) taskRow = i;
        QVERIFY(taskRow >= 0);
        list->setCurrentRow(taskRow);
        list->setFocus();
        QTest::keyClick(list, Qt::Key_Return);
        QCOMPARE(activated.count(), 1);
        QVERIFY(!activated.first()[1].toString().isEmpty());
        QCOMPARE(activated.first()[0].toInt(), 1);
        QVERIFY(activated.first()[2].toString().isEmpty());
        QVERIFY(!writes);
        // Destruction during in-flight requests must be safe.
        auto *temporary = new GlobalSearchDialog(&api, {}, "admin", "tester");
        temporary->search("old");
        delete temporary;
        QTest::qWait(250);
    }
};
QTEST_MAIN(GlobalSearchChecks)
#include "global_search_checks.moc"
