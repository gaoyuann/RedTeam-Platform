#include <QtTest>
#include <QtWidgets>
#include <QtNetwork>
#include "pages/PentagiSourceScanHost.h"
#include "ApiClient.h"

class PentagiSourceHostChecks : public QObject {
    Q_OBJECT
private slots:
    void targetSubmissionAndThreePaneResults() {
        QTcpServer server;
        bool created=false;
        int submissions=0;
        QJsonObject posted;
        QObject::connect(&server,&QTcpServer::newConnection,&server,[&]{
            while(auto *socket=server.nextPendingConnection()) {
                connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
                connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{
                    QByteArray bytes=socket->property("bytes").toByteArray()+socket->readAll();
                    socket->setProperty("bytes",bytes);
                    const int edge=bytes.indexOf("\r\n\r\n");
                    if(edge<0 || socket->property("done").toBool())return;
                    int length=0;
                    for(const auto &line:bytes.left(edge).split('\n'))
                        if(line.toLower().startsWith("content-length:"))length=line.mid(15).trimmed().toInt();
                    if(bytes.size()<edge+4+length)return;
                    socket->setProperty("done",true);
                    const auto request=bytes.left(bytes.indexOf('\r')).split(' ');
                    const QByteArray path=request.value(1);
                    QJsonValue data;
                    const QJsonObject scan{{"scan_task_id","scan-fixture"},{"pipeline_id","pipe_fixture"},
                        {"scan_type","source_scan"},{"status","COMPLETED"},{"target","http://fixture.invalid/source/"}};
                    if(request[0]=="POST") {
                        ++submissions;
                        posted=QJsonDocument::fromJson(bytes.mid(edge+4,length)).object();
                        created=true;
                        data=QJsonObject{{"scan_task_id","scan-fixture"},{"pipeline_id","pipe_fixture"},{"task_no","TASK-fixture"}};
                    } else if(path.contains("source-file?"))data=QJsonObject{{"sha256","fixture"},
                        {"content","int main() {\n return 0;\n}\n"},{"captured_at","fixture"}};
                    else if(path.contains("?scan_type="))data=created?QJsonArray{scan}:QJsonArray{};
                    else {
                        auto detail=scan;
                        detail["source_files"]=QJsonArray{QJsonObject{{"id",42},{"path","/work/src/main.c"},{"sha256","fixture"}}};
                        detail["results"]=QJsonArray{QJsonObject{{"id",1},{"scan_task_id","scan-fixture"},
                            {"result_type","source_finding"},{"severity","low"},{"result_data",QJsonObject{
                                {"file","/work/src/main.c"},{"start_line",2},{"end_line",2},{"title","模拟输入检查"},
                                {"reason","仅用于页面测试"},{"cwe","CWE-20"}}}}};
                        data=detail;
                    }
                    const auto body=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);
                    socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                        +QByteArray::number(body.size())+"\r\n\r\n"+body);
                    socket->disconnectFromHost();
                });
            }
        });
        QVERIFY(server.listen(QHostAddress::LocalHost,0));
        ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
        PentagiSourceScanHost host(&api);
        host.resize(1280,800);
        host.show();
        auto *target=host.findChild<QLineEdit*>("sourceFlowTarget");
        auto *authorized=host.findChild<QCheckBox*>("sourceFlowAuthorized");
        auto *create=host.findChild<QPushButton*>("sourceFlowCreate");
        QVERIFY(target && authorized && create);
        target->setText("http://fixture.invalid/source/");
        create->click();QCOMPARE(submissions,0);
        authorized->setChecked(true);create->click();
        QTRY_COMPARE(submissions,1);
        QCOMPARE(posted["target"].toString(),target->text());
        QVERIFY(!posted["request_id"].toString().isEmpty());
        QTRY_VERIFY(host.findChild<QPlainTextEdit*>("sourceScanCode"));
        auto *code=host.findChild<QPlainTextEdit*>("sourceScanCode");
        QTRY_VERIFY(code->toPlainText().contains("int main()"));
        auto *tree=host.findChild<QTreeWidget*>("sourceScanFileTree");
        auto *table=host.findChild<QTableWidget*>("sourceScanFindings");
        auto *split=host.findChild<QSplitter*>("sourceScanThreePanes");
        QVERIFY(tree && table && split);
        QCOMPARE(split->count(),3);
        QCOMPARE(table->rowCount(),1);
        QVERIFY(tree->mapTo(&host,QPoint()).x()<code->mapTo(&host,QPoint()).x());
        QVERIFY(code->mapTo(&host,QPoint()).x()<table->mapTo(&host,QPoint()).x());
        table->setCurrentCell(0,1);
        QTRY_COMPARE(code->textCursor().blockNumber(),1);
        create->click();
        QTRY_COMPARE(submissions,2);
        QTRY_VERIFY(create->isEnabled());
        // Retries retain the same request identity instead of blindly creating a new Flow.
        const QString key=posted["request_id"].toString();
        create->click();QTRY_COMPARE(submissions,3);
        QCOMPARE(posted["request_id"].toString(),key);
        const QString screenshot=qEnvironmentVariable("SOURCE_HOST_SCREENSHOT");
        if(!screenshot.isEmpty())QVERIFY(host.grab().save(screenshot));
    }
};
QTEST_MAIN(PentagiSourceHostChecks)
#include "pentagi_source_host_checks.moc"
