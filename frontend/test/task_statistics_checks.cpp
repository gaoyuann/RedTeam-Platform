#include <QtWidgets>
#include <QtNetwork>
#include <QtTest>
#include <functional>
#define private public
#include "pages/TaskStatisticsPanel.h"
#undef private

class StatisticsServer : public QTcpServer {
public:
  bool failReads=false;int delay=0;int requests=0;QList<QJsonObject> imports;QString lastPath;
  StatisticsServer(){connect(this,&QTcpServer::newConnection,this,[this]{while(hasPendingConnections()){
    auto *socket=nextPendingConnection();connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
    connect(socket,&QTcpSocket::readyRead,this,[this,socket]{
      auto bytes=socket->property("bytes").toByteArray()+socket->readAll();socket->setProperty("bytes",bytes);
      int end=bytes.indexOf("\r\n\r\n");if(end<0||socket->property("handled").toBool())return;
      auto match=QRegularExpression("Content-Length: (\\d+)",QRegularExpression::CaseInsensitiveOption).match(QString::fromUtf8(bytes.left(end)));
      const int size=match.hasMatch()?match.captured(1).toInt():0;if(bytes.size()<end+4+size)return;
      socket->setProperty("handled",true);++requests;lastPath=QString::fromUtf8(bytes.split(' ').value(1));
      QUrl url(lastPath);QUrlQuery query(url);const auto fp=query.queryItemValue("source_fingerprint");
      QJsonObject data;const bool a=lastPath.contains("/A/");
      if(lastPath.contains("/baselines")){
        auto body=QJsonDocument::fromJson(bytes.mid(end+4,size)).object();imports.append(body);data={{"valid",true},{"assets",1},{"vulnerabilities",1}};
      }else if(url.path().endsWith("/instances")){
        const QString conclusion=query.queryItemValue("conclusion");
        QJsonArray rows;if(conclusion=="all"||conclusion=="confirmed")rows.append(QJsonObject{{"instance_id",a?"fi_A":"fi_B"},{"severity","high"},{"conclusion","confirmed"},{"record_ids",QJsonArray{1,2}}});
        data={{"source_fingerprint",fp},{"rows",rows},{"page",QJsonObject{{"total",rows.size()},{"has_more",false},{"next_after",""}}}};
      }else data={{"source_fingerprint",fp},{"instance",QJsonObject{{"instance_id",a?"fi_A":"fi_B"}}}};
      const auto response=QJsonDocument(QJsonObject{{"status",failReads?"error":"ok"},{"data",data}}).toJson(QJsonDocument::Compact);QPointer<QTcpSocket> guard(socket);
      QTimer::singleShot(delay,this,[guard,response]{if(guard){guard->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(response.size())+"\r\n\r\n"+response);guard->disconnectFromHost();}});
    });
  }});}
};
static QJsonObject snapshot(const QString &id){return {{"pipeline_id",id},{"source_fingerprint",QString(64,id=="A"?'a':'b')},
  {"statistics",QJsonObject{{"findings",QJsonObject{{"records",2},{"instances",1},{"mapped_records",2},{"unmapped_records",0}}},
    {"checks",QJsonObject{{"states",QJsonObject{{"completed",1},{"failed",1}}}}},
    {"verifications",QJsonObject{{"executed_instances",1},{"confirmed_instances",1},{"conclusions",QJsonObject{{"confirmed",1},{"pending",0}}}}}}},
  {"coverage_checks",QJsonArray{QJsonObject{{"check_id","check-failed"},{"state","failed"}}}}};}
class StatisticsChecks : public QObject {
  Q_OBJECT
private slots:
  void filtersAndLateResponses(){
    StatisticsServer server;QVERIFY(server.listen(QHostAddress::LocalHost));ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
    TaskStatisticsPanel panel(&api);panel.resize(950,700);panel.show();QVERIFY(!panel.sync->isEnabled());
    panel.setSnapshot(snapshot("A"));QTRY_COMPARE(panel.table->rowCount(),1);QCOMPARE(panel.table->item(0,0)->text(),QString("fi_A"));panel.grab().save("/tmp/f09-statistics-widget.png");
    QTest::mouseClick(panel.conclusions,Qt::LeftButton,Qt::NoModifier,QPoint(10,38));QTRY_COMPARE(panel.table->rowCount(),0);QCOMPARE(panel.filter->currentData().toString(),QString("pending"));
    QTest::mouseClick(panel.checks,Qt::LeftButton,Qt::NoModifier,QPoint(10,38));QVERIFY(panel.detail->toPlainText().contains("check-failed"));
    panel.filter->setCurrentIndex(0);QTRY_COMPARE(panel.table->rowCount(),1);
    server.delay=180;int count=server.requests;panel.load(false);QTRY_VERIFY(server.requests>count);
    server.delay=0;panel.setSnapshot(snapshot("B"));QTRY_COMPARE(panel.table->rowCount(),1);QCOMPARE(panel.table->item(0,0)->text(),QString("fi_B"));
    QTest::qWait(230);QCOMPARE(panel.table->item(0,0)->text(),QString("fi_B"));
    panel.setSnapshot({});QCOMPARE(panel.table->rowCount(),0);QVERIFY(!panel.sync->isEnabled());
  }
  void retrySameSnapshotAfterReadFailure(){
    StatisticsServer server;QVERIFY(server.listen(QHostAddress::LocalHost));ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
    TaskStatisticsPanel panel(&api);server.failReads=true;panel.setSnapshot(snapshot("A"));
    QTRY_VERIFY(panel.detail->toPlainText().contains(QStringLiteral("读取失败")));
    QCOMPARE(panel.table->rowCount(),0);server.failReads=false;
    panel.setSnapshot(snapshot("A"));QTRY_COMPARE(panel.table->rowCount(),1);
    panel.invalidate();QVERIFY(!panel.isEnabled());
    const int before=server.requests;panel.setSnapshot(snapshot("A"));QVERIFY(panel.isEnabled());
    QTRY_VERIFY(server.requests>before);QTRY_COMPARE(panel.table->rowCount(),1);
  }
  void importPreviewAndConfirm(){
    StatisticsServer server;QVERIFY(server.listen(QHostAddress::LocalHost));ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
    TaskStatisticsPanel panel(&api);panel.setSnapshot(snapshot("A"));panel.show();
    QTemporaryDir dir;const QString name=dir.filePath("baseline.json");QFile file(name);QVERIFY(file.open(QIODevice::WriteOnly));file.write("{\"schema_version\":1,\"environment_id\":\"fixture\"}");file.close();
    bool selected=false,confirmed=false,changed=false;panel.changed=[&]{changed=true;};QTimer dialogs;
    connect(&dialogs,&QTimer::timeout,&panel,[&]{
      if(auto *dialog=qobject_cast<QFileDialog*>(QApplication::activeModalWidget())){if(!selected){selected=true;auto *edit=dialog->findChild<QLineEdit*>("fileNameEdit");if(edit)edit->setText(name);QTimer::singleShot(100,dialog,[dialog]{QMetaObject::invokeMethod(dialog,"accept",Qt::DirectConnection);});}}
      if(auto *box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget())){confirmed=true;box->button(QMessageBox::Yes)->click();}
    });dialogs.start(20);QTimer::singleShot(5000,&panel,[]{if(auto *d=qobject_cast<QDialog*>(QApplication::activeModalWidget()))d->reject();});panel.import->click();QTRY_VERIFY(changed);dialogs.stop();
    QVERIFY(selected);QVERIFY(confirmed);QCOMPARE(server.imports.size(),2);QVERIFY(server.imports[0].value("preview").toBool());QVERIFY(!server.imports[1].value("preview").toBool());
    QCOMPARE(server.imports[0].value("content"),server.imports[1].value("content"));
  }
};
int main(int argc,char **argv){QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);QApplication app(argc,argv);StatisticsChecks checks;return QTest::qExec(&checks,argc,argv);}
#include "task_statistics_checks.moc"
