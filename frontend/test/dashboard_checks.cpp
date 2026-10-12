#include <QtWidgets>
#include <QtNetwork>
#include <QtTest>
#include "ApiClient.h"
#include "pages/DashboardPage.h"
#include "widgets/MetricCard.h"
#include "AppStyle.h"

class DashboardChecks : public QObject {
 Q_OBJECT
private slots:
 void statesAndLateResponses() {
  QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost,0));
  QString mode="normal"; int delay=0; int requests=0; bool writes=false;
  connect(&server,&QTcpServer::newConnection,&server,[&](){while(server.hasPendingConnections()) {
   auto *socket=server.nextPendingConnection(); connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
   connect(socket,&QTcpSocket::readyRead,socket,[&,socket](){
    auto buffer=socket->property("buffer").toByteArray()+socket->readAll();socket->setProperty("buffer",buffer);
    if(!buffer.contains("\r\n\r\n") || socket->property("handled").toBool())return; socket->setProperty("handled",true); ++requests;
    const auto first=buffer.split('\n').first().split(' '); writes |= first[0]!="GET"; const auto path=first[1];
    QJsonObject out{{"status","ok"}};
    if(mode=="error")out={{"status","error"}};
    else if(path=="/api/pipelines") {
     QJsonArray rows;
     if(mode=="normal")for(int i=0;i<3;++i)rows.append(QJsonObject{{"target",i==2?"":"same.invalid"},{"status",i==1?"awaiting_approval":"completed"},{"updated_at",QString("2026-10-%1T10:00:00Z").arg(10+i)}, {"config",QJsonObject{{"task_name",QString("fixture-%1").arg(i)},{"test_type","web"}}},{"analysis_result",QJsonObject{{"risk_assessment",QJsonArray{QJsonObject{{"severity","high"}}}}}}});
     out["data"]=rows;
    }else if(path.startsWith("/api/reports"))out["data"]=QJsonObject{{"total",mode=="empty"?0:7}};
    else if(path=="/api/kg/stats")out["data"]=QJsonObject{{"node_count",8},{"edge_count",9}};
    const auto bytes=QJsonDocument(out).toJson(QJsonDocument::Compact);QPointer<QTcpSocket> guard(socket);
    QTimer::singleShot(delay,socket,[guard,bytes](){if(!guard)return;guard->write("HTTP/1.1 200 OK\r\nContent-Length: "+QByteArray::number(bytes.size())+"\r\nConnection: close\r\n\r\n"+bytes);guard->disconnectFromHost();});
   });
  }});
  ApiClient api(QString("http://127.0.0.1:%1").arg(server.serverPort()));
  DashboardPage page(&api);page.resize(1352,900);page.show();
  auto *table=page.findChild<QTableWidget*>();QVERIFY(table);
  QList<QFrame*> cards; for(auto *frame:page.findChildren<QFrame*>()) if(frame->property("metricCard").toBool()) cards.append(frame); QCOMPARE(cards.size(),4);
  auto value=[&](int i){return cards[i]->findChild<QLabel*>("metricValue")->text();};
  QTRY_COMPARE(table->rowCount(),3);QCOMPARE(value(0),QString("3"));QCOMPARE(value(1),QString("1"));QCOMPARE(value(2),QString("3"));QTRY_COMPARE(value(3),QString("7"));QCOMPARE(table->item(0,0)->text(),QString("fixture-2"));
  mode="error"; page.refresh();QCOMPARE(table->rowCount(),0);QTRY_VERIFY(table->findChild<QLabel*>("itemViewEmptyHint")->text().contains(QStringLiteral("失败")));QCOMPARE(value(0),QString("—"));
  mode="normal";delay=180;int before=requests;page.refresh();QTRY_VERIFY(requests>=before+4);
  mode="empty";delay=0;page.refresh();QTRY_COMPARE(value(0),QString("0"));QTest::qWait(250);QCOMPARE(value(0),QString("0"));QCOMPARE(table->rowCount(),0);QVERIFY(table->findChild<QLabel*>("itemViewEmptyHint")->text().contains(QStringLiteral("暂无")));
  QCOMPARE(page.findChildren<QProgressBar*>().size(),0);QVERIFY(!writes);
  MetricCard unchanged("legacy",Theme::Primary);QVERIFY(unchanged.findChild<QLabel*>("metricCaption")->isHidden());
 }
};
QTEST_MAIN(DashboardChecks)
#include "dashboard_checks.moc"
