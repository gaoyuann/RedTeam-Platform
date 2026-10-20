#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include "ApiClient.h"
#define private public
#include "pages/TaskStatisticsPanel.h"
#undef private

int main(int argc,char **argv) {
  QApplication app(argc,argv);QTcpServer server;int requests=0;bool wrongMethod=false;
  QObject::connect(&server,&QTcpServer::newConnection,&app,[&]{while(server.hasPendingConnections()){
    auto *socket=server.nextPendingConnection();QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{const auto request=socket->readAll();++requests;if(!request.startsWith("GET "))wrongMethod=true;
      const QJsonObject data{{"source_fingerprint","policy-fixture"},{"rows",QJsonArray{QJsonObject{{"instance_id","instance-fixture"},{"severity","low"},{"conclusion","confirmed"},{"record_ids",QJsonArray{1}}}}},{"page",QJsonObject{{"has_more",false}}}};
      const auto content=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+QByteArray::number(content.size())+"\r\nConnection: close\r\n\r\n"+content);socket->disconnectFromHost();});QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
  }});if(!server.listen(QHostAddress::LocalHost))return 1;
  ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));TaskStatisticsPanel panel(&api);panel.resize(1360,860);panel.show();
  const QJsonObject counts{{"confirmed_instances",1},{"conclusions",QJsonObject{{"confirmed",1}}}};
  auto snapshot=[](const QJsonObject &stats){return QJsonObject{{"pipeline_id","policy-task"},{"source_fingerprint","policy-fixture"},{"statistics",stats}};};
  const QJsonObject historical{{"schema_version",1},{"verifications",counts}};
  auto wait=[&]{for(int i=0;i<100&&panel.table->rowCount()!=1;++i)QTest::qWait(10);return panel.table->rowCount()==1;};
  panel.setSnapshot(snapshot(historical));if(!wait())return 2;
  if(!panel.historicalResults||!panel.conclusions->historicalConclusions||!panel.table->item(0,2)->text().startsWith("历史")||panel.filter->itemText(panel.filter->findData("confirmed")).contains("系统确认")||panel.metrics[4]->findChild<QLabel*>("metricValue")->text()!="—"||!panel.table->horizontalHeaderItem(2)->text().contains("历史"))return 3;
  if(statisticsConclusionLabel("confirmed",panel.conclusions->historicalConclusions).contains("系统确认"))return 4;
  panel.conclusions->selected("confirmed");if(!wait()||panel.filter->currentData()!="confirmed"||!panel.filter->currentText().startsWith("历史"))return 5;
  auto current=historical;current["result_schema_version"]=1;current["result_policy"]="system_evidence_only";
  // A policy change with the same server fingerprint is still a distinct display contract.
  panel.setSnapshot(snapshot(current));if(!wait()||panel.historicalResults||panel.conclusions->historicalConclusions||panel.filter->itemText(panel.filter->findData("confirmed"))!="系统确认目标达成"||panel.metrics[4]->findChild<QLabel*>("metricValue")->text()!="1"||panel.table->item(0,2)->text()!="系统确认目标达成")return 6;
  current["result_schema_version"]=99;panel.setSnapshot(snapshot(current));if(!wait()||!panel.historicalResults||!panel.table->item(0,2)->text().startsWith("历史"))return 7;
  if(wrongMethod||requests<3)return 8;qInfo()<<"Historical and current result statistics remain distinguishable in chart, filter, metric and table; loopback GET fixtures only.";return 0;
}
