#include "ApiClient.h"
#include "pages/FindingVerificationDialog.h"
#include <QApplication>
#include <QComboBox>
#include <QGroupBox>
#include <QJsonDocument>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <functional>

static void verify(bool condition,const char *message) {if(!condition)qFatal("%s",message);}
static bool waitFor(const std::function<bool()> &ready) {for(int i=0;i<300;i++){QCoreApplication::processEvents();if(ready())return true;QTest::qWait(10);}return false;}
int main(int argc,char **argv) {
  QApplication app(argc,argv);
  QTcpServer server;bool collected=false,rewritten=false;int collections=0,rewrites=0,executions=0;QJsonObject rewriteBody;
  QObject::connect(&server,&QTcpServer::newConnection,&server,[&](){
    while(auto *socket=server.nextPendingConnection())QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket](){
      const auto bytes=socket->property("buffer").toByteArray()+socket->readAll();socket->setProperty("buffer",bytes);
      const int split=bytes.indexOf("\r\n\r\n");if(split<0 || socket->property("handled").toBool())return;
      int length=0;for(const auto &line:bytes.left(split).split('\n'))if(line.toLower().startsWith("content-length:"))length=line.mid(15).trimmed().toInt();
      if(bytes.size()<split+4+length)return;socket->setProperty("handled",true);
      const auto request=bytes.left(bytes.indexOf('\r')).split(' ');const auto path=QString::fromUtf8(request[1]);
      const auto input=QJsonDocument::fromJson(bytes.mid(split+4,length)).object();QJsonObject data;
      if(request[0]=="POST") {
        if(path.endsWith("/payloads/collect")){++collections;collected=true;verify(input["expected_revision"].toInt()==0,"collection retains the current plan revision");}
        else if(path.endsWith("/payloads/python")){++rewrites;rewritten=true;rewriteBody=input;}
        else if(path.endsWith("/verifications")){const int finding=input["finding_id"].toInt();data={{"id",finding==101?"fv1":"fv2"},{"finding_id",finding},{"state","needs_conditions"}};}
        else ++executions;
      } else if(path.contains("/sources"))data={{"items",QJsonArray()},{"total",0}};
      else {
        const bool first=path.endsWith("fv1");
        const QJsonObject finding{{"title",first?"Source fixture":"Other fixture"},{"file","src/input.c"},{"start_line",12},{"evidence_origin",first?"cscan_report":"tool_output"}};
        QJsonArray records;
        if(first && collected) {
          const QJsonObject script{{"id","script1"},{"source_hash","hash1"},{"name","Fixture script"},{"language","sh"},{"content","printf fixture"},{"source_type","subtask"},{"source_id","s1"},{"usage","Review first"}};
          QJsonArray python;if(rewritten)python.append(QJsonObject{{"script_id","script1"},{"source_hash","hash1"},{"state","ready"},{"python_code","print('fixture')"},{"explanation","Equivalent input"},{"usage","Not executed"}});
          records.append(QJsonObject{{"id","pc1"},{"flow_id","91"},{"assistant_id","10"},{"state","ready"},{"scripts",QJsonArray{script}},{"rewrites",python}});
        }
        data={{"id",first?"fv1":"fv2"},{"finding_id",first?101:102},{"revision",0},{"state","needs_conditions"},{"eligible",true},
          {"finding",QJsonObject{{"result_data",QString::fromUtf8(QJsonDocument(finding).toJson(QJsonDocument::Compact))}}},
          {"plans",QJsonArray()},{"attempts",QJsonArray()},{"payloads",QJsonObject{{"matches",QJsonArray()}}},
          {"payload_artifacts",QJsonObject{{"supported",true},{"collections",records}}},{"readiness",QJsonObject{{"ready",false}}}};
      }
      const auto body=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);
      socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(body.size())+"\r\n\r\n"+body);socket->disconnectFromHost();
      QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
    });
  });
  verify(server.listen(QHostAddress::LocalHost,0),"mock API starts");
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  FindingVerificationDialog dialog(&api,"ap",{101,102});dialog.show();
  auto *collect=dialog.findChild<QPushButton*>("findingCollectPayloads"),*rewrite=dialog.findChild<QPushButton*>("findingRewritePython");
  auto *original=dialog.findChild<QPlainTextEdit*>("findingCollectedPayload"),*python=dialog.findChild<QPlainTextEdit*>("findingPythonPayload");
  QTableWidget *items=nullptr;for(auto *table:dialog.findChildren<QTableWidget*>())if(table->columnCount()==6)items=table;
  verify(items && waitFor([&]{return items->rowCount()==2;}),"both findings are available");
  for(int row=0;row<items->rowCount();row++)if(items->item(row,0)->data(Qt::UserRole)=="fv1")items->setCurrentCell(row,0);
  verify(waitFor([&]{return collect->isEnabled() && !dialog.findChild<QGroupBox*>("findingPayloadArtifacts")->isHidden();}),"source-only findings can collect before creating a plan");
  verify(!rewrite->isEnabled() && collections==0 && rewrites==0,"opening the dialog neither collects nor rewrites automatically");
  collect->click();verify(waitFor([&]{return original->toPlainText()=="printf fixture" && rewrite->isEnabled();}),"the collected script is visible and can be selected for conversion");
  rewrite->click();verify(waitFor([&]{return python->toPlainText().contains("print('fixture')");}),"the Python rewrite appears alongside its original");
  verify(rewriteBody["collection_id"]=="pc1" && rewriteBody["script_id"]=="script1" && rewriteBody["source_hash"]=="hash1","rewrites bind to the selected immutable source script");
  original->selectAll();python->selectAll();QTest::qWait(2200);
  verify(original->textCursor().hasSelection() && python->textCursor().hasSelection(),"periodic refresh preserves code selection for review and copying");
  verify(dialog.findChild<QLabel*>("findingArtifactStatus")->text().contains(QStringLiteral("不表示漏洞已验证")),"displayed scripts remain explicitly unverified");
  for(int row=0;row<items->rowCount();row++)if(items->item(row,0)->data(Qt::UserRole)=="fv2")items->setCurrentCell(row,0);
  verify(waitFor([&]{return dialog.findChild<QGroupBox*>("findingPayloadArtifacts")->isHidden() && original->toPlainText().isEmpty() && python->toPlainText().isEmpty();}),"switching findings clears old private script content");
  verify(collections==1 && rewrites==1 && executions==0,"collecting and rewriting never dispatch execution");
  return 0;
}
