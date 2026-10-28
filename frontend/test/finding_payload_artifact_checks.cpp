#include "ApiClient.h"
#include "pages/FindingVerificationDialog.h"
#include <QApplication>
#include <QComboBox>
#include <QGroupBox>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QTimer>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTabWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <functional>

static void verify(bool condition,const char *message) {if(!condition)qFatal("%s",message);}
static bool waitFor(const std::function<bool()> &ready) {for(int i=0;i<300;i++){QCoreApplication::processEvents();if(ready())return true;QTest::qWait(10);}return false;}
int main(int argc,char **argv) {
  QApplication app(argc,argv);
  QTcpServer server;bool collected=false,rewritten=false,sourceAsString=false;int collections=0,rewrites=0,executions=0,preparations=0,generations=0,codePlans=0;QJsonObject rewriteBody,codePlanInput;bool codeGenerated=false;QJsonObject codeInput;
  const QString generatedCode=QString("/* fixture */\n").repeated(250)+"int main(void) { return 0; }";
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
        else if(path.endsWith("/source-payload")){++preparations;verify(path.contains("/fv1/"),"only CScan findings use bounded source payload preparation");}
        else if(path.endsWith("/verification-code")){codeGenerated=true;codeInput=input;}
        else if(path.endsWith("/code-plan")){++codePlans;codePlanInput=input;}
        else if(path.endsWith("/generate")){++generations;verify(path.contains("/fv2/"),"non-CScan findings retain the existing plan-generation interface");}
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
        QJsonArray payloadItems;
        if(first && collected)payloadItems.append(QJsonObject{{"id","scan:pc1:script1"},{"name","Fixture script"},{"origin","scan"},{"code","printf fixture"}});
        if(first && codeGenerated)payloadItems.append(QJsonObject{{"id","generated:vc1:repro.c"},{"name","repro.c"},{"origin","generated"},{"code",generatedCode},{"artifact_id","vc1"},{"execution_supported",true}});
        data={{"current_payload",QJsonObject{{"state",payloadItems.isEmpty()?"missing":"available"},{"items",payloadItems}}},{"id",first?"fv1":"fv2"},{"finding_id",first?101:102},{"revision",0},{"state","needs_conditions"},{"eligible",true},
          {"finding",QJsonObject{{"result_data",first&&!sourceAsString?QJsonValue(finding):QJsonValue(QString::fromUtf8(QJsonDocument(finding).toJson(QJsonDocument::Compact)))}}},
          {"verification_code",first&&codeGenerated?QJsonArray{QJsonObject{{"id","vc1"},{"state","ready"},{"result",QJsonObject{{"files",QJsonArray{QJsonObject{{"filename","repro.c"},{"language","c"},{"source",generatedCode}}}},{"run_conditions",QJsonArray{"Local fixture"}},{"model_inferences",QJsonArray{"Suspected input issue"}}}}}}:QJsonArray()},
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
  verify(waitFor([&]{return !dialog.findChild<QGroupBox*>("findingPayloadArtifacts")->isVisible();}),"source-only collection is collapsed by default");
  verify(waitFor([&]{return items->item(items->currentRow(),3)->text()=="Source fixture";}),"object-format source finding keeps its title");
  verify(!rewrite->isEnabled() && collections==0 && rewrites==0,"opening the dialog neither collects nor rewrites automatically");
  QTabWidget *workflow=nullptr;
  for(auto *tabs:dialog.findChildren<QTabWidget*>())if(tabs->tabText(0)==QStringLiteral("漏洞与测试"))workflow=tabs;
  verify(workflow && workflow->count()==3 && workflow->tabText(1)==QStringLiteral("载荷代码")
    && workflow->tabText(2)==QStringLiteral("测试结果与历史"),"payload and results have separate workflow pages");
  auto *advanced=dialog.findChild<QGroupBox*>("findingAdvancedPayload");
  verify(advanced && !advanced->isVisible(),"manual payload wiring is collapsed by default");
  workflow->setCurrentIndex(1);
  auto *generateSource=dialog.findChild<QPushButton*>("findingGenerateSourcePayload");
  auto *requestCode=dialog.findChild<QPlainTextEdit*>("findingSourceRequestCode");
  verify(generateSource && requestCode && waitFor([&]{return !generateSource->isVisible();}),"generation is visible even before collection");
  verify(!requestCode->isVisible(),"legacy HTTP request panel is not presented");
  verify(!collect->isVisible(),"collection controls are not presented");
  auto *codeButton=dialog.findChild<QPushButton*>("findingGenerateVerificationCode");
  verify(codeButton && codeButton->isEnabled(),"code-only generation is available without a plan");
  codeButton->click();
  auto *generated=dialog.findChild<QPlainTextEdit*>("findingVerificationSource");
  verify(waitFor([&]{return generated->toPlainText().contains(generatedCode);}),"full code survives API response and display without log truncation");
  verify(codeInput["authorization_confirmed"].toBool() && codeInput["automatic_context"].toBool(),"one click requests server-resolved context");
  verify(!QApplication::activeModalWidget() && !codeInput.contains("source") && !codeInput.contains("environment"),"no context form or invented client inputs");
  verify(!dialog.findChild<QPlainTextEdit*>("findingVerificationCodeNotes"),"unused metadata viewer is not allocated");
  verify(!codeButton->isVisible(),"existing payload does not show another generation entry");
  auto *prepareCode=dialog.findChild<QPushButton*>("findingPrepareCode");
  verify(prepareCode && prepareCode->isVisible() && prepareCode->isEnabled(),"generated executable artifacts expose local test preparation");
  prepareCode->click();
  verify(waitFor([&]{return codePlans==1 && prepareCode->isEnabled();}),"preparation saves a local plan without starting execution");
  verify(codePlanInput["artifact_id"]=="vc1" && codePlanInput["expected_revision"].toInt()==0,"local plan uses the selected saved artifact and current revision");
  workflow->setCurrentIndex(0);
  auto *advancedSettings=dialog.findChild<QGroupBox*>("findingAdvancedSettings");
  verify(advancedSettings,"advanced settings remain available");advancedSettings->setChecked(true);
  verify(waitFor([&]{return collect->isVisible() && collect->isEnabled() && advanced->isVisible();}),"advanced settings expose collection retry and manual payload wiring");
  collect->click();verify(waitFor([&]{return original->toPlainText()=="printf fixture" && rewrite->isVisible() && rewrite->isEnabled();}),"the collected script is visible and can be selected for conversion");
  rewrite->click();verify(waitFor([&]{return python->toPlainText().contains("print('fixture')");}),"the Python rewrite appears alongside its original");
  verify(rewriteBody["collection_id"]=="pc1" && rewriteBody["script_id"]=="script1" && rewriteBody["source_hash"]=="hash1","rewrites bind to the selected immutable source script");
  workflow->setCurrentIndex(1);
  auto *payloadChoice=dialog.findChild<QComboBox*>("findingVerificationCodeHistory");
  verify(waitFor([&]{return payloadChoice->count()==2 && payloadChoice->isVisible();}),"only payloads linked to this finding are selectable");
  payloadChoice->setCurrentIndex(0);verify(generated->toPlainText()=="printf fixture","collected scan payload is shown in the same code viewer");
  verify(!prepareCode->isVisible(),"scan reference text is not treated as an executable local program");
  generated->selectAll();original->selectAll();python->selectAll();QTest::qWait(2200);
  verify(generated->textCursor().hasSelection(),"refresh preserves current payload code selection");
  verify(original->textCursor().hasSelection() && python->textCursor().hasSelection(),"periodic refresh preserves code selection for review and copying");
  verify(dialog.findChild<QLabel*>("findingArtifactStatus")->text().contains(QStringLiteral("不表示漏洞已验证")),"displayed scripts remain explicitly unverified");
  QPushButton *prepare=nullptr;
  for(auto *button:dialog.findChildren<QPushButton*>())if(button->text()==QStringLiteral("准备本次测试"))prepare=button;
  verify(prepare && waitFor([&]{return prepare->isEnabled();}),"the preparation action is available for the source finding");
  workflow->setCurrentIndex(0);
  verify(waitFor([&]{return dialog.findChild<QPushButton*>("findingSourceRuntime")->isVisible();}),"runtime settings remain accessible on the test page after simplifying payloads");
  verify(dialog.findChild<QLabel*>("findingPrepareFeedback")->isVisible() && dialog.findChild<QLabel*>("findingPrepareFeedback")->text().contains(QStringLiteral("尚未接入")),"missing execution environment is explained next to preparation");
  sourceAsString=true;
  prepare->click();
  verify(waitFor([&]{return preparations==1 && prepare->isEnabled();}),"CScan preparation generates bounded inputs independently of collection");
  prepare->click();
  verify(waitFor([&]{return preparations==2 && prepare->isEnabled();}),"legacy JSON-string source findings also use bounded source preparation");
  for(int row=0;row<items->rowCount();row++)if(items->item(row,0)->data(Qt::UserRole)=="fv2")items->setCurrentCell(row,0);
  verify(waitFor([&]{return dialog.findChild<QGroupBox*>("findingPayloadArtifacts")->isHidden() && original->toPlainText().isEmpty() && python->toPlainText().isEmpty();}),"switching findings clears old private script content");
  verify(waitFor([&]{return items->item(items->currentRow(),3)->text()=="Other fixture";}),"legacy JSON-string finding keeps its title");
  verify(waitFor([&]{return prepare->isEnabled();}),"legacy finding preparation remains available");
  prepare->click();
  verify(waitFor([&]{return generations==1;}),"legacy findings continue using the existing generator");
  verify(preparations==2 && generations==1,"source postprocessing and existing program generation remain distinct");
  verify(collections==1 && rewrites==1 && executions==0,"collecting and rewriting never dispatch execution");
  return 0;
}
