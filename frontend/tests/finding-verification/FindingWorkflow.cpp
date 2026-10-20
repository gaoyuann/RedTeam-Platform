#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include "ApiClient.h"
#include "AppStyle.h"
#define private public
#include "pages/FindingVerificationDialog.h"
#undef private

int main(int argc,char **argv) {
 QApplication app(argc,argv);app.setStyle("Fusion");app.setStyleSheet(Theme::GlobalStyle+Theme::ButtonStyle+Theme::ItemViewStyle);
 QTcpServer server;QMap<QString,int> requests;QMap<QString,QJsonObject> bodies;
 const bool slowPayload=app.arguments().contains("--slow-payload");
 int revision=0;QString state="needs_conditions";bool generated=false,bound=false,reviewed=false,createdHere=true;
 QJsonObject step{{"step_id","finding_step_0"},{"step_index",0},{"name","检查防护响应头"},{"tool_id","target-request"},
   {"args_template",QJsonArray{"{\"url\":\"http://fixture.invalid/{{entry}}\",\"method\":\"GET\"}"}},{"payload_variables",QJsonObject{{"entry","item"}}},{"consumption","none"},{"expected_evidence","HTML 响应和防护响应头"}};
 QJsonObject plan{{"name","Web 防护响应头检查"},{"target","http://fixture.invalid/item"},{"source_playbook_id","headers"},
   {"provenance",QJsonObject{{"kind","builtin"},{"label","内置定向方案"}}},{"prerequisites",QJsonArray{"明确授权当前入口"}},
   {"success_criteria","完整 HTML 缺少防护响应头"},{"cleanup","只读检查，无需清理"},{"max_attempts",2},{"duration_ms",300000},
   {"missing_conditions",QJsonArray{}},{"assessment_rule",QJsonObject{{"id","headers-v1"}}}};
 auto detail=[&] {
  auto s=step;if(bound){s["consumption"]="independent";s["payload_id"]="generated-header";s["payload_version"]="hash-1";s["payload_snapshot"]=QJsonObject{{"name","响应头检查输入"}};}
  auto p=plan;p["steps"]=QJsonArray{s};
  const auto payload=QJsonObject{{"payload_id","generated-header"},{"name","响应头检查输入"},{"version","hash-1"},{"consumption","tool_args"},{"provenance","ai"},{"created_here",createdHere},
    {"match_basis","与当前发现签名一致"},{"preview",QJsonArray{QJsonObject{{"label","方法"},{"value","GET"}},QJsonObject{{"label","位置"},{"value","http://fixture.invalid/item"}}}},
    {"compatible_steps",QJsonArray{QJsonObject{{"step_id","finding_step_0"},{"compatible",true}}}}};
  const auto evidence=QJsonObject{{"id",77},{"step_index",0},{"tool_id","target-request"},{"evidence_data",QJsonObject{{"status_code",200},{"payload_id","generated-header"},{"payload_version",1},{"summary","HTML 响应缺少防护头"},
    {"finding_verification",QJsonObject{{"payload_consumed",true}}}}}};
  return QJsonObject{{"id","v"},{"finding_id",123},{"eligible",true},{"revision",revision},{"state",state},{"default_target","http://fixture.invalid/item"},
    {"finding",QJsonObject{{"id",123},{"severity","medium"},{"source_tool","nikto"},{"result_data","{\"finding\":\"X-Content-Type-Options header not set\",\"path\":\"/item\"}"}}},
    {"plans",revision?QJsonArray{QJsonObject{{"revision",revision},{"fingerprint","fp"+QString::number(revision)},{"content",p}}}:QJsonArray{}},
    {"readiness",QJsonObject{{"ready",revision>0},{"reasons",revision?QJsonArray{}:QJsonArray{"请选择方案"}}}},
    {"payloads",QJsonObject{{"matches",generated?QJsonArray{payload}:QJsonArray{}}}},
    {"summary",QJsonObject{{"run_id",state=="completed"?"run-workflow":""},{"conclusion",state=="completed"?(reviewed?"inconclusive":"confirmed"):"pending"},{"method",state=="completed"?(reviewed?"manual":"automatic"):"pending"},{"note","根据实际响应判定"}}},
    {"attempts",state=="completed"?QJsonArray{QJsonObject{{"id","attempt"},{"state",state},{"stop_confirmed",1},{"revision",revision},{"evidence",QJsonArray{evidence}},
      {"assessments",QJsonArray{QJsonObject{{"conclusion","confirmed"},{"reason","完整 HTML 缺少防护头"},{"limitations","仅检查本入口配置"}}}}}}:QJsonArray{}}};
 };
 QObject::connect(&server,&QTcpServer::newConnection,&app,[&]{while(server.hasPendingConnections()){
  auto *socket=server.nextPendingConnection();QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
  QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{
   const auto bytes=socket->property("bytes").toByteArray()+socket->readAll();socket->setProperty("bytes",bytes);const int end=bytes.indexOf("\r\n\r\n");if(end<0||socket->property("done").toBool())return;
   const auto len=QRegularExpression("Content-Length: (\\d+)",QRegularExpression::CaseInsensitiveOption).match(QString::fromUtf8(bytes.left(end))).captured(1).toInt();if(bytes.size()<end+4+len)return;socket->setProperty("done",true);
   const auto first=bytes.left(bytes.indexOf('\r')).split(' ');const QString method=first[0];const QString path=QUrl(QString::fromUtf8(first[1])).path();requests[method+" "+path]++;
   const auto body=QJsonDocument::fromJson(bytes.mid(end+4)).object();bodies[path]=body;QJsonValue data;
   if(path.endsWith("/verifications"))data=QJsonObject{{"id","v"},{"finding_id",123},{"state",state}};
   else if(path.endsWith("/sources"))data=QJsonObject{{"total",1},{"items",QJsonArray{QJsonObject{{"playbook_id","headers"},{"name","Web 防护响应头检查"},{"status","directional_candidate"},{"source",QJsonObject{{"label","内置定向方案"}}},{"match_basis","当前发现对应配置检查"},{"steps",QJsonArray{step}}}}}};
   else if(path.endsWith("/select-template")){revision=1;state="draft";data=QJsonObject{{"revision",revision}};}
   else if(path.endsWith("/payloads/prepare")){generated=true;data=QJsonObject{{"state","generated"},{"payload_id","generated-header"},{"bound",false}};}
   else if(path.endsWith("/payloads/bind")){bound=true;revision=2;data=QJsonObject{{"revision",revision}};}
   else if(path.endsWith("/start")){state="completed";data=QJsonObject{{"run_id","run-workflow"}};}
   else if(path.endsWith("/reviews")){reviewed=true;data=QJsonObject{{"conclusion","inconclusive"}};}
   else data=detail();
   const auto content=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);
   auto respond=[socket,content]{socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(content.size())+"\r\n\r\n"+content);socket->disconnectFromHost();};
   if(slowPayload && path.endsWith("/payloads/prepare"))QTimer::singleShot(16500,socket,respond);
   else respond();
  });
 }});
 if(!server.listen(QHostAddress::LocalHost))return 1;ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
 FindingVerificationDialog dialog(&api,"p",{123});dialog.resize(1200,820);dialog.show();
 auto wait=[&](std::function<bool()> f,int limit=150){for(int i=0;i<limit;i++){if(f())return true;QTest::qWait(20);}return false;};
 if(!wait([&]{return dialog.m_sources->count()==1&&!dialog.m_loading;}))return 2;dialog.m_timer->stop();
 if(requests.value("POST /api/pipelines/p/verifications/v/generate")||revision!=0||dialog.m_sources->currentIndex()!=-1)return 3;
 dialog.m_sources->setCurrentIndex(0);if(!dialog.m_sourcePreview->toPlainText().contains("配置检查"))return 4;dialog.m_useSource->click();
 if(!wait([&]{return dialog.m_revision==1&&!dialog.m_loading&&!dialog.m_busy;}))return 5;
 if(!dialog.m_planSummary->toPlainText().contains("内置定向方案") || !dialog.m_planSummary->toPlainText().contains("GET http://fixture.invalid/item") || dialog.m_planSummary->toPlainText().contains("{{entry}}"))return 6;
 if(dialog.m_bindStep->currentIndex()!=-1)return 7;dialog.m_bindStep->setCurrentIndex(0);dialog.m_resolvePayload->click();
 if(!wait([&]{return dialog.m_payloads->count()==1&&!dialog.m_loading&&!dialog.m_busy;},slowPayload?1000:150))return 8;
 if(dialog.m_payloads->itemData(0,Qt::ForegroundRole).value<QColor>()!=QColor("#b45309")
     || !dialog.m_payloadOrigin->text().contains("已保存到载荷库"))return 20;
 if(bound||dialog.m_revision!=1||!dialog.m_payloadPreview->toPlainText().contains("本次新生成"))return 9;
 if(!dialog.m_payloadPreview->toPlainText().contains("GET"))return 10;
 dialog.m_bindPayload->click();if(!wait([&]{return dialog.m_revision==2&&!dialog.m_loading&&!dialog.m_busy;}))return 11;
 if(!dialog.m_payloadPreview->toPlainText().contains("已绑定"))return 12;
 dialog.grab().save("workflow-selected.png");
 const auto scroll=dialog.m_tabs->widget(0)->findChild<QScrollArea*>();scroll->verticalScrollBar()->setValue(scroll->verticalScrollBar()->maximum());QTest::qWait(40);dialog.grab().save("workflow-payload.png");
 scroll->verticalScrollBar()->setValue(0);
 dialog.resize(1024,600);QTest::qWait(40);if(dialog.size()!=QSize(1024,600))return 19;dialog.grab().save("workflow-narrow.png");
 QTimer::singleShot(0,[]{auto *box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget());if(box)box->button(QMessageBox::Yes)->click();});dialog.m_startSimple->click();
 if(!wait([&]{return dialog.m_detail["summary"].toObject()["conclusion"]=="confirmed"&&!dialog.m_loading;}))return 13;
 const auto started=bodies.value("/api/pipelines/p/verifications/v/start");if(started["fingerprint"]!="fp2"||!started["confirmed"].toBool())return 14;
 dialog.m_tabs->setCurrentIndex(1);if(!dialog.m_evidence->toPlainText().contains("自动判定")||!dialog.m_evidence->toPlainText().contains("实际消费载荷"))return 15;
 dialog.m_evidenceTable->item(0,0)->setCheckState(Qt::Checked);dialog.m_note->setPlainText("需要结合应用部署要求复核");dialog.m_conclusion->setCurrentIndex(dialog.m_conclusion->findData("inconclusive"));
 for(auto *button:dialog.findChildren<QPushButton*>())if(button->text()=="保存证据复核")button->click();
 if(!wait([&]{return dialog.m_detail["summary"].toObject()["method"]=="manual"&&!dialog.m_loading;}))return 16;
 if(bodies.value("/api/pipelines/p/verifications/v/reviews")["evidence_ids"].toArray()!=QJsonArray{77})return 17;
 dialog.grab().save("workflow-result.png");
 createdHere=false;dialog.load();
 if(!wait([&]{return !dialog.m_loading && dialog.m_payloadOrigin->text().contains("原始来源：AI");}))return 21;
 if(dialog.m_payloads->itemData(0,Qt::ForegroundRole).value<QColor>()!=QColor("#1d4ed8"))return 22;
 return 0;
}
