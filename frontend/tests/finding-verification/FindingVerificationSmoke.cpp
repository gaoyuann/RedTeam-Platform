#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include <functional>
#include "ApiClient.h"
#define private public
#include "pages/FindingVerificationDialog.h"
#undef private

int main(int argc,char **argv) {
  QApplication app(argc,argv);app.setStyle("Fusion");
  QTcpServer server;QMap<QString,int> requests;QMap<QString,QJsonObject> bodies;
  QString state="ready";QString conclusion="pending";
  QJsonObject plan{{"name","SQL 注入候选的独立验证"},{"target","http://fixture.invalid/item"},
    {"prerequisites",QJsonArray{"隔离环境与正常对照已准备"}},{"missing_conditions",QJsonArray{}},
    {"success_criteria","根据正常对照和实际证据人工复核；HTTP 成功不能证明漏洞成立"},{"cleanup","只读样例，无需清理"},
    {"steps",QJsonArray{QJsonObject{{"name","正常对照"},{"tool_id","target-request"},{"args_template",QJsonArray{"{\"url\":\"http://fixture.invalid/item\",\"method\":\"GET\"}"}},
      {"consumption","none"},{"expected_evidence","保存响应与正常对照"}}}}};
  QObject::connect(&server,&QTcpServer::newConnection,&app,[&]{while(server.hasPendingConnections()){
    auto *socket=server.nextPendingConnection();QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
    QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{
      QByteArray buffer=socket->property("buffer").toByteArray()+socket->readAll();socket->setProperty("buffer",buffer);
      const int end=buffer.indexOf("\r\n\r\n");if(end<0||socket->property("handled").toBool())return;
      const auto match=QRegularExpression("Content-Length: (\\d+)",QRegularExpression::CaseInsensitiveOption).match(QString::fromUtf8(buffer.left(end)));
      if(buffer.size()<end+4+match.captured(1).toInt())return;socket->setProperty("handled",true);
      const auto first=buffer.left(buffer.indexOf('\r')).split(' ');const QString method=first[0],path=first[1];requests[method+" "+path]++;
      const auto body=QJsonDocument::fromJson(buffer.mid(end+4)).object();bodies[method+" "+path]=body;
      QJsonValue data;
      if(path.endsWith("/verifications"))data=QJsonObject{{"id","v1"},{"finding_id",123},{"state",state}};
      else if(path.endsWith("/reviews"))data=QJsonObject{{"conclusion","not_verified"}};
      else if(path.endsWith("/sources"))data=QJsonArray{};
      else if(path.endsWith("/confirm")){data=QJsonObject{{"state","ready"}};}
      else if(path.endsWith("/start")){state="running";data=QJsonObject{{"state",state},{"run_id","run-fixture"}};}
      else if(path.endsWith("/cancel")){state="cancelling";data=QJsonObject{{"state",state}};}
      else data=QJsonObject{{"id","v1"},{"finding_id",123},{"readiness",QJsonObject{{"ready",state=="ready"||state=="completed"},{"reasons",QJsonArray{}}}},{"revision",1},{"state",state},{"finding",QJsonObject{{"id",123},{"result_data",QString::fromUtf8(QJsonDocument(QJsonObject{{"finding","SQL 注入候选"},{"url","http://fixture.invalid/item"},{"path","/item"},{"internal_marker","DO_NOT_DISPLAY_RAW_JSON"}}).toJson(QJsonDocument::Compact))}}},
        {"summary",QJsonObject{{"conclusion",conclusion},{"run_id","run-fixture"}}},{"plans",QJsonArray{QJsonObject{{"revision",1},{"fingerprint","fp1"},{"confirmed_at","fixture"},{"content",plan}}}},
        {"attempts",QJsonArray{QJsonObject{{"id","attempt-fixture"},{"run_id","run-fixture"},{"state",state},{"revision",1},{"stop_confirmed",1},
          {"evidence",QJsonArray{QJsonObject{{"id",77},{"step_index",0},{"tool_id","target-request"},
             {"evidence_data",QJsonObject{{"status_code",200},{"summary","返回登录页面；尚未证明存在注入"},{"internal_marker","DO_NOT_DISPLAY_RAW_JSON"}}},
             {"observation",QJsonObject{{"status_code",200},{"complete",true},{"response_headers",QJsonObject{{"x-frame-options","DENY"}}},{"login_form_present",true},{"cookie_attributes",QJsonArray{QJsonObject{{"name","fixture_session"},{"httponly",true},{"secure",false}}}}}},
             {"raw_stdout",R"({"internal_marker":"DO_NOT_DISPLAY_RAW_JSON","status_code":200,"response":"DO_NOT_DISPLAY_RAW_BODY","complete":true,"response_headers":{"content-type":"text/html","x-frame-options":"DENY"},"cookie_attributes_complete":true,"cookie_attributes":[{"name":"fixture_session","httponly":true,"secure":false}]})"}}}}}}},{"payloads",QJsonObject{{"matches",QJsonArray{}}}}};
      const auto payload=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);
      QPointer<QTcpSocket> guard(socket);QTimer::singleShot(path.endsWith("/v1")?30:0,&app,[guard,payload]{if(guard){guard->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(payload.size())+"\r\n\r\n"+payload);guard->disconnectFromHost();}});
    });
  }});
  if(!server.listen(QHostAddress::LocalHost))return 1;
  ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
  FindingVerificationDialog dialog(&api,"p",{123});dialog.show();
  auto wait=[&](std::function<bool()> condition){for(int i=0;i<100;i++){if(condition())return true;QTest::qWait(20);}return false;};
  if(!wait([&]{return dialog.m_revision==1;}))return 2;
  if(dialog.m_items->item(0,2)->text()!="证据不足（旧版接口）"||dialog.m_target->text()!="http://fixture.invalid/item")return 3;
  if(dialog.m_tabs->currentIndex()!=0 || !dialog.m_planSummary->toPlainText().contains("http://fixture.invalid/item") || !dialog.m_startSimple->isEnabled())return 12;
  if(dialog.m_planSummary->toPlainText().contains("判断方式：人工")||!dialog.m_planSummary->toPlainText().contains("人工意见：可选补充"))return 24;
  dialog.m_criteria->setPlainText("修改后的判据");if(dialog.m_start->isEnabled()||dialog.m_confirmButton->isEnabled()||dialog.m_startSimple->isEnabled()||dialog.m_confirmSimple->isEnabled())return 4;
  dialog.load(true);if(!wait([&]{return !dialog.m_dirty;}))return 5;
  QTimer::singleShot(0,[]{auto *box=QApplication::activeModalWidget();if(box)if(auto *yes=box->findChild<QPushButton*>("confirmFindingExecution"))yes->click();});QTest::mouseClick(dialog.m_start,Qt::LeftButton);
  if(!wait([&]{return state=="running"&&!dialog.m_busy;}))return 6;
  dialog.load(false);if(!wait([&]{return !dialog.m_start->isEnabled();}))return 7;
  const auto execute=bodies.value("POST /api/pipelines/p/verifications/v1/start");
  if(execute["revision"].toInt()!=1||execute["request_id"].toString().isEmpty())return 8;
  state="completed";dialog.load(false);if(!wait([&]{return dialog.m_items->item(0,1)->text().contains("执行结束");}))return 9;
  if(dialog.m_items->item(0,2)->text()!="证据不足（旧版接口）")return 10;
  if(!dialog.m_items->isEnabled() || !dialog.m_activeQueue.isEmpty() || !dialog.m_start->isEnabled())return 11;
  if(dialog.m_evidenceTable->rowCount()!=1 || !dialog.m_evidenceTable->item(0,3)->text().contains("200"))return 13;
  if(!dialog.m_context->toPlainText().contains("扫描位置：/item"))return 19;
  if(dialog.m_context->toPlainText().contains("DO_NOT_DISPLAY_RAW_JSON") || dialog.m_evidenceTable->item(0,3)->text().contains("DO_NOT_DISPLAY_RAW_JSON"))return 14;
  const auto observed=dialog.m_evidenceDetails->toPlainText();
  if(!observed.contains("x-frame-options：DENY") || !observed.contains("fixture_session") || !observed.contains("HttpOnly：是") || !observed.contains("Secure：否") || !observed.contains("检测到密码输入框特征：是") || observed.contains("DO_NOT_DISPLAY_RAW_BODY"))return 20;
  dialog.m_evidenceTable->item(0,0)->setCheckState(Qt::Checked);dialog.load(false);
  if(!wait([&]{return !dialog.m_loading;}))return 15;
  if(dialog.m_evidenceTable->item(0,0)->checkState()!=Qt::Checked)return 16;
  if(!dialog.m_conclusion->currentData().toString().isEmpty())return 21;
  auto saveReview=[&]{dialog.m_tabs->setCurrentWidget(dialog.findChild<QWidget*>("findingResultsPage"));dialog.m_resultDetails->setCurrentIndex(1);for(auto *button:dialog.findChildren<QPushButton*>())if(button->text()=="保存人工意见"){qobject_cast<QScrollArea*>(dialog.m_resultDetails->widget(1))->ensureWidgetVisible(button,0,0);QTest::qWait(20);QTest::mouseClick(button,Qt::LeftButton);}};
  saveReview();
  QTest::qWait(40);if(requests.value("POST /api/pipelines/p/verifications/v1/reviews")!=0)return 22;
  dialog.m_conclusion->setCurrentIndex(dialog.m_conclusion->findData("confirmed"));dialog.m_note->setPlainText("未提交的上一尝试说明");
  auto attempts=dialog.m_detail["attempts"].toArray();auto other=attempts.first().toObject();other["id"]="other-attempt";attempts.append(other);dialog.m_detail["attempts"]=attempts;
  dialog.renderAttempt(1);
  if(!dialog.m_conclusion->currentData().toString().isEmpty() || !dialog.m_note->toPlainText().isEmpty() || dialog.m_evidenceTable->item(0,0)->checkState()==Qt::Checked)return 23;
  dialog.renderAttempt(0);dialog.m_evidenceTable->item(0,0)->setCheckState(Qt::Checked);
  dialog.m_note->setPlainText("仅观察到正常页面，不满足预期判据");dialog.m_conclusion->setCurrentIndex(dialog.m_conclusion->findData("not_verified"));
  saveReview();
  if(!wait([&]{return requests.value("POST /api/pipelines/p/verifications/v1/reviews")==1;}))return 17;
  if(bodies.value("POST /api/pipelines/p/verifications/v1/reviews")["evidence_ids"].toArray()!=QJsonArray{77})return 18;
  dialog.m_timer->stop();dialog.grab().save("finding-verification-smoke.png");
  dialog.resize(1024,600);QTest::qWait(40);dialog.grab().save("finding-verification-narrow.png");
  dialog.m_tabs->setCurrentIndex(0);QTest::qWait(40);dialog.grab().save("finding-verification-plan.png");
  dialog.m_tabs->setCurrentWidget(dialog.findChild<QWidget*>("findingResultsPage"));QTest::qWait(40);dialog.grab().save("finding-verification-evidence.png");
  // A late reply must not dereference a destroyed dialog.
  auto *late=new FindingVerificationDialog(&api,"p",{124});delete late;QTest::qWait(100);
  return 0;
}
