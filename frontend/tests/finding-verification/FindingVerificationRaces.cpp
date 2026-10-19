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
  const QString mode=argc>1 ? QString::fromUtf8(argv[1]) : QString();
  QTcpServer server;QMap<QString,int> requests;QMap<QString,QJsonObject> bodies;
  QString state="ready";QString conclusion="pending";int revision=1;int detailDelay=30;int executeDelay=0;bool eligible=true;QString reason;
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
      else if(path.endsWith("/generate") && mode=="preparation-result") {state="preparation_failed";reason="方案准备失败，未启动新的验证执行：未提供可执行步骤。";data=QJsonObject{};}
      else if(path.endsWith("/select-template"))data=plan;
      else if(path.endsWith("/plans"))data=QJsonObject{};
      else if(path.contains("/sources"))data=QJsonObject{{"items",QJsonArray{QJsonObject{{"name","Fixture template"},{"playbook_id","fixture"},{"source",QJsonObject{{"label","内置模板"}}}}}},{"total",1}};
      else if(path.endsWith("/confirm")){data=QJsonObject{{"state","ready"}};}
      else if(path.endsWith("/start")){data=QJsonObject{{"state","queued"},{"run_id","run-fixture"}};}
      else if(path.endsWith("/cancel")){state="cancelling";data=QJsonObject{{"state",state}};}
      else data=QJsonObject{{"id","v1"},{"finding_id",123},{"readiness",QJsonObject{{"ready",revision>0&&eligible&&(state=="ready"||state=="completed")},{"reasons",QJsonArray{}}}},{"revision",revision},{"state",state},{"eligible",eligible},{"reason",reason},{"ineligibility_reason","此记录现归为信息，仅保留历史与停止操作。"},{"default_target","http://fixture.invalid/item"},{"finding",QJsonObject{{"id",123},{"result_data","SQL injection candidate"}}},
        {"summary",QJsonObject{{"conclusion",conclusion}}},{"plans",revision==0?QJsonArray{}:QJsonArray{QJsonObject{{"revision",revision},{"fingerprint","fp"+QString::number(revision)},{"confirmed_at","fixture"},{"content",plan}}}},
        {"attempts",QJsonArray{}},{"payloads",QJsonObject{{"matches",QJsonArray{}}}}};
      const auto payload=QJsonDocument(QJsonObject{{"status",(path.endsWith("/plans") || path.endsWith("/generate")&&mode=="preparation-result")?"error":"ok"},{"error",QJsonObject{{"message",reason.isEmpty()?QString("fixture rejected plan"):reason}}},{"data",data}}).toJson(QJsonDocument::Compact);
      QPointer<QTcpSocket> guard(socket);QTimer::singleShot(path.endsWith("/select-template")?250:path.endsWith("/v1")?detailDelay:path.endsWith("/start")?executeDelay:0,&app,[&,guard,payload,path]{if(path.endsWith("/start"))state="running";if(guard){guard->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(payload.size())+"\r\n\r\n"+payload);guard->disconnectFromHost();}});
    });
  }});
  if(!server.listen(QHostAddress::LocalHost))return 1;
  ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
  auto owned=std::make_unique<FindingVerificationDialog>(&api,"p",QList<qint64>{123});
  auto &dialog=*owned;dialog.show();
  auto wait=[&](std::function<bool()> condition){for(int i=0;i<100;i++){if(condition())return true;QTest::qWait(20);}return false;};
  if(!wait([&]{return dialog.m_revision==1;}))return 2;
  if(dialog.m_items->item(0,2)->text()!="待判定"||dialog.m_target->text()!="http://fixture.invalid/item")return 3;

  dialog.m_timer->stop();
  if(!wait([&]{return !dialog.m_loading;}))return 20;

  auto clickCancel=[&] {
    for(auto *button:dialog.findChildren<QPushButton*>())
      if(button->text()=="取消当前验证并停止队列")QTest::mouseClick(button,Qt::LeftButton);
  };
  const QString confirmKey="POST /api/pipelines/p/verifications/v1/start";
  const QString executeKey="POST /api/pipelines/p/verifications/v1/start";
  const QString cancelKey="POST /api/pipelines/p/verifications/v1/cancel";
  if(mode=="preparation-result") {
    revision=0;state="needs_conditions";dialog.load(true);
    if(!wait([&]{return !dialog.m_loading&&dialog.m_revision==0;}))return 70;
    QTest::mouseClick(dialog.m_prepareSimple,Qt::LeftButton);
    if(!wait([&]{return !dialog.m_busy&&!dialog.m_loading&&dialog.m_detail["state"]=="preparation_failed";}))return 71;
    if(!dialog.m_status->text().contains("未启动新的验证执行") || !dialog.m_planSummary->toPlainText().contains("方案准备失败"))return 72;
    if(dialog.m_startSimple->isEnabled() || dialog.m_confirmSimple->isEnabled() || !dialog.m_prepareSimple->isEnabled())return 73;
    if(requests.value(executeKey)!=0 || !dialog.m_detail["attempts"].toArray().isEmpty())return 74;
    return 0;
  }
  if(mode=="information-history") {
    eligible=false;dialog.load(false);
    if(!wait([&]{return !dialog.m_loading&&dialog.m_detail["eligible"]==false;}))return 75;
    if(dialog.m_prepareSimple->isEnabled() || dialog.m_confirmSimple->isEnabled() || dialog.m_startSimple->isEnabled() || dialog.m_save->isEnabled())return 76;
    if(!dialog.m_planSummary->toPlainText().contains("现归为信息"))return 77;
    clickCancel();if(!wait([&]{return requests.value(cancelKey)==1;}))return 78;
    return 0;
  }
  if(mode=="template-late-edit") {
    if(!wait([&]{return dialog.m_sources->count()==1;}))return 62;dialog.m_sourceChooser->setChecked(true);dialog.m_sources->setCurrentIndex(0);
    for(auto *button:dialog.findChildren<QPushButton*>())if(button->text()=="使用此方案")QTest::mouseClick(button,Qt::LeftButton);
    if(!wait([&]{return requests.value("POST /api/pipelines/p/verifications/v1/select-template")==1;}))return 60;
    dialog.m_criteria->setPlainText("EDIT_AFTER_TEMPLATE_REQUEST");
    QTest::qWait(450);
    if(dialog.m_criteria->toPlainText()!="EDIT_AFTER_TEMPLATE_REQUEST" || !dialog.m_dirty)return 61;
    return 0;
  }
  if(mode.startsWith("draft-")) {
    if(mode=="draft-inflight" || mode=="draft-deferred") {detailDelay=150;dialog.load(mode=="draft-inflight");QTest::qWait(30);if(mode=="draft-deferred")dialog.load(true);}
    dialog.m_criteria->setPlainText("UNSAVED_CRITERIA");
    const int reads=requests.value("GET /api/pipelines/p/verifications/v1");
    if(mode=="draft-column")dialog.m_items->setCurrentCell(0,1);
    if(mode=="draft-refresh" || mode=="draft-switch") {
      QTimer::singleShot(0,[] {
        auto *box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget());
        if(box)box->button(QMessageBox::Cancel)->click();
      });
      if(mode=="draft-refresh") {
        for(auto *button:dialog.findChildren<QPushButton*>())if(button->text()=="刷新")QTest::mouseClick(button,Qt::LeftButton);
      } else {
        dialog.m_items->insertRow(1);
        for(int col=0;col<6;col++)dialog.m_items->setItem(1,col,new QTableWidgetItem);
        dialog.m_items->item(1,0)->setData(Qt::UserRole,"v2");
        dialog.m_items->setCurrentCell(1,0);
      }
    }
    if(mode=="draft-failed-save")QTest::mouseClick(dialog.m_save,Qt::LeftButton);
    QTest::qWait(450);
    if(dialog.currentId()!="v1" || dialog.m_criteria->toPlainText()!="UNSAVED_CRITERIA" || !dialog.m_dirty)return 50;
    if(mode=="draft-column" && requests.value("GET /api/pipelines/p/verifications/v1")!=reads)return 51;
    return 0;
  }
  if(mode=="revision" || mode=="dirty-revision") {
    const auto before=dialog.m_target->text();
    if(mode=="dirty-revision")dialog.m_criteria->setPlainText("local unsaved criteria");
    revision=2;plan["target"]="http://fixture.invalid/different-entry";
    dialog.load(false);if(!wait([&]{return !dialog.m_loading&&dialog.m_detail["revision"].toInt()==2;}))return 21;
    if(dialog.m_revision!=1 || dialog.m_target->text()!=before || !dialog.m_stale)return 22;
    dialog.m_startSimple->click();QTest::qWait(60);
    if(requests.value(executeKey)!=0)return 23;
    if(mode=="dirty-revision" && dialog.m_criteria->toPlainText()!="local unsaved criteria")return 24;
    dialog.load(true);if(!wait([&]{return !dialog.m_loading&&!dialog.m_stale&&dialog.m_revision==2;}))return 25;
    if(dialog.m_target->text()!=plan["target"].toString())return 26;
    QTimer::singleShot(0,[]{auto *box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget());if(box)box->button(QMessageBox::Yes)->click();});
    dialog.m_startSimple->click();
    if(!wait([&]{return requests.value(executeKey)==1;}))return 27;
    const auto sent=bodies.value(executeKey);
    if(sent["revision"].toInt()!=2 || sent["fingerprint"].toString()!="fp2" || !sent["confirmed"].toBool())return 28;
    return 0;
  }
  if(mode=="reload-in-flight") {
    detailDelay=250;dialog.load(false);QTest::qWait(30);
    revision=2;plan["target"]="http://fixture.invalid/new-plan";
    dialog.load(true);
    if(!wait([&]{return !dialog.m_loading&&dialog.m_revision==2;}))return 29;
    if(dialog.m_target->text()!=plan["target"].toString()||dialog.m_stale)return 30;
    return 0;
  }
  if(mode.startsWith("single-")) {
    executeDelay=350;
    QTimer::singleShot(0,[]{auto *box=qobject_cast<QMessageBox*>(QApplication::activeModalWidget());if(box)box->button(QMessageBox::Yes)->click();});QTest::mouseClick(dialog.m_start,Qt::LeftButton);
    if(!wait([&]{return requests.value(executeKey)==1;}))return 40;
    const bool cancel=mode!="single-close-running";
    if(cancel)clickCancel();
    if(mode=="single-cancel-close" || !cancel)dialog.accept();
    if(mode=="single-cancel-destroy")owned.reset();
    QTest::qWait(800);
    if(requests.value(executeKey)!=1)return 41;
    if(cancel && (requests.value(cancelKey)<2 || state!="cancelling"))return 42;
    if(!cancel && (requests.value(cancelKey)!=0 || state!="running"))return 43;
    return 0;
  }
  if(mode=="cancel-start" || mode=="cancel-start-close" || mode=="cancel-start-destroy") {
    executeDelay=350;dialog.m_queuePlans["v1"]=dialog.m_detail["plans"].toArray().first().toObject();dialog.m_queue<<"v1";dialog.executeNext();
    if(!wait([&]{return requests.value(executeKey)==1;}))return 31;
    clickCancel();
    if(mode=="cancel-start-close")dialog.accept();
    if(mode=="cancel-start-destroy")owned.reset();
    QTest::qWait(800);
    if(requests.value(executeKey)!=1 || requests.value(cancelKey)<2 || state!="cancelling")return 32;
    return 0;
  }
  detailDelay=350;
  dialog.m_queuePlans["v1"]=dialog.m_detail["plans"].toArray().first().toObject();dialog.m_queue<<"v1";dialog.executeNext();
  QTest::qWait(30);
  if(mode=="close-details")dialog.accept();else clickCancel();
  QTest::qWait(900);
  if(requests.value(executeKey)!=0)return 33;
  if(mode!="close-details" && requests.value(cancelKey)!=1)return 34;
  return 0;
}
