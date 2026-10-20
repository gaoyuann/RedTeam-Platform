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
  const QString mode=argc>1?QString::fromUtf8(argv[1]):QString();
  auto fail=[](int code,const char *message){qCritical()<<message;return code;};
  auto system=[](const QString &status){return QJsonObject{{"schema_version",1},{"status",status},{"reason","隔离测试判据"},
    {"objective",QJsonObject{{"label","检查示例响应"}}},{"object",QJsonObject{{"target","http://fixture.invalid/item"}}}};};
  auto attempt=[&](const QString &id,const QString &run,const QString &state,const QString &status){return QJsonObject{
    {"id",id},{"run_id",run},{"revision",1},{"state",state},{"stop_confirmed",state=="completed"?1:0},{"created_at",id},
    {"summary",QJsonObject{{"result",system(status)}}},{"evidence",QJsonArray{}},{"reviews",QJsonArray{}}};};
  QJsonArray attempts{attempt("attempt-old","run-old","completed","inconclusive"),attempt("attempt-older","run-older","completed","inconclusive")};
  const QJsonObject plan{{"name","隔离示例方案"},{"target","http://fixture.invalid/item"},{"max_attempts",3},{"duration_ms",300000},
    {"success_criteria","平台判据"},{"cleanup","无需清理"},{"steps",QJsonArray{}},
    {"verification_contract",QJsonObject{{"schema_version",1},{"objective",QJsonObject{{"label","检查示例响应"}}},{"capability",QJsonObject{{"automatic",true}}}}}};
  int revision=1,detailDelay=30,startDelay=0,starts=0,cancels=0,writes=0;QString state="completed";
  bool recordOnAck=mode!="selection-deferred-run";
  auto addStarted=[&]{attempts.prepend(attempt("attempt-new","run-new","running","pending"));state="running";};
  auto detail=[&]{const bool ready=state=="completed"&&attempts.size()<3;return QJsonObject{
    {"id","v1"},{"finding_id",123},{"revision",revision},{"state",state},{"eligible",true},
    {"finding",QJsonObject{{"result_data","{\"finding\":\"Fixture finding\"}"}}},
    {"readiness",QJsonObject{{"ready",ready},{"attempts_used",attempts.size()},{"max_attempts",3},
      {"reasons",attempts.size()<3?QJsonArray{}:QJsonArray{"已达到此漏洞尝试上限；历史仍可查看"}}}},
    {"plans",QJsonArray{QJsonObject{{"revision",revision},{"fingerprint","fp"+QString::number(revision)},{"content",plan}}}},
    {"summary",QJsonObject{{"run_id",attempts.first().toObject()["run_id"]},{"result",system(state=="running"?"pending":"inconclusive")}}},
    {"attempts",attempts},{"payloads",QJsonObject{{"matches",QJsonArray{}}}}};};
  QTcpServer server;
  QObject::connect(&server,&QTcpServer::newConnection,&app,[&]{while(server.hasPendingConnections()){
    auto *socket=server.nextPendingConnection();QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
    QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{
      const auto bytes=socket->property("buffer").toByteArray()+socket->readAll();socket->setProperty("buffer",bytes);
      const int end=bytes.indexOf("\r\n\r\n");if(end<0||socket->property("handled").toBool())return;
      const auto match=QRegularExpression("Content-Length: (\\d+)",QRegularExpression::CaseInsensitiveOption).match(QString::fromUtf8(bytes.left(end)));
      if(bytes.size()<end+4+match.captured(1).toInt())return;socket->setProperty("handled",true);
      const auto first=bytes.left(bytes.indexOf('\r')).split(' ');const QString path=first[1];if(first[0]!="GET")++writes;QJsonObject data;int delay=0;
      if(path.endsWith("/verifications"))data={{"id","v1"},{"finding_id",123},{"state",state}};
      else if(path.contains("/sources"))data={{"items",QJsonArray{}},{"total",0}};
      else if(path.endsWith("/start")){++starts;delay=startDelay;data={{"run_id","run-new"},{"state","queued"}};}
      else if(path.endsWith("/cancel")){++cancels;state="cancelling";data={{"state",state}};}
      else {data=detail();delay=detailDelay;}
      const auto payload=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);QPointer<QTcpSocket> guard(socket);
      QTimer::singleShot(delay,&app,[&,guard,payload,path]{
        if(path.endsWith("/start")&&recordOnAck)addStarted();
        if(guard){guard->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(payload.size())+"\r\n\r\n"+payload);guard->disconnectFromHost();}
      });
    });
  }});
  if(!server.listen(QHostAddress::LocalHost))return fail(1,"mock listen failed");
  ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
  FindingVerificationDialog dialog(&api,"p",{123},nullptr,mode=="selection-existing-read"?"v1":"",mode=="selection-existing-read"?"attempt-older":"");dialog.show();
  auto wait=[&](std::function<bool()> condition){for(int i=0;i<150;i++){if(condition())return true;QTest::qWait(10);}return false;};
  if(!wait([&]{return dialog.m_revision==1&&!dialog.m_loading;}))return fail(2,"initial detail failed");dialog.m_timer->stop();
  if(mode=="selection-existing-read") {
    if(writes||dialog.m_attempts->currentData()!="attempt-older"||dialog.m_tabs->currentIndex()!=1)return fail(17,"opening existing history wrote data or selected the wrong attempt");
    dialog.m_attempts->setCurrentIndex(0);dialog.load(false);
    if(!wait([&]{return !dialog.m_loading;}))return fail(18,"existing history poll did not settle");
    if(writes||dialog.m_attempts->currentData()!="attempt-old")return fail(19,"initial attempt selection overrode later manual history choice");
    return 0;
  }
  if(!dialog.m_startSimple->isEnabled()||!dialog.m_conclusion->currentData().toString().isEmpty()||!dialog.m_queueLabel->toolTip().contains("已用 2/3"))return fail(3,"optional opinion or attempt budget blocks initial readiness");
  const auto *opinionHint=dialog.findChild<QLabel*>("findingOpinionHint");if(!opinionHint||!opinionHint->text().contains("无需填写"))return fail(4,"optional opinion hint missing");
  dialog.m_attempts->setCurrentIndex(1);
  if(mode=="selection-poll") {
    addStarted();dialog.load(false);
    if(!wait([&]{return !dialog.m_loading;}))return fail(5,"poll did not complete");
    if(dialog.m_attempts->currentData()!="attempt-older"||!dialog.m_attemptContext->text().contains("历史尝试"))return fail(6,"ordinary poll replaced explicit history selection");
    return 0;
  }
  dialog.m_queuePlans["v1"]=dialog.m_detail["plans"].toArray().first().toObject();
  if(mode=="selection-cancel-late"||mode=="selection-user-history"||mode=="selection-user-history-same")startDelay=180;
  // Include a pre-start detail response containing only old attempts.
  if(mode=="selection-stale-detail"){detailDelay=250;dialog.load(false);QTest::qWait(20);}
  dialog.startAttempt("v1",1);
  if(!wait([&]{return starts==1;}))return fail(7,"start request missing");
  if(mode=="selection-cancel-late")dialog.cancelCurrent();
  if(mode=="selection-user-history")dialog.m_attempts->setCurrentIndex(0);
  if(mode=="selection-user-history-same")QMetaObject::invokeMethod(dialog.m_attempts,"activated",Q_ARG(int,1));
  if(!wait([&]{return !dialog.m_queueStarting&&!dialog.m_loading;}))return fail(8,"start detail did not settle");
  if(mode=="selection-cancel-late"||mode=="selection-user-history"||mode=="selection-user-history-same") {
    const QString expected=mode=="selection-user-history"?"attempt-old":"attempt-older";
    if(dialog.m_attempts->currentData()!=expected||!dialog.m_pendingAttemptRunId.isEmpty())return fail(9,"cancel or explicit history selection was overridden by late start");
    if(mode=="selection-cancel-late"&&cancels<2)return fail(10,"late start cancellation was not replayed");
    return 0;
  }
  if(mode=="selection-deferred-run"||mode=="selection-stale-detail") {
    if(dialog.m_attempts->currentData()!="attempt-older"||dialog.m_pendingAttemptRunId!="run-new")return fail(11,"unmatched detail was incorrectly treated as the started run");
    if(mode=="selection-deferred-run")addStarted();
    dialog.load(false);if(!wait([&]{return !dialog.m_loading;}))return fail(12,"matching detail did not settle");
  }
  if(dialog.m_attempts->currentData()!="attempt-new"||!dialog.m_pendingAttemptRunId.isEmpty()||dialog.m_tabs->currentIndex()!=1||dialog.m_resultDetails->currentIndex()!=0||!dialog.m_resultConclusion->text().contains("等待结果"))return fail(13,"successful start did not select its matching run result");
  if(!dialog.m_note->toPlainText().isEmpty()||!dialog.m_conclusion->currentData().toString().isEmpty())return fail(14,"new attempt inherited optional opinion input");
  // A new draft version cannot restore a per-finding execution budget.
  state="completed";auto finished=attempts.first().toObject();finished["state"]="completed";attempts[0]=finished;++revision;dialog.load(true);
  if(!wait([&]{return !dialog.m_loading&&dialog.m_revision==2;}))return fail(15,"new draft refresh did not settle");
  if(dialog.m_startSimple->isEnabled()||!dialog.m_queueLabel->toolTip().contains("已用 3/3")||!dialog.m_startSimple->toolTip().contains("保存新方案不恢复尝试次数"))return fail(16,"new draft restored attempts or hid limit reason");
  qInfo()<<"Matching run selection, optional opinion and cumulative attempt budget checks passed; loopback mock only.";
  return 0;
}
