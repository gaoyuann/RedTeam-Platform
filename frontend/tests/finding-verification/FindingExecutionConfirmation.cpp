#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include <functional>
#include "ApiClient.h"
#include "AppStyle.h"
#define private public
#include "pages/FindingVerificationDialog.h"
#undef private

namespace {
QJsonObject directoryPlan(int version=2) {
  const QString target="http://fixture.invalid/listing/";
  QJsonArray steps,operations;
  for(int i=0;i<20;i++) {
    const auto id=QString("observe_%1").arg(i);
    const auto name=QString("检查目录第 %1 项：%2").arg(i+1).arg(QString("核对只读请求与目标范围，").repeated(8));
    steps.append(QJsonObject{{"step_id",id},{"step_index",i},{"name",name},{"tool_id","target-request"},
      {"args_template",QJsonArray{QString::fromUtf8(QJsonDocument(QJsonObject{{"url",target},{"method","GET"}}).toJson(QJsonDocument::Compact))}},
      {"consumption","none"},{"expected_evidence",QString("目录标题、导航与条目；").repeated(12)+"<b>仅作纯文本展示</b>"}});
    operations.append(QJsonObject{{"step_id",id},{"step_index",i},{"tool_id","target-request"},{"name",name}});
  }
  const auto rule=QJsonObject{{"id","f08-directory-index-v1"},{"version",version},{"kind","directory"},
    {"target",target},{"step_id","observe_0"},{"limitations","仅确认目录索引暴露，不证明敏感文件泄露。"}};
  const auto contract=QJsonObject{{"schema_version",1},{"object",QJsonObject{{"finding_id",123},{"target",target}}},
    {"objective",QJsonObject{{"id","f08-directory-index-v1"},{"category","configuration_exposure"},{"label","确认指定目录索引暴露"}}},
    {"operations",operations},{"capability",QJsonObject{{"automatic",true},{"reason",QJsonValue::Null}}},
    {"criterion",QJsonObject{{"id","f08-directory-index-v1"},{"version",version},{"step_id","observe_0"},
      {"required_evidence",QJsonArray{"same_attempt","same_entry","complete_response"}},{"supports_negative",true}}},
    {"limitations",rule["limitations"]}};
  return QJsonObject{{"name","目录索引只读测试"},{"target",target},{"prerequisites",QJsonArray{"仅使用本地模拟响应"}},
    {"missing_conditions",QJsonArray{}},{"success_criteria","HTTP 200 即通过"},{"cleanup","无需清理"},
    {"max_attempts",2},{"duration_ms",300000},{"steps",steps},{"assessment_rule",rule},{"verification_contract",contract}};
}

QJsonObject detailFor(const QString &id,const QJsonObject &plan) {
  return QJsonObject{{"id",id},{"finding_id",123},{"eligible",true},{"revision",1},{"state","ready"},
    {"default_target",plan["target"]},{"finding",QJsonObject{{"id",123},{"result_data","{\"finding\":\"目录索引候选\"}"}}},
    {"plans",QJsonArray{QJsonObject{{"revision",1},{"fingerprint","fp-"+id},{"content",plan}}}},
    {"readiness",QJsonObject{{"ready",true},{"reasons",QJsonArray{}}}},{"attempts",QJsonArray{}},
    {"summary",QJsonObject{{"conclusion","pending"}}},{"payloads",QJsonObject{{"matches",QJsonArray{}}}}};
}

QString judgement(const QString &summary) {
  for(const auto &line:summary.split('\n'))if(line.startsWith("如何判断："))return line;
  return {};
}
}

int main(int argc,char **argv) {
  QApplication app(argc,argv);app.setStyle("Fusion");app.setStyleSheet(Theme::GlobalStyle+Theme::ButtonStyle+Theme::ItemViewStyle);
  const QString mode=argc>1?QString::fromUtf8(argv[1]):QString();
  const auto plan=directoryPlan();
  QTcpServer server;QMap<QString,int> requests;QMap<QString,QJsonObject> bodies;
  QObject::connect(&server,&QTcpServer::newConnection,&app,[&]{while(server.hasPendingConnections()){
    auto *socket=server.nextPendingConnection();QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
    QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{
      const auto bytes=socket->property("bytes").toByteArray()+socket->readAll();socket->setProperty("bytes",bytes);
      const int end=bytes.indexOf("\r\n\r\n");if(end<0||socket->property("done").toBool())return;
      const auto length=QRegularExpression("Content-Length: (\\d+)",QRegularExpression::CaseInsensitiveOption).match(QString::fromUtf8(bytes.left(end))).captured(1).toInt();
      if(bytes.size()<end+4+length)return;socket->setProperty("done",true);
      const auto first=bytes.left(bytes.indexOf('\r')).split(' ');
      const QString path=QUrl(QString::fromUtf8(first[1])).path(),key=QString::fromUtf8(first[0])+" "+path;
      const auto body=QJsonDocument::fromJson(bytes.mid(end+4)).object();requests[key]++;bodies[key]=body;
      QJsonValue data;
      if(path.endsWith("/verifications"))data=QJsonObject{{"id","v"+QString::number(body["finding_id"].toInt())},{"state","ready"}};
      else if(path.endsWith("/sources"))data=QJsonObject{{"items",QJsonArray{}},{"total",0}};
      else if(path.endsWith("/start"))data=QJsonObject{{"state","running"},{"run_id","run-confirmation-fixture"}};
      else data=detailFor(path.section('/',-1),plan);
      const auto content=QJsonDocument(QJsonObject{{"status","ok"},{"data",data}}).toJson(QJsonDocument::Compact);
      socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(content.size())+"\r\n\r\n"+content);socket->disconnectFromHost();
    });
  }});
  if(!server.listen(QHostAddress::LocalHost))return 1;
  ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
  FindingVerificationDialog dialog(&api,"p",{123});dialog.show();
  auto wait=[&](std::function<bool()> condition){for(int i=0;i<100;i++){if(condition())return true;QTest::qWait(20);}return false;};
  if(!wait([&]{return dialog.m_revision==1&&!dialog.m_loading;}))return 2;
  dialog.addFinding(124);
  if(!wait([&]{return dialog.m_details.size()==2;}))return 2;
  dialog.m_timer->stop();
  const QString startKey="POST /api/pipelines/p/verifications/v123/start";
  auto starts=[&]{return requests.value(startKey)+requests.value("POST /api/pipelines/p/verifications/v124/start");};
  if(starts()!=0)return 3;

  if(mode=="criteria") {
    auto summaryFor=[&](const QJsonObject &p){return dialog.confirmationText(detailFor("v123",p));};
    for(const int version:{1,2}) {
      const auto summary=summaryFor(directoryPlan(version)),how=judgement(summary);
      if(how.isEmpty()||!how.contains("规则版本 "+QString::number(version))||!how.contains("标题")||!how.contains("父目录")||!how.contains("条目")
          ||how.contains("HTTP 200 即通过")||summary.contains("判据缺口：")
          ||!summary.contains("方案填写的判据（不改变系统规则）：HTTP 200 即通过"))return 10;
    }
    auto withRule=[&](const QString &id,const QString &kind,const QString &attribute,const QString &cookie,const QString &target) {
      auto candidate=plan,rule=plan["assessment_rule"].toObject(),contract=plan["verification_contract"].toObject();
      rule["id"]=id;rule["kind"]=kind;rule["version"]=1;rule["attribute"]=attribute;rule["target"]=target;
      if(cookie.isEmpty())rule.remove("cookie_name");else rule["cookie_name"]=cookie;
      auto criterion=contract["criterion"].toObject();criterion["id"]=id;criterion["version"]=1;contract["criterion"]=criterion;
      auto object=contract["object"].toObject();object["target"]=target;contract["object"]=object;
      auto steps=plan["steps"].toArray();
      for(int i=0;i<steps.size();i++) {auto step=steps[i].toObject();step["args_template"]=QJsonArray{QString::fromUtf8(QJsonDocument(QJsonObject{{"url",target},{"method","GET"}}).toJson(QJsonDocument::Compact))};steps[i]=step;}
      candidate["target"]=target;candidate["steps"]=steps;candidate["assessment_rule"]=rule;candidate["verification_contract"]=contract;return candidate;
    };
    const QString http="http://fixture.invalid/listing/",https="https://fixture.invalid/listing/";
    const auto frame=withRule("f08-web-headers-v1","headers","frame",{},http);
    const auto httpOnly=withRule("f08-cookie-flags-v1","cookie","httponly","FixtureSession",http);
    const auto secure=withRule("f08-cookie-flags-v1","cookie","secure","FixtureSession",https);
    const auto frameText=summaryFor(frame),httpOnlyText=summaryFor(httpOnly),secureText=summaryFor(secure);
    if(frameText.contains("判据缺口：")||!judgement(frameText).contains("X-Frame-Options")||!judgement(frameText).contains("CSP frame-ancestors"))return 14;
    if(httpOnlyText.contains("判据缺口：")||!judgement(httpOnlyText).contains("FixtureSession")||!judgement(httpOnlyText).contains("HttpOnly")
        ||!judgement(httpOnlyText).contains("未设置同名 Cookie"))return 15;
    if(secureText.contains("判据缺口：")||!judgement(secureText).contains("FixtureSession")||!judgement(secureText).contains("Secure"))return 16;
    QList<QJsonObject> unsupported;
    unsupported<<directoryPlan(99);
    unsupported<<withRule("f08-cookie-flags-v1","cookie","httponly",{},http)
      <<withRule("f08-cookie-flags-v1","cookie","unknown","FixtureSession",http)
      <<withRule("f08-web-headers-v1","headers","unknown",{},http)
      <<withRule("f08-cookie-flags-v1","cookie","secure","FixtureSession",http);
    auto noContract=plan;noContract.remove("verification_contract");unsupported<<noContract;
    auto noRule=plan;noRule.remove("assessment_rule");unsupported<<noRule;
    auto wrongTarget=plan;auto rule=plan["assessment_rule"].toObject();rule["target"]="http://fixture.invalid/other/";wrongTarget["assessment_rule"]=rule;unsupported<<wrongTarget;
    auto wrongTool=plan;auto steps=plan["steps"].toArray();auto step=steps[0].toObject();step["tool_id"]="other-tool";steps[0]=step;wrongTool["steps"]=steps;unsupported<<wrongTool;
    auto futureContract=plan;auto contract=plan["verification_contract"].toObject();contract["schema_version"]=2;
    futureContract["verification_contract"]=contract;unsupported<<futureContract;
    for(const auto &field:{QString("id"),QString("version"),QString("step_id")}) {
      auto mismatched=plan;contract=plan["verification_contract"].toObject();auto criterion=contract["criterion"].toObject();
      criterion[field]=field=="version"?QJsonValue(1):QJsonValue("different");contract["criterion"]=criterion;
      mismatched["verification_contract"]=contract;unsupported<<mismatched;
    }
    for(const auto &p:unsupported) {
      const auto summary=summaryFor(p),how=judgement(summary);
      if(!summary.contains("判据缺口：")||how.isEmpty()||how.contains("HTTP 200 即通过")||how.contains("父目录导航"))return 11;
    }
    auto capabilityOff=plan;contract=plan["verification_contract"].toObject();contract["capability"]=QJsonObject{{"automatic",false},{"reason","尚无适用的自动判据"}};
    capabilityOff["verification_contract"]=contract;
    if(!summaryFor(capabilityOff).contains("判据缺口：")||starts()!=0)return 12;
    dialog.close();QTest::qWait(30);return starts()==0?0:13;
  }

  QString failure;
  auto schedule=[&](std::function<void(QDialog*)> interact) {
    QTimer::singleShot(0,&dialog,[&,interact]{
      auto *modal=qobject_cast<QDialog*>(QApplication::activeModalWidget());
      if(!modal||modal->objectName()!="findingExecutionConfirmation") {
        failure="未打开有边界的执行确认窗口";if(modal)modal->reject();return;
      }
      interact(modal);
    });
  };
  auto checkLayout=[&](QDialog *modal,const QString &expected,const QString &screenshot) {
    auto *text=modal->findChild<QPlainTextEdit*>("findingConfirmationText");
    auto *yes=modal->findChild<QPushButton*>("confirmFindingExecution");
    auto *cancel=modal->findChild<QPushButton*>("cancelFindingExecution");
    const auto available=modal->windowHandle()->screen()->availableGeometry();
    if(!text||!text->isReadOnly()||text->toPlainText()!=expected||text->verticalScrollBar()->maximum()<=0)
      failure="长摘要正文不完整、不可滚动或允许修改";
    if(!available.contains(modal->frameGeometry()))failure="确认窗口超出可用屏幕";
    for(auto *button:{yes,cancel})if(!button||!button->isVisible()||!available.contains(QRect(button->mapToGlobal(QPoint()),button->size())))
      failure="确认或取消按钮不在屏内";
    if(!cancel||!cancel->isDefault()||!yes||yes->isDefault())failure="默认操作不是取消";
    if(text)text->verticalScrollBar()->setValue(text->verticalScrollBar()->maximum());
    modal->grab().save(screenshot);modal->reject();
  };
  if(mode=="layout") {
    const auto single=dialog.confirmationText(dialog.m_detail);
    if(!single.contains("20.")||!single.contains("<b>仅作纯文本展示</b>"))return 20;
    schedule([&](QDialog *modal){checkLayout(modal,single,"confirmation-single.png");});dialog.m_startSimple->click();
    if(!failure.isEmpty()){qWarning().noquote()<<failure;return 21;}
    QStringList batch;
    for(int row=0;row<dialog.m_items->rowCount();row++)batch<<dialog.confirmationText(dialog.m_details.value(dialog.m_items->item(row,0)->data(Qt::UserRole).toString()));
    const auto expected=batch.join("\n────────\n");
    schedule([&](QDialog *modal){checkLayout(modal,expected,"confirmation-batch.png");});dialog.m_queueButton->click();
    if(!failure.isEmpty()){qWarning().noquote()<<failure;return 22;}
    dialog.close();QTest::qWait(30);return starts()==0?0:23;
  }
  if(mode=="controls") {
    schedule([](QDialog *modal){modal->findChild<QPushButton*>("cancelFindingExecution")->click();});dialog.m_startSimple->click();
    schedule([](QDialog *modal){modal->close();});dialog.m_startSimple->click();
    schedule([](QDialog *modal){QTest::keyClick(modal,Qt::Key_Escape);});dialog.m_startSimple->click();
    schedule([](QDialog *modal){QTest::keyClick(modal,Qt::Key_Return);if(modal->isVisible())modal->reject();});dialog.m_startSimple->click();
    schedule([](QDialog *modal){auto *text=modal->findChild<QPlainTextEdit*>("findingConfirmationText");text->setFocus();QTest::keyClick(text,Qt::Key_Return);if(modal->isVisible())modal->reject();});dialog.m_startSimple->click();
    if(!failure.isEmpty()||starts()!=0||dialog.m_finished)return 30;
    const auto original=dialog.m_detail;
    schedule([&](QDialog *modal){++dialog.m_revision;modal->findChild<QPushButton*>("confirmFindingExecution")->click();});dialog.m_startSimple->click();
    dialog.m_revision=1;
    schedule([&](QDialog *modal){auto plans=dialog.m_detail["plans"].toArray();auto changed=plans.first().toObject();changed["fingerprint"]="changed-while-confirming";plans[0]=changed;dialog.m_detail["plans"]=plans;modal->findChild<QPushButton*>("confirmFindingExecution")->click();});dialog.m_startSimple->click();
    dialog.m_detail=original;
    QTest::qWait(30);if(!failure.isEmpty()||starts()!=0)return 31;
    schedule([](QDialog *modal){auto *yes=modal->findChild<QPushButton*>("confirmFindingExecution");yes->click();yes->click();});dialog.m_startSimple->click();
    dialog.m_startSimple->click();
    if(!wait([&]{return starts()==1&&!dialog.m_queueStarting;}))return 32;
    const auto sent=bodies.value(startKey);
    if(sent["revision"].toInt()!=1||sent["fingerprint"]!="fp-v123"||!sent["confirmed"].toBool()||sent["request_id"].toString().isEmpty())return 33;
    dialog.close();QTest::qWait(50);return starts()==1?0:34;
  }
  return 99;
}
