#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include "ApiClient.h"
#include "AppStyle.h"
#define private public
#include "pages/FindingVerificationDialog.h"
#undef private

namespace {
QJsonObject fixture() {
  const QJsonObject evidence{{"id",41},{"step_index",0},{"tool_id","target-request"},
    {"evidence_data",QJsonObject{{"summary","HTML 目录索引响应；展开查看各项判据"}}},
    {"observation",QJsonObject{{"url","http://fixture.invalid/docs/"},{"method","GET"},{"status_code",200},{"complete",true},{"received_bytes",1135},{"connected",true}}},
    {"criteria",QJsonObject{{"kind","directory"},{"rule_version",1},{"source","saved_evidence"},{"target_path","/docs/"},{"title_path","/docs"},
      {"checks",QJsonArray{QJsonObject{{"id","response_valid"},{"label","响应有效性"},{"status","passed"},{"detail","HTTP 200，HTML 响应完整"}},
        QJsonObject{{"id","directory_title"},{"label","对应目录标题"},{"status","failed"},{"detail","旧版规则严格比较 /docs 与 /docs/，路径未匹配"}},
        QJsonObject{{"id","parent_navigation"},{"label","父目录导航"},{"status","passed"},{"detail","已发现父目录导航"}},
        QJsonObject{{"id","same_directory_entry"},{"label","同目录条目"},{"status","passed"},{"detail","已发现同目录条目"}}}}}}};
  const QJsonObject automatic{{"conclusion","not_verified"},{"note","旧版规则的目录标题路径未匹配"},{"reason","旧版规则的目录标题路径未匹配"},{"rule_version",1},{"limitations","仅检查此入口的目录索引"}};
  const QJsonObject manual{{"conclusion","confirmed"},{"note","人工检查目录标题、父目录导航和同目录文件条目，确认目录索引暴露；未检查文件内容。"+QString("复核记录。").repeated(420)+"完整依据末尾"},{"reviewed_by","fixture-reviewer"},{"created_at","2026-10-20 10:20:00"}};
  QJsonObject historical{{"id","attempt-old"},{"state","completed"},{"revision",1},{"stop_confirmed",1},{"created_at","2026-10-20 10:10:00"},
    {"summary",QJsonObject{{"state","completed"},{"revision",1},{"conclusion","confirmed"},{"method","manual"},{"note",manual["note"]},{"automatic",automatic},{"manual",manual},{"disagreement",true}}},
    {"assessments",QJsonArray{automatic}},{"reviews",QJsonArray{manual}},{"evidence",QJsonArray{evidence}}};
  auto latest=historical;latest["id"]="attempt-latest";latest["revision"]=2;latest["created_at"]="2026-10-20 10:30:00";
  auto latestEvidence=evidence;auto criteria=evidence["criteria"].toObject();criteria["rule_version"]=2;auto checks=criteria["checks"].toArray();auto title=checks[1].toObject();title["status"]="passed";title["detail"]="目录末尾一个斜杠等价，目录标题匹配";checks[1]=title;criteria["checks"]=checks;latestEvidence["criteria"]=criteria;latest["evidence"]=QJsonArray{latestEvidence};
  auto latestAuto=automatic;latestAuto["conclusion"]="confirmed";latestAuto["note"]="完整响应满足目录标题、父目录导航和同目录条目三项判据";latestAuto["reason"]=latestAuto["note"];latestAuto["rule_version"]=2;
  latest["assessments"]=QJsonArray{latestAuto};latest["reviews"]=QJsonArray{};
  latest["summary"]=QJsonObject{{"state","completed"},{"revision",2},{"conclusion","confirmed"},{"method","automatic"},{"note",latestAuto["note"]},{"automatic",latestAuto},{"manual",QJsonValue::Null},{"disagreement",false}};
  auto system=[](const QString &status,const QString &reason){return QJsonObject{{"schema_version",1},{"status",status},{"reason",reason},{"evidence_ids",status=="achieved"?QJsonArray{41}:QJsonArray{}},{"objective",QJsonObject{{"label","确认目录索引暴露"},{"category","configuration_exposure"}}},{"object",QJsonObject{{"target","http://fixture.invalid/docs/"}}},{"unverified",QJsonArray{"仅确认目录暴露，不证明敏感文件泄露"}}};};
  auto oldSummary=historical["summary"].toObject();oldSummary["result"]=system("inconclusive","历史目标未明确，证据不足；人工意见不替代系统结论");historical["summary"]=oldSummary;
  auto newSummary=latest["summary"].toObject();newSummary["result"]=system("achieved",latestAuto["note"].toString());latest["summary"]=newSummary;
  return {{"id","fixture-verification"},{"task_no","TASK-20261023-000001"},{"revision",3},{"state","draft"},
    {"finding",QJsonObject{{"result_data","{\"finding\":\"Directory indexing found.\",\"path\":\"/docs/\"}"}}},
    {"summary",QJsonObject{{"conclusion","confirmed"},{"method","automatic"}}},{"attempts",QJsonArray{latest,historical}}};
}
}

int main(int argc,char **argv) {
  QApplication app(argc,argv);app.setStyle("Fusion");app.setStyleSheet(Theme::GlobalStyle+Theme::PageStyle);
  auto fail=[](int code,const char *message){qCritical()<<message;return code;};
  QJsonObject detail=fixture();const auto fixturePath=qEnvironmentVariable("F08_RESULT_FIXTURE");
  if(!fixturePath.isEmpty()) {QFile file(fixturePath);if(!file.open(QIODevice::ReadOnly))return fail(1,"cannot read safe result fixture");detail=QJsonDocument::fromJson(file.readAll()).object();if(detail["data"].isObject())detail=detail["data"].toObject();if(detail["attempts"].toArray().isEmpty())return fail(2,"fixture has no attempts");}
  QTcpServer server;int requests=0,starts=0;bool serveDetail=false;
  QObject::connect(&server,&QTcpServer::newConnection,&app,[&]{while(server.hasPendingConnections()){
    auto *socket=server.nextPendingConnection();QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket]{const auto bytes=socket->readAll();requests++;if(bytes.contains("/start"))starts++;if(!serveDetail){socket->write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");socket->disconnectFromHost();return;}
      const auto content=QJsonDocument(QJsonObject{{"status","ok"},{"data",detail}}).toJson(QJsonDocument::Compact);QPointer<QTcpSocket> guard(socket);QTimer::singleShot(100,&app,[guard,content]{if(guard){guard->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+QByteArray::number(content.size())+"\r\nConnection: close\r\n\r\n"+content);guard->disconnectFromHost();}});
    });QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
  }});if(!server.listen(QHostAddress::LocalHost))return fail(3,"mock listen failed");
  ApiClient api("http://127.0.0.1:"+QString::number(server.serverPort()));
  FindingVerificationDialog dialog(&api,"isolated-result-replay",{});dialog.m_timer->stop();dialog.m_detail=detail;dialog.m_revision=detail["revision"].toInt();
  {const QSignalBlocker guard(dialog.m_items);dialog.m_items->setRowCount(1);for(int col=0;col<6;col++)dialog.m_items->setItem(0,col,new QTableWidgetItem);dialog.m_items->item(0,0)->setCheckState(Qt::Checked);dialog.m_items->item(0,0)->setData(Qt::UserRole,detail["id"].toString());dialog.m_items->item(0,1)->setText("执行结束");const auto status=detail["attempts"].toArray().first().toObject()["summary"].toObject()["result"].toObject()["status"].toString();dialog.m_items->item(0,2)->setText(status=="achieved"?"目标已达成":status=="not_performed"?"未开展适用验证":"证据不足");dialog.m_items->item(0,3)->setText(fixturePath.isEmpty()?"Directory indexing found.":"历史记录");dialog.m_items->setCurrentCell(0,0);}
  const auto attempts=detail["attempts"].toArray();{const QSignalBlocker guard(dialog.m_attempts);for(const auto &v:attempts){const auto a=v.toObject();dialog.m_attempts->addItem(a["created_at"].toString()+" · 执行结束",a["id"]);}}
  auto *resultPage=dialog.findChild<QWidget*>("findingResultsPage");if(!resultPage)return fail(36,"result page is missing");
  dialog.m_tabs->setCurrentWidget(resultPage);dialog.renderAttempt(0);dialog.updateQueue();dialog.show();QTest::qWait(30);
  auto *identity=dialog.findChild<QLabel*>("findingTaskIdentity");
  if(!identity||!identity->text().contains("isolated-result-replay"))return fail(34,"legacy task identity is missing before detail loads");
  const auto screenshots=qEnvironmentVariable("F08_SCREENSHOT_DIR");if(!screenshots.isEmpty())QDir().mkpath(screenshots);
  auto screenshot=[&](const QString &name){if(!screenshots.isEmpty()&&!dialog.grab().save(QDir(screenshots).filePath(name+".png")))return false;return true;};
  auto summaryVisible=[&]{const auto resultRect=resultPage->rect();const QRect summaryRect(dialog.m_resultSummary->mapTo(resultPage,QPoint()),dialog.m_resultSummary->size());if(!resultRect.contains(summaryRect))return false;
    for(auto *label:{dialog.m_attemptContext,dialog.m_executionSummary,dialog.m_resultConclusion,dialog.m_automaticSummary,dialog.m_manualSummary,dialog.m_resultBasis}){const QRect rect(label->mapTo(dialog.m_resultSummary,QPoint()),label->size());if(!label->isVisible()||!dialog.m_resultSummary->rect().contains(rect)||label->height()<label->fontMetrics().height()||label->textFormat()!=Qt::PlainText)return false;}return true;};
  dialog.resize(1360,860);QTest::qWait(30);if(dialog.size()!=QSize(1360,860)||!summaryVisible())return fail(4,"normal summary is outside visible result region");if(!screenshot("result-latest-1360"))return 5;
  if(dialog.m_executionSummary->text().contains("草稿"))return fail(6,"draft state leaked into historical attempt");
  if(fixturePath.isEmpty()) {
    if(!dialog.m_resultConclusion->text().contains("目标已达成")||dialog.m_disagreement->isVisible())return fail(7,"latest attempt summary mismatch");
    if(!dialog.m_systemEvidence->isEnabled())return fail(24,"system evidence navigation is unavailable");
    dialog.m_systemEvidence->click();if(dialog.m_evidenceTable->currentRow()!=0||dialog.m_evidenceTable->item(0,0)->checkState()==Qt::Checked)return fail(25,"system evidence navigation changed opinion selection");
    dialog.m_attempts->setCurrentIndex(1);if(!dialog.m_attemptContext->text().contains("历史尝试")||!dialog.m_resultConclusion->text().contains("证据不足")||!dialog.m_disagreement->isVisible()||!dialog.m_executionSummary->text().contains("版本 1"))return fail(8,"historical result and source are unclear");
    if(!dialog.m_evidence->toPlainText().contains("未能验证")||!dialog.m_evidence->toPlainText().contains("认为证据支持")||!dialog.m_evidenceDetails->toPlainText().contains("旧版规则严格比较")||dialog.m_evidenceTable->rowHeight(0)>40||!dialog.m_evidence->toPlainText().contains("完整依据末尾"))return fail(9,"criteria details, full review note or compact evidence unavailable");
    dialog.m_evidenceTable->item(0,0)->setCheckState(Qt::Checked);dialog.m_conclusion->setCurrentIndex(dialog.m_conclusion->findData("confirmed"));dialog.m_note->setPlainText("同次刷新保留的复核依据");dialog.renderAttempt(1);
    if(dialog.m_evidenceTable->item(0,0)->checkState()!=Qt::Checked||dialog.m_note->toPlainText()!="同次刷新保留的复核依据")return fail(10,"same-attempt refresh lost review input");
    dialog.m_evidenceTable->setCurrentCell(0,3);if(dialog.m_evidenceTable->item(0,0)->checkState()!=Qt::Checked)return fail(11,"row selection changed review checkbox");
    if(!screenshot("result-history-1360"))return 12;
    // A detail poll started on the latest attempt must respect a later history selection.
    serveDetail=true;dialog.m_attempts->setCurrentIndex(0);dialog.load(false);dialog.m_attempts->setCurrentIndex(1);dialog.m_evidenceTable->item(0,0)->setCheckState(Qt::Checked);dialog.m_note->setPlainText("轮询期间填写的复核依据");dialog.m_conclusion->setCurrentIndex(dialog.m_conclusion->findData("inconclusive"));
    for(int i=0;i<80&&dialog.m_loading;i++)QTest::qWait(10);
    if(dialog.m_loading||dialog.m_attempts->currentData()!="attempt-old"||!dialog.m_resultConclusion->text().contains("证据不足")||!dialog.m_note->toPlainText().contains("轮询期间")||dialog.m_evidenceTable->item(0,0)->checkState()!=Qt::Checked)return fail(20,"late detail poll replaced selected history or review input");
    if(!identity->text().contains(detail["task_no"].toString())||!dialog.windowTitle().contains(detail["task_no"].toString()))return fail(35,"loaded task number is inconsistent with the verification window");
    auto old=attempts[1].toObject();old.remove("summary");auto compatible=attempts;compatible[1]=old;dialog.m_detail["attempts"]=compatible;dialog.renderAttempt(1);if(!dialog.m_resultConclusion->text().contains("证据不足")||!dialog.m_resultBasis->toolTip().contains("旧版接口"))return fail(13,"old service fallback crossed attempt boundary");dialog.m_detail=detail;
  }
  dialog.resize(1024,600);QTest::qWait(30);if(dialog.size()!=QSize(1024,600)||!summaryVisible()){qCritical()<<"actual narrow size"<<dialog.size()<<"minHint"<<dialog.minimumSizeHint()<<"result"<<resultPage->size()<<"summary"<<dialog.m_resultSummary->geometry();screenshot("result-narrow-failed");return fail(14,"narrow summary is outside visible result region");}if(!screenshot("result-history-1024"))return 15;
  if(dialog.m_evidenceTable->rowCount()) {auto *scroll=qobject_cast<QScrollArea*>(dialog.m_resultDetails->widget(0));const auto row=dialog.m_evidenceTable->visualItemRect(dialog.m_evidenceTable->item(0,3));const QRect visibleRow(dialog.m_evidenceTable->viewport()->mapTo(scroll->viewport(),row.topLeft()),row.size());if(!scroll->viewport()->rect().contains(visibleRow))return fail(22,"narrow first evidence row is clipped");scroll->ensureWidgetVisible(dialog.m_evidenceDetails,0,0);QTest::qWait(20);if(!summaryVisible()||!screenshot("result-criteria-1024"))return fail(23,"evidence scrolling hid the summary");}
  dialog.m_resultDetails->setCurrentIndex(1);QTest::qWait(20);if(!summaryVisible()||!screenshot("result-review-1024"))return fail(16,"review hides fixed summary");
  if(fixturePath.isEmpty()) {
    dialog.m_attempts->setCurrentIndex(0);if(!dialog.m_note->toPlainText().isEmpty()||!dialog.m_conclusion->currentData().toString().isEmpty()||dialog.m_evidenceTable->item(0,0)->checkState()==Qt::Checked)return fail(17,"switch inherited another attempt review input");
    auto pending=attempts[0].toObject();pending.remove("summary");pending["assessments"]=QJsonArray{};pending["reviews"]=QJsonArray{};dialog.m_detail["attempts"]=QJsonArray{pending};dialog.renderAttempt(0);if(!dialog.m_resultConclusion->text().contains("证据不足")||!dialog.m_resultBasis->toolTip().contains("旧版接口"))return fail(18,"missing rule was presented as a conclusion");
    dialog.m_detail["attempts"]=QJsonArray{};dialog.renderAttempt(-1);dialog.resize(1100,650);QTest::qWait(20);if(!dialog.m_resultBasis->toolTip().contains("选择并完整确认")||dialog.m_resultBasis->text().contains("系统依据"))return fail(21,"empty attempt inherited previous note after resize");
    const QJsonObject contract{{"schema_version",1},{"object",QJsonObject{{"target","http://fixture.invalid/docs/"}}},{"objective",QJsonObject{{"label","确认本次目录索引暴露"},{"category","configuration_exposure"}}},{"capability",QJsonObject{{"automatic",true}}}};
    const QJsonObject saved{{"name","目录方案"},{"target","http://fixture.invalid/docs/"},{"verification_contract",contract},{"objective_draft",QJsonObject{{"label","检查指定目录公开索引"},{"category","configuration_exposure"}}}};
    dialog.m_detail["plans"]=QJsonArray{QJsonObject{{"content",saved}}};dialog.renderAttempt(-1);
    if(!dialog.m_automaticSummary->toolTip().contains("确认本次目录索引暴露")||dialog.m_automaticSummary->text().contains("尚无适用")||!dialog.m_resultBasis->toolTip().contains("已保存适用方案")||!dialog.m_manualSummary->toolTip().contains("fixture.invalid/docs/"))return fail(26,"prepared automatic plan was confused with missing plan");
    dialog.displayPlan(saved);if(dialog.m_objective->text()!="检查指定目录公开索引"||dialog.m_objectiveCategory->currentData()!="configuration_exposure")return fail(27,"saved objective draft was not displayed");
    dialog.m_confirm->setChecked(true);dialog.m_objective->setText("确认指定入口的授权效果");dialog.m_objectiveCategory->setCurrentIndex(dialog.m_objectiveCategory->findData("effect"));
    const auto draft=dialog.planInput()["objective_draft"].toObject();if(draft["label"]!="确认指定入口的授权效果"||draft["category"]!="effect"||!dialog.m_dirty||dialog.m_confirm->isChecked()||dialog.planInput().contains("verification_contract"))return fail(28,"objective editing failed to invalidate confirmation or round-trip the draft");
    if(dialog.m_objective->maxLength()!=200)return fail(29,"objective input does not enforce service length limit");
    auto unsupported=saved;auto unsupportedContract=contract;unsupportedContract["capability"]=QJsonObject{{"automatic",false},{"reason","缺少本次目标的自动判据"}};unsupported["verification_contract"]=unsupportedContract;
    dialog.m_detail["plans"]=QJsonArray{QJsonObject{{"content",unsupported}}};dialog.renderAttempt(-1);if(!dialog.m_resultBasis->toolTip().contains("缺少本次目标的自动判据")||!dialog.m_resultConclusion->text().contains("未开展适用验证"))return fail(30,"unexecuted unsupported objective was presented as a result");
    dialog.displayPlan(QJsonObject{});if(dialog.planInput().contains("objective_draft"))return fail(31,"empty objective draft was submitted as a declared verification capability");
    for(const auto &value:QJsonArray{QJsonObject{{"schema_version",1},{"status","confirmed"}},QJsonObject{{"schema_version",1},{"status","unknown-status"}},QJsonObject{{"schema_version",99},{"status","achieved"}}}) {
      auto incompatible=attempts[1].toObject();auto incompatibleSummary=incompatible["summary"].toObject();
      auto incompatibleResult=incompatibleSummary["result"].toObject();const auto fields=value.toObject();
      incompatibleResult["schema_version"]=fields["schema_version"];incompatibleResult["status"]=fields["status"];incompatibleSummary["result"]=incompatibleResult;
      incompatible["summary"]=incompatibleSummary;detail["summary"]=incompatibleSummary;detail["attempts"]=QJsonArray{incompatible};
      dialog.load(false);for(int i=0;i<80&&dialog.m_loading;i++)QTest::qWait(10);
      if(dialog.m_loading||!dialog.m_items->item(0,2)->text().contains("证据不足")||!dialog.m_resultConclusion->text().contains("证据不足")||dialog.m_resultConclusion->text().contains("验证成立")||dialog.m_resultConclusion->text().contains("目标已达成")||!dialog.m_evidence->toPlainText().contains("认为证据支持"))return fail(32,"unknown result or legacy opinion was promoted into a system conclusion");
      const QString expected=fields["schema_version"].toInt()==1?"未知结果状态":"旧版接口";
      if(!dialog.m_resultBasis->toolTip().contains(expected)||!dialog.m_items->item(0,2)->text().contains(expected))return fail(33,"unknown schema and unknown result status have indistinguishable fallback reasons");
    }
  }
  QTest::qWait(30);if(starts||requests!=(fixturePath.isEmpty()?4:0))return fail(19,"result replay unexpectedly sent a request");
  qInfo()<<"F08 result summary, history, review state, compact evidence and viewport checks passed; isolated mock GET only, no target requests.";
  return 0;
}
