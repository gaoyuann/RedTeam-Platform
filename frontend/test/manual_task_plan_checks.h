#pragma once

static void runManualTaskPlanChecks(const std::function<void(bool,const char *)> &verify)
{
  const auto previousStyle=qApp->styleSheet();
  qApp->setStyleSheet(Theme::GlobalStyle+Theme::ButtonStyle+Theme::ItemViewStyle);
  MockServer server;
  bool allowed=true,sourceError=false,oldBackend=false;
  int planDelay=0;
  QString status="failed";
  QJsonObject plan;
  const auto selection=[&] {
    return QJsonObject{{"plan_selection",QJsonObject{{"pipeline_status",status},
      {"can_create_from_existing",allowed},{"requires_scan_failure_confirmation",status=="failed"&&allowed},
      {"reason",allowed?QStringLiteral("扫描未完整成功，已有发现和失败记录会保留；可选择已有预案建立草稿")
        :QStringLiteral("扫描工具停止未确认")}}}};
  };
  server.handler=[&](const QString &method,const QString &path)->MockReply {
    auto reply=[&](const QJsonValue &data)->MockReply {
      auto body=success(data);if(!oldBackend)body["meta"]=selection();return {body};
    };
    if(path.endsWith("/plan/sources")) {
      if(sourceError)return {QJsonObject{{"status","error"}}};
      return reply(QJsonArray{QJsonObject{{"playbook_id","preset"},{"name","已有测试预案"},{"steps_count",1}}});
    }
    if(path.endsWith("/plan") && method=="POST") {
      status="awaiting_approval";
      const QJsonObject content{{"name","已有测试预案"},{"target","http://fixture.invalid/"},
        {"source_playbook_id","preset"},{"source_playbook",QJsonObject{{"name","已有测试预案"}}},
        {"steps",QJsonArray{QJsonObject{{"step_id","observe"},{"name","观察目标"},{"tool_id","curl"},
          {"args_template",QJsonArray{"--head","<target>"}},{"optional",false}}}},{"suggestions",QJsonArray{}}};
      plan=QJsonObject{{"pipeline_id","manual-ui"},{"state","draft"},{"revision",1},{"content",content}};
      auto response=reply(plan);response.delay=80;return response;
    }
    if(path.endsWith("/plan/submit")) {
      plan["state"]="submitted";plan["revision"]=2;return reply(plan);
    }
    if(path.endsWith("/plan/approve")) {
      plan["state"]="approved";plan["revision"]=3;status="running";return reply(plan);
    }
    if(path.endsWith("/plan")) {
      auto response=reply(plan.isEmpty()?QJsonValue(QJsonValue::Null):QJsonValue(plan));
      response.delay=planDelay;return response;
    }
    return {success(QJsonArray{})};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  TaskPlanPage page(&api,"admin");page.resize(1024,600);page.show();
  auto task=taskRecord("manual-ui");task["status"]="failed";task["target"]="http://fixture.invalid/";
  task["config"]=QJsonObject{{"task_mode","assessment"},{"authorization_confirmed",true}};
  page.setTaskContext(task);
  verify(awaitCondition([&]{return page.m_create->isEnabled() && !page.m_busy;}),
    "failed scan with server-confirmed findings can select an existing task plan");
  verify(page.m_source->isEnabled() && page.m_canContinueFailedScan && page.m_status->text().contains("失败记录会保留"),
    "manual continuation explains retained scan failure before creation");
  const auto folder=qEnvironmentVariable("REDTEAM_MANUAL_PLAN_SCREENSHOT_DIR");
  if(!folder.isEmpty()) {QDir().mkpath(folder);verify(page.grab().save(folder+"/select-existing-plan.png"),"manual preset selection screenshot is saved");}
  allowed=false;page.refresh();
  verify(awaitCondition([&]{return !page.m_busy && page.m_status->text().contains("停止未确认");})
      && !page.m_source->isEnabled() && !page.m_create->isEnabled(),
    "unknown scanner stop state keeps preset creation disabled");
  allowed=true;sourceError=true;page.refresh();
  verify(awaitCondition([&]{return !page.m_busy && page.m_status->text().contains("加载失败");}) && !page.m_create->isEnabled(),
    "source read failure cannot expose stale selectable presets");
  sourceError=false;oldBackend=true;page.refresh();
  verify(awaitCondition([&]{return !page.m_busy && page.m_source->count()==1;}) && !page.m_create->isEnabled(),
    "old services without continuation metadata preserve their original failed-task restriction");
  oldBackend=false;page.refresh();
  verify(awaitCondition([&]{return page.m_create->isEnabled();}),"refresh recovers the explicit manual source choice");
  page.m_create->click();page.m_create->click();
  verify(awaitCondition([&]{return !page.m_busy && page.m_plan.value("state")=="draft";}),
    "successful manual source creation enters the original editable draft workflow");
  verify(server.requests.value("POST /api/pipelines/manual-ui/plan")==1,
    "repeated source-create clicks submit only once");
  const auto body=QJsonDocument::fromJson(server.requestBodies.value("POST /api/pipelines/manual-ui/plan")).object();
  verify(body.value("playbook_id")=="preset" && body.value("continue_after_scan_failure").toBool(),
    "manual continuation explicitly carries the selected preset and failure acknowledgement");
  verify(page.m_pipeline.value("status")=="awaiting_approval" && page.m_submit->isEnabled()
      && !page.m_canContinueFailedScan && page.m_content.value("target")=="http://fixture.invalid/",
    "server response preserves the same target and enables ordinary submission without claiming scan success");
  for(auto it=server.requests.cbegin();it!=server.requests.cend();++it)
    verify(!it.key().endsWith("/approve") && !it.key().endsWith("/execute") && !it.key().endsWith("/generate"),
      "selecting an existing plan never generates or executes it");

  // Selecting from the library starts a refresh before forwarding the chosen
  // source. A failed task must wait for server metadata instead of dropping it.
  plan={};status="failed";planDelay=80;
  task["config"]=QJsonObject{{"task_mode","assessment"},{"authorization_confirmed",true},{"auto_execute",false}};
  page.clearTaskContext();page.setTaskContext(task);
  page.useSourcePlaybook("preset");page.useSourcePlaybook("preset");
  verify(awaitCondition([&]{return !page.m_busy && page.m_plan.value("state")=="draft";}),
    "library selection waits for failed-task metadata then creates the chosen task draft");
  verify(server.requests.value("POST /api/pipelines/manual-ui/plan")==2,
    "repeated selection during loading creates only one additional draft");
  page.m_submit->click();
  verify(awaitCondition([&]{return page.m_approve->isEnabled() && page.m_plan.value("state")=="submitted";}),
    "historical scan-only task can submit its explicitly selected preset");
  bool confirmsEnabling=false;
  QTimer::singleShot(0,[&] {
    if(auto *box=qobject_cast<QMessageBox *>(QApplication::activeModalWidget())) {
      confirmsEnabling=box->text().contains(QStringLiteral("启用"));
      box->button(QMessageBox::No)->click();
    }
  });
  page.m_approve->click();
  verify(confirmsEnabling && server.requests.value("POST /api/pipelines/manual-ui/plan/approve")==0,
    "declining the explicit enable-and-execute confirmation does not approve or start");
  QTimer::singleShot(0,[] {
    if(auto *box=qobject_cast<QMessageBox *>(QApplication::activeModalWidget()))box->button(QMessageBox::Yes)->click();
  });
  page.m_approve->click();page.m_approve->click();
  verify(awaitCondition([&]{return !page.m_busy && page.m_plan.value("state")=="approved";}),
    "explicitly confirming the historical preset enters approved execution");
  const auto approvedBody=QJsonDocument::fromJson(server.requestBodies.value("POST /api/pipelines/manual-ui/plan/approve")).object();
  verify(approvedBody.value("enable_execution").toBool() && server.requests.value("POST /api/pipelines/manual-ui/plan/approve")==1,
    "execution enablement is explicit and duplicate approval clicks submit once");
  qApp->setStyleSheet(previousStyle);
}
