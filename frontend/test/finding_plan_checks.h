#pragma once

static void runFindingPlanChecks(const std::function<void(bool,const char *)> &verify)
{
  MockServer server;
  bool failList = false, failAppend = false, badDetail = false, failStart = false, ended = false;
  int listDelay = 0, detailDelay = 0, revision = 2;
  QString savedName = QStringLiteral("入口配置验证预案");
  auto planContent = [&]() {
    return QJsonObject{{"name",savedName},{"target","http://plan-a.invalid/item"},{"source_playbook_id","headers-template"},
      {"provenance",QJsonObject{{"kind","builtin"},{"label","配置检查模板"}}},
      {"prerequisites",QJsonArray{"已确认测试入口"}},{"missing_conditions",QJsonArray{}},
      {"success_criteria","核对指定响应头与完整响应"},{"cleanup","只读观察，无需清理"},
      {"max_attempts",3},{"duration_ms",10000},
      {"steps",QJsonArray{QJsonObject{{"step_id","observe"},{"step_index",0},{"name","观察入口"},{"tool_id","target-request"},
        {"args_template",QJsonArray{"{\"url\":\"http://plan-a.invalid/item\",\"method\":\"GET\"}"}},
        {"consumption","none"},{"expected_evidence","同次完整响应"}}}}};
  };
  auto detail = [&](int finding) {
    const auto result = QJsonObject{{"schema_version",1},{"status",ended?"inconclusive":"not_performed"},
      {"reason",ended?"连接失败，证据不足":"尚未执行"},{"objective",QJsonObject{{"label","观察指定响应头"}}},
      {"object",QJsonObject{{"target","http://plan-a.invalid/item"}}}};
    const auto attempt = QJsonObject{{"id","attempt-plan"},{"run_id","run-plan"},{"state","failed"},
      {"revision",revision},{"stop_confirmed",1},{"reason","fixture connection failed"},
      {"summary",QJsonObject{{"result",result}}},{"evidence",QJsonArray{}},{"reviews",QJsonArray{}},{"assessments",QJsonArray{}}};
    return QJsonObject{{"id","fv-"+QString::number(finding)},{"pipeline_id","plan-a"},{"finding_id",badDetail?99:finding},
      {"revision",revision},{"state",ended?"failed":"ready"},{"eligible",true},{"default_target","http://plan-a.invalid/item"},
      {"finding",QJsonObject{{"id",finding},{"result_type","web_vuln"},{"severity","medium"},{"source_tool","nikto"},
        {"result_data","{\"finding\":\"Missing response header\",\"url\":\"http://plan-a.invalid/item\"}"}}},
      {"plans",QJsonArray{QJsonObject{{"revision",revision},{"fingerprint","fingerprint-"+QString::number(revision)},{"content",planContent()}}}},
      {"readiness",QJsonObject{{"ready",!ended},{"reasons",QJsonArray{}}}},
      {"attempts",ended?QJsonArray{attempt}:QJsonArray{}},{"summary",QJsonObject{{"result",result},{"run_id",ended?"run-plan":""}}}};
  };
  server.handler = [&](const QString &method,const QString &url) -> MockReply {
    const QUrl parsed(url); const QString path=parsed.path(); const QUrlQuery query(parsed);
    const QString task=path.split('/').value(3);
    if (path=="/api/pipelines/plan-a" || path=="/api/pipelines/plan-b") {
      auto record=taskRecord(task);record["config"]=QJsonObject{{"workflow_mode","staged"},{"task_mode","assessment"}};
      return {success(record)};
    }
    if (path.endsWith("/results")) {
      if (query.queryItemValue("view")!="scans") return {success(resultsRecord(task))};
      const int after=query.queryItemValue("after").toInt();
      if (failList || failAppend && after) return {QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture list error"}}}},listDelay};
      QJsonArray rows;
      for (int i=after?3:1;i<=(after?3:2);++i) {
        const auto evidence=QJsonObject{{"finding",task+" finding "+QString::number(i)},{"url","http://"+task+".invalid/item"}};
        rows.append(QJsonObject{{"id",i},{"scan_task_id","scan-"+task},{"result_type","web_vuln"},{"category","vulnerability"},
          {"severity","medium"},{"result_data",QString::fromUtf8(QJsonDocument(evidence).toJson(QJsonDocument::Compact))},
          {"verification",i==1?QJsonValue(QJsonObject{{"id","fv-1"},{"revision",revision},{"state",ended?"failed":"ready"},
            {"run_id",ended?"run-plan":""},{"attempt_id",ended?"attempt-plan":""},
            {"result",QJsonObject{{"status",ended?"inconclusive":"not_performed"}}}}):QJsonValue::Null}});
      }
      return {success(QJsonObject{{"scan_records",rows},{"page",QJsonObject{{"total",3},{"next_after",after?3:2},{"through",3},{"has_more",!after}}}}),listDelay};
    }
    if (path.endsWith("/verifications") && method=="POST") return {success(QJsonObject{{"id","fv-1"},{"finding_id",1}})};
    if (path.endsWith("/verifications/fv-1")) return {success(detail(1)),detailDelay};
    if (path.endsWith("/verifications/fv-1/plans")) {
      const auto body=QJsonDocument::fromJson(server.requestBodies.value(method+" "+url)).object();
      savedName=body["name"].toString();++revision;
      return {success(QJsonObject{{"revision",revision},{"state","draft"}})};
    }
    if (path.endsWith("/verifications/fv-1/start")) {
      if (failStart) return {QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture preflight rejected"}}}}};
      ended=true;return {success(QJsonObject{{"run_id","run-plan"},{"id","attempt-plan"}})};
    }
    if (path.endsWith("/execution")) return {success(executionRecord(task))};
    return {success(QJsonArray{})};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  {
    TaskPlanPage page(&api,"admin");page.resize(1024,600);page.show();
    auto task=taskRecord("plan-a");task["config"]=QJsonObject{{"workflow_mode","staged"}};
    page.setTaskContext(task);
    auto *plans=page.m_findingPlans;
    verify(awaitCondition([&]{return plans->m_fresh && plans->m_table->rowCount()==2;}),"staged plan module lists the task findings and existing plan versions");
    verify(page.m_planViews->currentWidget()==plans && !page.m_name->isVisible() && !page.m_approve->isVisible(),
      "staged test hides the unrelated global approval form instead of requiring duplicate plans");
    verify(plans->m_table->item(0,4)->text()=="v2" && plans->m_table->item(1,4)->text()==QStringLiteral("未编制"),
      "existing and unprepared finding plans coexist in one list");
    plans->m_table->setCurrentCell(0,0);
    verify(awaitCondition([&]{return plans->m_detail->toPlainText().contains("headers-template");}),"plan selection reads the saved source template and concrete parameters");
    bool readOnly=true;for(auto it=server.requests.cbegin();it!=server.requests.cend();++it)if(it.key().startsWith("POST "))readOnly=false;
    verify(readOnly,"listing and inspecting plans creates no verification, model call or execution");
    plans->m_more->click();
    verify(awaitCondition([&]{return plans->m_fresh && plans->m_table->rowCount()==3;}),"finding plan pagination appends without dropping existing plans");
    verify(!plans->m_more->isVisible() && plans->m_table->item(0,0)->isSelected(),"pagination retains the selected plan and exposes its end");
    plans->m_open->click();
    auto editor=plans->m_editor;
    verify(editor && awaitCondition([&]{return !editor->m_loading && editor->m_revision==2;}),"plan editor opens the same saved verification with its revision");
    verify(server.requests.value("POST /api/pipelines/plan-a/verifications")==0 && editor->m_tabs->currentIndex()==0,
      "an existing plan opens by GET directly in the plan view without reinitializing it");
    for (auto *parent=editor->m_save->parentWidget();parent && parent!=editor;parent=parent->parentWidget())
      if (auto *group=qobject_cast<QGroupBox *>(parent)) if(group->isCheckable()) group->setChecked(true);
    editor->m_name->setText(QStringLiteral("当前漏洞独立预案"));
    page.hide();page.show();page.setTaskContext(task);
    verify(plans->m_editor==editor && editor->m_dirty && editor->m_name->text()==QStringLiteral("当前漏洞独立预案"),
      "module navigation and same-task refresh preserve the unsaved finding plan");
    plans->openFindings({2});
    verify(plans->m_editor==editor && editor->m_dirty,"opening another finding keeps the current unsaved editor available");
    editor->m_save->click();
    verify(awaitCondition([&]{return !editor->m_busy && !editor->m_loading && editor->m_revision==3;}),"saving the specific finding creates a new plan version");
    const auto saved=QJsonDocument::fromJson(server.requestBodies.value("POST /api/pipelines/plan-a/verifications/fv-1/plans")).object();
    verify(saved["source_playbook_id"]=="headers-template" && saved["target"]=="http://plan-a.invalid/item" && saved["expected_revision"]==2,
      "saved plan keeps the source template, target and optimistic version");
    verify(saved["max_attempts"]==3 && saved["duration_ms"]==10000,
      "editing a plan preserves its original attempt and duration limits");
    editor->close();
    verify(awaitCondition([&]{return plans->m_fresh && plans->m_table->item(0,4)->text()=="v3";}),"returning from the editor refreshes the same plan list version");
    failList=true;plans->refresh();
    verify(awaitCondition([&]{return !plans->m_busy;}),"failed plan refresh ends the pending state");
    verify(plans->m_table->rowCount()==2 && !plans->m_open->isEnabled() && plans->m_status->text().contains(QStringLiteral("失败")),
      "failed refresh retains old data but blocks opening unverified list entries");
    failList=false;plans->m_refresh->click();
    verify(awaitCondition([&]{return plans->m_fresh;}),"plan list recovers through its explicit retry button");
    failAppend=true;plans->m_more->click();
    verify(awaitCondition([&]{return !plans->m_busy;}) && plans->m_table->rowCount()==2 && !plans->m_open->isEnabled(),
      "append failure preserves the first page without allowing stale actions");
    failAppend=false;plans->refresh();verify(awaitCondition([&]{return plans->m_fresh;}),"plan list reloads after append failure");
    badDetail=true;plans->m_table->setCurrentCell(0,0);plans->showSelection();
    verify(awaitCondition([&]{return plans->m_detail->toPlainText().contains(QStringLiteral("来源不符"));}),"mismatched finding detail is rejected instead of showing another plan");
    badDetail=false;
    detailDelay=200;plans->showSelection();plans->m_table->setCurrentCell(1,0);
    QTest::qWait(250);
    verify(plans->m_detail->toPlainText().contains("#2") && !plans->m_detail->toPlainText().contains("headers-template"),
      "late plan detail cannot replace the newly selected finding");
    detailDelay=0;listDelay=200;plans->refresh();
    auto next=task;next["pipeline_id"]="plan-b";page.setTaskContext(next);
    verify(awaitCondition([&]{return plans->m_fresh && plans->record(0)["scan_task_id"]=="scan-plan-b";}),"switching tasks loads only the new task plan list");
    QTest::qWait(250);verify(plans->record(0)["scan_task_id"]=="scan-plan-b","late old-task plan pages cannot overwrite the selected test");
    listDelay=0;
  }
  {
    FlowPage flow(&api,"admin","fixture-user");flow.openFindingWorkspace("plan-a",{1});
    auto *plans=flow.m_planTab->m_findingPlans;
    verify(awaitCondition([&]{return plans->m_editor && plans->m_editor->m_revision==3 && !plans->m_editor->m_loading;}),
      "scan handoff opens the saved specific plan under the plan module");
    auto editor=plans->m_editor;
    verify(flow.workspaceStage()==4 && editor->m_target->text()=="http://plan-a.invalid/item","plan handoff retains the exact scan finding entry");
    failStart=true;
    auto confirm=[](){QTimer::singleShot(0,[](){if(auto *dialog=QApplication::activeModalWidget())if(auto *button=dialog->findChild<QPushButton*>("confirmFindingExecution"))button->click();});};
    confirm();editor->m_startSimple->click();
    verify(awaitCondition([&]{return editor->m_status->text().contains("fixture preflight rejected");}),"execution rejection remains visible in the plan editor");
    verify(flow.workspaceStage()==4 && plans->m_editor==editor,"failed start keeps the selected plan and does not navigate to an unrelated run");
    verify(awaitCondition([&]{return !editor->m_loading && editor->m_startSimple->isEnabled();}),
      "failed start reloads the same plan and restores the explicit retry action");
    failStart=false;confirm();editor->m_startSimple->click();
    verify(awaitCondition([&]{return flow.workspaceStage()==5;}),"confirmed plan execution switches to the attack module with the same test context");
    const auto start=QJsonDocument::fromJson(server.requestBodies.value("POST /api/pipelines/plan-a/verifications/fv-1/start")).object();
    verify(start["revision"]==3 && start["fingerprint"]=="fingerprint-3" && start["confirmed"].toBool(),
      "execution uses the explicitly confirmed saved plan version and fingerprint");
    verify(awaitCondition([&]{return !editor->m_loading && editor->m_assess->isEnabled();}),"failed execution evidence can enter assessment after stop confirmation");
    editor->m_assess->click();
    verify(flow.workspaceStage()==6 && flow.selectedTaskId()=="plan-a","evidence flows from the same plan execution into its test assessment");
    verify(server.requests.value("POST /api/pipelines/plan-a/results/reports")==0,"assessment leaves report generation as an explicit operation");
    flow.switchToStageTab(4);
    verify(awaitCondition([&]{return plans->m_fresh && plans->m_table->item(0,7)->text()==QStringLiteral("证据不足");}),
      "returning to the plan module keeps version, execution and conclusion together");
    const QString capture=qEnvironmentVariable("REDTEAM_PLAN_SCREENSHOT_DIR");
    if (!capture.isEmpty()) {
      QDir().mkpath(capture);flow.resize(1024,600);flow.show();QTest::qWait(40);
      verify(flow.grab().save(capture+"/finding-plans-"+qEnvironmentVariable("QT_SCALE_FACTOR","1")+".png"),"optional real Qt finding-plan screenshot is saved");
    }
  }
}
