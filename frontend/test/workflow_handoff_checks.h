#pragma once

static void runWorkflowHandoffChecks(const std::function<void(bool, const char *)> &verify)
{
  qRegisterMetaType<QList<qint64>>("QList<qint64>");
  MockServer server;
  bool contextFailure = false;
  bool failAdditionalFinding = false;
  bool failedTask = false;
  server.handler = [&](const QString &method, const QString &path) {
    if (path.endsWith("/test-context")) return MockReply{contextFailure
      ? QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture continuation failed"}}}}
      : success(QJsonObject{{"pipeline_id","task-a"},{"scan_task_id","scan-independent"}}), 120};
    for (const auto &id : {QString("task-a"), QString("task-b")}) {
      if (path == "/api/pipelines/" + id) {
        auto task = taskRecord(id);
        if (failedTask) { task["status"] = "failed"; task["error_message"] = "fixture scan incomplete"; }
        return MockReply{success(task), 100};
      }
      if (path == "/api/pipelines/" + id + "/execution") return MockReply{success(executionRecord(id))};
      if (path.startsWith("/api/pipelines/" + id + "/results")) return MockReply{success(resultsRecord(id))};
    }
    if (method == "POST" && path == "/api/pipelines/task-a/verifications") {
      const int finding=QJsonDocument::fromJson(server.requestBodies[method+" "+path]).object()["finding_id"].toInt();
      if(finding==124 && failAdditionalFinding) {
        failAdditionalFinding=false;
        return MockReply{QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture additional finding failed"}}}},80};
      }
      return MockReply{success(QJsonObject{{"id",finding==123?"fv-a":"fv-b"},{"finding_id",finding},{"state","needs_conditions"}}),finding==124?80:0};
    }
    if (path == "/api/pipelines/task-a/verifications/fv-b")
      return MockReply{success(QJsonObject{{"id","fv-b"},{"finding_id",124},{"revision",0},{"eligible",true},
        {"state","needs_conditions"},{"finding",QJsonObject{{"id",124},{"severity","high"},{"result_data","{\"title\":\"second finding\"}"}}},
        {"attempts",QJsonArray{}},{"plans",QJsonArray{}}})};
    if (path == "/api/pipelines/task-a/verifications/fv-a")
      return MockReply{success(QJsonObject{{"id","fv-a"},{"finding_id",123},{"revision",0},{"eligible",true},
        {"state","needs_conditions"},{"default_target","http://task-a.invalid/item"},
        {"finding",QJsonObject{{"id",123},{"source_tool","nikto"},{"severity","medium"},
          {"result_data","{\"finding\":\"missing response header\",\"url\":\"http://task-a.invalid/item\"}"}}},
        {"attempts",QJsonArray{}},{"plans",QJsonArray{}}})};
    return MockReply{success(QJsonArray{})};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  {
    ScanPage page(&api);
    page.m_pipelineId="task-a";
    page.updateStatusLabel({{"status","COMPLETED"},{"target","http://task-a.invalid"},{"scan_type","web_scan"}});
    const QJsonObject first{{"id",123},{"result_type","web_vuln"},{"severity","high"},
      {"result_data","{\"title\":\"first finding\"}"}};
    auto second=first;second["id"]=124;
    page.renderGroupedResults({first,second});
    QSignalSpy scope(&page,&ScanPage::findingPlansRequested);
    page.setCurrentFindingsChecked(true);
    page.m_resultTree->setCurrentItem(page.m_resultTree->topLevelItem(0));
    verify(page.m_prepareFinding->isEnabled(),"checked findings enable preparation even when the current row is a group");
    page.m_prepareFinding->click();
    verify(scope.count()==1 && qvariant_cast<QList<qint64>>(scope.first().at(1))==QList<qint64>({123,124}),
      "select-all followed by the main test button carries every checked finding");
    page.setCurrentFindingsChecked(false);
    page.m_resultTree->setCurrentItem(page.selectableFindingItems().last());
    page.m_prepareFinding->click();
    verify(scope.count()==2 && qvariant_cast<QList<qint64>>(scope.last().at(1))==QList<qint64>{124},
      "without checked rows the test button falls back to the current finding");
  }
  {
    TopologyPage page(&api);
    TopologyNodeRecord first; first.id="host-192.0.2.10";first.assetId="asset-a";first.ip="192.0.2.10";first.deviceType="host";
    TopologyNodeRecord second=first;second.id="host-192.0.2.11";second.assetId="asset-b";second.ip="192.0.2.11";
    page.m_topologyDocument.nodes={first,second};
    page.renderTopologyScene();page.selectWorkspaceMode("assets");
    page.m_assetTable->setCurrentCell(0,0);
    verify(page.currentSelectedNode() && page.currentSelectedNode()->assetId=="asset-a", "asset selection resolves the shared topology asset");
    QObject::connect(&page,&TopologyPage::topologyViewRequested,&page,[&]{page.selectWorkspaceMode("display");});
    page.m_viewAssetTopologyButton->click();
    verify(page.property("workspaceMode")=="display" && page.m_selectedNodeId==first.id && page.m_topologyDocument.nodes.size()==2,
      "view asset in topology preserves identity and reuses the existing document");
    page.selectWorkspaceMode("assets");page.m_assetTable->setCurrentCell(1,0);
    QSignalSpy scan(&page,&TopologyPage::testTargetRequested);
    page.m_nodeTestButton->click();
    verify(scan.count()==1 && scan.first().first().toString()==second.ip,"keyboard-selected asset supplies its own scan target");
  }
  {
    ScanPage page(&api);
    page.m_selectedTaskId="scan-independent";
    const QJsonObject finding{{"id",123},{"result_type","web_vuln"},{"severity","medium"},{"source_tool","nikto"},
      {"result_data","{\"finding\":\"missing response header\"}"}};
    page.updateStatusLabel({{"status","COMPLETED"},{"target","http://task-a.invalid"},{"scan_type","web_scan"}});
    page.renderGroupedResults({finding});
    page.m_resultTree->setCurrentItem(page.m_resultTree->topLevelItem(0)->child(0));
    QSignalSpy handoff(&page,&ScanPage::testContextRequested);
    verify(page.m_prepareFinding->isEnabled(),"a selected independent scan finding exposes the next operation");
    const int requests=server.requests.value("POST /api/scan-tasks/scan-independent/test-context");
    page.m_prepareFinding->click();page.m_prepareFinding->click();
    verify(awaitCondition([&]{return handoff.count()==1;}),"independent finding continues into the returned test context");
    verify(server.requests.value("POST /api/scan-tasks/scan-independent/test-context")==requests+1,"double click submits one context request");
    verify(handoff.first().first().toString()=="task-a" && qvariant_cast<QList<qint64>>(handoff.first().at(1))==QList<qint64>{123},
      "continuation carries the original finding identifier");
    page.m_prepareFinding->click();page.m_selectedTaskId="scan-other";
    QTest::qWait(160);
    verify(handoff.count()==1,"a late scan continuation cannot navigate away from a newly selected scan");
    page.m_selectedTaskId="scan-independent";contextFailure=true;page.updatePrepareFindingButton();page.m_prepareFinding->click();
    verify(awaitCondition([&]{return page.m_statusLabel->text().contains("fixture continuation failed");}),"continuation failure remains visible and retryable");
    verify(page.m_resultTree->topLevelItemCount()==1 && page.m_prepareFinding->isEnabled(),"continuation failure retains the finding and allows retry");
  }
  {
    FlowPage flow(&api,"admin","fixture-user");
    flow.openFindingWorkspace("task-a",{123});flow.openTaskAnalysis("task-b");
    verify(awaitCondition([&]{return flow.taskContextReady() && flow.selectedTaskId()=="task-b";}),"task switching waits for the new context");
    verify(server.requests.value("POST /api/pipelines/task-a/verifications")==0,"late task details cannot create a verification in an abandoned context");
    flow.openFindingWorkspace("task-a",{123});
    FindingVerificationDialog *dialog=nullptr;
    verify(awaitCondition([&]{dialog=flow.findChild<FindingVerificationDialog*>("findingPlanEditor");return dialog && dialog->m_target->text()=="http://task-a.invalid/item";}),
      "continued scan opens the finding plan with its concrete target filled in");
    verify(flow.workspaceStage()==4 && flow.m_planTab->m_planViews->currentWidget()==flow.m_planTab->m_findingPlans,
      "scan continuation belongs to the plan module and opens the shared finding plan workspace");
    verify(dialog->m_pipeline=="task-a" && dialog->m_detail["finding_id"].toInt()==123,"plan and evidence retain the same task and finding source");
    dialog->m_detail["attempts"]=QJsonArray{QJsonObject{{"state","failed"}}};dialog->updateButtons();
    verify(dialog->m_assess->isEnabled(),"failed attempts can proceed to assessment and reporting");
    dialog->m_assess->click();
    verify(flow.workspaceStage()==6 && flow.selectedTaskId()=="task-a","assessment handoff retains the test identity and opens its results");
    verify(server.requests.value("POST /api/pipelines/task-a/results/reports")==0,"entering assessment never generates a report automatically");
    auto snapshot=resultsRecord("task-a");
    snapshot["execution"]=findingExecutionRecord("task-a");
    snapshot["statistics"]=QJsonObject{{"verifications",QJsonObject{{"attempts",1}}},{"report_ready",true}};
    auto *results=flow.evalTab()->m_taskResults;
    results->m_snapshot=snapshot;results->render();
    verify(results->m_state->text().contains("已有 1 次逐漏洞测试记录") && results->m_state->text().contains("可生成"),
      "assessment recognizes child verification results and report readiness without a global run");
    snapshot=resultsRecord("task-a");
    auto execution=snapshot["execution"].toObject();auto run=execution["run"].toObject();
    run["status"]="COMPLETED";run["stop_reason"]="非可选步骤失败: system-tools";
    run["counts"]=QJsonObject{{"returned",6},{"steps",6},{"succeeded",5},{"failed",1}};
    execution["run"]=run;snapshot["execution"]=execution;
    results->m_snapshot=snapshot;results->render();
    verify(results->m_state->text().contains("待核对") && !results->m_state->text().contains("失败")
        && results->m_state->toolTip()==run["stop_reason"].toString(),
      "ended execution shows a concise review state and preserves the exact stop reason on demand");
    verify(results->m_metrics[1]->findChild<QLabel *>("metricValue")->text()==QStringLiteral("6 / 6"),
      "returned step count stays distinct from the execution outcome");
    failedTask=true;flow.loadFlowDetail("task-a");
    verify(awaitCondition([&]{return !flow.m_taskDetailBusy && flow.m_statusLabel->text().contains("待核对");})
        && flow.m_failureReason->isHidden() && flow.m_statusLabel->toolTip()=="fixture scan incomplete",
      "historical failed tasks retain diagnostics without a failure banner");
    failedTask=false;
  }
  {
    contextFailure = false;
    FlowPage flow(&api,"admin","fixture-user"); flow.setRibbonNavigation(true); flow.resize(1366,850); flow.show();
    const int before = server.requests.value("POST /api/pipelines/task-a/verifications");
    flow.openFindingAttackWorkspace("task-a",{123}); flow.openTaskAnalysis("task-b");
    verify(awaitCondition([&]{return flow.taskContextReady() && flow.selectedTaskId()=="task-b";}),
      "direct finding attack waits for the selected task context");
    verify(server.requests.value("POST /api/pipelines/task-a/verifications")==before,
      "abandoned attack handoff cannot create a verification for the previous task");
    flow.openTaskAnalysis("task-a");
    verify(awaitCondition([&]{return flow.taskContextReady() && flow.selectedTaskId()=="task-a";}),
      "current task is ready before checking retained verification editors");
    auto *foreign = new FindingVerificationDialog(&api,"task-b",{},&flow);
    foreign->setObjectName("taskFindingVerification");foreign->show();
    flow.openFindingAttackWorkspace("task-a",{123});
    QPointer<FindingVerificationDialog> attack;
    verify(awaitCondition([&]{
        for(auto *dialog:flow.findChildren<FindingVerificationDialog*>("taskFindingVerification"))
          if(dialog->pipelineId()=="task-a")attack=dialog;
        return attack && attack->m_target->text()=="http://task-a.invalid/item";}),
      "direct finding attack inherits the concrete scan target");
    verify(attack!=foreign && foreign->m_items->rowCount()==0
        && server.requests.value("POST /api/pipelines/task-b/verifications")==0,
      "an editor retained for another task never receives the current task findings");
    delete foreign;
    verify(flow.workspaceStage()==5 && flow.m_planTab->m_planViews->currentWidget()!=flow.m_planTab->m_findingPlans,
      "finding attack opens in the attack module without visiting the per-finding plan list");
    verify(attack->m_sources->isVisible() && attack->m_useSource->isVisible()
        && !attack->m_sourceChooser->isChecked(),
      "existing finding schemes remain visible without expanding advanced options or generating a plan");
    flow.m_execTab->selectAttackCategory(1);
    flow.openFindingAttackWorkspace("task-a",{123});
    verify(flow.m_execTab->attackCategory()==0, "direct finding attack clears unrelated scenario filters");
    verify(flow.findChildren<FindingVerificationDialog*>("taskFindingVerification").size()==1
        && server.requests.value("POST /api/pipelines/task-a/verifications")==before+1,
      "repeated attack clicks preserve one verification editor and its draft");
    attack->m_name->setText("unsaved source verification plan");attack->m_dirty=true;
    const auto original=attack->currentId();
    failAdditionalFinding=true;
    flow.openFindingAttackWorkspace("task-a",{123,124,124});
    flow.openFindingAttackWorkspace("task-a",{123,124});
    verify(awaitCondition([&]{return attack->m_status->text().contains("fixture additional finding failed");})
        && attack->m_items->rowCount()==1 && attack->m_name->text()=="unsaved source verification plan",
      "failed addition keeps existing findings and the current unsaved plan");
    flow.openFindingAttackWorkspace("task-a",{123,124});
    flow.openFindingAttackWorkspace("task-a",{123,124});
    verify(awaitCondition([&]{return attack->m_items->rowCount()==2;}),
      "reusing an open single-finding editor adds newly checked findings");
    verify(flow.findChildren<FindingVerificationDialog*>("taskFindingVerification").size()==1
        && attack->currentId()==original && attack->m_dirty && attack->m_name->text()=="unsaved source verification plan",
      "expanding a finding selection preserves the editor and unsaved current plan");
    verify(server.requests.value("POST /api/pipelines/task-a/verifications")==before+3,
      "repeated and overlapping selections do not duplicate pending verification creation");
    attack->m_items->item(1,0)->setCheckState(Qt::Unchecked);
    flow.openFindingAttackWorkspace("task-a",{124});
    verify(attack->m_items->rowCount()==2 && attack->m_items->item(1,0)->checkState()==Qt::Checked,
      "selecting a loaded finding rechecks its existing row without losing other findings");
    attack->m_dirty=false;
    auto *chooseExisting = flow.m_execTab->findChild<QPushButton *>("executionChoosePlaybook");
    auto *chooseFinding = flow.m_execTab->findChild<QPushButton *>("executionFindingAttack");
    verify(chooseExisting && chooseFinding && chooseExisting->isVisible() && chooseFinding->isVisible(),
      "current-task attack module exposes existing playbooks and per-finding attacks side by side");
    const auto folder = qEnvironmentVariable("REDTEAM_HANDOFF_SCREENSHOT_DIR");
    if (!folder.isEmpty()) {
      QDir().mkpath(folder);
      verify(flow.grab().save(folder + "/attack-options.png"), "both task attack choices are captured");
      verify(attack->grab().save(folder + "/finding-attack.png"), "direct finding attack editor is captured");
    }
    for (auto it=server.requests.cbegin();it!=server.requests.cend();++it)
      verify(!it.key().startsWith("POST ") || (!it.key().endsWith("/generate") && !it.key().endsWith("/execute")
          && !it.key().endsWith("/confirm") && !it.key().endsWith("/plan")),
        "opening either attack choice never generates a plan or starts execution");
    flow.openTaskAnalysis("task-b");
    verify(awaitCondition([&]{return flow.taskContextReady() && flow.selectedTaskId()=="task-b";}),
      "switching tasks invalidates the direct attack editor context");
    verify(!attack || !attack->isVisible(), "previous task attack editor closes on an explicit task switch");
  }

}
