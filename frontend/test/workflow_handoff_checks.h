#pragma once

static void runWorkflowHandoffChecks(const std::function<void(bool, const char *)> &verify)
{
  qRegisterMetaType<QList<qint64>>("QList<qint64>");
  MockServer server;
  bool contextFailure = false;
  server.handler = [&](const QString &method, const QString &path) {
    if (path.endsWith("/test-context")) return MockReply{contextFailure
      ? QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture continuation failed"}}}}
      : success(QJsonObject{{"pipeline_id","task-a"},{"scan_task_id","scan-independent"}}), 120};
    for (const auto &id : {QString("task-a"), QString("task-b")}) {
      if (path == "/api/pipelines/" + id) return MockReply{success(taskRecord(id)), 100};
      if (path == "/api/pipelines/" + id + "/execution") return MockReply{success(executionRecord(id))};
      if (path.startsWith("/api/pipelines/" + id + "/results")) return MockReply{success(resultsRecord(id))};
    }
    if (method == "POST" && path == "/api/pipelines/task-a/verifications")
      return MockReply{success(QJsonObject{{"id","fv-a"},{"finding_id",123},{"state","needs_conditions"}})};
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
  }
}
