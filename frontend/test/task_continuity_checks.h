#pragma once

static void runTaskContinuityChecks(const std::function<void(bool, const char *)> &verify, bool failedScan = false)
{
  const auto previousStyle = qApp->styleSheet();
  qApp->setStyleSheet(Theme::GlobalStyle + Theme::ButtonStyle + Theme::ItemViewStyle);
  MockServer server;
  auto task = taskRecord("journey"); task["status"] = "created"; task["run_id"] = "";
  auto other = taskRecord("another-task"); other["run_id"] = "";
  QJsonObject plan;
  bool created = false, reported = false;
  int taskDelay = 0;
  const auto planReply = [&](const QJsonValue &data) {
    auto response = success(data);
    if (failedScan) response["meta"] = QJsonObject{{"plan_selection",QJsonObject{
      {"pipeline_status",task.value("status")},{"can_create_from_existing",true},
      {"requires_scan_failure_confirmation",task.value("status") == "failed"},
      {"reason",task.value("status") == "failed" ? QStringLiteral("扫描未完整成功，可选择已有预案继续") : QString()}}}};
    return response;
  };
  const QJsonObject content{{"name","本次目标验证"},{"target","journey.invalid"},
    {"source_playbook_id","existing-method"},{"source_playbook",QJsonObject{{"name","已有验证方法"}}},
    {"notes",""},{"suggestions",QJsonArray{}},{"steps",QJsonArray{QJsonObject{
      {"step_id","observe"},{"name","核对指定入口"},{"tool_id","target-request"},
      {"args_template",QJsonArray{"fixture"}},{"optional",false}}}}};
  server.handler = [&](const QString &method, const QString &path) -> MockReply {
    const QString route = QUrl(path).path();
    const auto body = QJsonDocument::fromJson(server.requestBodies.value(method + ' ' + path)).object();
    if (route == "/api/pipelines" && method == "POST") {
      created = true; task["config"] = body["config"]; task["target"] = body["target"];
      auto reply = success(task); reply["meta"] = QJsonObject{{"task_identity_version",1}};
      return {reply};
    }
    if (route == "/api/pipelines") return {success(created ? QJsonArray{task,other} : QJsonArray{})};
    if (route == "/api/pipelines/journey/start") { task["status"] = "running"; return {success(task)}; }
    if (route == "/api/pipelines/journey") return {success(task),taskDelay};
    if (route == "/api/pipelines/another-task") return {success(other)};
    if (route == "/api/pipelines/journey/plan") {
      if (method == "POST") {
        if (failedScan) {
          verify(body.value("continue_after_scan_failure").toBool(),"failed-task journey acknowledges retained scan failure");
          task["status"]="awaiting_approval";
        }
        plan = QJsonObject{{"pipeline_id","journey"},{"state","draft"},{"revision",1},{"content",content}};
      }
      if (method == "PUT") { plan["content"] = body["content"]; plan["revision"] = 2; }
      return {planReply(plan.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(plan))};
    }
    if (route == "/api/pipelines/journey/plan/sources") return {planReply(QJsonArray{
      QJsonObject{{"playbook_id","existing-method"},{"name","已有验证方法"},{"steps_count",1}}})};
    if (route == "/api/pipelines/journey/plan/submit") { plan["state"] = "submitted"; plan["revision"] = 3; return {planReply(plan)}; }
    if (route == "/api/pipelines/journey/plan/approve") {
      plan["state"] = "approved"; plan["revision"] = 4;
      if (failedScan) {
        verify(body.value("enable_execution").toBool(),"failed-task journey explicitly enables reviewed execution for historical config");
        auto config=task["config"].toObject();config["auto_execute"]=true;task["config"]=config;
      }
      task["status"] = "running"; task["run_id"] = "run-journey";
      return {planReply(plan),60};
    }
    for (const QString id : {QString("journey"),QString("another-task")}) {
      if (route == "/api/pipelines/" + id + "/execution") {
        auto snapshot = executionRecord(id);
        auto run = snapshot["run"].toObject(); run["status"] = task["status"] == "completed" ? "COMPLETED" : "RUNNING";
        snapshot["run"] = id == "journey" && task["run_id"].toString().isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(run);
        return {success(snapshot)};
      }
      if (route == "/api/pipelines/" + id + "/results") {
        if (path.contains("view=scans")) return {success(QJsonObject{{"scan_records",QJsonArray{}},{"scan_sources",QJsonArray{}},
          {"page",QJsonObject{{"total",0},{"has_more",false},{"next_after",0},{"through",0}}}})};
        auto snapshot = resultsRecord(id); auto execution = snapshot["execution"].toObject();
        auto run = execution["run"].toObject(); run["status"] = "COMPLETED"; execution["run"] = run;
        snapshot["execution"] = execution;
        snapshot["reports"] = reported && id == "journey" ? QJsonArray{reportMetadata(id)} : QJsonArray{};
        return {success(snapshot)};
      }
    }
    if (route == "/api/pipelines/journey/results/reports" && method == "POST") {
      reported = true;
      return {success(QJsonObject{{"pipeline_id","journey"},{"run_id","run-journey"},{"report",reportMetadata("journey")}}),60};
    }
    if (route == "/api/pipelines/journey/results/reports/trace-journey") return {success(reportRecord("journey"))};
    return {success(QJsonArray{})};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  MainWindow shell(&api,"admin","fixture-user"); shell.m_dongleTimer->stop(); shell.m_ws->disconnectFromServer();
  shell.resize(1360,860); shell.show();
  const auto capture = [&](const QString &name) {
    const auto folder = qEnvironmentVariable("REDTEAM_JOURNEY_SCREENSHOT_DIR");
    if (folder.isEmpty()) return;
    QDir().mkpath(folder); QCoreApplication::processEvents();
    verify(shell.grab().save(folder + '/' + name + ".png"),"task journey screenshot is saved from actual widgets");
  };
  auto confirm = [] {
    QTimer::singleShot(0, [] {
      if (auto *box = qobject_cast<QMessageBox *>(QApplication::activeModalWidget())) box->button(QMessageBox::Yes)->click();
    });
  };
  QTimer::singleShot(30,&shell,[&] {
    auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
    verify(dialog && dialog->objectName() == "taskCreateDialog","home starts the existing test creation form");
    dialog->findChild<QLineEdit *>("taskTargetInput")->setText("journey.invalid");
    dialog->findChild<QCheckBox *>("taskAuthorizationCheck")->setChecked(true);
    dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
  });
  shell.findChild<QPushButton *>("homeCreateTest")->click();
  verify(awaitCondition([&] { return shell.m_flowPage && shell.m_flowPage->taskContextReady()
      && shell.m_flowPage->workspaceStage() == 1; }),"home creation starts and opens the same task scan workspace");
  auto *flow = shell.m_flowPage; auto *plans = flow->m_planTab;
  verify(!shell.m_taskGate->isVisible() && flow->m_stageTabs->tabBar()->isHidden(),
    "current module exposes its page without a second complete workflow navigation");
  const int revision = flow->taskSelectionRevision();
  for (const auto &entry : QList<QPair<QString,int>>{{"plans.scenario",2},{"topology.display",3},
      {"plans.task",4},{"attacks.data",5},{"evaluation.results",6},{"scans.system",1}}) {
    const auto *feature = ModuleRibbon::feature(entry.first);
    shell.m_navList->setCurrentRow(feature->module);
    shell.findChild<QToolButton *>("ribbon." + entry.first)->click();
    verify(flow->selectedTaskId() == "journey" && flow->taskSelectionRevision() == revision
        && flow->workspaceStage() == entry.second && shell.m_activeFeature == entry.first
        && !shell.m_taskGate->isVisible() && flow->m_stageTabs->tabBar()->isHidden(),
      "module clicks show only their own stage while preserving the same task");
    for (int stage = 0; stage < flow->m_stageTabs->count(); ++stage)
      verify(flow->m_stageTabs->widget(stage)->isVisible() == (stage == entry.second),
        "unrelated task stages stay hidden inside the selected module");
  }
  shell.openRibbonFeature("system.tasks");
  task["status"] = failedScan ? "failed" : "awaiting_approval";
  task["generated_playbook_id"] = failedScan ? "" : "existing-method";
  if (failedScan) {
    auto config=task["config"].toObject();config["auto_execute"]=false;task["config"]=config;
  }
  flow->loadFlowDetail("journey");
  verify(awaitCondition([&] { return flow->m_lastDisplayedDetail.value("status") == (failedScan ? "failed" : "awaiting_approval") && plans->m_create->isEnabled(); })
      && flow->taskListVisible() && shell.m_activeFeature == "system.tasks",
    "scan completion updates its task without taking over task management");
  flow->findChild<QPushButton *>("taskListContinue")->click();
  verify(flow->workspaceStage() == 1 && (failedScan || flow->m_approveBtn->isVisible()),
    "continuing returns to the saved scan stage with its next review action");
  shell.openRibbonFeature("attacks.data");
  auto *chooseExisting = flow->m_execTab->findChild<QPushButton *>("executionChoosePlaybook");
  verify(chooseExisting && chooseExisting->isVisible(), "attack module offers the established existing-playbook path");
  chooseExisting->click();
  verify(awaitCondition([&] { return flow->workspaceStage() == 4 && plans->m_create->isEnabled(); })
      && plans->m_planViews->currentWidget() == plans->m_globalPlan && plans->m_technicalDetails->isChecked(),
    "existing-playbook choice opens this task source selection without per-finding generation");
  plans->m_create->click();
  verify(awaitCondition([&] { return plans->m_plan.value("state") == "draft"; }),"existing method becomes the current task plan without another test");
  plans->m_name->setText(QStringLiteral("保留未保存的方案编辑"));
  const int planReads = server.requests.value("GET /api/pipelines/journey/plan");
  flow->m_backBtn->click();
  verify(flow->taskListVisible() && flow->selectedTaskId() == "journey" && plans->m_dirty,
    "return to task list retains the active task and its unsaved plan");
  shell.showHome(); shell.m_dashboardPage->m_continueTaskButton->click();
  verify(flow->workspaceStage() == 4 && plans->m_name->text() == QStringLiteral("保留未保存的方案编辑") && plans->m_dirty,
    "home continue restores the same plan editor and unsaved input");
  shell.m_switchTaskButton->click();
  verify(awaitCondition([&] { return flow->m_flowListFresh && flow->taskListVisible(); }),"explicit management browses tasks without clearing the current draft");
  flow->onFlowDoubleClicked(0);
  verify(awaitCondition([&] { return !flow->taskListVisible() && !shell.m_selectingFeatureTask && shell.m_pendingTaskFeature.isEmpty(); }),
    "reopening the same task also completes the explicit selector without a new task revision");
  verify(plans->m_dirty && plans->m_name->text() == QStringLiteral("保留未保存的方案编辑")
      && flow->taskSelectionRevision() == revision && server.requests.value("GET /api/pipelines/journey/plan") == planReads,
    "reopening current task does not rebuild or reload its draft");
  capture("plan-draft-retained");
  plans->m_save->click();
  verify(awaitCondition([&] { return !plans->m_busy && !plans->m_dirty && plans->m_plan.value("revision") == 2; }),"saved edit retains the same task plan version chain");
  plans->m_submit->click();
  verify(awaitCondition([&] { return plans->m_approve->isEnabled() && plans->m_plan.value("state") == "submitted"; }),"submitted current-task plan is ready for confirmation");
  confirm(); plans->m_approve->click(); plans->m_approve->click();
  verify(awaitCondition([&] { return flow->workspaceStage() == 5 && flow->m_lastDisplayedDetail.value("run_id") == "run-journey"; }),
    "confirming the reviewed version enters its execution without a new task selection");
  verify(server.requests.value("POST /api/pipelines/journey/plan/approve") == 1,"repeated clicks do not create a second execution");
  shell.openRibbonFeature("resources.tools"); shell.openRibbonFeature("attacks.data");
  verify(flow->selectedTaskId() == "journey" && flow->workspaceStage() == 5 && !shell.m_taskGate->isVisible(),
    "returning from global configuration keeps the executing task");
  task["status"] = "completed"; flow->loadFlowDetail("journey");
  auto *results = flow->m_evalTab->m_taskResults;
  verify(awaitCondition([&] { return flow->workspaceStage() == 6 && results->m_generate->isEnabled(); }),
    "execution completion enters the same task result ready for report generation");
  confirm(); results->m_generate->click(); results->m_generate->click();
  verify(awaitCondition([&] { return results->m_selectedReportId == "trace-journey" && !results->m_busy; }),
    "report generation refreshes and selects the report from this task execution");
  verify(server.requests.value("POST /api/pipelines/journey/results/reports") == 1
      && server.requests.value("POST /api/pipelines") == 1 && server.requests.value("POST /api/pipelines/journey/start") == 1,
    "the complete home-to-report journey creates and starts exactly one test");
  capture("same-task-report");
  shell.openRibbonFeature("system.tasks"); flow->findChild<QPushButton *>("taskListContinue")->click();
  verify(flow->selectedTaskId() == "journey" && flow->workspaceStage() == 6 && !flow->taskListVisible(),
    "continuing from management restores the report stage");
  taskDelay = 150; flow->loadFlowDetail("journey");
  shell.openRibbonFeature("system.tasks");
  verify(awaitCondition([&] { return flow->m_flowListFresh; }),"replacement task list loads");
  flow->onFlowDoubleClicked(1);
  verify(awaitCondition([&] { return flow->taskContextReady() && flow->selectedTaskId() == "another-task"; }),
    "only explicitly opening another task changes the task identity");
  QTest::qWait(180);
  verify(flow->selectedTaskId() == "another-task" && plans->m_pipeline.value("pipeline_id") == "another-task",
    "late prior-task details cannot restore the previous plan or execution");
  qApp->setStyleSheet(previousStyle);
}
