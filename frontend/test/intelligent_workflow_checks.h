#pragma once

static void runIntelligentWorkflowChecks(const std::function<void(bool, const char *)> &verify)
{
  MockServer server;
  auto task = taskRecord("intelligent-test");
  task["status"] = "running"; task["run_id"] = "";
  task["config"] = QJsonObject{{"workflow_mode","intelligent"},{"task_mode","assessment"},
    {"authorization_confirmed",true},{"authorization_scope","fixture only"},{"task_name","智能流程样例"}};
  QJsonObject plan{{"pipeline_id","intelligent-test"},{"state","submitted"},{"revision",2},
    {"content",QJsonObject{{"name","响应头核对"},{"target",task["target"]},{"source_playbook_id","generated-fixture"},
      {"source_playbook",QJsonObject{{"name","响应头核对"},{"description","仅核对指定页面的响应头"}}},
      {"notes",""},{"suggestions",QJsonArray{}},
      {"steps",QJsonArray{QJsonObject{{"step_id","observe"},{"name","读取页面响应头"},
        {"tool_id","curl"},{"args_template",QJsonArray{"-I","<target>"}},{"optional",false}}}}}},
    {"history",QJsonArray{QJsonObject{{"action","submit"},{"revision",2},{"note","系统自动编制并送审"}}}}};
  bool failApproval = false;
  server.handler = [&](const QString &method, const QString &path) -> MockReply {
    if (method == "POST" && path == "/api/pipelines") {
      task["status"] = "created";
      return {success(task)};
    }
    if (method == "POST" && path == "/api/pipelines/intelligent-test/start") {
      task["status"] = "running"; return {success(task)};
    }
    if (path == "/api/pipelines/intelligent-test") return {success(task)};
    if (path == "/api/pipelines/intelligent-test/plan/approve") {
      if (failApproval) return {QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture approval rejected"}}}},100};
      plan["state"] = "approved"; plan["revision"] = 3;
      task["status"] = "running"; task["run_id"] = "run-intelligent-test";
      return {success(plan),100};
    }
    if (path == "/api/pipelines/intelligent-test/plan")
      return {success(task["status"] == "running" && task["run_id"].toString().isEmpty() ? QJsonValue::Null : QJsonValue(plan))};
    if (path.endsWith("/execution")) return {success(executionRecord("intelligent-test"))};
    if (path.contains("/results")) return {success(resultsRecord("intelligent-test"))};
    if (path == "/api/pipelines") return {success(QJsonArray{})};
    if (path == "/api/scan-tasks") return {success(QJsonArray{})};
    return {success(QJsonObject{})};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  const auto capture = [&](QWidget *widget, const QString &name) {
    const auto folder = qEnvironmentVariable("REDTEAM_PENTAGI_UI_SCREENSHOT_DIR");
    if (folder.isEmpty()) return;
    QDir().mkpath(folder);
    verify(widget->grab().save(folder + '/' + name + '-' + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
      "optional local screenshot records the actual task controls");
  };
  FlowPage flow(&api,"admin","fixture-user"); flow.setRibbonNavigation(true); flow.resize(1366,860); flow.show();
  QTimer::singleShot(0, &flow, [&] {
    auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
    verify(dialog != nullptr,"intelligent task creation opens the existing target dialog");
    auto *target = dialog->findChild<QLineEdit *>("taskTargetInput");
    target->setText("http://127.0.0.1;8080");
    dialog->findChild<QCheckBox *>("taskAuthorizationCheck")->setChecked(true);
    verify(dialog->findChild<QLabel *>("taskTargetError")->isVisible()
        && !dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->isEnabled(),
      "malformed host separator is explained and cannot create a scan");
    target->setText("http://fixture.invalid/");
    auto *options = dialog->findChild<QToolButton *>("taskOptionsToggle");
    verify(options && !options->isChecked() && !dialog->findChild<QLineEdit *>("taskNameInput")->isVisible(),
      "task initiation requires a target while optional naming remains collapsed");
    QTest::qWait(20);
    auto *type = dialog->findChild<QComboBox *>("taskTestTypeInput");
    auto *form = dialog->findChild<QScrollArea *>("taskCreateScroll");
    verify(form->viewport()->rect().contains(type->mapTo(form->viewport(), type->rect().bottomLeft())),
      "the target type stays in the initial viewport on small scaled screens");
    for (auto *check : dialog->findChildren<QCheckBox *>()) if (check->text().contains("授权")) check->setChecked(true);
    capture(dialog, "create-task");
    dialog->accept();
  });
  flow.m_quickBtn->click();
  verify(awaitCondition([&] { return server.requests.value("POST /api/pipelines/intelligent-test/start") == 1; }),
    "new intelligent test starts scanning after target confirmation");
  const auto creation = QJsonDocument::fromJson(server.requestBodies.value("POST /api/pipelines")).object()["config"].toObject();
  verify(!creation.contains("workflow_mode") && creation["task_mode"] == "assessment" && creation["require_approval"].toBool(),
    "ordinary test reuses the original pipeline and keeps explicit execution review");
  verify(awaitCondition([&] { return flow.taskContextReady() && flow.m_lastDisplayedDetail["status"] == "running"; }),
    "intelligent test retains its task while scanning");
  verify(flow.m_stageTabs->tabBar()->isHidden(),
    "main ribbon owns stage navigation without a second workbench tab bar");
  flow.m_stageTabs->setCurrentIndex(2);
  verify(flow.selectedTaskId() == "intelligent-test" && flow.workspaceStage() == 2,
    "opening task analysis from scanning retains the same task");
  flow.m_stageTabs->setCurrentIndex(1);
  verify(awaitCondition([&] { return !flow.m_planTab->m_busy && flow.m_planTab->m_plan.isEmpty()
      && flow.m_planTab->m_reviewSummary->isHidden(); }),
    "pending model generation does not create a phantom plan or a ready summary");
  task["config"] = creation;
  task["generated_playbook_id"] = "generated-fixture";
  task["status"] = "awaiting_approval";
  flow.loadFlowDetail("intelligent-test");
  verify(awaitCondition([&] { return flow.workspaceStage() == 4 && !flow.m_planTab->m_busy; }),
    "original pipeline opens its own review when generation finishes");
  flow.requestWorkspaceStage(5);
  verify(flow.m_execTab->m_reviewPlan->isVisible() && flow.m_execTab->m_pipelineHint->isVisible(),
    "task execution exposes the review action outside the hidden standalone tabs");
  flow.m_execTab->m_reviewPlan->click();
  verify(flow.workspaceStage() == 4 && flow.selectedTaskId() == "intelligent-test",
    "attack entry returns to the same task review without creating an independent run");
  task["config"] = QJsonObject{{"workflow_mode","intelligent"},{"task_mode","assessment"},
    {"authorization_confirmed",true},{"authorization_scope","fixture only"}};
  task["status"] = "running"; flow.loadFlowDetail("intelligent-test");
  verify(awaitCondition([&] { return flow.m_lastDisplayedDetail["status"] == "running"; }),
    "existing intelligent task remains supported alongside the restored default");
  task["status"] = "awaiting_approval";
  task["summary"] = QJsonObject{{"plan",QJsonObject{{"state","submitted"},{"revision",2}}}};
  flow.loadFlowDetail("intelligent-test");
  verify(awaitCondition([&] { return flow.workspaceStage() == 4 && flow.m_planTab->m_plan["state"] == "submitted"; }),
    "automatically prepared plan opens in the plan module ready for review");
  auto *page = flow.m_planTab;
  verify(page->m_reviewSummary->text().contains("响应头核对") && page->m_reviewSummary->text().contains("无需填写工具参数"),
    "review presents a readable generated plan without requiring tool parameters");
  verify(awaitCondition([&] { return page->m_approve->isEnabled(); }),"generated plan is ready for explicit execution approval");
  verify(page->m_create->isHidden() && page->m_submit->isHidden(),"automatic review does not require manual draft creation or submission");
  verify(page->m_planConfiguration->isHidden() && page->m_stepEditor->isHidden(),
    "generated review keeps technical configuration out of the primary steps and confirmation view");
  verify(page->m_planKind->currentText() == QStringLiteral("整体任务方案"), "review clearly identifies the whole-task plan");
  page->showFindingPlanList();
  verify(page->m_planKind->currentIndex() == 1 && page->m_planViews->currentWidget() == page->m_findingPlans,
    "per-finding plans have an explicit view within the same task");
  flow.onApproveFlow();
  verify(awaitCondition([&] { return page->m_planKind->currentIndex() == 0 && !page->m_busy
      && page->m_planViews->currentWidget() == page->m_globalPlan; }),
    "review task plan returns from finding plans to the actual whole-task approval");
  capture(page, "review-plan");
  auto *more = page->findChild<QPushButton *>("planActionsMenu");
  verify(more && more->menu() && !page->m_technicalDetails->isChecked(),"secondary plan operations share a native action menu");
  more->menu()->actions().first()->trigger();
  verify(!page->m_planConfiguration->isHidden() && !page->m_stepEditor->isHidden()
      && !page->m_steps->isColumnHidden(1) && !page->m_steps->isColumnHidden(2)
      && page->m_plan.value("revision") == 2 && !page->m_dirty,
    "technical details open read only without modifying or submitting the plan");
  capture(page, "review-technical");
  more->menu()->actions().first()->trigger();
  verify(server.requests.value("POST /api/pipelines/intelligent-test/plan") == 0
      && server.requests.value("POST /api/pipelines/intelligent-test/plan/submit") == 0,
    "reading the generated review never recreates or resubmits a plan");
  auto answer = [](QMessageBox::StandardButton response) {
    QTimer::singleShot(0, [response] {
      if (auto *box = qobject_cast<QMessageBox *>(QApplication::activeModalWidget())) box->button(response)->click();
    });
  };
  answer(QMessageBox::No); page->m_approve->click();
  verify(server.requests.value("POST /api/pipelines/intelligent-test/plan/approve") == 0,
    "cancelling execution confirmation does not approve or start anything");
  failApproval = true; answer(QMessageBox::Yes); page->m_approve->click();
  verify(awaitCondition([&] { return page->m_status->text().contains("fixture approval rejected"); }) && flow.workspaceStage() == 4,
    "approval rejection stays visible on the same plan and remains retryable");
  failApproval = false; answer(QMessageBox::Yes); page->m_approve->click(); page->m_approve->click();
  verify(awaitCondition([&] { return flow.workspaceStage() == 5; }),
    "confirmed generated plan continues into execution using the same task");
  verify(awaitCondition([&] { return flow.m_execTab->m_taskMonitor->m_primaryPlan
      && flow.m_execTab->m_taskMonitor->m_parentDetails->isChecked()
      && flow.m_execTab->m_taskMonitor->m_tabs->currentWidget() == flow.m_execTab->m_taskMonitor->m_steps; }),
    "intelligent execution exposes its own steps and evidence without an optional-plan detour");
  const auto approved = QJsonDocument::fromJson(server.requestBodies.value("POST /api/pipelines/intelligent-test/plan/approve")).object();
  verify(approved["revision"] == 2 && server.requests.value("POST /api/pipelines/intelligent-test/plan/approve") == 2,
    "approval sends the displayed version once per explicit confirmation");
  verify(awaitCondition([&] { return flow.m_execTab->m_pipelineStatus == "running" && flow.m_execTab->m_reviewPlan->isHidden(); }),
    "running execution no longer exposes an approval action after task refresh");
  task["config"] = creation;
  task["status"] = "failed"; flow.loadFlowDetail("intelligent-test");
  verify(awaitCondition([&] { return flow.workspaceStage() == 6; }),
    "original pipeline retains a failed execution and opens its assessment");
  flow.requestWorkspaceStage(5);
  task["status"] = "completed"; flow.loadFlowDetail("intelligent-test");
  verify(awaitCondition([&] { return flow.workspaceStage() == 6; }) && flow.selectedTaskId() == "intelligent-test",
    "execution completion opens results with the same task identity");
  verify(server.requests.value("POST /api/pipelines/intelligent-test/results/reports") == 0,
    "automatic navigation to results leaves report generation explicit");
}
