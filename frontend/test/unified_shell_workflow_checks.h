#pragma once

static void runUnifiedShellWorkflowChecks(const std::function<void(bool, const char *)> &verify)
{
  const auto previousStyle = qApp->styleSheet();
  qApp->setStyleSheet(Theme::GlobalStyle + Theme::ButtonStyle + Theme::ItemViewStyle);
  MockServer server;
  bool childActive = false;
  auto task = taskRecord("unified-task"); task["status"] = "running"; task["run_id"] = "";
  task["config"] = QJsonObject{{"task_mode","assessment"}};
  server.handler = [&](const QString &, const QString &path) -> MockReply {
    const auto route = QUrl(path).path();
    if (route == "/api/pipelines") return {success(QJsonArray{task})};
    if (route == "/api/pipelines/unified-task") return {success(task), 60};
    if (route.endsWith("/execution")) {
      auto snapshot = childActive ? findingExecutionRecord("unified-task") : executionRecord("unified-task");
      snapshot["pipeline_status"] = task["status"];
      if (childActive) {
        auto child = snapshot["verification_runs"].toObject();
        child["active"] = 1; child["completed"] = 0;
        auto items = child["items"].toArray(); auto item = items[0].toObject();
        item["state"] = "running"; item["stop_confirmed"] = false; items[0] = item;
        child["items"] = items; snapshot["verification_runs"] = child;
      }
      if (task["run_id"].toString().isEmpty()) snapshot["run"] = QJsonValue::Null;
      return {success(snapshot)};
    }
    if (route.endsWith("/results")) return {success(resultsRecord("unified-task"))};
    if (route.endsWith("/plan")) return {QJsonObject{{"status","ok"},{"data",QJsonValue::Null}}};
    return {success(QJsonArray{})};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  MainWindow shell(&api, "admin", "fixture-user");
  shell.m_dongleTimer->stop(); shell.m_ws->disconnectFromServer(); shell.resize(1360,860); shell.show();
  const auto capture = [&](const QString &name) {
    const QString folder = qEnvironmentVariable("REDTEAM_UNIFIED_SCREENSHOT_DIR");
    if (folder.isEmpty()) return;
    QDir().mkpath(folder); QCoreApplication::processEvents();
    verify(shell.grab().save(folder + '/' + name + '-' + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
      "unified main window screenshot is saved");
  };
  for (const QString feature : {QString("scans.web"),QString("attacks.data"),QString("evaluation.results")}) {
    shell.openRibbonFeature(feature);
    verify(shell.m_taskGate->isVisible() && shell.m_stackWidget->currentIndex() == 1,
      "main scan attack and assessment require the same task context");
    verify(shell.m_stackWidget->widget(10)->property("deferredModule").toBool()
        && shell.m_stackWidget->widget(11)->property("deferredModule").toBool()
        && !shell.findChild<QPushButton *>("featureIndependent"),
      "opening main modules never constructs an independent testing workflow");
  }
  capture("no-task");
  auto *flow = shell.m_flowPage; auto *scan = flow->scanTab(); auto *execution = flow->execTab();
  const auto openFromList = [&] {
    shell.openRibbonFeature("system.tasks");
    verify(awaitCondition([&] { return flow->m_flowListFresh && flow->m_flowTable->rowCount() == 1; }),
      "task management displays the existing task");
    flow->m_flowTable->setCurrentCell(0,0);
    const QPoint position = flow->m_flowTable->visualItemRect(flow->m_flowTable->item(0,0)).center();
    QTest::mouseClick(flow->m_flowTable->viewport(), Qt::LeftButton, Qt::NoModifier, position);
    QTest::mouseDClick(flow->m_flowTable->viewport(), Qt::LeftButton, Qt::NoModifier, position);
    verify(awaitCondition([&] { return flow->taskContextReady() && !flow->taskListVisible()
        && flow->m_lastDisplayedDetail.value("status") == task.value("status")
        && flow->m_lastDisplayedDetail.value("run_id") == task.value("run_id"); }),
      "double clicking task management opens its task in the main window");
    verify(flow->m_stageTabs->tabBar()->isHidden() && !flow->m_backBtn->isHidden(),
      "main modules own navigation while return to task management stays reachable");
  };
  openFromList();
  verify(flow->workspaceStage() == 1 && shell.m_navList->currentRow() == 1,
    "a scanning task resumes in the main scan module");
  for (const auto &entry : QList<QPair<QString,int>>{{"scans.web",1},{"plans.task",4},{"attacks.data",5},{"evaluation.results",6}}) {
    shell.openRibbonFeature(entry.first);
    verify(flow->selectedTaskId() == "unified-task" && flow->workspaceStage() == entry.second
        && shell.m_stackWidget->currentWidget() == flow && flow->scanTab() == scan && flow->execTab() == execution,
      "main modules reuse the same task and page instances after opening from management");
    verify(flow->m_stageTabs->tabBar()->isHidden(), "each module omits the complete task workflow tab row");
    for (int stage = 0; stage < flow->m_stageTabs->count(); ++stage)
      verify(flow->m_stageTabs->widget(stage)->isVisible() == (stage == entry.second),
        "only the page owned by the selected module is visible");
    capture(entry.first);
  }
  task["status"] = "awaiting_approval"; task["generated_playbook_id"] = "fixture-plan";
  openFromList();
  verify(flow->workspaceStage() == 4 && shell.m_activeFeature == "plans.task",
    "a task awaiting approval resumes in the main plan module");
  shell.openRibbonFeature("attacks.data");
  verify(awaitCondition([&] { return !execution->m_taskMonitor->m_busy; }), "task execution read finishes before reviewing the main view");
  capture("attack-review");
  childActive = true; execution->refreshTaskRecords();
  verify(awaitCondition([&] { return execution->m_taskMonitor->m_state->text().contains(QStringLiteral("逐漏洞测试进行中")); }),
    "an active finding execution is not hidden by the unexecuted whole-task plan status");
  childActive = false;
  task["status"] = "running"; task["run_id"] = "run-unified-task";
  openFromList();
  verify(flow->workspaceStage() == 5 && shell.m_navList->currentRow() == 3,
    "a running attack resumes in the main attack module");
  task["status"] = "failed";
  task["error_message"] = QStringLiteral("参数检查未完成：工具超时");
  openFromList();
  verify(flow->workspaceStage() == 6 && shell.m_activeFeature == "evaluation.results",
    "an ended attack resumes in the main assessment with its evidence");
  verify(flow->m_statusLabel->isHidden() && flow->m_failureReason->isVisible()
      && flow->m_failureReason->text().contains(QStringLiteral("工具超时")),
    "task failure shows its real reason instead of a separate red failure badge");
  capture("task-assessment");
  shell.m_overviewButton->click(); shell.m_switchTaskButton->click();
  verify(awaitCondition([&] { return flow->m_flowListFresh && flow->taskListVisible(); }),
    "task overview offers the same task selector");
  flow->onFlowDoubleClicked(0);
  verify(awaitCondition([&] { return flow->taskContextReady() && !flow->taskListVisible()
      && flow->workspaceStage() == 0 && !shell.m_selectingFeatureTask && shell.m_pendingTaskFeature.isEmpty(); }),
    "selecting the current task from overview retains that stage and closes task management");
  shell.switchToPage(11);
  verify(shell.m_stackWidget->currentWidget() == flow && shell.m_stackWidget->widget(11)->property("deferredModule").toBool(),
    "legacy attack page identifiers resolve into the same main task page");
  for (auto it = server.requests.cbegin(); it != server.requests.cend(); ++it)
    verify(it.key().startsWith("GET "), "opening tasks and switching modules never creates a scan or attack");
  qApp->setStyleSheet(previousStyle);
}
