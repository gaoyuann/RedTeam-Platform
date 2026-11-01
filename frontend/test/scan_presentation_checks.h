#pragma once

static void runScanPresentationChecks(const std::function<void(bool, const char *)> &verify)
{
  const QString previousStyle = qApp->styleSheet();
  qApp->setStyleSheet(Theme::GlobalStyle + Theme::ButtonStyle + Theme::ItemViewStyle);
  MockServer server;
  bool failed = false, changed = false, unresolved = false;
  bool measurable = false;
  bool otherScanType = false;
  QString actionState = "running";
  QString state = "RUNNING";
  int delay = 0;
  QJsonObject standaloneTask;
  server.handler = [&](const QString &method, const QString &path) -> MockReply {
    const QUrl url(path); const QUrlQuery query(url);
    if (url.path() == "/api/pipelines/stable/verifications" && method == "POST") {
      const auto input=QJsonDocument::fromJson(server.requestBodies[method+" "+path]).object();
      return {success(QJsonObject{{"id","payload-stable"},{"finding_id",input["finding_id"]},{"state","needs_conditions"}})};
    }
    if (url.path() == "/api/pipelines/stable/verifications/payload-stable")
      return {success(QJsonObject{{"id","payload-stable"},{"finding_id",1},{"revision",0},{"eligible",true},
        {"finding",QJsonObject{{"result_data","{\"title\":\"Cookie fixture\"}"}}},
        {"current_payload",QJsonObject{{"state","available"},{"items",QJsonArray{QJsonObject{{"id","generated:code:repro.py"},
          {"name","repro.py"},{"origin","generated"},{"code","print('fixture')"}}}}}},
        {"plans",QJsonArray()},{"attempts",QJsonArray()},{"readiness",QJsonObject{{"ready",false}}}})};
    if (url.path() == "/api/pipelines/stable") {
      auto task = taskRecord("stable"); task["run_id"] = "";
      task["target"] = "fixture.invalid";
      const bool source = standaloneTask["scan_type"] == "source_scan";
      task["config"] = source ? QJsonObject{{"scan_mode","source_assisted"}} : QJsonObject{{"task_mode","assessment"}};
      task["summary"] = QJsonObject{{"scan_task_ids", QJsonArray{source ? "source-presentation" : "scan-stable"}}};
      return {success(task)};
    }
    if (url.path() == "/api/scan-tasks") return {success(standaloneTask.isEmpty() ? QJsonArray() : QJsonArray{standaloneTask})};
    if (url.path() == "/api/scan-tasks/scan-stable") return {success(standaloneTask)};
    if (url.path() != "/api/pipelines/stable/results") return {success(QJsonArray())};
    if (failed) return {QJsonObject{{"status", "error"}}, delay};
    const int after = query.queryItemValue("after").toInt();
    QJsonArray rows;
    const QStringList titles{QStringLiteral("会话 Cookie 未启用 Secure 标志，可能通过未加密连接传输"),
      QStringLiteral("目录索引暴露，可列出应用目录中的文件与子目录"),
      QStringLiteral("HTTP 响应缺少 Content-Security-Policy 安全标头")};
    for (int i = after; i < qMin(after + 100, 235); ++i) {
      const QJsonObject evidence{{"finding", i == 4 && changed ? QStringLiteral("Updated finding") : titles[i % titles.size()]},
        {"url", "https://fixture.invalid/login"}};
      rows.append(QJsonObject{{"id", i + 1}, {"scan_task_id", "scan-stable"}, {"result_type", "vulnerability"},
        {"category", "vulnerability"}, {"severity", "high"}, {"result_data",
          QString::fromUtf8(QJsonDocument(evidence).toJson(QJsonDocument::Compact))},
        {"payload_match",QJsonObject{{"status","none"}}},
        {"payload_code",i==0 ? QJsonValue(QJsonObject{{"schema_version",1},{"state","available"},{"scan_count",0},{"generated_count",1}}) : QJsonValue::Null}});
    }
    QJsonArray sources{QJsonObject{{"scan_task_id", "scan-stable"}, {"scan_type", otherScanType ? "web_scan" : "vuln_scan"},
        {"target", "fixture.invalid"}, {"status", state},
        {"error_message", otherScanType ? QStringLiteral("工具执行超时") : QString()}}};
    if (measurable) sources.append(QJsonObject{{"scan_task_id", "scan-finished"}, {"scan_type", "port_scan"},
        {"target", "fixture.invalid"}, {"status", "COMPLETED"}});
    return {success(QJsonObject{{"scan_records", rows},
      {"page", QJsonObject{{"total", 235}, {"next_after", after + rows.size()}, {"through", 235}, {"has_more", after + rows.size() < 235}}},
      {"scan_sources", sources},
      {"web_scan_process", QJsonArray{QJsonObject{{"result_type", "scan_agent_step"},
        {"result_data", QString::fromUtf8(QJsonDocument(QJsonObject{{"turn", 1}, {"action", "execute_check"},
          {"scan_type", "web_scan"}, {"state", actionState}}).toJson(QJsonDocument::Compact))}}}},
      {"scan_summary", QJsonObject{{"record_count", 235}, {"completeness", "complete"},
        {"active_calls", unresolved ? QJsonArray{QJsonObject{{"state", "unknown"}}} : QJsonArray()}}}}), delay};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  ScanPage page(&api); page.enableRibbonWorkspace(); page.resize(1024, 600); page.show();
  page.setPipelineScope("stable", {"scan-stable"}, "scanning");
  verify(awaitCondition([&] { return !page.m_scanPageBusy && page.m_aggregateRecords.size() == 100; }),
    "scan presentation fixture loads");
  page.m_pollTimer->stop();
  const QString capture = qEnvironmentVariable("REDTEAM_SCAN_SCREENSHOT_DIR");
  if (!capture.isEmpty()) QDir().mkpath(capture);
  auto *tree = page.m_resultTree;
  verify(tree->font().pixelSize() >= 14, "scan findings retain a readable body font");
  auto *payloadRow=tree->topLevelItem(0)->child(0);
  verify(!tree->isColumnHidden(3) && payloadRow->text(3).contains(QStringLiteral("暂无匹配"))
      && payloadRow->text(3).contains(QStringLiteral("AI 生成 1 份")),
    "saved finding code remains visible even when the payload catalog has no match");
  verify(tree->topLevelItem(0)->child(1)->text(3).contains(QStringLiteral("状态未提供")),
    "older responses never claim there is no generated code");
  tree->setCurrentItem(payloadRow);
  emit tree->itemClicked(payloadRow,3);
  auto *payloadDialog=page.findChild<FindingVerificationDialog*>("scanAuxPayloadVerification");
  verify(payloadDialog && awaitCondition([&]{return payloadDialog->currentId()=="payload-stable" && !payloadDialog->m_loading;}),
    "clicking payload status loads the selected finding directly");
  verify(payloadDialog->m_tabs->currentIndex()==1
      && payloadDialog->findChild<QPlainTextEdit*>("findingVerificationSource")->toPlainText()=="print('fixture')",
    "the direct entry displays associated code without a second finding picker");
  verify(server.requestBodies["POST /api/pipelines/stable/verifications"].contains("1")
      && server.requests["POST /api/pipelines/stable/verifications/payload-stable/verification-code"]==0
      && server.requests["POST /api/pipelines/stable/verifications/payload-stable/start"]==0,
    "viewing a payload neither generates code nor executes a test");
  payloadDialog->close();
  verify(awaitCondition([&]{return !page.m_scanPageBusy;}),"closing the payload workspace refreshes the task's summaries");
  page.m_pollTimer->stop();
  page.openRecordDetails(tree->topLevelItem(0)->child(0));
  auto *details = page.findChild<QDialog *>("scanAuxRecord");
  auto *evidence = details ? details->findChild<QPlainTextEdit *>() : nullptr;
  verify(evidence && evidence->font().pixelSize() >= 14 && evidence->isReadOnly(),
    "finding evidence dialog uses the readable body font");
  if (details) {
    QApplication::processEvents();
    if (!capture.isEmpty()) verify(details->grab().save(capture + "/finding-evidence.png"),
      "readable finding evidence screenshot is saved");
    details->close();
  }
  auto *tasks = page.findChild<QFrame *>("scanTasksPanel");
  auto *views = page.findChild<QComboBox *>("scanViewPicker");
  auto *spaces = page.findChild<QTabWidget *>("scanWorkspaces");
  verify(views && views->isVisible() && !spaces->tabBar()->isVisible() && !page.m_detailTabs->tabBar()->isVisible(),
    "one compact view selector replaces the two stacked tab bars");
  views->setCurrentIndex(1);
  verify(page.m_detailTabs->currentIndex() == 1 && spaces->currentIndex() == 0,
    "the view selector opens the existing recommendations workspace");
  page.m_detailTabs->setCurrentIndex(0);
  verify(views->currentIndex() == 0, "programmatic results navigation keeps the visible selector in sync");
  views->setCurrentIndex(2);
  verify(spaces->currentIndex() == 1 && !page.findChild<QWidget *>("scanToolbarActions")->isVisible(),
    "source view hides unrelated network scan controls");
  views->setCurrentIndex(0); QApplication::processEvents();
  verify(!tasks->isVisible() && tree->width() > 900 && tree->height() >= 360 && tree->mapTo(&page, QPoint()).y() <= 150,
    "aggregate scan reserves the first screen for results at 1024 by 600");
  verify(!page.m_webScanProcess->isVisible() && page.m_processToggle->isVisible(),
    "process logs remain reachable without occupying the default results layout");
  verify(page.m_scanProgress->maximum() == 0 && page.m_progressState->text().contains(QStringLiteral("进行中")),
    "running scan without measurable completion uses an indeterminate progress bar");
  verify(page.m_progressValue->text() == QStringLiteral("--%")
      && page.m_scanProgress->toolTip().contains(QStringLiteral("网站扫描 · 第 1 轮")),
    "waiting progress identifies the current persisted check without inventing a percentage");
  verify(page.m_scanProgress->height() == 12 && !page.findChild<QLabel *>("scanProgressDetail")
      && page.m_progressText->text() == QStringLiteral("扫描进度") && !page.m_compactStatus->isVisible(),
    "pentagi-style progress uses a prominent rounded bar and compact header without explanatory rows");
  measurable = true; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }) && page.m_scanProgress->maximum() == 100
      && page.m_scanProgress->value() == 50 && page.m_progressValue->text() == QStringLiteral("50% · 1 / 2"),
    "measurable progress displays actual ended scan counts");
  page.m_pollTimer->stop();
  if (!capture.isEmpty()) {
    QApplication::processEvents();
    verify(page.findChild<QFrame *>("scanProgressPanel")->grab().save(capture + "/scan-progress-strip.png"),
      "measurable pentagi-style progress strip is saved");
    verify(page.grab().save(capture + "/scan-progress-50-percent.png"), "measurable progress layout is saved");
  }
  actionState = "completed"; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; })
      && !page.m_scanProgress->toolTip().contains(QStringLiteral("网站扫描")),
    "a completed historical action is not presented as the currently running check");
  page.m_pollTimer->stop();
  measurable = false; actionState = "running"; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }), "waiting progress restores after a new scheduling round");
  page.m_pollTimer->stop();
  if (!capture.isEmpty()) {
    verify(page.grab().save(capture + "/scan-running-1024x600.png"), "running progress screenshot is saved");
  }
  page.m_tasksToggle->click(); verify(tasks->isVisible(), "collapsed scan tasks can be opened explicitly");
  page.m_tasksToggle->click();
  page.m_processToggle->click(); verify(page.m_webScanProcess->isVisible(), "process log toggle opens saved diagnostics");
  page.m_processToggle->click();
  auto *row = tree->topLevelItem(0)->child(4);
  tree->setCurrentItem(row); row->setCheckState(0, Qt::Checked);
  tree->verticalScrollBar()->setValue(8);
  const int scroll = tree->verticalScrollBar()->value();
  const QRect geometry = tree->geometry();
  QSignalSpy removed(tree->model(), &QAbstractItemModel::rowsRemoved);
  delay = 80;
  page.onRefreshTasks();
  const int request = page.m_scanPageRequest;
  page.onRefreshTasks(); page.onRefreshTasks();
  verify(page.m_scanPageRequest == request && tree->currentItem() == row && tree->geometry() == geometry,
    "overlapping refreshes coalesce while preserving visible rows and geometry");
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }), "coalesced scan refresh completes");
  page.m_pollTimer->stop();
  verify(removed.isEmpty() && tree->currentItem() == row && tree->verticalScrollBar()->value() == scroll
      && row->checkState(0) == Qt::Checked,
    "identical scan snapshots do not rebuild rows or reset focus, checks and scrolling");
  changed = true; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }), "changed scan snapshot completes");
  page.m_pollTimer->stop();
  verify(tree->currentItem() && tree->currentItem()->data(0, Qt::UserRole+1).toInt() == 5
      && tree->currentItem()->text(1).contains("Updated") && tree->currentItem()->checkState(0) == Qt::Checked
      && tree->verticalScrollBar()->value() == scroll,
    "changed evidence updates while preserving the finding identity and reading position");
  delay = 0;
  for (int i = 0; i < 2; ++i) {
    page.m_moreResultsButton->click();
    verify(awaitCondition([&] { return !page.m_scanPageBusy; }), "additional result page loads");
    page.m_pollTimer->stop();
  }
  page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }) && page.m_aggregateRecords.size() == 235
      && page.m_scanCursor == 235 && !page.m_moreResultsButton->isEnabled(),
    "refresh reloads the complete loaded window instead of discarding later result pages");
  page.m_pollTimer->stop();
  failed = true; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }) && page.m_aggregateRecords.size() == 235
      && !page.m_openCheckedFindings->isEnabled() && page.m_progressState->text().contains(QStringLiteral("失败"))
      && page.m_scanProgress->maximum() > 0,
    "failed refresh retains readable results, marks them stale and stops the waiting animation");
  failed = false; state = "COMPLETED"; unresolved = true; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }) && page.m_scanProgress->maximum() == 0
      && page.m_progressState->text().contains(QStringLiteral("待确认"))
      && page.m_scanProgress->toolTip().contains(QStringLiteral("等待工具")) && page.m_pollTimer->isActive(),
    "unfinished tool calls keep progress waiting even after scan records have ended");
  page.m_pollTimer->stop();
  unresolved = false; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }) && page.m_scanProgress->value() == page.m_scanProgress->maximum()
      && page.m_scanProgress->maximum() > 0 && !page.m_pollTimer->isActive() && page.m_openCheckedFindings->isEnabled(),
    "confirmed completion ends polling and successful recovery restores finding actions");
  otherScanType = true; page.m_ribbonScanType = "vuln_scan"; page.onRefreshTasks();
  verify(awaitCondition([&] { return !page.m_scanPageBusy; })
      && page.m_scanIssueSummary->isVisible()
      && page.m_scanIssueSummary->text().contains(QStringLiteral("当前筛选"))
      && page.m_scanIssueSummary->text().contains(QStringLiteral("工具执行超时")),
    "a different finding type and the actual scanner failure are explained above an empty filtered list");
  page.m_pollTimer->stop();
  page.clearTaskScope();
  verify(!page.m_scanIssueSummary->isVisible(), "clearing a task removes its scan diagnostics");
  otherScanType = false; page.setPipelineScope("stable", {"scan-stable"}, "scanning");
  verify(awaitCondition([&] { return !page.m_scanPageBusy; }), "scan scope restores after diagnostic checks");
  page.m_pollTimer->stop();
  if (!capture.isEmpty()) {
    QDir().mkpath(capture);
    for (const QSize size : {QSize(1024, 600), QSize(1366, 768)}) {
      page.resize(size); QApplication::processEvents();
      verify(page.grab().save(capture + QStringLiteral("/scan-%1x%2.png").arg(size.width()).arg(size.height())),
        "scan presentation screenshot is saved from real Qt controls");
    }
  }
  {
    MainWindow shell(&api, "admin", "fixture-user");
    shell.m_dongleTimer->stop(); shell.m_ws->disconnectFromServer();
    shell.resize(1366, 850); shell.show(); shell.openRibbonFeature("scans.system");
    QApplication::processEvents();
    verify(shell.m_taskGate->isVisible() && shell.m_newTaskButton->isVisible(),
      "the main scan page offers task selection and creation instead of a second independent workflow");
    if (!capture.isEmpty()) verify(shell.grab().save(capture + "/scan-window-empty.png"), "full empty scan window is saved");
    QTimer::singleShot(0, &shell, [&] {
      auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
      verify(dialog && dialog->objectName() == "taskCreateDialog", "main create action opens the shared task form");
      if (dialog) dialog->reject();
    });
    shell.m_newTaskButton->click();
    shell.m_flowPage->openTaskAnalysis("stable");
    verify(awaitCondition([&] { return shell.m_flowPage->taskContextReady(); }), "the main scan page loads its chosen test task");
    shell.openRibbonFeature("scans.system");
    auto *scan = shell.m_flowPage->scanTab();
    verify(!scan->findChild<QFrame *>("scanTasksPanel")->isVisible()
        && scan->findChild<QPushButton *>("scanQuickCreate")->isHidden(),
      "task scans use the shared task controls and hide independent creation");
    standaloneTask = QJsonObject{{"scan_task_id", "scan-stable"}, {"scan_type", "vuln_scan"},
      {"target", "fixture.invalid"}, {"status", "COMPLETED"}, {"results", page.m_aggregateRecords},
      {"created_at", "2026-10-31T12:00:00Z"}};
    scan->onRefreshTasks();
    verify(awaitCondition([&] { return scan->m_vulnScanTable->rowCount() == 1; }), "task scan source loads in the actual application");
    scan->m_tasksToggle->click(); scan->m_vulnScanTable->selectRow(0); emit scan->m_vulnScanTable->cellClicked(0, 0);
    verify(awaitCondition([&] { return scan->m_currentScanType == "vuln_scan"
        && scan->m_resultTree->topLevelItemCount() > 0; }), "task findings open through the scan source list");
    scan->m_tasksToggle->click();
    for (const QSize size : {QSize(1366, 850), QSize(1024, 720)}) {
      shell.resize(size); shell.m_navigationToggle->setChecked(false); QApplication::processEvents();
      auto *viewport = shell.m_workspaceScroll->viewport();
      auto *findings = scan->m_resultTree;
      const QRect area(findings->mapTo(viewport, QPoint()), findings->size());
      verify(findings->width() >= viewport->width() * 9 / 10 && findings->height() >= scan->height() * 3 / 5
          && viewport->rect().contains(area),
        "full application reserves most scan workspace height and width for readable findings");
      if (!capture.isEmpty()) verify(shell.grab().save(capture + QStringLiteral("/scan-window-%1x%2.png").arg(size.width()).arg(size.height())),
        "full application findings screenshot is saved");
    }
    standaloneTask=QJsonObject{{"scan_task_id","source-presentation"},{"scan_type","source_scan"},
      {"target",QStringLiteral("http://fixture.invalid/包含中文名称的源码工程/source/")},
      {"status","RUNNING"},{"created_at","2026-10-31T09:25:40.123Z"}};
    shell.m_flowPage->openTaskAnalysis("stable");
    verify(awaitCondition([&] { return shell.m_flowPage->taskContextReady(); }), "source task scope is loaded in the same main page");
    shell.openRibbonFeature("scans.system");
    scan->findChild<QComboBox*>("scanViewPicker")->setCurrentIndex(2);
    auto *sourceTasks=scan->findChild<QTableWidget*>("sourceFlowTasks");
    verify(awaitCondition([&]{return sourceTasks && sourceTasks->rowCount()==1;}),
      "source scan list loads through the real application workspace");
    for(const QSize size : {QSize(1366,850),QSize(1024,720)}) {
      shell.resize(size);QApplication::processEvents();
      auto *viewport=shell.m_workspaceScroll->viewport();
      const QRect area(sourceTasks->mapTo(viewport,QPoint()),sourceTasks->size());
      verify(viewport->rect().contains(area) && sourceTasks->height()>=scan->height()*3/5,
        "source task list stays fully inside the application viewport and owns most workspace height");
      for(int column : {1,2}) {
        const QRect cell=sourceTasks->visualItemRect(sourceTasks->item(0,column));
        verify(sourceTasks->viewport()->rect().contains(cell)
          && cell.width()>=sourceTasks->fontMetrics().horizontalAdvance(sourceTasks->item(0,column)->text())+8,
          "source scan status and complete date are readable in the actual application");
      }
      auto *picker=scan->findChild<QComboBox*>("scanViewPicker");
      verify(picker->width()>=picker->fontMetrics().horizontalAdvance(picker->currentText())+28,
        "source workspace selector displays its complete label");
      if(!capture.isEmpty())verify(shell.grab().save(capture+QStringLiteral("/source-window-%1x%2.png").arg(size.width()).arg(size.height())),
        "full source workspace screenshot is saved");
    }
    shell.openRibbonFeature("topology.display");
    auto *topology=shell.m_flowPage->topoTab();
    verify(topology,"application opens its existing topology canvas");
    if(topology) {
      TopologyDocument graph;
      for(int i=0;i<3;++i) {
        TopologyNodeRecord node;node.id=QString("presentation-%1").arg(i);
        node.ip=QString("192.0.2.%1").arg(i+1);node.deviceType="host";node.status="up";
        node.displayName=i==0 ? QStringLiteral("源主机") : i==1 ? QStringLiteral("服务器") : QStringLiteral("目标资产");
        if(i==0)node.tags.append("source");
        else if(i==1){node.deviceType="scanner";node.tags.append("server");}
        else node.tags.append("target");
        node.x=i*100;graph.nodes.append(node);
      }
      for(int i=0;i<2;++i) {
        TopologyEdgeRecord edge;edge.id=QString("edge-%1").arg(i);
        edge.sourceId=graph.nodes[i].id;edge.targetId=graph.nodes[i+1].id;
        edge.type=i==0 ? "task-request" : "reachability";
        edge.label=i==0 ? QStringLiteral("任务请求") : QStringLiteral("目标响应");graph.edges.append(edge);
      }
      topology->m_topologyDocument=graph;topology->m_selectedNodeId.clear();
      topology->m_selectedEdgeId.clear();topology->populateTopologyDocument();
      topology->selectWorkspaceMode("assets");
      topology->selectWorkspaceMode("display");
      verify(topology->m_statsLabel->text()==QStringLiteral("节点 3 | 连线 2 | 服务 0"),
        "switching from the asset list uses current graph counts instead of cached statistics");
      for(const QSize size : {QSize(1366,850),QSize(1024,720)}) {
        shell.resize(size);QApplication::processEvents();QApplication::processEvents();
        auto *view=topology->m_graphView;
        auto *viewport=shell.m_workspaceScroll->viewport();
        if(!capture.isEmpty()) shell.grab().save(capture+QStringLiteral("/topology-layout-%1x%2.png").arg(size.width()).arg(size.height()));
        if (!viewport->rect().contains(QRect(view->mapTo(viewport,QPoint()),view->size())))
          qWarning() << "Topology layout" << "viewport" << viewport->rect() << "canvas" << QRect(view->mapTo(viewport,QPoint()),view->size())
                     << "page" << topology->size() << "minimum" << topology->minimumSizeHint();
        verify(viewport->rect().contains(QRect(view->mapTo(viewport,QPoint()),view->size()))
          && view->height()>=topology->height()*3/5,
          "topology canvas remains complete inside the full application window");
        const QRectF visible=view->mapToScene(view->viewport()->rect()).boundingRect();
        const auto cards=topology->m_nodeItems.values();
        for(int i=0;i<cards.size();++i) {
          verify(visible.contains(cards[i]->sceneBoundingRect()),"every topology card is completely visible after window resize");
          for(int j=i+1;j<cards.size();++j)
            verify(!cards[i]->sceneBoundingRect().intersects(cards[j]->sceneBoundingRect()),"topology cards never obscure one another");
        }
        if(!capture.isEmpty())verify(shell.grab().save(capture+QStringLiteral("/topology-window-%1x%2.png").arg(size.width()).arg(size.height())),
          "full topology workspace screenshot is saved");
      }
      topology->findChild<QPushButton*>("topologySourcesButton")->click();
      QApplication::processEvents();QApplication::processEvents();
      const QRectF visible=topology->m_graphView->mapToScene(topology->m_graphView->viewport()->rect()).boundingRect();
      for(auto *card : topology->m_nodeItems)
        verify(visible.contains(card->sceneBoundingRect()),"opening the records panel refits the complete topology");
      if (!capture.isEmpty()) {
        shell.resize(1366,850);
        topology->m_nodeItems.value("presentation-0")->setSelected(true);
        QApplication::processEvents(); QApplication::processEvents();
        QTest::qWait(180); // Wait for tab underline animation before capturing.
        verify(shell.grab().save(capture + "/topology-properties.png"),
          "topology property editor and reference node screenshot is saved");
        for (auto *item : topology->m_graphScene->items()) {
          auto *text = dynamic_cast<QGraphicsSimpleTextItem *>(item);
          if (text && text->text() == QStringLiteral("源主机"))
            qInfo() << "Typography reference: node pixels" << text->font().pixelSize()
              << "canvas scale" << topology->m_graphView->transform().m11()
              << "field pixels" << topology->m_nodeNameEdit->font().pixelSize();
        }
      }
      topology->onZoomIn();
      const qreal zoom=topology->m_graphView->transform().m11();
      shell.resize(1100,740);QApplication::processEvents();QApplication::processEvents();
      verify(qAbs(topology->m_graphView->transform().m11()-zoom)<0.001,
        "explicit user zoom is retained when the window changes size");
    }
  }

  qApp->setStyleSheet(previousStyle);

}
