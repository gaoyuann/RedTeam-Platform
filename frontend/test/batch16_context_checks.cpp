#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include <functional>
#include <iostream>

#include "ApiClient.h"
#include "UiUtil.h"
#include "AppStyle.h"
#define private public
#include "pages/FlowPage.h"
#include "pages/ScanPage.h"
#include "pages/AnalysisPage.h"
#include "pages/TaskAiPanel.h"
#include "pages/TaskPlanPage.h"
#include "pages/TaskOverviewPage.h"
#include "pages/TaskLogPanel.h"
#include "pages/TopologyPage.h"
#include "pages/ExecutionPage.h"
#include "pages/EvaluatePage.h"
#include "pages/TaskExecutionPanel.h"
#include "pages/TaskResultsPanel.h"
#include "pages/StepIndicator.h"
#undef private

struct MockReply {
  QJsonObject body;
  int delay = 0;
};

class MockServer : public QTcpServer {
public:
  std::function<MockReply(const QString &, const QString &)> handler;
  QMap<QString, int> requests;
  QMap<QString, QByteArray> requestBodies;

  MockServer()
  {
    connect(this, &QTcpServer::newConnection, this, [this]() {
      while (hasPendingConnections()) {
        auto *socket = nextPendingConnection();
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
          const QByteArray buffer = socket->property("buffer").toByteArray() + socket->readAll();
          socket->setProperty("buffer", buffer);
          const int headersEnd = buffer.indexOf("\r\n\r\n");
          if (headersEnd < 0 || socket->property("handled").toBool()) return;
          const auto length = QRegularExpression("(?:^|\\r\\n)Content-Length:\\s*(\\d+)",
              QRegularExpression::CaseInsensitiveOption).match(QString::fromLatin1(buffer.left(headersEnd)));
          const int bodyLength = length.hasMatch() ? length.captured(1).toInt() : 0;
          if (buffer.size() < headersEnd + 4 + bodyLength) return;
          socket->setProperty("handled", true);
          const auto request = buffer.left(buffer.indexOf('\r')).split(' ');
          const QString method = QString::fromUtf8(request.value(0));
          const QString path = QString::fromUtf8(request.value(1));
          ++requests[method + " " + path];
          requestBodies[method + " " + path] = buffer.mid(headersEnd + 4, bodyLength);
          const auto response = handler(method, path);
          QPointer<QTcpSocket> guard(socket);
          QTimer::singleShot(response.delay, this, [guard, response]() {
            if (!guard) return;
            const auto body = QJsonDocument(response.body).toJson(QJsonDocument::Compact);
            guard->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                         + QByteArray::number(body.size()) + "\r\n\r\n" + body);
            guard->disconnectFromHost();
          });
        });
      }
    });
    if (!listen(QHostAddress::LocalHost, 0)) qFatal("Cannot bind isolated mock server");
  }
};

static QJsonObject success(const QJsonValue &data)
{
  return {{"status", "ok"}, {"data", data}};
}

static QJsonObject taskRecord(const QString &taskId)
{
  return {{"pipeline_id", taskId}, {"target", taskId + ".invalid"}, {"created_by", "fixture-user"},
          {"status", "completed"}, {"run_id", "run-" + taskId},
          {"config", QJsonObject{{"task_name", taskId + " fixture task"}}},
          {"analysis_result", QJsonObject{{"risk_assessment", QJsonArray{QJsonObject{{"name", taskId + " candidate"}}}}}},
          {"steps", QJsonArray()}, {"summary", QJsonObject{{"scan_task_ids", QJsonArray{"scan-" + taskId}}}}};
}

static QJsonObject scanRecord(const QString &taskId)
{
  return {{"scan_task_id", "scan-" + taskId}, {"target", taskId + ".invalid"},
          {"scan_type", "port_scan"}, {"status", "FAILED"},
          {"created_at", "2026-10-10T02:00:00Z"}, {"results", QJsonArray()}};
}

static QJsonObject executionRecord(const QString &taskId)
{
  const QJsonObject counts{{"steps", 0}, {"returned", 0}, {"succeeded", 0}, {"failed", 0}, {"attempts", 0}, {"evidence", 0}};
  return {{"version", 1}, {"pipeline_id", taskId}, {"owner", "fixture-user"}, {"target", taskId + ".invalid"},
          {"run", QJsonObject{{"run_id", "run-" + taskId}, {"status", "FAILED"}, {"counts", counts}}},
          {"steps", QJsonArray()}, {"attempts", QJsonArray()}, {"evidence", QJsonArray()}, {"preflight", QJsonArray()}};
}

static QJsonObject reportMetadata(const QString &taskId)
{
  return {{"report_id", "trace-" + taskId}, {"run_id", "run-" + taskId}, {"title", "Frozen fixture"},
          {"status", "draft"}, {"kind", "trace_snapshot"}, {"source_fingerprint", QString(64, '1')},
          {"created_at", "2026-10-10T02:00:00Z"},
          {"review", QJsonObject{{"available", true}, {"state", "draft"}, {"revision", 0},
                                  {"source_fingerprint", QString(64, '1')}, {"history", QJsonArray()},
                                  {"history_total", 0}, {"history_limit", 20}}}};
}

static QJsonObject resultsRecord(const QString &taskId)
{
  return {{"version", 1}, {"pipeline_id", taskId}, {"owner", "fixture-user"}, {"target", taskId + ".invalid"},
          {"source_fingerprint", QString(64, '1')}, {"execution", executionRecord(taskId)},
          {"findings", QJsonArray()}, {"reports", QJsonArray{reportMetadata(taskId)}},
          {"assessment", QJsonObject{{"notice", "工具成功不等于漏洞成立"}}}, {"trace", QJsonObject()}};
}

static QJsonObject reportRecord(const QString &taskId)
{
  auto report = reportMetadata(taskId);
  auto results = resultsRecord(taskId);
  results.remove("reports");
  report["content"] = QJsonObject{{"schema_version", 1}, {"type", "task_result_report"}, {"results", results},
      {"provenance", QJsonObject{{"pipeline_id", taskId}, {"owner", "fixture-user"}, {"target", taskId + ".invalid"},
                                 {"run_id", "run-" + taskId}, {"source_fingerprint", QString(64, '1')}}}};
  return {{"pipeline_id", taskId}, {"owner", "fixture-user"}, {"target", taskId + ".invalid"}, {"report", report}};
}

static bool awaitCondition(const std::function<bool()> &condition)
{
  QElapsedTimer timer;
  timer.start();
  while (!condition() && timer.elapsed() < 5000) QTest::qWait(10);
  return condition();
}

int main(int argc, char **argv)
{
  QTemporaryDir isolatedSettings;
  if (!isolatedSettings.isValid()) return 1;
  qputenv("XDG_CONFIG_HOME", isolatedSettings.path().toUtf8());
  qputenv("XDG_DATA_HOME", isolatedSettings.path().toUtf8());
  QApplication app(argc, argv);
  app.setQuitOnLastWindowClosed(false);
  int checks = 0;
  auto verify = [&](bool passed, const char *name) {
    if (!passed) {
      std::cerr << "FAIL " << name << std::endl;
      std::exit(1);
    }
    ++checks;
    std::cout << "PASS " << name << std::endl;
  };

  MockServer server;
  bool delayedTask = false;
  bool delayedScans = false;
  bool sourceOnly = false;
  QString sourceStatus = "COMPLETED";
  auto sourceRecord = [&]() {
    auto record = scanRecord("source");
    record["scan_type"] = "source_scan";
    record["target"] = "http://127.0.0.1:8089/";
    record["status"] = sourceStatus;
    record["results"] = QJsonArray{QJsonObject{{"id", 101}, {"result_type", "source_finding"},
      {"severity", "medium"}, {"result_data", QString::fromUtf8(QJsonDocument(QJsonObject{{"file", "input.c"},
        {"start_line", 12}, {"title", "Fixture input review"}}).toJson(QJsonDocument::Compact))}}};
    return record;
  };
  bool failedTask = false;
  server.handler = [&](const QString &, const QString &requestPath) -> MockReply {
    const QString path = QUrl(requestPath).path();
    if (sourceOnly && path == "/api/scan-tasks") return {success(QJsonArray{sourceRecord()})};
    if (sourceOnly && path == "/api/scan-tasks/scan-source") return {success(sourceRecord())};
    const QString taskId = path.split('/').value(3);
    if (path == "/api/pipelines") return {success(QJsonArray{taskRecord("A"), taskRecord("B")})};
    if (path == "/api/scan-tasks") return {success(QJsonArray{scanRecord("A"), scanRecord("B")}), delayedScans ? 250 : 0};
    if (path == "/api/scan-tasks/scan-A") return {success(scanRecord("A")), delayedScans ? 250 : 0};
    if (path == "/api/scan-tasks/scan-B") return {success(scanRecord("B"))};
    if (path == "/api/pipelines/" + taskId) {
      if (failedTask && taskId == "A")
        return {{{"status", "error"}, {"error", QJsonObject{{"message", "fixture task load failed"}}}}};
      return {success(taskRecord(taskId)), delayedTask && taskId == "A" ? 250 : 0};
    }
    if (path.endsWith("/execution")) return {success(executionRecord(taskId))};
    if (path.endsWith("/results")) return {success(resultsRecord(taskId))};
    if (path.contains("/results/reports/")) return {success(reportRecord(taskId))};
    if (path.endsWith("/plan")) return {success(QJsonValue::Null)};
    return {success(QJsonArray())};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  FlowPage flow(&api, "user", "fixture-user");
  flow.resize(1360, 860);
  flow.show();
  verify(awaitCondition([&]() { return flow.m_flowListFresh; }), "task index loads from isolated loopback");
  flow.openTaskAnalysis("A");
  verify(awaitCondition([&]() { return flow.m_aiPanel->m_pipelineId == "A" && flow.m_scanTab->m_selectedTaskId == "scan-A"; }), "selected task and scan finish loading");
  verify(flow.m_selectedPipelineId == "A", "task keeps exact identity");
  verify(flow.m_stepIndicator->phases().first().status == "pending", "missing authorization never displays confirmed preparation");
  verify(flow.m_analysisTab->m_pipeline.value("pipeline_id").toString() == "A", "analysis belongs to task A");
  verify(flow.m_planTab->m_pipeline.value("pipeline_id").toString() == "A", "plan belongs to task A");
  verify(flow.m_topoTab->m_pipelineId == "A" && flow.m_topoTab->m_pipelineScanIds == QStringList{"scan-A"}, "topology carries only task A scans");
  verify(flow.m_execTab->m_taskMonitor->m_expectedRunId == "run-A", "execution uses task A run");
  verify(flow.m_evalTab->m_taskResults->m_expectedRunId == "run-A", "results use task A run");
  verify(flow.m_scanTab->m_portScanTable->rowCount() == 1, "scan list excludes task B");
  for (int index = 0; index < flow.m_stageTabs->count(); ++index) {
    flow.switchToStageTab(index);
    verify(flow.m_selectedPipelineId == "A" && flow.m_aiPanel->m_stage == flow.m_stageTabs->tabText(index), "stage navigation preserves task and AI phase");
  }
  verify(awaitCondition([&]() { return flow.m_execTab->m_taskMonitor->m_snapshot.value("pipeline_id").toString() == "A"; }), "execution snapshot remains task-bound");
  verify(awaitCondition([&]() { return flow.m_evalTab->m_taskResults->m_snapshot.value("pipeline_id").toString() == "A"; }), "results snapshot remains task-bound");

  delayedTask = true;
  flow.loadFlowDetail("A");
  flow.openTaskReport("B", "trace-B");
  verify(flow.m_scanTab->m_scopeTaskIds.isEmpty() && flow.m_scanTab->m_selectedTaskId.isEmpty(), "switch immediately clears old scan identity");
  verify(flow.m_scanTab->m_portScanTable->rowCount() == 0 && flow.m_scanTab->m_currentTaskTarget.isEmpty(), "switch immediately clears old scan content");
  verify(flow.m_startBtn->isHidden() && flow.m_approveBtn->isHidden() && flow.m_moreBtn->isHidden(), "switch hides previous task actions while loading");
  verify(flow.m_targetLabel->text().contains("加载") && flow.m_targetLabel->toolTip().isEmpty(), "switch clears previous task header");
  verify(awaitCondition([&]() { return flow.m_evalTab->m_taskResults->m_report.value("pipeline_id").toString() == "B"; }), "exact task B report loads");
  QTest::qWait(300);
  verify(flow.m_selectedPipelineId == "B" && flow.m_aiPanel->m_pipelineId == "B", "late task A response cannot replace task B");
  verify(flow.m_analysisTab->m_pipeline.value("pipeline_id").toString() == "B" && flow.m_planTab->m_pipeline.value("pipeline_id").toString() == "B", "analysis and plan switch together");
  verify(flow.m_evalTab->m_taskResults->m_selectedReportId == "trace-B", "global report opens exact report ID");
  verify(flow.m_scanTab->m_scopeTaskIds == QStringList{"scan-B"}, "scan scope switches to task B");

  delayedScans = true;
  const int oldListRequests = server.requests.value("GET /api/scan-tasks");
  flow.m_scanTab->onRefreshTasks();
  verify(awaitCondition([&]() { return server.requests.value("GET /api/scan-tasks") > oldListRequests; }), "delayed scan list request is in flight");
  flow.setReturnPage(3, QStringLiteral("智能分析"));
  int returnedPage = -1;
  QObject::connect(&flow, &FlowPage::returnPageRequested, &flow, [&](int page) { returnedPage = page; });
  flow.onBackToList();
  QTest::qWait(350);
  verify(returnedPage == 3 && flow.m_stack->currentIndex() == 0, "return keeps exact source page");
  verify(flow.m_selectedPipelineId.isEmpty() && flow.m_aiPanel->m_pipelineId.isEmpty(), "return clears task and AI identity");
  verify(flow.m_analysisTab->m_pipeline.value("pipeline_id").toString().isEmpty()
      && flow.m_analysisTab->m_items.isEmpty() && flow.m_analysisTab->m_table->rowCount() == 0
      && flow.m_planTab->m_pipeline.value("pipeline_id").toString().isEmpty()
      && flow.m_planTab->m_steps->rowCount() == 0, "return clears analysis and plan content");
  verify(flow.m_scanTab->m_scopedTasks && flow.m_scanTab->m_scopeTaskIds.isEmpty() && flow.m_scanTab->m_selectedTaskId.isEmpty(), "return blocks global fallback and clears scan scope");
  verify(flow.m_scanTab->m_portScanTable->rowCount() == 0 && !flow.m_scanTab->m_pollTimer->isActive(), "late scan response cannot revive rows or polling");
  verify(flow.m_scanTab->m_portTargetInput->text().isEmpty() && flow.m_scanTab->m_currentTarget.isEmpty() && flow.m_scanTab->m_currentTaskTarget.isEmpty(), "return clears every scan target");
  verify(flow.m_execTab->m_taskMonitor->m_pipelineId.isEmpty() && flow.m_evalTab->m_taskResults->m_pipelineId.isEmpty(), "return clears execution and result identity");
  verify(flow.m_evalTab->m_taskResults->m_snapshot.isEmpty() && flow.m_evalTab->m_taskResults->m_report.isEmpty(), "return clears snapshot and report content");
  verify(flow.m_startBtn->isHidden() && flow.m_approveBtn->isHidden() && flow.m_resultBtn->isHidden() && flow.m_moreBtn->isHidden(), "return clears task toolbar");
  verify(!flow.m_cancelAction->isVisible() && !flow.m_deleteAction->isVisible() && !flow.m_reportAction->isVisible(), "return clears task menu");
  verify(flow.m_logPanel->m_pipelineId.isEmpty() && !flow.m_logToggleBtn->isEnabled(), "return clears task logs");
  bool phasesPending = flow.m_stepIndicator->phases().size() == 6;
  for (const auto &phase : flow.m_stepIndicator->phases()) phasesPending = phasesPending && phase.status == "pending";
  verify(phasesPending, "return clears previous phase completion");
  const int requestsAfterReturn = server.requests.value("GET /api/scan-tasks");
  flow.m_scanTab->onRefreshTasks();
  QTest::qWait(50);
  verify(server.requests.value("GET /api/scan-tasks") == requestsAfterReturn, "cleared scan page does not request global data");

  delayedTask = false;
  delayedScans = false;
  flow.openTaskAnalysis("A");
  verify(awaitCondition([&]() { return flow.m_scanTab->m_selectedTaskId == "scan-A"; }), "reopening restores exact task scope");
  delayedScans = true;
  const int oldDetailRequests = server.requests.value("GET /api/scan-tasks/scan-A");
  emit flow.m_scanTab->m_portScanTable->cellClicked(0, 0);
  verify(awaitCondition([&]() { return server.requests.value("GET /api/scan-tasks/scan-A") > oldDetailRequests; }), "delayed scan detail request is in flight");
  flow.onBackToList();
  delayedScans = false;
  flow.openTaskAnalysis("A");
  verify(awaitCondition([&]() { return flow.m_scanTab->m_currentTarget == "A.invalid"; }), "same task can reopen with fresh scan context");
  flow.m_scanTab->m_currentTarget = QStringLiteral("fresh-context-marker");
  QTest::qWait(350);
  verify(flow.m_scanTab->m_currentTarget == "fresh-context-marker", "old same-ID scan response cannot overwrite reopened context");
  flow.onBackToList();
  QTest::qWait(350);
  verify(flow.m_scanTab->m_currentTarget.isEmpty() && flow.m_scanTab->m_resultTree->topLevelItemCount() == 0, "late scan detail cannot restore old target or results");
  sourceOnly = true;
  ScanPage sourcePage(&api, "user", "fixture-user");
  sourcePage.setTaskScope({"scan-source"});
  verify(awaitCondition([&]() { return sourcePage.m_selectedTaskId == "scan-source" && sourcePage.m_sourceDemoBtn->isEnabled(); }), "source task loads in scoped workbench with demonstration selector");
  verify(sourcePage.m_sourceScanTable->rowCount() == 1 && sourcePage.m_scanTypeTabs->currentIndex() == 4, "C/C++ task selects its existing scan tab");
  verify(sourcePage.m_genBtn->text().contains("攻击测试预案"), "source generation offers the program test plan action");
  sourceStatus = "RUNNING";
  emit sourcePage.m_sourceScanTable->cellClicked(0, 0);
  verify(awaitCondition([&]() { return !sourcePage.m_genBtn->isEnabled(); }), "running source task disables generation");
  sourceStatus = "COMPLETED";
  sourcePage.onPollStatus();
  verify(awaitCondition([&]() { return sourcePage.m_genBtn->isEnabled() && sourcePage.m_sourceDemoBtn->isEnabled(); }), "source polling completion refreshes results and generation controls");
  bool selectionLoaded = false;
  QTimer::singleShot(0, &sourcePage, [&]() {
    auto *dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
    if (!dialog) return;
    auto *candidates = dialog->findChild<QTableWidget*>("sourceDemonstrationCandidates");
    dialog->setStyleSheet(Theme::GlobalStyle);
    app.processEvents();
    selectionLoaded = candidates && candidates->rowCount() == 1 && candidates->columnCount() == 6
        && candidates->item(0, 0)->data(Qt::UserRole).toInt() == 101;
    auto *check = candidates ? qobject_cast<QCheckBox*>(candidates->cellWidget(0, 0)) : nullptr;
    verify(selectionLoaded && check && check->isEnabled(), "source candidate has an explicit enabled checkbox");
    auto *buttons = dialog->findChild<QDialogButtonBox*>();
    auto *generate = buttons ? qobject_cast<QPushButton*>(buttons->buttons().last()) : nullptr;
    for (auto *button : dialog->findChildren<QPushButton*>())
      if (button->text() == QStringLiteral("生成攻击测试预案")) generate = button;
    check->setChecked(false);
    verify(generate && !generate->isEnabled(), "no selected findings keeps generation disabled");
    QTest::mouseClick(candidates->viewport(), Qt::LeftButton, Qt::NoModifier,
                      candidates->visualItemRect(candidates->item(0, 2)).center());
    verify(check->isChecked() && generate->isEnabled(), "clicking the finding row selects it and enables generation");
    QTest::mouseClick(check, Qt::LeftButton, Qt::NoModifier, QPoint(8, check->height()/2));
    verify(!check->isChecked() && !generate->isEnabled(), "checkbox mouse click toggles exactly once");
    check->setFocus();
    QTest::keyClick(check, Qt::Key_Space);
    verify(check->isChecked() && generate->isEnabled(), "keyboard selection enables the plan action");
    dialog->reject();
  });
  sourcePage.selectSourceDemonstration();
  verify(selectionLoaded, "generation opens source object list before sending any plan request");
  bool navigationReadOnly = true;
  for (auto iterator = server.requests.cbegin(); iterator != server.requests.cend(); ++iterator)
    navigationReadOnly = navigationReadOnly && iterator.key().startsWith("GET ");
  verify(navigationReadOnly, "navigation emits no write request before explicit generation");
  const auto selectionHandler = server.handler;
  server.handler = [&](const QString &method, const QString &path) -> MockReply {
    if (path == "/api/scan-tasks/scan-source/generate-playbook")
      return {success(QJsonObject{{"playbook_id", "selected-source"}, {"name", "Selected input comparison"}, {"steps_count", 2}})};
    if (path == "/api/playbooks/selected-source")
      return {success(QJsonObject{{"steps", QJsonArray{QJsonObject{{"step_index", 0}, {"tool_id", "target-request"}},
        QJsonObject{{"step_index", 1}, {"tool_id", "target-request"}}}}})};
    return selectionHandler(method, path);
  };
  QJsonArray selectableFindings;
  for (int index = 0; index < 12; ++index) {
    QJsonObject finding{{"file", "fixture.c"}, {"start_line", index+1}, {"title", QString("Fixture %1").arg(index+1)}};
    if (index == 11) {
      finding["demonstration_supported"] = false;
      finding["demonstration_reason"] = "需要正常对照和触发输入";
    }
    selectableFindings.append(QJsonObject{{"id", 201+index}, {"result_type", "source_finding"}, {"severity", "medium"},
      {"result_data", QString::fromUtf8(QJsonDocument(finding).toJson(QJsonDocument::Compact))}});
  }
  sourcePage.renderGroupedResults(selectableFindings);
  QTimer::singleShot(0, &sourcePage, [&]() {
    auto *dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
    verify(dialog != nullptr, "multi-finding selection dialog opens");
    dialog->setStyleSheet(Theme::GlobalStyle);
    auto *candidates = dialog->findChild<QTableWidget*>("sourceDemonstrationCandidates");
    QPushButton *generate = nullptr;
    for (auto *button : dialog->findChildren<QPushButton*>())
      if (button->text() == QStringLiteral("生成攻击测试预案")) generate = button;
    verify(candidates && candidates->rowCount() == 12 && generate, "large source result set exposes every candidate");
    auto clickRow = [&](int row) {
      candidates->scrollToItem(candidates->item(row, 2));
      app.processEvents();
      QTest::mouseClick(candidates->viewport(), Qt::LeftButton, Qt::NoModifier,
                        candidates->visualItemRect(candidates->item(row, 2)).center());
    };
    for (int row=0; row<10; ++row) clickRow(row);
    verify(generate->isEnabled(), "ten checked findings can generate a plan");
    clickRow(10);
    verify(!generate->isEnabled(), "eleven checked findings clearly disable over-limit generation");
    for (int row=0; row<9; ++row) clickRow(row);
    verify(generate->isEnabled(), "deselecting back to two findings restores generation");
    clickRow(11);
    auto *unsupported = qobject_cast<QCheckBox*>(candidates->cellWidget(11, 0));
    verify(unsupported && !unsupported->isEnabled() && !unsupported->isChecked()
        && unsupported->toolTip().contains("正常对照"), "unsupported runtime finding retains a visible reason and cannot be selected");
    dialog->grab().save(QCoreApplication::applicationDirPath()+"/source-selection-fixed.png");
    generate->click();
  });
  const int selectionRequests = server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook");
  sourcePage.selectSourceDemonstration();
  verify(awaitCondition([&]() { return !sourcePage.m_genPreviewWidget->isHidden()
      && sourcePage.m_genStepTable->rowCount() == 2; }), "selected findings reach generation and display the returned plan steps");
  const auto selectedBody = QJsonDocument::fromJson(server.requestBodies.value("POST /api/scan-tasks/scan-source/generate-playbook")).object();
  verify(server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook") == selectionRequests+1
      && selectedBody["finding_ids"].toArray() == QJsonArray{210,211} && selectedBody["demonstration"].toBool(),
      "generate button submits exactly the checked findings once");
  server.handler = selectionHandler;
  const auto afterSelectionRequests = server.requests;
  const auto existingHandler = server.handler;
  server.handler = [&](const QString &method, const QString &path) -> MockReply {
    if (path == "/api/topology/from-pipeline/source-topology")
      return {success(QJsonObject{{"topology", QJsonObject{{"target", "http://127.0.0.1:8089/"},
        {"summary", "程序入口响应"}, {"nodes", QJsonArray{QJsonObject{{"id", "runtime"}, {"ip", "127.0.0.1"}, {"status", "up"}}}},
        {"edges", QJsonArray()}}}})};
    return existingHandler(method, path);
  };
  {
    TopologyPage programTopology(&api, "user", "fixture-user");
    programTopology.setPipelineContext("source-topology", "http://127.0.0.1:8089/", {"scan-source"}, false);
    QJsonObject event{{"scanTaskId", "foreign-scan"}, {"scanType", "program_scan"}, {"status", "PARTIAL"}};
    programTopology.onScanCompleted(event);
    verify(!programTopology.m_autoTopologyGenerationIds.contains("foreign-scan"), "program topology ignores another task's event");
    event["scanTaskId"] = "scan-source";
    event["target"] = "http://127.0.0.1:8089/";
    programTopology.onScanCompleted(event);
    verify(awaitCondition([&]() { return !programTopology.m_progressDialog
        && programTopology.m_topologyDocument.flowId == "source-topology"
        && programTopology.m_autoTopologyGenerationIds.contains("scan-source")
        && !programTopology.m_topologyDocument.nodes.isEmpty(); }),
           "partial program scan event automatically displays its scoped runtime topology");
    programTopology.m_documentDirty = true;
    programTopology.m_autoTopologyGenerationIds.clear();
    event["scanType"] = "source_scan";
    event["status"] = "COMPLETED";
    programTopology.onScanCompleted(event);
    verify(programTopology.m_documentDirty && !programTopology.m_progressDialog,
           "source scan completion preserves unsaved topology edits");
  }
  server.handler = existingHandler;
  sourcePage.clearTaskScope();
  verify(sourcePage.m_sourceScanTable->rowCount() == 0 && sourcePage.m_sourceScanCount->text().contains("0"), "clearing scope clears C/C++ rows and count");
  verify(sourcePage.m_currentTarget.isEmpty() && !sourcePage.m_sourceDemoBtn->isEnabled() && sourcePage.m_resultTree->topLevelItemCount() == 0,
    "clearing source scope clears target, results and attack objects");

  failedTask = true;
  flow.openTaskAnalysis("A");
  verify(awaitCondition([&]() { return flow.m_targetLabel->text().contains(QStringLiteral("失败")); }), "task detail failure ends header loading state");
  verify(!flow.m_targetLabel->text().contains(QStringLiteral("加载中"))
      && flow.m_statusLabel->text().contains(QStringLiteral("失败")), "task detail failure is visible in header");
  verify(flow.m_overviewTab->m_state->text().contains(QStringLiteral("fixture task load failed"))
      && flow.m_analysisTab->m_stateLabel->text().contains(QStringLiteral("fixture task load failed")), "task detail failure reaches overview and analysis");
  verify(flow.m_scanTab->m_statusLabel->text().contains(QStringLiteral("fixture task load failed")), "task detail failure reaches scan workspace");
  bool readOnly = true;
  for (auto iterator = server.requests.cbegin(); iterator != server.requests.cend(); ++iterator)
    if (!iterator.key().startsWith("GET "))
      readOnly = readOnly && iterator.value() == afterSelectionRequests.value(iterator.key());
  verify(readOnly, "navigation emits no additional write request after explicit generation");
  // Exercise the actual source generation -> task draft navigation, including
  // a plan fetch still in flight when the generated playbook arrives.
  QJsonObject savedPlan;
  int generationDelay = 0;
  int sourceDetailDelay = 0;
  int failedGenerationsRemaining = 2;
  const QJsonArray generatedSteps{QJsonObject{{"step_id", "baseline"}, {"name", "Normal input"}, {"tool_id", "target-request"},
      {"args_template", QJsonArray{"fixture baseline"}}, {"optional", false}},
    QJsonObject{{"step_id", "verification"}, {"name", "Boundary input"}, {"tool_id", "target-request"},
      {"args_template", QJsonArray{"fixture boundary"}}, {"optional", false}}};
  auto sourcePipeline = [&]() {
    auto record = taskRecord("source");
    record["target"] = "http://127.0.0.1:8089/";
    record["status"] = "awaiting_approval";
    record["run_id"] = QJsonValue::Null;
    record["result"] = QJsonObject{{"paused_at", "source_selection"}};
    record["config"] = QJsonObject{{"scan_mode", "source_assisted"}, {"authorization_confirmed", true}};
    record["summary"] = QJsonObject{{"scan_task_ids", QJsonArray{"scan-source"}},
      {"plan", savedPlan.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(QJsonObject{{"state", "draft"}, {"revision", 0}})}};
    return record;
  };
  server.handler = [&](const QString &method, const QString &requestPath) -> MockReply {
    const QString path = QUrl(requestPath).path();
    if (path == "/api/pipelines/source") return {success(sourcePipeline())};
    if (path == "/api/pipelines") return {success(QJsonArray{sourcePipeline()})};
    if (path == "/api/scan-tasks") return {success(QJsonArray{sourceRecord()})};
    if (path == "/api/scan-tasks/scan-source") return {success(sourceRecord()), sourceDetailDelay};
    if (path.endsWith("/generate-playbook")) {
      if (failedGenerationsRemaining > 0) {
        --failedGenerationsRemaining;
        return {QJsonObject{{"status", "error"}, {"error", QJsonObject{{"message", "预案草稿未覆盖实际发现：缺少编号 101"}}}}, 100};
      }
      return {success(QJsonObject{{"playbook_id", "generated-source"}, {"name", "Input comparison"}, {"steps_count", 2}}), generationDelay};
    }
    if (path == "/api/playbooks/generated-source") return {success(QJsonObject{{"steps", generatedSteps}})};
    if (path == "/api/pipelines/source/plan/sources") return {success(QJsonArray{QJsonObject{{"playbook_id", "generated-source"}, {"name", "Input comparison"}, {"steps_count", 2}}})};
    if (path == "/api/pipelines/source/plan") {
      if (method == "POST") {
        savedPlan = {{"pipeline_id", "source"}, {"state", "draft"}, {"revision", 0}, {"content", QJsonObject{
          {"name", "Input comparison"}, {"source_playbook_id", "generated-source"},
          {"source_playbook", QJsonObject{{"name", "Input comparison"}}}, {"steps", generatedSteps}, {"suggestions", QJsonArray()}}}};
        return {success(savedPlan)};
      }
      return {success(savedPlan.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(savedPlan)), 250};
    }
    return {success(QJsonArray())};
  };
  flow.openTaskAnalysis("source");
  verify(awaitCondition([&]() { return flow.m_scanTab->m_selectedTaskId == "scan-source" && flow.m_scanTab->m_sourceDemoBtn->isEnabled(); }), "source pipeline loads generation context");
  const int beforeFailure = server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook");
  const int beforeFailedDraft = server.requests.value("POST /api/pipelines/source/plan");
  flow.m_scanTab->m_lastGeneratedId = "stale-source";
  flow.m_scanTab->m_genExecBtn->setEnabled(true);
  flow.m_analysisTab->m_planButton->click();
  verify(awaitCondition([&]() { return server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook") > beforeFailure; }), "first generation sends a real request before failing");
  flow.m_analysisTab->m_planButton->click();
  flow.m_scanTab->generatePlaybook(QJsonArray{101});
  verify(awaitCondition([&]() { return flow.m_scanTab->m_statusLabel->text().contains("预案生成失败"); }), "generation failure is shown in scan workspace");
  verify(server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook") == beforeFailure+1,
      "repeat clicks while generation is pending do not duplicate requests");
  verify(flow.m_scanTab->m_genBtn->isEnabled() && flow.m_scanTab->m_sourceDemoBtn->isEnabled()
      && !flow.m_scanTab->m_generationInProgress, "failed generation restores both retry controls");
  verify(flow.m_scanTab->m_lastGeneratedId.isEmpty() && !flow.m_scanTab->m_genExecBtn->isEnabled()
      && savedPlan.isEmpty() && server.requests.value("POST /api/pipelines/source/plan") == beforeFailedDraft,
      "failed generation cannot navigate to a stale playbook or create a task draft");
  verify(awaitCondition([&]() { return !flow.m_planTab->m_busy; }), "plan button is ready for retry after failure");
  // Re-selecting C/C++ used to clear the current task without restoring it.
  flow.m_scanTab->m_scanTypeTabs->setCurrentIndex(0);
  sourceDetailDelay = 100;
  flow.m_scanTab->m_scanTypeTabs->setCurrentIndex(4);
  verify(flow.m_scanTab->m_selectedTaskId == "scan-source" && flow.m_scanTab->m_currentScanType.isEmpty(),
      "returning to C/C++ selects its task while details load");
  flow.m_stageTabs->setCurrentWidget(flow.m_planTab);
  flow.m_planTab->m_generateSource->click();
  verify(flow.m_scanTab->m_pendingSourceVerification, "retry click waits for source details instead of only navigating");
  verify(awaitCondition([&]() { return server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook") == beforeFailure+2
      && !flow.m_scanTab->m_generationInProgress && flow.m_scanTab->m_statusLabel->text().contains("预案生成失败"); }),
      "task plan retry sends exactly one new request once source details are ready");
  verify(flow.m_scanTab->m_sourceDemoBtn->isEnabled() && !flow.m_scanTab->m_pendingSourceVerification && savedPlan.isEmpty(),
      "a second failure remains retryable without creating a draft");
  sourceDetailDelay = 0;
  flow.m_planTab->refresh();
  verify(flow.m_planTab->m_busy, "draft fetch overlaps source generation");
  verify(flow.m_analysisTab->m_planButton->isEnabled(), "analysis offers source generation without selecting an analysis note");
  flow.m_analysisTab->m_planButton->click();
  verify(awaitCondition([&]() { return flow.m_planTab->m_steps->rowCount() == 2; }), "generated source steps automatically become a visible task draft");
  verify(flow.m_stageTabs->currentWidget() == flow.m_planTab, "source generation opens task plan stage");
  verify(flow.m_scanTab->m_detailTabs->currentIndex() == 1 && flow.m_scanTab->m_genStepTable->rowCount() == 2,
      "generated source preview opens the details tab with steps");
  verify(flow.m_planTab->m_source->currentText() == "Input comparison", "draft source shows a readable playbook name");
  verify(server.requests.value("POST /api/pipelines/source/plan") == 1, "overlapping fetch creates the source draft exactly once");
  verify(awaitCondition([&]() { return !flow.m_statusLabel->text().contains("待选择"); }), "draft creation clears stale source-selection header");
  flow.m_planTab->useSourcePlaybook("generated-source");
  QTest::qWait(50);
  verify(server.requests.value("POST /api/pipelines/source/plan") == 1, "reopening the same generated source preserves the existing draft");
  flow.onBackToList();
  savedPlan = {};
  flow.openTaskAnalysis("source");
  verify(awaitCondition([&]() { return flow.m_planTab->m_source->count() == 1; }), "saved source playbook can be recovered after reopening without a draft");
  flow.m_planTab->m_create->click();
  verify(awaitCondition([&]() { return flow.m_planTab->m_steps->rowCount() == 2; }), "recovered source playbook creates a draft with executable steps");
  flow.onBackToList();
  savedPlan = {};
  generationDelay = 250;
  flow.openTaskAnalysis("source");
  verify(awaitCondition([&]() { return flow.m_scanTab->m_sourceDemoBtn->isEnabled(); }), "source context reloads before delayed generation");
  const int previousGenerations = server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook");
  const int previousDrafts = server.requests.value("POST /api/pipelines/source/plan");
  flow.m_analysisTab->m_planButton->click();
  verify(awaitCondition([&]() { return server.requests.value("POST /api/scan-tasks/scan-source/generate-playbook") > previousGenerations; }), "delayed generation is in flight");
  flow.onBackToList();
  QTest::qWait(350);
  verify(server.requests.value("POST /api/pipelines/source/plan") == previousDrafts
      && flow.m_planTab->m_steps->rowCount() == 0 && flow.m_selectedPipelineId.isEmpty(),
      "late generation cannot create a draft or restore content after leaving the task");
  std::cout << "TOTAL " << checks << " checks passed" << std::endl;
  return 0;
}
