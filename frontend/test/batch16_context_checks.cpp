#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include <functional>
#include <iostream>

#include "ApiClient.h"
#include "UiUtil.h"
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

  MockServer()
  {
    connect(this, &QTcpServer::newConnection, this, [this]() {
      while (hasPendingConnections()) {
        auto *socket = nextPendingConnection();
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
          const QByteArray buffer = socket->property("buffer").toByteArray() + socket->readAll();
          socket->setProperty("buffer", buffer);
          if (!buffer.contains("\r\n\r\n") || socket->property("handled").toBool()) return;
          socket->setProperty("handled", true);
          const auto request = buffer.left(buffer.indexOf('\r')).split(' ');
          const QString method = QString::fromUtf8(request.value(0));
          const QString path = QString::fromUtf8(request.value(1));
          ++requests[method + " " + path];
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
  bool failedTask = false;
  server.handler = [&](const QString &, const QString &requestPath) -> MockReply {
    const QString path = QUrl(requestPath).path();
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
    readOnly = readOnly && iterator.key().startsWith("GET ");
  verify(readOnly, "navigation emits no write request");
  std::cout << "TOTAL " << checks << " checks passed" << std::endl;
  return 0;
}
