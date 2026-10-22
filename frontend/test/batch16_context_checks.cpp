#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include <QtTest/QSignalSpy>
#include <functional>
#include <iostream>

#include "ApiClient.h"
#include "UiUtil.h"
#include "WsClient.h"
#include "AppStyle.h"
#include "StyleDark.h"
#include "widgets/ScanResultOverview.h"
#include "widgets/RemoteSourcePicker.h"
#define private public
#include "MainWindow.h"
#include "pages/FlowPage.h"
#include "pages/ScanPage.h"
#include "pages/FindingVerificationDialog.h"
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
  QMap<QString, QList<QByteArray>> requestHistory;

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
          requestHistory[method + " " + path].append(buffer.mid(headersEnd + 4, bodyLength));
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

static QJsonObject findingExecutionRecord(const QString &taskId, bool mainRun = false)
{
  auto record=executionRecord(taskId);
  if(!mainRun)record["run"]=QJsonValue::Null;
  record["pipeline_status"]="awaiting_approval";
  const QJsonObject result{{"schema_version",1},{"status","achieved"},{"reason","同次完整证据满足平台判据"},
    {"objective",QJsonObject{{"label","确认指定目录索引暴露"}}},{"object",QJsonObject{{"target",taskId+".invalid/docs/"}}}};
  const QJsonObject row{{"attempt_id","fva-"+taskId},{"verification_id","fv-"+taskId},{"finding_id",1231},
    {"run_id","child-"+taskId},{"revision",2},{"state","completed"},{"stop_confirmed",true},
    {"created_at","2026-10-20T10:00:00Z"},{"completed_at","2026-10-20T10:00:01Z"},
    {"finding_name","Directory indexing "+taskId},{"plan_name","目录检查"},{"objective",result["objective"]},
    {"result",result},{"tool_calls",1},{"evidence_count",1}};
  record["verification_runs"]=QJsonObject{{"schema_version",1},{"total",1},{"returned",1},{"has_more",false},
    {"active",0},{"completed",1},{"failed",0},{"aborted",0},{"unknown",0},{"invalid_source_count",0},{"items",QJsonArray{row}}};
  return record;
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

  {
    MockServer aggregateServer;
    bool delay = false;
    bool failResults = false;
    bool noCandidates = false;
    aggregateServer.handler = [&](const QString &, const QString &requestPath) -> MockReply {
      const QUrl url(requestPath); const QUrlQuery query(url);
      if (!url.path().contains("/results")) return {success(QJsonArray())};
      if (failResults) return {{{"status", "error"}}};
      const QString task = url.path().split('/').value(3);
      const int after = query.queryItemValue("after").toInt();
      const bool errors = query.queryItemValue("category") == "error";
      const int total = noCandidates && query.queryItemValue("category") == "vulnerability" ? 0 : errors ? 1 : 235;
      QJsonArray rows;
      for (int i = after; i < qMin(after + 100, total); ++i) rows.append(QJsonObject{
        {"id", i + 1}, {"scan_task_id", "scan-" + task}, {"result_type", errors ? "scan_error" : "vulnerability"},
        {"severity", errors ? "info" : "high"}, {"source_tool", "fixture"}, {"result_data", errors ? QStringLiteral("{\"error\":\"fixture timeout\"}") : "{\"finding\":\"" + task + " fixture\"}"}});
      const QJsonObject page{{"total", total}, {"next_after", after + rows.size()}, {"through", total}, {"has_more", after + rows.size() < total}};
      const QJsonObject data{{"scan_records", rows}, {"page", page},
        {"scan_summary", QJsonObject{{"record_count",235}, {"completeness","incomplete"}, {"unexecuted_checks",QJsonArray{"web_scan"}}}},
        {"scan_sources", QJsonArray{QJsonObject{{"scan_task_id","scan-"+task},{"scan_type","vuln_scan"},{"target","fixture.invalid"},{"status","PARTIAL"},{"error_message","fixture timeout"}}}}};
      return {success(data), delay && task == "A" ? 250 : 0};
    };
    ApiClient aggregateApi(QStringLiteral("http://127.0.0.1:%1").arg(aggregateServer.serverPort()));
    ScanPage aggregate(&aggregateApi, "user", "fixture-user"); aggregate.resize(1360,860); aggregate.show();
    aggregate.setPipelineScope("A", {});
    verify(awaitCondition([&]() { return aggregate.m_aggregateRecords.size() == 100; }), "aggregate first page returns 100 stable records");
    verify(aggregate.m_resultCategory->currentData() == "vulnerability"
      && aggregate.m_resultSource->itemText(0) == "全部扫描任务", "default filter is vulnerability with one task selector");
    verify(aggregate.m_resultTree->rootIndex().isValid(), "candidate-only view hides redundant group header");
    verify(aggregate.m_resultTree->isColumnHidden(2) && aggregate.m_resultTree->isColumnHidden(3)
      && aggregate.m_resultTree->isColumnHidden(7), "source payload and separate conclusion retained in model but hidden from main table");
    aggregate.resize(1024, 600); app.processEvents();
    verify(aggregate.m_resultTree->width() > 900 && !aggregate.m_statusLabel->isVisible(), "full-width first screen has no task sidebar or blue status block");
    auto *taskManager = aggregate.findChild<QDialog*>("scanAuxTasks");
    const auto beforePanels = aggregateServer.requests;
    aggregate.findChild<QPushButton*>("manageScanTasks")->click();
    verify(taskManager->isVisible(), "task management remains reachable");
    taskManager->close();
    aggregate.findChild<QPushButton*>("scanCheckDetails")->click();
    auto *overviewDialog = aggregate.findChild<QDialog*>("scanAuxOverview");
    verify(overviewDialog->isVisible() && aggregate.m_statusLabel->isVisible(), "detailed scan progress remains available on demand");
    overviewDialog->close();
    verify(aggregateServer.requests == beforePanels, "opening auxiliary panels never starts scans or requests");
    aggregate.resize(1360, 860); app.processEvents();
    aggregate.m_resultSource->setCurrentIndex(1);
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}), "selecting a child scan finishes filtered load");
    bool sourceRequested = false;
    for (auto it = aggregateServer.requests.cbegin(); it != aggregateServer.requests.cend(); ++it)
      if (it.key().contains("scan_task_id=scan-A")) sourceRequested = true;
    verify(sourceRequested && aggregate.m_resultSource->currentData() == "scan-A"
      && aggregate.m_resultSource->currentText().contains("fixture.invalid"), "merged selector uses stable ID and shows target/status");
    aggregate.m_allResultsButton->click();
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;} ) && aggregate.m_resultSource->currentData() == "scan-A",
      "refresh preserves selected task");
    aggregate.m_resultSource->setCurrentIndex(0);
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}), "all scan tasks remain reachable");
    failResults = true;
    aggregate.m_moreResultsButton->click();
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}) && aggregate.m_aggregateRecords.size() == 100
      && aggregate.m_moreResultsButton->isEnabled() && aggregate.m_resultHint->text().contains("失败"),
      "append failure retains loaded records and offers page retry");
    failResults = false;
    aggregate.m_selectAllFindings->click();
    verify(aggregate.m_checkedFindings.size() == 100, "select all covers only the first loaded page");
    aggregate.m_moreResultsButton->click();
    verify(!aggregate.m_selectAllFindings->isEnabled(), "select all disabled during page load");
    verify(awaitCondition([&]() { return aggregate.m_aggregateRecords.size() == 200; }), "aggregate second page passes former 150 limit");
    verify(aggregate.m_selectAllFindings->checkState() == Qt::PartiallyChecked
      && aggregate.m_checkedFindings.size() == 100, "new page remains unchecked and changes all to partial");
    aggregate.m_selectAllFindings->click();
    verify(aggregate.m_checkedFindings.size() == 200, "partial activation selects all loaded findings");
    aggregate.m_selectAllFindings->click();
    verify(aggregate.m_checkedFindings.isEmpty(), "all activation clears current findings");
    aggregate.m_moreResultsButton->click();
    verify(awaitCondition([&]() { return aggregate.m_aggregateRecords.size() == 235; }), "all 235 records are reachable without payloads");
    verify(!aggregate.m_moreResultsButton->isEnabled() && aggregate.m_resultHint->text().contains("235 / 235"), "list count and paging completion agree");
    verify(aggregate.m_statusLabel->text().contains("未执行") && aggregate.m_statusLabel->text().contains("部分完成"), "incomplete checks remain visible beside findings");
    QJsonArray informationRows{QJsonObject{{"id",9999},{"result_type","web_vuln"},{"category","information"},{"severity","low"},{"source_tool","nikto"},{"result_data","{\"finding\":\"Allowed HTTP Methods: GET, POST\"}"}}};
    aggregate.renderGroupedResults(informationRows);
    auto *informationItem=aggregate.m_resultTree->topLevelItem(0)->child(0);
    verify(informationItem->data(0,Qt::CheckStateRole).isNull(),"legacy informational Nikto finding has no verification checkbox");
    verify(aggregate.m_resultOverview->findChild<QFrame*>("findingMetric")->findChild<QLabel*>("metricValue")->text()=="0","legacy informational Nikto finding is excluded from vulnerability count");
    QJsonArray tableRows;
    const QStringList states{"", "running", "cancelling", "unknown", "completed", "failed", "ready"};
    for (int row = 0; row < states.size(); ++row) {
      QJsonObject finding{{"id", 500 + row}, {"category", "vulnerability"}, {"result_type", "web_vuln"},
        {"severity", "high"}, {"source_tool", "fixture"},
        {"result_data", "{\"title\":\"隔离夹具：目录索引已开启，未经认证可能浏览目录内容\",\"url\":\"https://fixture.invalid/docs/\",\"cwe\":\"CWE-548\"}"},
        {"verification", QJsonValue::Null}, {"payload_match", QJsonObject{{"status", "candidate"}}}};
      if (row) finding["verification"] = QJsonObject{{"state", states[row]}, {"conclusion", "confirmed"},
        {"result", QJsonObject{{"schema_version", 1}, {"status", row == 4 ? "achieved" : "inconclusive"},
          {"objective", QJsonObject{{"label", "目录索引暴露"}}}, {"reason", "fixture evidence"}}}};
      tableRows.append(finding);
    }
    tableRows.append(informationRows.first());
    tableRows.append(QJsonObject{{"id", 600}, {"result_type", "open_port"}, {"severity", "info"}, {"result_data", "{\"port\":443}"}});
    tableRows.append(QJsonObject{{"id", 601}, {"result_type", "scan_error"}, {"severity", "info"}, {"result_data", "{\"error\":\"fixture timeout\"}"}});
    aggregate.renderGroupedResults(tableRows);
    auto *candidates = aggregate.m_resultTree->topLevelItem(0);
    verify(candidates->childCount() == 7 && aggregate.m_resultTree->topLevelItemCount() == 4,
      "candidate table separates informational findings, ports and scan errors");
    verify(candidates->child(0)->text(6) == "未测试" && candidates->child(0)->text(7) == "待判定",
      "unverified candidate is never marked successful");
    verify(candidates->child(3)->text(6) == "停止未知" && candidates->child(4)->text(6) == "已完成"
      && candidates->child(4)->text(7) == "目标已达成", "execution state remains independent from evidence-based objective result");
    verify(candidates->child(0)->text(1).contains("CWE-548") && candidates->child(0)->text(5).contains("/docs/")
      && candidates->child(0)->text(0) == "500" && candidates->child(0)->text(4) == "高危", "rule, location and stable finding identity remain visible");
    verify(aggregate.m_resultTree->columnCount() == 8
      && aggregate.m_resultTree->findChildren<QPushButton*>("findingRowAction").isEmpty(),
      "finding table has no operation column or per-row action buttons");
    const QString tableCapture = qEnvironmentVariable("F04_SCREENSHOT_DIR");
    if (!tableCapture.isEmpty()) {
      aggregate.m_resultHint->setText("隔离布局夹具：7 条漏洞候选、1 条信息、1 条端口、1 条工具错误；无真实扫描");
      aggregate.setStatusText("本任务扫描：部分完成 · 隔离夹具\n网站检查未执行（fixture timeout）");
      QJsonArray candidateRows;
      for (int i = 0; i < 7; ++i) candidateRows.append(tableRows.at(i));
      aggregate.renderGroupedResults(candidateRows);
      app.processEvents(); aggregate.grab().save(tableCapture + "/finding-table-1360.png");
      aggregate.resize(1024, 600); app.processEvents(); aggregate.grab().save(tableCapture + "/finding-table-1024.png");
      aggregate.resize(1360, 860);
      auto *selected = aggregate.m_resultTree->topLevelItem(0)->child(0);
      selected->setCheckState(0, Qt::Checked);
      app.processEvents(); aggregate.grab().save(tableCapture + "/finding-selected.png");
      selected->setCheckState(0, Qt::Unchecked);
      aggregate.renderGroupedResults(tableRows);
    }
    const QString selectionCapture = qEnvironmentVariable("FINDING_SELECTION_SCREENSHOT_DIR");
    const QPalette originalPalette = app.palette();
    const QString originalStyle = app.styleSheet();
    for (bool dark : {false, true}) {
      QPalette themePalette = originalPalette;
      themePalette.setColor(QPalette::Window, QColor(dark ? "#1a202c" : "#ffffff"));
      themePalette.setColor(QPalette::WindowText, QColor(dark ? "#e2e8f0" : "#172033"));
      app.setPalette(themePalette);
      app.setStyleSheet(dark ? QString::fromUtf8(GLOBAL_STYLE_DARK) + Theme::DarkButtonStyle + Theme::ItemViewStyle
                            : Theme::GlobalStyle + Theme::ButtonStyle + Theme::ItemViewStyle);
      app.processEvents();
      verify(aggregate.m_findingSelectionCount->palette().color(QPalette::WindowText).lightness() < 128
          && aggregate.findChild<QFrame*>("scanDetailsPanel")->palette().color(QPalette::Window).lightness() > 200,
        "selection count remains dark on white panel with light and dark system palettes");
      auto *tree = aggregate.m_resultTree;
      auto *first = tree->topLevelItem(0)->child(0);
      tree->setCurrentItem(first, 0);
      tree->scrollToItem(first);
      tree->setFocus();
      app.processEvents();
      QStyleOptionViewItem option;
      option.initFrom(tree);
      option.rect = tree->visualItemRect(first);
      option.rect.setWidth(tree->columnWidth(0));
      option.features = QStyleOptionViewItem::HasCheckIndicator | QStyleOptionViewItem::HasDisplay;
      option.checkState = Qt::Unchecked;
      option.text = first->text(0);
      option.font = tree->font();
      const QRect indicator = tree->style()->subElementRect(QStyle::SE_ItemViewItemCheckIndicator, &option, tree);
      verify(indicator.isValid() && option.rect.contains(indicator), "checkbox hit area fits first column");
      const auto before = aggregateServer.requests;
      QTest::mouseClick(tree->viewport(), Qt::LeftButton, Qt::NoModifier, indicator.center());
      verify(first->checkState(0) == Qt::Checked && aggregate.m_selectAllFindings->checkState() == Qt::PartiallyChecked,
        "real mouse click checks finding and updates partial state under app theme");
      QTest::keyClick(tree, Qt::Key_Space);
      verify(first->checkState(0) == Qt::Unchecked && !aggregate.m_openCheckedFindings->isEnabled(),
        "space unchecks finding and disables opening empty selection");
      tree->topLevelItem(0)->setExpanded(false);
      QTest::mouseClick(aggregate.m_selectAllFindings, Qt::LeftButton, Qt::NoModifier, QPoint(8, aggregate.m_selectAllFindings->height()/2));
      verify(aggregate.m_checkedFindings.size() == 7 && aggregate.m_findingSelectionCount->text() == "已选 7 / 可选 7 条",
        "all includes collapsed findings and excludes information ports and errors");
      tree->topLevelItem(0)->setExpanded(true);
      QTest::keyClick(tree, Qt::Key_Space);
      verify(aggregate.m_selectAllFindings->checkState() == Qt::PartiallyChecked, "keyboard deselection updates partial state");
      app.processEvents();
      if (!selectionCapture.isEmpty()) {
        aggregate.grab().save(selectionCapture + (dark ? "/dark-partial.png" : "/light-partial.png"));
      }
      QTest::keyClick(aggregate.m_selectAllFindings, Qt::Key_Space);
      verify(aggregate.m_selectAllFindings->checkState() == Qt::Checked, "space on partial selects all");
      QTest::keyClick(aggregate.m_selectAllFindings, Qt::Key_Space);
      verify(aggregate.m_checkedFindings.isEmpty(), "space on all clears selection");
      verify(aggregateServer.requests == before, "selection changes never make API requests");
    }
    app.setStyleSheet(originalStyle);
    app.setPalette(originalPalette);
    aggregate.renderGroupedResults({});
    verify(!aggregate.m_selectAllFindings->isEnabled() && !aggregate.m_openCheckedFindings->isEnabled(),
      "empty results disable selection actions");
    aggregate.renderGroupedResults(tableRows);
    auto legacy = tableRows.first().toObject();
    legacy["verification"] = QJsonObject{{"state", "completed"}, {"conclusion", "confirmed"}};
    aggregate.renderGroupedResults(QJsonArray{legacy});
    verify(aggregate.m_resultTree->topLevelItem(0)->child(0)->text(7).contains("旧记录"),
      "legacy confirmed or manual opinion cannot masquerade as a supported system result");
    verify(ScanPage::buildResultSummary(QJsonArray{
      QJsonObject{{"result_type", "web_vuln"}, {"severity", "high"}},
      QJsonObject{{"result_type", "sql_injection"}, {"severity", "high"}},
      QJsonObject{{"result_type", "web_vuln"}, {"category", "information"}}}, "web_scan")
        == QStringLiteral("网站漏洞：1, SQL注入: 1"), "table grouping preserves web scan summary counts");
    aggregate.renderGroupedResults(aggregate.m_aggregateRecords);
    auto *firstFinding=aggregate.m_resultTree->topLevelItem(0)->child(0);
    auto *secondFinding=aggregate.m_resultTree->topLevelItem(0)->child(1);
    verify(firstFinding->flags().testFlag(Qt::ItemIsUserCheckable),"vulnerability rows expose checkboxes");
    firstFinding->setCheckState(0,Qt::Checked);secondFinding->setCheckState(0,Qt::Checked);
    aggregate.renderGroupedResults(aggregate.m_aggregateRecords);
    firstFinding=aggregate.m_resultTree->topLevelItem(0)->child(0);
    verify(firstFinding->checkState(0)==Qt::Checked,"checked findings survive result rerender");
    const auto beforeDetails = aggregateServer.requests;
    aggregate.m_resultTree->itemClicked(firstFinding,1);
    auto *recordDetails = aggregate.findChild<QDialog*>("scanAuxRecord");
    verify(recordDetails && recordDetails->isVisible()
      && aggregate.findChildren<FindingVerificationDialog*>().isEmpty()
      && aggregateServer.requests == beforeDetails, "single click opens read-only evidence without preparing verification");
    recordDetails->close(); QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    aggregate.m_resultTree->setCurrentItem(firstFinding, 1);
    QTest::keyClick(aggregate.m_resultTree, Qt::Key_Return);
    recordDetails = aggregate.findChild<QDialog*>("scanAuxRecord");
    verify(recordDetails && recordDetails->isVisible() && aggregateServer.requests == beforeDetails,
      "enter opens evidence without starting or preparing verification");
    recordDetails->findChild<QPushButton*>("prepareFindingVerification")->click();
    auto dialogs=aggregate.findChildren<FindingVerificationDialog*>();
    verify(dialogs.size()==1,"explicit prepare opens finding verification");
    verify(awaitCondition([&]{return aggregateServer.requests.value("POST /api/pipelines/A/verifications")==1;}),"explicit prepare submits exactly the selected finding");
    QSignalSpy closedRefresh(&aggregate,&ScanPage::findingVerificationChanged);
    dialogs.first()->reject();
    verify(awaitCondition([&]{return closedRefresh.count()==1 && aggregate.m_aggregateRecords.size()==100 && !aggregate.m_scanPageBusy;}),
      "closing finding history refreshes its unchanged task context");
    verify(aggregate.m_resultTree->topLevelItem(0)->child(0)->checkState(0)==Qt::Checked
      && aggregate.m_resultTree->topLevelItem(0)->child(1)->checkState(0)==Qt::Checked,
      "selected findings survive asynchronous history-close refresh");
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    aggregate.findChild<QPushButton*>("openCheckedFindings")->click();
    dialogs=aggregate.findChildren<FindingVerificationDialog*>();
    verify(dialogs.size()==1,"checked findings open a single verification window");
    verify(awaitCondition([&]{return aggregateServer.requests.value("POST /api/pipelines/A/verifications")==3;}),"checkbox batch sends exactly two selected findings");
    QSet<qint64> openedIds;
    const auto openedBodies = aggregateServer.requestHistory.value("POST /api/pipelines/A/verifications");
    for (const auto &body : openedBodies.mid(1))
      openedIds.insert(QJsonDocument::fromJson(body).object()["finding_id"].toVariant().toLongLong());
    verify(openedIds == QSet<qint64>{1,2}, "batch opening sends exactly current checked finding IDs in task A");
    bool started=false;for(auto it=aggregateServer.requests.cbegin();it!=aggregateServer.requests.cend();++it)if(it.key().endsWith("/execute"))started=true;
    verify(!started,"opening single or checked findings never executes tools");
    delete dialogs.first();
    aggregate.setPipelineScope("A", {"scan-A"});
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy && aggregate.m_aggregateRecords.size()==100;}),
      "same task child-scan scope refresh completes");
    verify(aggregate.m_findingSelectionCount->text() == "已选 2 / 可选 100 条",
      "same pipeline scope refresh retains selected IDs");
    aggregate.m_resultCategory->setCurrentIndex(aggregate.m_resultCategory->findData("error"));
    verify(awaitCondition([&]() { return aggregate.m_aggregateRecords.size() == 1; }), "tool errors have their own queryable category");
    verify(aggregate.m_resultTree->topLevelItem(0)->child(0)->text(1).contains("fixture timeout"), "tool error reason is visible in the result list");
    verify(!aggregate.m_selectAllFindings->isEnabled() && !aggregate.m_openCheckedFindings->isEnabled(),
      "error-only filter has no selectable findings");
    aggregate.m_resultCategory->setCurrentIndex(0);
    verify(awaitCondition([&]{return aggregate.m_aggregateRecords.size()==100;}), "returning to findings reloads results");
    verify(aggregate.m_findingSelectionCount->text() == "已选 2 / 可选 100 条", "filter return restores checked IDs");
    failResults = true;
    aggregate.loadPipelineResults();
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}), "failed refresh completes loading state");
    verify(!aggregate.m_selectAllFindings->isEnabled() && !aggregate.m_openCheckedFindings->isEnabled(),
      "failed replacement load cannot open stale findings");
    if (!tableCapture.isEmpty()) aggregate.grab().save(tableCapture + "/scan-load-failed.png");
    failResults = false;
    aggregate.m_resultCategory->setCurrentIndex(aggregate.m_resultCategory->findData("error"));
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}), "restore error filter after failure");
    delay = true; aggregate.loadPipelineResults();
    aggregate.setPipelineScope("B", {});
    verify(awaitCondition([&]() { return aggregate.m_aggregateRecords.size() == 100 && aggregate.m_resultCategory->currentData() == "vulnerability" && aggregate.m_aggregateRecords.first().toObject()["scan_task_id"].toString() == "scan-B"; }), "task switch resets to candidates and loads only B records");
    QTest::qWait(300);
    verify(aggregate.m_checkedFindings.isEmpty(), "task switch clears checked finding IDs");
    verify(aggregate.m_aggregateRecords.first().toObject()["scan_task_id"].toString() == "scan-B", "late A page cannot overwrite B records");
    const QString capture = qEnvironmentVariable("F04_SCREENSHOT_DIR");
    aggregate.m_resultCategory->setCurrentIndex(aggregate.m_resultCategory->findData("error"));
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy && aggregate.m_aggregateRecords.size() == 1;}), "task B error category remains reachable");
    if (!capture.isEmpty()) aggregate.grab().save(capture + "/scan-results-errors.png");
    aggregate.m_resultCategory->setCurrentIndex(0);
    verify(awaitCondition([&]() { return aggregate.m_aggregateRecords.size() == 100; }), "clearing filter restarts a bounded page");
    if (!capture.isEmpty()) aggregate.grab().save(capture + "/scan-results-unified.png");
    aggregate.openFindingVerification({1});
    verify(awaitCondition([&]{return !aggregate.findChildren<FindingVerificationDialog*>().isEmpty();}),"old task finding window exists before switching scope");
    auto *oldDialog=aggregate.findChildren<FindingVerificationDialog*>().first();
    aggregate.setPipelineScope("C",{});
    oldDialog->reject();
    verify(closedRefresh.count()==1,"closing old scanning context does not emit a new-task refresh");
    noCandidates = true;
    aggregate.setPipelineScope("empty", {});
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}) && aggregate.m_aggregateRecords.isEmpty()
      && aggregate.m_listTitle->text().contains("0") && aggregate.m_showAllRecords->isVisible(),
      "zero candidates show honest empty state and all-records navigation");
    if (!capture.isEmpty()) aggregate.grab().save(capture + "/scan-empty-candidates.png");
    aggregate.m_showAllRecords->click();
    verify(awaitCondition([&]{return !aggregate.m_scanPageBusy;}) && aggregate.m_aggregateRecords.size() == 100,
      "all records remain reachable when candidate category is empty");
    aggregate.m_resultTree->itemClicked(aggregate.m_resultTree->topLevelItem(0)->child(0), 1);
    taskManager->show(); overviewDialog->show();
    aggregate.clearTaskScope();
    verify(aggregate.m_checkedFindings.isEmpty() && !aggregate.m_selectAllFindings->isEnabled(), "leaving task clears selection controls");
    verify(aggregate.m_resultTree->topLevelItemCount() == 0 && aggregate.m_pipelineId.isEmpty(), "leaving aggregate clears all visible records and identity");
    for (auto *dialog : aggregate.findChildren<QDialog*>())
      if (dialog->objectName().startsWith("scanAux")) verify(!dialog->isVisible(), "leaving task closes auxiliary evidence and management windows");
  }

  {
    MockServer historyServer;
    bool delayedA=false;
    historyServer.handler=[&](const QString &,const QString &requestPath)->MockReply {
      const QString path=QUrl(requestPath).path(),task=path.split('/').value(3);
      if(path.endsWith("/execution"))return {success(findingExecutionRecord(task,task=="both")),delayedA&&task=="A"?250:0};
      if(path.endsWith("/verifications/fv-"+task)) {
        const auto execution=findingExecutionRecord(task),row=execution["verification_runs"].toObject()["items"].toArray()[0].toObject();
        const QJsonObject attempt{{"id",row["attempt_id"]},{"state","completed"},{"revision",2},{"stop_confirmed",1},
          {"created_at",row["created_at"]},{"summary",QJsonObject{{"result",row["result"]}}},{"evidence",QJsonArray()},{"reviews",QJsonArray()}};
        return {success(QJsonObject{{"id","fv-"+task},{"finding_id",1231},{"state","completed"},{"revision",2},
          {"finding",QJsonObject{{"result_data","{\"finding\":\"Directory indexing\"}"}}},
          {"summary",QJsonObject{{"result",row["result"]}}},{"plans",QJsonArray()},{"attempts",QJsonArray{attempt}}})};
      }
      return {success(QJsonArray())};
    };
    ApiClient historyApi(QStringLiteral("http://127.0.0.1:%1").arg(historyServer.serverPort()));
    TaskExecutionPanel monitor(&historyApi,"user","fixture-user");monitor.resize(1360,860);monitor.show();
    QSignalSpy selected(&monitor,&TaskExecutionPanel::runSelected),completed(&monitor,&TaskExecutionPanel::runCompleted);
    QSignalSpy refreshed(&monitor,&TaskExecutionPanel::findingVerificationChanged);
    monitor.setTaskContext("A",{},"A.invalid");
    verify(awaitCondition([&]{return monitor.m_verifications->rowCount()==1;}),"child execution is visible without a parent run");
    verify(!monitor.m_state->text().contains("主预案尚未执行")&&monitor.m_state->text().contains("已有 1 次逐漏洞测试记录")
        &&monitor.m_verifications->item(0,4)->text()=="目标已达成","parent absence never hides completed finding execution or system result");
    verify(selected.count()==0&&completed.count()==0,"finding child runs never emit parent run selection or completion");
    verify(!monitor.m_parentDetails->isChecked() && monitor.m_parentState->text().contains("主预案尚未执行")
      && monitor.m_tabs->currentWidget()==monitor.m_verifications,"optional parent status stays in collapsed detail while child records are primary");
    const auto originalSnapshot=monitor.m_snapshot;
    for(const QString state : {"queued","running","cancelling","completed","failed","aborted","unknown"}) {
      auto children=originalSnapshot["verification_runs"].toObject();
      const bool active=QStringList{"queued","running","cancelling"}.contains(state);
      children["active"]=active?1:0;children["completed"]=state=="completed"?1:0;
      children["failed"]=state=="failed"?1:0;children["aborted"]=state=="aborted"?1:0;children["unknown"]=state=="unknown"?1:0;
      auto row=children["items"].toArray()[0].toObject();row["state"]=state;children["items"]=QJsonArray{row};
      monitor.m_snapshot["verification_runs"]=children;monitor.render();
      verify(monitor.m_state->text().startsWith(active?"逐漏洞测试进行中":"已有 1 次逐漏洞测试记录"),"activity display follows queued/running/cancelling and terminal states");
      verify(monitor.m_verifications->item(0,3)->text()!=(QStringLiteral("未知 / 未记录")),"child lifecycle states remain individually readable");
      verify(monitor.m_snapshot["run"]==originalSnapshot["run"] && monitor.m_snapshot["pipeline_status"]==originalSnapshot["pipeline_status"],"render never mutates parent state");
    }
    monitor.m_snapshot=originalSnapshot;monitor.render();
    monitor.m_verifications->selectRow(0);monitor.m_parentDetails->setChecked(true);monitor.resize(1024,600);QTest::qWait(20);
    verify(monitor.size()==QSize(1024,600) && monitor.m_parentState->isVisible(),"optional parent detail remains reachable at narrow size");
    monitor.m_parentDetails->setChecked(false);monitor.render();
    verify(monitor.m_verifications->currentRow()==0,"parent detail toggle and refresh retain selected child history");
    monitor.resize(1360,860);
    monitor.m_verifications->selectRow(0);monitor.renderDetail();
    verify(monitor.m_detail->toPlainText().contains("child-A")&&!monitor.m_detail->toPlainText().contains("Run：run-A"),"finding detail uses its own run identity");
    emit monitor.m_verifications->cellDoubleClicked(0,0);
    verify(awaitCondition([&]{return historyServer.requests.value("GET /api/pipelines/A/verifications/fv-A")>0;}),"double click opens existing finding history with GET only");
    auto histories=monitor.findChildren<FindingVerificationDialog*>();
    verify(histories.size()==1&&awaitCondition([&]{return histories.first()->m_attempts->currentData()=="fva-A";}),"history opens the exact existing attempt");
    const int beforeClose=historyServer.requests.value("GET /api/pipelines/A/execution");
    histories.first()->reject();
    verify(awaitCondition([&]{return historyServer.requests.value("GET /api/pipelines/A/execution")>beforeClose;})&&refreshed.count()==1,"closing execution history refreshes only its bound task");
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
    monitor.setTaskContext("both","run-both","both.invalid");
    verify(awaitCondition([&]{return monitor.m_snapshot["pipeline_id"]=="both";}),"parent and child execution records coexist");
    verify(monitor.m_expectedRunId=="run-both"&&monitor.m_snapshot["run"].toObject()["run_id"]=="run-both"
        &&monitor.m_verifications->item(0,0)->text().contains("both"),"child listing never replaces parent run identity");
    monitor.setTaskContext("A",{},"A.invalid");
    verify(awaitCondition([&]{return monitor.m_snapshot["pipeline_id"]=="A";}),"finding history task can reopen");
    emit monitor.m_verifications->cellDoubleClicked(0,0);
    histories=monitor.findChildren<FindingVerificationDialog*>();
    monitor.setTaskContext("B",{},"B.invalid");
    verify(awaitCondition([&]{return monitor.m_snapshot["pipeline_id"]=="B";}),"task switch clears and loads child history for B");
    const int refreshCount=refreshed.count(),beforeB=historyServer.requests.value("GET /api/pipelines/B/execution");
    histories.first()->reject();QTest::qWait(30);
    verify(refreshed.count()==refreshCount&&historyServer.requests.value("GET /api/pipelines/B/execution")==beforeB,"closing an old task history cannot refresh the new task");
    delayedA=true;monitor.setTaskContext("A",{},"A.invalid");monitor.setTaskContext("B",{},"B.invalid");
    verify(awaitCondition([&]{return monitor.m_snapshot["pipeline_id"]=="B";}),"fresh B child snapshot loads while A is delayed");
    QTest::qWait(300);
    verify(monitor.m_verifications->item(0,0)->text().contains("B")&&monitor.m_snapshot["pipeline_id"]=="B","late A child execution snapshot cannot overwrite B");
    bool historyReadOnly=true;for(auto it=historyServer.requests.cbegin();it!=historyServer.requests.cend();++it)historyReadOnly=historyReadOnly&&it.key().startsWith("GET ");
    verify(historyReadOnly,"execution history open and close never send writes or start requests");
    const QString capture=qEnvironmentVariable("F08_MAIN_SCREENSHOT_DIR");
    if(!capture.isEmpty()){QDir().mkpath(capture);monitor.grab().save(capture+"/finding-execution-1360.png");monitor.resize(1024,600);QTest::qWait(30);monitor.grab().save(capture+"/finding-execution-1024.png");}
  }

  {
    ScanResultOverview overview;
    overview.setResults(QJsonArray{
      QJsonObject{{"result_type", "auth_finding"}, {"severity", "INFO"}},
      QJsonObject{{"result_type", "vulnerability"}, {"severity", "high"}},
      QJsonObject{{"result_type", "open_port"}, {"result_data", "{\"state\":\"closed\"}"}},
      QJsonObject{{"result_type", "open_port"}, {"result_data", "{\"state\":\"open\"}"}}
    });
    verify(overview.findChild<QFrame*>("findingMetric")->findChild<QLabel*>("metricValue")->text() == "1", "INFO legacy severity is not counted as a vulnerability");
    verify(overview.findChild<QFrame*>("portMetric")->findChild<QLabel*>("metricValue")->text() == "1", "closed port records are not counted as open ports");
  }

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
  bool showFindingExecutions = false;
  int findingActive=1, findingTotal=2;
  bool findingParent=false;
  QString findingParentState="FAILED";
  server.handler = [&](const QString &, const QString &requestPath) -> MockReply {
    const QString path = QUrl(requestPath).path();
    if (sourceOnly && path == "/api/scan-tasks") return {success(QJsonArray{sourceRecord()})};
    if (sourceOnly && path == "/api/scan-tasks/scan-source") return {success(sourceRecord())};
    const QString taskId = path.split('/').value(3);
    if (path == "/api/pipelines/analysis-index" || path == "/api/reports/index") {
      const QUrlQuery query{QUrl(requestPath)};
      const bool task = path.contains("pipelines");
      const QJsonObject row{{"pipeline_id", "B"}, {"report_id", "trace-B"},
        {"task_name", "fixture task B"}, {"title", "fixture report B"},
        {"owner", "fixture-user"}, {"kind", "trace_snapshot"}};
      return {success(QJsonObject{{"schema_version", 1}, {"records", QJsonArray{row}},
        {"total", 1}, {"offset", 0}, {"limit", 50}, {"search", query.queryItemValue("search", QUrl::FullyDecoded)},
        {task ? "state" : "kind", "all"}})};
    }
    if (path == "/api/pipelines") return {success(QJsonArray{taskRecord("A"), taskRecord("B")})};
    if (path == "/api/scan-tasks") return {success(QJsonArray{scanRecord("A"), scanRecord("B")}), delayedScans ? 250 : 0};
    if (path == "/api/scan-tasks/scan-A") return {success(scanRecord("A")), delayedScans ? 250 : 0};
    if (path == "/api/scan-tasks/scan-B") return {success(scanRecord("B"))};
    if (path == "/api/pipelines/" + taskId) {
      if (failedTask && taskId == "A")
        return {{{"status", "error"}, {"error", QJsonObject{{"message", "fixture task load failed"}}}}};
      auto record=taskRecord(taskId);
      if(showFindingExecutions) {
        record["status"]="awaiting_approval";
        if(!findingParent)record["run_id"]=QJsonValue::Null;
        auto summary=record["summary"].toObject();
        if(findingParent)summary["execution"]=QJsonObject{{"run_id","run-"+taskId},{"status",findingParentState}};
        summary["finding_verifications"]=QJsonObject{{"total",findingTotal},{"completed",1},{"active",findingActive},{"failed",0},{"aborted",0},{"unknown",0}};
        record["summary"]=summary;
      }
      return {success(record), delayedTask && taskId == "A" ? 250 : 0};
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
  verify(awaitCondition([&]() { return flow.m_scanTab->m_allScanResults && flow.m_scanTab->m_portScanTable->rowCount() == 1; }), "network task defaults to aggregate results and scoped child list");
  const QString scanCapture = qEnvironmentVariable("F04_SCREENSHOT_DIR");
  if (!scanCapture.isEmpty()) {
    flow.switchToStageTab(1);
    flow.m_scanTab->renderGroupedResults(QJsonArray{QJsonObject{{"id", 7001}, {"category", "vulnerability"},
      {"result_type", "web_vuln"}, {"severity", "medium"}, {"source_tool", "fixture"},
      {"result_data", "{\"title\":\"隔离夹具：目录索引暴露，长名称用于检查换行与完整任务工作台的首屏显示\",\"url\":\"https://fixture.invalid/docs/\"}"}}});
    flow.m_scanTab->setStatusText("本任务扫描：部分完成 · 隔离夹具\n检查详情保留未完成范围");
    flow.m_scanTab->m_listTitle->setText("漏洞候选 · 共 1 条");
    flow.m_scanTab->m_resultHint->setText("隔离夹具 · 已加载 1 / 1 条记录 · 未去重");
    QTest::qWait(80);
    flow.grab().save(scanCapture + "/flow-scan-1360.png");
    flow.resize(1024,600); QTest::qWait(80);
    const auto footerPosition = flow.m_scanTab->m_moreResultsButton->mapTo(&flow, QPoint(0, 0));
    verify(flow.rect().contains(QRect(footerPosition, flow.m_scanTab->m_moreResultsButton->size())),
      "complete narrow workbench keeps scan pagination inside viewport");
    flow.grab().save(scanCapture + "/flow-scan-1024.png");
    flow.resize(1360,860);
  }
  emit flow.m_scanTab->m_portScanTable->cellClicked(0, 0);
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
  const QString activityCapture=qEnvironmentVariable("F08_MAIN_SCREENSHOT_DIR");
  showFindingExecutions=true;flow.loadFlowDetail("A");
  verify(awaitCondition([&]{return flow.m_stepIndicator->phases()[4].statusText=="逐漏洞测试进行中"&&flow.m_stepIndicator->phases()[4].summary.contains("活动 1");}),"main phase shows finding execution activity beside the parent stage");
  verify(flow.m_stepIndicator->phases()[4].status=="running"&&flow.m_lastDisplayedDetail["status"]=="awaiting_approval","finding activity never falsely completes the parent task or phase");
  if(!activityCapture.isEmpty())flow.m_stepIndicator->grab().save(activityCapture+"/execution-node-active.png");
  const int beforeFindingRefresh=server.requests.value("GET /api/pipelines/A");
  emit flow.m_scanTab->findingVerificationChanged("A");
  verify(awaitCondition([&]{return server.requests.value("GET /api/pipelines/A")>beforeFindingRefresh;}),"finding-window close signal refreshes parent task detail");
  const int afterFindingRefresh=server.requests.value("GET /api/pipelines/A");
  emit flow.m_scanTab->findingVerificationChanged("foreign");QTest::qWait(30);
  verify(server.requests.value("GET /api/pipelines/A")==afterFindingRefresh,"foreign finding-window notification cannot refresh selected task");
  findingActive=0;flow.loadFlowDetail("A");
  verify(awaitCondition([&]{return flow.m_stepIndicator->phases()[4].statusText=="已有 2 次测试记录";}),"terminal finding records use neutral record count");
  verify(flow.m_stepIndicator->phases()[4].status=="info" && flow.m_lastDisplayedDetail["status"]=="awaiting_approval","records never mark parent complete or achieved");
  if(!activityCapture.isEmpty()){flow.m_stepIndicator->grab().save(activityCapture+"/execution-node-records.png");}
  findingTotal=0;flow.loadFlowDetail("A");
  verify(awaitCondition([&]{return flow.m_stepIndicator->phases()[4].statusText=="待执行验证" && flow.m_stepIndicator->phases()[4].status=="pending";}),"no parent or child execution shows grey pending verification");
  if(!activityCapture.isEmpty())flow.m_stepIndicator->grab().save(activityCapture+"/execution-node-pending.png");
  findingParent=true;findingTotal=2;flow.loadFlowDetail("A");
  verify(awaitCondition([&]{return flow.m_stepIndicator->phases()[4].statusText=="已有 3 次测试记录";}),"parent Run and child attempts count independently without replacing identities");
  findingParentState="RUNNING";flow.loadFlowDetail("A");
  verify(awaitCondition([&]{return flow.m_stepIndicator->phases()[4].statusText=="主预案执行中";}),"active parent comes from its own Run status when no child is active");
  findingActive=1;flow.loadFlowDetail("A");
  verify(awaitCondition([&]{return flow.m_stepIndicator->phases()[4].statusText=="逐漏洞测试进行中";}),"child activity takes display priority while parent Run remains independently active");
  verify(flow.m_lastDisplayedDetail["summary"].toObject()["execution"].toObject()["status"]=="RUNNING","child display never overwrites parent Run status");
  showFindingExecutions=false;

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

  emit flow.m_scanTab->m_portScanTable->cellClicked(0, 0);
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
  verify(awaitCondition([&]() { return flow.m_scanTab->m_portScanTable->rowCount() == 1; }), "child list reopens for explicit selection");
  emit flow.m_scanTab->m_portScanTable->cellClicked(0, 0);
  verify(awaitCondition([&]() { return flow.m_scanTab->m_selectedTaskId == "scan-A"; }), "reopening restores exact task scope");
  delayedScans = true;
  const int oldDetailRequests = server.requests.value("GET /api/scan-tasks/scan-A");
  emit flow.m_scanTab->m_portScanTable->cellClicked(0, 0);
  verify(awaitCondition([&]() { return server.requests.value("GET /api/scan-tasks/scan-A") > oldDetailRequests; }), "delayed scan detail request is in flight");
  flow.onBackToList();
  delayedScans = false;
  flow.openTaskAnalysis("A");
  verify(awaitCondition([&]() { return flow.m_scanTab->m_portScanTable->rowCount() == 1; }), "fresh scoped child list loads");
  emit flow.m_scanTab->m_portScanTable->cellClicked(0, 0);
  verify(awaitCondition([&]() { return flow.m_scanTab->m_currentTarget == "A.invalid"; }), "same task can reopen with fresh scan context");
  flow.m_scanTab->m_currentTarget = QStringLiteral("fresh-context-marker");
  QTest::qWait(350);
  verify(flow.m_scanTab->m_currentTarget == "fresh-context-marker", "old same-ID scan response cannot overwrite reopened context");
  flow.onBackToList();
  QTest::qWait(350);
  verify(flow.m_scanTab->m_currentTarget.isEmpty() && flow.m_scanTab->m_resultTree->topLevelItemCount() == 0, "late scan detail cannot restore old target or results");
  {
    MockServer reportServer;
    auto record=QJsonObject{{"scan_task_id","report-retry"},{"scan_type","source_scan"},{"target","/src/project"},
      {"status","PARTIAL"},{"can_reparse_report",true},{"results",QJsonArray{}}};
    bool retryFailed=true;
    reportServer.handler=[&](const QString &method,const QString &path)->MockReply {
      if(method=="POST" && path=="/api/scan-tasks/report-retry/reparse") {
        if(retryFailed) return {QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture retry failure"}}}}};
        return {success(QJsonObject{{"scan_task_id","report-retry"}})};
      }
      if(path=="/api/scan-tasks") return {success(QJsonArray{record})};
      if(path=="/api/scan-tasks/report-retry") return {success(record)};
      return {success(QJsonArray{})};
    };
    ApiClient reportApi(QStringLiteral("http://127.0.0.1:%1").arg(reportServer.serverPort()));
    ScanPage reportPage(&reportApi,"user","fixture-user");
    reportPage.m_selectedTaskId="report-retry";
    auto running=record;running["status"]="RUNNING";running["can_reparse_report"]=false;
    const auto phaseResult=[](const QString &phase) {
      return QJsonObject{{"result_type","source_coverage"},{"result_data",QString::fromUtf8(QJsonDocument(QJsonObject{
        {"engine","cscan"},{"input_mode","service_path"},{"cscan",QJsonObject{{"state",phase}}}}).toJson(QJsonDocument::Compact))}};
    };
    running["results"]=QJsonArray{phaseResult("parsing")};reportPage.updateStatusLabel(running);
    verify(reportPage.m_statusLabel->text().contains("正在解析报告") && reportPage.m_compactStatus->text() == "正在解析报告" && !reportPage.m_sourceDemoBtn->isEnabled(),
      "source report parsing is visible and cannot open finding selection");
    running["results"]=QJsonArray{phaseResult("importing")};reportPage.updateStatusLabel(running);
    verify(reportPage.m_statusLabel->text().contains("正在导入漏洞") && reportPage.m_compactStatus->text() == "正在导入漏洞","source report import has a distinct phase");
    reportPage.updateStatusLabel(record);
    verify(reportPage.m_reexecBtn->text()=="重新解析报告" && reportPage.m_reexecBtn->isEnabled(),
      "retained source report enables report retry");
    reportPage.onReexecScan();
    verify(awaitCondition([&]{return reportPage.m_statusLabel->text().contains("fixture retry failure");}),
      "source report retry displays the actual API failure");
    retryFailed=false;reportPage.onReexecScan();
    verify(awaitCondition([&]{return reportServer.requests.value("POST /api/scan-tasks/report-retry/reparse")==2;}),
      "failed report retry can be repeated against the same task");
    verify(reportServer.requests.value("POST /api/scan-tasks/report-retry/retry")==0,
      "source report retry never requests a new scan");
  }
  sourceOnly = true;
  ScanPage sourcePage(&api, "user", "fixture-user");
  verify(sourcePage.m_programInputKind->currentData().toString() == "agent",
      "source scanning defaults to passing a path or address to CScan");
  {
    MockServer nativeServer;
    nativeServer.listen(QHostAddress::LocalHost,0);
    nativeServer.handler=[](const QString &method,const QString &path)->MockReply {
      if(method=="GET" && path=="/api/scan-tasks/source-connections")
        return {success(QJsonArray{QJsonObject{{"id","ssh-project"},{"name","Project"},{"kind","ssh"},{"targets",QJsonArray{"http://192.0.2.40:8089/"}}}})};
      if(method=="POST" && path=="/api/scan-tasks/source-directory")
        return {success(QJsonObject{{"path","project"},{"parent",""},
          {"entries",QJsonArray{QJsonObject{{"name","src"},{"directory",true},{"path","project/src"}}}}})};
      if(method=="POST" && path=="/api/scan-tasks")
        return {QJsonObject{{"status","error"},{"error",QJsonObject{{"message","fixture: creation captured without execution"}}}}};
      return {success(QJsonArray())};
    };
    ApiClient nativeApi(QStringLiteral("http://127.0.0.1:%1").arg(nativeServer.serverPort()));
    ScanPage nativePage(&nativeApi,"user","fixture-user");
    nativePage.m_programInputKind->setCurrentIndex(nativePage.m_programInputKind->findData("agent"));
    nativePage.m_scanTypeTabs->setCurrentIndex(4);
    nativePage.m_sourceTargetInput->setText("http://192.0.2.40:8089/");
    nativePage.m_sourceNotesInput->setText("check fixture input bounds");
    nativePage.onCreateScan();
    verify(awaitCondition([&]() {return nativeServer.requestBodies.contains("POST /api/scan-tasks");}),
        "source creation submits an actual request to the platform adapter");
    const auto nativeBody=QJsonDocument::fromJson(nativeServer.requestBodies.value("POST /api/scan-tasks")).object();
    const auto nativeParameters=nativeBody["parameters"].toObject();
    verify(nativeParameters["cscan_target"].toString()=="http://192.0.2.40:8089/"
        && nativeParameters["source_notes"].toString()=="check fixture input bounds"
        && nativeParameters["input_kind"].toString()=="agent"
        && !nativeParameters.contains("source_path") && !nativeParameters.contains("source_url"),
        "source request forwards the remote target and audit requirements without a local or mounted path");
    nativePage.m_programInputKind->setCurrentIndex(nativePage.m_programInputKind->findData("remote_directory"));
    auto *picker=nativePage.m_remoteSourcePicker;
    picker->findChild<QPushButton*>("remoteSourceBrowse")->click();
    auto *directoryDialog=picker->findChild<QDialog*>("remoteSourceDirectoryDialog");
    verify(directoryDialog!=nullptr,"remote directory picker opens instead of a local file dialog");
    verify(awaitCondition([&]{return directoryDialog->findChild<QComboBox*>()->currentData().toString()=="ssh-project";}),
      "directory browsing prefers the configured SSH connection");
    directoryDialog->findChild<QLineEdit*>("remoteSourceDirectoryPath")->setText("project");
    directoryDialog->findChild<QPushButton*>("remoteSourceLoad")->click();
    auto *selectDirectory=directoryDialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok);
    verify(awaitCondition([&]{return selectDirectory->isEnabled();}),"server directory response enables selecting the folder");
    selectDirectory->click();
    verify(picker->hasSelection(),"confirmed target folder is retained");
    const int oldRequests=nativeServer.requests.value("POST /api/scan-tasks");
    nativePage.onCreateScan();
    verify(awaitCondition([&]{return nativeServer.requests.value("POST /api/scan-tasks")>oldRequests;}),
      "selected target folder is submitted through the scan form");
    const auto folderParameters=QJsonDocument::fromJson(nativeServer.requestBodies.value("POST /api/scan-tasks"))
      .object()["parameters"].toObject();
    verify(folderParameters["input_kind"].toString()=="remote_directory"
      && folderParameters["connection_id"].toString()=="ssh-project" && folderParameters["source_subdir"].toString()=="project"
      && !folderParameters.contains("cscan_target"),"folder selection retains the remote location for direct CScan submission");
    nativePage.m_sourceTargetInput->setText("http://192.0.2.41:8089/");
    verify(!picker->hasSelection(),"changing target discards the previous host's folder");
  }
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
    // A developer's legacy archive may be present beside the build tree.
    // This fixture models an unedited auto-generated topology.
    programTopology.m_topologyDocument.metadata["manuallyEdited"] = false;
    QJsonObject event{{"scanTaskId", "foreign-scan"}, {"scanType", "program_scan"}, {"status", "PARTIAL"}};
    programTopology.onScanCompleted(event);
    verify(!programTopology.m_autoTopologyGenerationIds.contains("foreign-scan"), "program topology ignores another task's event");
    event["scanTaskId"] = "scan-source";
    event["target"] = "http://127.0.0.1:8089/";
    programTopology.onScanCompleted(event);
    verify(awaitCondition([&]() { return !programTopology.m_topologyRequestPending
        && programTopology.m_topologyDocument.flowId == "source-topology"
        && programTopology.m_autoTopologyGenerationIds.contains("scan-source")
        && !programTopology.m_topologyDocument.nodes.isEmpty(); }),
           "partial program scan event automatically displays its scoped runtime topology");
    programTopology.m_documentDirty = true;
    programTopology.m_autoTopologyGenerationIds.clear();
    event["scanType"] = "source_scan";
    event["status"] = "COMPLETED";
    programTopology.onScanCompleted(event);
    verify(programTopology.m_documentDirty && !programTopology.m_topologyRequestPending,
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
  // Exercise the actual shell wiring, not just the dialog's output signal.
  failedTask = false;
  flow.hide();
  MainWindow window(&api, "user", "fixture-user");
  window.m_dongleTimer->stop(); // Exercise lock transitions explicitly; never access hardware.
  window.m_ws->disconnectFromServer();
  window.show();
  verify(!window.findChild<QLineEdit*>("globalSearch") && !window.findChild<QPushButton*>("shellSettings"),
    "header removes search and settings shortcuts");
  auto *toggle = window.findChild<QPushButton*>("navigationToggle");
  verify(toggle && window.m_navList->flow() == QListView::LeftToRight, "header has horizontal collapsible navigation");
  window.resize(1024, 600);
  QTest::qWait(100);
  auto *header = window.findChild<QFrame*>("appTopBar");
  verify(header && header->height() <= 70 && header->geometry().contains(toggle->mapTo(header, toggle->rect().center())),
    "navigation and account controls share a compact header");
  verify(!window.findChild<QLabel*>("appBrand") && !window.findChild<QLabel*>("appSubtitle"),
    "compact header removes brand titles");
  for (int row = 0; row < 7; ++row) {
    window.m_navList->scrollToItem(window.m_navList->item(row));
    QCoreApplication::processEvents();
    QTest::mouseClick(window.m_navList->viewport(), Qt::LeftButton, Qt::NoModifier,
      window.m_navList->visualItemRect(window.m_navList->item(row)).center());
    verify(window.m_stackWidget->currentIndex() == row, "horizontal module click selects matching page");
  }
  const int expandedHeight = window.m_stackWidget->height();
  toggle->click();
  QTest::qWait(50);
  verify(!window.m_navList->isVisible() && window.m_stackWidget->height() > expandedHeight,
    "collapse gives header space back to business page");
  window.switchToPage(1);
  verify(toggle->text().contains(QStringLiteral("测试任务")), "collapsed header follows programmatic navigation");
  toggle->click();
  verify(window.m_navList->isVisible() && window.m_navList->currentRow() == 1, "expand preserves selected module");
  window.setDongleLocked(true, "fixture lock");
  verify(!window.m_navList->isEnabled(), "lock disables header navigation");
  window.switchToPage(5);
  verify(window.m_stackWidget->currentIndex() == 7, "locked navigation cannot leave lock page");
  window.setDongleLocked(false);
  verify(window.m_navList->isEnabled() && window.m_stackWidget->currentIndex() == 1,
    "unlock restores selected module");
  QTest::qWait(100);
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
  int selectionDialogs = 0;
  QTimer chooseFinding;
  chooseFinding.setInterval(10);
  QObject::connect(&chooseFinding, &QTimer::timeout, [&]() {
    auto *dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
    if (!dialog || dialog->property("testSelected").toBool()) return;
    auto *table = dialog->findChild<QTableWidget*>("sourceDemonstrationCandidates");
    if (!table) return;
    dialog->setProperty("testSelected", true);
    auto *check = qobject_cast<QCheckBox*>(table->cellWidget(0, 0));
    verify(check != nullptr, "generation presents explicit finding selection on the current page");
    if (selectionDialogs++ > 0) verify(check->isChecked(), "retry retains the previously selected finding");
    check->setChecked(true);
    for (auto *button : dialog->findChildren<QPushButton*>())
      if (button->text() == QStringLiteral("生成攻击测试预案")) { button->click(); break; }
  });
  chooseFinding.start();
  flow.openTaskAnalysis("source");
  verify(awaitCondition([&]() { return flow.m_scanTab->m_selectedTaskId == "scan-source" && flow.m_scanTab->m_sourceDemoBtn->isEnabled(); }), "source pipeline loads generation context");
  verify(flow.m_stepIndicator->phases()[3].summary == QStringLiteral("尚未生成任务预案"), "empty plan never claims to be ready for approval");
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
  verify(flow.m_stageTabs->currentWidget() == flow.m_planTab, "failed generation stays on the task plan page");
  verify(flow.m_planTab->m_status->text().contains("缺少编号 101"), "plan page shows the concrete generation failure");
  verify(flow.m_scanTab->m_sourceDemoBtn->isEnabled() && !flow.m_scanTab->m_pendingSourceVerification && savedPlan.isEmpty(),
      "a second failure remains retryable without creating a draft");
  sourceDetailDelay = 0;
  flow.m_planTab->refresh();
  verify(flow.m_planTab->m_busy, "draft fetch overlaps source generation");
  verify(flow.m_analysisTab->m_planButton->isEnabled(), "analysis offers source generation without selecting an analysis note");
  flow.m_analysisTab->m_planButton->click();
  verify(awaitCondition([&]() { return flow.m_planTab->m_steps->rowCount() == 2; }), "generated source steps automatically become a visible task draft");
  verify(flow.m_stageTabs->currentWidget() == flow.m_planTab, "successful generation preserves the current task plan stage");
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
  // A v2 report belongs to its task even when there is no main execution Run.
  {
    TaskResultsPanel panel(&api, "user", "fixture-user");
    auto current=resultsRecord("scan-only");
    auto execution=current.value("execution").toObject();execution["run"]=QJsonValue(QJsonValue::Null);
    execution["steps"]=QJsonArray{};execution["evidence"]=QJsonArray{};execution["attempts"]=QJsonArray{};
    current["execution"]=execution;current["statistics"]=QJsonObject{{"report_ready",true}};
    panel.m_pipelineId="scan-only";panel.m_target="scan-only.invalid";panel.m_snapshot=current;panel.m_fresh=true;
    panel.updateButtons();verify(panel.m_generate->isEnabled(),"pure scan task enables report generation when server confirms stopped");
    auto document=reportRecord("scan-only");auto metadata=document.value("report").toObject();metadata["run_id"]=QJsonValue(QJsonValue::Null);
    auto content=metadata.value("content").toObject();auto provenance=content.value("provenance").toObject();provenance["run_id"]=QJsonValue(QJsonValue::Null);
    content["schema_version"]=2;content["provenance"]=provenance;content["results"]=current;metadata["content"]=content;document["report"]=metadata;
    verify(panel.validReport(document,metadata.value("report_id").toString(),true),"v2 frozen report accepts null main Run with matching task identity");
    document["pipeline_id"]="foreign";verify(!panel.validReport(document,metadata.value("report_id").toString(),true),"v2 report rejects foreign task identity");
  }
  {
    TaskResultsPanel panel(&api,"user","fixture-user");panel.m_timer->stop();panel.m_pipelineId="result-status";
    auto snapshot=resultsRecord("result-status");QJsonArray findings;
    const QList<QPair<QString,QString>> states{{"achieved","目标已达成"},{"not_achieved","目标未达成"},{"inconclusive","证据不足"},{"not_performed","未开展适用验证"},{"pending","等待结果"}};
    for(const auto &entry:states)findings.append(QJsonObject{{"id",entry.first},{"category","scan_candidate"},{"state","unreviewed"},{"name",entry.first},{"source","structured_scan"},{"verification",QJsonObject{{"result",QJsonObject{{"schema_version",1},{"status",entry.first}}},{"manual",QJsonObject{{"conclusion","confirmed"}}}}}});
    findings.append(QJsonObject{{"id","legacy"},{"name","legacy"},{"verification",QJsonObject{{"conclusion","confirmed"},{"method","manual"}}}});
    findings.append(QJsonObject{{"id","unexecuted"},{"name","unexecuted"}});
    snapshot["findings"]=findings;panel.m_snapshot=snapshot;panel.render();
    for(int row=0;row<states.size();++row)verify(panel.m_findings->item(row,3)->text()==states[row].second,"task result candidate displays its system outcome, independent of manual opinion");
    verify(panel.m_findings->item(5,3)->text()=="证据不足（旧版接口）","task result does not promote legacy manual confirmation");
    verify(panel.m_findings->item(6,3)->text()=="未开展适用验证","task result distinguishes an unexecuted finding");
  }
  chooseFinding.stop();
  {
    MockServer nodeServer;nodeServer.listen(QHostAddress::LocalHost,0);
    nodeServer.handler=[](const QString &method,const QString &requestPath)->MockReply {
      const QString path=QUrl(requestPath).path();
      if(method=="POST" && path=="/api/pipelines")return {success(QJsonObject{{"pipeline_id","node-followup"}})};
      if(path=="/api/pipelines/node-followup/start")return {success(QJsonObject{})};
      if(path=="/api/pipelines")return {success(QJsonArray{taskRecord("node-followup")})};
      if(path=="/api/pipelines/node-followup")return {success(taskRecord("node-followup"))};
      if(path.endsWith("/execution"))return {success(executionRecord("node-followup"))};
      if(path.endsWith("/results"))return {success(resultsRecord("node-followup"))};
      if(path.endsWith("/plan"))return {success(QJsonValue::Null)};
      return {success(QJsonArray{})};
    };
    ApiClient nodeApi(QStringLiteral("http://127.0.0.1:%1").arg(nodeServer.serverPort()));
    FlowPage nodeFlow(&nodeApi,"user","fixture-user");
    const QString observedService="http://192.0.2.40:8089/";
    QTimer::singleShot(0,&nodeFlow,[&]() {
      auto *dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget());
      verify(dialog && dialog->objectName()=="topologyTargetTaskDialog","node action opens an explicit target confirmation form");
      if(dialog) {
        verify(dialog->findChild<QLineEdit*>("taskTargetInput")->text()==observedService,"node task preserves the exact discovered service URL");
        verify(!dialog->findChild<QCheckBox*>("taskAuthorizationCheck")->isChecked(),"node task requires fresh explicit authorization");
        verify(!dialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->isEnabled(),"node scan cannot start before target authorization");
        dialog->reject();
      }
    });
    emit nodeFlow.m_topoTab->testTargetRequested(observedService);
    verify(nodeServer.requests.value("POST /api/pipelines")==0,"cancelling target confirmation creates no task or scan");
    QTimer::singleShot(0,&nodeFlow,[&]() {
      auto *dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget());
      if(!dialog) {verify(false,"second node confirmation is visible");return;}
      dialog->findChild<QCheckBox*>("taskAuthorizationCheck")->setChecked(true);
      dialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->click();
    });
    emit nodeFlow.m_topoTab->testTargetRequested(observedService);
    verify(awaitCondition([&]() {return nodeServer.requests.value("POST /api/pipelines/node-followup/start")==1
      && nodeFlow.m_selectedPipelineId=="node-followup";}),"confirmed node target creates and starts exactly one task then opens its workbench");
    const auto body=QJsonDocument::fromJson(nodeServer.requestBodies.value("POST /api/pipelines")).object();
    const auto config=body["config"].toObject();
    verify(body["target"].toString()==observedService && config["test_type"].toString()=="web"
      && config["task_scope"].toObject()["includes"].toArray()==QJsonArray{observedService},
      "new node task is scoped to the chosen Web service rather than the whole subnet");
    verify(nodeServer.requests.value("POST /api/pipelines")==1,"node confirmation submits one task creation request");
    const auto previous=nodeServer.requests.value("POST /api/pipelines/node-followup/verifications");
    emit nodeFlow.m_topoTab->nodeFindingsRequested("foreign-task",{41});
    verify(nodeFlow.findChildren<FindingVerificationDialog*>().isEmpty(),"late node finding actions cannot open another task's verification");
    emit nodeFlow.m_topoTab->nodeFindingsRequested("node-followup",{41,42});
    verify(awaitCondition([&](){return nodeServer.requests.value("POST /api/pipelines/node-followup/verifications")>previous;}),
      "node findings open the existing per-finding preparation workflow");
    for(auto *dialog:nodeFlow.findChildren<FindingVerificationDialog*>())delete dialog;
    QTimer::singleShot(0,&nodeFlow,[&]() {
      auto *dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget());
      if(!dialog) {verify(false,"remote CScan task form is visible");return;}
      auto *type=dialog->findChild<QComboBox*>("taskTestTypeInput");
      type->setCurrentIndex(type->findData("program"));
      auto *inputKind=dialog->findChild<QComboBox*>("taskProgramInputKind");
      verify(inputKind->currentData().toString()=="agent",
        "CScan task defaults to selecting the target folder");
      inputKind->setCurrentIndex(inputKind->findData("agent"));
      dialog->findChild<QLineEdit*>("taskTargetInput")->setText(observedService);
      dialog->findChild<QLineEdit*>("taskSourceNotesInput")->setText("Source is on the target in /var/www/project");
      bool localPicker=false;
      for(auto *button:dialog->findChildren<QPushButton*>())
        if(button->text().contains("选择文件")) localPicker=true;
      verify(!localPicker,"remote CScan form has no local source file picker");
      dialog->findChild<QCheckBox*>("taskAuthorizationCheck")->setChecked(true);
      dialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->click();
    });
    nodeFlow.createFlow(true);
    verify(awaitCondition([&]() {return nodeServer.requests.value("POST /api/pipelines")==2;}),
      "remote CScan task submits a normal pipeline request");
    const auto remoteBody=QJsonDocument::fromJson(nodeServer.requestBodies.value("POST /api/pipelines")).object();
    const auto remoteConfig=remoteBody["config"].toObject();
    verify(remoteConfig["cscan_target"].toString()==observedService
      && remoteConfig["source_notes"].toString().contains("/var/www/project")
      && !remoteConfig.contains("source_path") && !remoteConfig.contains("source_url"),
      "target and audit requirements are sent to the remote Flow without requiring a local or /src directory");
    bool noExecution=true;
    for(auto it=nodeServer.requests.cbegin();it!=nodeServer.requests.cend();++it)
      if(it.key().contains("/attempts") || it.key().startsWith("POST /api/runs"))noExecution=false;
    verify(noExecution,"opening a node's findings never executes an attack");
  }
  {
    MockServer sourceServer;
    sourceServer.handler=[](const QString &,const QString &){return MockReply{success(QJsonArray()),0};};
    ApiClient sourceApi(QStringLiteral("http://127.0.0.1:%1").arg(sourceServer.serverPort()));
    ScanPage sourcePage(&sourceApi);
    const QJsonObject finding{{"id",901},{"result_type","source_finding"},{"severity","high"},{"source_tool","cscan"},
      {"result_data",QString::fromUtf8(QJsonDocument(QJsonObject{{"title","Unchecked copy"},{"file","src/input.c"},
        {"start_line",12},{"end_line",14},{"cwe","CWE-120"},{"reason","Destination capacity is not checked"}}).toJson(QJsonDocument::Compact))}};
    const auto coverage=[](const QString &phase){return QJsonObject{{"id",900},{"result_type","source_coverage"},{"severity","info"},
      {"result_data",QString::fromUtf8(QJsonDocument(QJsonObject{{"engine","cscan"},{"input_mode","remote_agent"},
        {"cscan",QJsonObject{{"state",phase},{"subtask_progress",QJsonObject{{"finished",1},{"total",2}}}}}}).toJson(QJsonDocument::Compact))}};};
    const QJsonObject raw{{"id",902},{"result_type","raw_output"},{"severity","info"},{"result_data","{\"report\":\"retained report\"}"}};
    for(const auto &phase:{QString("running"),QString("parsing"),QString("importing")}) {
      const QJsonArray records{coverage(phase),finding,raw};
      sourcePage.updateStatusLabel(QJsonObject{{"status","RUNNING"},{"target","http://fixture.invalid/source/"},{"scan_type","source_scan"},{"results",records}});
      sourcePage.renderGroupedResults(records);
      verify(sourcePage.m_resultTree->topLevelItemCount()==0,"source scan and report processing never expose intermediate findings");
      verify(sourcePage.m_resultHint->text().contains(phase=="parsing"?QStringLiteral("解析"):phase=="importing"?QStringLiteral("保存"):QStringLiteral("扫描中")),"source phase remains visible without partial findings");
    }
    const QJsonArray finalRecords{coverage("finished"),finding,raw};
    sourcePage.updateStatusLabel(QJsonObject{{"status","COMPLETED"},{"target","http://fixture.invalid/source/"},{"scan_type","source_scan"},{"results",finalRecords}});
    sourcePage.renderGroupedResults(finalRecords);
    verify(sourcePage.m_resultTree->topLevelItemCount()==1 && sourcePage.m_resultTree->rootIndex().isValid(),"completed source scan shows one flat findings table");
    auto *row=sourcePage.m_resultTree->topLevelItem(0)->child(0);
    verify(row->text(1)=="Unchecked copy" && row->text(3)=="CWE-120" && row->text(5)=="src/input.c:12","source table exposes title, category and source location");
    sourcePage.m_showAllRecords->click();
    verify(sourcePage.m_sourceRecordsMode && sourcePage.m_resultTree->topLevelItemCount()>1,"raw reports and progress remain available in explicit records view");
    sourcePage.m_showAllRecords->click();
    verify(!sourcePage.m_sourceRecordsMode && sourcePage.m_resultTree->rootIndex().isValid(),"returning from records restores the final table");
    sourcePage.clearDetailPanel();
    verify(!sourcePage.m_sourceResultsView && sourcePage.m_sourceRecords.isEmpty(),"switching task clears source presentation state");
  }
  std::cout << "TOTAL " << checks << " checks passed" << std::endl;
  return 0;
}
