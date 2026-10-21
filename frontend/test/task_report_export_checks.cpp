#include <QtWidgets>
#include <QtNetwork>
#include <QtTest>
#include <functional>
#include "ApiClient.h"
#include "ReportFileActions.h"
#define private public
#include "pages/TaskResultsPanel.h"
#undef private

namespace {
class EnvironmentValue {
public:
  EnvironmentValue(const char *key, const QByteArray &value)
      : m_key(key), m_wasSet(qEnvironmentVariableIsSet(key)), m_previous(qgetenv(key))
  { qputenv(key, value); }
  ~EnvironmentValue() { if (m_wasSet) qputenv(m_key.constData(), m_previous); else qunsetenv(m_key.constData()); }
private:
  QByteArray m_key;
  bool m_wasSet;
  QByteArray m_previous;
};

QJsonObject reportDocument(const QString &task = "A", const QString &id = "trace-A")
{
  const QString fingerprint(64, 'a');
  const QJsonObject identity{{"pipeline_id", task}, {"owner", "fixture-user"}, {"target", task + ".invalid"}};
  auto provenance = identity;
  provenance["run_id"] = "run-" + task;
  provenance["source_fingerprint"] = fingerprint;
  auto results = identity;
  results["source_fingerprint"] = fingerprint;
  results["execution"] = QJsonObject{{"run", QJsonObject{{"run_id", "run-" + task}}}};
  const QJsonObject report{{"report_id", id}, {"kind", "trace_snapshot"}, {"run_id", "run-" + task},
    {"source_fingerprint", fingerprint}, {"title", "Frozen fixture"}, {"status", "draft"},
    {"content", QJsonObject{{"schema_version", 1}, {"type", "task_result_report"},
      {"provenance", provenance}, {"results", results}}}};
  auto document = identity;
  document["report"] = report;
  return document;
}

QJsonObject resultsSnapshot(const QString &task)
{
  const QJsonObject identity{{"version", 1}, {"pipeline_id", task}, {"owner", "fixture-user"}, {"target", task + ".invalid"}};
  auto execution = identity;
  execution["run"] = QJsonObject{{"run_id", "run-" + task}, {"status", "COMPLETED"},
    {"counts", QJsonObject{{"steps", 0}, {"returned", 0}, {"succeeded", 0}, {"failed", 0}, {"attempts", 0}, {"evidence", 0}}}};
  for (const auto &key : {"steps", "attempts", "evidence"}) execution[key] = QJsonArray{};
  auto snapshot = identity;
  QJsonArray reports;
  for (const auto &id : {"trace-" + task, "other-" + task}) {
    auto metadata = reportDocument(task, id).value("report").toObject();
    metadata.remove("content"); reports.append(metadata);
  }
  snapshot["execution"] = execution;
  snapshot["source_fingerprint"] = QString(64, 'a');
  snapshot["findings"] = QJsonArray{};
  snapshot["reports"] = reports;
  snapshot["assessment"] = QJsonObject{};
  snapshot["trace"] = QJsonObject{};
  return snapshot;
}

QJsonObject reportPresentation()
{
  return {{"schema_version", 1}, {"title", QStringLiteral("任务攻击测试结果报告")},
    {"sections", QJsonArray{
      QJsonObject{{"title", QStringLiteral("本次攻击测试概况")}, {"headers", QJsonArray{"项目", "结果"}},
        {"rows", QJsonArray{QJsonArray{"测试对象", "A.invalid/saved-path"}, QJsonArray{"已实施验证", "1 项"}}}},
      QJsonObject{{"title", QStringLiteral("逐漏洞攻击效果表")},
        {"headers", QJsonArray{"漏洞及位置", "实施操作", "预期效果", "实际效果与证据", "结果"}},
        {"rows", QJsonArray{QJsonArray{"目录索引 /saved-path", "请求目录并检查响应", "确认指定目录索引暴露",
          "观察到目录清单；证据 42；作用仅限此路径", "目标已达成"},
          QJsonArray{"<b>未实施候选</b>", "未实施验证", "尚无适用判据", "未取得验证证据", "未开展适用验证"}}}},
      QJsonObject{{"title", QStringLiteral("攻击测试结论")},
        {"paragraphs", QJsonArray{"已保存的目录暴露验证达到预期效果；其他安全影响未验证。"}}}
    }}};
}

QByteArray content(const QString &format)
{
  if (format == "docx") return QByteArray::fromHex("504b0304") + "mock docx payload";
  if (format == "pdf") return "%PDF-1.7\nmock pdf payload";
  if (format == "html") return "<!doctype html><html><body>Frozen fixture</body></html>";
  return QJsonDocument(reportDocument()).toJson(QJsonDocument::Compact);
}

struct Reply {
  QByteArray bytes;
  QByteArray filename;
  int status = 200;
  int delay = 0;
};

class ExportServer : public QTcpServer {
public:
  int exports = 0;
  int resultReads = 0;
  int reportReads = 0;
  int delay = 0;
  QString lastPath;
  std::function<Reply(const QString &)> response;
  std::function<QJsonObject(const QString &, const QString &)> reportResponse;

  ExportServer()
  {
    connect(this, &QTcpServer::newConnection, this, [this] {
      while (hasPendingConnections()) {
        auto *socket = nextPendingConnection();
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
          const auto bytes = socket->property("request").toByteArray() + socket->readAll();
          socket->setProperty("request", bytes);
          if (!bytes.contains("\r\n\r\n") || socket->property("handled").toBool()) return;
          socket->setProperty("handled", true);
          const QString path = QString::fromUtf8(bytes.split(' ').value(1));
          const QUrl url(path);
          Reply reply;
          if (url.path().endsWith("/export")) {
            ++exports; lastPath = path;
            const QString format = QUrlQuery(url).queryItemValue("format");
            reply = response ? response(format) : Reply{content(format), ("report_trace-A." + format).toUtf8(), 200, delay};
          } else {
            const auto parts = url.path().split('/');
            QJsonValue data = QJsonArray{};
            if (url.path().contains("/reports/")) {
              ++reportReads;
              data = reportResponse ? reportResponse(parts.value(3), parts.last()) : reportDocument(parts.value(3), parts.last());
            }
            else if (url.path().endsWith("/results")) {
              ++resultReads; data = resultsSnapshot(parts.value(3));
            }
            reply.bytes = QJsonDocument(QJsonObject{{"status", "ok"}, {"data", data}}).toJson(QJsonDocument::Compact);
          }
          QPointer<QTcpSocket> guard(socket);
          QTimer::singleShot(reply.delay, socket, [guard, reply] {
            if (!guard) return;
            QByteArray headers = "HTTP/1.1 " + QByteArray::number(reply.status) + (reply.status == 200 ? " OK" : " Error")
                + "\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n";
            if (!reply.filename.isEmpty()) headers += "Content-Disposition: attachment; filename=\"" + reply.filename + "\"\r\n";
            guard->write(headers + "Content-Length: " + QByteArray::number(reply.bytes.size()) + "\r\n\r\n" + reply.bytes);
            guard->disconnectFromHost();
          });
        });
      }
    });
  }
};

void prepare(TaskResultsPanel &panel, const QString &task = "A")
{
  panel.clearTaskContext();
  panel.m_pipelineId = task;
  panel.m_expectedRunId = "run-" + task;
  panel.m_target = task + ".invalid";
  panel.m_snapshot = {{"pipeline_id", task}, {"owner", "fixture-user"}, {"target", task + ".invalid"}};
  panel.m_tabs->setCurrentWidget(panel.m_reports);
  panel.m_reports->blockSignals(true);
  panel.m_reports->setRowCount(2);
  for (int row = 0; row < 2; ++row) {
    const QString id = row == 0 ? "trace-" + task : "other-" + task;
    auto *item = new QTableWidgetItem(id);
    auto metadata = reportDocument(task, id).value("report").toObject();
    metadata.remove("content");
    item->setData(Qt::UserRole, metadata);
    panel.m_reports->setItem(row, 0, item);
  }
  panel.m_reports->selectRow(0);
  panel.m_reports->blockSignals(false);
  panel.m_selectedReportId = "trace-" + task;
  panel.m_report = reportDocument(task, panel.m_selectedReportId);
  panel.m_reportMetadata = panel.m_report.value("report").toObject();
  panel.m_reportMetadata.remove("content");
  panel.m_fresh = true;
  panel.updateButtons();
}

QByteArray readFile(const QString &path)
{
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) return {};
  return file.readAll();
}

bool writeFile(const QString &path, const QByteArray &bytes, bool executable = false)
{
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size()) return false;
  file.close();
  return !executable || file.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
}

QStringList launchedPaths(const QString &log)
{
  QStringList paths;
  const auto lines = QString::fromUtf8(readFile(log)).split('\n', Qt::SkipEmptyParts);
  for (int index = 0; index + 1 < lines.size(); index += 2) {
    if (lines[index] != "1") return {};
    paths.append(lines[index + 1]);
  }
  return paths;
}
} // namespace

class TaskReportExportChecks : public QObject {
  Q_OBJECT
private slots:
  void formatsAndAtomicSave()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    QTemporaryDir files; QVERIFY(files.isValid());
    QCOMPARE(panel.m_formatCombo->currentData().toString(), QString("docx"));
    QCOMPARE(panel.m_formatCombo->count(), 4);
    QCOMPARE(panel.m_formatCombo->itemText(0), QStringLiteral("DOCX"));
    QCOMPARE(panel.m_formatCombo->itemText(3), QStringLiteral("JSON（完整快照）"));
    for (const auto &format : {"docx", "pdf", "html", "json"}) {
      panel.m_formatCombo->setCurrentIndex(panel.m_formatCombo->findData(format));
      QCOMPARE(panel.m_openWps->isEnabled(), (QStringList{"docx", "pdf"}.contains(format)));
      const QString path = files.filePath(QString("report.") + format);
      panel.downloadReport(format, path, false);
      QTRY_VERIFY(!panel.m_exporting);
      QCOMPARE(readFile(path), content(format));
      QVERIFY(panel.m_exportResult->text().contains(QString(format) == "json"
          ? QStringLiteral("完整保存快照") : QStringLiteral("攻击测试简报")));
      QVERIFY(panel.m_export->isEnabled());
    }
    QCOMPARE(server.exports, 4);
    auto legacy = panel.m_report.value("report").toObject(); legacy["kind"] = "legacy"; panel.m_report["report"] = legacy;
    panel.updateButtons(); QVERIFY(!panel.m_export->isEnabled()); QVERIFY(!panel.m_openWps->isEnabled());
  }

  void selectedReportRendersSavedPresentation()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    QJsonObject selectedDocument;
    server.reportResponse = [&](const QString &task, const QString &id) {
      auto document = reportDocument(task, id);
      auto report = document.value("report").toObject();
      auto savedContent = report.value("content").toObject();
      auto savedResults = savedContent.value("results").toObject();
      savedResults["assessment"] = QJsonObject{{"notice", "RAW_ASSESSMENT_MARKER"}};
      savedResults["statistics"] = QJsonObject{{"raw_statistics", "RAW_STATISTICS_MARKER"}};
      savedContent["results"] = savedResults;
      report["content"] = savedContent;
      document["report"] = report;
      document["presentation"] = reportPresentation();
      selectedDocument = document;
      return document;
    };
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.m_reports->selectRow(1);
    QTRY_VERIFY(server.reportReads > 0 && !panel.m_report.isEmpty());
    panel.m_reports->selectRow(0);
    QTRY_VERIFY(server.reportReads > 1 && panel.m_selectedReportId == "trace-A" && !panel.m_report.isEmpty());
    const QString detail = panel.m_detail->toPlainText();
    for (const auto &text : {"任务攻击测试结果报告", "本次攻击测试概况", "逐漏洞攻击效果表", "攻击测试结论",
                            "请求目录并检查响应", "观察到目录清单", "作用仅限此路径", "目标已达成", "未开展适用验证"})
      QVERIFY(detail.contains(QString::fromUtf8(text)));
    QVERIFY(detail.contains("<b>未实施候选</b>"));
    for (const auto &raw : {"RAW_ASSESSMENT_MARKER", "RAW_STATISTICS_MARKER", "source_fingerprint", "schema_version", "provenance"})
      QVERIFY(!detail.contains(raw));
    const QByteArray frozen = QJsonDocument(panel.m_report).toJson();
    panel.m_snapshot["statistics"] = QJsonObject{{"confirmed_instances", 999}, {"notice", "CURRENT_STATISTICS_MARKER"}};
    panel.m_snapshot["assessment"] = QJsonObject{{"notice", "CURRENT_ASSESSMENT_MARKER"}};
    panel.m_snapshot["findings"] = QJsonArray{QJsonObject{{"name", "CURRENT_FINDING_MARKER"}}};
    panel.renderDetail();
    QCOMPARE(panel.m_detail->toPlainText(), detail);
    QCOMPARE(QJsonDocument(panel.m_report).toJson(), frozen);

    server.response = [selectedDocument](const QString &format) {
      return Reply{format == "json" ? QJsonDocument(selectedDocument).toJson() : content(format),
        ("report_trace-A." + format).toUtf8()};
    };
    panel.m_formatCombo->setCurrentIndex(panel.m_formatCombo->findData("json"));
    QTemporaryDir files; const QString path = files.filePath("snapshot.json");
    panel.downloadReport("json", path, false); QTRY_VERIFY(!panel.m_exporting);
    const QByteArray json = readFile(path);
    QVERIFY(json.contains("RAW_ASSESSMENT_MARKER")); QVERIFY(json.contains("RAW_STATISTICS_MARKER"));
    QVERIFY(!json.contains("CURRENT_STATISTICS_MARKER"));
    QVERIFY(panel.m_exportResult->text().contains(QStringLiteral("完整保存快照")));
  }

  void missingPresentationRemainsCompatible()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.m_snapshot["statistics"] = QJsonObject{{"confirmed_instances", 999}};
    panel.m_reports->selectRow(1);
    QTRY_VERIFY(server.reportReads > 0 && !panel.m_report.isEmpty());
    QVERIFY(panel.m_detail->toPlainText().contains(QStringLiteral("详细攻击效果未提供，请刷新或更新后端")));
    QVERIFY(panel.m_detail->toPlainText().contains("Frozen fixture"));
    QVERIFY(!panel.m_detail->toPlainText().contains("999"));
    QVERIFY(!panel.m_detail->toPlainText().contains("source_fingerprint"));
    QVERIFY(panel.m_export->isEnabled());
    auto report = panel.m_report.value("report").toObject();
    report["kind"] = "legacy";
    report["content"] = QJsonObject{{"notice", "旧报告缺少来源；原结论未重新验证"}};
    panel.m_report["report"] = report; panel.renderDetail();
    QVERIFY(panel.m_detail->toPlainText().contains(QStringLiteral("旧报告缺少来源；原结论未重新验证")));
    QVERIFY(!panel.m_detail->toPlainText().contains(QStringLiteral("详细攻击效果未提供")));
  }

  void saveDialogCancelAndAccept()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    QTemporaryDir files; const QString path = files.filePath("chosen.docx");
    bool cancel = true, visited = false;
    QTimer dialogs;
    connect(&dialogs, &QTimer::timeout, &panel, [&] {
      if (auto *dialog = qobject_cast<QFileDialog *>(QApplication::activeModalWidget())) {
        if (visited) return;
        visited = true;
        if (cancel) dialog->reject();
        else {
          // selectFile() does not reliably replace the preselected filename on
          // an already visible non-native dialog. Simulate the filename edit.
          auto *filename = dialog->findChild<QLineEdit *>("fileNameEdit");
          QVERIFY(filename);
          filename->setText(path);
          QMetaObject::invokeMethod(dialog, "accept", Qt::QueuedConnection);
        }
      }
    });
    dialogs.start(10);
    panel.m_export->click();
    QVERIFY(visited); QCOMPARE(server.exports, 0); QVERIFY(!QFileInfo::exists(path));
    cancel = false; visited = false;
    panel.m_export->click();
    QTRY_VERIFY(!panel.m_exporting);
    dialogs.stop();
    QVERIFY(visited); QCOMPARE(server.exports, 1); QCOMPARE(readFile(path), content("docx"));
  }

  void rejectsInvalidDownload_data()
  {
    QTest::addColumn<QString>("format");
    QTest::addColumn<QByteArray>("bytes");
    QTest::addColumn<QByteArray>("filename");
    QTest::addColumn<int>("status");
    QTest::newRow("empty") << QString("docx") << QByteArray{} << QByteArray("report_trace-A.docx") << 200;
    QTest::newRow("json-error-as-pdf") << QString("pdf") << QByteArray("{\"status\":\"error\"}") << QByteArray("report_trace-A.pdf") << 200;
    QTest::newRow("html-as-docx") << QString("docx") << QByteArray("<html>error</html>") << QByteArray("report_trace-A.docx") << 200;
    QTest::newRow("wrong-filename") << QString("docx") << content("docx") << QByteArray("../report_trace-A.docx") << 200;
    QTest::newRow("missing-filename") << QString("docx") << content("docx") << QByteArray{} << 200;
    QTest::newRow("http-failure") << QString("pdf") << content("pdf") << QByteArray("report_trace-A.pdf") << 500;
    QTest::newRow("foreign-json") << QString("json") << QJsonDocument(reportDocument("B", "trace-A")).toJson()
      << QByteArray("report_trace-A.json") << 200;
    QTest::newRow("too-large") << QString("docx") << (QByteArray::fromHex("504b0304") + QByteArray(16 * 1024 * 1024, 'x'))
      << QByteArray("report_trace-A.docx") << 200;
  }

  void rejectsInvalidDownload()
  {
    QFETCH(QString, format); QFETCH(QByteArray, bytes); QFETCH(QByteArray, filename); QFETCH(int, status);
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    server.response = [&](const QString &) { return Reply{bytes, filename, status}; };
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.m_formatCombo->setCurrentIndex(panel.m_formatCombo->findData(format));
    QTemporaryDir files; const QString path = files.filePath("existing." + format);
    QVERIFY(writeFile(path, "existing file"));
    panel.downloadReport(format, path, false);
    QTRY_VERIFY(!panel.m_exporting);
    QCOMPARE(readFile(path), QByteArray("existing file"));
    QVERIFY(panel.m_exportResult->text().contains(QStringLiteral("未写入文件")));
    if (QString::fromLatin1(QTest::currentDataTag()) == "too-large")
      QVERIFY(panel.m_exportResult->text().contains(QStringLiteral("16 MiB")));
    QVERIFY(panel.m_export->isEnabled());
  }

  void writeFailureIsRetryable()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    QTemporaryDir files;
    panel.downloadReport("docx", files.filePath("missing/report.docx"), false);
    QTRY_VERIFY(!panel.m_exporting);
    QVERIFY(panel.m_exportResult->text().contains(QStringLiteral("无法写入")));
    QVERIFY(panel.m_export->isEnabled());
    const QString path = files.filePath("retry.docx");
    panel.downloadReport("docx", path, false);
    QTRY_VERIFY(!panel.m_exporting);
    QCOMPARE(readFile(path), content("docx"));
  }

  void readableDownloadErrors_data()
  {
    QTest::addColumn<int>("status");
    QTest::addColumn<QByteArray>("body");
    QTest::addColumn<QString>("expected");
    QTest::newRow("server-size-limit") << 413
      << QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "报告文件超过 16 MiB 导出上限，请尝试其他导出格式"}}}}).toJson()
      << QStringLiteral("报告文件超过 16 MiB");
    QTest::newRow("missing-font") << 500
      << QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "PDF 中文字体加载失败，请检查报告字体文件后重试"}}}}).toJson()
      << QStringLiteral("PDF 中文字体加载失败");
    QTest::newRow("permission-denied") << 403
      << QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "没有权限查看此任务结果或报告"}}}}).toJson()
      << QStringLiteral("没有权限");
    QTest::newRow("html-error") << 502 << QByteArray("<html><body>Raw error body must not be shown</body></html>") << QString("HTTP 502");
    QTest::newRow("plain-error") << 503 << QByteArray("Raw error body must not be shown") << QString("HTTP 503");
    QTest::newRow("oversized-error-json") << 500
      << QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "Raw error body must not be shown"}, {"padding", QString(70 * 1024, 'x')}}}}).toJson()
      << QString("HTTP 500");
    QTest::newRow("non-string-message") << 500
      << QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", QJsonObject{{"raw", "Raw error body must not be shown"}}}}}}).toJson()
      << QString("HTTP 500");
    QTest::newRow("literal-and-bounded-message") << 500
      << QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "<b>plain message</b>" + QString(1000, 'x')}}},
                                  {"sensitive_body", "Raw error body must not be shown"}}).toJson()
      << QString("<b>plain message</b>");
  }

  void readableDownloadErrors()
  {
    QFETCH(int, status); QFETCH(QByteArray, body); QFETCH(QString, expected);
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    server.response = [&](const QString &) { return Reply{body, "server_error.pdf", status}; };
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    QSignalSpy errors(&api, &ApiClient::apiError);
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.m_formatCombo->setCurrentIndex(panel.m_formatCombo->findData("pdf"));
    QTemporaryDir files; const QString path = files.filePath("existing.pdf"); QVERIFY(writeFile(path, "old file"));
    panel.downloadReport("pdf", path, false);
    QTRY_VERIFY(!panel.m_exporting);
    QVERIFY(panel.m_exportResult->text().contains(expected));
    QVERIFY(panel.m_exportResult->text().contains(QStringLiteral("报告下载失败")));
    QVERIFY(!panel.m_exportResult->text().contains(QStringLiteral("来源校验失败")));
    QVERIFY(!panel.m_exportResult->text().contains("Raw error body"));
    QVERIFY(panel.m_exportResult->text().size() < 600);
    QCOMPARE(panel.m_exportResult->textFormat(), Qt::PlainText);
    QVERIFY(panel.m_exportResult->wordWrap());
    QVERIFY(panel.m_exportResult->textInteractionFlags().testFlag(Qt::TextSelectableByMouse));
    QCOMPARE(readFile(path), QByteArray("old file"));
    QCOMPARE(errors.size(), 1);
    const QString emitted = errors.first().at(1).toString();
    QVERIFY(emitted.contains(expected)); QVERIFY(!emitted.contains("Raw error body")); QVERIFY(emitted.size() <= 512);
  }

  void legacyDownloadCallbackRemainsCompatible()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    bool finished = false, ok = false; QByteArray bytes; QString filename;
    const auto callback = [&](bool success, const QByteArray &data, const QString &name) {
      ok = success; bytes = data; filename = name; finished = true;
    };
    api.download("/api/pipelines/A/results/reports/trace-A/export?format=docx", 30000, callback);
    QTRY_VERIFY(finished); QVERIFY(ok); QCOMPARE(bytes, content("docx")); QCOMPARE(filename, QString("report_trace-A.docx"));
    server.response = [](const QString &) {
      return Reply{QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "fixture denied"}}}}).toJson(), "error.docx", 403};
    };
    finished = false;
    api.download("/api/pipelines/A/results/reports/trace-A/export?format=docx", 30000, callback);
    QTRY_VERIFY(finished); QVERIFY(!ok); QVERIFY(bytes.isEmpty()); QVERIFY(filename.isEmpty());
  }

  void networkFailureHasNoFilePayload()
  {
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    connect(&server, &QTcpServer::newConnection, &server, [&] {
      while (server.hasPendingConnections()) {
        auto *socket = server.nextPendingConnection();
        socket->abort(); socket->deleteLater();
      }
    });
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    bool finished = false, success = true; QByteArray bytes; QString filename, error;
    api.downloadWithError("/isolated-network-error", 30000,
      [&](bool ok, const QByteArray &data, const QString &name, const QString &message) {
        success = ok; bytes = data; filename = name; error = message; finished = true;
      });
    QTRY_VERIFY(finished); QVERIFY(!success); QVERIFY(bytes.isEmpty()); QVERIFY(filename.isEmpty());
    QVERIFY(error.contains(QStringLiteral("网络下载失败")));
  }

  void exportResultSurvivesRealRefreshTimer()
  {
    QTemporaryDir files; const QString executable = files.filePath("broken-wps");
    QVERIFY(writeFile(executable, "#!/no-such-report-interpreter\n", true));
    EnvironmentValue wps("WPS_PATH", executable.toUtf8());
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.resize(1000, 700); panel.show();
    QTRY_VERIFY(server.resultReads >= 1 && panel.m_fresh && !panel.m_busy && !panel.m_report.isEmpty());
    QVERIFY(panel.validSnapshot(panel.m_snapshot));
    panel.m_timer->setInterval(50); panel.m_timer->start();
    QSignalSpy ticks(panel.m_timer, &QTimer::timeout);
    panel.openInWps(); QTRY_VERIFY(!panel.m_exporting);
    const QString retained = panel.m_exportResult->text();
    QVERIFY(retained.contains(QStringLiteral("无法启动 WPS")));
    const QString saved = retained.split('\n').value(1);
    QCOMPARE(readFile(saved), content("docx"));
    int reads = server.resultReads, tickCount = ticks.size();
    QTRY_VERIFY(server.resultReads >= reads + 2 && ticks.size() >= tickCount + 2 && !panel.m_busy);
    QCOMPARE(panel.m_exportResult->text(), retained);
    QVERIFY(panel.m_fresh); QVERIFY(panel.validSnapshot(panel.m_snapshot));
    QVERIFY(!panel.m_state->text().contains(saved));

    server.response = [](const QString &) {
      return Reply{QJsonDocument(QJsonObject{{"error", QJsonObject{{"message", "PDF 中文字体加载失败"}}}}).toJson(), {}, 500};
    };
    panel.downloadReport("docx", files.filePath("failure.docx"), false);
    QVERIFY(panel.m_exportResult->text().isEmpty());
    QTRY_VERIFY(!panel.m_exporting);
    const QString failure = panel.m_exportResult->text(); QVERIFY(failure.contains(QStringLiteral("PDF 中文字体加载失败")));
    reads = server.resultReads; tickCount = ticks.size();
    QTRY_VERIFY(server.resultReads >= reads + 2 && ticks.size() >= tickCount + 2 && !panel.m_busy);
    QCOMPARE(panel.m_exportResult->text(), failure);
    panel.m_timer->stop();

    panel.m_formatCombo->setCurrentIndex(1); QVERIFY(panel.m_exportResult->text().isEmpty());
    panel.m_exportResult->setText("old selection result");
    panel.m_reports->selectRow(1); QVERIFY(panel.m_exportResult->text().isEmpty());
    QTRY_VERIFY(!panel.m_report.isEmpty());
    panel.m_exportResult->setText("old linked result");
    panel.showReport("trace-A"); QVERIFY(panel.m_exportResult->text().isEmpty());
    QTRY_VERIFY(!panel.m_report.isEmpty());
    panel.m_exportResult->setText("old task result");
    panel.setTaskContext("B", "run-B", "B.invalid"); QVERIFY(panel.m_exportResult->text().isEmpty());
    panel.m_timer->stop();
    QTRY_VERIFY(!panel.m_busy);
    panel.m_exportResult->setText("clear context result");
    panel.clearTaskContext(); QVERIFY(panel.m_exportResult->text().isEmpty());
  }

  void taskAndReportRoundTripsDiscardLateDownloads()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost)); server.delay = 180;
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    QTemporaryDir files; const QString taskPath = files.filePath("task.docx");
    panel.downloadReport("docx", taskPath, false);
    QTRY_COMPARE(server.exports, 1);
    prepare(panel, "B"); prepare(panel, "A");
    panel.m_exportResult->setText("Current task message");
    QTest::qWait(230); QVERIFY(!QFileInfo::exists(taskPath)); QVERIFY(!panel.m_exporting);
    QCOMPARE(panel.m_exportResult->text(), QString("Current task message"));
    const QString reportPath = files.filePath("selection.docx");
    panel.downloadReport("docx", reportPath, false);
    QTRY_COMPARE(server.exports, 2);
    panel.m_reports->selectRow(1); panel.m_reports->selectRow(0);
    QTRY_VERIFY(!panel.m_report.isEmpty());
    panel.m_exportResult->setText("Current selection message");
    QTest::qWait(230);
    QCOMPARE(panel.m_selectedReportId, QString("trace-A")); QVERIFY(!QFileInfo::exists(reportPath));
    QCOMPARE(panel.m_exportResult->text(), QString("Current selection message"));
    QVERIFY(panel.m_export->isEnabled());
  }

  void formatRoundTripDoesNotClearNewRequest()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost)); server.delay = 160;
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    QTemporaryDir files; const QString oldPath = files.filePath("old.docx"), newPath = files.filePath("new.docx");
    panel.downloadReport("docx", oldPath, false);
    panel.downloadReport("docx", oldPath, false);
    panel.openInWps();
    QTRY_COMPARE(server.exports, 1);
    panel.m_formatCombo->setCurrentIndex(1); panel.m_formatCombo->setCurrentIndex(0);
    server.delay = 400;
    panel.downloadReport("docx", newPath, false);
    QTRY_COMPARE(server.exports, 2);
    panel.m_exportResult->setText("New download in progress");
    QTest::qWait(200); QVERIFY(panel.m_exporting); QVERIFY(!QFileInfo::exists(oldPath));
    QCOMPARE(panel.m_exportResult->text(), QString("New download in progress"));
    QTRY_VERIFY(!panel.m_exporting); QCOMPARE(readFile(newPath), content("docx"));
  }

  void destroyedPanelCannotWrite()
  {
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost)); server.delay = 160;
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    auto *panel = new TaskResultsPanel(&api, "user", "fixture-user"); prepare(*panel);
    QTemporaryDir files; const QString path = files.filePath("destroyed.docx");
    panel->downloadReport("docx", path, false);
    QTRY_COMPARE(server.exports, 1); delete panel;
    QTest::qWait(220); QVERIFY(!QFileInfo::exists(path));
  }

  void wpsUsesFreshIndependentCopiesAndSurvivesPageExit()
  {
    QTemporaryDir files; QVERIFY(files.isValid());
    const QString executable = files.filePath("fake wps"), log = files.filePath("opened.log");
    QVERIFY(writeFile(executable, "#!/bin/sh\nprintf '%s\\n' \"$#\" \"$1\" >> \"$REPORT_WPS_LOG\"\n", true));
    EnvironmentValue wps("WPS_PATH", executable.toUtf8()), logPath("REPORT_WPS_LOG", log.toUtf8());
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    auto *panel = new TaskResultsPanel(&api, "user", "fixture-user"); prepare(*panel);
    panel->openInWps();
    QTRY_COMPARE(launchedPaths(log).size(), 1);
    const QString first = launchedPaths(log).first();
    QCOMPARE(readFile(first), content("docx"));
    QVERIFY(writeFile(first, "WPS local edits"));
    panel->openInWps();
    QTRY_COMPARE(launchedPaths(log).size(), 2);
    const QString second = launchedPaths(log).last();
    QVERIFY(first != second); QCOMPARE(readFile(first), QByteArray("WPS local edits")); QCOMPARE(readFile(second), content("docx"));
    panel->m_formatCombo->setCurrentIndex(1); panel->openInWps();
    QTRY_COMPARE(launchedPaths(log).size(), 3);
    const QString third = launchedPaths(log).last(); QVERIFY(third.endsWith(".pdf")); QCOMPARE(readFile(third), content("pdf"));
    QCOMPARE(server.exports, 3);
    delete panel;
    QVERIFY(QFileInfo::exists(first)); QVERIFY(QFileInfo::exists(second)); QVERIFY(QFileInfo::exists(third));
  }

  void lateAndInvalidWpsNeverLaunch()
  {
    QTemporaryDir files; const QString executable = files.filePath("fake-wps"), log = files.filePath("opened.log");
    QVERIFY(writeFile(executable, "#!/bin/sh\nprintf '%s\\n' \"$#\" \"$1\" >> \"$REPORT_WPS_LOG\"\n", true));
    EnvironmentValue wps("WPS_PATH", executable.toUtf8()), logPath("REPORT_WPS_LOG", log.toUtf8());
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost)); server.delay = 160;
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.openInWps(); QTRY_COMPARE(server.exports, 1);
    panel.m_formatCombo->setCurrentIndex(1); panel.m_formatCombo->setCurrentIndex(0);
    QTest::qWait(220); QVERIFY(!QFileInfo::exists(log));
    server.response = [](const QString &) { return Reply{"invalid file", "report_trace-A.docx"}; };
    panel.openInWps(); QTRY_VERIFY(!panel.m_exporting);
    QVERIFY(!QFileInfo::exists(log));
    server.response = {}; panel.openInWps(); QTRY_COMPARE(server.exports, 3);
    prepare(panel, "B"); prepare(panel, "A");
    QTest::qWait(220); QVERIFY(!QFileInfo::exists(log));
  }

  void failedWpsStartRetainsSavedCopy()
  {
    QTemporaryDir files; const QString executable = files.filePath("broken-wps");
    QVERIFY(writeFile(executable, "#!/no-such-report-interpreter\n", true));
    EnvironmentValue wps("WPS_PATH", executable.toUtf8());
    ExportServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    ApiClient api("http://127.0.0.1:" + QString::number(server.serverPort()));
    TaskResultsPanel panel(&api, "user", "fixture-user"); prepare(panel);
    panel.openInWps(); QTRY_VERIFY(!panel.m_exporting);
    QVERIFY(panel.m_exportResult->text().contains(QStringLiteral("无法启动 WPS")));
    const auto lines = panel.m_exportResult->text().split('\n');
    QVERIFY(lines.size() >= 2); QCOMPARE(readFile(lines[1]), content("docx"));
    QVERIFY(panel.m_openWps->isEnabled());
  }

  void absentOrNonExecutableWpsDoesNotLoseFile()
  {
    QTemporaryDir files; const QString executable = files.filePath("not-executable"), document = files.filePath("report.pdf");
    QVERIFY(writeFile(executable, "not a program")); QVERIFY(writeFile(document, content("pdf")));
    EnvironmentValue wps("WPS_PATH", executable.toUtf8()), path("PATH", ""), wsl("WSL_DISTRO_NAME", "");
    // Never launch a machine's real Office while running an isolated regression.
    if (!ReportFileActions::findWpsExecutable().isEmpty()) QSKIP("System WPS exists; missing-installation scenario is unavailable");
    const auto result = ReportFileActions::openInWps(document);
    QVERIFY(result.status == ReportFileActions::OpenStatus::NotFound);
    QVERIFY(result.message.contains(document)); QCOMPARE(readFile(document), content("pdf"));
  }
};

int main(int argc, char **argv)
{
  QTemporaryDir isolated; if (!isolated.isValid()) return 1;
  EnvironmentValue cache("XDG_CACHE_HOME", isolated.path().toUtf8()), config("XDG_CONFIG_HOME", isolated.path().toUtf8());
  QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("RedTeamTests");
  QCoreApplication::setApplicationName("TaskReportExportChecks");
  TaskReportExportChecks checks;
  return QTest::qExec(&checks, argc, argv);
}
#include "task_report_export_checks.moc"
