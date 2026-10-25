#include "models/SourceScanTypes.h"
#include "services/source_scan/SourceScanStore.h"
#include "services/source_scan/SourceScanService.h"
#include "services/pentagi/PentagiService.h"
#include "config/ConfigManager.h"
#include "ui/pages/source_scan/SourceScanPage.h"
#include <QApplication>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QLabel>
#include <QFileInfo>
#include <QFontDatabase>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QSysInfo>
#include <QDateTime>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QSqlQuery>
#include <QSqlError>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTest>
#include <QTextBrowser>
#include <QTimer>
#include <QTreeWidget>

namespace {
bool writeFile(const QString &path, const QByteArray &data) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(data) == data.size();
}
QJsonObject finding(const QString &path) {
    return {{"path", path},
            {"line", 2},
            {"endLine", 2},
            {"severity", "high"},
            {"title", QStringLiteral("不安全的输入复制")},
            {"cwe", "CWE-120"},
            {"description", QStringLiteral("测试审计结果：未检查长度。")},
            {"evidence", "strcpy(dst, input);"},
            {"recommendation", QStringLiteral("进行边界检查。")}};
}
QString parsedReply(const QString &path) {
    return QString::fromUtf8(QJsonDocument(QJsonObject{{"findings", QJsonArray{finding(path)}}}).toJson());
}
class FakeBackend : public QTcpServer {
  public:
    FakeBackend() {
        connect(this, &QTcpServer::newConnection, this, [this]() {
            while (hasPendingConnections()) {
                auto *socket = nextPendingConnection();
                auto buffer = std::make_shared<QByteArray>();
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, this, [this, socket, buffer]() {
                    *buffer += socket->readAll();
                    const int boundary = buffer->indexOf("\r\n\r\n");
                    if (boundary < 0)
                        return;
                    const QByteArray header = buffer->left(boundary);
                    int length = 0;
                    for (const auto &line : header.split('\n'))
                        if (line.toLower().startsWith("content-length:"))
                            length = line.mid(15).trimmed().toInt();
                    if (buffer->size() < boundary + 4 + length)
                        return;
                    const auto request = QJsonDocument::fromJson(buffer->mid(boundary + 4, length)).object();
                    const auto response = handle(request);
                    const QByteArray body = QJsonDocument(response).toJson(QJsonDocument::Compact);
                    socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: "
                                  "close\r\nContent-Length: " +
                                  QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        listen(QHostAddress::LocalHost, 0);
    }
    QString url() const {
        return QStringLiteral("http://127.0.0.1:%1/api/v1/graphql").arg(serverPort());
    }
    QString parserUrl() const {
        return QStringLiteral("http://127.0.0.1:%1/v1").arg(serverPort());
    }
    int creates = 0, puts = 0, assistantCreates = 0, calls = 0, parses = 0, requests = 0, assistantPolls = 0;
    bool flowCreated = false, loseCreate = false, losePut = false, loseAssistant = false, loseCall = false;
    bool parserFails = false, invalidParse = false, flowFinished = false;
    int delayedAssistantPolls = 0, pendingAssistantPolls = 0;
    QString pendingAssistantMessage;
    QStringList sourceInputs;
    QStringList assistantProviders;
    QJsonArray logs;
    QString sourcePath;
    QJsonObject flow() const {
        return {
            {"id", "flow-1"}, {"title", "source test"}, {"status", flowFinished ? "finished" : "running"}};
    }
    QJsonObject assistant() const {
        return {{"id", "assistant-1"}, {"flowId", "flow-1"}, {"status", "waiting"}};
    }
    void appendAssistantReply(const QString &message) {
        logs << QJsonObject{{"id", QString::number(logs.size() + 1)},
                            {"type", "assistant"},
                            {"message", message},
                            {"createdAt", QString::number(logs.size() + 1).rightJustified(4, '0')}};
    }
    void addReply(const QString &input, bool delay = false) {
        logs << QJsonObject{{"id", QString::number(logs.size() + 1)},
                            {"type", "user"},
                            {"message", input},
                            {"createdAt", QString::number(logs.size() + 1).rightJustified(4, '0')}};
        pendingAssistantMessage =
            QStringLiteral("已发现源码漏洞 %1:2，证据 strcpy(dst, input);，修复应检查长度。").arg(sourcePath);
        if (delay && delayedAssistantPolls > 0) {
            pendingAssistantPolls = delayedAssistantPolls;
        } else {
            appendAssistantReply(pendingAssistantMessage);
            pendingAssistantMessage.clear();
        }
    }
    QJsonObject handle(const QJsonObject &r) {
        ++requests;
        const QString op = r["operationName"].toString();
        const auto v = r["variables"].toObject();
        QJsonObject data;
        const QJsonObject lost{
            {"errors", QJsonArray{QJsonObject{{"message", "simulated uncertain response"}}}}};
        if (r.contains("messages")) {
            ++parses;
            if (parserFails)
                return {{"choices", QJsonArray{}}};
            const QString content = invalidParse ? QStringLiteral("not-json") : parsedReply(sourcePath);
            const QJsonObject message{{"content", content}};
            const QJsonObject choice{{"message", message}};
            return QJsonObject{{"choices", QJsonArray{choice}}};
        }
        if (op == "GetFlows")
            data["flows"] = flowCreated ? QJsonArray{flow()} : QJsonArray{};
        else if (op == "CreateFlow") {
            ++creates;
            flowCreated = true;
            sourceInputs << v["input"].toString();
            if (loseCreate) {
                loseCreate = false;
                return lost;
            }
            data["createFlow"] = flow();
        } else if (op == "PutUserInput") {
            ++puts;
            sourceInputs << v["input"].toString();
            if (losePut) {
                losePut = false;
                return lost;
            }
            data["putUserInput"] = "success";
        } else if (op == "GetFlowDetails") {
            QJsonArray tasks;
            for (int i = 0; i < sourceInputs.size(); ++i)
                tasks << QJsonObject{{"id", QString::number(i)}, {"input", sourceInputs[i]}};
            data["flow"] = flow();
            data["tasks"] = tasks;
        } else if (op == "GetFlowStats")
            data["flowStatsByFlow"] = QJsonObject{};
        else if (op == "GetAssistants")
            data["assistants"] = assistantCreates ? QJsonArray{assistant()} : QJsonArray{};
        else if (op == "CreateAssistant") {
            ++assistantCreates;
            assistantProviders << v.value(QStringLiteral("modelProvider")).toString();
            addReply(v["input"].toString());
            if (loseAssistant) {
                loseAssistant = false;
                return lost;
            }
            data["createAssistant"] = QJsonObject{{"assistant", assistant()}};
        } else if (op == "CallAssistant") {
            ++calls;
            addReply(v["input"].toString(), true);
            if (loseCall) {
                loseCall = false;
                return lost;
            }
            data["callAssistant"] = "success";
        } else if (op == "GetAssistantLogs") {
            ++assistantPolls;
            if (pendingAssistantPolls > 0 && --pendingAssistantPolls == 0) {
                appendAssistantReply(pendingAssistantMessage);
                pendingAssistantMessage.clear();
            }
            data["assistantLogs"] = logs;
        }
        else
            return {{"errors", QJsonArray{QJsonObject{{"message", "unexpected operation: " + op}}}}};
        return {{"data", data}};
    }
};
AppConfig configFor(const FakeBackend &backend) {
    AppConfig config{};
    config.pentagi.graphqlUrl = backend.url();
    config.pentagi.modelProvider = "custom";
    config.openaiCompatible.baseUrl = backend.parserUrl();
    config.openaiCompatible.model = "fake-model";
    config.openaiCompatible.apiKey = "test-only";
    config.openaiCompatible.contextLength = 8192;
    return config;
}
} // namespace
class SourceScanTests : public QObject {
    Q_OBJECT
  private slots:
    void assistantCreationRequiresConfiguredProvider() {
        PentagiService service;
        service.setConfig(PentagiConfig{});
        QString error;
        const FlowAssistantRecord assistant = service.createAssistant(
            QStringLiteral("flow-1"), QString(), QStringLiteral("test request"), false, &error);
        QVERIFY(assistant.id.isEmpty());
        QVERIFY(error.contains(QStringLiteral("Provider")));
    }

    void initTestCase() {
        const auto fontPath = QFINDTESTDATA("../src/resources/fonts/NotoSansCJK-Regular.ttc");
        const int id = QFontDatabase::addApplicationFont(fontPath);
        if (id >= 0) {
            const auto families = QFontDatabase::applicationFontFamilies(id);
            if (!families.isEmpty())
                qApp->setFont(QFont(families.first(), 10));
        }
    }
    void selectionAndSnapshots() {
        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());
        const auto root = tmp.path() + "/project";
        QVERIFY(writeFile(root + "/main.cpp", "int main() {}\n"));
        QVERIFY(writeFile(root + "/.hidden/auth.h", "// header\n"));
        QVERIFY(writeFile(root + "/ignore.hpp", "ignored"));
        QList<SourceScanFile> files;
        QString error;
        QVERIFY2(SourceScan::collectFiles({root, root + "/main.cpp"}, &files, &error), qPrintable(error));
        QCOMPARE(files.size(), 2);
        QCOMPARE(files[0].path, QString("project/.hidden/auth.h"));
        QCOMPARE(files[1].content, QString("int main() {}\n"));
        QVERIFY(writeFile(root + "/bad.cpp", QByteArray("\xff", 1)));
        QVERIFY(!SourceScan::collectFiles({root}, &files, &error));
        QVERIFY(files.isEmpty());
        QVERIFY(error.contains("UTF-8"));
        QFile::remove(root + "/bad.cpp");
        QVERIFY(!SourceScan::collectFiles({root + "/ignore.hpp"}, &files, &error));
        QCOMPARE(SourceScan::endpointAddress(" https://user:secret@example.test/graphql?tenant=one "),
                 QString("https://user:secret@example.test/graphql?tenant=one"));
        QVERIFY(writeFile(root + "/too-large.cpp", QByteArray(2 * 1024 * 1024 + 1, 'x')));
        QVERIFY(!SourceScan::collectFiles({root + "/too-large.cpp"}, &files, &error));
        QVERIFY(error.contains(QStringLiteral("限制")));
        QFile::remove(root + "/too-large.cpp");
#ifndef Q_OS_WIN
        QVERIFY(QFile::link(root + "/main.cpp", root + "/linked.cpp"));
        QVERIFY(!SourceScan::collectFiles({root}, &files, &error));
        QVERIFY(error.contains(QStringLiteral("符号链接")));
#endif
    }
    void batchingPreservesContents() {
        SourceScanTask task;
        task.id = "test";
        task.name = "chunk test";
        const QString content =
            QString(11999, 'a') + QString::fromUtf8("😀") + QString(25000, 'b') + "\nlast line\n";
        const auto batches = SourceScan::batches(
            task, {{"source/a.cpp", "unused", content}, {"source/empty.h", "unused", QStringLiteral("")}});
        QVERIFY(batches.size() > 3);
        QString reassembled;
        int currentLine = 1;
        for (int i = 0; i < batches.size(); ++i) {
            const auto input = batches[i];
            const int begin = input.indexOf('{'), end = input.lastIndexOf('}');
            const auto o = QJsonDocument::fromJson(input.mid(begin, end - begin + 1).toUtf8()).object();
            QVERIFY(!o.isEmpty());
            QVERIFY(input.contains(QStringLiteral("[SOURCE_BATCH:%1/%2]").arg(i + 1).arg(batches.size())));
            if (o["path"] == "source/a.cpp") {
                QCOMPARE(o["startLine"].toInt(), currentLine);
                const QString chunk = o["content"].toString();
                currentLine += chunk.count('\n');
                reassembled += chunk;
            }
        }
        QCOMPARE(reassembled, content);
        QVERIFY(batches.last().contains("SOURCE_SCAN_UPLOAD_COMPLETE"));
    }
    void strictParsingAndDedup() {
        const QList<SourceScanFile> files{
            {"project/test.cpp", "unused", "void f() {\nstrcpy(dst, input);\n}\n"}};
        QString error;
        QList<SourceScanFinding> findings;
        const auto o = finding(files.first().path);
        const auto json =
            QString::fromUtf8(QJsonDocument(QJsonObject{{"findings", QJsonArray{o, o}}}).toJson());
        QVERIFY2(SourceScan::parseFindings(json, files, &findings, &error), qPrintable(error));
        QCOMPARE(findings.size(), 1);
        QVERIFY(!findings.first().key.isEmpty());
        auto bad = o;
        bad["path"] = "../../secret";
        QVERIFY(!SourceScan::parseFindings(
            QString::fromUtf8(QJsonDocument(QJsonObject{{"findings", QJsonArray{o, bad}}}).toJson()), files,
            &findings, &error));
        QVERIFY(findings.isEmpty());
        bad = o;
        bad["line"] = 100;
        QVERIFY(!SourceScan::parseFindings(
            QString::fromUtf8(QJsonDocument(QJsonObject{{"findings", QJsonArray{bad}}}).toJson()), files,
            &findings, &error));
        QVERIFY(!SourceScan::parseFindings("{\"findings\":null}", files, &findings, &error));
        QVERIFY(SourceScan::parseFindings("{\"findings\":[]}", files, &findings, &error));
        QVERIFY(findings.isEmpty());
        QVERIFY(!SourceScan::parseFindings(QString(2 * 1024 * 1024 + 1, ' '), files, &findings, &error));
        QVERIFY(error.contains(QStringLiteral("2 MiB")));
    }
    void sqlitePersistenceAndRollback() {
        QTemporaryDir tmp;
        QString error;
        SourceScanTask task;
        task.id = "test";
        task.name = QStringLiteral("源码快照");
        task.createdAt = task.updatedAt = SourceScan::now();
        task.createPending = true;
        task.baselineFlows = QStringList{"old-flow"};
        task.pendingBatch = 2;
        QList<SourceScanFile> files{{"project/test.cpp", "original", "void f() {\nstrcpy(dst, input);\n}\n"}};
        QList<SourceScanFinding> findings;
        QVERIFY(SourceScan::parseFindings(parsedReply(files[0].path), files, &findings, &error));
        {
            SourceScanStore store(tmp.path());
            QVERIFY2(store.open(&error), qPrintable(error));
            QVERIFY2(store.create(task, files, &error), qPrintable(error));
            QVERIFY(store.merge(task.id, findings, "raw", "parsed", &error));
            QVERIFY(store.merge(task.id, findings, "raw", "parsed", &error));
            QCOMPARE(store.findings(task.id, &error).size(), 1);
            QVERIFY(!store.create(task, files, &error));
            error.clear();
            QCOMPARE(store.tasks(&error).size(), 1);
            QCOMPARE(store.files(task.id, &error).size(), 1);
            SourceScanTask duplicate;
            duplicate.id = "rollback";
            duplicate.updatedAt = task.updatedAt;
            QVERIFY(!store.create(duplicate, {files[0], files[0]}, &error));
            error.clear();
            QCOMPARE(store.tasks(&error).size(), 1);
        }
        {
            SourceScanStore store(tmp.path());
            QVERIFY(store.open(&error));
            const auto saved = store.task(task.id, &error);
            QVERIFY(saved.createPending);
            QCOMPARE(saved.baselineFlows, task.baselineFlows);
            QCOMPARE(saved.pendingBatch, 2);
            QCOMPARE(store.files(task.id, &error).first().content, files[0].content);
            QCOMPARE(store.findings(task.id, &error).size(), 1);
        }
        {
            auto db = QSqlDatabase::addDatabase("QSQLITE", "version-test");
            db.setDatabaseName(tmp.path() + "/source_scans.sqlite");
            QVERIFY(db.open());
            QSqlQuery q(db);
            QVERIFY(q.exec("PRAGMA user_version=99"));
        }
        QSqlDatabase::removeDatabase("version-test");
        {
            SourceScanStore store(tmp.path());
            QVERIFY(!store.open(&error));
            QVERIFY(error.contains(QStringLiteral("版本")));
        }
    }
    void sqlMigrationAndPlainEndpoint_data() {
        QTest::addColumn<int>("version");
        QTest::newRow("version-1") << 1;
        QTest::newRow("version-2") << 2;
    }
    void sqlMigrationAndPlainEndpoint() {
        QFETCH(int, version);
        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());
        const QString endpoint = QStringLiteral("https://scan.example/graphql?tenant=alpha&token=private");
        {
            const auto dbPath = tmp.path() + QStringLiteral("/source_scans.sqlite");
            const QString connection = QStringLiteral("legacy-fixture");
            {
                auto db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connection);
                db.setDatabaseName(dbPath);
                QVERIFY(db.open());
                QFile migration(QStringLiteral(":/source_scan/migrations/001_initial.sql"));
                QVERIFY(migration.open(QIODevice::ReadOnly));
                const auto statements =
                    QString::fromUtf8(migration.readAll()).split(QLatin1Char(';'), QString::SkipEmptyParts);
                QSqlQuery q(db);
                for (const auto &statement : statements) {
                    QStringList sqlLines;
                    for (const QString &line : statement.split(QLatin1Char('\n')))
                        if (!line.trimmed().startsWith(QStringLiteral("--")))
                            sqlLines << line;
                    const QString sql = sqlLines.join(QLatin1Char('\n')).trimmed();
                    if (!sql.isEmpty())
                        QVERIFY2(q.exec(sql), qPrintable(q.lastError().text()));
                }
                q.prepare(QStringLiteral("INSERT INTO tasks VALUES(?,?,?)"));
                q.addBindValue(QStringLiteral("legacy-task"));
                q.addBindValue(QString::fromUtf8(QJsonDocument(QJsonObject{
                    {"id", "legacy-task"}, {"name", "legacy"}, {"endpoint", endpoint},
                    {"status", "running"}, {"createdAt", SourceScan::now()},
                    {"updatedAt", SourceScan::now()}}).toJson(QJsonDocument::Compact)));
                q.addBindValue(SourceScan::now());
                QVERIFY2(q.exec(), qPrintable(q.lastError().text()));
                q.prepare(QStringLiteral("INSERT INTO tasks VALUES(?,?,?)"));
                q.addBindValue(QStringLiteral("old-hash-task"));
                q.addBindValue(QString::fromUtf8(QJsonDocument(QJsonObject{
                    {"id", "old-hash-task"}, {"name", "old hash"}, {"endpoint", "sha256:legacy"},
                    {"status", "running"}, {"createdAt", SourceScan::now()},
                    {"updatedAt", SourceScan::now()}}).toJson(QJsonDocument::Compact)));
                q.addBindValue(SourceScan::now());
                QVERIFY2(q.exec(), qPrintable(q.lastError().text()));
                QVERIFY(q.exec(QStringLiteral("PRAGMA user_version=%1").arg(version)));
                db.close();
            }
            QSqlDatabase::removeDatabase(connection);
            SourceScanStore store(tmp.path());
            QString error;
            QVERIFY2(store.open(&error), qPrintable(error));
            const auto task = store.task(QStringLiteral("legacy-task"), &error);
            QCOMPARE(task.id, QStringLiteral("legacy-task"));
            QCOMPARE(task.endpoint, endpoint);
            QCOMPARE(store.task(QStringLiteral("old-hash-task"), &error).endpoint, QString());
            QVERIFY(QFileInfo::exists(dbPath));
        }
        {
            const QString connection = QStringLiteral("verify-migrated-schema");
            {
                auto db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connection);
                db.setDatabaseName(tmp.path() + QStringLiteral("/source_scans.sqlite"));
                QVERIFY(db.open());
                QSqlQuery q(db);
                QVERIFY(q.exec(QStringLiteral("PRAGMA user_version")));
                QVERIFY(q.next());
                QCOMPARE(q.value(0).toInt(), 3);
                q.finish();
                db.close();
            }
            QSqlDatabase::removeDatabase(connection);
        }
    }
    void operationLockAndCrashRecovery() {
        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());
        const auto source = tmp.path() + "/test.cpp";
        QVERIFY(writeFile(source, "void f() {\nstrcpy(dst, input);\n}\n"));
        const auto dir = tmp.path() + "/new-config";
        FakeBackend backend;
        backend.sourcePath = "test.cpp";
        SourceScanService service(dir);
        QSignalSpy done(&service, &SourceScanService::finished);
        QSignalSpy created(&service, &SourceScanService::taskCreated);
        QVERIFY(service.start(configFor(backend), "lock test", {source}));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 1, 10000);
        QVERIFY2(done.last()[1].toString().isEmpty(), qPrintable(done.last()[1].toString()));
        QCOMPARE(created.size(), 1);
        const auto id = created.first()[0].toString();
        const auto lockPath = dir + "/source_scans.operation.lock";
        QVERIFY(!QFileInfo::exists(lockPath));
        {
            QLockFile held(lockPath);
            held.setStaleLockTime(0);
            QVERIFY(held.tryLock(0));
#ifndef Q_OS_WIN
            // Windows holds QLockFile exclusively; aging its open file is only
            // supported on Unix. Both platforms still verify exclusion below.
            QFile file(lockPath);
            QVERIFY(file.open(QIODevice::ReadWrite));
            QVERIFY(file.setFileTime(QDateTime::currentDateTimeUtc().addSecs(-120),
                                     QFileDevice::FileModificationTime));
            file.close();
#endif
            const int requests = backend.requests;
            QVERIFY(service.refresh(configFor(backend), id));
            QTRY_COMPARE_WITH_TIMEOUT(done.size(), 2, 10000);
            QVERIFY(done.last()[1].toString().contains(QStringLiteral("另一个")));
            QCOMPARE(backend.requests, requests);
            QVERIFY(QFileInfo::exists(lockPath));
        }
        // A nonexistent local owner simulates a process that crashed.
        QVERIFY(writeFile(lockPath, QByteArray("2147483647\npentagi-source-scan-crashed\n") +
                                       QSysInfo::machineHostName().toUtf8() + "\n"));
        QVERIFY(service.refresh(configFor(backend), id));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 3, 10000);
        QVERIFY2(done.last()[1].toString().isEmpty(), qPrintable(done.last()[1].toString()));
        QVERIFY(!QFileInfo::exists(lockPath));
        QCOMPARE(backend.creates, 1);
    }
    void flowAssistantAndFailures() {
        QTemporaryDir tmp;
        const auto source = tmp.path() + "/project/test.cpp";
        QVERIFY(writeFile(source, "void f() {\nstrcpy(dst, input);\n}\n"));
        FakeBackend backend;
        backend.sourcePath = "test.cpp";
        const auto config = configFor(backend);
        SourceScanService service(tmp.path());
        QSignalSpy done(&service, &SourceScanService::finished);
        QSignalSpy created(&service, &SourceScanService::taskCreated);
        QVERIFY(service.start(config, "audit", {source}));
        QVERIFY(!service.start(config, "duplicate", {source}));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 1, 10000);
        QCOMPARE(created.size(), 1);
        QVERIFY2(done[0][1].toString().isEmpty(), qPrintable(done[0][1].toString()));
        const QString id = created[0][0].toString();
        QCOMPARE(backend.creates, 1);
        QCOMPARE(backend.assistantCreates, 1);
        QCOMPARE(backend.assistantProviders, QStringList{QStringLiteral("custom")});
        QCOMPARE(backend.parses, 1);
        QVERIFY(backend.sourceInputs.first().contains("strcpy(dst, input)"));
        QString error;
        {
            SourceScanStore store(tmp.path());
            QVERIFY(store.open(&error));
            QCOMPARE(store.findings(id, &error).size(), 1);
        }
        QVERIFY(service.refresh(config, id));
        QVERIFY(!service.refresh(config, id));
        backend.delayedAssistantPolls = 3;
        const int pollsBefore = backend.assistantPolls;
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 2, 10000);
        QVERIFY2(done[1][1].toString().isEmpty(), qPrintable(done[1][1].toString()));
        QCOMPARE(backend.assistantCreates, 1);
        QCOMPARE(backend.calls, 1);
        QVERIFY(backend.assistantPolls - pollsBefore >= 4);
        backend.parserFails = true;
        QVERIFY(service.refresh(config, id));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 3, 10000);
        QVERIFY(!done[2][1].toString().isEmpty());
        const int calls = backend.calls;
        {
            SourceScanStore store(tmp.path());
            QVERIFY(store.open(&error));
            QCOMPARE(store.findings(id, &error).size(), 1);
        }
        backend.parserFails = false;
        QVERIFY(service.refresh(config, id));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 4, 10000);
        QVERIFY2(done[3][1].toString().isEmpty(), qPrintable(done[3][1].toString()));
        QCOMPARE(backend.calls, calls);
        auto other = config;
        other.pentagi.graphqlUrl = "http://127.0.0.1:1/wrong";
        const int requests = backend.requests;
        QVERIFY(service.refresh(other, id));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 5, 10000);
        QVERIFY(done[4][1].toString().contains(QStringLiteral("不同")));
        QCOMPARE(backend.requests, requests);
    }
    void uncertainOperationsResume_data() {
        QTest::addColumn<QString>("operation");
        QTest::newRow("flow") << "flow";
        QTest::newRow("batch") << "batch";
        QTest::newRow("assistant") << "assistant";
        QTest::newRow("call") << "call";
    }
    void uncertainOperationsResume() {
        QFETCH(QString, operation);
        QTemporaryDir tmp;
        const auto source = tmp.path() + "/long.cpp";
        QVERIFY(writeFile(source, "// test\nstrcpy(dst, input);\n" + QByteArray(15000, 'a')));
        FakeBackend backend;
        backend.sourcePath = "long.cpp";
        backend.loseCreate = operation == "flow";
        backend.losePut = operation == "batch";
        backend.loseAssistant = operation == "assistant";
        const auto config = configFor(backend);
        SourceScanService service(tmp.path());
        QSignalSpy done(&service, &SourceScanService::finished);
        QSignalSpy created(&service, &SourceScanService::taskCreated);
        QVERIFY(service.start(config, "resume", {source}));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 1, 10000);
        QCOMPARE(created.size(), 1);
        const QString id = created[0][0].toString();
        if (operation == "call") {
            QVERIFY(done[0][1].toString().isEmpty());
            backend.loseCall = true;
            QVERIFY(service.refresh(config, id));
            QTRY_COMPARE_WITH_TIMEOUT(done.size(), 2, 10000);
        }
        QVERIFY(!done.last()[1].toString().isEmpty());
        const int expected = done.size() + 1;
        QVERIFY(service.refresh(config, id));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), expected, 10000);
        QVERIFY2(done.last()[1].toString().isEmpty(), qPrintable(done.last()[1].toString()));
        QCOMPARE(backend.creates, 1);
        QCOMPARE(backend.assistantCreates, 1);
        QCOMPARE(backend.calls, operation == "call" ? 1 : 0);
        SourceScanTask t;
        t.id = id;
        t.name = "resume";
        QList<SourceScanFile> files;
        QString error;
        QVERIFY(SourceScan::collectFiles({source}, &files, &error));
        QCOMPARE(backend.puts, SourceScan::batches(t, files).size() - 1);
    }
    void autoRefreshAndManualGate() {
        QTemporaryDir tmp;
        const auto source = tmp.path() + "/test.cpp";
        QVERIFY(writeFile(source, "void f() {\nstrcpy(dst, input);\n}\n"));
        QDir().mkpath(tmp.path() + "/config");
        QVERIFY(writeFile(tmp.path() + "/config/default.json", "{}"));
        const auto old = QDir::currentPath();
        QDir::setCurrent(tmp.path());
        ConfigManager config;
        QVERIFY(config.initialize());
        QDir::setCurrent(old);
        FakeBackend backend;
        backend.sourcePath = "test.cpp";
        QVERIFY(config.saveUserConfig(configFor(backend)));
        SourceScanService service(config.configDirPath());
        QSignalSpy done(&service, &SourceScanService::finished);
        QSignalSpy created(&service, &SourceScanService::taskCreated);
        QVERIFY(service.start(config.currentConfig(), "timer test", {source}));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 1, 10000);
        const auto id = created.first()[0].toString();
        PentagiSourceScanDetailDialog dialog(&config, &service, id);
        dialog.show();
        auto *timer = dialog.findChild<QTimer *>("sourceScanAutoRefresh");
        QVERIFY(timer);
        QCOMPARE(timer->interval(), 1000);
        timer->stop();
        for (int i = 0; i < 299; ++i)
            QVERIFY(QMetaObject::invokeMethod(timer, "timeout"));
        QCOMPARE(backend.calls, 0);
        QVERIFY(QMetaObject::invokeMethod(timer, "timeout"));
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 2, 10000);
        QCOMPARE(backend.calls, 1);
        auto *button = dialog.findChild<QPushButton *>("sourceScanRefresh");
        QVERIFY(button);
        button->click();
        button->click();
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 3, 10000);
        QCOMPARE(backend.calls, 2);
        dialog.hide();
        for (int i = 0; i < 305; ++i)
            QVERIFY(QMetaObject::invokeMethod(timer, "timeout"));
        QCOMPARE(backend.calls, 2);
        backend.flowFinished = true;
        dialog.show();
        button->click();
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 4, 10000);
        const int calls = backend.calls;
        for (int i = 0; i < 305; ++i)
            QVERIFY(QMetaObject::invokeMethod(timer, "timeout"));
        QCOMPARE(backend.calls, calls);
        button->click();
        QTRY_COMPARE_WITH_TIMEOUT(done.size(), 5, 10000);
        QCOMPARE(backend.calls, calls + 1);
    }
    void mockTaskStaysOffline() {
        QTemporaryDir tmp;
        const QString old = QDir::currentPath();
        QDir().mkpath(tmp.path() + "/config");
        QVERIFY(writeFile(tmp.path() + "/config/default.json", "{}"));
        QVERIFY(QDir::setCurrent(tmp.path()));
        ConfigManager config;
        QVERIFY(config.initialize());
        QDir::setCurrent(old);
        SourceScanTask task;
        task.id = "mock-demo-test"; task.name = "Mock demo";
        task.endpoint = "mock://offline-demo"; task.status = "completed";
        task.flowStatus = "finished"; task.assistantState = "idle";
        task.error = "Mock fixture; no real scan";
        task.createdAt = task.updatedAt = task.lastRefresh = SourceScan::now();
        QString error;
        { SourceScanStore store(config.configDirPath());
          QVERIFY(store.open(&error));
          QVERIFY(store.create(task, {{"demo.cpp", "mock://demo.cpp", "int main() {}\n"}}, &error)); }
        SourceScanService service(config.configDirPath());
        PentagiSourceScanDetailDialog dialog(&config, &service, task.id);
        dialog.show();
        auto *button = dialog.findChild<QPushButton *>("sourceScanRefresh");
        QVERIFY(button && !button->isEnabled());
        auto *timer = dialog.findChild<QTimer *>("sourceScanAutoRefresh");
        for (int i = 0; i < 310; ++i) QVERIFY(QMetaObject::invokeMethod(timer, "timeout"));
        QVERIFY(!service.busy());
        QVERIFY(dialog.findChild<QLabel *>("sourceScanStatus")->text().contains("Mock"));
    }
    void detailSnapshotAndNavigation() {
        QTemporaryDir tmp;
        const QString old = QDir::currentPath();
        QDir().mkpath(tmp.path() + "/config");
        QVERIFY(writeFile(tmp.path() + "/config/default.json", "{}"));
        QVERIFY(QDir::setCurrent(tmp.path()));
        ConfigManager config;
        QVERIFY(config.initialize());
        QDir::setCurrent(old);
        SourceScanTask task;
        task.id = "preview";
        task.name = QStringLiteral("源码扫描界面验收");
        task.endpoint = "http://test";
        task.status = "completed";
        task.flowStatus = "finished";
        task.flowId = "preview-flow";
        task.assistantState = "idle";
        task.createdAt = task.updatedAt = task.lastRefresh = SourceScan::now();
        QList<SourceScanFile> files{
            {"project/src/test.cpp", "/not/exist", "void f() {\nstrcpy(dst, input);\n}\n"},
            {"project/src/zsafe.h", "/also/not/exist", "#pragma once\nvoid safe();\n"}};
        QList<SourceScanFinding> findings;
        QString error;
        QVERIFY(SourceScan::parseFindings(parsedReply(files[0].path), files, &findings, &error));
        {
            SourceScanStore store(config.configDirPath());
            QVERIFY(store.open(&error));
            QVERIFY(store.create(task, files, &error));
            QVERIFY(store.merge(task.id, findings, "test fixture", "test fixture", &error));
        }
        SourceScanService service(config.configDirPath());
        PentagiSourceScanDetailDialog window(&config, &service, task.id);
        window.show();
        QTest::qWait(100);
        auto *tree = window.findChild<QTreeWidget *>("sourceScanFileTree");
        auto *code = window.findChild<QPlainTextEdit *>("sourceScanCode");
        auto *results = window.findChild<QTableWidget *>("sourceScanFindings");
        QVERIFY(tree);
        QVERIFY(code);
        QVERIFY(results);
        QVERIFY(code->isReadOnly());
        QCOMPARE(code->toPlainText(), files[0].content);
        auto *secondFile = tree->topLevelItem(0)->child(0)->child(1);
        tree->setCurrentItem(secondFile);
        QCOMPARE(code->toPlainText(), files[1].content);
        QCOMPARE(results->rowCount(), 1);
        QVERIFY(QMetaObject::invokeMethod(results, "cellClicked", Q_ARG(int, 0), Q_ARG(int, 0)));
        QCOMPARE(code->textCursor().blockNumber(), 1);
        QVERIFY(
            window.findChild<QTextBrowser *>("sourceScanFindingDetail")->toPlainText().contains("CWE-120"));
        const auto screenshot = qEnvironmentVariable("SOURCE_SCAN_TEST_SCREENSHOT");
        if (!screenshot.isEmpty())
            QVERIFY(window.grab().save(screenshot));
        SourceScanPage page(&config);
        page.resize(1400, 750);
        page.show();
        QTest::qWait(50);
        QCOMPARE(page.findChild<QTableWidget *>("sourceScanTasks")->rowCount(), 1);
        auto *embedded = page.findChild<PentagiSourceScanDetailDialog *>();
        QVERIFY(embedded);
        QVERIFY(!embedded->isWindow());
        QVERIFY(embedded->isVisible());
        const QString pageScreenshot = qEnvironmentVariable("SOURCE_SCAN_PAGE_SCREENSHOT");
        if (!pageScreenshot.isEmpty()) QVERIFY(page.grab().save(pageScreenshot));
    }
};
QTEST_MAIN(SourceScanTests)
#include "SourceScanTests.moc"
