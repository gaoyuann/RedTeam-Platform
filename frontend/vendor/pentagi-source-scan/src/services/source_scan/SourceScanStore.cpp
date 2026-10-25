#include "SourceScanStore.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>

namespace {
QString json(const QJsonObject &o) {
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}
QStringList strings(const QJsonValue &v) {
    QStringList out;
    for (const auto &x : v.toArray())
        out << x.toString();
    return out;
}
QJsonObject encode(const SourceScanTask &t) {
    return {{"id", t.id},
            {"name", t.name},
            {"endpoint", t.endpoint},
            {"flowId", t.flowId},
            {"assistantId", t.assistantId},
            {"status", t.status},
            {"flowStatus", t.flowStatus},
            {"error", t.error},
            {"createdAt", t.createdAt},
            {"updatedAt", t.updatedAt},
            {"lastRefresh", t.lastRefresh},
            {"selectedPaths", QJsonArray::fromStringList(t.selectedPaths)},
            {"baselineFlows", QJsonArray::fromStringList(t.baselineFlows)},
            {"nextBatch", t.nextBatch},
            {"pendingBatch", t.pendingBatch},
            {"createPending", t.createPending},
            {"assistantState", t.assistantState},
            {"assistantRequest", t.assistantRequest},
            {"baselineLogs", QJsonArray::fromStringList(t.baselineLogs)}};
}
SourceScanTask decode(const QString &s) {
    const auto o = QJsonDocument::fromJson(s.toUtf8()).object();
    SourceScanTask t;
    t.id = o["id"].toString();
    t.name = o["name"].toString();
    t.endpoint = o["endpoint"].toString();
    t.flowId = o["flowId"].toString();
    t.assistantId = o["assistantId"].toString();
    t.status = o["status"].toString();
    t.flowStatus = o["flowStatus"].toString();
    t.error = o["error"].toString();
    t.createdAt = o["createdAt"].toString();
    t.updatedAt = o["updatedAt"].toString();
    t.lastRefresh = o["lastRefresh"].toString();
    t.selectedPaths = strings(o["selectedPaths"]);
    t.baselineFlows = strings(o["baselineFlows"]);
    t.nextBatch = o["nextBatch"].toInt();
    t.pendingBatch = o["pendingBatch"].toInt(-1);
    t.createPending = o["createPending"].toBool();
    t.assistantState = o["assistantState"].toString();
    t.assistantRequest = o["assistantRequest"].toString();
    t.baselineLogs = strings(o["baselineLogs"]);
    return t;
}
bool run(QSqlQuery &q, QString *error) {
    if (q.exec())
        return true;
    if (error)
        *error = QStringLiteral("源码扫描数据库错误：%1").arg(q.lastError().text());
    return false;
}
} // namespace
SourceScanStore::SourceScanStore(const QString &dir)
    : m_path(QDir(dir).filePath(QStringLiteral("source_scans.sqlite"))),
      m_connection(QStringLiteral("source-scan-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces))) {
}
SourceScanStore::~SourceScanStore() {
    if (m_db.isValid()) {
        m_db.close();
        m_db = QSqlDatabase();
        QSqlDatabase::removeDatabase(m_connection);
    }
}
bool SourceScanStore::open(QString *error) {
    if (error)
        error->clear();
    if (m_db.isOpen())
        return true;
    if (!QDir().mkpath(QFileInfo(m_path).absolutePath())) {
        if (error)
            *error = QStringLiteral("无法创建源码扫描数据库目录。");
        return false;
    }
    m_db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_connection);
    m_db.setDatabaseName(m_path);
    m_db.setConnectOptions(QStringLiteral("QSQLITE_BUSY_TIMEOUT=5000"));
    if (!m_db.open()) {
        if (error)
            *error = QStringLiteral("无法打开源码扫描 SQLite 数据库（请检查 QSQLITE 插件）：%1")
                         .arg(m_db.lastError().text());
        return false;
    }
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral("PRAGMA foreign_keys=ON")) ||
        !q.exec(QStringLiteral("PRAGMA foreign_keys")) || !q.next() || q.value(0).toInt() != 1 ||
        !q.exec(QStringLiteral("PRAGMA journal_mode=DELETE")) ||
        !q.exec(QStringLiteral("PRAGMA user_version")) || !q.next()) {
        if (error)
            *error = QStringLiteral("无法读取源码扫描 SQLite 数据库版本：%1").arg(q.lastError().text());
        return false;
    }
    const int version = q.value(0).toInt();
    q.finish();
    if (version > 3) {
        if (error)
            *error = QStringLiteral("源码扫描数据库版本高于当前客户端，请勿降级使用。");
        return false;
    }
    if (version == 0) {
        if (!m_db.transaction()) {
            if (error)
                *error = m_db.lastError().text();
            return false;
        }
        QFile migration(QStringLiteral(":/source_scan/migrations/001_initial.sql"));
        if (!migration.open(QIODevice::ReadOnly)) {
            m_db.rollback();
            if (error)
                *error = QStringLiteral("无法读取内置源码扫描 SQL 迁移文件。");
            return false;
        }
        const QStringList statements =
            QString::fromUtf8(migration.readAll()).split(QLatin1Char(';'), QString::SkipEmptyParts);
        for (const QString &statement : statements) {
            QStringList sqlLines;
            for (const QString &line : statement.split(QLatin1Char('\n'))) {
                if (!line.trimmed().startsWith(QStringLiteral("--")))
                    sqlLines << line;
            }
            const QString sql = sqlLines.join(QLatin1Char('\n')).trimmed();
            if (sql.isEmpty())
                continue;
            q.finish();
            if (!q.exec(sql)) {
                m_db.rollback();
                if (error)
                    *error = QStringLiteral("应用源码扫描 SQL 迁移失败：%1").arg(q.lastError().text());
                return false;
            }
        }
        q.finish();
        if (!q.exec(QStringLiteral("PRAGMA user_version=1")) || !m_db.commit()) {
            m_db.rollback();
            if (error)
                *error = QStringLiteral("提交源码扫描初始数据库迁移失败：%1").arg(m_db.lastError().text());
            return false;
        }
    }

    // Version 2 was a bookkeeping version; leave endpoint values as plain URLs.
    if (version <= 1) {
        if (!m_db.transaction()) {
            if (error)
                *error = m_db.lastError().text();
            return false;
        }
        if (!q.exec(QStringLiteral("PRAGMA user_version=2")) || !m_db.commit()) {
            m_db.rollback();
            if (error)
                *error = QStringLiteral("提交源码扫描数据库版本迁移失败：%1").arg(m_db.lastError().text());
            return false;
        }
    }

    // Version 3 removes the old irreversible endpoint hash. Since the original
    // address cannot be recovered, mark those records unbound; the service binds
    // them to the configured URL on their next refresh.
    if (version <= 2) {
        if (!m_db.transaction()) {
            if (error)
                *error = m_db.lastError().text();
            return false;
        }
        QSqlQuery rows(m_db);
        if (!rows.exec(QStringLiteral("SELECT id,payload FROM tasks"))) {
            m_db.rollback();
            if (error)
                *error = rows.lastError().text();
            return false;
        }
        QList<QPair<QString, QString>> updates;
        while (rows.next()) {
            const QString id = rows.value(0).toString();
            QJsonParseError parseError;
            const QJsonDocument taskDoc = QJsonDocument::fromJson(rows.value(1).toString().toUtf8(), &parseError);
            if (parseError.error != QJsonParseError::NoError || !taskDoc.isObject()) {
                m_db.rollback();
                if (error)
                    *error = QStringLiteral("任务 %1 的数据库记录无效，未执行迁移。").arg(id);
                return false;
            }
            QJsonObject payload = taskDoc.object();
            if (payload.value(QStringLiteral("endpoint")).toString().startsWith(QStringLiteral("sha256:"))) {
                payload.insert(QStringLiteral("endpoint"), QString());
                updates.append(qMakePair(id, json(payload)));
            }
        }
        rows.finish();
        QSqlQuery update(m_db);
        for (const auto &item : updates) {
            update.prepare(QStringLiteral("UPDATE tasks SET payload=? WHERE id=?"));
            update.addBindValue(item.second);
            update.addBindValue(item.first);
            if (!run(update, error)) {
                m_db.rollback();
                return false;
            }
        }
        update.finish();
        if (!update.exec(QStringLiteral("PRAGMA user_version=3")) || !m_db.commit()) {
            m_db.rollback();
            if (error)
                *error = QStringLiteral("提交源码扫描数据库版本迁移失败：%1").arg(m_db.lastError().text());
            return false;
        }
    }
    return true;
}
bool SourceScanStore::save(const SourceScanTask &t, QString *error) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE tasks SET payload=?,updated_at=? WHERE id=?"));
    q.addBindValue(json(encode(t)));
    q.addBindValue(t.updatedAt);
    q.addBindValue(t.id);
    if (!run(q, error))
        return false;
    if (q.numRowsAffected() != 1) {
        if (error)
            *error = QStringLiteral("源码扫描任务不存在，未保存状态。");
        return false;
    }
    return true;
}
bool SourceScanStore::create(const SourceScanTask &t, const QList<SourceScanFile> &files, QString *error) {
    if (!m_db.transaction()) {
        if (error)
            *error = m_db.lastError().text();
        return false;
    }
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("INSERT INTO tasks VALUES(?,?,?)"));
    q.addBindValue(t.id);
    q.addBindValue(json(encode(t)));
    q.addBindValue(t.updatedAt);
    if (!run(q, error)) {
        m_db.rollback();
        return false;
    }
    for (const auto &f : files) {
        q.prepare(QStringLiteral("INSERT INTO files VALUES(?,?,?,?)"));
        q.addBindValue(t.id);
        q.addBindValue(f.path);
        q.addBindValue(f.originalPath);
        q.addBindValue(f.content);
        if (!run(q, error)) {
            m_db.rollback();
            return false;
        }
    }
    if (!m_db.commit()) {
        if (error)
            *error = m_db.lastError().text();
        return false;
    }
    return true;
}
QList<SourceScanTask> SourceScanStore::tasks(QString *error) {
    QList<SourceScanTask> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT payload FROM tasks ORDER BY updated_at DESC,id"));
    if (run(q, error))
        while (q.next())
            out << decode(q.value(0).toString());
    return out;
}
SourceScanTask SourceScanStore::task(const QString &id, QString *error) {
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT payload FROM tasks WHERE id=?"));
    q.addBindValue(id);
    if (run(q, error) && q.next())
        return decode(q.value(0).toString());
    if (error && error->isEmpty())
        *error = QStringLiteral("源码扫描任务不存在。");
    return {};
}
QList<SourceScanFile> SourceScanStore::files(const QString &id, QString *error) {
    QList<SourceScanFile> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT path,original_path,content FROM files WHERE task_id=? ORDER BY path"));
    q.addBindValue(id);
    if (run(q, error))
        while (q.next())
            out << SourceScanFile{q.value(0).toString(), q.value(1).toString(), q.value(2).toString()};
    return out;
}
QList<SourceScanFinding> SourceScanStore::findings(const QString &id, QString *error) {
    QList<SourceScanFinding> out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT payload FROM findings WHERE task_id=? ORDER BY finding_key"));
    q.addBindValue(id);
    if (run(q, error))
        while (q.next()) {
            const auto o = QJsonDocument::fromJson(q.value(0).toString().toUtf8()).object();
            SourceScanFinding f;
            f.key = o["key"].toString();
            f.path = o["path"].toString();
            f.line = o["line"].toInt();
            f.endLine = o["endLine"].toInt();
            f.severity = o["severity"].toString();
            f.title = o["title"].toString();
            f.cwe = o["cwe"].toString();
            f.description = o["description"].toString();
            f.evidence = o["evidence"].toString();
            f.recommendation = o["recommendation"].toString();
            out << f;
        }
    return out;
}
bool SourceScanStore::merge(const QString &id, const QList<SourceScanFinding> &findings, const QString &raw,
                            const QString &parsed, QString *error) {
    if (!m_db.transaction()) {
        if (error)
            *error = m_db.lastError().text();
        return false;
    }
    QSqlQuery q(m_db);
    for (const auto &f : findings) {
        const QJsonObject o{{"key", f.key},           {"path", f.path},
                            {"line", f.line},         {"endLine", f.endLine},
                            {"severity", f.severity}, {"title", f.title},
                            {"cwe", f.cwe},           {"description", f.description},
                            {"evidence", f.evidence}, {"recommendation", f.recommendation}};
        q.prepare(QStringLiteral("INSERT OR REPLACE INTO findings VALUES(?,?,?)"));
        q.addBindValue(id);
        q.addBindValue(f.key);
        q.addBindValue(json(o));
        if (!run(q, error)) {
            m_db.rollback();
            return false;
        }
    }
    q.prepare(QStringLiteral("INSERT INTO responses(task_id,created_at,raw,parsed) VALUES(?,?,?,?)"));
    q.addBindValue(id);
    q.addBindValue(SourceScan::now());
    q.addBindValue(raw);
    q.addBindValue(parsed);
    if (!run(q, error)) {
        m_db.rollback();
        return false;
    }
    if (!m_db.commit()) {
        if (error)
            *error = m_db.lastError().text();
        return false;
    }
    return true;
}
