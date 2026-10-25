#pragma once
#include "models/SourceScanTypes.h"
#include <QSqlDatabase>

// One connection per instance, created and destroyed on its owning thread.
class SourceScanStore {
  public:
    explicit SourceScanStore(const QString &configDir);
    ~SourceScanStore();
    SourceScanStore(const SourceScanStore &) = delete;
    SourceScanStore &operator=(const SourceScanStore &) = delete;
    bool open(QString *error);
    bool create(const SourceScanTask &task, const QList<SourceScanFile> &files, QString *error);
    bool save(const SourceScanTask &task, QString *error);
    QList<SourceScanTask> tasks(QString *error);
    SourceScanTask task(const QString &id, QString *error);
    QList<SourceScanFile> files(const QString &id, QString *error);
    QList<SourceScanFinding> findings(const QString &id, QString *error);
    bool merge(const QString &id, const QList<SourceScanFinding> &findings, const QString &raw,
               const QString &parsed, QString *error);

  private:
    QString m_path, m_connection;
    QSqlDatabase m_db;
};
