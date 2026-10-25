#pragma once
#include <QList>
#include <QString>
#include <QStringList>

struct SourceScanFile {
    QString path, originalPath, content;
};
struct SourceScanFinding {
    QString key, path;
    int line = 0;
    int endLine = 0;
    QString severity, title, cwe, description, evidence, recommendation;
};
struct SourceScanTask {
    QString id, name, endpoint, flowId, assistantId;
    QString status = QStringLiteral("prepared");
    QString flowStatus, error, createdAt, updatedAt, lastRefresh;
    QStringList selectedPaths, baselineFlows;
    int nextBatch = 0;
    int pendingBatch = -1;
    bool createPending = false;
    QString assistantState, assistantRequest;
    QStringList baselineLogs;
};
namespace SourceScan {
QString now();
QString endpointAddress(const QString &url);
bool terminal(const QString &status);
QString statusText(const SourceScanTask &task);
bool collectFiles(const QStringList &paths, QList<SourceScanFile> *files, QString *error);
QStringList batches(const SourceScanTask &task, const QList<SourceScanFile> &files);
bool parseFindings(const QString &text, const QList<SourceScanFile> &files,
                   QList<SourceScanFinding> *findings, QString *error);
} // namespace SourceScan
