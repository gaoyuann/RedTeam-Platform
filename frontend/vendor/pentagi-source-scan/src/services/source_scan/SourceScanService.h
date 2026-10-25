#pragma once
#include "config/AppConfig.h"
#include "models/SourceScanTypes.h"
#include <QObject>
#include <atomic>
#include <memory>

class QThread;
class SourceScanService : public QObject {
    Q_OBJECT
  public:
    explicit SourceScanService(const QString &configDir, QObject *parent = nullptr);
    ~SourceScanService() override;
    bool busy() const {
        return m_busy;
    }
    bool start(const AppConfig &config, const QString &name, const QStringList &paths);
    bool refresh(const AppConfig &config, const QString &taskId);
  signals:
    void taskCreated(const QString &id);
    void changed(const QString &id);
    void progress(const QString &id, const QString &message);
    void finished(const QString &id, const QString &error);

  private:
    bool launch(const AppConfig &config, const QString &id, const QString &name, const QStringList &paths);
    QString m_configDir;
    bool m_busy = false;
    QThread *m_worker = nullptr;
    std::shared_ptr<std::atomic_bool> m_cancel;
};
