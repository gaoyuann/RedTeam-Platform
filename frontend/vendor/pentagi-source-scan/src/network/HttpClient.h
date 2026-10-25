#pragma once

#include <QObject>
#include <QJsonDocument>
#include <QNetworkRequest>

#include <atomic>

class QNetworkAccessManager;

class HttpClient : public QObject {
    Q_OBJECT

public:
    explicit HttpClient(QObject *parent = nullptr);

    static QString sslSupportSummary();
    static bool isSslRuntimeCompatible(QString *detail = nullptr);

    void setBearerToken(const QString &token);
    void setTimeoutMs(int timeoutMs);
    int timeoutMs() const;
    void setCancellationFlag(const std::atomic_bool *cancelFlag);

    QJsonDocument getJson(const QUrl &url, QString *errorMessage = nullptr);
    QJsonDocument postJson(const QUrl &url,
                           const QJsonDocument &body,
                           QString *errorMessage = nullptr,
                           const std::atomic_bool *cancelFlag = nullptr);
    QJsonDocument putJson(const QUrl &url, const QJsonDocument &body, QString *errorMessage = nullptr);
    QJsonDocument deleteJson(const QUrl &url, QString *errorMessage = nullptr);

private:
    static int detectOpenSslMajorVersion(const QString &versionText);

    QJsonDocument performJsonRequest(
        const QNetworkRequest &request,
        const QByteArray &verb,
        const QByteArray &body,
        QString *errorMessage = nullptr,
        const std::atomic_bool *cancelFlag = nullptr);

    QNetworkRequest createRequest(const QUrl &url) const;

    QNetworkAccessManager *m_networkAccessManager;
    QString m_bearerToken;
    int m_timeoutMs;
    const std::atomic_bool *m_cancelFlag;
};
