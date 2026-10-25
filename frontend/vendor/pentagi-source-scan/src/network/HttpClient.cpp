#include "HttpClient.h"

#include <QEventLoop>
#include <QElapsedTimer>
#include <QIODevice>
#include <QJsonObject>
#include <cstring>
#include <memory>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QRegularExpression>
#ifndef QT_NO_SSL
#include <QSslError>
#include <QSslSocket>
#endif
#include <QTimer>

namespace {
// Qt 5.12 can rewind and resend POST data after an unexpected connection close.
// A GraphQL mutation must not run twice just because its response was lost.
class SingleUseUpload final : public QIODevice {
public:
    explicit SingleUseUpload(const QByteArray &data) : m_data(data) { open(QIODevice::ReadOnly); }
    bool isSequential() const override { return true; }
    bool reset() override { return false; }
    qint64 bytesAvailable() const override { return m_data.size() - m_offset + QIODevice::bytesAvailable(); }
protected:
    qint64 readData(char *data, qint64 maximum) override {
        const qint64 count = qMin(maximum, qint64(m_data.size()) - m_offset);
        if (count <= 0) return -1;
        std::memcpy(data, m_data.constData() + m_offset, size_t(count));
        m_offset += count;
        return count;
    }
    qint64 writeData(const char *, qint64) override { return -1; }
private:
    QByteArray m_data;
    qint64 m_offset = 0;
};
}

HttpClient::HttpClient(QObject *parent)
    : QObject(parent),
      m_networkAccessManager(new QNetworkAccessManager(this)),
      m_timeoutMs(30000),
      m_cancelFlag(nullptr) {
}

QString HttpClient::sslSupportSummary() {
#ifdef QT_NO_SSL
    return QStringLiteral("SSL 支持：不可用（Qt 构建时未启用 SSL）");
#else
    return QStringLiteral("SSL 支持：%1 | Qt 构建时 OpenSSL：%2 | 运行时 OpenSSL：%3")
        .arg(QSslSocket::supportsSsl() ? QStringLiteral("可用") : QStringLiteral("不可用"))
        .arg(QSslSocket::sslLibraryBuildVersionString())
        .arg(QSslSocket::sslLibraryVersionString());
#endif
}

bool HttpClient::isSslRuntimeCompatible(QString *detail) {
#ifdef QT_NO_SSL
    if (detail) {
        *detail = QStringLiteral("当前 Qt 5.12.8 构建未启用 SSL 支持。");
    }
    return false;
#else
    if (!QSslSocket::supportsSsl()) {
        if (detail) {
            *detail = QStringLiteral("当前 Qt 网络模块未检测到可用的 SSL 支持。");
        }
        return false;
    }

    const QString buildVersion = QSslSocket::sslLibraryBuildVersionString();
    const QString runtimeVersion = QSslSocket::sslLibraryVersionString();
    const int buildMajor = detectOpenSslMajorVersion(buildVersion);
    const int runtimeMajor = detectOpenSslMajorVersion(runtimeVersion);
    const bool compatible = !(buildMajor > 0 && runtimeMajor > 0 && buildMajor != runtimeMajor);

    if (detail) {
        if (compatible) {
            *detail = QStringLiteral("当前 SSL 运行时版本与 Qt 构建时版本主版本一致：build=%1, runtime=%2")
                          .arg(buildVersion, runtimeVersion);
        } else {
            *detail = QStringLiteral(
                          "检测到 Qt 5.12.8 的 OpenSSL 运行时版本不兼容：build=%1, runtime=%2。"
                          "Qt 5.12.8 通常要求 OpenSSL 1.1 运行库；若当前系统只有 OpenSSL 3，HTTPS 常会直接报 SSL handshake failed。")
                          .arg(buildVersion, runtimeVersion);
        }
    }

    return compatible;
#endif
}

void HttpClient::setBearerToken(const QString &token) {
    m_bearerToken = token.trimmed();
}

void HttpClient::setTimeoutMs(int timeoutMs) {
    m_timeoutMs = qMax(1000, timeoutMs);
}

int HttpClient::timeoutMs() const {
    return m_timeoutMs;
}

void HttpClient::setCancellationFlag(const std::atomic_bool *cancelFlag) {
    m_cancelFlag = cancelFlag;
}

QJsonDocument HttpClient::getJson(const QUrl &url, QString *errorMessage) {
    return performJsonRequest(createRequest(url), "GET", QByteArray(), errorMessage);
}

QJsonDocument HttpClient::postJson(const QUrl &url,
                                   const QJsonDocument &body,
                                   QString *errorMessage,
                                   const std::atomic_bool *cancelFlag) {
    return performJsonRequest(createRequest(url), "POST", body.toJson(QJsonDocument::Compact), errorMessage,
                              cancelFlag ? cancelFlag : m_cancelFlag);
}

QJsonDocument HttpClient::putJson(const QUrl &url, const QJsonDocument &body, QString *errorMessage) {
    return performJsonRequest(createRequest(url), "PUT", body.toJson(QJsonDocument::Compact), errorMessage);
}

QJsonDocument HttpClient::deleteJson(const QUrl &url, QString *errorMessage) {
    return performJsonRequest(createRequest(url), "DELETE", QByteArray(), errorMessage);
}

QJsonDocument HttpClient::performJsonRequest(
    const QNetworkRequest &request,
    const QByteArray &verb,
    const QByteArray &body,
    QString *errorMessage,
    const std::atomic_bool *cancelFlag) {
    if (errorMessage) errorMessage->clear();
    QElapsedTimer elapsed;
    elapsed.start();
    const bool mutation = verb == "POST" && QJsonDocument::fromJson(body).object()
        .value(QStringLiteral("query")).toString().trimmed().startsWith(QStringLiteral("mutation"));
    std::unique_ptr<SingleUseUpload> upload;
    std::unique_ptr<QNetworkAccessManager> mutationManager;
#ifndef QT_NO_SSL
    QStringList sslErrorTexts;
#endif
    QNetworkReply *reply = nullptr;
    if (verb == "GET") {
        reply = m_networkAccessManager->get(request);
    } else if (verb == "POST") {
        if (mutation) {
            QNetworkRequest singleRequest(request);
            singleRequest.setAttribute(QNetworkRequest::DoNotBufferUploadDataAttribute, true);
            singleRequest.setHeader(QNetworkRequest::ContentLengthHeader, body.size());
            singleRequest.setRawHeader("Connection", "close");
            upload.reset(new SingleUseUpload(body));
            mutationManager.reset(new QNetworkAccessManager);
            reply = mutationManager->post(singleRequest, upload.get());
        } else {
            reply = m_networkAccessManager->post(request, body);
        }
    } else if (verb == "PUT") {
        reply = m_networkAccessManager->put(request, body);
    } else if (verb == "DELETE") {
        reply = m_networkAccessManager->sendCustomRequest(request, "DELETE", body);
    }

    if (!reply) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("无法创建网络请求。");
        }
        return {};
    }

    QEventLoop loop;
    QTimer timeoutTimer;
    QTimer cancelTimer;
    timeoutTimer.setSingleShot(true);
    bool timedOut = false;
    bool canceled = false;
    connect(&timeoutTimer, &QTimer::timeout, reply, [&timedOut, reply]() {
        timedOut = true;
        reply->abort();
    });
    if (cancelFlag) {
        cancelTimer.setInterval(100);
        connect(&cancelTimer, &QTimer::timeout, reply, [cancelFlag, &canceled, reply]() {
            if (cancelFlag->load()) {
                canceled = true;
                reply->abort();
            }
        });
        cancelTimer.start();
    }
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
#ifndef QT_NO_SSL
    connect(reply, &QNetworkReply::sslErrors, reply, [&sslErrorTexts](const QList<QSslError> &errors) {
        for (const QSslError &error : errors) {
            sslErrorTexts.append(error.errorString());
        }
    });
#endif
    timeoutTimer.start(m_timeoutMs);
    loop.exec();

    const QByteArray payload = reply->readAll();
    if (reply->error() != QNetworkReply::NoError) {
        if (errorMessage) {
            QStringList details;
            details.append(QStringLiteral("请求地址：%1").arg(request.url().toString()));
            const QVariant status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
            details.append(QStringLiteral("耗时：%1 秒；网络错误码：%2%3")
                .arg(elapsed.elapsed() / 1000.0, 0, 'f', 1).arg(int(reply->error()))
                .arg(status.isValid() ? QStringLiteral("；HTTP 状态：%1").arg(status.toInt()) : QString()));
            if (canceled) {
                details.append(QStringLiteral("请求已由用户取消。"));
            } else if (timedOut) {
                details.append(QStringLiteral("%1：请求超时，已等待 %2 秒后自动停止。")
                                   .arg(QString::fromUtf8(verb))
                                   .arg(m_timeoutMs / 1000));
            } else {
                details.append(QStringLiteral("%1：%2").arg(QString::fromUtf8(verb),
                    reply->error() == QNetworkReply::ContentReSendError
                        ? QStringLiteral("连接或上传需重试，已阻止自动重发（ContentReSendError）") : reply->errorString()));
            }
            if (mutation) {
                details.append(QStringLiteral("写入请求未自动重发。连接中断不代表服务端未创建资源，请先核对远端状态。"));
            }
            if (reply->error() == QNetworkReply::HostNotFoundError) {
                details.append(QStringLiteral(
                    "诊断：当前错误发生在域名解析阶段，不是 SSL 握手失败。"
                    "请检查本机 DNS、网络连通性、防火墙或 VPN/TUN 客户端状态。"));
            } else if (reply->error() == QNetworkReply::ProxyConnectionRefusedError
                       || reply->error() == QNetworkReply::ProxyConnectionClosedError
                       || reply->error() == QNetworkReply::ProxyNotFoundError
                       || reply->error() == QNetworkReply::ProxyTimeoutError
                       || reply->error() == QNetworkReply::ProxyAuthenticationRequiredError) {
                details.append(QStringLiteral("诊断：当前错误来自代理连接，请检查 Windows 系统代理或 VPN 客户端状态。"));
            }
#ifndef QT_NO_SSL
            if (!sslErrorTexts.isEmpty()) {
                details.append(QStringLiteral("SSL 详情：%1").arg(sslErrorTexts.join(QStringLiteral("；"))));
            }
#endif
            if (request.url().scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0) {
                QString compatibilityDetail;
                if (!isSslRuntimeCompatible(&compatibilityDetail)) {
                    details.append(compatibilityDetail);
                    details.append(QStringLiteral(
                        "建议：为本程序随包提供 OpenSSL 1.1 运行库（libssl / libcrypto 1.1），"
                        "并通过启动脚本设置 LD_LIBRARY_PATH；或者重编 Qt 5.12.8 以适配 OpenSSL 3。"));
                }
            }
            *errorMessage = details.join(QStringLiteral("\n"));
        }
        // This helper is also used from short-lived worker threads. A deferred
        // delete can outlive that thread and race with network-manager cleanup.
        delete reply;
        return {};
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("返回内容不是合法 JSON：%1").arg(parseError.errorString());
        }
        delete reply;
        return {};
    }

    delete reply;
    return document;
}

QNetworkRequest HttpClient::createRequest(const QUrl &url) const {
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader("Accept", "application/json");
    request.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    if (!m_bearerToken.isEmpty()) {
        request.setRawHeader("Authorization", QByteArray("Bearer ") + m_bearerToken.toUtf8());
    }
    return request;
}

int HttpClient::detectOpenSslMajorVersion(const QString &versionText) {
    const QRegularExpression pattern(QStringLiteral("(\\d+)\\."));
    const QRegularExpressionMatch match = pattern.match(versionText);
    if (!match.hasMatch()) {
        return -1;
    }
    return match.captured(1).toInt();
}
