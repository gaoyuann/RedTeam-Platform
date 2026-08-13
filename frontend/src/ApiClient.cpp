#include "ApiClient.h"
#include <QSettings>

ApiClient::ApiClient(const QString &baseUrl, QObject *parent)
    : QObject(parent), m_baseUrl(baseUrl) {
  m_mgr = new QNetworkAccessManager(this);
}

// ── Server URL management ───────────────────────────────────────────────

void ApiClient::setBaseUrl(const QString &url) {
  m_baseUrl = url;
}

QString ApiClient::baseUrl() const {
  return m_baseUrl;
}

// ── JWT token management ────────────────────────────────────────────────

void ApiClient::setToken(const QString &token) {
  m_token = token;
}

void ApiClient::clearToken() {
  m_token.clear();
  m_refreshToken.clear();
}

QString ApiClient::token() const {
  return m_token;
}

void ApiClient::setRefreshToken(const QString &token) {
  m_refreshToken = token;
}

QString ApiClient::refreshToken() const {
  return m_refreshToken;
}

// ── Request building ────────────────────────────────────────────────────

QNetworkRequest ApiClient::makeRequest(const QString &path,
                                        int timeoutMs) const {
  QUrl url(m_baseUrl + path);
  QNetworkRequest req(url);
  req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  req.setTransferTimeout(timeoutMs);
  // Attach JWT token if available
  if (!m_token.isEmpty()) {
    req.setRawHeader("Authorization",
      QString("Bearer %1").arg(m_token).toUtf8());
  }
  return req;
}

// ── Response handling ───────────────────────────────────────────────────

void ApiClient::handleReply(
    QNetworkReply *reply, const QString &path,
    std::function<void(const QJsonObject &)> callback) {
  if (!reply)
    return;

  connect(reply, &QNetworkReply::finished, this, [this, reply, path, callback]() {
    QJsonObject result;
    if (reply->error() == QNetworkReply::NoError) {
      QByteArray data = reply->readAll();
      QJsonParseError err;
      QJsonDocument doc = QJsonDocument::fromJson(data, &err);
      if (err.error == QJsonParseError::NoError && doc.isObject()) {
        result = doc.object();
        // Normalize: ensure success responses have status:"ok"
        if (!result.contains("status")) {
          result["status"] = "ok";
        }
      } else {
        result["status"] = "error";
        result["error"] = QJsonObject{{"message", "Invalid JSON response"}};
        emit apiError(path, "Invalid JSON response");
      }
    } else {
      // Check for 401 with TOKEN_EXPIRED — attempt auto-refresh
      int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
      if (statusCode == 401) {
        QByteArray body = reply->readAll();
        QJsonDocument errDoc = QJsonDocument::fromJson(body, nullptr);
        QString code = errDoc.object().value("error").toObject().value("code").toString();
        if (code == "TOKEN_EXPIRED" && !m_refreshToken.isEmpty()) {
          reply->deleteLater();
          // Will be handled by attemptTokenRefresh — but we don't have
          // enough context here. Just report auth expired.
          result["status"] = "error";
          result["error"] = QJsonObject{{"message", "令牌已过期"}, {"code", "TOKEN_EXPIRED"}};
          emit authExpired();
          if (callback) callback(result);
          return;
        }
      }

      QString errMsg = reply->errorString();
      result["status"] = "error";
      result["error"] = QJsonObject{
          {"message", errMsg},
          {"code", QString::number(reply->error())}};
      emit apiError(path, errMsg);
    }
    reply->deleteLater();
    if (callback)
      callback(result);
  });
}

// ── Token refresh ───────────────────────────────────────────────────────

void ApiClient::attemptTokenRefresh(const QString &path, const QJsonObject &body,
                                     int timeoutMs, bool isPost,
                                     std::function<void(const QJsonObject &)> callback) {
  QJsonObject refreshBody;
  refreshBody["refresh_token"] = m_refreshToken;

  // Temporarily clear token to avoid sending expired token on refresh request
  QString savedToken = m_token;
  m_token.clear();

  post("/api/users/refresh", refreshBody, 5000, [this, path, body, timeoutMs, isPost, callback, savedToken](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      auto data = res["data"].toObject();
      m_token = data["access_token"].toString();
      m_refreshToken = data["refresh_token"].toString();

      // Save new tokens to QSettings
      QSettings settings("RedTeam", "RedTeam-Platform");
      settings.setValue("auth/refresh_token", m_refreshToken);

      // Retry original request
      if (isPost) {
        post(path, body, timeoutMs, callback);
      } else {
        get(path, timeoutMs, callback);
      }
    } else {
      // Refresh failed — need to re-login
      m_token.clear();
      m_refreshToken.clear();
      emit authExpired();
      if (callback) {
        QJsonObject errResult;
        errResult["status"] = "error";
        errResult["error"] = QJsonObject{{"message", "认证已过期，请重新登录"}, {"code", "AUTH_EXPIRED"}};
        callback(errResult);
      }
    }
  });
}

// ── HTTP methods ────────────────────────────────────────────────────────

void ApiClient::get(const QString &path, int timeoutMs,
                    std::function<void(const QJsonObject &)> callback) {
  auto req = makeRequest(path, timeoutMs);
  auto *reply = m_mgr->get(req);
  handleReply(reply, path, callback);
}

void ApiClient::post(const QString &path, const QJsonObject &body,
                     int timeoutMs,
                     std::function<void(const QJsonObject &)> callback) {
  auto req = makeRequest(path, timeoutMs);
  auto *reply =
      m_mgr->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
  handleReply(reply, path, callback);
}

void ApiClient::put(const QString &path, const QJsonObject &body,
                     int timeoutMs,
                     std::function<void(const QJsonObject &)> callback) {
  auto req = makeRequest(path, timeoutMs);
  auto *reply =
      m_mgr->put(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
  handleReply(reply, path, callback);
}

void ApiClient::del(const QString &path, int timeoutMs,
                    std::function<void(const QJsonObject &)> callback) {
  auto req = makeRequest(path, timeoutMs);
  auto *reply = m_mgr->deleteResource(req);
  handleReply(reply, path, callback);
}
