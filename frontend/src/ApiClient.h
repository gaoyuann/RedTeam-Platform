#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
#include <functional>

class ApiClient : public QObject {
  Q_OBJECT
public:
  explicit ApiClient(const QString &baseUrl = "http://127.0.0.1:3002",
                     QObject *parent = nullptr);

  // HTTP methods
  void get(const QString &path, int timeoutMs = 5000,
           std::function<void(const QJsonObject &)> callback = nullptr);

  void post(const QString &path, const QJsonObject &body, int timeoutMs = 30000,
            std::function<void(const QJsonObject &)> callback = nullptr);

  void put(const QString &path, const QJsonObject &body, int timeoutMs = 30000,
            std::function<void(const QJsonObject &)> callback = nullptr);

  void del(const QString &path, int timeoutMs = 5000,
           std::function<void(const QJsonObject &)> callback = nullptr);

  // Server URL management
  void setBaseUrl(const QString &url);
  QString baseUrl() const;

  // JWT token management
  void setToken(const QString &token);
  void clearToken();
  QString token() const;

  // Refresh token (stored separately for auto-refresh)
  void setRefreshToken(const QString &token);
  QString refreshToken() const;

signals:
  // Emitted on any API error; MainWindow connects to status bar
  void apiError(const QString &path, const QString &message);

  // Emitted when auth token expires and refresh fails — triggers re-login
  void authExpired();

private:
  QNetworkRequest makeRequest(const QString &path, int timeoutMs) const;
  void handleReply(QNetworkReply *reply, const QString &path,
                   std::function<void(const QJsonObject &)> callback);

  // Attempt to refresh the access token using the stored refresh token
  void attemptTokenRefresh(const QString &path, const QJsonObject &body,
                           int timeoutMs, bool isPost,
                           std::function<void(const QJsonObject &)> callback);

  QNetworkAccessManager *m_mgr;
  QString m_baseUrl;
  QString m_token;         // JWT access token
  QString m_refreshToken;  // Refresh token for auto-renewal
};
