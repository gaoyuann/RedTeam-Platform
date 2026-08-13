#pragma once

#include <QObject>
#include <QJsonObject>
#include <QTimer>

#ifdef HAS_QT_WEBSOCKETS
#include <QWebSocket>
#endif

class ApiClient;

// ── WebSocket Client ──────────────────────────────────────────────────
// Connects to the backend WebSocket server for real-time event push.
// When HAS_QT_WEBSOCKETS is not defined, all methods are no-ops.

class WsClient : public QObject {
  Q_OBJECT
public:
  explicit WsClient(ApiClient *api, QObject *parent = nullptr);

  void connectToServer();
  void disconnectFromServer();
  bool isConnected() const;

signals:
  void connected();
  void disconnected();
  void connectionError(const QString &error);

  // Domain events
  void scanCreated(const QJsonObject &data);
  void scanStarted(const QJsonObject &data);
  void scanCompleted(const QJsonObject &data);
  void runStepStart(const QJsonObject &data);
  void runStepComplete(const QJsonObject &data);
  void runCompleted(const QJsonObject &data);
  void containerStatus(const QJsonObject &data);

private slots:
  void onTextMessageReceived(const QString &message);
  void onPingTimeout();

#ifdef HAS_QT_WEBSOCKETS
private slots:
  void onConnected();
  void onDisconnected();
  void onError(QAbstractSocket::SocketError error);
#endif

private:
  void sendAuth();

  ApiClient *m_api;
#ifdef HAS_QT_WEBSOCKETS
  QWebSocket *m_socket;
  QString m_serverUrl;
#endif
  QTimer *m_pingTimer;
  bool m_authenticated;
};
