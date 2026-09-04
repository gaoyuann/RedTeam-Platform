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

  // Domain events — aligned with backend broadcast event names
  void scanCreated(const QJsonObject &data);      // scan:created
  void scanStarted(const QJsonObject &data);      // scan:started
  void scanCompleted(const QJsonObject &data);    // scan:completed
  void runCreated(const QJsonObject &data);       // run:created
  void runStarted(const QJsonObject &data);       // run:started
  void runStepComplete(const QJsonObject &data);  // run:step  (step finished)
  void runCompleted(const QJsonObject &data);     // run:complete
  void containerStatus(const QJsonObject &data);  // container:status

  // Campaign events
  void campaignStarted(const QJsonObject &data);   // campaign:started
  void campaignPaused(const QJsonObject &data);    // campaign:paused
  void campaignAborted(const QJsonObject &data);   // campaign:aborted
  void campaignCompleted(const QJsonObject &data); // campaign:completed
  void phaseStarted(const QJsonObject &data);      // phase:started
  void phaseCompleted(const QJsonObject &data);    // phase:completed
  void phaseSkipped(const QJsonObject &data);      // phase:skipped

  // Capture events
  void captureCreated(const QJsonObject &data);    // capture:created
  void captureStarted(const QJsonObject &data);    // capture:started
  void capturePacket(const QJsonObject &data);     // capture:packet
  void captureCompleted(const QJsonObject &data);  // capture:completed
  void captureAnalyzed(const QJsonObject &data);   // capture:analyzed

  // Pipeline events
  void pipelineCreated(const QJsonObject &data);      // pipeline:created
  void pipelineStatus(const QJsonObject &data);       // pipeline:status
  void pipelineStep(const QJsonObject &data);         // pipeline:step
  void pipelineLog(const QJsonObject &data);          // pipeline:log

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
  void scheduleReconnect();

  ApiClient *m_api;
#ifdef HAS_QT_WEBSOCKETS
  QWebSocket *m_socket;
  QString m_serverUrl;
#endif
  QTimer *m_pingTimer;
  QTimer *m_reconnectTimer;
  bool m_authenticated;
  bool m_manualDisconnect = false;
};
