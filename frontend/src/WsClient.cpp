#include "WsClient.h"
#include "ApiClient.h"
#include <QJsonDocument>

#ifdef HAS_QT_WEBSOCKETS

WsClient::WsClient(ApiClient *api, QObject *parent)
    : QObject(parent)
    , m_api(api)
    , m_socket(new QWebSocket(QString(), QWebSocketProtocol::VersionLatest, this))
    , m_pingTimer(new QTimer(this))
    , m_reconnectTimer(new QTimer(this))
    , m_authenticated(false)
{
  QString baseUrl = m_api->baseUrl();
  m_serverUrl = baseUrl;
  m_serverUrl.replace("http://", "ws://");
  m_serverUrl.replace("https://", "wss://");
  m_serverUrl += "/ws";

  connect(m_socket, &QWebSocket::connected, this, &WsClient::onConnected);
  connect(m_socket, &QWebSocket::disconnected, this, &WsClient::onDisconnected);
  connect(m_socket, &QWebSocket::textMessageReceived, this, &WsClient::onTextMessageReceived);
  connect(m_socket, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
          this, &WsClient::onError);

  m_pingTimer->setInterval(25000);
  connect(m_pingTimer, &QTimer::timeout, this, &WsClient::onPingTimeout);

  m_reconnectTimer->setSingleShot(true);
  m_reconnectTimer->setInterval(4000);
  connect(m_reconnectTimer, &QTimer::timeout, this, &WsClient::connectToServer);
}

void WsClient::connectToServer()
{
  m_manualDisconnect = false;
  m_reconnectTimer->stop();
  if (m_socket->state() == QAbstractSocket::ConnectedState ||
      m_socket->state() == QAbstractSocket::ConnectingState) {
    return;
  }
  m_authenticated = false;
  m_socket->open(m_serverUrl);
}

void WsClient::disconnectFromServer()
{
  m_manualDisconnect = true;
  m_pingTimer->stop();
  m_reconnectTimer->stop();
  m_socket->close();
  m_authenticated = false;
}

bool WsClient::isConnected() const
{
  return m_socket->state() == QAbstractSocket::ConnectedState && m_authenticated;
}

void WsClient::onConnected()
{
  sendAuth();
}

void WsClient::sendAuth()
{
  QJsonObject authMsg;
  authMsg["type"] = "auth";
  authMsg["token"] = m_api->token();
  m_socket->sendTextMessage(QJsonDocument(authMsg).toJson(QJsonDocument::Compact));
}

void WsClient::onDisconnected()
{
  m_pingTimer->stop();
  m_authenticated = false;
  emit disconnected();
  if (!m_manualDisconnect) {
    scheduleReconnect();
  }
}

void WsClient::onError(QAbstractSocket::SocketError)
{
  emit connectionError(m_socket->errorString());
  if (!m_manualDisconnect) {
    scheduleReconnect();
  }
}

void WsClient::scheduleReconnect()
{
  if (!m_reconnectTimer->isActive()) {
    m_reconnectTimer->start();
  }
}

void WsClient::onPingTimeout()
{
  if (m_socket->state() == QAbstractSocket::ConnectedState) {
    QJsonObject ping;
    ping["type"] = "ping";
    m_socket->sendTextMessage(QJsonDocument(ping).toJson(QJsonDocument::Compact));
  }
}

#else // !HAS_QT_WEBSOCKETS — no-op stubs

WsClient::WsClient(ApiClient *api, QObject *parent)
    : QObject(parent)
    , m_api(api)
    , m_pingTimer(new QTimer(this))
    , m_reconnectTimer(new QTimer(this))
    , m_authenticated(false)
{
}

void WsClient::connectToServer() {}
void WsClient::disconnectFromServer() {}
bool WsClient::isConnected() const { return false; }
void WsClient::onPingTimeout() {}
void WsClient::scheduleReconnect() {}

#endif // HAS_QT_WEBSOCKETS

// ── Common message dispatch (both builds) ──────────────────────────────
void WsClient::onTextMessageReceived(const QString &message)
{
  QJsonParseError err;
  QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8(), &err);
  if (err.error != QJsonParseError::NoError || !doc.isObject()) return;

  QJsonObject msg = doc.object();
  QString event = msg["event"].toString();
  QJsonObject data = msg["data"].toObject();

  if (event == "auth:ok") {
    m_authenticated = true;
    m_pingTimer->start();
    emit connected();
    return;
  }
  if (event == "auth:error") {
    m_authenticated = false;
    return;
  }
  if (event == "pong") return;

  // Domain event dispatch — aligned with backend event names
  if (event == "scan:created")      emit scanCreated(data);
  if (event == "scan:started")      emit scanStarted(data);
  if (event == "scan:completed")    emit scanCompleted(data);
  if (event == "run:created")       emit runCreated(data);
  if (event == "run:started")       emit runStarted(data);
  if (event == "run:step")          emit runStepComplete(data);
  if (event == "run:complete")      emit runCompleted(data);
  if (event == "container:status")  emit containerStatus(data);

  // Campaign events
  if (event == "campaign:started")    emit campaignStarted(data);
  if (event == "campaign:paused")     emit campaignPaused(data);
  if (event == "campaign:aborted")    emit campaignAborted(data);
  if (event == "campaign:completed")  emit campaignCompleted(data);
  if (event == "phase:started")       emit phaseStarted(data);
  if (event == "phase:completed")     emit phaseCompleted(data);
  if (event == "phase:skipped")       emit phaseSkipped(data);

  // Pipeline events
  if (event == "pipeline:created")    emit pipelineCreated(data);
  if (event == "pipeline:status")     emit pipelineStatus(data);
  if (event == "pipeline:step")       emit pipelineStep(data);
  if (event == "pipeline:log")        emit pipelineLog(data);

  // Capture events
  if (event == "capture:created")     emit captureCreated(data);
  if (event == "capture:started")     emit captureStarted(data);
  if (event == "capture:packet")      emit capturePacket(data);
  if (event == "capture:completed")   emit captureCompleted(data);
  if (event == "capture:analyzed")    emit captureAnalyzed(data);
}
