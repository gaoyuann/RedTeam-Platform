#include "WsClient.h"
#include "ApiClient.h"
#include <QJsonDocument>

#ifdef HAS_QT_WEBSOCKETS

WsClient::WsClient(ApiClient *api, QObject *parent)
    : QObject(parent)
    , m_api(api)
    , m_socket(new QWebSocket())
    , m_pingTimer(new QTimer(this))
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
}

void WsClient::connectToServer()
{
  if (m_socket->state() == QAbstractSocket::ConnectedState ||
      m_socket->state() == QAbstractSocket::ConnectingState) {
    return;
  }
  m_authenticated = false;
  m_socket->open(m_serverUrl);
}

void WsClient::disconnectFromServer()
{
  m_pingTimer->stop();
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
}

void WsClient::onError(QAbstractSocket::SocketError)
{
  emit connectionError(m_socket->errorString());
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
    , m_authenticated(false)
{
}

void WsClient::connectToServer() {}
void WsClient::disconnectFromServer() {}
bool WsClient::isConnected() const { return false; }
void WsClient::onPingTimeout() {}

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
}
