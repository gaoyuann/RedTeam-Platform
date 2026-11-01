#include <QtTest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QPointer>
#include "ApiClient.h"
#include "LoginDialog.h"
#include "LocalLoginStore.h"

class LoginServer : public QTcpServer {
public:
  int status = 200;
  int delay = 0;
  int requests = 0;
  QJsonObject response{{"status", "ok"}, {"data", QJsonObject{
    {"username", "fixture"}, {"role", "admin"},
    {"access_token", "fixture-access"}, {"refresh_token", "fixture-refresh"}}}};

  LoginServer() {
    connect(this, &QTcpServer::newConnection, this, [this]() {
      while (hasPendingConnections()) {
        auto *socket = nextPendingConnection();
        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
          const auto buffer = socket->property("buffer").toByteArray() + socket->readAll();
          socket->setProperty("buffer", buffer);
          const int headerEnd = buffer.indexOf("\r\n\r\n");
          if (headerEnd < 0 || socket->property("handled").toBool()) return;
          int length = 0;
          for (const auto &line : buffer.left(headerEnd).split('\n'))
            if (line.toLower().startsWith("content-length:"))
              length = line.mid(line.indexOf(':') + 1).trimmed().toInt();
          if (buffer.size() < headerEnd + 4 + length) return;
          socket->setProperty("handled", true);
          ++requests;
          const auto body = QJsonDocument(response).toJson(QJsonDocument::Compact);
          const auto bytes = "HTTP/1.1 " + QByteArray::number(status) + " Fixture\r\n"
            "Content-Type: application/json\r\nContent-Length: " + QByteArray::number(body.size())
            + "\r\nConnection: close\r\n\r\n" + body;
          QTimer::singleShot(delay, socket, [socket, bytes]() {
            socket->write(bytes);
            socket->disconnectFromHost();
          });
        });
      }
    });
  }

  QString url() const { return QString("http://127.0.0.1:%1").arg(serverPort()); }
};

class LoginChecks : public QObject {
  Q_OBJECT
  QTemporaryDir m_config;

  static void submit(LoginDialog &dialog, const QString &password = " fixture-password ") {
    dialog.findChild<QLineEdit *>("loginUsername")->setText("fixture");
    dialog.findChild<QLineEdit *>("loginPassword")->setText(password);
    dialog.findChild<QPushButton *>("loginSubmit")->click();
  }

private slots:
  void initTestCase() {
    QVERIFY(m_config.isValid());
    QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, m_config.path());
    QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, m_config.path() + "/system");
  }

  void init() {
    QSettings settings("RedTeam", "RedTeam-Platform");
    settings.clear();
    settings.sync();
  }

  void cacheIsScopedAndRejectsInvalidData() {
    QSettings settings("RedTeam", "RedTeam-Platform");
    LocalLoginStore store(settings);
    QVERIFY(store.cache("http://fixture.invalid:3002", "fixture", " password ", "admin"));
    QCOMPARE(store.verify("http://fixture.invalid:3002/", "fixture", " password "), QString("admin"));
    QVERIFY(store.verify("http://fixture.invalid:3002", "fixture", "password").isEmpty());
    QVERIFY(store.verify("http://other.invalid:3002", "fixture", " password ").isEmpty());
    QVERIFY(store.verify("http://fixture.invalid:3002", "other", " password ").isEmpty());
    QVERIFY(!store.cache("http://fixture.invalid:3002", "fixture", "password", "unknown"));
    const auto profile = settings.value(settings.allKeys().first()).toMap();
    QCOMPARE(profile["hash"].toByteArray().size(), 32);
    QVERIFY(!profile.contains("password"));
    const auto firstSalt = profile["salt"].toByteArray();
    QVERIFY(store.cache("http://fixture.invalid:3002", "fixture", "replacement", "user"));
    QVERIFY(firstSalt != settings.value(settings.allKeys().first()).toMap()["salt"].toByteArray());
    QVERIFY(store.verify("http://fixture.invalid:3002", "fixture", " password ").isEmpty());
    QCOMPARE(store.verify("http://fixture.invalid:3002", "fixture", "replacement"), QString("user"));
    settings.setValue(settings.allKeys().first(), QVariantMap{{"version", 1}, {"hash", QByteArray("broken")}});
    QVERIFY(store.verify("http://fixture.invalid:3002", "fixture", "replacement").isEmpty());
  }

  void onlineLoginThenConnectionRefused() {
    LoginServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    ApiClient api(server.url());
    LoginDialog online(&api);
    submit(online);
    QTRY_COMPARE(online.result(), int(QDialog::Accepted));
    QCOMPARE(api.token(), QString("fixture-access"));
    QCOMPARE(online.role(), QString("admin"));
    QSettings settings("RedTeam", "RedTeam-Platform");
    QVERIFY(!settings.contains("login/password"));
    QVERIFY(!settings.contains("login/username"));
    server.close();

    LoginDialog offline(&api);
    QVERIFY(api.token().isEmpty());
    QVERIFY(api.refreshToken().isEmpty());
    submit(offline);
    QTRY_COMPARE(offline.result(), int(QDialog::Accepted));
    QCOMPARE(offline.username(), QString("fixture"));
    QCOMPARE(offline.role(), QString("admin"));
    QVERIFY(api.token().isEmpty());
    QCOMPARE(server.requests, 1);

    LoginDialog wrong(&api);
    submit(wrong, "wrong");
    QTRY_VERIFY(wrong.findChild<QPushButton *>("loginSubmit")->isEnabled());
    QCOMPARE(wrong.result(), int(QDialog::Rejected));
    QVERIFY(wrong.findChild<QLabel *>("loginError")->text().contains(QStringLiteral("离线打开界面")));
  }

  void serverRejectionNeverUsesCache_data() {
    QTest::addColumn<int>("status");
    QTest::newRow("wrong-password") << 401;
    QTest::newRow("disabled-account") << 403;
  }

  void serverRejectionNeverUsesCache() {
    QFETCH(int, status);
    LoginServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    server.status = status;
    server.response = {{"status", "error"}, {"error", QJsonObject{{"message", "fixture denied"}}}};
    QSettings settings("RedTeam", "RedTeam-Platform");
    QVERIFY(LocalLoginStore(settings).cache(server.url(), "fixture", " fixture-password ", "admin"));
    ApiClient api(server.url());
    LoginDialog login(&api);
    submit(login);
    QTRY_VERIFY(login.findChild<QPushButton *>("loginSubmit")->isEnabled());
    QCOMPARE(login.result(), int(QDialog::Rejected));
    QCOMPARE(login.findChild<QLabel *>("loginError")->text(), QString("fixture denied"));
    QVERIFY(LocalLoginStore(settings).verify(server.url(), "fixture", " fixture-password ").isEmpty());
    QVERIFY(api.token().isEmpty());
  }

  void serverFailureUsesCache() {
    LoginServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    server.status = 503;
    server.response = {{"status", "error"}};
    QSettings settings("RedTeam", "RedTeam-Platform");
    QVERIFY(LocalLoginStore(settings).cache(server.url(), "fixture", " fixture-password ", "user"));
    ApiClient api(server.url());
    LoginDialog login(&api);
    submit(login);
    QTRY_COMPARE(login.result(), int(QDialog::Accepted));
    QCOMPARE(login.role(), QString("user"));
    QVERIFY(api.token().isEmpty());
  }

  void guestEntryIgnoresLateLoginResponse() {
    LoginServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    server.delay = 150;
    ApiClient api(server.url());
    LoginDialog login(&api);
    submit(login);
    QTRY_COMPARE(server.requests, 1);
    login.findChild<QPushButton *>("loginOffline")->click();
    QCOMPARE(login.result(), int(QDialog::Accepted));
    QCOMPARE(login.username(), QStringLiteral("离线访客"));
    QCOMPARE(login.role(), QString("user"));
    QTest::qWait(250);
    QVERIFY(api.token().isEmpty());
    QCOMPARE(login.username(), QStringLiteral("离线访客"));
    QSettings settings("RedTeam", "RedTeam-Platform");
    QVERIFY(settings.allKeys().isEmpty());
  }

  void guestEntryNeedsNoConnectionOrCredentials() {
    ApiClient api("http://fixture.invalid:3002");
    QSignalSpy errors(&api, &ApiClient::apiError);
    LoginDialog login(&api);
    login.findChild<QPushButton *>("loginOffline")->click();
    QCOMPARE(login.result(), int(QDialog::Accepted));
    QVERIFY(api.token().isEmpty());
    QCOMPARE(errors.count(), 0);
  }

  void timeoutIsClassifiedAsTransportFailure() {
    LoginServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    server.delay = 200;
    ApiClient api(server.url());
    QJsonObject result;
    api.post("/api/users/login", {}, 40, [&](const QJsonObject &response) { result = response; });
    QTRY_VERIFY(!result.isEmpty());
    QCOMPARE(result["status"].toString(), QString("error"));
    QVERIFY(result["transport_error"].toBool());
    QCOMPARE(result["http_status"].toInt(), 0);
  }

  void closingPendingDialogIsSafe() {
    LoginServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost, 0));
    server.delay = 100;
    ApiClient api(server.url());
    auto *login = new LoginDialog(&api);
    submit(*login);
    QTRY_COMPARE(server.requests, 1);
    delete login;
    QTest::qWait(200);
    QVERIFY(api.token().isEmpty());
  }
};

QTEST_MAIN(LoginChecks)
#include "login_checks.moc"
