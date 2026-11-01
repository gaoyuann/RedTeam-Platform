#pragma once

#include <QPasswordDigestor>
#include <QSettings>
#include <QUuid>
#include <QVariantMap>
#include <QUrl>

// A local desktop lock only; this profile never grants backend permissions.
class LocalLoginStore {
public:
  explicit LocalLoginStore(QSettings &settings) : m_settings(settings) {}

  bool cache(const QString &server, const QString &username,
             const QString &password, const QString &role) {
    if (username.trimmed().isEmpty() || password.isEmpty()
        || (role != "admin" && role != "user"))
      return false;
    const QByteArray salt = QUuid::createUuid().toRfc4122();
    const QByteArray hash = digest(password, salt);
    if (hash.size() != 32) return false;
    m_settings.setValue(key(server, username), QVariantMap{
      {"version", 1}, {"username", username.trimmed()}, {"role", role},
      {"salt", salt}, {"hash", hash}});
    m_settings.sync();
    return m_settings.status() == QSettings::NoError;
  }

  QString verify(const QString &server, const QString &username, const QString &password) const {
    const auto profile = m_settings.value(key(server, username)).toMap();
    const auto salt = profile.value("salt").toByteArray();
    const auto expected = profile.value("hash").toByteArray();
    if (profile.value("version").toInt() != 1 || salt.size() != 16
        || expected.size() != 32 || password.isEmpty()
        || username.trimmed() != profile.value("username").toString())
      return {};
    const QString role = profile.value("role").toString();
    if (role != "admin" && role != "user") return {};
    const auto actual = digest(password, salt);
    if (actual.size() != expected.size()) return {};
    unsigned int difference = 0;
    for (int i = 0; i < actual.size(); ++i)
      difference |= static_cast<unsigned char>(actual[i])
                  ^ static_cast<unsigned char>(expected[i]);
    return difference == 0 ? role : QString();
  }

  void remove(const QString &server, const QString &username) {
    m_settings.remove(key(server, username));
    m_settings.sync();
  }

private:
  static QString key(const QString &server, const QString &username) {
    QUrl url(server);
    QString path = url.path();
    while (path.endsWith('/')) path.chop(1);
    url.setPath(path);
    const auto identity = url.toEncoded() + '\n' + username.trimmed().toUtf8();
    return "offlineLogin/" + QString::fromLatin1(
      QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex());
  }
  static QByteArray digest(const QString &password, const QByteArray &salt) {
    return QPasswordDigestor::deriveKeyPbkdf2(
      QCryptographicHash::Sha256, password.toUtf8(), salt, 100000, 32);
  }

  QSettings &m_settings;
};
