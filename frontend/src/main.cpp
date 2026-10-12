#include "MainWindow.h"
#include "SplashDialog.h"
#include "LoginDialog.h"
#include "ApiClient.h"
#include "Theme.h"
#include "AppStyle.h"
#include "services/dongle/DongleService.h"
#include <QApplication>
#include <QMessageBox>
#include <QProcess>
#include <QFontDatabase>
#include <QDir>
#include <QTimer>
#include <QSettings>
#include <QScreen>
#include <QNetworkProxyFactory>
#include <QNetworkProxy>
#include <QDebug>
#include <functional>

static void loadBundledFonts() {
  QDir appDir(QCoreApplication::applicationDirPath());
  QString fontDir = appDir.filePath("../fonts");
  if (!QDir(fontDir).exists()) return;

  int loaded = 0;
  for (const auto &entry : QDir(fontDir).entryInfoList(
         {"*.ttf", "*.otf", "*.ttc"}, QDir::Files)) {
    int id = QFontDatabase::addApplicationFont(entry.absoluteFilePath());
    if (id != -1) loaded++;
  }
  if (loaded > 0) {
    QFont font = QApplication::font();
    font.setFamily("Noto Sans CJK SC");
    QApplication::setFont(font);
  }
}

int main(int argc, char *argv[])
{
    // ── Input Method (IME) setup ───────────────────────────────────────
    // On Linux/X11, Qt5 needs QT_IM_MODULE to connect to an IME framework.
    // If not set, auto-detect: prefer fcitx5 > fcitx > ibus > compose.
    // This must happen BEFORE QApplication is constructed.
    if (!qEnvironmentVariableIsSet("QT_IM_MODULE")) {
      // Check for running IME processes
      QProcess imeCheck;
      bool foundIme = false;

      // Try fcitx5 first (most common on modern Linux)
      imeCheck.start("pgrep", {"-x", "fcitx5"});
      imeCheck.waitForFinished(1000);
      if (imeCheck.exitCode() == 0) {
        qputenv("QT_IM_MODULE", "fcitx");
        foundIme = true;
      }

      if (!foundIme) {
        imeCheck.start("pgrep", {"-x", "fcitx"});
        imeCheck.waitForFinished(1000);
        if (imeCheck.exitCode() == 0) {
          qputenv("QT_IM_MODULE", "fcitx");
          foundIme = true;
        }
      }

      if (!foundIme) {
        imeCheck.start("pgrep", {"-x", "ibus-daemon"});
        imeCheck.waitForFinished(1000);
        if (imeCheck.exitCode() == 0) {
          qputenv("QT_IM_MODULE", "ibus");
          foundIme = true;
        }
      }

      if (!foundIme) {
        // No IME process found — try ibus as default if plugin exists
        // (ibus plugin ships with libqt5gui on Ubuntu)
        qputenv("QT_IM_MODULE", "ibus");
      }
    }

    QApplication app(argc, argv);

    // Disable ALL proxy — frontend connects directly to backend on LAN.
    // Going through a proxy causes "Host requires authentication" errors.
    // setUseSystemConfiguration(false) alone is not enough if http_proxy
    // env vars or system transparent proxy exist.
    QNetworkProxyFactory::setUseSystemConfiguration(false);
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);

    // Global font & stylesheet (fonts loaded in splash below)
    QFont baseFont = app.font();
    baseFont.setPointSize(11);
    app.setFont(baseFont);

    // Dark mode detection: check system palette or QSettings override
    QSettings themeSettings("RedTeam", "RedTeam-Platform");
    bool useDark = themeSettings.value("appearance/dark", false).toBool();
    if (!useDark) {
        // Auto-detect from system palette
        useDark = QApplication::palette().window().color().lightness() < 128;
    }
    if (useDark) {
        #include "StyleDark.h"
        app.setStyleSheet(QString::fromUtf8(GLOBAL_STYLE_DARK) + Theme::DarkButtonStyle + Theme::ItemViewStyle);
    } else {
        app.setStyleSheet(Theme::GlobalStyle + Theme::ButtonStyle + Theme::ItemViewStyle);
    }

    // ── Splash (event-driven) ──────────────────────────────────────────
    SplashDialog splash;
    splash.show();
    splash.updateProgress(10, "正在加载资源...");
    app.processEvents();

    // Real loading: fonts
    loadBundledFonts();
    splash.updateProgress(30, "资源加载完成");
    app.processEvents();

    // Real loading: determine server address (priority: --server arg > env > QSettings > default)
    QString serverArg;
    {
        QStringList args = app.arguments();
        int sidx = args.indexOf("--server");
        if (sidx >= 0 && sidx + 1 < args.size()) {
            serverArg = args[sidx + 1];
        }
    }
    QString serverUrl;
    if (!serverArg.isEmpty()) {
        serverUrl = "http://" + serverArg;
    } else if (qEnvironmentVariableIsSet("REDTEAM_SERVER")) {
        serverUrl = "http://" + QString::fromLocal8Bit(qgetenv("REDTEAM_SERVER"));
    } else {
        QSettings savedSettings("RedTeam", "RedTeam-Platform");
        QString saved = savedSettings.value("server/url").toString();
        serverUrl = saved.isEmpty() ? QString("http://127.0.0.1:3002") : ("http://" + saved);
    }

    ApiClient api(serverUrl);
    qDebug() << "[main] Server URL:" << serverUrl;
    QEventLoop healthLoop;
    QTimer healthTimer;
    bool backendOk = false;

    api.get("/api/health", 5000, [&](const QJsonObject &res) {
      backendOk = (res["status"].toString() == "ok");
      splash.updateProgress(80, backendOk ? "后端已连接" : "后端未连接（可离线使用）");
      app.processEvents();
      healthLoop.quit();
    });
    healthTimer.singleShot(5000, &healthLoop, &QEventLoop::quit);
    healthLoop.exec();

    // Proceed as soon as the real initialization has finished.
    splash.updateProgress(100, "就绪");
    splash.hide();

    // ── Login + Main Window loop ─────────────────────────────────────
    // Loop supports logout → re-login with role switching.
    // Each iteration: login → create window → event loop → window destroyed.
    // This avoids all the dangling-pointer issues of signal-based window swapping.

    while (true) {
        // ── 加密锁校验闸 ───────────────────────────────────────────────
        // 策略未启用时 verifyPolicy 直接返回 true，零影响。
        // 启用且未通过则弹错误框并退出，与 pentagi-v3 行为一致。
        QString dongleError;
        if (!DongleService::verifyPolicy(DongleService::policyDir(), &dongleError)) {
            QMessageBox::critical(nullptr, QStringLiteral("加密锁校验失败"),
                dongleError + QStringLiteral("\n\n请重新插入本机已绑定的加密锁后重启客户端。"));
            return 0;
        }

        LoginDialog login(&api);
        if (login.exec() != QDialog::Accepted) {
            return 0;
        }

        QString role = login.role();
        QString username = login.username();

        QMainWindow *window = new MainWindow(&api, role, username);

        // Match splash/login size and position (76% width, 76% height, centered)
        auto *scr = QGuiApplication::primaryScreen();
        if (scr) {
            int sw = scr->geometry().width();
            int sh = scr->geometry().height();
            int winW = sw * 76 / 100;
            int winH = sh * 76 / 100;
            window->resize(winW, winH);
            window->move(scr->geometry().x() + (sw - winW) / 2,
                         scr->geometry().y() + (sh - winH) / 2);
        }

        window->show();

        // Run event loop until the window is closed or logout is requested.
        bool quitRequested = false;
        auto quitConnection = QObject::connect(&app, &QApplication::aboutToQuit,
            [&]() { quitRequested = true; });

        // Handle auth expiration — token expired and refresh failed
        auto authConnection = QObject::connect(&api, &ApiClient::authExpired,
            [&]() { QApplication::quit(); });

        app.exec();

        QObject::disconnect(quitConnection);
        QObject::disconnect(authConnection);

        // If the window was just closed (X button), exit the app
        if (!quitRequested) {
            delete window;
            return 0;
        }

        // Logout: destroy the old window and loop back to login
        delete window;
    }
}
