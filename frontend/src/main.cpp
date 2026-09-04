#include "MainWindow.h"
#include "SimpleMainWindow.h"
#include "SplashDialog.h"
#include "LoginDialog.h"
#include "ApiClient.h"
#include <QApplication>
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

static const char *GLOBAL_STYLE = R"css(
QWidget { color: #172033; }
QWidget#contentArea { background: #f3f6fb; }

QPushButton {
  background: #f8fafc; color: #1e293b; border: 1px solid #cbd5e1; border-radius: 8px;
  padding: 7px 14px; font-size: 14px; font-weight: 600; min-height: 30px;
}
QPushButton:hover { background: #eef4ff; border-color: #93b4ed; }
QPushButton:pressed { background: #dbeafe; }
QPushButton:disabled { background: #f1f5f9; color: #94a3b8; border-color: #e2e8f0; }
QPushButton[primary="true"] { background: #2563eb; color: #ffffff; border-color: #1d4ed8; }
QPushButton[primary="true"]:hover { background: #1d4ed8; border-color: #1e40af; }
QPushButton[danger="true"], QPushButton#dangerBtn { background: #fff1f2; color: #b42318; border-color: #fecdd3; }
QPushButton[danger="true"]:hover, QPushButton#dangerBtn:hover { background: #ffe4e6; border-color: #fda4af; }
QPushButton#checkBtn {
  background: transparent; color: #cbd5e1; border: 1px solid #41546e;
  border-radius: 7px; padding: 4px 12px; font-weight: 500; min-height: 22px;
}
QPushButton#checkBtn:hover { background: #253955; color: #ffffff; border-color: #6b8db8; }

QLineEdit, QComboBox, QSpinBox {
  border: 1px solid #cbd5e1; border-radius: 8px; padding: 6px 10px;
  font-size: 14px; background: #ffffff; min-height: 28px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #3b82f6; background: #fefeff; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { selection-background-color: #2563eb; selection-color: #ffffff; border: 1px solid #cbd5e1; }

QTableWidget, QTreeWidget {
  border: 1px solid #dbe3ef; border-radius: 10px; gridline-color: #edf2f7;
  font-size: 14px; background: #ffffff; alternate-background-color: #f8fbff;
}
QTableWidget::item, QTreeWidget::item { padding: 7px 8px; }
QHeaderView::section {
  background: #eef4fb; color: #334155; font-size: 13px; font-weight: 700;
  padding: 9px 8px; border: none; border-bottom: 1px solid #dbe3ef;
}
QTableWidget::item:selected, QTreeWidget::item:selected { background: #dbeafe; color: #1e3a8a; }

QTabWidget::pane { border: 1px solid #dbe3ef; border-radius: 10px; background: #ffffff; padding: 8px; }
QTabBar::tab {
  background: transparent; color: #64748b; padding: 9px 16px; font-size: 14px;
  font-weight: 600; border-bottom: 2px solid transparent; margin-right: 4px;
}
QTabBar::tab:selected { color: #1d4ed8; border-bottom-color: #2563eb; }
QTabBar::tab:hover:!selected { color: #334155; background: #f1f5f9; border-radius: 6px; }

QTextEdit, QPlainTextEdit {
  border: 1px solid #cbd5e1; border-radius: 8px; font-size: 13px;
  background: #fbfdff; padding: 8px;
}
QCheckBox, QRadioButton { font-size: 14px; spacing: 8px; }
QProgressBar { background: #e2e8f0; border: none; border-radius: 5px; text-align: center; color: #334155; min-height: 10px; }
QProgressBar::chunk { background: #2563eb; border-radius: 5px; }

QScrollBar:vertical { background: transparent; width: 10px; border: none; }
QScrollBar::handle:vertical { background: #cbd5e1; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #94a3b8; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar:horizontal { background: transparent; height: 10px; border: none; }
QScrollBar::handle:horizontal { background: #cbd5e1; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #94a3b8; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }

QStatusBar { background: #10243e; color: #cbd5e1; font-size: 13px; padding: 2px 8px; }
QLabel#statusSuccess { color: #166534; }
QLabel#statusError   { color: #b42318; }
QLabel#statusWarning { color: #b45309; }
QLabel#statusInfo    { color: #1d4ed8; }

QFrame#sidebar { background: #10243e; border: none; }
QLabel#sidebarBrand { color: #ffffff; font-size: 19px; font-weight: 800; letter-spacing: 1px; }
QLabel#sidebarSubtitle { color: #93b4d5; font-size: 12px; }
QFrame#sidebarDivider { color: #294667; background: #294667; max-height: 1px; }
QLabel#sidebarFooter { color: #6f91b5; font-size: 11px; padding: 4px 2px; }
QListWidget#navList {
  background: transparent; color: #a8bdd5; border: none;
  font-size: 14px; font-weight: 600; outline: none; padding: 2px 0;
}
QListWidget#navList::item { padding: 12px 13px; border-radius: 8px; margin: 2px 0; }
QListWidget#navList::item:selected { background: #2563eb; color: #ffffff; }
QListWidget#navList::item:hover:!selected { background: #1d3655; color: #ffffff; }
)css";

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
        app.setStyleSheet(GLOBAL_STYLE_DARK);
    } else {
        app.setStyleSheet(GLOBAL_STYLE);
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

    // Animate progress from 80% → 100% over ~10 seconds (1% per 500ms)
    // so the user sees the progress bar moving during the wait.
    QEventLoop finishLoop;
    QTimer animTimer;
    int animProgress = 80;
    animTimer.start(500);

    QObject::connect(&animTimer, &QTimer::timeout, [&]() {
      animProgress++;
      QString msg;
      if (animProgress < 85)       msg = QStringLiteral("正在初始化模块...");
      else if (animProgress < 90)  msg = QStringLiteral("正在加载配置...");
      else if (animProgress < 100) msg = QStringLiteral("正在准备界面...");
      else                         msg = QStringLiteral("就绪");

      splash.updateProgress(animProgress, msg);

      if (animProgress >= 100) {
        animTimer.stop();
        splash.hide();
        finishLoop.quit();
      }
    });

    finishLoop.exec();

    // ── Login + Main Window loop ─────────────────────────────────────
    // Loop supports logout → re-login with role switching.
    // Each iteration: login → create window → event loop → window destroyed.
    // This avoids all the dangling-pointer issues of signal-based window swapping.

    while (true) {
        LoginDialog login(&api);
        if (login.exec() != QDialog::Accepted) {
            return 0;
        }

        QString role = login.role();
        QString username = login.username();

        // Create the appropriate window type for this role
        QMainWindow *window = nullptr;
        if (role == "admin" || role == "teacher") {
            window = new MainWindow(&api, role, username);
        } else {
            window = new SimpleMainWindow(&api, role, username);
        }

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
        // Both MainWindow and SimpleMainWindow call QApplication::quit() on
        // logout-with-exit, and close() on window close. We intercept quit
        // to distinguish "logout" (loop again) from "real quit" (return 0).
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
