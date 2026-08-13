#include "MainWindow.h"
#include "SimpleMainWindow.h"
#include "SplashDialog.h"
#include "LoginDialog.h"
#include "ApiClient.h"
#include <QApplication>
#include <QFontDatabase>
#include <QDir>
#include <QTimer>
#include <QSettings>
#include <QScreen>
#include <functional>

static const char *GLOBAL_STYLE = R"css(
/* ── QPushButton ──────────────────────────────────────────────── */
QPushButton {
  background: #2a7dd6; color: #ffffff; border: none; border-radius: 5px;
  padding: 8px 20px; font-size: 14px; font-weight: bold; min-height: 32px;
}
QPushButton:hover { background: #1e6bb8; }
QPushButton:pressed { background: #165a9e; }
QPushButton:disabled { background: #bdc3c7; color: #7f8c8d; }
QPushButton#secondaryBtn { background: #e8ecf0; color: #1a2a3a; font-weight: normal; }
QPushButton#secondaryBtn:hover { background: #dce1e8; }
QPushButton#dangerBtn { background: #e74c3c; color: #ffffff; }
QPushButton#dangerBtn:hover { background: #c0392b; }
QPushButton#checkBtn {
  background: transparent; color: #aabbcc; border: 1px solid #3a5a7a;
  border-radius: 4px; padding: 4px 14px; font-weight: normal; min-height: 24px;
}
QPushButton#checkBtn:hover { background: #243447; color: #ffffff; }

/* ── QLineEdit ────────────────────────────────────────────────── */
QLineEdit {
  border: 1px solid #dce1e8; border-radius: 5px; padding: 6px 10px;
  font-size: 14px; background: #ffffff; min-height: 28px;
}
QLineEdit:focus { border-color: #2a7dd6; }

/* ── QComboBox ────────────────────────────────────────────────── */
QComboBox {
  border: 1px solid #dce1e8; border-radius: 5px; padding: 6px 10px;
  font-size: 14px; background: #ffffff; min-height: 28px;
}
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
  selection-background-color: #2a7dd6; selection-color: #ffffff;
  border: 1px solid #dce1e8;
}

/* ── QTableWidget ─────────────────────────────────────────────── */
QTableWidget {
  border: 1px solid #dce1e8; border-radius: 4px; gridline-color: #e8ecf0;
  font-size: 14px; background: #ffffff; alternate-background-color: #f0f4f8;
}
QTableWidget::item { padding: 6px; }
QHeaderView::section {
  background: #1a2a3a; color: #ffffff; font-size: 14px; font-weight: bold;
  padding: 8px 6px; border: none;
}
QTableWidget::item:selected { background: #2a7dd6; color: #ffffff; }

/* ── QTabWidget ───────────────────────────────────────────────── */
QTabWidget::pane {
  border: 1px solid #dce1e8; border-radius: 4px; background: #f5f7fa;
  padding: 8px;
}
QTabBar::tab {
  background: #e8ecf0; color: #5a6a7a; padding: 10px 24px; font-size: 14px;
  font-weight: bold; border-top-left-radius: 5px; border-top-right-radius: 5px;
  margin-right: 2px;
}
QTabBar::tab:selected { background: #2a7dd6; color: #ffffff; }
QTabBar::tab:hover:!selected { background: #dce1e8; }

/* ── QTreeWidget ──────────────────────────────────────────────── */
QTreeWidget {
  border: 1px solid #dce1e8; border-radius: 4px; font-size: 14px;
  background: #ffffff; alternate-background-color: #f0f4f8;
}
QTreeWidget::item { padding: 4px; }

/* ── QTextEdit ────────────────────────────────────────────────── */
QTextEdit {
  border: 1px solid #dce1e8; border-radius: 4px; font-size: 13px;
  background: #fafbfc; padding: 8px;
}

/* ── QCheckBox ────────────────────────────────────────────────── */
QCheckBox { font-size: 14px; spacing: 8px; }

/* ── QProgressBar ─────────────────────────────────────────────── */
QProgressBar {
  background: #1a2a3a; border: none; border-radius: 4px;
  text-align: center; color: #ffffff; min-height: 10px;
}
QProgressBar::chunk { background: #3a8fd6; border-radius: 4px; }

/* ── QScrollBar ───────────────────────────────────────────────── */
QScrollBar:vertical { background: #f0f4f8; width: 10px; border: none; }
QScrollBar::handle:vertical { background: #bdc3c7; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #95a5a6; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar:horizontal { background: #f0f4f8; height: 10px; border: none; }
QScrollBar::handle:horizontal { background: #bdc3c7; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #95a5a6; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }

/* ── QStatusBar ───────────────────────────────────────────────── */
QStatusBar { background: #1a2a3a; color: #aabbcc; font-size: 13px; }

/* ── Status label colors (unified) ────────────────────────────── */
QLabel#statusSuccess { color: #166534; }
QLabel#statusError   { color: #991b1b; }
QLabel#statusWarning { color: #b45309; }
QLabel#statusInfo    { color: #1d4ed8; }

/* ── Content area ─────────────────────────────────────────────── */
QWidget#contentArea { background: #f5f7fa; }

/* ── Navigation list ──────────────────────────────────────────── */
QListWidget#navList {
  background: #1a2a3a; color: #aabbcc; border: none;
  font-size: 15px; font-weight: bold; outline: none; padding: 8px;
}
QListWidget#navList::item { padding: 14px 16px; border-radius: 6px; margin: 2px 4px; }
QListWidget#navList::item:selected { background: #2a7dd6; color: #ffffff; }
QListWidget#navList::item:hover:!selected { background: #243447; color: #ffffff; }
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
    QApplication app(argc, argv);

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

    splash.updateProgress(100, "就绪");
    app.processEvents();

    // Brief display of "ready" state — show splash for ~10 seconds total
    QTimer::singleShot(9500, &splash, &SplashDialog::hide);
    QEventLoop finishLoop;
    QTimer::singleShot(9600, &finishLoop, &QEventLoop::quit);
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

        // Update ApiClient server URL if user changed it in login dialog
        QString loginServer = login.serverUrl();
        if (!loginServer.isEmpty()) {
            QString fullUrl = loginServer.startsWith("http") ? loginServer : ("http://" + loginServer);
            if (api.baseUrl() != fullUrl) {
                api.setBaseUrl(fullUrl);
            }
        }

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
