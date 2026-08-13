#include "LoginDialog.h"
#include "ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QScreen>
#include <QGuiApplication>
#include <QApplication>
#include <QAction>
#include <QSettings>
#include <QCheckBox>
#include <QFrame>
#include <QPainter>
#include <QPixmap>

// ── Painted icons for password visibility toggle ──────────────────────
// SVG/QIcon::fromTheme often fails on Linux/WSL; draw with QPainter instead.

static QIcon visibilityIcon() {
  QPixmap pix(24, 24);
  pix.fill(Qt::transparent);
  QPainter p(&pix);
  p.setRenderHint(QPainter::Antialiasing);
  QPen pen(QColor("#a0aec0"), 2);
  pen.setCapStyle(Qt::RoundCap);
  p.setPen(pen);
  p.setBrush(Qt::NoBrush);
  // Eye outline: ellipse
  p.drawEllipse(2, 7, 20, 10);
  // Pupil: circle
  p.setBrush(QColor("#a0aec0"));
  p.drawEllipse(9, 9, 6, 6);
  p.end();
  return QIcon(pix);
}

static QIcon visibilityOffIcon() {
  QPixmap pix(24, 24);
  pix.fill(Qt::transparent);
  QPainter p(&pix);
  p.setRenderHint(QPainter::Antialiasing);
  QPen pen(QColor("#a0aec0"), 2);
  pen.setCapStyle(Qt::RoundCap);
  p.setPen(pen);
  p.setBrush(Qt::NoBrush);
  // Eye outline: ellipse
  p.drawEllipse(2, 7, 20, 10);
  // Pupil: circle (lighter)
  p.setBrush(QColor("#5a6a7a"));
  p.drawEllipse(9, 9, 6, 6);
  // Strike-through line
  p.setPen(QPen(QColor("#e53e3e"), 2));
  p.drawLine(4, 4, 20, 20);
  p.end();
  return QIcon(pix);
}

// ── Theme detection ───────────────────────────────────────────────────

static bool isDarkMode() {
  QSettings settings("RedTeam", "RedTeam-Platform");
  bool useDark = settings.value("appearance/dark", false).toBool();
  if (!useDark) {
    useDark = QApplication::palette().window().color().lightness() < 128;
  }
  return useDark;
}

// ── LoginDialog ───────────────────────────────────────────────────────

LoginDialog::LoginDialog(ApiClient *api, QWidget *parent)
    : QDialog(parent), m_api(api) {
  setWindowTitle("登录");
  setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

  // Size: ~3/4 screen (76% width, 76% height) — matches splash
  auto *screen = QGuiApplication::primaryScreen();
  int screenW = screen ? screen->geometry().width() : 1920;
  int screenH = screen ? screen->geometry().height() : 1080;
  int dlgW = screenW * 76 / 100;
  int dlgH = screenH * 76 / 100;
  setFixedSize(dlgW, dlgH);

  bool dark = isDarkMode();

  // Background
  setAttribute(Qt::WA_StyledBackground, true);
  if (dark) {
    setStyleSheet("QDialog { background: #0c1a30; }");
  } else {
    setStyleSheet("QDialog { background: #f5f7fa; }");
  }

  // Outer layout
  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->setContentsMargins(0, 0, 0, 0);

  // Top spacer — push card to vertical center
  outerLayout->addStretch(5);

  // ── Central card ────────────────────────────────────────────────
  auto *card = new QFrame;
  if (dark) {
    card->setStyleSheet(
      "QFrame { background: #111d2e; border: 1px solid #1e3050; border-radius: 20px; }");
  } else {
    card->setStyleSheet(
      "QFrame { background: #ffffff; border: 1px solid #dce1e8; border-radius: 20px; }");
  }
  card->setFixedWidth(qMin(480, dlgW - 200));
  card->setMinimumHeight(400);

  auto *cardLayout = new QVBoxLayout(card);
  cardLayout->setContentsMargins(52, 48, 52, 40);
  cardLayout->setSpacing(14);

  // Title
  auto *titleLabel = new QLabel("信息系统渗透智能化测试平台");
  titleLabel->setAlignment(Qt::AlignCenter);
  if (dark) {
    titleLabel->setStyleSheet("color: #e2e8f0; font-size: 24px; font-weight: bold;");
  } else {
    titleLabel->setStyleSheet("color: #1a2a3a; font-size: 24px; font-weight: bold;");
  }
  cardLayout->addWidget(titleLabel);

  // Subtitle
  auto *subLabel = new QLabel("RedTeam Platform v1.0");
  subLabel->setAlignment(Qt::AlignCenter);
  if (dark) {
    subLabel->setStyleSheet("color: #5a7a9a; font-size: 13px; margin-bottom: 4px;");
  } else {
    subLabel->setStyleSheet("color: #718096; font-size: 13px; margin-bottom: 4px;");
  }
  cardLayout->addWidget(subLabel);

  // Separator line
  auto *sep = new QFrame;
  sep->setFixedHeight(1);
  if (dark) {
    sep->setStyleSheet("background: #1e3050; margin: 8px 0;");
  } else {
    sep->setStyleSheet("background: #dce1e8; margin: 8px 0;");
  }
  cardLayout->addWidget(sep);

  cardLayout->addSpacing(8);

  // Form
  auto *formLayout = new QFormLayout;
  formLayout->setSpacing(18);
  formLayout->setLabelAlignment(Qt::AlignRight);

  // Input field style strings
  QString inputStyle, inputFocusStyle, labelStyle;
  if (dark) {
    inputStyle =
      "QLineEdit { font-size: 15px; padding: 4px 14px; "
      "background: #162236; color: #e2e8f0; border: 1px solid #2d4a6a; border-radius: 8px; }";
    inputFocusStyle =
      "QLineEdit:focus { border-color: #3a8fd6; background: #1a2a3a; }";
    labelStyle = "color: #a0aec0; font-size: 14px;";
  } else {
    inputStyle =
      "QLineEdit { font-size: 15px; padding: 4px 14px; "
      "background: #ffffff; color: #1a2a3a; border: 1px solid #dce1e8; border-radius: 8px; }";
    inputFocusStyle =
      "QLineEdit:focus { border-color: #2a7dd6; background: #f8fbff; }";
    labelStyle = "color: #4a5568; font-size: 14px;";
  }

  // Server address (new — above username)
  QSettings savedSettings("RedTeam", "RedTeam-Platform");
  QString savedServer = savedSettings.value("server/url").toString();
  // Strip http:// prefix if present for display
  if (savedServer.startsWith("http://")) savedServer = savedServer.mid(7);
  if (savedServer.startsWith("https://")) savedServer = savedServer.mid(8);

  m_serverEdit = new QLineEdit;
  m_serverEdit->setPlaceholderText("如: 192.168.1.100:3002");
  m_serverEdit->setText(savedServer.isEmpty() ? "127.0.0.1:3002" : savedServer);
  m_serverEdit->setFixedHeight(44);
  m_serverEdit->setStyleSheet(inputStyle + inputFocusStyle);
  formLayout->addRow("服务器:", m_serverEdit);

  // Username
  m_usernameEdit = new QLineEdit;
  m_usernameEdit->setPlaceholderText("请输入用户名");
  m_usernameEdit->setFixedHeight(44);
  m_usernameEdit->setStyleSheet(inputStyle + inputFocusStyle);
  formLayout->addRow("用户名:", m_usernameEdit);

  // Password
  m_passwordEdit = new QLineEdit;
  m_passwordEdit->setPlaceholderText("请输入密码");
  m_passwordEdit->setEchoMode(QLineEdit::Password);
  m_passwordEdit->setFixedHeight(44);
  m_passwordEdit->setStyleSheet(inputStyle + inputFocusStyle);

  // Password visibility toggle — use inline SVG icons
  auto *toggleAction = m_passwordEdit->addAction(visibilityIcon(), QLineEdit::TrailingPosition);
  toggleAction->setToolTip("显示/隐藏密码");
  connect(toggleAction, &QAction::triggered, this, [this, toggleAction]() {
    if (m_passwordEdit->echoMode() == QLineEdit::Password) {
      m_passwordEdit->setEchoMode(QLineEdit::Normal);
      toggleAction->setIcon(visibilityOffIcon());
    } else {
      m_passwordEdit->setEchoMode(QLineEdit::Password);
      toggleAction->setIcon(visibilityIcon());
    }
  });

  formLayout->addRow("密  码:", m_passwordEdit);

  // Style form labels
  for (int i = 0; i < formLayout->rowCount(); i++) {
    auto *labelItem = formLayout->itemAt(i, QFormLayout::LabelRole);
    if (labelItem && labelItem->widget()) {
      labelItem->widget()->setStyleSheet(labelStyle);
    }
  }

  cardLayout->addLayout(formLayout);

  // Remember password
  auto *rememberCheck = new QCheckBox("记住密码");
  if (dark) {
    rememberCheck->setStyleSheet("color: #8899aa; font-size: 13px;");
  } else {
    rememberCheck->setStyleSheet("color: #718096; font-size: 13px;");
  }
  cardLayout->addWidget(rememberCheck);

  // Load saved credentials
  QString savedUser = savedSettings.value("login/username").toString();
  QString savedPass = savedSettings.value("login/password").toString();
  if (!savedUser.isEmpty()) {
    m_usernameEdit->setText(savedUser);
    rememberCheck->setChecked(true);
  }
  if (!savedPass.isEmpty()) {
    m_passwordEdit->setText(savedPass);
  }

  // Error label
  m_errorLabel = new QLabel;
  m_errorLabel->setAlignment(Qt::AlignCenter);
  m_errorLabel->setStyleSheet("color: #fc8181; font-size: 13px; padding: 2px;");
  m_errorLabel->hide();
  cardLayout->addWidget(m_errorLabel);

  cardLayout->addSpacing(16);

  // Buttons
  auto *btnLayout = new QHBoxLayout;
  btnLayout->setSpacing(24);

  auto *exitBtn = new QPushButton("退出");
  exitBtn->setAutoDefault(false);
  exitBtn->setDefault(false);
  exitBtn->setFixedSize(150, 46);
  if (dark) {
    exitBtn->setStyleSheet(
      "QPushButton { background: #2d3748; color: #cbd5e0; border: none; border-radius: 8px; font-size: 15px; }"
      "QPushButton:hover { background: #4a5568; }");
  } else {
    exitBtn->setStyleSheet(
      "QPushButton { background: #e8ecf0; color: #4a5568; border: none; border-radius: 8px; font-size: 15px; }"
      "QPushButton:hover { background: #dce1e8; }");
  }

  m_loginBtn = new QPushButton("登  录");
  m_loginBtn->setAutoDefault(true);
  m_loginBtn->setDefault(true);
  m_loginBtn->setFixedSize(150, 46);
  // Primary blue button — same in both themes
  m_loginBtn->setStyleSheet(
    "QPushButton { background: #3a8fd6; color: #ffffff; border: none; border-radius: 8px; font-size: 15px; font-weight: bold; }"
    "QPushButton:hover { background: #4da3e8; }"
    "QPushButton:pressed { background: #2a7dd6; }");

  btnLayout->addStretch();
  btnLayout->addWidget(exitBtn);
  btnLayout->addWidget(m_loginBtn);
  btnLayout->addStretch();
  cardLayout->addLayout(btnLayout);

  // Center the card horizontally
  auto *hCenter = new QHBoxLayout;
  hCenter->addStretch();
  hCenter->addWidget(card);
  hCenter->addStretch();
  outerLayout->addLayout(hCenter);

  // Bottom spacer
  outerLayout->addStretch(4);

  // Center on screen
  if (screen) {
    auto geo = screen->geometry();
    move(geo.x() + (geo.width() - dlgW) / 2, geo.y() + (geo.height() - dlgH) / 2);
  }

  // Signals
  connect(m_loginBtn, &QPushButton::clicked, this, [this, rememberCheck]() { onLogin(rememberCheck->isChecked()); });
  connect(exitBtn, &QPushButton::clicked, this, &QDialog::reject);
  connect(m_passwordEdit, &QLineEdit::returnPressed, this, [this, rememberCheck]() { onLogin(rememberCheck->isChecked()); });
  connect(m_usernameEdit, &QLineEdit::returnPressed, m_passwordEdit,
          qOverload<>(&QWidget::setFocus));
}

QString LoginDialog::username() const { return m_username; }
QString LoginDialog::role() const { return m_role; }
QString LoginDialog::serverUrl() const { return m_serverUrl; }

void LoginDialog::onLogin(bool remember) {
  QString server = m_serverEdit->text().trimmed();
  QString user = m_usernameEdit->text().trimmed();
  QString pass = m_passwordEdit->text().trimmed();

  if (server.isEmpty()) {
    m_errorLabel->setText("请输入服务器地址");
    m_errorLabel->show();
    return;
  }
  if (user.isEmpty() || pass.isEmpty()) {
    m_errorLabel->setText("请输入用户名和密码");
    m_errorLabel->show();
    return;
  }

  // Update ApiClient server URL if changed
  QString fullServerUrl = server.startsWith("http") ? server : ("http://" + server);
  if (m_api->baseUrl() != fullServerUrl) {
    m_api->setBaseUrl(fullServerUrl);
  }

  m_loginBtn->setEnabled(false);
  m_loginBtn->setText("验证中...");
  m_errorLabel->hide();

  QJsonObject body;
  body["username"] = user;
  body["password"] = pass;

  m_api->post("/api/users/login", body, 10000, [this, user, pass, remember, server](const QJsonObject &res) {
    m_loginBtn->setEnabled(true);
    m_loginBtn->setText("登  录");

    if (res["status"].toString() == "ok") {
      auto data = res["data"].toObject();
      m_username = data["username"].toString();
      m_role = data["role"].toString();
      m_serverUrl = server;

      // Save JWT tokens to ApiClient
      QString accessToken = data["access_token"].toString();
      QString refreshToken = data["refresh_token"].toString();
      m_api->setToken(accessToken);
      m_api->setRefreshToken(refreshToken);

      // Save credentials and server to QSettings
      QSettings settings("RedTeam", "RedTeam-Platform");
      settings.setValue("server/url", server);
      settings.setValue("auth/username", user);
      settings.setValue("auth/refresh_token", refreshToken);
      if (remember) {
        settings.setValue("login/username", user);
        settings.setValue("login/password", pass);
      } else {
        settings.remove("login/username");
        settings.remove("login/password");
      }

      accept();
    } else {
      auto err = res["error"].toObject();
      QString msg = err["message"].toString();
      if (msg.isEmpty()) msg = "连接服务器失败，请确认服务器地址和端口";
      m_errorLabel->setText(msg);
      m_errorLabel->show();
      m_passwordEdit->clear();
      m_passwordEdit->setFocus();
    }
  });
}
