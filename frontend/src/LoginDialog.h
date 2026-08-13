#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>

class ApiClient;

class LoginDialog : public QDialog {
  Q_OBJECT
public:
  explicit LoginDialog(ApiClient *api, QWidget *parent = nullptr);

  QString username() const;
  QString role() const;

private slots:
  void onLogin(bool remember);

private:
  ApiClient *m_api;
  QLineEdit *m_usernameEdit;
  QLineEdit *m_passwordEdit;
  QLabel *m_errorLabel;
  QPushButton *m_loginBtn;

  QString m_username;
  QString m_role;
};
