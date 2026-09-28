#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QTextEdit>
#include <QJsonArray>
#include <QJsonObject>

class ApiClient;
class DeployConfigPage;
class DongleVerificationPage;

class SystemPage : public QWidget {
  Q_OBJECT
public:
  explicit SystemPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

private slots:
  void onRefreshUsers();
  void onAddUser();
  void onDeleteUser();
  void onRefreshConfig();
  void onSaveConfig();
  void onConfigDoubleClicked(int row, int col);
  void onRefreshAssignments();
  void onRefreshSubmissions();
  void onRefreshPermissions();
  void onSavePermissions();

private:
  void setupUI();

  ApiClient *m_api;
  QTabWidget *m_tabs;

  // Users tab
  QTableWidget *m_userTable;
  QLineEdit *m_newUsername;
  QLineEdit *m_newPassword;
  QComboBox *m_newRole;

  // Config tab
  QTableWidget *m_configTable;
  QPushButton *m_configSaveBtn;

  // Assignments tab
  QTableWidget *m_assignmentTable;

  // Submissions tab
  QTableWidget *m_submissionTable;

  // Permissions tab
  QTableWidget *m_permTable;
  QPushButton *m_permSaveBtn;

  // Deploy config tab (moved from top-level navigation)
  DeployConfigPage *m_deployTab = nullptr;

  // 加密锁校验 tab
  DongleVerificationPage *m_dongleTab = nullptr;

  QString m_role;     // store role for conditional UI
  QString m_username; // store username for sub-pages
};
