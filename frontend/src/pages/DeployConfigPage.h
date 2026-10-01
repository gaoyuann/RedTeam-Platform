#pragma once
#include <QWidget>
#include <QLabel>
#include <QGridLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>

class ApiClient;

class DeployConfigPage : public QWidget {
  Q_OBJECT
public:
  explicit DeployConfigPage(ApiClient *api, const QString &role = "", const QString &username = "", QWidget *parent = nullptr);

private slots:
  void onRefresh();
  void onCheckBackend();
  void onSaveLlmConfig();
  void onTestLlmConnection();
  void onSaveSandboxConfig();

private:
  void setupUI();
  void loadToolList();
  void loadConfig();
  void loadLlmConfig();
  void loadSandboxConfig();
  static void tryParseLlmValue(const QString &jsonStr, QJsonObject &out);
  void loadLabList();
  void onLabAction(const QString &action, const QString &name);
  void onLabVerify(const QString &name);
  void fitTableHeight(QTableWidget *t, int cap);

  ApiClient *m_api;

  // Platform status
  QLabel *m_versionLabel;       // 启动时间
  QLabel *m_uptimeLabel;        // 运行时长
  QLabel *m_dbSizeLabel;        // 数据库大小
  QLabel *m_dbTablesCaption;
  QGridLayout *m_dbTablesGrid;

  // Container images / tools / config (existing)
  QLabel *m_engineLabel;
  QTableWidget *m_imageTable;
  QTableWidget *m_toolTable;
  QTableWidget *m_configTable;
  QPushButton *m_refreshBtn;
  QPushButton *m_checkBtn;

  // LLM config
  QLineEdit *m_llmApiKey;
  QLineEdit *m_llmBaseUrl;
  QLineEdit *m_llmModel;
  QPushButton *m_llmSaveBtn;
  QPushButton *m_llmTestBtn;
  QLabel *m_llmStatusLabel;

  // Sandbox config
  QCheckBox *m_sandboxEnabled;
  QComboBox *m_sandboxType;
  QPushButton *m_sandboxSaveBtn;
  QLabel *m_sandboxStatusLabel;

  // Lab management
  QTableWidget *m_labTable;
  QLabel *m_labStatusLabel;
  QPushButton *m_labRefreshBtn;
};
