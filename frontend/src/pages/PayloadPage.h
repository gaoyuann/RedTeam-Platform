#pragma once
#include <QWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QTextEdit>
#include <QSplitter>
#include <QStackedWidget>
#include <QDialog>
#include <QPointer>

class ApiClient;

class PayloadPage : public QWidget {
  Q_OBJECT
public:
  explicit PayloadPage(ApiClient *api, const QString &role = "",
                       const QString &username = "", QWidget *parent = nullptr);

  void selectPayload(const QString &payloadId);

private slots:
  void onLoadCategories();
  void onCategoryClicked(QTreeWidgetItem *item, int column);
  void onPayloadClicked(int row, int col);
  void onSearchChanged(const QString &text);
  void onTypeFilterChanged(int index);
  void onCopyCommand();
  void onAiGenerate();
  void onBindToPlaybook();

private:
  void setupUI();
  void loadPayloadList(const QString &category = "", const QString &type = "", const QString &keyword = "");
  void loadPayloadDetail(const QString &id);
  void showPayloadDetail(const QJsonObject &payload);
  void clearDetail();

  ApiClient *m_api;
  QString m_role;
  QString m_username;

  // Left panel: category tree + payload list
  QTreeWidget *m_categoryTree;
  QTableWidget *m_payloadTable;
  QComboBox *m_typeFilter;
  QLineEdit *m_searchInput;

  // Right panel: detail
  QStackedWidget *m_detailStack;
  QLabel *m_placeholderLabel;  // "选择载荷查看详情"

  // Detail content widgets
  QLabel *m_nameLabel;
  QLabel *m_categoryLabel;
  QLabel *m_descLabel;
  QTextEdit *m_commandsEdit;
  QTextEdit *m_bypassEdit;
  QTextEdit *m_defenseEdit;
  QTextEdit *m_opsecEdit;

  // Action buttons
  QPushButton *m_copyBtn;
  QPushButton *m_bindBtn;
  QPushButton *m_aiGenBtn;

  // State
  QString m_selectedId;
  QString m_currentCategory;
  QString m_currentType;
  QString m_currentKeyword;
  QString m_primaryCommand;  // for copy
};
