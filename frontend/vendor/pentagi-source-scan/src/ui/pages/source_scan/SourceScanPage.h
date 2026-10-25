#pragma once
#include "models/SourceScanTypes.h"
#include <QDialog>
#include <QMap>
#include <QPointer>
#include <QWidget>

class ConfigManager;
class SourceScanService;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QComboBox;
class QTableWidget;
class QTextBrowser;
class QTreeWidget;
class QTreeWidgetItem;
class QStackedWidget;
class PentagiSourceScanDetailDialog : public QDialog {
    Q_OBJECT
  public:
    PentagiSourceScanDetailDialog(ConfigManager *config, SourceScanService *service, const QString &id,
                           QWidget *parent = nullptr);
    void reload();
    void reject() override;

  private:
    void refresh();
    void showFile(const QString &path, int line = 0, int endLine = 0);
    void showFinding(int row);
    void updateFindings();
    void tick();
    ConfigManager *m_config;
    SourceScanService *m_service;
    QString m_id, m_currentPath;
    SourceScanTask m_task;
    QList<SourceScanFile> m_files;
    QList<SourceScanFinding> m_findings;
    QMap<QString, QTreeWidgetItem *> m_fileItems;
    QLabel *m_heading, *m_sourceLabel, *m_summary, *m_notice, *m_countdown;
    QTreeWidget *m_tree;
    QPlainTextEdit *m_code;
    QTableWidget *m_results;
    QTextBrowser *m_details;
    QComboBox *m_severity;
    QPushButton *m_refresh;
    int m_remaining = 300;
};
class SourceScanPage : public QWidget {
    Q_OBJECT
  public:
    explicit SourceScanPage(ConfigManager *config, QWidget *parent = nullptr);
    void reload();

  protected:
    void showEvent(QShowEvent *event) override;

  private:
    void newScan();
    void openTask(const QString &id);
    void filterTasks();
    ConfigManager *m_config;
    SourceScanService *m_service;
    QTableWidget *m_tasks;
    QLineEdit *m_search;
    QComboBox *m_state;
    QLabel *m_notice;
    QPushButton *m_newScan;
    QMap<QString, QPointer<PentagiSourceScanDetailDialog>> m_windows;
    QStackedWidget *m_workspace;
};
