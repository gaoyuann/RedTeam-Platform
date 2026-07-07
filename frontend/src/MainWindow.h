#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QStatusBar>
#include <QNetworkAccessManager>
#include <QPushButton>
#include <QTableWidget>
#include <QLabel>
#include <QTextEdit>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onModuleChanged(int row);
    void onCheckBackend();
    void onBackendReply(QNetworkReply *reply);
    void onFetchDbData();
    void onDbDataReply(QNetworkReply *reply);
    void onContainerTest();
    void onContainerTestReply(QNetworkReply *reply);

private:
    void setupUI();
    void setupVerificationPage(QWidget *page);

    QListWidget *m_navList;
    QStackedWidget *m_stackWidget;
    QPushButton *m_checkBackendBtn;
    QNetworkAccessManager *m_networkMgr;

    // Verification page widgets
    QLabel *m_backendStatusLabel;
    QTableWidget *m_dbTable;
    QPushButton *m_fetchDbBtn;
    QPushButton *m_containerTestBtn;
    QTextEdit *m_containerOutput;

    const QStringList m_modules = {
        QStringLiteral("渗透测试资源部署配置"),
        QStringLiteral("漏洞利用想定与预案"),
        QStringLiteral("网络拓扑探测与绘制"),
        QStringLiteral("脆弱性扫描"),
        QStringLiteral("漏洞攻击测试"),
        QStringLiteral("测试评估"),
        QStringLiteral("系统管理")
    };
};

#endif // MAINWINDOW_H
