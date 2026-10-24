#pragma once
#include <QDialog>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <QList>
#include <QStringList>

class ApiClient;
class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
class QPlainTextEdit;
class QTableWidget;
class QComboBox;
class QTimer;

class SourceScanDetailDialog : public QDialog {
  Q_OBJECT
public:
  SourceScanDetailDialog(ApiClient *api,const QStringList &taskIds,const QString &target,QWidget *parent=nullptr);
  void refresh();
  void setSnapshots(const QJsonArray &tasks);
  void selectFinding(qint64 id);
signals:
  void testRequested(const QList<qint64> &findingIds);
private:
  void rebuildFiles();
  void updateFindings();
  void showFinding(int row);
  void showAttackTable();
  void clearEvidence();
  void loadSource(int line=0);
  static QJsonObject resultData(const QJsonObject &row);
  static QString fileKey(const QJsonObject &row);
  static QString riskText(const QString &risk);
  ApiClient *m_api;
  QStringList m_taskIds;
  QString m_target,m_selectedFile,m_progressReport;
  QJsonArray m_displayRows,m_finalRows;
  QMap<QString,QTreeWidgetItem*> m_files;
  QMap<QString,QJsonObject> m_received,m_sourceFiles;
  QString m_error;
  int m_request=0,m_outstanding=0,m_snapshotRevision=0,m_sourceRequest=0;
  bool m_pending=true,m_fresh=false,m_canTest=false;
  QLabel *m_summary,*m_notice,*m_location,*m_codeNotice;
  QPushButton *m_refresh,*m_attack;
  QTreeWidget *m_tree;
  QPlainTextEdit *m_code,*m_evidence,*m_details;
  QTableWidget *m_findings;
  QComboBox *m_severity;
  QTimer *m_timer;
};
