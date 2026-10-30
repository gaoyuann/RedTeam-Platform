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
class QLineEdit;

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
  void filterFiles();
  void updateFindings(bool preserveFile=false);
  void showFinding(int row,bool navigate=true);
  void prepareSelectedFinding();
  qint64 selectedTestFinding() const;
  void updateTestButton();
  void clearEvidence();
  void loadSource(int line=0,int endLine=0);
  static QJsonObject resultData(const QJsonObject &row);
  static QString fileKey(const QJsonObject &row);
  static QString riskText(const QString &risk);
  ApiClient *m_api;
  QStringList m_taskIds;
  QString m_target,m_selectedFile,m_progressReport;
  QJsonArray m_displayRows,m_finalRows;
  QMap<QString,QTreeWidgetItem*> m_files;
  QMap<QString,bool> m_searchExpansion;
  QMap<QString,QJsonObject> m_received,m_sourceFiles;
  QString m_error;
  int m_request=0,m_outstanding=0,m_sourceRequest=0;
  qint64 m_requestedFinding=0;
  bool m_pending=true,m_fresh=false,m_canTest=false,m_browsingFile=false;
  QLabel *m_summary,*m_notice,*m_location,*m_codeNotice,*m_fileSummary;
  QLineEdit *m_fileSearch;
  QPushButton *m_refresh,*m_attack;
  QTreeWidget *m_tree;
  QPlainTextEdit *m_code,*m_evidence,*m_details;
  QTableWidget *m_findings;
  QComboBox *m_severity;
  QTimer *m_timer;
};
