#pragma once
#include <QDialog>
#include <QJsonObject>
#include <QJsonArray>
#include <QList>
#include <memory>
class ApiClient;
class QTableWidget;
class QLineEdit;
class QPlainTextEdit;
class QComboBox;
class QCheckBox;
class QLabel;
class QTimer;
class QPushButton;
class QTabWidget;
class FindingVerificationDialog : public QDialog {
  Q_OBJECT
public:
  FindingVerificationDialog(ApiClient *api, const QString &pipeline, const QList<qint64> &findings, QWidget *parent=nullptr);
protected:
  void done(int result) override;
private:
  bool allowDiscardDraft();
  void addFinding(qint64 finding);
  void load(bool editor=false);
  void renderAttempt(int index);
  void displayPlan(const QJsonObject &plan);
  QJsonObject planInput() const;
  void action(const QString &path, const QJsonObject &body, bool reloadEditor=false);
  void executeNext();
  void startCurrent();
  void startAttempt(const QString &id, int revision);
  void cancelCurrent();
  void updateButtons();
  QString base() const;
  QString currentId() const;
  ApiClient *m_api;
  QString m_pipeline;
  QTableWidget *m_items, *m_steps, *m_evidenceTable;
  QLineEdit *m_name, *m_target;
  QPlainTextEdit *m_conditions, *m_missing, *m_criteria, *m_cleanup, *m_evidence, *m_note, *m_context;
  QComboBox *m_sources, *m_payloads, *m_attempts, *m_conclusion;
  QCheckBox *m_confirm;
  QLabel *m_status;
  QTabWidget *m_tabs;
  QPlainTextEdit *m_planSummary;
  QPushButton *m_prepareSimple, *m_confirmSimple, *m_startSimple;
  QTimer *m_timer;
  QPushButton *m_save, *m_start, *m_confirmButton, *m_generate;
  QJsonObject m_detail;
  QJsonArray m_matches, m_planSteps;
  QString m_evidenceAttempt;
  QStringList m_queue;
  QString m_activeQueue, m_queueRunId;
  quint64 m_queueGeneration=0, m_contextGeneration=0, m_editGeneration=0, m_templateGeneration=0;
  bool m_queuePreparing=false, m_queueStarting=false, m_finished=false;
  bool m_stale=false, m_reloadEditor=false;
  std::shared_ptr<bool> m_queueCancelled=std::make_shared<bool>(false);
  bool m_loading=false, m_busy=false, m_dirty=false, m_setting=false;
  int m_revision=0;
  QString m_sourceId;
};
