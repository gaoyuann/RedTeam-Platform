#pragma once
#include <QDialog>
#include <QJsonObject>
#include <QJsonArray>
#include <QList>
#include <QMap>
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
class QGroupBox;
class FindingVerificationDialog : public QDialog {
  Q_OBJECT
public:
  FindingVerificationDialog(ApiClient *api, const QString &pipeline, const QList<qint64> &findings, QWidget *parent=nullptr,
      const QString &existingVerificationId={}, const QString &existingAttemptId={});
protected:
  void done(int result) override;
  void resizeEvent(QResizeEvent *event) override;
private:
  bool allowDiscardDraft();
  void addFinding(qint64 finding);
  void addExistingFinding(const QString &id, qint64 finding, const QString &state={});
  void load(bool editor=false);
  void loadSources();
  void showSourcePreview();
  void showPayloadPreview();
  void updateQueue();
  void startChecked();
  QString confirmationText(const QJsonObject &detail) const;
  bool confirmExecution(const QString &title, const QString &text);
  void renderAttempt(int index);
  void renderEvidence(int row);
  void setStatus(const QString &text);
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
  QLineEdit *m_name, *m_target, *m_objective;
  QPlainTextEdit *m_conditions, *m_missing, *m_criteria, *m_cleanup, *m_evidence, *m_note, *m_context, *m_evidenceDetails;
  QComboBox *m_sources, *m_payloads, *m_attempts, *m_conclusion, *m_objectiveCategory;
  QCheckBox *m_confirm;
  QLabel *m_status;
  QLabel *m_attemptContext, *m_executionSummary, *m_resultConclusion, *m_automaticSummary, *m_manualSummary, *m_disagreement, *m_resultBasis=nullptr;
  QTabWidget *m_tabs;
  QTabWidget *m_resultDetails;
  QGroupBox *m_resultSummary;
  QPlainTextEdit *m_planSummary;
  QPushButton *m_prepareSimple, *m_confirmSimple, *m_startSimple;
  QTimer *m_timer;
  QPushButton *m_systemEvidence, *m_save, *m_start, *m_confirmButton, *m_generate;
  QJsonObject m_detail;
  QJsonArray m_matches, m_planSteps, m_sourceItems;
  QPlainTextEdit *m_sourcePreview, *m_payloadPreview;
  QGroupBox *m_sourceChooser;
  QComboBox *m_bindStep;
  QPushButton *m_useSource, *m_adjustAI, *m_bindPayload, *m_unbindPayload, *m_resolvePayload, *m_queueButton, *m_sourcesNext, *m_sourcesPrevious;
  QLineEdit *m_sourceSearch;
  QLabel *m_queueLabel;
  QMap<QString,QJsonObject> m_details;
  QMap<QString,QJsonObject> m_queuePlans;
  bool m_browseSources=false;
  int m_sourceOffset=0;
  quint64 m_sourceRequest=0;
  QString m_evidenceAttempt, m_pendingPayload;
  QString m_pendingAttemptRunId;
  QString m_pendingExistingAttemptId;
  quint64 m_attemptSelectionGeneration=0;
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
