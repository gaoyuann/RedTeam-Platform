#pragma once

#include <QJsonObject>
#include <QWidget>
#include <functional>

class ApiClient;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;

class TaskPlanPage : public QWidget {
  Q_OBJECT
public:
  explicit TaskPlanPage(ApiClient *api, const QString &role, QWidget *parent = nullptr);
  void setTaskContext(const QJsonObject &pipeline);
  void clearTaskContext();
  void addCandidate(const QString &category, int index, const QJsonValue &source);
  void useSourcePlaybook(const QString &playbookId);

signals:
  void planChanged();
  void executionStarted();
  void sourceVerificationRequested();

private:
  void refresh(bool discard = false);
  void loadSources(int requestVersion);
  void render();
  void updateControls();
  void markDirty();
  void editStep();
  void showStep();
  void moveStep(int direction);
  void save();
  void transition(const QString &action);
  void sendCandidate(const QJsonObject &candidate);
  void mutate(const QString &suffix, const QJsonObject &body, bool put = false,
              std::function<void()> after = nullptr);
  void message(const QString &text, bool error = false);

  ApiClient *m_api;
  QString m_role;
  QJsonObject m_pipeline;
  QJsonObject m_plan;
  QJsonObject m_content;
  int m_contextVersion = 0;
  int m_requestVersion = 0;
  bool m_busy = false;
  bool m_dirty = false;
  bool m_rendering = false;
  QString m_pendingSourcePlaybookId;
  QLabel *m_status;
  QLabel *m_scope;
  QComboBox *m_source;
  QPushButton *m_create;
  QPushButton *m_generateSource;
  QPushButton *m_refresh;
  QPushButton *m_save;
  QPushButton *m_submit;
  QPushButton *m_reopen;
  QPushButton *m_reject;
  QPushButton *m_approve;
  QLineEdit *m_name;
  QPlainTextEdit *m_notes;
  QTableWidget *m_steps;
  QLineEdit *m_stepName;
  QPlainTextEdit *m_args;
  QCheckBox *m_optional;
  QPushButton *m_up;
  QPushButton *m_down;
  QPushButton *m_remove;
  QTableWidget *m_suggestions;
  QPlainTextEdit *m_suggestionDetail;
  QTableWidget *m_history;
};
