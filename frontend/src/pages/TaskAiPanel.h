#pragma once

#include <QJsonObject>
#include <QList>
#include <QWidget>

class ApiClient;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QScrollArea;
class QVBoxLayout;

class TaskAiPanel : public QWidget {
  Q_OBJECT
public:
  explicit TaskAiPanel(ApiClient *api, QWidget *parent = nullptr);

  void setTaskContext(const QJsonObject &pipeline);
  void clearTaskContext();
  void setStage(const QString &stage);
  void setQuestion(const QString &question);

private slots:
  void onAsk();

private:
  struct ConversationMessage {
    QString role;
    QString text;
  };

  void setupUI();
  void rebuildContext();
  void addCard(const QString &title, const QString &text, const QString &accent);
  void addConversationCard(const ConversationMessage &message);
  void scrollToBottom();

  ApiClient *m_api;
  QJsonObject m_pipeline;
  QString m_pipelineId;
  QString m_stage;
  QList<ConversationMessage> m_messages;

  QLabel *m_stageLabel;
  QLabel *m_contextStateLabel;
  QLabel *m_emptyLabel;
  QScrollArea *m_scrollArea;
  QWidget *m_contentWidget;
  QVBoxLayout *m_contentLayout;
  QPlainTextEdit *m_promptEdit;
  QPushButton *m_askButton;
  int m_contextRevision = 0;
  bool m_requestInFlight = false;
};
