#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include <QFrame>
#include <QMap>
#include <QSet>

class ApiClient;

class CortexPanel : public QWidget {
  Q_OBJECT
public:
  explicit CortexPanel(ApiClient *api, QWidget *parent = nullptr);

  void addReactThought(const QString &observation,
                        const QString &thought,
                        const QString &action,
                        const QString &timestamp = {},
                        int stepIndex = -1,
                        const QString &toolId = {},
                        bool isDynamic = false);

  void addPayloadCard(const QString &payloadName,
                       const QString &payloadContext,
                       const QString &timestamp = {},
                       int stepIndex = -1);

  void clearMessages();

  void setEngineInfo(const QString &engineType, const QString &modelName = {});

  void setStatus(const QString &status);

private:
  void setupUI();
  QWidget *createReactWidget(const QString &observation, const QString &thought,
                              const QString &action, const QString &timestamp);
  QWidget *createPayloadWidget(const QString &name, const QString &context, const QString &timestamp);
  QWidget *createCollapsibleText(const QString &text, int collapseThreshold, const QString &key);
  QWidget *createStepSeparator(int stepIndex, const QString &toolId, bool isDynamic);
  void scrollToBottom();

  ApiClient *m_api;

  QLabel *m_engineLabel;
  QLabel *m_statusDot;
  QLabel *m_emptyLabel;

  QVBoxLayout *m_msgLayout;
  QScrollArea *m_scrollArea;
  QWidget *m_msgContainer;

  QSet<int> m_stepHeadersAdded;
  bool m_payloadSectionAdded = false;

  QSet<QString> m_expandedTexts;
  int m_widgetCounter = 0;
};
