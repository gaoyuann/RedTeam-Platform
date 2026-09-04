#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QFrame>
#include <QPointer>

class ApiClient;

/**
 * CortexPanel — 决策核心对话面板
 *
 * 移植自 RedTeam-Edu AIDecisionPanel，适配 Qt5 浅色主题。
 * 展示四种消息：
 *   - User:      用户输入指令
 *   - Model:     AI 系统回复（TTP 格式）
 *   - ReactThought: ReAct 推理过程（发现→分析→动作）
 *   - Payload:   载荷知识注入（攻防一体卡片）
 */
class CortexPanel : public QWidget {
  Q_OBJECT
public:
  enum class Role { User, Model, ReactThought, Payload };

  explicit CortexPanel(ApiClient *api, QWidget *parent = nullptr);

  /// 添加普通消息
  void addMessage(Role role, const QString &text, const QString &timestamp = {});

  /// 添加结构化 ReAct 思考消息
  void addReactThought(const QString &observation,
                        const QString &thought,
                        const QString &action,
                        const QString &timestamp = {});

  /// 添加载荷知识卡片
  void addPayloadCard(const QString &payloadName,
                       const QString &payloadContext,
                       const QString &timestamp = {});

  /// 清空所有消息
  void clearMessages();

  /// 设置自动驾驶模式（锁定输入）
  void setAutoMode(bool autoMode);

  /// 设置引擎信息（显示在 header）
  void setEngineInfo(const QString &engineType, const QString &modelName = {});

signals:
  /// 用户发送了一条指令
  void userMessageSent(const QString &text);

private:
  void setupUI();
  QWidget *createMessageWidget(Role role, const QString &text, const QString &timestamp);
  QWidget *createReactWidget(const QString &observation, const QString &thought,
                              const QString &action, const QString &timestamp);
  QWidget *createPayloadWidget(const QString &name, const QString &context, const QString &timestamp);
  QWidget *createTtpWidget(const QString &text, const QString &timestamp);
  void scrollToBottom();

  ApiClient *m_api;

  // Header
  QLabel *m_engineLabel;
  QLabel *m_statusDot;

  // Message area
  QVBoxLayout *m_msgLayout;
  QScrollArea *m_scrollArea;
  QWidget *m_msgContainer;

  // Input area
  QLineEdit *m_input;
  QPushButton *m_sendBtn;
  bool m_autoMode = false;
};
