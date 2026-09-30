#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include <QFrame>
#include <QMap>
#include <QSet>

class ApiClient;

/**
 * CortexPanel — 决策核心面板
 *
 * 结构化决策时间线，展示 ReAct 推理过程和载荷知识注入。
 * 按步骤分组，支持长内容展开/折叠。
 */
class CortexPanel : public QWidget {
  Q_OBJECT
public:
  explicit CortexPanel(ApiClient *api, QWidget *parent = nullptr);

  /// 添加结构化 ReAct 思考消息
  void addReactThought(const QString &observation,
                        const QString &thought,
                        const QString &action,
                        const QString &timestamp = {},
                        int stepIndex = -1,
                        const QString &toolId = {},
                        bool isDynamic = false);

  /// 添加载荷知识卡片
  void addPayloadCard(const QString &payloadName,
                       const QString &payloadContext,
                       const QString &timestamp = {},
                       int stepIndex = -1);

  /// 清空所有消息
  void clearMessages();

  /// 设置引擎信息（显示在 header）
  void setEngineInfo(const QString &engineType, const QString &modelName = {});

  /// 设置运行状态（驱动状态点颜色）
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

  // Header
  QLabel *m_engineLabel;
  QLabel *m_statusDot;

  // Message area
  QVBoxLayout *m_msgLayout;
  QScrollArea *m_scrollArea;
  QWidget *m_msgContainer;

  // Step grouping: track which step indices already have separators
  QSet<int> m_stepHeadersAdded;
  bool m_payloadSectionAdded = false;

  // Expand/collapse state
  QSet<QString> m_expandedTexts;
  int m_widgetCounter = 0;
};
