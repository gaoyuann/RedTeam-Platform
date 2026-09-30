#include "CortexPanel.h"
#include "Theme.h"
#include "ApiClient.h"
#include <QHBoxLayout>
#include <QScrollBar>
#include <QTimer>
#include <QDateTime>
#include <QPushButton>

// ── Helpers ──────────────────────────────────────────────────────────────

static QString nowTime() {
  return QTime::currentTime().toString(QStringLiteral("HH:mm:ss"));
}

// ── Constructor ──────────────────────────────────────────────────────────

CortexPanel::CortexPanel(ApiClient *api, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
}

void CortexPanel::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(0, 0, 0, 0);
  mainLayout->setSpacing(0);

  // ── Header ────────────────────────────────────────────────────────────
  auto *headerFrame = new QFrame;
  headerFrame->setStyleSheet(
    "QFrame { background: #ffffff; border-bottom: 1px solid #dbe5f0; }");
  auto *headerL = new QHBoxLayout(headerFrame);
  headerL->setContentsMargins(12, 6, 12, 6);

  auto *titleLbl = new QLabel(QStringLiteral("决策核心"));
  titleLbl->setStyleSheet("font-size: 13px; font-weight: bold; color: #1a2a3a;");
  headerL->addWidget(titleLbl);

  headerL->addStretch();

  m_engineLabel = new QLabel(QStringLiteral("引擎: 未配置"));
  m_engineLabel->setStyleSheet(
    "font-size: 10px; color: #64748b; background: #f1f5f9; "
    "border: 1px solid #e2e8f0; border-radius: 4px; padding: 2px 8px;");
  headerL->addWidget(m_engineLabel);

  m_statusDot = new QLabel(QStringLiteral("●"));
  m_statusDot->setStyleSheet("font-size: 12px; color: #94a3b8;");
  headerL->addWidget(m_statusDot);

  mainLayout->addWidget(headerFrame);

  // ── Message area ──────────────────────────────────────────────────────
  m_msgContainer = new QWidget;
  m_msgLayout = new QVBoxLayout(m_msgContainer);
  m_msgLayout->setContentsMargins(8, 8, 8, 8);
  m_msgLayout->setSpacing(6);
  m_msgLayout->addStretch();  // push messages up

  m_scrollArea = new QScrollArea;
  m_scrollArea->setWidgetResizable(true);
  m_scrollArea->setFrameShape(QFrame::NoFrame);
  m_scrollArea->setWidget(m_msgContainer);
  m_scrollArea->setStyleSheet("QScrollArea { background: #f8fafc; }");
  mainLayout->addWidget(m_scrollArea, 1);
}

// ── Public API ───────────────────────────────────────────────────────────

void CortexPanel::addReactThought(const QString &observation, const QString &thought,
                                    const QString &action, const QString &timestamp,
                                    int stepIndex, const QString &toolId, bool isDynamic) {
  QString ts = timestamp.isEmpty() ? nowTime() : timestamp;

  // Insert step separator if this step hasn't been seen before
  if (stepIndex >= 0 && !m_stepHeadersAdded.contains(stepIndex)) {
    m_stepHeadersAdded.insert(stepIndex);
    auto *sep = createStepSeparator(stepIndex, toolId, isDynamic);
    m_msgLayout->insertWidget(m_msgLayout->count() - 1, sep);
  }

  auto *w = createReactWidget(observation, thought, action, ts);
  m_msgLayout->insertWidget(m_msgLayout->count() - 1, w);
  scrollToBottom();
}

void CortexPanel::addPayloadCard(const QString &payloadName, const QString &payloadContext,
                                   const QString &timestamp, int stepIndex) {
  QString ts = timestamp.isEmpty() ? nowTime() : timestamp;

  // Insert payload section separator before the first payload card
  if (!m_payloadSectionAdded) {
    m_payloadSectionAdded = true;
    auto *sepFrame = new QFrame;
    sepFrame->setStyleSheet(
      "QFrame { background: #fffbeb; border: none; border-left: 3px solid #f59e0b; "
      "border-radius: 0 4px 4px 0; }");
    auto *sepL = new QHBoxLayout(sepFrame);
    sepL->setContentsMargins(10, 4, 10, 4);
    auto *sepLbl = new QLabel(QStringLiteral("⚡ 载荷知识"));
    sepLbl->setStyleSheet("font-size: 11px; font-weight: bold; color: #92400e;");
    sepL->addWidget(sepLbl);
    sepL->addStretch();
    m_msgLayout->insertWidget(m_msgLayout->count() - 1, sepFrame);
  }

  auto *w = createPayloadWidget(payloadName, payloadContext, ts);
  m_msgLayout->insertWidget(m_msgLayout->count() - 1, w);
  scrollToBottom();
}

void CortexPanel::clearMessages() {
  // Remove all widgets except the stretch at the end
  while (m_msgLayout->count() > 1) {
    auto *item = m_msgLayout->takeAt(0);
    if (item->widget()) item->widget()->deleteLater();
    delete item;
  }
  m_stepHeadersAdded.clear();
  m_payloadSectionAdded = false;
}

void CortexPanel::setEngineInfo(const QString &engineType, const QString &modelName) {
  QString engine = engineType.isEmpty() ? QStringLiteral("mechanical") : engineType;
  QString label;
  QString color = QStringLiteral("#64748b");  // gray default

  if (engine == QStringLiteral("mechanical")) {
    label = QStringLiteral("固定流程（未配置 LLM）");
    color = QStringLiteral("#b45309");  // amber — indicates missing config
  } else if (engine == QStringLiteral("react")) {
    label = QStringLiteral("推理决策");
    color = QStringLiteral("#166534");  // green — LLM active
  } else if (engine == QStringLiteral("ai")) {
    label = QStringLiteral("智能决策");
    color = QStringLiteral("#166534");
  } else {
    label = engine;
  }

  if (!modelName.isEmpty()) {
    m_engineLabel->setText(QStringLiteral("引擎: %1 | %2").arg(label, modelName));
  } else {
    m_engineLabel->setText(QStringLiteral("引擎: %1").arg(label));
  }
  m_engineLabel->setStyleSheet(
    QStringLiteral("font-size: 10px; color: %1; background: #f1f5f9; "
                   "border: 1px solid #e2e8f0; border-radius: 4px; padding: 2px 8px;")
      .arg(color));
}

void CortexPanel::setStatus(const QString &status) {
  QString color;
  QString s = status.toLower();
  if (s == QStringLiteral("running") || s == QStringLiteral("执行中"))
    color = QStringLiteral("#3b82f6");   // blue — active
  else if (s == QStringLiteral("completed") || s == QStringLiteral("已完成"))
    color = QStringLiteral("#22c55e");   // green — done
  else if (s == QStringLiteral("failed") || s == QStringLiteral("失败"))
    color = QStringLiteral("#ef4444");   // red — error
  else if (s == QStringLiteral("aborted") || s == QStringLiteral("已中止"))
    color = QStringLiteral("#f59e0b");   // amber — stopped
  else
    color = QStringLiteral("#94a3b8");   // gray — idle/pending

  m_statusDot->setStyleSheet(QStringLiteral("font-size: 12px; color: %1;").arg(color));
}

// ── Widget factories ─────────────────────────────────────────────────────

QWidget *CortexPanel::createStepSeparator(int stepIndex, const QString &toolId, bool isDynamic) {
  auto *frame = new QFrame;
  frame->setStyleSheet(
    "QFrame { background: #f1f5f9; border: none; border-left: 3px solid #3b82f6; "
    "border-radius: 0 4px 4px 0; }");
  auto *l = new QHBoxLayout(frame);
  l->setContentsMargins(10, 4, 10, 4);
  l->setSpacing(6);

  auto *lbl = new QLabel(QStringLiteral("步骤 %1: %2").arg(stepIndex).arg(toolId));
  lbl->setStyleSheet("font-size: 11px; font-weight: bold; color: #1e40af;");
  l->addWidget(lbl);

  if (isDynamic) {
    auto *dynTag = new QLabel(QStringLiteral("🔀 AI 动态插入"));
    dynTag->setStyleSheet(
      "font-size: 9px; font-weight: bold; color: #92400e; "
      "background: #fffbeb; border: 1px solid #fcd34d; border-radius: 4px; padding: 1px 6px;");
    l->addWidget(dynTag);
  }

  l->addStretch();
  return frame;
}

QWidget *CortexPanel::createReactWidget(const QString &observation, const QString &thought,
                                          const QString &action, const QString &timestamp) {
  auto *card = new QFrame;
  card->setStyleSheet(
    "QFrame { background: #ffffff; border: 1px solid #bfdbfe; border-radius: 8px; }");
  auto *cardL = new QVBoxLayout(card);
  cardL->setContentsMargins(10, 8, 10, 8);
  cardL->setSpacing(6);

  // Timestamp
  auto *timeLbl = new QLabel(timestamp);
  timeLbl->setStyleSheet("font-size: 9px; color: #94a3b8;");
  cardL->addWidget(timeLbl);

  // Observation — warning style
  if (!observation.isEmpty()) {
    auto *obsLbl = new QLabel(QStringLiteral("🔍 发现: ") + observation);
    obsLbl->setWordWrap(true);
    obsLbl->setStyleSheet(
      "font-size: 12px; color: #92400e; background: #fffbeb; "
      "border-left: 3px solid #f59e0b; padding: 4px 8px; border-radius: 0 4px 4px 0;");
    cardL->addWidget(obsLbl);
  }

  // Thought — info style, collapsible
  if (!thought.isEmpty()) {
    QString key = QStringLiteral("thought_%1").arg(m_widgetCounter++);
    cardL->addWidget(createCollapsibleText(thought, 150, key));
  }

  // Action — badge
  if (!action.isEmpty()) {
    QString actionText = action;
    QString actionBg = QStringLiteral("#f0fdf4");
    QString actionBorder = QStringLiteral("#86efac");
    QString actionFg = QStringLiteral("#166534");
    QString icon = QStringLiteral("▶");

    if (action.contains(QStringLiteral("插入"))) {
      actionBg = QStringLiteral("#eff6ff"); actionBorder = QStringLiteral("#93c5fd");
      actionFg = QStringLiteral("#1d4ed8"); icon = QStringLiteral("🔀");
    } else if (action.contains(QStringLiteral("中止")) || action.contains(QStringLiteral("终止"))) {
      actionBg = QStringLiteral("#fef2f2"); actionBorder = QStringLiteral("#fca5a5");
      actionFg = QStringLiteral("#991b1b"); icon = QStringLiteral("🛑");
    } else if (action.contains(QStringLiteral("并行"))) {
      actionBg = QStringLiteral("#faf5ff"); actionBorder = QStringLiteral("#c4b5fd");
      actionFg = QStringLiteral("#6b21a8"); icon = QStringLiteral("⚡");
    } else if (action.contains(QStringLiteral("调整"))) {
      actionBg = QStringLiteral("#fffbeb"); actionBorder = QStringLiteral("#fcd34d");
      actionFg = QStringLiteral("#92400e"); icon = QStringLiteral("🔧");
    }

    auto *actionLbl = new QLabel(icon + QStringLiteral(" 动作: ") + actionText);
    actionLbl->setStyleSheet(
      QStringLiteral("font-size: 11px; font-weight: bold; color: %3; "
                     "background: %1; border: 1px solid %2; border-radius: 6px; padding: 4px 10px;")
        .arg(actionBg, actionBorder, actionFg));
    cardL->addWidget(actionLbl);
  }

  return card;
}

QWidget *CortexPanel::createPayloadWidget(const QString &name, const QString &context,
                                            const QString &timestamp) {
  auto *card = new QFrame;
  card->setStyleSheet(
    "QFrame { background: #fffbeb; border: 1px solid #fcd34d; border-radius: 8px; }");
  auto *cardL = new QVBoxLayout(card);
  cardL->setContentsMargins(10, 8, 10, 8);
  cardL->setSpacing(4);

  // Header line: name + timestamp
  auto *headerL = new QHBoxLayout;
  if (!name.isEmpty()) {
    auto *nameLbl = new QLabel(QStringLiteral("⚡ ") + name);
    nameLbl->setStyleSheet("font-size: 12px; font-weight: bold; color: #92400e;");
    headerL->addWidget(nameLbl);
  }
  auto *timeLbl = new QLabel(timestamp);
  timeLbl->setStyleSheet("font-size: 9px; color: #b45309;");
  headerL->addStretch();
  headerL->addWidget(timeLbl);
  cardL->addLayout(headerL);

  // Context body — collapsible
  QString displayText = context;
  if (displayText.isEmpty() && !name.isEmpty()) {
    displayText = name;
  }
  if (!displayText.isEmpty()) {
    QString key = QStringLiteral("payload_%1").arg(m_widgetCounter++);
    cardL->addWidget(createCollapsibleText(displayText, 200, key));
  }

  return card;
}

QWidget *CortexPanel::createCollapsibleText(const QString &text, int collapseThreshold, const QString &key) {
  auto *w = new QWidget;
  auto *l = new QVBoxLayout(w);
  l->setContentsMargins(0, 0, 0, 0);
  l->setSpacing(2);

  bool isLong = text.length() > collapseThreshold;
  bool expanded = m_expandedTexts.contains(key);

  if (!isLong) {
    // Short text — plain label, no toggle
    auto *lbl = new QLabel(text);
    lbl->setWordWrap(true);
    lbl->setStyleSheet(
      "font-size: 12px; color: #1e40af; background: #eff6ff; "
      "border-left: 3px solid #3b82f6; padding: 4px 8px; border-radius: 0 4px 4px 0;");
    l->addWidget(lbl);
    return w;
  }

  // Long text — collapsible
  QString displayText = expanded ? text : text.left(collapseThreshold) + QStringLiteral("...");

  auto *lbl = new QLabel(displayText);
  lbl->setWordWrap(true);
  lbl->setStyleSheet(
    "font-size: 12px; color: #1e40af; background: #eff6ff; "
    "border-left: 3px solid #3b82f6; padding: 4px 8px; border-radius: 0 4px 4px 0;");
  l->addWidget(lbl);

  auto *toggleBtn = new QPushButton(expanded ? QStringLiteral("收起 ▴") : QStringLiteral("展开 ▾"));
  toggleBtn->setStyleSheet(
    "QPushButton { font-size: 10px; color: #3b82f6; background: transparent; "
    "border: none; padding: 0; text-align: left; }"
    "QPushButton:hover { color: #1d4ed8; text-decoration: underline; }");
  l->addWidget(toggleBtn);

  connect(toggleBtn, &QPushButton::clicked, this, [this, key, lbl, toggleBtn, text, collapseThreshold]() {
    if (m_expandedTexts.contains(key)) {
      // Collapse
      m_expandedTexts.remove(key);
      lbl->setText(text.left(collapseThreshold) + QStringLiteral("..."));
      toggleBtn->setText(QStringLiteral("展开 ▾"));
    } else {
      // Expand
      m_expandedTexts.insert(key);
      lbl->setText(text);
      toggleBtn->setText(QStringLiteral("收起 ▴"));
    }
  });

  return w;
}

void CortexPanel::scrollToBottom() {
  // Defer scroll to allow layout to update
  QTimer::singleShot(50, this, [this]() {
    m_scrollArea->verticalScrollBar()->setValue(m_scrollArea->verticalScrollBar()->maximum());
  });
}
