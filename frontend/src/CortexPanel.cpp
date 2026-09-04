#include "CortexPanel.h"
#include "Theme.h"
#include "ApiClient.h"
#include <QHBoxLayout>
#include <QFormLayout>
#include <QScrollBar>
#include <QTimer>
#include <QDateTime>
#include <QRegularExpression>

// ── Helpers ──────────────────────────────────────────────────────────────

static QString nowTime() {
  return QTime::currentTime().toString(QStringLiteral("HH:mm:ss"));
}

static QLabel *makeAvatar(const QString &emoji, const QString &bgColor,
                           const QString &borderColor, QWidget *parent = nullptr) {
  auto *lbl = new QLabel(emoji, parent);
  lbl->setFixedSize(32, 32);
  lbl->setAlignment(Qt::AlignCenter);
  lbl->setStyleSheet(
    QStringLiteral("font-size: 16px; background: %1; border: 1px solid %2; border-radius: 8px;")
      .arg(bgColor, borderColor));
  return lbl;
}

static QLabel *makeTag(const QString &text, const QString &bgColor,
                        const QString &textColor, QWidget *parent = nullptr) {
  auto *lbl = new QLabel(text, parent);
  lbl->setStyleSheet(
    QStringLiteral("font-size: 10px; font-weight: bold; color: %2; "
                   "background: %1; border-radius: 4px; padding: 2px 6px;")
      .arg(bgColor, textColor));
  return lbl;
}

static QTextEdit *makeBody(const QString &text, const QString &bgColor,
                            const QString &borderColor, QWidget *parent = nullptr) {
  auto *te = new QTextEdit(parent);
  te->setReadOnly(true);
  te->setPlainText(text);
  te->setMaximumHeight(180);
  te->setStyleSheet(
    QStringLiteral("QTextEdit { background: %1; border: 1px solid %2; border-radius: 8px; "
                   "padding: 8px; font-size: 12px; color: #334155; }")
      .arg(bgColor, borderColor));
  return te;
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
  headerL->setContentsMargins(12, 8, 12, 8);

  auto *titleLbl = new QLabel(QStringLiteral("🧠 决策核心"));
  titleLbl->setStyleSheet("font-size: 14px; font-weight: bold; color: #1a2a3a;");
  headerL->addWidget(titleLbl);

  headerL->addStretch();

  m_engineLabel = new QLabel(QStringLiteral("引擎: 机械"));
  m_engineLabel->setStyleSheet(
    "font-size: 10px; color: #64748b; background: #f1f5f9; "
    "border: 1px solid #e2e8f0; border-radius: 4px; padding: 2px 8px;");
  headerL->addWidget(m_engineLabel);

  m_statusDot = new QLabel(QStringLiteral("●"));
  m_statusDot->setStyleSheet("font-size: 12px; color: #22c55e;");
  headerL->addWidget(m_statusDot);

  mainLayout->addWidget(headerFrame);

  // ── Message area ──────────────────────────────────────────────────────
  m_msgContainer = new QWidget;
  m_msgLayout = new QVBoxLayout(m_msgContainer);
  m_msgLayout->setContentsMargins(8, 8, 8, 8);
  m_msgLayout->setSpacing(8);
  m_msgLayout->addStretch();  // push messages up

  m_scrollArea = new QScrollArea;
  m_scrollArea->setWidgetResizable(true);
  m_scrollArea->setFrameShape(QFrame::NoFrame);
  m_scrollArea->setWidget(m_msgContainer);
  m_scrollArea->setStyleSheet("QScrollArea { background: #f8fafc; }");
  mainLayout->addWidget(m_scrollArea, 1);

  // ── Input area ────────────────────────────────────────────────────────
  auto *inputFrame = new QFrame;
  inputFrame->setStyleSheet(
    "QFrame { background: #ffffff; border-top: 1px solid #dbe5f0; }");
  auto *inputL = new QHBoxLayout(inputFrame);
  inputL->setContentsMargins(8, 6, 8, 6);

  m_input = new QLineEdit;
  m_input->setPlaceholderText(QStringLiteral("输入指令..."));
  m_input->setStyleSheet(
    "QLineEdit { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; "
    "padding: 8px 12px; font-size: 12px; }"
    "QLineEdit:focus { border: 1px solid #60a5fa; }");
  inputL->addWidget(m_input, 1);

  m_sendBtn = new QPushButton(QStringLiteral("发送"));
  m_sendBtn->setProperty("primary", true);
  m_sendBtn->setFixedWidth(64);
  inputL->addWidget(m_sendBtn);

  mainLayout->addWidget(inputFrame);

  // ── Signals ───────────────────────────────────────────────────────────
  connect(m_sendBtn, &QPushButton::clicked, this, [this]() {
    QString text = m_input->text().trimmed();
    if (text.isEmpty()) return;
    addMessage(Role::User, text, nowTime());
    emit userMessageSent(text);
    m_input->clear();
  });
  connect(m_input, &QLineEdit::returnPressed, m_sendBtn, &QPushButton::click);
}

// ── Public API ───────────────────────────────────────────────────────────

void CortexPanel::addMessage(Role role, const QString &text, const QString &timestamp) {
  QString ts = timestamp.isEmpty() ? nowTime() : timestamp;

  if (role == Role::ReactThought) {
    // Fallback: unstructured react thought
    auto *w = createReactWidget(QString(), text, QString(), ts);
    m_msgLayout->insertWidget(m_msgLayout->count() - 1, w);
  } else if (role == Role::Payload) {
    auto *w = createPayloadWidget(QString(), text, ts);
    m_msgLayout->insertWidget(m_msgLayout->count() - 1, w);
  } else {
    auto *w = createMessageWidget(role, text, ts);
    m_msgLayout->insertWidget(m_msgLayout->count() - 1, w);
  }
  scrollToBottom();
}

void CortexPanel::addReactThought(const QString &observation, const QString &thought,
                                    const QString &action, const QString &timestamp) {
  QString ts = timestamp.isEmpty() ? nowTime() : timestamp;
  auto *w = createReactWidget(observation, thought, action, ts);
  m_msgLayout->insertWidget(m_msgLayout->count() - 1, w);
  scrollToBottom();
}

void CortexPanel::addPayloadCard(const QString &payloadName, const QString &payloadContext,
                                   const QString &timestamp) {
  QString ts = timestamp.isEmpty() ? nowTime() : timestamp;
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
}

void CortexPanel::setAutoMode(bool autoMode) {
  m_autoMode = autoMode;
  m_input->setEnabled(!autoMode);
  m_sendBtn->setEnabled(!autoMode);
  m_input->setPlaceholderText(autoMode
    ? QStringLiteral("自动驾驶中，输入已锁定...")
    : QStringLiteral("输入指令..."));
}

void CortexPanel::setEngineInfo(const QString &engineType, const QString &modelName) {
  QString engine = engineType.isEmpty() ? QStringLiteral("机械") : engineType;
  if (engine == QStringLiteral("mechanical")) engine = QStringLiteral("固定流程");
  else if (engine == QStringLiteral("react")) engine = QStringLiteral("推理决策");
  else if (engine == QStringLiteral("ai")) engine = QStringLiteral("智能决策");
  if (!modelName.isEmpty()) {
    m_engineLabel->setText(QStringLiteral("引擎: %1 | %2").arg(engine, modelName));
  } else {
    m_engineLabel->setText(QStringLiteral("引擎: %1").arg(engine));
  }
}

// ── Message widget factories ─────────────────────────────────────────────

QWidget *CortexPanel::createMessageWidget(Role role, const QString &text, const QString &timestamp) {
  auto *w = new QWidget;
  auto *h = new QHBoxLayout(w);
  h->setContentsMargins(0, 0, 0, 0);
  h->setSpacing(8);

  if (role == Role::User) {
    // Right-aligned
    h->addStretch();
    auto *col = new QVBoxLayout;
    auto *meta = new QHBoxLayout;
    meta->addWidget(makeTag(QStringLiteral("操作员"), QStringLiteral("#eff6ff"), QStringLiteral("#1d4ed8")));
    auto *timeLbl = new QLabel(timestamp);
    timeLbl->setStyleSheet("font-size: 9px; color: #94a3b8;");
    meta->addWidget(timeLbl);
    meta->addStretch();
    col->addLayout(meta);
    auto *body = makeBody(text, QStringLiteral("#eff6ff"), QStringLiteral("#bfdbfe"));
    body->setAlignment(Qt::AlignRight);
    col->addWidget(body);
    h->addLayout(col);
    auto *avatar = makeAvatar(QStringLiteral("👤"), QStringLiteral("#eff6ff"), QStringLiteral("#bfdbfe"));
    h->addWidget(avatar);
  } else {
    // Model — left-aligned, try TTP rendering
    auto *avatar = makeAvatar(QStringLiteral("🤖"), QStringLiteral("#f1f5f9"), QStringLiteral("#e2e8f0"));
    h->addWidget(avatar);
    auto *col = new QVBoxLayout;
    auto *meta = new QHBoxLayout;
    meta->addWidget(makeTag(QStringLiteral("智能系统"), QStringLiteral("#f1f5f9"), QStringLiteral("#475569")));
    auto *timeLbl = new QLabel(timestamp);
    timeLbl->setStyleSheet("font-size: 9px; color: #94a3b8;");
    meta->addWidget(timeLbl);
    meta->addStretch();
    col->addLayout(meta);

    // Check if TTP format
    if (text.contains(QStringLiteral("**战术**")) || text.contains(QStringLiteral("**技术**"))) {
      col->addWidget(createTtpWidget(text, timestamp));
    } else {
      col->addWidget(makeBody(text, QStringLiteral("#ffffff"), QStringLiteral("#e2e8f0")));
    }
    h->addLayout(col);
    h->addStretch();
  }

  return w;
}

QWidget *CortexPanel::createReactWidget(const QString &observation, const QString &thought,
                                          const QString &action, const QString &timestamp) {
  auto *w = new QWidget;
  auto *h = new QHBoxLayout(w);
  h->setContentsMargins(0, 0, 0, 0);
  h->setSpacing(8);

  auto *avatar = makeAvatar(QStringLiteral("🧠"), QStringLiteral("#eff6ff"), QStringLiteral("#bfdbfe"));
  h->addWidget(avatar);

  auto *col = new QVBoxLayout;
  col->setSpacing(4);

  // Meta line
  auto *meta = new QHBoxLayout;
  meta->addWidget(makeTag(QStringLiteral("ISST 思考"), QStringLiteral("#eff6ff"), QStringLiteral("#1d4ed8")));
  auto *timeLbl = new QLabel(timestamp);
  timeLbl->setStyleSheet("font-size: 9px; color: #94a3b8;");
  meta->addWidget(timeLbl);
  meta->addStretch();
  col->addLayout(meta);

  // Card frame
  auto *card = new QFrame;
  card->setStyleSheet(
    "QFrame { background: #ffffff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 8px; }");
  auto *cardL = new QVBoxLayout(card);
  cardL->setContentsMargins(10, 8, 10, 8);
  cardL->setSpacing(6);

  // Observation — warning style
  if (!observation.isEmpty()) {
    auto *obsLbl = new QLabel(QStringLiteral("🔍 发现: ") + observation);
    obsLbl->setWordWrap(true);
    obsLbl->setStyleSheet(
      "font-size: 12px; color: #92400e; background: #fffbeb; "
      "border-left: 3px solid #f59e0b; padding: 4px 8px; border-radius: 0 4px 4px 0;");
    cardL->addWidget(obsLbl);
  }

  // Thought — info style
  if (!thought.isEmpty()) {
    auto *thoughtLbl = new QLabel(QStringLiteral("💭 分析: ") + thought);
    thoughtLbl->setWordWrap(true);
    thoughtLbl->setStyleSheet(
      "font-size: 12px; color: #1e40af; background: #eff6ff; "
      "border-left: 3px solid #3b82f6; padding: 4px 8px; border-radius: 0 4px 4px 0;");
    // Limit display height for long thoughts
    if (thought.length() > 200) {
      thoughtLbl->setMaximumHeight(80);
    }
    cardL->addWidget(thoughtLbl);
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

  col->addWidget(card);
  h->addLayout(col);
  h->addStretch();

  return w;
}

QWidget *CortexPanel::createPayloadWidget(const QString &name, const QString &context,
                                            const QString &timestamp) {
  auto *w = new QWidget;
  auto *h = new QHBoxLayout(w);
  h->setContentsMargins(0, 0, 0, 0);
  h->setSpacing(8);

  auto *avatar = makeAvatar(QStringLiteral("⚡"), QStringLiteral("#fffbeb"), QStringLiteral("#fcd34d"));
  h->addWidget(avatar);

  auto *col = new QVBoxLayout;
  col->setSpacing(4);

  // Meta line
  auto *meta = new QHBoxLayout;
  meta->addWidget(makeTag(QStringLiteral("载荷知识"), QStringLiteral("#fffbeb"), QStringLiteral("#b45309")));
  if (!name.isEmpty()) {
    auto *nameTag = makeTag(name, QStringLiteral("#fef3c7"), QStringLiteral("#92400e"));
    meta->addWidget(nameTag);
  }
  auto *timeLbl = new QLabel(timestamp);
  timeLbl->setStyleSheet("font-size: 9px; color: #94a3b8;");
  meta->addWidget(timeLbl);
  meta->addStretch();
  col->addLayout(meta);

  // Card — warning/amber style
  auto *card = new QFrame;
  card->setStyleSheet(
    "QFrame { background: #fffbeb; border: 1px solid #fcd34d; border-radius: 8px; }");
  auto *cardL = new QVBoxLayout(card);
  cardL->setContentsMargins(10, 8, 10, 8);
  cardL->setSpacing(4);

  // Parse context into sections
  QString displayText = context;
  if (displayText.isEmpty() && !name.isEmpty()) {
    displayText = name;
  }

  // Render structured sections if present
  auto *body = new QTextEdit;
  body->setReadOnly(true);
  body->setPlainText(displayText);
  body->setMaximumHeight(160);
  body->setStyleSheet(
    "QTextEdit { background: transparent; border: none; font-size: 11px; "
    "color: #78350f; padding: 0; }");
  cardL->addWidget(body);

  col->addWidget(card);
  h->addLayout(col);
  h->addStretch();

  return w;
}

QWidget *CortexPanel::createTtpWidget(const QString &text, const QString &/*timestamp*/) {
  // Parse TTP format: **战术**: xxx, **技术**: xxx, **指令**: xxx, **分析**: xxx
  auto *w = new QWidget;
  auto *l = new QVBoxLayout(w);
  l->setContentsMargins(0, 0, 0, 0);
  l->setSpacing(4);

  const auto lines = text.split('\n');
  for (const auto &line : lines) {
    if (line.trimmed().isEmpty()) continue;

    if (line.contains(QStringLiteral("**战术**"))) {
      auto *h = new QHBoxLayout;
      h->addWidget(makeTag(QStringLiteral("战术"), QStringLiteral("#eff6ff"), QStringLiteral("#1d4ed8")));
      QString content = line;
      content.remove(QRegularExpression(QStringLiteral("\\*\\*战术\\*\\*[:：]?\\s*")));
      auto *lbl = new QLabel(content.trimmed());
      lbl->setStyleSheet("font-size: 12px; font-weight: bold; color: #1e40af;");
      h->addWidget(lbl);
      h->addStretch();
      l->addLayout(h);
    } else if (line.contains(QStringLiteral("**技术**"))) {
      auto *h = new QHBoxLayout;
      h->addWidget(makeTag(QStringLiteral("技术"), QStringLiteral("#faf5ff"), QStringLiteral("#7c3aed")));
      QString content = line;
      content.remove(QRegularExpression(QStringLiteral("\\*\\*技术\\*\\*[:：]?\\s*")));
      auto *lbl = new QLabel(content.trimmed());
      lbl->setStyleSheet("font-size: 12px; font-family: monospace; color: #6b21a8;");
      h->addWidget(lbl);
      h->addStretch();
      l->addLayout(h);
    } else if (line.contains(QStringLiteral("**指令**"))) {
      QString content = line;
      content.remove(QRegularExpression(QStringLiteral("\\*\\*指令\\*\\*[:：]?\\s*")));
      auto *lbl = new QLabel(QStringLiteral("$ ") + content.trimmed());
      lbl->setStyleSheet(
        "font-size: 11px; font-family: monospace; color: #166534; "
        "background: #f0fdf4; border: 1px solid #86efac; border-radius: 6px; padding: 6px 10px;");
      lbl->setWordWrap(true);
      l->addWidget(lbl);
    } else if (line.contains(QStringLiteral("**分析**"))) {
      QString content = line;
      content.remove(QRegularExpression(QStringLiteral("\\*\\*分析\\*\\*[:：]?\\s*")));
      auto *lbl = new QLabel(content.trimmed());
      lbl->setWordWrap(true);
      lbl->setStyleSheet(
        "font-size: 12px; color: #1e40af; background: #eff6ff; "
        "border-left: 3px solid #3b82f6; padding: 4px 8px; border-radius: 0 4px 4px 0;");
      l->addWidget(lbl);
    } else {
      auto *lbl = new QLabel(line);
      lbl->setWordWrap(true);
      lbl->setStyleSheet("font-size: 12px; color: #334155;");
      l->addWidget(lbl);
    }
  }

  return w;
}

void CortexPanel::scrollToBottom() {
  // Defer scroll to allow layout to update
  QTimer::singleShot(50, this, [this]() {
    m_scrollArea->verticalScrollBar()->setValue(m_scrollArea->verticalScrollBar()->maximum());
  });
}
