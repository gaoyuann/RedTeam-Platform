#include "DongleLockPage.h"

#include <QFont>
#include <QLabel>
#include <QVariant>
#include <QVBoxLayout>

DongleLockPage::DongleLockPage(QWidget *parent)
    : QWidget(parent),
      m_messageLabel(nullptr) {
    setStyleSheet(QStringLiteral(
        "QWidget { background:#f3f6fb; color:#0f172a; }"
        "QLabel { background:transparent; }"
        "QLabel[title=\"true\"] { color:#991b1b; font-size:24px; font-weight:700; }"
        "QLabel[message=\"true\"] { color:#475569; font-size:14px; }"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 24, 24, 24);
    root->setAlignment(Qt::AlignCenter);

    auto *icon = new QLabel(QString::fromUtf8("\xF0\x9F\x94\x92"), this);
    QFont iconFont = icon->font();
    iconFont.setPointSize(64);
    icon->setFont(iconFont);
    icon->setAlignment(Qt::AlignCenter);
    root->addWidget(icon);

    auto *title = new QLabel(QStringLiteral("加密锁校验失败"), this);
    title->setProperty("title", QVariant(true));
    title->setAlignment(Qt::AlignCenter);
    root->addWidget(title);

    m_messageLabel = new QLabel(this);
    m_messageLabel->setProperty("message", QVariant(true));
    m_messageLabel->setWordWrap(true);
    m_messageLabel->setAlignment(Qt::AlignCenter);
    m_messageLabel->setMaximumWidth(680);
    root->addWidget(m_messageLabel);
}

void DongleLockPage::setErrorMessage(const QString &message) {
    const QString detail = message.trimmed().isEmpty()
                               ? QStringLiteral("未检测到已注册的加密锁。请插入加密锁，系统会自动重新校验。")
                               : message;
    m_messageLabel->setText(detail + QStringLiteral("\n\n请插入已注册的加密锁，系统会自动重新校验。"));
}
