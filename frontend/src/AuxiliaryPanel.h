#pragma once

#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QFormLayout>
#include <QHideEvent>
#include <QLabel>
#include <QPointer>
#include <QShowEvent>
#include <QToolButton>
#include <QVBoxLayout>

// Reusable, non-native auxiliary panel. Closing only hides this widget; no
// window-manager transition, nested event loop, data refresh or destruction.
class AuxiliaryPanel : public QDialog {
public:
    explicit AuxiliaryPanel(QWidget *owner)
        : QDialog(owner->window(), Qt::Widget), m_owner(owner)
    {
        // QDialog's constructor adds Qt::Dialog even when flags are zero.
        // Reset the type explicitly after construction to stay in the host widget.
        setWindowFlags(Qt::Widget);
        setAttribute(Qt::WA_StyledBackground);
        setProperty("auxiliaryPanel", true);
        setFocusPolicy(Qt::StrongFocus);
        setStyleSheet(
            "QDialog[auxiliaryPanel=\"true\"] { background:#ffffff; "
            "border:1px solid #b9cbe3; border-radius:10px; }");
        owner->installEventFilter(this);
        parentWidget()->installEventFilter(this);
        connect(owner, &QObject::destroyed, this, &QObject::deleteLater);
        hide();
    }

    void present()
    {
        if (!m_owner || !m_owner->isVisible()) return;
        if (!m_header) {
            m_preferredSize = size();
            m_header = new QWidget(this);
            auto *row = new QHBoxLayout(m_header);
            row->setContentsMargins(4, 2, 0, 8);
            auto *title = new QLabel(windowTitle(), m_header);
            title->setStyleSheet("font-size:16px;font-weight:600;color:#172033;");
            row->addWidget(title, 1);
            auto *close = new QToolButton(m_header);
            close->setObjectName("auxiliaryClose");
            close->setText(QStringLiteral("×"));
            close->setAccessibleName(QStringLiteral("关闭"));
            close->setToolTip(QStringLiteral("关闭（Esc）"));
            close->setFixedSize(30, 30);
            close->setStyleSheet(
                "QToolButton { font-size:22px;color:#475569;border:0;border-radius:6px; }"
                "QToolButton:hover { background:#edf2f7; }");
            row->addWidget(close);
            connect(close, &QToolButton::clicked, this, &QDialog::reject);
            if (auto *box = qobject_cast<QBoxLayout *>(layout())) box->insertWidget(0, m_header);
            else if (auto *form = qobject_cast<QFormLayout *>(layout())) form->insertRow(0, m_header);
        }
        if (!isVisible()) m_previousFocus = QApplication::focusWidget();
        fitToHost();
        show();
        raise();
        setFocus(Qt::OtherFocusReason);
    }

protected:
    bool eventFilter(QObject *object, QEvent *event) override
    {
        if (object == m_owner && event->type() == QEvent::Hide) hide();
        if (object == parentWidget() && event->type() == QEvent::Resize && isVisible())
            fitToHost();
        return QDialog::eventFilter(object, event);
    }

    void hideEvent(QHideEvent *event) override
    {
        QDialog::hideEvent(event);
        if (m_previousFocus && m_previousFocus->isVisible())
            m_previousFocus->setFocus(Qt::OtherFocusReason);
        m_previousFocus.clear();
    }

private:
    void fitToHost()
    {
        const QRect available = parentWidget()->rect().adjusted(16, 16, -16, -16);
        const QSize wanted(qMin(m_preferredSize.width(), available.width()),
                           qMin(m_preferredSize.height(), available.height()));
        setGeometry(QRect(available.center() - QPoint(wanted.width()/2, wanted.height()/2), wanted));
    }

    QPointer<QWidget> m_owner;
    QPointer<QWidget> m_previousFocus;
    QWidget *m_header = nullptr;
    QSize m_preferredSize;
};
