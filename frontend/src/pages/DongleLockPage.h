#pragma once

#include <QWidget>

class QLabel;

// 加密锁校验失败时占据整个内容区的锁屏页。
class DongleLockPage : public QWidget {
    Q_OBJECT

public:
    explicit DongleLockPage(QWidget *parent = nullptr);

    void setErrorMessage(const QString &message);

private:
    QLabel *m_messageLabel;
};
