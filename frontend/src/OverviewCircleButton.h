#pragma once

#include <QColor>
#include <QPushButton>

class QTimer;

/**
 * OverviewCircleButton — 总览大屏圆形状态按钮
 *
 * 移植自 pentagi-v3 OverviewCircleButton，适配浅色主题。
 * 显示工作流某阶段的运行状态：
 *   - 待命 (idle)：纯色圆 + 标题 + "待命"
 *   - 运行中 (running)：旋转弧线动画 + 脉冲光晕 + "运行中"
 *   - 可显示进度百分比、自定义状态文字和提示文字
 */
class OverviewCircleButton : public QPushButton {
    Q_OBJECT

public:
    explicit OverviewCircleButton(const QString &title, QWidget *parent = nullptr);

    void setRunning(bool running);
    bool isRunning() const;

    void setHintText(const QString &text);
    void setStatusText(const QString &text);
    void setProgressValue(int value);
    void setIdleColor(const QColor &color);
    void setActiveColor(const QColor &color);

protected:
    void paintEvent(QPaintEvent *event) override;
    void enterEvent(QEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    QString m_title;
    QString m_hintText;
    QString m_statusText;
    bool m_running;
    bool m_hovered;
    int m_progressValue;
    QColor m_idleColor;
    QColor m_activeColor;
    QTimer *m_spinTimer;
    int m_spinAngle;
};
