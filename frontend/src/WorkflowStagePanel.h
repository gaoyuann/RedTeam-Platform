#pragma once

#include <QFrame>

class OverviewCircleButton;

/**
 * WorkflowStagePanel — 工作流阶段箭头连线面板
 *
 * 移植自 pentagi-v3 WorkflowStagePanel，适配浅色主题。
 * 在四个 OverviewCircleButton 之间绘制贝塞尔曲线箭头，
 * 箭头颜色随阶段状态变化，运行时有流动光点动画。
 *
 * 工作流方向：拓扑 → 扫描 → (目标攻击, 方法攻击)
 */
class WorkflowStagePanel : public QFrame {
    Q_OBJECT

public:
    explicit WorkflowStagePanel(QWidget *parent = nullptr);

    /// 注册四个圆形按钮（必须在显示前调用）
    void setButtons(OverviewCircleButton *topologyButton,
                    OverviewCircleButton *scanButton,
                    OverviewCircleButton *targetButton,
                    OverviewCircleButton *methodsButton);

    /// 更新某阶段的状态，触发箭头重绘
    void setStageState(const QString &pageId, int state);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QPointF mapPoint(QWidget *widget, const QPoint &point) const;
    bool isArrowActive(int fromState, int toState) const;
    QColor colorForState(int state) const;
    void drawArrow(QPainter *painter,
                   const QPointF &start,
                   const QPointF &end,
                   int fromState,
                   int toState,
                   qreal curveOffset);

    OverviewCircleButton *m_topologyButton;
    OverviewCircleButton *m_scanButton;
    OverviewCircleButton *m_targetButton;
    OverviewCircleButton *m_methodsButton;
    int m_topologyState;
    int m_scanState;
    int m_targetState;
    int m_methodsState;
    int m_phase;
    QTimer *m_timer;
};
