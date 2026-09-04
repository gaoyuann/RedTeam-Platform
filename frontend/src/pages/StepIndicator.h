#pragma once
#include <QWidget>
#include <QVector>

// 3-phase campaign progress indicator widget
// Draws: ① 数据窃取 ──→ ② 信息篡改 ──→ ③ 设备夺控
// Each node shows status: pending/running/completed/skipped/failed

struct PhaseStep {
  QString phaseType;   // data-exfiltration / tampering-deception / device-control
  QString displayName; // 中文显示名
  QString phaseId;     // phase_xxx
  QString status;      // pending / running / completed / skipped / failed
};

class StepIndicator : public QWidget {
  Q_OBJECT
public:
  explicit StepIndicator(QWidget *parent = nullptr);

  void setPhases(const QVector<PhaseStep> &phases);
  QVector<PhaseStep> phases() const;

  QSize minimumSizeHint() const override;
  QSize sizeHint() const override;

signals:
  void phaseClicked(int index);

protected:
  void paintEvent(QPaintEvent *event) override;
  void mousePressEvent(QMouseEvent *event) override;

private:
  QVector<PhaseStep> m_phases;
  int m_hoverIndex = -1;

  QRect nodeRect(int index) const;
  int nodeAtPos(const QPoint &pos) const;
};
