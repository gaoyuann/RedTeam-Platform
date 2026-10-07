#pragma once
#include <QWidget>
#include <QJsonArray>

class QLabel;

/// 攻击结果统计卡（演示④）：左环形图（状态分布+成功率），右预案结果条形榜。
/// 纯 QPainter 自绘 — 不用 QtCharts（GPL-3 与保密交付冲突）。
class StatsSummaryCard : public QWidget {
  Q_OBJECT
public:
  explicit StatsSummaryCard(QWidget *parent = nullptr);
  /// 传入 /api/runs 返回的执行记录数组，内部聚合
  void setRuns(const QJsonArray &runs);

protected:
  void paintEvent(QPaintEvent *event) override;

private:
  struct PbStat {
    QString id;
    int ok = 0;
    int fail = 0;
    int other = 0;
    int total() const { return ok + fail + other; }
  };
  int m_total = 0;
  int m_ok = 0;
  int m_fail = 0;
  int m_active = 0;   // RUNNING / PENDING / awaiting
  int m_other = 0;
  QVector<PbStat> m_topPbs;  // 按总次数排序取前5
};
