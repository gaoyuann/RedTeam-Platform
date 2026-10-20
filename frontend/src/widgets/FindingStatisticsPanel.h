#pragma once
#include "MetricCard.h"
#include <QJsonObject>
#include <QProgressBar>
#include <cmath>

// All values come from the task-wide statistics, never the current page/filter.
class FindingStatisticsPanel : public QFrame {
public:
  explicit FindingStatisticsPanel(QWidget *parent = nullptr) : QFrame(parent) {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto *cards = new QHBoxLayout;
    const QStringList titles{"已知基线", "扫描候选", "已测试", "验证成立", "未测试"};
    const QStringList colors{"#64748b", "#2563eb", "#0284c7", "#15803d", "#b45309"};
    for (int i = 0; i < 5; ++i) {
      m_cards[i] = new MetricCard(titles[i], colors[i], this);
      m_cards[i]->setObjectName("findingMetric" + QString::number(i));
      cards->addWidget(m_cards[i]);
    }
    layout->addLayout(cards);
    m_progress = new QProgressBar(this);
    m_progress->setObjectName("findingTestProgress");
    m_progress->setRange(0, 100);
    layout->addWidget(m_progress);
    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::PlainText);
    m_summary->setWordWrap(true);
    m_summary->setStyleSheet("color:#475569;font-size:12px;");
    layout->addWidget(m_summary);
    setStatistics({});
  }

  void setStatistics(const QJsonObject &stats) {
    const QStringList keys{"expected_count", "candidate_records", "tested_records", "confirmed_records", "untested_records"};
    auto count = [&stats](const QString &key) {
      const auto value = stats.value(key);
      const double n = value.toDouble(-1);
      return value.isDouble() && std::isfinite(n) && n >= 0 && n <= 9007199254740991.0 && std::floor(n) == n
          ? QString::number(static_cast<qint64>(n)) : QStringLiteral("—");
    };
    for (int i = 0; i < 5; ++i) m_cards[i]->setValue(count(keys[i]));
    m_cards[0]->setToolTip("仅使用已登记的靶场漏洞基线；未登记时不推算应有漏洞数或检出率。");
    const double total = stats.value("candidate_records").toDouble(-1);
    const double tested = stats.value("tested_records").toDouble(-1);
    const bool valid = count("candidate_records") != "—" && count("tested_records") != "—" && tested <= total;
    m_progress->setValue(valid && total > 0 ? int(tested * 100.0 / total) : 0);
    m_progress->setFormat(valid && total > 0 ? QString("测试进度 %1 / %2（%p%）").arg(count("tested_records"), count("candidate_records"))
        : valid ? QStringLiteral("暂无漏洞候选") : QStringLiteral("统计待加载"));
    QStringList lines;
    lines << QString("实际测试：%1　尝试：%2 次　执行失败：%3　待复核：%4")
        .arg(count("tested_records"), count("attempt_count"), count("failed_records"), count("unreviewed_records"));
    if (!stats.value("conclusion").toString().isEmpty()) lines << stats.value("conclusion").toString();
    if (stats.value("unknown_attempts").toInt() > 0) lines << "有调用停止状态未确认，请先核查，不能开始下一轮。";
    lines << "按任务全部发现记录统计，尚未跨工具去重；重试不增加已测试数，测试进度不代表攻击成功率。";
    if (count("expected_count") == "—") lines << "应有漏洞：未知（尚未登记基线），不计算检出率。";
    m_summary->setText(lines.join('\n'));
  }
  QString text() const { return m_summary->text(); }
private:
  MetricCard *m_cards[5];
  QProgressBar *m_progress;
  QLabel *m_summary;
};
