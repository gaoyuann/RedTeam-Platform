#pragma once
#include "MetricCard.h"
#include "../Theme.h"
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>

// Summarizes existing records without filtering or transforming the result tree.
class ScanResultOverview : public QFrame {
public:
  explicit ScanResultOverview(QWidget *parent = nullptr) : QFrame(parent) {
    setObjectName("scanResultOverview");
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(10);
    auto *row = new QHBoxLayout;
    row->setSpacing(10);
    m_ports = new MetricCard(QStringLiteral("开放端口"), Theme::Primary, this);
    m_findings = new MetricCard(QStringLiteral("漏洞发现"), Theme::Error, this);
    m_credentials = new MetricCard(QStringLiteral("凭据发现"), Theme::Warning, this);
    m_ports->setObjectName("portMetric");
    m_findings->setObjectName("findingMetric");
    m_credentials->setObjectName("credentialMetric");
    for (auto *card : {m_ports, m_findings, m_credentials}) row->addWidget(card, 1);
    m_ports->setToolTip(QStringLiteral("开放端口结果记录数；同一端口的多条记录分别计数。"));
    m_findings->setToolTip(QStringLiteral("漏洞、网站漏洞和 SQL 注入结果记录数；不代表去重后的漏洞数。"));
    m_credentials->setToolTip(QStringLiteral("凭据类型的结果记录数。"));
    layout->addLayout(row);
    m_note = new QLabel(this);
    m_note->setObjectName("overviewNote");
    m_note->setWordWrap(true);
    m_note->setStyleSheet("color:#64748b; font-size:12px; background:transparent;");
    layout->addWidget(m_note);
    clear();
  }
  void clear() {
    for (auto *card : {m_ports, m_findings, m_credentials}) card->setValue(QStringLiteral("—"));
    m_note->setText(QStringLiteral("选择扫描任务，查看发现概览与完整结果。"));
  }
  void setResults(const QJsonArray &results) {
    int ports = 0, findings = 0, credentials = 0, raw = 0, other = 0;
    for (const auto &value : results) {
      const auto type = value.toObject().value("result_type").toString();
      if (type == "open_port") ++ports;
      else if (type == "vulnerability" || type == "web_vuln" || type == "sql_injection") ++findings;
      else if (type == "credential") ++credentials;
      else if (type == "raw_output") ++raw;
      else ++other;
    }
    m_ports->setValue(QString::number(ports));
    m_findings->setValue(QString::number(findings));
    m_credentials->setValue(QString::number(credentials));
    m_note->setText(results.isEmpty()
        ? QStringLiteral("尚无返回结果，请结合任务状态查看扫描进展。")
        : QStringLiteral("当前返回记录 · 其他信息 %1 条 · 原始输出 %2 条 · 各类结果未去重").arg(other).arg(raw));
  }
private:
  MetricCard *m_ports;
  MetricCard *m_findings;
  MetricCard *m_credentials;
  QLabel *m_note;
};