#include "FindingVerificationDialog.h"
#include "../widgets/WorkbenchTabs.h"
#include "ScanPage.h"
#include "../widgets/RemoteSourcePicker.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include "../widgets/ScanResultOverview.h"
#include <QSplitter>
#include <QStyledItemDelegate>
#include <QPainter>
#include <QTextLayout>
#include <QKeyEvent>
#include <QHelpEvent>
#include <QToolTip>
#include <QGridLayout>
#include <QTabBar>
#include <QDialog>
#include <QDialogButtonBox>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMessageBox>
#include <QSettings>
#include <QCompleter>
#include <QStringListModel>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QDateTime>
#include <QTreeWidgetItem>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QPointer>
#include <QUrl>
#include <QUuid>
#include <QHash>
#include <QSignalBlocker>
#include <QTreeWidgetItemIterator>

// Keep the existing record columns for evidence/actions, with five visible columns.
class ScanFindingDelegate final : public QStyledItemDelegate {
public:
  using QStyledItemDelegate::QStyledItemDelegate;
  void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override {
    QStyledItemDelegate::initStyleOption(option, index);
    if (!index.parent().isValid()) return;
    if (index.column() == 0) option->text.clear();
    if (index.column() == 6) {
      const auto conclusion = index.sibling(index.row(), 7).data().toString();
      if (!conclusion.isEmpty() && conclusion != "—") option->text += "\n" + conclusion;
    }
  }
  bool helpEvent(QHelpEvent *event, QAbstractItemView *view, const QStyleOptionViewItem &option, const QModelIndex &index) override {
    if (index.column() == 1 && index.parent().isValid()) {
      QToolTip::showText(event->globalPos(), index.data().toString(), view); return true;
    }
    return QStyledItemDelegate::helpEvent(event, view, option, index);
  }
  QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override {
    auto size = QStyledItemDelegate::sizeHint(option, index);
    if (index.parent().isValid()) size.setHeight(option.fontMetrics.height() * 2 + 18);
    return size;
  }
  void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override {
    if (index.column() == 6 && index.parent().isValid()) {
      QStyleOptionViewItem styled(option); initStyleOption(&styled, index); styled.text.clear();
      const auto *widget = styled.widget;
      (widget ? widget->style() : QApplication::style())->drawControl(QStyle::CE_ItemViewItem, &styled, painter, widget);
      painter->save(); painter->setClipRect(option.rect); painter->setFont(styled.font);
      const QRect area = option.rect.adjusted(8, 7, -8, -7);
      const auto stateBrush = index.data(Qt::ForegroundRole);
      painter->setPen(styled.state & QStyle::State_Selected ? QColor("#1e3a8a")
        : stateBrush.isValid() ? stateBrush.value<QBrush>().color() : QColor("#334155"));
      painter->drawText(area, Qt::AlignLeft | Qt::AlignTop, index.data().toString());
      const auto resultBrush = index.sibling(index.row(), 7).data(Qt::ForegroundRole);
      painter->setPen(resultBrush.isValid() ? resultBrush.value<QBrush>().color() : QColor("#64748b"));
      painter->drawText(area.adjusted(0, styled.fontMetrics.height()+2, 0, 0), Qt::AlignLeft | Qt::AlignTop,
        styled.fontMetrics.elidedText(index.sibling(index.row(), 7).data().toString(), Qt::ElideRight, area.width()));
      painter->restore(); return;
    }
    if (index.column() != 1 || !index.parent().isValid()) {
      QStyledItemDelegate::paint(painter, option, index); return;
    }
    QStyleOptionViewItem styled(option); initStyleOption(&styled, index);
    const QString text = styled.text; styled.text.clear();
    const auto *widget = styled.widget;
    const auto *style = widget ? widget->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &styled, painter, widget);
    const QRect area = option.rect.adjusted(8, 7, -8, -7);
    painter->save(); painter->setClipRect(area); painter->setFont(styled.font);
    painter->setPen(styled.state & QStyle::State_Selected ? QColor("#1e3a8a") : QColor("#172033"));
    QTextLayout layout(text, styled.font);
    QTextOption wrapping; wrapping.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere); layout.setTextOption(wrapping);
    layout.beginLayout();
    qreal y = 0;
    QList<QTextLine> lines;
    for (int i = 0; i < 2; ++i) {
      auto line = layout.createLine(); if (!line.isValid()) break;
      line.setLineWidth(area.width()); line.setPosition(QPointF(0, y)); y += line.height(); lines.append(line);
    }
    layout.endLayout();
    for (int i = 0; i < lines.size(); ++i) {
      const auto line = lines[i];
      if (i == 1 && line.textStart() + line.textLength() < text.size()) {
        const QRect lastLine(area.left(), area.top() + int(line.y()), area.width(), int(line.height()) + 2);
        painter->drawText(lastLine, Qt::AlignLeft | Qt::AlignTop,
          styled.fontMetrics.elidedText(text.mid(line.textStart()).simplified(), Qt::ElideRight, area.width()));
      } else line.draw(painter, area.topLeft());
    }
    painter->restore();
  }
};

// Partial selection is a display state; user activation always selects or clears all.
class FindingSelectAllCheckBox final : public QCheckBox {
public:
  using QCheckBox::QCheckBox;
protected:
  void nextCheckState() override {
    setCheckState(checkState() == Qt::Checked ? Qt::Unchecked : Qt::Checked);
  }
};

static QString findingIndicatorStyle(const QString &selector) {
  QString style;
  const QList<QPair<QString, QString>> states{
    {"unchecked", "off"}, {"checked", "on"}, {"indeterminate", "partial"},
    {"unchecked:disabled", "off_disabled"}, {"checked:disabled", "on_disabled"},
    {"indeterminate:disabled", "partial_disabled"}};
  for (const auto &state : states)
    style += selector + "::indicator:" + state.first
      + " { image: url(:/icons/checkbox_" + state.second + ".png); }";
  return style;
}

static bool isProgramScan(const QString &type) { return type == "program_scan" || type == "source_scan"; }
static bool isProgramFinding(const QString &type) { return type == "program_finding" || type == "source_finding"; }

static bool isVerificationRecord(const QJsonObject &row) {
  if(row.contains("category"))return row["category"].toString()=="vulnerability";
  const QStringList types{"vulnerability","web_vuln","sql_injection","misconfiguration","auth_finding","source_vuln","source_finding","program_finding"};
  return types.contains(row["result_type"].toString()) && !QStringList{"info","inf"}.contains(row["severity"].toString().toLower());
}
// Keep record roles on column 0 and existing name/source consumers on columns 1–2.
static void showFindingSummary(QTreeWidgetItem *item, const QJsonObject &record, bool aggregate) {
  const bool candidate = isVerificationRecord(record);
  item->setData(0, Qt::UserRole+2, candidate ? QString("vulnerability") : record["category"].toString());
  if (!candidate) {
    for (int column : {3, 6, 7}) item->setText(column, QStringLiteral("—"));
    return;
  }
  const auto match = record["payload_match"].toObject();
  const QMap<QString, QString> payloadLabels{{"linked", "已关联（待核对条件）"}, {"stale", "关联已失效"},
    {"candidate", "有匹配候选"}, {"none", "暂无匹配"}};
  item->setText(3, payloadLabels.value(match["status"].toString(), QStringLiteral("待匹配")));
  item->setToolTip(3, match["name"].toString() + "\n" + match["match_basis"].toString()
    + QStringLiteral("\n匹配或关联不代表可执行；载荷版本、消费方式和条件须在准备测试时核对。"));
  // A single-scan response does not carry the task verification summary.
  if (!aggregate || !record.contains("verification")) {
    item->setText(6, QStringLiteral("状态未提供"));
    item->setText(7, QStringLiteral("待核对"));
    return;
  }
  const auto verification = record["verification"].toObject();
  const QMap<QString, QString> states{{"needs_conditions", "缺少条件"}, {"preparation_failed", "准备失败"},
    {"draft", "准备中"}, {"ready", "已就绪"}, {"queued", "排队中"}, {"running", "执行中"},
    {"cancelling", "取消中"}, {"unknown", "停止未知"}, {"completed", "已完成"},
    {"failed", "执行失败"}, {"aborted", "已中止"}};
  item->setText(6, verification.isEmpty() ? QStringLiteral("未测试")
    : states.value(verification["state"].toString(), QStringLiteral("未知状态")));
  const auto result = verification["result"].toObject();
  const QMap<QString, QString> conclusions{{"achieved", "目标已达成"}, {"not_achieved", "目标未达成"},
    {"inconclusive", "证据不足"}, {"not_performed", "待判定（未验证）"}, {"pending", "待判定"}};
  item->setText(7, verification.isEmpty() ? QStringLiteral("待判定")
    : result["schema_version"].toInt() != 1 ? QStringLiteral("证据不足（旧记录）")
    : conclusions.value(result["status"].toString(), QStringLiteral("证据不足（未知结论）")));
  item->setToolTip(6, verification["reason"].toString());
  item->setToolTip(7, QStringLiteral("验证目标：%1\n依据：%2\n限制：%3\n执行完成不等于漏洞成立；人工意见在验证详情中单独展示。")
    .arg(result["objective"].toObject()["label"].toString(), result["reason"].toString(), result["limitations"].toString()));
  if (result["schema_version"].toInt() == 1 && result["status"].toString() == "achieved")
    item->setForeground(7, QColor(Theme::Success));
  if (QStringList{"unknown", "failed", "preparation_failed"}.contains(verification["state"].toString()))
    item->setForeground(6, QColor(Theme::Warning));
}

// ── Translate nikto finding text to Chinese ───────────────────────────
static QString translateNiktoFinding(const QString &finding) {
  if (finding.contains("X-Frame-Options header is not present"))
    return "缺少 X-Frame-Options 防点击劫持头";
  if (finding.contains("X-XSS-Protection") && finding.contains("not defined"))
    return "缺少 X-XSS-Protection 防XSS头";
  if (finding.contains("X-Content-Type-Options") && finding.contains("not set"))
    return "缺少 X-Content-Type-Options 防MIME嗅探头";
  if (finding.contains("httponly flag"))
    return QString("会话标识未设置 HttpOnly 标志") +
           (finding.contains("PHPSESSID") ? " (PHPSESSID)" :
            finding.contains("security")  ? " (security)" : "");
  if (finding.contains("Directory indexing found"))
    return "目录索引已开启";
  if (finding.contains("Configuration information may be available"))
    return "配置信息可能可远程访问";
  if (finding.contains("Admin login page") || finding.contains("login page/section"))
    return "发现管理员登录页面";
  if (finding.contains("Apache default file found"))
    return "发现 Apache 默认文件";
  if (finding.contains("Server leaks inodes via ETags"))
    return "服务器通过 ETag 泄露 inode 信息";
  if (finding.contains("Allowed HTTP Methods"))
    return "允许的 HTTP 方法";
  if (finding.contains("Help directory should not be accessible"))
    return "Help 目录不应可访问";
  if (finding.contains("No CGI Directories found"))
    return "";
  if (finding.contains("OSVDB-3233") || finding.contains("default file"))
    return "发现默认文件";
  return finding;
}

static QString translateSqlmapDetail(const QString &detail) {
  if (detail.contains("is vulnerable to SQL injection"))
    return "目标存在 SQL 注入漏洞";
  if (detail.contains("is injectable"))
    return "参数存在注入";
  return detail;
}

static QString formatResultType(const QString &type) {
  if (type == "finding_candidates") return "漏洞候选（扫描发现，非攻击成功）";
  if (type == "information") return "信息与普通提示（不计入漏洞）";
  if (type == "program_finding") return "程序漏洞发现 / 攻击效果";
  if (type == "program_coverage") return "智能体检测覆盖";
  if (type == "program_agent_step") return "智能体检测过程";
  if (type == "program_agent_summary") return "智能体扫描结论";
  if (type == "open_port")    return "开放端口";
  if (type == "vulnerability") return "漏洞";
  if (type == "web_vuln")     return "网站漏洞";
  if (type == "source_vuln")  return "旧版静态发现";
  if (type == "source_finding") return "源码候选 / 复核结果";
  if (type == "application_observation") return "程序入口响应";
  if (type == "source_coverage") return "分析覆盖情况";
  if (type == "sql_injection") return "SQL注入";
  if (type == "credential")   return "凭据";
  if (type == "raw_output")   return "原始输出";
  if (type == "service_info") return "服务信息";
  if (type == "http_probe") return "HTTP 探测";
  if (type == "technology_detection") return "应用指纹";
  if (type == "scan_error") return "工具失败";
  return type;
}

// ── Formatting helpers ────────────────────────────────────────────────

QString ScanPage::formatScanType(const QString &type) {
  if (type == "port_scan")   return "端口扫描";
  if (type == "vuln_scan")   return "漏洞扫描";
  if (type == "web_scan")    return "网站扫描";
  if (type == "app_discovery") return "应用发现";
  if (type == "brute_force") return "暴力破解";
  if (isProgramScan(type)) return "程序漏洞测试";
  return type;
}

QString ScanPage::formatStatus(const QString &s, bool hasStructured) {
  if (s == "COMPLETED")  return hasStructured ? "已完成" : "无有效结果";
  if (s == "PARTIAL")    return "部分完成";
  if (s == "RUNNING")    return "运行中";
  if (s == "PENDING")    return "待执行";
  if (s == "FAILED")     return "失败";
  if (s == "CANCELLED")  return "已取消";
  return s;
}

QString ScanPage::formatSeverity(const QString &s) {
  QString sl = s.toLower();
  if (sl == "critical") return "严重";
  if (sl == "high")     return "高危";
  if (sl == "medium")   return "中危";
  if (sl == "low")      return "低危";
  if (sl == "info" || sl == "inf") return "信息";
  return s;
}

QString ScanPage::formatDifficulty(const QString &s) {
  if (s == "easy")   return "简单";
  if (s == "medium") return "中等";
  if (s == "hard")   return "困难";
  return s;
}

QString ScanPage::formatBaselineGroup(const QString &s) {
  if (s == "recon")                           return "侦察";
  if (s == "web-vuln-scan")                   return "网站漏洞扫描";
  if (s == "windows-exploitation")            return "Windows利用";
  if (s == "post-exploitation")               return "后渗透";
  if (s == "internal-network-exploitation")   return "内网横向";
  if (s == "local-security-check")            return "本地安全检查";
  if (s == "impact-demonstration")            return "影响演示";
  if (s == "domain-osint")                    return "域信息收集";
  if (s == "brute")                           return "暴力破解";
  if (s == "exploit")                         return "漏洞利用";
  if (s == "vuln_scan")                       return "漏洞扫描";
  return s;
}

QString ScanPage::formatTime(const QString &iso) {
  if (iso.isEmpty()) return "";
  auto dt = QDateTime::fromString(iso, Qt::ISODate);
  if (!dt.isValid()) return iso.left(16);
  return dt.toString("MM-dd HH:mm");
}

QString ScanPage::formatResultData(const QString &json, const QString &resultType) {
  if (json.isEmpty()) return "";
  auto doc = QJsonDocument::fromJson(json.toUtf8());
  if (doc.isObject()) {
    auto obj = doc.object();

    if (resultType == "open_port") {
      int port = obj["port"].toInt();
      QString proto = obj["protocol"].toString("tcp");
      QString state = obj["state"].toString();
      QString service = obj["service"].toString();
      if (port > 0) {
        QString text = QString("%1/%2").arg(port).arg(proto);
        if (state == "open") text += " 开放";
        if (!service.isEmpty()) text += QString(" — %1").arg(service);
        return text;
      }
    }

    if (resultType == "credential") {
      QString login = obj["login"].toString();
      QString password = obj["password"].toString();
      QString service = obj["service"].toString();
      int port = obj["port"].toInt();
      if (!login.isEmpty() || !password.isEmpty()) {
        QString text = QString("用户: %1  密码: %2").arg(login, password);
        if (!service.isEmpty()) text += QString("  [%1]").arg(service);
        if (port > 0) text += QString("  端口:%1").arg(port);
        return text;
      }
    }

    if (resultType == "vulnerability") {
      QString title = obj["title"].toString();
      QString tmpl = obj["template"].toString();
      QString protocol = obj["protocol"].toString();
      QString detail = obj["detail"].toString();
      if (!tmpl.isEmpty()) {
        QString text = tmpl;
        if (!protocol.isEmpty()) text += QString(" [%1]").arg(protocol);
        if (!detail.isEmpty()) text += " — " + detail;
        return text;
      }
      if (!title.isEmpty()) return title + (detail.isEmpty() ? "" : " — " + detail);
    }

    if (resultType == "sql_injection") {
      QString detail = obj["detail"].toString();
      if (!detail.isEmpty()) return translateSqlmapDetail(detail);
    }

    if (resultType == "web_vuln") {
      QString finding = obj["finding"].toString();
      QString path = obj["path"].toString();
      QString cn = translateNiktoFinding(finding);
      if (cn.isEmpty()) return "";
      if (!path.isEmpty() && !finding.contains(path)) cn += QString(" — %1").arg(path);
      return cn;
    }

    if (isProgramFinding(resultType)) {
      const auto review = obj["review"].toObject();
      const QString status = review["status"].toString();
      QString label = status == "supported" ? "复核：证据支持" : status == "not_reproduced" ? "复核：未复现" : status == "inconclusive" ? "复核：条件不足" : "待验证";
      if(status.isEmpty() && obj["counter_review"].toObject()["verdict"].toString()=="unlikely") label="静态反证：疑点可能不成立，待复核";
      if(resultType=="program_finding") return QString("%1 [%2] %3 — %4").arg(obj["url"].toString(),obj["cwe"].toString(),obj["title"].toString(),label);
      return QString("%1:%2 [%3] %4 — %5").arg(obj["file"].toString()).arg(obj["start_line"].toInt())
        .arg(obj["cwe"].toString(), obj["title"].toString(), label);
    }
    if (resultType == "application_observation")
      return QString("%1 · %2\n%3").arg(obj["url"].toString(),
        obj["error"].isNull() ? QString("响应已保存（不代表漏洞验证成功）") : obj["error"].toString(),
        obj["response"].toString().left(300));
    if (resultType == "source_coverage") {
      if (obj["engine"].toString() == "cscan" && (obj["input_mode"].toString()=="service_path" || obj["input_mode"].toString()=="remote_agent")) {
        const auto flow=obj["cscan"].toObject();
        const QMap<QString,QString> states={{"preparing","准备扫描"},{"submitting","正在提交"},{"created","已创建"},
          {"running","扫描中"},{"waiting","核对任务状态"},{"report_ready","报告已收齐"},{"parsing","正在解析报告"},
          {"importing","正在导入漏洞"},{"finished","报告处理完成"},{"report_error","报告解析存在缺口"},
          {"import_error","报告导入失败"},{"error","扫描失败"},{"timed_out","扫描超时"},{"cancelled","已取消"},
          {"interrupted","服务重启中断"},{"source_unavailable","未取得源码"}};
        QStringList errors;for(const auto &v:obj["source_errors"].toArray()) errors.append(v.toString());
        for(const auto &v:obj["parse_errors"].toArray()) errors.append(v.toString());
        const auto tasks=flow["task_progress"].toObject(),subs=flow["subtask_progress"].toObject();
        const QString progress=tasks.isEmpty()?QString():QString("\n任务完成 %1/%2；子任务完成 %3/%4")
          .arg(tasks["finished"].toInt()).arg(tasks["total"].toInt()).arg(subs["finished"].toInt()).arg(subs["total"].toInt());
        return QString("CScan 审计目标：%1；Flow %2；状态：%3\n%4\n%5")
          .arg(obj["source_target"].toString(),flow["flow_id"].toString(),states.value(flow["state"].toString(),flow["state"].toString()),obj["note"].toString(),errors.join("；"))+progress;
      }
      if (obj["engine"].toString() == "cscan" && obj["source_read"].toBool()) {
        const auto flow = obj["cscan"].toObject();
        const QMap<QString,QString> states={{"preparing","准备源码"},{"submitting","正在提交"},{"created","已创建"},
          {"running","扫描中"},{"waiting","等待输入"},{"finished","扫描结束"},{"error","扫描失败"},
          {"report_error","报告导入失败"},{"timed_out","扫描超时"},{"cancelled","已取消"},{"interrupted","服务重启中断"}};
        QStringList errors;for(const auto &error:obj["source_errors"].toArray()) errors.append(error.toString());
        const auto tasks=flow["task_progress"].toObject(),subtasks=flow["subtask_progress"].toObject();
        const QString progress=tasks.isEmpty()?QString():QString("\n任务完成 %1/%2；子任务完成 %3/%4，失败 %5。")
          .arg(tasks["finished"].toInt()).arg(tasks["total"].toInt())
          .arg(subtasks["finished"].toInt()).arg(subtasks["total"].toInt()).arg(subtasks["failed"].toInt());
        return QString("CScan 扫描：%1；Flow %2；已采集 %3 个源码文件，服务报告已审阅 %4 个。%5\n%6\n%7")
          .arg(states.value(flow["state"].toString(),flow["state"].toString()), flow["flow_id"].toString()).arg(obj["files"].toInt())
          .arg(obj["reviewed_files"].toArray().size())
          .arg(obj["cscan_complete"].toBool() ? "快照分析完成。" : "分析未完成或存在覆盖缺口。", obj["note"].toString(),errors.join("；"))+progress;
      }
      if (!obj["source_read"].toBool()) {
        QStringList errors;for(const auto &error:obj["source_errors"].toArray()) errors.append(error.toString());
        if(!errors.isEmpty()) return "源码读取失败："+errors.join("；")+"。本次未完成源码审阅。";
        return "远程程序测试：本次未读取源码；可根据响应生成测试预案";
      }
      const QString source=obj["source_url"].toString();
      const auto compilation=obj["compilation"].toObject(),counter=obj["ai_counter_review"].toObject();
      QString extra;
      if(compilation["requested"].toBool()) {
        if(!compilation["available"].toBool()) extra+=" 未取得有效构建信息，使用普通扫描配置。";
        else extra+=QString(" 编译配置：%1 个单元已接入，%2 个使用普通扫描。").arg(compilation["configured_units"].toInt()).arg(compilation["fallback_units"].toInt());
        if(compilation["ignored_options"].toInt() || compilation["external_paths"].toInt() || compilation["skipped_units"].toInt()) extra+=" 部分构建信息未接入，详情见覆盖证据。";
      }
      if(counter["requested"].toInt()>0) {
        extra+=QString(" 独立反证复核：%1/%2 项。").arg(counter["reviewed"].toInt()).arg(counter["requested"].toInt());
        if(counter["omitted"].toInt()>0) extra+=QString(" 另有 %1 项因预算限制未复核。").arg(counter["omitted"].toInt());
      }
      return (source.isEmpty() ? QString() : "源码目录：" + source + "\n") + QString("已读取 %1 个文件；AI 分析 %2/%3 个片段；跳过 %4 个文件。%5")
        .arg(obj["files"].toInt()).arg(obj["ai_reviewed_chunks"].toInt()).arg(obj["total_chunks"].toInt())
        .arg(obj["skipped"].toArray().size()).arg(obj["note"].toString())+extra;
    }
    if (resultType == "source_vuln") {
      QString file = obj["file"].toString();
      if (file.startsWith("/src/")) {  // 去掉容器挂载前缀，只留相对路径
        int slash = file.indexOf('/', 5);
        file = slash > 0 ? file.mid(slash + 1) : file.mid(5);
      }
      int line = obj["line"].toInt();
      QString cwe = obj["cwe"].toString();
      QString msg = obj["message"].toString();
      QString text = file;
      if (line > 0) text += QString(":%1").arg(line);
      if (!cwe.isEmpty()) text += QString(" [%1]").arg(cwe);
      if (!msg.isEmpty()) text += " — " + msg;
      return text;
    }

    if (resultType == "scan_error") return obj["error"].toString();
    if (resultType == "http_probe" || resultType == "technology_detection") {
      return QString("%1 [%2] %3").arg(obj["url"].toString())
          .arg(obj["status_code"].toInt()).arg(obj["title"].toString());
    }

    QStringList parts;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
      QString val = it.value().isString() ? it.value().toString()
                    : it.value().isDouble() ? QString::number(it.value().toDouble())
                    : it.value().toVariant().toString();
      parts << QString("%1=%2").arg(it.key(), val);
    }
    return parts.join(", ");
  }
  return json.length() > 200 ? json.left(200) + "…" : json;
}

QColor ScanPage::severityColor(const QString &sev) {
  QString sl = sev.toLower();
  if (sl == "critical") return QColor("#ef4444");
  if (sl == "high")     return QColor("#f97316");
  if (sl == "medium")   return QColor("#eab308");
  if (sl == "low")      return QColor("#22c55e");
  if (sl == "info" || sl == "inf") return QColor("#94a3b8");
  return QColor("#94a3b8");
}

QString ScanPage::formatDuration(const QString &started, const QString &completed) {
  if (started.isEmpty() || completed.isEmpty()) return "";
  auto s = QDateTime::fromString(started, Qt::ISODate);
  auto c = QDateTime::fromString(completed, Qt::ISODate);
  if (!s.isValid() || !c.isValid()) return "";
  qint64 secs = s.secsTo(c);
  if (secs < 60) return QString("耗时: %1s").arg(secs);
  if (secs < 3600) return QString("耗时: %1m%2s").arg(secs / 60).arg(secs % 60);
  return QString("耗时: %1h%2m").arg(secs / 3600).arg((secs % 3600) / 60);
}

QString ScanPage::buildResultSummary(const QJsonArray &results, const QString &scanType) {
  if (results.isEmpty()) return "";

  if (scanType == "port_scan") {
    QStringList ports;
    for (const auto &r : results) {
      auto obj = r.toObject();
      if (obj["result_type"].toString() == "open_port") {
        QJsonObject data;
        { QJsonParseError err; auto doc = QJsonDocument::fromJson(obj["result_data"].toString().toUtf8(), &err); if (err.error == QJsonParseError::NoError && doc.isObject()) data = doc.object(); }
        int port = data["port"].toInt();
        if (port > 0) ports << QString::number(port);
      }
    }
    if (!ports.isEmpty()) return "开放端口: " + ports.join(", ");
  }
  else if (scanType == "vuln_scan") {
    QMap<QString, int> counts;
    for (const auto &r : results) {
      QString sev = r.toObject()["severity"].toString();
      if (!sev.isEmpty()) counts[sev]++;
    }
    QStringList parts;
    for (const auto &sev : {"critical", "high", "medium", "low"}) {
      if (counts.contains(sev) && counts[sev] > 0)
        parts << QString("%1: %2").arg(formatSeverity(sev)).arg(counts[sev]);
    }
    if (!parts.isEmpty()) return parts.join(", ");
  }
  else if (scanType == "web_scan") {
    int sqli = 0, webVulns = 0;
    for (const auto &r : results) {
      QString type = r.toObject()["category"].toString()=="information" ? "information" : r.toObject()["result_type"].toString();
      if (type == "sql_injection") sqli++;
      if (type == "web_vuln") webVulns++;
    }
    QStringList parts;
    if (webVulns > 0) parts << QString("网站漏洞：%1").arg(webVulns);
    if (sqli > 0) parts << QString("SQL注入: %1").arg(sqli);
    if (!parts.isEmpty()) return parts.join(", ");
  }
  else if (scanType == "brute_force") {
    int creds = 0;
    for (const auto &r : results) {
      if (r.toObject()["result_type"].toString() == "credential") creds++;
    }
    if (creds > 0) return QString("破解成功: %1").arg(creds);
  }
  else if (isProgramScan(scanType)) {
    QMap<QString, int> counts;
    for (const auto &r : results) {
      auto obj = r.toObject();
      if (obj["result_type"].toString() != "source_vuln" && !isProgramFinding(obj["result_type"].toString())) continue;
      QString sev = obj["severity"].toString();
      if (!sev.isEmpty()) counts[sev]++;
    }
    QStringList parts;
    for (const auto &sev : {"critical", "high", "medium", "low"}) {
      if (counts.contains(sev) && counts[sev] > 0)
        parts << QString("%1: %2").arg(formatSeverity(sev)).arg(counts[sev]);
    }
    if (!parts.isEmpty()) return parts.join(", ");
  }
  return "";
}

static QColor statusColor(const QString &status, bool hasStructured = true) {
  QString sl = status.toLower();
  if (sl == "completed")  return hasStructured ? QColor("#22c55e") : QColor("#f59e0b");
  if (sl == "partial")    return QColor("#f59e0b");
  if (sl == "running")    return QColor("#3b82f6");
  if (sl == "failed")     return QColor("#ef4444");
  if (sl == "pending")    return QColor("#f59e0b");
  if (sl == "cancelled")  return QColor("#94a3b8");
  return QColor("#94a3b8");
}

bool ScanPage::hasStructuredResults(const QJsonArray &results) {
  for (const auto &r : results) {
    QString type = r.toObject()["category"].toString()=="information" ? "information" : r.toObject()["result_type"].toString();
    if (type != "raw_output" && type != "scan_error") return true;
  }
  return false;
}

// ── Helper: map scan_type string to the corresponding table ───────────
static QTableWidget *tableForScanType(const QString &scanType,
                                       QTableWidget *port, QTableWidget *vuln,
                                       QTableWidget *web, QTableWidget *brute,
                                       QTableWidget *source) {
  if (scanType == "port_scan")   return port;
  if (scanType == "vuln_scan")   return vuln;
  if (scanType == "web_scan" || scanType == "app_discovery") return web;
  if (scanType == "brute_force") return brute;
  if (isProgramScan(scanType)) return source;
  return nullptr;
}

// ── Helper: enable/disable the delete button in the currently active tab ─
void ScanPage::enableCurrentTabDelBtn(bool enabled) {
  // A selected task can belong to another tab. Never expose a delete action
  // for it after the user has switched tabs.
  m_portDelBtn->setEnabled(false);
  m_vulnDelBtn->setEnabled(false);
  m_webDelBtn->setEnabled(false);
  m_bruteDelBtn->setEnabled(false);
  m_sourceDelBtn->setEnabled(false);
  if (!enabled || m_selectedTaskId.isEmpty()) return;

  int idx = m_scanTypeTabs->currentIndex();
  QTableWidget *activeTable = idx == 0 ? m_portScanTable
                            : idx == 1 ? m_vulnScanTable
                            : idx == 2 ? m_webScanTable
                            : idx == 3 ? m_bruteForceTable
                                       : m_sourceScanTable;
  bool taskIsInActiveTab = false;
  for (int row = 0; row < activeTable->rowCount(); ++row) {
    auto *item = activeTable->item(row, 0);
    if (item && item->data(Qt::UserRole).toString() == m_selectedTaskId) {
      taskIsInActiveTab = true;
      break;
    }
  }
  if (!taskIsInActiveTab) return;

  switch (idx) {
    case 0: m_portDelBtn->setEnabled(true); break;
    case 1: m_vulnDelBtn->setEnabled(true); break;
    case 2: m_webDelBtn->setEnabled(true); break;
    case 3: m_bruteDelBtn->setEnabled(true); break;
    case 4: m_sourceDelBtn->setEnabled(true); break;
    default: break;
  }
}

// ── Constructor ───────────────────────────────────────────────────────

ScanPage::ScanPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent) : QWidget(parent), m_api(api) {
  (void)role; (void)username;
  setupUI();
  onRefreshTasks();
}

void ScanPage::setStatusText(const QString &text) {
  m_statusLabel->setText(text);
  if (!m_compactStatus) return;
  QString shortText = text.section('\n', 0, 0);
  const bool warning = text.contains("失败") || text.contains("不完整") || text.contains("待补") || text.contains("未确认") || text.contains("部分完成");
  if (text.startsWith("本任务扫描：")) shortText = text.section(QStringLiteral(" · "), 0, 0).mid(6);
  if (shortText.size() > 16) shortText = shortText.left(15) + QStringLiteral("…");
  m_compactStatus->setText(shortText);
  m_compactStatus->setToolTip(text);
  m_compactStatus->setStyleSheet(QStringLiteral("color:%1; background:transparent;").arg(warning ? "#b45309" : "#475569"));
}

void ScanPage::resizeResultColumns() {
  const int available = qMax(100, m_resultTree->viewport()->width() - 260);
  m_resultTree->setColumnWidth(0, 52);
  m_resultTree->setColumnWidth(4, 72);
  m_resultTree->setColumnWidth(6, 136);
  m_resultTree->setColumnWidth(1, available * 3 / 5);
  m_resultTree->setColumnWidth(5, available - available * 3 / 5);
}

bool ScanPage::eventFilter(QObject *object, QEvent *event) {
  if (object == m_resultTree->viewport() && event->type() == QEvent::Resize) resizeResultColumns();
  if (object == m_resultTree && event->type() == QEvent::KeyPress) {
    auto *key = static_cast<QKeyEvent*>(event);
    if (key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter) {
      openRecordDetails(m_resultTree->currentItem()); return true;
    }
  }
  return QWidget::eventFilter(object, event);
}

void ScanPage::openRecordDetails(QTreeWidgetItem *item) {
  if (!item || !item->parent() || m_scanPageBusy) return;
  for (auto *old : findChildren<QDialog*>("scanAuxRecord")) old->close();
  auto *dialog = new QDialog(this);
  dialog->setObjectName("scanAuxRecord");
  dialog->setAttribute(Qt::WA_DeleteOnClose);
  dialog->setWindowTitle(QStringLiteral("发现详情与证据"));
  dialog->resize(760, 520);
  auto *layout = new QVBoxLayout(dialog);
  auto *text = new QPlainTextEdit;
  text->setReadOnly(true);
  text->setPlainText(QStringLiteral("%1\n\n编号：%2\n严重性：%3\n目标 / 位置：%4\n测试状态：%5\n验证结论：%6\n来源工具：%7\n载荷情况：%8\n\n证据与原始记录：\n%9")
    .arg(item->text(1), item->text(0), item->text(4), item->text(5), item->text(6), item->text(7), item->text(2), item->text(3), item->toolTip(1)));
  text->appendPlainText(QStringLiteral("\n验证依据：\n") + item->toolTip(7)
    + QStringLiteral("\n载荷说明：\n") + item->toolTip(3)
    + QStringLiteral("\n漏洞候选尚需证据验证；匹配载荷不代表可直接执行。"));
  layout->addWidget(text);
  auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
  buttons->button(QDialogButtonBox::Close)->setText(QStringLiteral("关闭"));
  connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
  const qint64 id = item->data(0, Qt::UserRole+1).toLongLong();
  if (!m_pipelineId.isEmpty() && item->data(0, Qt::UserRole+2).toString() == "vulnerability" && id > 0) {
    auto *prepare = buttons->addButton(QStringLiteral("准备验证"), QDialogButtonBox::ActionRole);
    prepare->setObjectName("prepareFindingVerification");
    const QString pipeline = m_pipelineId;
    const int scope = m_scopeRevision;
    connect(prepare, &QPushButton::clicked, this, [this, dialog, id, pipeline, scope]() {
      if (pipeline != m_pipelineId || scope != m_scopeRevision) return;
      dialog->close(); openFindingVerification({id});
    });
  }
  layout->addWidget(buttons);
  dialog->show();
}

void ScanPage::setTarget(const QString &target)
{
  m_portTargetInput->setText(target);
  m_vulnTargetInput->setText(target);
  m_webTargetInput->setText(target);
  m_bruteTargetInput->setText(target);
  m_sourceTargetInput->setText(target);
}

void ScanPage::setPipelineScope(const QString &pipelineId, const QStringList &taskIds, const QString &state)
{
  if(m_pipelineId!=pipelineId) {
    m_checkedFindings.clear();
    const QSignalBlocker categoryBlock(m_resultCategory);
    m_resultCategory->setCurrentIndex(m_resultCategory->findData("vulnerability"));
    m_detailTabs->setCurrentIndex(0);
  }
  if (m_pipelineId == pipelineId && m_scopeTaskIds == taskIds) {
    if (m_pipelineScanState != state && m_allScanResults) { m_pipelineScanState = state; loadPipelineResults(); }
    return;
  }
  const auto checkedFindings = m_checkedFindings;
  setTaskScope(taskIds);
  m_checkedFindings = checkedFindings;
  m_pipelineId = pipelineId; m_pipelineScanState = state;
  m_resultSource->blockSignals(true); m_resultSource->clear(); m_resultSource->addItem(QStringLiteral("全部扫描任务"), QString()); m_resultSource->blockSignals(false);
  m_allScanResults = true;
  m_selectInitialScopeTask = false;
  m_aggregateControls->show();
  m_moreResultsButton->show();
  loadPipelineResults();
}

void ScanPage::loadPipelineResults(bool append)
{
  if (m_pipelineId.isEmpty()) return;
  const int request = ++m_scanPageRequest;
  const QString pipeline = m_pipelineId;
  const int scope = m_scopeRevision;
  if (!append) { if(m_webScanProcess){m_webScanProcess->clear();m_webScanProcess->hide();} m_scanCursor = 0; m_aggregateRecords = {}; m_resultTree->setRootIndex(QModelIndex()); m_resultTree->clear(); m_resultOverview->clear(); }
  m_allScanResults = true;
  m_selectedTaskId.clear();
  m_reexecBtn->hide(); m_genBtn->setEnabled(false);
  m_scanPageBusy = true; m_moreResultsButton->setEnabled(false);
  m_moreResultsButton->show();
  if (!append) {
    setStatusText(QStringLiteral("正在加载扫描结果…"));
    m_listTitle->setText(QStringLiteral("加载中…"));
    m_resultHint->setText(QStringLiteral("正在加载当前筛选结果…"));
    UiUtil::EmptyHint::setState(m_resultTree, QStringLiteral("正在加载…"));
  }
  updateFindingSelection();
  QString path = "/api/pipelines/" + pipeline + "/results?view=scans&limit=100&after=" + QString::number(m_scanCursor)
      + "&category=" + m_resultCategory->currentData().toString();
  if (append) path += "&through=" + QString::number(m_scanThrough);
  if (!m_resultSource->currentData().toString().isEmpty()) path += "&scan_task_id=" + m_resultSource->currentData().toString();
  QPointer<ScanPage> guard(this);
  m_api->get(path, 10000, [this, guard, request, pipeline, scope, append](const QJsonObject &response) {
    if (!guard || request != m_scanPageRequest || pipeline != m_pipelineId || scope != m_scopeRevision || !m_allScanResults) return;
    m_scanPageBusy = false;
    updateFindingSelection();
    if (response["status"].toString() != "ok") {
      setStatusText(QStringLiteral("扫描结果加载失败，请重试"));
      m_listTitle->setText(QStringLiteral("加载失败"));
      m_resultHint->setText(append ? QStringLiteral("加载更多失败，已加载记录保留；点击加载更多重试") : QStringLiteral("加载失败，请点击刷新重试"));
      m_moreResultsButton->setEnabled(append);
      UiUtil::EmptyHint::setState(m_resultTree, QStringLiteral("加载失败，请点击刷新重试"), true);
      return;
    }
    const auto data = response["data"].toObject();
    QStringList processLines;
    for (const auto &value : data["web_scan_process"].toArray()) {
      const auto row = value.toObject();
      const auto step = QJsonDocument::fromJson(row["result_data"].toString().toUtf8()).object();
      if (row["result_type"].toString() == "scan_agent_summary")
        processLines << QStringLiteral("ReAct 调度结束：%1 · 决策 %2 轮 · 派发 %3 项 · %4")
          .arg(step["reason"].toString()).arg(step["decisions"].toInt()).arg(step["dispatches"].toInt())
          .arg(step["complete"].toBool() ? QStringLiteral("已接入检查完成") : QStringLiteral("覆盖不完整，查看检查详情"));
      else if (row["result_type"].toString() == "scan_capability_assessment") {
        const auto stateText=[](const QJsonValue &v) { return v.isBool() ? (v.toBool() ? QStringLiteral("是") : QStringLiteral("否")) : QStringLiteral("不适用或未知"); };
        processLines << QStringLiteral("能力 %1 · 观察成功：%2 · 检测执行：%3 · 检测完成：%4 · %5")
          .arg(step["capability"].toString(),stateText(step["observation_success"]),stateText(step["detection_executed"]),stateText(step["detection_complete"]),
            step["coverage_incomplete"].toBool() ? QStringLiteral("覆盖不足") : QStringLiteral("本项检查完成"));
      }
      else if (row["result_type"].toString() == "scan_agent_step")
        processLines << QStringLiteral("ReAct 第 %1 轮 · %2 · %3 · %4：%5")
          .arg(step["turn"].toInt()).arg(step["action"].toString(), step["scan_type"].toString(), step["state"].toString(), step["reason"].toString());
      else if (row["result_type"].toString() == "web_scan_summary")
        processLines << QStringLiteral("结束：%1 · SQL 派发尝试 %2 次 · 工具启动 %3 次 · 页面请求 %4 次 · %5")
            .arg(step["reason"].toString()).arg(step["checks"].isDouble() ? QString::number(step["checks"].toInt()) : QStringLiteral("未知")).arg(step["checks_started"].isDouble() ? QString::number(step["checks_started"].toInt()) : QStringLiteral("未知")).arg(step["pages"].isDouble() ? QString::number(step["pages"].toInt()) : QStringLiteral("未知"))
            .arg(step["complete"].toBool() ? QStringLiteral("检查计划完成") : QStringLiteral("覆盖不完整"));
      else if(step["action"].toString()=="authentication")
        processLines << QStringLiteral("本次独立会话安全等级：%1 · %2").arg(step["security_level"].toString(),step["reason"].toString());
      else processLines << QStringLiteral("第 %1 轮 · %2 · %3：%4")
          .arg(step["turn"].toInt()).arg(step["action"].toString(), step["state"].toString(), step["reason"].toString() + (step["result"].toString().isEmpty() ? QString() : " · " + step["result"].toString()));
    }
    for (const auto &value : data["web_scan_process"].toArray()) {
      const auto row=value.toObject();
      if(row["result_type"].toString()!="scan_agent_summary")continue;
      const auto summary=QJsonDocument::fromJson(row["result_data"].toString().toUtf8()).object();
      const auto budget=summary["budget"].toObject(),used=budget["used"].toObject(),limits=budget["limits"].toObject();
      if(budget.isEmpty())continue;
      QStringList counts;
      const QStringList keys{"decisions","checks","pages","tools","sql_checks"};
      const QStringList labels{QStringLiteral("模型决策"),QStringLiteral("检查派发"),QStringLiteral("页面请求"),QStringLiteral("工具尝试"),QStringLiteral("SQL 尝试")};
      for(int i=0;i<keys.size();++i)
        counts << QStringLiteral("%1 %2/%3").arg(labels[i]).arg(used[keys[i]].toInt()).arg(limits[keys[i]].toInt());
      processLines << QStringLiteral("全任务预算：%1").arg(counts.join(QStringLiteral(" · ")));
    }
    if (data["web_scan_process_truncated"].toBool()) processLines.prepend(QStringLiteral("仅显示最近 100 条过程，完整记录见全部扫描记录"));
    m_webScanProcess->setPlainText(processLines.join("\n")); m_webScanProcess->setVisible(!processLines.isEmpty());
    const auto page = data["page"].toObject();
    for (const auto &row : data["scan_records"].toArray()) m_aggregateRecords.append(row);
    m_scanCursor = page["next_after"].toVariant().toLongLong();
    m_scanThrough = page["through"].toVariant().toLongLong();
    renderGroupedResults(m_aggregateRecords);
    m_moreResultsButton->setEnabled(page["has_more"].toBool());
    m_listTitle->setText(QStringLiteral("%1 · 共 %2 条").arg(m_resultCategory->currentText()).arg(page["total"].toInt()));
    m_resultHint->setText(QStringLiteral("已加载 %1 / %2 条记录 · 未去重")
        .arg(m_aggregateRecords.size()).arg(page["total"].toInt()));
    const auto summary = data["scan_summary"].toObject();
    QStringList states;
    bool active = false;
    const QString selected = m_resultSource->currentData().toString();
    m_resultSource->blockSignals(true); m_resultSource->clear();
    m_resultSource->addItem(QStringLiteral("全部扫描任务"), QString());
    for (const auto &value : data["scan_sources"].toArray()) {
      const auto source = value.toObject(); const QString id = source["scan_task_id"].toString();
      m_resultSource->addItem(formatScanType(source["scan_type"].toString()) + " · "
        + source["target"].toString(QStringLiteral("目标未记录")) + " · " + formatStatus(source["status"].toString()) + " · " + id.right(8), id);
      m_resultSource->setItemData(m_resultSource->count()-1, id, Qt::ToolTipRole);
      active = active || source["status"].toString() == "RUNNING" || source["status"].toString() == "PENDING";
      states << formatScanType(source["scan_type"].toString()) + "：" + formatStatus(source["status"].toString())
          + (source["error_message"].toString().isEmpty() ? QString() : "（" + source["error_message"].toString() + "）");
    }
    const bool unresolvedCalls = !summary["active_calls"].toArray().isEmpty();
    if (unresolvedCalls) states << QStringLiteral("工具调用尚未结束或停止状态未确认，请勿据此恢复环境");
    if (active || unresolvedCalls) m_pollTimer->start(2000); else m_pollTimer->stop();
    m_resultSource->setCurrentIndex(qMax(0, m_resultSource->findData(selected))); m_resultSource->blockSignals(false);
    for (const auto &value : summary["unexecuted_checks"].toArray()) states << formatScanType(value.toString()) + "：未执行";
    const int unfinishedChecks = summary.value("unfinished_check_count").toInt();
    if (unfinishedChecks > 0) states << QStringLiteral("检查覆盖仍有 %1 项未完成、未支持或缺条件").arg(unfinishedChecks);
    const QString scanState = unresolvedCalls ? QStringLiteral("工具尚未结束 / 停止未确认") : active ? QStringLiteral("进行中")
        : summary["completeness"].toString() == "complete"
          ? (unfinishedChecks > 0 ? QStringLiteral("结果已保存，检查覆盖待补") : QStringLiteral("已结束"))
          : QStringLiteral("结果不完整 / 待核对");
    setStatusText(QStringLiteral("本任务扫描：%1 · 共 %2 条记录（非去重漏洞数）\n%3")
        .arg(scanState)
        .arg(summary["record_count"].toInt()).arg(states.join("；")));
    m_statusLabel->setToolTip(QString::fromUtf8(QJsonDocument(data["scan_runs"].toArray()).toJson(QJsonDocument::Indented)));
    renderCoverage(data["scan_coverage"].toObject());
  });
}

void ScanPage::renderCoverage(const QJsonObject &coverage)
{
  m_coverageTree->clear();
  if (coverage.isEmpty()) { m_coverageTree->hide(); return; }
  QHash<QString, QTreeWidgetItem *> assets, services, entries;
  const auto statusText = [](const QString &state) {
    const QHash<QString, QString> names{{"reachable", "可达"}, {"observed", "已发现"},
      {"declared", "用户声明"}, {"unverified", "待探测"}, {"http_observed", "HTTP 已响应"},
      {"planned", "待执行"}, {"running", "执行中"}, {"completed", "已完成"},
      {"partial", "部分完成"}, {"failed", "失败"}, {"cancelled", "已取消"},
      {"unreachable", "不可达"}, {"unsupported", "未支持"},
      {"missing_condition", "缺条件"}, {"not_checked", "未检查"},
      {"not_applicable", "不适用"}, {"out_of_scope", "范围外"}};
    return names.value(state, state);
  };
  const auto add = [this, &statusText](QTreeWidgetItem *parent, const QString &name, const QJsonObject &row) {
    auto *item = parent ? new QTreeWidgetItem(parent) : new QTreeWidgetItem(m_coverageTree);
    item->setText(0, name);
    item->setText(1, statusText(row.value("state").toString()));
    item->setText(2, row.value("source_record_id").isNull() ? QString() : row.value("source_record_id").toVariant().toString());
    item->setToolTip(0, row.value("reason").toString());
    return item;
  };
  for (const auto &value : coverage.value("assets").toArray()) {
    const auto row = value.toObject();
    assets.insert(row.value("asset_id").toString(), add(nullptr, QStringLiteral("资产 %1").arg(row.value("host").toString()), row));
  }
  for (const auto &value : coverage.value("services").toArray()) {
    const auto row = value.toObject();
    const QString name = QStringLiteral("%1/%2 · %3").arg(row.value("port").toVariant().toString(),
      row.value("protocol").toString(), row.value("name").toString());
    services.insert(row.value("service_id").toString(), add(assets.value(row.value("asset_id").toString(), nullptr), name, row));
  }
  for (const auto &value : coverage.value("entries").toArray()) {
    const auto row = value.toObject();
    entries.insert(row.value("entry_id").toString(), add(services.value(row.value("service_id").toString(), nullptr),
      QStringLiteral("入口 %1 · %2").arg(row.value("kind").toString(), row.value("value").toString()), row));
  }
  for (const auto &value : coverage.value("checks").toArray()) {
    const auto row = value.toObject();
    auto *parent = entries.value(row.value("entry_id").toString(), services.value(row.value("service_id").toString(), nullptr));
    add(parent, QStringLiteral("检查 %1 · %2").arg(row.value("check_type").toString(), row.value("target").toString()), row);
  }
  const auto counts = coverage.value("counts").toObject();
  auto *summary = new QTreeWidgetItem(m_coverageTree);
  summary->setText(0, QStringLiteral("覆盖清单：资产 %1 · 服务 %2 · 入口 %3 · 检查 %4%5")
    .arg(counts.value("assets").toInt()).arg(counts.value("services").toInt())
    .arg(counts.value("entries").toInt()).arg(counts.value("checks").toInt())
    .arg(coverage.value("truncated").toBool() ? QStringLiteral("（当前仅显示前 500 项）") : QString()));
  m_coverageTree->insertTopLevelItem(0, m_coverageTree->takeTopLevelItem(m_coverageTree->indexOfTopLevelItem(summary)));
  m_coverageTree->expandToDepth(1);
  m_coverageTree->show();
}

void ScanPage::setTaskScope(const QStringList &taskIds)
{
  if (m_scopedTasks && taskIds == m_scopeTaskIds) return;
  clearTaskScope();
  m_scopedTasks = true;
  m_scopeTaskIds = taskIds;
  m_selectInitialScopeTask = !taskIds.isEmpty();
  for (auto *button : findChildren<QPushButton*>("scanCreateToggle")) {
    button->setChecked(false);
    button->hide();
  }
  if (!taskIds.isEmpty()) onRefreshTasks();
}

void ScanPage::clearTaskScope()
{
  for (auto *dialog : findChildren<QDialog*>())
    if (dialog->objectName().startsWith("scanAux")) dialog->close();
  ++m_scopeRevision;
  m_checkedFindings.clear();
  ++m_scanPageRequest; m_scanPageBusy = false; m_pipelineId.clear(); m_allScanResults = false;
  if (m_aggregateControls) m_aggregateControls->hide();
  if (m_moreResultsButton) m_moreResultsButton->hide();
  if (m_showAllRecords) m_showAllRecords->hide();
  m_scopedTasks = true;
  m_scopeTaskIds.clear();
  m_selectInitialScopeTask = false;
  m_selectedTaskId.clear();
  m_runningTaskIds.clear();
  m_pollErrorCount = 0;
  if (m_pollTimer) m_pollTimer->stop();
  for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable}) {
    if (table) table->setRowCount(0);
  }
  for (auto *count : {m_portScanCount, m_vulnScanCount, m_webScanCount, m_bruteForceCount, m_sourceScanCount}) {
    if (count) count->setText(QStringLiteral("共 0 个"));
  }
  setTarget(QString());
  clearDetailPanel();
}

void ScanPage::showTaskContextError(const QString &message)
{
  setStatusText(QStringLiteral("任务数据加载失败：%1。请返回任务列表后重试。").arg(message));
  m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
}

void ScanPage::setupUI() {
  setObjectName("scanPage");
  // Local styling: do not alter other pages or the application theme.
  setStyleSheet(Theme::PageStyle + QStringLiteral(
      "QWidget#scanPage { background:#f3f6fb; }"
      "QFrame#scanTasksPanel, QFrame#scanDetailsPanel { background:#ffffff; border:1px solid #dbe3ef; border-radius:14px; }"
      "QLabel#scanPanelTitle { color:#172033; font-size:17px; font-weight:700; }"
      "QLabel#scanPanelHint { color:#64748b; font-size:12px; }"
      "QTabWidget#scanDetailTabs::pane { border:none; background:#ffffff; padding:0; }"
      "QTableWidget, QTreeWidget { background:#ffffff; alternate-background-color:#f8fbff; border:1px solid #e2e8f0; border-radius:8px; }"
      "QTableWidget::item, QTreeWidget::item { padding:7px 6px; border:none; }"
      "QTableWidget::item:selected, QTreeWidget::item:selected { background:#dbeafe; color:#1e3a8a; }"
      "QHeaderView::section { background:#f1f5f9; color:#475569; border:none; border-bottom:1px solid #e2e8f0; padding:8px 6px; font-weight:600; }"
      "QSplitter::handle { background:transparent; }"
      "QSplitter::handle:hover { background:#dbeafe; }"));

  auto *mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(12, 12, 12, 12);
  mainLayout->setSpacing(12);

  // ══ Left Panel ══════════════════════════════════════════════════════
  auto *left = new QVBoxLayout;

  // ── 4-Tab scan type layout ──────────────────────────────────────────
  m_scanTypeTabs = new WorkbenchTabs;

  QSettings settings("RedTeam", "RedTeam-Platform");
  QStringList history = settings.value("history/targets").toStringList();

  // --- Tab: 端口扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    // Input row
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_portTargetInput = new QLineEdit;
    m_portTargetInput->setPlaceholderText("例: 192.168.1.1");
    m_portTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_portTargetInput->setCompleter(completer);
    h->addWidget(m_portTargetInput, 0, 1);
    h->addWidget(new QLabel("端口:"), 1, 0);
    m_portsInput = new QLineEdit;
    m_portsInput->setPlaceholderText("22,80");
    m_portsInput->setMinimumWidth(150);
    h->addWidget(m_portsInput, 1, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    // Task table
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("端口扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_portScanCount = new QLabel;
    m_portScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_portScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_portScanTable = new QTableWidget(0, 3);
    m_portScanTable->setObjectName("scanPortTasks");
    UiUtil::EmptyHint::attach(m_portScanTable, QStringLiteral("暂无端口扫描任务"));
    m_portScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_portScanTable->setAlternatingRowColors(true);
    m_portScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_portScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_portScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_portScanTable->setSortingEnabled(false);
    m_portScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_portScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_portScanTable, 1);
    connect(m_portScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    // Buttons
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    // Store per-tab delete button
    m_portDelBtn = delBtn;
    // Right-click menu
    connect(m_portScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_portScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_portScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("端口扫描"));
  }

  // --- Tab: 系统漏洞扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_vulnTargetInput = new QLineEdit;
    m_vulnTargetInput->setPlaceholderText("例: 192.168.1.1");
    m_vulnTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_vulnTargetInput->setCompleter(completer);
    h->addWidget(m_vulnTargetInput, 0, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("系统漏洞扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_vulnScanCount = new QLabel;
    m_vulnScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_vulnScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_vulnScanTable = new QTableWidget(0, 3);
    m_vulnScanTable->setObjectName("scanVulnTasks");
    UiUtil::EmptyHint::attach(m_vulnScanTable, QStringLiteral("暂无漏洞扫描任务"));
    m_vulnScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_vulnScanTable->setAlternatingRowColors(true);
    m_vulnScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_vulnScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_vulnScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_vulnScanTable->setSortingEnabled(false);
    m_vulnScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_vulnScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_vulnScanTable, 1);
    connect(m_vulnScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_vulnDelBtn = delBtn;
    connect(m_vulnScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_vulnScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_vulnScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("系统漏洞扫描"));
  }

  // --- Tab: Web漏洞扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_webTargetInput = new QLineEdit;
    m_webTargetInput->setPlaceholderText("例: http://target:8080");
    m_webTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_webTargetInput->setCompleter(completer);
    h->addWidget(m_webTargetInput, 0, 1);
    h->addWidget(new QLabel("会话标识："), 1, 0);
    m_cookieInput = new QLineEdit;
    m_cookieInput->setPlaceholderText("PHPSESSID=abc; security=low");
    m_cookieInput->setMinimumWidth(150);
    h->addWidget(m_cookieInput, 1, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("网站漏洞扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_webScanCount = new QLabel;
    m_webScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_webScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_webScanTable = new QTableWidget(0, 3);
    m_webScanTable->setObjectName("scanWebTasks");
    UiUtil::EmptyHint::attach(m_webScanTable, QStringLiteral("暂无网站扫描任务"));
    m_webScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_webScanTable->setAlternatingRowColors(true);
    m_webScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_webScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_webScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_webScanTable->setSortingEnabled(false);
    m_webScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_webScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_webScanTable, 1);
    connect(m_webScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_webDelBtn = delBtn;
    connect(m_webScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_webScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_webScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("网站漏洞扫描"));
  }

  // --- Tab: 弱口令扫描 ---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("目标:"), 0, 0);
    m_bruteTargetInput = new QLineEdit;
    m_bruteTargetInput->setPlaceholderText("例: 192.168.1.1");
    m_bruteTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_bruteTargetInput->setCompleter(completer);
    h->addWidget(m_bruteTargetInput, 0, 1);
    h->addWidget(new QLabel("服务:"), 1, 0);
    m_serviceCombo = new QComboBox;
    for (const auto &pair : QList<QPair<QString,QString>>{
      {"HTTP表单", "http-post-form"}, {"SSH", "ssh"}, {"FTP", "ftp"},
      {"SMB", "smb"}, {"RDP", "rdp"}, {"MySQL", "mysql"},
      {"PostgreSQL", "postgres"}, {"Telnet", "telnet"}
    }) {
      m_serviceCombo->addItem(pair.first, pair.second);
    }
    h->addWidget(m_serviceCombo, 1, 1);
    auto *btn = new QPushButton("创建扫描");
    btn->setProperty("primary", true);
    h->addWidget(btn, 2, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    // Form definition row (only for http-post-form)
    auto *h2 = new QHBoxLayout;
    auto *formDefLabel = new QLabel("表单:");
    m_formDefInput = new QLineEdit;
    m_formDefInput->setPlaceholderText("/login:user=^USER^&pass=^PASS^:F=Incorrect");
    h2->addWidget(formDefLabel);
    h2->addWidget(m_formDefInput, 1);
    h2->addStretch();
    layout->addLayout(h2);
    const bool needsForm = m_serviceCombo->currentData().toString() == "http-post-form";
    formDefLabel->setVisible(needsForm);
    m_formDefInput->setVisible(needsForm);
    connect(m_serviceCombo, &QComboBox::currentTextChanged, this, [this, formDefLabel]() {
      bool isForm = (m_serviceCombo->currentData().toString() == "http-post-form");
      formDefLabel->setVisible(isForm);
      m_formDefInput->setVisible(isForm);
    });
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("弱口令扫描"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_bruteForceCount = new QLabel;
    m_bruteForceCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_bruteForceCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_bruteForceTable = new QTableWidget(0, 3);
    m_bruteForceTable->setObjectName("scanCredentialTasks");
    UiUtil::EmptyHint::attach(m_bruteForceTable, QStringLiteral("暂无弱口令扫描任务"));
    m_bruteForceTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_bruteForceTable->setAlternatingRowColors(true);
    m_bruteForceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_bruteForceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_bruteForceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_bruteForceTable->setSortingEnabled(false);
    m_bruteForceTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_bruteForceTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_bruteForceTable, 1);
    connect(m_bruteForceTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_bruteDelBtn = delBtn;
    connect(m_bruteForceTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_bruteForceTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_bruteForceTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("弱口令扫描"));
  }

  // --- Tab: 源代码扫描（C/C++ 静态审计）---
  {
    auto *tab = new QWidget;
    auto *layout = new QVBoxLayout(tab);
    auto *h = new QGridLayout;
    h->addWidget(new QLabel("程序 / 源码地址:"), 0, 0);
    m_sourceTargetInput = new QLineEdit;
    m_sourceTargetInput->setPlaceholderText("源码路径或局域网源码地址，例如 /opt/project 或 http://主机/project/");
    m_sourceTargetInput->clear();
    m_sourceTargetInput->setMinimumWidth(150);
    auto *completer = new QCompleter(history, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_sourceTargetInput->setCompleter(completer);
    h->addWidget(m_sourceTargetInput, 0, 1);
    m_programInputKind = new QComboBox;
    m_programInputKind->addItem("选择目标主机的源码文件夹", "remote_directory");
    m_programInputKind->addItem("程序运行入口", "runtime");
    m_programInputKind->addItem("源码路径／地址（CScan 自行读取）", "agent");
    m_programInputKind->setCurrentIndex(m_programInputKind->findData("agent"));
    h->addWidget(m_programInputKind, 0, 2);
    m_remoteSourcePicker=new RemoteSourcePicker(m_api,this);
    m_remoteSourcePicker->hide();
    h->addWidget(m_remoteSourcePicker,2,0,1,3);
    connect(m_sourceTargetInput,&QLineEdit::textChanged,m_remoteSourcePicker,&RemoteSourcePicker::setTarget);
    connect(m_programInputKind,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){
      m_remoteSourcePicker->setVisible(m_programInputKind->currentData().toString()=="remote_directory");
    });
    m_programRuntimeInput = new QLineEdit;
    m_programRuntimeInput->setPlaceholderText("可选：对应程序的 HTTP/TCP 运行入口；只有文件也能扫描");
    h->addWidget(new QLabel("攻击测试运行入口:"), 8, 0);
    h->addWidget(m_programRuntimeInput, 8, 1, 1, 2);
    auto *preset = new QComboBox;
    preset->addItem("vulnerable-webapp · HTTP 8089", "http://192.168.1.113:8089");
    preset->addItem("vuln-demo · HTTP 8090", "http://192.168.1.113:8090");
    preset->addItem("exploit_me · TCP 8091", "tcp://192.168.1.113:8091");
    h->addWidget(new QLabel("靶场入口:"), 1, 0);
    h->addWidget(preset, 1, 1);
    connect(preset, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this,preset](int) {
      m_sourceTargetInput->setText(preset->currentData().toString());
      m_programInputKind->setCurrentIndex(1);
    });
    m_sourceNotesInput = new QLineEdit;
    m_sourceNotesInput->setMaxLength(4000);
    m_sourceNotesInput->setPlaceholderText("可选：审计范围、关注问题和补充要求");
    h->addWidget(new QLabel("审计说明:"), 4, 0);h->addWidget(m_sourceNotesInput, 4, 1, 1, 2);
    connect(m_programInputKind,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int) {
      m_sourceTargetInput->setPlaceholderText(m_programInputKind->currentData().toString()=="agent"
        ? "靶机 IP:端口、HTTP/TCP 地址或远端源码路径" : "目标主机地址：http://主机:端口/ 或 tcp://主机:端口");
    });
    m_sourceAdaptiveCheck = new QCheckBox("生成预案时允许 Agent 根据执行证据补充验证请求");
    m_sourceAdaptiveCheck->setChecked(true);
    h->addWidget(m_sourceAdaptiveCheck, 5, 1, 1, 2);
    auto *hint = new QLabel("填写源码路径或局域网源码地址，可在审计说明中注明目标主机及目录。平台仅提交位置和要求，由 CScan Agent 自行访问、读取和扫描；访问失败时显示服务返回原因，不上传源码或创建挂载。");
    hint->setWordWrap(true);
    hint->setStyleSheet("color:#64748b; font-size:12px;");
    h->addWidget(hint, 6, 0, 1, 3);
    auto *btn = new QPushButton("创建测试");
    btn->setProperty("primary", true);
    h->addWidget(btn, 7, 1);
    layout->addLayout(h);
    connect(btn, &QPushButton::clicked, this, &ScanPage::onCreateScan);
    auto *headerH = new QHBoxLayout;
    auto *label = new QLabel("程序漏洞测试"); label->setStyleSheet(Theme::SectionStyle);
    headerH->addWidget(label);
    m_sourceScanCount = new QLabel;
    m_sourceScanCount->setStyleSheet("color:#64748b; font-size:13px;");
    headerH->addWidget(m_sourceScanCount);
    headerH->addStretch();
    layout->addLayout(headerH);
    m_sourceScanTable = new QTableWidget(0, 3);
    m_sourceScanTable->setObjectName("scanSourceTasks");
    UiUtil::EmptyHint::attach(m_sourceScanTable, QStringLiteral("暂无程序测试任务"));
    m_sourceScanTable->setHorizontalHeaderLabels({"目标", "状态", "时间"});
    m_sourceScanTable->setAlternatingRowColors(true);
    m_sourceScanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_sourceScanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_sourceScanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_sourceScanTable->setSortingEnabled(false);
    m_sourceScanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_sourceScanTable->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(m_sourceScanTable, 1);
    connect(m_sourceScanTable, &QTableWidget::cellClicked, this, &ScanPage::onTaskClicked);
    auto *btnH = new QHBoxLayout;
    auto *delBtn = new QPushButton("删除选中");
    delBtn->setProperty("danger", true);
    delBtn->setEnabled(false);
    auto *refreshBtn = new QPushButton("刷新任务列表");
    btnH->addWidget(delBtn);
    btnH->addStretch();
    btnH->addWidget(refreshBtn);
    layout->addLayout(btnH);
    connect(delBtn, &QPushButton::clicked, this, &ScanPage::onDeleteTask);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanPage::onRefreshTasks);
    m_sourceDelBtn = delBtn;
    connect(m_sourceScanTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
      auto *item = m_sourceScanTable->itemAt(pos);
      if (!item) return;
      QMenu menu;
      menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
      menu.exec(m_sourceScanTable->viewport()->mapToGlobal(pos));
    });
    m_scanTypeTabs->addTab(tab, QStringLiteral("程序漏洞测试"));
  }

  left->setContentsMargins(14, 14, 14, 14);
  left->setSpacing(10);
  auto *typePicker = new QComboBox(this);
  typePicker->setObjectName("scanTypePicker");
  for (int i = 0; i < m_scanTypeTabs->count(); ++i) {
    typePicker->addItem(m_scanTypeTabs->tabText(i));
    auto *tabLayout = qobject_cast<QVBoxLayout*>(m_scanTypeTabs->widget(i)->layout());
    auto *form = new QWidget;
    auto *formLayout = new QVBoxLayout(form);
    formLayout->setContentsMargins(0, 0, 0, 0);
    auto *inputItem = tabLayout->takeAt(0);
    formLayout->addLayout(inputItem->layout());
    if (i == 3) {
      auto *extraItem = tabLayout->takeAt(0);
      formLayout->addLayout(extraItem->layout());
    }
    auto *formDialog = new QDialog(this);
    formDialog->setObjectName("scanCreateDialog");
    formDialog->setWindowTitle(QStringLiteral("新建") + m_scanTypeTabs->tabText(i));
    formDialog->setWindowModality(Qt::WindowModal);
    formDialog->setMinimumWidth(460);
    auto *dialogLayout = new QVBoxLayout(formDialog);
    dialogLayout->setContentsMargins(20, 20, 20, 20);
    dialogLayout->addWidget(form);
    auto *cancel = new QDialogButtonBox(QDialogButtonBox::Cancel, formDialog);
    UiUtil::styleDialogButtons(cancel);
    cancel->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    connect(cancel, &QDialogButtonBox::rejected, formDialog, &QDialog::reject);
    dialogLayout->addWidget(cancel);
    auto *newScan = new QPushButton(QStringLiteral("＋ 新建扫描"));
    newScan->setObjectName("scanCreateToggle");
    newScan->setProperty("primary", true);
    connect(newScan, &QPushButton::clicked, formDialog, [formDialog]() {
      formDialog->show();
      formDialog->raise();
      formDialog->activateWindow();
    });
    tabLayout->insertWidget(0, newScan);
    tabLayout->setContentsMargins(0, 8, 0, 0);
  }
  m_scanTypeTabs->tabBar()->hide();
  m_scanTypeTabs->setStyleSheet("QTabWidget::pane { border:0; background:transparent; }");
  connect(typePicker, QOverload<int>::of(&QComboBox::currentIndexChanged), m_scanTypeTabs, &QTabWidget::setCurrentIndex);
  connect(m_scanTypeTabs, &QTabWidget::currentChanged, typePicker, &QComboBox::setCurrentIndex);
  auto *taskTitle = new QLabel(QStringLiteral("扫描任务"));
  taskTitle->setObjectName("scanPanelTitle");
  auto *taskHint = new QLabel(QStringLiteral("按类型查看任务与扫描结果"));
  taskHint->setObjectName("scanPanelHint");
  left->addWidget(taskTitle);
  left->addWidget(taskHint);
  left->addWidget(typePicker);
  left->addWidget(m_scanTypeTabs, 1);

  auto *leftW = new QFrame;
  leftW->setObjectName("scanTasksPanel");
  leftW->setLayout(left);
  auto *taskManager = new QDialog(this);
  taskManager->setObjectName("scanAuxTasks");
  taskManager->setWindowTitle(QStringLiteral("管理扫描任务"));
  taskManager->resize(680, 500);
  auto *taskLayout = new QVBoxLayout(taskManager);
  taskLayout->addWidget(leftW);
  auto *viewResults = new QPushButton(QStringLiteral("查看结果"));
  taskLayout->addWidget(viewResults, 0, Qt::AlignRight);
  connect(viewResults, &QPushButton::clicked, this, [this, taskManager]() {
    if (!m_pipelineId.isEmpty()) {
      const int index = m_resultSource->findData(m_selectedTaskId);
      if (index >= 0 && index != m_resultSource->currentIndex()) m_resultSource->setCurrentIndex(index);
      else loadPipelineResults();
    }
    m_detailTabs->setCurrentIndex(0);
    taskManager->hide();
  });
  auto *overviewDialog = new QDialog(this);
  overviewDialog->setObjectName("scanAuxOverview");
  overviewDialog->setWindowTitle(QStringLiteral("扫描进展与检查详情"));
  overviewDialog->resize(820, 560);
  auto *overviewLayout = new QVBoxLayout(overviewDialog);
  auto *overviewClose = new QDialogButtonBox(QDialogButtonBox::Close);
  overviewClose->button(QDialogButtonBox::Close)->setText(QStringLiteral("关闭"));
  connect(overviewClose, &QDialogButtonBox::rejected, overviewDialog, &QDialog::hide);

  // ══ Right Panel ═════════════════════════════════════════════════════
  auto *detailLayout = new QVBoxLayout;
  detailLayout->setContentsMargins(14, 14, 14, 14);
  detailLayout->setSpacing(10);
  auto *detailTabs = new WorkbenchTabs;
  m_detailTabs = detailTabs;
  detailTabs->setObjectName("scanDetailTabs");
  auto *resultsPage = new QWidget;
  auto *right = new QVBoxLayout(resultsPage);
  right->setContentsMargins(0, 12, 0, 0);
  right->setSpacing(10);
  auto *plansPage = new QWidget;
  auto *plansLayout = new QVBoxLayout(plansPage);
  plansLayout->setContentsMargins(0, 12, 0, 0);
  plansLayout->setSpacing(10);

  // ── Status label ──────────────────────────────────────────────────
  m_statusLabel = new QLabel("选择任务查看详情");
  m_statusLabel->setObjectName("scanStatus");
  m_statusLabel->setTextFormat(Qt::PlainText);
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_statusLabel->setWordWrap(true);
  m_statusLabel->setStyleSheet("color:#475569; background:transparent; border:none;");
  overviewLayout->addWidget(m_statusLabel);
  auto *heading = new QHBoxLayout;
  auto *pageTitle = new QLabel(QStringLiteral("扫描发现"));
  pageTitle->setObjectName("scanPanelTitle");
  heading->addWidget(pageTitle);
  heading->addStretch();
  m_compactStatus = new QLabel(QStringLiteral("请选择扫描任务"));
  m_compactStatus->setObjectName("scanCompactStatus");
  m_compactStatus->setTextFormat(Qt::PlainText);
  heading->addWidget(m_compactStatus);
  auto *checks = new QPushButton(QStringLiteral("查看检查详情"));
  checks->setObjectName("scanCheckDetails");
  heading->addWidget(checks);
  auto *manage = new QPushButton(QStringLiteral("管理扫描任务"));
  manage->setObjectName("manageScanTasks");
  heading->addWidget(manage);
  connect(checks, &QPushButton::clicked, overviewDialog, [overviewDialog]() { overviewDialog->show(); overviewDialog->raise(); });
  connect(manage, &QPushButton::clicked, taskManager, [taskManager]() { taskManager->show(); taskManager->raise(); });
  detailLayout->addLayout(heading);

  // ── Re-execute button (hidden by default) ─────────────────────────
  auto *reexecH = new QHBoxLayout;
  m_reexecBtn = new QPushButton("重新执行");
  m_reexecBtn->setVisible(false);
  reexecH->addWidget(m_reexecBtn);
  reexecH->addStretch();
  taskLayout->insertLayout(1, reexecH);
  connect(m_reexecBtn, &QPushButton::clicked, this, &ScanPage::onReexecScan);

  // ── Results (QTreeWidget grouped by result_type) ──────────────────
  auto *resLabel = new QLabel(QStringLiteral("结果概览"));
  resLabel->setStyleSheet(Theme::SectionStyle);
  overviewLayout->addWidget(resLabel);
  m_aggregateControls = new QWidget(resultsPage);
  auto *aggregateLayout = new QHBoxLayout(m_aggregateControls);
  aggregateLayout->setContentsMargins(0, 0, 0, 0);
  m_allResultsButton = new QPushButton(QStringLiteral("刷新"));
  m_allResultsButton->setObjectName("allScanResults");
  m_moreResultsButton = new QPushButton(QStringLiteral("加载更多"));
  m_moreResultsButton->setObjectName("moreScanResults");
  m_resultCategory = new QComboBox;
  m_resultSource = new QComboBox;
  const QStringList categoryNames{"全部记录", "漏洞候选", "资产 / 端口 / 指纹", "信息级发现", "凭据记录", "工具错误 / 警告", "输出证据", "其他记录"};
  const QStringList categoryKeys{"all", "vulnerability", "asset", "information", "credential", "error", "evidence", "other"};
  for (int i = 0; i < categoryNames.size(); ++i) m_resultCategory->addItem(categoryNames[i], categoryKeys[i]);
  m_resultCategory->setCurrentIndex(m_resultCategory->findData("vulnerability"));
  m_resultSource->addItem(QStringLiteral("全部扫描任务"), QString());
  for (auto *combo : {m_resultSource, m_resultCategory}) {
    combo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    combo->setMinimumContentsLength(12);
  }
  aggregateLayout->addWidget(m_resultSource, 3);
  aggregateLayout->addWidget(m_resultCategory, 2);
  aggregateLayout->addStretch(1);
  aggregateLayout->addWidget(m_allResultsButton);
  connect(m_allResultsButton, &QPushButton::clicked, this, [this]() { loadPipelineResults(); });
  connect(m_moreResultsButton, &QPushButton::clicked, this, [this]() { loadPipelineResults(true); });
  connect(m_resultCategory, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() { if (!m_pipelineId.isEmpty()) loadPipelineResults(); });
  connect(m_resultSource, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() { if (!m_pipelineId.isEmpty()) loadPipelineResults(); });
  right->addWidget(m_aggregateControls); m_aggregateControls->hide();
  m_resultOverview = new ScanResultOverview(resultsPage);
  overviewLayout->addWidget(m_resultOverview);
  m_resultHint = new QLabel(QStringLiteral("点击名称查看完整证据；勾选漏洞后可准备验证"));
  m_resultHint->setObjectName("scanPanelHint");
  m_resultHint->setWordWrap(true);

  m_coverageTree = new QTreeWidget(resultsPage);
  m_coverageTree->setObjectName(QStringLiteral("scanCoverageTree"));
  m_coverageTree->setHeaderLabels({QStringLiteral("资产 / 服务 / 入口 / 检查"), QStringLiteral("状态"), QStringLiteral("来源记录")});
  m_coverageTree->setMinimumHeight(150);
  m_coverageTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_coverageTree->hide();
  overviewLayout->addWidget(m_coverageTree, 1);
  overviewLayout->addWidget(overviewClose);
  m_sourceDemoBtn = new QPushButton("选择漏洞生成预案…");
  m_sourceDemoBtn->setObjectName("sourceDemonstrationButton");
  m_sourceDemoBtn->hide();
  m_sourceDemoBtn->setEnabled(false);
  right->addWidget(m_sourceDemoBtn);
  connect(m_sourceDemoBtn, &QPushButton::clicked, this, &ScanPage::selectSourceDemonstration);
  m_webScanProcess = new QPlainTextEdit(resultsPage);
  m_webScanProcess->setObjectName("webScanProcess"); m_webScanProcess->setReadOnly(true);
  m_webScanProcess->setMaximumHeight(150); m_webScanProcess->hide(); right->addWidget(m_webScanProcess);
  m_resultTree = new QTreeWidget;
  m_resultTree->setMinimumHeight(120);
  m_resultTree->setObjectName("scanResultTree");
  m_resultTree->setItemDelegate(new ScanFindingDelegate(m_resultTree));
  m_resultTree->setWordWrap(true);
  m_resultTree->viewport()->installEventFilter(this);
  m_resultTree->installEventFilter(this);
  connect(m_resultTree, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem *item, int column) {
    if (column == 1) openRecordDetails(item);
  });
  UiUtil::EmptyHint::attach(m_resultTree, QStringLiteral("扫描完成后在此展示结果"));
  m_resultTree->setHeaderLabels({"选择 / 编号", "漏洞名称 / 记录内容", "来源工具", "载荷情况",
    "严重性", "目标与位置", "测试状态", "验证结论"});
  // Keep identity and independent status/result visible first; location and source remain horizontally reachable.
  const QList<int> visualOrder{0, 4, 1, 5, 6, 7, 3, 2};
  for (int visual = 0; visual < visualOrder.size(); ++visual)
    m_resultTree->header()->moveSection(m_resultTree->header()->visualIndex(visualOrder[visual]), visual);
  m_resultTree->headerItem()->setToolTip(0, "稳定发现 ID；扫描结果表自增编号，用于跨筛选、分页和验证追溯。");
  m_resultTree->headerItem()->setToolTip(7, "来自系统验证目标与证据；不将工具成功或人工意见替代为自动结论。");
  m_resultTree->setAlternatingRowColors(true);
  m_resultTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
  m_resultTree->setStyleSheet(findingIndicatorStyle("QTreeWidget#scanResultTree")
    + "QTreeWidget#scanResultTree { color:#172033; }"
      "QTreeWidget#scanResultTree::item:selected { color:#1e3a8a; }");
  auto *selectionBar = new QHBoxLayout;
  m_listTitle = new QLabel(QStringLiteral("漏洞候选"));
  m_listTitle->setObjectName("scanListTitle");
  m_listTitle->setStyleSheet(Theme::SectionStyle);
  selectionBar->addWidget(m_listTitle);
  selectionBar->addStretch();
  m_selectAllFindings = new FindingSelectAllCheckBox("全选当前列表");
  m_selectAllFindings->setObjectName("selectAllCurrentFindings");
  m_selectAllFindings->setTristate(true);
  m_selectAllFindings->setStyleSheet(findingIndicatorStyle("QCheckBox#selectAllCurrentFindings")
    + "QCheckBox#selectAllCurrentFindings { color:#172033; }"
      "QCheckBox#selectAllCurrentFindings:disabled { color:#64748b; }");
  m_selectAllFindings->setToolTip("仅选择当前筛选下已加载的漏洞，包含折叠分组；加载更多后可再次全选。");
  m_findingSelectionCount = new QLabel;
  m_findingSelectionCount->setObjectName("findingSelectionCount");
  m_findingSelectionCount->setStyleSheet("QLabel#findingSelectionCount { color:#172033; }");
  m_openCheckedFindings = new QPushButton("打开勾选的漏洞");
  m_openCheckedFindings->setObjectName("openCheckedFindings");
  m_openCheckedFindings->setToolTip("只打开当前列表勾选的漏洞；打开窗口不会启动验证。");
  selectionBar->addWidget(m_selectAllFindings);
  selectionBar->addWidget(m_findingSelectionCount);
  selectionBar->addStretch();
  selectionBar->addWidget(m_openCheckedFindings);
  right->addLayout(selectionBar);
  connect(m_selectAllFindings, &QCheckBox::clicked, this, [this]() {
    setCurrentFindingsChecked(m_selectAllFindings->checkState() == Qt::Checked);
  });
  connect(m_openCheckedFindings, &QPushButton::clicked, this, [this]() {
    if (m_pipelineId.isEmpty() || m_scanPageBusy) return;
    QList<qint64> ids;
    for (auto *item : selectableFindingItems())
      if (item->checkState(0) == Qt::Checked)
        ids.append(item->data(0, Qt::UserRole+1).toLongLong());
    openFindingVerification(ids);
  });
  connect(m_resultTree, &QTreeWidget::itemChanged, this, [this](QTreeWidgetItem *item, int column) {
    if (column != 0 || !selectableFindingItems().contains(item)) return;
    const auto id = item->data(0, Qt::UserRole+1).toLongLong();
    if (item->checkState(0) == Qt::Checked) m_checkedFindings.insert(id);
    else m_checkedFindings.remove(id);
    updateFindingSelection();
  });
  updateFindingSelection();
  m_resultTree->setContextMenuPolicy(Qt::CustomContextMenu);
  m_resultTree->header()->setStretchLastSection(false);
  m_resultTree->header()->setSectionResizeMode(QHeaderView::Interactive);
  m_resultTree->setColumnWidth(1, 240);
  m_resultTree->setColumnWidth(0, 70);
  m_resultTree->setColumnWidth(2, 85);
  m_resultTree->setColumnWidth(3, 180);
  m_resultTree->setIndentation(12);
  for (int column : {2, 3, 7}) m_resultTree->setColumnHidden(column, true);
  right->addWidget(m_resultTree, 1);
  auto *footer = new QHBoxLayout;
  footer->addWidget(m_resultHint, 1);
  m_showAllRecords = new QPushButton(QStringLiteral("查看全部记录"));
  m_showAllRecords->setObjectName("showAllScanRecords");
  connect(m_showAllRecords, &QPushButton::clicked, this, [this]() {
    m_resultCategory->setCurrentIndex(m_resultCategory->findData("all"));
  });
  footer->addWidget(m_showAllRecords);
  footer->addWidget(m_moreResultsButton);
  right->addLayout(footer);
  m_moreResultsButton->hide();
  m_showAllRecords->hide();
  connect(m_resultTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_resultTree->itemAt(pos);
    if (!item) return;
    QMenu menu;
    // Copy the most useful column (data column = 1 for child items, 0 for group items)
    QString text = item->text(1).isEmpty() ? item->text(0) : item->text(1);
    menu.addAction("复制内容", [text]() { QApplication::clipboard()->setText(text); });
    if (m_allScanResults && item->parent() && item->data(0, Qt::UserRole+2).toString() == "vulnerability")
      menu.addAction("查看 / 关联匹配载荷", [this, item]() { showPayloadMatches(item); });
    if (!m_pipelineId.isEmpty() && item->data(0,Qt::UserRole+1).toLongLong()>0
        && item->data(0,Qt::UserRole+2).toString()=="vulnerability")
      menu.addAction("准备此漏洞验证 / 查看历史", [this,item]() {
        openFindingVerification({item->data(0,Qt::UserRole+1).toLongLong()});
      });
    // 演示动线：漏洞结果一键发起攻击
    const QString resultType = item->data(0, Qt::UserRole).toString();
    const QStringList payloadFindings = {"vulnerability", "web_vuln", "sql_injection", "misconfiguration",
      "auth_finding", "source_vuln", "source_finding", "program_finding"};
    const int findingId = item->data(0, Qt::UserRole+1).toInt();
    if (findingId > 0 && item->data(0,Qt::UserRole+2).toString()!="information" && (payloadFindings.contains(resultType)
      || (m_allScanResults && item->data(0, Qt::UserRole+2).toString() == "vulnerability"))) {
      menu.addAction("查找或生成此漏洞载荷", [this, findingId]() { showPayloadForFinding(findingId); });
    }
    if (!m_allScanResults && (isProgramFinding(resultType) || resultType == "application_observation" || resultType == "source_coverage" || resultType == "program_coverage")) {
      menu.addAction("查看源码 / 请求证据", [this,item]() { showSourceEvidence(item); });
      if (isProgramFinding(resultType) && m_sourceDemoBtn->isEnabled()) {
        menu.addAction("生成此项攻击演示预案", [this,item]() {
          generatePlaybook(QJsonArray{item->data(0,Qt::UserRole+1).toInt()});
        });
      }
    }
    const QStringList attackable = {"vulnerability", "web_vuln", "sql_injection", "credential"};
    if (m_pipelineId.isEmpty() && !m_allScanResults && !m_currentTaskTarget.isEmpty() && attackable.contains(resultType)) {
      menu.addSeparator();
      menu.addAction("⚔ 对此漏洞发起攻击", [this, item, resultType]() {
        const QString raw = item->toolTip(1);  // 优先原始 JSON（关键词更全），展示文本兜底
        emit attackRequested(m_currentTaskTarget, raw.isEmpty() ? item->text(1) : raw, resultType);
      });
    }
    menu.exec(m_resultTree->viewport()->mapToGlobal(pos));
  });
  // ── Recommendations ───────────────────────────────────────────────
  auto *recLabel = new QLabel("推荐预案"); recLabel->setStyleSheet(Theme::SectionStyle);
  plansLayout->addWidget(recLabel);
  m_recTable = new QTableWidget(0, 6);
  m_recTable->setMinimumHeight(140);
  m_recTable->setObjectName("scanRecommendations");
  UiUtil::EmptyHint::attach(m_recTable, QStringLiteral("暂无推荐预案 · 先完成扫描"));
  m_recTable->setHorizontalHeaderLabels({"名称", "难度", "基线组", "匹配原因", "匹配分", "推荐类型/条件"});
  m_recTable->verticalHeader()->hide();
  m_recTable->horizontalHeader()->setMinimumSectionSize(50);
  m_recTable->setAlternatingRowColors(true);
  m_recTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_recTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_recTable->setSortingEnabled(true);
  m_recTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_recTable->horizontalHeader()->setStretchLastSection(false);
  m_recTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_recTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
  m_recTable->setColumnWidth(1, 60);
  m_recTable->setColumnWidth(2, 90);
  m_recTable->setColumnWidth(4, 70);
  m_recTable->setColumnWidth(5, 180);
  plansLayout->addWidget(m_recTable, 1);
  connect(m_recTable, &QTableWidget::cellClicked, this, &ScanPage::onRecommendationClicked);

  // ── 推荐预案"前往执行→"按钮 ─────────────────────────────────────
  auto *recExecH = new QHBoxLayout;
  m_recExecBtn = new QPushButton("前往执行 →");
  m_recExecBtn->setVisible(false);
  m_recExecBtn->setProperty("primary", true);
  recExecH->addWidget(m_recExecBtn);
  recExecH->addStretch();
  plansLayout->addLayout(recExecH);
  connect(m_recExecBtn, &QPushButton::clicked, this, &ScanPage::onRecExecClicked);

  // ── AI Generate Playbook ──────────────────────────────────────────
  auto *bottomH = new QHBoxLayout;
  m_genBtn = new QPushButton("智能生成预案");
  m_genBtn->setEnabled(false);
  m_genBtn->setProperty("primary", true);
  bottomH->addWidget(m_genBtn);
  bottomH->addStretch();
  plansLayout->addLayout(bottomH);
  connect(m_genBtn, &QPushButton::clicked, this, &ScanPage::onGeneratePlaybook);

  // ── AI 生成预案预览区（初始隐藏）──────────────────────────────────
  m_genPreviewWidget = new QWidget;
  auto *genPreviewLayout = new QVBoxLayout(m_genPreviewWidget);
  genPreviewLayout->setContentsMargins(0, 0, 0, 0);

  m_genPreviewTitle = new QLabel;
  m_genPreviewTitle->setStyleSheet(Theme::SectionStyle);
  genPreviewLayout->addWidget(m_genPreviewTitle);

  m_genStepTable = new QTableWidget(0, 4);
  m_genStepTable->setMinimumHeight(140);
  m_genStepTable->setObjectName("scanGeneratedSteps");
  UiUtil::EmptyHint::attach(m_genStepTable, QStringLiteral("生成预案后展示步骤"));
  m_genStepTable->setHorizontalHeaderLabels({"步骤", "工具", "目标参数", "描述"});
  m_genStepTable->setAlternatingRowColors(true);
  m_genStepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_genStepTable->setSortingEnabled(false);
  m_genStepTable->horizontalHeader()->setStretchLastSection(true);
  m_genStepTable->setContextMenuPolicy(Qt::CustomContextMenu);
  genPreviewLayout->addWidget(m_genStepTable);

  auto *genExecH = new QHBoxLayout;
  m_genExecBtn = new QPushButton("前往执行 →");
  m_genExecBtn->setProperty("primary", true);
  genExecH->addWidget(m_genExecBtn);
  genExecH->addStretch();
  genPreviewLayout->addLayout(genExecH);
  connect(m_genExecBtn, &QPushButton::clicked, this, &ScanPage::onGenExecClicked);

  m_genPreviewWidget->setVisible(false);
  plansLayout->addWidget(m_genPreviewWidget);

  // 步骤表格右键菜单
  connect(m_genStepTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_genStepTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_genStepTable->viewport()->mapToGlobal(pos));
  });

  auto *rightW = new QFrame;
  rightW->setObjectName("scanDetailsPanel");
  auto scrollableDetail = [](QWidget *content) {
    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("QScrollArea { background:#ffffff; border:none; }");
    content->setObjectName("scanScrollableContent");
    content->setStyleSheet("QWidget#scanScrollableContent { background:#ffffff; }");
    scroll->setWidget(content);
    return scroll;
  };
  detailTabs->addTab(resultsPage, QStringLiteral("漏洞与记录"));
  detailTabs->addTab(scrollableDetail(plansPage), QStringLiteral("推荐与生成方案"));
  detailLayout->addWidget(detailTabs, 1);
  rightW->setLayout(detailLayout);
  rightW->setMinimumWidth(350);

  mainLayout->addWidget(rightW, 1);

  for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable}) {
    table->verticalHeader()->hide();
    table->verticalHeader()->setDefaultSectionSize(36);
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table->setColumnWidth(1, 76);
    table->setColumnWidth(2, 100);
    table->setTextElideMode(Qt::ElideMiddle);
  }

  // ── Poll timer for running scans ──────────────────────────────────
  m_pollTimer = new QTimer(this);
  m_pollTimer->setInterval(2000);
  connect(m_pollTimer, &QTimer::timeout, this, &ScanPage::onPollStatus);

  // ── Tab switch: update delete button state ────────────────────────
  connect(m_scanTypeTabs, &QTabWidget::currentChanged, this, [this]() {
    const bool pendingVerification = m_pendingSourceVerification;
    m_selectedTaskId.clear();
    clearDetailPanel();
    m_pendingSourceVerification = pendingVerification;
    const QList<QTableWidget*> tables{m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable};
    auto *table = tables.value(m_scanTypeTabs->currentIndex());
    if (table && table->rowCount() > 0) {
      const int row = qMax(0, table->currentRow());
      table->selectRow(row);
      emit table->cellClicked(row, 0);
    } else {
      setStatusText(QStringLiteral("当前扫描类型暂无任务"));
    }
  });

  // ── Result tree: 攻击动线入口（右键 / 双击漏洞行）──────────────────
  // ── Right-click menu for rec table ────────────────────────────────
  connect(m_recTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_recTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
    menu.exec(m_recTable->viewport()->mapToGlobal(pos));
  });
}

// ── Update status label from task detail object ───────────────────────
void ScanPage::updateStatusLabel(const QJsonObject &d) {
  QString status = d["status"].toString();
  QString target = d["target"].toString();
  QString scanType = formatScanType(d["scan_type"].toString());
  m_currentTaskTarget = target;              // 供"对此漏洞发起攻击"取目标
  m_currentScanType = d["scan_type"].toString();
  auto arr = d["results"].toArray();
  bool structured = hasStructuredResults(arr);
  const bool sourceTask = isProgramScan(m_currentScanType);
  m_canReparseReport = d["can_reparse_report"].toBool();
  m_reexecBtn->setText(sourceTask ? "重新解析报告" : "重新执行");
  m_reexecBtn->setEnabled(!sourceTask || m_canReparseReport);
  m_reexecBtn->setToolTip(sourceTask ? "使用已保存的完整报告重试解析和导入；扫描未完成时请新建任务" : "");
  const bool finished = status == "COMPLETED" || status == "PARTIAL";
  bool sourceFindings = false;
  for (const auto &result : arr) {
    if (isProgramFinding(result.toObject()["result_type"].toString())) sourceFindings = true;
  }
  m_sourceDemoBtn->setVisible(sourceTask);
  m_sourceDemoBtn->setEnabled(sourceTask && finished && sourceFindings);
  m_resultHint->setText(sourceTask
      ? QStringLiteral("扫描 → 生成预案 → 攻击测试 → 查看实际攻击效果。源码和运行发现均保留证据，疑点及工具成功不等于攻击成功。")
      : QStringLiteral("点击名称查看完整证据；勾选漏洞后可准备验证"));
  m_genBtn->setText(sourceTask && sourceFindings ? "生成攻击测试预案" : sourceTask ? "生成远程诊断预案" : "智能生成预案");

  QStringList parts;
  parts << QString("目标: %1").arg(target);
  parts << scanType;
  if (status == "RUNNING")
    parts << "⏳ " + formatStatus(status, structured);
  else
    parts << "状态: " + formatStatus(status, structured);
  if (sourceTask && status == "RUNNING") {
    for (const auto &result : arr) {
      const auto row = result.toObject();
      if (row["result_type"].toString() != "source_coverage") continue;
      const auto coverage = QJsonDocument::fromJson(row["result_data"].toString().toUtf8()).object();
      const auto phase = coverage["cscan"].toObject()["state"].toString();
      if (phase == "parsing") parts << "正在解析报告";
      else if (phase == "importing") parts << "正在导入漏洞";
      else if (phase == "report_ready") parts << "报告已收齐，准备解析";
    }
  }
  QString dur = formatDuration(d["started_at"].toString(), d["completed_at"].toString());
  if (!dur.isEmpty()) parts << dur;

  int structuredCount = 0;
  for (const auto &r : arr) {
    if (r.toObject()["result_type"].toString() != "raw_output" && r.toObject()["result_type"].toString() != "scan_error") structuredCount++;
  }
  if (structuredCount > 0)
    parts << QString("有效结果: %1").arg(structuredCount);
  else if (arr.size() > 0)
    parts << "仅原始输出";

  QString summary = buildResultSummary(arr, d["scan_type"].toString());
  if (!summary.isEmpty()) parts << summary;

  setStatusText(parts.join(" | "));
  m_compactStatus->setText(formatStatus(status, structured));
  if (sourceTask && status == "RUNNING") {
    if (parts.contains(QStringLiteral("正在解析报告"))) m_compactStatus->setText(QStringLiteral("正在解析报告"));
    else if (parts.contains(QStringLiteral("正在导入漏洞"))) m_compactStatus->setText(QStringLiteral("正在导入漏洞"));
    else if (parts.contains(QStringLiteral("报告已收齐，准备解析"))) m_compactStatus->setText(QStringLiteral("报告已收齐，准备解析"));
  }
  if (status == "FAILED")
    m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
  else if (status == "PARTIAL" || (status == "COMPLETED" && !structured))
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
  else
    m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
}

// ── Render grouped results in QTreeWidget ─────────────────────────────
void ScanPage::renderGroupedResults(const QJsonArray &results) {
  const QSignalBlocker blocker(m_resultTree);
  if (!m_allScanResults && m_webScanProcess) { m_webScanProcess->clear(); m_webScanProcess->hide(); }
  m_resultOverview->setResults(results);
  m_resultTree->setRootIndex(QModelIndex());
  m_resultTree->clear();
  m_resultTree->setColumnHidden(3, false);
  m_coverageTree->clear();
  m_coverageTree->hide();

  // Group by result_type
  QMap<QString, QJsonArray> groups;
  // Define display order
  QStringList order = {"finding_candidates", "information", "program_coverage", "program_agent_step", "program_agent_summary", "program_finding", "source_coverage", "application_observation", "source_finding", "open_port", "vulnerability", "web_vuln", "source_vuln", "sql_injection",
                       "credential", "service_info", "http_probe", "technology_detection", "scan_error", "raw_output"};

  for (const auto &r : results) {
    const auto row = r.toObject();
    QString type = isVerificationRecord(row) ? "finding_candidates"
      : (row["category"].toString()=="information"
          || (QStringList{"info", "inf"}.contains(row["severity"].toString().trimmed().toLower())
              && QStringList{"vulnerability", "web_vuln", "source_vuln", "source_finding", "program_finding", "auth_finding", "misconfiguration", "sql_injection"}.contains(row["result_type"].toString())))
        ? "information" : row["result_type"].toString();
    groups[type].append(r);
  }

  // Render groups in defined order, then any remaining types
  QStringList renderedTypes;
  for (const auto &type : order) {
    if (!groups.contains(type) || groups[type].isEmpty()) continue;
    renderedTypes << type;

    auto &arr = groups[type];
    QString groupName = formatResultType(type) + QString(" (%1)").arg(arr.size());

    auto *groupItem = new QTreeWidgetItem(m_resultTree, {groupName, "", "", ""});
    QFont groupFont = groupItem->font(0);
    groupFont.setBold(true);
    groupItem->setFont(0, groupFont);
    groupItem->setFirstColumnSpanned(true);
    // Group header separates result types without competing with severity colors
    for (int col = 0; col < m_resultTree->columnCount(); col++) {
      groupItem->setBackground(col, QColor("#eaf1fa"));
      groupItem->setForeground(col, QColor("#334155"));
    }

    for (const auto &r : arr) {
      auto obj = r.toObject();
      QString sev = obj["severity"].toString();
      QString resultType = obj["result_type"].toString();
      QString rawData = obj["result_data"].toString();
      QString tool = obj["source_tool"].toString();

      auto *child = new QTreeWidgetItem(groupItem);
      child->setText(4, formatSeverity(sev));
      child->setForeground(4, severityColor(sev));
      child->setData(0, Qt::UserRole+1, obj["id"].toVariant().toLongLong());
      child->setData(0, Qt::UserRole, resultType);  // 供右键"发起攻击"判断类型
      child->setText(1, formatResultData(rawData, resultType));
      child->setToolTip(1, rawData);
      child->setText(2, tool + (m_allScanResults ? " · " + obj["scan_task_id"].toString() + " #" + QString::number(obj["id"].toVariant().toLongLong()) : QString()));
      showFindingSummary(child, obj, m_allScanResults);
      decorateResultRow(child, obj);
      if(!m_pipelineId.isEmpty() && isVerificationRecord(obj) && obj["id"].toVariant().toLongLong() > 0) {
        child->setFlags(child->flags()|Qt::ItemIsUserCheckable);
        child->setCheckState(0,m_checkedFindings.contains(obj["id"].toVariant().toLongLong())?Qt::Checked:Qt::Unchecked);
      }

      // Dim raw_output items
      if (resultType == "raw_output") {
        child->setForeground(0, QColor("#94a3b8"));
        child->setForeground(1, QColor("#94a3b8"));
      }
    }

    // raw_output group default collapsed, others expanded
    if (type == "raw_output") {
      groupItem->setExpanded(false);
    } else {
      groupItem->setExpanded(true);
    }
  }

  // Render any types not in the predefined order
  for (auto it = groups.begin(); it != groups.end(); ++it) {
    if (renderedTypes.contains(it.key())) continue;
    auto &arr = it.value();
    QString groupName = formatResultType(it.key()) + QString(" (%1)").arg(arr.size());

    auto *groupItem = new QTreeWidgetItem(m_resultTree, {groupName, "", "", ""});
    QFont groupFont = groupItem->font(0);
    groupFont.setBold(true);
    groupItem->setFont(0, groupFont);
    groupItem->setFirstColumnSpanned(true);
    for (int col = 0; col < m_resultTree->columnCount(); col++) {
      groupItem->setBackground(col, QColor("#eaf1fa"));
      groupItem->setForeground(col, QColor("#334155"));
    }

    for (const auto &r : arr) {
      auto obj = r.toObject();
      QString sev = obj["severity"].toString();
      QString resultType = obj["result_type"].toString();
      QString rawData = obj["result_data"].toString();
      QString tool = obj["source_tool"].toString();

      auto *child = new QTreeWidgetItem(groupItem);
      child->setText(4, formatSeverity(sev));
      child->setForeground(4, severityColor(sev));
      child->setData(0, Qt::UserRole+1, obj["id"].toVariant().toLongLong());
      child->setData(0, Qt::UserRole, resultType);  // 供右键"发起攻击"判断类型
      child->setText(1, formatResultData(rawData, resultType));
      child->setToolTip(1, rawData);
      child->setText(2, tool + (m_allScanResults ? " · " + obj["scan_task_id"].toString() + " #" + QString::number(obj["id"].toVariant().toLongLong()) : QString()));
      showFindingSummary(child, obj, m_allScanResults);
      decorateResultRow(child, obj);
      if(!m_pipelineId.isEmpty() && isVerificationRecord(obj) && obj["id"].toVariant().toLongLong() > 0) {
        child->setFlags(child->flags()|Qt::ItemIsUserCheckable);
        child->setCheckState(0,m_checkedFindings.contains(obj["id"].toVariant().toLongLong())?Qt::Checked:Qt::Unchecked);
      }
    }
    groupItem->setExpanded(true);
  }

  const bool candidatesOnly = m_allScanResults && m_resultCategory->currentData() == "vulnerability";
  if (candidatesOnly && m_resultTree->topLevelItemCount() == 1)
    m_resultTree->setRootIndex(m_resultTree->model()->index(0, 0));
  m_resultTree->setRootIsDecorated(!candidatesOnly);
  m_resultTree->setHeaderLabels({"选择", "漏洞名称 / 记录内容", "来源工具", "载荷情况", "严重性", "目标 / 位置", "验证状态", "验证结论"});
  for (int column : {2, 3, 7}) m_resultTree->setColumnHidden(column, true);
  for (QTreeWidgetItemIterator it(m_resultTree); *it; ++it) {
    if (!(*it)->parent()) continue;
    (*it)->setToolTip(0, QStringLiteral("发现编号：") + (*it)->text(0));
    (*it)->setToolTip(5, (*it)->text(5));
    (*it)->setToolTip(6, (*it)->text(6) + " / " + (*it)->text(7));
  }
  m_listTitle->setText(candidatesOnly ? QStringLiteral("漏洞候选") : QStringLiteral("扫描记录"));
  m_showAllRecords->setVisible(candidatesOnly);
  UiUtil::EmptyHint::setState(m_resultTree, candidatesOnly ? QStringLiteral("当前范围暂无漏洞候选，可查看全部记录；未完成检查不代表安全。") : QStringLiteral("当前范围暂无记录"));
  resizeResultColumns();
  updateFindingSelection();
}

QList<QTreeWidgetItem*> ScanPage::selectableFindingItems() const {
  QList<QTreeWidgetItem*> items;
  if (m_pipelineId.isEmpty()) return items;
  for (QTreeWidgetItemIterator it(m_resultTree); *it; ++it) {
    auto *item = *it;
    if (item->parent() && item->data(0, Qt::UserRole+2).toString() == "vulnerability"
        && item->data(0, Qt::UserRole+1).toLongLong() > 0
        && item->flags().testFlag(Qt::ItemIsEnabled)
        && item->flags().testFlag(Qt::ItemIsUserCheckable)
        && item->data(0, Qt::CheckStateRole).isValid()) items.append(item);
  }
  return items;
}

void ScanPage::updateFindingSelection() {
  if (!m_selectAllFindings) return;
  const auto items = selectableFindingItems();
  int selected = 0;
  for (auto *item : items) if (item->checkState(0) == Qt::Checked) ++selected;
  const QSignalBlocker blocker(m_selectAllFindings);
  m_selectAllFindings->setCheckState(selected == 0 ? Qt::Unchecked
    : selected == items.size() ? Qt::Checked : Qt::PartiallyChecked);
  m_selectAllFindings->setEnabled(!m_scanPageBusy && !items.isEmpty());
  m_findingSelectionCount->setText(QString("已选 %1 / 可选 %2 条").arg(selected).arg(items.size()));
  m_openCheckedFindings->setEnabled(!m_scanPageBusy && selected > 0);
}

void ScanPage::setCurrentFindingsChecked(bool checked) {
  if (m_scanPageBusy) return;
  const QSignalBlocker blocker(m_resultTree);
  for (auto *item : selectableFindingItems()) {
    const auto id = item->data(0, Qt::UserRole+1).toLongLong();
    item->setCheckState(0, checked ? Qt::Checked : Qt::Unchecked);
    if (checked) m_checkedFindings.insert(id); else m_checkedFindings.remove(id);
  }
  updateFindingSelection();
}

void ScanPage::decorateResultRow(QTreeWidgetItem *item, const QJsonObject &record) {
  const auto id = record["id"].toVariant().toLongLong();
  item->setText(0, id > 0 ? QString::number(id) : QStringLiteral("未记录"));
  item->setToolTip(0, QStringLiteral("稳定发现 ID：%1").arg(id));
  const auto data = QJsonDocument::fromJson(record["result_data"].toString().toUtf8()).object();
  QStringList locations;
  for (const auto &key : {"target", "host", "url", "path", "file", "file_path", "parameter", "param"}) {
    const QString value = data[key].toString();
    if (!value.isEmpty() && !locations.contains(value)) locations << value;
  }
  for (const auto &key : {"port", "line", "start_line"}) {
    const auto value = data[key];
    if (value.isDouble() || value.isString()) locations << QString("%1: %2").arg(key, value.toVariant().toString());
  }
  item->setText(5, locations.isEmpty() ? QStringLiteral("未记录") : locations.join(" · "));
  item->setToolTip(5, item->text(5));
  const auto detection = data["detection_status"].toString();
  if (!detection.isEmpty()) {
    const QString label = detection == "tool_positive" ? QStringLiteral("工具检测阳性") : QStringLiteral("证据不足，需复核");
    item->setText(5, item->text(5) + " · " + label);
    item->setToolTip(5, item->text(5) + QStringLiteral("\n扫描检出状态独立于后续验证结论"));
  }
  if (isVerificationRecord(record)) {
    QString name;
    for (const auto &key : {"title", "name", "finding", "template"}) {
      name = data[key].toString();
      if (!name.isEmpty()) break;
    }
    if (!name.isEmpty()) item->setText(1, translateNiktoFinding(name));
    QStringList rules;
    for (const auto &key : {"cve", "cwe", "rule_id", "template_id"}) {
      const auto value = data[key];
      if (value.isString() && !value.toString().isEmpty()) rules << value.toString();
      if (value.isArray()) for (const auto &entry : value.toArray()) if (entry.isString()) rules << entry.toString();
    }
    if (!rules.isEmpty()) item->setText(1, item->text(1) + " [" + rules.join(" / ") + "]");
  }

}

void ScanPage::showPayloadMatches(QTreeWidgetItem *item) {
  if (!m_allScanResults || m_pipelineId.isEmpty() || !item) return;
  const qint64 findingId = item->data(0, Qt::UserRole+1).toLongLong();
  if (findingId <= 0) return;
  const QString pipeline = m_pipelineId;
  const QString base = "/api/pipelines/" + QString::fromLatin1(QUrl::toPercentEncoding(pipeline))
    + "/results/records/" + QString::number(findingId);
  auto *dialog = new QDialog(this);
  dialog->setAttribute(Qt::WA_DeleteOnClose);
  dialog->setWindowTitle(QStringLiteral("漏洞 #%1 · 匹配载荷").arg(findingId));
  dialog->resize(940, 540);
  auto *layout = new QVBoxLayout(dialog);
  auto *status = new QLabel(QStringLiteral("正在读取匹配载荷…"), dialog);
  status->setWordWrap(true);
  layout->addWidget(status);
  auto *table = new QTableWidget(0, 6, dialog);
  table->setHorizontalHeaderLabels({"载荷", "匹配依据", "适用条件 / 待核对", "类型 / 消费方式", "版本", "状态"});
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  layout->addWidget(table);
  auto *history = new QLabel(dialog);
  history->setWordWrap(true);
  layout->addWidget(history);
  auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
  auto *bind = buttons->addButton(QStringLiteral("关联所选载荷"), QDialogButtonBox::ActionRole);
  bind->setEnabled(false);
  connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
  connect(table, &QTableWidget::itemSelectionChanged, dialog, [table, bind]() {
    bind->setEnabled(table->currentRow() >= 0);
  });
  QPointer<ScanPage> self(this);
  QPointer<QDialog> guard(dialog);
  m_api->get(base + "/payload-matches", 10000, [self, guard, table, status, history](const QJsonObject &response) {
    if (!self || !guard) return;
    if (response["status"].toString() != "ok") {
      status->setText(QStringLiteral("读取匹配失败：") + response["error"].toObject()["message"].toString());
      return;
    }
    const auto data = response["data"].toObject();
    const auto matches = data["matches"].toArray();
    const auto links = data["links"].toArray();
    status->setText(matches.isEmpty() ? QStringLiteral("暂无可解释的匹配载荷；漏洞仍保留，可后续补充。")
      : QStringLiteral("匹配结果仅供选择，执行前须核对条件并由验证预案实际消费。历史关联 %1 条。").arg(links.size()));
    QStringList historyLines;
    for (const auto &value : links) {
      const auto link = value.toObject();
      historyLines << QStringLiteral("%1 @ %2 · %3%4").arg(link["payload_id"].toString(),
        link["version"].toString().left(20),
        link["availability"].toString() == "available" ? QStringLiteral("版本可用") : QStringLiteral("版本已变化或不可用"),
        link["active"].toBool() ? QStringLiteral(" · 当前关联") : QStringLiteral(" · 历史版本"));
    }
    history->setText(historyLines.isEmpty() ? QString() : QStringLiteral("已保存关联：\n") + historyLines.join("\n"));
    table->setRowCount(matches.size());
    for (int row = 0; row < matches.size(); ++row) {
      const auto match = matches[row].toObject();
      auto *name = new QTableWidgetItem(match["name"].toString());
      name->setData(Qt::UserRole, match["payload_id"].toString());
      name->setData(Qt::UserRole+1, match["version"].toString());
      name->setToolTip(match["version"].toString());
      table->setItem(row, 0, name);
      table->setItem(row, 1, new QTableWidgetItem(match["match_basis"].toString()));
      QStringList conditions;
      for (const auto &value : match["prerequisites"].toArray()) conditions << value.toString();
      for (const auto &value : match["missing_conditions"].toArray()) conditions << value.toString();
      const QStringList variables = match["variables"].toObject().keys();
      if (!variables.isEmpty()) conditions << QStringLiteral("步骤变量：") + variables.join(", ");
      table->setItem(row, 2, new QTableWidgetItem(conditions.join("；")));
      const QString type = match["payload_type"].toString();
      const QString consumption = match["consumption"].toString();
      table->setItem(row, 3, new QTableWidgetItem(
        (type == "web" ? QStringLiteral("Web") : type == "intranet" ? QStringLiteral("内网")
          : type == "tool" ? QStringLiteral("工具") : type)
        + " / " + (consumption == "tool_args" ? QStringLiteral("结构化工具参数")
          : consumption == "tool_command_reference" ? QStringLiteral("工具命令参考") : QStringLiteral("预案步骤引用"))));
      auto *versionItem = new QTableWidgetItem(match["version"].toString().left(20));
      versionItem->setToolTip(match["version"].toString());
      table->setItem(row, 4, versionItem);
      table->setItem(row, 5, new QTableWidgetItem(match["linked"].toBool() ? QStringLiteral("已关联")
        : match["match_status"].toString() == "specific_candidate" ? QStringLiteral("具体候选") : QStringLiteral("待核对")));
    }
  });
  connect(bind, &QPushButton::clicked, dialog, [self, guard, table, status, bind, base, pipeline, findingId]() {
    if (!self || !guard || pipeline != self->m_pipelineId) return;
    auto *selected = table->item(table->currentRow(), 0);
    if (!selected) return;
    bind->setEnabled(false);
    status->setText(QStringLiteral("正在保存关联…"));
    const QString payloadId = selected->data(Qt::UserRole).toString();
    const QString version = selected->data(Qt::UserRole+1).toString();
    const QString name = selected->text();
    const QString basis = table->item(table->currentRow(), 1)->text();
    self->m_api->post(base + "/payload-links", QJsonObject{{"payload_id", payloadId}, {"version", version}}, 10000,
      [self, guard, table, status, bind, pipeline, findingId, payloadId, version, name, basis](const QJsonObject &response) {
        if (!self || !guard || pipeline != self->m_pipelineId) return;
        if (response["status"].toString() != "ok") {
          status->setText(QStringLiteral("关联失败：") + response["error"].toObject()["message"].toString());
          bind->setEnabled(table->currentRow() >= 0);
          return;
        }
        for (int index = 0; index < self->m_aggregateRecords.size(); ++index) {
          auto record = self->m_aggregateRecords[index].toObject();
          if (record["id"].toVariant().toLongLong() != findingId) continue;
          record["payload_match"] = QJsonObject{{"status", "linked"}, {"payload_id", payloadId},
            {"version", version}, {"name", name}, {"match_basis", basis}};
          self->m_aggregateRecords[index] = record;
          break;
        }
        guard->accept();
        self->renderGroupedResults(self->m_aggregateRecords);
      });
  });
  dialog->show();
}

// ── Create scan (auto-execute) ───────────────────────────────────────
void ScanPage::onCreateScan() {
  // Determine scan type from current tab
  int tabIdx = m_scanTypeTabs->currentIndex();
  QString scanType;
  QString target;
  switch (tabIdx) {
    case 0: scanType = "port_scan";   target = m_portTargetInput->text().trimmed(); break;
    case 1: scanType = "vuln_scan";   target = m_vulnTargetInput->text().trimmed(); break;
    case 2: scanType = "web_scan";    target = m_webTargetInput->text().trimmed(); break;
    case 3: scanType = "brute_force"; target = m_bruteTargetInput->text().trimmed(); break;
    case 4: scanType = "program_scan"; target = m_sourceTargetInput->text().trimmed(); break;
    default: return;
  }

  if (target.isEmpty()) {
    setStatusText("请先填写扫描目标。");
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
    return;
  }

  // Save target to history
  {
    QSettings settings("RedTeam", "RedTeam-Platform");
    QStringList history = settings.value("history/targets").toStringList();
    history.removeAll(target);
    history.prepend(target);
    while (history.size() > 20) history.removeLast();
    settings.setValue("history/targets", history);
    // Update completers for all target inputs
    for (auto *input : {m_portTargetInput, m_vulnTargetInput, m_webTargetInput, m_bruteTargetInput, m_sourceTargetInput}) {
      if (auto *c = input->completer()) {
        auto *m = qobject_cast<QStringListModel*>(c->model());
        if (m) m->setStringList(history);
      }
    }
  }

  QJsonObject body;
  body["target"] = target;
  body["scan_type"] = scanType;

  QJsonObject parameters;
  // Tab-specific parameters
  if (scanType == "port_scan") {
    QString ports = m_portsInput->text().trimmed();
    if (!ports.isEmpty()) parameters["ports"] = ports;
  }
  if (scanType == "web_scan") {
    QString cookie = m_cookieInput->text().trimmed();
    if (!cookie.isEmpty()) parameters["cookie"] = cookie;
  }
  if (scanType == "brute_force") {
    parameters["service"] = m_serviceCombo->currentData().toString();
    QString formDef = m_formDefInput->text().trimmed();
    if (!formDef.isEmpty() && m_serviceCombo->currentData().toString() == "http-post-form") {
      parameters["form_definition"] = formDef;
    }
  }
  if (isProgramScan(scanType)) {
    if(m_programInputKind->currentData().toString()=="remote_directory") {
      if(!m_remoteSourcePicker->hasSelection()) {
        setStatusText("请先浏览并选择目标主机的源码文件夹。");return;
      }
      parameters=m_remoteSourcePicker->selection();
    }
    if(m_programInputKind->currentData().toString()=="agent") parameters["cscan_target"]=target;
    parameters["source_notes"]=m_sourceNotesInput->text().trimmed();
    parameters["input_kind"] = m_programInputKind->currentData().toString();
    if (!m_programRuntimeInput->text().trimmed().isEmpty()) parameters["runtime_target"] = m_programRuntimeInput->text().trimmed();
  }
  if (!parameters.isEmpty()) body["parameters"] = parameters;

  m_api->post("/api/scan-tasks", body, 10000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      setStatusText("创建扫描任务失败：" + res["error"].toObject()["message"].toString());
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }
    for (auto *dialog : findChildren<QDialog*>("scanCreateDialog")) dialog->accept();
    QString taskId = res["data"].toObject()["scan_task_id"].toString();
    m_selectedTaskId = taskId;
    setStatusText(QString("已创建: %1 — 正在自动执行...").arg(taskId.left(16)));
    m_statusLabel->setStyleSheet(Theme::StatusSuccessStyle);
    // Clear the target input for the current tab
    int tabIdx = m_scanTypeTabs->currentIndex();
    switch (tabIdx) {
      case 0: m_portTargetInput->clear(); m_portsInput->clear(); break;
      case 1: m_vulnTargetInput->clear(); break;
      case 2: m_webTargetInput->clear(); m_cookieInput->clear(); break;
      case 3: m_bruteTargetInput->clear(); break;
      case 4: /* Keep the runtime address for subsequent independent tests. */ break;
    }
    onRefreshTasks();

    QJsonObject empty;
    m_api->post("/api/scan-tasks/" + taskId + "/execute", empty, 5000, [this, taskId](const QJsonObject &execRes) {
      if (execRes["status"].toString() == "ok") {
        m_reexecBtn->setVisible(false);
        if (!m_runningTaskIds.contains(taskId)) m_runningTaskIds << taskId;
        startPollingIfNeeded();
        onRefreshTasks();
      } else {
        setStatusText("创建成功但执行失败，可点击「重新执行」");
        m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
        m_reexecBtn->setVisible(true);
        onRefreshTasks();
      }
    });
  });
}

// ── Start polling ─────────────────────────────────────────────────────
void ScanPage::startPollingIfNeeded() {
  bool needPoll = !m_runningTaskIds.isEmpty();
  if (needPoll && !m_pollTimer->isActive()) {
    m_pollTimer->start();
  } else if (!needPoll && m_pollTimer->isActive()) {
    m_pollTimer->stop();
  }
}

// ── Refresh task list ─────────────────────────────────────────────────
void ScanPage::onRefreshTasks() {
  if (m_allScanResults && !m_pipelineId.isEmpty()) { loadPipelineResults(); return; }
  if (m_scopedTasks && m_scopeTaskIds.isEmpty()) return;
  const int scopeRevision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  m_api->get("/api/scan-tasks", 5000, [this, guard, scopeRevision](const QJsonObject &res) {
    if (!guard || scopeRevision != m_scopeRevision) return;
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();

    // Clear all 5 tables
    m_portScanTable->setRowCount(0);
    m_vulnScanTable->setRowCount(0);
    m_webScanTable->setRowCount(0);
    m_bruteForceTable->setRowCount(0);
    m_sourceScanTable->setRowCount(0);

    QMap<QString, int> counts = {{"port_scan", 0}, {"vuln_scan", 0}, {"web_scan", 0}, {"brute_force", 0}, {"source_scan", 0}};
    QStringList runningIds;
    int selectTabIdx = -1;
    int selectRowInTab = -1;

    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      QString taskId = t["scan_task_id"].toString();
      if (m_scopedTasks && !m_scopeTaskIds.contains(taskId)) continue;
      QString scanType = t["scan_type"].toString();
      QString status = t["status"].toString();

      auto *table = tableForScanType(scanType, m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable);
      if (!table) continue;

      int row = table->rowCount();
      table->setRowCount(row + 1);
      counts[scanType == "app_discovery" ? "web_scan" : isProgramScan(scanType) ? "source_scan" : scanType]++;

      auto *targetItem = new QTableWidgetItem(t["target"].toString());
      targetItem->setData(Qt::UserRole, taskId);
      targetItem->setToolTip(formatScanType(scanType) + "\n" + t["target"].toString());
      table->setItem(row, 0, targetItem);

      auto *statusItem = new QTableWidgetItem(formatStatus(status));
      statusItem->setForeground(statusColor(status));
      table->setItem(row, 1, statusItem);

      table->setItem(row, 2, new QTableWidgetItem(formatTime(t["created_at"].toString())));

      if (status == "RUNNING" || status == "PENDING") {
        runningIds << taskId;
      }

      // Track selected task
      if (!m_selectedTaskId.isEmpty() && taskId == m_selectedTaskId) {
        selectTabIdx = (scanType == "port_scan") ? 0 :
                       (scanType == "vuln_scan") ? 1 :
                       (scanType == "web_scan" || scanType == "app_discovery") ? 2 :
                       (scanType == "brute_force") ? 3 :
                       (isProgramScan(scanType)) ? 4 : -1;
        selectRowInTab = row;
      }
    }

    // Resize columns
    for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable}) {
      table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    }

    // Update count labels
    m_portScanCount->setText(QString("共 %1 个").arg(counts["port_scan"]));
    m_vulnScanCount->setText(QString("共 %1 个").arg(counts["vuln_scan"]));
    m_webScanCount->setText(QString("共 %1 个").arg(counts["web_scan"]));
    m_bruteForceCount->setText(QString("共 %1 个").arg(counts["brute_force"]));
    m_sourceScanCount->setText(QString("共 %1 个").arg(counts["source_scan"]));

    // Select the previously selected task (only highlight row, don't switch tabs
    // to avoid jarring UX when user is viewing a different tab)
    if (selectTabIdx >= 0 && selectRowInTab >= 0) {
      // Only switch tab if the selected task is in the currently visible tab
      if (m_scanTypeTabs->currentIndex() == selectTabIdx) {
        auto *table = tableForScanType(
          selectTabIdx == 0 ? "port_scan" : selectTabIdx == 1 ? "vuln_scan" : selectTabIdx == 2 ? "web_scan" : selectTabIdx == 3 ? "brute_force" : "source_scan",
          m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable);
        if (table) {
          table->selectRow(selectRowInTab);
          enableCurrentTabDelBtn(true);
        }
      }
    }

    // Opening a pipeline should show its results, not unrelated global tasks.
    if (!m_allScanResults && m_scopedTasks && m_selectInitialScopeTask && m_selectedTaskId.isEmpty()) {
      const QList<QTableWidget*> tables{m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable};
      for (int tab = 0; tab < tables.size(); ++tab) {
        if (tables[tab]->rowCount() == 0) continue;
        m_scanTypeTabs->setCurrentIndex(tab);
        tables[tab]->selectRow(0);
        emit tables[tab]->cellClicked(0, 0);
        m_selectInitialScopeTask = false;
        break;
      }
    }

    m_runningTaskIds = runningIds;
    startPollingIfNeeded();
  });
}

// ── Task clicked → show detail in right panel ────────────────────────
void ScanPage::onTaskClicked(int row, int) {
  m_allScanResults = false; ++m_scanPageRequest; m_scanPageBusy = false;
  // Determine which table sent the signal
  auto *table = qobject_cast<QTableWidget*>(sender());
  if (!table) return;

  auto *idItem = table->item(row, 0);
  if (!idItem) return;
  QString id = idItem->data(Qt::UserRole).toString();
  if (id.isEmpty()) return;
  if (id == m_selectedTaskId && m_generationInProgress) return;
  if (id != m_selectedTaskId) {
    const bool pendingVerification = m_pendingSourceVerification;
    clearDetailPanel();
    m_pendingSourceVerification = pendingVerification;
  }
  m_selectedTaskId = id;
  enableCurrentTabDelBtn(true);

  const int scopeRevision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  m_api->get("/api/scan-tasks/" + id, 5000, [this, guard, id, scopeRevision](const QJsonObject &res) {
    if (!guard || scopeRevision != m_scopeRevision || id != m_selectedTaskId) return;
    if (res["status"].toString() != "ok") {
      m_pendingSourceVerification = false;
      if (m_currentScanType.isEmpty()) m_selectedTaskId.clear();
      setStatusText(QStringLiteral("扫描详情加载失败，请点击生成重试或重新选择任务。"));
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    // Save current target for cross-page navigation
    m_currentTarget = d["target"].toString();

    // Update status in the originating table (find across all 5 tables)
    for (auto *t : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable}) {
      for (int i = 0; i < t->rowCount(); i++) {
        auto *item = t->item(i, 0);
        if (item && item->data(Qt::UserRole).toString() == id) {
          auto *statusItem = new QTableWidgetItem(formatStatus(status));
          statusItem->setForeground(statusColor(status));
          t->setItem(i, 1, statusItem);
          break;
        }
      }
    }

    updateStatusLabel(d);

    auto arr = d["results"].toArray();
    renderGroupedResults(arr);

    // Clear per-task state
    m_lastGeneratedId.clear();
    m_selectedRecPlaybookId.clear();
    m_selectedRecPlaybookName.clear();
    m_recExecBtn->setVisible(false);
    m_genPreviewWidget->setVisible(false);
    m_genStepTable->setRowCount(0);

    bool structured = hasStructuredResults(arr);
    if ((status == "COMPLETED" || status == "PARTIAL") && structured) {
      m_genBtn->setEnabled(true);
      m_reexecBtn->setVisible(status == "PARTIAL");
      loadRecommendations(id);
      // 不再自动触发 AI 生成，需用户手动点击
    } else if ((status == "COMPLETED" || status == "PARTIAL") && !structured) {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(true);
      m_recTable->setRowCount(0);
    } else if (status == "PENDING") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
    } else if (status == "RUNNING") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
      if (!m_runningTaskIds.contains(id)) m_runningTaskIds << id;
      startPollingIfNeeded();
    } else if (status == "FAILED" || status == "CANCELLED") {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(true);
      m_recTable->setRowCount(0);
    } else {
      m_genBtn->setEnabled(false);
      m_reexecBtn->setVisible(false);
      m_recTable->setRowCount(0);
    }
    if (m_pendingSourceVerification) {
      m_pendingSourceVerification = false;
      beginSourceVerification();
    }
  });
}

// ── Load results (used by poll completion) ───────────────────────────
void ScanPage::loadResults(const QString &taskId) {
  const int scopeRevision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  m_api->get("/api/scan-tasks/" + taskId, 5000, [this, guard, taskId, scopeRevision](const QJsonObject &res) {
    if (!guard || scopeRevision != m_scopeRevision || taskId != m_selectedTaskId) return;
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    updateStatusLabel(d);
    m_currentTarget = d["target"].toString();
    auto arr = d["results"].toArray();
    renderGroupedResults(arr);
  });
}

// ── Load recommendations ─────────────────────────────────────────────
void ScanPage::loadRecommendations(const QString &taskId) {
  const int scopeRevision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  m_api->get("/api/scan-tasks/" + taskId + "/recommendations", 5000, [this, guard, taskId, scopeRevision](const QJsonObject &res) {
    if (!guard || scopeRevision != m_scopeRevision || taskId != m_selectedTaskId) return;
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    const bool sorting = m_recTable->isSortingEnabled();
    m_recTable->setSortingEnabled(false);
    m_recTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto r = arr[i].toObject();
      auto *nameItem = new QTableWidgetItem(r["name"].toString());
      nameItem->setData(Qt::UserRole, r["playbook_id"].toString());
      m_recTable->setItem(i, 0, nameItem);
      m_recTable->setItem(i, 1, new QTableWidgetItem(formatDifficulty(r["difficulty"].toString())));
      m_recTable->setItem(i, 2, new QTableWidgetItem(formatBaselineGroup(r["baseline_group"].toString())));
      auto *reason = new QTableWidgetItem(r["match_reason"].toString());
      reason->setToolTip(reason->text());
      m_recTable->setItem(i, 3, reason);
      auto *scoreItem = new QTableWidgetItem;
      scoreItem->setData(Qt::DisplayRole, r["match_score"].toDouble());
      scoreItem->setToolTip(QStringLiteral("用于候选排序，不是漏洞概率或执行成功率"));
      m_recTable->setItem(i, 4, scoreItem);
      auto *stageItem = new QTableWidgetItem(r["match_stage_label"].toString()
          + QStringLiteral(" · ") + r["match_status_label"].toString());
      stageItem->setToolTip(r["match_reason"].toString());
      m_recTable->setItem(i, 5, stageItem);
    }
    m_recTable->setSortingEnabled(sorting);
    m_recTable->sortItems(4, Qt::DescendingOrder);
    m_recTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_recTable->horizontalHeader()->setStretchLastSection(false);
  });
}

// ── AI Generate Playbook ──────────────────────────────────────────────
void ScanPage::onGeneratePlaybook() {
  if (isProgramScan(m_currentScanType) && m_sourceDemoBtn->isEnabled()) {
    QJsonArray ids;
    for (int group=0; group<m_resultTree->topLevelItemCount(); ++group) {
      auto *parent=m_resultTree->topLevelItem(group);
      for (int i=0; i<parent->childCount(); ++i) {
        auto *item=parent->child(i);
        if (!isProgramFinding(item->data(0,Qt::UserRole).toString())) continue;
        const auto data=QJsonDocument::fromJson(item->toolTip(1).toUtf8()).object();
        if (data["demonstration_supported"].isBool() && !data["demonstration_supported"].toBool()) continue;
        ids.append(item->data(0,Qt::UserRole+1).toInt());
      }
    }
    if (ids.isEmpty()) {setStatusText("发现尚缺验证条件，请查看证据与前提。");return;}
    if (ids.size()>10) {selectSourceDemonstration();return;}
    generatePlaybook(ids);
    return;
  }
  generatePlaybook();
}

void ScanPage::beginSourceVerification() {
  m_detailTabs->setCurrentIndex(0);
  if (m_generationInProgress) {
    setStatusText(QStringLiteral("预案正在生成，请等待结果；失败后可重新生成。"));
    emit sourceGenerationStatus(m_statusLabel->text(), false);
    return;
  }
  if (m_scopedTasks && !m_scopeTaskIds.isEmpty()
      && (m_selectedTaskId.isEmpty() || m_currentScanType.isEmpty())) {
    const bool refresh = !m_pendingSourceVerification;
    m_pendingSourceVerification = true;
    setStatusText(QStringLiteral("正在加载本任务扫描发现，加载完成后继续生成预案…"));
    if (refresh && m_selectedTaskId.isEmpty()) {
      m_selectInitialScopeTask = true;
      onRefreshTasks();
    }
    emit sourceGenerationStatus(m_statusLabel->text(), false);
    return;
  }
  if (!isProgramScan(m_currentScanType) || !m_sourceDemoBtn->isEnabled()) {
    setStatusText(QStringLiteral("请选择已完成的程序扫描并检查漏洞发现，再生成预案。"));
    m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
    emit sourceGenerationStatus(m_statusLabel->text(), false);
    return;
  }
  selectSourceDemonstration();
}

void ScanPage::selectSourceDemonstration() {
  if (m_selectedTaskId.isEmpty() || !m_sourceDemoBtn->isEnabled()) return;
  QDialog dialog(this);
  dialog.setWindowTitle("选择漏洞生成预案");
  dialog.resize(1000, 520);
  auto *layout = new QVBoxLayout(&dialog);
  auto *hint = new QLabel("目标：" + m_currentTarget + "\n勾选复选框或点击发现行，选择 1–10 条生成预案。只有源码时可以生成待补运行条件的草稿。", &dialog);
  hint->setWordWrap(true);
  layout->addWidget(hint);
  auto *table = new QTableWidget(0, 6, &dialog);
  table->setObjectName("sourceDemonstrationCandidates");
  table->setHorizontalHeaderLabels({"选择 / 编号", "严重度", "发现 / CWE", "入口 / 源码位置", "触发前提", "复核状态"});
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setAlternatingRowColors(true);
  table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
  for (int group = 0; group < m_resultTree->topLevelItemCount(); ++group) {
    auto *parent = m_resultTree->topLevelItem(group);
    for (int index = 0; index < parent->childCount(); ++index) {
      auto *item = parent->child(index);
      if (!isProgramFinding(item->data(0, Qt::UserRole).toString())) continue;
      const auto data = QJsonDocument::fromJson(item->toolTip(1).toUtf8()).object();
      const int row = table->rowCount();
      table->insertRow(row);
      const int id = item->data(0, Qt::UserRole+1).toInt();
      auto *select = new QTableWidgetItem;
      select->setData(Qt::UserRole, id);
      select->setFlags(select->flags() & ~Qt::ItemIsUserCheckable);
      const bool supported=!data["demonstration_supported"].isBool() || data["demonstration_supported"].toBool();
      table->setItem(row, 0, select);
      auto *check = new QCheckBox(QString("#%1").arg(id), table);
      check->setObjectName(QString("sourceFindingSelection%1").arg(id));
      check->setEnabled(supported);
      check->setChecked(supported && (m_lastSourceSelectionTask == m_selectedTaskId
          ? m_lastSourceSelection.contains(QJsonValue(id)) : item == m_resultTree->currentItem()));
      if (!supported) check->setToolTip(data["demonstration_reason"].toString());
      table->setCellWidget(row, 0, check);
      table->setItem(row, 1, new QTableWidgetItem(item->text(0)));
      table->setItem(row, 2, new QTableWidgetItem(data["title"].toString() + " " + data["cwe"].toString()));
      table->setItem(row, 3, new QTableWidgetItem(data["file"].toString().isEmpty() ? data["url"].toString() : QString("%1:%2").arg(data["file"].toString()).arg(data["start_line"].toInt())));
      const QString conditions = data["preconditions"].toString();
      auto *condition = new QTableWidgetItem(conditions.isEmpty() ? "需确认输入点及运行条件" : conditions);
      condition->setToolTip(condition->text());
      table->setItem(row, 4, condition);
      const QString status = data["review"].toObject()["status"].toString();
      table->setItem(row, 5, new QTableWidgetItem(status == "supported" ? "证据支持" : status == "not_reproduced" ? "未复现" : status == "inconclusive" ? "条件不足" : "待验证"));
    }
  }
  table->resizeColumnToContents(0);
  table->resizeColumnToContents(1);
  layout->addWidget(table);
  auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, &dialog);
  auto *generate = buttons->addButton("生成攻击测试预案", QDialogButtonBox::AcceptRole);
  auto *selection = new QLabel(&dialog);
  layout->addWidget(selection);
  layout->addWidget(buttons);
  auto updateSelection = [table, generate, selection]() {
    int count = 0;
    for (int row = 0; row < table->rowCount(); ++row) {
      auto *check = qobject_cast<QCheckBox*>(table->cellWidget(row, 0));
      if (check && check->isChecked()) ++count;
    }
    selection->setText(QString("已选择 %1 条 · 每项单独保留步骤和证据，最多 10 条").arg(count));
    generate->setEnabled(count >= 1 && count <= 10);
  };
  for (int row = 0; row < table->rowCount(); ++row) {
    auto *check = qobject_cast<QCheckBox*>(table->cellWidget(row, 0));
    connect(check, &QCheckBox::toggled, &dialog, [updateSelection](bool) { updateSelection(); });
  }
  connect(table, &QTableWidget::cellClicked, &dialog, [table](int row, int) {
    auto *check = qobject_cast<QCheckBox*>(table->cellWidget(row, 0));
    if (check && check->isEnabled()) check->toggle();
  });
  updateSelection();
  connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  const QString taskId = m_selectedTaskId;
  if (dialog.exec() != QDialog::Accepted || taskId != m_selectedTaskId) return;
  QJsonArray ids;
  for (int row = 0; row < table->rowCount(); ++row) {
    auto *check = qobject_cast<QCheckBox*>(table->cellWidget(row, 0));
    if (check && check->isChecked()) ids.append(table->item(row, 0)->data(Qt::UserRole).toInt());
  }
  m_lastSourceSelection = ids;
  m_lastSourceSelectionTask = taskId;
  generatePlaybook(ids);
}

void ScanPage::generatePlaybook(const QJsonArray &findingIds) {
  if (m_selectedTaskId.isEmpty() || m_generationInProgress) return;
  const QString taskId = m_selectedTaskId;
  const bool sourceDemo = isProgramScan(m_currentScanType) && !findingIds.isEmpty();
  const bool selectionEnabled = m_sourceDemoBtn->isEnabled();
  m_generationInProgress = true;
  emit sourceGenerationStatus(QStringLiteral("正在生成所选漏洞的验证步骤，请等待…"), false);
  const int generationRevision = ++m_generationRevision;
  m_lastGeneratedId.clear();
  m_genExecBtn->setEnabled(false);
  const QString buttonText = m_genBtn->text();
  m_genBtn->setEnabled(false);
  m_sourceDemoBtn->setEnabled(false);
  m_genBtn->setText("智能生成中...");
  m_genPreviewWidget->setVisible(false);
  m_genStepTable->setRowCount(0);
  QJsonObject body;
  body["adaptive"] = m_sourceAdaptiveCheck->isChecked();
  if (sourceDemo) {
    body["finding_ids"] = findingIds;
    body["demonstration"] = true;
  }
  const int scopeRevision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  // A source plan may require one validated model correction (2 x 120 s).
  const int generationTimeout = isProgramScan(m_currentScanType) ? 270000 : 150000;
  m_api->post("/api/scan-tasks/" + taskId + "/generate-playbook", body, generationTimeout, [this, guard, scopeRevision, generationRevision, taskId, sourceDemo, selectionEnabled, buttonText](const QJsonObject &res) {
    if (!guard || scopeRevision != m_scopeRevision) return;
    if (taskId != m_selectedTaskId || generationRevision != m_generationRevision) return;
    m_generationInProgress = false;
    m_genBtn->setEnabled(true);
    m_genBtn->setText(buttonText);
    m_sourceDemoBtn->setEnabled(selectionEnabled);
    if (res["status"].toString() == "ok") {
      auto data = res["data"].toObject();
      if(data["requires_runtime_target"].toBool()) {
        setStatusText("预案草稿已保存；缺少程序运行条件，尚未执行攻击。");
        m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
        emit sourceGenerationStatus(m_statusLabel->text(), true);
        m_lastGeneratedId.clear();m_genExecBtn->setEnabled(false);
        QDialog draftDialog(this);draftDialog.setWindowTitle("攻击测试预案 · 待补充运行条件");draftDialog.resize(900,600);
        auto *layout=new QVBoxLayout(&draftDialog);
        auto *view=new QPlainTextEdit(&draftDialog);view->setReadOnly(true);
        view->setPlainText(QString::fromUtf8(QJsonDocument(data["draft"].toObject()).toJson(QJsonDocument::Indented)));
        layout->addWidget(view);auto *close=new QDialogButtonBox(QDialogButtonBox::Close,&draftDialog);layout->addWidget(close);
        connect(close,&QDialogButtonBox::rejected,&draftDialog,&QDialog::reject);draftDialog.exec();
        return;
      }
      QString pbId = data["playbook_id"].toString();
      QString pbName = data["name"].toString();
      int steps = data["steps_count"].toInt();

      m_lastGeneratedId = pbId;

      // 显示预览区标题
      m_genPreviewTitle->setText(QString("%1：%2（%3步）").arg(sourceDemo ? "攻击测试预案" : "智能生成预案", pbName).arg(steps));
      m_genExecBtn->setText(QString("%1「%2」→").arg(m_scopedTasks ? "前往任务预案" : "前往执行", pbName.left(20)));

      // 加载 Playbook 详情并渲染步骤表格
      m_api->get("/api/playbooks/" + pbId, 8000, [this, guard, scopeRevision, generationRevision, taskId, sourceDemo, pbId](const QJsonObject &pbRes) {
        if (!guard || scopeRevision != m_scopeRevision) return;
        if (taskId != m_selectedTaskId || generationRevision != m_generationRevision) return;
        if (pbRes["status"].toString() != "ok") {
          setStatusText(QStringLiteral("预案已生成，但步骤加载失败，请在推荐列表中重新打开预案。"));
          m_statusLabel->setStyleSheet(Theme::StatusWarningStyle);
          emit sourceGenerationStatus(m_statusLabel->text(), true);
          return;
        }
        auto pb = pbRes["data"].toObject();
        auto stepsArr = pb["steps"].toArray();
        m_genStepTable->setRowCount(stepsArr.size());
        for (int i = 0; i < stepsArr.size(); i++) {
          auto s = stepsArr[i].toObject();
          int stepNum = s["step_index"].toInt(i);
          const auto evidence = QJsonDocument::fromJson(s["evidence_config"].toString().toUtf8()).object();
          QStringList findingLabels;
          for (const auto &id : evidence["finding_ids"].toArray()) findingLabels << QString("#%1").arg(id.toInt());
          const QString phase = evidence["phase"].toString();
          m_genStepTable->setItem(i, 0, new QTableWidgetItem(QString("步骤 %1 %2 %3").arg(stepNum + 1).arg(findingLabels.join(", "), phase == "baseline" ? "正常对照" : phase == "verification" ? "漏洞验证" : "")));
          m_genStepTable->setItem(i, 1, new QTableWidgetItem(s["tool_id"].toString()));
          QStringList args;
          auto at = s["args_template"];
          if (at.isString()) {
            QJsonArray argsArr = QJsonDocument::fromJson(at.toString().toUtf8()).array();
            for (const auto &v : argsArr) args << v.toVariant().toString();
          } else if (at.isArray()) {
            for (const auto &v : at.toArray()) args << v.toVariant().toString();
          }
          m_genStepTable->setItem(i, 2, new QTableWidgetItem(args.join(" ")));
          m_genStepTable->setItem(i, 3, new QTableWidgetItem(s["description"].toString()));
        }
        m_genStepTable->resizeColumnsToContents();
        m_genStepTable->horizontalHeader()->setStretchLastSection(true);
        m_genExecBtn->setEnabled(!stepsArr.isEmpty());
        if (sourceDemo && m_scopedTasks && !stepsArr.isEmpty())
          emit sourcePlaybookGenerated(pbId);
      });

      // 显示预览区
      m_genPreviewWidget->setVisible(true);
      m_detailTabs->setCurrentIndex(1);
      setStatusText(sourceDemo && m_scopedTasks
          ? QStringLiteral("验证预案已生成，正在加载步骤并建立任务草稿…")
          : QStringLiteral("预案已生成，请查看步骤后前往执行。"));
      m_statusLabel->setStyleSheet(Theme::StatusSuccessStyle);

      loadRecommendations(m_selectedTaskId);
    } else {
      QString errMsg = res["error"].toObject()["message"].toString();
      const QString errCode = res["error"].toObject()["code"].toString();
      if (errMsg.isEmpty()) errMsg = res["data"].toObject()["error"].toString();
      if (errCode == "PLAYBOOK_VALIDATION_ERROR")
        errMsg = "预案校验失败，自动修正后仍有不支持的步骤或变量依赖，请调整任务信息后重试";
      else if (errCode == "PLAYBOOK_FORMAT_ERROR")
        errMsg = "模型返回格式错误，自动修正后仍无法解析，请重试";
      else if (!errCode.startsWith("LLM_") && (errMsg.startsWith("LLM API 401:")
          || errMsg.contains("invalid api key", Qt::CaseInsensitive)))
        errMsg = "模型服务密钥无效，请在「系统管理→系统配置」中检查模型服务配置";
      else if (errMsg.contains("timed out", Qt::CaseInsensitive))
        errMsg = "模型服务请求超时，请稍后重试";
      else if (errMsg.contains("No LLM API key", Qt::CaseInsensitive))
        errMsg = "未配置模型服务密钥，请在「系统管理→系统配置」中设置模型服务配置";
      else if (errMsg.isEmpty())
        errMsg = "未知错误";
      setStatusText(QString("✗ 预案生成失败: %1。可重新选择漏洞或点击生成重试。").arg(errMsg));
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      emit sourceGenerationStatus(m_statusLabel->text(), true);
    }
  });
}

// ── Recommendation clicked → 仅选中，不跳转 ───────────────────────────
void ScanPage::onRecommendationClicked(int row, int) {
  auto *item = m_recTable->item(row, 0);
  if (!item) return;
  QString pbId = item->data(Qt::UserRole).toString();
  if (pbId.isEmpty()) return;
  // 仅选中，不跳转
  m_selectedRecPlaybookId = pbId;
  m_selectedRecPlaybookName = item->text();
  // 显示"前往执行"按钮
  m_recExecBtn->setVisible(true);
  m_recExecBtn->setText(QString("%1「%2」→").arg(m_scopedTasks ? "前往任务预案" : "前往执行", m_selectedRecPlaybookName.left(20)));
}

// ── 推荐预案"前往执行→"按钮 ──────────────────────────────────────────
void ScanPage::onRecExecClicked() {
  if (m_selectedRecPlaybookId.isEmpty()) return;
  emit playbookNavigateRequested(m_selectedRecPlaybookId, m_currentTarget);
}

// ── AI生成预案"前往执行→"按钮 ────────────────────────────────────────
void ScanPage::onGenExecClicked() {
  if (m_lastGeneratedId.isEmpty()) return;
  emit playbookNavigateRequested(m_lastGeneratedId, m_currentTarget);
}

// ── Re-execute scan ──────────────────────────────────────────────────
void ScanPage::onReexecScan() {
  if (m_selectedTaskId.isEmpty()) return;
  const QString originalId = m_selectedTaskId;
  const int revision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  if (isProgramScan(m_currentScanType)) {
    if (!m_canReparseReport) return;
    const QString scanType = m_currentScanType;
    clearDetailPanel();
    m_reexecBtn->hide();
    setStatusText("正在重新解析已保存报告...");
    m_api->post("/api/scan-tasks/" + originalId + "/reparse", QJsonObject(), 5000,
      [this, guard, originalId, revision, scanType](const QJsonObject &res) {
        if (!guard || revision != m_scopeRevision || m_selectedTaskId != originalId) return;
        if (res["status"].toString() == "ok") {
          if (!m_runningTaskIds.contains(originalId)) m_runningTaskIds << originalId;
          startPollingIfNeeded();
          onRefreshTasks();
        } else {
          m_currentScanType = scanType;
          m_canReparseReport = true;
          setStatusText("报告重试失败：" + res["error"].toObject()["message"].toString());
          m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
          m_reexecBtn->show();
        }
      });
    return;
  }
  m_reexecBtn->setVisible(false);
  clearDetailPanel();
  setStatusText("创建关联扫描中...");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);

  if (m_retryRequestSource != originalId || m_retryRequestId.isEmpty()) {
    m_retryRequestSource = originalId;
    m_retryRequestId = QUuid::createUuid().toString(QUuid::WithoutBraces);
  }
  QJsonObject empty{{"request_id", m_retryRequestId}};
  m_api->post("/api/scan-tasks/" + originalId + "/retry", empty, 5000, [this, guard, originalId, revision](const QJsonObject &res) {
    if (!guard || revision != m_scopeRevision || m_selectedTaskId != originalId) return;
    if (res["status"].toString() == "ok") {
      m_retryRequestId.clear();
      m_selectedTaskId = res["data"].toObject()["scan_task_id"].toString();
      // Explicit follow-up scope; the parent run's original evidence is unchanged.
      m_pipelineId.clear(); m_allScanResults = false; m_aggregateControls->hide();
      m_scopeTaskIds = QStringList{m_selectedTaskId};
      if (!m_runningTaskIds.contains(m_selectedTaskId)) m_runningTaskIds << m_selectedTaskId;
      startPollingIfNeeded();
      onRefreshTasks();
    } else {
      setStatusText("重新执行失败");
      m_statusLabel->setStyleSheet(Theme::StatusErrorStyle);
      m_reexecBtn->setVisible(true);
    }
  });
}

// ── Delete task ───────────────────────────────────────────────────────
void ScanPage::onDeleteTask() {
  if (m_selectedTaskId.isEmpty()) return;

  const QString taskId = m_selectedTaskId;
  const int revision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  m_api->get("/api/scan-tasks/" + taskId, 5000, [this, guard, taskId, revision](const QJsonObject &res) {
    if (!guard || revision != m_scopeRevision || taskId != m_selectedTaskId) return;
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString status = d["status"].toString();

    if (status == "RUNNING") {
      QMessageBox::warning(this->window(), "无法删除",
        "正在运行的任务无法删除，请先等待完成。");
      return;
    }

    QString target = d["target"].toString();
    QString type = formatScanType(d["scan_type"].toString());
    auto reply = QMessageBox::question(this->window(), "确认删除",
      QString("确定要删除此扫描任务吗？\n目标: %1 | %2\n此操作不可撤销。").arg(target, type),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes || revision != m_scopeRevision || taskId != m_selectedTaskId) return;

    m_api->del("/api/scan-tasks/" + taskId, 5000, [this, guard, taskId, revision](const QJsonObject &response) {
      if (!guard || revision != m_scopeRevision || taskId != m_selectedTaskId) return;
      if (response["status"].toString() != "ok") {
        setStatusText(response["error"].toObject()["message"].toString(QStringLiteral("删除失败，原结果仍保留"))); return;
      }
      m_selectedTaskId.clear();
      clearDetailPanel();  // also disables delete button
      onRefreshTasks();
    });
  });
}

// ── Clear detail panel ────────────────────────────────────────────────
void ScanPage::clearDetailPanel() {
  ++m_generationRevision;
  m_generationInProgress = false;
  m_pendingSourceVerification = false;
  for (auto *dialog : findChildren<QDialog*>("scanAuxRecord")) dialog->close();
  m_resultOverview->clear();
  m_coverageTree->clear(); m_coverageTree->hide();
  if (m_webScanProcess) {m_webScanProcess->clear();m_webScanProcess->hide();}
  m_listTitle->setText(QStringLiteral("漏洞候选"));
  m_showAllRecords->hide(); m_moreResultsButton->hide();
  setStatusText("选择任务查看详情");
  m_statusLabel->setStyleSheet(Theme::StatusInfoStyle);
  m_resultTree->setRootIndex(QModelIndex());
  m_resultTree->clear();
  updateFindingSelection();
  m_recTable->setRowCount(0);
  m_genBtn->setEnabled(false);
  m_genBtn->setText("智能生成预案");
  m_sourceDemoBtn->hide();
  m_sourceDemoBtn->setEnabled(false);
  m_resultHint->setText("点击名称查看完整证据；勾选漏洞后可准备验证");
  m_reexecBtn->setVisible(false);
  m_selectedRecPlaybookId.clear();
  m_selectedRecPlaybookName.clear();
  m_recExecBtn->setVisible(false);
  m_genPreviewWidget->setVisible(false);
  m_genStepTable->setRowCount(0);
  m_lastGeneratedId.clear();
  m_genExecBtn->setEnabled(false);
  m_currentTarget.clear();
  m_currentTaskTarget.clear();
  m_currentScanType.clear();
  m_canReparseReport = false;
  enableCurrentTabDelBtn(false);
}

// ── Poll scan status ──────────────────────────────────────────────────
void ScanPage::onPollStatus() {
  if (m_allScanResults) { if (!m_scanPageBusy) loadPipelineResults(); return; }
  if (m_runningTaskIds.isEmpty()) {
    m_pollTimer->stop();
    return;
  }

  const int scopeRevision = m_scopeRevision;
  QPointer<ScanPage> guard(this);
  m_api->get("/api/scan-tasks", 5000, [this, guard, scopeRevision](const QJsonObject &res) {
    if (!guard || scopeRevision != m_scopeRevision || m_allScanResults) return;
    if (res["status"].toString() != "ok") {
      // API error — tolerate transient failures, then stop polling to avoid spin
      if (++m_pollErrorCount >= 10) {
        m_pollTimer->stop();
        m_runningTaskIds.clear();
      }
      return;
    }
    m_pollErrorCount = 0;
    auto arr = res["data"].toArray();

    QStringList stillRunning;
    bool selectedTaskFinished = false;

    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      QString taskId = t["scan_task_id"].toString();
      if (m_scopedTasks && !m_scopeTaskIds.contains(taskId)) continue;
      QString status = t["status"].toString();

      if (m_runningTaskIds.contains(taskId)) {
        // Update status in the corresponding table
        for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable}) {
          for (int row = 0; row < table->rowCount(); row++) {
            auto *idItem = table->item(row, 0);
            if (idItem && idItem->data(Qt::UserRole).toString() == taskId) {
              auto *statusItem = new QTableWidgetItem(formatStatus(status));
              statusItem->setForeground(statusColor(status));
              table->setItem(row, 1, statusItem);
              break;
            }
          }
        }

        if (status == "RUNNING" || status == "PENDING") {
          stillRunning << taskId;
        } else {
          if (taskId == m_selectedTaskId) {
            selectedTaskFinished = true;
          }
        }
      }
    }

    m_runningTaskIds = stillRunning;
    startPollingIfNeeded();

    const bool selectedSourceRunning=stillRunning.contains(m_selectedTaskId) && m_scanTypeTabs->currentIndex()==4;
    if ((selectedTaskFinished || selectedSourceRunning) && !m_selectedTaskId.isEmpty()) {
      // Re-trigger task click to load full details
      bool found = false;
      for (auto *table : {m_portScanTable, m_vulnScanTable, m_webScanTable, m_bruteForceTable, m_sourceScanTable}) {
        if (found) break;
        for (int row = 0; row < table->rowCount(); row++) {
          auto *idItem = table->item(row, 0);
          if (idItem && idItem->data(Qt::UserRole).toString() == m_selectedTaskId) {
            // Directly load the task details
            const QString selectedId = m_selectedTaskId;
      m_api->get("/api/scan-tasks/" + selectedId, 5000, [this, guard, selectedId, scopeRevision](const QJsonObject &detailRes) {
        if (!guard || scopeRevision != m_scopeRevision || selectedId != m_selectedTaskId) return;
              if (detailRes["status"].toString() != "ok") return;
              auto d = detailRes["data"].toObject();
              m_currentTarget = d["target"].toString();
              updateStatusLabel(d);
              renderGroupedResults(d["results"].toArray());
              // Trigger recommendations for completed tasks
              QString status = d["status"].toString();
              auto arr = d["results"].toArray();
              bool structured = hasStructuredResults(arr);
              if ((status == "COMPLETED" || status == "PARTIAL") && structured) {
                m_genBtn->setEnabled(true);
                m_reexecBtn->setVisible(status == "PARTIAL");
                loadRecommendations(m_selectedTaskId);
                // 不再自动触发 AI 生成
              } else if ((status == "COMPLETED" || status == "PARTIAL") && !structured) {
                m_genBtn->setEnabled(false);
                m_reexecBtn->setVisible(true);
              } else if (status == "FAILED" || status == "CANCELLED") {
                m_genBtn->setEnabled(false);
                m_reexecBtn->setVisible(true);
              }
            });
            found = true;
            break;
          }
        }
      }
    } else if (!m_selectedTaskId.isEmpty() && m_runningTaskIds.contains(m_selectedTaskId)) {
      // Still running — update results incrementally
      const QString selectedId = m_selectedTaskId;
      m_api->get("/api/scan-tasks/" + selectedId, 5000, [this, guard, selectedId, scopeRevision](const QJsonObject &detailRes) {
        if (!guard || scopeRevision != m_scopeRevision || selectedId != m_selectedTaskId) return;
        if (detailRes["status"].toString() != "ok") return;
        auto d = detailRes["data"].toObject();
        m_currentTarget = d["target"].toString();
        updateStatusLabel(d);
        renderGroupedResults(d["results"].toArray());
      });
    }
  });
}

void ScanPage::showPayloadForFinding(int findingId) {
  auto *dialog = new QDialog(this);
  dialog->setAttribute(Qt::WA_DeleteOnClose);
  dialog->setWindowTitle(QStringLiteral("漏洞载荷匹配与生成"));
  dialog->resize(760, 480);
  auto *layout = new QVBoxLayout(dialog);
  auto *status = new QLabel(QStringLiteral("正在检索可复用载荷；没有适用载荷时将调用模型生成并校验…"), dialog);
  status->setWordWrap(true);
  layout->addWidget(status);
  auto *preview = new QPlainTextEdit(dialog);
  preview->setReadOnly(true);
  layout->addWidget(preview);
  auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
  connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
  layout->addWidget(buttons);
  dialog->show();

  QPointer<QDialog> safeDialog(dialog);
  QPointer<ScanPage> self(this);
  m_api->post("/api/payloads/resolve", QJsonObject{{"finding_id", findingId}}, 130000,
    [self, safeDialog, status, preview](const QJsonObject &response) {
      if (!self || !safeDialog) return;
      if (response["status"].toString() != "ok") {
        status->setText(QStringLiteral("载荷处理失败"));
        status->setStyleSheet("color:#b91c1c; font-weight:700;");
        preview->setPlainText(response["error"].toObject()["message"].toString());
        return;
      }
      const auto data = response["data"].toObject();
      const auto payload = data["payload"].toObject();
      const bool generated = data["state"].toString() == "generated";
      status->setText(generated ? QStringLiteral("本次新生成 · 已保存到载荷库")
                                : QStringLiteral("已有载荷 · 已从载荷库复用"));
      status->setStyleSheet(generated ? "color:#b45309; font-weight:700;" : "color:#1d4ed8; font-weight:700;");
      const auto name = payload["name"].isObject() ? payload["name"].toObject()["zh"].toString()
                                                    : payload["name"].toString();
      const auto consumption = payload["consumption"].toObject();
      const auto validation = payload["validation"].toObject();
      QStringList lines{
        QStringLiteral("发现 ID：%1").arg(data["finding_id"].toInt()),
        QStringLiteral("匹配依据：%1").arg(data["match_reason"].toString()),
        QStringLiteral("载荷：%1 (%2)").arg(name, payload["id"].toString()),
        QStringLiteral("内容版本：%1 · 来源：%2").arg(payload["version"].toInt(1)).arg(payload["_type"].toString()),
        QStringLiteral("载荷库版本：%1").arg(data["catalog_version"].toString()),
        QStringLiteral("消费方式：%1 · 工具：%2").arg(consumption["type"].toString(), consumption["tool_id"].toString()),
        QStringLiteral("校验：%1；生成时未进行实际运行验证").arg(validation["status"].toString()),
        QStringLiteral("变量：<target>（由执行任务的授权目标替换）"),
        QStringLiteral("参数预览："),
      };
      for (const auto &arg : consumption["args_template"].toArray()) lines << QStringLiteral("  %1").arg(arg.toString());
      const auto references = data["reference_payloads"].toArray();
      if (!references.isEmpty()) {
        lines << QStringLiteral("静态载荷库参考样本（仅供参考，未经结构化消费校验）：");
        for (const auto &entry : references) {
          const auto sample = entry.toObject();
          lines << QStringLiteral("  %1 · %2 · %3").arg(sample["id"].toString(),
            sample["name"].toString(), sample["match_basis"].toString());
        }
      }
      const auto prerequisites = payload["prerequisites"].toArray();
      if (!prerequisites.isEmpty()) {
        lines << QStringLiteral("适用条件：");
        for (const auto &entry : prerequisites) lines << QStringLiteral("  %1").arg(entry.isObject()
          ? entry.toObject()["zh"].toString() : entry.toString());
      }
      const auto history = payload["verification_history"].toArray();
      lines << QStringLiteral("运行记录：%1 次可见工具调用（工具成功不等于漏洞验证成立）").arg(history.size());
      for (const auto &entry : history) {
        const auto record = entry.toObject();
        lines << QStringLiteral("  %1 · 运行 %2 · 工具%3").arg(record["recorded_at"].toString(),
          record["run_id"].toString(), record["tool_success"].toInt() != 0 ? QStringLiteral("成功") : QStringLiteral("失败"));
      }
      preview->setPlainText(lines.join('\n'));
      if (self->m_allScanResults && !self->m_pipelineId.isEmpty()) self->loadPipelineResults();
    });
}

void ScanPage::showSourceEvidence(QTreeWidgetItem *item) {
  const QString taskId=m_selectedTaskId;
  const int findingId=item->data(0,Qt::UserRole+1).toInt();
  const QString type=item->data(0,Qt::UserRole).toString();
  const auto data=QJsonDocument::fromJson(item->toolTip(1).toUtf8()).object();
  QDialog dialog(this);
  dialog.setWindowTitle("程序测试证据");
  dialog.resize(850,650);
  auto *layout=new QVBoxLayout(&dialog);
  auto *view=new QPlainTextEdit(&dialog);
  view->setReadOnly(true);
  QString text;
  if(isProgramFinding(type)) {
    text=QString("%1\n%2:%3–%4\nCWE: %5\n快照: %6\n\n依据：%7\n\n触发前提：%8\n\n修复建议：%9\n\n")
      .arg(data["title"].toString(),data["file"].toString()).arg(data["start_line"].toInt()).arg(data["end_line"].toInt())
      .arg(data["cwe"].toString(),data["snapshot_id"].toString(),data["reason"].toString(),data["preconditions"].toString(),data["suggestion"].toString());
    const auto lines=data["code"].toString().split('\n');
    if(data["evidence_origin"].toString()=="cscan_report") {
      QStringList subtasks;
      for(const auto &value:data["source_subtask_ids"].toArray()) subtasks<<value.toString();
      text+=QString("CScan Flow：%1\n来源子任务：%2\n报告定位与源码版本待复核；尚未验证运行效果。\n")
        .arg(data["cscan_flow_id"].toString(),subtasks.join("、"));
    }
    for(int i=0;i<lines.size();i++) text+=QString("%1  %2\n").arg(data["start_line"].toInt()+i).arg(lines[i]);
    for(const auto &entry:data["trace"].toArray()) {
      const auto item=entry.toObject();
      text+=QString("\n证据链 [%1] %2:%3–%4\n%5\n%6\n").arg(item["role"].toString(),item["file"].toString())
        .arg(item["start_line"].toInt()).arg(item["end_line"].toInt()).arg(item["note"].toString(),item["code"].toString());
    }
    for(const auto &entry:data["analyses"].toArray()) {
      const auto item=entry.toObject();
      text+=QString("\n分析来源：%1\n%2\n前提：%3\n").arg(item["tool"].toString(),item["reason"].toString(),item["preconditions"].toString());
    }
    const auto assessment=data["assessment"].toObject();
    const auto counter=data["counter_review"].toObject();
    const QMap<QString,QString> judgments={{"controlled","有代码依据"},{"not_controlled","不可控"},{"supported","有代码依据"},
      {"blocked","存在阻断"},{"effective","有有效检查"},{"ineffective","检查不足"},{"unknown","尚不确定"},
      {"candidate","保留疑点"},{"unlikely","反证提示可能不成立"},{"needs_information","需要补充条件"}};
    const auto showJudgment=[&](const QJsonObject &value,const QString &name){
      if(value.isEmpty()) return;
      text+=QString("\n%1：%2\n输入控制：%3；代码可达：%4；边界检查：%5\n%6\n").arg(name,
        judgments.value(value["verdict"].toString(),"尚不确定"),judgments.value(value["input_control"].toString(),"尚不确定"),
        judgments.value(value["reachability"].toString(),"尚不确定"),judgments.value(value["guard"].toString(),"尚不确定"),value["reason"].toString());
      for(const auto &condition:value["missing_conditions"].toArray()) text+="待补条件："+condition.toString()+"\n";
      for(const auto &entry:value["citations"].toArray()) {const auto cite=entry.toObject();text+=QString("依据 %1:%2 — %3\n%4\n")
        .arg(cite["file"].toString()).arg(cite["start_line"].toInt()).arg(cite["note"].toString(),cite["code"].toString());}
      for(const auto &entry:value["counter_evidence"].toArray()) {const auto cite=entry.toObject();text+=QString("反证 %1:%2 — %3\n%4\n")
        .arg(cite["file"].toString()).arg(cite["start_line"].toInt()).arg(cite["note"].toString(),cite["code"].toString());}
    };
    showJudgment(assessment,"证据判断");showJudgment(counter,"独立反证复核");
    const auto mapping=data["runtime_mapping"].toObject();
    for(const auto &entry:mapping["entries"].toArray()) text+="候选运行入口："+entry.toObject()["url"].toString()+"（调用与输入关系待确认）\n";
    for(const auto &condition:mapping["missing_conditions"].toArray()) text+="入口待补条件："+condition.toString()+"\n";
    text+="\n静态发现不等于运行时漏洞。\n最近复核：\n"+QString::fromUtf8(QJsonDocument(data["review"].toObject()).toJson(QJsonDocument::Indented));
  } else text=QString::fromUtf8(QJsonDocument(data).toJson(QJsonDocument::Indented));
  view->setPlainText(text); layout->addWidget(view);
  auto *buttons=new QDialogButtonBox(QDialogButtonBox::Close,&dialog);
  auto *generate=buttons->addButton(isProgramFinding(type) ? "生成此项攻击演示预案" : "生成验证预案",QDialogButtonBox::ActionRole);
  generate->setEnabled(m_genBtn->isEnabled());
  connect(generate,&QPushButton::clicked,&dialog,[this,&dialog,taskId,findingId,type](){
    if(taskId==m_selectedTaskId) {
      if(isProgramFinding(type)) generatePlaybook(QJsonArray{findingId});
      else onGeneratePlaybook();
    }
    dialog.accept();
  });
  if(isProgramFinding(type)) {
    auto *review=buttons->addButton("查看执行证据并复核",QDialogButtonBox::ActionRole);
    connect(review,&QPushButton::clicked,&dialog,[this,&dialog,taskId,findingId](){
      if(taskId==m_selectedTaskId) reviewSourceFinding(findingId);
      dialog.accept();
    });
  }
  connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
  layout->addWidget(buttons); dialog.exec();
}

void ScanPage::reviewSourceFinding(int findingId) {
  const QString taskId=m_selectedTaskId;
  m_api->get("/api/scan-tasks/"+taskId+"/source-verifications",10000,[this,taskId,findingId](const QJsonObject &res){
    if(taskId!=m_selectedTaskId) return;
    if(res["status"].toString()!="ok") {QMessageBox::warning(this,"读取失败",res["error"].toObject()["message"].toString());return;}
    const auto runs=res["data"].toObject()["runs"].toArray();
    if(runs.isEmpty()) {QMessageBox::information(this,"尚无执行记录","请先生成并执行验证预案，然后根据实际执行证据复核。");return;}
    QDialog dialog(this); dialog.setWindowTitle("漏洞发现 · 攻击效果复核"); dialog.resize(900,700);
    auto *layout=new QVBoxLayout(&dialog);
    auto *runCombo=new QComboBox;
    for(const auto &value:runs) {const auto run=value.toObject();runCombo->addItem(run["run_id"].toString()+" · "+run["status"].toString());}
    layout->addWidget(runCombo);
    auto *tree=new QTreeWidget; tree->setHeaderLabels({"引用证据","步骤","输出摘要"}); layout->addWidget(tree);
    auto *raw=new QPlainTextEdit;raw->setReadOnly(true);layout->addWidget(raw);
    auto populate=[tree,raw,runs,findingId](int index){
      tree->clear();raw->clear();
      for(const auto &value:runs[index].toObject()["evidence"].toArray()) {
        const auto evidence=value.toObject();
        const auto details=QJsonDocument::fromJson(evidence["evidence_data"].toString().toUtf8()).object();
        if(!details["source_verification"].toObject()["finding_ids"].toArray().contains(QJsonValue(findingId))) continue;
        auto *row=new QTreeWidgetItem(tree);
        row->setText(0,QString::number(evidence["id"].toInt())); row->setData(0,Qt::UserRole,evidence["id"].toInt());
        row->setCheckState(0,Qt::Unchecked);row->setText(1,QString::number(evidence["step_index"].toInt()));
        QString output=evidence["raw_stdout"].toString()+"\n"+evidence["raw_stderr"].toString();
        const auto comparison=details["source_comparison"].toObject();
        if(!comparison.isEmpty()) output="预案判定："+comparison["reason"].toString()+"\n限制："+comparison["limitations"].toString()+"\n\n"+output;
        if(details.contains("source_diagnostics")) output+="\n运行诊断（需要核对真实日志及部署版本）：\n"+QString::fromUtf8(QJsonDocument(details["source_diagnostics"].toObject()).toJson(QJsonDocument::Indented));
        row->setText(2,output.left(150));row->setData(2,Qt::UserRole,output);
      }
      tree->resizeColumnToContents(0);tree->resizeColumnToContents(1);
    };
    connect(runCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),&dialog,populate);populate(0);
    connect(tree,&QTreeWidget::currentItemChanged,&dialog,[raw](QTreeWidgetItem *current,QTreeWidgetItem*){if(current) raw->setPlainText(current->data(2,Qt::UserRole).toString());});
    auto *conclusion=new QComboBox;
    conclusion->addItem("条件不足 / 结论不明确","inconclusive");
    conclusion->addItem("证据支持此问题","supported");
    conclusion->addItem("本次未复现（不代表不存在）","not_reproduced");
    layout->addWidget(conclusion);
    auto *note=new QPlainTextEdit;note->setPlaceholderText("填写判断依据，并勾选支持结论的实际执行证据");note->setMaximumHeight(100);layout->addWidget(note);
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel);
    connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    connect(buttons,&QDialogButtonBox::accepted,&dialog,[&](){
      QJsonArray ids;for(int i=0;i<tree->topLevelItemCount();i++) if(tree->topLevelItem(i)->checkState(0)==Qt::Checked) ids.append(tree->topLevelItem(i)->data(0,Qt::UserRole).toInt());
      if(ids.isEmpty()||note->toPlainText().trimmed().isEmpty()) {QMessageBox::information(&dialog,"需要证据","请勾选执行证据并填写判断依据。");return;}
      QJsonObject body{{"finding_id",findingId},{"run_id",runs[runCombo->currentIndex()].toObject()["run_id"]},
        {"status",conclusion->currentData().toString()},{"evidence_ids",ids},{"note",note->toPlainText()}};
      m_api->post("/api/scan-tasks/"+taskId+"/source-verifications",body,10000,[this,taskId](const QJsonObject &saved){
        if(saved["status"].toString()!="ok") QMessageBox::warning(this,"复核保存失败",saved["error"].toObject()["message"].toString());
        else if(taskId==m_selectedTaskId) loadResults(taskId);
      });
      dialog.accept();
    });
    layout->addWidget(buttons);dialog.exec();
  });
}

void ScanPage::openFindingVerification(const QList<qint64> &ids) {
  if(m_pipelineId.isEmpty() || ids.isEmpty())return;
  auto *dialog=new FindingVerificationDialog(m_api,m_pipelineId,ids,this);
  const QString pipeline=m_pipelineId;
  const int context=m_scopeRevision;
  connect(dialog,&QDialog::finished,this,[this,pipeline,context](){
    if(m_pipelineId!=pipeline || m_scopeRevision!=context)return;
    onRefreshTasks();
    emit findingVerificationChanged(pipeline);
  });
  dialog->setAttribute(Qt::WA_DeleteOnClose);dialog->show();
}
