#include "StatsSummaryCard.h"

#include <QJsonObject>
#include <QPainter>
#include <QPainterPath>
#include <QtMath>
#include <algorithm>

namespace {
// 状态色
const QColor kOkColor(34, 197, 94);       // #22c55e
const QColor kFailColor(239, 68, 68);     // #ef4444
const QColor kActiveColor(59, 130, 246);  // #3b82f6
const QColor kOtherColor(148, 163, 184);  // #94a3b8
const QColor kTrackColor(226, 232, 240);  // #e2e8f0
const QColor kTextColor(51, 65, 85);      // #334155
const QColor kMutedColor(100, 116, 139);  // #64748b
}  // namespace

StatsSummaryCard::StatsSummaryCard(QWidget *parent) : QWidget(parent) {
  setMinimumHeight(190);
}

void StatsSummaryCard::setRuns(const QJsonArray &runs) {
  m_total = m_ok = m_fail = m_active = m_other = 0;
  m_topPbs.clear();
  QMap<QString, PbStat> byPb;
  for (const auto &v : runs) {
    auto r = v.toObject();
    const QString status = r["status"].toString().toUpper();
    const QString pb = r["playbook_id"].toString();
    if (pb.isEmpty()) continue;
    auto &s = byPb[pb];
    s.id = pb;
    if (status == "COMPLETED") { m_ok++; s.ok++; }
    else if (status == "FAILED" || status == "ABORTED") { m_fail++; s.fail++; }
    else if (status == "RUNNING" || status == "PENDING" || status == "AWAITING_APPROVAL") { m_active++; s.other++; }
    else { m_other++; s.other++; }
  }
  m_total = m_ok + m_fail + m_active + m_other;
  m_topPbs = byPb.values().toVector();
  std::sort(m_topPbs.begin(), m_topPbs.end(), [](const PbStat &a, const PbStat &b) {
    return a.total() > b.total();
  });
  if (m_topPbs.size() > 5) m_topPbs.resize(5);
  update();
}

void StatsSummaryCard::paintEvent(QPaintEvent *) {
  QPainter p(this);
  p.setRenderHint(QPainter::Antialiasing, true);

  // 卡片底
  p.setPen(Qt::NoPen);
  p.setBrush(QColor("#ffffff"));
  p.drawRoundedRect(rect().adjusted(1, 1, -1, -1), 10, 10);
  p.setPen(QColor("#dbe3ef"));
  p.setBrush(Qt::NoBrush);
  p.drawRoundedRect(rect().adjusted(1, 1, -2, -2), 10, 10);

  QFont titleFont = font();
  titleFont.setPointSize(font().pointSize() + 1);
  titleFont.setBold(true);
  p.setFont(titleFont);
  p.setPen(QColor("#1e293b"));
  p.drawText(rect().adjusted(18, 10, -18, -10), Qt::AlignTop | Qt::AlignLeft, QStringLiteral("执行状态统计"));

  if (m_total == 0) {
    p.setFont(font());
    p.setPen(kMutedColor);
    p.drawText(rect(), Qt::AlignCenter, QStringLiteral("暂无执行记录 — 执行任务后此处展示统计"));
    return;
  }

  // ── 左：状态环形图（下方留 26px 图例带）──────────────────────────
  const QRect cardRect = rect().adjusted(18, 34, -18, -12);
  const QRect donutZone = cardRect.adjusted(0, 0, 0, -26);
  const int r = qMin(58, donutZone.height() / 2);
  const QRect donutRect(donutZone.left(), donutZone.center().y() - r, r * 2, r * 2);

  struct Seg { int v; QColor c; };
  const QVector<Seg> segs = {
    {m_ok, kOkColor}, {m_fail, kFailColor}, {m_active, kActiveColor}, {m_other, kOtherColor}};
  const qreal totalF = m_total;
  qreal startAngle = 90 * 16;
  QPen segPen(Qt::NoPen);
  for (const auto &seg : segs) {
    if (seg.v <= 0) continue;
    const qreal span = 360.0 * seg.v / totalF;
    p.setPen(segPen);
    p.setBrush(seg.c);
    // 环形：外弧 + 内孔，用 painter path
    QPainterPath ring;
    ring.arcMoveTo(donutRect, startAngle / 16.0);
    ring.arcTo(donutRect, startAngle / 16.0, -span);
    const qreal holeRatio = 0.62;
    QRect inner(donutRect.x() + donutRect.width() * (1 - holeRatio) / 2,
                donutRect.y() + donutRect.height() * (1 - holeRatio) / 2,
                donutRect.width() * holeRatio, donutRect.height() * holeRatio);
    ring.arcTo(inner, (startAngle - span * 16) / 16.0, span);
    ring.closeSubpath();
    p.drawPath(ring);
    startAngle -= span * 16;
  }

  // 环心：成功率（上）+ 小标签（下），都收在内孔里
  const int decided = m_ok + m_fail;
  const int rate = decided > 0 ? qRound(100.0 * m_ok / decided) : 0;
  QFont bigFont = font();
  bigFont.setPointSize(font().pointSize() + 4);
  bigFont.setBold(true);
  p.setFont(bigFont);
  p.setPen(kTextColor);
  p.drawText(donutRect.adjusted(0, -9, 0, -9), Qt::AlignCenter, QString("%1%").arg(rate));
  QFont smallFont = font();
  smallFont.setPointSize(qMax(7, font().pointSize() - 2));
  p.setFont(smallFont);
  p.setPen(kMutedColor);
  p.drawText(QRect(donutRect.left(), donutRect.center().y() + 7, donutRect.width(), 14),
             Qt::AlignHCenter | Qt::AlignTop, QStringLiteral("成功率"));

  // 图例（环下方一行）
  p.setFont(smallFont);
  int ly = donutRect.bottom() + 8;
  const QVector<QPair<QString, QPair<int, QColor>>> legend = {
    {QStringLiteral("成功"), {m_ok, kOkColor}},
    {QStringLiteral("失败"), {m_fail, kFailColor}},
    {QStringLiteral("进行中"), {m_active, kActiveColor}},
    {QStringLiteral("其他"), {m_other, kOtherColor}}};
  int lx = donutRect.left();
  for (const auto &item : legend) {
    if (item.second.first <= 0) continue;
    p.setBrush(item.second.second);
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(lx, ly, 9, 9, 2, 2);
    p.setPen(kMutedColor);
    const QString txt = QStringLiteral("%1 %2").arg(item.first).arg(item.second.first);
    const int tw = QFontMetrics(smallFont).horizontalAdvance(txt);
    p.drawText(lx + 14, ly - 1, tw + 2, 14, Qt::AlignLeft | Qt::AlignVCenter, txt);
    lx += 14 + tw + 16;
  }

  // ── 右：预案结果条形榜（前5）────────────────────────────────────
  const int listLeft = donutRect.right() + 34;
  const QRect listRect(listLeft, cardRect.top(), cardRect.right() - listLeft, cardRect.height());
  p.setFont(smallFont);
  p.setPen(kMutedColor);
  p.drawText(listRect.adjusted(0, -16, 0, 0), Qt::AlignTop | Qt::AlignLeft, QStringLiteral("预案执行榜 · 按次数（绿=成功 红=失败 灰=其他）"));

  if (m_topPbs.isEmpty()) return;
  const int rowH = qMin(24, (listRect.height() - 10) / m_topPbs.size());
  int maxTotal = 1;
  for (const auto &pb : m_topPbs) maxTotal = qMax(maxTotal, pb.total());
  const int barMaxW = qMax(40, listRect.width() - 250);
  int y = listRect.top() + 10;

  QFont nameFont = font();
  nameFont.setPointSize(qMax(7, font().pointSize() - 1));
  p.setFont(nameFont);
  for (const auto &pb : m_topPbs) {
    // 预案名
    QString name = pb.id;
    const int nameW = 168;
    name = QFontMetrics(nameFont).elidedText(name, Qt::ElideRight, nameW);
    p.setPen(kTextColor);
    p.drawText(QRect(listRect.left(), y, nameW, rowH), Qt::AlignLeft | Qt::AlignVCenter, name);
    // 条形
    const int barX = listRect.left() + nameW + 8;
    const int barH = qMin(12, rowH - 8);
    const int barY = y + (rowH - barH) / 2;
    p.setPen(Qt::NoPen);
    p.setBrush(kTrackColor);
    p.drawRoundedRect(barX, barY, barMaxW, barH, barH / 2.0, barH / 2.0);
    const qreal unit = qreal(barMaxW) / maxTotal;
    qreal bx = barX;
    const QVector<QPair<int, QColor>> parts = {{pb.ok, kOkColor}, {pb.fail, kFailColor}, {pb.other, kOtherColor}};
    for (const auto &part : parts) {
      if (part.first <= 0) continue;
      const int w = qMax(2, qRound(part.first * unit));
      p.setBrush(part.second);
      p.drawRoundedRect(QRectF(bx, barY, w, barH), barH / 2.0, barH / 2.0);
      bx += w;
    }
    // 计数
    p.setPen(kMutedColor);
    p.drawText(QRect(barX + barMaxW + 8, y, 70, rowH), Qt::AlignLeft | Qt::AlignVCenter,
               QString("%1/%2").arg(pb.ok).arg(pb.total()));
    y += rowH;
  }
}
