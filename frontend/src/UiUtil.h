#pragma once

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QEvent>
#include <QLabel>

// ── 纯视觉层小工具（不改数据流） ─────────────────────────────────────
namespace UiUtil {

// 表格/树/列表空状态提示：model 无行时在视口居中显示一行浅色说明文字。
// 用法：UiUtil::EmptyHint::attach(table, "暂无扫描任务");
class EmptyHint : public QObject {
public:
  explicit EmptyHint(QObject *parent = nullptr) : QObject(parent) {}

  static void attach(QAbstractItemView *view, const QString &text)
  {
    if (!view || !view->model()) return;
    auto *w = new EmptyHint(view);
    w->m_view = view;
    w->m_label = new QLabel(text, view->viewport());
    w->m_label->setAlignment(Qt::AlignCenter);
    w->m_label->setStyleSheet(
      "color:#b6c2d2; font-size:13px; background:transparent; padding:0 16px;");
    w->m_label->setAttribute(Qt::WA_TransparentForMouseEvents);
    w->m_label->setWordWrap(true);
    w->m_label->show();
    w->m_label->setGeometry(view->viewport()->rect());
    view->viewport()->installEventFilter(w);

    auto update = [w]() {
      QAbstractItemModel *m = w->m_view->model();
      w->m_label->setVisible(!m || m->rowCount() == 0);
    };
    auto *m = view->model();
    QObject::connect(m, &QAbstractItemModel::rowsInserted, w, update);
    QObject::connect(m, &QAbstractItemModel::rowsRemoved, w, update);
    QObject::connect(m, &QAbstractItemModel::modelReset, w, update);
    QObject::connect(m, &QAbstractItemModel::layoutChanged, w, update);
  }

  bool eventFilter(QObject *obj, QEvent *ev) override
  {
    // Resize 跟随视口变化；Paint 兜底同步。用 visibleRegion 而非 rect：
    // 页面内嵌 QScrollArea 导致视图只有部分可见时，提示仍居中于可见区域。
    if (m_label && obj == m_view->viewport() &&
        (ev->type() == QEvent::Resize || ev->type() == QEvent::Paint ||
         ev->type() == QEvent::Show || ev->type() == QEvent::Move)) {
      QWidget *vp = static_cast<QWidget*>(obj);
      QRect r = vp->visibleRegion().boundingRect();
      if (r.width() < vp->width() || r.height() < vp->height())
        m_label->setGeometry(r);
      else
        m_label->setGeometry(vp->rect());
    }
    return QObject::eventFilter(obj, ev);
  }

private:
  QAbstractItemView *m_view = nullptr;
  QLabel *m_label = nullptr;
};

} // namespace UiUtil
