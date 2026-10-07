#pragma once

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QEvent>
#include <QLabel>
#include <QPointer>

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
    auto *label = new QLabel(text, view->viewport());
    auto *hint = new EmptyHint(label);
    hint->m_viewport = view->viewport();
    hint->m_label = label;
    label->setAlignment(Qt::AlignCenter);
    label->setStyleSheet(
      "color:#b6c2d2; font-size:13px; background:transparent; padding:0 16px;");
    label->setAttribute(Qt::WA_TransparentForMouseEvents);
    label->setWordWrap(true);
    label->setGeometry(view->viewport()->rect());
    view->viewport()->installEventFilter(hint);

    QPointer<QAbstractItemModel> model(view->model());
    auto update = [hint, model]() {
      if (hint->m_label)
        hint->m_label->setVisible(!model || model->rowCount() == 0);
    };
    QObject::connect(model.data(), &QAbstractItemModel::rowsInserted, hint, update);
    QObject::connect(model.data(), &QAbstractItemModel::rowsRemoved, hint, update);
    QObject::connect(model.data(), &QAbstractItemModel::modelReset, hint, update);
    QObject::connect(model.data(), &QAbstractItemModel::layoutChanged, hint, update);
    update();
  }

  bool eventFilter(QObject *obj, QEvent *ev) override
  {
    // Resize 跟随视口变化；Paint 兜底同步。用 visibleRegion 而非 rect：
    // 页面内嵌 QScrollArea 导致视图只有部分可见时，提示仍居中于可见区域。
    if (m_label && m_viewport && obj == m_viewport.data() &&
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
  QPointer<QWidget> m_viewport;
  QPointer<QLabel> m_label;
};

} // namespace UiUtil
