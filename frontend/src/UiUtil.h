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
    // The hint dies with the viewport, before the view model is destroyed.
    auto *w = new EmptyHint(view->viewport());
    w->m_viewport = view->viewport();
    w->m_label = new QLabel(text, view->viewport());
    w->m_label->setAlignment(Qt::AlignCenter);
    w->m_label->setStyleSheet(
      "color:#64748b; font-size:13px; background:transparent; padding:0 16px;");
    w->m_label->setAttribute(Qt::WA_TransparentForMouseEvents);
    w->m_label->setWordWrap(true);
    w->m_label->show();
    w->m_label->setGeometry(view->viewport()->rect());
    view->viewport()->installEventFilter(w);

    auto update = [w, model = QPointer<QAbstractItemModel>(view->model())]() {
      if (!w->m_label) return;
      w->m_label->setVisible(!model || model->rowCount() == 0);
    };
    auto *m = view->model();
    QObject::connect(m, &QAbstractItemModel::rowsInserted, w, update);
    QObject::connect(m, &QAbstractItemModel::rowsRemoved, w, update);
    QObject::connect(m, &QAbstractItemModel::modelReset, w, update);
    QObject::connect(m, &QAbstractItemModel::layoutChanged, w, update);
    update();
  }

  bool eventFilter(QObject *obj, QEvent *ev) override
  {
    // Layout changes are handled outside paint events; painting must not
    // schedule another child geometry/repaint cycle when a panel is uncovered.
    if (m_label && obj == m_viewport &&
        (ev->type() == QEvent::Resize || ev->type() == QEvent::Show)) {
      const QRect r = static_cast<QWidget *>(obj)->rect();
      if (m_label->geometry() != r) m_label->setGeometry(r);
    }
    return QObject::eventFilter(obj, ev);
  }

private:
  QPointer<QWidget> m_viewport;
  QPointer<QLabel> m_label;
};

} // namespace UiUtil
