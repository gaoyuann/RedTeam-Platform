#pragma once

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QEvent>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QJsonObject>
#include <QApplication>
#include <QClipboard>
#include <QToolTip>
#include <QCursor>
#include <QRegularExpression>
#include "Theme.h"

// ── 纯视觉层小工具（不改数据流） ─────────────────────────────────────
namespace UiUtil {

inline QString taskIdentifier(const QJsonObject &task)
{
  const auto number = task.value("task_no").toString().trimmed();
  return number.isEmpty() ? task.value("pipeline_id").toString() : number;
}

inline QString taskIdentifierTip(const QJsonObject &task)
{
  return task.value("task_no").toString().isEmpty()
      ? QStringLiteral("%1\n任务编号尚未提供，当前显示原任务ID。").arg(taskIdentifier(task))
      : taskIdentifier(task);
}

inline bool isTaskIdentifier(const QString &text)
{
  static const QRegularExpression pattern(QStringLiteral("^(TASK-[0-9]{8}-[0-9]{6,}|pipe_[a-z0-9-]+)$"), QRegularExpression::CaseInsensitiveOption);
  return pattern.match(text.trimmed()).hasMatch();
}

inline void copyTaskIdentifier(const QString &identifier)
{
  if (identifier.isEmpty()) return;
  QApplication::clipboard()->setText(identifier);
  QToolTip::showText(QCursor::pos(), QStringLiteral("任务ID已复制"));
}

inline QString taskStatusText(const QString &status)
{
  if (status == "created") return QStringLiteral("待运行");
  if (status == "running") return QStringLiteral("进行中");
  if (status == "paused") return QStringLiteral("已暂停");
  if (status == "awaiting_approval") return QStringLiteral("待确认");
  if (status == "completed") return QStringLiteral("已完成");
  if (status == "failed") return QStringLiteral("失败");
  if (status == "cancelled") return QStringLiteral("已取消");
  return status.isEmpty() ? QStringLiteral("未知") : QStringLiteral("未知状态：%1").arg(status);
}

inline void styleToolbarButton(QPushButton *button)
{
  button->setFixedHeight(Theme::ControlHeight);
  button->setCursor(Qt::PointingHandCursor);
  button->setStyleSheet(Theme::ToolbarButtonStyle);
}


inline void styleDialogButtons(QDialogButtonBox *box)
{
  for (auto *button : box->buttons()) {
    const auto role = box->buttonRole(button);
    if (role == QDialogButtonBox::AcceptRole || role == QDialogButtonBox::ApplyRole)
      button->setProperty("primary", true);
    if (role == QDialogButtonBox::DestructiveRole)
      button->setProperty("danger", true);
  }
  if (auto *cancel = box->button(QDialogButtonBox::Cancel))
    cancel->setText(QStringLiteral("取消"));
  box->setStyleSheet(Theme::ButtonStyle);
}

// 表格/树/列表空状态提示：model 无行时在视口居中显示一行浅色说明文字。
// 用法：UiUtil::EmptyHint::attach(table, "暂无扫描任务");
class EmptyHint : public QObject {
public:
  explicit EmptyHint(QObject *parent = nullptr) : QObject(parent) {}

  static void attach(QAbstractItemView *view, const QString &text)
  {
    if (!view || !view->model()) return;
    if (auto *existing = view->viewport()->findChild<QLabel *>(QStringLiteral("itemViewEmptyHint"), Qt::FindDirectChildrenOnly)) {
      existing->setProperty("emptyText", text);
      reset(view);
      return;
    }
    auto *label = new QLabel(text, view->viewport());
    label->setObjectName(QStringLiteral("itemViewEmptyHint"));
    label->setProperty("emptyText", text);
    label->setTextFormat(Qt::PlainText);
    auto *hint = new EmptyHint(label);
    hint->m_viewport = view->viewport();
    hint->m_label = label;
    label->setAlignment(Qt::AlignCenter);
    label->setStyleSheet(
      "color:#64748b; font-size:13px; background:transparent; padding:0 16px;");
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

  static void setState(QAbstractItemView *view, const QString &text, bool error = false)
  {
    if (!view) return;
    auto *label = view->viewport()->findChild<QLabel *>(QStringLiteral("itemViewEmptyHint"), Qt::FindDirectChildrenOnly);
    if (!label) return;
    label->setText(text);
    label->setStyleSheet(QStringLiteral("color:%1; font-size:13px; background:transparent; padding:0 16px;")
        .arg(error ? QStringLiteral("#b42318") : QStringLiteral("#64748b")));
  }

  static void reset(QAbstractItemView *view)
  {
    if (!view) return;
    auto *label = view->viewport()->findChild<QLabel *>(QStringLiteral("itemViewEmptyHint"), Qt::FindDirectChildrenOnly);
    if (label) setState(view, label->property("emptyText").toString());
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
