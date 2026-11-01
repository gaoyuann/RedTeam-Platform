#pragma once
#include "widgets/PageComponents.h"

static void runPageComponentsChecks(const std::function<void(bool, const char *)> &verify)
{
  QWidget host;
  auto *layout = new QVBoxLayout(&host);
  auto *source = new QPushButton("查看详情", &host);
  source->setCheckable(true);
  int clicks = 0;
  QObject::connect(source, &QPushButton::clicked, &host, [&] { ++clicks; });
  auto *menu = PageComponents::actionMenu("更多", {source}, &host);
  layout->addWidget(menu);
  host.show();
  auto *action = menu->menu()->actions().first();
  verify(source->isHidden() && clicks == 0,"menu presentation keeps original actions hidden and never invokes them while building");
  action->trigger();
  verify(clicks == 1 && source->isChecked() && action->isChecked(),"menu forwards one explicit click and mirrors checked state");
  source->setEnabled(false);
  action->trigger();
  verify(!action->isEnabled() && clicks == 1,"disabled business actions remain disabled through the menu");
  source->setEnabled(true); source->setText("刷新详情");
  QMetaObject::invokeMethod(menu->menu(), "aboutToShow", Qt::DirectConnection);
  verify(action->isEnabled() && action->text() == "刷新详情" && clicks == 1,"opening a menu synchronizes labels without executing a request");
  delete source;
  action->trigger();
  verify(!action->isEnabled() && clicks == 1,"a removed action owner cannot be invoked through a surviving menu");
  auto *unparented = new QPushButton("检查详情");
  unparented->setObjectName("unparentedSource");
  layout->addWidget(PageComponents::actionMenu("检查", {unparented}, &host));
  verify(host.findChild<QPushButton *>("unparentedSource") == unparented && unparented->isHidden(),
    "menu owns buttons previously parented by toolbar layouts and preserves lookup and lifetime");
  auto *input = new QLineEdit("未提交的任务名称", &host);
  auto *details = new PageComponents::Disclosure("更多任务选项", input, &host);
  layout->addWidget(details);
  details->show();
  verify(!details->toggle()->isChecked() && !input->isVisible(),"optional fields start collapsed");
  details->toggle()->click();
  verify(input->isVisible() && input->text() == "未提交的任务名称","expansion preserves existing field contents");
  details->toggle()->click();
  verify(!input->isVisible() && input->text() == "未提交的任务名称","collapsing fields preserves unsaved input");
}
