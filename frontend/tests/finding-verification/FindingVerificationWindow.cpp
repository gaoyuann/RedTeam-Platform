#include <QtWidgets>
#include <QtTest/QTest>
#include "ApiClient.h"
#include "AppStyle.h"
#include "UiTypography.h"
#include "pages/FindingVerificationDialog.h"

static void verify(bool condition,const char *message) {if(!condition)qFatal("%s",message);}

int main(int argc,char **argv) {
  QApplication app(argc,argv);app.setStyle("Fusion");app.setFont(Theme::uiFont());
  app.setStyleSheet(Theme::GlobalStyle+Theme::PageStyle);
  ApiClient api("http://127.0.0.1:1");
  QWidget parent;parent.resize(1000,700);parent.show();
  QWidget page(&parent);page.show();
  FindingVerificationDialog dialog(&api,"TASK-20261101-000004",{},&page);
  dialog.show();QTest::qWait(30);
  verify(dialog.windowModality()==Qt::WindowModal && QApplication::activeModalWidget()==&dialog,"workspace blocks interaction with its parent window");
  verify(dialog.windowHandle()->transientParent()==parent.windowHandle(),"native dialog belongs to the top-level window instead of its nested page");
  const QRect available=dialog.screen()->availableGeometry();
  qInfo()<<"available"<<available<<"frame"<<dialog.frameGeometry()<<"minimum"<<dialog.minimumSize();
  verify(available.contains(dialog.frameGeometry()),"initial frame and title must fit the available screen");
  verify(dialog.width()<=1120 && dialog.height()<=720,"initial window must use the compact default size");
  verify(dialog.isSizeGripEnabled(),"window exposes a resize grip");
  auto *queue=dialog.findChild<QLabel*>("findingQueueSummary");
  queue->setText(QString("Cookie PHPSESSID created without the httponly flag; ").repeated(100));
  QApplication::processEvents();
  verify(available.contains(dialog.frameGeometry()),"long queue feedback must not expand the window beyond the screen");
  auto *title=dialog.findChild<QLabel*>("findingWindowTitle");
  verify(title && title->isVisible(),"a visible title provides a drag handle inside the window");
  const QPoint start=title->mapToGlobal(QPoint(20,title->height()/2));
  const QPoint before=dialog.pos(),delta(30,20);
  QMouseEvent press(QEvent::MouseButtonPress,QPointF(title->mapFromGlobal(start)),QPointF(start),Qt::LeftButton,Qt::LeftButton,Qt::NoModifier);
  QApplication::sendEvent(title,&press);
  QMouseEvent move(QEvent::MouseMove,QPointF(title->mapFromGlobal(start+delta)),QPointF(start+delta),Qt::NoButton,Qt::LeftButton,Qt::NoModifier);
  QApplication::sendEvent(title,&move);
  QMouseEvent release(QEvent::MouseButtonRelease,QPointF(title->mapFromGlobal(start+delta)),QPointF(start+delta),Qt::LeftButton,Qt::NoButton,Qt::NoModifier);
  QApplication::sendEvent(title,&release);
  verify(dialog.pos()==before+delta,"dragging the title must move the window");
  dialog.setWindowTitle("Updated task title");verify(title->text()==dialog.windowTitle(),"drag title follows task identity updates");
  auto *maximize=dialog.findChild<QToolButton*>("findingWindowMaximize");
  maximize->click();QTest::qWait(20);verify(dialog.isMaximized(),"maximize control works");
  maximize->click();QTest::qWait(20);verify(!dialog.isMaximized(),"restore control works");
  verify(QApplication::activeModalWidget()==&dialog && dialog.windowHandle()->transientParent()==parent.windowHandle(),"maximize and restore preserve modal ownership");
  for(auto *tabs:dialog.findChildren<QTabWidget*>())if(tabs->tabText(0)=="漏洞与测试")tabs->setCurrentIndex(2);
  dialog.resize(800,480);QTest::qWait(20);
  verify(dialog.width()<=800 && dialog.height()<=480,"results allow a smaller manually resized window");
  auto *scroll=dialog.findChild<QScrollArea*>("findingResultsScroll");
  verify(scroll && scroll->isVisible(),"results remain accessible inside a scroll area");
  for(auto *button:dialog.findChildren<QPushButton*>())if(button->text()=="关闭窗口") {
    verify(dialog.rect().contains(QRect(button->mapTo(&dialog,QPoint()),button->size())),"close action remains within the window");
    dialog.resize(320,220);QTest::qWait(20);
    auto *workspace=dialog.findChild<QScrollArea*>("findingWorkspaceScroll");
    workspace->ensureWidgetVisible(button,0,0);QApplication::processEvents();
    verify(workspace->viewport()->rect().contains(QRect(button->mapTo(workspace->viewport(),QPoint()),button->size())),"footer remains reachable by scrolling on a very small desktop");
    verify(title->isVisible() && dialog.rect().contains(QRect(title->mapTo(&dialog,QPoint()),title->size())),"drag title remains reachable while the workspace scrolls");
  }
  dialog.resize(800,480);QTest::qWait(20);
  const auto capture=qEnvironmentVariable("REDTEAM_WINDOW_SCREENSHOT_DIR");
  if(!capture.isEmpty()){QDir().mkpath(capture);verify(dialog.grab().save(capture+"/finding-window.png"),"window screenshot is saved");}
  dialog.findChild<QToolButton*>("findingWindowClose")->click();
  verify(!dialog.isVisible(),"title close control closes the dialog");
  return 0;
}
