#include <QtWidgets>
#include <QtNetwork>
#include <QtTest/QTest>
#include "ApiClient.h"
#include "pages/SourceScanDetailDialog.h"

static void verify(bool value,const char *message){if(!value)qFatal("%s",message);}
static QJsonObject finding(int id,const QString &file,int line,const QString &risk=QStringLiteral("high")) {
  return {{"id",id},{"result_type","source_finding"},{"severity",risk},
    {"result_data",QJsonObject{{"title",QStringLiteral("输入长度检查缺失")},{"file",file},{"start_line",line},{"end_line",line+1},
      {"severity",risk},{"cwe","CWE-120"},{"reason",QStringLiteral("<b>来自报告的原文依据</b>：复制前未检查目标容量。")},
      {"preconditions",QStringLiteral("输入可控性与部署版本待核对")},{"suggestion",QStringLiteral("核对长度并拒绝超限输入")},{"code",""}}}};
}
static QJsonObject task(const QString &id,const QString &status,const QJsonArray &rows) {
  return {{"scan_task_id",id},{"scan_type","source_scan"},{"status",status},{"results",rows}};
}
static bool waitFor(const std::function<bool()> &condition) {
  for(int i=0;i<200;++i){if(condition())return true;QTest::qWait(10);}return false;
}
static QTreeWidgetItem *fileItem(QTreeWidget *tree,const QString &key) {
  for(QTreeWidgetItemIterator it(tree);*it;++it)if((*it)->data(0,Qt::UserRole).toString()==key)return *it;
  return nullptr;
}
int main(int argc,char **argv) {
  QApplication app(argc,argv);qRegisterMetaType<QList<qint64>>();
  SourceScanDetailDialog view(nullptr,{},"http://fixture.invalid/source/");view.setAttribute(Qt::WA_DeleteOnClose,false);view.resize(1280,760);view.show();
  auto *attack=view.findChild<QPushButton*>("sourceScanAttack");auto *list=view.findChild<QTableWidget*>("sourceScanFindings");
  auto *tree=view.findChild<QTreeWidget*>("sourceScanFileTree");auto *evidence=view.findChild<QPlainTextEdit*>("sourceScanEvidence");
  auto *code=view.findChild<QPlainTextEdit*>("sourceScanCode");auto *severity=view.findChild<QComboBox*>("sourceScanSeverity");
  QList<qint64> emitted;int testRequests=0;
  QObject::connect(&view,&SourceScanDetailDialog::testRequested,&view,[&](const QList<qint64> &ids){emitted=ids;++testRequests;});
  auto a=finding(901,"src/input.c",12),b=finding(902,"src/reader.cpp",25,"medium");
  view.setSnapshots({task("source-1","RUNNING",QJsonArray{QJsonObject{{"result_type","raw_output"},{"result_data",QJsonObject{{"report",QStringLiteral("正在核对源码访问条件，尚未形成漏洞结论。")}}}}})});
  verify(tree->topLevelItemCount()==0 && view.findChild<QPlainTextEdit*>("sourceScanRawReport")->toPlainText().contains(QStringLiteral("访问条件")) && !attack->isEnabled(),"unstructured progress remains readable without inventing file findings");
  auto running=task("source-1","RUNNING",QJsonArray{a});
  running["source_scan"]=QJsonObject{{"phase","parsing"},{"subtask_progress",QJsonObject{{"finished",1},{"total",2}}}};
  running["source_preview"]=QJsonObject{{"findings",QJsonArray{a["result_data"],b["result_data"]}},{"parsing",true},{"parse_errors",QJsonArray{QStringLiteral("阶段模型暂不可用")}}};
  view.setSnapshots({running});
  verify(view.findChild<QLabel*>("sourceScanNotice")->text().contains(QStringLiteral("过程预览")),"preview remains marked as provisional while processing reports");
  verify(view.findChild<QLabel*>("sourceScanNotice")->text().contains(QStringLiteral("正在整理")) && view.findChild<QLabel*>("sourceScanNotice")->text().contains(QStringLiteral("原始报告仍可查看")),"background extraction and partial parser failures remain visible with existing previews");
  verify(!attack->isEnabled(),"an active scan cannot prepare a test");
  verify(list->rowCount()==2 && evidence->toPlainText().contains("<b>"),"progress findings are browsable as literal text");
  verify(code->toPlainText().isEmpty(),"missing source code is not invented from report prose");
  verify(testRequests==0,"viewing progress must not request testing");
  view.setSnapshots({task("source-1","COMPLETED",QJsonArray{a,b})});
  verify(attack->isEnabled(),"completed report enables preparation for the current finding");
  QTreeWidgetItem *reader=nullptr;
  for(QTreeWidgetItemIterator it(tree);*it;++it)if((*it)->data(0,Qt::UserRole).toString().endsWith("src/reader.cpp"))reader=*it;
  verify(reader,"file tree contains report paths");tree->setCurrentItem(reader);
  verify(list->rowCount()==2 && view.findChild<QLabel*>("sourceScanLocation")->text().contains("reader.cpp"),"file selection keeps all task findings available");
  severity->setCurrentIndex(severity->findData("high"));verify(list->rowCount()==1,"severity filter applies across all files");
  verify(testRequests==0,"browsing and filtering findings never prepare or execute tests");
  attack->click();
  verify(testRequests==1 && emitted==QList<qint64>{901},"the current finding proceeds directly to test preparation");
  verify(!view.findChild<QDialog*>("sourceScanAttackSelection"),"preparation does not open a duplicate vulnerability selector");
  view.setSnapshots({running});attack->click();
  verify(testRequests==1,"resuming a scan disables preparation against stale findings");
  severity->setCurrentIndex(0);
  view.setSnapshots({task("source-1","PARTIAL",QJsonArray{b})});
  attack->click();verify(testRequests==2 && emitted==QList<qint64>{902},"saved findings from a partial scan remain testable");
  view.setSnapshots({task("source-1","COMPLETED",QJsonArray{finding(905,"info.c",1,"info")})});
  verify(!attack->isEnabled(),"information findings cannot enter test preparation");
  view.setSnapshots({task("source-1","COMPLETED",QJsonArray{finding(0,"missing-id.c",1)})});
  verify(!attack->isEnabled(),"findings without a persisted identity cannot enter test preparation");
  severity->setCurrentIndex(0);view.setSnapshots({task("source-1","COMPLETED",QJsonArray{a,b})});
  view.selectFinding(901);QTest::qWait(30);if(qEnvironmentVariable("QT_SCALE_FACTOR")=="1")view.grab().save("/tmp/redteam-source-scan-three-pane.png");
  view.setSnapshots({task("source-1","COMPLETED",QJsonArray{finding(903,"/src/same.c",4),finding(904,"src/same.c",8)})});
  view.selectFinding(903);verify(view.findChild<QLabel*>("sourceScanLocation")->text().startsWith("/src/same.c"),"absolute file retains its own identity");
  view.selectFinding(904);verify(view.findChild<QLabel*>("sourceScanLocation")->text().startsWith("src/same.c"),"relative file is not merged into absolute path");
  auto failed=task("source-1","FAILED",{});failed["error_message"]=QStringLiteral("CScan 未能取得目标源码");view.setSnapshots({failed});
  verify(!attack->isEnabled() && view.findChild<QLabel*>("sourceScanNotice")->text().contains(QStringLiteral("未能取得目标源码")),"actual source access errors remain visible after scan failure");

  SourceScanDetailDialog navigation(nullptr,{"tree-task"},"project");navigation.setAttribute(Qt::WA_DeleteOnClose,false);navigation.resize(1280,760);navigation.show();
  auto treeTask=task("tree-task","COMPLETED",QJsonArray{
    finding(4001,"project/src/main.cpp",2),finding(4002,"project/generated/reader.cpp",4,"medium"),
    finding(4003,"project/generated/reader.cpp",8,"low"),finding(4004,"/project/generated/reader.cpp",3,"low")});
  QJsonArray sourceFiles{
    QJsonObject{{"id",1},{"path","/work/src/project/src/main.cpp"}},
    QJsonObject{{"id",2},{"path","/work/src/project/include/util.h"}},
    QJsonObject{{"id",3},{"path","/work/src/project/README.h"}},
    QJsonObject{{"id",4},{"path","/work/src/group/a.cpp"}},
    QJsonObject{{"id",5},{"path","/work/src/project/generated/helper.h"}}};
  for(int i=0;i<60;++i)sourceFiles.append(QJsonObject{{"id",10+i},{"path",QStringLiteral("/work/src/project/src/module_%1.cpp").arg(i,2,10,QChar('0'))}});
  treeTask["source_files"]=sourceFiles;navigation.setSnapshots({treeTask});
  auto *navTree=navigation.findChild<QTreeWidget*>("sourceScanFileTree");
  auto *search=navigation.findChild<QLineEdit*>("sourceScanFileSearch");
  auto *mainFile=fileItem(navTree,"tree-task\nproject/src/main.cpp");
  auto *reportFile=fileItem(navTree,"tree-task\nproject/generated/reader.cpp");
  auto *absoluteFile=fileItem(navTree,"tree-task\n/project/generated/reader.cpp");
  verify(mainFile && reportFile && absoluteFile,"snapshots and both report path kinds remain independently navigable");
  verify(reportFile->text(0)=="reader.cpp" && reportFile->parent()->text(0)=="generated"
    && reportFile->parent()->parent()->text(0)=="project","report paths form directories instead of flat full-path labels");
  verify(navTree->topLevelItemCount()==3 && mainFile->parent()->parent()->parent()==nullptr
    && reportFile->parent()->parent()==mainFile->parent()->parent(),"snapshot and report paths share the real project root without provenance wrapper directories");
  verify(reportFile->parent()==fileItem(navTree,"tree-task\nproject/generated/helper.h")->parent(),"report-only and saved files in the same directory share one directory node");
  verify(reportFile->toolTip(0).contains(QStringLiteral("未匹配源码正文"))
    && mainFile->toolTip(0).contains(QStringLiteral("已保存源码快照")),"file tooltips distinguish available source from report-only locations within one tree");
  verify(navigation.findChild<QLabel*>("sourceScanFileSummary")->text().contains(QStringLiteral("2 个报告定位")),"duplicate report locations count as one file while absolute paths stay separate");
  verify(!mainFile->icon(0).isNull() && !mainFile->parent()->icon(0).isNull()
    && mainFile->toolTip(0).contains("/work/src/project/src/main.cpp"),"navigation provides file and folder drawings and the full source path");
  verify(fileItem(navTree,"tree-task\ngroup/a.cpp")->parent()->text(0)=="group","a real directory name cannot collide with a navigation group key");
  auto *project=mainFile->parent()->parent();
  verify(project->child(0)->text(0)=="generated" && project->child(1)->text(0)=="include"
    && project->child(project->childCount()-1)->text(0)=="README.h","directories from both sources sort together ahead of root-level files");
  navTree->expandAll();
  auto *manual=fileItem(navTree,"tree-task\nproject/include/util.h");navTree->setCurrentItem(manual);
  reportFile->parent()->setExpanded(false);
  QTest::qWait(20);navTree->verticalScrollBar()->setValue(navTree->verticalScrollBar()->maximum()/2);
  const int treeScroll=navTree->verticalScrollBar()->value();verify(treeScroll>0,"large source navigation has a meaningful scroll position");
  navigation.setSnapshots({treeTask});
  verify(navTree->currentItem()->data(0,Qt::UserRole).toString()=="tree-task\nproject/include/util.h","refresh preserves a manually browsed source file instead of jumping to the selected finding");
  reportFile=fileItem(navTree,"tree-task\nproject/generated/reader.cpp");
  verify(!reportFile->parent()->isExpanded() && navTree->verticalScrollBar()->value()==treeScroll,"refresh preserves collapsed directories and tree scroll position");
  search->setText("INCLUDE/UTIL.H");
  manual=fileItem(navTree,"tree-task\nproject/include/util.h");mainFile=fileItem(navTree,"tree-task\nproject/src/main.cpp");
  verify(!manual->isHidden() && manual->parent()->isExpanded() && mainFile->isHidden()
    && fileItem(navTree,"tree-task\n/project/generated/reader.cpp")->isHidden(),"case-insensitive full-path search reveals only matching file branches");
  navigation.setSnapshots({treeTask});
  verify(search->text()=="INCLUDE/UTIL.H" && fileItem(navTree,"tree-task\nproject/src/main.cpp")->isHidden(),"refresh preserves the active file filter");
  search->clear();
  verify(!fileItem(navTree,"tree-task\nproject/src/main.cpp")->isHidden()
    && !fileItem(navTree,"tree-task\nproject/generated/reader.cpp")->parent()->isExpanded(),"clearing search restores the previous directory expansion state");
  auto *navFindings=navigation.findChild<QTableWidget*>("sourceScanFindings");
  search->setText("util.h");
  QTest::mouseClick(navFindings->viewport(),Qt::LeftButton,Qt::NoModifier,navFindings->visualItemRect(navFindings->item(0,0)).center());
  verify(search->text().isEmpty() && navTree->currentItem()==fileItem(navTree,"tree-task\nproject/src/main.cpp"),"clicking the already selected finding restores its file and clears a conflicting navigation filter");
  navigation.selectFinding(4002);
  verify(navTree->currentItem()==fileItem(navTree,"tree-task\nproject/generated/reader.cpp")
    && navigation.findChild<QPlainTextEdit*>("sourceScanCode")->toPlainText().isEmpty(),"finding navigation still selects report-only files without inventing source bodies");
  auto resolvedTreeTask=treeTask;auto resolvedFiles=sourceFiles;
  resolvedFiles.append(QJsonObject{{"id",90},{"path","/work/src/project/generated/reader.cpp"}});
  resolvedTreeTask["source_files"]=resolvedFiles;
  navigation.setSnapshots({resolvedTreeTask});
  auto *resolvedFile=fileItem(navTree,"tree-task\nproject/generated/reader.cpp");
  verify(resolvedFile && resolvedFile->parent()->childCount()==2 && navTree->topLevelItemCount()==3
    && resolvedFile->toolTip(0).contains(QStringLiteral("已保存源码快照")),"newly captured report-only files update in their existing directory without duplicate branches");
  auto secondTreeTask=treeTask;secondTreeTask["scan_task_id"]="other-tree-task";
  navigation.setSnapshots({treeTask,secondTreeTask});
  verify(fileItem(navTree,"tree-task\nproject/src/main.cpp")!=fileItem(navTree,"other-tree-task\nproject/src/main.cpp")
    && navTree->topLevelItemCount()==2,"identical source paths from different scans retain separate navigation branches");

  QTcpServer server;int gets=0,mutations=0;bool fail=false;
  QObject::connect(&server,&QTcpServer::newConnection,&server,[&](){
    while(auto *socket=server.nextPendingConnection())QObject::connect(socket,&QTcpSocket::readyRead,socket,[&,socket](){
      auto buffer=socket->property("buffer").toByteArray()+socket->readAll();socket->setProperty("buffer",buffer);
      if(!buffer.contains("\r\n\r\n") || socket->property("handled").toBool())return;socket->setProperty("handled",true);
      const auto request=buffer.left(buffer.indexOf('\r')).split(' ');if(request[0]=="GET")++gets;else ++mutations;
      const QString id=QString::fromUtf8(request[1]).section('/',-1);QJsonArray rows;
      for(int i=0;i<(id=="source-a"?501:1);++i)rows.append(finding(id=="source-a"?1000+i:2000,"module/"+id+".c",i+1));
      if(request[1].contains("/source-file?")) {
        const auto payload=QJsonDocument(QJsonObject{{"status","ok"},{"data",QJsonObject{{"sha256","copy-hash"},{"content","int main() {\n return 0;\n}\n"},{"captured_at","fixture-time"}}}}).toJson(QJsonDocument::Compact);
        socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(payload.size())+"\r\n\r\n"+payload);socket->disconnectFromHost();return;
      }
      const auto body=QJsonDocument(fail?QJsonObject{{"status","error"}}:QJsonObject{{"status","ok"},{"data",task(id,"COMPLETED",rows)}}).toJson(QJsonDocument::Compact);
      socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+QByteArray::number(body.size())+"\r\n\r\n"+body);socket->disconnectFromHost();QObject::connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
    });
  });
  verify(server.listen(QHostAddress::LocalHost,0),"mock server starts");
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  SourceScanDetailDialog complete(&api,{"source-a","source-b"},"fixture");complete.setAttribute(Qt::WA_DeleteOnClose,false);complete.show();
  auto *completeAttack=complete.findChild<QPushButton*>("sourceScanAttack");
  complete.selectFinding(1250);
  verify(waitFor([&](){return completeAttack->isEnabled();}),"full task details loaded");
  auto *large=complete.findChild<QTableWidget*>("sourceScanFindings");
  verify(large && large->rowCount()==502,"the detail finding list loads beyond the aggregate page limit");
  verify(large->item(large->currentRow(),0)->data(Qt::UserRole+1).toString().contains("|1250|"),"a requested finding is selected after asynchronous details load");
  verify(gets==2 && mutations==0,"opening and selecting source evidence perform only scoped reads");
  auto copied=task("source-a","COMPLETED",{});
  copied["source_files"]=QJsonArray{QJsonObject{{"id",42},{"path","/work/src/clean.c"},{"sha256","copy-hash"}}};
  complete.setSnapshots({copied});
  auto *copyCode=complete.findChild<QPlainTextEdit*>("sourceScanCode");
  verify(waitFor([&](){return copyCode->toPlainText().contains("int main()");}),"files without findings load their actual complete saved body");
  verify(complete.findChild<QTableWidget*>("sourceScanFindings")->rowCount()==0,"a saved source file does not invent findings");

  auto matched=finding(3001,"clean.c",2);
  auto unmatched=finding(3002,"missing.c",1,"medium");
  copied["results"]=QJsonArray{matched,unmatched};
  complete.setSnapshots({copied});complete.selectFinding(3001);
  verify(waitFor([&](){return copyCode->extraSelections().size()==2;}),"relative report path matches /work/src snapshot and highlights range");
  verify(copyCode->textCursor().blockNumber()==1,"finding navigates to requested source line");
  verify(complete.findChild<QLabel*>("sourceScanSummary")->text().contains(QStringLiteral("源码快照 1 个文件")),"unmatched report paths do not inflate snapshot count");
  complete.selectFinding(3002);
  verify(copyCode->toPlainText().isEmpty() && copyCode->extraSelections().isEmpty(),"unmatched finding clears previous source and highlights");
  complete.setSnapshots({copied});
  verify(complete.findChild<QLabel*>("sourceScanLocation")->text()=="missing.c","refresh preserves selected finding");
  complete.selectFinding(3001);
  verify(waitFor([&](){return !copyCode->toPlainText().isEmpty();}),"matched file remains selectable after unmatched result");
  fail=true;complete.refresh();verify(waitFor([&](){return complete.findChild<QPushButton*>("sourceScanRefresh")->isEnabled();}),"refresh failure completes");
  verify(!completeAttack->isEnabled(),"failed refresh cannot authorize testing against stale data");
  fail=false;
  auto preview=task("source-a","COMPLETED",QJsonArray{finding(5001,"sample/src/main.cpp",2),finding(5002,"sample/src/reader.cpp",8,"medium")});
  preview["source_files"]=QJsonArray{
    QJsonObject{{"id",42},{"path","/work/src/sample/src/main.cpp"},{"sha256","copy-hash"}},
    QJsonObject{{"id",43},{"path","/work/src/sample/include/config.h"},{"sha256","copy-hash"}}};
  complete.setSnapshots({preview});
  verify(waitFor([&](){return copyCode->textCursor().blockNumber()==1 && !copyCode->toPlainText().isEmpty();}),"saved source remains loadable after a failed refresh and navigation changes");
  if(qEnvironmentVariable("QT_SCALE_FACTOR")=="1") {
    complete.resize(1280,760);complete.findChild<QTreeWidget*>("sourceScanFileTree")->expandAll();
    QTest::qWait(20);complete.grab().save("/tmp/redteam-source-navigation.png");
  }
  return 0;
}
