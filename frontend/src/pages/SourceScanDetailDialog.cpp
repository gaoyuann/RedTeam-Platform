#include "SourceScanDetailDialog.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QtWidgets>
#include <QJsonDocument>
#include <QPointer>
#include <algorithm>

QJsonObject SourceScanDetailDialog::resultData(const QJsonObject &row) {
  auto data=row["result_data"].isObject()?row["result_data"].toObject():QJsonDocument::fromJson(row["result_data"].toString().toUtf8()).object();
  if(data["severity"].toString().isEmpty())data["severity"]=row["severity"];
  return data;
}
QString SourceScanDetailDialog::fileKey(const QJsonObject &row) {
  return row["scan_task_id"].toString()+"\n"+resultData(row)["file"].toString();
}
QString SourceScanDetailDialog::riskText(const QString &risk) {
  const QMap<QString,QString> labels{{"critical","严重"},{"high","高危"},{"medium","中危"},{"low","低危"},{"info","信息"}};
  return labels.value(risk,QStringLiteral("待核对"));
}

SourceScanDetailDialog::SourceScanDetailDialog(ApiClient *api,const QStringList &taskIds,const QString &target,QWidget *parent)
  :QDialog(parent),m_api(api),m_taskIds(taskIds),m_target(target) {
  m_taskIds.removeDuplicates();
  setObjectName("sourceScanDetail");setWindowTitle(QStringLiteral("源码扫描详情"));
  setAttribute(Qt::WA_DeleteOnClose);setWindowFlag(Qt::WindowMinMaxButtonsHint,true);
  auto size=QSize(1460,880);
  if(auto *screen=QGuiApplication::primaryScreen())size=size.boundedTo(screen->availableGeometry().size()-QSize(24,48));
  resize(size);setMinimumSize(QSize(860,520).boundedTo(size));
  setStyleSheet(QStringLiteral("QDialog{background:#f3f6fb;} QTreeWidget,QTableWidget,QPlainTextEdit{background:white;border:1px solid #dbe3ef;border-radius:6px;} QLabel{color:#172033;} QPushButton{padding:7px 12px;}"));
  auto *layout=new QVBoxLayout(this);auto *top=new QHBoxLayout;
  auto *heading=new QLabel(QStringLiteral("源码扫描 · ")+target);heading->setTextFormat(Qt::PlainText);heading->setWordWrap(true);heading->setStyleSheet("font-size:18px;font-weight:600;");top->addWidget(heading,1);
  m_refresh=new QPushButton(QStringLiteral("刷新扫描进度"));m_refresh->setObjectName("sourceScanRefresh");top->addWidget(m_refresh);
  m_attack=new QPushButton(QStringLiteral("攻击测试"));m_attack->setObjectName("sourceScanAttack");m_attack->setEnabled(false);top->addWidget(m_attack);layout->addLayout(top);
  m_summary=new QLabel(QStringLiteral("正在读取扫描记录…"));m_summary->setTextFormat(Qt::PlainText);m_summary->setWordWrap(true);layout->addWidget(m_summary);
  auto *split=new QSplitter(Qt::Horizontal);split->setObjectName("sourceScanThreePanes");split->setChildrenCollapsible(false);layout->addWidget(split,1);
  m_tree=new QTreeWidget(split);m_tree->setObjectName("sourceScanFileTree");m_tree->setHeaderLabel(QStringLiteral("报告涉及的文件"));m_tree->setMinimumWidth(130);
  auto *middle=new QWidget(split);auto *center=new QVBoxLayout(middle);center->setContentsMargins(0,0,0,0);
  m_location=new QLabel(QStringLiteral("请选择文件或扫描发现"));m_location->setObjectName("sourceScanLocation");m_location->setTextFormat(Qt::PlainText);m_location->setWordWrap(true);center->addWidget(m_location);
  m_codeNotice=new QLabel;m_codeNotice->setTextFormat(Qt::PlainText);m_codeNotice->setWordWrap(true);center->addWidget(m_codeNotice);
  auto *tabs=new QTabWidget;tabs->setObjectName("sourceScanEvidenceTabs");
  m_evidence=new QPlainTextEdit;m_evidence->setObjectName("sourceScanEvidence");m_evidence->setReadOnly(true);tabs->addTab(m_evidence,QStringLiteral("审计依据"));
  m_code=new QPlainTextEdit;m_code->setObjectName("sourceScanCode");m_code->setReadOnly(true);m_code->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));tabs->addTab(m_code,QStringLiteral("源码片段"));center->addWidget(tabs,1);
  auto *right=new QWidget(split);right->setMinimumWidth(290);auto *rightLayout=new QVBoxLayout(right);rightLayout->setContentsMargins(0,0,0,0);
  auto *filter=new QHBoxLayout;filter->addWidget(new QLabel(QStringLiteral("当前文件的扫描发现")));filter->addStretch();
  m_severity=new QComboBox;m_severity->setObjectName("sourceScanSeverity");m_severity->addItem(QStringLiteral("全部严重度"),QString());
  for(const auto &risk:QStringList{"critical","high","medium","low","info"})m_severity->addItem(riskText(risk),risk);
  filter->addWidget(m_severity);rightLayout->addLayout(filter);
  auto *vertical=new QSplitter(Qt::Vertical);
  m_findings=new QTableWidget(0,2,vertical);m_findings->setObjectName("sourceScanFindings");m_findings->setHorizontalHeaderLabels({QStringLiteral("级别"),QStringLiteral("发现 / 位置")});m_findings->verticalHeader()->hide();m_findings->setEditTriggers(QAbstractItemView::NoEditTriggers);m_findings->setSelectionBehavior(QAbstractItemView::SelectRows);m_findings->setSelectionMode(QAbstractItemView::SingleSelection);m_findings->setColumnWidth(0,62);m_findings->horizontalHeader()->setStretchLastSection(true);
  m_details=new QPlainTextEdit(vertical);m_details->setObjectName("sourceScanFindingDetail");m_details->setReadOnly(true);vertical->setStretchFactor(0,1);vertical->setStretchFactor(1,2);rightLayout->addWidget(vertical,1);
  split->setStretchFactor(0,0);split->setStretchFactor(1,3);split->setStretchFactor(2,2);split->setSizes({210,640,450});
  m_notice=new QLabel(QStringLiteral("文件与依据随扫描报告返回而更新；扫描结束后可进入攻击测试选择漏洞。"));m_notice->setObjectName("sourceScanNotice");m_notice->setTextFormat(Qt::PlainText);m_notice->setWordWrap(true);layout->addWidget(m_notice);
  connect(m_tree,&QTreeWidget::currentItemChanged,this,[this](QTreeWidgetItem *item,QTreeWidgetItem*){
    if(!item || !item->data(0,Qt::UserRole).isValid())return;m_selectedFile=item->data(0,Qt::UserRole).toString();updateFindings();
  });
  connect(m_findings,&QTableWidget::currentCellChanged,this,[this](int row,int,int,int){showFinding(row);});
  connect(m_severity,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](){updateFindings();});
  connect(m_refresh,&QPushButton::clicked,this,&SourceScanDetailDialog::refresh);
  connect(m_attack,&QPushButton::clicked,this,&SourceScanDetailDialog::showAttackTable);
  m_timer=new QTimer(this);m_timer->setInterval(5000);connect(m_timer,&QTimer::timeout,this,[this](){if(isVisible())refresh();});
  connect(this,&QDialog::finished,this,[this](){++m_request;m_timer->stop();});
  clearEvidence();
  if(m_api && !m_taskIds.isEmpty())QTimer::singleShot(0,this,&SourceScanDetailDialog::refresh);
}

void SourceScanDetailDialog::refresh() {
  if(!m_api || m_taskIds.isEmpty() || m_outstanding)return;
  const int request=++m_request;m_outstanding=m_taskIds.size();m_received.clear();m_error.clear();m_fresh=false;m_attack->setEnabled(false);m_refresh->setEnabled(false);
  QPointer<SourceScanDetailDialog> guard(this);
  for(const auto &id:m_taskIds)m_api->get("/api/scan-tasks/"+QString::fromLatin1(QUrl::toPercentEncoding(id)),10000,[this,guard,request,id](const QJsonObject &response){
    if(!guard || request!=m_request)return;
    const auto data=response["data"].toObject();
    if(response["status"].toString()!="ok" || data["scan_task_id"].toString()!=id)m_error=QStringLiteral("扫描记录刷新失败，保留上次内容；请重试。");
    else m_received.insert(id,data);
    if(--m_outstanding)return;
    m_refresh->setEnabled(true);
    if(!m_error.isEmpty()){m_notice->setText(m_error);return;}
    QJsonArray tasks;for(const auto &id:m_taskIds)tasks.append(m_received.value(id));setSnapshots(tasks);
  });
}

void SourceScanDetailDialog::setSnapshots(const QJsonArray &tasks) {
  ++m_snapshotRevision;
  m_displayRows={};m_finalRows={};m_progressReport.clear();m_pending=false;m_canTest=!tasks.isEmpty();m_fresh=true;
  QStringList statuses,progressNotes,errors;bool truncated=false,previewParsing=false,previewError=false;
  for(const auto &value:tasks) {
    const auto task=value.toObject();const auto status=task["status"].toString();
    const bool active=QStringList{"PENDING","RUNNING"}.contains(status);m_pending=m_pending || active;
    m_canTest=m_canTest && QStringList{"COMPLETED","PARTIAL"}.contains(status);
    const QMap<QString,QString> labels{{"PENDING","待扫描"},{"RUNNING","扫描中"},{"COMPLETED","已完成"},{"PARTIAL","部分完成"},{"FAILED","失败"},{"CANCELLED","已取消"}};
    statuses << labels.value(status,QStringLiteral("状态待核对"));
    if(!task["error_message"].toString().isEmpty())errors << task["error_message"].toString();
    const auto state=task["source_scan"].toObject();
    const QMap<QString,QString> phases{{"submitting","正在创建扫描任务"},{"running","正在执行源码扫描"},
      {"waiting","核对远端任务状态"},{"parsing","正在解析完整报告"},{"importing","正在保存漏洞结果"}};
    if(active && phases.contains(state["phase"].toString()))progressNotes << phases.value(state["phase"].toString());
    const auto subtaskProgress=state["subtask_progress"].toObject();
    if(active && subtaskProgress["total"].toInt()>0)progressNotes << QStringLiteral("子任务 %1/%2 完成").arg(subtaskProgress["finished"].toInt()).arg(subtaskProgress["total"].toInt());
    int finals=0;
    for(const auto &entry:task["results"].toArray()) {
      auto row=entry.toObject();
      if(row["result_type"].toString()=="raw_output" && m_progressReport.size()<64000) {
        const auto report=resultData(row)["report"].toString();
        if(!report.isEmpty())m_progressReport+=(QStringLiteral("扫描报告 · ")+task["scan_task_id"].toString()+"\n"+report+"\n\n").left(64000-m_progressReport.size());
      }
      if(row["result_type"].toString()!="source_finding" || active)continue;
      row["scan_task_id"]=task["scan_task_id"];row["preview"]=false;
      m_finalRows.append(row);m_displayRows.append(row);++finals;
    }
    const auto preview=task["source_preview"].toObject();truncated=truncated || preview["truncated"].toBool();
    previewParsing=previewParsing || preview["parsing"].toBool();previewError=previewError || !preview["parse_errors"].toArray().isEmpty();
    if(active || finals==0)for(const auto &entry:preview["findings"].toArray())
      m_displayRows.append(QJsonObject{{"scan_task_id",task["scan_task_id"]},{"preview",true},{"result_data",entry}});
  }
  QList<QJsonValue> sorted;for(const auto &row:m_displayRows)sorted.append(row);
  std::sort(sorted.begin(),sorted.end(),[](const QJsonValue &a,const QJsonValue &b){
    const auto x=resultData(a.toObject()),y=resultData(b.toObject());
    const QStringList order{"critical","high","medium","low","info"};
    const int rx=order.indexOf(x["severity"].toString()),ry=order.indexOf(y["severity"].toString());
    if(rx!=ry)return rx<ry;if(x["file"]!=y["file"])return x["file"].toString()<y["file"].toString();return x["start_line"].toInt()<y["start_line"].toInt();
  });
  m_displayRows={};for(const auto &row:sorted)m_displayRows.append(row);
  rebuildFiles();statuses.removeDuplicates();
  m_summary->setText(QStringLiteral("%1 · 报告涉及 %2 个文件 · %3 条扫描发现").arg(statuses.join(" / ")).arg(m_files.size()).arg(m_displayRows.size()));
  progressNotes.removeDuplicates();if(!progressNotes.isEmpty())m_summary->setText(m_summary->text()+QStringLiteral(" · ")+progressNotes.join(QStringLiteral(" · ")));
  m_notice->setText(m_pending?QStringLiteral("扫描发现为过程预览，可能被后续报告修正；攻击测试在扫描结束后开放。")
    :QStringLiteral("按文件查看依据与修复建议；点击“攻击测试”查看全部已保存漏洞并选择测试对象。"));
  if(!m_pending && !m_canTest)m_notice->setText(QStringLiteral("本次扫描未成功完成，已有过程记录仅供核对；攻击测试暂不可用。"));
  else if(!m_pending && m_finalRows.isEmpty())m_notice->setText(QStringLiteral("扫描已结束，暂无可测试漏洞；过程报告仍可查看。"));
  if(truncated)m_notice->setText(m_notice->text()+QStringLiteral(" 当前过程预览达到显示上限，最终结果以完整报告处理为准。"));
  if(m_pending && previewParsing)m_notice->setText(m_notice->text()+QStringLiteral(" 正在整理已完成子任务的阶段发现。"));
  if(m_pending && previewError)m_notice->setText(m_notice->text()+QStringLiteral(" 部分阶段报告暂未解析，原始报告仍可查看，最终结果将统一处理。"));
  errors.removeDuplicates();if(!errors.isEmpty())m_notice->setText(m_notice->text()+QStringLiteral("\n扫描说明：")+errors.join(QStringLiteral("；")));
  m_attack->setEnabled(m_canTest && !m_pending && !m_finalRows.isEmpty());m_refresh->setEnabled(true);
  if(m_pending && m_api)m_timer->start();else m_timer->stop();
}

void SourceScanDetailDialog::rebuildFiles() {
  const QSignalBlocker block(m_tree);m_tree->clear();m_files.clear();QMap<QString,QTreeWidgetItem*> nodes;
  QTreeWidgetItem *progress=nullptr;
  if(!m_progressReport.isEmpty()){progress=new QTreeWidgetItem(m_tree,{QStringLiteral("扫描过程报告")});progress->setData(0,Qt::UserRole,QStringLiteral("__progress__"));}
  for(const auto &value:m_displayRows) {
    const auto row=value.toObject(),data=resultData(row);const QString file=data["file"].toString();if(file.isEmpty())continue;
    const QString key=fileKey(row);if(m_files.contains(key))continue;
    const QString task=row["scan_task_id"].toString();QTreeWidgetItem *parent=nullptr;QString prefix=task;
    if(m_taskIds.size()>1) {
      if(!nodes.contains(task))nodes.insert(task,new QTreeWidgetItem(m_tree,{QStringLiteral("扫描 ")+task.right(8)}));parent=nodes.value(task);
    }
    if(file.startsWith('/')) {
      const QString rootKey=task+"|absolute-root";
      if(!nodes.contains(rootKey))nodes.insert(rootKey,parent?new QTreeWidgetItem(parent,{QStringLiteral("/")}):new QTreeWidgetItem(m_tree,{QStringLiteral("/")}));
      parent=nodes.value(rootKey);prefix=task+"|absolute";
    } else prefix=task+"|relative";
    const auto parts=file.split('/',QString::SkipEmptyParts);
    for(int i=0;i<parts.size();++i) {
      prefix+='/'+parts[i];auto *node=nodes.value(prefix,nullptr);
      if(!node){node=parent?new QTreeWidgetItem(parent,{parts[i]}):new QTreeWidgetItem(m_tree,{parts[i]});nodes.insert(prefix,node);}
      parent=node;
      if(i==parts.size()-1){node->setData(0,Qt::UserRole,key);m_files.insert(key,node);}
    }
  }
  m_tree->expandToDepth(2);
  if(!m_files.contains(m_selectedFile) && !(progress && m_selectedFile=="__progress__"))m_selectedFile=m_files.isEmpty()?(progress?QStringLiteral("__progress__"):QString()):m_files.firstKey();
  if(m_files.contains(m_selectedFile))m_tree->setCurrentItem(m_files.value(m_selectedFile));
  else if(progress)m_tree->setCurrentItem(progress);
  updateFindings();
}

void SourceScanDetailDialog::updateFindings() {
  const QSignalBlocker block(m_findings);m_findings->setRowCount(0);clearEvidence();
  for(int i=0;i<m_displayRows.size();++i) {
    const auto row=m_displayRows[i].toObject(),data=resultData(row);
    if(fileKey(row)!=m_selectedFile || (!m_severity->currentData().toString().isEmpty() && data["severity"].toString()!=m_severity->currentData().toString()))continue;
    const int n=m_findings->rowCount();m_findings->insertRow(n);
    auto *risk=new QTableWidgetItem(riskText(data["severity"].toString()));risk->setData(Qt::UserRole,i);
    const QMap<QString,QString> colors{{"critical","#991b1b"},{"high","#dc2626"},{"medium","#b45309"},{"low","#2563eb"},{"info","#64748b"}};
    risk->setForeground(QColor(colors.value(data["severity"].toString(),"#475569")));m_findings->setItem(n,0,risk);
    m_findings->setItem(n,1,new QTableWidgetItem(QStringLiteral("%1 · 第 %2 行%3").arg(data["title"].toString()).arg(data["start_line"].toInt()).arg(row["preview"].toBool()?QStringLiteral("（扫描中发现）"):QString())));
  }
  if(m_findings->rowCount()){m_findings->selectRow(0);showFinding(0);}
}

void SourceScanDetailDialog::clearEvidence() {
  m_location->setText(QStringLiteral("请选择报告中的文件"));m_code->clear();m_code->setPlaceholderText(QStringLiteral("报告尚未返回源码片段。"));
  m_codeNotice->setText(QStringLiteral("文件树来自扫描报告，不代表完整源码目录；未提供的源码正文不会补写。"));
  m_evidence->clear();m_evidence->setPlaceholderText(QStringLiteral("等待 CScan 返回带文件、行号和依据的扫描发现。"));m_details->clear();
  if(!m_progressReport.isEmpty() && (m_selectedFile.isEmpty() || m_selectedFile=="__progress__")) {
    m_location->setText(QStringLiteral("扫描过程报告"));m_evidence->setPlainText(m_progressReport
      +(m_progressReport.size()>=64000?QStringLiteral("\n（过程预览达到显示上限，完整报告仍保存在扫描记录中。）"):QString()));
  }
}

void SourceScanDetailDialog::showFinding(int row) {
  if(row<0 || !m_findings->item(row,0))return;const int index=m_findings->item(row,0)->data(Qt::UserRole).toInt();
  if(index<0 || index>=m_displayRows.size())return;const auto record=m_displayRows[index].toObject(),data=resultData(record);
  const int line=data["start_line"].toInt(),end=data["end_line"].toInt(line);
  m_location->setText(QStringLiteral("%1 · 第 %2–%3 行").arg(data["file"].toString()).arg(line).arg(end));
  const QString code=data["code"].toString();m_code->clear();
  if(!code.isEmpty()) {QStringList numbered;const auto lines=code.split('\n');for(int i=0;i<lines.size();++i)numbered<<QStringLiteral("%1  %2").arg(line+i).arg(lines[i]);m_code->setPlainText(numbered.join('\n'));}
  m_codeNotice->setText(code.isEmpty()?QStringLiteral("当前报告未返回源码正文；下方显示审计依据及报告定位。") : QStringLiteral("返回的源码片段，非完整文件；行号与部署版本仍需核对。"));
  m_evidence->setPlainText(data["reason"].toString());
  m_details->setPlainText(QStringLiteral("%1\n%2 · %3\n\n触发前提\n%4\n\n修复建议\n%5\n\n%6")
    .arg(data["title"].toString(),riskText(data["severity"].toString()),data["cwe"].toString(),data["preconditions"].toString(QStringLiteral("未提供")),data["suggestion"].toString(QStringLiteral("未提供")),record["preview"].toBool()?QStringLiteral("过程预览，尚未发布为可测试漏洞。") : QStringLiteral("扫描发现不等于攻击验证成立。")));
}

void SourceScanDetailDialog::selectFinding(qint64 id) {
  for(const auto &value:m_displayRows) {
    const auto row=value.toObject();if(row["id"].toVariant().toLongLong()!=id)continue;
    m_selectedFile=fileKey(row);m_severity->setCurrentIndex(0);rebuildFiles();
    for(int i=0;i<m_findings->rowCount();++i)if(m_displayRows[m_findings->item(i,0)->data(Qt::UserRole).toInt()].toObject()["id"].toVariant().toLongLong()==id){m_findings->selectRow(i);showFinding(i);return;}
  }
}

void SourceScanDetailDialog::showAttackTable() {
  if(!m_fresh || m_pending || !m_canTest || m_finalRows.isEmpty())return;
  auto *dialog=new QDialog(this);dialog->setObjectName("sourceScanAttackSelection");dialog->setAttribute(Qt::WA_DeleteOnClose);dialog->setWindowTitle(QStringLiteral("选择漏洞进行攻击测试"));dialog->resize(1050,620);
  if(auto *screen=QGuiApplication::primaryScreen())dialog->resize(dialog->size().boundedTo(screen->availableGeometry().size()-QSize(24,48)));
  auto *layout=new QVBoxLayout(dialog);auto *hint=new QLabel(QStringLiteral("全部已保存漏洞 · 勾选后进入测试准备，实际执行仍需确认。"));hint->setWordWrap(true);layout->addWidget(hint);
  auto *table=new QTableWidget(0,5);table->setObjectName("sourceScanAttackTable");table->setHorizontalHeaderLabels({"选择","严重性","漏洞名称","源码位置","CWE"});table->setEditTriggers(QAbstractItemView::NoEditTriggers);table->verticalHeader()->hide();table->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Stretch);table->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);layout->addWidget(table,1);
  for(const auto &value:m_finalRows) {
    const auto row=value.toObject(),data=resultData(row);const int n=table->rowCount();table->insertRow(n);
    auto *check=new QTableWidgetItem;check->setFlags(Qt::ItemIsEnabled|Qt::ItemIsUserCheckable);check->setCheckState(Qt::Unchecked);check->setData(Qt::UserRole,row["id"].toVariant());
    if(data["severity"].toString()=="info" || row["id"].toVariant().toLongLong()<=0)check->setFlags(Qt::NoItemFlags);
    table->setItem(n,0,check);table->setItem(n,1,new QTableWidgetItem(riskText(data["severity"].toString())));table->setItem(n,2,new QTableWidgetItem(data["title"].toString()));table->setItem(n,3,new QTableWidgetItem(QStringLiteral("%1:%2").arg(data["file"].toString()).arg(data["start_line"].toInt())));table->setItem(n,4,new QTableWidgetItem(data["cwe"].toString()));
  }
  auto *buttons=new QDialogButtonBox(QDialogButtonBox::Cancel);auto *prepare=buttons->addButton(QStringLiteral("准备测试"),QDialogButtonBox::AcceptRole);prepare->setObjectName("sourceScanPrepareTest");prepare->setEnabled(false);layout->addWidget(buttons);
  connect(table,&QTableWidget::itemChanged,dialog,[table,prepare](){bool selected=false;for(int i=0;i<table->rowCount();++i)selected=selected || table->item(i,0)->checkState()==Qt::Checked;prepare->setEnabled(selected);});
  connect(buttons,&QDialogButtonBox::rejected,dialog,&QDialog::close);
  const int snapshot=m_snapshotRevision;
  connect(prepare,&QPushButton::clicked,dialog,[this,dialog,table,hint,snapshot](){
    if(!m_fresh || m_pending || !m_canTest || snapshot!=m_snapshotRevision){hint->setText(QStringLiteral("扫描状态或结果已变化，请关闭本窗口并重新选择漏洞。"));return;}
    QList<qint64> ids;for(int i=0;i<table->rowCount();++i)if(table->item(i,0)->flags().testFlag(Qt::ItemIsEnabled) && table->item(i,0)->checkState()==Qt::Checked)ids<<table->item(i,0)->data(Qt::UserRole).toLongLong();
    if(ids.isEmpty())return;dialog->close();emit testRequested(ids);
  });
  dialog->show();
}
