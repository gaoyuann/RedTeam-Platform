#include "SourceScanDetailDialog.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QtWidgets>
#include <QJsonDocument>
#include <QPointer>
#include <algorithm>

// Code editor reused from pentagi-v3 SourceScanPage.cpp.
namespace {
class SourceHighlighter : public QSyntaxHighlighter {
  public:
    explicit SourceHighlighter(QTextDocument *doc) : QSyntaxHighlighter(doc) {}

  protected:
    void highlightBlock(const QString &text) override {
        const QRegularExpression words(
            QStringLiteral("\\b(alignas|auto|bool|break|case|catch|char|class|const|constexpr|continue|"
                           "default|delete|do|double|else|enum|explicit|extern|false|float|for|friend|if|"
                           "inline|int|long|namespace|new|noexcept|nullptr|operator|private|protected|public|"
                           "return|short|signed|sizeof|static|struct|switch|template|this|throw|true|try|"
                           "typedef|typename|union|unsigned|using|virtual|void|volatile|while)\\b"));
        auto matches = words.globalMatch(text);
        while (matches.hasNext()) {
            auto m = matches.next();
            setFormat(m.capturedStart(), m.capturedLength(), QColor("#7c3aed"));
        }
        const QRegularExpression strings(QStringLiteral("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'"));
        matches = strings.globalMatch(text);
        while (matches.hasNext()) {
            auto m = matches.next();
            setFormat(m.capturedStart(), m.capturedLength(), QColor("#047857"));
        }
        if (text.trimmed().startsWith('#'))
            setFormat(0, text.size(), QColor("#0369a1"));
        setCurrentBlockState(0);
        int start = previousBlockState() == 1 ? 0 : text.indexOf("/*");
        while (start >= 0) {
            const int end = text.indexOf("*/", start + 2);
            const int count = end < 0 ? text.size() - start : end - start + 2;
            setFormat(start, count, QColor("#64748b"));
            if (end < 0) {
                setCurrentBlockState(1);
                break;
            }
            start = text.indexOf("/*", start + count);
        }
        const int comment = text.indexOf("//");
        if (comment >= 0)
            setFormat(comment, text.size() - comment, QColor("#64748b"));
    }
};
class CodeEditor;
class LineNumbers : public QWidget {
  public:
    explicit LineNumbers(CodeEditor *editor);

  protected:
    void paintEvent(QPaintEvent *) override;

  private:
    CodeEditor *m_editor;
};
class CodeEditor : public QPlainTextEdit {
  public:
    explicit CodeEditor(QWidget *parent) : QPlainTextEdit(parent), m_gutter(new LineNumbers(this)) {
        setReadOnly(true);
        setLineWrapMode(QPlainTextEdit::NoWrap);
        setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        new SourceHighlighter(document());
        connect(this, &QPlainTextEdit::blockCountChanged, this, [this]() { margin(); });
        connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect &r, int dy) {
            if (dy)
                m_gutter->scroll(0, dy);
            else
                m_gutter->update(0, r.y(), m_gutter->width(), r.height());
        });
        margin();
    }
    void drawNumbers(QPaintEvent *) {
        QPainter p(m_gutter);
        p.fillRect(m_gutter->rect(), QColor("#f1f5f9"));
        p.setPen(QColor("#64748b"));
        p.setFont(font());
        QTextBlock block = firstVisibleBlock();
        int number = block.blockNumber();
        int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
        while (block.isValid() && top <= m_gutter->height()) {
            const int height = qRound(blockBoundingRect(block).height());
            if (block.isVisible() && top + height >= 0)
                p.drawText(0, top, m_gutter->width() - 8, fontMetrics().height(), Qt::AlignRight,
                           QString::number(number + 1));
            top += height;
            block = block.next();
            ++number;
        }
    }

  protected:
    void resizeEvent(QResizeEvent *e) override {
        QPlainTextEdit::resizeEvent(e);
        margin();
    }

  private:
    void margin() {
        int digits = 1;
        for (int n = qMax(1, blockCount()); n >= 10; n /= 10)
            ++digits;
        const int width = 16 + fontMetrics().horizontalAdvance('9') * digits;
        setViewportMargins(width, 0, 0, 0);
        m_gutter->setGeometry(contentsRect().left(), contentsRect().top(), width, contentsRect().height());
        m_gutter->update();
    }
    LineNumbers *m_gutter;
};
LineNumbers::LineNumbers(CodeEditor *editor) : QWidget(editor), m_editor(editor) {}
void LineNumbers::paintEvent(QPaintEvent *e) {
    m_editor->drawNumbers(e);
}
}


QJsonObject SourceScanDetailDialog::resultData(const QJsonObject &row) {
  auto data=row["result_data"].isObject()?row["result_data"].toObject():QJsonDocument::fromJson(row["result_data"].toString().toUtf8()).object();
  if(data["severity"].toString().isEmpty())data["severity"]=row["severity"];
  return data;
}
QString SourceScanDetailDialog::fileKey(const QJsonObject &row) {
  QString file=resultData(row)["file"].toString();
  if(file.startsWith("/work/src/"))file=file.mid(QStringLiteral("/work/src/").size());
  return row["scan_task_id"].toString()+"\n"+file;
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
  m_attack=new QPushButton(QStringLiteral("准备当前漏洞测试"));m_attack->setObjectName("sourceScanAttack");m_attack->setEnabled(false);top->addWidget(m_attack);layout->addLayout(top);
  m_summary=new QLabel(QStringLiteral("正在读取扫描记录…"));m_summary->setObjectName("sourceScanSummary");m_summary->setTextFormat(Qt::PlainText);m_summary->setWordWrap(true);layout->addWidget(m_summary);
  auto *split=new QSplitter(Qt::Horizontal);split->setObjectName("sourceScanThreePanes");split->setChildrenCollapsible(false);layout->addWidget(split,1);
  m_tree=new QTreeWidget(split);m_tree->setObjectName("sourceScanFileTree");m_tree->setHeaderLabel(QStringLiteral("文件树 · 扫描时快照"));m_tree->setMinimumWidth(130);
  auto *middle=new QWidget(split);auto *center=new QVBoxLayout(middle);center->setContentsMargins(0,0,0,0);
  m_location=new QLabel(QStringLiteral("请选择文件或扫描发现"));m_location->setObjectName("sourceScanLocation");m_location->setTextFormat(Qt::PlainText);m_location->setWordWrap(true);center->addWidget(m_location);
  m_codeNotice=new QLabel;m_codeNotice->setTextFormat(Qt::PlainText);m_codeNotice->setWordWrap(true);center->addWidget(m_codeNotice);
  m_code=new CodeEditor(middle);m_code->setObjectName("sourceScanCode");center->addWidget(m_code,1);
  auto *right=new QWidget(split);right->setMinimumWidth(290);auto *rightLayout=new QVBoxLayout(right);rightLayout->setContentsMargins(0,0,0,0);
  auto *filter=new QHBoxLayout;filter->addWidget(new QLabel(QStringLiteral("全部扫描发现")));filter->addStretch();
  m_severity=new QComboBox;m_severity->setObjectName("sourceScanSeverity");m_severity->addItem(QStringLiteral("全部严重度"),QString());
  for(const auto &risk:QStringList{"critical","high","medium","low","info"})m_severity->addItem(riskText(risk),risk);
  filter->addWidget(m_severity);rightLayout->addLayout(filter);
  auto *vertical=new QSplitter(Qt::Vertical);
  m_findings=new QTableWidget(0,2,vertical);m_findings->setObjectName("sourceScanFindings");m_findings->setHorizontalHeaderLabels({QStringLiteral("级别"),QStringLiteral("发现 / 位置")});m_findings->verticalHeader()->hide();m_findings->setEditTriggers(QAbstractItemView::NoEditTriggers);m_findings->setSelectionBehavior(QAbstractItemView::SelectRows);m_findings->setSelectionMode(QAbstractItemView::SingleSelection);m_findings->setColumnWidth(0,62);m_findings->horizontalHeader()->setStretchLastSection(true);
  auto *detailTabs=new QTabWidget(vertical);
  m_details=new QPlainTextEdit(detailTabs);m_details->setObjectName("sourceScanFindingDetail");m_details->setReadOnly(true);detailTabs->addTab(m_details,QStringLiteral("漏洞详情"));
  m_evidence=new QPlainTextEdit(detailTabs);m_evidence->setObjectName("sourceScanEvidence");m_evidence->setReadOnly(true);detailTabs->addTab(m_evidence,QStringLiteral("依据"));
  auto *report=new QPlainTextEdit(detailTabs);report->setObjectName("sourceScanRawReport");report->setReadOnly(true);detailTabs->addTab(report,QStringLiteral("原始报告"));
  vertical->setStretchFactor(0,3);vertical->setStretchFactor(1,2);rightLayout->addWidget(vertical,1);
  split->setStretchFactor(0,0);split->setStretchFactor(1,3);split->setStretchFactor(2,2);split->setSizes({210,640,450});
  m_notice=new QLabel(QStringLiteral("文件与依据随扫描报告返回而更新；扫描结束后可选择发现并准备测试。"));m_notice->setObjectName("sourceScanNotice");m_notice->setTextFormat(Qt::PlainText);m_notice->setWordWrap(true);layout->addWidget(m_notice);
  connect(m_tree,&QTreeWidget::currentItemChanged,this,[this](QTreeWidgetItem *item,QTreeWidgetItem*){
    if(!item || !item->data(0,Qt::UserRole).isValid())return;m_selectedFile=item->data(0,Qt::UserRole).toString();m_code->clear();m_code->setExtraSelections({});loadSource();
  });
  connect(m_findings,&QTableWidget::currentCellChanged,this,[this](int row,int,int,int){showFinding(row);});
  connect(m_severity,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](){updateFindings();});
  connect(m_refresh,&QPushButton::clicked,this,&SourceScanDetailDialog::refresh);
  connect(m_attack,&QPushButton::clicked,this,&SourceScanDetailDialog::prepareSelectedFinding);
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
  m_displayRows={};m_finalRows={};m_sourceFiles.clear();m_progressReport.clear();m_pending=false;m_canTest=!tasks.isEmpty();m_fresh=true;
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
      {"waiting","核对远端任务状态"},{"collecting_report","正在收集完整报告"},{"parsing","正在解析完整报告"},{"importing","正在保存漏洞结果"}};
    if(active && phases.contains(state["phase"].toString()))progressNotes << phases.value(state["phase"].toString());
    const auto subtaskProgress=state["subtask_progress"].toObject();
    if(active && subtaskProgress["total"].toInt()>0)progressNotes << QStringLiteral("子任务 %1/%2 完成").arg(subtaskProgress["finished"].toInt()).arg(subtaskProgress["total"].toInt());
    for(const auto &entry:task["source_files"].toArray()) {
      auto file=entry.toObject();file["scan_task_id"]=task["scan_task_id"];
      const QJsonObject row{{"scan_task_id",task["scan_task_id"]},{"result_data",QJsonObject{{"file",file["path"]}}}};
      m_sourceFiles.insert(fileKey(row),file);
    }
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
  findChild<QPlainTextEdit*>("sourceScanRawReport")->setPlainText(m_progressReport+(m_progressReport.size()>=64000?QStringLiteral("\n（预览已达上限，完整报告保存在扫描记录中。）"):QString()));
  rebuildFiles();statuses.removeDuplicates();
  m_summary->setText(QStringLiteral("%1 · 源码快照 %2 个文件 · %3 条扫描发现（待复核）").arg(statuses.join(" / ")).arg(m_sourceFiles.size()).arg(m_displayRows.size()));
  progressNotes.removeDuplicates();if(!progressNotes.isEmpty())m_summary->setText(m_summary->text()+QStringLiteral(" · ")+progressNotes.join(QStringLiteral(" · ")));
  m_notice->setText(m_pending?QStringLiteral("扫描发现为过程预览，可能被后续报告修正；攻击测试在扫描结束后开放。")
    :QStringLiteral("点击发现定位源码行；未匹配源码的报告定位单独列为待核对，扫描发现不等于漏洞已验证。"));
  if(!m_pending && !m_canTest)m_notice->setText(QStringLiteral("本次扫描未成功完成，已有过程记录仅供核对；攻击测试暂不可用。"));
  else if(!m_pending && m_finalRows.isEmpty())m_notice->setText(QStringLiteral("扫描已结束，暂无可测试漏洞；过程报告仍可查看。"));
  if(truncated)m_notice->setText(m_notice->text()+QStringLiteral(" 当前过程预览达到显示上限，最终结果以完整报告处理为准。"));
  if(m_pending && previewParsing)m_notice->setText(m_notice->text()+QStringLiteral(" 正在整理已完成子任务的阶段发现。"));
  if(m_pending && previewError)m_notice->setText(m_notice->text()+QStringLiteral(" 部分阶段报告暂未解析，原始报告仍可查看，最终结果将统一处理。"));
  errors.removeDuplicates();if(!errors.isEmpty())m_notice->setText(m_notice->text()+QStringLiteral("\n扫描说明：")+errors.join(QStringLiteral("；")));
  if(m_requestedFinding>0)selectFinding(m_requestedFinding);
  updateTestButton();m_refresh->setEnabled(true);
  if(m_pending && m_api)m_timer->start();else m_timer->stop();
}

void SourceScanDetailDialog::rebuildFiles() {
  const QSignalBlocker block(m_tree);m_tree->clear();m_files.clear();QMap<QString,QTreeWidgetItem*> nodes;
  QJsonArray fileRows;
  for(const auto &file:m_sourceFiles)fileRows.append(QJsonObject{{"scan_task_id",file["scan_task_id"]},{"result_data",QJsonObject{{"file",file["path"]}}}});
  for(const auto &row:m_displayRows)if(!m_sourceFiles.contains(fileKey(row.toObject())))fileRows.append(row);
  QTreeWidgetItem *unmatched=nullptr;
  for(const auto &value:fileRows) {
    const auto row=value.toObject(),data=resultData(row);const QString file=fileKey(row).section('\n',1);if(file.isEmpty())continue;
    const QString key=fileKey(row);if(m_files.contains(key))continue;
    const QString task=row["scan_task_id"].toString();QTreeWidgetItem *parent=nullptr;QString prefix=task;
    if(!m_sourceFiles.contains(key)) {
      if(!unmatched)unmatched=new QTreeWidgetItem(m_tree,{QStringLiteral("待核对 · 未匹配源码")});
      auto *node=new QTreeWidgetItem(unmatched,{file});node->setData(0,Qt::UserRole,key);m_files.insert(key,node);continue;
    }
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
  if(!m_files.contains(m_selectedFile))m_selectedFile=m_sourceFiles.isEmpty()?QString():m_sourceFiles.firstKey();
  if(m_files.contains(m_selectedFile))m_tree->setCurrentItem(m_files.value(m_selectedFile));
  updateFindings();
}

void SourceScanDetailDialog::updateFindings() {
  const auto *previous=m_findings->item(m_findings->currentRow(),0);
  const QString selected=previous?previous->data(Qt::UserRole+1).toString():QString();
  int selectedRow=0;
  const QSignalBlocker block(m_findings);m_findings->setRowCount(0);clearEvidence();
  for(int i=0;i<m_displayRows.size();++i) {
    const auto row=m_displayRows[i].toObject(),data=resultData(row);
    if(!m_severity->currentData().toString().isEmpty() && data["severity"].toString()!=m_severity->currentData().toString())continue;
    const int n=m_findings->rowCount();m_findings->insertRow(n);
    auto *risk=new QTableWidgetItem(riskText(data["severity"].toString()));risk->setData(Qt::UserRole,i);
    const QString identity=fileKey(row)+QStringLiteral("|%1|%2|%3").arg(row["id"].toVariant().toString(),data["title"].toString()).arg(data["start_line"].toInt());
    risk->setData(Qt::UserRole+1,identity);if(identity==selected)selectedRow=n;
    const QMap<QString,QString> colors{{"critical","#991b1b"},{"high","#dc2626"},{"medium","#b45309"},{"low","#2563eb"},{"info","#64748b"}};
    risk->setForeground(QColor(colors.value(data["severity"].toString(),"#475569")));m_findings->setItem(n,0,risk);
    m_findings->setItem(n,1,new QTableWidgetItem(QStringLiteral("%1 — %2:%3%4").arg(data["title"].toString(),data["file"].toString()).arg(data["start_line"].toInt()).arg(row["preview"].toBool()?QStringLiteral("（扫描中发现）"):QString())));
  }
  if(m_findings->rowCount()){m_findings->selectRow(selectedRow);showFinding(selectedRow);}
  else loadSource();
  updateTestButton();
}

void SourceScanDetailDialog::clearEvidence() {
  ++m_sourceRequest;
  m_location->setText(QStringLiteral("请选择源码文件或报告定位"));m_code->clear();m_code->setPlaceholderText(QStringLiteral("请选择已有源码快照；未匹配文件不会补写源码。"));
  m_codeNotice->setText(QStringLiteral("点击扫描发现可定位源码；未匹配的报告路径单独列出。"));
  m_evidence->clear();m_evidence->setPlaceholderText(QStringLiteral("等待 CScan 返回带文件、行号和依据的扫描发现。"));m_details->clear();
  if(!m_progressReport.isEmpty() && (m_selectedFile.isEmpty() || m_selectedFile=="__progress__")) {
    m_location->setText(QStringLiteral("扫描过程报告"));m_evidence->setPlainText(m_progressReport
      +(m_progressReport.size()>=64000?QStringLiteral("\n（过程预览达到显示上限，完整报告仍保存在扫描记录中。）"):QString()));
  }
}

void SourceScanDetailDialog::showFinding(int row) {
  ++m_sourceRequest;
  if(row<0 || !m_findings->item(row,0))return;const int index=m_findings->item(row,0)->data(Qt::UserRole).toInt();
  if(index<0 || index>=m_displayRows.size())return;const auto record=m_displayRows[index].toObject(),data=resultData(record);
  m_selectedFile=fileKey(record);
  {const QSignalBlocker block(m_tree);if(auto *item=m_files.value(m_selectedFile)){m_tree->setCurrentItem(item);m_tree->scrollToItem(item);}}
  const int line=data["start_line"].toInt(),end=data["end_line"].toInt(line);
  m_location->setText(QStringLiteral("%1 · 第 %2–%3 行").arg(data["file"].toString()).arg(line).arg(end));
  m_code->clear();m_code->setExtraSelections({});
  m_evidence->setPlainText(data["reason"].toString());
  m_details->setPlainText(QStringLiteral("%1\n%2 · %3\n\n触发前提\n%4\n\n修复建议\n%5\n\n%6")
    .arg(data["title"].toString(),riskText(data["severity"].toString()),data["cwe"].toString(),data["preconditions"].toString(QStringLiteral("未提供")),data["suggestion"].toString(QStringLiteral("未提供")),record["preview"].toBool()?QStringLiteral("过程预览，尚未发布为可测试漏洞。") : QStringLiteral("扫描发现不等于攻击验证成立。")));
  m_details->appendPlainText(QStringLiteral("\n依据\n")+data["reason"].toString());
  m_details->moveCursor(QTextCursor::Start);
  loadSource(line,end);
  updateTestButton();
}

void SourceScanDetailDialog::loadSource(int line,int endLine) {
  if(!m_sourceFiles.contains(m_selectedFile)){m_code->clear();m_code->setExtraSelections({});m_location->setText(m_selectedFile.section('\n',1));m_codeNotice->setText(QStringLiteral("未匹配源码快照 · 报告定位待核对"));return;}
  if(!m_api)return;
  const auto file=m_sourceFiles.value(m_selectedFile);const int request=++m_sourceRequest;
  const QString key=m_selectedFile;QPointer<SourceScanDetailDialog> guard(this);
  m_location->setText(file["path"].toString());m_codeNotice->setText(QStringLiteral("正在读取已保存的源码副本…"));
  m_api->get("/api/scan-tasks/"+QString::fromLatin1(QUrl::toPercentEncoding(file["scan_task_id"].toString()))+"/source-file?id="+QString::number(file["id"].toVariant().toLongLong()),10000,
    [this,guard,request,key,line,endLine,file](const QJsonObject &response){
      if(!guard || request!=m_sourceRequest || key!=m_selectedFile)return;
      const auto data=response["data"].toObject();
      if(response["status"].toString()!="ok" || data["sha256"]!=file["sha256"]){m_codeNotice->setText(QStringLiteral("源码副本已更新或读取失败，请刷新后重试。"));return;}
      m_code->setPlainText(data["content"].toString());
      m_codeNotice->setText(QStringLiteral("真实源码副本 · %1 · 尚不代表全部已审计或与部署版本一致").arg(data["captured_at"].toString()));
      if(line>0 && line<=m_code->document()->blockCount()) {
        QTextCursor cursor(m_code->document()->findBlockByNumber(line-1));m_code->setTextCursor(cursor);m_code->centerCursor();
        QList<QTextEdit::ExtraSelection> selections;
        for(int n=line;n<=qMin(qMin(qMax(line,endLine),line+500),m_code->document()->blockCount());++n){
          QTextEdit::ExtraSelection selection;selection.cursor=QTextCursor(m_code->document()->findBlockByNumber(n-1));selection.format.setBackground(QColor("#fff2bf"));selection.format.setProperty(QTextFormat::FullWidthSelection,true);selections.append(selection);
        }m_code->setExtraSelections(selections);
      } else {m_code->setExtraSelections({});if(line>0)m_codeNotice->setText(m_codeNotice->text()+QStringLiteral(" · 报告行号超出快照范围，待核对"));}
    });
}

void SourceScanDetailDialog::selectFinding(qint64 id) {
  m_requestedFinding=id;
  for(const auto &value:m_displayRows) {
    const auto row=value.toObject();if(row["id"].toVariant().toLongLong()!=id)continue;
    m_requestedFinding=0;
    m_selectedFile=fileKey(row);m_severity->setCurrentIndex(0);rebuildFiles();
    for(int i=0;i<m_findings->rowCount();++i)if(m_displayRows[m_findings->item(i,0)->data(Qt::UserRole).toInt()].toObject()["id"].toVariant().toLongLong()==id){m_findings->selectRow(i);showFinding(i);return;}
  }
}

qint64 SourceScanDetailDialog::selectedTestFinding() const {
  if(!m_fresh || m_pending || !m_canTest)return 0;
  const auto *item=m_findings->item(m_findings->currentRow(),0);
  if(!item)return 0;
  const int index=item->data(Qt::UserRole).toInt();
  if(index<0 || index>=m_displayRows.size())return 0;
  const auto row=m_displayRows[index].toObject(),data=resultData(row);
  const auto severity=data["severity"].toString(row["severity"].toString()).trimmed().toLower();
  if(row["preview"].toBool() || severity=="info" || severity=="inf")return 0;
  return row["id"].toVariant().toLongLong();
}

void SourceScanDetailDialog::updateTestButton() {
  m_attack->setEnabled(selectedTestFinding()>0);
  m_attack->setToolTip(QStringLiteral("准备右侧当前选中的漏洞；打开测试窗口不会执行测试。批量选择可在扫描发现列表中完成。"));
}

void SourceScanDetailDialog::prepareSelectedFinding() {
  const qint64 id=selectedTestFinding();
  if(id>0)emit testRequested({id});
}
