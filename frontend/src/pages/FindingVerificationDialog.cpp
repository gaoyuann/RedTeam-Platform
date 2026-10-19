#include "FindingVerificationDialog.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QTableWidget>
#include <QHeaderView>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QTimer>
#include <QPointer>
#include <QUrl>
#include <QUuid>
#include <QJsonDocument>
#include <QMessageBox>
#include <QMap>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSet>

namespace {
QString stateText(const QString &s) {
  static const QMap<QString,QString> labels{{"needs_conditions","待补条件"},{"preparation_failed","方案未就绪"},{"draft","草稿"},{"ready","就绪"},
    {"queued","排队中"},{"running","执行中"},{"cancelling","取消中"},{"unknown","停止待核查"},
    {"completed","执行结束，待判定"},{"failed","执行异常"},{"aborted","已中止"},
    {"pending","待判定"},{"confirmed","验证成立"},{"not_verified","未能验证"},{"inconclusive","条件不足"},{"false_positive","人工判定误报"}};
  return labels.value(s,s);
}
QString readable(const QJsonValue &value) {
  if(value.isString()) {
    const auto text=value.toString().trimmed();
    if(text.startsWith('{')||text.startsWith('['))return QString();
    return text.left(2000);
  }
  if(value.isBool())return value.toBool()?"是":"否";
  if(value.isDouble())return QString::number(value.toDouble());
  if(value.isArray()){QStringList parts;for(const auto &v:value.toArray()){const auto text=readable(v);if(!text.isEmpty())parts<<text;}return parts.join("；");}
  return {};
}
QString join(const QJsonArray &array) {return readable(array);}
QJsonArray lines(QPlainTextEdit *edit) {
  QJsonArray result;for(const auto &line:edit->toPlainText().split('\n'))if(!line.trimmed().isEmpty())result.append(line.trimmed());return result;
}
QString keyFacts(const QJsonObject &data) {
  static const QList<QPair<QString,QString>> fields{
    {"title","名称"},{"finding","发现"},{"description","说明"},{"url","位置"},{"location","位置"},{"endpoint","入口"},
    {"path","扫描位置"},{"method","请求方法"},{"parameter","参数"},{"cve","漏洞编号"},{"cwe","弱点类型"},{"status_code","响应状态"},
    {"statusCode","响应状态"},{"status","响应状态"},{"connected","连接状态"},{"summary","观察摘要"},
    {"detail","观察结果"},{"error","异常原因"},{"exit_code","退出码"},{"response","响应摘要"}};
  QStringList result;
  for(const auto &field:fields){const auto text=readable(data[field.first]);if(!text.isEmpty())result<<field.second+"："+text;}
  return result.join('\n');
}
QString contextText(const QJsonObject &detail) {
  const auto finding=detail["finding"].toObject();const auto data=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();
  QStringList result{"本次验证入口："+detail["default_target"].toString("待确认"),"扫描来源："+finding["source_tool"].toString(),"严重程度："+finding["severity"].toString(),keyFacts(data)};
  if(data.isEmpty())result<<"暂无可展示的结构化发现详情。";
  for(const auto &v:detail["payloads"].toObject()["matches"].toArray()) {
    const auto payload=v.toObject();const auto name=payload["name"].isObject()?payload["name"].toObject()["zh"].toString():payload["name"].toString();
    result<<"\n候选载荷："+name<<"匹配依据："+readable(payload["match_basis"])<<"适用条件："+readable(payload["prerequisites"]);
  }
  return result.join('\n');
}
QString evidenceFacts(const QJsonObject &e) {
  const auto data=e["evidence_data"].toObject();
  const auto output=QJsonDocument::fromJson(e["raw_stdout"].toString().toUtf8()).object();
  QStringList result;const auto facts=keyFacts(data),observed=keyFacts(output);
  if(!facts.isEmpty())result<<facts;if(!observed.isEmpty())result<<observed;
  if(result.isEmpty())result<<"未提取到关键观察数据，不能据此认定漏洞成立。";
  return result.join('\n');
}
QString attemptText(const QJsonObject &a) {
  QStringList result{"状态："+stateText(a["state"].toString()),"执行时间："+a["created_at"].toString(),
    QString("方案版本：%1 · 停止确认：%2").arg(a["revision"].toInt()).arg(a["stop_confirmed"].toInt()==1?"已确认":"未确认"),readable(a["reason"])};
  for(const auto &v:a["steps"].toArray()){const auto step=v.toObject();result<<QString("步骤 %1 · %2 · %3").arg(step["step_index"].toInt()+1).arg(step["tool_id"].toString(),step["success"].toInt()==1?"工具完成":"执行异常");}
  for(const auto &v:a["reviews"].toArray()){const auto review=v.toObject();result<<"复核结论："+stateText(review["conclusion"].toString())<<"依据："+readable(review["note"]);}
  return result.join('\n');
}
QString cell(QTableWidget *table,int row,int col) {return table->item(row,col)?table->item(row,col)->text():QString();}
}
FindingVerificationDialog::FindingVerificationDialog(ApiClient *api,const QString &pipeline,const QList<qint64> &findings,QWidget *parent)
  :QDialog(parent),m_api(api),m_pipeline(pipeline) {
  setWindowTitle("逐漏洞验证 · "+pipeline);resize(1200,820);
  auto *layout=new QVBoxLayout(this);
  layout->addWidget(new QLabel("每条发现独立保存计划、执行尝试和证据。工具成功不代表漏洞成立；未去重的发现按记录展示。"));
  auto *split=new QSplitter(this);layout->addWidget(split,1);
  m_items=new QTableWidget(0,6);m_items->setHorizontalHeaderLabels({"选择","执行状态","验证结论","漏洞名称","位置","严重程度"});
  m_items->setSelectionBehavior(QAbstractItemView::SelectRows);m_items->setSelectionMode(QAbstractItemView::SingleSelection);
  m_items->setEditTriggers(QAbstractItemView::NoEditTriggers);m_items->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);m_items->horizontalHeader()->moveSection(3,1);m_items->hideColumn(4);m_items->hideColumn(5);
  m_items->setColumnWidth(3,170);m_items->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);
  split->addWidget(m_items);
  auto *tabs=new QTabWidget;m_tabs=tabs;split->addWidget(tabs);split->setStretchFactor(1,3);split->setSizes({360,840});
  auto *simple=new QWidget;auto *simpleLayout=new QVBoxLayout(simple);
  auto *intro=new QLabel("1. 准备方案 → 2. 核对并确认 → 3. 开始验证 → 4. 查看结果");intro->setWordWrap(true);simpleLayout->addWidget(intro);
  m_planSummary=new QPlainTextEdit;m_planSummary->setReadOnly(true);simpleLayout->addWidget(m_planSummary,1);
  m_prepareSimple=new QPushButton("1. 准备验证方案");m_confirmSimple=new QPushButton("2. 确认此方案");m_startSimple=new QPushButton("3. 开始验证");
  m_startSimple->setStyleSheet(Theme::ButtonStyle);
  auto *simpleActions=new QHBoxLayout;simpleActions->addWidget(m_prepareSimple);simpleActions->addWidget(m_confirmSimple);simpleActions->addWidget(m_startSimple);simpleLayout->addLayout(simpleActions);
  auto *resultSimple=new QPushButton("查看执行进度与结果");simpleLayout->addWidget(resultSimple);
  tabs->addTab(simple,"漏洞与方案");
  connect(m_prepareSimple,&QPushButton::clicked,this,[this]{
    if(!allowDiscardDraft())return;
    action("/generate",{{"expected_revision",m_revision}},true);
  });
  connect(m_confirmSimple,&QPushButton::clicked,this,[this]{
    if(QMessageBox::question(this,"确认验证方案","请核对上方目标、步骤、前置条件和成功判据。确认后可启动，当前不会执行工具。",QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Yes)return;
    action("/confirm",{{"revision",m_revision},{"conditions_confirmed",true},{"criteria_confirmed",true}});
  });
  connect(m_startSimple,&QPushButton::clicked,this,&FindingVerificationDialog::startCurrent);
  connect(resultSimple,&QPushButton::clicked,this,[tabs]{tabs->setCurrentIndex(2);});
  m_context=new QPlainTextEdit;m_context->setReadOnly(true);simpleLayout->insertWidget(1,m_context);m_context->setMaximumHeight(130);
  auto *planWidget=new QWidget;auto *p=new QVBoxLayout(planWidget);auto *advancedScroll=new QScrollArea;advancedScroll->setWidgetResizable(true);advancedScroll->setWidget(planWidget);tabs->addTab(advancedScroll,"调整方案");
  auto *form=new QFormLayout;m_name=new QLineEdit;m_target=new QLineEdit;
  form->addRow("计划名称",m_name);form->addRow("具体入口",m_target);p->addLayout(form);
  auto *templates=new QHBoxLayout;m_sources=new QComboBox;templates->addWidget(m_sources,1);
  auto *use=new QPushButton("使用模板");templates->addWidget(use);m_generate=m_prepareSimple;p->addLayout(templates);
  auto *fields=new QHBoxLayout;
  auto field=[&](const QString &name,QPlainTextEdit *&edit){auto *column=new QVBoxLayout;column->addWidget(new QLabel(name));edit=new QPlainTextEdit;edit->setMaximumHeight(80);column->addWidget(edit);fields->addLayout(column);};
  field("前置条件（每行一项）",m_conditions);field("尚缺条件（有内容则不能启动）",m_missing);p->addLayout(fields);
  p->addWidget(new QLabel("验证步骤（由方案准备生成，核对每一步的目的与预期结果）"));
  m_steps=new QTableWidget(0,3);m_steps->setHorizontalHeaderLabels({"步骤名称","工具","预期证据"});
  m_steps->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);p->addWidget(m_steps,1);
  auto *payloadRow=new QHBoxLayout;m_payloads=new QComboBox;payloadRow->addWidget(m_payloads,1);
  auto *bind=new QPushButton("绑定到所选步骤");auto *resolve=new QPushButton("查找或生成载荷");payloadRow->addWidget(bind);payloadRow->addWidget(resolve);p->addLayout(payloadRow);
  auto *bottom=new QHBoxLayout;auto *criteriaCol=new QVBoxLayout;criteriaCol->addWidget(new QLabel("成功判据、正常对照与限制"));m_criteria=new QPlainTextEdit;m_criteria->setMaximumHeight(75);criteriaCol->addWidget(m_criteria);bottom->addLayout(criteriaCol);
  auto *cleanupCol=new QVBoxLayout;cleanupCol->addWidget(new QLabel("清理动作 / 无需清理的依据"));m_cleanup=new QPlainTextEdit;m_cleanup->setMaximumHeight(75);cleanupCol->addWidget(m_cleanup);bottom->addLayout(cleanupCol);p->addLayout(bottom);
  m_confirm=new QCheckBox(this);m_confirm->hide();
  m_save=new QPushButton("保存方案调整");p->addWidget(m_save);
  m_confirmButton=m_confirmSimple;m_start=m_startSimple;
  auto *evidenceWidget=new QWidget;auto *e=new QVBoxLayout(evidenceWidget);tabs->addTab(evidenceWidget,"执行结果");
  m_attempts=new QComboBox;e->addWidget(m_attempts);m_evidence=new QPlainTextEdit;m_evidence->setReadOnly(true);m_evidence->setMaximumHeight(80);e->addWidget(m_evidence);
  e->addWidget(new QLabel("勾选支持结论的证据，再填写判断依据。工具完成不等于漏洞成立。"));
  m_evidenceTable=new QTableWidget(0,4);m_evidenceTable->setHorizontalHeaderLabels({"选用","步骤","工具","关键观察"});
  m_evidenceTable->setMinimumHeight(130);m_evidenceTable->setColumnWidth(0,45);m_evidenceTable->setColumnWidth(1,50);m_evidenceTable->setColumnWidth(2,110);
  m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);m_evidenceTable->setWordWrap(true);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);e->addWidget(m_evidenceTable,1);
  auto *reviewForm=new QFormLayout;m_conclusion=new QComboBox;for(const auto &key:QStringList{"confirmed","not_verified","inconclusive","false_positive"})m_conclusion->addItem(stateText(key),key);
  reviewForm->addRow("复核结论",m_conclusion);e->addLayout(reviewForm);
  m_note=new QPlainTextEdit;m_note->setPlaceholderText("对照保存的成功判据，说明实际证据及判定限制");m_note->setMaximumHeight(60);e->addWidget(m_note);auto *review=new QPushButton("保存证据复核");e->addWidget(review);
  layout->addWidget(new QLabel("默认最多 2 次尝试，每次 5 分钟。关闭窗口停止待执行队列；当前调用继续，可重新打开查看或取消。"));
  m_status=new QLabel;m_status->setWordWrap(true);layout->addWidget(m_status);
  auto *global=new QHBoxLayout;auto *refresh=new QPushButton("刷新");auto *queue=new QPushButton("顺序验证勾选项");auto *cancel=new QPushButton("取消当前验证并停止队列");auto *close=new QPushButton("关闭窗口");
  for(auto *button:{refresh,queue,cancel,close})global->addWidget(button);layout->addLayout(global);
  m_timer=new QTimer(this);m_timer->setInterval(2000);connect(m_timer,&QTimer::timeout,this,[this]{load(false);});m_timer->start();
  connect(m_items,&QTableWidget::currentCellChanged,this,[this](int row,int,int previousRow,int previousColumn){
    if(row==previousRow) return;
    if(!allowDiscardDraft()) {
      const QSignalBlocker guard(m_items);
      m_items->setCurrentCell(previousRow,previousColumn);
      return;
    }
    ++m_contextGeneration;m_detail={};m_revision=0;m_dirty=false;m_stale=true;
    m_confirm->setChecked(false);updateButtons();load(true);
  });
  connect(refresh,&QPushButton::clicked,this,[this]{if(allowDiscardDraft())load(true);});connect(close,&QPushButton::clicked,this,&QDialog::accept);
  connect(m_save,&QPushButton::clicked,this,[this]{action("/plans",planInput(),true);});
  connect(use,&QPushButton::clicked,this,[this]{
    if(m_finished || m_busy || m_loading || m_stale || !m_activeQueue.isEmpty() || !allowDiscardDraft())return;
    const auto id=currentId();if(id.isEmpty())return;
    const auto context=m_contextGeneration, edits=m_editGeneration;
    const auto request=++m_templateGeneration;
    QPointer<FindingVerificationDialog> self(this);
    m_api->post(base()+"/"+id+"/template",{{"playbook_id",m_sources->currentData().toString()}},10000,
      [self,id,context,edits,request](const QJsonObject &r){
        if(!self || self->m_finished || self->currentId()!=id || self->m_contextGeneration!=context
            || self->m_templateGeneration!=request) return;
        if(self->m_editGeneration!=edits || !self->m_activeQueue.isEmpty()) {
          self->m_status->setText("模板返回期间计划已编辑或启动，保留当前内容；需要时请重新选择模板。");return;
        }
        if(r["status"]=="ok") {
          self->displayPlan(r["data"].toObject());++self->m_editGeneration;
          self->m_dirty=true;self->updateButtons();
        } else self->m_status->setText(r["error"].toObject()["message"].toString());
      });
  });
  connect(bind,&QPushButton::clicked,this,[this]{
    const int row=m_steps->currentRow(),index=m_payloads->currentIndex();if(row<0||index<0||row>=m_planSteps.size())return;
    const auto payload=m_matches[index].toObject();if(payload["consumption"]!="tool_args"){m_status->setText("此载荷仅供参考，不能直接用于执行。");return;}
    auto step=m_planSteps[row].toObject();step["consumption"]="independent";step["payload_id"]=payload["payload_id"];step["payload_version"]=payload["version"];m_planSteps[row]=step;
    ++m_editGeneration;m_dirty=true;m_confirm->setChecked(false);updateButtons();m_status->setText("已选择步骤载荷，请保存方案调整。工具适用性由服务端校验。");
  });
  connect(resolve,&QPushButton::clicked,this,[this]{const auto id=currentId();if(id.isEmpty())return;QPointer<FindingVerificationDialog> self(this);m_status->setText("正在查找或生成此漏洞载荷…");m_api->post("/api/payloads/resolve",{{"finding_id",m_detail["finding_id"]}},130000,[self,id](const QJsonObject &r){if(!self||self->currentId()!=id)return;self->m_status->setText(r["status"]=="ok"?"载荷已准备，请绑定步骤并核对工具与适用条件。":r["error"].toObject()["message"].toString());self->load(false);});});
  connect(m_attempts,QOverload<int>::of(&QComboBox::currentIndexChanged),this,&FindingVerificationDialog::renderAttempt);
  connect(review,&QPushButton::clicked,this,[this]{
    QJsonArray ids;for(int row=0;row<m_evidenceTable->rowCount();row++)if(m_evidenceTable->item(row,0)->checkState()==Qt::Checked)ids.append(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt());
    action("/reviews",{{"attempt_id",m_attempts->currentData().toString()},{"conclusion",m_conclusion->currentData().toString()},{"evidence_ids",ids},{"note",m_note->toPlainText()}});
  });
  connect(queue,&QPushButton::clicked,this,[this]{
    if(m_queuePreparing || m_queueStarting || !m_activeQueue.isEmpty()) return;
    ++m_queueGeneration;
    m_queueCancelled=std::make_shared<bool>(false);
    m_queue.clear();
    for(int row=0;row<m_items->rowCount();row++)
      if(m_items->item(row,0)->checkState()==Qt::Checked) m_queue<<m_items->item(row,0)->data(Qt::UserRole).toString();
    executeNext();
  });
  connect(cancel,&QPushButton::clicked,this,&FindingVerificationDialog::cancelCurrent);
  auto changed=[this] {if(!m_setting){++m_editGeneration;m_dirty=true;m_confirm->setChecked(false);updateButtons();}};
  connect(m_name,&QLineEdit::textChanged,this,changed);connect(m_target,&QLineEdit::textChanged,this,changed);
  for(auto *edit:{m_conditions,m_missing,m_criteria,m_cleanup})connect(edit,&QPlainTextEdit::textChanged,this,changed);
  connect(m_steps,&QTableWidget::itemChanged,this,[changed](QTableWidgetItem*){changed();});

  for(qint64 finding:findings)addFinding(finding);
  updateButtons();
}
bool FindingVerificationDialog::allowDiscardDraft() {
  if(!m_dirty) return true;
  return QMessageBox::question(this,"未保存的验证计划","当前修改尚未保存。是否放弃这些修改？",
    QMessageBox::Discard|QMessageBox::Cancel,QMessageBox::Cancel)==QMessageBox::Discard;
}
QString FindingVerificationDialog::base() const {return "/api/pipelines/"+QString::fromLatin1(QUrl::toPercentEncoding(m_pipeline))+"/verifications";}
QString FindingVerificationDialog::currentId() const {const int row=m_items->currentRow();return row>=0&&m_items->item(row,0)?m_items->item(row,0)->data(Qt::UserRole).toString():QString();}
void FindingVerificationDialog::addFinding(qint64 finding) {
  QPointer<FindingVerificationDialog> self(this);
  m_api->post(base(),{{"finding_id",finding}},10000,[self,finding](const QJsonObject &response){
    if(!self || self->m_finished)return;
    if(response["status"]!="ok"){self->m_status->setText(response["error"].toObject()["message"].toString());return;}
    const auto data=response["data"].toObject();const QString id=data["id"].toString();
    const int row=self->m_items->rowCount();self->m_items->insertRow(row);
    auto *choice=new QTableWidgetItem;choice->setToolTip(QString("发现记录 #%1").arg(finding));choice->setData(Qt::UserRole,id);
    choice->setFlags(choice->flags()|Qt::ItemIsUserCheckable);choice->setCheckState(Qt::Checked);self->m_items->setItem(row,0,choice);
    self->m_items->setItem(row,1,new QTableWidgetItem(stateText(data["state"].toString())));
    self->m_items->setItem(row,2,new QTableWidgetItem("待判定"));
    for(int col=3;col<6;col++)self->m_items->setItem(row,col,new QTableWidgetItem);
    self->m_items->item(row,3)->setText("读取发现…");
    if(row==0){self->m_items->setCurrentCell(0,0);return;}
    self->m_api->get(self->base()+"/"+id,10000,[self,id](const QJsonObject &reply){
      if(!self || self->m_finished)return;
      for(int row=0;row<self->m_items->rowCount();row++)if(self->m_items->item(row,0)->data(Qt::UserRole).toString()==id){
        if(reply["status"]!="ok"){self->m_items->item(row,3)->setText("读取失败，点击重试");return;}
        const auto detail=reply["data"].toObject(),finding=detail["finding"].toObject();
        const auto value=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();
        self->m_items->item(row,3)->setText(value["title"].toString(value["name"].toString(value["finding"].toString("漏洞候选"))));
        self->m_items->item(row,3)->setToolTip(self->m_items->item(row,3)->text());
        self->m_items->item(row,2)->setText(stateText(detail["summary"].toObject()["conclusion"].toString()));return;
      }
    });
  });
}
void FindingVerificationDialog::displayPlan(const QJsonObject &plan) {
  m_setting=true;
  m_sourceId=plan["source_playbook_id"].toString();m_name->setText(plan["name"].toString());m_target->setText(plan["target"].toString());
  m_conditions->setPlainText(join(plan["prerequisites"].toArray()));m_missing->setPlainText(join(plan["missing_conditions"].toArray()));m_criteria->setPlainText(plan["success_criteria"].toString());m_cleanup->setPlainText(plan["cleanup"].toString());
  m_planSteps=plan["steps"].toArray();m_steps->setRowCount(m_planSteps.size());
  for(int row=0;row<m_planSteps.size();row++){const auto step=m_planSteps[row].toObject();
    m_steps->setItem(row,0,new QTableWidgetItem(step["name"].toString()));
    auto *tool=new QTableWidgetItem(step["tool_id"].toString());tool->setFlags(tool->flags()&~Qt::ItemIsEditable);m_steps->setItem(row,1,tool);
    m_steps->setItem(row,2,new QTableWidgetItem(step["expected_evidence"].toString()));
  }
  m_confirm->setChecked(false);m_setting=false;m_dirty=false;updateButtons();
}
QJsonObject FindingVerificationDialog::planInput() const {
  QJsonArray steps;for(int row=0;row<m_steps->rowCount();row++) {
    auto step=m_planSteps[row].toObject();step["name"]=cell(m_steps,row,0);step["expected_evidence"]=cell(m_steps,row,2);
    if(step["args_template"].isString())step["args_template"]=QJsonDocument::fromJson(step["args_template"].toString().toUtf8()).array();
    steps.append(step);
  }
  return {{"expected_revision",m_revision},{"name",m_name->text()},{"target",m_target->text()},{"source_playbook_id",m_sourceId},{"prerequisites",lines(m_conditions)},{"missing_conditions",lines(m_missing)},{"success_criteria",m_criteria->toPlainText()},{"cleanup",m_cleanup->toPlainText()},{"max_attempts",2},{"duration_ms",300000},{"steps",steps}};
}
void FindingVerificationDialog::load(bool editor) {
  const auto id=currentId();
  if(m_finished || id.isEmpty()) return;
  if(m_loading) {m_reloadEditor=m_reloadEditor || editor;return;}
  m_loading=true;
  const auto context=m_contextGeneration;
  const auto edits=m_editGeneration;
  QPointer<FindingVerificationDialog> self(this);
  m_api->get(base()+"/"+id,10000,[self,id,editor,context,edits](const QJsonObject &r){if(!self || self->m_finished)return;self->m_loading=false;if(self->m_reloadEditor || self->currentId()!=id || self->m_contextGeneration!=context){const bool switched=self->currentId()!=id || self->m_contextGeneration!=context;self->m_reloadEditor=false;self->load(switched || edits==self->m_editGeneration);return;}if(r["status"]!="ok"){self->m_status->setText(r["error"].toObject()["message"].toString());return;}
    self->m_detail=r["data"].toObject();self->m_context->setPlainText(contextText(self->m_detail));const bool replaceEditor=editor && edits==self->m_editGeneration;if(replaceEditor) {
      self->m_revision=self->m_detail["revision"].toInt();self->m_stale=false;
    } else if(self->m_revision!=self->m_detail["revision"].toInt()) {
      self->m_stale=true;self->m_confirm->setChecked(false);
      self->m_status->setText("计划版本已变化，当前显示内容已过期。请刷新完整计划并重新核对。");
    }const auto summary=self->m_detail["summary"].toObject();const QString state=self->m_detail["state"].toString();const int row=self->m_items->currentRow();self->m_items->item(row,1)->setText(stateText(state));self->m_items->item(row,2)->setText(stateText(summary["conclusion"].toString()));const auto finding=self->m_detail["finding"].toObject();const auto found=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();self->m_items->item(row,3)->setText(found["title"].toString(found["name"].toString(found["finding"].toString())));self->m_items->item(row,4)->setText(found["url"].toString(found["location"].toString()));self->m_items->item(row,5)->setText(finding["severity"].toString());for(int c=0;c<6;c++)self->m_items->item(row,c)->setToolTip(self->m_items->item(row,c)->text());
    if(replaceEditor){const auto plans=self->m_detail["plans"].toArray();if(!plans.isEmpty())self->displayPlan(plans.first().toObject()["content"].toObject());else self->displayPlan({{"name","发现 #"+QString::number(self->m_detail["finding_id"].toInt())+" 验证"},{"target",self->m_detail["default_target"]}});}
    const auto findingRecord=self->m_detail["finding"].toObject();
    const auto findingData=QJsonDocument::fromJson(findingRecord["result_data"].toString().toUtf8()).object();
    QStringList overview{findingData["title"].toString(findingData["name"].toString(findingData["finding"].toString("漏洞候选"))),
      "状态："+stateText(state)+" · 结论："+stateText(summary["conclusion"].toString()),
      "扫描发现是候选，不代表已证实漏洞。"};
    const auto savedPlans=self->m_detail["plans"].toArray();
    if(self->m_detail["eligible"]==false) overview<<"\n"+self->m_detail["ineligibility_reason"].toString();
    else if(savedPlans.isEmpty()) overview<<"\n下一步：点击“准备验证方案”。系统将根据此条发现生成步骤并保存草稿，不会立即执行。";
    else {
      const auto saved=savedPlans.first().toObject();const auto plan=saved["content"].toObject();
      overview<<"\n目标："+plan["target"].toString()<<"方案："+plan["name"].toString()
        <<QString("保存版本：%1%2").arg(saved["revision"].toInt()).arg(saved["confirmed_at"].toString().isEmpty()?" · 待确认":" · 已确认")
        <<"\n前置条件：\n"+join(plan["prerequisites"].toArray());
      int number=0;overview<<"\n计划步骤：";
      for(const auto &v:plan["steps"].toArray()){const auto step=v.toObject();overview<<QString("%1. %2\n   预期证据：%3").arg(++number).arg(step["name"].toString(),step["expected_evidence"].toString());}
      overview<<"\n成功判据与限制：\n"+plan["success_criteria"].toString()<<"\n清理说明：\n"+plan["cleanup"].toString();
      if(!plan["missing_conditions"].toArray().isEmpty())overview<<"\n尚缺条件：\n"+join(plan["missing_conditions"].toArray());
    }
    if(self->m_stale)overview<<"\n版本发生变化：请刷新后重新核对，当前禁止执行。";
    if(self->m_dirty)overview<<"\n方案调整中有未保存修改：请先保存，当前禁止执行。";
    if(!self->m_detail["reason"].toString().isEmpty())overview<<"\n需要处理："+self->m_detail["reason"].toString();
    self->m_planSummary->setPlainText(overview.join('\n'));
    const QString selected=self->m_attempts->currentData().toString();self->m_attempts->blockSignals(true);self->m_attempts->clear();for(const auto &v:self->m_detail["attempts"].toArray()){const auto a=v.toObject();self->m_attempts->addItem(a["created_at"].toString()+" · "+stateText(a["state"].toString()),a["id"].toString());}const int index=self->m_attempts->findData(selected);self->m_attempts->setCurrentIndex(index<0?0:index);self->m_attempts->blockSignals(false);const auto attempts=self->m_detail["attempts"].toArray();self->renderAttempt(self->m_attempts->currentIndex());
    self->m_matches=self->m_detail["payloads"].toObject()["matches"].toArray();const auto payloadId=self->m_payloads->currentData();self->m_payloads->clear();for(const auto &v:self->m_matches){const auto a=v.toObject();self->m_payloads->addItem(a["name"].toString(a["payload_id"].toString())+ (a["consumption"]=="tool_args"?" · 可用于步骤":" · 参考资料"),a["payload_id"].toString());}self->m_payloads->setCurrentIndex(qMax(0,self->m_payloads->findData(payloadId)));self->updateButtons();
    if(!self->m_detail["reason"].toString().isEmpty())self->m_status->setText(self->m_detail["reason"].toString());
    if(!self->m_queueStarting && !self->m_queueRunId.isEmpty() && summary["run_id"].toString()==self->m_queueRunId && self->m_activeQueue==id && QStringList{"completed","failed","aborted","unknown"}.contains(state)){self->m_activeQueue.clear();self->m_queueRunId.clear();self->m_items->setEnabled(true);self->updateButtons();if(state=="unknown"||state=="aborted")self->m_queue.clear();self->executeNext();}
  });
  if(editor)m_api->get(base()+"/"+id+"/sources",10000,[self,id](const QJsonObject &r){if(!self||self->currentId()!=id)return;self->m_sources->clear();for(const auto &v:r["data"].toArray()){const auto s=v.toObject();self->m_sources->addItem(s["name"].toString(),s["playbook_id"].toString());}});
}
void FindingVerificationDialog::action(const QString &path,const QJsonObject &body,bool editor) {
  if(m_finished||m_busy||currentId().isEmpty())return;
  if(m_stale && path!="/reviews") {m_status->setText("请刷新最新完整计划后再操作。");return;}const auto id=currentId();const auto edits=m_editGeneration;const auto context=m_contextGeneration;m_busy=true;updateButtons();m_status->setText("正在处理…");QPointer<FindingVerificationDialog> self(this);
  m_api->post(base()+"/"+id+path,body,path=="/generate"?130000:15000,[self,id,editor,edits,context](const QJsonObject &r){if(!self)return;self->m_busy=false;self->updateButtons();if(self->currentId()!=id || self->m_contextGeneration!=context)return;self->m_status->setText(r["status"]=="ok"?(r["data"].toObject()["state"]=="needs_conditions"?"方案尚缺条件，未启动验证。":"已保存；请查看当前状态与证据。"):r["error"].toObject()["message"].toString());self->load(editor && r["status"]=="ok" && edits==self->m_editGeneration);});
}
void FindingVerificationDialog::done(int result) {
  m_finished=true;
  ++m_queueGeneration;
  m_queue.clear();
  m_timer->stop();
  // Closing prevents future dispatch. Calls already submitted keep running unless cancelled.
  QDialog::done(result);
}
void FindingVerificationDialog::cancelCurrent() {
  ++m_queueGeneration;
  *m_queueCancelled=true;
  m_queue.clear();
  m_queuePreparing=false;
  updateButtons();
  const auto id=m_activeQueue.isEmpty()?currentId():m_activeQueue;
  if(id.isEmpty()) return;
  QPointer<FindingVerificationDialog> self(this);
  m_api->post(base()+"/"+id+"/cancel",{},10000,[self](const QJsonObject &r){
    if(!self || self->m_finished) return;
    self->m_status->setText(r["status"]=="ok"?"取消请求已提交，等待实际停止确认。":r["error"].toObject()["message"].toString());
    self->load(false);
  });
}
void FindingVerificationDialog::executeNext() {
  if(m_finished || m_queuePreparing || m_queueStarting || m_queue.isEmpty() || !m_activeQueue.isEmpty()) return;
  const auto id=m_queue.takeFirst();
  const auto generation=m_queueGeneration;
  const auto cancelled=m_queueCancelled;
  m_queuePreparing=true;
  updateButtons();
  QPointer<FindingVerificationDialog> self(this);
  m_api->get(base()+"/"+id,10000,[self,id,generation,cancelled](const QJsonObject &r){
    if(!self || self->m_finished || generation!=self->m_queueGeneration || *cancelled) return;
    self->m_queuePreparing=false;
    self->updateButtons();
    const auto d=r["data"].toObject();
    const auto plans=d["plans"].toArray();
    if(r["status"]!="ok" || plans.isEmpty() || plans.first().toObject()["confirmed_at"].toString().isEmpty()
        || !QStringList{"ready","completed","failed"}.contains(d["state"].toString())) {
      self->m_status->setText("队列跳过未准备好的验证项 "+id);
      self->executeNext();return;
    }
    self->startAttempt(id,d["revision"].toInt());
  });
}
void FindingVerificationDialog::startCurrent() {
  if(m_detail["eligible"]==false || m_finished || m_busy || m_loading || m_dirty || m_stale || m_revision<1
      || m_queuePreparing || m_queueStarting || !m_activeQueue.isEmpty() || currentId().isEmpty()) return;
  if(QStringList{"queued","running","cancelling","unknown"}.contains(m_detail["state"].toString())) return;
  ++m_queueGeneration;
  m_queue.clear();
  m_queueCancelled=std::make_shared<bool>(false);
  startAttempt(currentId(),m_revision);
}
void FindingVerificationDialog::startAttempt(const QString &id,int revision) {
  if(m_finished || m_queueStarting || !m_activeQueue.isEmpty() || *m_queueCancelled) return;
  const auto generation=m_queueGeneration;
  const auto cancelled=m_queueCancelled;
  m_activeQueue=id;
  m_queueRunId.clear();
  m_queueStarting=true;
  updateButtons();
  m_items->setEnabled(false);
  for(int row=0;row<m_items->rowCount();row++)
    if(m_items->item(row,0)->data(Qt::UserRole).toString()==id) m_items->setCurrentCell(row,0);
  const auto path=base()+"/"+id;
  QPointer<FindingVerificationDialog> self(this);
  QPointer<ApiClient> api(m_api);
  m_api->post(path+"/execute",{{"revision",revision},{"request_id",QUuid::createUuid().toString(QUuid::WithoutBraces)}},15000,
    [self,api,path,id,generation,cancelled](const QJsonObject &reply){
      // Both single and queued starts retain cancellation independently of the window lifetime.
      if(*cancelled && api) api->post(path+"/cancel",{},10000);
      if(!self || self->m_finished || self->m_activeQueue!=id) return;
      self->m_queueStarting=false;
      self->m_queueRunId=reply["data"].toObject()["run_id"].toString();
      if(generation!=self->m_queueGeneration) self->m_queue.clear();
      if(reply["status"]!="ok") {
        self->m_status->setText(reply["error"].toObject()["message"].toString());
        self->m_activeQueue.clear();self->m_items->setEnabled(true);self->m_queue.clear();
      }
      self->updateButtons();
      self->load(false);
    });
}
void FindingVerificationDialog::updateButtons() {
  const bool idle=m_detail["eligible"]!=false && m_activeQueue.isEmpty()&&!m_finished&&!m_stale&&!m_queuePreparing&&!m_queueStarting&&!m_loading&&!m_busy&&!currentId().isEmpty()&&!QStringList{"queued","running","cancelling","unknown"}.contains(m_detail["state"].toString());
  const auto plans=m_detail["plans"].toArray();
  const bool confirmed=!plans.isEmpty()&&!plans.first().toObject()["confirmed_at"].toString().isEmpty();
  m_prepareSimple->setEnabled(idle&&!m_dirty);
  m_confirmSimple->setEnabled(idle&&m_revision>0&&!m_dirty&&m_detail["state"].toString()!="needs_conditions");
  m_startSimple->setEnabled(idle&&m_revision>0&&!m_dirty&&confirmed);
  m_save->setEnabled(idle&&m_dirty);
}

void FindingVerificationDialog::renderAttempt(int index) {
  const auto attempts=m_detail["attempts"].toArray();
  if(index<0 || index>=attempts.size()){m_evidence->clear();m_evidenceTable->setRowCount(0);m_evidenceAttempt.clear();return;}
  const auto attempt=attempts[index].toObject();QSet<int> checked;
  if(m_evidenceAttempt==attempt["id"].toString())for(int row=0;row<m_evidenceTable->rowCount();row++)if(m_evidenceTable->item(row,0)->checkState()==Qt::Checked)checked.insert(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt());
  m_evidenceAttempt=attempt["id"].toString();m_evidence->setPlainText(attemptText(attempt));
  const auto records=attempt["evidence"].toArray();m_evidenceTable->setRowCount(records.size());
  for(int row=0;row<records.size();row++){const auto record=records[row].toObject();auto *choice=new QTableWidgetItem;choice->setTextAlignment(Qt::AlignTop|Qt::AlignHCenter);choice->setData(Qt::UserRole,record["id"].toInt());choice->setFlags(choice->flags()|Qt::ItemIsUserCheckable);choice->setCheckState(checked.contains(record["id"].toInt())?Qt::Checked:Qt::Unchecked);m_evidenceTable->setItem(row,0,choice);
    m_evidenceTable->setItem(row,1,new QTableWidgetItem(QString::number(record["step_index"].toInt()+1)));m_evidenceTable->setItem(row,2,new QTableWidgetItem(record["tool_id"].toString()));m_evidenceTable->setItem(row,3,new QTableWidgetItem(evidenceFacts(record)));
  }m_evidenceTable->resizeRowsToContents();
  for(int row=0;row<m_evidenceTable->rowCount();row++)for(int col=1;col<4;col++)m_evidenceTable->item(row,col)->setTextAlignment(Qt::AlignTop|Qt::AlignLeft);
}
