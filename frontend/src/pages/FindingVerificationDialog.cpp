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
#include <QGroupBox>
#include <QInputDialog>

namespace {
void comboPlaceholder(QComboBox *combo,const QString &text) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
  combo->setPlaceholderText(text);
#else
  combo->setEditable(true);combo->lineEdit()->setReadOnly(true);combo->lineEdit()->setPlaceholderText(text);
#endif
}
QString stateText(const QString &s) {
  static const QMap<QString,QString> labels{{"needs_conditions","待补条件"},{"preparation_failed","方案未就绪"},{"draft","草稿"},{"ready","就绪"},
    {"queued","排队中"},{"running","执行中"},{"cancelling","取消中"},{"unknown","停止待核查"},
    {"completed","执行结束"},{"failed","执行异常"},{"aborted","已中止"},
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
    {"detail","观察结果"},{"error","异常原因"},{"exit_code","退出码"}};
  QStringList result;
  for(const auto &field:fields){const auto text=readable(data[field.first]);if(!text.isEmpty())result<<field.second+"："+text;}
  return result.join('\n');
}
QString contextText(const QJsonObject &detail) {
  const auto finding=detail["finding"].toObject();const auto data=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();
  QStringList result{data["title"].toString(data["name"].toString(data["finding"].toString("漏洞候选"))),"本次测试入口："+detail["default_target"].toString("待确认"),"来源："+finding["source_tool"].toString()+" · 严重程度："+finding["severity"].toString()};
  if(data.contains("path"))result<<"扫描位置："+readable(data["path"]);
  if(data.isEmpty())result<<"暂无可展示的结构化发现详情。";
  for(const auto &v:detail["payloads"].toObject()["matches"].toArray()) {
    const auto payload=v.toObject();const auto name=payload["name"].isObject()?payload["name"].toObject()["zh"].toString():payload["name"].toString();
    result<<"\n候选载荷："+name<<"匹配依据："+readable(payload["match_basis"])<<"适用条件："+readable(payload["prerequisites"]);
  }
  return result.join('\n');
}
QString evidenceFacts(const QJsonObject &e) {
  const auto data=e["evidence_data"].toObject();
  const auto output=e["observation"].isObject()?e["observation"].toObject():QJsonDocument::fromJson(e["raw_stdout"].toString().toUtf8()).object();
  QStringList result;const auto facts=keyFacts(data),observed=keyFacts(output);
  if(!facts.isEmpty())result<<facts;if(!observed.isEmpty())result<<observed;
  const auto headers=output["response_headers"].toObject();
  for(const auto &name:{"content-type","x-content-type-options","x-frame-options","content-security-policy"}) {
    if(headers.contains(name))result<<QString::fromLatin1(name)+"："+readable(headers[name]);
  }
  if(output.contains("received_bytes"))result<<"响应字节数："+readable(output["received_bytes"]);
  if(output.contains("login_form_present"))result<<"检测到密码输入框特征："+readable(output["login_form_present"]);
  if(output.contains("observation_note"))result<<readable(output["observation_note"]);
  if(output.contains("complete"))result<<"响应完整："+readable(output["complete"]);
  if(output.contains("cookie_attributes_complete"))result<<"Cookie 属性采集完整："+readable(output["cookie_attributes_complete"]);
  for(const auto &value:output["cookie_attributes"].toArray()) {
    const auto cookie=value.toObject();result<<"Cookie "+readable(cookie["name"])+" · HttpOnly："+readable(cookie["httponly"])+" · Secure："+readable(cookie["secure"]);
  }
  if(result.isEmpty())result<<"未提取到关键观察数据，不能据此认定漏洞成立。";
  return result.join('\n');
}
QString attemptText(const QJsonObject &a) {
  QStringList result{"状态："+stateText(a["state"].toString()),"执行时间："+a["created_at"].toString(),
    QString("方案版本：%1 · 停止确认：%2").arg(a["revision"].toInt()).arg(a["stop_confirmed"].toInt()==1?"已确认":"未确认"),readable(a["reason"])};
  for(const auto &v:a["steps"].toArray()){const auto step=v.toObject();result<<QString("步骤 %1 · %2 · %3").arg(step["step_index"].toInt()+1).arg(step["tool_id"].toString(),step["success"].toInt()==1?"工具完成":"执行异常");}
  if(a["state"]=="completed" && a["assessments"].toArray().isEmpty() && a["reviews"].toArray().isEmpty())result<<"执行已完成，尚无漏洞结论：请按方案判据查看证据并人工复核。";
  for(const auto &v:a["assessments"].toArray()){const auto judgement=v.toObject();result<<"自动判定："+stateText(judgement["conclusion"].toString())<<"依据："+readable(judgement["reason"])<<"限制："+readable(judgement["limitations"]);}
  for(const auto &v:a["evidence"].toArray()){const auto data=v.toObject()["evidence_data"].toObject();const auto link=data["finding_verification"].toObject();
    if(link["payload_consumed"].toBool())result<<"实际消费载荷："+data["payload_id"].toString()+" · 版本 "+readable(data["payload_version"]);
    else if(!data["payload_id"].toString().isEmpty())result<<"历史载荷引用（未确认实际消费）："+data["payload_id"].toString();
  }
  for(const auto &v:a["reviews"].toArray()){const auto review=v.toObject();result<<"复核结论："+stateText(review["conclusion"].toString())<<"依据："+readable(review["note"]);}
  return result.join('\n');
}
QString stepInputSummary(const QJsonObject &step,const QString &target) {
  const auto payload=step["payload_snapshot"].toObject();const auto consumption=payload["consumption"].toObject();
  QJsonValue args=consumption["args_template"].isArray()?consumption["args_template"]:step["args_template"];
  if(args.isString())args=QJsonDocument::fromJson(args.toString().toUtf8()).array();
  QJsonArray array;
  const auto variables=step["payload_variables"].toObject();
  for(const auto &value:args.toArray()) {
    auto rendered=value.toString().replace("<target>",target);
    for(auto it=variables.begin();it!=variables.end();++it)rendered.replace("{{"+it.key()+"}}",it.value().toString());
    array.append(rendered);
  }
  if(step["tool_id"]=="target-request"&&!array.isEmpty()) {
    const auto spec=QJsonDocument::fromJson(array.first().toString().replace("<target>",target).toUtf8()).object();
    QStringList parts{spec["method"].toString(spec["url"].toString().startsWith("tcp:")?"TCP 交互":"GET")+" "+spec["url"].toString()};
    if(!spec["body"].toString().isEmpty())parts<<"测试输入："+readable(spec["body"]);
    if(!spec["exchanges"].toArray().isEmpty())parts<<QString("交互 %1 轮").arg(spec["exchanges"].toArray().size());
    return parts.join("；");
  }
  QStringList parts;for(const auto &arg:array){auto text=readable(arg);if(!text.isEmpty())parts<<text.replace("<target>",target);}return parts.join(" ");
}
QString cell(QTableWidget *table,int row,int col) {return table->item(row,col)?table->item(row,col)->text():QString();}
}
FindingVerificationDialog::FindingVerificationDialog(ApiClient *api,const QString &pipeline,const QList<qint64> &findings,QWidget *parent)
  :QDialog(parent),m_api(api),m_pipeline(pipeline) {
  setWindowTitle("逐漏洞攻击测试 · "+pipeline);resize(1200,820);
  auto *layout=new QVBoxLayout(this);
  layout->addWidget(new QLabel("针对勾选的漏洞选择方案和载荷，统一确认后测试。执行结果与漏洞结论分别记录。"));
  auto *split=new QSplitter(this);layout->addWidget(split,1);
  m_items=new QTableWidget(0,6);m_items->setHorizontalHeaderLabels({"选择","执行状态","验证结论","漏洞名称","位置","严重程度"});
  m_items->setSelectionBehavior(QAbstractItemView::SelectRows);m_items->setSelectionMode(QAbstractItemView::SingleSelection);
  m_items->setEditTriggers(QAbstractItemView::NoEditTriggers);m_items->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);m_items->horizontalHeader()->moveSection(3,1);m_items->hideColumn(4);m_items->hideColumn(5);
  m_items->setColumnWidth(3,170);m_items->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);
  split->addWidget(m_items);
  auto *tabs=new QTabWidget;m_tabs=tabs;split->addWidget(tabs);split->setStretchFactor(1,3);split->setSizes({360,840});
  auto *mainPage=new QWidget;auto *mainLayout=new QVBoxLayout(mainPage);
  auto *scroll=new QScrollArea;scroll->setWidgetResizable(true);scroll->setWidget(mainPage);
  auto *mainHost=new QWidget;auto *hostLayout=new QVBoxLayout(mainHost);hostLayout->setContentsMargins(0,0,0,0);hostLayout->addWidget(scroll,1);tabs->addTab(mainHost,"攻击测试方案");
  auto section=[mainLayout](const QString &title){auto *box=new QGroupBox(title);auto *content=new QVBoxLayout(box);mainLayout->addWidget(box);return content;};
  auto *findingSection=section("当前漏洞");m_context=new QPlainTextEdit;m_context->setReadOnly(true);m_context->setMaximumHeight(80);findingSection->addWidget(m_context);
  auto *sourceSection=section("1. 选择攻击测试方案");
  m_sourceChooser=new QGroupBox("查看推荐方案 / 更换方案");m_sourceChooser->setCheckable(true);m_sourceChooser->setChecked(true);
  auto *chooserLayout=new QVBoxLayout(m_sourceChooser);auto *candidateBody=new QWidget;auto *candidateLayout=new QVBoxLayout(candidateBody);candidateLayout->setContentsMargins(0,0,0,0);chooserLayout->addWidget(candidateBody);sourceSection->addWidget(m_sourceChooser);
  connect(m_sourceChooser,&QGroupBox::toggled,candidateBody,&QWidget::setVisible);
  m_sources=new QComboBox;m_sources->setMinimumContentsLength(16);candidateLayout->addWidget(m_sources);
  m_sourcePreview=new QPlainTextEdit;m_sourcePreview->setReadOnly(true);m_sourcePreview->setMaximumHeight(75);m_sourcePreview->hide();candidateLayout->addWidget(m_sourcePreview);
  auto *sourceActions=new QHBoxLayout;m_useSource=new QPushButton("使用此方案");m_prepareSimple=new QPushButton("AI 生成新方案");m_adjustAI=new QPushButton("AI 辅助调整当前方案");
  candidateLayout->addWidget(m_useSource);sourceActions->addWidget(m_prepareSimple);sourceActions->addWidget(m_adjustAI);sourceSection->addLayout(sourceActions);
  auto *browse=new QHBoxLayout;m_sourceSearch=new QLineEdit;m_sourceSearch->setPlaceholderText("无合适候选？搜索其他方案");auto *search=new QPushButton("浏览其他方案");
  m_sourcesPrevious=new QPushButton("上一页");m_sourcesNext=new QPushButton("下一页");browse->addWidget(m_sourceSearch,1);browse->addWidget(search);browse->addWidget(m_sourcesPrevious);browse->addWidget(m_sourcesNext);candidateLayout->addLayout(browse);
  m_planSummary=new QPlainTextEdit;m_planSummary->setReadOnly(true);m_planSummary->setMinimumHeight(130);m_planSummary->setMaximumHeight(130);sourceSection->addWidget(m_planSummary);
  auto *editBox=new QGroupBox("调整当前草稿（按需展开）");editBox->setCheckable(true);editBox->setChecked(false);auto *editLayout=new QVBoxLayout(editBox);auto *editBody=new QWidget;auto *p=new QVBoxLayout(editBody);editLayout->addWidget(editBody);editBody->hide();connect(editBox,&QGroupBox::toggled,editBody,&QWidget::setVisible);sourceSection->addWidget(editBox);
  auto *form=new QFormLayout;m_name=new QLineEdit;m_target=new QLineEdit;form->addRow("方案名称",m_name);form->addRow("实际入口",m_target);p->addLayout(form);
  auto field=[p](const QString &label,QPlainTextEdit *&edit){p->addWidget(new QLabel(label));edit=new QPlainTextEdit;edit->setMaximumHeight(65);p->addWidget(edit);};
  field("前置条件",m_conditions);field("缺失条件",m_missing);
  m_steps=new QTableWidget(0,3);m_steps->setHorizontalHeaderLabels({"步骤名称","工具","预期证据"});m_steps->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);m_steps->setMinimumHeight(100);p->addWidget(m_steps);
  field("成功判据与限制",m_criteria);field("清理说明",m_cleanup);m_save=new QPushButton("保存方案调整");p->addWidget(m_save);
  auto *payloadSection=section("2. 本次载荷与步骤关联");m_payloads=new QComboBox;payloadSection->addWidget(m_payloads);
  m_payloadPreview=new QPlainTextEdit;m_payloadPreview->setReadOnly(true);m_payloadPreview->setMinimumHeight(120);payloadSection->addWidget(m_payloadPreview);
  auto *binding=new QHBoxLayout;m_bindStep=new QComboBox;comboPlaceholder(m_bindStep,"请手动选择目标步骤");binding->addWidget(m_bindStep,1);
  m_bindPayload=new QPushButton("绑定到此步骤");m_unbindPayload=new QPushButton("解除绑定");binding->addWidget(m_bindPayload);binding->addWidget(m_unbindPayload);payloadSection->addLayout(binding);
  m_resolvePayload=new QPushButton("为所选步骤查找或生成载荷");payloadSection->addWidget(m_resolvePayload);
  auto *preflightSection=section("3. 执行前检查");auto *hint=new QLabel("核对方案来源、目标、前提、步骤输入及载荷。开始测试时统一确认，修改方案或载荷后需重新核对。");hint->setWordWrap(true);preflightSection->addWidget(hint);
  m_startSimple=new QPushButton("开始测试");m_startSimple->setStyleSheet(Theme::ButtonStyle);hostLayout->addWidget(m_startSimple);
  m_start=m_startSimple;m_generate=m_prepareSimple;m_confirmButton=m_startSimple;m_confirmSimple=m_startSimple;
  m_confirm=new QCheckBox(this);m_confirm->hide();
  connect(m_sources,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showSourcePreview();updateButtons();});
  connect(search,&QPushButton::clicked,this,[this]{m_browseSources=true;m_sourceOffset=0;loadSources();});
  connect(m_sourcesPrevious,&QPushButton::clicked,this,[this]{m_sourceOffset=qMax(0,m_sourceOffset-20);loadSources();});
  connect(m_sourcesNext,&QPushButton::clicked,this,[this]{m_sourceOffset+=20;loadSources();});
  connect(m_useSource,&QPushButton::clicked,this,[this]{if(!allowDiscardDraft()||m_sources->currentIndex()<0)return;action("/select-template",{{"playbook_id",m_sources->currentData().toString()},{"expected_revision",m_revision}},true);});
  connect(m_prepareSimple,&QPushButton::clicked,this,[this]{if(allowDiscardDraft())action("/generate",{{"expected_revision",m_revision},{"mode","new"}},true);});
  connect(m_adjustAI,&QPushButton::clicked,this,[this]{if(!allowDiscardDraft())return;bool ok=false;const auto instruction=QInputDialog::getText(this,"AI 辅助调整","说明希望调整的内容",QLineEdit::Normal,{},&ok);if(ok)action("/generate",{{"expected_revision",m_revision},{"mode","adjust"},{"instruction",instruction}},true);});
  connect(m_payloads,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showPayloadPreview();updateButtons();});
  connect(m_bindStep,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showPayloadPreview();updateButtons();});
  connect(m_bindPayload,&QPushButton::clicked,this,[this]{const int i=m_payloads->currentIndex();if(i<0||m_bindStep->currentIndex()<0)return;const auto payload=m_matches[i].toObject();action("/payloads/bind",{{"expected_revision",m_revision},{"step_id",m_bindStep->currentData().toString()},{"payload_id",payload["payload_id"]},{"version",payload["version"]}},true);});
  connect(m_unbindPayload,&QPushButton::clicked,this,[this]{if(m_bindStep->currentIndex()>=0)action("/payloads/unbind",{{"expected_revision",m_revision},{"step_id",m_bindStep->currentData().toString()}},true);});
  connect(m_resolvePayload,&QPushButton::clicked,this,[this]{if(m_bindStep->currentIndex()<0){m_status->setText("请先手动选择步骤。");return;}action("/payloads/prepare",{{"expected_revision",m_revision},{"step_id",m_bindStep->currentData().toString()}},false);});
  connect(m_startSimple,&QPushButton::clicked,this,&FindingVerificationDialog::startCurrent);
  auto *evidenceWidget=new QWidget;auto *e=new QVBoxLayout(evidenceWidget);auto *resultScroll=new QScrollArea;resultScroll->setWidgetResizable(true);resultScroll->setWidget(evidenceWidget);tabs->addTab(resultScroll,"测试结果与历史");
  m_attempts=new QComboBox;e->addWidget(m_attempts);m_evidence=new QPlainTextEdit;m_evidence->setReadOnly(true);m_evidence->setMaximumHeight(80);e->addWidget(m_evidence);
  e->addWidget(new QLabel("勾选支持结论的证据，再填写判断依据。工具完成不等于漏洞成立。"));
  m_evidenceTable=new QTableWidget(0,4);m_evidenceTable->setHorizontalHeaderLabels({"选用","步骤","工具","关键观察"});
  m_evidenceTable->setMinimumHeight(130);m_evidenceTable->setColumnWidth(0,45);m_evidenceTable->setColumnWidth(1,50);m_evidenceTable->setColumnWidth(2,110);
  m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);m_evidenceTable->setWordWrap(true);
  m_evidenceTable->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);e->addWidget(m_evidenceTable,1);
  auto *reviewForm=new QFormLayout;m_conclusion=new QComboBox;m_conclusion->addItem("请选择复核结论",QString());for(const auto &key:QStringList{"confirmed","not_verified","inconclusive","false_positive"})m_conclusion->addItem(stateText(key),key);
  reviewForm->addRow("复核结论",m_conclusion);e->addLayout(reviewForm);
  m_note=new QPlainTextEdit;m_note->setPlaceholderText("对照保存的成功判据，说明实际证据及判定限制");m_note->setMaximumHeight(60);e->addWidget(m_note);auto *review=new QPushButton("保存证据复核");e->addWidget(review);
  layout->addWidget(new QLabel("默认最多 2 次尝试，每次 5 分钟。关闭窗口停止待执行队列；当前调用继续，可重新打开查看或取消。"));
  m_queueLabel=new QLabel; m_queueLabel->setWordWrap(true);layout->addWidget(m_queueLabel);
  m_status=new QLabel;m_status->setWordWrap(true);layout->addWidget(m_status);
  auto *global=new QHBoxLayout;auto *refresh=new QPushButton("刷新");auto *queue=new QPushButton("顺序测试已就绪漏洞");m_queueButton=queue;auto *cancel=new QPushButton("取消当前验证并停止队列");auto *close=new QPushButton("关闭窗口");
  for(auto *button:{refresh,queue,cancel,close})global->addWidget(button);layout->addLayout(global);
  m_timer=new QTimer(this);m_timer->setInterval(2000);connect(m_timer,&QTimer::timeout,this,[this]{load(false);});m_timer->start();
  connect(m_items,&QTableWidget::currentCellChanged,this,[this](int row,int,int previousRow,int previousColumn){
    if(row==previousRow) return;
    if(!allowDiscardDraft()) {
      const QSignalBlocker guard(m_items);
      m_items->setCurrentCell(previousRow,previousColumn);
      return;
    }
    ++m_contextGeneration;m_pendingPayload.clear();m_browseSources=false;m_sourceOffset=0;m_detail={};
    m_sources->blockSignals(true);m_sources->clear();m_sources->blockSignals(false);m_sourceItems={};m_sourcePreview->clear();
    m_payloads->blockSignals(true);m_payloads->clear();m_payloads->blockSignals(false);m_matches={};m_payloadPreview->clear();
    m_context->clear();m_planSummary->setPlainText("正在读取此漏洞的方案与载荷…");m_revision=0;m_dirty=false;m_stale=true;
    m_confirm->setChecked(false);updateButtons();load(true);
  });
  connect(refresh,&QPushButton::clicked,this,[this]{if(allowDiscardDraft())load(true);});connect(close,&QPushButton::clicked,this,&QDialog::accept);
  connect(m_save,&QPushButton::clicked,this,[this]{action("/plans",planInput(),true);});
  connect(m_attempts,QOverload<int>::of(&QComboBox::currentIndexChanged),this,&FindingVerificationDialog::renderAttempt);
  connect(review,&QPushButton::clicked,this,[this]{
    if(m_conclusion->currentData().toString().isEmpty()){m_status->setText("请明确选择复核结论；执行完成不代表漏洞成立。");return;}
    QJsonArray ids;for(int row=0;row<m_evidenceTable->rowCount();row++)if(m_evidenceTable->item(row,0)->checkState()==Qt::Checked)ids.append(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt());
    action("/reviews",{{"attempt_id",m_attempts->currentData().toString()},{"conclusion",m_conclusion->currentData().toString()},{"evidence_ids",ids},{"note",m_note->toPlainText()}});
  });
  connect(queue,&QPushButton::clicked,this,&FindingVerificationDialog::startChecked);
  connect(cancel,&QPushButton::clicked,this,&FindingVerificationDialog::cancelCurrent);
  auto changed=[this] {if(!m_setting){++m_editGeneration;m_dirty=true;m_confirm->setChecked(false);updateButtons();}};
  connect(m_name,&QLineEdit::textChanged,this,changed);connect(m_target,&QLineEdit::textChanged,this,changed);
  for(auto *edit:{m_conditions,m_missing,m_criteria,m_cleanup})connect(edit,&QPlainTextEdit::textChanged,this,changed);
  connect(m_steps,&QTableWidget::itemChanged,this,[changed](QTableWidgetItem*){changed();});

  connect(m_items,&QTableWidget::itemChanged,this,[this](QTableWidgetItem*){updateQueue();});
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
        const auto detail=reply["data"].toObject(),finding=detail["finding"].toObject();self->m_details[id]=detail;self->updateQueue();
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
    self->m_detail=r["data"].toObject();self->m_details[id]=self->m_detail;self->m_context->setPlainText(contextText(self->m_detail));const bool replaceEditor=editor && edits==self->m_editGeneration;if(replaceEditor) {
      self->m_revision=self->m_detail["revision"].toInt();self->m_stale=false;
    } else if(self->m_revision!=self->m_detail["revision"].toInt()) {
      self->m_stale=true;self->m_confirm->setChecked(false);
      self->m_status->setText("计划版本已变化，当前显示内容已过期。请刷新完整计划并重新核对。");
    }const auto summary=self->m_detail["summary"].toObject();const QString state=self->m_detail["state"].toString();const int row=self->m_items->currentRow();self->m_items->item(row,1)->setText(stateText(state));self->m_items->item(row,2)->setText(stateText(summary["conclusion"].toString()));const auto finding=self->m_detail["finding"].toObject();const auto found=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();self->m_items->item(row,3)->setText(found["title"].toString(found["name"].toString(found["finding"].toString())));self->m_items->item(row,4)->setText(found["url"].toString(found["location"].toString()));self->m_items->item(row,5)->setText(finding["severity"].toString());for(int c=0;c<6;c++)self->m_items->item(row,c)->setToolTip(self->m_items->item(row,c)->text());
    if(replaceEditor)self->m_sourceChooser->setChecked(self->m_detail["plans"].toArray().isEmpty());
    if(replaceEditor){const auto plans=self->m_detail["plans"].toArray();if(!plans.isEmpty())self->displayPlan(plans.first().toObject()["content"].toObject());else self->displayPlan({{"name","发现 #"+QString::number(self->m_detail["finding_id"].toInt())+" 验证"},{"target",self->m_detail["default_target"]}});}
    const auto findingRecord=self->m_detail["finding"].toObject();
    const auto findingData=QJsonDocument::fromJson(findingRecord["result_data"].toString().toUtf8()).object();
    QStringList overview;
    const auto savedPlans=self->m_detail["plans"].toArray();
    if(self->m_detail["eligible"]==false) overview<<"\n"+self->m_detail["ineligibility_reason"].toString();
    else if(savedPlans.isEmpty()) overview<<"\n下一步：选择已有方案并点击“使用此方案”，或明确点击“AI 生成新方案”。保存草稿不会执行目标请求。";
    else {
      const auto saved=savedPlans.first().toObject();const auto plan=saved["content"].toObject();
      overview<<"当前方案："+plan["name"].toString()<<"目标："+plan["target"].toString()<<"来源："+plan["provenance"].toObject()["label"].toString("历史来源未记录")
        <<QString("保存版本：%1%2").arg(saved["revision"].toInt()).arg(saved["confirmed_at"].toString().isEmpty()?" · 待确认":" · 已确认")
        <<"\n前置条件：\n"+join(plan["prerequisites"].toArray());
      int number=0;overview<<"\n计划步骤：";
      for(const auto &v:plan["steps"].toArray()){const auto step=v.toObject();overview<<QString("%1. %2\n   预期证据：%3").arg(++number).arg(step["name"].toString(),step["expected_evidence"].toString());overview<<"   实际输入："+stepInputSummary(step,plan["target"].toString());}
      overview<<"\n判断方式："+(plan["assessment_rule"].toObject().isEmpty()?QString("人工证据复核"):QString("平台定向规则自动判断，仍可人工复核"))
        <<"\n成功判据与限制：\n"+plan["success_criteria"].toString()<<"\n清理说明：\n"+plan["cleanup"].toString();
      if(!plan["missing_conditions"].toArray().isEmpty())overview<<"\n尚缺条件：\n"+join(plan["missing_conditions"].toArray());
    }
    if(self->m_stale)overview<<"\n版本发生变化：请刷新后重新核对，当前禁止执行。";
    if(self->m_dirty)overview<<"\n方案调整中有未保存修改：请先保存，当前禁止执行。";
    if(!self->m_detail["reason"].toString().isEmpty())overview<<"\n需要处理："+self->m_detail["reason"].toString();
    const auto readiness=self->m_detail["readiness"].toObject();
    overview<<"\n执行前检查："+(readiness["ready"].toBool()?QString("已就绪，开始前统一确认"):join(readiness["reasons"].toArray()));
    self->m_planSummary->setPlainText(overview.join('\n'));
    const QString selected=self->m_attempts->currentData().toString();self->m_attempts->blockSignals(true);self->m_attempts->clear();for(const auto &v:self->m_detail["attempts"].toArray()){const auto a=v.toObject();self->m_attempts->addItem(a["created_at"].toString()+" · "+stateText(a["state"].toString()),a["id"].toString());}const int index=self->m_attempts->findData(selected);self->m_attempts->setCurrentIndex(index<0?0:index);self->m_attempts->blockSignals(false);const auto attempts=self->m_detail["attempts"].toArray();self->renderAttempt(self->m_attempts->currentIndex());
    const auto chosenStep=self->m_bindStep->currentData().toString();self->m_bindStep->blockSignals(true);self->m_bindStep->clear();
    if(!savedPlans.isEmpty())for(const auto &v:savedPlans.first().toObject()["content"].toObject()["steps"].toArray()){const auto step=v.toObject();self->m_bindStep->addItem(step["name"].toString()+" · "+step["tool_id"].toString(),step["step_id"].toString());}
    self->m_bindStep->setCurrentIndex(chosenStep.isEmpty()?-1:self->m_bindStep->findData(chosenStep));self->m_bindStep->blockSignals(false);
    self->m_matches=self->m_detail["payloads"].toObject()["matches"].toArray();const auto selectedPayload=self->m_pendingPayload.isEmpty()?self->m_payloads->currentData():QVariant(self->m_pendingPayload);self->m_pendingPayload.clear();
    self->m_payloads->blockSignals(true);self->m_payloads->clear();for(const auto &v:self->m_matches){const auto payload=v.toObject();self->m_payloads->addItem(payload["name"].toString()+ (payload["created_here"].toBool()?" · 本次新生成":" · 已有载荷"),payload["payload_id"].toString());}
    self->m_payloads->setCurrentIndex(self->m_payloads->findData(selectedPayload));self->m_payloads->blockSignals(false);
    self->showPayloadPreview();self->updateButtons();self->updateQueue();
    if(!self->m_detail["reason"].toString().isEmpty())self->m_status->setText(self->m_detail["reason"].toString());
    if(!self->m_queueStarting && !self->m_queueRunId.isEmpty() && summary["run_id"].toString()==self->m_queueRunId && self->m_activeQueue==id && QStringList{"completed","failed","aborted","unknown"}.contains(state)){self->m_activeQueue.clear();self->m_queueRunId.clear();self->m_items->setEnabled(true);self->updateButtons();if(state=="unknown"||state=="aborted")self->m_queue.clear();self->executeNext();}
  });
  if(editor)loadSources();
}
void FindingVerificationDialog::action(const QString &path,const QJsonObject &body,bool editor) {
  if(m_finished||m_busy||currentId().isEmpty())return;
  if(m_stale && path!="/reviews") {m_status->setText("请刷新最新完整计划后再操作。");return;}const auto id=currentId();const auto edits=m_editGeneration;const auto context=m_contextGeneration;m_busy=true;updateButtons();m_status->setText("正在处理…");QPointer<FindingVerificationDialog> self(this);
  m_api->post(base()+"/"+id+path,body,path=="/generate"?130000:15000,[self,id,editor,edits,context,path](const QJsonObject &r){if(!self)return;self->m_busy=false;self->updateButtons();if(self->currentId()!=id || self->m_contextGeneration!=context)return;self->m_status->setText(r["status"]=="ok"?(r["data"].toObject()["state"]=="needs_conditions"?"方案尚缺条件，未启动验证。":"已保存；请查看当前状态与证据。"):r["error"].toObject()["message"].toString());if(path=="/payloads/prepare" && r["status"]=="ok") {
      self->m_pendingPayload=r["data"].toObject()["payload_id"].toString();
      self->m_status->setText(r["data"].toObject()["state"]=="generated"?"本次新生成载荷，尚未验证。请预览后手动绑定步骤。":"已找到库中载荷，请预览后手动绑定步骤。");
    }
    self->load(editor && r["status"]=="ok" && edits==self->m_editGeneration);});
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
    const auto approved=self->m_queuePlans.value(id);
    if(r["status"]!="ok" || plans.isEmpty() || !d["readiness"].toObject()["ready"].toBool()
        || plans.first().toObject()["revision"]!=approved["revision"] || plans.first().toObject()["fingerprint"]!=approved["fingerprint"]) {
      self->m_status->setText("队列已停止：方案版本或条件变化，请刷新并重新确认。");self->m_queue.clear();self->updateQueue();return;
    }
    self->m_details[id]=d;
    self->startAttempt(id,d["revision"].toInt());
  });
}
void FindingVerificationDialog::startCurrent() {
  if(m_detail["eligible"]==false || m_finished || m_busy || m_loading || m_dirty || m_stale || m_revision<1
      || m_queuePreparing || m_queueStarting || !m_activeQueue.isEmpty() || currentId().isEmpty()) return;
  if(QStringList{"queued","running","cancelling","unknown"}.contains(m_detail["state"].toString())) return;
  if(!m_detail["readiness"].toObject()["ready"].toBool())return;
  const auto shown=m_detail;const int shownRevision=m_revision;
  if(QMessageBox::question(this,"确认并开始攻击测试",confirmationText(shown),QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Yes)return;
  if(m_dirty || m_stale || m_revision!=shownRevision || currentId()!=shown["id"].toString() || m_detail["plans"].toArray().isEmpty() || m_detail["plans"].toArray().first().toObject()["fingerprint"]!=shown["plans"].toArray().first().toObject()["fingerprint"])return;
  ++m_queueGeneration;m_queue.clear();m_queuePlans.clear();
  m_queuePlans[currentId()]=shown["plans"].toArray().first().toObject();
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
  m_api->post(path+"/start",{{"revision",revision},{"fingerprint",m_queuePlans.value(id)["fingerprint"]},{"confirmed",true},{"request_id",QUuid::createUuid().toString(QUuid::WithoutBraces)}},15000,
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
  m_prepareSimple->setEnabled(idle&&!m_dirty);m_adjustAI->setEnabled(idle&&!m_dirty&&m_revision>0);
  m_useSource->setEnabled(idle&&!m_dirty&&m_sources->currentIndex()>=0);
  m_startSimple->setEnabled(idle&&!m_dirty&&m_detail["readiness"].toObject()["ready"].toBool());
  m_save->setEnabled(idle&&m_dirty);updateQueue();
  const int payload=m_payloads->currentIndex(),step=m_bindStep->currentIndex();bool compatible=false;
  if(payload>=0 && step>=0)for(const auto &v:m_matches[payload].toObject()["compatible_steps"].toArray()){const auto c=v.toObject();if(c["step_id"].toString()==m_bindStep->currentData().toString())compatible=c["compatible"].toBool();}
  m_bindPayload->setEnabled(idle&&!m_dirty&&compatible);
  m_unbindPayload->setEnabled(idle&&!m_dirty&&step>=0&&step<m_planSteps.size()&&!m_planSteps[step].toObject()["payload_id"].toString().isEmpty());
  m_resolvePayload->setEnabled(idle&&!m_dirty&&step>=0);
}

void FindingVerificationDialog::renderAttempt(int index) {
  const auto attempts=m_detail["attempts"].toArray();
  if(index<0 || index>=attempts.size()){m_evidence->clear();m_evidenceTable->setRowCount(0);m_evidenceAttempt.clear();return;}
  const auto attempt=attempts[index].toObject();QSet<int> checked;
  if(m_evidenceAttempt==attempt["id"].toString())for(int row=0;row<m_evidenceTable->rowCount();row++)if(m_evidenceTable->item(row,0)->checkState()==Qt::Checked)checked.insert(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt());
  if(m_evidenceAttempt!=attempt["id"].toString()){m_conclusion->setCurrentIndex(0);m_note->clear();}
  m_evidenceAttempt=attempt["id"].toString();m_evidence->setPlainText(attemptText(attempt));
  const auto records=attempt["evidence"].toArray();m_evidenceTable->setRowCount(records.size());
  for(int row=0;row<records.size();row++){const auto record=records[row].toObject();auto *choice=new QTableWidgetItem;choice->setTextAlignment(Qt::AlignTop|Qt::AlignHCenter);choice->setData(Qt::UserRole,record["id"].toInt());choice->setFlags(choice->flags()|Qt::ItemIsUserCheckable);choice->setCheckState(checked.contains(record["id"].toInt())?Qt::Checked:Qt::Unchecked);m_evidenceTable->setItem(row,0,choice);
    m_evidenceTable->setItem(row,1,new QTableWidgetItem(QString::number(record["step_index"].toInt()+1)));m_evidenceTable->setItem(row,2,new QTableWidgetItem(record["tool_id"].toString()));m_evidenceTable->setItem(row,3,new QTableWidgetItem(evidenceFacts(record)));
  }m_evidenceTable->resizeRowsToContents();
  for(int row=0;row<m_evidenceTable->rowCount();row++)for(int col=1;col<4;col++)m_evidenceTable->item(row,col)->setTextAlignment(Qt::AlignTop|Qt::AlignLeft);
}

void FindingVerificationDialog::loadSources() {
  const auto id=currentId();if(id.isEmpty()||m_finished)return;
  const auto context=m_contextGeneration,request=++m_sourceRequest;const auto selected=m_sources->currentData().toString();
  const QString query="?mode="+QString(m_browseSources?"all":"recommended")+"&offset="+QString::number(m_sourceOffset)+"&limit=20&q="+QString::fromLatin1(QUrl::toPercentEncoding(m_sourceSearch->text()));
  QPointer<FindingVerificationDialog> self(this);
  m_api->get(base()+"/"+id+"/sources"+query,10000,[self,id,context,request,selected](const QJsonObject &r){
    if(!self || self->m_finished || self->currentId()!=id || self->m_contextGeneration!=context || self->m_sourceRequest!=request)return;
    self->m_sources->blockSignals(true);self->m_sources->clear();self->m_sourceItems={};
    if(r["status"]=="ok")self->m_sourceItems=r["data"].toObject()["items"].toArray();
    for(const auto &v:self->m_sourceItems){const auto source=v.toObject();self->m_sources->addItem(source["name"].toString()+" · "+source["source"].toObject()["label"].toString(),source["playbook_id"].toString());}
    self->m_sources->setCurrentIndex(selected.isEmpty()?-1:self->m_sources->findData(selected));comboPlaceholder(self->m_sources,self->m_sourceItems.isEmpty()?"暂无适用方案，可浏览其他方案或 AI 生成":"请选择已有方案（不会自动使用）");self->m_sources->blockSignals(false);
    self->m_sourcePreview->setPlainText(r["status"]=="ok"?(self->m_sourceItems.isEmpty()?"没有找到适用方案；请核对漏洞条件，或选择 AI 生成新方案。":"请选择候选查看匹配依据、条件和步骤。"):("方案读取失败："+r["error"].toObject()["message"].toString()));
    self->m_sourcePreview->setVisible(self->m_sourceItems.isEmpty() || self->m_sources->currentIndex()>=0);
    if(self->m_sources->currentIndex()>=0)self->showSourcePreview();
    self->m_sourcesPrevious->setEnabled(self->m_sourceOffset>0);self->m_sourcesNext->setEnabled(self->m_sourceOffset+self->m_sourceItems.size()<r["data"].toObject()["total"].toInt());self->updateButtons();
  });
}
void FindingVerificationDialog::showSourcePreview() {
  const int i=m_sources->currentIndex();if(i<0||i>=m_sourceItems.size())return;const auto source=m_sourceItems[i].toObject();m_sourcePreview->show();
  const QString status=source["status"]=="directional_candidate"?"定向候选，仍须核对条件":source["status"]=="needs_conditions"?"待补条件":"相关参考";
  QStringList text{source["description"].toString(),"匹配状态："+status,"依据："+source["match_basis"].toString(),"待核对："+join(source["missing_conditions"].toArray())};
  for(const auto &v:source["steps"].toArray()){const auto step=v.toObject();text<<step["name"].toString()+" · "+step["tool_id"].toString();}
  m_sourcePreview->setPlainText(text.join('\n'));
}
void FindingVerificationDialog::showPayloadPreview() {
  QStringList text;const auto plans=m_detail["plans"].toArray();
  if(plans.isEmpty())text<<"请先选择方案，才能核对步骤所需载荷。";
  else for(const auto &v:plans.first().toObject()["content"].toObject()["steps"].toArray()) {
    const auto step=v.toObject();const auto mode=step["consumption"].toString();
    const auto name=step["payload_snapshot"].toObject()["name"];const auto label=name.isObject()?name.toObject()["zh"].toString():name.toString();
    text<<step["name"].toString()+"："+(mode=="independent"?"已绑定 "+label:mode=="internal"?"工具内部生成输入":mode=="pending"?"需要手动选择载荷":"无需独立载荷");
  }
  const int i=m_payloads->currentIndex();
  if(i>=0&&i<m_matches.size()) {
    const auto p=m_matches[i].toObject();text<<"\n所选载荷："+p["name"].toString()<<"来源："+(p["provenance"]=="ai"?QString("AI 生成"):QString("载荷库"))+(p["created_here"].toBool()?" · 本次新生成，尚未验证":" · 已有载荷")
      <<"用途："+(p["consumption"]=="tool_args"?QString("可执行输入，须手动绑定步骤"):QString("仅供参考，不能绑定执行"))<<"依据："+p["match_basis"].toString()<<"前提："+join(p["prerequisites"].toArray());
    for(const auto &v:p["preview"].toArray()){const auto field=v.toObject();text<<field["label"].toString()+"："+readable(field["value"]);}
    for(const auto &v:p["compatible_steps"].toArray()){const auto c=v.toObject();if(c["step_id"].toString()==m_bindStep->currentData().toString()&&!c["compatible"].toBool())text<<"不可绑定："+c["reason"].toString();}
  } else text<<(m_matches.isEmpty()?"\n暂无匹配载荷；需要独立载荷的步骤可手动选择后查找或生成。":"\n请选择载荷预览，再手动选择目标步骤。名称相近不代表已使用。");
  m_payloadPreview->setPlainText(text.join('\n'));
}
QString FindingVerificationDialog::confirmationText(const QJsonObject &detail) const {
  const auto plans=detail["plans"].toArray();if(plans.isEmpty())return "暂无方案";
  const auto plan=plans.first().toObject()["content"].toObject();
  QStringList text{plan["name"].toString(),"来源："+plan["provenance"].toObject()["label"].toString("历史来源未记录"),"目标："+plan["target"].toString(),"前提："+join(plan["prerequisites"].toArray())};
  for(const auto &v:plan["steps"].toArray()){const auto s=v.toObject();text<<s["name"].toString()+" · "+s["tool_id"].toString()+" · "+(s["payload_id"].toString().isEmpty()?"无独立载荷":s["payload_id"].toString())<<stepInputSummary(s,plan["target"].toString());}
  text<<"判据："+plan["success_criteria"].toString()<<"清理："+plan["cleanup"].toString()<<QString("最多 %1 次尝试，每次 %2 秒").arg(plan["max_attempts"].toInt()).arg(plan["duration_ms"].toInt()/1000)<<"确认后将执行以上步骤。";
  return text.join('\n');
}
void FindingVerificationDialog::updateQueue() {
  int selected=0,ready=0;QStringList missing;
  for(int row=0;row<m_items->rowCount();row++)if(m_items->item(row,0)&&m_items->item(row,0)->checkState()==Qt::Checked) {
    ++selected;const auto id=m_items->item(row,0)->data(Qt::UserRole).toString();const auto detail=m_details.value(id);
    const bool current=id==currentId();
    if(detail["readiness"].toObject()["ready"].toBool()&&!(current&&(m_dirty||m_stale)))++ready;
    else missing<<cell(m_items,row,3)+"："+(current&&m_dirty?"有未保存修改":join(detail["readiness"].toObject()["reasons"].toArray()));
  }
  m_queueLabel->setText(QString("已勾选 %1 条，其中 %2 条就绪").arg(selected).arg(ready)+(missing.isEmpty()?QString():"\n未就绪："+missing.join("；")));
  m_queueButton->setText(QString("顺序测试 %1 条已就绪漏洞").arg(ready));
  m_queueButton->setEnabled(ready>0&&!m_busy&&!m_queuePreparing&&!m_queueStarting&&m_activeQueue.isEmpty());
}
void FindingVerificationDialog::startChecked() {
  if(m_finished||m_busy||m_queuePreparing||m_queueStarting||!m_activeQueue.isEmpty())return;
  QStringList selected,summary;QMap<QString,QJsonObject> plans;
  for(int row=0;row<m_items->rowCount();row++)if(m_items->item(row,0)->checkState()==Qt::Checked) {
    const auto id=m_items->item(row,0)->data(Qt::UserRole).toString();const auto detail=m_details.value(id);
    if(!detail["readiness"].toObject()["ready"].toBool() || (id==currentId()&&(m_dirty||m_stale)))continue;
    selected<<id;plans[id]=detail["plans"].toArray().first().toObject();summary<<confirmationText(detail);
  }
  if(selected.isEmpty())return;
  if(QMessageBox::question(this,"确认批量攻击测试",summary.join("\n────────\n"),QMessageBox::Yes|QMessageBox::Cancel,QMessageBox::Cancel)!=QMessageBox::Yes)return;
  ++m_queueGeneration;m_queueCancelled=std::make_shared<bool>(false);m_queuePlans=plans;m_queue=selected;executeNext();
}
