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
#include <QDialogButtonBox>
#include <QMap>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSet>
#include <QGroupBox>
#include <QInputDialog>
#include <QGuiApplication>
#include <QScreen>
#include <QResizeEvent>
#include <QWindow>

namespace {
QScreen *widgetScreen(const QWidget *widget) {
  const auto *window=widget?widget->window()->windowHandle():nullptr;
  if(window && window->screen())return window->screen();
  return QGuiApplication::primaryScreen();
}
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
    {"achieved","目标已达成"},{"not_achieved","目标未达成"},{"not_performed","未开展适用验证"},{"pending","等待结果"},{"confirmed","验证成立"},{"not_verified","未能验证"},{"inconclusive","证据不足"},{"false_positive","人工判定误报"}};
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
QString attemptBudgetText(const QJsonObject &detail) {
  const auto readiness=detail["readiness"].toObject();
  const int used=readiness["attempts_used"].toInt(detail["attempts"].toArray().size());
  const auto plans=detail["plans"].toArray();
  const int limit=readiness["max_attempts"].toInt(plans.isEmpty()?0:plans.first().toObject()["content"].toObject()["max_attempts"].toInt());
  return limit>0?QString("本漏洞已用 %1/%2 次尝试").arg(used).arg(limit):QString("本漏洞已执行 %1 次（上限未记录）").arg(used);
}
QString judgementText(const QJsonValue &value) {return value.isString()?value.toString().trimmed():readable(value);}
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
QJsonObject observation(const QJsonObject &e) {
  return e["observation"].isObject()?e["observation"].toObject():QJsonDocument::fromJson(e["raw_stdout"].toString().toUtf8()).object();
}
bool supportedSystemResultStatus(const QString &status) {
  static const QStringList statuses{"achieved","not_achieved","inconclusive","not_performed","pending"};
  return statuses.contains(status);
}
QJsonObject attemptSummary(const QJsonObject &attempt) {
  auto summary=attempt["summary"].toObject(),result=summary["result"].toObject();
  if(result["schema_version"].toInt()==1) {
    if(!supportedSystemResultStatus(result["status"].toString())) {
      result["status"]="inconclusive";result["reason"]="未知结果状态，无法确认系统验证结论";
      auto unverified=result["unverified"].toArray();unverified.append(result["reason"]);result["unverified"]=unverified;summary["result"]=result;
    }
    return summary;
  }
  // Never promote a legacy manual/automatic label into a new system result.
  return {{"result",QJsonObject{{"schema_version",1},{"status","inconclusive"},
    {"reason","旧版接口，无法确认系统结果"},{"objective",QJsonObject{{"label","历史验证目标未记录"}}},
    {"unverified",QJsonArray{"缺少版本化验证契约；历史判断仅供参考"}}}}};
}
QString systemResultLabel(const QJsonObject &summary) {
  const auto result=summary["result"].toObject();
  if(result["schema_version"].toInt()!=1)return "证据不足（旧版接口）";
  const auto status=result["status"].toString();
  return supportedSystemResultStatus(status)?stateText(status):QString("证据不足（未知结果状态）");
}
QString opinionText(const QString &value) {
  static const QMap<QString,QString> values{{"confirmed","认为证据支持"},{"not_verified","认为证据不支持"},{"inconclusive","暂无法判断"},{"false_positive","认为原发现误报"}};
  return values.value(value,value);
}
QString criteriaText(const QJsonObject &criteria) {
  if(criteria.isEmpty())return {};
  QStringList text{QString("目录索引判据 · 规则版本 %1 · 根据已保存证据派生").arg(criteria["rule_version"].toInt()),
    "目标目录："+criteria["target_path"].toString("无法判断")+" · 标题目录："+criteria["title_path"].toString("无法判断")};
  for(const auto &v:criteria["checks"].toArray()) {
    const auto check=v.toObject();const auto status=check["status"].toString();
    text<<check["label"].toString()+"："+(status=="passed"?"通过":status=="failed"?"未通过":"无法判断")+" · "+readable(check["detail"]);
  }
  text<<"目录索引暴露不代表敏感文件泄露或获得系统权限。";
  return text.join('\n');
}
QString attemptText(const QJsonObject &a) {
  QStringList result{"状态："+stateText(a["state"].toString()),"执行时间："+a["created_at"].toString(),
    QString("方案版本：%1 · 停止确认：%2").arg(a["revision"].toInt()).arg(a["stop_confirmed"].toInt()==1?"已确认":"未确认"),readable(a["reason"])};
  for(const auto &v:a["steps"].toArray()){const auto step=v.toObject();result<<QString("步骤 %1 · %2 · %3").arg(step["step_index"].toInt()+1).arg(step["tool_id"].toString(),step["success"].toInt()==1?"工具完成":"执行异常");}
  if(a["state"]=="completed" && a["assessments"].toArray().isEmpty() && a["reviews"].toArray().isEmpty())result<<"执行已完成；是否达成目标请查看系统结果，人工意见为可选补充。";
  for(const auto &v:a["assessments"].toArray()){const auto judgement=v.toObject();result<<"已保存自动判断（原始记录）："+stateText(judgement["conclusion"].toString())<<"依据："+judgementText(judgement["reason"])<<"限制："+judgementText(judgement["limitations"]);}
  for(const auto &v:a["evidence"].toArray()){const auto data=v.toObject()["evidence_data"].toObject();const auto link=data["finding_verification"].toObject();
    if(link["payload_consumed"].toBool())result<<"实际消费载荷："+data["payload_id"].toString()+" · 版本 "+readable(data["payload_version"]);
    else if(!data["payload_id"].toString().isEmpty())result<<"历史载荷引用（未确认实际消费）："+data["payload_id"].toString();
  }
  for(const auto &v:a["reviews"].toArray()){const auto review=v.toObject();result<<"\n人工意见（不替代自动验证结论）："+opinionText(review["conclusion"].toString())+" · "+readable(review["created_at"])+" · 复核人："+readable(review["reviewed_by"])<<"依据："+judgementText(review["note"]);}
  const auto system=attemptSummary(a)["result"].toObject();
  result.prepend("系统结果："+stateText(system["status"].toString())+"\n目标："+system["objective"].toObject()["label"].toString()+"\n系统依据："+judgementText(system["reason"])+"\n尚未验证："+join(system["unverified"].toArray()));
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
QString payloadSummary(const QJsonObject &step) {
  const QString mode=step["consumption"].toString(), id=step["payload_id"].toString();
  if(mode=="independent" && !id.isEmpty()) {
    const auto name=step["payload_snapshot"].toObject()["name"];
    const QString label=name.isObject()?name.toObject()["zh"].toString(id):name.toString(id);
    return QString("已绑定 %1（%2，版本 %3）").arg(label,id,readable(step["payload_version"]));
  }
  if(mode=="pending" || mode=="independent")return "缺口：尚未手动绑定所需载荷";
  if(mode=="internal")return "工具内部输入";
  if(mode=="none")return "无需独立载荷";
  return "载荷方式未记录，请核对方案";
}
QString frozenCriterionText(const QJsonObject &plan) {
  const auto contract=plan["verification_contract"].toObject();
  const auto criterion=contract["criterion"].toObject(),rule=plan["assessment_rule"].toObject();
  const QString id=rule["id"].toString(),kind=rule["kind"].toString(),stepId=rule["step_id"].toString();
  const int version=rule["version"].toInt(-1);
  if(contract["schema_version"].toInt()!=1 || !contract["capability"].toObject()["automatic"].toBool()
      || id.isEmpty() || stepId.isEmpty() || criterion["id"].toString()!=id
      || criterion["version"].toInt(-1)!=version || criterion["step_id"].toString()!=stepId
      || plan["target"].toString().isEmpty() || rule["target"]!=plan["target"])return {};
  bool hasStep=false;
  for(const auto &value:plan["steps"].toArray()) {
    const auto step=value.toObject();
    if(step["step_id"].toString()==stepId && step["tool_id"]=="target-request")hasStep=true;
  }
  if(!hasStep)return {};
  QString text;
  const QString attribute=rule["attribute"].toString();
  if(id=="f08-directory-index-v1" && kind=="directory" && (version==1 || version==2)) {
    text="成功且完整的 HTML 同时满足对应目录标题、父目录导航及同目录条目；HTTP 200 单独不能确认目录索引暴露。";
    text+=version==1 ? "标题路径严格匹配。" : "标题路径接受末尾一个斜杠的等价差异，排除歧义编码。";
  } else if(id=="f08-web-headers-v1" && kind=="headers" && version==1) {
    if(attribute=="nosniff")text="成功且完整的 HTML 缺少 X-Content-Type-Options 才确认该配置缺陷；有效 nosniff 表示本次未确认缺陷，其他值为证据不足。";
    else if(attribute=="frame")text="成功且完整的 HTML 同时缺少 X-Frame-Options 与受支持的 CSP frame-ancestors 防护才确认；DENY、SAMEORIGIN 或 frame-ancestors 'self' / 'none' 为有效防护，模糊策略为证据不足。";
  } else if(id=="f08-cookie-flags-v1" && kind=="cookie" && version==1
      && !rule["cookie_name"].toString().isEmpty() && (attribute=="httponly" || attribute=="secure")
      && (attribute!="secure" || plan["target"].toString().startsWith("https:"))) {
    text=QString("本次成功且完整响应设置同名 Cookie %1，且一致缺少 %2 属性才确认该配置缺陷；属性已设置则本次未确认，未设置同名 Cookie、采集不全或属性不一致为证据不足。")
      .arg(rule["cookie_name"].toString(),attribute=="httponly"?"HttpOnly":"Secure");
  }
  return text.isEmpty()?QString():QString("系统冻结判据（规则版本 %1）：%2").arg(version).arg(text);
}
QString cell(QTableWidget *table,int row,int col) {return table->item(row,col)?table->item(row,col)->text():QString();}
}
FindingVerificationDialog::FindingVerificationDialog(ApiClient *api,const QString &pipeline,const QList<qint64> &findings,QWidget *parent,
    const QString &existingVerificationId,const QString &existingAttemptId)
  :QDialog(parent),m_api(api),m_pipeline(pipeline) {
  setWindowTitle("逐漏洞攻击测试 · "+pipeline);setWindowFlag(Qt::WindowMaximizeButtonHint,true);
  const auto *screen=widgetScreen(parent);
  resize(QSize(1360,860).boundedTo(screen?screen->availableGeometry().size():QSize(1360,860)));
  auto *layout=new QVBoxLayout(this);
  auto *identityLabel = new QLabel(QStringLiteral("任务ID：%1 · 核对授权范围并确认本次执行").arg(pipeline), this);
  identityLabel->setObjectName("findingTaskIdentity");
  identityLabel->setTextFormat(Qt::PlainText);
  identityLabel->setWordWrap(true);
  identityLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
  identityLabel->setToolTip(QStringLiteral("逐漏洞测试无需先生成、审批或执行全局预案；仍需核对授权范围并确认本次执行。"));
  identityLabel->setProperty("taskId", pipeline);
  layout->addWidget(identityLabel);
  auto *split=new QSplitter(this);layout->addWidget(split,1);
  m_items=new QTableWidget(0,6);m_items->setHorizontalHeaderLabels({"选择","执行状态","最新系统结果","漏洞名称","位置","严重程度"});
  m_items->setMinimumWidth(0);
  m_items->setSelectionBehavior(QAbstractItemView::SelectRows);m_items->setSelectionMode(QAbstractItemView::SingleSelection);
  m_items->setEditTriggers(QAbstractItemView::NoEditTriggers);m_items->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);m_items->horizontalHeader()->moveSection(3,1);m_items->hideColumn(4);m_items->hideColumn(5);
  m_items->setColumnWidth(3,170);m_items->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);
  split->addWidget(m_items);
  auto *tabs=new QTabWidget;m_tabs=tabs;tabs->setMinimumWidth(0);split->addWidget(tabs);split->setStretchFactor(0,1);split->setStretchFactor(1,3);split->setSizes({330,990});
  auto *mainPage=new QWidget;auto *mainLayout=new QVBoxLayout(mainPage);
  auto *scroll=new QScrollArea;scroll->setWidgetResizable(true);scroll->setWidget(mainPage);
  auto *mainHost=new QWidget;auto *hostLayout=new QVBoxLayout(mainHost);hostLayout->setContentsMargins(0,0,0,0);hostLayout->addWidget(scroll,1);tabs->addTab(mainHost,"攻击测试方案");
  auto section=[mainLayout](const QString &title){auto *box=new QGroupBox(title);auto *content=new QVBoxLayout(box);mainLayout->addWidget(box);return content;};
  auto *findingSection=section("当前漏洞");m_context=new QPlainTextEdit;m_context->setReadOnly(true);m_context->setMaximumHeight(80);findingSection->addWidget(m_context);
  auto *sourceSection=section("1. 攻击测试方案与本次摘要");
  auto *planHelp=new QLabel("方案用于组织本次目标、步骤、载荷绑定和结果判据；已有适用方案可直接复用。");
  planHelp->setWordWrap(true);sourceSection->addWidget(planHelp);
  m_planSummary=new QPlainTextEdit;m_planSummary->setReadOnly(true);m_planSummary->setMinimumHeight(130);m_planSummary->setMaximumHeight(130);sourceSection->addWidget(m_planSummary);
  m_sourceChooser=new QGroupBox("查看推荐方案 / 更换方案");m_sourceChooser->setCheckable(true);m_sourceChooser->setChecked(true);
  auto *chooserLayout=new QVBoxLayout(m_sourceChooser);auto *candidateBody=new QWidget;auto *candidateLayout=new QVBoxLayout(candidateBody);candidateLayout->setContentsMargins(0,0,0,0);chooserLayout->addWidget(candidateBody);sourceSection->addWidget(m_sourceChooser);
  connect(m_sourceChooser,&QGroupBox::toggled,candidateBody,&QWidget::setVisible);
  m_sources=new QComboBox;m_sources->setMinimumContentsLength(16);candidateLayout->addWidget(m_sources);
  m_sourcePreview=new QPlainTextEdit;m_sourcePreview->setReadOnly(true);m_sourcePreview->setMaximumHeight(75);m_sourcePreview->hide();candidateLayout->addWidget(m_sourcePreview);
  auto *sourceActions=new QHBoxLayout;m_useSource=new QPushButton("使用此方案");m_prepareSimple=new QPushButton("整理证据并生成方案");m_adjustAI=new QPushButton("AI 辅助调整当前方案");
  candidateLayout->addWidget(m_useSource);sourceActions->addWidget(m_prepareSimple);sourceActions->addWidget(m_adjustAI);sourceSection->addLayout(sourceActions);
  auto *browse=new QHBoxLayout;m_sourceSearch=new QLineEdit;m_sourceSearch->setPlaceholderText("无合适候选？搜索其他方案");auto *search=new QPushButton("浏览其他方案");
  m_sourcesPrevious=new QPushButton("上一页");m_sourcesNext=new QPushButton("下一页");browse->addWidget(m_sourceSearch,1);browse->addWidget(search);browse->addWidget(m_sourcesPrevious);browse->addWidget(m_sourcesNext);candidateLayout->addLayout(browse);
  auto *editBox=new QGroupBox("调整当前草稿（按需展开）");editBox->setCheckable(true);editBox->setChecked(false);auto *editLayout=new QVBoxLayout(editBox);auto *editBody=new QWidget;auto *p=new QVBoxLayout(editBody);editLayout->addWidget(editBody);editBody->hide();connect(editBox,&QGroupBox::toggled,editBody,&QWidget::setVisible);sourceSection->addWidget(editBox);
  auto *form=new QFormLayout;m_name=new QLineEdit;m_target=new QLineEdit;m_objective=new QLineEdit;m_objective->setMaxLength(200);m_objective->setPlaceholderText("说明本次要确认的具体目标；填写目标不代表具备自动判据");
  m_objectiveCategory=new QComboBox;m_objectiveCategory->addItem("效果验证","effect");m_objectiveCategory->addItem("可访问性检查","accessibility");m_objectiveCategory->addItem("配置／暴露事实","configuration_exposure");
  form->addRow("方案名称",m_name);form->addRow("实际入口",m_target);form->addRow("本次验证目标",m_objective);form->addRow("目标类别",m_objectiveCategory);p->addLayout(form);
  auto field=[p](const QString &label,QPlainTextEdit *&edit){p->addWidget(new QLabel(label));edit=new QPlainTextEdit;edit->setMaximumHeight(65);p->addWidget(edit);};
  field("前置条件",m_conditions);field("缺失条件",m_missing);
  m_steps=new QTableWidget(0,3);m_steps->setHorizontalHeaderLabels({"步骤名称","工具","预期证据"});m_steps->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);m_steps->setMinimumHeight(100);p->addWidget(m_steps);
  field("成功判据与限制",m_criteria);field("清理说明",m_cleanup);m_save=new QPushButton("保存方案调整");p->addWidget(m_save);
  auto *payloadSection=section("2. 本次载荷与步骤关联");
  auto *payloadHelp=new QLabel("载荷是步骤使用的具体输入；匹配或生成只准备候选，须手动绑定。无需独立载荷的步骤可直接使用工具输入。");
  payloadHelp->setWordWrap(true);payloadSection->addWidget(payloadHelp);
  m_artifactBox=new QGroupBox("源码漏洞载荷 · Assistant 收集与 Python 改写");m_artifactBox->setObjectName("findingPayloadArtifacts");
  auto *artifacts=new QVBoxLayout(m_artifactBox);payloadSection->addWidget(m_artifactBox);
  m_artifactStatus=new QLabel;m_artifactStatus->setObjectName("findingArtifactStatus");m_artifactStatus->setWordWrap(true);artifacts->addWidget(m_artifactStatus);
  auto *artifactActions=new QHBoxLayout;m_collectArtifacts=new QPushButton("Assistant 收集载荷");m_collectArtifacts->setObjectName("findingCollectPayloads");
  m_rewritePython=new QPushButton("将所选载荷改写为 Python");m_rewritePython->setObjectName("findingRewritePython");
  m_stopArtifacts=new QPushButton("停止收集或改写");m_stopArtifacts->setObjectName("findingStopArtifacts");
  for(auto *button:{m_collectArtifacts,m_rewritePython,m_stopArtifacts})artifactActions->addWidget(button);artifacts->addLayout(artifactActions);
  m_artifactCollections=new QComboBox;m_artifactCollections->setObjectName("findingArtifactCollections");artifacts->addWidget(m_artifactCollections);
  m_collectedScripts=new QComboBox;m_collectedScripts->setObjectName("findingCollectedScripts");artifacts->addWidget(m_collectedScripts);
  auto *codeColumns=new QHBoxLayout;
  for(const auto &python:{false,true}) {
    auto *column=new QVBoxLayout;column->addWidget(new QLabel(python?"Python 改写结果（尚未执行验证）":"当前 Flow 中的原始载荷"));
    auto *code=new QPlainTextEdit;code->setReadOnly(true);code->setMinimumHeight(130);code->setMaximumHeight(200);
    code->setObjectName(python?"findingPythonPayload":"findingCollectedPayload");column->addWidget(code);codeColumns->addLayout(column,1);
    if(python)m_pythonCode=code;else m_collectedCode=code;
  }
  artifacts->addLayout(codeColumns);m_artifactUsage=new QLabel;m_artifactUsage->setWordWrap(true);m_artifactUsage->setTextFormat(Qt::PlainText);artifacts->addWidget(m_artifactUsage);
  connect(m_artifactCollections,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showCollectedScript();updateButtons();});
  connect(m_collectedScripts,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showCollectedScript();updateButtons();});
  connect(m_collectArtifacts,&QPushButton::clicked,this,[this]{m_artifactCollections->setCurrentIndex(-1);action("/payloads/collect",{{"expected_revision",m_revision},{"refresh",true}},false);});
  connect(m_rewritePython,&QPushButton::clicked,this,[this]{
    const int i=m_collectedScripts->currentIndex();if(i<0 || i>=m_scriptRecords.size())return;const auto script=m_scriptRecords[i].toObject();
    action("/payloads/python",{{"expected_revision",m_revision},{"collection_id",m_artifactCollections->currentData().toString()},{"script_id",script["id"]},{"source_hash",script["source_hash"]}},false);
  });
  connect(m_stopArtifacts,&QPushButton::clicked,this,[this]{action("/payloads/collection-cancel",{},false);});
  m_payloads=new QComboBox;payloadSection->addWidget(m_payloads);
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
  connect(m_prepareSimple,&QPushButton::clicked,this,[this]{if(allowDiscardDraft())action("/prepare",{{"expected_revision",m_revision},{"mode","new"}},true);});
  connect(m_adjustAI,&QPushButton::clicked,this,[this]{if(!allowDiscardDraft())return;bool ok=false;const auto instruction=QInputDialog::getText(this,"AI 辅助调整","说明希望调整的内容",QLineEdit::Normal,{},&ok);if(ok)action("/generate",{{"expected_revision",m_revision},{"mode","adjust"},{"instruction",instruction}},true);});
  connect(m_payloads,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showPayloadPreview();updateButtons();});
  connect(m_bindStep,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){showPayloadPreview();updateButtons();});
  connect(m_bindPayload,&QPushButton::clicked,this,[this]{const int i=m_payloads->currentIndex();if(i<0||m_bindStep->currentIndex()<0)return;const auto payload=m_matches[i].toObject();action("/payloads/bind",{{"expected_revision",m_revision},{"step_id",m_bindStep->currentData().toString()},{"payload_id",payload["payload_id"]},{"version",payload["version"]}},true);});
  connect(m_unbindPayload,&QPushButton::clicked,this,[this]{if(m_bindStep->currentIndex()>=0)action("/payloads/unbind",{{"expected_revision",m_revision},{"step_id",m_bindStep->currentData().toString()}},true);});
  connect(m_resolvePayload,&QPushButton::clicked,this,[this]{if(m_bindStep->currentIndex()<0){setStatus("请先手动选择步骤。");return;}action("/payloads/prepare",{{"expected_revision",m_revision},{"step_id",m_bindStep->currentData().toString()}},false);});
  connect(m_startSimple,&QPushButton::clicked,this,&FindingVerificationDialog::startCurrent);
  auto *resultWidget=new QWidget;auto *resultLayout=new QVBoxLayout(resultWidget);tabs->addTab(resultWidget,"测试结果与历史");
  resultLayout->setContentsMargins(8,8,8,8);resultLayout->setSpacing(6);
  m_attempts=new QComboBox;m_attempts->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);m_attempts->setMinimumContentsLength(12);resultLayout->addWidget(m_attempts);
  m_resultSummary=new QGroupBox("本次结果");m_resultSummary->setObjectName("findingResultSummary");
  auto *summaryLayout=new QVBoxLayout(m_resultSummary);summaryLayout->setContentsMargins(10,5,10,6);summaryLayout->setSpacing(2);
  auto label=[summaryLayout](const QString &name){auto *value=new QLabel;value->setObjectName(name);value->setTextFormat(Qt::PlainText);value->setWordWrap(true);value->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Minimum);value->setMinimumHeight(value->fontMetrics().height()+2);summaryLayout->addWidget(value);return value;};
  m_attemptContext=label("findingAttemptContext");m_attemptContext->setStyleSheet(QString("color:%1;").arg(Theme::TextSecondary));
  m_executionSummary=label("findingExecutionSummary");
  m_resultConclusion=label("findingResultConclusion");auto resultFont=m_resultConclusion->font();resultFont.setPointSize(resultFont.pointSize()+2);resultFont.setBold(true);m_resultConclusion->setFont(resultFont);
  m_resultConclusion->setMinimumHeight(m_resultConclusion->fontMetrics().height()+10);
  m_automaticSummary=label("findingAutomaticSummary");m_manualSummary=label("findingManualSummary");m_automaticSummary->setWordWrap(false);m_manualSummary->setWordWrap(false);
  summaryLayout->removeWidget(m_automaticSummary);summaryLayout->removeWidget(m_manualSummary);auto *judgements=new QHBoxLayout;judgements->addWidget(m_automaticSummary,1);judgements->addWidget(m_manualSummary,1);summaryLayout->addLayout(judgements);
  m_disagreement=label("findingResultDisagreement");m_disagreement->setStyleSheet(QString("color:%1; font-weight:600; padding:2px 0;").arg(Theme::Warning));m_disagreement->hide();
  m_resultBasis=label("findingResultBasis");m_resultBasis->setWordWrap(false);m_resultBasis->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Fixed);resultLayout->addWidget(m_resultSummary);
  m_resultDetails=new QTabWidget;resultLayout->addWidget(m_resultDetails,1);
  m_systemEvidence=new QPushButton("定位系统证据");m_systemEvidence->setObjectName("findingSystemEvidence");m_systemEvidence->setEnabled(false);m_resultDetails->setCornerWidget(m_systemEvidence,Qt::TopRightCorner);
  connect(m_systemEvidence,&QPushButton::clicked,this,[this]{
    const auto attempts=m_detail["attempts"].toArray();const int index=m_attempts->currentIndex();if(index<0||index>=attempts.size())return;
    const auto ids=attemptSummary(attempts[index].toObject())["result"].toObject()["evidence_ids"].toArray();if(ids.isEmpty())return;
    for(int row=0;row<m_evidenceTable->rowCount();++row)if(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt()==ids.first().toInt()){
      m_resultDetails->setCurrentIndex(0);m_evidenceTable->setCurrentCell(row,1);m_evidenceTable->scrollToItem(m_evidenceTable->item(row,1));
      qobject_cast<QScrollArea*>(m_resultDetails->widget(0))->ensureWidgetVisible(m_evidenceDetails,0,0);break;
    }
  });
  auto *evidenceWidget=new QWidget;auto *e=new QVBoxLayout(evidenceWidget);e->setContentsMargins(6,6,6,6);e->setSpacing(5);
  auto *evidenceScroll=new QScrollArea;evidenceScroll->setWidgetResizable(true);evidenceScroll->setWidget(evidenceWidget);m_resultDetails->addTab(evidenceScroll,"证据与判据");
  auto *evidenceHint=new QLabel("选中行即可查看系统证据，无需勾选或填写人工意见。");evidenceHint->setObjectName("findingEvidenceHint");evidenceHint->setToolTip("勾选框仅用于可选人工意见，不影响系统结果或执行就绪状态。");evidenceHint->setWordWrap(true);e->addWidget(evidenceHint);
  m_evidenceTable=new QTableWidget(0,6);m_evidenceTable->setObjectName("findingEvidenceTable");m_evidenceTable->setHorizontalHeaderLabels({"选用","步骤","工具","HTTP","完整性","观察摘要"});
  m_evidenceTable->setToolTip("选中行查看详情；勾选框用于人工意见。行选中不会勾选证据，工具完成不等于漏洞成立。");
  m_evidenceTable->setMinimumHeight(100);m_evidenceTable->setMaximumHeight(180);m_evidenceTable->setColumnWidth(0,42);m_evidenceTable->setColumnWidth(1,42);m_evidenceTable->setColumnWidth(2,108);m_evidenceTable->setColumnWidth(3,56);m_evidenceTable->setColumnWidth(4,70);
  m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);m_evidenceTable->setWordWrap(false);m_evidenceTable->setSelectionBehavior(QAbstractItemView::SelectRows);m_evidenceTable->setSelectionMode(QAbstractItemView::SingleSelection);
  m_evidenceTable->verticalHeader()->hide();m_evidenceTable->verticalHeader()->setDefaultSectionSize(32);m_evidenceTable->horizontalHeader()->setSectionResizeMode(5,QHeaderView::Stretch);e->addWidget(m_evidenceTable,1);
  m_evidenceDetails=new QPlainTextEdit;m_evidenceDetails->setObjectName("findingEvidenceDetails");m_evidenceDetails->setReadOnly(true);m_evidenceDetails->setMinimumHeight(160);e->addWidget(m_evidenceDetails,2);
  auto *reviewWidget=new QWidget;auto *reviewLayout=new QVBoxLayout(reviewWidget);auto *reviewScroll=new QScrollArea;reviewScroll->setWidgetResizable(true);reviewScroll->setWidget(reviewWidget);m_resultDetails->addTab(reviewScroll,"人工意见与历史");
  auto *reviewHint=new QLabel("人工意见为可选补充，不替代自动验证结论。无需填写也可查看结果、结束流程；填写意见不会恢复尝试次数。");reviewHint->setObjectName("findingOpinionHint");reviewHint->setWordWrap(true);reviewLayout->addWidget(reviewHint);
  auto *reviewForm=new QFormLayout;m_conclusion=new QComboBox;m_conclusion->addItem("请选择人工意见",QString());for(const auto &key:QStringList{"confirmed","not_verified","inconclusive","false_positive"})m_conclusion->addItem(opinionText(key),key);
  reviewForm->addRow("人工意见",m_conclusion);reviewLayout->addLayout(reviewForm);
  m_note=new QPlainTextEdit;m_note->setPlaceholderText("对照保存的成功判据，说明实际证据及判定限制");m_note->setMinimumHeight(70);m_note->setMaximumHeight(100);reviewLayout->addWidget(m_note);auto *review=new QPushButton("保存人工意见");reviewLayout->addWidget(review);
  reviewLayout->addWidget(new QLabel("本次尝试的完整判断依据、限制与复核历史"));m_evidence=new QPlainTextEdit;m_evidence->setReadOnly(true);m_evidence->setMinimumHeight(160);reviewLayout->addWidget(m_evidence,1);
  const QString budgetHint="默认最多 2 次尝试，每次 5 分钟。关闭窗口停止待执行队列；当前调用继续，可重新打开查看或取消。";
  auto *budget=new QLabel(budgetHint);budget->setObjectName("findingBudgetHint");layout->addWidget(budget);
  m_queueLabel=new QLabel;m_queueLabel->setObjectName("findingQueueSummary");m_queueLabel->setWordWrap(true);layout->addWidget(m_queueLabel);
  m_status=new QLabel;m_status->setWordWrap(true);m_status->setMaximumHeight(36);m_status->hide();layout->addWidget(m_status);
  auto *global=new QHBoxLayout;auto *refresh=new QPushButton("刷新");auto *queue=new QPushButton("顺序测试已就绪漏洞");m_queueButton=queue;auto *cancel=new QPushButton("取消当前验证并停止队列");auto *close=new QPushButton("关闭窗口");
  queue->setToolTip(budgetHint);close->setToolTip(budgetHint);
  for(auto *button:{refresh,queue,cancel,close})global->addWidget(button);layout->addLayout(global);
  m_timer=new QTimer(this);m_timer->setInterval(2000);connect(m_timer,&QTimer::timeout,this,[this]{load(false);});m_timer->start();
  connect(m_items,&QTableWidget::currentCellChanged,this,[this](int row,int,int previousRow,int previousColumn){
    if(row==previousRow) return;
    if(!allowDiscardDraft()) {
      const QSignalBlocker guard(m_items);
      m_items->setCurrentCell(previousRow,previousColumn);
      return;
    }
    ++m_contextGeneration;++m_attemptSelectionGeneration;m_pendingAttemptRunId.clear();m_pendingExistingAttemptId.clear();m_pendingPayload.clear();m_browseSources=false;m_sourceOffset=0;m_detail={};
    m_sources->blockSignals(true);m_sources->clear();m_sources->blockSignals(false);m_sourceItems={};m_sourcePreview->clear();
    m_payloads->blockSignals(true);m_payloads->clear();m_payloads->blockSignals(false);m_matches={};m_payloadPreview->clear();
    renderPayloadArtifacts();
    m_context->clear();m_planSummary->setPlainText("正在读取此漏洞的方案与载荷…");m_revision=0;m_dirty=false;m_stale=true;
    renderAttempt(-1);
    m_confirm->setChecked(false);updateButtons();load(true);
  });
  connect(refresh,&QPushButton::clicked,this,[this]{if(allowDiscardDraft())load(true);});connect(close,&QPushButton::clicked,this,&QDialog::accept);
  connect(m_save,&QPushButton::clicked,this,[this]{action("/plans",planInput(),true);});
  connect(m_attempts,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int index){
    // An explicit history selection wins over a start response that arrives later.
    ++m_attemptSelectionGeneration;m_pendingAttemptRunId.clear();m_pendingExistingAttemptId.clear();renderAttempt(index);
  });
  connect(m_attempts,QOverload<int>::of(&QComboBox::activated),this,[this](int){
    // Re-selecting the same history item is also an explicit user choice.
    ++m_attemptSelectionGeneration;m_pendingAttemptRunId.clear();m_pendingExistingAttemptId.clear();
  });
  connect(m_evidenceTable,&QTableWidget::currentCellChanged,this,[this](int row,int,int,int){renderEvidence(row);});
  connect(review,&QPushButton::clicked,this,[this]{
    if(m_conclusion->currentData().toString().isEmpty()){setStatus("请明确选择人工意见；它不替代自动验证结论。");return;}
    QJsonArray ids;for(int row=0;row<m_evidenceTable->rowCount();row++)if(m_evidenceTable->item(row,0)->checkState()==Qt::Checked)ids.append(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt());
    action("/reviews",{{"attempt_id",m_attempts->currentData().toString()},{"conclusion",m_conclusion->currentData().toString()},{"evidence_ids",ids},{"note",m_note->toPlainText()}});
  });
  connect(queue,&QPushButton::clicked,this,&FindingVerificationDialog::startChecked);
  connect(cancel,&QPushButton::clicked,this,&FindingVerificationDialog::cancelCurrent);
  auto changed=[this] {if(!m_setting){++m_editGeneration;m_dirty=true;m_confirm->setChecked(false);updateButtons();}};
  connect(m_name,&QLineEdit::textChanged,this,changed);connect(m_target,&QLineEdit::textChanged,this,changed);connect(m_objective,&QLineEdit::textChanged,this,changed);connect(m_objectiveCategory,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[changed](int){changed();});
  for(auto *edit:{m_conditions,m_missing,m_criteria,m_cleanup})connect(edit,&QPlainTextEdit::textChanged,this,changed);
  connect(m_steps,&QTableWidget::itemChanged,this,[changed](QTableWidgetItem*){changed();});

  connect(m_items,&QTableWidget::itemChanged,this,[this](QTableWidgetItem*){updateQueue();});
  if(existingVerificationId.isEmpty())for(qint64 finding:findings)addFinding(finding);
  else {
    addExistingFinding(existingVerificationId,findings.isEmpty()?0:findings.first());
    m_pendingExistingAttemptId=existingAttemptId;
    m_tabs->setCurrentIndex(1);
  }
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
    if(response["status"]!="ok"){self->setStatus(response["error"].toObject()["message"].toString());return;}
    const auto data=response["data"].toObject();self->addExistingFinding(data["id"].toString(),finding,data["state"].toString());
  });
}
void FindingVerificationDialog::addExistingFinding(const QString &id,qint64 finding,const QString &state) {
    const int row=m_items->rowCount();m_items->insertRow(row);
    auto *choice=new QTableWidgetItem;choice->setToolTip(QString("发现记录 #%1").arg(finding));choice->setData(Qt::UserRole,id);
    choice->setFlags(choice->flags()|Qt::ItemIsUserCheckable);choice->setCheckState(Qt::Checked);m_items->setItem(row,0,choice);
    m_items->setItem(row,1,new QTableWidgetItem(stateText(state)));
    m_items->setItem(row,2,new QTableWidgetItem("待判定"));
    for(int col=3;col<6;col++)m_items->setItem(row,col,new QTableWidgetItem);
    m_items->item(row,3)->setText("读取发现…");
    if(row==0){m_items->setCurrentCell(0,0);return;}
    QPointer<FindingVerificationDialog> self(this);
    m_api->get(base()+"/"+id,10000,[self,id](const QJsonObject &reply){
      if(!self || self->m_finished)return;
      for(int row=0;row<self->m_items->rowCount();row++)if(self->m_items->item(row,0)->data(Qt::UserRole).toString()==id){
        if(reply["status"]!="ok"){self->m_items->item(row,3)->setText("读取失败，点击重试");return;}
        const auto detail=reply["data"].toObject(),finding=detail["finding"].toObject();self->m_details[id]=detail;self->updateQueue();
        const auto value=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();
        self->m_items->item(row,3)->setText(value["title"].toString(value["name"].toString(value["finding"].toString("漏洞候选"))));
        self->m_items->item(row,3)->setToolTip(self->m_items->item(row,3)->text());
        self->m_items->item(row,2)->setText(systemResultLabel(detail["summary"].toObject()));return;
      }
    });
}
void FindingVerificationDialog::displayPlan(const QJsonObject &plan) {
  m_setting=true;
  m_sourceId=plan["source_playbook_id"].toString();m_name->setText(plan["name"].toString());m_target->setText(plan["target"].toString());
  const auto objective=plan["objective_draft"].isObject()?plan["objective_draft"].toObject():plan["verification_contract"].toObject()["objective"].toObject();m_objective->setText(objective["label"].toString());const int category=m_objectiveCategory->findData(objective["category"].toString("effect"));m_objectiveCategory->setCurrentIndex(category<0?0:category);
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
  QJsonObject input{{"expected_revision",m_revision},{"name",m_name->text()},{"target",m_target->text()},{"source_playbook_id",m_sourceId},{"prerequisites",lines(m_conditions)},{"missing_conditions",lines(m_missing)},{"success_criteria",m_criteria->toPlainText()},{"cleanup",m_cleanup->toPlainText()},{"max_attempts",2},{"duration_ms",300000},{"steps",steps}};
  if(!m_objective->text().trimmed().isEmpty())input["objective_draft"]=QJsonObject{{"label",m_objective->text().trimmed()},{"category",m_objectiveCategory->currentData().toString()}};
  return input;
}
void FindingVerificationDialog::load(bool editor) {
  const auto id=currentId();
  if(m_finished || id.isEmpty()) return;
  if(m_loading) {m_reloadEditor=m_reloadEditor || editor;return;}
  m_loading=true;
  const auto context=m_contextGeneration;
  const auto edits=m_editGeneration;
  QPointer<FindingVerificationDialog> self(this);
  m_api->get(base()+"/"+id,10000,[self,id,editor,context,edits](const QJsonObject &r){if(!self || self->m_finished)return;self->m_loading=false;if(self->m_reloadEditor || self->currentId()!=id || self->m_contextGeneration!=context){const bool switched=self->currentId()!=id || self->m_contextGeneration!=context;self->m_reloadEditor=false;self->load(switched || edits==self->m_editGeneration);return;}if(r["status"]!="ok"){self->setStatus(r["error"].toObject()["message"].toString());return;}
    self->m_detail=r["data"].toObject();
    const auto taskNumber = self->m_detail["task_no"].toString(self->m_pipeline);
    self->setWindowTitle(QStringLiteral("逐漏洞攻击测试 · %1").arg(taskNumber));
    if (auto *label = self->findChild<QLabel*>("findingTaskIdentity")) {
      label->setText(QStringLiteral("任务ID：%1 · 核对授权范围并确认本次执行").arg(taskNumber)); label->setProperty("taskId", taskNumber);
    }
    self->m_details[id]=self->m_detail;self->m_context->setPlainText(contextText(self->m_detail));const bool replaceEditor=editor && edits==self->m_editGeneration;if(replaceEditor) {
      self->m_revision=self->m_detail["revision"].toInt();self->m_stale=false;
    } else if(self->m_revision!=self->m_detail["revision"].toInt()) {
      self->m_stale=true;self->m_confirm->setChecked(false);
      self->setStatus("计划版本已变化，当前显示内容已过期。请刷新完整计划并重新核对。");
    }const auto summary=self->m_detail["summary"].toObject();const QString state=self->m_detail["state"].toString();const int row=self->m_items->currentRow();self->m_items->item(row,1)->setText(stateText(state));self->m_items->item(row,2)->setText(systemResultLabel(summary));const auto finding=self->m_detail["finding"].toObject();const auto found=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();self->m_items->item(row,3)->setText(found["title"].toString(found["name"].toString(found["finding"].toString())));self->m_items->item(row,4)->setText(found["url"].toString(found["location"].toString()));self->m_items->item(row,5)->setText(finding["severity"].toString());for(int c=0;c<6;c++)self->m_items->item(row,c)->setToolTip(self->m_items->item(row,c)->text());
    if(replaceEditor)self->m_sourceChooser->setChecked(self->m_detail["plans"].toArray().isEmpty());
    if(replaceEditor){const auto plans=self->m_detail["plans"].toArray();if(!plans.isEmpty())self->displayPlan(plans.first().toObject()["content"].toObject());else self->displayPlan({{"name","发现 #"+QString::number(self->m_detail["finding_id"].toInt())+" 验证"},{"target",self->m_detail["default_target"]}});}
    const auto findingRecord=self->m_detail["finding"].toObject();
    const auto findingData=QJsonDocument::fromJson(findingRecord["result_data"].toString().toUtf8()).object();
    QStringList overview;
    const auto savedPlans=self->m_detail["plans"].toArray();
    if(self->m_detail["eligible"]==false) overview<<"\n"+self->m_detail["ineligibility_reason"].toString();
    else if(savedPlans.isEmpty()) overview<<"\n下一步：选择已有方案并点击“使用此方案”，或明确点击“AI 生成新方案”。保存草稿不会执行目标请求。";
    else {
      const auto saved=savedPlans.first().toObject();
      overview<<self->confirmationText(self->m_detail)
        <<QString("保存版本：%1%2").arg(saved["revision"].toInt()).arg(saved["confirmed_at"].toString().isEmpty()?" · 开始前待确认":" · 已确认");
    }
    if(self->m_stale)overview<<"\n版本发生变化：请刷新后重新核对，当前禁止执行。";
    if(self->m_dirty)overview<<"\n方案调整中有未保存修改：请先保存，当前禁止执行。";
    if(!self->m_detail["reason"].toString().isEmpty())overview<<"\n需要处理："+self->m_detail["reason"].toString();
    const auto readiness=self->m_detail["readiness"].toObject();
    overview<<"\n执行前检查："+(readiness["ready"].toBool()?QString("已就绪，开始前统一确认"):join(readiness["reasons"].toArray()));
    self->m_planSummary->setPlainText(overview.join('\n'));
    const QString selected=self->m_attempts->currentData().toString();
    const auto attempts=self->m_detail["attempts"].toArray();int startedIndex=-1,existingIndex=-1;
    self->m_attempts->blockSignals(true);self->m_attempts->clear();
    for(int i=0;i<attempts.size();++i){
      const auto a=attempts[i].toObject();self->m_attempts->addItem(a["created_at"].toString()+" · "+stateText(a["state"].toString()),a["id"].toString());
      if(!self->m_pendingAttemptRunId.isEmpty()&&a["run_id"].toString()==self->m_pendingAttemptRunId)startedIndex=i;
      if(!self->m_pendingExistingAttemptId.isEmpty()&&a["id"].toString()==self->m_pendingExistingAttemptId)existingIndex=i;
    }
    const int selectedIndex=self->m_attempts->findData(selected);
    self->m_attempts->setCurrentIndex(startedIndex>=0?startedIndex:existingIndex>=0?existingIndex:selectedIndex<0?0:selectedIndex);self->m_attempts->blockSignals(false);
    if(existingIndex>=0)self->m_pendingExistingAttemptId.clear();
    if(startedIndex>=0){self->m_pendingAttemptRunId.clear();self->m_tabs->setCurrentIndex(1);self->m_resultDetails->setCurrentIndex(0);}
    self->renderAttempt(self->m_attempts->currentIndex());
    const auto chosenStep=self->m_bindStep->currentData().toString();self->m_bindStep->blockSignals(true);self->m_bindStep->clear();
    if(!savedPlans.isEmpty())for(const auto &v:savedPlans.first().toObject()["content"].toObject()["steps"].toArray()){const auto step=v.toObject();self->m_bindStep->addItem(step["name"].toString()+" · "+step["tool_id"].toString(),step["step_id"].toString());}
    self->m_bindStep->setCurrentIndex(chosenStep.isEmpty()?-1:self->m_bindStep->findData(chosenStep));self->m_bindStep->blockSignals(false);
    self->m_matches=self->m_detail["payloads"].toObject()["matches"].toArray();const auto selectedPayload=self->m_pendingPayload.isEmpty()?self->m_payloads->currentData():QVariant(self->m_pendingPayload);self->m_pendingPayload.clear();
    self->m_payloads->blockSignals(true);self->m_payloads->clear();for(const auto &v:self->m_matches){const auto payload=v.toObject();self->m_payloads->addItem(payload["name"].toString()+ (payload["created_here"].toBool()?" · 本次新生成":" · 已有载荷"),payload["payload_id"].toString());}
    self->m_payloads->setCurrentIndex(self->m_payloads->findData(selectedPayload));self->m_payloads->blockSignals(false);
    self->showPayloadPreview();self->renderPayloadArtifacts();self->updateButtons();self->updateQueue();
    if(!self->m_detail["reason"].toString().isEmpty())self->setStatus(self->m_detail["reason"].toString());
    if(!self->m_queueStarting && !self->m_queueRunId.isEmpty() && summary["run_id"].toString()==self->m_queueRunId && self->m_activeQueue==id && QStringList{"completed","failed","aborted","unknown"}.contains(state)){self->m_activeQueue.clear();self->m_queueRunId.clear();self->m_items->setEnabled(true);self->updateButtons();if(state=="unknown"||state=="aborted")self->m_queue.clear();self->executeNext();}
  });
  if(editor)loadSources();
}
void FindingVerificationDialog::action(const QString &path,const QJsonObject &body,bool editor) {
  if(m_finished||m_busy||currentId().isEmpty())return;
  if(m_stale && path!="/reviews") {setStatus("请刷新最新完整计划后再操作。");return;}const auto id=currentId();const auto edits=m_editGeneration;const auto context=m_contextGeneration;m_busy=true;updateButtons();setStatus("正在处理…");QPointer<FindingVerificationDialog> self(this);
  m_api->post(base()+"/"+id+path,body,path=="/prepare"?360000:path=="/generate"?130000:15000,[self,id,editor,edits,context,path](const QJsonObject &r){if(!self)return;self->m_busy=false;self->updateButtons();if(self->currentId()!=id || self->m_contextGeneration!=context)return;self->setStatus(r["status"]=="ok"?(r["data"].toObject()["state"]=="needs_conditions"?"方案尚缺条件，未启动验证。":"已保存；请查看当前状态与证据。"):r["error"].toObject()["message"].toString());if(path=="/payloads/prepare" && r["status"]=="ok") {
      self->m_pendingPayload=r["data"].toObject()["payload_id"].toString();
      self->setStatus(r["data"].toObject()["state"]=="generated"?"本次新生成载荷，尚未验证。请预览后手动绑定步骤。":"已找到库中载荷，请预览后手动绑定步骤。");
    }
    self->load(editor && r["status"]=="ok" && edits==self->m_editGeneration);});
}
void FindingVerificationDialog::setStatus(const QString &text) {
  m_status->setText(text);m_status->setToolTip(text);m_status->setVisible(!text.isEmpty());
}
void FindingVerificationDialog::done(int result) {
  m_finished=true;
  ++m_attemptSelectionGeneration;m_pendingAttemptRunId.clear();
  ++m_queueGeneration;
  m_queue.clear();
  m_timer->stop();
  // Closing prevents future dispatch. Calls already submitted keep running unless cancelled.
  QDialog::done(result);
}
void FindingVerificationDialog::resizeEvent(QResizeEvent *event) {
  QDialog::resizeEvent(event);
  for(const auto &name:{"findingEvidenceHint","findingBudgetHint"})if(auto *hint=findChild<QLabel*>(name))hint->setVisible(width()>=1200);
  if(auto *queue=findChild<QLabel*>("findingQueueSummary")){queue->setWordWrap(width()>=1200);queue->setText(width()>=1200?queue->toolTip():queue->fontMetrics().elidedText(queue->toolTip().simplified(),Qt::ElideRight,qMax(100,width()-22)));}
  for(auto *label:{m_automaticSummary,m_manualSummary})if(label && !label->toolTip().isEmpty())label->setText(label->fontMetrics().elidedText(label->toolTip(),Qt::ElideRight,label->width()));
  if(m_resultBasis && !m_resultBasis->toolTip().isEmpty())m_resultBasis->setText(m_resultBasis->fontMetrics().elidedText((m_evidenceAttempt.isEmpty()?QString():QString("系统依据："))+m_resultBasis->toolTip(),Qt::ElideRight,m_resultBasis->width()));
}
void FindingVerificationDialog::cancelCurrent() {
  ++m_attemptSelectionGeneration;m_pendingAttemptRunId.clear();
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
    self->setStatus(r["status"]=="ok"?"取消请求已提交，等待实际停止确认。":r["error"].toObject()["message"].toString());
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
      self->setStatus("队列已停止：方案版本或条件变化，请刷新并重新确认。");self->m_queue.clear();self->updateQueue();return;
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
  if(!confirmExecution("确认并开始攻击测试",confirmationText(shown)))return;
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
  m_pendingAttemptRunId.clear();m_pendingExistingAttemptId.clear();
  m_queueRunId.clear();
  m_queueStarting=true;
  updateButtons();
  m_items->setEnabled(false);
  for(int row=0;row<m_items->rowCount();row++)
    if(m_items->item(row,0)->data(Qt::UserRole).toString()==id) m_items->setCurrentCell(row,0);
  const auto selectionGeneration=m_attemptSelectionGeneration;
  const auto path=base()+"/"+id;
  QPointer<FindingVerificationDialog> self(this);
  QPointer<ApiClient> api(m_api);
  m_api->post(path+"/start",{{"revision",revision},{"fingerprint",m_queuePlans.value(id)["fingerprint"]},{"confirmed",true},{"request_id",QUuid::createUuid().toString(QUuid::WithoutBraces)}},15000,
    [self,api,path,id,generation,cancelled,selectionGeneration](const QJsonObject &reply){
      // Both single and queued starts retain cancellation independently of the window lifetime.
      if(*cancelled && api) api->post(path+"/cancel",{},10000);
      if(!self || self->m_finished || self->m_activeQueue!=id) return;
      self->m_queueStarting=false;
      self->m_queueRunId=reply["data"].toObject()["run_id"].toString();
      if(reply["status"]=="ok" && !self->m_queueRunId.isEmpty() && !*cancelled
          && generation==self->m_queueGeneration && selectionGeneration==self->m_attemptSelectionGeneration && self->currentId()==id)
        self->m_pendingAttemptRunId=self->m_queueRunId;
      if(generation!=self->m_queueGeneration) self->m_queue.clear();
      if(reply["status"]!="ok") {
        self->setStatus(reply["error"].toObject()["message"].toString());
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
  m_startSimple->setToolTip(attemptBudgetText(m_detail)+"。"+join(m_detail["readiness"].toObject()["reasons"].toArray())+"\n人工意见为可选补充，不影响执行就绪。保存新方案不恢复尝试次数。");
  m_save->setEnabled(idle&&m_dirty);updateQueue();
  const int payload=m_payloads->currentIndex(),step=m_bindStep->currentIndex();bool compatible=false;
  if(payload>=0 && step>=0)for(const auto &v:m_matches[payload].toObject()["compatible_steps"].toArray()){const auto c=v.toObject();if(c["step_id"].toString()==m_bindStep->currentData().toString())compatible=c["compatible"].toBool();}
  m_bindPayload->setEnabled(idle&&!m_dirty&&compatible);
  m_unbindPayload->setEnabled(idle&&!m_dirty&&step>=0&&step<m_planSteps.size()&&!m_planSteps[step].toObject()["payload_id"].toString().isEmpty());
  m_resolvePayload->setEnabled(idle&&!m_dirty&&step>=0);
  const auto artifacts=m_detail["payload_artifacts"].toObject();
  const auto latest=artifacts["collections"].toArray().isEmpty()?QJsonObject():artifacts["collections"].toArray().first().toObject();
  bool artifactBusy=latest["state"].toString()=="collecting",stoppable=QStringList{"collecting","interrupted","uncertain"}.contains(latest["state"].toString());
  for(const auto &collection:artifacts["collections"].toArray())for(const auto &value:collection.toObject()["rewrites"].toArray()) {
    const auto state=value.toObject()["state"].toString();artifactBusy=artifactBusy || state=="rewriting";stoppable=stoppable || state=="rewriting";
  }
  m_collectArtifacts->setEnabled(idle&&!m_dirty&&artifacts["supported"].toBool()&&!artifactBusy);
  m_rewritePython->setEnabled(idle&&!m_dirty&&!artifactBusy&&m_collectedScripts->currentIndex()>=0);
  m_stopArtifacts->setEnabled(!m_busy&&!m_finished&&!currentId().isEmpty()&&stoppable);
}

void FindingVerificationDialog::renderPayloadArtifacts() {
  const auto finding=m_detail["finding"].toObject();auto data=finding["result_data"].toObject();
  if(finding["result_data"].isString())data=QJsonDocument::fromJson(finding["result_data"].toString().toUtf8()).object();
  m_artifactBox->setVisible(data["evidence_origin"].toString()=="cscan_report");
  const QString selected=m_artifactCollections->currentData().toString();m_collectionRecords=m_detail["payload_artifacts"].toObject()["collections"].toArray();
  const QMap<QString,QString> states{{"collecting","收集中"},{"ready","已收集"},{"empty","暂无载荷"},{"uncertain","待核对"},{"interrupted","已中断"},{"error","未完成"},{"cancelled","已停止"}};
  m_artifactCollections->blockSignals(true);m_artifactCollections->clear();
  for(const auto &value:m_collectionRecords){const auto row=value.toObject();m_artifactCollections->addItem(row["updated_at"].toString()+" · "+states.value(row["state"].toString(),"状态待核对"),row["id"].toString());}
  const int index=m_artifactCollections->findData(selected);m_artifactCollections->setCurrentIndex(index>=0?index:m_collectionRecords.isEmpty()?-1:0);m_artifactCollections->blockSignals(false);
  const auto row=m_collectionRecords.isEmpty()?QJsonObject():m_collectionRecords.first().toObject();const auto state=row["state"].toString();
  const QMap<QString,QString> labels{{"collecting","Assistant 正在收集"},{"ready","已收集载荷"},{"empty","本 Flow 尚无与此漏洞关联的载荷"},{"uncertain","原请求待核对，可继续收集"},{"interrupted","等待已中断，可继续原请求"},{"error","收集未完成，历史结果仍保留"},{"cancelled","收集已停止"}};
  m_artifactStatus->setText(labels.value(state,"从当前扫描 Flow 收集已有载荷，再选择一项改写为 Python。")+"。收集和改写均不会执行代码，也不表示漏洞已验证。"+(row["error_message"].toString().isEmpty()?QString():"\n"+row["error_message"].toString()));
  m_collectArtifacts->setText(QStringList{"uncertain","interrupted"}.contains(state)?"继续收集原请求":row.isEmpty()?"Assistant 收集载荷":"刷新收集载荷");
  showCollectedScript();
}

void FindingVerificationDialog::showCollectedScript() {
  const int selectedCollection=m_artifactCollections->currentIndex();const QString previous=m_collectedScripts->currentData().toString();
  const auto collection=selectedCollection>=0&&selectedCollection<m_collectionRecords.size()?m_collectionRecords[selectedCollection].toObject():QJsonObject();
  m_scriptRecords=collection["scripts"].toArray();m_collectedScripts->blockSignals(true);m_collectedScripts->clear();
  for(const auto &value:m_scriptRecords){const auto script=value.toObject();m_collectedScripts->addItem(script["name"].toString()+" · "+script["language"].toString(),script["id"].toString());}
  const int index=m_collectedScripts->findData(previous);m_collectedScripts->setCurrentIndex(index>=0?index:m_scriptRecords.isEmpty()?-1:0);m_collectedScripts->blockSignals(false);
  const int selected=m_collectedScripts->currentIndex();const auto script=selected>=0?m_scriptRecords[selected].toObject():QJsonObject();
  if(m_collectedCode->toPlainText()!=script["content"].toString())m_collectedCode->setPlainText(script["content"].toString());
  QString pythonText;QStringList usage;
  if(!script.isEmpty())usage<<"来源：Flow "+collection["flow_id"].toString()+" / "+script["source_type"].toString()+" "+script["source_id"].toString()<<script["purpose"].toString()<<script["usage"].toString()<<script["safety_notes"].toString();
  for(const auto &value:collection["rewrites"].toArray()) {
    const auto rewrite=value.toObject();if(rewrite["script_id"]!=script["id"] || rewrite["source_hash"]!=script["source_hash"])continue;
    pythonText=rewrite["python_code"].toString();
    const QMap<QString,QString> labels{{"rewriting","模型正在改写 Python"},{"ready","Python 改写已保存，尚未执行验证"},{"error","Python 改写未完成"},{"interrupted","Python 改写已中断，可重试"}};
    usage<<labels.value(rewrite["state"].toString())<<rewrite["explanation"].toString()<<rewrite["usage"].toString()<<rewrite["error_message"].toString();
  }
  if(m_pythonCode->toPlainText()!=pythonText)m_pythonCode->setPlainText(pythonText);
  m_artifactUsage->setText(usage.join('\n'));
}

void FindingVerificationDialog::renderAttempt(int index) {
  const auto attempts=m_detail["attempts"].toArray();
  if(index<0 || index>=attempts.size()){
    m_attemptContext->setText("暂无执行尝试");m_executionSummary->setText("本次执行：尚未执行");m_resultConclusion->setText("系统验证结果：未开展适用验证");m_resultConclusion->setStyleSheet(Theme::StatusInfoStyle);
    const auto plans=m_detail["plans"].toArray();const auto plan=plans.isEmpty()?QJsonObject():plans.first().toObject()["content"].toObject();const auto contract=plan["verification_contract"].toObject();
    const QString target=plans.isEmpty()?QString("验证目标：尚无适用的验证方案"):QString("目标：")+contract["objective"].toObject()["label"].toString("旧方案目标未明确，请保存新版本");
    const QString capability=plans.isEmpty()?QString("对象：尚未选择方案"):QString("对象：")+contract["object"].toObject()["target"].toString(plan["target"].toString("未记录"));
    m_automaticSummary->setToolTip(target);m_manualSummary->setToolTip(capability);m_automaticSummary->setText(target);m_manualSummary->setText(capability);m_disagreement->hide();
    const QString basis=plans.isEmpty()?QString("选择并完整确认方案后才会执行。打开窗口或查看详情不会请求目标。"):contract["capability"].toObject()["automatic"].toBool()?QString("已保存适用方案；尚未执行，开始前仍需完整确认。"):contract.isEmpty()?QString("历史方案缺少版本化验证契约，请保存新版本并重新确认。"):contract["capability"].toObject()["reason"].toString("尚无受支持的自动判据，当前不能确认目标达成");
    m_resultBasis->setToolTip(basis);m_resultBasis->setText(basis);
    m_systemEvidence->setEnabled(false);m_evidence->clear();m_evidenceDetails->clear();m_evidenceTable->setRowCount(0);m_evidenceAttempt.clear();m_conclusion->setCurrentIndex(0);m_note->clear();return;
  }
  const auto attempt=attempts[index].toObject();QSet<int> checked;
  int selectedEvidence=-1;if(m_evidenceTable->currentRow()>=0&&m_evidenceTable->item(m_evidenceTable->currentRow(),0))selectedEvidence=m_evidenceTable->item(m_evidenceTable->currentRow(),0)->data(Qt::UserRole).toInt();
  if(m_evidenceAttempt==attempt["id"].toString())for(int row=0;row<m_evidenceTable->rowCount();row++)if(m_evidenceTable->item(row,0)->checkState()==Qt::Checked)checked.insert(m_evidenceTable->item(row,0)->data(Qt::UserRole).toInt());
  if(m_evidenceAttempt!=attempt["id"].toString()){m_conclusion->setCurrentIndex(0);m_note->clear();selectedEvidence=-1;}
  m_evidenceAttempt=attempt["id"].toString();m_evidence->setPlainText(attemptText(attempt));
  const auto summary=attemptSummary(attempt),result=summary["result"].toObject();
  const auto status=result["status"].toString("inconclusive");
  m_systemEvidence->setEnabled(!result["evidence_ids"].toArray().isEmpty());
  m_attemptContext->setText((index==0?QString("最新尝试"):QString("正在查看历史尝试 · 左侧为最新系统结果"))+" · "+attempt["created_at"].toString());
  m_executionSummary->setText(QString("本次执行：%1 · 方案版本 %2 · 停止确认：%3").arg(stateText(attempt["state"].toString())).arg(attempt["revision"].toInt()).arg(attempt["stop_confirmed"].toInt()==1?"已确认":"未确认"));
  m_resultConclusion->setText("系统验证结果："+stateText(status));
  m_resultConclusion->setStyleSheet(status=="achieved"?Theme::StatusSuccessStyle:status=="inconclusive"?Theme::StatusWarningStyle:Theme::StatusInfoStyle);
  const auto objective=result["objective"].toObject();
  m_automaticSummary->setText("目标："+objective["label"].toString("目标未明确"));
  m_manualSummary->setText("对象："+result["object"].toObject()["target"].toString("未记录"));
  m_automaticSummary->setToolTip(m_automaticSummary->text());m_manualSummary->setToolTip(m_manualSummary->text());
  for(auto *label:{m_automaticSummary,m_manualSummary})label->setText(label->fontMetrics().elidedText(label->toolTip(),Qt::ElideRight,qMax(100,label->width())));
  m_disagreement->setText("存在人工补充意见；意见不替代系统验证结论。");
  m_disagreement->setVisible(!attempt["reviews"].toArray().isEmpty());
  const auto note=readable(result["reason"]);m_resultBasis->setToolTip(note);
  m_resultBasis->setText(m_resultBasis->fontMetrics().elidedText("系统依据："+note,Qt::ElideRight,qMax(100,m_resultBasis->width())));
  const QSignalBlocker tableSignals(m_evidenceTable);
  const auto records=attempt["evidence"].toArray();m_evidenceTable->setRowCount(records.size());
  int selectedRow=0;
  for(int row=0;row<records.size();row++){const auto record=records[row].toObject();auto *choice=new QTableWidgetItem;choice->setTextAlignment(Qt::AlignTop|Qt::AlignHCenter);choice->setData(Qt::UserRole,record["id"].toInt());choice->setFlags(choice->flags()|Qt::ItemIsUserCheckable);choice->setCheckState(checked.contains(record["id"].toInt())?Qt::Checked:Qt::Unchecked);m_evidenceTable->setItem(row,0,choice);
    const auto observed=observation(record),data=record["evidence_data"].toObject();
    const auto http=observed.contains("status_code")?observed["status_code"]:data["status_code"];
    QString brief=readable(data["summary"]);if(brief.isEmpty())brief=readable(observed["summary"]);if(brief.isEmpty())brief=readable(observed["error"]);if(brief.isEmpty())brief=observed["connected"]==true?"已连接；选中查看事实与判据":"选中查看事实与判据";
    m_evidenceTable->setItem(row,1,new QTableWidgetItem(QString::number(record["step_index"].toInt()+1)));m_evidenceTable->setItem(row,2,new QTableWidgetItem(record["tool_id"].toString()));
    m_evidenceTable->setItem(row,3,new QTableWidgetItem(http.isUndefined()?"未记录":readable(http)));
    m_evidenceTable->setItem(row,4,new QTableWidgetItem(observed.contains("complete")?(observed["complete"].toBool()?"完整":"不完整"):"未记录"));
    m_evidenceTable->setItem(row,5,new QTableWidgetItem(brief.simplified()));
    for(int col=1;col<6;col++)m_evidenceTable->item(row,col)->setToolTip(m_evidenceTable->item(row,col)->text());
    if(record["id"].toInt()==selectedEvidence)selectedRow=row;
    m_evidenceTable->setRowHeight(row,32);
  }
  if(!records.isEmpty())m_evidenceTable->setCurrentCell(selectedRow,1);
  renderEvidence(records.isEmpty()?-1:selectedRow);
}
void FindingVerificationDialog::renderEvidence(int row) {
  for(const auto &value:m_detail["attempts"].toArray()) {
    const auto attempt=value.toObject();if(attempt["id"].toString()!=m_evidenceAttempt)continue;
    const auto records=attempt["evidence"].toArray();if(row<0||row>=records.size())break;
    const auto record=records[row].toObject();QStringList text{QString("步骤 %1 · %2 · 证据 #%3").arg(record["step_index"].toInt()+1).arg(record["tool_id"].toString()).arg(record["id"].toInt())};
    const auto criteria=criteriaText(record["criteria"].toObject());if(!criteria.isEmpty())text<<criteria+"\n";
    const auto system=attemptSummary(attempt)["result"].toObject();
    text<<"验证目标："+system["objective"].toObject()["label"].toString()<<"系统依据："+judgementText(system["reason"])<<"尚未验证："+join(system["unverified"].toArray());
    for(const auto &v:system["operations"].toArray()){const auto op=v.toObject();if(op["step_index"]==record["step_index"])text<<"操作："+op["name"].toString()+" · 实际启动："+(op["started"].isBool()?readable(op["started"]):QString("未记录"));}
    text<<evidenceFacts(record);
    m_evidenceDetails->setPlainText(text.join('\n'));return;
  }
  m_evidenceDetails->setPlainText("暂无可查看的证据。缺少证据不能认定漏洞成立。");
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
  QStringList text{source["verification_capability"].toObject()["reason"].toString("尚无适用的验证方案或自动效果判据"),source["description"].toString(),"匹配状态："+status,"依据："+source["match_basis"].toString(),"待核对："+join(source["missing_conditions"].toArray())};
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
  const auto contract=plan["verification_contract"].toObject();
  QStringList operations, payloads;
  for(const auto &value:plan["steps"].toArray()) {
    const auto step=value.toObject();
    operations<<step["name"].toString(step["tool_id"].toString());
    payloads<<payloadSummary(step);
  }
  QString criteria=plan["success_criteria"].toString().trimmed();
  if(criteria.isEmpty())criteria="尚缺结果判据";
  const QString systemCriterion=frozenCriterionText(plan);
  QStringList text{"本次测试摘要", "测什么："+contract["objective"].toObject()["label"].toString("目标未明确，请先保存新版本"),
    "做哪些操作："+operations.join("；"), "使用哪些载荷："+payloads.join("；"),
    "如何判断："+(systemCriterion.isEmpty()?QString("当前不能确认系统自动判断方式"):systemCriterion)};
  if(systemCriterion.isEmpty())text<<"判据缺口："+contract["capability"].toObject()["reason"].toString("冻结契约或规则缺失、不匹配或版本不受支持，不能自动确认目标达成");
  else text<<"系统证据要求：同一入口、同一尝试及冻结版本的完整证据与已保存自动判断一致；执行异常或证据不完整时不能确认目标达成。";
  text<<"方案填写的判据（不改变系统规则）："+criteria;
  if(!contract["limitations"].toString().isEmpty())text<<"系统判据限制："+contract["limitations"].toString();
  text<<"\n测试入口："+plan["target"].toString()<<"步骤与输入详情：";
  int index=0;
  for(const auto &v:plan["steps"].toArray()) {
    const auto step=v.toObject();
    text<<QString("%1. %2 · %3").arg(++index).arg(step["name"].toString(),step["tool_id"].toString())
      <<"   实际输入："+stepInputSummary(step,plan["target"].toString())
      <<"   使用载荷："+payloadSummary(step)<<"   预期证据："+step["expected_evidence"].toString("未记录");
  }
  text<<"人工意见：可选补充，不替代系统验证结果。"
    <<"方案："+plan["name"].toString()<<"来源："+plan["provenance"].toObject()["label"].toString("历史来源未记录")
    <<"前提与范围："+join(plan["prerequisites"].toArray());
  if(!plan["missing_conditions"].toArray().isEmpty())text<<"尚缺条件："+join(plan["missing_conditions"].toArray());
  text<<"清理："+plan["cleanup"].toString()<<QString("最多 %1 次尝试，每次 %2 秒").arg(plan["max_attempts"].toInt()).arg(plan["duration_ms"].toInt()/1000)
    <<"仅在确认开始后执行以上步骤。";
  return text.join('\n');
}
bool FindingVerificationDialog::confirmExecution(const QString &title,const QString &text) {
  QDialog dialog(this);
  dialog.setObjectName("findingExecutionConfirmation");
  dialog.setWindowTitle(title);
  dialog.setSizeGripEnabled(true);
  auto *layout=new QVBoxLayout(&dialog);
  auto *hint=new QLabel("核对本次目标、操作、载荷与系统判据；确认后才会执行。",&dialog);
  hint->setWordWrap(true);layout->addWidget(hint);
  auto *body=new QPlainTextEdit(&dialog);
  body->setObjectName("findingConfirmationText");
  body->setReadOnly(true);body->setMinimumSize(0,0);body->setPlainText(text);
  layout->addWidget(body,1);
  auto *buttons=new QDialogButtonBox(QDialogButtonBox::Yes|QDialogButtonBox::Cancel,&dialog);
  auto *confirm=buttons->button(QDialogButtonBox::Yes),*cancel=buttons->button(QDialogButtonBox::Cancel);
  confirm->setObjectName("confirmFindingExecution");confirm->setText("确认并开始测试");confirm->setAutoDefault(false);
  cancel->setObjectName("cancelFindingExecution");cancel->setText("取消");cancel->setDefault(true);
  layout->addWidget(buttons);
  connect(confirm,&QPushButton::clicked,&dialog,&QDialog::accept);
  connect(cancel,&QPushButton::clicked,&dialog,&QDialog::reject);
  connect(this,&QDialog::finished,&dialog,&QDialog::reject);
  const auto *screen=widgetScreen(this);
  const QRect available=screen?screen->availableGeometry():QRect(0,0,800,600);
  const QSize limit=(available.size()-QSize(32,64)).expandedTo(QSize(1,1));
  dialog.setMaximumSize(limit);
  dialog.resize(QSize(900,620).boundedTo(limit));
  dialog.move(available.center()-QPoint(dialog.width()/2,dialog.height()/2));
  cancel->setFocus();
  return dialog.exec()==QDialog::Accepted && !m_finished;
}
void FindingVerificationDialog::updateQueue() {
  int selected=0,ready=0;QStringList missing;
  for(int row=0;row<m_items->rowCount();row++)if(m_items->item(row,0)&&m_items->item(row,0)->checkState()==Qt::Checked) {
    ++selected;const auto id=m_items->item(row,0)->data(Qt::UserRole).toString();const auto detail=m_details.value(id);
    const bool current=id==currentId();
    if(detail["readiness"].toObject()["ready"].toBool()&&!(current&&(m_dirty||m_stale)))++ready;
    else missing<<cell(m_items,row,3)+"："+(current&&m_dirty?"有未保存修改":join(detail["readiness"].toObject()["reasons"].toArray()));
  }
  const auto budget=attemptBudgetText(m_detail);
  const auto queueText=QString("已勾选 %1 条，其中 %2 条就绪 · %3").arg(selected).arg(ready).arg(budget)+(missing.isEmpty()?QString():"\n未就绪："+missing.join("；"));
  if(auto *hint=findChild<QLabel*>("findingBudgetHint"))hint->setText(budget+"。保存新方案不恢复次数；人工意见可选。关闭窗口停止待执行队列；当前调用继续。");
  m_queueLabel->setToolTip(queueText);m_queueLabel->setWordWrap(width()>=1200);m_queueLabel->setText(width()>=1200?queueText:m_queueLabel->fontMetrics().elidedText(queueText.simplified(),Qt::ElideRight,qMax(100,width()-22)));
  m_queueButton->setText(QString("顺序测试 %1 条已就绪漏洞").arg(ready));
  m_queueButton->setToolTip(queueText+"\n人工意见为可选补充，不影响是否就绪。保存新方案不恢复尝试次数。");
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
  if(!confirmExecution("确认批量攻击测试",summary.join("\n────────\n")))return;
  ++m_queueGeneration;m_queueCancelled=std::make_shared<bool>(false);m_queuePlans=plans;m_queue=selected;executeNext();
}
