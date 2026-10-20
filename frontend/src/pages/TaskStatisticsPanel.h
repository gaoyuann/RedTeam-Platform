#pragma once
#include "../ApiClient.h"
#include "../widgets/MetricCard.h"
#include <QGroupBox>
#include <QWidget>
#include <QJsonArray>
#include <QJsonDocument>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QPlainTextEdit>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <QPointer>
#include <QPainter>
#include <QMouseEvent>
#include <QUrl>
#include <functional>

inline QString statisticsLabel(const QString &key) {
  static const QMap<QString,QString> names{{"all","全部"},{"pending","待判定"},{"confirmed","验证成立"},{"not_verified","未验证成立"},
    {"inconclusive","证据不足"},{"false_positive","误报"},{"conflict","结论冲突"},{"completed","完成"},{"partial","部分完成"},
    {"failed","失败"},{"cancelled","取消"},{"running","运行中"},{"planned","计划中"},{"unsupported","未支持"},
    {"missing_condition","缺少条件"},{"not_checked","未检查"},{"not_applicable","不适用"},{"out_of_scope","范围外"},
    {"unreachable","不可达"},{"unknown","未知"},{"info","信息"},{"low","低"},{"medium","中"},{"high","高"},{"critical","严重"}};
  return names.value(key,key);
}

class StatisticsBars : public QWidget {
public:
  explicit StatisticsBars(QWidget *parent=nullptr):QWidget(parent){setMinimumHeight(100);}
  QJsonObject values;
  std::function<void(QString)> selected;
  void setValues(const QJsonObject &v){values=v;setMinimumHeight(qMax(60,v.size()*26));update();}
protected:
  void paintEvent(QPaintEvent *) override {
    QPainter p(this);double maximum=1;for(auto it=values.begin();it!=values.end();++it)maximum=qMax(maximum,it.value().toDouble());
    int n=0;for(auto it=values.begin();it!=values.end();++it,++n){
      const int y=n*26;p.setPen(palette().text().color());p.drawText(0,y,150,24,Qt::AlignVCenter,statisticsLabel(it.key()));
      p.fillRect(155,y+5,int(qMax(0,width()-220)*it.value().toDouble()/maximum),14,QColor("#3b82f6"));
      p.drawText(width()-60,y,60,24,Qt::AlignVCenter,QString::number(it.value().toInt()));
    }
  }
  void mousePressEvent(QMouseEvent *e) override {const auto keys=values.keys();int n=e->pos().y()/26;if(n>=0&&n<keys.size()&&selected)selected(keys[n]);}
};

class TaskStatisticsPanel : public QWidget {
public:
  explicit TaskStatisticsPanel(ApiClient *client,QWidget *parent=nullptr):QWidget(parent),api(client){
    auto *layout=new QVBoxLayout(this);
    auto *cards=new QHBoxLayout;const QStringList titles{"原始候选记录","已归并实例","未归并记录","已执行验证实例","验证成立实例"};
    for(int n=0;n<5;++n){metrics[n]=new MetricCard(titles[n],QStringLiteral("#3b82f6"),this);cards->addWidget(metrics[n]);}layout->addLayout(cards);
    summary=new QLabel(this);summary->setWordWrap(true);summary->setTextFormat(Qt::PlainText);layout->addWidget(summary);
    auto *actions=new QHBoxLayout;sync=new QPushButton("同步漏洞实例",this);import=new QPushButton("导入基准 JSON",this);
    actions->addWidget(sync);actions->addWidget(import);filter=new QComboBox(this);for(const auto &key:QStringList{"all","pending","confirmed","not_verified","inconclusive","false_positive","conflict"})filter->addItem(statisticsLabel(key),key);actions->addWidget(filter);
    severity=new QComboBox(this);for(const auto &key:QStringList{"all","unknown","info","low","medium","high","critical"})severity->addItem(statisticsLabel(key),key);actions->addWidget(severity);
    more=new QPushButton("下一页",this);actions->addWidget(more);layout->addLayout(actions);
    auto *charts=new QHBoxLayout;checks=new StatisticsBars(this);conclusions=new StatisticsBars(this);
    const QList<QPair<QString,StatisticsBars*>> plots{{"检查状态（按检查项）",checks},{"验证结论（按实例）",conclusions}};
    for(const auto &plot:plots){auto *group=new QGroupBox(plot.first,this);auto *box=new QVBoxLayout(group);box->addWidget(plot.second);charts->addWidget(group);}layout->addLayout(charts);
    table=new QTableWidget(0,4,this);table->setObjectName("f09Instances");table->setHorizontalHeaderLabels({"漏洞实例","扫描严重性标签","当前结论","原始记录数"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);table->setSelectionBehavior(QAbstractItemView::SelectRows);table->setColumnWidth(0,300);table->setColumnWidth(1,140);table->setColumnWidth(2,140);table->horizontalHeader()->setStretchLastSection(true);layout->addWidget(table);
    layout->addWidget(new QLabel("实例 → 原始发现 → 验证尝试 → 证据引用",this));
    detail=new QPlainTextEdit(this);detail->setReadOnly(true);detail->setMaximumHeight(150);layout->addWidget(detail);
    connect(filter,&QComboBox::currentTextChanged,this,[this]{load(false);});connect(severity,&QComboBox::currentTextChanged,this,[this]{load(false);});
    connect(more,&QPushButton::clicked,this,[this]{load(true);});
    connect(sync,&QPushButton::clicked,this,[this]{mutate("/instances/sync",QJsonObject{{"source_fingerprint",fingerprint}});});
    connect(import,&QPushButton::clicked,this,[this]{importBaseline();});
    connect(table,&QTableWidget::cellClicked,this,[this](int row,int){
      if(!table->item(row,0))return;const auto id=table->item(row,0)->text();const auto p=pipeline,f=fingerprint;const int seq=++selection;
      QPointer<TaskStatisticsPanel> guard(this);
      api->get(path()+"/instances/"+id+"?source_fingerprint="+f,5000,[guard,p,f,seq](const QJsonObject &r){
        if(!guard||guard->pipeline!=p||guard->fingerprint!=f||guard->selection!=seq)return;
        if(!guard->accepted(r,f))return;
        guard->detail->setPlainText(QString::fromUtf8(QJsonDocument(r.value("data").toObject()).toJson(QJsonDocument::Indented)));
      });
    });
    conclusions->selected=[this](const QString &key){filter->setCurrentIndex(filter->findData(key));};
    checks->selected=[this](const QString &key){QJsonArray rows;for(const auto &v:coverage)if(v.toObject().value("state").toString()==key)rows.append(v);
      ++selection;detail->setPlainText(QString::fromUtf8(QJsonDocument(rows).toJson(QJsonDocument::Indented)));};
    setSnapshot({});
  }
  std::function<void()> changed;
  void invalidate(){ ++epoch; ++request; ++selection; needsReload=true; setEnabled(false); }
  void setSnapshot(const QJsonObject &snapshot){
    const QString next=snapshot.value("pipeline_id").toString(), fp=snapshot.value("source_fingerprint").toString();
    if(!next.isEmpty()&&next==pipeline&&fp==fingerprint){
      if(needsReload){setEnabled(true);sync->setEnabled(true);import->setEnabled(true);load(false);}return;
    }
    pipeline=next;fingerprint=fp;++epoch;++request;++selection;cursor.clear();table->setRowCount(0);detail->clear();
    const auto stats=snapshot.value("statistics").toObject();coverage=snapshot.value("coverage_checks").toArray();
    const auto f=stats.value("findings").toObject(),v=stats.value("verifications").toObject();
    const bool valid=!pipeline.isEmpty()&&!stats.isEmpty();setEnabled(valid);sync->setEnabled(valid);import->setEnabled(valid);more->setEnabled(false);
    const QList<QJsonValue> numbers{f.value("records"),f.value("instances"),f.value("unmapped_records"),v.value("executed_instances"),v.value("confirmed_instances")};
    for(int n=0;n<5;++n)metrics[n]->setValue(valid&&numbers[n].isDouble()?QString::number(numbers[n].toInt()):QStringLiteral("—"));
    summary->setText(valid?QString("%1\n资产：至少一项检查覆盖率 %2；已知漏洞发现率 %3（扫描标签不是风险评级）")
      .arg(f.value("sync_pending").toBool()?"映射待更新，请同步实例":f.value("unmapped_records").toInt()>0?"信息不足的候选保留为未归并记录":"当前候选已同步；实例详情保留原始发现和证据引用")
      .arg(ratio(stats.value("assets").toObject().value("coverage").toObject())).arg(ratio(stats.value("baseline").toObject().value("discovery").toObject())):"该快照未记录 F09 统计");
    checks->setValues(stats.value("checks").toObject().value("states").toObject());conclusions->setValues(v.value("conclusions").toObject());
    if(valid)load(false);
  }
private:
  QString ratio(const QJsonObject &r) const {return r.value("value").isDouble()?QString::number(r.value("value").toDouble()*100,'f',1)+"%":r.value("reason").toString("基准未知");}
  QString path()const{return "/api/pipelines/"+QString::fromLatin1(QUrl::toPercentEncoding(pipeline))+"/results";}
  bool accepted(const QJsonObject &r,const QString &fp){
    if(r.value("status").toString()!="ok"||r.value("data").toObject().value("source_fingerprint").toString()!=fp){
      needsReload=true;detail->setPlainText("来源已变化或读取失败，请刷新来源。"+r.value("error").toObject().value("message").toString());more->setEnabled(false);return false;}return true;
  }
  void load(bool next){
    if(pipeline.isEmpty()||fingerprint.isEmpty())return;const auto p=pipeline,f=fingerprint;const int seq=++request;++selection;detail->clear();
    needsReload=false;if(!next){cursor.clear();table->setRowCount(0);}more->setEnabled(false);QPointer<TaskStatisticsPanel> guard(this);
    api->get(path()+"/instances?source_fingerprint="+f+"&conclusion="+filter->currentData().toString()+"&severity="+severity->currentData().toString()+"&after="+cursor,5000,[guard,p,f,seq](const QJsonObject &r){
      if(!guard||guard->pipeline!=p||guard->fingerprint!=f||guard->request!=seq)return;if(!guard->accepted(r,f))return;
      const auto data=r.value("data").toObject();for(const auto &value:data.value("rows").toArray()){
        const auto item=value.toObject();int row=guard->table->rowCount();guard->table->insertRow(row);
        const QStringList cells{item.value("instance_id").toString(),statisticsLabel(item.value("severity").toString()),statisticsLabel(item.value("conclusion").toString()),QString::number(item.value("record_ids").toArray().size())};
        for(int c=0;c<cells.size();++c)guard->table->setItem(row,c,new QTableWidgetItem(cells[c]));
      }const auto page=data.value("page").toObject();guard->cursor=page.value("next_after").toString();guard->more->setEnabled(page.value("has_more").toBool());
    });
  }
  void mutate(const QString &route,const QJsonObject &body){
    const auto p=pipeline,f=fingerprint;const int context=epoch;sync->setEnabled(false);import->setEnabled(false);QPointer<TaskStatisticsPanel> guard(this);
    api->post(path()+route,body,15000,[guard,p,f,context](const QJsonObject &r){
      if(!guard||guard->epoch!=context||guard->pipeline!=p||guard->fingerprint!=f)return;guard->sync->setEnabled(true);guard->import->setEnabled(true);
      if(r.value("status").toString()!="ok")guard->detail->setPlainText("操作失败："+r.value("error").toObject().value("message").toString());
      else if(guard->changed)guard->changed();
    });
  }
  void importBaseline(){
    const auto p=pipeline,f=fingerprint;const int context=epoch;const QString filename=QFileDialog::getOpenFileName(this,"导入版本化基准",{},"JSON (*.json)");
    if(filename.isEmpty()||epoch!=context||pipeline!=p||fingerprint!=f)return;QFile file(filename);
    if(!file.open(QIODevice::ReadOnly)||file.size()>96*1024){detail->setPlainText("文件读取失败或超过 96 KiB");return;}
    QJsonParseError error;const auto document=QJsonDocument::fromJson(file.readAll(),&error);
    if(error.error!=QJsonParseError::NoError||!document.isObject()){detail->setPlainText("无效的 JSON 对象");return;}
    const auto content=document.object();QPointer<TaskStatisticsPanel> guard(this);
    api->post(path()+"/baselines",QJsonObject{{"source_fingerprint",f},{"content",content},{"preview",true}},10000,[guard,p,f,content,context](const QJsonObject &r){
      if(!guard||guard->epoch!=context||guard->pipeline!=p||guard->fingerprint!=f)return;
      if(r.value("status").toString()!="ok"){guard->detail->setPlainText(r.value("error").toObject().value("message").toString());return;}
      const auto data=r.value("data").toObject();
      if(QMessageBox::question(guard,"确认导入基准",QString("校验通过：%1 项资产、%2 项已知漏洞。保存为不可变版本并启用？").arg(data.value("assets").toInt()).arg(data.value("vulnerabilities").toInt()))!=QMessageBox::Yes)return;
      if(guard&&guard->epoch==context&&guard->pipeline==p&&guard->fingerprint==f)guard->mutate("/baselines",QJsonObject{{"source_fingerprint",f},{"content",content}});
    });
  }
  ApiClient *api;QString pipeline,fingerprint,cursor;int request=0,selection=0,epoch=0;bool needsReload=false;QJsonArray coverage;
  MetricCard *metrics[5];QLabel *summary;QPushButton *sync,*import,*more;QComboBox *filter,*severity;StatisticsBars *checks,*conclusions;QTableWidget *table;QPlainTextEdit *detail;
};
