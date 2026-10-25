#include "PentagiSourceScanHost.h"
#include "SourceScanDetailDialog.h"
#include "FindingVerificationDialog.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QtWidgets>
#include <QPointer>

PentagiSourceScanHost::PentagiSourceScanHost(ApiClient *api, QWidget *parent)
    : QWidget(parent), m_api(api) {
    setObjectName("pentagiSourceScanHost");
    setStyleSheet(Theme::PageStyle);
    auto *layout=new QVBoxLayout(this);
    auto *form=new QFormLayout;
    m_target=new QLineEdit(this);
    m_target->setObjectName("sourceFlowTarget");
    m_target->setPlaceholderText(QStringLiteral("源码地址，例如 http://目标:端口/source/，由远端 Agent 获取"));
    m_runtime=new QLineEdit(this);
    m_runtime->setObjectName("sourceFlowRuntime");
    m_runtime->setPlaceholderText(QStringLiteral("可选：对应程序的运行入口；生成验证任务时使用"));
    form->addRow(QStringLiteral("源码目标"),m_target);
    form->addRow(QStringLiteral("验证运行入口"),m_runtime);
    layout->addLayout(form);
    auto *bar=new QHBoxLayout;
    m_authorized=new QCheckBox(QStringLiteral("已获授权审计上述目标"),this);
    m_authorized->setObjectName("sourceFlowAuthorized");
    bar->addWidget(m_authorized);
    bar->addStretch();
    m_create=new QPushButton(QStringLiteral("开始源码扫描"),this);
    m_create->setObjectName("sourceFlowCreate");
    m_create->setProperty("primary",true);
    bar->addWidget(m_create);
    auto *refresh=new QPushButton(QStringLiteral("刷新任务"),this);
    bar->addWidget(refresh);
    layout->addLayout(bar);
    m_notice=new QLabel(QStringLiteral("提交目标后自动获取源码、审计并整理报告；验证方案生成后可查看步骤并执行。"),this);
    m_notice->setObjectName("sourceFlowNotice");
    m_notice->setWordWrap(true);
    layout->addWidget(m_notice);
    m_tasks=new QTableWidget(0,3,this);
    m_tasks->setObjectName("sourceFlowTasks");
    m_tasks->setHorizontalHeaderLabels({QStringLiteral("源码目标"),QStringLiteral("状态"),QStringLiteral("时间")});
    m_tasks->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
    m_tasks->setColumnWidth(1,100);
    m_tasks->setColumnWidth(2,160);
    m_tasks->setMaximumHeight(130);
    m_tasks->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tasks->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(m_tasks);
    m_workspace=new QStackedWidget(this);
    auto *empty=new QLabel(QStringLiteral("开始或选择扫描任务，查看目录树、源码和漏洞。"),this);
    empty->setAlignment(Qt::AlignCenter);
    m_workspace->addWidget(empty);
    layout->addWidget(m_workspace,1);
    connect(m_create,&QPushButton::clicked,this,[this]{create();});
    connect(refresh,&QPushButton::clicked,this,[this]{reload();});
    connect(m_tasks,&QTableWidget::cellClicked,this,[this](int row,int){openTask(row);});
    auto *timer=new QTimer(this);
    timer->setInterval(5000);
    connect(timer,&QTimer::timeout,this,[this]{if(isVisible())reload();});
    timer->start();
    if(m_api)QTimer::singleShot(0,this,[this]{reload();});
}
void PentagiSourceScanHost::create() {
    if(!m_api)return;
    if(m_target->text().trimmed().isEmpty() || !m_authorized->isChecked()) {
        m_notice->setText(QStringLiteral("请填写源码目标并确认审计授权。"));
        return;
    }
    const QString content=m_target->text().trimmed()+"\n"+m_runtime->text().trimmed();
    if(m_requestId.isEmpty() || content!=m_requestContent) {
        m_requestContent=content;
        m_requestId=QUuid::createUuid().toString(QUuid::WithoutBraces);
    }
    m_create->setEnabled(false);
    QPointer<PentagiSourceScanHost> self(this);
    m_api->post("/api/scan-tasks/source-flow",{{"target",m_target->text().trimmed()},
        {"runtime_target",m_runtime->text().trimmed()},{"authorization_confirmed",true},{"request_id",m_requestId}},15000,
        [self](const QJsonObject &reply){
            if(!self)return;
            self->m_create->setEnabled(true);
            if(reply["status"]!="ok") {
                self->m_notice->setText(reply["error"].toObject()["message"].toString(QStringLiteral("提交结果待确认，再次点击将核对原请求。")));
                return;
            }
            const auto data=reply["data"].toObject();
            self->m_notice->setText(QStringLiteral("扫描已提交 · ")+data["task_no"].toString());
            self->m_currentScan.clear();
            self->reload();
        });
}
void PentagiSourceScanHost::reload() {
    if(!m_api)return;
    QPointer<PentagiSourceScanHost> self(this);
    m_api->get("/api/scan-tasks?scan_type=source_scan",10000,[self](const QJsonObject &reply){
        if(!self || reply["status"]!="ok")return;
        const auto rows=reply["data"].toArray();
        self->m_tasks->setRowCount(rows.size());
        for(int i=0;i<rows.size();++i) {
            auto row=rows[i].toObject();
            auto *item=new QTableWidgetItem(row["target"].toString());
            item->setData(Qt::UserRole,row);
            self->m_tasks->setItem(i,0,item);
            const QMap<QString,QString> names{{"PENDING","等待中"},{"RUNNING","扫描与后处理中"},{"PARTIAL","报告待复核"},{"COMPLETED","已完成"},{"FAILED","失败"},{"CANCELLED","已取消"}};
            self->m_tasks->setItem(i,1,new QTableWidgetItem(names.value(row["status"].toString(),row["status"].toString())));
            self->m_tasks->setItem(i,2,new QTableWidgetItem(row["created_at"].toString()));
        }
        if(self->m_currentScan.isEmpty() && !rows.isEmpty())self->openTask(0);
    });
}
void PentagiSourceScanHost::openTask(int row) {
    if(!m_tasks->item(row,0))return;
    const auto task=m_tasks->item(row,0)->data(Qt::UserRole).toJsonObject();
    const QString id=task["scan_task_id"].toString(),pipeline=task["pipeline_id"].toString();
    if(id.isEmpty() || id==m_currentScan)return;
    m_currentScan=id;
    while(m_workspace->count()>1) {
        auto *old=m_workspace->widget(1);
        m_workspace->removeWidget(old);
        old->deleteLater();
    }
    auto *detail=new SourceScanDetailDialog(m_api,{id},task["target"].toString(),m_workspace);
    detail->setWindowFlags(Qt::Widget);
    detail->setAttribute(Qt::WA_DeleteOnClose,false);
    detail->setMinimumSize(0,360);
    m_workspace->addWidget(detail);
    m_workspace->setCurrentWidget(detail);
    connect(detail,&SourceScanDetailDialog::testRequested,this,[this,pipeline](const QList<qint64> &findings){
        if(pipeline.isEmpty()) {
            m_notice->setText(QStringLiteral("此历史扫描缺少任务归属，请从任务页查看或新建源码扫描。"));
            return;
        }
        auto *window=new FindingVerificationDialog(m_api,pipeline,findings,this);
        window->setAttribute(Qt::WA_DeleteOnClose);
        window->show();
    });
}
