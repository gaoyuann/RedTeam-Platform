#include "PentagiSourceScanHost.h"
#include "SourceScanDetailDialog.h"
#include "FindingVerificationDialog.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include "../UiUtil.h"
#include <QtWidgets>
#include <QPointer>

PentagiSourceScanHost::PentagiSourceScanHost(ApiClient *api, QWidget *parent)
    : QWidget(parent), m_api(api) {
    setObjectName("pentagiSourceScanHost");
    setStyleSheet(Theme::PageStyle);
    auto *layout=new QVBoxLayout(this);
    layout->setContentsMargins(10,8,10,8);
    layout->setSpacing(8);
    auto *toolbar=new QHBoxLayout;
    auto *newScan=new QPushButton(QStringLiteral("＋ 新建源码扫描"),this);
    newScan->setObjectName("sourceFlowNew");
    newScan->setProperty("primary",true);
    auto *open=new QPushButton(QStringLiteral("打开详情"),this);
    open->setObjectName("sourceFlowOpenDetails");
    open->setEnabled(false);
    auto *refresh=new QPushButton(QStringLiteral("刷新任务"),this);
    refresh->setObjectName("sourceFlowRefresh");
    toolbar->addWidget(newScan);
    toolbar->addWidget(open);
    toolbar->addStretch();
    toolbar->addWidget(refresh);
    layout->addLayout(toolbar);

    // Match PentAGI's list-first workspace: creation has its own bounded form.
    auto *dialog=new QDialog(this);
    dialog->setObjectName("sourceFlowCreateDialog");
    dialog->setWindowTitle(QStringLiteral("新建源码扫描"));
    dialog->setWindowModality(Qt::WindowModal);
    dialog->setStyleSheet(Theme::PageStyle);
    dialog->resize(640,300);
    auto *dialogLayout=new QVBoxLayout(dialog);
    dialogLayout->setContentsMargins(18,16,18,16);
    dialogLayout->setSpacing(12);
    auto *form=new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    m_target=new QLineEdit(dialog);
    m_target->setObjectName("sourceFlowTarget");
    m_target->setPlaceholderText(QStringLiteral("http://目标:端口/source/"));
    m_runtime=new QLineEdit(dialog);
    m_runtime->setObjectName("sourceFlowRuntime");
    m_runtime->setPlaceholderText(QStringLiteral("可选：程序运行入口"));
    form->addRow(QStringLiteral("源码地址"),m_target);
    form->addRow(QStringLiteral("验证运行入口"),m_runtime);
    dialogLayout->addLayout(form);
    auto *hint=new QLabel(QStringLiteral("远端 Agent 获取源码、审计并整理报告。验证运行入口仅在生成验证任务时使用。"),dialog);
    hint->setWordWrap(true);
    dialogLayout->addWidget(hint);
    m_authorized=new QCheckBox(QStringLiteral("已获授权审计上述目标"),dialog);
    m_authorized->setObjectName("sourceFlowAuthorized");
    dialogLayout->addWidget(m_authorized);
    auto *message=new QLabel(dialog);
    message->setObjectName("sourceFlowSubmissionMessage");
    message->setWordWrap(true);
    message->setTextFormat(Qt::PlainText);
    dialogLayout->addWidget(message);
    auto *buttons=new QDialogButtonBox(dialog);
    m_create=buttons->addButton(QStringLiteral("开始源码扫描"),QDialogButtonBox::AcceptRole);
    m_create->setObjectName("sourceFlowCreate");
    m_create->setProperty("primary",true);
    auto *cancel=buttons->addButton(QStringLiteral("取消"),QDialogButtonBox::RejectRole);
    dialogLayout->addWidget(buttons);
    connect(cancel,&QPushButton::clicked,dialog,&QDialog::reject);
    connect(newScan,&QPushButton::clicked,dialog,[dialog,message]{
        message->clear();dialog->show();dialog->raise();dialog->activateWindow();
    });

    m_tasks=new QTableWidget(0,3,this);
    m_tasks->setObjectName("sourceFlowTasks");
    UiUtil::EmptyHint::attach(m_tasks,QStringLiteral("暂无源码扫描任务，点击“新建源码扫描”开始。"));
    m_tasks->setHorizontalHeaderLabels({QStringLiteral("源码目标"),QStringLiteral("状态"),QStringLiteral("创建时间")});
    m_tasks->horizontalHeader()->setStretchLastSection(false);
    m_tasks->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
    m_tasks->horizontalHeader()->setSectionResizeMode(1,QHeaderView::ResizeToContents);
    m_tasks->horizontalHeader()->setSectionResizeMode(2,QHeaderView::ResizeToContents);
    m_tasks->verticalHeader()->hide();
    m_tasks->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tasks->setWordWrap(true);
    m_tasks->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tasks->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tasks->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tasks->setAlternatingRowColors(true);
    layout->addWidget(m_tasks,1);
    m_notice=new QLabel(QStringLiteral("选择任务查看源码与发现，双击可打开详情。"),this);
    m_notice->setObjectName("sourceFlowNotice");
    m_notice->setTextFormat(Qt::PlainText);
    m_notice->setWordWrap(true);
    layout->addWidget(m_notice);
    connect(m_tasks,&QTableWidget::itemSelectionChanged,this,[this,open]{open->setEnabled(m_tasks->currentRow()>=0);});
    connect(open,&QPushButton::clicked,this,[this]{openTask(m_tasks->currentRow());});
    connect(m_create,&QPushButton::clicked,this,[this]{create();});
    connect(refresh,&QPushButton::clicked,this,[this]{reload();});
    connect(m_tasks,&QTableWidget::cellDoubleClicked,this,[this](int row,int){openTask(row);});
    auto *timer=new QTimer(this);
    timer->setInterval(5000);
    connect(timer,&QTimer::timeout,this,[this]{if(isVisible())reload();});
    timer->start();
    if(m_api)QTimer::singleShot(0,this,[this]{reload();});
}
void PentagiSourceScanHost::create() {
    if(!m_api)return;
    if(m_target->text().trimmed().isEmpty() || !m_authorized->isChecked()) {
        findChild<QLabel*>("sourceFlowSubmissionMessage")->setText(QStringLiteral("请填写源码目标并确认审计授权。"));
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
                self->findChild<QLabel*>("sourceFlowSubmissionMessage")->setText(reply["error"].toObject()["message"].toString(QStringLiteral("提交结果待确认，再次点击将核对原请求。")));
                return;
            }
            const auto data=reply["data"].toObject();
            self->findChild<QDialog*>("sourceFlowCreateDialog")->accept();
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
        QString selected;
        if(auto *item=self->m_tasks->item(self->m_tasks->currentRow(),0))
            selected=item->data(Qt::UserRole).toJsonObject()["scan_task_id"].toString();
        const int scroll=self->m_tasks->verticalScrollBar()->value();
        const QSignalBlocker selectionBlocker(self->m_tasks);
        self->m_tasks->clearSelection();
        self->m_tasks->setCurrentCell(-1,-1);
        self->m_tasks->setRowCount(rows.size());
        for(int i=0;i<rows.size();++i) {
            auto row=rows[i].toObject();
            auto *item=new QTableWidgetItem(row["target"].toString());
            item->setData(Qt::UserRole,row);
            item->setToolTip(item->text());
            self->m_tasks->setItem(i,0,item);
            const QMap<QString,QString> names{{"PENDING","等待中"},{"RUNNING","扫描与后处理中"},{"PARTIAL","报告待复核"},{"COMPLETED","已完成"},{"FAILED","失败"},{"CANCELLED","已取消"}};
            self->m_tasks->setItem(i,1,new QTableWidgetItem(names.value(row["status"].toString(),row["status"].toString())));
            const QString rawTime=row["created_at"].toString();
            const auto time=QDateTime::fromString(rawTime,Qt::ISODate);
            auto *timeItem=new QTableWidgetItem(time.isValid()
                ? time.toLocalTime().toString("yyyy-MM-dd HH:mm:ss") : rawTime);
            timeItem->setToolTip(rawTime);
            self->m_tasks->setItem(i,2,timeItem);
            if(!selected.isEmpty() && row["scan_task_id"].toString()==selected)self->m_tasks->selectRow(i);
        }
        self->m_tasks->verticalScrollBar()->setValue(scroll);
        self->findChild<QPushButton*>("sourceFlowOpenDetails")->setEnabled(self->m_tasks->currentRow()>=0);

    });
}
void PentagiSourceScanHost::openTask(int row) {
    if(!m_tasks->item(row,0))return;
    const auto task=m_tasks->item(row,0)->data(Qt::UserRole).toJsonObject();
    const QString id=task["scan_task_id"].toString(),pipeline=task["pipeline_id"].toString();
    if(id.isEmpty())return;
    showScanDetails({id},task["target"].toString(),pipeline);
}
void PentagiSourceScanHost::showScanDetails(const QStringList &ids,const QString &target,const QString &pipeline) {
    if(ids.isEmpty())return;
    const auto key=ids.join(",");
    if(key==m_currentScan && m_detail){m_detail->show();m_detail->raise();m_detail->activateWindow();return;}
    m_currentScan=key;
    m_notice->setText(QStringLiteral("正在查看所选扫描结果：")+target);

    if(m_detail)m_detail->close();
    auto *detail=new SourceScanDetailDialog(m_api,ids,target,this);
    m_detail=detail;
    detail->setAttribute(Qt::WA_DeleteOnClose);
    detail->show();
    connect(detail,&SourceScanDetailDialog::testRequested,this,[this,pipeline](const QList<qint64> &findings){
        if(pipeline.isEmpty()) {
            m_notice->setText(QStringLiteral("此历史扫描缺少任务归属，请从任务页查看或新建源码扫描。"));
            return;
        }
        if (verificationRequested) {
            verificationRequested(pipeline, findings);
            return;
        }
        auto *window=new FindingVerificationDialog(m_api,pipeline,findings,this);
        window->setAttribute(Qt::WA_DeleteOnClose);
        window->show();
    });
}
