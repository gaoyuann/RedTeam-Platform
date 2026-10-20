#pragma once
#include "../ApiClient.h"
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPointer>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>
#include <memory>

// Shared by standalone scans and task creation. All listing comes from the
// backend; QFileDialog would browse the operator's computer instead.
class RemoteSourcePicker : public QWidget {
public:
  explicit RemoteSourcePicker(ApiClient *api, QWidget *parent=nullptr)
      : QWidget(parent), m_api(api) {
    auto *row=new QHBoxLayout(this);row->setContentsMargins(0,0,0,0);
    m_summary=new QLineEdit(this);m_summary->setReadOnly(true);
    m_summary->setPlaceholderText("尚未选择目标主机的源码文件夹");
    m_summary->setObjectName("remoteSourceSelection");
    auto *button=new QPushButton("选择目标文件夹…",this);
    button->setObjectName("remoteSourceBrowse");
    row->addWidget(m_summary,1);row->addWidget(button);
    connect(button,&QPushButton::clicked,this,[this]{browse();});
  }
  void setTarget(const QString &target) {
    if(m_target==target.trimmed()) return;
    m_target=target.trimmed();m_selection={};m_summary->clear();
  }
  bool hasSelection() const {return !m_selection.isEmpty();}
  QJsonObject selection() const {return m_selection;}

private:
  void browse() {
    auto *dialog=new QDialog(this);dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setObjectName("remoteSourceDirectoryDialog");
    dialog->setWindowTitle("选择目标主机的源码文件夹");dialog->resize(640,440);
    auto *layout=new QVBoxLayout(dialog);
    const QString target=m_target;
    layout->addWidget(new QLabel("目标主机："+target,dialog));
    auto *mode=new QComboBox(dialog);mode->setObjectName("remoteSourceConnection");
    mode->addItem("目标网站公开的源码目录（HTTP）","");
    layout->addWidget(mode);
    auto *path=new QLineEdit("/",dialog);path->setObjectName("remoteSourceDirectoryPath");
    path->setPlaceholderText("目标目录，例如 /source/；SSH 从已配置根目录开始");
    layout->addWidget(path);
    auto *actions=new QHBoxLayout;
    auto *load=new QPushButton("读取目录",dialog),*up=new QPushButton("上一级",dialog);
    load->setObjectName("remoteSourceLoad");up->setEnabled(false);
    actions->addWidget(load);actions->addWidget(up);layout->addLayout(actions);
    auto *list=new QListWidget(dialog);list->setObjectName("remoteSourceDirectories");layout->addWidget(list,1);
    auto *status=new QLabel("可浏览 HTTP 目录索引，或选择已配置的 SSH 连接。",dialog);
    status->setWordWrap(true);layout->addWidget(status);
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,dialog);
    auto *ok=buttons->button(QDialogButtonBox::Ok);ok->setText("选择当前文件夹");ok->setEnabled(false);
    layout->addWidget(buttons);
    // State belongs to the dialog; delayed responses cannot update a closed
    // dialog, a different target, or a newer directory request.
    struct State {int generation=0;QJsonObject choice;QString parent;bool hasParent=false;};
    auto state=std::make_shared<State>();
    QPointer<QDialog> guard(dialog);QPointer<RemoteSourcePicker> owner(this);
    auto read=[=] {
      const int generation=++state->generation;state->choice={};ok->setEnabled(false);
      list->clear();status->setText("正在读取目标目录…");
      const QString connection=mode->currentData().toString();
      QJsonObject body{{"target",target}};
      if(connection.isEmpty()) body["source_url"]=path->text().trimmed();
      else {body["connection_id"]=connection;body["source_subdir"]=path->text().trimmed();}
      m_api->post("/api/scan-tasks/source-directory",body,65000,[=](const QJsonObject &response){
        if(!guard || !owner || owner->m_target!=target || generation!=state->generation) return;
        if(response["status"].toString()!="ok") {
          status->setText(response["error"].toObject()["message"].toString());return;
        }
        const auto data=response["data"].toObject();state->choice=body;
        if(connection.isEmpty()) {state->choice["source_url"]=data["url"];path->setText(data["url"].toString());}
        else {state->choice["source_subdir"]=data["path"];path->setText(data["path"].toString());}
        state->hasParent=!data["parent"].isNull() && !data["parent"].isUndefined();
        state->parent=data["parent"].toString();up->setEnabled(state->hasParent);
        for(const auto &value:data["entries"].toArray()) {
          const auto entry=value.toObject();if(!entry["directory"].toBool()) continue;
          auto *item=new QListWidgetItem(entry["name"].toString(),list);
          item->setData(Qt::UserRole,(connection.isEmpty()?entry["url"]:entry["path"]).toString());
        }
        status->setText(data["truncated"].toBool() ? "目录较多，仅显示前 500 项；可输入子目录后读取。"
          : "仅将所选路径或地址交给 CScan，由 Agent 自行读取；不上传文件，浏览成功不代表 CScan 已有访问权限。");
        ok->setEnabled(true);
      });
    };
    connect(load,&QPushButton::clicked,dialog,read);
    connect(path,&QLineEdit::textEdited,dialog,[=]{++state->generation;state->choice={};ok->setEnabled(false);});
    connect(path,&QLineEdit::returnPressed,dialog,read);
    connect(list,&QListWidget::itemDoubleClicked,dialog,[=](QListWidgetItem *item){path->setText(item->data(Qt::UserRole).toString());read();});
    connect(up,&QPushButton::clicked,dialog,[=]{if(state->hasParent){path->setText(state->parent);read();}});
    connect(mode,QOverload<int>::of(&QComboBox::currentIndexChanged),dialog,[=](int){
      path->setText(mode->currentData().toString().isEmpty()?"/":"");read();
    });
    connect(buttons,&QDialogButtonBox::rejected,dialog,&QDialog::reject);
    connect(buttons,&QDialogButtonBox::accepted,dialog,[=]{
      if(!owner || owner->m_target!=target || state->choice.isEmpty()) return;
      m_selection=state->choice;m_selection.remove("target");
      const QString selected=m_selection.contains("source_url")?m_selection["source_url"].toString()
        : mode->currentText()+" /"+m_selection["source_subdir"].toString();
      m_summary->setText(selected);dialog->accept();
    });
    m_api->get("/api/scan-tasks/source-connections",10000,[=](const QJsonObject &response){
      if(!guard || !owner || owner->m_target!=target) return;
      if(response["status"].toString()!="ok") return;
      for(const auto &value:response["data"].toArray()) {
        const auto c=value.toObject();if(c["kind"].toString()!="ssh") continue;
        bool matches=false;
        for(const auto &v:c["targets"].toArray())
          if(QUrl(v.toString()).adjusted(QUrl::StripTrailingSlash)==QUrl(target).adjusted(QUrl::StripTrailingSlash)) matches=true;
        if(matches) mode->addItem(c["name"].toString()+"（SSH）",c["id"].toString());
      }
      if(mode->count()>1) mode->setCurrentIndex(1);
    });
    dialog->setModal(true);dialog->show();
    if(target.isEmpty()) {load->setEnabled(false);status->setText("请先填写目标主机地址。");}
  }
  ApiClient *m_api;
  QLineEdit *m_summary;
  QString m_target;
  QJsonObject m_selection;
};
