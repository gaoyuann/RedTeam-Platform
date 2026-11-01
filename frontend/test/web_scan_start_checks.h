#pragma once

static void runWebScanStartChecks(const std::function<void(bool, const char *)> &verify)
{
  {
    MockServer sessionServer;
    auto sessionTask = taskRecord("session-test");
    sessionTask["status"] = "created";
    sessionTask["target"] = "https://fixture.test/app/";
    sessionTask["run_id"] = "";
    sessionTask["config"] = QJsonObject{{"scan_orchestrator",QJsonObject{{"version",1},{"mode","react"}}}};
    sessionServer.handler=[&](const QString &method, const QString &path)->MockReply {
      if(method=="GET" && path=="/api/pipelines")return {success(QJsonArray{})};
      if(method=="POST" && path.endsWith("/retry-scan")) {
        sessionTask["pipeline_id"]="session-retry";sessionTask["status"]="created";
        return {success(sessionTask)};
      }
      if(method=="POST" && path=="/api/pipelines") {
        sessionTask["pipeline_id"]="session-created";
        return {success(sessionTask)};
      }
      if(method=="POST" && path.endsWith("/start")) {
        sessionTask["status"]="running";
        return {success(sessionTask),100};
      }
      if(path=="/api/pipelines/"+sessionTask["pipeline_id"].toString())return {success(sessionTask)};
      if(path.contains("/results"))return {success(resultsRecord("session-test"))};
      if(path.endsWith("/execution"))return {success(executionRecord("session-test"))};
      return {success(QJsonObject{})};
    };
    ApiClient sessionApi(QStringLiteral("http://127.0.0.1:%1").arg(sessionServer.serverPort()));
    FlowPage sessionFlow(&sessionApi,"user");
    sessionFlow.openTaskAnalysis("session-test");
    verify(awaitCondition([&]{return sessionFlow.m_scanOptionsAction->isVisible();}),"optional Web settings are available in more actions before starting");
    int unexpectedDialogs=0;
    QTimer modalGuard;
    QObject::connect(&modalGuard,&QTimer::timeout,&sessionFlow,[&]{
      if(auto *dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget())) {++unexpectedDialogs;dialog->reject();}
    });
    modalGuard.start(10);
    sessionFlow.m_startBtn->click();
    sessionFlow.m_scanOptionsAction->trigger();
    sessionFlow.onStartFlow();
    verify(awaitCondition([&]{return sessionServer.requests.value("POST /api/pipelines/session-test/start")==1
        && sessionFlow.m_lastDisplayedDetail["status"]=="running";}),"ordinary Web start submits once without a session prompt");
    verify(unexpectedDialogs==0 && QJsonDocument::fromJson(sessionServer.requestBodies.value("POST /api/pipelines/session-test/start")).object().isEmpty(),
      "default start needs no credentials or POST template and duplicate start actions are ignored");
    verify(!sessionFlow.m_scanOptionsAction->isVisible(),"advanced start is hidden for running tasks");
    sessionTask["status"]="created";
    sessionFlow.submitTaskCreation(QJsonObject{{"target","https://fixture.test/app/"}},true);
    verify(awaitCondition([&]{return sessionServer.requests.value("POST /api/pipelines/session-created/start")==1
        && sessionFlow.m_lastDisplayedDetail["pipeline_id"]=="session-created"
        && sessionFlow.m_lastDisplayedDetail["status"]=="running";}),"create-and-start also scans anonymously without an extra dialog");
    sessionTask["status"]="completed";
    sessionFlow.loadFlowDetail("session-created");
    verify(awaitCondition([&]{return sessionFlow.m_lastDisplayedDetail["status"]=="completed";}),"finished Web fixture offers a new scan");
    sessionFlow.m_startBtn->click();
    verify(awaitCondition([&]{return sessionServer.requests.value("POST /api/pipelines/session-retry/start")==1
        && sessionFlow.m_lastDisplayedDetail["status"]=="running";}),"retry creates a fresh task and starts without a session prompt");
    verify(unexpectedDialogs==0,"ordinary creation, start and retry never open advanced settings");
    modalGuard.stop();

    sessionTask["pipeline_id"]="session-test";sessionTask["status"]="created";
    sessionFlow.openTaskAnalysis("session-test");
    verify(awaitCondition([&]{return sessionFlow.m_scanOptionsAction->isVisible();}),"advanced settings return for a new pending scan");
    QTimer::singleShot(0,&sessionFlow,[&]{
      auto *dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget());
      verify(dialog && dialog->objectName()=="webScanOptionsDialog","advanced settings require an explicit action");
      dialog->reject();
    });
    sessionFlow.m_scanOptionsAction->trigger();
    QTest::qWait(30);
    verify(sessionServer.requests.value("POST /api/pipelines/session-test/start")==1,"cancelling advanced settings leaves the task unstarted");
    QTimer::singleShot(0,&sessionFlow,[&]{
      auto *dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget());
      verify(dialog && dialog->objectName()=="webScanOptionsDialog","explicit advanced action opens optional session settings");
      auto *mode=dialog->findChild<QComboBox*>("scanSessionMode");
      auto *value=dialog->findChild<QLineEdit*>("scanSessionValue");
      verify(mode && value && mode->currentData()=="anonymous","anonymous is the default with no credential required");
      mode->setCurrentIndex(mode->findData("bearer"));
      verify(!dialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->isEnabled(),"empty selected bearer cannot start");
      value->setText("fixture-session-token");
      verify(value->echoMode()==QLineEdit::Password,"session value is masked");
      dialog->findChild<QPlainTextEdit*>("scanPostRequests")->setPlainText(QStringLiteral(
        "[{\"url\":\"https://fixture.test/app/lookup\",\"encoding\":\"json\",\"fields\":{\"id\":\"1\"},\"parameters\":[\"id\"],\"read_only_confirmed\":true}]"));
      dialog->findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->click();
    });
    sessionFlow.m_scanOptionsAction->trigger();
    verify(awaitCondition([&]{return sessionServer.requests.value("POST /api/pipelines/session-test/start")==2;}),"temporary session submitted only after explicit advanced start");
    const auto startBody=QJsonDocument::fromJson(sessionServer.requestBodies.value("POST /api/pipelines/session-test/start")).object();
    const auto auth=startBody["authentication"].toObject();
    verify(auth["type"]=="bearer" && auth["value"]=="fixture-session-token","selected session reaches start request without task config storage");
    verify(startBody["post_requests"].toArray().size()==1,"advanced start preserves the optional POST request template");
    verify(awaitCondition([&]{return sessionFlow.m_lastDisplayedDetail["status"]=="running";}),"advanced start finishes before leaving the fixture");
    sessionTask["status"]="created";sessionTask["target"]="192.0.2.10";
    sessionFlow.loadFlowDetail("session-test");
    verify(awaitCondition([&]{return sessionFlow.m_lastDisplayedDetail["target"]=="192.0.2.10";})
        && !sessionFlow.m_scanOptionsAction->isVisible(),"non-Web targets have no optional Web settings action");
  }
}
