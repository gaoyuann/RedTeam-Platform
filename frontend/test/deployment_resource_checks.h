#pragma once

template<class Verify>
void runDeploymentResourceChecks(Verify verify)
{
  const QString originalStyle = qApp->styleSheet();
  qApp->setStyleSheet(Theme::GlobalStyle + Theme::ButtonStyle + Theme::ItemViewStyle);
  MockServer server;
  bool failImages = false, failTools = false, failSandbox = false, legacy = false;
  const QStringList names{"nmap", "whatweb", "gobuster", "ffuf", "httpx", "amass", "curl", "nuclei", "nikto", "sqlmap", "python3", "target-request", "webshell"};
  const QStringList purposes{"端口与服务探测", "Web 技术指纹识别", "目录与 DNS 枚举", "Web 路径与参数枚举", "HTTP 服务探测", "域名与资产枚举", "HTTP 请求与响应检查", "模板化漏洞检测", "Web 服务配置与漏洞检测", "SQL 注入检测", "Python 脚本执行", "目标 HTTP 请求", "WebShell 交互处理"};
  server.handler = [&](const QString &, const QString &path) -> MockReply {
    if (path == "/api/config/sandbox" && failSandbox)
      return {QJsonObject{{"status", "error"}}};
    if (path == "/api/labs")
      return {success(QJsonArray{QJsonObject{{"name", "dvwa"}, {"status", "stopped"}}})};
    if (path == "/api/tools/list") {
      if (failTools) return {QJsonObject{{"status", "error"}}};
      QJsonArray tools;
      for (int i = 0; i < names.size(); ++i) {
        QJsonObject row{{"toolId", names[i]}, {"virtual", i == 12},
          {"image", i == 12 ? QJsonValue(QJsonValue::Null) : QJsonValue(i == 11 ? "builtin" : i == 10 ? "rt-web" : i >= 7 ? "rt-vuln-scan" : "rt-recon")}};
        if (!legacy) row["purpose"] = purposes[i];
        tools.append(row);
      }
      return {success(tools), 80};
    }
    if (path == "/api/tools/containers/status") {
      if (failImages) return {success(QJsonObject{{"engine", "docker"}, {"images", QJsonArray()}, {"imageInventoryStatus", "error"}})};
      QJsonObject status{{"engine", "docker"}, {"images", QJsonArray{"rt-recon:latest", "rt-web:latest", "rt-vuln-scan:old"}},
        {"expectedImages", QJsonArray{"rt-recon:latest", "rt-web:latest", "rt-vuln-scan:latest", "rt-system:latest"}},
        {"imageSizes", QJsonObject{{"rt-recon:latest", "737MB"}, {"rt-web:latest", "117MB"}, {"rt-vuln-scan:old", "396MB"}}}};
      if (!legacy) {
        status["imageInventoryStatus"] = "ok";
        status["imageCapabilities"] = QJsonObject{{"rt-recon", "资产探测与枚举"}, {"rt-web", "Web 参数与登录测试"},
            {"rt-vuln-scan", "漏洞扫描"}, {"rt-system", "系统信息与命令"}};
      }
      return {success(status), 10};
    }
    return {success(QJsonArray())};
  };
  ApiClient api(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()));
  DeployConfigPage page(&api, "admin", "fixture");
  page.showSection("tools"); page.resize(1280, 720); page.show();
  verify(awaitCondition([&]() {return page.m_toolsLoaded && page.m_imagesLoaded;}), "resource inventory joins independent tool and image responses");
  const auto findRow = [](QTableWidget *table, const QString &name, const QString &tag = QString()) {
    for (int row = 0; row < table->rowCount(); ++row)
      if (table->item(row, 0)->text() == name && (tag.isEmpty() || table->item(row, 1)->text() == tag)) return row;
    return -1;
  };
  verify(!page.m_formScroll->isVisible() && page.m_resourceTabs->isVisible() && page.m_resourceTabs->count() == 2,
      "tools use one full-height table without the outer form scroll area");
  verify(page.m_toolTable->item(findRow(page.m_toolTable, "nmap"), 4)->text() == QStringLiteral("已加载"), "container tool reflects its exact latest image");
  verify(page.m_toolTable->item(findRow(page.m_toolTable, "nuclei"), 4)->text() == QStringLiteral("未安装"), "another tag does not satisfy a latest image dependency");
  const auto *uninstalled = page.m_imageTable->item(findRow(page.m_imageTable, "rt-system", "latest"), 2);
  verify(uninstalled->text() == QStringLiteral("未安装") && uninstalled->toolTip().contains(QStringLiteral("按需")),
      "uninstalled registered images describe optional installation rather than a task failure");
  verify(page.m_imageTable->item(findRow(page.m_imageTable, "rt-recon"), 5)->text() == QStringLiteral("资产探测与枚举"),
      "image capabilities come from server metadata");
  verify(page.m_toolTable->item(findRow(page.m_toolTable, "target-request"), 2)->text() == QStringLiteral("内置处理器")
      && page.m_toolTable->item(findRow(page.m_toolTable, "webshell"), 4)->text() == QStringLiteral("不适用"), "built-in and virtual handlers do not claim missing container images");
  verify(findRow(page.m_imageTable, "rt-system", "latest") >= 0
      && page.m_imageTable->item(findRow(page.m_imageTable, "rt-recon"), 4)->text() == QStringLiteral("7 个工具"), "image view includes missing expected images and associated tool counts");
  page.m_resourceSearch->setText(QStringLiteral("指纹"));
  verify(!page.m_toolTable->isRowHidden(findRow(page.m_toolTable, "whatweb")) && page.m_resourceSummary->text() == QStringLiteral("1 / 13 项"), "search includes tool purposes");
  page.m_resourceSearch->clear(); page.m_resourceType->setCurrentIndex(2);
  verify(page.m_resourceSummary->text() == QStringLiteral("1 / 13 项"), "execution mode filters preserve built-in handlers");
  page.m_resourceType->setCurrentIndex(0);
  for (const int width : {1024, 1366}) {
    page.resize(width, 600); QTest::qWait(40);
    verify(page.width() == width && page.m_toolTable->height() >= 350, "resource table uses the available height at small window sizes");
  }
  const QString screenshots = qEnvironmentVariable("REDTEAM_RESOURCE_SCREENSHOT_DIR");
  const auto capture = [&](const QString &name) {
    if (screenshots.isEmpty()) return;
    QDir().mkpath(screenshots);
    QTest::qWait(40);
    verify(page.grab().save(screenshots + '/' + name + '-' + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"), "actual resource widgets saved for visual review");
  };
  capture("tools");
  page.m_resourceTabs->setCurrentIndex(1); capture("images");
  verify(!page.m_resourceType->isVisible(), "image view hides tool-only mode filter");
  page.m_resourceSearch->setText(QStringLiteral("漏洞扫描"));
  verify(page.m_resourceSummary->text() == QStringLiteral("2 / 5 项"), "images can be filtered by applicable testing capability");
  page.m_resourceSearch->setText("nmap");
  verify(page.m_resourceSummary->text() == QStringLiteral("1 / 5 项"), "images can be found by associated tool name");
  page.m_resourceSearch->clear();
  failImages = true; page.loadSandboxConfig();
  verify(awaitCondition([&]() {return page.m_imagesLoaded;}), "failed engine inventory response settles");
  verify(page.m_toolTable->item(findRow(page.m_toolTable, "nmap"), 4)->text() == QStringLiteral("未确认"), "failed image query clears old loaded state instead of asserting missing or available");
  failImages = false; legacy = true; page.loadSandboxConfig(); page.loadToolList();
  verify(awaitCondition([&]() {return page.m_imagesLoaded && page.m_toolsLoaded;}), "resource refresh recovers with an older server schema");
  verify(page.m_toolTable->item(findRow(page.m_toolTable, "nmap"), 4)->text() == QStringLiteral("已加载"), "legacy schema still resolves image dependencies");
  verify(page.m_imageTable->item(findRow(page.m_imageTable, "rt-recon"), 5)->text() == QStringLiteral("—"),
      "legacy servers without capability metadata do not invent requirements");
  failTools = true; page.loadToolList();
  verify(awaitCondition([&]() {return page.m_toolTable->rowCount() == 0;}), "failed tool reads clear old records");
  failTools = false; page.loadToolList();
  verify(awaitCondition([&]() {return page.m_toolsLoaded;}), "tool inventory recovers after a failed read");
  page.showSection("runtime"); QTest::qWait(40); capture("runtime");
  verify(!page.m_formScroll->isVisible() && page.m_sections["runtime"]->isVisible()
      && page.m_resourceTabs->currentIndex() == 1 && !page.m_resourceTabs->tabBar()->isVisible(),
      "runtime configuration uses a compact card above its image inventory without a form scroll area");
  for (const int width : {1024, 1366}) {
    page.resize(width, 600); QTest::qWait(40);
    verify(page.size() == QSize(width, 600) && page.m_sections["runtime"]->height() < 180
        && page.m_imageTable->height() >= 350,
        "runtime card stays compact and gives the image inventory the remaining height");
    verify(page.m_sandboxStatusLabel->y() >= page.m_sandboxSaveBtn->geometry().bottom()
        && page.m_sandboxSaveBtn->geometry().right() < page.m_sections["runtime"]->width(),
        "runtime feedback occupies its own row without squeezing the save action");
  }
  page.showSection("llm");
  verify(page.m_formScroll->isVisible() && !page.m_resourceTabs->isVisible(), "switching back to model configuration hides resource tables");
  page.showSection("config");
  verify(!page.m_labTable->isVisible() && !page.m_labRefreshBtn->isVisible(),
      "lab controls do not leak into general configuration");
  legacy = false;
  MainWindow shell(&api, "admin", "fixture");
  shell.openRibbonFeature("resources.tools"); shell.resize(1024, 600); shell.show();
  verify(awaitCondition([&]() { return shell.m_deployPage->m_toolsLoaded && shell.m_deployPage->m_imagesLoaded; }),
      "resource inventory loads inside the real application shell");
  QTest::qWait(40);
  verify(shell.size() == QSize(1024, 600) && shell.m_deployPage->m_toolTable->isVisible()
      && shell.m_workspaceScroll->verticalScrollBar()->maximum() == 0,
      "small application window keeps a single table scrollbar without scrolling the whole workspace");
  shell.resize(1366, 768); QTest::qWait(40);
  auto *configuration = shell.m_deployPage;
  const auto clickResource = [&](const QString &section) {
    auto *button = shell.m_ribbon->findChild<QToolButton *>("ribbon.resources." + section);
    verify(button && button->isVisible() && button->isEnabled(), "resource navigation has a visible enabled command button");
    auto *scroll = shell.m_ribbon->findChild<QScrollArea *>("ribbonScroll0");
    scroll->ensureWidgetVisible(button);
    QTest::mouseClick(button, Qt::LeftButton);
    verify(shell.m_deployPage == configuration && shell.m_stackWidget->currentIndex() == 8
        && shell.m_activeFeature == "resources." + section
        && configuration->property("activeSection").toString() == section,
        "clicking a resource command selects its actual content on the existing page");
    verify(configuration->m_llmModel->isVisible() == (section == "llm")
        && configuration->m_labTable->isVisible() == (section == "labs")
        && configuration->m_labRefreshBtn->isVisible() == (section == "labs")
        && configuration->m_sandboxType->isVisible() == (section == "runtime")
        && configuration->m_toolTable->isVisible() == (section == "tools")
        && configuration->m_imageTable->isVisible() == (section == "runtime"),
        "resource commands show their controls and hide content from previous sections");
  };
  clickResource("llm");
  configuration->m_llmModel->setText("fixture-unsaved-model");
  for (const auto &section : QStringList{"labs", "runtime", "labs", "tools", "labs", "llm", "labs", "labs"})
    clickResource(section);
  verify(configuration->m_labTable->rowCount() == 1
      && configuration->m_labTable->item(0, 0)->text() == "Dvwa",
      "lab navigation displays the actual loaded lab record");
  verify(configuration->m_llmModel->text() == "fixture-unsaved-model",
      "switching resource pages preserves unsaved model input");
  bool navigationReadOnly = true;
  for (auto it = server.requests.cbegin(); it != server.requests.cend(); ++it)
    navigationReadOnly = navigationReadOnly && it.key().startsWith("GET ");
  verify(navigationReadOnly, "resource navigation never saves configuration or starts a lab");
  if (!screenshots.isEmpty()) {
    QTest::qWait(40);
    verify(shell.grab().save(screenshots + "/labs-shell-" + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
        "lab navigation in the application shell saved for visual review");
  }
  clickResource("tools");
  if (!screenshots.isEmpty()) {
    shell.resize(1366, 768); QTest::qWait(80);
    verify(shell.grab().save(screenshots + "/tools-shell-" + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
        "full application resource view saved for visual review");
  }
  shell.openRibbonFeature("resources.runtime"); shell.resize(1024, 600); QTest::qWait(80);
  verify(shell.size() == QSize(1024, 600) && shell.m_deployPage->m_imageTable->isVisible()
      && shell.m_workspaceScroll->verticalScrollBar()->maximum() == 0,
      "runtime configuration fits the small application workspace with only the image table scrolling");
  auto *runtime = shell.m_deployPage;
  runtime->m_sandboxEnabled->setChecked(true);
  runtime->m_sandboxType->setCurrentIndex(runtime->m_sandboxType->findData("podman"));
  failSandbox = true; runtime->loadSandboxConfig();
  verify(awaitCondition([&]() { return runtime->m_sandboxStatusLabel->text().contains(QStringLiteral("读取失败")); })
      && !runtime->m_sandboxSaveBtn->isEnabled() && runtime->m_sandboxEnabled->isChecked()
      && runtime->m_sandboxType->currentData().toString() == "podman",
      "runtime read failure preserves inputs and disables saving in the compact card");
  QTest::qWait(40);
  verify(shell.m_workspaceScroll->verticalScrollBar()->maximum() == 0
      && runtime->m_sections["runtime"]->height() < 180 && runtime->m_imageTable->height() >= 150,
      "runtime error feedback does not expand the card or push the image inventory out of the workspace");
  if (!screenshots.isEmpty()) {
    verify(shell.grab().save(screenshots + "/runtime-error-small-" + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
        "small runtime error view saved for visual review");
    shell.resize(1366, 768); QTest::qWait(80);
    verify(shell.grab().save(screenshots + "/runtime-error-shell-" + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
        "full application runtime error view saved for visual review");
  }
  failSandbox = false; runtime->loadSandboxConfig();
  verify(awaitCondition([&]() { return runtime->m_sandboxLoaded && runtime->m_sandboxSaveBtn->isEnabled(); }),
      "runtime configuration can be refreshed after a read failure");
  if (!screenshots.isEmpty()) {
    QTest::qWait(80);
    verify(shell.grab().save(screenshots + "/runtime-shell-" + qEnvironmentVariable("QT_SCALE_FACTOR", "1") + ".png"),
        "full application runtime view saved for visual review");
  }
  qApp->setStyleSheet(originalStyle);
}
