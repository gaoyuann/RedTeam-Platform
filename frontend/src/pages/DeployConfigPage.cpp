#include "DeployConfigPage.h"
#include "../ApiClient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QScrollArea>
#include <QFrame>
#include "../Theme.h"
#include <QMenu>
#include <QApplication>
#include <QClipboard>

DeployConfigPage::DeployConfigPage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api) {
  setupUI();
  onRefresh();
}

void DeployConfigPage::setupUI() {
  setStyleSheet(Theme::PageStyle);

  auto *scrollArea = new QScrollArea(this);
  scrollArea->setWidgetResizable(true);
  scrollArea->setFrameShape(QFrame::NoFrame);
  auto *container = new QWidget;
  auto *layout = new QVBoxLayout(container);

  // ── 1. Platform Status ─────────────────────────────────────────────
  auto *platLabel = new QLabel("平台状态"); platLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(platLabel);

  auto *platH = new QHBoxLayout;
  m_checkBtn = new QPushButton("检测后端连接");
  m_engineLabel = new QLabel("未检测");
  m_engineLabel->setStyleSheet("font-size: 14px; font-weight: bold;");
  platH->addWidget(m_checkBtn);
  platH->addWidget(m_engineLabel);
  platH->addStretch();
  layout->addLayout(platH);
  connect(m_checkBtn, &QPushButton::clicked, this, &DeployConfigPage::onCheckBackend);

  auto *platInfoH = new QHBoxLayout;
  m_versionLabel = new QLabel("版本: -");
  m_dbSizeLabel = new QLabel("数据库: -");
  m_dbTablesLabel = new QLabel("表行数: -");
  platInfoH->addWidget(m_versionLabel);
  platInfoH->addWidget(m_dbSizeLabel);
  platInfoH->addWidget(m_dbTablesLabel);
  platInfoH->addStretch();
  layout->addLayout(platInfoH);

  // ── 2. LLM Config ─────────────────────────────────────────────────
  auto *llmLabel = new QLabel("大语言模型 (LLM) 配置"); llmLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(llmLabel);

  auto *llmH1 = new QHBoxLayout;
  llmH1->addWidget(new QLabel("API Key:"));
  m_llmApiKey = new QLineEdit;
  m_llmApiKey->setEchoMode(QLineEdit::Password);
  m_llmApiKey->setPlaceholderText("sk-...");
  llmH1->addWidget(m_llmApiKey, 1);
  layout->addLayout(llmH1);

  auto *llmH2 = new QHBoxLayout;
  llmH2->addWidget(new QLabel("Base URL:"));
  m_llmBaseUrl = new QLineEdit;
  m_llmBaseUrl->setPlaceholderText("https://api.deepseek.com/v1");
  llmH2->addWidget(m_llmBaseUrl, 1);
  llmH2->addWidget(new QLabel("模型:"));
  m_llmModel = new QLineEdit;
  m_llmModel->setPlaceholderText("deepseek-chat");
  m_llmModel->setMaximumWidth(200);
  llmH2->addWidget(m_llmModel);
  layout->addLayout(llmH2);

  auto *llmBtnH = new QHBoxLayout;
  m_llmSaveBtn = new QPushButton("保存 LLM 配置");
  m_llmSaveBtn->setProperty("primary", true);
  m_llmTestBtn = new QPushButton("测试连接");
  m_llmStatusLabel = new QLabel;
  llmBtnH->addWidget(m_llmSaveBtn);
  llmBtnH->addWidget(m_llmTestBtn);
  llmBtnH->addWidget(m_llmStatusLabel);
  llmBtnH->addStretch();
  layout->addLayout(llmBtnH);
  connect(m_llmSaveBtn, &QPushButton::clicked, this, &DeployConfigPage::onSaveLlmConfig);
  connect(m_llmTestBtn, &QPushButton::clicked, this, &DeployConfigPage::onTestLlmConnection);

  // ── 3. Sandbox Config ─────────────────────────────────────────────
  auto *sbLabel = new QLabel("沙箱运行环境配置"); sbLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(sbLabel);

  auto *sbH = new QHBoxLayout;
  m_sandboxEnabled = new QCheckBox("启用沙箱");
  sbH->addWidget(m_sandboxEnabled);
  sbH->addWidget(new QLabel("容器引擎:"));
  m_sandboxType = new QComboBox;
  m_sandboxType->addItem("自动", "auto");
  m_sandboxType->addItem("Podman", "podman");
  m_sandboxType->addItem("Docker", "docker");
  m_sandboxType->addItem("无", "none");
  sbH->addWidget(m_sandboxType);
  m_sandboxSaveBtn = new QPushButton("保存沙箱配置");
  m_sandboxSaveBtn->setProperty("primary", true);
  sbH->addWidget(m_sandboxSaveBtn);
  sbH->addStretch();
  layout->addLayout(sbH);
  connect(m_sandboxSaveBtn, &QPushButton::clicked, this, &DeployConfigPage::onSaveSandboxConfig);

  // ── 4. Container Images (existing) ────────────────────────────────
  auto *imgLabel = new QLabel("容器镜像状态"); imgLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(imgLabel);
  m_imageTable = new QTableWidget(0, 3);
  m_imageTable->setHorizontalHeaderLabels({"镜像", "标签", "大小"});
  m_imageTable->setAlternatingRowColors(true);
  m_imageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_imageTable->setSortingEnabled(true);
  m_imageTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_imageTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  m_imageTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  m_imageTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  layout->addWidget(m_imageTable, 1);

  // ── 5. Tool List (existing) ───────────────────────────────────────
  auto *toolLabel = new QLabel("工具列表"); toolLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(toolLabel);
  m_toolTable = new QTableWidget(0, 3);
  m_toolTable->setHorizontalHeaderLabels({"工具ID", "镜像", "类型"});
  m_toolTable->setAlternatingRowColors(true);
  m_toolTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_toolTable->setSortingEnabled(true);
  m_toolTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_toolTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_toolTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_toolTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  layout->addWidget(m_toolTable, 1);

  // ── 6. System Config (existing) ───────────────────────────────────
  auto *cfgLabel = new QLabel("系统配置"); cfgLabel->setStyleSheet(Theme::SectionStyle);
  layout->addWidget(cfgLabel);
  m_configTable = new QTableWidget(0, 3);
  m_configTable->setHorizontalHeaderLabels({"配置项", "值", "类别"});
  m_configTable->setAlternatingRowColors(true);
  m_configTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_configTable->setSortingEnabled(true);
  m_configTable->setContextMenuPolicy(Qt::CustomContextMenu);
  m_configTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  m_configTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  m_configTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  layout->addWidget(m_configTable);

  // ── Right-click menus ────────────────────────────────────────────────
  connect(m_imageTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_imageTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_imageTable->viewport()->mapToGlobal(pos));
  });
  connect(m_toolTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_toolTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_toolTable->viewport()->mapToGlobal(pos));
  });
  connect(m_configTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
    auto *item = m_configTable->itemAt(pos);
    if (!item) return;
    QMenu menu;
    menu.addAction("复制单元格内容", [item]() {
      QApplication::clipboard()->setText(item->text());
    });
    menu.exec(m_configTable->viewport()->mapToGlobal(pos));
  });

  // ── Refresh ───────────────────────────────────────────────────────
  m_refreshBtn = new QPushButton("刷新全部");
  layout->addWidget(m_refreshBtn);
  connect(m_refreshBtn, &QPushButton::clicked, this, &DeployConfigPage::onRefresh);

  scrollArea->setWidget(container);
  auto *outerLayout = new QVBoxLayout(this);
  outerLayout->addWidget(scrollArea);
}

// ── Slot: Refresh all ────────────────────────────────────────────────
void DeployConfigPage::onRefresh() {
  onCheckBackend();       // merged: also loads platform status
  loadLlmConfig();
  loadSandboxConfig();    // merged: also loads container status
  loadToolList();
  loadConfig();
}

// ── Slot: Check backend (merged with loadPlatformStatus) ─────────────
void DeployConfigPage::onCheckBackend() {
  m_api->get("/api/health", 3000, [this](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      m_engineLabel->setText("已连接");
      m_engineLabel->setStyleSheet(Theme::StatusSuccessStyle);

      // Also update platform status (was separate loadPlatformStatus)
      QString ts = res["timestamp"].toString();
      double uptime = res["uptime"].toDouble();
      QString uptimeStr = uptime > 3600 ? QString("%1h").arg(int(uptime / 3600))
                       : uptime > 60   ? QString("%1m").arg(int(uptime / 60))
                       :                  QString("%1s").arg(int(uptime));
      m_versionLabel->setText(QString("启动时间: %1 | 运行: %2").arg(ts.left(19), uptimeStr));
    } else {
      m_engineLabel->setText("未连接");
      m_engineLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });

  // DB stats (separate endpoint, keep as-is)
  m_api->get("/api/db/stats", 3000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    qint64 size = d["dbSizeBytes"].toVariant().toLongLong();
    QString sizeStr = size > 1048576 ? QString("%1 MB").arg(size / 1048576.0, 0, 'f', 1)
                   : size > 1024   ? QString("%1 KB").arg(size / 1024.0, 0, 'f', 0)
                   :                  QString("%1 B").arg(size);
    m_dbSizeLabel->setText("数据库: " + sizeStr);

    auto tables = d["tableRowCounts"].toObject();
    QStringList parts;
    for (auto it = tables.begin(); it != tables.end(); ++it) {
      parts << QString("%1:%2").arg(it.key(), QString::number(it.value().toInt()));
    }
    m_dbTablesLabel->setText("表行数: " + parts.join("  "));
    m_dbTablesLabel->setWordWrap(true);
  });
}

// ── Load LLM config ──────────────────────────────────────────────────
void DeployConfigPage::loadLlmConfig() {
  m_api->get("/api/config/llm", 3000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    // Look for the 'default' entry or first entry
    QJsonObject defaultEntry;
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      if (c["config_key"].toString() == "default") {
        tryParseLlmValue(c["config_value"].toString(), defaultEntry);
        break;
      }
    }
    // If no 'default', try first entry
    if (defaultEntry.isEmpty() && arr.size() > 0) {
      tryParseLlmValue(arr[0].toObject()["config_value"].toString(), defaultEntry);
    }
    if (!defaultEntry.isEmpty()) {
      m_llmApiKey->setText(defaultEntry["key"].toString());
      m_llmBaseUrl->setText(defaultEntry["url"].toString());
      m_llmModel->setText(defaultEntry["model"].toString());
    }
  });
}

// ── Save LLM config ──────────────────────────────────────────────────
void DeployConfigPage::onSaveLlmConfig() {
  QJsonObject entry;
  entry["key"] = m_llmApiKey->text();
  entry["url"] = m_llmBaseUrl->text();
  entry["model"] = m_llmModel->text();

  QJsonObject body;
  body["config_value"] = entry;
  body["description"] = "LLM model: default";

  m_llmSaveBtn->setEnabled(false);
  m_api->put("/api/config/llm/default", body, 5000, [this](const QJsonObject &res) {
    m_llmSaveBtn->setEnabled(true);
    if (res["status"].toString() == "ok") {
      m_llmStatusLabel->setText("已保存");
      m_llmStatusLabel->setStyleSheet(Theme::StatusSuccessStyle);
    } else {
      m_llmStatusLabel->setText("保存失败");
      m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
    }
  });
}

// ── Test LLM connection ──────────────────────────────────────────────
void DeployConfigPage::onTestLlmConnection() {
  // Save first, then test in the save callback (fixes async race)
  QJsonObject entry;
  entry["key"] = m_llmApiKey->text();
  entry["url"] = m_llmBaseUrl->text();
  entry["model"] = m_llmModel->text();

  QJsonObject body;
  body["config_value"] = entry;
  body["description"] = "LLM model: default";

  m_llmSaveBtn->setEnabled(false);
  m_llmTestBtn->setEnabled(false);
  m_llmStatusLabel->setText("保存并测试中...");
  m_llmStatusLabel->setStyleSheet(Theme::StatusInfoStyle);

  m_api->put("/api/config/llm/default", body, 5000, [this](const QJsonObject &saveRes) {
    m_llmSaveBtn->setEnabled(true);
    if (saveRes["status"].toString() != "ok") {
      m_llmTestBtn->setEnabled(true);
      m_llmStatusLabel->setText("保存失败");
      m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
      return;
    }
    // Save succeeded, now test by reading back
    m_api->get("/api/config/llm/default", 3000, [this](const QJsonObject &res) {
      m_llmTestBtn->setEnabled(true);
      if (res["status"].toString() == "ok") {
        auto val = res["data"].toObject()["config_value"].toString();
        if (!val.isEmpty() && val != "null") {
          m_llmStatusLabel->setText("配置已就绪");
          m_llmStatusLabel->setStyleSheet(Theme::StatusSuccessStyle);
        } else {
          m_llmStatusLabel->setText("配置为空");
          m_llmStatusLabel->setStyleSheet(Theme::StatusWarningStyle);
        }
      } else {
        m_llmStatusLabel->setText("读取失败");
        m_llmStatusLabel->setStyleSheet(Theme::StatusErrorStyle);
      }
    });
  });
}

// ── Load sandbox config (merged with loadContainerStatus) ────────────
void DeployConfigPage::loadSandboxConfig() {
  m_api->get("/api/config/sandbox", 3000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") {
      // No sandbox config yet — defaults
      m_sandboxEnabled->setChecked(true);
      m_sandboxType->setCurrentIndex(0);
      return;
    }
    auto arr = res["data"].toArray();
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      QString key = c["config_key"].toString();
      if (key == "enabled") {
        m_sandboxEnabled->setChecked(c["config_value"].toString() == "true");
      } else if (key == "engine") {
        QString val = c["config_value"].toString();
        int idx = m_sandboxType->findData(val);
        if (idx >= 0) m_sandboxType->setCurrentIndex(idx);
      }
    }
  });

  // Container status — also populates image table (was separate loadContainerStatus)
  m_api->get("/api/tools/containers/status", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto d = res["data"].toObject();
    QString engine = d["engine"].toString();
    QString ver = d["engineVersion"].toString();
    int loaded = d["loadedCount"].toInt(), total = d["expectedCount"].toInt();
    m_engineLabel->setText(
        QString("引擎: %1 %2 | 镜像: %3/%4").arg(engine, ver).arg(loaded).arg(total));

    // Also populate image table (was loadContainerStatus)
    auto imgs = d["images"].toArray();
    // Also get image sizes from the backend if available
    auto imgSizes = d["imageSizes"].toObject();
    m_imageTable->setRowCount(imgs.size());
    for (int i = 0; i < imgs.size(); i++) {
      QString img = imgs[i].toString();
      auto parts = img.split(':');
      QString repo = parts.value(0);
      QString tag = parts.value(1, "latest");
      m_imageTable->setItem(i, 0, new QTableWidgetItem(repo));
      m_imageTable->setItem(i, 1, new QTableWidgetItem(tag));
      // Try to get size from imageSizes object, fallback to empty
      QString sizeStr = imgSizes[img].toString();
      if (sizeStr.isEmpty()) sizeStr = imgSizes[repo].toString();
      m_imageTable->setItem(i, 2, new QTableWidgetItem(sizeStr.isEmpty() ? "-" : sizeStr));
    }
  });
}

// ── Save sandbox config ──────────────────────────────────────────────
void DeployConfigPage::onSaveSandboxConfig() {
  QJsonObject bodyEnabled;
  bodyEnabled["config_value"] = m_sandboxEnabled->isChecked();
  bodyEnabled["description"] = "Sandbox enabled toggle";

  QJsonObject bodyEngine;
  bodyEngine["config_value"] = m_sandboxType->currentData().toString();
  bodyEngine["description"] = "Sandbox container engine";

  m_sandboxSaveBtn->setEnabled(false);
  m_api->put("/api/config/sandbox/enabled", bodyEnabled, 3000, [this, bodyEngine](const QJsonObject &) {
    m_api->put("/api/config/sandbox/engine", bodyEngine, 3000, [this](const QJsonObject &) {
      m_sandboxSaveBtn->setEnabled(true);
    });
  });
}

// ── Load tool list (existing) ────────────────────────────────────────
void DeployConfigPage::loadToolList() {
  m_api->get("/api/tools/list", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_toolTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto t = arr[i].toObject();
      m_toolTable->setItem(i, 0, new QTableWidgetItem(t["toolId"].toString()));
      QString img;
      if (t["virtual"].toBool()) {
        img = QStringLiteral("—（虚拟）");
      } else if (t["image"].isNull() || t["image"].toString().isEmpty()) {
        img = QStringLiteral("未配置");
      } else {
        img = t["image"].toString();
      }
      m_toolTable->setItem(i, 1, new QTableWidgetItem(img));
      m_toolTable->setItem(i, 2, new QTableWidgetItem(t["virtual"].toBool() ? QStringLiteral("虚拟") : QStringLiteral("容器")));
    }
  });
}

// ── Load system config (existing) ────────────────────────────────────
void DeployConfigPage::loadConfig() {
  m_api->get("/api/config", 5000, [this](const QJsonObject &res) {
    if (res["status"].toString() != "ok") return;
    auto arr = res["data"].toArray();
    m_configTable->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
      auto c = arr[i].toObject();
      m_configTable->setItem(i, 0, new QTableWidgetItem(c["config_key"].toString()));
      m_configTable->setItem(i, 1, new QTableWidgetItem(c["config_value"].toString()));
      m_configTable->setItem(i, 2, new QTableWidgetItem(c["category"].toString()));
    }
  });
}

// ── Helper: parse LLM config_value JSON ──────────────────────────────
void DeployConfigPage::tryParseLlmValue(const QString &jsonStr, QJsonObject &out) {
  QJsonParseError err;
  auto doc = QJsonDocument::fromJson(jsonStr.toUtf8(), &err);
  if (err.error == QJsonParseError::NoError && doc.isObject()) {
    out = doc.object();
  }
}
