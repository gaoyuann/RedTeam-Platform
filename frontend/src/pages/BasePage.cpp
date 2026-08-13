#include "BasePage.h"
#include "../ApiClient.h"
#include "../Theme.h"
#include <QHeaderView>

BasePage::BasePage(ApiClient *api, const QString &role, const QString &username, QWidget *parent)
    : QWidget(parent), m_api(api), m_role(role), m_username(username) {}

// ── UI helpers ────────────────────────────────────────────────────────
QLabel* BasePage::createSectionHeader(const QString &title) {
  auto *label = new QLabel(title);
  label->setStyleSheet(Theme::SectionStyle);
  return label;
}

QTableWidget* BasePage::createReadOnlyTable(int cols, const QStringList &headers,
                                             bool alternating) {
  auto *table = new QTableWidget(0, cols);
  table->setHorizontalHeaderLabels(headers);
  if (alternating) table->setAlternatingRowColors(true);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  return table;
}

// ── API wrappers ──────────────────────────────────────────────────────
void BasePage::apiGet(const QString &path, int timeout,
                       std::function<void(const QJsonObject &)> onSuccess,
                       std::function<void()> onError) {
  m_api->get(path, timeout, [onSuccess, onError](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      if (onSuccess) onSuccess(res);
    } else {
      if (onError) onError();
    }
  });
}

void BasePage::apiPost(const QString &path, const QJsonObject &body, int timeout,
                        std::function<void(const QJsonObject &)> onSuccess,
                        std::function<void()> onError) {
  m_api->post(path, body, timeout, [onSuccess, onError](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      if (onSuccess) onSuccess(res);
    } else {
      if (onError) onError();
    }
  });
}

void BasePage::apiPut(const QString &path, const QJsonObject &body, int timeout,
                        std::function<void(const QJsonObject &)> onSuccess,
                        std::function<void()> onError) {
  m_api->put(path, body, timeout, [onSuccess, onError](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      if (onSuccess) onSuccess(res);
    } else {
      if (onError) onError();
    }
  });
}

void BasePage::apiDel(const QString &path, int timeout,
                       std::function<void(const QJsonObject &)> onSuccess,
                       std::function<void()> onError) {
  m_api->del(path, timeout, [onSuccess, onError](const QJsonObject &res) {
    if (res["status"].toString() == "ok") {
      if (onSuccess) onSuccess(res);
    } else {
      if (onError) onError();
    }
  });
}

// ── Dialog helpers ────────────────────────────────────────────────────
bool BasePage::confirmDelete(const QString &itemName) {
  auto reply = QMessageBox::question(this, "确认删除",
    QString("确定要删除 \"%1\" 吗？此操作不可撤销。").arg(itemName),
    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
  return reply == QMessageBox::Yes;
}
