#pragma once
#include <QWidget>
#include <QLabel>
#include <QTableWidget>
#include <QMessageBox>
#include <functional>

class ApiClient;

// ── Base class for all page widgets ───────────────────────────────────
// Provides common utilities: section headers, table factories,
// API call wrappers with auto status-check, and delete confirmation.

class BasePage : public QWidget {
  Q_OBJECT
public:
  explicit BasePage(ApiClient *api, const QString &role = "",
                    const QString &username = "", QWidget *parent = nullptr);

protected:
  // ── UI helpers ─────────────────────────────────────────────────────
  // Create a section header label with the global SectionStyle
  QLabel* createSectionHeader(const QString &title);

  // Create a read-only table with standard config
  QTableWidget* createReadOnlyTable(int cols, const QStringList &headers,
                                    bool alternating = true);

  // ── API wrappers ───────────────────────────────────────────────────
  // Auto-checks status=="ok"; calls onSuccess only on success.
  // onError is called on failure (optional — default does nothing).

  void apiGet(const QString &path, int timeout,
              std::function<void(const QJsonObject &)> onSuccess,
              std::function<void()> onError = nullptr);

  void apiPost(const QString &path, const QJsonObject &body, int timeout,
               std::function<void(const QJsonObject &)> onSuccess,
               std::function<void()> onError = nullptr);

  void apiPut(const QString &path, const QJsonObject &body, int timeout,
               std::function<void(const QJsonObject &)> onSuccess,
               std::function<void()> onError = nullptr);

  void apiDel(const QString &path, int timeout,
              std::function<void(const QJsonObject &)> onSuccess,
              std::function<void()> onError = nullptr);

  // ── Dialog helpers ─────────────────────────────────────────────────
  // Show a "confirm delete?" dialog; returns true if user confirms
  bool confirmDelete(const QString &itemName);

  // ── Refresh on page show ───────────────────────────────────────────
  // Override in subclasses to refresh data when page becomes visible
  virtual void refresh() {}

  ApiClient *m_api;
  QString m_role;
  QString m_username;
};
