#pragma once

#include <QWidget>
#include <QJsonObject>
#include <QListWidget>
#include <QLabel>
#include <QPushButton>

// ── Live Activity Panel ────────────────────────────────────────────────
// Displays a real-time stream of WebSocket events (scan/run activity).
// Used as a bottom panel in SimpleMainWindow and as the main content in DashboardPage.

class LiveActivityPanel : public QWidget {
  Q_OBJECT
public:
  explicit LiveActivityPanel(const QString &role = "admin",
                              const QString &username = "",
                              QWidget *parent = nullptr);

  /// Set whether the panel is in "compact" mode (bottom bar) vs "full" mode (dashboard)
  void setCompact(bool compact);

public slots:
  void onScanCreated(const QJsonObject &data);
  void onScanStarted(const QJsonObject &data);
  void onScanCompleted(const QJsonObject &data);
  void onRunCreated(const QJsonObject &data);
  void onRunStarted(const QJsonObject &data);
  void onRunStepComplete(const QJsonObject &data);
  void onRunCompleted(const QJsonObject &data);
  void onToggleCollapse();

private:
  void addEvent(const QString &icon, const QString &text, const QString &color);
  QString formatUser(const QJsonObject &data) const;
  QString nowTime() const;

  QString m_role;
  QString m_username;
  bool m_compact = true;
  bool m_collapsed = false;

  // Header
  QLabel *m_titleLabel;
  QPushButton *m_collapseBtn;
  QLabel *m_countLabel;

  // Event list
  QListWidget *m_eventList;

  static constexpr int MAX_EVENTS = 50;
};
