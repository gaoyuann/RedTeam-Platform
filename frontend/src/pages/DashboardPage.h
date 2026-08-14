#pragma once

#include <QWidget>
#include <QJsonObject>

class ApiClient;
class LiveActivityPanel;
class QLabel;

// ── Dashboard Page (总览大屏) ──────────────────────────────────────────
// Admin-only overview dashboard showing:
// - Top: summary stat cards (scan counts, run counts)
// - Center: full-size LiveActivityPanel
// - Bottom: recent scan results summary

class DashboardPage : public QWidget {
  Q_OBJECT
public:
  explicit DashboardPage(ApiClient *api, const QString &role = "admin",
                          const QString &username = "",
                          QWidget *parent = nullptr);

  /// Get the activity panel (for wiring WebSocket signals)
  LiveActivityPanel *activityPanel() const;

public slots:
  void refreshStats();

private:
  void setupUI();

  ApiClient *m_api;
  QString m_role;
  LiveActivityPanel *m_activityPanel;

  // Stat cards
  QLabel *m_scanTotalLabel;
  QLabel *m_scanRunningLabel;
  QLabel *m_scanCompletedLabel;
  QLabel *m_runTotalLabel;
  QLabel *m_runRunningLabel;
  QLabel *m_runCompletedLabel;
};
