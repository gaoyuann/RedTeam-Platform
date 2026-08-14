#pragma once

#include <QWidget>
#include <QJsonObject>

class ApiClient;
class LiveActivityPanel;
class QLabel;
class QTableWidget;

// ── Dashboard Page (总览大屏) ──────────────────────────────────────────
// Admin-only overview dashboard — white-background, matches other pages.
// Layout:
//   1. Stat cards row (4 cards: scan total / running / completed / run total)
//   2. Recent activity table (last 20 scan + run records)
//   3. Real-time event stream (LiveActivityPanel)

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

  // Stat card value labels
  QLabel *m_scanTotalLabel;
  QLabel *m_scanRunningLabel;
  QLabel *m_scanCompletedLabel;
  QLabel *m_runTotalLabel;

  // Recent activity table
  QTableWidget *m_activityTable;
};
