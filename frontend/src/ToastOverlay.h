#pragma once

#include <QWidget>
#include <QJsonObject>

class QVBoxLayout;

// ── Toast Overlay ──────────────────────────────────────────────────────
// Floating notification cards in the top-right corner.
// Cards auto-dismiss after 3 seconds with a fade-out animation.
// Only shown for admin role (student doesn't need self-notifications).

class ToastOverlay : public QWidget {
  Q_OBJECT
public:
  explicit ToastOverlay(QWidget *parent = nullptr);

  /// Show a toast notification
  void showToast(const QString &icon, const QString &title,
                  const QString &message, const QString &color = "#63b3ed");

  /// Reposition to top-right corner of parent widget
  void reposition();

public slots:
  void onScanCompleted(const QJsonObject &data);
  void onRunStepComplete(const QJsonObject &data);
  void onRunCompleted(const QJsonObject &data);

private:
  QVBoxLayout *m_layout;
  int m_activeCount = 0;

  static constexpr int MAX_TOASTS = 3;
  static constexpr int TOAST_DURATION_MS = 3000;
};
