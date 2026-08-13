#pragma once
#include <QWidget>
#include <QProgressBar>
#include <QLabel>
#include <QPixmap>

class SplashDialog : public QWidget {
  Q_OBJECT
public:
  explicit SplashDialog(QWidget *parent = nullptr);

  void updateProgress(int value, const QString &message);

protected:
  void paintEvent(QPaintEvent *event) override;

private:
  QProgressBar *m_progress;
  QLabel *m_statusLabel;
  QPixmap m_bgPixmap;
};
