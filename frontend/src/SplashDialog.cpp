#include "SplashDialog.h"
#include <QVBoxLayout>
#include <QPainter>
#include <QPixmap>
#include <QPainterPath>
#include <QScreen>
#include <QGuiApplication>

SplashDialog::SplashDialog(QWidget *parent) : QWidget(parent) {
  setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
  setAttribute(Qt::WA_TranslucentBackground);

  // Size: ~3/4 screen (76% width, 76% height)
  auto *screen = QGuiApplication::primaryScreen();
  int w = screen ? screen->geometry().width() * 76 / 100 : 1460;
  int h = screen ? screen->geometry().height() * 76 / 100 : 820;
  setFixedSize(w, h);

  // Load and cache the background image (scaled to fill the entire widget)
  m_bgPixmap = QPixmap(":/images/logo.png");
  if (!m_bgPixmap.isNull()) {
    m_bgPixmap = m_bgPixmap.scaled(w, h, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  }

  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(48, 48, 48, 48);
  layout->setSpacing(4);

  // Push all content to the bottom
  layout->addStretch(1);

  // ── Title — big, bold, white ────────────────────────────────────────
  auto *titleLabel = new QLabel(QStringLiteral("信息系统渗透智能化测试平台"));
  titleLabel->setAlignment(Qt::AlignCenter);
  titleLabel->setStyleSheet(
    "color: rgba(255,255,255,235); font-size: 42px; font-weight: bold; letter-spacing: 6px;");
  layout->addWidget(titleLabel);

  // ── Version ─────────────────────────────────────────────────────────
  auto *versionLabel = new QLabel(QStringLiteral("版本 2.0.1"));
  versionLabel->setAlignment(Qt::AlignCenter);
  versionLabel->setStyleSheet("color: rgba(200,220,245,190); font-size: 16px;");
  layout->addWidget(versionLabel);

  layout->addSpacing(14);

  // ── Status ──────────────────────────────────────────────────────────
  m_statusLabel = new QLabel(QStringLiteral("正在初始化..."));
  m_statusLabel->setAlignment(Qt::AlignCenter);
  m_statusLabel->setStyleSheet("color: rgba(170,200,230,200); font-size: 15px;");
  layout->addWidget(m_statusLabel);

  // ── Progress bar ────────────────────────────────────────────────────
  m_progress = new QProgressBar;
  m_progress->setRange(0, 100);
  m_progress->setValue(0);
  m_progress->setTextVisible(false);
  m_progress->setFixedHeight(8);
  m_progress->setStyleSheet(
    "QProgressBar { background: rgba(255,255,255,40); border: none; border-radius: 4px; }"
    "QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #2a7dd6,stop:1 #5bb8ff); border-radius: 4px; }");
  layout->addWidget(m_progress);

  layout->addSpacing(20);

  // ── Attribution lines (matching pentagi-v3) ─────────────────────────
  auto *line1 = new QLabel(QStringLiteral("西南交通大学研制"));
  line1->setAlignment(Qt::AlignCenter);
  line1->setStyleSheet("color: rgba(200,216,239,180); font-size: 16px;");
  layout->addWidget(line1);

  auto *line2 = new QLabel(QStringLiteral("国防科技大学监制"));
  line2->setAlignment(Qt::AlignCenter);
  line2->setStyleSheet("color: rgba(200,216,239,180); font-size: 16px;");
  layout->addWidget(line2);

  layout->addSpacing(8);

  // Center on screen
  if (screen) {
    auto geo = screen->geometry();
    move(geo.x() + (geo.width() - w) / 2, geo.y() + (geo.height() - h) / 2);
  }
}

void SplashDialog::updateProgress(int value, const QString &message) {
  m_progress->setValue(value);
  m_statusLabel->setText(message);
}

void SplashDialog::paintEvent(QPaintEvent *) {
  QPainter p(this);
  p.setRenderHint(QPainter::Antialiasing);
  p.setRenderHint(QPainter::SmoothPixmapTransform);

  // Clip to rounded rect for frameless window corners
  QPainterPath clipPath;
  clipPath.addRoundedRect(rect(), 20, 20);
  p.setClipPath(clipPath);

  // 1. Draw background image filling the entire widget
  if (!m_bgPixmap.isNull()) {
    int xoff = (m_bgPixmap.width() - width()) / 2;
    int yoff = (m_bgPixmap.height() - height()) / 2;
    p.drawPixmap(0, 0, m_bgPixmap, xoff, yoff, width(), height());
  } else {
    QLinearGradient bgGrad(rect().topLeft(), rect().bottomLeft());
    bgGrad.setColorAt(0, QColor("#0c1a30"));
    bgGrad.setColorAt(1, QColor("#0a1225"));
    p.setBrush(bgGrad);
    p.setPen(Qt::NoPen);
    p.drawRect(rect());
  }

  // 2. Bottom gradient overlay — wider gradient for bigger title area
  //    Covers ~55% of height from bottom, ensuring all text is readable
  QLinearGradient overlay(QPointF(0, height()), QPointF(0, height() * 0.40));
  overlay.setColorAt(0.0, QColor(8, 16, 32, 235));   // bottom: near-opaque dark
  overlay.setColorAt(0.25, QColor(8, 16, 32, 210));   // strong dark
  overlay.setColorAt(0.50, QColor(8, 16, 32, 160));   // mid: semi-dark
  overlay.setColorAt(0.75, QColor(8, 16, 32, 70));    // fading
  overlay.setColorAt(1.0, QColor(8, 16, 32, 0));      // top: fully transparent
  p.setBrush(overlay);
  p.setPen(Qt::NoPen);
  p.drawRect(rect());
}
