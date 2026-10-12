#pragma once
#include "Theme.h"

namespace Theme {
inline const QString GlobalStyle = QString(R"css(
QWidget { color: #172033; }
QWidget#contentArea { background: #f5f7fa; }

QPushButton#checkBtn {
  background: #ffffff; color: #475569; border: 1px solid #d1e1f5;
  border-radius: 7px; padding: 4px 12px; font-weight: 500; min-height: 22px;
}
QPushButton#checkBtn:hover { background: #f0f6ff; color: #1d4ed8; border-color: #adc5ef; }

QLabel#appBrand { color:#12213c; font-size:18px; font-weight:700; }
QLabel#appSubtitle { color:#36527a; font-size:11px; }
QFrame#appTopBar { background: #ffffff; border-bottom: 1px solid #e1eaf5; }
QLineEdit#globalSearch { background: #fbfdff; border: 1px solid #d1e1f5; border-radius: 8px; padding: 7px 12px; min-height: 24px; color: #1e3a63; }
QLineEdit#globalSearch:focus { border-color: #60a5fa; background: #ffffff; }

QLineEdit, QComboBox, QSpinBox {
  border: 1px solid #cbd5e1; border-radius: 8px; padding: 6px 10px;
  font-size: 13px; background: #ffffff; min-height: 22px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #3b82f6; background: #fefeff; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { selection-background-color: #2563eb; selection-color: #ffffff; border: 1px solid #cbd5e1; }

QTableWidget, QTreeWidget {
  border: 1px solid #dbe3ef; border-radius: 10px; gridline-color: #edf2f7;
  font-size: 14px; background: #ffffff; alternate-background-color: #f8fbff;
}
QTableWidget::item, QTreeWidget::item { padding: 7px 8px; }
QHeaderView::section {
  background: #eef4fb; color: #334155; font-size: 13px; font-weight: 700;
  padding: 9px 8px; border: none; border-bottom: 1px solid #dbe3ef;
}
QTableWidget::item:selected, QTreeWidget::item:selected { background: #dbeafe; color: #1e3a8a; }

QTabWidget::pane { border: 1px solid #dbe3ef; border-radius: 10px; background: #ffffff; padding: 8px; }
QTabBar::tab {
  background: transparent; color: #64748b; padding: 7px 13px; font-size: 14px;
  font-weight: 600; border-bottom: 2px solid transparent; margin-right: 4px;
}
QTabBar::tab:selected { color: #1d4ed8; border-bottom-color: #2563eb; }
QTabBar::tab:hover:!selected { color: #334155; background: #f1f5f9; border-radius: 6px; }

QTextEdit, QPlainTextEdit {
  border: 1px solid #cbd5e1; border-radius: 8px; font-size: 13px;
  background: #fbfdff; padding: 8px;
}
QCheckBox, QRadioButton { font-size: 14px; spacing: 8px; }
QProgressBar { background: #e2e8f0; border: none; border-radius: 5px; text-align: center; color: #334155; min-height: 10px; }
QProgressBar::chunk { background: #2563eb; border-radius: 5px; }

QScrollBar:vertical { background: transparent; width: 10px; border: none; }
QScrollBar::handle:vertical { background: #cbd5e1; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #94a3b8; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar:horizontal { background: transparent; height: 10px; border: none; }
QScrollBar::handle:horizontal { background: #cbd5e1; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #94a3b8; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }

QStatusBar { background: #ffffff; color: #64748b; font-size: 13px; padding: 3px 10px; border-top: 1px solid #dbe3ef; }
QLabel#statusSuccess { color: #166534; }
QLabel#statusError   { color: #b42318; }
QLabel#statusWarning { color: #b45309; }
QLabel#statusInfo    { color: #1d4ed8; }

QFrame#sidebar { background: #ffffff; border: none; border-right: 1px solid #e1eaf5; }
QLabel#sidebarBrand { color: #12213c; font-size: 15px; font-weight: 800; }
QLabel#sidebarSubtitle { color: #7c91ad; font-size: 9px; }
QFrame#sidebarDivider { color: #e5edf7; background: #e5edf7; max-height: 1px; }
QLabel#sidebarFooter { color: #94a3b8; font-size: 11px; padding: 4px 2px; }
QListWidget#navList {
  background: transparent; color: #36527a; border: none;
  font-size: 14px; font-weight: 600; outline: none; padding: 2px 0;
}
QListWidget#navList::item { padding: 8px 10px; border-radius: 8px; margin: 2px 0; }
QListWidget#navList::item:selected { background: #2563eb; color: #ffffff; }
QListWidget#navList::item:hover:!selected { background: #f0f6ff; color: #1d4ed8; }

QMenu {
  background: #ffffff; border: 1px solid #dbe3ef; border-radius: 8px; padding: 5px 3px;
}
QMenu::item { padding: 7px 22px; border-radius: 6px; font-size: 13px; }
QMenu::item:selected { background: #dbeafe; color: #1e3a8a; }
QMenu::separator { height: 1px; background: #e2e8f0; margin: 4px 8px; }

/* 指示器尺寸只由 16x16 图片驱动 —— 不要再写 width/height：
   Qt 5.15 下 QSS 硬设的指示器尺寸不计入 sizeHint，会导致
   QCheckBox 文字被裁（权限管理页 读/写 重叠就是这么来的） */
QCheckBox::indicator:unchecked { image: url(:/icons/checkbox_off.png); }
QCheckBox::indicator:checked { image: url(:/icons/checkbox_on.png); }
QCheckBox::indicator:checked:disabled { image: url(:/icons/checkbox_on_disabled.png); }
QCheckBox::indicator:unchecked:disabled { image: url(:/icons/checkbox_off_disabled.png); }
QRadioButton::indicator:unchecked { image: url(:/icons/radio_off.png); }
QRadioButton::indicator:checked { image: url(:/icons/radio_on.png); }

QToolTip {
  background: #10243e; color: #e2e8f0; border: 1px solid #1d3655;
  border-radius: 6px; padding: 5px 9px; font-size: 12px;
}

QTableWidget QHeaderView::section:vertical {
  background: #fbfdff; color: #94a3b8; font-weight: 600;
  border: none; border-right: 1px solid #edf2f7; padding: 6px 4px;
}
QTableCornerButton::section { background: #eef4fb; border: none; }

QListWidget {
  background: #ffffff; border: 1px solid #dbe3ef; border-radius: 10px;
  font-size: 13px; outline: none; padding: 4px;
}
QListWidget::item { padding: 8px 10px; border-radius: 6px; }
QListWidget::item:selected { background: #dbeafe; color: #1e3a8a; }
QListWidget::item:hover:!selected { background: #f1f5f9; }
 )css").replace("#f5f7fa", Background)
    .replace("#172033", Text)
    .replace("#64748b", TextSecondary)
    .replace("#ffffff", Card)
    .replace("#2563eb", Primary)
    .replace("#dbe3ef", Border)
    .replace("#dbeafe", Selected);

}
