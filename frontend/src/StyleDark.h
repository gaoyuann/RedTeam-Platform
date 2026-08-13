// ── Dark mode stylesheet ──────────────────────────────────────────────
// Inverted palette: dark backgrounds, light text, adjusted accents

static const char *GLOBAL_STYLE_DARK = R"css(
/* ── QPushButton ──────────────────────────────────────────────── */
QPushButton {
  background: #3a8fd6; color: #1a2a3a; border: none; border-radius: 5px;
  padding: 8px 20px; font-size: 14px; font-weight: bold; min-height: 32px;
}
QPushButton:hover { background: #4da3e8; }
QPushButton:pressed { background: #2a7dd6; }
QPushButton:disabled { background: #4a5568; color: #718096; }
QPushButton#secondaryBtn { background: #2d3748; color: #e2e8f0; font-weight: normal; }
QPushButton#secondaryBtn:hover { background: #4a5568; }
QPushButton#dangerBtn { background: #e53e3e; color: #ffffff; }
QPushButton#dangerBtn:hover { background: #c53030; }
QPushButton#checkBtn {
  background: transparent; color: #a0aec0; border: 1px solid #4a5568;
  border-radius: 4px; padding: 4px 14px; font-weight: normal; min-height: 24px;
}
QPushButton#checkBtn:hover { background: #2d3748; color: #ffffff; }

/* ── QLineEdit ────────────────────────────────────────────────── */
QLineEdit {
  border: 1px solid #4a5568; border-radius: 5px; padding: 6px 10px;
  font-size: 14px; background: #2d3748; color: #e2e8f0; min-height: 28px;
}
QLineEdit:focus { border-color: #3a8fd6; }

/* ── QComboBox ────────────────────────────────────────────────── */
QComboBox {
  border: 1px solid #4a5568; border-radius: 5px; padding: 6px 10px;
  font-size: 14px; background: #2d3748; color: #e2e8f0; min-height: 28px;
}
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
  selection-background-color: #3a8fd6; selection-color: #1a2a3a;
  border: 1px solid #4a5568; background: #2d3748; color: #e2e8f0;
}

/* ── QTableWidget ─────────────────────────────────────────────── */
QTableWidget {
  border: 1px solid #4a5568; border-radius: 4px; gridline-color: #4a5568;
  font-size: 14px; background: #1a202c; alternate-background-color: #2d3748; color: #e2e8f0;
}
QTableWidget::item { padding: 6px; }
QHeaderView::section {
  background: #0d1520; color: #e2e8f0; font-size: 14px; font-weight: bold;
  padding: 8px 6px; border: none;
}
QTableWidget::item:selected { background: #3a8fd6; color: #1a2a3a; }

/* ── QTabWidget ───────────────────────────────────────────────── */
QTabWidget::pane {
  border: 1px solid #4a5568; border-radius: 4px; background: #1a202c;
  padding: 8px;
}
QTabBar::tab {
  background: #2d3748; color: #a0aec0; padding: 10px 24px; font-size: 14px;
  font-weight: bold; border-top-left-radius: 5px; border-top-right-radius: 5px;
  margin-right: 2px;
}
QTabBar::tab:selected { background: #3a8fd6; color: #1a2a3a; }
QTabBar::tab:hover:!selected { background: #4a5568; }

/* ── QTreeWidget ──────────────────────────────────────────────── */
QTreeWidget {
  border: 1px solid #4a5568; border-radius: 4px; font-size: 14px;
  background: #1a202c; alternate-background-color: #2d3748; color: #e2e8f0;
}
QTreeWidget::item { padding: 4px; }

/* ── QTextEdit ────────────────────────────────────────────────── */
QTextEdit {
  border: 1px solid #4a5568; border-radius: 4px; font-size: 13px;
  background: #2d3748; color: #e2e8f0; padding: 8px;
}

/* ── QCheckBox ────────────────────────────────────────────────── */
QCheckBox { font-size: 14px; spacing: 8px; color: #e2e8f0; }

/* ── QProgressBar ─────────────────────────────────────────────── */
QProgressBar {
  background: #2d3748; border: none; border-radius: 4px;
  text-align: center; color: #e2e8f0; min-height: 10px;
}
QProgressBar::chunk { background: #3a8fd6; border-radius: 4px; }

/* ── QScrollBar ───────────────────────────────────────────────── */
QScrollBar:vertical { background: #1a202c; width: 10px; border: none; }
QScrollBar::handle:vertical { background: #4a5568; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #718096; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar:horizontal { background: #1a202c; height: 10px; border: none; }
QScrollBar::handle:horizontal { background: #4a5568; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #718096; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }

/* ── QStatusBar ───────────────────────────────────────────────── */
QStatusBar { background: #0d1520; color: #a0aec0; font-size: 13px; }

/* ── Content area ─────────────────────────────────────────────── */
QWidget#contentArea { background: #1a202c; }

/* ── Navigation list ──────────────────────────────────────────── */
QListWidget#navList {
  background: #0d1520; color: #a0aec0; border: none;
  font-size: 15px; font-weight: bold; outline: none; padding: 8px;
}
QListWidget#navList::item { padding: 14px 16px; border-radius: 6px; margin: 2px 4px; }
QListWidget#navList::item:selected { background: #3a8fd6; color: #1a2a3a; }
QListWidget#navList::item:hover:!selected { background: #2d3748; color: #ffffff; }

/* ── Status label colors (unified) ────────────────────────────── */
QLabel#statusSuccess { color: #68d391; }
QLabel#statusError   { color: #fc8181; }
QLabel#statusWarning { color: #f6ad55; }
QLabel#statusInfo    { color: #63b3ed; }

/* ── QMenu (right-click) ──────────────────────────────────────── */
QMenu { background: #2d3748; color: #e2e8f0; border: 1px solid #4a5568; }
QMenu::item:selected { background: #3a8fd6; color: #1a2a3a; }

/* ── QRadioButton ─────────────────────────────────────────────── */
QRadioButton { color: #e2e8f0; }

/* ── QSpinBox ─────────────────────────────────────────────────── */
QSpinBox {
  border: 1px solid #4a5568; border-radius: 5px; padding: 4px;
  background: #2d3748; color: #e2e8f0;
}

/* ── QSplitter handle ─────────────────────────────────────────── */
QSplitter::handle { background: #4a5568; }
)css";
