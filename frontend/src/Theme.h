#pragma once
#include <QString>

// ── Global Theme Constants ────────────────────────────────────────────
// Single source of truth for all colors and shared style strings.
// Replace scattered inline hex values with these named constants.

namespace Theme {

// ── Brand / Primary ──────────────────────────────────────────────────
constexpr const char* Primary       = "#2563eb";
constexpr const char* PrimaryHover  = "#1d4ed8";
constexpr const char* PrimaryPress  = "#1e40af";

// ── Dark palette (nav, table headers, status bar) ────────────────────
constexpr const char* Dark          = "#10243e";
constexpr const char* DarkLighter   = "#1d3655";

// ── Surface / Background ─────────────────────────────────────────────
constexpr const char* Background    = "#f3f6fb";
constexpr const char* Surface       = "#eef4fb";
constexpr const char* SurfaceHover  = "#dbeafe";
constexpr const char* Border        = "#dbe3ef";

// ── Status colors (unified across all pages) ─────────────────────────
constexpr const char* Success       = "#166534";
constexpr const char* SuccessBg     = "#f0fdf4";
constexpr const char* Error         = "#991b1b";
constexpr const char* ErrorBg       = "#fef2f2";
constexpr const char* Warning       = "#b45309";
constexpr const char* WarningBg     = "#fffbeb";
constexpr const char* Info          = "#1d4ed8";
constexpr const char* InfoBg        = "#eff6ff";

// ── Danger (destructive actions) ─────────────────────────────────────
constexpr const char* Danger        = "#e74c3c";
constexpr const char* DangerHover   = "#c0392b";

// ── Muted / Disabled ─────────────────────────────────────────────────
constexpr const char* Muted         = "#bdc3c7";
constexpr const char* MutedText     = "#7f8c8d";
constexpr const char* NavText       = "#aabbcc";

// ── Table ────────────────────────────────────────────────────────────
constexpr const char* TableAltRow   = "#f0f4f8";

// ── Section header QSS ───────────────────────────────────────────────
// Replaces the duplicated sectionStyle string in 6 page files.
constexpr const char* SectionStyle =
  "font-size:17px; font-weight:700; color:#172033; "
  "padding:4px 0 7px; border-bottom:1px solid #dbe3ef;";

// Shared button roles used by pages, dialogs and toolbars. Sizes are variants,
// not separate visual themes; enabled state and action wiring remain native.
inline const QString ButtonStyle = R"css(
  QPushButton {
    background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #ffffff,stop:1 #fafcff); color:#475569; border:1px solid #d5deeb;
    border-radius:8px; padding:0 14px; min-height:34px;
    font-size:13px; font-weight:500;
  }
  QPushButton:hover { background:#f2f6ff; color:#1d4ed8; border-color:#adc5ef; }
  QPushButton:pressed { background:#e6efff; border-color:#7ea6e8; }
  QPushButton:focus { border-color:#7ea6e8; }
  QPushButton[primary="true"] { background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #3b82f6,stop:1 #2563eb); color:#ffffff; border-color:#2563eb; font-weight:600; }
  QPushButton[primary="true"]:hover { background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #4b8cf7,stop:1 #2d6aee); border-color:#3475e9; }
  QPushButton[primary="true"]:pressed { background:#1e40af; border-color:#1e40af; }
  QPushButton[primary="true"]:focus { border-color:#93c5fd; }
  QPushButton[quiet="true"] { background:transparent; border-color:transparent; }
  QPushButton[quiet="true"]:hover { background:#f1f5fb; color:#1d4ed8; border-color:#e2e8f0; }
  QPushButton[quiet="true"]:focus { border-color:#7ea6e8; }
  QPushButton[iconOnly="true"] { padding:0; font-size:18px; }
  QPushButton[iconOnly="true"]::menu-indicator { image:none; width:0; }
  QPushButton[menuAction="true"] { padding-right:24px; }
  QPushButton[menuAction="true"]::menu-indicator { subcontrol-position:center right; right:9px; }

  QPushButton[danger="true"], QPushButton#dangerBtn { background:#fff1f2; color:#b42318; border-color:#fecdd3; }
  QPushButton[danger="true"]:hover, QPushButton#dangerBtn:hover { background:#ffe4e6; border-color:#fda4af; }
  QPushButton[danger="true"]:pressed, QPushButton#dangerBtn:pressed { background:#fecdd3; border-color:#f87171; }
  QPushButton[warning="true"] { background:#fffbeb; color:#a16207; border-color:#fde68a; }
  QPushButton[warning="true"]:hover { background:#fef3c7; border-color:#facc15; }
  QPushButton[warning="true"]:pressed { background:#fde68a; }
  QPushButton[compact="true"] { min-height:26px; padding:0 10px; font-size:12px; border-radius:6px; }
  QPushButton[large="true"] { min-height:44px; font-size:15px; }
  QPushButton[danger="true"]:focus, QPushButton[warning="true"]:focus { border-color:#7ea6e8; }
  QPushButton:disabled, QPushButton[primary="true"]:disabled,
  QPushButton[danger="true"]:disabled, QPushButton#dangerBtn:disabled, QPushButton[warning="true"]:disabled,
  QPushButton[quiet="true"]:disabled {
    background:#f1f4f8; color:#9aa7ba; border-color:#e3e8f0;
  }
)css";
inline const QString ToolbarButtonStyle = ButtonStyle;

// Dark surfaces use the same geometry and interaction states.
inline const QString DarkButtonStyle = ButtonStyle + R"css(
  QPushButton { background:#253449; color:#e2e8f0; border-color:#475569; }
  QPushButton:hover { background:#304563; color:#bfdbfe; border-color:#6487b7; }
  QPushButton:pressed { background:#1d3655; }
  QPushButton[danger="true"], QPushButton#dangerBtn { background:#442b36; color:#fda4af; border-color:#794152; }
  QPushButton[danger="true"]:hover, QPushButton#dangerBtn:hover { background:#5d3041; }
  QPushButton[warning="true"] { background:#443c27; color:#fde68a; border-color:#80652e; }
  QPushButton[warning="true"]:hover { background:#5b4827; }
  QPushButton:disabled, QPushButton[primary="true"]:disabled, QPushButton[danger="true"]:disabled,
  QPushButton#dangerBtn:disabled, QPushButton[warning="true"]:disabled {
    background:#263244; color:#7b8da5; border-color:#37465c;
  }
)css";

// The selected row already identifies the active item. Suppress only the
// native dotted/gray focus outline; keep focus, selection and keyboard behavior.
inline const QString ItemViewStyle =
  "QTableView, QTreeView, QListView { outline:0; }";

// Pages share one set of controls while keeping their existing card layout.
inline const QString PageStyle = QStringLiteral(
  "QLabel { background:transparent; border:none; }"
  "QFrame[card=\"true\"] { background:#ffffff; border:1px solid #dbe3ef; border-radius:14px; }"
  "QFrame[softCard=\"true\"] { background:#f8fbff; border:1px solid #dbe3ef; border-radius:12px; }"
  "QLineEdit, QPlainTextEdit, QComboBox, QSpinBox { "
    "background:#ffffff; border:1px solid #cbd5e1; border-radius:8px; padding:6px 9px; }"
  "QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { "
    "border:1px solid #3b82f6; }"
  ) + ButtonStyle + ItemViewStyle;

// ── Status label styles (colored background + border + rounded) ──────
constexpr const char* StatusSuccessStyle =
  "color:#166534; background:#f0fdf4; border:1px solid #bbf7d0; "
  "border-radius:8px; padding:8px 10px;";
constexpr const char* StatusErrorStyle =
  "color:#991b1b; background:#fef2f2; border:1px solid #fecaca; "
  "border-radius:8px; padding:8px 10px;";
constexpr const char* StatusInfoStyle =
  "color:#1d4ed8; background:#eff6ff; border:1px solid #bfdbfe; "
  "border-radius:8px; padding:8px 10px;";
constexpr const char* StatusWarningStyle =
  "color:#b45309; background:#fffbeb; border:1px solid #fde68a; "
  "border-radius:8px; padding:8px 10px;";

} // namespace Theme
