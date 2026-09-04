#pragma once

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

// ── Page-level stylesheet (TopologyPage style) ───────────────────────
// Apply via setStyleSheet(Theme::PageStyle) at start of each page's setupUI().
// Provides: rounded input fields, 3 button variants (default/primary/danger),
// card frames, and consistent focus styling.
constexpr const char* PageStyle =
  "QLabel { background:transparent; border:none; }"
  "QFrame[card=\"true\"] { background:#ffffff; border:1px solid #dbe3ef; border-radius:14px; }"
  "QFrame[softCard=\"true\"] { background:#f8fbff; border:1px solid #dbe3ef; border-radius:12px; }"
  "QLineEdit, QPlainTextEdit, QComboBox, QSpinBox { "
    "background:#ffffff; border:1px solid #cbd5e1; border-radius:8px; padding:6px 9px; }"
  "QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { "
    "border:1px solid #3b82f6; }"
  "QPushButton { "
    "background:#f8fafc; color:#1e293b; border:1px solid #cbd5e1; "
    "border-radius:8px; padding:7px 14px; font-weight:600; }"
  "QPushButton:hover { background:#eef4ff; border:1px solid #93b4ed; }"
  "QPushButton[primary=\"true\"] { "
    "background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; }"
  "QPushButton[primary=\"true\"]:hover { "
    "background:#1d4ed8; border:1px solid #1e40af; }"
  "QPushButton[danger=\"true\"] { "
    "background:#fff1f2; color:#b42318; border:1px solid #fecdd3; }"
  "QPushButton[danger=\"true\"]:hover { "
    "background:#ffe4e6; border:1px solid #fda4af; }"
  "QPushButton:disabled { "
    "background:#e5e7eb; color:#94a3b8; border:1px solid #d1d5db; }";

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
