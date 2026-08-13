#pragma once

// ── Global Theme Constants ────────────────────────────────────────────
// Single source of truth for all colors and shared style strings.
// Replace scattered inline hex values with these named constants.

namespace Theme {

// ── Brand / Primary ──────────────────────────────────────────────────
constexpr const char* Primary       = "#2a7dd6";
constexpr const char* PrimaryHover  = "#1e6bb8";
constexpr const char* PrimaryPress  = "#165a9e";

// ── Dark palette (nav, table headers, status bar) ────────────────────
constexpr const char* Dark          = "#1a2a3a";
constexpr const char* DarkLighter   = "#243447";

// ── Surface / Background ─────────────────────────────────────────────
constexpr const char* Background    = "#f5f7fa";
constexpr const char* Surface       = "#e8ecf0";
constexpr const char* SurfaceHover  = "#dce1e8";
constexpr const char* Border        = "#dce1e8";

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
  "font-size: 16px; font-weight: bold; color: #1a2a3a; "
  "padding: 4px 0; border-bottom: 2px solid #2a7dd6;";

// ── Page-level stylesheet (TopologyPage style) ───────────────────────
// Apply via setStyleSheet(Theme::PageStyle) at start of each page's setupUI().
// Provides: rounded input fields, 3 button variants (default/primary/danger),
// card frames, and consistent focus styling.
constexpr const char* PageStyle =
  "QLabel { background:transparent; border:none; }"
  "QFrame[card=\"true\"] { background:#ffffff; border:1px solid #dbe5f0; border-radius:16px; }"
  "QFrame[softCard=\"true\"] { background:#f8fbff; border:1px solid #dbe5f0; border-radius:12px; }"
  "QLineEdit, QPlainTextEdit, QComboBox, QSpinBox { "
    "background:#ffffff; border:1px solid #cfd9e6; border-radius:8px; padding:6px 8px; }"
  "QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { "
    "border:1px solid #60a5fa; }"
  "QPushButton { "
    "background:#eef3fb; color:#0f172a; border:1px solid #c7d5ea; "
    "border-radius:8px; padding:8px 14px; font-weight:600; }"
  "QPushButton:hover { background:#d9e8ff; border:1px solid #9fc2f7; }"
  "QPushButton[primary=\"true\"] { "
    "background:#2563eb; color:#ffffff; border:1px solid #1d4ed8; }"
  "QPushButton[primary=\"true\"]:hover { "
    "background:#1d4ed8; border:1px solid #1e40af; }"
  "QPushButton[danger=\"true\"] { "
    "background:#fff1f2; color:#b42318; border:1px solid #f3b5bd; }"
  "QPushButton[danger=\"true\"]:hover { "
    "background:#ffe4e6; border:1px solid #e58b97; }"
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
