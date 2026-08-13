#!/usr/bin/env bash
# RedTeam Platform - ARM64 Client Package Script
# Creates a portable client-only bundle for cloud laptops
# Run on ARM64 cloud laptop after building
set -uo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_ROOT/dist/RedTeam-Platform-Client-ARM64"

BINARY="$PROJECT_ROOT/build/frontend/RedTeam-Platform"

QT_PREFIX="$(qmake -query QT_INSTALL_PREFIX 2>/dev/null || echo '/usr')"
QT_PLUGINS="$(qmake -query QT_INSTALL_PLUGINS 2>/dev/null || echo '/usr/lib/aarch64-linux-gnu/qt5/plugins')"

echo "=== RedTeam Platform - ARM64 Client Bundle ==="
echo "Architecture: $(uname -m)"
echo "Output: $DIST_DIR"

# ── Clean ──────────────────────────────────────────────────────────────
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"/{bin,lib/qt,lib/openssl,plugins/platforms,plugins/imageformats,plugins/iconengines,fonts}

# ── 1. Copy Qt binary ─────────────────────────────────────────────────
if [ ! -x "$BINARY" ]; then
  echo "ERROR: Binary not found at $BINARY"
  echo "Run: scripts/build-client-arm64;64.sh"
  exit 1
fi
cp "$BINARY" "$DIST_DIR/bin/RedTeam-Platform"
strip "$DIST_DIR/bin/RedTeam-Platform" 2>/dev/null || true
echo "[1/5] Copied binary ($(du -5h "$DIST_DIR/bin/RedTeam-Platform" | cut -f1))"

# ── 2. Copy Qt shared libraries (via ldd) ─────────────────────────────
COPIED_LIBS=0
copy_lib() {
  local src="$1"
  local name="$(basename "$src")"
  local dest="$DIST_DIR/lib/qt/$name"
  if [ ! -f "$dest" ]; then
    cp "$src" "$dest"
    COPIED_LIBS=$((COPIED_LIBS + 1))
  fi
}

while read -r line; do
  lib_path="$(echo "$line" | awk '{print $3}')"
  [ -z "$lib_path" ] && continue
  [ ! -f "$lib_path" ] && continue
  name="$(basename "$lib_path")"
  case "$name in
    libQt5*|libicu*) copy_lib "$lib_path" ;;
  esac
done < <(ldd "$BINARY")

echo "[2/5] Copied $COPIED_LIBS shared libraries"

# ── 3. Copy Qt plugins ────────────────────────────────────────────────
copy_plugins() {
  local category="$1"
  local dest="$DIST_DIR/plugins/$category"
  if [ -d "$QT_PLUGINS/$category" ]; then
    for f in "$QT_PLUGINS/$category"/*.so; do
      [ -f "$f" ] || continue
      cp "$f" "$dest/"
      while read -r line; do
        lib_path="$(echo "$line" | awk '{print $3}')"
        [ -z "$lib_path" ] && continue
        [ ! -f "$lib_path" ] && continue
        name="$(basename "$lib_path")"
        case "$name" in libQt5*|libicu*) copy_lib "$lib_path" ;; esac
      done < <(ldd "$f" 2>/dev/null)
    done
  fi
}

copy_plugins platforms
copy_plugins imageformats
copy_plugins iconengines
echo "[3/5] Copied Qt plugins"

# ── 4. Copy fonts (NotoSansCJK) ───────────────────────────────────────
FONT_COPIED=0
for f in /usr/share/fonts/truetype/noto/NotoSansCJK* \
         /usr/share/fonts/opentype/noto/NotoSansCJK* \
         /usr/share/fonts/noto-cjk/NotoSansCJK*; do
  if [ -f "$f" ]; then
    cp "$f" "$DIST_DIR/fonts/"
    FONT_COPIED=$((FONT_COPIED + 1))
  fi
done
echo "[4/5] Fonts: copied $FONT_COPIED CJK fonts"

# ── 5. Copy start-client.sh ───────────────────────────────────────────
cp "$SCRIPT_DIR/start-client.sh" "$DIST_DIR/start-client.sh"
chmod +x "$DIST_DIR/start-client.sh"
echo "[5/5] Copied start-client.sh"

# ── Generate qt.conf ──────────────────────────────────────────────────
cat > "$DIST_DIR/bin/qt.conf" << 'EOF'
[Paths]
Prefix = ..
Libraries = lib/qt
Plugins = plugins
EOF

# ── Summary ───────────────────────────────────────────────────────────
TOTAL_SIZE="$(du -sh "$DIST_DIR" | cut -f1)"
echo ""
echo "=== Bundle Complete ==="
echo "  Directory: $DIST_DIR"
echo "  Total size: $TOTAL_SIZE"
echo "  Architecture: $(uname -m)"
echo ""
echo "  Transfer to cloud laptop and run:"
echo "    cd $DIST_DIR && ./start-client.sh <服务器IP:3002>"
