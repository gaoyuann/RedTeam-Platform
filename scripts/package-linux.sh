#!/usr/bin/env bash
# RedTeam Platform - Linux Portable Bundle Builder
# Creates a self-contained directory with Qt libs, Node.js runtime, backend, and data
set -uo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_ROOT/dist/RedTeam-Platform"

BINARY="$PROJECT_ROOT/build/frontend/RedTeam-Platform"
BACKEND_DIR="$PROJECT_ROOT/backend"
DATA_DIR="$PROJECT_ROOT/data"
CONTAINER_TAR_DIR="$PROJECT_ROOT/containers/tar"

QT_PREFIX="$(qmake -query QT_INSTALL_PREFIX 2>/dev/null || echo '/usr')"
QT_PLUGINS="$(qmake -query QT_INSTALL_PLUGINS 2>/dev/null || echo '/usr/lib/x86_64-linux-gnu/qt5/plugins')"

echo "=== RedTeam Platform - Linux Portable Bundle ==="
echo "Output: $DIST_DIR"

# ── Clean ──────────────────────────────────────────────────────────────
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"/{bin,lib/qt,lib/openssl,plugins/platforms,plugins/imageformats,plugins/iconengines,plugins/xcbglintegrations,backend,data,containers/tar,node,fonts}

# ── 1. Copy Qt binary ─────────────────────────────────────────────────
if [ ! -x "$BINARY" ]; then
  echo "ERROR: Binary not found at $BINARY"
  echo "Run: cmake -B build -S . && cmake --build build"
  exit 1
fi
cp "$BINARY" "$DIST_DIR/bin/RedTeam-Platform"
strip "$DIST_DIR/bin/RedTeam-Platform" 2>/dev/null || true
echo "[1/7] Copied binary ($(du -sh "$DIST_DIR/bin/RedTeam-Platform" | cut -f1))"

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

# Scan binary dependencies
while read -r line; do
  lib_path="$(echo "$line" | awk '{print $3}')"
  [ -z "$lib_path" ] && continue
  [ ! -f "$lib_path" ] && continue
  name="$(basename "$lib_path")"
  case "$name" in
    libQt5*|libicu*) copy_lib "$lib_path" ;;
  esac
done < <(ldd "$BINARY")

echo "[2/7] Copied $COPIED_LIBS shared libraries"

# ── 3. Copy Qt plugins ────────────────────────────────────────────────
copy_plugins() {
  local category="$1"
  local dest="$DIST_DIR/plugins/$category"
  if [ -d "$QT_PLUGINS/$category" ]; then
    for f in "$QT_PLUGINS/$category"/*.so; do
      [ -f "$f" ] || continue
      cp "$f" "$dest/"
      # Scan plugin for additional Qt deps
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
copy_plugins xcbglintegrations
echo "[3/7] Copied Qt plugins"

# ── 4. Copy OpenSSL 1.1 (if available) ────────────────────────────────
SSL_COPIED=0
for lib in libssl.so.1.1 libcrypto.so.1.1; do
  path="$(ldconfig -p 2>/dev/null | grep "$lib" | head -1 | awk '{print $NF}')"
  if [ -n "$path" ] && [ -f "$path" ]; then
    cp "$path" "$DIST_DIR/lib/openssl/"
    SSL_COPIED=$((SSL_COPIED + 1))
  fi
done
echo "[4/7] OpenSSL: copied $SSL_COPIED libs (install libssl1.1 if 0)"

# ── 5. Copy backend + node_modules ────────────────────────────────────
cp -r "$BACKEND_DIR/src" "$DIST_DIR/backend/"
cp "$BACKEND_DIR/package.json" "$DIST_DIR/backend/"
if [ -d "$BACKEND_DIR/node_modules" ]; then
  cp -r "$BACKEND_DIR/node_modules" "$DIST_DIR/backend/"
fi
echo "[5/7] Copied backend ($(du -sh "$DIST_DIR/backend" | cut -f1))"

# ── 6. Copy data + container tars ─────────────────────────────────────
cp "$DATA_DIR"/redteam.db "$DIST_DIR/data/" 2>/dev/null || true
cp -r "$DATA_DIR/wordlists" "$DIST_DIR/data/" 2>/dev/null || true
if [ -d "$CONTAINER_TAR_DIR" ]; then
  cp "$CONTAINER_TAR_DIR"/*.tar "$DIST_DIR/containers/tar/" 2>/dev/null || true
fi
echo "[6/7] Copied data and container tars"

# ── 7. Copy fonts (NotoSansCJK if available) ──────────────────────────
FONT_COPIED=0
for f in /usr/share/fonts/truetype/noto/NotoSansCJK* \
         /usr/share/fonts/opentype/noto/NotoSansCJK* \
         /usr/share/fonts/noto-cjk/NotoSansCJK*; do
  if [ -f "$f" ]; then
    cp "$f" "$DIST_DIR/fonts/"
    FONT_COPIED=$((FONT_COPIED + 1))
  fi
done
echo "[7/7] Fonts: copied $FONT_COPIED CJK fonts"

# ── Generate qt.conf ──────────────────────────────────────────────────
cat > "$DIST_DIR/bin/qt.conf" << 'EOF'
[Paths]
Prefix = ..
Libraries = lib/qt
Plugins = plugins
EOF

# ── Copy start.sh ─────────────────────────────────────────────────────
cp "$SCRIPT_DIR/start.sh" "$DIST_DIR/start.sh"
chmod +x "$DIST_DIR/start.sh"

# ── Summary ───────────────────────────────────────────────────────────
TOTAL_SIZE="$(du -sh "$DIST_DIR" | cut -f1)"
echo ""
echo "=== Bundle Complete ==="
echo "  Directory: $DIST_DIR"
echo "  Total size: $TOTAL_SIZE"
echo "  Run: cd $DIST_DIR && ./start.sh"
