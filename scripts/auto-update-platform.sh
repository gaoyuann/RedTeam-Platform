#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [ -n "${CONFIG_FILE:-}" ]; then
  while IFS= read -r config_line || [ -n "$config_line" ]; do
    config_line="${config_line#"${config_line%%[![:space:]]*}"}"
    case "$config_line" in ''|'#'*) continue ;; esac
    config_key="${config_line%%=*}"
    config_value="${config_line#*=}"
    case "$config_key" in
      ROLE|PROJECT_DIR|BRANCH|POLL_INTERVAL|FETCH_TIMEOUT|SOURCE_URL|SOURCE_REF|TRACKING_REF|STATE_DIR|BACKUP_DIR|BACKEND_SERVICE|DB_PATH|HEALTH_URL|NODE_BIN|BUILD_JOBS|SSH_COMMAND|DISPLAY|XAUTHORITY|REDTEAM_SERVER) ;;
      *) printf 'Unsupported configuration key: %s\n' "$config_key" >&2; exit 2 ;;
    esac
    [[ "$config_line" = *=* ]] || { echo 'Invalid configuration assignment' >&2; exit 2; }
    config_value="${config_value#"${config_value%%[![:space:]]*}"}"
    config_value="${config_value%"${config_value##*[![:space:]]}"}"
    case "$config_value" in
      \"*\"|\'*\') config_value="${config_value:1:${#config_value}-2}" ;;
      *[[:space:]]*) printf 'Quote configuration values containing spaces: %s\n' "$config_key" >&2; exit 2 ;;
    esac
    printf -v "$config_key" '%s' "$config_value"
    export "$config_key"
  done < "$CONFIG_FILE"
  unset CONFIG_FILE
fi

ROLE="${ROLE:?Set ROLE to server or client}"
PROJECT_DIR="${PROJECT_DIR:?Set PROJECT_DIR}"
BRANCH="${BRANCH:-main}"
POLL_INTERVAL="${POLL_INTERVAL:-300}"
FETCH_TIMEOUT="${FETCH_TIMEOUT:-120}"
SOURCE_URL="${SOURCE_URL:-$(git -C "$PROJECT_DIR" config --get remote.origin.url)}"
SOURCE_REF="${SOURCE_REF:-refs/heads/$BRANCH}"
TRACKING_REF="${TRACKING_REF:-refs/remotes/origin/$BRANCH}"
STATE_DIR="${STATE_DIR:-$HOME/.local/state/redteam/platform-update}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/redteam-deploy-backups/automatic}"
BACKEND_SERVICE="${BACKEND_SERVICE:-redteam-backend.service}"
DB_PATH="${DB_PATH:-$PROJECT_DIR/data/redteam.db}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:3002/api/health}"
NODE_BIN="${NODE_BIN:-node}"
BUILD_JOBS="${BUILD_JOBS:-2}"
MODE="${1:---once}"

case "$ROLE" in server|client) ;; *) echo 'Invalid ROLE' >&2; exit 2 ;; esac
case "$MODE" in --once|--daemon) ;; *) echo 'Use --once or --daemon' >&2; exit 2 ;; esac
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_SSH_COMMAND="${SSH_COMMAND:-ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes}"
if [ "$ROLE" = server ]; then
  export PATH="$(dirname "$(command -v "$NODE_BIN")"):$PATH"
fi
mkdir -p "$STATE_DIR" "$BACKUP_DIR"
cd "$PROJECT_DIR"

log() { printf '[%s] [%s] %s\n' "$(date -Is)" "$ROLE" "$*"; }

healthy() {
  curl -fsS --connect-timeout 3 --max-time 5 "$HEALTH_URL" |
    python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ok" else 1)'
}

wait_healthy() {
  local attempt
  for attempt in $(seq 1 30); do
    if healthy >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

database_backup() {
  python3 - "$DB_PATH" "$1" <<'PY'
import pathlib
import os
import sqlite3
import sys
source_path, destination_path = map(pathlib.Path, sys.argv[1:])
source = sqlite3.connect(source_path.resolve().as_uri() + '?mode=ro', uri=True)
temporary_path = destination_path.with_name(destination_path.name + '.tmp')
with sqlite3.connect(temporary_path) as destination:
    source.backup(destination)
    if destination.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise RuntimeError('Database backup failed integrity check')
destination.close()
source.close()
os.replace(temporary_path, destination_path)
PY
}

restore_markers() {
  local marker
  for marker in deployed.sha deployed.binary.sha deployed; do
    if [ -f "$1/$marker.before" ]; then
      cp -p "$1/$marker.before" "$STATE_DIR/$marker"
    else
      rm -f "$STATE_DIR/$marker"
    fi
  done
}

busy() {
  local started pending
  started=$(systemctl show "$BACKEND_SERVICE" --property=ExecMainStartTimestampMonotonic --value)
  if ! pending=$(python3 - "$DB_PATH" "$started" <<'PY'
import datetime
import pathlib
import sqlite3
import sys
import time
database = sqlite3.connect(pathlib.Path(sys.argv[1]).resolve().as_uri() + '?mode=ro', uri=True)
monotonic_started = int(sys.argv[2])
service_started = time.time() - time.monotonic() + monotonic_started / 1000000 if monotonic_started else 0
for table in ('execution_runs', 'scan_tasks', 'pipelines', 'capture_tasks'):
    columns = {row[1] for row in database.execute('PRAGMA table_info(' + table + ')')}
    if 'status' not in columns:
        continue
    timestamp = next((name for name in ('started_at', 'created_at') if name in columns), None)
    query = 'SELECT status, ' + (timestamp or 'NULL') + ' FROM ' + table
    for status, started_at in database.execute(query):
        if str(status).upper() not in {'RUNNING', 'EXECUTING', 'SCANNING', 'CAPTURING'}:
            continue
        if started_at:
            try:
                started = datetime.datetime.fromisoformat(str(started_at).replace('Z', '+00:00'))
                if started.tzinfo is None:
                    started = started.replace(tzinfo=datetime.timezone.utc)
                if started.timestamp() < service_started:
                    continue
            except ValueError:
                pass
        print('Deferring deployment: active work in ' + table)
        sys.exit(0)
PY
  ); then
    log 'Cannot inspect running work; deferring deployment'
    return 0
  fi
  if [ -n "$pending" ]; then log "$pending"; return 0; fi
  return 1
}

trust_binary() {
  if command -v kysec_set >/dev/null 2>&1; then
    sudo -n "$(command -v kysec_set)" -n exectl -v verified "$1"
  fi
}

restart_client() {
  local process_id executable
  if systemctl --user is-active --quiet redteam-client.service; then
    systemctl --user restart redteam-client.service
  else
    for process_id in $(pgrep -u "$(id -u)" -f 'RedTeam-Platform' || true); do
      executable=$(readlink "/proc/$process_id/exe" 2>/dev/null || true)
      if [ "$executable" = "$PROJECT_DIR/build/frontend/RedTeam-Platform" ]; then
        kill "$process_id" 2>/dev/null || true
      fi
    done
    systemctl --user reset-failed redteam-client.service 2>/dev/null || true
    systemd-run --user --unit=redteam-client --collect \
      --property=Type=exec --property=Restart=on-failure \
      --setenv="DISPLAY=${DISPLAY:-:0}" \
      --setenv="XAUTHORITY=${XAUTHORITY:-$HOME/.Xauthority}" \
      --setenv="REDTEAM_SERVER=${REDTEAM_SERVER:-192.168.1.103:3002}" \
      "$PROJECT_DIR/scripts/start-app.sh"
  fi
  sleep 5
  systemctl --user is-active --quiet redteam-client.service || return 1
  process_id=$(systemctl --user show redteam-client.service --property=MainPID --value)
  [ "$(readlink "/proc/$process_id/exe")" = "$PROJECT_DIR/build/frontend/RedTeam-Platform" ] &&
    cmp -s "/proc/$process_id/exe" "$PROJECT_DIR/build/frontend/RedTeam-Platform"
}

update_server() (
  set -Eeuo pipefail
  local previous="$1" candidate="$2" backup="$3" stage published dependencies_changed=0 activated=0
  published=$(git rev-parse --verify "refs/heads/deployed-$BRANCH" 2>/dev/null || true)
  stage=$(mktemp -d "$STATE_DIR/stage.XXXXXX")
  rollback() {
    local result=$?
    trap - EXIT
    if [ "$result" -ne 0 ] && [ "$activated" = 1 ]; then
      log 'Deployment failed; restoring previous code, dependencies and database'
      sudo -n systemctl stop "$BACKEND_SERVICE" || true
      git reset --hard "$previous" || true
      if [ -n "$published" ]; then
        git update-ref "refs/heads/deployed-$BRANCH" "$published" || true
      else
        git update-ref -d "refs/heads/deployed-$BRANCH" || true
      fi
      restore_markers "$backup" || log 'CRITICAL: deployment marker restore failed'
      if [ -d "$backup/node_modules" ]; then
        rm -rf "$PROJECT_DIR/backend/node_modules"
        mv "$backup/node_modules" "$PROJECT_DIR/backend/node_modules"
      fi
      if [ -f "$backup/redteam.db" ]; then
        rm -f "$DB_PATH-wal" "$DB_PATH-shm"
        cp -p "$backup/redteam.db" "$DB_PATH" || log 'CRITICAL: database restore failed'
      fi
      sudo -n systemctl start "$BACKEND_SERVICE" || true
      if ! wait_healthy; then log 'CRITICAL: rollback health check failed'; fi
    fi
    rm -rf "$stage"
    exit "$result"
  }
  trap rollback EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  git archive "$candidate" | tar -xf - -C "$stage"
  if ! git diff --quiet "$previous" "$candidate" -- backend/package.json backend/package-lock.json; then
    dependencies_changed=1
    (cd "$stage/backend" && npm ci --omit=dev --no-audit --no-fund)
  else
    ln -s "$PROJECT_DIR/backend/node_modules" "$stage/backend/node_modules"
  fi
  find "$stage/backend/src" -name '*.js' -print0 | xargs -0 -n 1 "$NODE_BIN" --check
  database_backup "$stage/migration-check.db"
  (cd "$stage/backend" && "$NODE_BIN" --input-type=module - "$stage/migration-check.db" <<'JS'
import Database from 'better-sqlite3';
import { runMigrations } from './src/db/migrate.js';
import { resolve } from 'node:path';
const database = new Database(process.argv[2]);
database.pragma('foreign_keys = ON');
await runMigrations(database, resolve('src/db/migrations'));
if (database.pragma('quick_check', { simple: true }) !== 'ok') throw new Error('Migration integrity check failed');
database.close();
JS
  )
  if busy; then log 'Update deferred until running work finishes'; return 0; fi
  git diff --quiet HEAD || { log 'Tracked files changed during validation; refusing deployment'; return 1; }
  sudo -n systemctl stop "$BACKEND_SERVICE"
  activated=1
  database_backup "$backup/redteam.db"
  if [ "$dependencies_changed" = 1 ]; then
    mv "$PROJECT_DIR/backend/node_modules" "$backup/node_modules"
    mv "$stage/backend/node_modules" "$PROJECT_DIR/backend/node_modules"
  fi
  git reset --hard "$candidate"
  sudo -n systemctl start "$BACKEND_SERVICE"
  wait_healthy
  git update-ref "refs/heads/deployed-$BRANCH" "$candidate"
  printf '%s\n' "$candidate" > "$STATE_DIR/deployed.sha"
  activated=0
  log "Backend healthy; published deployed-$BRANCH=$candidate"
)

update_client() (
  set -Eeuo pipefail
  local previous="$1" candidate="$2" backup="$3" stage activated=0
  local live_binary="$PROJECT_DIR/build/frontend/RedTeam-Platform"
  stage=$(mktemp -d "$STATE_DIR/stage.XXXXXX")
  rollback() {
    local result=$?
    trap - EXIT
    if [ "$result" -ne 0 ] && [ "$activated" = 1 ]; then
      log 'Client switch failed; restoring previous code and executable'
      git reset --hard "$previous" || true
      restore_markers "$backup" || log 'CRITICAL: deployment marker restore failed'
      if [ -f "$backup/RedTeam-Platform" ]; then
        if [ -d "$backup/third_party" ]; then
          rm -rf "$(dirname "$live_binary")/third_party"
          cp -a "$backup/third_party" "$(dirname "$live_binary")/" || log 'CRITICAL: client library restore failed'
        fi
        install -m 755 "$backup/RedTeam-Platform" "$live_binary.next" &&
          trust_binary "$live_binary.next" && mv -f "$live_binary.next" "$live_binary" &&
          trust_binary "$live_binary" && trust_binary "$PROJECT_DIR/scripts/start-app.sh" &&
          restart_client || log 'CRITICAL: client rollback failed'
      fi
    fi
    rm -rf "$stage"
    exit "$result"
  }
  trap rollback EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  git archive "$candidate" | tar -xf - -C "$stage"
  mkdir -p "$STATE_DIR/source"
  rsync -rc --links --perms --delete "$stage/" "$STATE_DIR/source/"
  cmake -S "$STATE_DIR/source" -B "$STATE_DIR/build"
  cmake --build "$STATE_DIR/build" -j"$BUILD_JOBS"
  test -x "$STATE_DIR/build/frontend/RedTeam-Platform"
  healthy >/dev/null
  git diff --quiet HEAD || { log 'Tracked files changed during build; refusing deployment'; return 1; }
  cp -p "$live_binary" "$backup/RedTeam-Platform"
  if [ -d "$(dirname "$live_binary")/third_party" ]; then
    cp -a "$(dirname "$live_binary")/third_party" "$backup/third_party"
  fi
  activated=1
  git reset --hard "$candidate"
  mkdir -p "$(dirname "$live_binary")"
  if [ -d "$STATE_DIR/build/frontend/third_party" ]; then
    cp -a "$STATE_DIR/build/frontend/third_party" "$(dirname "$live_binary")/"
  fi
  install -m 755 "$STATE_DIR/build/frontend/RedTeam-Platform" "$live_binary.next"
  trust_binary "$live_binary.next"
  mv -f "$live_binary.next" "$live_binary"
  trust_binary "$live_binary"
  trust_binary "$PROJECT_DIR/scripts/start-app.sh"
  restart_client
  printf '%s\n' "$candidate" > "$STATE_DIR/deployed.sha"
  sha256sum "$live_binary" | cut -d ' ' -f 1 > "$STATE_DIR/deployed.binary.sha"
  date -Is > "$STATE_DIR/deployed"
  activated=0
  log "ARM64 client deployed and running: $candidate"
)

update_once() (
  set -Eeuo pipefail
  local previous candidate backup marker
  exec 9>"$STATE_DIR/update.lock"
  flock -n 9 || { log 'Another update is running; skipping'; return 0; }
  [ "$(git branch --show-current)" = "$BRANCH" ] || { log 'Unexpected branch; refusing update'; return 1; }
  git diff --quiet HEAD || { log 'Uncommitted tracked changes; refusing update'; return 1; }
  timeout "$FETCH_TIMEOUT" git fetch --no-tags "$SOURCE_URL" "+$SOURCE_REF:$TRACKING_REF"
  previous=$(git rev-parse HEAD)
  candidate=$(git rev-parse "$TRACKING_REF")
  git merge-base --is-ancestor "$previous" "$candidate" || { log 'Non-fast-forward update refused'; return 1; }
  if [ "$previous" = "$candidate" ]; then
    if [ "$ROLE" = server ]; then
      if [ "$(cat "$STATE_DIR/deployed.sha" 2>/dev/null || true)" = "$candidate" ] &&
         [ "$(git rev-parse --verify "refs/heads/deployed-$BRANCH" 2>/dev/null || true)" = "$candidate" ]; then
        healthy >/dev/null
        log "Already current and healthy: $candidate"
        return 0
      fi
    elif [ "$(cat "$STATE_DIR/deployed.sha" 2>/dev/null || true)" = "$candidate" ] &&
       [ "$(sha256sum "$PROJECT_DIR/build/frontend/RedTeam-Platform" | cut -d ' ' -f 1)" = "$(cat "$STATE_DIR/deployed.binary.sha" 2>/dev/null || true)" ]; then
      log "Already current: $candidate"
      return 0
    fi
  fi
  declare -A tracked_paths=() untracked_paths=() collision_paths=()
  while IFS= read -r -d '' path; do tracked_paths["$path"]=1; done < <(git ls-tree -r -z --name-only "$candidate")
  while IFS= read -r -d '' path; do untracked_paths["$path"]=1; done < <(git ls-files --others --exclude-standard -z)
  record_collision() {
    local candidate_path="$1" local_path="$2" key="$1\x00$2"
    if [ -z "${collision_paths["$key"]+present}" ]; then
      collision_paths["$key"]=1
      collisions+=("$candidate_path ↔ $local_path")
    fi
  }
  collisions=()
  for local_path in "${!untracked_paths[@]}"; do
    path="$local_path"
    while :; do
      if [ -n "${tracked_paths["$path"]+present}" ]; then record_collision "$path" "$local_path"; fi
      [ "$path" = "${path%/*}" ] && break
      path="${path%/*}"
    done
  done
  for candidate_path in "${!tracked_paths[@]}"; do
    path="$candidate_path"
    while :; do
      if [ -n "${untracked_paths["$path"]+present}" ]; then record_collision "$candidate_path" "$path"; fi
      [ "$path" = "${path%/*}" ] && break
      path="${path%/*}"
    done
  done
  if [ "${#collisions[@]}" -gt 0 ]; then
    preview=$(IFS=', '; printf '%s' "${collisions[*]:0:5}")
    printf 'Refusing to overwrite local files or deploy path collisions: %s\n' "$preview" >&2
    exit 1
  fi
  if [ -n "${tracked_paths[.env]+present}" ]; then
    echo 'Refusing to overwrite local files or deploy tracked secrets/database files' >&2
    exit 1
  fi
  for path in "${!tracked_paths[@]}"; do
    if [[ "$path" == data/*.db ]]; then
      echo 'Refusing to overwrite local files or deploy tracked secrets/database files' >&2
      exit 1
    fi
  done
  if [ "$ROLE" = server ] && busy; then log 'Update deferred until running work finishes'; return 0; fi
  backup="$BACKUP_DIR/$(date +%Y%m%dT%H%M%S)-${previous:0:12}"
  mkdir -p "$backup"
  git archive --format=tar.gz "$previous" > "$backup/source.tar.gz"
  printf '%s\n' "$previous" > "$backup/head.before"
  for marker in deployed.sha deployed.binary.sha deployed; do
    if [ -f "$STATE_DIR/$marker" ]; then cp -p "$STATE_DIR/$marker" "$backup/$marker.before"; fi
  done
  if [ -f .env ]; then cp -p .env "$backup/environment.before"; fi
  log "Deploying $previous -> $candidate; backup=$backup"
  if [ "$ROLE" = server ]; then
    update_server "$previous" "$candidate" "$backup"
  else
    update_client "$previous" "$candidate" "$backup"
  fi
)

if [ "$MODE" = --once ]; then
  update_once
else
  while true; do
    if bash "$0" --once; then
      log 'Update check completed'
    else
      log 'Update check failed; retaining current deployment and retrying later'
    fi
    sleep "$POLL_INTERVAL"
  done
fi
