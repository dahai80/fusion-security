#!/usr/bin/env bash
# fusion-security lifecycle manager (start|stop|restart|status)
# REST API on port 11454 (health endpoint: /api/v1/system/health, 公开无需鉴权)。
# Callers: fusion-studio UpstreamServiceManager (auto-start on launch + manual start)。
# Affected API: start.sh start|stop|restart|status; status exits 0 if running, 1 if not。
# Data schemas: PID file .fusion-security.pid; logs/stdout.log + logs/stderr.log。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# VENV 可移植:优先用 VENV 环境变量,否则回退 monorepo 共享 .venv(上一级目录)。
VENV="${VENV:-$(dirname "$SCRIPT_DIR")/.venv}"
PID_FILE="${SCRIPT_DIR}/.fusion-security.pid"
LOG_DIR="${SCRIPT_DIR}/logs"
STDOUT_LOG="${LOG_DIR}/stdout.log"
STDERR_LOG="${LOG_DIR}/stderr.log"
PORT="${FUSION_SECURITY_PORT:-11454}"
HOST="${FUSION_SECURITY_HOST:-127.0.0.1}"

mkdir -p "$LOG_DIR"

log_info()  { printf "\033[0;32m[INFO]\033[0m  %s\n" "$*"; }
log_error() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*"; }

is_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

ensure_venv() {
    if [[ -f "${VENV}/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "${VENV}/bin/activate"
    fi
}

do_start() {
    if is_running; then
        log_info "fusion-security already running (pid $(cat "$PID_FILE"))"
        return 0
    fi
    ensure_venv
    log_info "starting fusion-security API on ${HOST}:${PORT} ..."
    nohup uvicorn fusion_security.api.app:app \
        --host "$HOST" --port "$PORT" \
        >> "$STDOUT_LOG" 2>> "$STDERR_LOG" &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    sleep 2
    if is_running; then
        log_info "fusion-security started (pid $pid, port $PORT)"
    else
        log_error "fusion-security failed to start, see $STDERR_LOG"
        rm -f "$PID_FILE"
        return 1
    fi
}

do_stop() {
    if ! is_running; then
        log_info "fusion-security not running"
        rm -f "$PID_FILE"
        return 0
    fi
    local pid
    pid="$(cat "$PID_FILE")"
    log_info "stopping fusion-security (pid $pid)"
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        log_error "force kill (pid $pid)"
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    log_info "fusion-security stopped"
}

do_status() {
    if is_running; then
        echo "running (pid $(cat "$PID_FILE"), port $PORT)"
        return 0
    fi
    echo "stopped"
    return 1
}

ACTION="${1:-start}"
case "$ACTION" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    restart) do_stop || true; do_start ;;
    *) echo "usage: $0 {start|stop|status|restart}" >&2; exit 1 ;;
esac
