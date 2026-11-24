#!/usr/bin/env bash
# ============================================================
#  统一入口（给桌面快捷方式用）
#
#    ctl.sh start    启动后台（服务端 + 采集端 + 模拟主机）
#    ctl.sh stop     停止全部
#    ctl.sh status   查看状态
#    ctl.sh open     没运行就先启动，然后打开浏览器  ← 桌面图标调这个
# ============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${MONITOR_PYTHON:-$ROOT/.venv/bin/python}"

PORT=$("$PY" -c "import json;print(json.load(open('config/settings.json'))['listen_port'])" 2>/dev/null || echo 8090)
URL="http://127.0.0.1:${PORT}"

running() { curl -sf --max-time 2 "${URL}/api/health" >/dev/null 2>&1; }

case "${1:-open}" in
  start)
    bash scripts/start.sh
    ;;
  stop)
    bash scripts/stop.sh
    ;;
  status)
    bash scripts/status.sh
    ;;
  open|desktop)
    # 桌面版：交给 GUI 外壳（后端没起来时窗口里会自动拉起）
    exec bash scripts/monitor-desktop.sh
    ;;
  browser)
    # 想用浏览器打开时用这个（调试用）
    if ! running; then bash scripts/start.sh >/tmp/monitor-start.log 2>&1 & fi
    for i in $(seq 1 60); do running && break; sleep 1; done
    xdg-open "$URL" >/dev/null 2>&1 &
    ;;
  *)
    sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
