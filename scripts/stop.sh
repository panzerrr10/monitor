#!/usr/bin/env bash
# 停止监控系统（保留数据库）
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for name in server agent-host; do
  if [[ -f "logs/${name}.pid" ]]; then
    pid=$(cat "logs/${name}.pid")
    if kill "$pid" 2>/dev/null; then echo "  ✅ 已停止 ${name} (pid $pid)"; fi
    rm -f "logs/${name}.pid"
  fi
done

for c in sim-host-1 sim-host-2 ops-demo; do
  docker rm -f "$c" >/dev/null 2>&1 && echo "  ✅ 已移除 $c"
done

docker network rm monitor-net >/dev/null 2>&1 || true
echo "  ✅ 网络已清理"
echo
echo "  数据库保留：data/monitor.db（要清空就 rm -f data/monitor.db*）"
