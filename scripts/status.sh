#!/usr/bin/env bash
# 查看监控系统状态
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${MONITOR_PYTHON:-$ROOT/.venv/bin/python}"
PORT=$("$PY" -c "import json;print(json.load(open('config/settings.json'))['listen_port'])")

echo "────────── 进程 ──────────"
for n in server agent-host; do
  if [[ -f "logs/${n}.pid" ]] && kill -0 "$(cat "logs/${n}.pid")" 2>/dev/null; then
    printf '  %-12s ✅ 运行中 (pid %s)\n' "$n" "$(cat "logs/${n}.pid")"
  else
    printf '  %-12s ❌ 未运行\n' "$n"
  fi
done
for c in sim-host-1 sim-host-2 ops-demo; do
  printf '  %-12s %s\n' "$c" "$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo 不存在)"
done

echo "────────── 服务端 ──────────"
curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:${PORT}/api/health" \
  && printf '  HTTP :%s ✅\n' "$PORT" || printf '  HTTP :%s ❌\n' "$PORT"

echo "────────── 主机与告警 ──────────"
TOKEN=$("$PY" -c "
import json
try:
    print((json.load(open('config/settings.json')).get('auth') or {}).get('local_token',''))
except Exception:
    print('')
")
curl -s --max-time 3 -H "X-Local-Token: ${TOKEN}" "http://127.0.0.1:${PORT}/api/overview" -o /tmp/_ov.json 2>/dev/null
"$PY" - /tmp/_ov.json <<'PY'
import json, sys
from datetime import datetime
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("  （服务端不可达）"); raise SystemExit
for h in d["hosts"]:
    m = h.get("metrics") or {}
    state = "✅ 在线" if h["online"] else "❌ 离线"
    age = f"{h['age_sec']}s前" if h.get("age_sec") is not None else "—"
    core = f"容器{ h.get('cpu_cores'):g}核" if h.get("in_container") else f"物理{h.get('cpu_cores'):g}核"
    print(f"  {state} {h['name']:14s} cpu={m.get('cpu_pct','—')!s:>6}% "
          f"mem={m.get('mem_pct','—')!s:>6}% disk={m.get('disk_pct','—')!s:>6}% "
          f"{core} 上报{age}")
print()
al = d["alerts"]
print(f"  活跃告警：{len(al)} 条")
for a in al:
    print(f"    [{'严重' if a['severity']=='critical' else '警告'}] {a['rule_name']} @ {a['host_name']} = {a['value']}")
s = d["stats"]
print(f"\n  数据：原始 {s['raw_points']} 点 / 聚合 {s['agg_points']} 点")
PY
rm -f /tmp/_ov.json
