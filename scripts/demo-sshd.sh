#!/usr/bin/env bash
# ============================================================
#  重建「运维演示主机」ops-demo
#
#  正常情况下 scripts/start.sh 会自动建好三台主机：
#    sim-host-1  SSH 2221
#    sim-host-2  SSH 2223
#    ops-demo    SSH 2222   ← 本脚本只管这一台
#
#  什么时候用：把 ops-demo 玩坏了（删了/改乱了），想单独恢复它。
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${MONITOR_PYTHON:-$ROOT/.venv/bin/python}"

KEY="$HOME/.ssh/id_monitor"
if [[ ! -f "$KEY" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$KEY" -C "monitor-ops" >/dev/null
  echo "  ✅ 已生成密钥 $KEY"
fi

read -r PORT TOKEN INTERVAL < <("$PY" - "$ROOT" <<'PY'
import json, sys, os
d = json.load(open(os.path.join(sys.argv[1], "config/settings.json"), encoding="utf-8"))
print(d["listen_port"], d["ingest_token"], d["interval_sec"])
PY
)
LOCAL_TOKEN=$("$PY" - "$ROOT" <<'PY'
import json, sys, os
d = json.load(open(os.path.join(sys.argv[1], "config/settings.json"), encoding="utf-8"))
print((d.get("auth") or {}).get("local_token", ""))
PY
)

docker rm -f ops-demo >/dev/null 2>&1 || true
docker run -d --name ops-demo --network=host \
  --memory=1g --cpus=2 --hostname ops-demo \
  -e SSH_PORT=2222 -e AUTHORIZED_KEY="$(cat "$KEY.pub")" \
  monitor-host:latest \
  --server "http://127.0.0.1:${PORT}" --token "$TOKEN" \
  --host-id ops-demo --interval "$INTERVAL" >/dev/null

curl -s -o /dev/null -X POST "http://127.0.0.1:${PORT}/api/remote/creds" \
  -H "Content-Type: application/json" -H "X-Local-Token: ${LOCAL_TOKEN}" \
  -d '{"host_id":"ops-demo","ssh_host":"127.0.0.1","ssh_user":"ops","ssh_port":2222,"key_path":"~/.ssh/id_monitor","os_type":"linux","enabled":true}'

echo "  ✅ ops-demo 已重建（host_id=ops-demo，SSH 127.0.0.1:2222，用户 ops）"
echo
echo "  自测：ssh -i ~/.ssh/id_monitor -p 2222 -o StrictHostKeyChecking=accept-new ops@127.0.0.1 'hostname'"
