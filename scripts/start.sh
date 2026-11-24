#!/usr/bin/env bash
# ============================================================
#  一键启动监控系统
#
#  组件：
#    服务端（Flask，含告警引擎/降采样/SSE）  :8090
#    被监控主机 ×3（Docker，Alpine + sshd + agent）
#      · sim-host-1   SSH 2221  仅被监控
#      · sim-host-2   SSH 2223  仅被监控
#      · ops-demo     SSH 2222  运维演示主机（专门用来试终端/SFTP）
#    本机采集端（agent.py，后台进程）
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${MONITOR_PYTHON:-$ROOT/.venv/bin/python}"
read -r PORT TOKEN INTERVAL < <("$PY" - "$ROOT" <<'PY'
import json, sys, os
d = json.load(open(os.path.join(sys.argv[1], "config/settings.json"), encoding="utf-8"))
print(d["listen_port"], d["ingest_token"], d["interval_sec"])
PY
)

# 主机清单：容器名:host_id:SSH端口
HOSTS=(
  "sim-host-1:sim-1:2221"
  "sim-host-2:sim-2:2223"
  "ops-demo:ops-demo:2222"
)

echo "══════════ 1. 准备目录 ══════════"
mkdir -p data logs
echo "  ✅ data/ logs/ 就绪"

echo
echo "══════════ 2. 构建模拟主机镜像 ══════════"
if ! docker image inspect monitor-host:latest >/dev/null 2>&1; then
  docker build -q -t monitor-host:latest agent/ >/dev/null
  echo "  ✅ monitor-host:latest 已构建（Alpine + sshd + python3 + agent）"
else
  echo "  ✅ monitor-host:latest 已存在（改了 agent/ 下的文件请先 docker rmi monitor-host:latest）"
fi

echo
echo "══════════ 3. 启动服务端 ══════════"
if [[ -f logs/server.pid ]] && kill -0 "$(cat logs/server.pid)" 2>/dev/null; then
  kill "$(cat logs/server.pid)" 2>/dev/null || true; sleep 1
fi
nohup "$PY" server/app.py >logs/server.out 2>&1 &
echo $! >logs/server.pid
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null || { echo "  ❌ 服务端启动失败，看 logs/server.out"; tail -20 logs/server.out; exit 1; }
echo "  ✅ 服务端就绪 → http://127.0.0.1:${PORT}"

echo
echo "══════════ 4. 启动本机采集端 ══════════"
if [[ -f logs/agent-host.pid ]] && kill -0 "$(cat logs/agent-host.pid)" 2>/dev/null; then
  kill "$(cat logs/agent-host.pid)" 2>/dev/null || true; sleep 0.5
fi
nohup "$PY" agent/agent.py --server "http://127.0.0.1:${PORT}" --token "$TOKEN" \
  --host-id ubuntu-host --interval "$INTERVAL" >logs/agent-host.out 2>&1 &
echo $! >logs/agent-host.pid
echo "  ✅ 本机采集端已启动（host_id=ubuntu-host）"

echo
echo "══════════ 5. 启动被监控主机 ×3 ══════════"
PUBKEY="$(cat "$HOME/.ssh/id_monitor.pub" 2>/dev/null || true)"
if [[ -z "$PUBKEY" ]]; then
  echo "  ⚠️ 没有 ~/.ssh/id_monitor.pub，SSH 将不可用（先跑 ssh-keygen -t ed25519 -f ~/.ssh/id_monitor）"
fi
# 老的演示容器（占用 2222）清掉，避免端口冲突
docker rm -f sshd-demo >/dev/null 2>&1 || true
for spec in "${HOSTS[@]}"; do
  IFS=: read -r cname hid sshport <<< "$spec"
  docker rm -f "$cname" >/dev/null 2>&1 || true
  if ! docker run -d --name "$cname" --network=host \
      --memory=1g --cpus=2 --hostname "$cname" \
      -e SSH_PORT="$sshport" -e AUTHORIZED_KEY="$PUBKEY" \
      monitor-host:latest \
      --server "http://127.0.0.1:${PORT}" --token "$TOKEN" \
      --host-id "$hid" --interval "$INTERVAL" >/dev/null 2>&1; then
    echo "  ⚠️ $cname 启动失败（看 docker logs $cname）"
    continue
  fi
  echo "  ✅ $cname（host_id=$hid · SSH 端口 $sshport · 1GiB / 2 核）"
done

echo
echo "══════════ 6. 配置演示主机的 SSH 连接 ══════════"
LOCAL_TOKEN=$("$PY" - "$ROOT" <<'PY'
import json, sys, os
d = json.load(open(os.path.join(sys.argv[1], "config/settings.json"), encoding="utf-8"))
print((d.get("auth") or {}).get("local_token", ""))
PY
)
for spec in "${HOSTS[@]}"; do
  IFS=: read -r cname hid sshport <<< "$spec"
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${PORT}/api/remote/creds" \
    -H "Content-Type: application/json" -H "X-Local-Token: ${LOCAL_TOKEN}" \
    -d "{\"host_id\":\"${hid}\",\"ssh_host\":\"127.0.0.1\",\"ssh_user\":\"ops\",\"ssh_port\":${sshport},\"key_path\":\"~/.ssh/id_monitor\",\"os_type\":\"linux\",\"enabled\":true}")
  [[ "$code" == "200" ]] && echo "  ✅ $hid → 127.0.0.1:${sshport}（用户 ops）" || echo "  ⚠️ $hid 连接配置写入失败（HTTP $code）"
done

echo
echo "══════════ 7. 等待第一轮上报 ══════════"
for i in $(seq 1 40); do
  n=$(curl -s "http://127.0.0.1:${PORT}/api/hosts" 2>/dev/null \
      | "$PY" -c "import json,sys;print(len([h for h in json.load(sys.stdin) if h['online']]))" 2>/dev/null || echo 0)
  if [[ "${n:-0}" -ge 4 ]]; then echo "  ✅ ${n} 台主机已上线"; break; fi
  sleep 1
done

echo
echo "════════════════════════════════════════"
echo " 监控系统已启动"
echo "   页面    http://127.0.0.1:${PORT}"
echo "   主机    本机 ubuntu-host + sim-host-1/2 + ops-demo"
echo "   运维    sim-host-1/2 与 ops-demo 均可 SSH（端口 2221 / 2223 / 2222）"
echo "   周期    ${INTERVAL}s（页面可改，会下发给采集端）"
echo "════════════════════════════════════════"
echo " 停止：bash scripts/stop.sh"
echo
bash scripts/status.sh || true
