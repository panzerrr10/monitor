#!/usr/bin/env bash
# ============================================================
#  把采集端部署到一台 Windows 主机（通过 SSH，需先配好密钥）
#
#  用法：
#    bash scripts/deploy-windows-agent.sh <Windows IP> <用户名> [host_id]
#  例：
#    bash scripts/deploy-windows-agent.sh 192.168.1.76 panzerrr win10-pc
#
#  做三件事：
#    1. 把 agent_windows.py / start-agent.bat / start-agent.vbs 传到
#       C:\Users\<用户>\monitor-agent\
#    2. 注册计划任务 MonitorAgent（登录时自启）
#    3. 立即启动一次
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WIN_IP="${1:?用法: $0 <Windows IP> <用户名> [host_id]}"
WIN_USER="${2:?缺少用户名}"
HOST_ID="${3:-win10-pc}"
KEY="$HOME/.ssh/id_monitor"
PY="${MONITOR_PYTHON:-$ROOT/.venv/bin/python}"

read -r PORT TOKEN < <("$PY" - "$ROOT" <<'PY'
import json, sys, os
d = json.load(open(os.path.join(sys.argv[1], "config/settings.json"), encoding="utf-8"))
print(d["listen_port"], d["ingest_token"])
PY
)

# 服务端地址要让 Windows 能访问到 → 用本机局域网 IP
LAN_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
SERVER="http://${LAN_IP}:${PORT}"

SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10 ${WIN_USER}@${WIN_IP}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "══════════ 1. 准备文件 ══════════"
cp agent/agent_windows.py "$TMP/"
# 注意：.bat 里不要写中文！cmd 用 GBK 解析文件，UTF-8 中文会导致整行报错
cat > "$TMP/start-agent.bat" <<BAT
@echo off
cd /d "%~dp0"
:loop
python agent_windows.py --server ${SERVER} --token ${TOKEN} --host-id ${HOST_ID} --interval 10 >> agent.log 2>&1
timeout /t 15 /nobreak >nul
goto loop
BAT
cat > "$TMP/start-agent.vbs" <<'VBS'
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run "cmd /c """ & dir & "\start-agent.bat""", 0, False
VBS
echo "  ✅ 服务端地址：${SERVER}"

echo
echo "══════════ 2. 上传到 Windows ══════════"
REMOTE_DIR="C:/Users/${WIN_USER}/monitor-agent"
$SSH "if not exist C:\\Users\\${WIN_USER}\\monitor-agent mkdir C:\\Users\\${WIN_USER}\\monitor-agent" || {
  echo "  ❌ 连不上 ${WIN_USER}@${WIN_IP}，先确认 SSH 密钥已配好"; exit 1; }
scp -i "$KEY" -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$TMP"/* "${WIN_USER}@${WIN_IP}:${REMOTE_DIR}/"
echo "  ✅ 已上传到 C:\\Users\\${WIN_USER}\\monitor-agent\\"

echo
echo "══════════ 3. 注册计划任务并启动 ══════════"
WIN_VBS="C:\\Users\\${WIN_USER}\\monitor-agent\\start-agent.vbs"
$SSH "schtasks /Create /F /SC ONLOGON /TN MonitorAgent /TR \"wscript.exe ${WIN_VBS}\""
$SSH "schtasks /Run /TN MonitorAgent" || true
echo "  ✅ 计划任务 MonitorAgent 已注册（登录时自启）"

echo
echo "══════════ 4. 等它上报 ══════════"
for i in $(seq 1 30); do
  if curl -s -H "X-Local-Token: $(echo)" "$SERVER/api/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
sleep 12
echo "  去页面「概览」看是否出现了 ${HOST_ID}（显示名会是 Windows 计算机名）"
echo
echo "  卸载方法（在 Windows 上）："
echo "    schtasks /Delete /TN MonitorAgent /F"
echo "    以及删除目录 C:\\Users\\${WIN_USER}\\monitor-agent\\"
