#!/usr/bin/env bash
# ============================================================
#  启用本机 SSH（让监控面板能通过 SSH 运维这台机器）
#
#  做四件事：
#    1. 安装 openssh-server（没装才装）
#    2. 把监控公钥加进 ~/.ssh/authorized_keys（幂等）
#    3. 加固：只允许公钥登录、禁止 root 登录
#    4. 启动并设为开机自启，最后自检
#
#  需要 sudo 密码，请在**你自己的终端**里运行：
#      bash scripts/enable-local-ssh.sh
#
#  想保留密码登录（不推荐）：先 export ALLOW_PASSWORD=1 再运行
# ============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY="$HOME/.ssh/id_monitor"
ALLOW_PASSWORD="${ALLOW_PASSWORD:-0}"

say() { printf '  %s\n' "$*"; }
ok()  { printf '  ✅ %s\n' "$*"; }
warn(){ printf '  ⚠️  %s\n' "$*"; }
die() { printf '  ❌ %s\n' "$*"; exit 1; }

echo "══════════ 0. 前置检查 ══════════"
[[ "$(id -u)" -eq 0 ]] && die "请不要用 sudo 直接跑这个脚本，用普通用户运行，脚本内部会自己调 sudo"
[[ -f "$KEY" ]] || die "找不到私钥 $KEY（先跑 ssh-keygen -t ed25519 -N '' -f $KEY）"
ok "私钥存在：$KEY"
command -v sudo >/dev/null || die "没有 sudo"
ok "当前用户：$(id -un)"

echo
echo "══════════ 1. 安装 openssh-server ══════════"
if dpkg -s openssh-server >/dev/null 2>&1; then
  ok "已安装（$(dpkg-query -W -f='${Version}' openssh-server)）"
else
  say "未安装，开始安装（下载约 2MB，网络慢可能要等一两分钟）…"
  sudo apt-get install -y --no-install-recommends openssh-server || die "安装失败（可以先 sudo apt-get update 再试）"
  ok "安装完成"
fi

echo
echo "══════════ 2. 写入监控公钥 ══════════"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
if grep -qF "$(cat "$KEY.pub")" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
  ok "公钥已存在，跳过"
else
  cat "$KEY.pub" >> "$HOME/.ssh/authorized_keys"
  ok "已追加到 authorized_keys"
fi
chmod 600 "$HOME/.ssh/authorized_keys"

echo
echo "══════════ 3. 加固 sshd ══════════"
if [[ "$ALLOW_PASSWORD" == "1" ]]; then
  warn "ALLOW_PASSWORD=1 → 保留密码登录（仅建议临时用）"
  sudo tee /etc/ssh/sshd_config.d/99-monitor.conf >/dev/null <<'CONF'
# 由 Monitor 项目的 scripts/enable-local-ssh.sh 生成
PubkeyAuthentication yes
PermitRootLogin no
CONF
else
  sudo tee /etc/ssh/sshd_config.d/99-monitor.conf >/dev/null <<'CONF'
# 由 Monitor 项目的 scripts/enable-local-ssh.sh 生成
# 只允许公钥登录：防止局域网内被暴力破解
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
CONF
  ok "已写入 /etc/ssh/sshd_config.d/99-monitor.conf（仅公钥登录）"
fi
# Ubuntu 24.04 用 socket 激活（ssh.socket），手动跑 sshd -t 时会因为
# /run/sshd 还没被 RuntimeDirectory 创建而报 "Missing privilege separation directory"。
# 那不是配置错误，先建目录再检查；而且检查失败也不该阻断启动。
sudo mkdir -p /run/sshd
if sudo sshd -t 2>/tmp/.sshd_t.err; then
  ok "sshd 配置语法检查通过"
else
  warn "sshd -t 有输出：$(cat /tmp/.sshd_t.err 2>/dev/null | head -2 | tr '\n' ' ')"
  warn "继续尝试启动（如果确实有语法错误，启动会失败）"
fi
rm -f /tmp/.sshd_t.err

echo
echo "══════════ 4. 启动服务 ══════════"
# Ubuntu 24.04 默认 socket 激活：ssh.socket 监听 22，连接到来时才拉 sshd。
# 两个都启用最稳（老版本只有 ssh.service）。
sudo systemctl enable --now ssh.socket 2>/dev/null || true
sudo systemctl enable --now ssh 2>/dev/null || true
if systemctl is-active --quiet ssh.socket || systemctl is-active --quiet ssh; then
  ok "SSH 已启动（$(systemctl is-active ssh.socket 2>/dev/null | sed 's/active/socket 激活/'; systemctl is-active ssh 2>/dev/null | sed 's/active/service/') 并设为开机自启）"
else
  die "启动失败：systemctl status ssh.socket / ssh 看原因"
fi

sleep 1
echo
echo "══════════ 5. 自检 ══════════"
if ss -lntp 2>/dev/null | grep -qE '(0\.0\.0\.0|\*|\[::\]):22\s'; then
  ok "22 端口已监听"
else
  warn "没看到 22 端口监听"
fi
if ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
      -o ConnectTimeout=5 -p 22 "$(id -un)@127.0.0.1" 'echo MONITOR_SSH_OK' 2>/dev/null | grep -q MONITOR_SSH_OK; then
  ok "密钥登录本机成功（MONITOR_SSH_OK）"
else
  warn "密钥登录自检失败，检查 ~/.ssh/authorized_keys 权限与内容"
fi

echo
echo "════════════════════════════════════════"
echo " 完成。回到 Monitor 页面："
echo "   运维 → 主机选「$(hostname)」→ 连接并打开控制台"
echo " 连接参数：127.0.0.1:22  用户 $(id -un)  密钥 ~/.ssh/id_monitor"
echo "════════════════════════════════════════"
