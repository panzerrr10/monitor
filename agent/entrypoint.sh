#!/bin/sh
# 模拟主机入口：先起 sshd（可被运维），再起 agent（可被监控）
set -e

: "${SSH_PORT:=22}"
: "${AUTHORIZED_KEY:=}"

# 每个容器实例都要有独立的 host key（否则同一个 IP 换容器会触发 host key 变更告警）
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
  ssh-keygen -A
fi

# Alpine 的 adduser -D 会把账号密码字段设成 "!"（锁定状态），
# sshd 会以 "account is locked" 拒绝**公钥**登录 —— 必须给一个随机密码解锁。
# 同时下面把 PasswordAuthentication 关掉，所以这个密码没人能用。
RAND_PW=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-28)
echo "ops:${RAND_PW}" | chpasswd

# 只允许公钥认证
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# 写入公钥，允许 ops 用户免密登录
if [ -n "$AUTHORIZED_KEY" ]; then
  mkdir -p /home/ops/.ssh
  printf '%s\n' "$AUTHORIZED_KEY" > /home/ops/.ssh/authorized_keys
  chown -R ops:ops /home/ops/.ssh
  chmod 700 /home/ops/.ssh
  chmod 600 /home/ops/.ssh/authorized_keys
fi

mkdir -p /run/sshd
# -D 前台运行，-e 日志打到 stderr（docker logs 能看到）
/usr/sbin/sshd -D -e -p "$SSH_PORT" &

echo "[host] sshd 已在 0.0.0.0:$SSH_PORT 启动，用户 ops" >&2

# 采集端放前台，容器生命周期跟它绑定
exec python3 /opt/agent.py "$@"
