# 模拟主机：既能被监控（agent），又能被 SSH 运维（sshd）
#
# 为什么用 Alpine 而不是 Debian：apt 在这台机器上只有 ~24KB/s，装 openssh 会卡死；
# Alpine 的 apk 装 openssh + python3 实测 56 秒搞定。
FROM alpine:3.21

RUN apk add --no-cache openssh python3 procps iproute2 tzdata \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh ops \
 && mkdir -p /run/sshd

COPY agent.py /opt/agent.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# SSH 端口和主机名由运行参数决定（每台不同，避免 host 网络下端口冲突）
ENV SSH_PORT=22
EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
