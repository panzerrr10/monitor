#!/usr/bin/env bash
# ============================================================
#  故障注入 —— 用来验证告警真的会亮
#
#  用法：
#    ./sim/chaos.sh cpu     sim-host-1    把 CPU 打满（在 2 核限额内跑满）
#    ./sim/chaos.sh mem     sim-host-1    吃掉约 900MB（容器限额 1GiB）
#    ./sim/chaos.sh kill    sim-host-1    停容器 = 主机离线
#    ./sim/chaos.sh recover sim-host-1    恢复
#    ./sim/chaos.sh recover all           全部恢复
#
#  注意：磁盘告警演示不了 —— 容器和宿主共享同一块盘（460G 只用了 12%）。
#        想验证磁盘告警链路，去页面「规则」里把磁盘阈值临时改成 10% 即可。
# ============================================================
set -uo pipefail
ACTION="${1:-}"; NODE="${2:-}"
NODES=(sim-host-1 sim-host-2 ops-demo)

usage() { sed -n '5,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[[ -z "$ACTION" ]] && usage
require() { docker inspect "$NODE" >/dev/null 2>&1 || { echo "❌ 没有容器 $NODE（可选：${NODES[*]}）"; exit 1; }; }

cpu_start() {
  # --cpus=2 的容器，起 4 个 yes 就能把它自身的 2 核占满（CPU% 会跑到 100）
  docker exec "$NODE" sh -c 'rm -f /tmp/chaos_cpu.pid; for i in 1 2 3 4; do nohup yes > /dev/null 2>&1 & echo $! >> /tmp/chaos_cpu.pid; done'
  echo "  🔥 $NODE：已启动 4 个 yes 进程，CPU 将在几秒内打满"
}
cpu_stop() {
  docker exec "$NODE" sh -c 'if [ -f /tmp/chaos_cpu.pid ]; then while read p; do kill "$p" 2>/dev/null; done < /tmp/chaos_cpu.pid; rm -f /tmp/chaos_cpu.pid; fi' >/dev/null 2>&1 || true
}
mem_start() {
  docker exec "$NODE" sh -c 'rm -f /tmp/chaos_mem.pid; nohup python3 -c "a=bytearray(900*1024*1024); import time; time.sleep(1800)" >/dev/null 2>&1 & echo $! > /tmp/chaos_mem.pid'
  echo "  🔥 $NODE：已分配约 900MB（容器限额 1GiB）"
}
mem_stop() {
  docker exec "$NODE" sh -c 'if [ -f /tmp/chaos_mem.pid ]; then kill "$(cat /tmp/chaos_mem.pid)" 2>/dev/null; rm -f /tmp/chaos_mem.pid; fi' >/dev/null 2>&1 || true
}
recover_one() {
  mem_stop; cpu_stop
  docker start "$NODE" >/dev/null 2>&1 || true
  echo "  ♻️  $NODE 已恢复"
}

case "$ACTION" in
  cpu)  require; cpu_start ;;
  mem)  require; mem_start ;;
  kill) require; docker stop "$NODE" >/dev/null; echo "  💀 $NODE 已停止（约 30 秒后触发「主机离线」）" ;;
  recover)
    if [[ "$NODE" == "all" || -z "$NODE" ]]; then
      for n in "${NODES[@]}"; do docker inspect "$n" >/dev/null 2>&1 && recover_one "$n"; done
    else require; recover_one; fi ;;
  *) usage ;;
esac

echo
echo "  告警都带「持续时间」，不会立刻亮：CPU/内存 120s、磁盘/负载 300s、离线 30s"
