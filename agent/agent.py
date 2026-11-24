#!/usr/bin/env python3
"""监控采集端 —— 纯标准库，零第三方依赖

设计要点：
  1. 不依赖 psutil：直接读 /proc 和 /sys，一台最小化的机器也能跑
  2. 自动识别「物理机 / 容器」两种视角：
       物理机  → 读 /proc/stat、/proc/meminfo（整机视角）
       容器    → 读 cgroup v2（容器自己的视角）
     为什么必须区分：容器共享宿主内核，容器里的 /proc/stat 就是宿主的，
     不区分的话三台容器的 CPU 会完全一样（这个坑实测过）
  3. 增量计算：cpu/网络 都是累计值，要两次采样相减才是「使用率/速率」

用法：
  python3 agent.py --server http://127.0.0.1:8090 --token xxx --host-id sim-1
  python3 agent.py --once          # 只采一次打印出来（不推送），用于调试
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


# ============================================================
#  基础读取
# ============================================================
def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return default


def read_int(path: str, default: int = 0) -> int:
    try:
        with open(path, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return default


# ============================================================
#  环境识别：物理机 还是 容器
# ============================================================
def detect_container() -> tuple[bool, float]:
    """返回 (是否容器, 可用 CPU 核数)

    判断依据：cgroup v2 的 memory.max 若不是 "max"，说明这个 cgroup 被设了内存上限，
    那我们就在一个受限的 cgroup（容器）里。
    同时从 cpu.max 读出 CPU 配额（形如 "200000 100000" = 2 核）。
    """
    mem_max = read_text("/sys/fs/cgroup/memory.max").strip()
    cpu_max = read_text("/sys/fs/cgroup/cpu.max").strip()

    in_container = mem_max not in ("", "max")

    cores = float(os.cpu_count() or 1)
    if cpu_max and not cpu_max.startswith("max"):
        parts = cpu_max.split()
        if len(parts) == 2:
            try:
                cores = int(parts[0]) / int(parts[1])
            except (ValueError, ZeroDivisionError):
                pass
    return in_container, max(0.1, cores)


# ============================================================
#  CPU
# ============================================================
def cpu_times_host() -> tuple[float, float]:
    """物理机：从 /proc/stat 读累计 CPU 时间，返回 (总时间, 空闲时间)"""
    line = read_text("/proc/stat").splitlines()[0] if read_text("/proc/stat") else ""
    nums = [float(x) for x in line.split()[1:]] if line.startswith("cpu") else []
    if len(nums) < 4:
        return 0.0, 0.0
    total = sum(nums[:8])
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0.0)   # idle + iowait
    return total, idle


def cpu_usage_usec_cgroup() -> float:
    """容器：从 cgroup v2 cpu.stat 读累计 CPU 时间（微秒）"""
    txt = read_text("/sys/fs/cgroup/cpu.stat")
    for line in txt.splitlines():
        if line.startswith("usage_usec"):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return 0.0
    return 0.0


# ============================================================
#  内存
# ============================================================
def mem_host() -> dict:
    info = {}
    for line in read_text("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        try:
            info[k] = int(v.split()[0]) * 1024
        except (IndexError, ValueError):
            info[k] = 0
    total = info.get("MemTotal", 0) or 1
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    return {
        "mem_total": total,
        "mem_avail": avail,
        "mem_pct": round((1 - avail / total) * 100, 2),
        "swap_pct": round((1 - swap_free / swap_total) * 100, 2) if swap_total else 0.0,
    }


def mem_container() -> dict:
    cur = read_int("/sys/fs/cgroup/memory.current")
    mx_txt = read_text("/sys/fs/cgroup/memory.max").strip()
    try:
        mx = int(mx_txt)
    except ValueError:
        mx = 0
    if mx <= 0:
        mx = 1024 ** 3
    avail = max(0, mx - cur)
    return {
        "mem_total": mx,
        "mem_avail": avail,
        "mem_pct": round((1 - avail / mx) * 100, 2),
        "swap_pct": 0.0,
    }


# ============================================================
#  磁盘 / 网络 / 进程
# ============================================================
def disk_stats(mount: str = "/") -> dict:
    try:
        st = os.statvfs(mount)
    except OSError:
        return {"disk_pct": 0.0, "disk_avail": 0}
    size = st.f_blocks * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    used = size - st.f_bfree * st.f_frsize
    pct = (used / size * 100) if size else 0.0
    return {"disk_pct": round(pct, 2), "disk_avail": avail}


def net_totals() -> tuple[int, int]:
    rx = tx = 0
    for line in read_text("/proc/net/dev").splitlines()[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        if name.strip() == "lo":
            continue
        cols = rest.split()
        if len(cols) >= 9:
            rx += int(cols[0])
            tx += int(cols[8])
    return rx, tx


def proc_count() -> int:
    try:
        return sum(1 for d in os.listdir("/proc") if d.isdigit())
    except OSError:
        return 0


def uptime_sec() -> float:
    try:
        return float(read_text("/proc/uptime").split()[0])
    except (IndexError, ValueError):
        return 0.0


def host_info(cores: float) -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": read_text("/etc/os-release").split('PRETTY_NAME="')[-1].split('"')[0]
              if "PRETTY_NAME" in read_text("/etc/os-release") else "unknown",
        "kernel": read_text("/proc/sys/kernel/osrelease").strip() or "unknown",
        "cpu_cores": round(cores, 2),
    }


# ============================================================
#  采集器
# ============================================================
class Collector:
    def __init__(self) -> None:
        self.in_container, self.cores = detect_container()
        self._prev: dict = {}

    def sample(self) -> dict:
        now = time.time()

        # ---- CPU ----
        cpu_pct = 0.0
        if self.in_container:
            cur = cpu_usage_usec_cgroup()
            if "cg_cpu" in self._prev:
                d_used = max(0.0, (cur - self._prev["cg_cpu"]) / 1e6)
                d_wall = max(1e-6, now - self._prev["ts"])
                cpu_pct = min(100.0, d_used / (d_wall * self.cores) * 100)
            self._prev["cg_cpu"] = cur
        else:
            total, idle = cpu_times_host()
            if "cpu_total" in self._prev:
                d_total = total - self._prev["cpu_total"]
                d_idle = idle - self._prev["cpu_idle"]
                cpu_pct = (1 - d_idle / d_total) * 100 if d_total > 0 else 0.0
            self._prev["cpu_total"], self._prev["cpu_idle"] = total, idle

        # ---- 内存 ----
        mem = mem_container() if self.in_container else mem_host()

        # ---- 负载 ----
        try:
            load1 = os.getloadavg()[0]
        except OSError:
            load1 = 0.0
        if self.in_container:
            # 容器共享宿主的 loadavg，所以用自身 CPU 使用率推导
            load1 = cpu_pct / 100 * self.cores
        load_per_core = load1 / self.cores if self.cores else 0.0

        # ---- 磁盘 ----
        disk = disk_stats("/")

        # ---- 网络（速率，不是累计）----
        rx, tx = net_totals()
        rx_kbps = tx_kbps = 0.0
        if "rx" in self._prev:
            d_wall = max(1e-6, now - self._prev["ts"])
            rx_kbps = max(0.0, (rx - self._prev["rx"]) / d_wall / 1024)
            tx_kbps = max(0.0, (tx - self._prev["tx"]) / d_wall / 1024)
        self._prev["rx"], self._prev["tx"] = rx, tx
        self._prev["ts"] = now

        return {
            "ts": int(now),
            "in_container": self.in_container,
            "cpu_cores": self.cores,
            "info": host_info(self.cores),
            "metrics": {
                "cpu_pct": round(cpu_pct, 2),
                "mem_pct": mem["mem_pct"],
                "mem_total": mem["mem_total"],
                "mem_avail": mem["mem_avail"],
                "swap_pct": mem["swap_pct"],
                "disk_pct": disk["disk_pct"],
                "disk_avail": disk["disk_avail"],
                "load1_per_core": round(load_per_core, 3),
                "net_rx_kbps": round(rx_kbps, 2),
                "net_tx_kbps": round(tx_kbps, 2),
                "procs": proc_count(),
                "uptime_hours": round(uptime_sec() / 3600, 2),
            },
        }


# ============================================================
#  上报
# ============================================================
def push(server: str, token: str, host_id: str, payload: dict) -> dict | None:
    body = dict(payload)
    body["host_id"] = host_id
    data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(
        server.rstrip("/") + "/api/ingest",
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            if not (200 <= r.status < 300):
                return None
            try:
                return json.loads(r.read().decode() or "{}")
            except json.JSONDecodeError:
                return {}
    except urllib.error.HTTPError as e:
        print(f"[agent] 上报失败 HTTP {e.code}: {e.read()[:200].decode(errors='ignore')}",
              file=sys.stderr)
    except Exception as e:
        print(f"[agent] 上报失败: {e}", file=sys.stderr)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="监控采集端")
    ap.add_argument("--server", default=os.environ.get("MONITOR_SERVER", "http://127.0.0.1:8090"))
    ap.add_argument("--token", default=os.environ.get("MONITOR_TOKEN", ""))
    ap.add_argument("--host-id", default=os.environ.get("MONITOR_HOST_ID", socket.gethostname()))
    ap.add_argument("--interval", type=int, default=int(os.environ.get("MONITOR_INTERVAL", "10")))
    ap.add_argument("--once", action="store_true", help="只采一次并打印，不推送")
    args = ap.parse_args()

    col = Collector()
    print(f"[agent] host_id={args.host_id} 容器模式={col.in_container} "
          f"可用核数={col.cores} 间隔={args.interval}s", flush=True)

    # 第一轮只建基准（累计型指标需要两次采样才有差值）
    col.sample()
    if args.once:
        time.sleep(1)
        print(json.dumps(col.sample(), ensure_ascii=False, indent=2))
        return 0

    interval = args.interval
    time.sleep(interval)
    while True:
        try:
            payload = col.sample()
            resp = push(args.server, args.token, args.host_id, payload)
            m = payload["metrics"]
            print(f"[agent] cpu={m['cpu_pct']}% mem={m['mem_pct']}% "
                  f"disk={m['disk_pct']}% load/core={m['load1_per_core']} "
                  f"{'✅' if resp is not None else '❌'}", flush=True)
            # 服务端可以远程下发新的采集周期，改页面设置即可生效
            if resp and isinstance(resp.get("interval"), int) and resp["interval"] >= 1:
                if resp["interval"] != interval:
                    print(f"[agent] 采集周期由 {interval}s 调整为 {resp['interval']}s", flush=True)
                    interval = resp["interval"]
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            print(f"[agent] 采集异常: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
