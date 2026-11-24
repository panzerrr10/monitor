#!/usr/bin/env python3
"""Windows 采集端 —— 纯标准库 + ctypes，零第三方依赖

为什么不用 Linux 那个 agent.py：
  它读 /proc、/sys、cgroup，Windows 上都没有。
  这里改为直接调 Win32 API（kernel32 / psapi），所以不需要 pip install 任何东西
  （你那台机器没装 psutil，正好也不需要）。

协议与 Linux 版完全一致（POST /api/ingest + Bearer token），服务端无需改动。

用法：
  python agent_windows.py --server http://192.168.1.177:8090 --token xxx --host-id win10-pc
  python agent_windows.py --once          # 只采一次打印，不推送
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from ctypes import wintypes as wt

try:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
except (AttributeError, OSError):          # 非 Windows 上 import 也不报错
    k32 = psapi = None


# ============================================================
#  Win32 结构体
# ============================================================
class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wt.DWORD),
        ("dwMemoryLoad", wt.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _ft64(ft: FILETIME) -> int:
    return (ft.hi << 32) | ft.lo


# ============================================================
#  指标采集
# ============================================================
def cpu_times() -> tuple[int, int, int] | None:
    """返回 (idle, kernel, user) 累计 tick。
    注意：Windows 的 kernel 时间**包含** idle，所以算使用率时要减掉。"""
    idle, kern, user = FILETIME(), FILETIME(), FILETIME()
    if not k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)):
        return None
    return _ft64(idle), _ft64(kern), _ft64(user)


def memory() -> tuple[int, int] | None:
    """返回 (总内存, 可用内存)，单位字节"""
    m = MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(m)
    if not k32.GlobalMemoryStatusEx(ctypes.byref(m)):
        return None
    return int(m.ullTotalPhys), int(m.ullAvailPhys)


def disk_usage(path: str = None) -> tuple[float, int]:
    """返回 (使用率%, 可用字节)。默认看系统盘。"""
    if path is None:
        path = os.environ.get("SystemDrive", "C:") + "\\"
    free = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    total_free = ctypes.c_ulonglong(0)
    ok = k32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p(path),
        ctypes.byref(free), ctypes.byref(total), ctypes.byref(total_free))
    if not ok or total.value == 0:
        return 0.0, 0
    used = total.value - total_free.value
    return round(used / total.value * 100, 2), int(free.value)


def uptime_sec() -> float:
    return k32.GetTickCount64() / 1000.0


def proc_count() -> int:
    """枚举进程数（psapi.EnumProcesses）"""
    arr = (wt.DWORD * 8192)()
    needed = wt.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
        return 0
    n = needed.value // ctypes.sizeof(wt.DWORD)
    return sum(1 for i in range(n) if arr[i])


def host_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "kernel": platform.version(),
        "cpu_cores": os.cpu_count() or 1,
    }


# ============================================================
#  采集器
# ============================================================
class Collector:
    def __init__(self) -> None:
        self.cores = os.cpu_count() or 1
        self._prev = {}

    def sample(self) -> dict:
        now = time.time()

        # ---- CPU ----
        cpu_pct = 0.0
        t = cpu_times()
        if t:
            idle, kern, user = t
            if "idle" in self._prev:
                d_idle = idle - self._prev["idle"]
                d_total = (kern - self._prev["kern"]) + (user - self._prev["user"])
                if d_total > 0:
                    cpu_pct = max(0.0, min(100.0, (1 - d_idle / d_total) * 100))
            self._prev.update(idle=idle, kern=kern, user=user)

        # ---- 内存 ----
        mem = memory() or (0, 0)
        mem_total, mem_avail = mem
        mem_pct = round((1 - mem_avail / mem_total) * 100, 2) if mem_total else 0.0

        # ---- 磁盘 ----
        disk_pct, disk_avail = disk_usage()

        # ---- 负载（Windows 没有 loadavg，用 CPU 使用率推导，和容器模式一致）----
        load_per_core = round(cpu_pct / 100, 3)

        metrics = {
            "cpu_pct": round(cpu_pct, 2),
            "mem_pct": mem_pct,
            "mem_total": mem_total,
            "mem_avail": mem_avail,
            "swap_pct": 0.0,
            "disk_pct": disk_pct,
            "disk_avail": disk_avail,
            "load1_per_core": load_per_core,
            "procs": proc_count(),
            "uptime_hours": round(uptime_sec() / 3600, 2),
        }
        # 注意：Windows 版暂不上报网络速率（GetIfTable2 结构体太复杂，
        # 值不值得另说）。前端概览与曲线也只画 CPU/内存/磁盘/负载，不影响展示。

        return {
            "ts": int(now),
            "in_container": False,
            "cpu_cores": self.cores,
            "info": host_info(),
            "metrics": metrics,
        }


# ============================================================
#  上报
# ============================================================
def push(server: str, token: str, host_id: str, payload: dict) -> dict | None:
    body = dict(payload)
    body["host_id"] = host_id
    req = urllib.request.Request(
        server.rstrip("/") + "/api/ingest",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        print(f"[agent-win] 上报失败 HTTP {e.code}: "
              f"{e.read()[:200].decode(errors='ignore')}", file=sys.stderr)
    except Exception as e:
        print(f"[agent-win] 上报失败: {e}", file=sys.stderr)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Windows 采集端")
    ap.add_argument("--server", default=os.environ.get("MONITOR_SERVER", "http://127.0.0.1:8090"))
    ap.add_argument("--token", default=os.environ.get("MONITOR_TOKEN", ""))
    ap.add_argument("--host-id", default=os.environ.get("MONITOR_HOST_ID") or socket.gethostname().lower())
    ap.add_argument("--interval", type=int, default=int(os.environ.get("MONITOR_INTERVAL", "10")))
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    if k32 is None:
        print("[agent-win] 这个脚本只能在 Windows 上运行", file=sys.stderr)
        return 2

    col = Collector()
    col.sample()            # 建基准（CPU 是累计值，需要两次采样）
    if args.once:
        time.sleep(1)
        print(json.dumps(col.sample(), ensure_ascii=False, indent=2))
        return 0

    print(f"[agent-win] host_id={args.host_id} 核数={col.cores} 间隔={args.interval}s", flush=True)
    time.sleep(args.interval)
    interval = args.interval
    while True:
        try:
            payload = col.sample()
            resp = push(args.server, args.token, args.host_id, payload)
            m = payload["metrics"]
            print(f"[agent-win] cpu={m['cpu_pct']}% mem={m['mem_pct']}% "
                  f"disk={m['disk_pct']}% procs={m['procs']} "
                  f"{'OK' if resp is not None else 'FAIL'}", flush=True)
            if resp and isinstance(resp.get("interval"), int) and resp["interval"] >= 1:
                interval = resp["interval"]
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            print(f"[agent-win] 采集异常: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
