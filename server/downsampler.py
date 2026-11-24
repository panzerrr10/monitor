"""降采样线程

原始数据保留 24 小时（精度高、量大），
聚合数据保留 7 天（5 分钟粒度、量小）。

为什么分层：点数量 = 主机数 × 指标数 × (时间 / 采集间隔)。
10 秒采集、4 台主机、12 个指标 → 一天约 41 万个点；7 天就是 290 万。
而看一周前的趋势，5 分钟粒度完全够用，所以聚合后只有 1/30 的量。
"""
from __future__ import annotations

import threading
import time
from typing import Callable

import db


class Downsampler(threading.Thread):
    def __init__(self, settings_fn: Callable[[], dict]) -> None:
        super().__init__(daemon=True, name="downsampler")
        self.settings_fn = settings_fn
        self._stop = threading.Event()

    def run(self) -> None:
        # 启动时先等一个周期，避免和首次采集抢资源
        self._stop.wait(30)
        while not self._stop.is_set():
            try:
                s = self.settings_fn()
                step = int(s.get("agg_step_sec", 300))
                n = db.downsample(step,
                                  int(s.get("raw_retention_hours", 24)),
                                  int(s.get("agg_retention_days", 7)))
                if n:
                    print(f"[downsampler] 聚合 {n} 行，清理过期数据", flush=True)
            except Exception as e:
                print(f"[downsampler] 异常: {e}", flush=True)
            self._stop.wait(int(self.settings_fn().get("agg_step_sec", 300)))

    def stop(self) -> None:
        self._stop.set()
