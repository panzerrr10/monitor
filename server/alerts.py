"""告警引擎

核心是一个**状态机**，而不是「超阈值就报」：

    条件满足            持续超过 duration_sec
 OK ─────────→ PENDING ────────────────────→ FIRING
  ↑                                             │
  │              条件恢复                        │
  └─────────────── RESOLVED ←───────────────────┘

为什么要 PENDING：
  CPU 瞬冲到 90% 不该报警。只有**持续**超标才升级为 FIRING，
  这就是过滤指标抖动，避免告警刷屏。

三个防噪音机制：
  1. duration（持续时间）—— 过滤抖动
  2. 去重 —— 同一规则同一主机只保留一条 firing，不重复创建
  3. 抑制 —— 主机离线时，抑制它上面所有指标类告警（否则断网一次炸出 6 条）
"""
from __future__ import annotations

import threading
import time
from typing import Callable

import db

OPS = {
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


class AlertEngine(threading.Thread):
    def __init__(self, settings_fn: Callable[[], dict],
                 broadcast: Callable[[str, dict], None]) -> None:
        super().__init__(daemon=True, name="alert-engine")
        self.settings_fn = settings_fn
        self.broadcast = broadcast
        self._stop = threading.Event()

    # --------------------------------------------------
    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.evaluate()
            except Exception as e:                      # 引擎不能因为一次异常就死掉
                print(f"[alerts] 评估异常: {e}", flush=True)
            self._stop.wait(int(self.settings_fn().get("eval_interval_sec", 5)))

    def stop(self) -> None:
        self._stop.set()

    # --------------------------------------------------
    def evaluate(self) -> None:
        s = self.settings_fn()
        offline_after = int(s.get("offline_after_sec", 60))
        now = int(time.time())

        hosts = db.list_hosts()
        rules = [r for r in db.list_rules() if r["enabled"]]
        latest = db.latest_all()

        for host in hosts:
            hid = host["id"]

            # monitor=0 的主机（手动添加、只做 SSH 运维）不参与任何告警评估，
            # 否则一台没装 agent 的机器会永远报「主机离线」
            if not host.get("monitor", 1):
                for rule in rules:
                    self._clear(rule, host)
                continue

            last_seen = host.get("last_seen") or 0
            offline = (now - last_seen) > offline_after

            metrics = dict(latest.get(hid, {}))
            metrics["agent_up"] = 0.0 if offline else 1.0

            for rule in rules:
                metric = rule["metric"]

                # ---- 抑制：主机离线时，只有「主机离线」这条规则生效 ----
                if offline and metric != "agent_up":
                    self._clear(rule, host)
                    continue

                if metric not in metrics:
                    # 指标还没上报（刚加的主机），跳过
                    continue

                value = float(metrics[metric])
                matched = OPS.get(rule["op"], OPS[">"])(value, float(rule["threshold"]))
                self._transition(rule, host, value, matched, now)

    # --------------------------------------------------
    def _transition(self, rule: dict, host: dict, value: float,
                    matched: bool, now: int) -> None:
        st = db.get_state(rule["id"], host["id"])
        state = st["state"] if st else "ok"
        since = st["since"] if st else now

        if matched:
            if state == "ok":
                # 刚满足条件 → 进入 PENDING（开始计时，先不报）
                db.set_state(rule["id"], host["id"], "pending", now, value)
                self.broadcast("alert_pending", {
                    "rule_id": rule["id"], "host_id": host["id"],
                    "rule_name": rule["name"], "value": value,
                })
            elif state == "pending":
                if now - since >= int(rule["duration_sec"]):
                    # 持续够久 → 正式 FIRING
                    db.set_state(rule["id"], host["id"], "firing", since, value)
                    self._fire(rule, host, value)
                else:
                    db.set_state(rule["id"], host["id"], "pending", since, value)
            else:  # firing：只更新最新值
                db.set_state(rule["id"], host["id"], "firing", since, value)
        else:
            if state in ("pending", "firing"):
                if state == "firing":
                    self._resolve(rule, host, value)
                db.set_state(rule["id"], host["id"], "ok", now, value)

    # --------------------------------------------------
    def _fire(self, rule: dict, host: dict, value: float) -> None:
        # 去重：已经有这条告警在 firing 就不重复创建
        if db.open_alert_for(rule["id"], host["id"]):
            return
        aid = db.create_alert(rule, host["id"], host["name"] or host["id"], value)
        alert = db.get_alert(aid) or {}
        print(f"[alerts] 🔴 FIRING  {rule['name']} @ {host['name']} = {value}", flush=True)
        self.broadcast("alert_firing", alert)

    def _resolve(self, rule: dict, host: dict, value: float) -> None:
        a = db.open_alert_for(rule["id"], host["id"])
        if not a:
            return
        db.resolve_alert(a["id"])
        print(f"[alerts] ✅ RESOLVED {rule['name']} @ {host['name']} = {value}", flush=True)
        self.broadcast("alert_resolved", {"id": a["id"], "rule_name": rule["name"],
                                          "host_name": host["name"], "value": value})

    def _clear(self, rule: dict, host: dict) -> None:
        """抑制时把该规则的状态清回 ok（如果之前在 pending/firing）"""
        st = db.get_state(rule["id"], host["id"])
        if st and st["state"] != "ok":
            if st["state"] == "firing":
                a = db.open_alert_for(rule["id"], host["id"])
                if a:
                    db.resolve_alert(a["id"])
                    self.broadcast("alert_resolved", {"id": a["id"], "rule_name": rule["name"],
                                                      "host_name": host["name"], "value": None})
            db.set_state(rule["id"], host["id"], "ok", int(time.time()), 0.0)
