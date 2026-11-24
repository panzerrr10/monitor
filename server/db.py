"""存储层：SQLite（WAL 模式）

表设计说明：
  hosts        主机注册表（agent 第一次上报时自动注册）
  metrics_raw  原始指标点（保留 24h，用于精确曲线）
  metrics_agg  5 分钟聚合点（保留 7d，用于长期趋势）
  rules        告警规则（页面可改）
  alerts       告警事件（每次 firing 一条，恢复时回填 resolved_at）
  alert_state  引擎内部状态机（避免重启丢掉 pending 计时）
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, "data", "monitor.db")


@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=8000")
        yield c
        c.commit()
    finally:
        c.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id            TEXT PRIMARY KEY,
    name          TEXT,
    info_json     TEXT,
    in_container  INTEGER DEFAULT 0,
    cpu_cores     REAL DEFAULT 1,
    first_seen    INTEGER,
    last_seen     INTEGER,
    -- source: agent（采集端上报时自动注册）/ manual（页面手动添加，纯 SSH）
    source        TEXT DEFAULT 'agent',
    -- monitor: 1=参与采集与告警评估；0=只做 SSH 运维，不产生任何告警
    monitor       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS metrics_raw (
    host_id TEXT NOT NULL,
    metric  TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    value   REAL,
    PRIMARY KEY (host_id, metric, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_raw_ts ON metrics_raw(ts);

CREATE TABLE IF NOT EXISTS metrics_agg (
    host_id TEXT NOT NULL,
    metric  TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    value   REAL,
    PRIMARY KEY (host_id, metric, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    metric       TEXT NOT NULL,
    op           TEXT NOT NULL,
    threshold    REAL NOT NULL,
    duration_sec INTEGER NOT NULL DEFAULT 60,
    severity     TEXT NOT NULL DEFAULT 'warning',
    enabled      INTEGER NOT NULL DEFAULT 1,
    builtin      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER,
    rule_name   TEXT,
    host_id     TEXT,
    host_name   TEXT,
    metric      TEXT,
    op          TEXT,
    threshold   REAL,
    severity    TEXT,
    status      TEXT NOT NULL,
    value       REAL,
    started_at  INTEGER,
    resolved_at INTEGER,
    acked       INTEGER DEFAULT 0,
    acked_at    INTEGER,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, started_at DESC);

CREATE TABLE IF NOT EXISTS alert_state (
    rule_id    INTEGER NOT NULL,
    host_id    TEXT NOT NULL,
    state      TEXT NOT NULL,
    since      INTEGER NOT NULL,
    last_value REAL,
    PRIMARY KEY (rule_id, host_id)
);

-- 远程运维：每台主机的 SSH 连接参数（只存密钥路径，不存密码）
CREATE TABLE IF NOT EXISTS host_creds (
    host_id   TEXT PRIMARY KEY,
    ssh_host  TEXT,
    ssh_user  TEXT,
    ssh_port  INTEGER DEFAULT 22,
    key_path  TEXT,
    os_type   TEXT DEFAULT 'linux',
    enabled   INTEGER DEFAULT 1
);

-- 远程运维：命令审计日志
CREATE TABLE IF NOT EXISTS command_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     TEXT,
    host_name   TEXT,
    kind        TEXT,
    cmd         TEXT,
    rc          INTEGER,
    output      TEXT,
    ts          INTEGER,
    duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cmdlog_ts ON command_log(ts DESC);

-- 远程运维：快捷任务（可在页面里开关）
CREATE TABLE IF NOT EXISTS quick_tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    cmd_linux   TEXT,
    cmd_windows TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    builtin     INTEGER NOT NULL DEFAULT 0,
    sort        INTEGER NOT NULL DEFAULT 0
);
"""

# 预置运维快捷任务：Linux / Windows 各一套命令，页面里可开关
BUILTIN_TASKS = [
    ("磁盘使用",
     "df -h",
     "Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free -AutoSize"),
    ("内存使用",
     "free -h",
     "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List"),
    ("系统信息",
     "uname -a; echo; id; echo; uptime",
     "$env:COMPUTERNAME; [Environment]::OSVersion.VersionString; Get-Date"),
    ("CPU Top 10",
     "ps aux --sort=-%cpu | head -11",
     "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,CPU,WS | Format-Table -AutoSize"),
    ("大目录 Top 10",
     "du -ah / 2>/dev/null | sort -rh | head -10",
     "Get-ChildItem C:/ -Directory | ForEach-Object { $s=(Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; [PSCustomObject]@{Dir=$_.Name; GB=[math]::Round($s/1GB,2)} } | Sort-Object GB -Descending | Select-Object -First 10 | Format-Table -AutoSize"),
    ("失败的服务",
     "systemctl list-units --failed --no-pager",
     "Get-Service | Where-Object {$_.Status -eq 'Stopped'} | Select-Object -First 20 Name,DisplayName | Format-Table -AutoSize"),
    ("最近日志",
     "journalctl -n 50 --no-pager 2>/dev/null || tail -n 50 /var/log/syslog",
     "Get-WinEvent -LogName System -MaxEvents 30 | Format-Table TimeCreated,Id,LevelDisplayName -AutoSize"),
    ("监听端口",
     "ss -lntp 2>/dev/null || netstat -lntp",
     "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize"),
    ("网络连通",
     "ping -c 4 223.5.5.5",
     "Test-Connection 223.5.5.5 -Count 4"),
]

# 内置规则：第一次初始化时写入（builtin=1，页面可改阈值但建议保留该条）
BUILTIN_RULES = [
    # 名称,           指标,              运算符, 阈值,  持续时间, 级别
    ("主机离线",       "agent_up",        "<",    1,     30,       "critical"),
    ("CPU 使用率过高", "cpu_pct",         ">",    85,    120,      "warning"),
    ("内存使用率过高", "mem_pct",         ">",    90,    120,      "warning"),
    ("磁盘使用率过高", "disk_pct",        ">",    85,    300,      "warning"),
    ("磁盘即将写满",   "disk_pct",        ">",    95,    60,       "critical"),
    ("系统负载过高",   "load1_per_core",  ">",    2.0,   300,      "warning"),
]


def init() -> None:
    with conn() as c:
        c.executescript(SCHEMA)
        # 轻量迁移：老版本库里没有 ssh_host 列
        cols = {r[1] for r in c.execute("PRAGMA table_info(host_creds)").fetchall()}
        if "ssh_host" not in cols:
            c.execute("ALTER TABLE host_creds ADD COLUMN ssh_host TEXT")
        acols = {r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()}
        if "note" not in acols:
            c.execute("ALTER TABLE alerts ADD COLUMN note TEXT")
        hcols = {r[1] for r in c.execute("PRAGMA table_info(hosts)").fetchall()}
        if "source" not in hcols:
            c.execute("ALTER TABLE hosts ADD COLUMN source TEXT DEFAULT 'agent'")
        if "monitor" not in hcols:
            c.execute("ALTER TABLE hosts ADD COLUMN monitor INTEGER DEFAULT 1")

        if c.execute("SELECT COUNT(*) FROM quick_tasks").fetchone()[0] == 0:
            c.executemany(
                "INSERT INTO quick_tasks(name, cmd_linux, cmd_windows, enabled, builtin, sort)"
                " VALUES (?,?,?,1,1,?)",
                [(n, l, w, i) for i, (n, l, w) in enumerate(BUILTIN_TASKS)],
            )
        n = c.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        if n == 0:
            c.executemany(
                "INSERT INTO rules(name, metric, op, threshold, duration_sec, severity, enabled, builtin)"
                " VALUES (?,?,?,?,?,?,1,1)",
                BUILTIN_RULES,
            )


# ============================================================
#  主机
# ============================================================
def upsert_host(host_id: str, info: dict, in_container: bool, cpu_cores: float) -> None:
    now = int(time.time())
    with conn() as c:
        row = c.execute("SELECT id FROM hosts WHERE id=?", (host_id,)).fetchone()
        if row:
            c.execute(
                "UPDATE hosts SET info_json=?, in_container=?, cpu_cores=?, last_seen=? WHERE id=?",
                (json.dumps(info, ensure_ascii=False), int(in_container), cpu_cores, now, host_id),
            )
        else:
            c.execute(
                "INSERT INTO hosts(id, name, info_json, in_container, cpu_cores, first_seen, last_seen)"
                " VALUES (?,?,?,?,?,?,?)",
                (host_id, info.get("hostname") or host_id, json.dumps(info, ensure_ascii=False),
                 int(in_container), cpu_cores, now, now),
            )


def list_hosts() -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT * FROM hosts ORDER BY name").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["info"] = json.loads(d.pop("info_json") or "{}")
        except json.JSONDecodeError:
            d["info"] = {}
        out.append(d)
    return out


def rename_host(host_id: str, name: str) -> None:
    with conn() as c:
        c.execute("UPDATE hosts SET name=? WHERE id=?", (name, host_id))


def delete_host(host_id: str, purge_alerts: bool = False) -> None:
    """把主机从监控里移除。

    默认**保留历史告警**（purge_alerts=False）——出过什么事还能回查。
    连接配置（host_creds）一并删除，否则下次添加同名主机会带着旧参数。
    """
    with conn() as c:
        c.execute("DELETE FROM hosts WHERE id=?", (host_id,))
        c.execute("DELETE FROM metrics_raw WHERE host_id=?", (host_id,))
        c.execute("DELETE FROM metrics_agg WHERE host_id=?", (host_id,))
        c.execute("DELETE FROM alert_state WHERE host_id=?", (host_id,))
        c.execute("DELETE FROM host_creds WHERE host_id=?", (host_id,))
        if purge_alerts:
            c.execute("DELETE FROM alerts WHERE host_id=?", (host_id,))


# ============================================================
#  主机：手动新增 / 修改（对应页面的「新增主机」「编辑」）
# ============================================================
def create_host(host_id: str, name: str, monitor: bool = False,
                cpu_cores: float = 1) -> None:
    """手动添加一台主机（不依赖 agent 上报）。

    monitor=False 表示"只做 SSH 运维"：不会触发任何告警（包括离线告警）。
    """
    now = int(time.time())
    with conn() as c:
        c.execute(
            "INSERT INTO hosts(id, name, info_json, in_container, cpu_cores,"
            " first_seen, last_seen, source, monitor) VALUES (?,?,?,?,?,?,NULL,'manual',?)",
            (host_id, name, json.dumps({}, ensure_ascii=False), 0, cpu_cores, now,
             1 if monitor else 0),
        )


def update_host(host_id: str, name: str | None = None,
                monitor: bool | None = None) -> None:
    sets, vals = [], []
    if name is not None:
        sets.append("name=?")
        vals.append(name)
    if monitor is not None:
        sets.append("monitor=?")
        vals.append(1 if monitor else 0)
    if not sets:
        return
    vals.append(host_id)
    with conn() as c:
        c.execute(f"UPDATE hosts SET {', '.join(sets)} WHERE id=?", vals)


def delete_creds(host_id: str) -> None:
    with conn() as c:
        c.execute("DELETE FROM host_creds WHERE host_id=?", (host_id,))


def host_exists(host_id: str) -> bool:
    with conn() as c:
        return c.execute("SELECT 1 FROM hosts WHERE id=?", (host_id,)).fetchone() is not None


# ============================================================
#  指标
# ============================================================
def insert_metrics(host_id: str, ts: int, metrics: dict[str, float]) -> int:
    rows = [(host_id, k, ts, float(v)) for k, v in metrics.items()
            if isinstance(v, (int, float))]
    if not rows:
        return 0
    with conn() as c:
        c.executemany(
            "INSERT OR REPLACE INTO metrics_raw(host_id, metric, ts, value) VALUES (?,?,?,?)", rows
        )
    return len(rows)


def latest_metrics(host_id: str) -> dict[str, float]:
    """取每台主机每个指标的最后一条值"""
    with conn() as c:
        rows = c.execute(
            "SELECT metric, value, ts FROM metrics_raw WHERE host_id=?"
            " AND ts=(SELECT MAX(ts) FROM metrics_raw r2"
            "         WHERE r2.host_id=metrics_raw.host_id AND r2.metric=metrics_raw.metric)",
            (host_id,),
        ).fetchall()
    return {r["metric"]: r["value"] for r in rows}


def latest_all() -> dict[str, dict[str, float]]:
    with conn() as c:
        rows = c.execute(
            "SELECT m.host_id, m.metric, m.value FROM metrics_raw m"
            " JOIN (SELECT host_id, metric, MAX(ts) AS ts FROM metrics_raw GROUP BY host_id, metric) t"
            "   ON m.host_id=t.host_id AND m.metric=t.metric AND m.ts=t.ts"
        ).fetchall()
    out: dict[str, dict[str, float]] = {}
    for r in rows:
        out.setdefault(r["host_id"], {})[r["metric"]] = r["value"]
    return out


def history(host_id: str, metric: str, start_ts: int, end_ts: int,
            max_points: int = 600) -> tuple[list[list], str]:
    """返回 ([[ts_ms, value], ...], 数据来源)

    策略：优先查原始表；如果查询范围内原始数据的基本没有，就回退到聚合表。
    """
    with conn() as c:
        rows = c.execute(
            "SELECT ts, value FROM metrics_raw WHERE host_id=? AND metric=? AND ts>=? AND ts<=?"
            " ORDER BY ts",
            (host_id, metric, start_ts, end_ts),
        ).fetchall()
        if len(rows) >= 2:
            pts = [[r["ts"] * 1000, None if r["value"] is None else round(r["value"], 2)]
                   for r in rows]
            return _thin(pts, max_points), "raw"

        rows = c.execute(
            "SELECT ts, value FROM metrics_agg WHERE host_id=? AND metric=? AND ts>=? AND ts<=?"
            " ORDER BY ts",
            (host_id, metric, start_ts, end_ts),
        ).fetchall()
    pts = [[r["ts"] * 1000, None if r["value"] is None else round(r["value"], 2)] for r in rows]
    return _thin(pts, max_points), "agg"


def _thin(pts: list[list], max_points: int) -> list[list]:
    if len(pts) <= max_points:
        return pts
    step = len(pts) / max_points
    return [pts[int(i * step)] for i in range(max_points)]


# ============================================================
#  规则
# ============================================================
def list_rules() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM rules ORDER BY id").fetchall()]


def get_rule(rule_id: int) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    return dict(r) if r else None


def add_rule(name: str, metric: str, op: str, threshold: float,
             duration_sec: int, severity: str) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO rules(name, metric, op, threshold, duration_sec, severity, enabled, builtin)"
            " VALUES (?,?,?,?,?,?,1,0)",
            (name, metric, op, threshold, duration_sec, severity),
        )
        return int(cur.lastrowid)


def update_rule(rule_id: int, fields: dict[str, Any]) -> bool:
    allowed = {"name", "metric", "op", "threshold", "duration_sec", "severity", "enabled"}
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k}=?")
            vals.append(v)
    if not sets:
        return False
    vals.append(rule_id)
    with conn() as c:
        c.execute(f"UPDATE rules SET {', '.join(sets)} WHERE id=?", vals)
    return True


def delete_rule(rule_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM rules WHERE id=? AND builtin=0", (rule_id,))
        c.execute("DELETE FROM alert_state WHERE rule_id=?", (rule_id,))


# ============================================================
#  告警
# ============================================================
def active_alerts(include_acked: bool = False) -> list[dict]:
    """当前正在告的警。

    include_acked=False（默认）时**排除已确认的**：
    「确认」的语义就是「我看到了，别再弹了」，所以确认后应从顶部横幅和
    概览的告警计数里消失（但记录本身还在，告警页仍能查到、仍会正常恢复）。
    """
    sql = ("SELECT * FROM alerts WHERE status='firing'"
           + ("" if include_acked else " AND IFNULL(acked,0)=0")
           + " ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, started_at DESC")
    with conn() as c:
        rows = c.execute(sql).fetchall()
    return [dict(r) for r in rows]


def recent_alerts(limit: int = 100) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT * FROM alerts ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def open_alert_for(rule_id: int, host_id: str) -> dict | None:
    with conn() as c:
        r = c.execute(
            "SELECT * FROM alerts WHERE rule_id=? AND host_id=? AND status='firing' LIMIT 1",
            (rule_id, host_id),
        ).fetchone()
    return dict(r) if r else None


def create_alert(rule: dict, host_id: str, host_name: str, value: float) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO alerts(rule_id, rule_name, host_id, host_name, metric, op, threshold,"
            " severity, status, value, started_at) VALUES (?,?,?,?,?,?,?,?, 'firing', ?, ?)",
            (rule["id"], rule["name"], host_id, host_name, rule["metric"], rule["op"],
             rule["threshold"], rule["severity"], value, int(time.time())),
        )
        return int(cur.lastrowid)


def resolve_alert(alert_id: int) -> None:
    """恢复告警。

    注意：**不要**用恢复时的值覆盖 value —— value 记录的是「触发时」的指标值，
    否则离线告警恢复后 value 会变成 1（在线），语义就错了。
    """
    with conn() as c:
        c.execute(
            "UPDATE alerts SET status='resolved', resolved_at=? WHERE id=?",
            (int(time.time()), alert_id),
        )


def ack_alert(alert_id: int) -> None:
    with conn() as c:
        c.execute("UPDATE alerts SET acked=1, acked_at=? WHERE id=?",
                  (int(time.time()), alert_id))


def get_alert(alert_id: int) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return dict(r) if r else None


# ============================================================
#  告警引擎状态
# ============================================================
def get_state(rule_id: int, host_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM alert_state WHERE rule_id=? AND host_id=?",
                      (rule_id, host_id)).fetchone()
    return dict(r) if r else None


def set_state(rule_id: int, host_id: str, state: str, since: int, value: float) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO alert_state(rule_id, host_id, state, since, last_value) VALUES (?,?,?,?,?)"
            " ON CONFLICT(rule_id, host_id) DO UPDATE SET"
            " state=excluded.state, since=excluded.since, last_value=excluded.last_value",
            (rule_id, host_id, state, since, value),
        )


# ============================================================
#  保留策略
# ============================================================
def downsample(step: int, raw_hours: int, agg_days: int) -> int:
    """把原始数据聚合成 5 分钟粒度，并清理过期数据"""
    now = int(time.time())
    raw_cutoff = now - raw_hours * 3600
    agg_cutoff = now - agg_days * 86400
    n = 0
    with conn() as c:
        # 聚合：只处理还没聚合过的桶（最近 2 个 step 之外）
        cur = c.execute(
            "INSERT OR REPLACE INTO metrics_agg(host_id, metric, ts, value)"
            " SELECT host_id, metric, (ts/?)*? AS bucket, AVG(value)"
            " FROM metrics_raw WHERE ts >= ?"
            " GROUP BY host_id, metric, bucket",
            (step, step, raw_cutoff),
        )
        n = cur.rowcount
        c.execute("DELETE FROM metrics_raw WHERE ts < ?", (raw_cutoff,))
        c.execute("DELETE FROM metrics_agg WHERE ts < ?", (agg_cutoff,))
    return n


def stats() -> dict:
    with conn() as c:
        raw = c.execute("SELECT COUNT(*) FROM metrics_raw").fetchone()[0]
        agg = c.execute("SELECT COUNT(*) FROM metrics_agg").fetchone()[0]
        hosts = c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        firing = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='firing' AND IFNULL(acked,0)=0"
        ).fetchone()[0]
        oldest_agg = c.execute("SELECT MIN(ts) FROM metrics_agg").fetchone()[0]
    return {"raw_points": raw, "agg_points": agg, "hosts": hosts,
            "firing_alerts": firing, "oldest_agg": oldest_agg}


# ============================================================
#  远程运维：主机 SSH 连接凭据
#  只存密钥路径，不存密码 —— 密码落库是最常见的运维事故来源之一
# ============================================================
def get_creds(host_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM host_creds WHERE host_id=?", (host_id,)).fetchone()
    return dict(r) if r else None


def list_creds() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM host_creds").fetchall()]


def upsert_creds(host_id: str, ssh_host: str, ssh_user: str, ssh_port: int,
                 key_path: str, os_type: str, enabled: bool) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO host_creds(host_id, ssh_host, ssh_user, ssh_port, key_path, os_type, enabled)"
            " VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(host_id) DO UPDATE SET"
            " ssh_host=excluded.ssh_host, ssh_user=excluded.ssh_user, ssh_port=excluded.ssh_port,"
            " key_path=excluded.key_path, os_type=excluded.os_type, enabled=excluded.enabled",
            (host_id, ssh_host, ssh_user, int(ssh_port), key_path, os_type, 1 if enabled else 0),
        )


# ============================================================
#  远程运维：命令审计
# ============================================================
def log_command(host_id: str, host_name: str, kind: str, cmd: str,
                rc: int | None, output: str, duration_ms: int) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO command_log(host_id, host_name, kind, cmd, rc, output, ts, duration_ms)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (host_id, host_name, kind, cmd, rc, (output or "")[:8000],
             int(time.time()), duration_ms),
        )


def list_commands(limit: int = 100) -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, host_id, host_name, kind, cmd, rc, ts, duration_ms"
            " FROM command_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]


# ============================================================
#  快捷任务
# ============================================================
def list_quick_tasks(enabled_only: bool = False) -> list[dict]:
    q = "SELECT * FROM quick_tasks"
    if enabled_only:
        q += " WHERE enabled=1"
    q += " ORDER BY sort, id"
    with conn() as c:
        return [dict(r) for r in c.execute(q).fetchall()]


def add_quick_task(name: str, cmd_linux: str, cmd_windows: str) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO quick_tasks(name, cmd_linux, cmd_windows, enabled, builtin, sort)"
            " VALUES (?,?,?,1,0,999)", (name, cmd_linux, cmd_windows))
        return int(cur.lastrowid)


def update_quick_task(task_id: int, fields: dict) -> None:
    allowed = {"name", "cmd_linux", "cmd_windows", "enabled", "sort"}
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k}=?")
            vals.append(v)
    if not sets:
        return
    vals.append(task_id)
    with conn() as c:
        c.execute(f"UPDATE quick_tasks SET {', '.join(sets)} WHERE id=?", vals)


def delete_quick_task(task_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM quick_tasks WHERE id=? AND builtin=0", (task_id,))


def get_quick_task(task_id: int) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM quick_tasks WHERE id=?", (task_id,)).fetchone()
    return dict(r) if r else None


# ============================================================
#  告警记录管理
# ============================================================
def _alert_filters(status: str, severity: str, host_id: str, q: str, days: int):
    where, params = [], []
    if status and status != "all":
        where.append("status=?")
        params.append(status)
    if severity and severity != "all":
        where.append("severity=?")
        params.append(severity)
    if host_id:
        where.append("host_id=?")
        params.append(host_id)
    if q:
        where.append("(rule_name LIKE ? OR host_name LIKE ? OR IFNULL(note,'') LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]
    if days and days > 0:
        where.append("started_at >= ?")
        params.append(int(time.time()) - days * 86400)
    return (" WHERE " + " AND ".join(where)) if where else "", params


def list_alerts(status: str = "all", severity: str = "all", host_id: str = "",
                q: str = "", days: int = 0, limit: int = 50, offset: int = 0):
    w, params = _alert_filters(status, severity, host_id, q, days)
    with conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM alerts{w}", params).fetchone()[0]
        rows = c.execute(
            f"SELECT * FROM alerts{w} ORDER BY started_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return [dict(r) for r in rows], total


def delete_alerts(alert_ids: list[int]) -> int:
    if not alert_ids:
        return 0
    marks = ",".join("?" * len(alert_ids))
    with conn() as c:
        cur = c.execute(f"DELETE FROM alerts WHERE id IN ({marks})", alert_ids)
        return cur.rowcount


def set_alert_note(alert_id: int, note: str) -> None:
    with conn() as c:
        c.execute("UPDATE alerts SET note=? WHERE id=?", (note, alert_id))


def alert_stats(days: int = 7) -> dict:
    since = int(time.time()) - days * 86400
    with conn() as c:
        total = c.execute("SELECT COUNT(*) FROM alerts WHERE started_at>=?", (since,)).fetchone()[0]
        firing = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='firing' AND IFNULL(acked,0)=0"
        ).fetchone()[0]
        by_sev = c.execute(
            "SELECT severity, COUNT(*) n FROM alerts WHERE started_at>=? GROUP BY severity",
            (since,)).fetchall()
        by_host = c.execute(
            "SELECT host_name, COUNT(*) n FROM alerts WHERE started_at>=?"
            " GROUP BY host_name ORDER BY n DESC LIMIT 10", (since,)).fetchall()
        by_rule = c.execute(
            "SELECT rule_name, COUNT(*) n FROM alerts WHERE started_at>=?"
            " GROUP BY rule_name ORDER BY n DESC LIMIT 10", (since,)).fetchall()
        daily = c.execute(
            "SELECT date(started_at,'unixepoch','localtime') d, COUNT(*) n"
            " FROM alerts WHERE started_at>=? GROUP BY d ORDER BY d", (since,)).fetchall()
        avg_dur = c.execute(
            "SELECT AVG(resolved_at-started_at) FROM alerts"
            " WHERE started_at>=? AND resolved_at IS NOT NULL", (since,)).fetchone()[0]
    return {
        "days": days,
        "total": total,
        "firing": firing,
        "by_severity": {r["severity"]: r["n"] for r in by_sev},
        "by_host": [{"name": r["host_name"], "n": r["n"]} for r in by_host],
        "by_rule": [{"name": r["rule_name"], "n": r["n"]} for r in by_rule],
        "daily": [{"date": r["d"], "n": r["n"]} for r in daily],
        "avg_duration_sec": int(avg_dur) if avg_dur else None,
    }
