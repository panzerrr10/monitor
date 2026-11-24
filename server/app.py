#!/usr/bin/env python3
"""监控服务端

职责：
  1. 接收采集端上报（POST /api/ingest，Bearer token 鉴权）
  2. 存指标（SQLite，原始 + 聚合两层）
  3. 跑告警引擎（状态机）
  4. 通过 SSE 把「新指标 / 告警变化」实时推给浏览器
  5. 提供页面和 REST API（规则、设置、历史、告警确认）
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import queue
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict

from datetime import timedelta

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session)
from flask_sock import Sock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db                                    # noqa: E402
import sftp_manager                          # noqa: E402
import ssh_manager                           # noqa: E402
from alerts import AlertEngine               # noqa: E402
from downsampler import Downsampler          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")

app = Flask(__name__,
            template_folder=os.path.join(ROOT, "server", "templates"),
            static_folder=os.path.join(ROOT, "server", "static"))
sock = Sock(app)

# ============================================================
#  登录鉴权
#
#  设计：
#    - 密码用 PBKDF2-SHA256（12 万轮）+ 随机盐，**不存明文**
#    - 首次启动自动生成随机密码，写到 config/初始密码.txt（权限 600）
#    - 用 Flask session（签名 Cookie），浏览器关掉就失效
#    - /static 放行（登录页要加载样式），其余全部要登录
# ============================================================
# /api/ingest 走的是 Bearer token 鉴权，不能要求登录会话；
# /api/health 给启动脚本做就绪探测用（只暴露主机数和告警数，无敏感信息）
PUBLIC_PATHS = {"/login", "/api/login", "/api/ingest", "/api/health", "/desktop-login"}

# 桌面版一次性登录票据：桌面外壳用本机令牌换一张票，再用票换会话
# 为什么不用"直接把令牌放 URL"：票是一次性的、60 秒过期，泄露了也没用
_desktop_tickets: dict[str, float] = {}
_ticket_lock = threading.Lock()


def _pbkdf2(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()


def init_auth() -> None:
    s = load_settings()
    auth = s.get("auth") or {}
    changed = False
    if not auth.get("session_secret"):
        auth["session_secret"] = secrets.token_hex(32)
        changed = True
    if not auth.get("local_token"):
        # 给本机命令行工具（status.sh 等）用，避免它们需要输入密码
        auth["local_token"] = secrets.token_hex(24)
        changed = True
    if not auth.get("hash"):
        pwd = secrets.token_urlsafe(9)
        auth["salt"] = secrets.token_hex(16)
        auth["hash"] = _pbkdf2(pwd, auth["salt"])
        auth["enabled"] = True
        changed = True
        path = os.path.join(ROOT, "config", "初始密码.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"监控页面登录密码：{pwd}\n\n登录后可在「设置」页修改。\n")
        os.chmod(path, 0o600)
        print(f"[auth] 已生成初始密码：{pwd}", flush=True)
        print(f"[auth] 同时写在 {path}", flush=True)
    if changed:
        s["auth"] = auth
        save_settings(s)
        refresh_settings()
    app.secret_key = auth["session_secret"]
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)


def auth_enabled() -> bool:
    return bool((settings().get("auth") or {}).get("enabled", True))


def verify_password(pw: str) -> bool:
    auth = settings().get("auth") or {}
    if not auth.get("hash"):
        return False
    return hmac.compare_digest(_pbkdf2(pw, auth.get("salt", "")), auth["hash"])


@app.before_request
def _require_login():
    if not auth_enabled():
        return None
    p = request.path
    if p in PUBLIC_PATHS or p.startswith("/static/"):
        return None
    if session.get("auth") is True:
        return None
    local = (settings().get("auth") or {}).get("local_token")
    if local and hmac.compare_digest(request.headers.get("X-Local-Token", ""), local):
        return None
    if p.startswith("/api/") or p.startswith("/ws/"):
        return jsonify({"error": "未登录或会话已过期，请刷新页面重新登录"}), 401
    return redirect("/login")


@app.get("/login")
def login_page():
    if session.get("auth") is True:
        return redirect("/")
    return render_template("login.html")


@app.post("/api/login")
def api_login():
    b = request.get_json(silent=True) or {}
    if verify_password(str(b.get("password") or "")):
        # 桌面版每次打开都要求登录太烦，所以给 30 天持久会话
        session.permanent = True
        session["auth"] = True
        return jsonify({"ok": True})
    time.sleep(0.6)          # 简单的防爆破：每次失败拖 0.6 秒
    return jsonify({"error": "密码错误"}), 401


@app.post("/api/desktop-ticket")
def api_desktop_ticket():
    """桌面外壳用本机令牌换一次性登录票据"""
    if not auth_enabled():
        return jsonify({"ok": True, "auth_disabled": True})
    local = (settings().get("auth") or {}).get("local_token")
    if not local or not hmac.compare_digest(request.headers.get("X-Local-Token", ""), local):
        return jsonify({"error": "无效的本机令牌"}), 401
    ticket = secrets.token_urlsafe(24)
    now = time.time()
    with _ticket_lock:
        # 顺手清理过期票
        for k, exp in list(_desktop_tickets.items()):
            if exp < now:
                _desktop_tickets.pop(k, None)
        _desktop_tickets[ticket] = now + 60
    return jsonify({"ok": True, "ticket": ticket, "ttl": 60})


@app.get("/desktop-login")
def desktop_login():
    """桌面窗口用票据换会话，然后跳回首页"""
    ticket = request.args.get("ticket", "")
    now = time.time()
    ok = False
    with _ticket_lock:
        exp = _desktop_tickets.pop(ticket, None)      # 用后即焚
        ok = exp is not None and exp >= now
    if ok:
        session.permanent = True
        session["auth"] = True
    return redirect("/")


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/password")
def api_change_password():
    b = request.get_json(silent=True) or {}
    old = str(b.get("old") or "")
    new = str(b.get("new") or "")
    if not verify_password(old):
        return jsonify({"error": "原密码错误"}), 400
    if len(new) < 6:
        return jsonify({"error": "新密码至少 6 位"}), 400
    s = load_settings()
    auth = s.get("auth") or {}
    auth["salt"] = secrets.token_hex(16)
    auth["hash"] = _pbkdf2(new, auth["salt"])
    s["auth"] = auth
    save_settings(s)
    refresh_settings()
    return jsonify({"ok": True})

# ============================================================
#  设置
# ============================================================
_settings_lock = threading.Lock()


def load_settings() -> dict:
    # 首次运行（git clone 后没有 settings.json）：从示例复制一份落盘，
    # 之后 init_auth() 会在里面生成随机会话密钥与初始登录密码。
    # 这样仓库里不需要提交任何真实密钥，克隆下来也能直接跑起来。
    if not os.path.exists(SETTINGS_PATH):
        example = os.path.join(os.path.dirname(SETTINGS_PATH), "settings.example.json")
        with open(example, encoding="utf-8") as f:
            data = json.load(f)
        save_settings(data)
        print(f"[config] 未找到 settings.json，已从示例生成：{SETTINGS_PATH}", flush=True)
        return data
    with open(SETTINGS_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_settings(data: dict) -> None:
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_PATH)


_set_cache: dict = {}
_set_cache_ts = 0.0


def settings() -> dict:
    """带缓存的读取（告警引擎每秒都会读，别每次都碰磁盘）"""
    global _set_cache, _set_cache_ts
    now = time.time()
    if not _set_cache or now - _set_cache_ts > 2:
        _set_cache = load_settings()
        _set_cache_ts = now
    return _set_cache


def refresh_settings() -> dict:
    global _set_cache_ts
    _set_cache_ts = 0
    return settings()


# ============================================================
#  SSE 广播
# ============================================================
class Hub:
    def __init__(self) -> None:
        self._subs: set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def publish(self, event: str, data: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait((event, data))
            except queue.Full:
                pass


hub = Hub()


# ============================================================
#  鉴权
# ============================================================
def check_token() -> bool:
    auth = request.headers.get("Authorization", "")
    expect = settings().get("ingest_token", "")
    if not expect:
        return False
    return auth == "Bearer " + expect


# ============================================================
#  采集上报
# ============================================================
@app.post("/api/ingest")
def api_ingest():
    if not check_token():
        return jsonify({"error": "token 无效"}), 401

    body = request.get_json(silent=True) or {}
    host_id = str(body.get("host_id") or "").strip()
    metrics = body.get("metrics")
    if not host_id or not isinstance(metrics, dict):
        return jsonify({"error": "host_id 和 metrics 必填"}), 400

    ts = int(body.get("ts") or time.time())
    info = body.get("info") or {}
    cores = float(body.get("cpu_cores") or 1)
    in_container = bool(body.get("in_container"))

    db.upsert_host(host_id, info, in_container, cores)
    n = db.insert_metrics(host_id, ts, metrics)

    # 顺带把「这台主机最近一次的全量指标」推给前端
    hub.publish("metrics", {
        "host_id": host_id,
        "ts": ts,
        "metrics": metrics,
        "in_container": in_container,
        "cpu_cores": cores,
    })

    return jsonify({"ok": True, "stored": n,
                    "interval": int(settings().get("interval_sec", 10))})


# ============================================================
#  概览 / 历史
# ============================================================
def _host_view() -> list[dict]:
    s = settings()
    offline_after = int(s.get("offline_after_sec", 60))
    now = int(time.time())
    latest = db.latest_all()
    out = []
    for h in db.list_hosts():
        m = latest.get(h["id"], {})
        last_seen = h.get("last_seen") or 0
        out.append({
            "id": h["id"],
            "name": h["name"] or h["id"],
            "source": h.get("source") or "agent",
            "monitor": bool(h.get("monitor", 1)),
            "info": h.get("info", {}),
            "in_container": bool(h.get("in_container")),
            "cpu_cores": h.get("cpu_cores"),
            "last_seen": last_seen,
            "age_sec": now - last_seen if last_seen else None,
            "online": bool(last_seen) and (now - last_seen) <= offline_after,
            "metrics": m,
        })
    return out


@app.get("/api/overview")
def api_overview():
    return jsonify({
        "hosts": _host_view(),
        "alerts": db.active_alerts(),
        "rules": db.list_rules(),
        "stats": db.stats(),
        "settings": settings(),
    })


@app.get("/api/hosts")
def api_hosts():
    return jsonify(_host_view())


@app.get("/api/history")
def api_history():
    host_id = request.args.get("host_id", "")
    metric = request.args.get("metric", "cpu_pct")
    hours = float(request.args.get("hours", "1"))
    if not host_id:
        return jsonify({"error": "host_id 必填"}), 400
    end = int(time.time())
    start = end - int(hours * 3600)
    pts, source = db.history(host_id, metric, start, end)
    return jsonify({"points": pts, "source": source, "metric": metric,
                    "hours": hours})


# ============================================================
#  告警
# ============================================================
@app.get("/api/alerts")
def api_alerts():
    scope = request.args.get("scope", "active")
    if scope == "all":
        return jsonify({"active": db.active_alerts(), "recent": db.recent_alerts(200)})
    return jsonify(db.active_alerts())


@app.post("/api/alerts/<int:alert_id>/ack")
def api_alert_ack(alert_id: int):
    if not db.get_alert(alert_id):
        return jsonify({"error": "告警不存在"}), 404
    db.ack_alert(alert_id)
    hub.publish("alert_acked", {"id": alert_id})
    return jsonify({"ok": True})


# ============================================================
#  告警记录管理（筛选 / 确认 / 备注 / 删除 / 导出 / 统计）
# ============================================================
def _int_param(name: str, default: int, lo: int = 0, hi: int = 100000) -> int:
    try:
        v = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


@app.get("/api/alerts/records")
def api_alerts_records():
    status = request.args.get("status", "all")
    severity = request.args.get("severity", "all")
    host_id = request.args.get("host_id", "")
    q = request.args.get("q", "").strip()
    days = _int_param("days", 0, 0, 3650)
    limit = _int_param("limit", 50, 1, 500)
    offset = _int_param("offset", 0, 0, 10_000_000)

    rows, total = db.list_alerts(status, severity, host_id, q, days, limit, offset)
    return jsonify({"rows": rows, "total": total, "limit": limit, "offset": offset})


@app.get("/api/alerts/stats")
def api_alerts_stats():
    return jsonify(db.alert_stats(_int_param("days", 7, 1, 3650)))


@app.post("/api/alerts/<int:alert_id>/note")
def api_alert_note(alert_id: int):
    if not db.get_alert(alert_id):
        return jsonify({"error": "告警不存在"}), 404
    b = request.get_json(silent=True) or {}
    note = str(b.get("note") or "")[:1000]
    db.set_alert_note(alert_id, note)
    return jsonify({"ok": True})


@app.delete("/api/alerts/<int:alert_id>")
def api_alert_delete(alert_id: int):
    if not db.get_alert(alert_id):
        return jsonify({"error": "告警不存在"}), 404
    db.delete_alerts([alert_id])
    return jsonify({"ok": True})


@app.post("/api/alerts/bulk-delete")
def api_alerts_bulk_delete():
    b = request.get_json(silent=True) or {}
    ids = b.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"error": "ids 必填"}), 400
    try:
        ids = [int(i) for i in ids]
    except (TypeError, ValueError):
        return jsonify({"error": "ids 必须是整数数组"}), 400
    n = db.delete_alerts(ids)
    return jsonify({"ok": True, "deleted": n})


@app.get("/api/alerts/export.csv")
def api_alerts_export():
    status = request.args.get("status", "all")
    severity = request.args.get("severity", "all")
    host_id = request.args.get("host_id", "")
    q = request.args.get("q", "").strip()
    days = _int_param("days", 0, 0, 3650)
    rows, _ = db.list_alerts(status, severity, host_id, q, days, 100000, 0)

    buf = io.StringIO()
    buf.write("\ufeff")          # BOM，Excel 打开中文不乱码
    w = csv.writer(buf)
    w.writerow(["ID", "规则", "主机", "级别", "状态", "指标", "条件",
                "触发值", "开始时间", "恢复时间", "持续(秒)", "是否确认", "备注"])
    for a in rows:
        dur = (a["resolved_at"] - a["started_at"]) if a.get("resolved_at") else ""
        w.writerow([
            a["id"], a["rule_name"], a["host_name"], a["severity"],
            "进行中" if a["status"] == "firing" else "已恢复",
            a["metric"], f'{a["metric"]} {a["op"]} {a["threshold"]}',
            a["value"],
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["started_at"] or 0)),
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["resolved_at"])) if a.get("resolved_at") else "",
            dur, "是" if a.get("acked") else "否", a.get("note") or "",
        ])
    fn = f"alerts-{time.strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8", headers={
        "Content-Disposition": f"attachment; filename={fn}",
    })


# ============================================================
#  规则
# ============================================================
VALID_OPS = {">", ">=", "<", "<=", "==", "!="}
VALID_SEV = {"warning", "critical"}


@app.get("/api/rules")
def api_rules():
    return jsonify(db.list_rules())


@app.post("/api/rules")
def api_rule_add():
    b = request.get_json(silent=True) or {}
    try:
        name = str(b["name"]).strip()
        metric = str(b["metric"]).strip()
        op = str(b["op"]).strip()
        threshold = float(b["threshold"])
        duration = int(b.get("duration_sec", 60))
        severity = str(b.get("severity", "warning"))
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "参数不完整或类型错误"}), 400
    if not name or not metric:
        return jsonify({"error": "名称和指标不能为空"}), 400
    if op not in VALID_OPS:
        return jsonify({"error": f"运算符必须是 {sorted(VALID_OPS)}"}), 400
    if severity not in VALID_SEV:
        return jsonify({"error": "级别必须是 warning / critical"}), 400
    if duration < 0 or duration > 86400:
        return jsonify({"error": "持续时间 0~86400 秒"}), 400
    rid = db.add_rule(name, metric, op, threshold, duration, severity)
    hub.publish("rules_changed", {"action": "add", "id": rid})
    return jsonify({"ok": True, "id": rid})


@app.put("/api/rules/<int:rule_id>")
def api_rule_update(rule_id: int):
    if not db.get_rule(rule_id):
        return jsonify({"error": "规则不存在"}), 404
    b = request.get_json(silent=True) or {}
    fields: dict = {}
    if "name" in b:
        fields["name"] = str(b["name"]).strip()
    if "metric" in b:
        fields["metric"] = str(b["metric"]).strip()
    if "op" in b:
        if b["op"] not in VALID_OPS:
            return jsonify({"error": "非法运算符"}), 400
        fields["op"] = b["op"]
    if "threshold" in b:
        try:
            fields["threshold"] = float(b["threshold"])
        except (TypeError, ValueError):
            return jsonify({"error": "阈值必须是数字"}), 400
    if "duration_sec" in b:
        try:
            fields["duration_sec"] = int(b["duration_sec"])
        except (TypeError, ValueError):
            return jsonify({"error": "持续时间必须是整数"}), 400
    if "severity" in b:
        if b["severity"] not in VALID_SEV:
            return jsonify({"error": "非法级别"}), 400
        fields["severity"] = b["severity"]
    if "enabled" in b:
        fields["enabled"] = 1 if b["enabled"] else 0
    if not fields:
        return jsonify({"error": "没有要修改的字段"}), 400
    db.update_rule(rule_id, fields)
    hub.publish("rules_changed", {"action": "update", "id": rule_id})
    return jsonify({"ok": True})


@app.delete("/api/rules/<int:rule_id>")
def api_rule_delete(rule_id: int):
    r = db.get_rule(rule_id)
    if not r:
        return jsonify({"error": "规则不存在"}), 404
    if r["builtin"]:
        return jsonify({"error": "内置规则不能删除，可以停用"}), 400
    db.delete_rule(rule_id)
    hub.publish("rules_changed", {"action": "delete", "id": rule_id})
    return jsonify({"ok": True})


# ============================================================
#  设置
# ============================================================
@app.get("/api/settings")
def api_settings_get():
    return jsonify(settings())


@app.post("/api/settings")
def api_settings_post():
    b = request.get_json(silent=True) or {}
    cur = load_settings()
    rules: dict[str, tuple[int, int]] = {
        "interval_sec": (1, 3600),
        "raw_retention_hours": (1, 720),
        "agg_retention_days": (1, 365),
        "agg_step_sec": (60, 86400),
        "offline_after_sec": (10, 3600),
        "eval_interval_sec": (1, 60),
    }
    changed = []
    for k, (lo, hi) in rules.items():
        if k in b:
            try:
                v = int(b[k])
            except (TypeError, ValueError):
                return jsonify({"error": f"{k} 必须是整数"}), 400
            if not (lo <= v <= hi):
                return jsonify({"error": f"{k} 必须在 {lo}~{hi} 之间"}), 400
            if cur.get(k) != v:
                changed.append(k)
            cur[k] = v
    if "ingest_token" in b:
        tok = str(b["ingest_token"]).strip()
        if len(tok) < 6:
            return jsonify({"error": "token 至少 6 个字符"}), 400
        cur["ingest_token"] = tok
        changed.append("ingest_token")
    if not changed:
        return jsonify({"ok": True, "changed": [], "message": "没有变化"})
    save_settings(cur)
    refresh_settings()
    hub.publish("settings_changed", {"changed": changed})
    hint = ""
    if "interval_sec" in changed:
        hint = "（采集周期会在采集端下一次上报后生效）"
    if "ingest_token" in changed:
        hint += "（token 改了，采集端必须同步修改，否则会被 401 拒绝）"
    return jsonify({"ok": True, "changed": changed,
                    "message": "已保存：" + ", ".join(changed) + hint})


@app.post("/api/hosts/<host_id>/rename")
def api_host_rename(host_id: str):
    b = request.get_json(silent=True) or {}
    name = str(b.get("name", "")).strip()
    if not name:
        return jsonify({"error": "名称不能为空"}), 400
    db.rename_host(host_id, name)
    return jsonify({"ok": True})


@app.delete("/api/hosts/<host_id>")
def api_host_delete(host_id: str):
    db.delete_host(host_id)
    return jsonify({"ok": True})


# ============================================================
#  SSE
# ============================================================
@app.get("/api/stream")
def api_stream():
    def gen():
        q = hub.subscribe()
        try:
            # 连上先发一份全量快照，避免前端要额外请求
            yield _sse("snapshot", {
                "hosts": _host_view(),
                "alerts": db.active_alerts(),
                "rules": db.list_rules(),
                "stats": db.stats(),
                "settings": settings(),
            })
            last_ping = time.time()
            while True:
                try:
                    event, data = q.get(timeout=15)
                    yield _sse(event, data)
                except queue.Empty:
                    # 心跳，防止中间层断连接
                    if time.time() - last_ping > 10:
                        last_ping = time.time()
                        yield ": ping\n\n"
        finally:
            hub.unsubscribe(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# ============================================================
#  关闭后台服务
#
#  为什么要单独做：页面关掉只是关浏览器，服务端和采集端还在后台跑。
#  这个接口会调用 scripts/stop.sh，把服务端、采集端、模拟主机容器一起停掉。
#  先返回响应，再在后台线程里执行停止，避免把连接掐断导致前端拿不到结果。
# ============================================================
@app.post("/api/shutdown")
def api_shutdown():
    def _do():
        time.sleep(0.8)
        try:
            subprocess.Popen(["bash", os.path.join(ROOT, "scripts", "stop.sh")],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        time.sleep(2.5)
        print("[server] 收到关闭指令，已退出", flush=True)
        os._exit(0)

    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"ok": True, "message": "后台服务正在关闭"})


@app.get("/api/whoami")
def api_whoami():
    auth = settings().get("auth") or {}
    return jsonify({"auth_enabled": auth_enabled(),
                    "password_file": "config/初始密码.txt" if os.path.exists(
                        os.path.join(ROOT, "config", "初始密码.txt")) else None})


# ============================================================
#  命令库（数据在 config/commands.json，可直接编辑）
# ============================================================
_CMD_CACHE = {"mtime": 0.0, "data": None}


@app.get("/api/commands")
def api_commands():
    path = os.path.join(ROOT, "config", "commands.json")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return jsonify({"groups": [], "commands": []})
    # 文件被改过就重新读 —— 改命令库不需要重启服务
    if _CMD_CACHE["data"] is None or _CMD_CACHE["mtime"] != mtime:
        try:
            with open(path, encoding="utf-8") as f:
                _CMD_CACHE["data"] = json.load(f)
            _CMD_CACHE["mtime"] = mtime
        except (OSError, ValueError) as e:
            return jsonify({"groups": [], "commands": [], "error": str(e)})
    return jsonify(_CMD_CACHE["data"])


# ============================================================
#  主机管理：新增 / 修改 / 删除
# ============================================================
def _creds_payload(b: dict) -> dict | None:
    """把请求体里的连接参数校验/规范化，返回 None 表示校验失败（已写响应）"""
    os_type = str(b.get("os_type") or "linux").lower()
    if os_type not in ("linux", "windows"):
        return None
    try:
        port = int(b.get("ssh_port") or 22)
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None
    return {
        "ssh_host": str(b.get("ssh_host") or "").strip(),
        "ssh_user": str(b.get("ssh_user") or "root").strip(),
        "ssh_port": port,
        "key_path": str(b.get("key_path") or "").strip(),
        "os_type": os_type,
        "enabled": bool(b.get("enabled", True)),
    }


@app.post("/api/hosts")
def api_host_create():
    b = request.get_json(silent=True) or {}
    name = str(b.get("name") or "").strip()
    host_id = str(b.get("id") or "").strip()
    if not name or not host_id:
        return jsonify({"error": "id 和 name 必填"}), 400
    if not host_id.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return jsonify({"error": "id 只能包含字母数字和 - _ ."}), 400
    if db.host_exists(host_id):
        return jsonify({"error": f"主机 id 已存在：{host_id}"}), 400

    c = _creds_payload(b)
    if c is None:
        return jsonify({"error": "连接参数不合法（端口 1-65535，系统类型 linux/windows）"}), 400
    if not c["ssh_host"]:
        return jsonify({"error": "SSH 地址不能为空"}), 400

    db.create_host(host_id, name, monitor=bool(b.get("monitor", False)))
    db.upsert_creds(host_id=host_id, ssh_host=c["ssh_host"], ssh_user=c["ssh_user"],
                    ssh_port=c["ssh_port"], key_path=c["key_path"],
                    os_type=c["os_type"], enabled=c["enabled"])
    hub.publish("hosts_changed", {"action": "create", "id": host_id})
    return jsonify({"ok": True, "id": host_id})


@app.put("/api/hosts/<host_id>")
def api_host_update(host_id: str):
    if not db.host_exists(host_id):
        return jsonify({"error": "主机不存在"}), 404
    b = request.get_json(silent=True) or {}

    name = str(b.get("name") or "").strip() or None
    monitor = bool(b["monitor"]) if "monitor" in b else None
    db.update_host(host_id, name=name, monitor=monitor)

    # 连接参数：只要请求里带了 ssh_host 就一并更新
    if str(b.get("ssh_host") or "").strip():
        c = _creds_payload(b)
        if c is None:
            return jsonify({"error": "连接参数不合法"}), 400
        db.upsert_creds(host_id=host_id, ssh_host=c["ssh_host"], ssh_user=c["ssh_user"],
                        ssh_port=c["ssh_port"], key_path=c["key_path"],
                        os_type=c["os_type"], enabled=c["enabled"])
    hub.publish("hosts_changed", {"action": "update", "id": host_id})
    return jsonify({"ok": True})


@app.post("/api/hosts/<host_id>/delete")
def api_host_delete_post(host_id: str):
    if not db.host_exists(host_id):
        return jsonify({"error": "主机不存在"}), 404
    b = request.get_json(silent=True) or {}
    db.delete_host(host_id, purge_alerts=bool(b.get("purge_alerts", False)))
    hub.publish("hosts_changed", {"action": "delete", "id": host_id})
    return jsonify({"ok": True})


# ============================================================
#  终端会话：列出 / 断开
#
#  为什么不能记 Popen 的 pid：gnome-terminal 客户端把窗口交给
#  gnome-terminal-server 之后就立刻退出了，那个 pid 是没用的。
#  所以改成扫描 /proc，按「ssh + 密钥 + 端口 + 用户@主机」匹配出真正的会话进程。
# ============================================================
def _scan_ssh_sessions() -> list[dict]:
    creds = db.list_creds()
    hosts = {h["id"]: h for h in db.list_hosts()}
    by_target = {}
    for c in creds:
        key = (str(c.get("ssh_user") or "").lower(),
               str(c.get("ssh_host") or "").lower(),
               int(c.get("ssh_port") or 22))
        by_target[key] = c["host_id"]

    out = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return out
    for pd in pids:
        try:
            with open(f"/proc/{pd}/cmdline", "rb") as f:
                argv = [x.decode("utf-8", "replace") for x in f.read().split(b"\0") if x]
        except OSError:
            continue
        if not argv or os.path.basename(argv[0]) != "ssh":
            continue
        # 只认本项目发起的（带 ServerAliveInterval=30 这个标记）
        if "ServerAliveInterval=30" not in argv:
            continue
        target = next((a for a in argv if "@" in a), "")
        if not target:
            continue
        user, _, host = target.rpartition("@")
        port = 22
        if "-p" in argv:
            i = argv.index("-p")
            if i + 1 < len(argv):
                try:
                    port = int(argv[i + 1])
                except ValueError:
                    pass
        hid = by_target.get((user.lower(), host.lower(), port))
        if not hid:
            continue
        ppid = None
        try:
            with open(f"/proc/{pd}/stat") as f:
                ppid = int(f.read().split(") ", 1)[1].split()[1])
        except Exception:
            pass
        out.append({
            "pid": int(pd),
            "ppid": ppid,
            "host_id": hid,
            "host_name": (hosts.get(hid) or {}).get("name") or hid,
            "target": target,
            "port": port,
        })
    return out


@app.get("/api/remote/sessions")
def api_sessions():
    return jsonify(_scan_ssh_sessions())


@app.post("/api/remote/disconnect")
def api_disconnect():
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "")
    sessions = _scan_ssh_sessions()
    if host_id:
        sessions = [s for s in sessions if s["host_id"] == host_id]
    killed = []
    for s in sessions:
        # 先杀父进程（bash -lc 包装层）再杀 ssh —— 只杀 ssh 的话，
        # 包装脚本会打印「连接已断开」然后等着你按 Enter，窗口不会关
        for pid in (s.get("ppid"), s["pid"]):
            if not pid:
                continue
            try:
                os.kill(pid, 15)
                killed.append(pid)
            except OSError:
                pass
    return jsonify({"ok": True, "killed": killed, "count": len(sessions)})


# ============================================================
#  页面
# ============================================================
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def api_health():
    st = db.stats()
    return jsonify({"ok": True, "hosts": st["hosts"],
                    "firing_alerts": st["firing_alerts"]})


@app.get("/api/metrics_catalog")
def api_metrics_catalog():
    """给规则编辑页用的指标清单（含中文说明）"""
    return jsonify([
        {"key": "cpu_pct", "label": "CPU 使用率(%)"},
        {"key": "mem_pct", "label": "内存使用率(%)"},
        {"key": "swap_pct", "label": "Swap 使用率(%)"},
        {"key": "disk_pct", "label": "磁盘使用率(%)"},
        {"key": "load1_per_core", "label": "每核负载"},
        {"key": "net_rx_kbps", "label": "网络接收(KB/s)"},
        {"key": "net_tx_kbps", "label": "网络发送(KB/s)"},
        {"key": "procs", "label": "进程数"},
        {"key": "uptime_hours", "label": "开机时长(小时)"},
        {"key": "agent_up", "label": "采集端在线(1/0)"},
    ])


# ============================================================
#  远程运维：SSH 连接设置
# ============================================================
@app.get("/api/remote/creds")
def api_remote_creds():
    creds = {c["host_id"]: c for c in db.list_creds()}
    out = []
    for h in db.list_hosts():
        c = creds.get(h["id"]) or {}
        out.append({
            "host_id": h["id"],
            "name": h["name"] or h["id"],
            "online": bool(h.get("last_seen")),
            "ssh_host": c.get("ssh_host") or "",
            "ssh_user": c.get("ssh_user") or "",
            "ssh_port": c.get("ssh_port") or 22,
            "key_path": c.get("key_path") or "",
            "os_type": c.get("os_type") or "linux",
            "enabled": bool(c.get("enabled")) if c else False,
            "configured": bool(c),
        })
    return jsonify(out)


@app.post("/api/remote/creds")
def api_remote_creds_save():
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "").strip()
    if not host_id:
        return jsonify({"error": "host_id 必填"}), 400
    os_type = str(b.get("os_type") or "linux").lower()
    if os_type not in ("linux", "windows"):
        return jsonify({"error": "os_type 只能是 linux / windows"}), 400
    try:
        port = int(b.get("ssh_port") or 22)
    except (TypeError, ValueError):
        return jsonify({"error": "端口必须是数字"}), 400
    if not (1 <= port <= 65535):
        return jsonify({"error": "端口范围 1~65535"}), 400

    ssh_host = str(b.get("ssh_host") or "").strip()
    if not ssh_host:
        return jsonify({"error": "SSH 地址不能为空"}), 400

    db.upsert_creds(
        host_id=host_id,
        ssh_host=ssh_host,
        ssh_user=str(b.get("ssh_user") or "root").strip(),
        ssh_port=port,
        key_path=str(b.get("key_path") or "").strip(),
        os_type=os_type,
        enabled=bool(b.get("enabled", True)),
    )
    return jsonify({"ok": True})


@app.post("/api/remote/test")
def api_remote_test():
    """测试 SSH 连通性（不执行任何命令，只握手 + 取系统标识）"""
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "").strip()
    try:
        client = ssh_manager.connect(host_id, timeout=8)
    except ssh_manager.SSHError as e:
        return jsonify({"ok": False, "error": str(e)}), 200
    try:
        chan = client.get_transport().open_session()
        chan.settimeout(8)
        chan.exec_command("echo MONITOR_OK && uname -s 2>/dev/null || echo WINDOWS")
        out = chan.makefile("r", -1).read().strip()
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        chan.close()
        return jsonify({"ok": True, "result": out})
    except Exception as e:
        return jsonify({"ok": False, "error": f"执行测试命令失败：{e}"}), 200
    finally:
        client.close()


# ============================================================
#  远程运维：快捷任务
# ============================================================
@app.get("/api/remote/tasks")
def api_tasks_list():
    include_disabled = request.args.get("all") == "1"
    return jsonify(db.list_quick_tasks(enabled_only=not include_disabled))


@app.post("/api/remote/tasks")
def api_tasks_add():
    b = request.get_json(silent=True) or {}
    name = str(b.get("name") or "").strip()
    if not name:
        return jsonify({"error": "任务名称不能为空"}), 400
    tid = db.add_quick_task(name,
                            str(b.get("cmd_linux") or "").strip(),
                            str(b.get("cmd_windows") or "").strip())
    return jsonify({"ok": True, "id": tid})


@app.put("/api/remote/tasks/<int:task_id>")
def api_tasks_update(task_id: int):
    if not db.get_quick_task(task_id):
        return jsonify({"error": "任务不存在"}), 404
    b = request.get_json(silent=True) or {}
    fields = {}
    for k in ("name", "cmd_linux", "cmd_windows"):
        if k in b:
            fields[k] = str(b[k]).strip()
    if "enabled" in b:
        fields["enabled"] = 1 if b["enabled"] else 0
    if "sort" in b:
        try:
            fields["sort"] = int(b["sort"])
        except (TypeError, ValueError):
            return jsonify({"error": "sort 必须是整数"}), 400
    if not fields:
        return jsonify({"error": "没有要修改的字段"}), 400
    db.update_quick_task(task_id, fields)
    return jsonify({"ok": True})


@app.delete("/api/remote/tasks/<int:task_id>")
def api_tasks_delete(task_id: int):
    t = db.get_quick_task(task_id)
    if not t:
        return jsonify({"error": "任务不存在"}), 404
    if t["builtin"]:
        return jsonify({"error": "内置任务不能删除，可以停用"}), 400
    db.delete_quick_task(task_id)
    return jsonify({"ok": True})


# ============================================================
#  远程运维：执行命令（单条，带危险命令拦截 + 审计）
# ============================================================
@app.post("/api/remote/exec")
def api_remote_exec():
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "").strip()
    if not host_id:
        return jsonify({"error": "host_id 必填"}), 400

    creds = db.get_creds(host_id) or {}
    os_type = (creds.get("os_type") or "linux").lower()

    # 两种来源：task_id（快捷任务）或 cmd（手输）
    if b.get("task_id") is not None:
        task = db.get_quick_task(int(b["task_id"]))
        if not task:
            return jsonify({"error": "任务不存在"}), 404
        if not task.get("enabled"):
            return jsonify({"error": "该任务已停用"}), 400
        cmd = task["cmd_windows"] if os_type == "windows" and task.get("cmd_windows") else task["cmd_linux"]
        kind = f"task:{task['name']}"
    else:
        cmd = str(b.get("cmd") or "").strip()
        kind = "manual"

    if not cmd:
        return jsonify({"error": "命令为空"}), 400

    danger = ssh_manager.check_danger(cmd)
    if danger:
        db.log_command(host_id, host_id, kind, cmd, -1, f"[已拦截] {danger}", 0)
        return jsonify({"error": f"命令被拦截：{danger}", "blocked": True}), 403

    timeout = int(settings().get("ssh_command_timeout_sec", 30))
    try:
        r = ssh_manager.exec_command(host_id, cmd, timeout=timeout)
    except ssh_manager.SSHError as e:
        db.log_command(host_id, host_id, kind, cmd, -1, str(e), 0)
        return jsonify({"error": str(e)}), 200

    db.log_command(host_id, host_id, kind, cmd, r["rc"], r["output"], r["duration_ms"])
    return jsonify({"ok": True, "cmd": cmd, "rc": r["rc"], "output": r["output"],
                    "duration_ms": r["duration_ms"]})


@app.get("/api/remote/logs")
def api_remote_logs():
    return jsonify(db.list_commands(int(request.args.get("limit", 100))))


# ============================================================
#  远程运维：弹出「原生终端窗口」
#
#  为什么这么做：Web 终端里跑 vim / top / htop 这类全屏程序体验很差。
#  改成点「打开控制台」后，由服务端在本机桌面上拉起一个真正的终端窗口
#  （gnome-terminal），并且已经用密钥自动 ssh 上去，体验和 Ctrl+Alt+T 一致。
#
#  前提：服务端进程要有图形环境变量（DISPLAY / WAYLAND_DISPLAY / DBUS）。
#  正常情况下从桌面启动就有；万一没有，会尝试从 gnome-shell 进程里捞一份。
# ============================================================
TERMINALS = [
    ("gnome-terminal", ["--title={title}", "--", "bash", "-lc", "{cmd}"]),
    ("x-terminal-emulator", ["-T", "{title}", "-e", "bash", "-lc", "{cmd}"]),
    ("xfce4-terminal", ["--title={title}", "-x", "bash", "-lc", "{cmd}"]),
    ("konsole", ["-p", "tabtitle={title}", "-e", "bash", "-lc", "{cmd}"]),
    ("xterm", ["-T", "{title}", "-e", "bash", "-lc", "{cmd}"]),
]


def _desktop_env() -> dict:
    """确保有图形环境变量；缺了就想办法补上"""
    env = dict(os.environ)
    need = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
    if all(env.get(k) for k in ("DISPLAY", "XDG_RUNTIME_DIR")):
        return env
    if env.get("WAYLAND_DISPLAY") and env.get("XDG_RUNTIME_DIR"):
        return env
    # 从图形会话进程里捞一份
    try:
        out = subprocess.run(["pgrep", "-u", str(os.getuid()), "-x", "gnome-shell"],
                             capture_output=True, text=True, timeout=5).stdout.split()
        for pid in out[:1]:
            with open(f"/proc/{pid}/environ", "rb") as f:
                for kv in f.read().split(b"\0"):
                    if b"=" not in kv:
                        continue
                    k, _, v = kv.partition(b"=")
                    k, v = k.decode(errors="ignore"), v.decode(errors="ignore")
                    if k in need and not env.get(k):
                        env[k] = v
    except Exception:
        pass
    return env


def _pick_terminal() -> tuple[str, list[str]] | None:
    for name, args in TERMINALS:
        path = shutil.which(name)
        if path:
            return path, args
    return None


@app.post("/api/remote/console")
def api_remote_console():
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "").strip()
    if not host_id:
        return jsonify({"error": "host_id 必填"}), 400

    try:
        argv, title = ssh_manager.build_ssh_argv(host_id)
    except ssh_manager.SSHError as e:
        return jsonify({"error": str(e)}), 200

    term = _pick_terminal()
    if not term:
        return jsonify({"error": "本机找不到可用的终端程序（gnome-terminal / xterm 等）"}), 200
    term_path, term_args = term

    # 窗口里的完整脚本：连着 ssh，断开后提示并按回车关闭
    # 注意：整段脚本是作为**单个 argv** 传给 bash -lc 的，外层不会再做 shell 解析，
    # 所以这里不需要（也不应该）手动转义引号。
    inner = (shlex.join(argv)
             + '; echo; echo "[连接已断开] 按 Enter 关闭窗口"; read -r _')

    cmd = [term_path]
    for a in term_args:
        cmd.append(a.format(title=title, cmd=inner))

    env = _desktop_env()
    if not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        return jsonify({"error": "服务端没有图形环境（DISPLAY/WAYLAND_DISPLAY），无法弹出终端窗口。"
                                 "请从桌面图标启动监控，或手动运行 scripts/ctl.sh open"}), 200

    try:
        subprocess.Popen(cmd, env=env, start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        return jsonify({"error": f"启动终端失败：{e}"}), 200

    db.log_command(host_id, host_id, "console", shlex.join(argv), 0, "弹出原生终端", 0)
    return jsonify({"ok": True, "message": f"已在桌面弹出终端：{title}"})


# ============================================================
#  远程运维：文件管理（SFTP）
# ============================================================
@app.get("/api/files")
def api_files_list():
    host_id = request.args.get("host_id", "")
    path = request.args.get("path", "/")
    if not host_id:
        return jsonify({"error": "host_id 必填"}), 400
    try:
        return jsonify(sftp_manager.list_dir(host_id, path))
    except sftp_manager.SftpError as e:
        return jsonify({"error": str(e)}), 200
    except Exception as e:
        return jsonify({"error": f"读取失败：{e}"}), 200


@app.get("/api/files/download")
def api_files_download():
    host_id = request.args.get("host_id", "")
    path = request.args.get("path", "")
    if not host_id or not path:
        return jsonify({"error": "host_id 和 path 必填"}), 400
    try:
        gen, filename, size = sftp_manager.download(host_id, path)
    except sftp_manager.SftpError as e:
        return jsonify({"error": str(e)}), 200
    except Exception as e:
        return jsonify({"error": f"下载失败：{e}"}), 200

    db.log_command(host_id, host_id, "sftp:download", path, 0, f"{size} bytes", 0)
    quoted = urllib.parse.quote(filename)
    return Response(gen, mimetype="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quoted}",
        "Content-Length": str(size),
        "X-Accel-Buffering": "no",
    })


@app.post("/api/files/upload")
def api_files_upload():
    host_id = request.form.get("host_id", "")
    path = request.form.get("path", "/")
    if not host_id:
        return jsonify({"error": "host_id 必填"}), 400
    files = request.files.getlist("file")
    if not files:
        return jsonify({"error": "没有收到文件"}), 400

    max_mb = int(settings().get("upload_max_mb", 200))
    done = []
    for f in files:
        if not f.filename:
            continue
        try:
            r = sftp_manager.upload(host_id, path, f.filename, f.stream,
                                    max_bytes=max_mb * 1024 * 1024)
            done.append(r["path"])
            db.log_command(host_id, host_id, "sftp:upload", r["path"], 0,
                           f"{r['size']} bytes", 0)
        except sftp_manager.SftpError as e:
            db.log_command(host_id, host_id, "sftp:upload", f.filename, -1, str(e), 0)
            return jsonify({"error": str(e), "uploaded": done}), 200
        except Exception as e:
            return jsonify({"error": f"上传失败：{e}", "uploaded": done}), 200
    return jsonify({"ok": True, "uploaded": done})


@app.post("/api/files/mkdir")
def api_files_mkdir():
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "")
    path = str(b.get("path") or "")
    if not host_id or not path:
        return jsonify({"error": "host_id 和 path 必填"}), 400
    try:
        p = sftp_manager.mkdir(host_id, path)
        db.log_command(host_id, host_id, "sftp:mkdir", p, 0, "", 0)
        return jsonify({"ok": True, "path": p})
    except sftp_manager.SftpError as e:
        return jsonify({"error": str(e)}), 200


@app.post("/api/files/delete")
def api_files_delete():
    b = request.get_json(silent=True) or {}
    host_id = str(b.get("host_id") or "")
    paths = b.get("paths") or []
    if not host_id or not isinstance(paths, list) or not paths:
        return jsonify({"error": "host_id 和 paths 必填"}), 400
    try:
        done = sftp_manager.remove(host_id, paths)
        db.log_command(host_id, host_id, "sftp:delete", ", ".join(done), 0, "", 0)
        return jsonify({"ok": True, "deleted": done})
    except sftp_manager.SftpError as e:
        return jsonify({"error": str(e)}), 200


# ============================================================
#  远程运维：Web 终端（WebSocket + paramiko PTY）
# ============================================================
@sock.route("/ws/terminal")
def ws_terminal(ws):
    host_id = request.args.get("host_id", "")
    client = chan = None
    stop = threading.Event()
    try:
        client, chan = ssh_manager.open_shell(host_id, 120, 32)
        ws.send(json.dumps({"type": "status",
                            "data": f"\r\n\x1b[36m[monitor] 已连接到 {host_id}\x1b[0m\r\n"},
                           ensure_ascii=False))
        db.log_command(host_id, host_id, "terminal", "打开终端会话", 0, "", 0)

        def pump():
            """SSH 输出 → WebSocket"""
            while not stop.is_set():
                try:
                    data = chan.recv(8192)
                except socket.timeout:
                    continue
                except Exception as e:
                    if not stop.is_set():
                        try:
                            ws.send(json.dumps({"type": "error", "data": str(e)},
                                               ensure_ascii=False))
                        except Exception:
                            pass
                    break
                if not data:
                    break
                try:
                    ws.send(json.dumps({"type": "output",
                                        "data": data.decode("utf-8", "replace")},
                                       ensure_ascii=False))
                except Exception:
                    break
            stop.set()

        threading.Thread(target=pump, daemon=True).start()

        while not stop.is_set():
            raw = ws.receive()
            if raw is None:
                break
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            t = msg.get("type")
            if t == "input":
                chan.send(msg.get("data", ""))
            elif t == "resize":
                try:
                    chan.resize_pty(width=int(msg.get("cols", 120)),
                                    height=int(msg.get("rows", 32)))
                except Exception:
                    pass
    except ssh_manager.SSHError as e:
        try:
            ws.send(json.dumps({"type": "error", "data": str(e)}, ensure_ascii=False))
        except Exception:
            pass
    except Exception as e:
        try:
            ws.send(json.dumps({"type": "error", "data": f"终端异常：{e}"},
                               ensure_ascii=False))
        except Exception:
            pass
    finally:
        stop.set()
        for obj in (chan, client):
            try:
                obj.close()
            except Exception:
                pass


# ============================================================
#  启动
# ============================================================
def bootstrap() -> None:
    init_auth()
    db.init()
    s = settings()
    engine = AlertEngine(settings, hub.publish)
    engine.start()
    down = Downsampler(settings)
    down.start()
    app.config["MAX_CONTENT_LENGTH"] = int(settings().get("upload_max_mb", 200)) * 1024 * 1024 + 1024 * 1024
    print(f"[server] 告警引擎 + 降采样器已启动", flush=True)


bootstrap()

if __name__ == "__main__":
    s = settings()
    print(f"[server] 监听 http://{s.get('listen_host', '127.0.0.1')}:{s.get('listen_port', 8090)}",
          flush=True)
    app.run(host=s.get("listen_host", "127.0.0.1"),
            port=int(s.get("listen_port", 8090)),
            debug=False, threaded=True, use_reloader=False)
