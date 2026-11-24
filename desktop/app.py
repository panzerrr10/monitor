#!/usr/bin/env python3
"""Monitor 桌面版 —— GTK3 + WebKit2 原生窗口

为什么这样拆分：
  · GUI 外壳用**系统 python**（/usr/bin/python3），因为 PyGObject(gi) 只有系统 python 里有
  · 后端 Flask 继续用项目自己的 .venv（要 flask/paramiko）
  · 两者通过本地 127.0.0.1 通信，对用户来说就是一个独立窗口应用，不经过浏览器

窗口行为：
  · 同一时间只允许一个窗口（Gtk.Application 单实例，再点图标会把已有窗口提到前台）
  · 后端没起来 → 显示「启动中」页面，并自动拉起
  · 页面里的「退出后台」会停掉后端 → 本窗口检测到后切换到「服务已停止」页，可一键重启
  · 关闭窗口时询问：停止后台并退出 / 仅关闭窗口
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")          # 必须锁 3.0，否则会解析到 Gdk 4.0 与 Gtk3 冲突
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, Gdk, GLib, WebKit2  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS = os.path.join(ROOT, "config", "settings.json")
ICON = os.path.join(os.path.expanduser("~"), ".local", "share", "icons", "monitor.svg")
STATE_DIR = os.path.join(os.path.expanduser("~"), ".config", "monitor-desktop")


def read_port() -> int:
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            return int(json.load(f).get("listen_port", 8090))
    except Exception:
        return 8090


PORT = read_port()
BASE = f"http://127.0.0.1:{PORT}/"

OFFLINE_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<style>
 body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
      font-family:-apple-system,"Noto Sans CJK SC",sans-serif;background:#f5f7fa;color:#1f2328}
 .box{text-align:center;max-width:520px;padding:30px}
 h1{font-size:20px;color:#14395f;margin:0 0 10px}
 p{font-size:13.5px;color:#6b7280;line-height:1.8;margin:0 0 22px}
 button{background:#2c6fbb;color:#fff;border:0;padding:11px 26px;border-radius:8px;
        font-size:14px;font-family:inherit;cursor:pointer}
 button:hover{background:#255e9f}
 button:disabled{background:#9db4cf;cursor:not-allowed}
 .log{margin-top:18px;font-size:11.5px;color:#9ca3af;font-family:monospace;
      white-space:pre-wrap;text-align:left;max-height:120px;overflow:auto}
</style></head><body><div class="box">
 <h1 id="t">后台服务未运行</h1>
 <p id="d">监控服务端没有在 %PORT% 上响应。<br>点下面的按钮启动它（采集端和模拟主机会一起启动）。</p>
 <button id="b" onclick="go()">启动后台服务</button>
 <div class="log" id="log"></div>
</div>
<script>
function go(){
  const b=document.getElementById('b');
  b.disabled=true; b.textContent='正在启动…';
  document.getElementById('t').textContent='正在启动后台服务';
  document.getElementById('d').textContent='首次启动需要几秒，请稍候…';
  if (window.monitorCtl) window.monitorCtl.post('start');
}
window.__monitorSetState = function(state, detail){
  document.getElementById('t').textContent = state === 'starting' ? '正在启动后台服务' : '后台服务已停止';
  document.getElementById('d').textContent = detail || '';
  const b=document.getElementById('b');
  b.disabled = state === 'starting';
  b.textContent = state === 'starting' ? '正在启动…' : '重新启动后台服务';
};
</script></body></html>""".replace("%PORT%", str(PORT))


class MonitorWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application):
        super().__init__(application=app, title="Monitor 监控运维")
        geo = self._load_geometry()
        self.set_default_size(geo.get("w", 1440), geo.get("h", 920))
        if geo.get("maximized"):
            self.maximize()
        self.set_position(Gtk.WindowPosition.CENTER)
        self.starting = False
        self.backend_up = False
        if os.path.isfile(ICON):
            try:
                self.set_icon_from_file(ICON)
            except Exception:
                pass

        # ---- 顶栏（原生菜单条）----
        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.set_title("Monitor 监控运维")
        self.set_titlebar(hb)

        btn_reload = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        btn_reload.set_tooltip_text("重新加载 (Ctrl+R)")
        btn_reload.connect("clicked", lambda *_: self.reload())
        hb.pack_start(btn_reload)

        self.lbl_state = Gtk.Label(label="连接中…")
        hb.pack_start(self.lbl_state)

        menu_btn = Gtk.MenuButton()
        menu_btn.set_image(Gtk.Image.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.BUTTON))
        pop = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_border_width(6)
        for label, cb in [
            ("重新加载", self.reload),
            ("全屏 / 退出全屏 (F11)", self.toggle_fullscreen),
            ("在浏览器中打开", self.open_in_browser),
            ("打开数据目录", self.open_data_dir),
            ("停止后台服务", self.stop_backend),
            ("退出", self.on_close),
        ]:
            b = Gtk.ModelButton(label=label)
            b.connect("clicked", lambda w, c=cb: (pop.popdown(), c()))
            box.add(b)
        box.show_all()
        pop.add(box)
        menu_btn.set_popover(pop)
        hb.pack_end(menu_btn)

        # ---- WebView ----
        ucm = WebKit2.UserContentManager()
        self.web = WebKit2.WebView.new_with_user_content_manager(ucm)
        settings = self.web.get_settings()
        settings.set_enable_developer_extras(False)
        try:
            settings.set_enable_media_stream(False)
        except Exception:
            pass
        self.web.set_background_color(Gdk.RGBA(0.96, 0.97, 0.98, 1))

        bridge = WebKit2.UserScript.new(
            "window.monitorCtl = { post: function(a){ window.webkit.messageHandlers.monitorCtl.postMessage(a); } };",
            WebKit2.UserContentInjectedFrames.TOP_FRAME,
            WebKit2.UserScriptInjectionTime.START, None, None)
        ucm.add_script(bridge)
        ucm.register_script_message_handler("monitorCtl")
        ucm.connect("script-message-received::monitorCtl", self.on_bridge)

        self.web.connect("load-failed", self.on_load_failed)
        self.add(self.web)

        self.connect("delete-event", self.on_delete_event)
        self.connect("destroy", lambda *_: self._save_geometry())
        self.connect("key-press-event", self.on_key)

        self.show_all()
        self.ensure_backend_async()

    # ---------------- 窗口状态 ----------------
    def _geo_file(self) -> str:
        return os.path.join(STATE_DIR, "window.json")

    def _load_geometry(self) -> dict:
        try:
            with open(self._geo_file(), encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_geometry(self) -> None:
        try:
            w, h = self.get_size()
            data = {"w": w, "h": h, "maximized": self.is_maximized()}
            with open(self._geo_file(), "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    # ---------------- 后端管理 ----------------
    def health(self) -> bool:
        try:
            with urllib.request.urlopen(BASE + "api/health", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def ensure_backend_async(self) -> None:
        if self.health():
            self.backend_up = True
            self.go_online()
            return
        self.go_offline("starting")
        self.start_backend()

    def start_backend(self) -> None:
        if self.starting:
            return
        self.starting = True
        self.go_offline("starting")

        def worker():
            try:
                subprocess.run(["bash", os.path.join(ROOT, "scripts", "start.sh")],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240)
            except Exception:
                pass
            for _ in range(60):
                if self.health():
                    GLib.idle_add(self.go_online)
                    GLib.idle_add(lambda: setattr(self, "starting", False))
                    return
                time.sleep(1)
            GLib.idle_add(lambda: self.go_offline("failed"))
            GLib.idle_add(lambda: setattr(self, "starting", False))

        threading.Thread(target=worker, daemon=True).start()

    def _local_token(self) -> str:
        try:
            with open(SETTINGS, encoding="utf-8") as f:
                return ((json.load(f).get("auth") or {}).get("local_token") or "")
        except Exception:
            return ""

    def _login_url(self) -> str:
        """用本机令牌换一次性票据，实现桌面窗口免输密码
        换不到（比如没令牌/已关鉴权）就退回普通首页，用户手动登录即可。"""
        token = self._local_token()
        if not token:
            return BASE
        try:
            req = urllib.request.Request(
                BASE + "api/desktop-ticket", data=b"{}", method="POST",
                headers={"Content-Type": "application/json", "X-Local-Token": token})
            with urllib.request.urlopen(req, timeout=4) as r:
                d = json.loads(r.read().decode())
            if d.get("ticket"):
                return BASE + "desktop-login?ticket=" + d["ticket"]
        except Exception:
            pass
        return BASE

    def go_online(self) -> None:
        self.backend_up = True
        self.lbl_state.set_text("已连接")
        self.web.load_uri(self._login_url())

    def go_offline(self, reason: str = "stopped") -> None:
        self.backend_up = False
        self.lbl_state.set_text("服务未运行")
        self.web.load_html(OFFLINE_PAGE, BASE)
        if reason == "failed":
            GLib.timeout_add(600, self._set_failed_state)

    def _set_failed_state(self) -> bool:
        self.web.evaluate_javascript(
            "window.__monitorSetState && window.__monitorSetState('stopped','启动失败，请检查 logs/server.out')",
            -1, None, None, None) if hasattr(self.web, "evaluate_javascript") else None
        return False

    def stop_backend(self) -> None:
        try:
            req = urllib.request.Request(BASE + "api/shutdown", data=b"{}", method="POST",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=4).read()
        except Exception:
            pass
        self.backend_up = False
        self.lbl_state.set_text("服务已停止")
        GLib.timeout_add(1600, lambda: (self.go_offline("stopped"), False)[1])

    # ---------------- 交互 ----------------
    def open_in_browser(self) -> None:
        try:
            subprocess.Popen(["xdg-open", BASE])
        except Exception:
            pass

    def reload(self) -> None:
        if self.health():
            self.backend_up = True
            self.web.load_uri(self._login_url())
        else:
            self.ensure_backend_async()

    def toggle_fullscreen(self) -> None:
        if self.is_fullscreen():
            self.unfullscreen()
        else:
            self.fullscreen()

    def open_data_dir(self) -> None:
        try:
            subprocess.Popen(["xdg-open", os.path.join(ROOT, "data")])
        except Exception:
            pass

    def on_bridge(self, ucm, result) -> None:
        try:
            msg = result.get_js_value().to_string()
        except Exception:
            try:
                msg = result.to_string()
            except Exception:
                return
        if msg == "start":
            self.start_backend()

    def on_load_failed(self, web, event, uri, error) -> bool:
        # 主页面加载失败（后端挂了）→ 显示离线页，自己处理掉，不再弹默认错误页
        if uri.startswith(BASE):
            GLib.idle_add(self.go_offline, "stopped")
            return True
        return False

    def on_key(self, widget, event) -> bool:
        ctrl = bool(event.state & Gdk.ModifierType.CONTROL_MASK)
        if event.keyval == Gdk.KEY_F11:
            self.toggle_fullscreen(); return True
        if ctrl and event.keyval in (Gdk.KEY_r, Gdk.KEY_R):
            self.reload(); return True
        if ctrl and event.keyval in (Gdk.KEY_q, Gdk.KEY_Q):
            self.on_close(); return True
        return False

    def on_delete_event(self, *_):
        self.on_close()
        return True

    def on_close(self) -> None:
        if not self.backend_up:
            self.destroy()
            Gtk.Application.get_default().quit()
            return
        dlg = Gtk.MessageDialog(
            transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            text="关闭 Monitor？")
        dlg.format_secondary_text(
            "选择「停止并退出」会同时关闭后台服务、采集端和模拟主机容器。\n"
            "选择「仅关窗口」则后台继续运行，下次打开更快。")
        dlg.add_button("仅关窗口", Gtk.ResponseType.NO)
        dlg.add_button("停止并退出", Gtk.ResponseType.YES)
        dlg.add_button("取消", Gtk.ResponseType.CANCEL)
        resp = dlg.run()
        dlg.destroy()
        if resp == Gtk.ResponseType.CANCEL:
            return
        if resp == Gtk.ResponseType.YES:
            self.stop_backend()
            GLib.timeout_add(1800, lambda: (self.destroy(),
                                            Gtk.Application.get_default().quit(), False)[2])
            return
        self.destroy()
        Gtk.Application.get_default().quit()


def on_activate(app: Gtk.Application) -> None:
    win = app.get_active_window()
    if win:
        win.present()
        return
    MonitorWindow(app)


def main() -> int:
    os.makedirs(STATE_DIR, exist_ok=True)
    GLib.set_prgname("monitor-desktop")
    GLib.set_application_name("Monitor 监控运维")
    app = Gtk.Application(application_id="com.pz.monitor.desktop")
    app.connect("activate", on_activate)
    return app.run([sys.argv[0]])


if __name__ == "__main__":
    sys.exit(main())
