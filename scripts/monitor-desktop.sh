#!/usr/bin/env bash
# ============================================================
#  Monitor 桌面版启动器（供 .desktop 调用）
#
#  用**系统 python** 跑 GUI 外壳（只有它装了 PyGObject），
#  后端 Flask 仍由项目自己的 .venv 负责，由窗口检测到未运行后自动拉起。
# ============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYS_PY="${MONITOR_GUI_PYTHON:-/usr/bin/python3}"

err() {
  echo "❌ $*" >&2
  command -v zenity >/dev/null 2>&1 && zenity --error --title="Monitor" --text="$*" 2>/dev/null
  exit 1
}

[[ -x "$SYS_PY" ]] || err "找不到系统 python：$SYS_PY"

"$SYS_PY" - <<'PY' 2>/dev/null || err "缺少 GTK3 / WebKit2 依赖，无法启动桌面窗口。请安装：sudo apt install python3-gi gir1.2-webkit2-4.1"
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, WebKit2
PY

exec "$SYS_PY" "$ROOT/desktop/app.py" "$@"
