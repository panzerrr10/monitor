#!/usr/bin/env bash
# ============================================================
#  安装桌面快捷方式：应用菜单 + 左侧 Dock + 桌面图标
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$HOME/.local/share/applications"
DESK="$HOME/桌面"
[[ -d "$DESK" ]] || DESK="$HOME/Desktop"
ICON="$HOME/.local/share/icons/monitor.svg"

mkdir -p "$APP_DIR" "$(dirname "$ICON")"

# 图标：圆角方块 + 心电图，跟页面顶部那个 emoji 呼应
cat > "$ICON" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="26" fill="#14395f"/>
  <rect x="18" y="26" width="92" height="60" rx="8" fill="#f5f7fa"/>
  <rect x="26" y="34" width="76" height="44" rx="4" fill="#1b1f27"/>
  <polyline points="30,62 42,62 48,48 55,72 62,55 69,64 78,64 86,52 98,52"
            fill="none" stroke="#4ade80" stroke-width="4"
            stroke-linecap="round" stroke-linejoin="round"/>
  <rect x="52" y="92" width="24" height="6" rx="3" fill="#2c6fbb"/>
  <rect x="44" y="100" width="40" height="5" rx="2.5" fill="#2c6fbb" opacity=".7"/>
</svg>
SVG

cat > "$APP_DIR/monitor.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Version=1.0
Name=Monitor
Name[zh_CN]=Monitor 监控运维
GenericName=Host Monitor
GenericName[zh_CN]=主机监控与远程运维
Comment=Desktop app for host monitoring and remote ops
Comment[zh_CN]=主机监控与远程运维（桌面应用）
Exec=$ROOT/scripts/monitor-desktop.sh
Icon=$ICON
Terminal=false
Categories=System;Monitor;
Keywords=monitor;ops;ssh;sftp;alerts;
StartupNotify=true
StartupWMClass=monitor-desktop
X-GNOME-SingleWindow=true
DESKTOP

chmod +x "$APP_DIR/monitor.desktop" "$ROOT/scripts/ctl.sh"

# 桌面图标
if [[ -d "$DESK" ]]; then
  cp "$APP_DIR/monitor.desktop" "$DESK/monitor.desktop"
  chmod +x "$DESK/monitor.desktop"
  gio set "$DESK/monitor.desktop" metadata::trusted true 2>/dev/null || true
  echo "  ✅ 桌面图标：$DESK/monitor.desktop"
fi

# 左侧 Dock（GNOME 收藏夹）
if command -v gsettings >/dev/null 2>&1; then
  CUR=$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || echo "[]")
  if [[ "$CUR" != *"monitor.desktop"* ]]; then
    NEW=$(python3 - "$CUR" <<'PY'
import sys, ast
try:
    lst = ast.literal_eval(sys.argv[1])
except Exception:
    lst = []
lst.append("monitor.desktop")
print("[" + ", ".join("'%s'" % x for x in lst) + "]")
PY
)
    gsettings set org.gnome.shell favorite-apps "$NEW" 2>/dev/null \
      && echo "  ✅ 已加入左侧 Dock" || echo "  ⚠️ Dock 写入失败（可手动右键图标固定）"
  else
    echo "  ✅ Dock 里已存在"
  fi
fi

update-desktop-database "$APP_DIR" 2>/dev/null || true
echo
echo "  完成。图标位置："
echo "    应用菜单 → 搜索 Monitor"
echo "    左侧 Dock（可能需要注销重登才显示）"
echo "    桌面：$DESK/monitor.desktop"
