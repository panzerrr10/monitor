#!/usr/bin/env bash
# ============================================================
#  重置监控页面登录密码
#
#    bash scripts/set-password.sh '新密码'     直接设置
#    bash scripts/set-password.sh              交互输入
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${MONITOR_PYTHON:-$ROOT/.venv/bin/python}"

PW="${1:-}"
if [[ -z "$PW" ]]; then
  read -r -s -p "  输入新密码（至少 6 位）：" PW; echo
  read -r -s -p "  再输一次：" PW2; echo
  [[ "$PW" == "$PW2" ]] || { echo "  ❌ 两次不一致"; exit 1; }
fi
if [[ ${#PW} -lt 6 ]]; then echo "  ❌ 密码至少 6 位"; exit 1; fi

"$PY" - "$PW" <<'PY'
import hashlib, json, os, secrets, sys
pw = sys.argv[1]
p = "config/settings.json"
d = json.load(open(p, encoding="utf-8"))
a = d.get("auth") or {}
a["salt"] = secrets.token_hex(16)
a["hash"] = hashlib.pbkdf2_hmac("sha256", pw.encode(), a["salt"].encode(), 120_000).hex()
a.setdefault("session_secret", secrets.token_hex(32))
a.setdefault("local_token", secrets.token_hex(24))
a["enabled"] = True
d["auth"] = a
json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
f = "config/初始密码.txt"
with open(f, "w", encoding="utf-8") as fh:
    fh.write(f"监控页面登录密码：{pw}\n\n登录后可在「设置」页修改。\n")
os.chmod(f, 0o600)
print("  ✅ 密码已重置，并写入", f)
PY

echo "  提示：已登录的浏览器会话仍有效（Cookie 签名不变），要强制下线就重启服务端。"
