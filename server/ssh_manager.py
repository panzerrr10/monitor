"""远程运维：SSH 连接管理

设计取舍：
  1. **只用密钥认证**，不存密码。密码落库是运维事故的常见来源，而且 paramiko 存密码
     必然要明文或可解密，风险不可控。
  2. 主机指纹用 AutoAddPolicy（首次自动信任）。在生产里应该用 known_hosts 校验，
     这里为了"接一台新机器就能用"做了妥协，README 里写明了。
  3. 快捷任务走 exec_command（单条命令），可以逐个做危险命令拦截 + 审计；
     Web 终端走 PTY 全交互，**无法逐条拦命令**（就像真 SSH 一样），只记连接审计。
"""
from __future__ import annotations

import os
import re
import socket
import time
from typing import Any

import paramiko

import db

# 危险命令黑名单：只作用于「快捷任务」的单条命令执行
DANGER_PATTERNS = [
    (r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|/\*|~/?|\$HOME)", "递归删除根目录或家目录"),
    (r"\bmkfs(\.\w+)?\b", "格式化文件系统"),
    (r"\bdd\b[^|]*\bof=/dev/(sd|nvme|hd|vd)", "直接写裸磁盘"),
    (r"\b(shutdown|reboot|halt|poweroff|init\s+0)\b", "关机/重启"),
    (r"\bchmod\s+-R\s+777\s+/(\s|$)", "递归改根目录权限"),
    (r":\(\)\s*\{.*\};?\s*:", "fork 炸弹"),
    (r"\bDROP\s+(DATABASE|TABLE)\b", "删库/删表"),
    (r"\bTRUNCATE\s+TABLE\b", "清空表"),
    (r"Remove-Item[^|]*-Recurse[^|]*-Force[^|]*\bC:(/|\\\\)\s*$", "递归删除 C 盘"),
    (r"\b(Format-Volume|Clear-Disk)\b", "格式化磁盘"),
]


class SSHError(Exception):
    pass


def check_danger(cmd: str) -> str | None:
    """返回命中的危险说明；不危险返回 None"""
    for pat, why in DANGER_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE):
            return why
    return None


def _resolve_key(creds: dict) -> str:
    key_path = (creds.get("key_path") or "").strip()
    if not key_path:
        raise SSHError("没有配置 SSH 密钥路径")
    path = os.path.expanduser(key_path)
    if not os.path.isfile(path):
        raise SSHError(f"密钥文件不存在：{path}")
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise SSHError(f"密钥权限过宽（{oct(mode)}），请执行 chmod 600 {path}")
    return path


def connect(host_id: str, timeout: int = 10) -> paramiko.SSHClient:
    creds = db.get_creds(host_id)
    if not creds:
        raise SSHError(f"主机 {host_id} 未配置 SSH 连接参数")
    if not creds.get("enabled"):
        raise SSHError(f"主机 {host_id} 的远程运维已停用")

    host = (creds.get("ssh_host") or "").strip()
    if not host:
        raise SSHError("没有配置 SSH 地址（ssh_host），请在「连接设置」里填写目标机的 IP")
    key = _resolve_key(creds)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=int(creds.get("ssh_port") or 22),
            username=creds.get("ssh_user") or "root",
            key_filename=key,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
    except paramiko.AuthenticationException as e:
        raise SSHError(f"认证失败（检查用户名和公钥是否已加到目标机）：{e}") from e
    except (socket.timeout, OSError) as e:
        raise SSHError(f"连接失败（目标 {host}:{creds.get('ssh_port') or 22}）：{e}") from e
    except paramiko.SSHException as e:
        raise SSHError(f"SSH 协议错误：{e}") from e
    return client



def open_shell(host_id: str, cols: int = 120, rows: int = 32) -> tuple[paramiko.SSHClient, paramiko.Channel]:
    """打开一个交互式 PTY 会话"""
    creds = db.get_creds(host_id) or {}
    os_type = (creds.get("os_type") or "linux").lower()
    client = connect(host_id)
    transport = client.get_transport()
    if not transport or not transport.is_active():
        raise SSHError("SSH 传输层不可用")

    if os_type == "windows":
        # Windows 的默认 shell 是 cmd，要 PowerShell 得显式指定
        chan = transport.open_session()
        chan.get_pty(term="xterm-256color", width=cols, height=rows)
        chan.exec_command("powershell.exe -NoLogo -NoProfile")
    else:
        chan = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
    chan.settimeout(0.0)
    return client, chan


def exec_command(host_id: str, cmd: str, timeout: int = 30) -> dict:
    """执行单条命令（快捷任务用）"""
    creds = db.get_creds(host_id) or {}
    os_type = (creds.get("os_type") or "linux").lower()

    real = cmd
    if os_type == "windows":
        # 1) 用 PowerShell 语义执行，而不是 cmd
        # 2) 强制 UTF-8 输出：Windows 默认是 GBK(936)，不改的话返回给前端的
        #    "家庭中文版" 这类中文会变成乱码
        prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        real = ('powershell.exe -NoProfile -NonInteractive -Command "'
                + (prefix + cmd).replace('"', '\\"') + '"')

    t0 = time.time()
    client = connect(host_id)
    try:
        stdin, stdout, stderr = client.exec_command(real, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        text = out + (("\n[stderr]\n" + err) if err.strip() else "")
        return {"rc": rc, "output": text, "duration_ms": int((time.time() - t0) * 1000)}
    except socket.timeout:
        raise SSHError(f"命令执行超时（{timeout}s）")
    finally:
        client.close()


def build_ssh_argv(host_id: str) -> tuple[list[str], str]:
    """构造 ssh 命令行（给"弹出原生终端"用），返回 (参数列表, 窗口标题)"""
    creds = db.get_creds(host_id)
    if not creds:
        raise SSHError(f"主机 {host_id} 未配置 SSH 连接参数")
    if not creds.get("enabled"):
        raise SSHError(f"主机 {host_id} 的远程运维已停用")
    host = (creds.get("ssh_host") or "").strip()
    if not host:
        raise SSHError("没有配置 SSH 地址（ssh_host）")

    key = _resolve_key(creds)
    hosts = {h["id"]: h for h in db.list_hosts()}
    name = (hosts.get(host_id) or {}).get("name") or host_id

    argv = [
        "ssh",
        "-i", key,
        "-p", str(creds.get("ssh_port") or 22),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        f"{creds.get('ssh_user') or 'root'}@{host}",
    ]
    # Windows 的 cmd 默认 GBK，中文会乱码；先切 65001(UTF-8) 再进 cmd
    if (creds.get("os_type") or "linux").lower() == "windows":
        argv += ["chcp 65001>nul & cmd"]
    return argv, f"monitor: {name}"
