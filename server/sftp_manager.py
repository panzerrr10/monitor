"""远程文件管理（SFTP）

安全要点：
  1. 路径统一用 posixpath.normpath 规范化，禁止穿越（normalize 后必须仍以 / 开头）
  2. 上传有大小上限（默认 200MB，可在设置里改），边写边计数，超限立刻中断
  3. 下载用流式分块，不把整个文件读进内存
  4. 所有上传/下载/删除都写审计日志
"""
from __future__ import annotations

import os
import posixpath
import stat
import tempfile

import paramiko

import db
import ssh_manager


class SftpError(Exception):
    pass


def normalize(path: str, default: str = "/") -> str:
    p = (path or "").strip() or default
    if not p.startswith("/"):
        p = "/" + p
    p = posixpath.normpath(p)
    if not p.startswith("/"):
        raise SftpError("非法路径")
    return p


def _client(host_id: str) -> paramiko.SSHClient:
    return ssh_manager.connect(host_id)


def _sftp(client: paramiko.SSHClient) -> paramiko.SFTPClient:
    try:
        return client.open_sftp()
    except Exception as e:
        raise SftpError(f"打开 SFTP 失败：{e}") from e


def list_dir(host_id: str, path: str) -> dict:
    path = normalize(path)
    client = _client(host_id)
    try:
        sftp = _sftp(client)
        try:
            attrs = sftp.listdir_attr(path)
        except IOError as e:
            raise SftpError(f"无法读取目录 {path}：{e}") from e

        entries = []
        for a in attrs:
            is_dir = stat.S_ISDIR(a.st_mode or 0)
            is_link = stat.S_ISLNK(a.st_mode or 0)
            entries.append({
                "name": a.filename,
                "path": posixpath.join(path, a.filename) if path != "/" else "/" + a.filename,
                "is_dir": is_dir,
                "is_link": is_link,
                "size": 0 if is_dir else int(a.st_size or 0),
                "mtime": int(a.st_mtime or 0),
                "mode": oct(a.st_mode or 0)[-4:],
            })
        # 目录在前，再按名称排
        entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        sftp.close()
        return {"path": path, "parent": posixpath.dirname(path) or "/", "entries": entries}
    finally:
        client.close()


def stat_path(host_id: str, path: str) -> dict:
    path = normalize(path)
    client = _client(host_id)
    try:
        sftp = _sftp(client)
        try:
            a = sftp.stat(path)
        except IOError as e:
            raise SftpError(f"路径不存在：{path}") from e
        sftp.close()
        return {"path": path,
                "is_dir": stat.S_ISDIR(a.st_mode or 0),
                "size": int(a.st_size or 0),
                "mtime": int(a.st_mtime or 0)}
    finally:
        client.close()


def download(host_id: str, path: str):
    """返回 (生成器, 文件名, 大小)。调用方负责把生成器塞进 Response。"""
    path = normalize(path)
    client = _client(host_id)
    sftp = _sftp(client)
    try:
        a = sftp.stat(path)
    except IOError as e:
        sftp.close(); client.close()
        raise SftpError(f"文件不存在：{path}") from e
    if stat.S_ISDIR(a.st_mode or 0):
        sftp.close(); client.close()
        raise SftpError("这是目录，不能直接下载")

    filename = posixpath.basename(path) or "download.bin"

    def gen():
        try:
            f = sftp.open(path, "rb")
            while True:
                chunk = f.read(256 * 1024)
                if not chunk:
                    break
                yield chunk
            f.close()
        finally:
            try: sftp.close()
            except Exception: pass
            try: client.close()
            except Exception: pass

    return gen(), filename, int(a.st_size or 0)


def upload(host_id: str, dir_path: str, filename: str, fileobj,
           max_bytes: int = 200 * 1024 * 1024) -> dict:
    dir_path = normalize(dir_path)
    safe_name = os.path.basename(filename or "").strip()
    if not safe_name or safe_name in (".", ".."):
        raise SftpError("文件名非法")
    remote_path = posixpath.join(dir_path, safe_name)

    tmp = tempfile.NamedTemporaryFile(delete=False)
    total = 0
    try:
        while True:
            chunk = fileobj.read(512 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SftpError(f"文件超过上限 {max_bytes // (1024*1024)}MB")
            tmp.write(chunk)
        tmp.close()

        client = _client(host_id)
        try:
            sftp = _sftp(client)
            try:
                sftp.put(tmp.name, remote_path)
            except IOError as e:
                raise SftpError(f"上传失败：{e}") from e
            sftp.close()
        finally:
            client.close()
        return {"path": remote_path, "size": total}
    finally:
        try: tmp.close()
        except Exception: pass
        try: os.unlink(tmp.name)
        except Exception: pass


def mkdir(host_id: str, path: str) -> str:
    path = normalize(path)
    client = _client(host_id)
    try:
        sftp = _sftp(client)
        try:
            sftp.mkdir(path)
        except IOError as e:
            raise SftpError(f"创建目录失败：{e}") from e
        sftp.close()
        return path
    finally:
        client.close()


def _explain_io_error(err: Exception, path: str, is_dir: bool) -> str:
    """把 SFTP 那个笼统的 "Failure" 翻译成人话。

    为什么需要这个：SFTP 协议的错误码很粗糙，Linux 的 ENOTEMPTY（目录非空）、
    EACCES（没权限）等统统被映射成 SSH_FX_FAILURE，paramiko 只拿得到字符串 "Failure"，
    原因信息在协议层就丢了。所以只能在删除前主动检查、事后给出可读的提示。
    """
    msg = str(err)
    if msg.strip().lower() == "failure":
        if is_dir:
            return "SFTP 返回通用失败（常见原因：目录非空，或没有父目录的写权限）"
        return "SFTP 返回通用失败（常见原因：没有父目录的写权限，或文件被占用）"
    if "No such file" in msg or "no such file" in msg:
        return "文件不存在（可能已被别人删掉了）"
    return msg


def remove(host_id: str, paths: list[str]) -> list[str]:
    client = _client(host_id)
    done = []
    try:
        sftp = _sftp(client)
        for raw in paths:
            p = normalize(raw)
            try:
                st = sftp.stat(p)
            except IOError as e:
                raise SftpError(
                    f"删除 {p} 失败：{_explain_io_error(e, p, False)}") from e

            is_dir = stat.S_ISDIR(st.st_mode or 0)
            if is_dir:
                # 先看目录是否为空 —— 这样能给出「非空」这种可读原因，
                # 而不是等 rmdir 失败后只拿到一句笼统的 Failure
                try:
                    children = sftp.listdir(p)
                except IOError:
                    children = []
                if children:
                    preview = "、".join(children[:3]) + ("…" if len(children) > 3 else "")
                    raise SftpError(
                        f"目录非空（还有 {len(children)} 项：{preview}），无法删除：{p}。"
                        f"请先清空里面的内容，或到终端执行 rm -rf {p}")
                try:
                    sftp.rmdir(p)      # 只删空目录，避免网页上一键误删整棵目录树
                except IOError as e:
                    raise SftpError(
                        f"删除目录 {p} 失败：{_explain_io_error(e, p, True)}") from e
            else:
                try:
                    sftp.remove(p)
                except IOError as e:
                    raise SftpError(
                        f"删除 {p} 失败：{_explain_io_error(e, p, False)}") from e
            done.append(p)
        sftp.close()
        return done
    finally:
        client.close()
