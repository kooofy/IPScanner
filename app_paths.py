# -*- coding: utf-8 -*-
"""运行时路径助手：同时兼容开发模式与 PyInstaller 打包（--onefile）模式。

- resource_dir()：图片等被打进 exe 内部的资源文件目录。
- data_dir()：数据库 / 配置 / 日志等需要持久化的用户数据目录。

数据目录策略（按顺序探测，取第一个可写的）：
  1. 开发模式        → 源码目录
  2. 冻结态 · 便携    → exe 所在目录（绿色部署 / U 盘场景，数据随 exe 走）
  3. 冻结态 · 用户目录 → %LOCALAPPDATA%\\IPScanner（Windows）
                        ~/.local/share/IPScanner（Linux/macOS）
  4. 兜底            → 系统临时目录下的 IPScanner

之所以需要 2→3 的回退：exe 被放进 C:\\Program Files\\ 这类受保护目录时，
普通用户对该目录没有写权限，直接在此建 SQLite 会抛
`unable to open database file`，导致程序启动即崩溃。
"""
import os
import sys
import tempfile

_APP_DIR_NAME = "IPScanner"

# 缓存探测结果，避免每次调用都做一次磁盘写入探测
_data_dir_cache = None
_data_dir_source = None      # "dev" / "portable" / "user" / "temp"

_SOURCE_LABELS = {
    "dev": "开发模式（源码目录）",
    "portable": "便携模式（exe 所在目录）",
    "user": "用户数据目录",
    "temp": "临时目录（数据不会长期保留）",
}


def is_frozen():
    """是否处于 PyInstaller 打包后的运行环境。"""
    return getattr(sys, "frozen", False)


def resource_dir():
    """返回资源文件（图片等）所在目录。"""
    if is_frozen():
        # 单文件 exe：资源被解压到临时目录 sys._MEIPASS
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def _probe_writable(path):
    """实际写一个临时文件来验证目录可写（os.access 在 Windows 上不可靠）。"""
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        return False
    try:
        fd, probe = tempfile.mkstemp(prefix=".wprobe_", dir=path)
        os.close(fd)
        os.remove(probe)
        return True
    except Exception:
        return False


def _user_data_dir():
    """平台标准的用户级可写数据目录。"""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, _APP_DIR_NAME)


def _resolve_data_dir():
    """按策略探测并返回 (目录, 来源标记)。"""
    if not is_frozen():
        return os.path.dirname(os.path.abspath(__file__)), "dev"

    # 1) 便携模式：exe 所在目录可写则数据随 exe 走
    try:
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    except Exception:
        exe_dir = ""
    if exe_dir and _probe_writable(exe_dir):
        return exe_dir, "portable"

    # 2) 回退到用户数据目录（Program Files 等受保护目录场景）
    user_dir = _user_data_dir()
    if _probe_writable(user_dir):
        return user_dir, "user"

    # 3) 最后兜底：临时目录，至少保证程序能启动
    tmp_dir = os.path.join(tempfile.gettempdir(), _APP_DIR_NAME)
    try:
        os.makedirs(tmp_dir, exist_ok=True)
    except Exception:
        # 走到这里说明源码目录 / exe 目录 / 用户数据目录 / 临时目录全部不可写，
        # 已无路可退；返回该路径让调用方在真正写文件时抛出可读的错误。
        # 此处不能记日志 —— app_logging 依赖本模块，此时它还没就绪。
        pass
    return tmp_dir, "temp"


def data_dir():
    """返回用户数据（db/ini/日志）目录，保证可写且持久化。"""
    global _data_dir_cache, _data_dir_source
    if _data_dir_cache is None:
        _data_dir_cache, _data_dir_source = _resolve_data_dir()
    return _data_dir_cache


def data_dir_source():
    """返回数据目录来源标记："dev" / "portable" / "user" / "temp"。"""
    if _data_dir_source is None:
        data_dir()
    return _data_dir_source


def data_dir_label():
    """返回数据目录来源的中文说明（供「关于」对话框 / 状态栏展示）。"""
    return _SOURCE_LABELS.get(data_dir_source(), data_dir_source())


def is_portable():
    """数据是否随 exe 存放（便携模式）。"""
    return data_dir_source() == "portable"


def reset_cache():
    """清除路径探测缓存（仅供测试使用）。"""
    global _data_dir_cache, _data_dir_source
    _data_dir_cache = None
    _data_dir_source = None
