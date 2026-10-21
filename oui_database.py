# -*- coding: utf-8 -*-
"""
MAC OUI 厂商数据库
数据来源: IEEE 官方 OUI 数据库
存储: SQLite (oui.db) + 内存 LRU 缓存

路径优先级：data_dir()/oui.db（用户更新版）> resource_dir()/oui.db（内置版）
"""
import sqlite3
import os
import functools
import threading
from app_paths import resource_dir, data_dir


def _db_path():
    """返回 oui.db 路径。优先用户数据目录（可写），回退资源目录（只读内置）。"""
    user_path = os.path.join(data_dir(), "oui.db")
    if os.path.exists(user_path):
        return user_path
    bundled_path = os.path.join(resource_dir(), "oui.db")
    return bundled_path


_lock = threading.Lock()
_conn = None
_conn_init_lock = threading.Lock()
_db_path_cache = None


def _get_conn():
    """返回进程级单例只读连接（惰性初始化，双检锁保证只建一次）。"""
    global _conn, _db_path_cache
    if _conn is None:
        with _conn_init_lock:
            if _conn is None:
                _db_path_cache = _db_path()
                _conn = sqlite3.connect(_db_path_cache, check_same_thread=False)
    return _conn


@functools.lru_cache(maxsize=2048)
def _query_oui(prefix: str) -> str:
    """查询单个 OUI 前缀，SQLite 索引查找 O(1) + LRU 缓存"""
    try:
        with _lock:
            row = _get_conn().execute(
                "SELECT vendor FROM oui WHERE prefix=?", (prefix,)
            ).fetchone()
        return row[0] if row else ""
    except Exception:
        return ""


def get_mac_vendor(mac: str) -> str:
    """根据 MAC 地址获取厂商名称"""
    if not mac:
        return ""
    mac = mac.lower().replace("-", ":")
    if len(mac) < 8:
        return ""
    oui = mac[:8]
    return _query_oui(oui)


def is_randomized_mac(mac: str) -> bool:
    """判断 MAC 是否为「随机 / 本地管理」地址（IEEE 802 的 U/L 位 = 1）。

    首字节的 bit 1（掩码 0x02）是 U/L 位：**0 = 全局唯一**（厂商出厂烧录），
    **1 = 本地管理**（由操作系统生成）。手机 / 笔记本的「随机硬件地址」、
    虚拟网卡、部分热点的软 AP 都属于后者。

    🔴 为什么需要这个判据：随机 MAC 的前缀**不属于任何厂商**，`get_mac_vendor()`
    对它必然返回空串。界面若把"随机 MAC"和"OUI 库没收录"都显示成 `—`，
    用户就无法区分「这台是开了隐私地址的手机」和「这台是库里没收录的陌生设备」。
    两者该采取的动作完全不同，所以必须分开表达。

    容错：接受 `AA:BB:..` / `AA-BB-..`，大小写不敏感；空串与非法输入返回 False
    （**不**把无法解析的值当成随机 MAC —— 宁可显示 `—` 也不要误导）。
    """
    if not mac:
        return False
    head = mac.strip().replace("-", ":").split(":")[0]
    if len(head) != 2:
        return False
    try:
        return bool(int(head, 16) & 0x02)
    except ValueError:
        return False


def reload_db():
    """关闭并重新打开数据库连接（OUI 更新后调用）。"""
    global _conn, _db_path_cache
    with _conn_init_lock:
        if _conn is not None:
            _conn.close()
            _conn = None
        _db_path_cache = None
        _query_oui.cache_clear()


def current_db_path() -> str:
    """返回当前使用的 oui.db 路径（用于 UI 展示）。"""
    global _db_path_cache
    if _db_path_cache is None:
        _get_conn()
    return _db_path_cache or _db_path()
