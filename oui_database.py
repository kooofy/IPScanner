# -*- coding: utf-8 -*-
"""
MAC OUI 厂商数据库
数据来源: IEEE 官方 OUI 数据库 (39,762 条记录)
存储: SQLite (oui.db) + 内存 LRU 缓存

比原来 1.4MB 的 Python 字典文件缩小了 97%，import 不再需要解析大量代码。
"""

import sqlite3
import os
import functools
import threading

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.db")
_LOCK = threading.Lock()

@functools.lru_cache(maxsize=2048)
def _query_oui(prefix: str) -> str:
    """查询单个 OUI 前缀，SQLite 索引查找 O(1) + LRU 缓存"""
    try:
        conn = sqlite3.connect(_DB_PATH)
        row = conn.execute("SELECT vendor FROM oui WHERE prefix=?", (prefix,)).fetchone()
        conn.close()
        return row[0] if row else ""
    except Exception:
        return ""


def get_mac_vendor(mac: str) -> str:
    """根据 MAC 地址获取厂商名称

    Args:
        mac: MAC 地址，格式如 "aa:bb:cc:dd:ee:ff" 或 "aa-bb-cc-dd-ee-ff"

    Returns:
        厂商名称字符串，未找到返回空字符串
    """
    if not mac:
        return ""
    mac = mac.lower().replace("-", ":")
    if len(mac) < 8:
        return ""
    oui = mac[:8]
    return _query_oui(oui)
