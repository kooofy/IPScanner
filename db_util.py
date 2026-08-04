# -*- coding: utf-8 -*-
"""线程安全的 SQLite 单例连接管理器。

按 db_path 缓存连接，惰性创建，check_same_thread=False 允许跨线程复用。
每条连接配一把锁串行化该连接上的并发操作，避免 SQLite 'database is locked'。
init_fn 仅在首次创建连接时执行一次（建表 / 去重等初始化）。

用法：
    with db_util.connection(path, init_fn=_init_db, pragmas=("PRAGMA journal_mode=WAL",)) as conn:
        rows = conn.execute(...).fetchall()
"""
import contextlib
import sqlite3
import threading

_conns = {}                  # db_path -> (conn, lock)
_dict_lock = threading.Lock()


def get_connection(db_path, init_fn=None, pragmas=()):
    """返回 (conn, lock)，惰性创建并按 db_path 缓存。"""
    with _dict_lock:
        entry = _conns.get(db_path)
        if entry is None:
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            for p in pragmas:
                conn.execute(p)
            if init_fn:
                init_fn(conn)
            entry = (conn, threading.Lock())
            _conns[db_path] = entry
    return entry


@contextlib.contextmanager
def connection(db_path, init_fn=None, pragmas=()):
    """上下文管理器：获取单例连接并加锁，yield conn。"""
    conn, lock = get_connection(db_path, init_fn, pragmas)
    with lock:
        yield conn


def close_connection(db_path):
    """关闭并移除某路径的连接（供测试 teardown / 库重建调用）。"""
    with _dict_lock:
        entry = _conns.pop(db_path, None)
    if entry:
        try:
            entry[0].close()
        except Exception:
            pass


def close_all():
    """关闭所有缓存连接。"""
    with _dict_lock:
        items = list(_conns.items())
        _conns.clear()
    for _, (conn, _lock) in items:
        try:
            conn.close()
        except Exception:
            pass