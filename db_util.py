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

from app_logging import get_logger

_log = get_logger(__name__)

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
        except Exception as e:  # noqa: BLE001
            # 连接已坏时 close 会抛错，此时连接也已被移除，无需再处理
            _log.debug("关闭数据库连接失败 %s: %s", db_path, e)


def close_all():
    """关闭所有缓存连接（应用退出前调用）。

    关闭前先做一次 `wal_checkpoint(TRUNCATE)`：把 WAL 里尚未并回主库的内容
    写进 .db，并把 -wal 截断为 0。否则进程退出后会残留 `oui.db-wal` /
    `*.db-shm`（仓库里就出现过这两个文件），而且"直接拷 .db 就能用"这个
    假设会不成立 —— 最后一批写入还在 WAL 里。
    """
    with _dict_lock:
        items = list(_conns.items())
        _conns.clear()
    for _path, (conn, _lock) in items:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception as e:  # noqa: BLE001
            # 非 WAL 模式的库执行 checkpoint 会直接报错，属预期情况
            _log.debug("WAL checkpoint 跳过 %s: %s", _path, e)
        try:
            conn.close()
        except Exception as e:  # noqa: BLE001
            _log.debug("关闭数据库连接失败 %s: %s", _path, e)


def shutdown():
    """退出前的安全清理入口：关闭全部连接（含 WAL checkpoint），**保证不抛异常**。

    供 GUI 的 `aboutToQuit` 与 CLI 的 `finally` 共用。做成"不抛异常"是有意的：
    退出路径上的清理一旦抛异常，用户看到的是"窗口关不掉"或"退出码不对"，
    比残留一个 -wal 文件严重得多。
    """
    try:
        close_all()
    except Exception as e:  # noqa: BLE001
        # close_all 内部已逐条容错，这里只兜住意料之外的失败（例如字典被并发改动）。
        # 退出清理失败不应影响退出本身。
        _log.debug("关闭数据库连接时出现意外错误: %s", e)