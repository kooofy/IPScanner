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


def _user_version(conn) -> int:
    """读 `PRAGMA user_version`（未设置过时为 0）。"""
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _table_exists(conn, name) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def infer_legacy_version(conn, legacy_tables) -> int:
    """给"引入 `user_version` 之前建的库"推断它相当于哪一版。

    做法是看**哪些表已经存在** —— 每张表属于引入它的那一版，取其中最大的版本号。
    比写死一个常量稳：老库的形态不止一种（同一个 `scan_history.db`，v1.7.6 之前只有
    `snapshots`/`devices`，加了定位查询才有 `switch_map`/`port_map`，四刀之后才有
    `security_findings`）—— 写死常量会让"只建到一半的老库"被误判成最新版，
    于是缺的那几张表永远不会被补上。

    没有任何已知表 → 返回 0（新库，走完整迁移链）。
    """
    version = 0
    for table, introduced in legacy_tables:
        if introduced > version and _table_exists(conn, table):
            version = introduced
    return version


def apply_migrations(conn, migrations, legacy_tables=()):
    """按 `PRAGMA user_version` 顺序应用迁移链，返回最终版本号。

    - `migrations`：`[(版本号, SQL 脚本, 说明), ...]`，版本号**连续且从 1 开始**。
    - `legacy_tables`：`[(表名, 引入它的版本号), ...]`，用于识别"引入 `user_version`
      之前建的库"（表都在、版本号却是 0）。

    为什么需要 `legacy_tables`：`user_version` 是**后加的**。加它之前发布的那些库
    结构完全正确，只是版本号是 0。若把 0 一律当成"全新库"去重放迁移 1..N，
    现在的迁移恰好全是 `IF NOT EXISTS` 所以无害，但**将来任何一条 `ALTER TABLE`
    的迁移都会被重复执行** —— 轻则报错，重则改错数据。所以先按已有表**推断**出它
    的真实版本、直接盖章，不重放。

    库的版本比程序支持的还高（用新版建的库被旧版程序打开）时**不降级、不报错**，
    只记一条 warning 后原样返回 —— 报错会让"回退到旧版 exe"变成一个打不开的库，
    比版本不一致严重得多。
    """
    current = _user_version(conn)
    if current == 0:
        inferred = infer_legacy_version(conn, legacy_tables)
        if inferred:
            current = inferred
            _log.info("历史库无 schema 版本号，按已有表推断为 v%d", current)
    if current > migrations[-1][0]:
        _log.warning(
            "库的 schema 版本 v%d 高于本程序支持的 v%d，跳过迁移",
            current, migrations[-1][0],
        )
        return current
    for version, script, desc in migrations:
        if version <= current:
            continue
        _log.info("应用 schema 迁移 v%d：%s", version, desc)
        conn.executescript(script)
        # `PRAGMA` 不支持参数绑定，只能拼字符串。version 来自调用方的模块常量，
        # 不是外部输入。
        conn.execute("PRAGMA user_version = %d" % version)
        current = version
    # 统一落盘：新库走完循环已是 SCHEMA_VERSION；老库推断出的版本在这一步才写进去。
    if _user_version(conn) != current:
        conn.execute("PRAGMA user_version = %d" % current)
    conn.commit()
    return current


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