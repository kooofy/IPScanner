# -*- coding: utf-8 -*-
"""审计日志的 SQLite 存储。

记录扫描活动事件（开始/停止/完成、网段操作、冲突检测、结果清理等），
用于操作回溯与安全审计。

- 单表 audit_logs：ts / category / action / detail
- 支持按分类，关键词查询，保留上限自动裁剪（默认最近 1000 条）

纯标准库 + sqlite3，无 PyQt 依赖，便于单元测试。
"""
import contextlib
import os
import time
from app_paths import data_dir
from i18n import tr

import db_util

DB_PATH = os.path.join(data_dir(), "audit_log.db")

# ── 事件分类 ──
CAT_SCAN = tr("扫描")
CAT_CONFLICT = tr("冲突检测")
CAT_RANGE = tr("网段")
CAT_RESULT = tr("结果")
CAT_LIBRARY = tr("地址库")
CAT_EXPORT = tr("导出")
CAT_DEVICE = tr("设备操作")
CAT_SYSTEM = tr("系统")

CATEGORIES = [
    CAT_SCAN, CAT_CONFLICT, CAT_RANGE, CAT_RESULT,
    CAT_LIBRARY, CAT_EXPORT, CAT_DEVICE, CAT_SYSTEM,
]

DEFAULT_MAX_KEEP = 1000

_PRAGMAS = ("PRAGMA journal_mode=WAL",)


def _init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       REAL NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            action   TEXT NOT NULL DEFAULT '',
            detail   TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
        CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit_logs(category);
        """
    )
    conn.commit()


@contextlib.contextmanager
def _conn(db_path=None):
    """复用进程级单例连接（按 db_path 缓存，线程安全）。"""
    path = db_path or DB_PATH
    with db_util.connection(path, init_fn=_init_db, pragmas=_PRAGMAS) as c:
        yield c


def log_event(category, action, detail="", db_path=None, max_keep=DEFAULT_MAX_KEEP):
    """记录一条审计事件，并按上限裁剪旧记录。"""
    with _conn(db_path) as conn:
        conn.execute(
            "INSERT INTO audit_logs (ts, category, action, detail) VALUES (?,?,?,?)",
            (time.time(), category, action, detail),
        )
        conn.commit()
    prune(max_keep=max_keep, db_path=db_path)


def query_logs(category=None, keyword=None, limit=DEFAULT_MAX_KEEP, db_path=None):
    """查询审计日志，按时间倒序（最新在前）返回 dict 列表。

    - category: 仅该分类（None = 全部）
    - keyword:  在 action / detail / category 中模糊匹配（None = 全部）
    """
    with _conn(db_path) as conn:
        sql = "SELECT id, ts, category, action, detail FROM audit_logs WHERE 1=1"
        args = []
        if category:
            sql += " AND category=?"
            args.append(category)
        if keyword:
            sql += " AND (action LIKE ? OR detail LIKE ? OR category LIKE ?)"
            kw = f"%{keyword}%"
            args.extend([kw, kw, kw])
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        rows = conn.execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def count_logs(category=None, db_path=None) -> int:
    """统计日志条数（可按分类过滤）。"""
    with _conn(db_path) as conn:
        if category:
            return conn.execute(
                "SELECT COUNT(*) AS c FROM audit_logs WHERE category=?", (category,)
            ).fetchone()["c"]
        return conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"]


def clear_logs(db_path=None):
    """清空全部审计日志。"""
    with _conn(db_path) as conn:
        conn.execute("DELETE FROM audit_logs")
        conn.commit()


def prune(max_keep=DEFAULT_MAX_KEEP, db_path=None):
    """仅保留最近 max_keep 条日志，删除更早的。"""
    if max_keep is None or max_keep <= 0:
        return
    with _conn(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"]
        if count > max_keep:
            excess = count - max_keep
            conn.execute(
                "DELETE FROM audit_logs WHERE id IN ("
                "SELECT id FROM audit_logs ORDER BY id ASC LIMIT ?)",
                (excess,),
            )
            conn.commit()
