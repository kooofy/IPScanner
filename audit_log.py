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
# 存库值一律使用**语言无关的规范代码**（下面的小写字符串）。
# 旧版本曾把 tr() 的结果直接入库（中文环境写「扫描」、英文环境写「Scan」），
# 同一个逻辑分类在库里变成两个不同的值，导致按分类筛选和统计失效。
# 显示时才通过 category_label() 翻译，因此切换语言不会污染历史数据。
CAT_SCAN = "scan"
CAT_CONFLICT = "conflict"
CAT_RANGE = "range"
CAT_RESULT = "result"
CAT_LIBRARY = "library"
CAT_EXPORT = "export"
CAT_DEVICE = "device"
CAT_SYSTEM = "system"

CATEGORIES = [
    CAT_SCAN, CAT_CONFLICT, CAT_RANGE, CAT_RESULT,
    CAT_LIBRARY, CAT_EXPORT, CAT_DEVICE, CAT_SYSTEM,
]

# 规范代码 -> 翻译原文（显示时再 tr()，切勿在 import 期求值）
_CATEGORY_TEXT = {
    CAT_SCAN: "扫描",
    CAT_CONFLICT: "冲突检测",
    CAT_RANGE: "网段",
    CAT_RESULT: "结果",
    CAT_LIBRARY: "地址库",
    CAT_EXPORT: "导出",
    CAT_DEVICE: "设备操作",
    CAT_SYSTEM: "系统",
}

# 历史库兼容：旧版本入库的是翻译后的字符串，两种语言都要能识别
_LEGACY_CATEGORY_MAP = {}
for _code, _text in _CATEGORY_TEXT.items():
    _LEGACY_CATEGORY_MAP[_text] = _code          # 中文原文
    _LEGACY_CATEGORY_MAP[_text.lower()] = _code
for _code, _text in (
    (CAT_SCAN, "Scan"), (CAT_CONFLICT, "Conflict"), (CAT_RANGE, "Range"),
    (CAT_RESULT, "Result"), (CAT_LIBRARY, "Library"), (CAT_EXPORT, "Export"),
    (CAT_DEVICE, "Device"), (CAT_SYSTEM, "System"),
):
    _LEGACY_CATEGORY_MAP[_text] = _code
    _LEGACY_CATEGORY_MAP[_text.lower()] = _code


def category_label(code: str) -> str:
    """分类代码 -> 当前语言的显示名（惰性翻译，切换语言后立即生效）。

    未知代码原样返回，避免历史数据因代码变更而显示为空。
    """
    if not code:
        return ""
    text = _CATEGORY_TEXT.get(code)
    if text is None:
        return str(code)
    return tr(text)


def normalize_category(value: str) -> str:
    """把任意（含旧版本翻译后的）分类值归一为规范代码。"""
    if not value:
        return ""
    v = str(value).strip()
    if v in _CATEGORY_TEXT:            # 已是规范代码
        return v
    return _LEGACY_CATEGORY_MAP.get(v, _LEGACY_CATEGORY_MAP.get(v.lower(), v))


def _migrate_legacy_categories(conn):
    """把库里历史遗留的「翻译后分类」就地改写为规范代码（幂等）。"""
    try:
        rows = conn.execute(
            "SELECT DISTINCT category FROM audit_logs WHERE category <> ''"
        ).fetchall()
    except Exception:
        return 0
    migrated = 0
    for row in rows:
        old = row["category"]
        new = _LEGACY_CATEGORY_MAP.get(old)
        if new and new != old:
            conn.execute(
                "UPDATE audit_logs SET category=? WHERE category=?", (new, old)
            )
            migrated += 1
    if migrated:
        conn.commit()
    return migrated

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
    _migrate_legacy_categories(conn)



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

    - category: 仅该分类（None = 全部）。接受规范代码，也兼容旧版翻译后的值。
    - keyword:  在 action / detail / category 中模糊匹配（None = 全部）
    """
    category = normalize_category(category)
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
    """统计日志条数（可按分类过滤）。接受规范代码或旧版翻译后的值。"""
    category = normalize_category(category)
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
