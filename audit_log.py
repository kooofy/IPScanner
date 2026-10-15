# -*- coding: utf-8 -*-
"""审计日志的 SQLite 存储。

记录扫描活动事件（开始/停止/完成、网段操作、冲突检测、结果清理等），
用于操作回溯与安全审计。

- 单表 audit_logs：ts / category / action / detail
- 支持按分类，关键词查询，保留上限自动裁剪（默认最近 1000 条）

纯标准库 + sqlite3，无 PyQt 依赖，便于单元测试。
"""
import contextlib
import json
import os
import time
from app_paths import data_dir
from app_logging import get_logger
from i18n import tr

import db_util

_audit_log = get_logger(__name__)

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


# ══════════════════════════════════════════════════════════════════════
#  扫描汇总事件（v2.2 §3.3 自查视图）
# ══════════════════════════════════════════════════════════════════════

# 既有扫描事件的 action / detail 是**给人看的本地化文本**（`tr()` 的结果
# 直接入库，历史如此，老 viewer 照旧）。拿它们做聚合就是"拿 tr() 结果作
# 比较" —— 切一次界面语言，同一类事件在 GROUP BY 里裂成两行，聚合结果
# 随界面语言漂移（项目铁律：绝不把 tr() 结果写库或作比较）。
#
# 因此自查视图专用一条事件：
#   * `action` = 规范码 `SUM_ACTION`（永不翻译，筛选条件只用它）；
#   * `detail` = JSON，键与值**全部语言无关**（网段串 / 整数计数 / 协议码）。
#
# 🔴 数据源仍然**只有 audit_logs 一张表**：不新增采集器、不建新库、
# 不改既有事件的写入方式 —— "不新增采集"指的是采集机制，一次扫描多写
# 一行汇总事件是同一套 `log_event()` 管道，不引入第二个数据源。
SUM_ACTION = "scan-summary"

# detail JSON 的 schema（读时逐项兜底，缺失键按"未记录"处理，绝不猜测）
SUM_SCHEMA_KEYS = (
    "ranges",        # [{"range": str, "ips": int}, ...] 本次网段与各自地址数
    "ips",           # int  本次覆盖的地址总数
    "online",        # int  本次发现的在线设备数
    "protocols",     # [str, ...] 应用层协议规范码（HTTP / SSH / SNMP...）
    "ports_scanned",  # int|None 端口探测的端口数；None = 本次没扫端口
    "throttle",      # str  礼貌档规范名（fast / polite...）
    "source",        # str  "gui" / "cli" —— 出口，便于核对两条路径都记账
)

# 时间窗选项（显示值 -> 小时数；None = 全部历史）
WINDOW_CHOICES = {"24h": 24, "7d": 168, "all": None}

# 空数据的 reason（照抄 history_store.port_utilization() 的教训：
# 绝不返回空表让用户得出反结论）
REASON_NO_RECORDS = "no_records"


def _normalize_summary(summary) -> dict:
    """把外部传入的 summary 收敛成**只含语言无关值**的 dict。

    入参来自 GUI / CLI 调用点，可能是 None / 缺键 / 类型不对 —— 逐项兜底
    而不是抛：记账失败不该把一次已经成功的扫描拖失败（与
    `_audit_throttle` 同口径：审计是旁路）。
    """
    src = summary if isinstance(summary, dict) else {}
    out = {}

    ranges = []
    for item in src.get("ranges") or []:
        if isinstance(item, dict):
            r = str(item.get("range") or "").strip()
            try:
                n = int(item.get("ips") or 0)
            except (TypeError, ValueError):
                n = 0
        else:
            r, n = str(item).strip(), 0
        if r:
            ranges.append({"range": r[:120], "ips": max(0, n)})
    out["ranges"] = ranges

    def _int(key):
        try:
            return max(0, int(src.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    out["ips"] = _int("ips")
    out["online"] = _int("online")

    protos = []
    for p in src.get("protocols") or []:
        # 只收字符串规范码：None / 数字之类是**上游类型错**，跳过而不是
        # str() 成 "None" 进直方图 —— 聚合视图里出现 "None" 协议比缺一行
        # 更难排查（看着像真有这个协议）。
        if not isinstance(p, str):
            continue
        s = p.strip()
        if s and s not in protos:
            protos.append(s[:32])
    out["protocols"] = protos

    raw_ports = src.get("ports_scanned")
    out["ports_scanned"] = None if raw_ports is None else _int("ports_scanned")

    out["throttle"] = str(src.get("throttle") or "").strip()[:32]
    out["source"] = str(src.get("source") or "").strip()[:32]
    return out


def log_scan_summary(summary, db_path=None) -> None:
    """写一条扫描汇总事件（规范码 action + JSON detail）。不抛。"""
    payload = json.dumps(_normalize_summary(summary), sort_keys=True)
    log_event(CAT_SCAN, SUM_ACTION, payload, db_path=db_path)


def read_scan_summaries(since_ts=None, db_path=None) -> list:
    """按时间**正序**读扫描汇总事件，返回 ``[{"ts", "summary"}, ...]``。

    时间窗过滤在 **SQL 侧**完成（``WHERE ts>=?``）—— 不把全表事件捞进
    内存再筛。返回集合的规模上限 = prune 上限（一次扫描一行）。
    单条 detail 不是合法 JSON 时跳过并留痕（debug）—— 绝不静默。
    """
    with _conn(db_path) as conn:
        if since_ts is None:
            rows = conn.execute(
                "SELECT ts, detail FROM audit_logs "
                "WHERE category=? AND action=? ORDER BY ts",
                (CAT_SCAN, SUM_ACTION),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT ts, detail FROM audit_logs "
                "WHERE category=? AND action=? AND ts>=? ORDER BY ts",
                (CAT_SCAN, SUM_ACTION, float(since_ts)),
            ).fetchall()
    out = []
    for r in rows:
        try:
            data = json.loads(r["detail"])
            if not isinstance(data, dict):
                raise ValueError("detail 不是 JSON 对象")
        except (ValueError, TypeError) as e:
            _audit_log.debug("跳过无法解析的扫描汇总事件（ts=%s）：%s", r["ts"], e)
            continue
        out.append({"ts": float(r["ts"]), "summary": _normalize_summary(data)})
    return out


def estimated_probes(summary) -> int:
    """一次扫描的**估算**发包数（下限，不是精确计数）。

    只覆盖两条**确定走网络**的路径：
      * 主机发现：每个地址一发 ICMP（`engine.PingPhase` 逐 IP `ping_ip`）；
        直连网段上离线地址还会多一发 ARP（`ArpPhase`）—— 不计入 ⇒ 是**下限**；
      * 端口探测：只对**在线**设备做（`engine._enrich_device` 对离线设备
        不探端口）× `ports_scanned`。

    不在内的：mDNS 组播（每次扫描一发，可忽略）、协议识别的补充探测
    （端口已覆盖时跳过）、NetBIOS / WMI / SNMP 等按需 enrich。
    字段一律叫 ``estimated_*``，界面标注"估算" —— 没有真实包计数器，
    宁可给有据可查的下限，也不编一个精确数。
    """
    s = _normalize_summary(summary)
    probes = s["ips"]
    if s["ports_scanned"]:
        probes += s["online"] * s["ports_scanned"]
    return probes


def activity_summary(window_hours=24, db_path=None) -> dict:
    """聚合"过去一段时间向哪些网段发起了多少次扫描"（自查视图数据源）。

    Args:
        window_hours: 24 / 168 / None（None = 全部历史）。窗口过滤在 SQL 侧。
        db_path: 测试注入用。

    Returns:
        dict（键固定英文，供 CLI/JSON 与 GUI 共用）::

            {
              "reason": "",              # "" = 有数据；"no_records" = 窗口内无记录
              "window_hours": 24,        # None = 全部
              "scan_count": 3,           # 窗口内扫描次数
              "range_count": 2,          # 涉及的不同网段数
              "total_ips": 762,          # 覆盖地址总数（同一网段重复扫会累加）
              "total_online": 36,        # 在线设备总数（同上，按次累加）
              "estimated_probes": 1602,  # 发包估算（下限，见 estimated_probes）
              "port_scan_count": 1,      # 其中扫了端口的扫描次数
              "protocols": {"HTTP": 3},  # 协议规范码 -> 使用次数
              "throttles": {"fast": 2},  # 礼貌档规范名 -> 使用次数
              "ranges": [                # 按最近一次倒序
                {"range": "...", "scans": 2, "ips": 508,
                 "last_scan_ts": 123.0, "estimated_probes": 508}
              ],
              "first_ts": 111.0, "last_ts": 222.0,
            }

    🔴 **空数据必须给 reason**，不能返回空表让用户得出"我没扫过"的反结论
    （照抄 `history_store.port_utilization()` 的教训）。
    """
    if window_hours is not None:
        window_hours = float(window_hours)
        if window_hours <= 0:
            raise ValueError("window_hours 必须为正数或 None（全部）")
        # JSON / 界面契约：整数值回成 int（24 而不是 24.0）
        if window_hours.is_integer():
            window_hours = int(window_hours)
        since_ts = time.time() - window_hours * 3600.0
    else:
        since_ts = None

    rows = read_scan_summaries(since_ts=since_ts, db_path=db_path)
    if not rows:
        return {
            "reason": REASON_NO_RECORDS, "window_hours": window_hours,
            "scan_count": 0, "range_count": 0, "total_ips": 0,
            "total_online": 0, "estimated_probes": 0, "port_scan_count": 0,
            "protocols": {}, "throttles": {}, "ranges": [],
            "first_ts": None, "last_ts": None,
        }

    protocols = {}
    throttles = {}
    ranges = {}
    total_ips = total_online = 0
    port_scan_count = 0
    for row in rows:
        s = row["summary"]
        ts = row["ts"]
        total_ips += s["ips"]
        total_online += s["online"]
        if s["ports_scanned"]:
            port_scan_count += 1
        for p in s["protocols"]:
            protocols[p] = protocols.get(p, 0) + 1
        if s["throttle"]:
            throttles[s["throttle"]] = throttles.get(s["throttle"], 0) + 1
        for item in s["ranges"]:
            agg = ranges.setdefault(
                item["range"],
                {"range": item["range"], "scans": 0, "ips": 0,
                 "last_scan_ts": ts, "estimated_probes": 0},
            )
            agg["scans"] += 1
            agg["ips"] += item["ips"]
            agg["last_scan_ts"] = ts          # rows 正序，后写即更近
            agg["estimated_probes"] += item["ips"]

    range_list = sorted(
        ranges.values(),
        key=lambda a: (a["last_scan_ts"], a["range"]), reverse=True,
    )
    return {
        "reason": "", "window_hours": window_hours,
        "scan_count": len(rows), "range_count": len(range_list),
        "total_ips": total_ips, "total_online": total_online,
        "estimated_probes": sum(estimated_probes(r["summary"]) for r in rows),
        "port_scan_count": port_scan_count,
        "protocols": protocols, "throttles": throttles,
        "ranges": range_list,
        "first_ts": rows[0]["ts"], "last_ts": rows[-1]["ts"],
    }
