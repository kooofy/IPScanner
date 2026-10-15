"""趋势观测层的**纯计算**部分（零 DB、零 PyQt）。

为什么单独开一个模块
--------------------
`history_store.py` 负责「趋势数据怎么存、怎么读」，本模块负责
「读出来之后怎么算」。拆开的理由和 `scanner/` 与 UI 的拆法一样：

- **可测**：本模块的输入是 `list[dict]`，输出是 `dict` —— 不需要建库、
  不需要 Qt、不需要 `ensure_qt_app()`，测试是纯函数级的（毫秒级）。
- **可复用**：CLI 与 GUI 拿同一份计算代码，口径不会分裂。

🔴 本模块**不 import `i18n`**、**不 import PyQt5**、**不碰 SQLite**。
   所有「显示给人看的文字」由调用方翻译；本模块产出的键与值一律
   **语言无关**（`status` 用 `online`/`offline`，事件类型用英文规范值）。

为什么趋势数据不能建在 `devices` 上
-----------------------------------
`history_store.prune(max_keep=20)` 只留最近 20 份快照，`devices` 靠
`ON DELETE CASCADE` 跟着被删 ⇒ 拿 `devices` 画曲线，曲线会**随时间自己变短**。
所以趋势行写进独立的 `trend_observations` / `asset_events`：
**无外键、不参与 prune、独立保留**。详见 `docs/ROADMAP_V2.3.md` §4。
"""

import time
from typing import Dict, Iterable, List, Optional

from app_logging import get_logger

_log = get_logger(__name__)

# ── 事件类型（🔴 语言无关的规范值，绝不 `tr()`）─────────────────────────
#
# 为什么用英文规范值而不是中文：这些值会被**落库**、被 JSON 导出、被比较。
# 一旦写进库的是 `tr()` 的结果，结论就会随界面语言漂移（v2.2 §3.3 的教训：
# 审计聚合当初就是因为事件名是中文才无法用）。
EVENT_FIRST_SEEN = "first_seen"
EVENT_STATUS_FLIP = "status_flip"
EVENT_PORT_OPEN = "port_open"
EVENT_PORT_CLOSE = "port_close"
EVENT_IP_CHANGED = "ip_changed"
EVENT_MAC_CHANGED = "mac_changed"
EVENT_MAC_RANDOMIZED = "mac_randomized"

#: 全部事件类型（顺序即文档顺序）。测试断言"库里的 event_type ⊆ 这张表"。
EVENT_TYPES = (
    EVENT_FIRST_SEEN,
    EVENT_STATUS_FLIP,
    EVENT_PORT_OPEN,
    EVENT_PORT_CLOSE,
    EVENT_IP_CHANGED,
    EVENT_MAC_CHANGED,
    EVENT_MAC_RANDOMIZED,
)

# ── 时间窗 ──────────────────────────────────────────────────────────
#
# 形态照 `audit_log.WINDOW_CHOICES`：`None` 表示"全部"，不设下界。
WINDOW_HOURS: Dict[str, Optional[int]] = {
    "24h": 24,
    "7d": 168,
    "30d": 720,
    "all": None,
}

#: `--window` 的取值顺序（CLI `choices` 与 GUI 下拉都用它，避免两处漂移）。
WINDOW_CHOICES = tuple(WINDOW_HOURS)

#: 粒度：`raw` 一次观测一个点，`day` 按自然日聚合成一个点。
GRANULARITY_CHOICES = ("raw", "day")

# ── 一行趋势观测的字段（🔴 语言无关，等于 `trend_observations` 的列）──────
TREND_SCHEMA_KEYS = (
    "time",
    "total",
    "online",
    "offline",
    "ranges_json",
    "ports_scanned",
    "duration_s",
    "source",
)

#: 趋势保留天数（默认一年）。一行几十字节 ⇒ 一年 365 行仅几十 KB。
DEFAULT_KEEP_DAYS = 365

# ── 空数据的理由（照 v2.2 §3.3 的口径：给 reason + 下一步，不给空表）──────
REASON_NO_RECORDS = "no_records"
REASON_OUT_OF_WINDOW = "out_of_window"
REASON_INSUFFICIENT_SAMPLES = "insufficient_samples"


def window_start(now: Optional[float] = None, window: str = "24h") -> Optional[float]:
    """返回时间窗的起始时间戳；`all` 返回 `None`（不设下界）。

    `window` 不在 `WINDOW_HOURS` 里时**抛 `ValueError`** —— 拼 SQL 的下界
    必须是可信值，静默当成"全部"会让用户以为"没数据"而实际是"参数写错"。
    """
    if window not in WINDOW_HOURS:
        raise ValueError("未知时间窗：%s（可选：%s）"
                         % (window, "/".join(WINDOW_CHOICES)))
    hours = WINDOW_HOURS[window]
    if hours is None:
        return None
    ts = time.time() if now is None else now
    return ts - hours * 3600.0


def normalize_hours(window: str) -> Optional[float]:
    """把时间窗名换成小时数（整数回 `int`，照 `audit_log.activity_summary` 的契约）。

    整数值回成 `int` 而不是 `float`：这个数会进 JSON，
    `24.0` 会让用户的 diff / 断言无谓地抖。
    """
    hours = WINDOW_HOURS[window]
    if hours is None:
        return None
    value = float(hours)
    return int(value) if value.is_integer() else value


def _as_int(value) -> int:
    """宽松转 int：空 / 非法一律 0，**不抛**。

    趋势数据来自落库的历史行，可能含空串或早期版本留下的脏值 ——
    这里抛异常会让"有一行坏数据"变成"整条曲线看不到"。
    """
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def online_ratio(online: object, total: object) -> float:
    """在线率（0.0–1.0）。**总数为 0 时返回 0.0 并记 debug**，不除零。

    ⚠️ "总数为 0"与"在线率为 0%"是两件事：前者是**没有观测**，
    后者是**观测到了但都不在线**。混同会让空数据看起来像"全离线"。
    """
    try:
        o = float(online or 0)
        t = float(total or 0)
    except (TypeError, ValueError):
        return 0.0
    if t <= 0:
        return 0.0
    ratio = o / t
    # 观测数不可能大于总数，越界说明上游写错了 —— 夹住但记一条 warning。
    if ratio > 1.0:
        _log.warning("在线数 %.0f 大于总数 %.0f，在线率被夹到 1.0", o, t)
        return 1.0
    return ratio


def _day_key(ts: float) -> int:
    """把时间戳折成「本地时区的自然日」序号。

    ⚠️ **必须按本地时区**：`time.localtime()` 与 `fromtimestamp()` 同口径。
    用 UTC 会让"今天"在东八区偏 8 小时，曲线上的点与用户的日历对不上。
    """
    lt = time.localtime(ts)
    return lt.tm_year * 10000 + lt.tm_mon * 100 + lt.tm_mday


def bucket_by_day(rows: Iterable[dict]) -> List[dict]:
    """把原始观测行按**自然日**聚合成一行一天。

    同一天多次扫描时：
    - `time` 取**当天最后一次**（画曲线用末值，符合"这天结束时什么样"）；
    - `total` / `online` / `offline` 取**当天最大值**（当天扫到的最大规模，
      取均值会被"只扫了一个子网的那次"拉低，进而让在线率失真）；
    - `samples` 是当天的观测次数（给"这天扫了几次"用）。

    返回按 `time` 升序。
    """
    buckets: Dict[int, dict] = {}
    for r in rows:
        try:
            ts = float(r.get("time") or 0)
        except (TypeError, ValueError):
            continue
        if ts <= 0:
            continue
        key = _day_key(ts)
        cur = buckets.get(key)
        if cur is None:
            buckets[key] = {
                "time": ts,
                "total": _as_int(r.get("total")),
                "online": _as_int(r.get("online")),
                "offline": _as_int(r.get("offline")),
                "samples": 1,
            }
            continue
        cur["samples"] += 1
        if ts >= cur["time"]:
            cur["time"] = ts
        for field in ("total", "online", "offline"):
            value = _as_int(r.get(field))
            if value > cur[field]:
                cur[field] = value
    return [buckets[k] for k in sorted(buckets)]


def online_ratio_series(rows: Iterable[dict], granularity: str = "raw") -> List[dict]:
    """把观测行转成曲线点：`[{"time":…, "total":…, "online":…, "ratio":…}]`。

    `ratio` 是 0.0–1.0 的浮点数；`total` 为 0 的行**仍然输出**
    （`ratio` 为 0.0），因为"这轮扫到 0 台"本身是有效观测 ——
    但它与"没有观测"是两回事，后者由调用方用 `REASON_NO_RECORDS` 表达。

    `granularity` 不是 `GRANULARITY_CHOICES` 里的值时抛 `ValueError`。
    """
    if granularity not in GRANULARITY_CHOICES:
        raise ValueError("未知粒度：%s（可选：%s）"
                         % (granularity, "/".join(GRANULARITY_CHOICES)))
    source = list(rows)
    if granularity == "day":
        source = bucket_by_day(source)
    # 🔴 **先过滤、再排序** —— 不能让 `sorted` 的 key 直接 float() 一个脏值：
    #    那会抛 ValueError 而不是"跳过这一行"，于是**一行坏数据毁掉整条曲线**
    #    （曲线是"看趋势"的入口，崩在这里用户什么都看不到）。
    clean = []
    for r in source:
        try:
            ts = float(r.get("time") or 0)
        except (TypeError, ValueError):
            continue
        if ts <= 0:
            continue
        clean.append((ts, r))
    clean.sort(key=lambda kv: kv[0])
    out = []
    for ts, r in clean:
        total = _as_int(r.get("total"))
        online = _as_int(r.get("online"))
        out.append({
            "time": ts,
            "total": total,
            "online": online,
            "ratio": online_ratio(online, total),
        })
    return out
