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

import json
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
REASON_NO_RANGE_DATA = "no_range_data"
REASON_INSUFFICIENT_SAMPLES = "insufficient_samples"
#: 窗口内**一条 `port_open` / `port_close` 都没有**（v2.3 §3.3）。
#: ⚠️ 与 `REASON_NO_RECORDS` **分开**：趋势行有、曲线画得出，但端口事件没有，
#: 这两件事的下一步动作不同（前者去跑扫描，后者只说明"窗口内端口没开关过"）。
REASON_NO_PORT_EVENTS = "no_port_events"


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


def row_range_counts(row: dict) -> Dict[str, dict]:
    """一行趋势的按网段计数 → `{网段: {"total": int, "online": int}}`。

    `ranges_json` 有三种可能，全都**不抛**：
    * JSON 字符串（正常情况，`history_store._range_counts()` 写的）；
    * 已是 list（调用方先 `json.loads` 过）；
    * 旧格式 / 空（v2.3 §3.2 之前是纯网段名列表，或压根没写）⇒ 返回 `{}`
      —— 没有每网段计数可给，按网段视图自然为空（**不猜**）。
    """
    raw = row.get("ranges_json")
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            items = json.loads(raw)
        except (TypeError, ValueError):
            return {}
    else:
        items = raw
    if not isinstance(items, list):
        return {}
    out: Dict[str, dict] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        name = it.get("range")
        if not isinstance(name, str) or not name:
            continue
        out[name] = {"total": _as_int(it.get("total")),
                     "online": _as_int(it.get("online"))}
    return out


def range_names(rows: Iterable[dict]) -> List[str]:
    """窗口内出现过的网段名（去重、升序）—— GUI 下拉与 CLI `--range` 的取值来源。"""
    names = set()
    for r in rows:
        names.update(row_range_counts(r))
    return sorted(names)


def online_ratio_series(rows: Iterable[dict], granularity: str = "raw",
                        range_name: Optional[str] = None) -> List[dict]:
    """把观测行转成曲线点：`[{"time":…, "total":…, "online":…, "ratio":…}]`。

    `ratio` 是 0.0–1.0 的浮点数；`total` 为 0 的行**仍然输出**
    （`ratio` 为 0.0），因为"这轮扫到 0 台"本身是有效观测 ——
    但它与"没有观测"是两回事，后者由调用方用 `REASON_NO_RECORDS` 表达。

    `range_name` 非空时画**该网段**的曲线：只取该网段每行的 `total`/`online`，
    不含该网段的行**跳过**（那次扫描没扫它）。🔴 计数是写入端按网段算好的
    （`history_store._range_counts()`）—— 读的时候拆不出来，所以旧数据
    （没有每网段计数）在按网段视图里就是空的，这是事实不是缺陷。

    `granularity` 不是 `GRANULARITY_CHOICES` 里的值时抛 `ValueError`。
    """
    if granularity not in GRANULARITY_CHOICES:
        raise ValueError("未知粒度：%s（可选：%s）"
                         % (granularity, "/".join(GRANULARITY_CHOICES)))
    # 先归一化成"全局 或 选定网段"的 total/online，再交给 `bucket_by_day` ——
    # 这样分档聚合逻辑只有一份（`bucket_by_day` 只认 total/online/time）。
    source = []
    for r in rows:
        if range_name is None:
            total, online = _as_int(r.get("total")), _as_int(r.get("online"))
        else:
            hit = row_range_counts(r).get(range_name)
            if hit is None:
                continue
            total, online = hit["total"], hit["online"]
        source.append({"time": r.get("time"), "total": total, "online": online,
                       "offline": max(total - online, 0)})
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


# ── 时长单位（🔴 语言无关的规范值，由调用方 `tr()` 后再拼） ─────────────────
#
# 本模块**不 import `i18n`**，所以不能返回"20.0 分钟"这种已经拼好的中文 ——
# 那等于把显示层的事塞进领域层。只给单位名，让 CLI / GUI 各自翻译。
DURATION_UNIT_SECOND = "second"
DURATION_UNIT_MINUTE = "minute"
DURATION_UNIT_HOUR = "hour"
DURATION_UNIT_DAY = "day"
DURATION_UNIT_NONE = "insufficient"


def duration_parts(seconds):
    """秒 → `(数值, 单位规范值)`；`None` / 非法 → `(None, insufficient)`。

    分档：< 60 秒用秒，< 1 小时用分钟，< 1 天用小时，再往上用天。
    """
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return (None, DURATION_UNIT_NONE)
    if value != value or value in (float("inf"), float("-inf")):  # NaN / inf
        return (None, DURATION_UNIT_NONE)
    if value < 0:
        value = 0.0
    if value < 60:
        return (value, DURATION_UNIT_SECOND)
    if value < 3600:
        return (value / 60.0, DURATION_UNIT_MINUTE)
    if value < 86400:
        return (value / 3600.0, DURATION_UNIT_HOUR)
    return (value / 86400.0, DURATION_UNIT_DAY)


def _flips_by_device(events):
    """`status_flip` 事件按设备分组 → `{identity_key: [(ts, to_status), ...]}`。

    每组按 `ts` 升序（不管调用方给的是什么顺序）。
    """
    out: Dict[str, List[tuple]] = {}
    for e in events:
        if e.get("event_type") != EVENT_STATUS_FLIP:
            continue
        try:
            detail = json.loads(e.get("detail_json") or "{}")
        except (TypeError, ValueError):
            continue
        if detail.get("to") not in ("online", "offline"):
            continue
        try:
            ts = float(e.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        out.setdefault(e.get("identity_key", ""), []).append(
            (ts, detail["to"]))
    for seq in out.values():
        seq.sort(key=lambda kv: kv[0])
    return out


def stability(events, top=10):
    """稳定性：抖动次数 / MTBF / MTTR / 抖得最凶的几台。

    🔴 **这是采样近似，不是连续监控** —— 我们只知道"扫描那一刻"的状态，
    真实掉线发生在两次扫描之间 ⇒ **精度下限就是扫描间隔**。
    若扫描间隔（1 天）远大于掉线时长（5 分钟），短抖动会被**完全漏掉**：
    这时"翻转 0 次"不代表网络稳定，只代表"没看见"。

    所以样本不足时 MTBF / MTTR 返回 **`None`** 并给
    `reason=insufficient_samples` —— 🔴 **不返回 0.0 冒充结果**
    （照 v2.2 §3.4-a「数据不可信报 UNKNOWN 不猜 OK」的原则）。

    返回键：`devices` / `flips` / `failures` / `mtbf_seconds` /
    `mttr_seconds` / `mtbf_samples` / `mttr_samples` / `reason` / `flappers`。
    """
    flips = _flips_by_device(events)
    if not flips:
        return {"devices": 0, "flips": 0, "failures": 0,
                "mtbf_seconds": None, "mttr_seconds": None,
                "mtbf_samples": 0, "mttr_samples": 0,
                "reason": REASON_INSUFFICIENT_SAMPLES, "flappers": []}

    between = []   # 相邻两次掉线之间的时长 ≈ 无故障时间（MTBF 的分子）
    repair = []    # 掉线 → 恢复的时长（MTTR）
    per_device = []
    for key, seq in flips.items():
        offs = [ts for ts, st in seq if st == "offline"]
        ons = [ts for ts, st in seq if st == "online"]
        per_device.append({"identity_key": key, "flips": len(seq),
                           "failures": len(offs)})
        between.extend(b - a for a, b in zip(offs, offs[1:]) if b > a)
        for off_ts in offs:
            later = [t for t in ons if t >= off_ts]
            if later:
                repair.append(later[0] - off_ts)

    per_device.sort(key=lambda d: (-d["flips"], d["identity_key"]))
    return {
        "devices": len(flips),
        "flips": sum(d["flips"] for d in per_device),
        "failures": sum(d["failures"] for d in per_device),
        "mtbf_seconds": (sum(between) / len(between)) if between else None,
        "mttr_seconds": (sum(repair) / len(repair)) if repair else None,
        "mtbf_samples": len(between),
        "mttr_samples": len(repair),
        "reason": None if between else REASON_INSUFFICIENT_SAMPLES,
        "flappers": per_device[:top] if top else per_device,
    }


def first_seen_devices(events, limit=None):
    """窗口内**新出现**的设备（按时间降序，最近优先）。

    只认 `first_seen` 事件 —— 它天然就是"新出现的身份键"，
    🔴 不需要拿"上一次快照"来比：那份快照随时可能被 `prune()` 删掉，
    于是"新增 0 台"到底是真没有还是基线丢了，用户无从分辨
    （这正是 §3.1 把 `new_count` 从趋势表里拿掉的原因）。
    """
    out = []
    for e in events:
        if e.get("event_type") != EVENT_FIRST_SEEN:
            continue
        try:
            detail = json.loads(e.get("detail_json") or "{}")
        except (TypeError, ValueError):
            detail = {}
        try:
            ts = float(e.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        out.append({"ts": ts, "identity_key": e.get("identity_key", ""),
                    "ip": detail.get("ip", ""), "mac": detail.get("mac", "")})
    out.sort(key=lambda d: -d["ts"])
    return out[:limit] if limit else out


# ── 端口长期暴露时长（v2.3 §3.3）─────────────────────────────────────
#
# 🔴 为什么必须重放 `asset_events` 而不是读 `assets.open_ports`：
#    后者只存**此刻**开放的端口串，没有时间维度 ——
#    「这个 23 端口是昨天开的还是开了两年」答不上来。
#
# 🔴 为什么只记**实际开放**的端口（新旧差集）而不是"扫过的全部端口"：
#    `all` 档有 65535 个端口，逐端口落库会胀爆（v2.2 §3.3 的教训）。
#    两侧都是"开着的端口"，差集天然很小。


def _port_events_by_device(events):
    """`port_open` / `port_close` 按设备分组 → `{key: [(ts, 类型, 端口, baseline, ip), …]}`。

    每组按 `ts` 升序；同 `ts` 时保持调用方给的顺序（即 `id` 序 —— `list.sort`
    是稳定的），所以「同一次扫描写下的 open 与 close」次序不会被打乱。

    `detail_json` 坏掉 / 不是对象 / `ports` 不是列表 / 端口不是整数 的行**跳过**
    （不抛）：一行坏数据不该让整张暴露表消失。
    """
    out = {}
    for e in events:
        etype = e.get("event_type")
        if etype not in (EVENT_PORT_OPEN, EVENT_PORT_CLOSE):
            continue
        try:
            detail = json.loads(e.get("detail_json") or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(detail, dict):
            continue
        ports = detail.get("ports")
        if not isinstance(ports, list):
            continue
        try:
            ts = float(e.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        key = e.get("identity_key", "")
        ip = str(detail.get("ip") or "")
        baseline = bool(detail.get("baseline"))
        for p in ports:
            try:
                port = int(p)
            except (TypeError, ValueError):
                continue
            out.setdefault(key, []).append((ts, etype, port, baseline, ip))
    for seq in out.values():
        seq.sort(key=lambda row: row[0])
    return out


def port_exposure(events, now=None, identity_key=None, top=None):
    """端口长期暴露时长：按设备、按端口重放 `port_open` / `port_close`。

    `open` 记下起点，`close` 收一段闭合区间；窗口结束时仍未闭合的，
    暴露时长 = `now − 起点`。

    🔴 **从最近一次 open 起算**：`close` 会把起点清掉，所以
    「开 → 关 → 再开」报的是**再开那一刻**起的时长，不是首次。

    🔴 **`baseline` 为真的行，起点是"我们第一次观测到它"，不是"端口真的开了"**：
    那类端口的真实开放时刻只会**更早** ⇒ 它给的是时长**下界**，调用方必须
    显示成「**至少** N」。当成准确起点会**低估**暴露时长 —— 而低估暴露时长
    恰好是**危险**的那个方向（照 §3.2 的「只陈述事实」红线）。

    参数：
    * `now` —— 算时长的"当前时刻"（默认 `time.time()`；测试传固定值）；
    * `identity_key` —— 只算这一台（设备详情面板用），`None` 表示全部；
    * `top` —— 两个列表各截断到前 N 条。⚠️ `open_count` / `closed_count`
      仍是**截断前**的真实条数（与 `stability(top=…)` 同口径）。

    返回键：`devices` / `open` / `closed` / `open_count` / `closed_count` / `reason`。
    * `open` —— 仍在暴露的 `(设备, 端口)`，按 `seconds` 降序（最久的在最前）；
    * `closed` —— 已闭合区间，按 `end` 降序；
    * `reason` —— 一条 `port_*` 事件都没有 ⇒ `REASON_NO_PORT_EVENTS`（**不给空表**）；
      有事件但都已闭合 ⇒ `None` + `open_count == 0`，那是事实
      「当前没有暴露中的端口」，**不是**"没数据"。
    """
    current = time.time() if now is None else now
    by_dev = _port_events_by_device(events)
    if identity_key is not None:
        by_dev = {identity_key: by_dev.get(identity_key, [])}

    open_rows, closed_rows = [], []
    devices = 0
    for key, seq in by_dev.items():
        if not seq:
            continue
        devices += 1
        # 设备最近一次被看到的 IP（取序列里最后一个非空值）—— 展示用。
        ip = ""
        for _ts, _et, _port, _base, row_ip in reversed(seq):
            if row_ip:
                ip = row_ip
                break
        started: Dict[int, tuple] = {}   # port -> (since_ts, baseline)
        for ts, etype, port, baseline, _row_ip in seq:
            if etype == EVENT_PORT_OPEN:
                # 🔴 重复 open（中间没有 close）**不覆盖**起点：保留更早的那个
                #    = 更长的暴露时长 = 更保守的判断。`baseline` 重放时最容易
                #    出现（状态缺失 / 库被清过），那时把时长改短是错的方向。
                started.setdefault(port, (ts, baseline))
                continue
            prev = started.pop(port, None)
            if prev is None:
                continue   # 没见过 open 的 close：忽略（不猜）
            closed_rows.append({
                "identity_key": key, "ip": ip, "port": port,
                "start": prev[0], "end": ts,
                "seconds": max(ts - prev[0], 0.0),
                "baseline": prev[1],
            })
        for port, (since, baseline) in started.items():
            open_rows.append({
                "identity_key": key, "ip": ip, "port": port,
                "since": since,
                "seconds": max(current - since, 0.0),
                "baseline": baseline,
            })

    open_rows.sort(key=lambda r: (-r["seconds"], r["identity_key"], r["port"]))
    closed_rows.sort(key=lambda r: (-r["end"], r["identity_key"], r["port"]))
    open_count, closed_count = len(open_rows), len(closed_rows)
    if top:
        open_rows, closed_rows = open_rows[:top], closed_rows[:top]
    return {
        "devices": devices,
        "open": open_rows,
        "closed": closed_rows,
        "open_count": open_count,
        "closed_count": closed_count,
        "reason": None if devices else REASON_NO_PORT_EVENTS,
    }
