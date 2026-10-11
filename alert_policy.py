# -*- coding: utf-8 -*-
"""告警策略层：维护窗口 / 静音 / 通知去重（仅标准库、零 Qt）。

为什么需要这一层
----------------
告警系统的价值取决于**信噪比**。本项目已经有四个通知渠道
（``notifier.py``：webhook / 企业微信 / 钉钉 / 邮件）和外部定时扫描
（``scheduler.py``），但缺一层「这条到底要不要发」的判断 —— 于是：

* 凌晨 1–4 点的备份窗口里，交换机重启、终端下线全都推给人；
* 一台已知在检修的打印机，每 30 分钟报一次「设备消失」；
* 设备网络抖动（在线 → 离线 → 在线），每轮扫描都推一条。

同类产品的用户抱怨榜里，「告警噪声 + 没有维护窗口」常年排前二
（见 ``docs/PRODUCT_ADVISORY.md`` 建议 #6）。本模块就是补上这一层。

三个子能力
----------
1. **维护窗口**：按「星期 + 时段」，可再叠加「网段 / 设备 / 变更类型」限定范围。
2. **静音**：按「MAC / IP / 网段」，可再叠加「变更类型」与「到期时间」。
3. **通知去重**：同一 ``(设备, 变更类型)`` 在冷却窗口内只发一次。

设计取舍
--------
* **抑制 ≠ 隐藏。** 被抑制的变更照常计入**退出码**与**审计日志**，只是不发通知。
  「静音」是给人耳的，「退出码」是给机器的 —— CI 需要真实信号，不该被静音吃掉。
* **去重状态必须落盘。** 定时扫描由系统调度器以**独立进程**拉起
  （``schtasks`` / ``cron``），进程内状态活不过一次运行 —— 只存内存等于没有去重。
* **发送成功才记账。** :meth:`AlertPolicy.evaluate` 只**读**去重状态；调用方在渠道
  发送成功之后才 :meth:`DedupStore.record`。发送失败不记账，下一轮会重试 ——
  否则一次网络抖动就会静默吞掉告警。
* **不静默。** 每次抑制都留日志（条数与原因）；部分抑制时，通知正文里会附一行
  「另有 N 条被抑制」，让收到告警的人知道全貌。
* **失败安全（fail-open）。** 配置写错时**不抑制** —— 宁可多报，不可漏报。
  解析失败只记 warning 并跳过该条规则，不影响其余规则。

配置（并入 ``notify.json``）::

    {
      "channels": [ ... ],
      "dedup": {"window_minutes": 60, "key": "device_type"},
      "maintenance_windows": [
        {"name": "夜间备份", "days": ["mon", "tue", "wed", "thu", "fri"],
         "start": "01:00", "end": "04:00",
         "ranges": ["10.0.0.0/24"], "types": ["device_gone"]}
      ],
      "mutes": [
        {"name": "打印机检修", "mac": "AA:BB:CC:DD:EE:FF",
         "until": "2026-11-01"},
        {"name": "测试网段", "range": "10.9.0.0/16", "types": ["new_device"]}
      ]
    }

**零第三方依赖**：只用 ``ipaddress`` + ``json`` + ``datetime``。
"""
import ipaddress
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

from app_logging import get_logger
from i18n import tr

_log = get_logger(__name__)

# ── 抑制原因（规范值，落日志/审计用；展示时才 tr()） ─────────────────
SUPPRESS_MAINTENANCE = "maintenance_window"
SUPPRESS_MUTED = "muted"
SUPPRESS_DEDUPED = "deduped"

# ── 去重键 ──────────────────────────────────────────────────────────
DEDUP_KEY_DEVICE_TYPE = "device_type"
DEDUP_KEY_DEVICE = "device"
DEDUP_KEY_IP = "ip"
DEDUP_KEY_TYPE = "type"
DEDUP_KEYS = (DEDUP_KEY_DEVICE_TYPE, DEDUP_KEY_DEVICE, DEDUP_KEY_IP,
              DEDUP_KEY_TYPE)

DEFAULT_DEDUP_WINDOW_MINUTES = 60
DEFAULT_DEDUP_KEY = DEDUP_KEY_DEVICE_TYPE

# 去重状态至少保留 1 小时，避免「窗口 5 分钟」时状态文件被清得太勤
_STATE_MIN_TTL = 3600


def suppress_reason_label(reason: str) -> str:
    """抑制原因的显示名（惰性翻译，可随语言切换）。"""
    return {
        SUPPRESS_MAINTENANCE: tr("维护窗口"),
        SUPPRESS_MUTED: tr("静音"),
        SUPPRESS_DEDUPED: tr("去重冷却"),
    }.get(reason, reason)


# ── 小工具 ──────────────────────────────────────────────────────────

def _as_list(value) -> List[str]:
    """把 ``None`` / 字符串 / 列表统一成字符串列表。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    s = str(value).strip()
    if not s:
        return []
    # 允许 "a,b,c" 这种逗号分隔写法（配置文件手写时很常见）
    if "," in s:
        return [p.strip() for p in s.split(",") if p.strip()]
    return [s]


def normalize_mac(mac) -> str:
    """统一 MAC 为 ``aa:bb:cc:dd:ee:ff`` 小写形式，便于比较。

    刻意不复用 ``excel_handler.normalize_mac``：那会把这个零依赖模块
    和 openpyxl 绑在一起。
    """
    if not mac:
        return ""
    raw = "".join(ch for ch in str(mac).lower() if ch in "0123456789abcdef")
    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    return raw


def _parse_hhmm(raw) -> Optional[int]:
    """``"HH:MM"`` → 当天第几分钟。非法返回 ``None``。"""
    s = str(raw or "").strip()
    parts = s.split(":")
    if len(parts) < 2:
        return None
    try:
        hh, mm = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        return None
    return hh * 60 + mm


_WEEKDAY_ALIASES = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
    "周一": 0, "周二": 1, "周三": 2, "周四": 3, "周五": 4, "周六": 5, "周日": 6,
    "星期一": 0, "星期二": 1, "星期三": 2, "星期四": 3,
    "星期五": 4, "星期六": 5, "星期日": 6, "星期天": 6,
}

_WEEKDAY_SETS = {
    "weekday": {0, 1, 2, 3, 4},
    "工作日": {0, 1, 2, 3, 4},
    "weekend": {5, 6},
    "周末": {5, 6},
}


def _parse_days(raw) -> Optional[frozenset]:
    """解析星期集合。``None`` / 空 → ``None``（表示每天）。"""
    items = _as_list(raw)
    if not items:
        return None
    days = set()
    for item in items:
        token = item.strip().lower()
        if token in _WEEKDAY_SETS:
            days |= _WEEKDAY_SETS[token]
            continue
        if token in _WEEKDAY_ALIASES:
            days.add(_WEEKDAY_ALIASES[token])
            continue
        # 允许数字 0–6（0 = 周一，与 datetime.weekday() 一致）
        if token.isdigit() and 0 <= int(token) <= 6:
            days.add(int(token))
            continue
        _log.warning("告警策略：忽略无法识别的星期 %r", item)
    return frozenset(days) if days else None


def _parse_until(raw) -> Optional[datetime]:
    """解析静音到期时间。只给日期（``2026-11-01``）时按**当天结束**处理。"""
    s = str(raw or "").strip()
    if not s:
        return None
    text = s.replace("/", "-")
    if "T" not in text and " " not in text:
        # 用户写「到 11 月 1 日」的意图是"整个 11 月 1 日都还算静音"，
        # 若按 00:00 处理会在当天零点就提前解除。
        text += " 23:59:59"
    else:
        text = text.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    _log.warning("告警策略：忽略无法解析的静音到期时间 %r", raw)
    return None


def _parse_ranges(values) -> Tuple:
    out = []
    for v in _as_list(values):
        try:
            out.append(ipaddress.ip_network(v, strict=False))
        except ValueError as e:
            _log.warning("告警策略：忽略无法解析的网段 %r: %s", v, e)
    return tuple(out)


def _ip_in_ranges(networks: Sequence, ip: str) -> bool:
    if not networks or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ── 作用域：网段 / 设备 / 变更类型 ──────────────────────────────────

@dataclass(frozen=True)
class Scope:
    """一条规则作用在哪些变更上。

    三个维度都是「空 = 不限」，且是**与**关系：网段、设备、类型都写时，
    只有全部命中的变更才被这条规则管到。
    """
    macs: frozenset = field(default_factory=frozenset)
    ips: frozenset = field(default_factory=frozenset)
    ranges: Tuple = ()
    types: frozenset = field(default_factory=frozenset)

    def matches(self, change) -> bool:
        if self.types and change.change_type not in self.types:
            return False
        if not (self.macs or self.ips or self.ranges):
            # 只按类型限定（或完全不限）—— 类型已在上一步判定过
            return True
        mac = normalize_mac(getattr(change, "mac", ""))
        ip = str(getattr(change, "ip", "") or "").strip()
        if self.macs and mac and mac in self.macs:
            return True
        if self.ips and ip and ip in self.ips:
            return True
        return _ip_in_ranges(self.ranges, ip)

    @property
    def has_identity(self) -> bool:
        """是否至少有一个身份维度（网段/设备/IP）。"""
        return bool(self.macs or self.ips or self.ranges)


def _build_scope(item: dict) -> Scope:
    """从配置项里抽出作用域。同时接受单数/复数键名。"""
    return Scope(
        macs=frozenset(
            m for m in (normalize_mac(x) for x in
                        _as_list(item.get("mac")) + _as_list(item.get("macs"))
                        + _as_list(item.get("devices"))) if m),
        ips=frozenset(x for x in
                      _as_list(item.get("ip")) + _as_list(item.get("ips")) if x),
        ranges=_parse_ranges(_as_list(item.get("range"))
                             + _as_list(item.get("ranges"))),
        types=frozenset(str(t).strip() for t in _as_list(item.get("types"))
                        if str(t).strip()),
    )


# ── 维护窗口 ────────────────────────────────────────────────────────

@dataclass
class MaintenanceWindow:
    name: str
    start: int                      # 当天第几分钟
    end: int                        # 当天第几分钟（不含）
    days: Optional[frozenset] = None   # None = 每天；否则为「起始日」
    scope: Scope = field(default_factory=Scope)

    def active(self, now: datetime) -> bool:
        """``now`` 是否落在窗口内。时段按 ``[start, end)`` 半开区间。

        跨午夜（``start > end``，如 23:00–02:00）时，``days`` 指的是
        **起始日** —— 与人的直觉一致：「周五 23:00–02:00」是周五开始的那一段。
        """
        if self.start == self.end:
            # 空窗口：fail-open，不抑制（并在解析时已记 warning）
            return False
        t = now.hour * 60 + now.minute
        wd = now.weekday()          # 周一 = 0

        if self.start < self.end:
            if self.days is not None and wd not in self.days:
                return False
            return self.start <= t < self.end

        # 跨午夜
        if self.days is None:
            return t >= self.start or t < self.end
        if wd in self.days and t >= self.start:
            return True
        prev_day = (wd - 1) % 7
        return prev_day in self.days and t < self.end


def _build_window(item) -> Optional[MaintenanceWindow]:
    if not isinstance(item, dict):
        _log.warning("告警策略：忽略非对象的维护窗口配置 %r", item)
        return None
    start = _parse_hhmm(item.get("start"))
    end = _parse_hhmm(item.get("end"))
    name = str(item.get("name") or "").strip() or "maintenance"
    if start is None or end is None:
        _log.warning("告警策略：维护窗口 %r 的 start/end 非法，已忽略", name)
        return None
    if start == end:
        _log.warning("告警策略：维护窗口 %r 的 start 与 end 相同，"
                     "视为空窗口（不抑制任何告警）", name)
    return MaintenanceWindow(name=name, start=start, end=end,
                             days=_parse_days(item.get("days")),
                             scope=_build_scope(item))


# ── 静音 ────────────────────────────────────────────────────────────

@dataclass
class Mute:
    name: str
    scope: Scope
    until: Optional[datetime] = None    # None = 不过期

    def matches(self, change, now: datetime) -> bool:
        if self.until is not None and now >= self.until:
            return False
        return self.scope.matches(change)


def _build_mute(item) -> Optional[Mute]:
    if not isinstance(item, dict):
        _log.warning("告警策略：忽略非对象的静音配置 %r", item)
        return None
    name = str(item.get("name") or "").strip() or "mute"
    scope = _build_scope(item)
    if not scope.has_identity and not scope.types:
        # 既没写设备/网段、也没写变更类型 → 这条规则会静音**一切**，
        # 几乎肯定是配置漏了字段。fail-open：忽略并提示。
        _log.warning("告警策略：静音 %r 未指定设备/网段/变更类型，"
                     "为避免误静音全部告警已忽略", name)
        return None
    return Mute(name=name, scope=scope, until=_parse_until(item.get("until")))


# ── 通知去重 ────────────────────────────────────────────────────────

def change_signature(change, key: str = DEFAULT_DEDUP_KEY) -> str:
    """一条变更的去重签名。"""
    mac = normalize_mac(getattr(change, "mac", ""))
    ip = str(getattr(change, "ip", "") or "").strip()
    if key == DEDUP_KEY_TYPE:
        return change.change_type
    if key == DEDUP_KEY_IP:
        return ip
    ident = mac or ip
    if key == DEDUP_KEY_DEVICE:
        return ident
    return f"{ident}|{change.change_type}"


def default_state_path() -> str:
    """去重状态文件路径：数据目录下的 alert_dedup.json。

    必须落盘（而非内存）：定时扫描是**独立进程**，见模块 docstring。
    """
    import app_paths
    return os.path.join(app_paths.data_dir(), "alert_dedup.json")


class DedupStore:
    """``(签名 → 上次发送时刻)`` 的落盘账本。

    ``evaluate()`` 期间只读；调用方在发送成功后 :meth:`record` + :meth:`save`。
    """

    def __init__(self, path: Optional[str] = None,
                 window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES,
                 key: str = DEFAULT_DEDUP_KEY):
        self.path = path or default_state_path()
        self.window = max(0, int(window_minutes)) * 60     # 秒
        self.key = key if key in DEDUP_KEYS else DEFAULT_DEDUP_KEY
        self._seen: Dict[str, float] = {}
        self._loaded = False
        self._dirty = False

    # ── 状态文件 ──
    def load(self) -> None:
        self._loaded = True
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:  # noqa: BLE001
            _log.warning("去重状态读取失败 %s: %s", self.path, e)
            return
        seen = (data or {}).get("seen") if isinstance(data, dict) else None
        if not isinstance(seen, dict):
            return
        for sig, ts in seen.items():
            try:
                self._seen[str(sig)] = float(ts)
            except (TypeError, ValueError):
                continue

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path) or ".",
                                       prefix=".alert_dedup_", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"seen": self._seen}, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
            self._dirty = False
        except Exception as e:  # noqa: BLE001
            # 状态写不进去只是「下次可能重复告警」，不该让本次扫描失败
            _log.warning("去重状态写入失败 %s: %s", self.path, e)

    # ── 判定 ──
    def is_suppressed(self, change, now: datetime) -> bool:
        if self.window <= 0:
            return False
        if not self._loaded:
            self.load()
        last = self._seen.get(change_signature(change, self.key))
        if last is None:
            return False
        return (now.timestamp() - last) < self.window

    def remaining_seconds(self, change, now: datetime) -> int:
        """距该签名冷却结束还剩多少秒（用于日志说明）。"""
        last = self._seen.get(change_signature(change, self.key))
        if last is None:
            return 0
        return max(0, int(self.window - (now.timestamp() - last)))

    def record(self, changes, now: datetime) -> None:
        """把**已成功发出**的变更记进账本。"""
        if self.window <= 0:
            return
        if not self._loaded:
            self.load()
        ts = now.timestamp()
        for c in changes:
            self._seen[change_signature(c, self.key)] = ts
        self._dirty = True

    def prune(self, now: datetime) -> None:
        """清掉早已过期的签名，避免状态文件无限增长。"""
        ttl = max(self.window * 2, _STATE_MIN_TTL)
        now_ts = now.timestamp()
        stale = [k for k, ts in self._seen.items() if now_ts - ts > ttl]
        for k in stale:
            del self._seen[k]
        if stale:
            self._dirty = True

    def reset(self) -> None:
        self._seen.clear()
        self._dirty = True


# ── 判定结果 ────────────────────────────────────────────────────────

@dataclass
class Suppressed:
    change: object
    reason: str                 # 规范值：SUPPRESS_*
    detail: str = ""            # 命中的窗口/静音名，或冷却剩余秒数说明


@dataclass
class PolicyResult:
    notify: List = field(default_factory=list)
    suppressed: List[Suppressed] = field(default_factory=list)

    @property
    def all_suppressed(self) -> bool:
        return not self.notify and bool(self.suppressed)

    def count_by_reason(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for s in self.suppressed:
            out[s.reason] = out.get(s.reason, 0) + 1
        return out


# ── 策略 ────────────────────────────────────────────────────────────

class AlertPolicy:
    """把配置编译成可判定的规则集。"""

    def __init__(self, windows: Sequence[MaintenanceWindow] = (),
                 mutes: Sequence[Mute] = (),
                 dedup_window_minutes: int = 0,
                 dedup_key: str = DEFAULT_DEDUP_KEY,
                 dedup_path: Optional[str] = None):
        self.windows = list(windows)
        self.mutes = list(mutes)
        self.dedup_window_minutes = max(0, int(dedup_window_minutes))
        self.dedup_key = dedup_key if dedup_key in DEDUP_KEYS \
            else DEFAULT_DEDUP_KEY
        self.dedup_path = dedup_path

    @classmethod
    def from_config(cls, config: Optional[dict]) -> "AlertPolicy":
        """从 ``notify.json`` 的内容编译策略。**从不抛异常**（fail-open）。"""
        cfg = config if isinstance(config, dict) else {}

        windows = []
        for item in cfg.get("maintenance_windows") or []:
            w = _build_window(item)
            if w is not None:
                windows.append(w)

        mutes = []
        for item in cfg.get("mutes") or []:
            m = _build_mute(item)
            if m is not None:
                mutes.append(m)

        raw_dedup = cfg.get("dedup")
        if isinstance(raw_dedup, dict):
            minutes = raw_dedup.get("window_minutes",
                                    DEFAULT_DEDUP_WINDOW_MINUTES)
            key = str(raw_dedup.get("key") or DEFAULT_DEDUP_KEY).strip()
            path = raw_dedup.get("path") or None
        elif raw_dedup in (False, None):
            minutes, key, path = 0, DEFAULT_DEDUP_KEY, None
        else:
            # 写成 true / 数字 也算数：true → 默认窗口
            minutes = DEFAULT_DEDUP_WINDOW_MINUTES if raw_dedup is True \
                else raw_dedup
            key, path = DEFAULT_DEDUP_KEY, None
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            _log.warning("告警策略：dedup.window_minutes 非法 %r，已关闭去重",
                         minutes)
            minutes = 0

        return cls(windows=windows, mutes=mutes,
                   dedup_window_minutes=minutes, dedup_key=key,
                   dedup_path=path)

    @property
    def enabled(self) -> bool:
        return bool(self.windows or self.mutes
                    or self.dedup_window_minutes > 0)

    def make_store(self) -> DedupStore:
        return DedupStore(path=self.dedup_path,
                          window_minutes=self.dedup_window_minutes,
                          key=self.dedup_key)

    # ── 判定 ──
    def _reason_for(self, change, now: datetime,
                    store: Optional[DedupStore]):
        """返回 ``(原因, 说明)``；不抑制则返回 ``None``。

        判定顺序固定：维护窗口 → 静音 → 去重。窗口排最前是因为它是
        「计划内的运维时段」，语义上优先级最高，也便于用户理解日志。
        """
        for w in self.windows:
            if w.active(now) and w.scope.matches(change):
                return SUPPRESS_MAINTENANCE, w.name
        for m in self.mutes:
            if m.matches(change, now):
                return SUPPRESS_MUTED, m.name
        if store is not None and store.is_suppressed(change, now):
            secs = store.remaining_seconds(change, now)
            return SUPPRESS_DEDUPED, f"{secs}s"
        return None

    def evaluate(self, changes: Sequence, now: Optional[datetime] = None,
                 store: Optional[DedupStore] = None) -> PolicyResult:
        """把变更列表分成「该发」与「被抑制」。

        **只读** ``store`` —— 记账由调用方在发送成功后做（见模块 docstring）。
        """
        now = now or datetime.now()
        result = PolicyResult()
        for c in changes:
            hit = self._reason_for(c, now, store)
            if hit is None:
                result.notify.append(c)
            else:
                result.suppressed.append(Suppressed(c, hit[0], hit[1]))
        return result


# ── 渲染（纯函数，便于单测） ────────────────────────────────────────

def render_suppression_note(suppressed: Sequence[Suppressed],
                            max_items: int = 10) -> str:
    """把被抑制的变更渲染成通知正文里的一段附注。

    为什么要在**告警正文里**提一句被抑制的条数：抑制本身是「不发消息」，
    如果连收件人都不知道有东西被压下去了，那和静默丢告警没有区别。
    """
    if not suppressed:
        return ""
    lines = [tr("另有 {n} 条变更被抑制（未计入上方告警）：").format(
        n=len(suppressed))]
    for s in suppressed[:max_items]:
        c = s.change
        line = f"- [{suppress_reason_label(s.reason)}] {c.type_label} {c.ip}"
        if getattr(c, "hostname", ""):
            line += f" ({c.hostname})"
        lines.append(line.rstrip())
    if len(suppressed) > max_items:
        lines.append(tr("… 其余 {n} 条已省略").format(
            n=len(suppressed) - max_items))
    return "\n".join(lines)
