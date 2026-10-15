# -*- coding: utf-8 -*-
"""Nagios 插件契约（v2.2 §3.4-a）：一次性执行 + 退出码表达状态 + perfdata。

**为什么它不违反项目身份**：`/metrics` 与 SNMP trap 要**常驻监听 / 常驻进程**，
所以永远出局；而 Nagios 插件是**被监控系统按需拉起的短命进程** —— 不常驻、
不开端口、不装 agent、不加第三方依赖，三条铁律一条不破
（裁定见 `docs/ROADMAP_V2.1.md` §3 adv #7 与 `docs/PRODUCT_ADVISORY.md` §8）。

输出遵循 Nagios 插件开发规范（单行）::

    <STATUS> - <一行说明> | 'label'=value[UOM];warn;crit;min;max ...

🔴 **本子命令的退出码与 CLI 其它子命令语义不同**（这是插件规范的硬要求）：

    0 OK       没有新增设备 / 身份变动
    1 WARNING  有新增设备，或身份变动（MAC 变更 / 随机 MAC）达到 warn 阈值
    2 CRITICAL 新增设备或身份变动达到 crit 阈值
    3 UNKNOWN  没有快照 / 快照过期（**无法判断就报 UNKNOWN，绝不猜成 OK**）

🔴 **插件行一律 ASCII 英文** —— 与 CLI 其它子命令的中文输出**有意不同**：这行
是给监控系统解析、告警短信携带的，非 ASCII 在部分 NMS（老版 Nagios / 短信网关）
会乱码或被截断；`OK/WARNING/CRITICAL/UNKNOWN` 本身也是规范的固定英文词。
人读的详细报告请用 `--format json` 或 GUI。

数据源只有 `history_store`（本地 SQLite，**零网络**）：把**最近两次快照**做一次
`change_detector.detect_changes()`。⚠️ 消失设备只计数**不告警**：ARP / 快照间隔
会让"没扫到"看起来像"设备没了"（与 `watch` 的立场一致）。
"""
import time

import change_detector
import history_store

# ── 状态与退出码（Nagios 插件规范） ──
STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_UNKNOWN = "UNKNOWN"

EXIT_CODES = {
    STATUS_OK: 0,
    STATUS_WARNING: 1,
    STATUS_CRITICAL: 2,
    STATUS_UNKNOWN: 3,
}

#: 「无法判断」的原因（语言无关规范值）→ 英文说明 + 下一步。
#: 🔴 每条都必须带下一步：监控里看到 UNKNOWN 而不知道该做什么，等于没有告警。
REASON_NO_SNAPSHOT = "no_snapshot"
REASON_STALE = "stale"
REASON_NO_BASELINE = "no_baseline"

REASON_TEXT = {
    REASON_NO_SNAPSHOT: (
        "no snapshot in history DB",
        "run a scan with --save-snapshot first",
    ),
    REASON_STALE: (
        "latest snapshot is older than max_age_hours",
        "schedule a scan (cli.py schedule) or raise --max-age-hours",
    ),
    REASON_NO_BASELINE: (
        "only one snapshot; nothing to compare against",
        "run one more scan with --save-snapshot to establish a baseline",
    ),
}

#: 计入「身份变动」的变更类型：MAC 变了 / MAC 是随机化的 —— 两者都可能意味着
#: 有人在伪装设备身份，是比"多了台设备"更值得看一眼的信号。
IDENTITY_CHANGE_TYPES = (
    change_detector.CHANGE_MAC_CHANGED,
    change_detector.CHANGE_MAC_RANDOMIZED,
)


class _SnapResult:
    """把快照里的设备字典适配成 `detect_changes()` 需要的对象接口。

    与 `cli._SnapResult` 同形（那一个是私有类，插件模块不该反向依赖 CLI）。
    """

    __slots__ = ("ip", "status", "mac", "hostname")

    def __init__(self, d: dict):
        self.ip = d.get("ip", "") or ""
        self.status = d.get("status", "") or ""
        self.mac = d.get("mac", "") or ""
        self.hostname = d.get("hostname", "") or ""


def _perf(label: str, value, warn="", crit="", minimum=0, maximum="") -> str:
    """一条 perfdata：`'label'=value[UOM];warn;crit;min;max`。

    空字段必须**保留分号**（`'new'=2;1;5;0`）—— 省略分号会让 NMS 把后面的
    数字读成别的字段，图形就画错了。`min` 恒为 0（这些度量都不可能是负数）。
    """
    return "'%s'=%s;%s;%s;%s;%s" % (label, value, warn, crit, minimum, maximum)

def check_once(db_path=None, max_age_hours=24, warn_new=1, crit_new=5,
               warn_identity=1, crit_identity=3, now=None) -> dict:
    """跑一次检查，返回结构化结果（**不打印、不退出** —— 便于单测）。

    Args:
        max_age_hours: 最近快照超过这个年龄 ⇒ UNKNOWN（数据不可信，不猜）。
        warn_new / crit_new: 新增设备数阈值（`crit_new` 优先）。
        warn_identity / crit_identity: 身份变动数阈值。
        now: 注入当前时间（测试用）。

    Returns:
        ``{"status", "code", "reason", "message", "perfdata", "metrics",
        "next_step"}`` —— `reason` 为 `""` 表示有可比对的数据；
        `metrics` 键固定英文（`devices` / `new` / `gone` / `identity` / `age`）。
    """
    if now is None:
        now = time.time()
    max_age = max(0.0, float(max_age_hours)) * 3600.0

    snaps = history_store.list_snapshots(db_path=db_path)
    if not snaps:
        text, action = REASON_TEXT[REASON_NO_SNAPSHOT]
        return _result(STATUS_UNKNOWN, REASON_NO_SNAPSHOT, text, action)

    latest_meta = snaps[-1]
    age = max(0.0, now - float(latest_meta["time"] or 0.0))
    if age > max_age:
        text, action = REASON_TEXT[REASON_STALE]
        return _result(
            STATUS_UNKNOWN, REASON_STALE,
            "%s (%.1fh > %.1fh)" % (text, age / 3600.0, max_age_hours),
            action,
            metrics={"devices": int(latest_meta["device_count"] or 0),
                     "age": int(age)},
        )

    devices = int(latest_meta["device_count"] or 0)
    age_sec = int(age)

    if len(snaps) < 2:
        # 首次运行：没有基线可对比 ⇒ 不编造"新增 0 台"，如实说"无从判断"，
        # 但**不报 UNKNOWN**（那样新部署一上线就是告警噪声），报 OK + 说明。
        text, action = REASON_TEXT[REASON_NO_BASELINE]
        return _result(
            STATUS_OK, REASON_NO_BASELINE, text, action,
            metrics={"devices": devices, "new": 0, "gone": 0,
                     "identity": 0, "age": age_sec},
        )

    previous = history_store.get_snapshot(snaps[-2]["id"], db_path=db_path)
    latest = history_store.get_snapshot(latest_meta["id"], db_path=db_path)
    if previous is None or latest is None:
        text, action = REASON_TEXT[REASON_NO_SNAPSHOT]
        return _result(STATUS_UNKNOWN, REASON_NO_SNAPSHOT, text, action)

    current = [_SnapResult(d) for d in latest["devices"]]
    changes = change_detector.detect_changes(current, previous["devices"])
    new_count = sum(1 for c in changes
                    if c.change_type == change_detector.CHANGE_NEW_DEVICE)
    gone_count = sum(1 for c in changes
                     if c.change_type == change_detector.CHANGE_DEVICE_GONE)
    identity_count = sum(1 for c in changes
                         if c.change_type in IDENTITY_CHANGE_TYPES)

    metrics = {"devices": devices, "new": new_count, "gone": gone_count,
               "identity": identity_count, "age": age_sec}
    warn_new = max(1, int(warn_new))
    crit_new = max(1, int(crit_new))
    warn_identity = max(1, int(warn_identity))
    crit_identity = max(1, int(crit_identity))

    if new_count >= crit_new:
        status = STATUS_CRITICAL
        message = "new devices: %d (>= crit %d)" % (new_count, crit_new)
    elif identity_count >= crit_identity:
        status = STATUS_CRITICAL
        message = ("identity changes: %d (>= crit %d)"
                   % (identity_count, crit_identity))
    elif new_count >= warn_new:
        status = STATUS_WARNING
        message = "new devices: %d (>= warn %d)" % (new_count, warn_new)
    elif identity_count >= warn_identity:
        status = STATUS_WARNING
        message = ("identity changes: %d (>= warn %d)"
                   % (identity_count, warn_identity))
    else:
        status = STATUS_OK
        message = "no new device, no identity change"

    if status != STATUS_OK and gone_count:
        message += "; devices gone: %d (informational)" % gone_count
    return _result(status, "", message, "",
                   metrics=metrics, warn_new=warn_new, crit_new=crit_new,
                   warn_identity=warn_identity, crit_identity=crit_identity)


def _result(status, reason, message, next_step, metrics=None, warn_new="",
            crit_new="", warn_identity="", crit_identity=""):
    """组装结果 + perfdata（perfdata 永远给出，NMS 才能画图）。"""
    metrics = metrics or {}
    parts = []
    if "devices" in metrics:
        parts.append(_perf("devices", metrics["devices"]))
    if "new" in metrics:
        parts.append(_perf("new", metrics["new"], warn_new, crit_new))
    if "gone" in metrics:
        parts.append(_perf("gone", metrics["gone"]))
    if "identity" in metrics:
        parts.append(_perf("identity", metrics["identity"],
                           warn_identity, crit_identity))
    if "age" in metrics:
        # UOM = s（秒）—— NMS 据此把值当"秒数"显示，而不是无单位整数。
        parts.append(_perf("age", "%ds" % metrics["age"]))
    return {
        "status": status,
        "code": EXIT_CODES[status],
        "reason": reason,
        "message": message,
        "next_step": next_step,
        "perfdata": " ".join(parts),
        "metrics": metrics,
    }


def render_plugin_line(result) -> str:
    """渲染 Nagios 插件单行输出：`STATUS - message | perfdata`。

    ⚠️ 非 `ok` 状态的**下一步**也拼进去（Nagios 的告警正文就是这一行，
    没有"再看一眼详情页"的机会）。perfdata 为空时**不写竖线**。
    """
    line = "%s - %s" % (result["status"], result["message"])
    if result.get("next_step"):
        line += " [next: %s]" % result["next_step"]
    if result.get("perfdata"):
        line += " | " + result["perfdata"]
    return line
