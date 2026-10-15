# -*- coding: utf-8 -*-
"""通用工具函数：网关探测、快照对比、IP 校验与排序键、时长显示。"""
import ipaddress

import trend_store
from i18n import tr
from scanner.constants import device_class_label
from app_logging import get_logger

_log = get_logger(__name__)


def _detect_gateway() -> str:
    """推测默认网关 IP：优先解析系统路由表，失败则按本机网段 .1 推测。"""
    import subprocess as sp
    import socket as sock
    local_ip = ""
    try:
        local_ip = sock.gethostbyname(sock.gethostname())
    except Exception as e:  # noqa: BLE001
        # 解析不到本机主机名很常见（hosts 未登记 / DNS 不可达），下面还有回退
        _log.debug("解析本机主机名失败，改用网段推测网关: %s", e)
    gw_ip = None
    # Windows 路由表 (0.0.0.0/0 的下一跳)
    try:
        out = sp.run(["route", "print", "-4"], capture_output=True, text=True, timeout=3,
                     creationflags=getattr(sp, "CREATE_NO_WINDOW", 0)).stdout
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                cand = cols[2]
                if _is_valid_ip(cand):
                    gw_ip = cand
                    break
    except Exception as e:  # noqa: BLE001
        # 非 Windows 平台没有 route 命令，属预期；下面按 .1 推测
        _log.debug("读取系统路由表失败，改用网段推测网关: %s", e)
    if not gw_ip and local_ip:
        parts = local_ip.split(".")
        if len(parts) == 4:
            gw_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return gw_ip or ""


def _compare_snapshots(base: dict, target: dict) -> list:
    """对比两个快照，返回差异行列表：{ip, change, old, new}。"""
    base_map = {d["ip"]: d for d in base.get("devices", [])}
    target_map = {d["ip"]: d for d in target.get("devices", [])}
    diffs = []

    def _fmt(d):
        parts = [d.get("status", "?"), d.get("hostname") or "—", d.get("mac") or "—"]
        if d.get("device_class"):
            parts.append(device_class_label(d.get("device_class")))
        return " / ".join(str(p) for p in parts)

    for ip, td in target_map.items():
        if ip not in base_map:
            diffs.append({"ip": ip, "change": tr("新增设备"), "old": "—", "new": _fmt(td)})
    for ip, bd in base_map.items():
        if ip not in target_map:
            diffs.append({"ip": ip, "change": tr("消失设备"), "old": _fmt(bd), "new": "—"})
    for ip in base_map:
        if ip in target_map:
            bd, td = base_map[ip], target_map[ip]
            if bd.get("status") != td.get("status"):
                diffs.append({"ip": ip, "change": tr("状态变更"),
                              "old": bd.get("status", "—"), "new": td.get("status", "—")})
            if (bd.get("mac") or "") != (td.get("mac") or ""):
                diffs.append({"ip": ip, "change": tr("MAC 变更"),
                              "old": bd.get("mac") or "—", "new": td.get("mac") or "—"})
            if (bd.get("hostname") or "") != (td.get("hostname") or ""):
                diffs.append({"ip": ip, "change": tr("主机名变更"),
                              "old": bd.get("hostname") or "—", "new": td.get("hostname") or "—"})
            # 设备识别类字段变更（新增字段，旧快照缺省为空，不影响兼容）
            for field, label in (
                ("device_class", tr("设备类型变更")),
                ("open_ports", tr("开放端口变更")),
                ("location", tr("位置变更")),
                ("user", tr("使用者变更")),
            ):
                bv, tv = bd.get(field) or "", td.get(field) or ""
                if bv != tv:
                    diffs.append({"ip": ip, "change": label,
                                  "old": bv or "—", "new": tv or "—"})
    return diffs


def _is_valid_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _ip_to_int(ip: str):
    """IP 地址转整数排序键；非法地址返回 -1（排最前）。

    使用 ipaddress 解析，IPv4/IPv6 统一为整数，保证与 __lt__ 比较时类型一致
    （不会出现 int 与 str 混比引发 TypeError）。
    """
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return -1


# ── 时长显示（v2.3 §3.2 / §3.3）──────────────────────────────────────
#
# 🔴 **分档逻辑只有一份**，在 `trend_store.duration_parts()`（零 i18n 的领域层）——
#    本模块只负责把 `(数值, 单位规范值)` 翻成给人看的字。
#    ⚠️ `cli.py` 另有一份**刻意不共享**的实现（`cli._fmt_duration`）：CLI 不
#    import `i18n`、输出恒为中文，而本函数会 `tr()` —— 共享会让 CLI 的输出
#    随界面语言漂移。

#: 时长单位规范值（`trend_store.DURATION_UNIT_*`）→ 后缀。
#: 🔴 这是**字面量标签表**：AST 收集不到，必须登记进
#: `tests/test_i18n_lazy.py::_label_tables()`，否则漏翻**无告警**。
DURATION_UNIT_TEXT = {
    trend_store.DURATION_UNIT_SECOND: "秒",
    trend_store.DURATION_UNIT_MINUTE: "分钟",
    trend_store.DURATION_UNIT_HOUR: "小时",
    trend_store.DURATION_UNIT_DAY: "天",
}

#: 算不出时长时的说明。照「不猜」原则：**不拿 0 冒充结果**
#: （v2.2 §3.4-a「数据不可信报 UNKNOWN 不猜 OK」的同一条）。
DURATION_INSUFFICIENT_TEXT = "样本不足"


def format_duration(seconds) -> str:
    """秒 → 人话（`None` / 非法一律「样本不足」，🔴 不拿 0 冒充结果）。

    分档在 `trend_store.duration_parts()`（**只有一份**），本函数只管翻译与拼装。
    """
    value, unit = trend_store.duration_parts(seconds)
    if unit == trend_store.DURATION_UNIT_NONE:
        return tr(DURATION_INSUFFICIENT_TEXT)
    suffix = tr(DURATION_UNIT_TEXT[unit])
    if unit == trend_store.DURATION_UNIT_SECOND:
        return "%.0f %s" % (value, suffix)
    return "%.1f %s" % (value, suffix)


def format_exposure_rows(rows) -> list:
    """端口暴露行（`trend_store.port_exposure()['open']`）→ 一行一句。

    🔴 `baseline` 为真的行，起点是"我们第一次观测到它"，**不是**"端口真的开了"
    ⇒ 必须写成「**至少** N」。写成"已开放 N"会**低估**暴露时长 ——
    而低估暴露时长恰好是危险的那个方向（真实开放时刻只会更早）。

    算不出时长的行（`seconds` 是 `None` / 非法）**整行丢掉**，
    不显示「已开放 样本不足」这种读不通的句子。
    """
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        try:
            port = int(r.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue
        _value, unit = trend_store.duration_parts(r.get("seconds"))
        if unit == trend_store.DURATION_UNIT_NONE:
            continue
        dur = format_duration(r.get("seconds"))
        if r.get("baseline"):
            out.append(tr("端口 {port} 至少已开放 {dur}"
                          "（自首次观测起算，真实开放时刻更早）").format(
                              port=port, dur=dur))
        else:
            out.append(tr("端口 {port} 已开放 {dur}").format(port=port, dur=dur))
    return out
