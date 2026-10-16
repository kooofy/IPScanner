# -*- coding: utf-8 -*-
"""跨网段补齐 MAC：用 SNMP 读三层设备的 ARP 表。

**它解决什么问题**
------------------
MAC 是二层概念。扫描机与目标不在同一网段时，本机 ARP 表里永远只有网关的
MAC，界面上那一列就是一片「—」。出路是**换一台"看得见"这些设备的机器去读
它的 ARP 表**：持有目标网段三层接口的那台路由器 / 三层交换机（通常就是本机
默认网关）。它要转发数据包，就必须自己 ARP 出目标的 MAC。

**分层**
--------
- 解析（OID 后缀 → IP、6 字节 → MAC）在 ``scanner/arp_mib.py``，零网络、可离线单测；
- 本模块负责**传输方式分叉**（SNMPv3 优先、v2c 兜底）+ 用户可见文案 + 回填。
  与 ``switch_mapper.py`` 是同一套写法（那个读 BRIDGE-MIB 的 MAC→端口，
  这个读 ipNetToMedia 的 IP→MAC）。

**为什么不能定点查**
--------------------
``ipNetToMediaTable`` 的索引是 ``(ifIndex, IP)``，不知道 ifIndex 就没法定点
GET ⇒ 只能整表 walk 一次，然后按 IP 查表。好在这张表的索引后缀**自带 IP**，
一次 walk 就够（见 ``arp_mib``）。

**边界（不粉饰）**
------------------
- 只对**目标网段的最后一跳**有效。若目标网段还挂在下一台路由器后面，
  网关的 ARP 表里只有那台路由器的 MAC。
- 表项会老化（思科默认 4 小时，华为 / 华三通常 20 分钟）⇒ 要**扫完立刻读**。
  扫描本身的 ICMP 恰好会促使网关 ARP 出目标的 MAC，所以顺序天然合适。
- 纯二层交换机只有 BRIDGE-MIB（没有 IP，见 ``switch_mapper``），拿不到
  这张表 —— 得换成持有目标网段三层接口的设备来查。
"""
import ipaddress
import platform
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from app_logging import get_logger
from i18n import tr

from scanner.arp_mib import (
    DEFAULT_MAX_ITERATIONS, SOURCE_NET_TO_MEDIA, SOURCE_NET_TO_PHYSICAL,
    walk_arp_table,
)
from scanner.constants import _SNMP_DEFAULT_COMMUNITIES
from scanner.snmp import snmp_get_system, snmp_walk
from scanner.snmp_v3 import ERR_NO_RESPONSE, snmp_v3_get_system, snmp_v3_walk

try:
    from oui_database import get_mac_vendor
except ImportError:      # pragma: no cover — OUI 库缺失时厂商留空，不影响 MAC
    def get_mac_vendor(mac: str) -> str:
        return ""

_log = get_logger(__name__)

#: ``ScanResult.mac_source`` 的规范值：MAC 来自「网关 ARP 表（SNMP）」。
#: 语言无关 —— 与 ``discovery_method`` / ``device_class`` 同一套规矩，
#: **绝不**把 ``tr()`` 结果写进结果对象。
MAC_SOURCE_SNMP_ARP = "snmp-arp"

#: 展示名表（**字面量标签表**，取用时过 ``tr()``）。已登记进
#: ``tests/test_i18n_lazy.py::_label_tables()``。
MAC_SOURCE_TEXT = {
    MAC_SOURCE_SNMP_ARP: "网关 ARP 表（SNMP）",
}


def mac_source_label(source: str) -> str:
    """MAC 来源的显示名；未知来源原样返回（不吞、不猜）。"""
    if not source:
        return ""
    return tr(MAC_SOURCE_TEXT.get(source, source))


def detect_default_gateway() -> str:
    """解析系统路由表取**默认网关**；取不到返回空串。

    🔴 刻意**不**复用 ``ui_utils._detect_gateway()``：那个函数在路由表读不到时
    会退化成「本机网段 .1」的猜测（它服务的是拓扑图的"分层根"这种容错场景）。
    拿猜出来的地址去查 SNMP，会静默查一台不相干的设备，然后把结果说成
    「网关不支持 SNMP」—— 比直接报"没检测到默认网关"难排查得多。
    """
    try:
        if platform.system() == "Windows":
            out = subprocess.run(
                ["route", "print", "-4"], capture_output=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).stdout.decode("utf-8", errors="replace")
            for line in out.splitlines():
                cols = line.split()
                if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                    if _is_ipv4(cols[2]):
                        return cols[2]
        else:
            from scanner.util import _run_cmd
            for cmd in (["ip", "route", "show", "default"], ["route", "-n"]):
                for line in _run_cmd(cmd, timeout=5).splitlines():
                    cols = line.split()
                    if not cols:
                        continue
                    if cols[0] == "default" and "via" in cols:
                        cand = cols[cols.index("via") + 1]
                        if _is_ipv4(cand):
                            return cand
                    if len(cols) >= 2 and cols[0] == "0.0.0.0" and _is_ipv4(cols[1]):
                        return cols[1]
    except Exception as e:  # noqa: BLE001
        # 非 Windows 没有 route print / 命令缺失：属预期，交给调用方报"未检测到"
        _log.debug("解析系统路由表取默认网关失败: %s", e)
    return ""


def _is_ipv4(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
    except ValueError:
        return False


#: 「三层设备地址」的哨兵值：不写死 IP，扫描时自动探测本机默认网关。
#: 空串是另一层意思 —— **不做补齐**（见 ``ui_threads.ScanThread.arp_gateway``）。
GATEWAY_AUTO = "auto"


@dataclass
class ArpTableResult:
    """一次 ARP 表读取的结果。"""
    host: str                       # 被查询的三层设备
    sys_name: str = ""
    sys_descr: str = ""
    #: 命中的 MIB 规范名（``arp_mib.SOURCE_*``）；没取到时为空串
    source: str = ""
    #: ``{ip: mac}``（MAC 一律小写 ``aa:bb:cc:dd:ee:ff``）
    entries: Dict[str, str] = field(default_factory=dict)
    #: 失败原因（成功时为空串）。**只影响 MAC 补齐**，绝不让扫描失败。
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.entries)


def _walk_v2c(host: str, community: str, timeout: float, port: int):
    """构造 v2c 的 ``walk_fn``（``(base_oid, max_iterations) -> dict``）。

    做成工厂函数而不是在循环里内联闭包：闭包会捕获循环变量，
    后续一旦有人把调用改成延迟执行就会静默用错团体字。

    🔴 内部吞掉异常并返回空表 —— 读 ARP 表失败只该导致"补不到 MAC"，
    **绝不能**让一次已经跑完的扫描失败（见 ``fetch_arp_table`` 的承诺）。
    """
    def _fn(base_oid: str, max_iterations: int) -> dict:
        try:
            return snmp_walk(host, base_oid, community=community, timeout=timeout,
                             port=port, max_iterations=max_iterations)
        except Exception as e:  # noqa: BLE001
            _log.warning("SNMP v2c walk 异常（按未取到处理）%s: %s", host, e)
            return {}
    return _fn


def _walk_v3(host: str, user, timeout: float, port: int):
    """构造 v3 的 ``walk_fn``（同 ``_walk_v2c``：内部吞异常，不外抛）。"""
    def _fn(base_oid: str, max_iterations: int) -> dict:
        try:
            return snmp_v3_walk(host, user, base_oid, timeout=timeout, port=port,
                                max_iterations=max_iterations)
        except Exception as e:  # noqa: BLE001
            _log.warning("SNMP v3 walk 异常（按未取到处理）%s: %s", host, e)
            return {}
    return _fn


def fetch_arp_table(host: str, communities: Optional[List[str]] = None,
                    timeout: float = 1.5,
                    progress_cb: Optional[Callable[[str], None]] = None,
                    snmp_v3_user=None, port: int = 161,
                    max_iterations: int = DEFAULT_MAX_ITERATIONS) -> ArpTableResult:
    """读指定三层设备的 ARP 表。

    Args:
        host: 持有目标网段三层接口的设备 IP（通常 = 本机默认网关）。
        communities: SNMPv2c 团体字候选，按序尝试。``None`` = 用全局默认。
        timeout: 每次 GETNEXT 的超时（秒）。
        progress_cb: 进度回调（接收**已翻译**的状态文本）。
        snmp_v3_user: ``scanner.snmp_v3.SnmpV3User`` 或 None。传入时 **v3 优先**，
            仅在目标根本不回话（``ERR_NO_RESPONSE``）时才回退 v2c —— 与
            ``scanner.engine._identify_snmp`` / ``topology_discovery._SnmpClient``
            同一口径，避免把"密码写错了"伪装成"这台设备不支持 SNMP"。
        port: SNMP 端口（默认 161；开放出来主要是为了可测试）。
        max_iterations: 单次 walk 的迭代上限。

    Returns:
        ``ArpTableResult``。**永不抛异常** —— 失败收成 ``error`` 非空 + 空表，
        调用方据此提示，扫描结果原样保留。
    """
    info = ArpTableResult(host=host)
    cands = list(communities) if communities else list(_SNMP_DEFAULT_COMMUNITIES)

    def _progress(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _sysinfo(fn, *args, **kwargs) -> dict:
        """取设备系统信息（sysName / sysDescr）；任何异常都按「没取到」处理。

        🔴 本函数的对外承诺是**永不抛异常**（见 docstring 的 Returns）。
        sysName / sysDescr 只用于让失败提示能区分「没开 SNMP」与「纯二层交换机」，
        取不到就退回前一档说明，**绝不能**因此让一次已经跑完的扫描失败。
        非 dict 的返回值同样按「没取到」处理（防御 SNMP 层被替换 / mock 坏）。
        """
        try:
            res = fn(*args, **kwargs)
            return res if isinstance(res, dict) else {}
        except Exception as e:  # noqa: BLE001
            _log.warning("读取设备系统信息异常（按未取到处理）%s: %s", host, e)
            return {}

    _progress(tr("正在读取网关 ARP 表..."))

    # ── SNMPv3 优先 ──
    if snmp_v3_user is not None:
        # 取不到 sysinfo（含抛异常）时 sys_res 为空 dict ⇒ 走"再试 v3 walk、
        # 失败则回退 v2c"这条路，与"v3 可达但没这张表"同一路径，行为正确
        sys_res = _sysinfo(snmp_v3_get_system, host, snmp_v3_user,
                           timeout=timeout, port=port)
        if "error" not in sys_res:
            info.sys_name = sys_res.get("sys_name", "")
            info.sys_descr = sys_res.get("sys_descr", "")
            table, source = walk_arp_table(
                _walk_v3(host, snmp_v3_user, timeout, port), max_iterations)
            if table:
                info.entries = table
                info.source = source
                _progress(tr("ARP 表读取完成：{n} 条").format(n=len(table)))
                return info
        elif sys_res.get("error_kind") != ERR_NO_RESPONSE:
            # 凭据 / 配置类错误：不再拿明文团体字去撞，直接如实上报
            _log.warning("SNMPv3 读取 ARP 表失败 %s: %s", host, sys_res.get("error", ""))
            info.error = tr("SNMPv3 认证或配置失败，未回退到 v2c 团体字。") + \
                " " + str(sys_res.get("error", ""))
            return info
        # 走到这里 = v3 不可用（没开 / 不回话 / 没有这张表）→ 回退 v2c

    # ── v2c 兜底 ──
    if not info.sys_name and not info.sys_descr:
        sys_res = _sysinfo(snmp_get_system, host, communities=cands,
                           timeout=timeout, port=port)
        if sys_res:
            info.sys_name = sys_res.get("sys_name", "")
            info.sys_descr = sys_res.get("sys_descr", "")
    for community in cands:
        table, source = walk_arp_table(
            _walk_v2c(host, community, timeout, port), max_iterations)
        if table:
            info.entries = table
            info.source = source
            _progress(tr("ARP 表读取完成：{n} 条").format(n=len(table)))
            return info

    info.error = _build_error(host, info)
    _log.warning("读取网关 ARP 表失败 %s: %s", host, info.error.replace("\n", " "))
    return info


def _build_error(host: str, info: ArpTableResult) -> str:
    """拼出**可操作**的失败说明。

    🔴 必须区分「没开 SNMP / 团体字不对」与「这是台纯二层交换机」——
    后者换团体字怎么试都没用，得换设备查。两者混成一句会让人白折腾。
    """
    head = tr("无法从 {host} 读取 ARP 表。").format(host=host)
    if not info.sys_name and not info.sys_descr:
        return head + "\n" + tr(
            "该设备对 SNMP 查询没有响应。请确认：\n"
            "  1. 三层设备（路由器 / 三层交换机）已开启 SNMP，且团体字 / v3 用户正确\n"
            "  2. 本机到它的 UDP 161 可达（没有被 ACL 或防火墙拦）\n"
            "  3. 它确实是**持有目标网段三层接口**的那台设备")
    return head + "\n" + tr(
        "能取到设备信息但取不到 ARP 表，常见原因：\n"
        "  1. 这是一台**纯二层交换机** —— 它只有 BRIDGE-MIB（MAC→端口，没有 IP），\n"
        "     请改查持有目标网段三层接口的路由器 / 三层交换机\n"
        "  2. 该设备的 MIB 视图把 ipNetToMediaTable 排除了（部分设备默认只暴露子集）\n"
        "  3. ARP 表刚好为空（设备刚重启，或与目标网段尚无通信）")


def apply_arp_table(results, entries: Dict[str, str]) -> int:
    """把 ARP 表回填到扫描结果，返回**实际补上 MAC 的台数**。

    🔴 只补 **status == "online"** 且 ``mac`` 为空的设备：
    网关的 ARP 表条目可能已经老化（思科默认 4 小时），把它挂到一台**本次
    没扫到（离线）**的行上，会让台账把"两个不同时期的设备"当成同一台 ——
    而 MAC 正是资产台账的身份键（见 ``asset_lifecycle`` / ``resolve_identity``）。
    宁可离线行留空，也不写一个可能是别的设备的 MAC。

    同时写 ``mac_source``（规范值）与 ``mac_updated``（让 UI 重渲染那一行）。
    """
    filled = 0
    for r in results or []:
        if r.status != "online" or r.mac:
            continue
        mac = (entries or {}).get(r.ip, "")
        if not mac:
            continue
        r.mac = mac
        if not r.vendor:
            r.vendor = get_mac_vendor(mac)
        r.mac_source = MAC_SOURCE_SNMP_ARP
        # 扫描过程中这一行已经渲染过（enrich 回调），必须让 UI 知道要重渲染
        r.mac_updated = True
        filled += 1
    return filled


def source_label(source: str) -> str:
    """MIB 来源的显示名（``arp_mib.SOURCE_*`` → 文案）。"""
    if source == SOURCE_NET_TO_MEDIA:
        return tr("ipNetToMediaTable（RFC 1213）")
    if source == SOURCE_NET_TO_PHYSICAL:
        return tr("ipNetToPhysicalTable（RFC 4293）")
    return source or ""


__all__ = [
    "MAC_SOURCE_SNMP_ARP", "MAC_SOURCE_TEXT", "mac_source_label",
    "GATEWAY_AUTO",
    "ArpTableResult", "detect_default_gateway", "fetch_arp_table",
    "apply_arp_table", "source_label",
]
