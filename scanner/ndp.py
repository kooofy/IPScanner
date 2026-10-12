# -*- coding: utf-8 -*-
"""IPv6 可见性（v2.0 §2.4）：只**读**，不扫。

本模块与 IPv4 的关系
--------------------
本工具**只扫 IPv4**，这是刻意的决定而非缺口（见 `scanner/range.py` 模块
docstring：下游 ARP / NetBIOS / WMI / SNMP 全假设 IPv4）。但现代网络里
手机与 Windows 默认都带 IPv6，只看 IPv4 会漏掉「只有 IPv6 的设备」。

**完整的 IPv6 资产盘点在语义上不成立** —— 一个 /64 有 2⁶⁴ 个地址，
「扫描」它没有意义。所以本模块只做**可见性**：

1. dump 本机 **NDP / 邻居缓存**整表（`dump_ndp_cache()`）—— 零发包，
   对应 IPv4 的 ARP 表 dump（`scanner/passive.py:dump_arp_table()`）；
2. **可选**发一次 `ff02::1`（全节点）ICMPv6 echo（`probe_all_nodes()`），
   促使链路上的设备回一个邻居通告，再读缓存 —— 这**不遍历地址空间**，
   等价于 IPv4 的 `ping 255.255.255.255`。默认**不发**（与 mDNS 的
   `listen_only` 同口径：默认零发包）。

拿到的 IPv6 地址**挂到已有 IPv4 资产上**（`attach_ipv6()`，按 MAC 关联），
**不新建**「IPv6-only 资产」这种一等实体。这是本项边界的一部分：
产出的是**可见性**，不是**IPv6 资产清单**。

为什么能按 MAC 关联
-------------------
NDP 缓存里的 **link-local（`fe80::`）** 条目一定带 MAC —— 链路本地地址本就
只在一段链路上有意义，邻居缓存必然记着它的 L2 地址。设备如果同时有 IPv4
（绝大多数双栈设备都有），那份 IPv4 结果的 `mac` 就能与这里对上。
**只有 IPv6 没有任何 IPv4 痕迹的设备**关联不上（`attach_ipv6()` 里没有
对应 MAC 的宿主），本模块**如实丢弃**，不硬造一行 —— 与 `range.py` 拒 IPv6
是同一种诚实（见模块 docstring 的「不做清单」）。
"""
import ipaddress
import platform
import re
from typing import Dict

from app_logging import get_logger

from .util import _run_cmd

_log = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"
_IS_DARWIN = platform.system() == "Darwin"

#: 组播地址不是「一台设备」。`ff02::1` = 全节点，`ff02::2` = 全路由器，
#: `ff02::1:ffXX:XXXX` = solicited-node 组播 …… 缓存里它们会以空 MAC 或
#: `Permanent` 类型出现，凡 `ff00::/8` 一律跳过。
_MULTICAST_V6 = ipaddress.ip_network("ff00::/8")

#: `ff02::1` —— 链路本地全节点多播地址（所有 IPv6 设备都必须加入）。
ALL_NODES_MULTICAST = "ff02::1"

#: 这些 MAC 不代表单台设备（与 `scanner/passive.py` 同口径）。
#: `00-00-00-00-00-00` 在 NDP 缓存里配 `Unreachable` / `Incomplete` 出现，
#: 表示「解析尚未完成」，是**过期槽位**而不是一台设备。
_UNUSABLE_MACS = frozenset({"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"})
_MULTICAST_PREFIXES = ("01:00:5e", "33:33")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def _mac_usable(mac: str) -> bool:
    """这个 MAC 能不能代表一台真实设备（与 passive.py 同判据）。"""
    m = (mac or "").lower()
    if not _MAC_RE.match(m):
        return False
    if m in _UNUSABLE_MACS:
        return False
    return not m.startswith(_MULTICAST_PREFIXES)


def _addr_usable(addr: str) -> bool:
    """这个 IPv6 地址值不值得记下来。

    跳过两类：
    - **组播**（`ff00::/8`）—— 不是一台设备；
    - **回环**（`::1`）—— 是本机自己，不是「身边的设备」。
    """
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_loopback:
        return False
    return True


# ── NDP 缓存解析（三种平台格式，各自独立函数以便喂样本单测） ──────────────

# Windows `netsh interface ipv6 show neighbors`：
#     fe80::9f5:f060:f6c1:7135                      c8-4d-44-32-67-3d  Stale
#     ff02::2                                                          Permanent
#     fe80::xxxx                                    00-00-00-00-00-00  Unreachable
#
# 三列不等宽（地址 44 + 2 空格、MAC 17 + 2 空格），所以用**至少两个空格**
# 分隔而不是定长切片 —— 微软改列宽时定长切片会静默错位。
_WIN_NDP_LINE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F:]+)"
    r"(?:\s{2,}(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}))?"
    r"\s{2,}(?P<state>\S+)\s*$")


def parse_windows_ndp_cache(output: str) -> Dict[str, str]:
    """解析 Windows ``netsh interface ipv6 show neighbors`` → ``{ipv6: mac}``。

    只有**既有地址又有可用 MAC** 的行才进结果 —— `Permanent` 的组播行没有
    MAC，`Unreachable` 行的 MAC 是 `00-00-00-00-00-00`，两者都不是设备。
    同一地址在多张网卡上重复出现时后写覆盖（值相同，无影响）。
    """
    out: Dict[str, str] = {}
    for line in (output or "").splitlines():
        m = _WIN_NDP_LINE.match(line)
        if not m:
            continue
        addr = m.group("addr")
        raw_mac = m.group("mac")
        if not raw_mac:
            continue          # 组播 / 系统条目：没有 L2 地址
        if not _addr_usable(addr):
            continue
        mac = raw_mac.replace("-", ":").lower()
        if _mac_usable(mac):
            out[addr.lower()] = mac
    return out


# Linux `ip -6 neigh`（或 `ip -6 neigh show`）：
#     fe80::1 dev eth0 lladdr 50:2b:73:xx:xx:xx REACHABLE
#     fe80::2 dev eth0  FAILED                     ← 无 lladdr，跳过
_LINUX_NEIGH_LINE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F:]+)\s+dev\s+\S+"
    r"(?:\s+lladdr\s+(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}))?")


def parse_linux_ip_neigh(output: str) -> Dict[str, str]:
    """解析 Linux ``ip -6 neigh`` → ``{ipv6: mac}``。

    没有 ``lladdr`` 的条目（`INCOMPLETE` / `FAILED`）没有 MAC，跳过。
    """
    out: Dict[str, str] = {}
    for line in (output or "").splitlines():
        m = _LINUX_NEIGH_LINE.match(line)
        if not m:
            continue
        addr = m.group("addr")
        raw_mac = m.group("mac")
        if not raw_mac:
            continue
        if not _addr_usable(addr):
            continue
        mac = raw_mac.lower()
        if _mac_usable(mac):
            out[addr.lower()] = mac
    return out


# macOS `ndp -an`：
#     fe80::1%en0  50:2b:73:xx:xx:xx  en0  S    R
#     fe80::2%en0  (incomplete)       en0  S    R    ← 括号形式，跳过
#
# 地址列带 `%iface` 作用域后缀，解析时剥掉（同一 `fe80::1` 在不同网卡上是
# **不同**的设备，但本工具只有一条链路可观测，剥掉作用域不会造成实际混淆；
# 保留作用域又会让它与 IPv4 侧的 MAC 关联时对不上 key 形状）。
_MACOS_NDP_LINE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F:]+)(?:%\S+)?\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")


def parse_macos_ndp(output: str) -> Dict[str, str]:
    """解析 macOS ``ndp -an`` → ``{ipv6: mac}``。

    `(incomplete)` 之类的括号占位符匹配不上 MAC 形状，自然被跳过。
    """
    out: Dict[str, str] = {}
    for line in (output or "").splitlines():
        m = _MACOS_NDP_LINE.match(line)
        if not m:
            continue
        addr = m.group("addr")
        if not _addr_usable(addr):
            continue
        mac = m.group("mac").lower()
        if _mac_usable(mac):
            out[addr.lower()] = mac
    return out


def ipv6_enabled() -> bool:
    """本机是否可能启用 IPv6 —— 用于「优雅降级」提示，不做任何发包。

    `socket.has_ipv6` 只表示**编译期**支持，不代表本机装了 IPv6 栈。
    这里尽力而为：本机连一个非回环 IPv6 地址都拿不到时，`False`。
    调用方据此把「本机未启用 IPv6」和「周围设备都没有 IPv6」分开提示 ——
    否则用户会看到同一句「没发现 IPv6 设备」而反复排查。
    """
    import socket
    if not getattr(socket, "has_ipv6", False):
        return False
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET6):
            addr = info[4][0]
            if addr and addr != "::1":
                return True
    except Exception as e:  # noqa: BLE001
        # 解析本机名失败是**预期分支**（离线 / 无 DNS / 只有 hosts），
        # 与「有没有 IPv6」无关，只记 debug。
        _log.debug("查询本机 IPv6 地址失败: %s", e)
    return False


def dump_ndp_cache() -> Dict[str, str]:
    """读**本机 NDP / IPv6 邻居缓存整表**，返回 ``{ipv6: mac}``。**零发包**。

    三平台各自的命令：
    - Windows：``netsh interface ipv6 show neighbors``
    - Linux：``ip -6 neigh``
    - macOS：``ndp -an``

    命令不可用或本机未启用 IPv6 时返回**空 dict**，不抛异常 —— 这属于
    「无 IPv6 环境」的正常路径（与 IPv4 侧读不到 ARP 表同一立场）。
    但**只有**在确实本机没启用 IPv6 时才退回空；
    缓存**有内容**而解析结果为空，说明是**解析器**出了问题、不是环境问题，
    这种情况记 warning（用户能感知的结果缺失必须留痕）。
    """
    if _IS_WINDOWS:
        raw = _run_cmd(["netsh", "interface", "ipv6", "show", "neighbors"],
                       timeout=8)
        return parse_windows_ndp_cache(raw)
    if _IS_DARWIN:
        raw = _run_cmd(["ndp", "-an"], timeout=8)
        return parse_macos_ndp(raw)
    # Linux 及未识别平台：`ip -6 neigh` 在多数发行版可用。
    raw = _run_cmd(["ip", "-6", "neigh"], timeout=8)
    table = parse_linux_ip_neigh(raw)
    if not table and raw.strip():
        # 命令有输出但一条都没解析出来 —— 多半是 `ip` 的输出格式变了。
        _log.warning("NDP 缓存有输出但未能解析出任何条目（`ip -6 neigh` 格式变了？）")
    return table


# ── 可选的 ff02::1 单次多播（唯一会发包的一步） ──────────────────────────

def probe_all_nodes(timeout: float = 1.5) -> bool:
    """向 `ff02::1` 发**一次** ICMPv6 echo，促使设备回邻居通告。

    返回 ``True`` 表示包已发出（不保证有响应）。**这是本模块唯一会发包的
    函数** —— 调用方必须在用户显式开启时才调用（与 mDNS 的 `mdns_active`
    同口径，默认关）。

    **不做地址遍历**：只发往全节点多播地址一次，等价于 IPv4 的
    `ping 255.255.255.255`。接收方会回 ICMPv6 echo reply（单播），
    其源地址随即进入双方邻居缓存 —— 之后再调 `dump_ndp_cache()` 就能看到它们。

    为什么要手写而不是走系统 `ping -6 ff02::1`：
    - Windows 的 ``ping -6`` 对 link-local 目标需要 ``%iface`` 作用域，
      且不同版本对 ``ff02::1`` 的处理不一致；
    - 直接构造 ICMPv6 包能精确控制「只发一个」，符合本项的「不发多余包」口径。

    失败（无 IPv6 网卡 / 无组播路由 / 权限不足）时记 warning 并返回 ``False``，
    **不抛异常** —— 看得到多少算多少，不能因为探测失败把已读到的缓存丢掉。
    """
    import socket
    import struct

    # 源：向 ff02::1 的 53 端口「连」一下，让内核选出一条 IPv6 出接口，
    # 拿到它的 link-local 源地址。UDP connect 不发包，只是选路。
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            probe.connect((ALL_NODES_MULTICAST, 53))
            src = probe.getsockname()[0]
            iface = probe.getsockname()[3] if len(probe.getsockname()) > 3 else 0
        finally:
            probe.close()
    except OSError as e:
        _log.warning("本机没有可用的 IPv6 出接口，跳过 ff02::1 探测: %s", e)
        return False

    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                             socket.IPPROTO_ICMPV6)
        if iface:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                                struct.pack("I", iface))
            except OSError as e:
                # 设组播出接口失败不致命：多数单网卡机器上内核会自己选对。
                _log.debug("设置 IPv6 组播出接口失败（继续）: %s", e)
        # ICMPv6 echo request：type=128 code=0 checksum(由内核补/校验) id=0x4953 seq=1
        # 内核负责 IPv6 头与 ICMPv6 校验和（多数平台自动计算），
        # 所以这里只给 ICMPv6 载荷。
        payload = struct.pack("!BBHHH", 128, 0, 0, 0x4953, 1)
        sock.sendto(payload, (ALL_NODES_MULTICAST, 0, 0, iface or 0))
        _log.debug("已向 %s 发出一次 ICMPv6 echo（源 %s）", ALL_NODES_MULTICAST, src)
        return True
    except OSError as e:
        # 原始套接字需要管理员/root。权限不足是**预期分支**，
        # 提示用户改用「只读缓存」即可，不算错误。
        _log.warning("发送 ff02::1 探测失败（需要管理员/root 或本机无 IPv6）: %s", e)
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception as e:  # noqa: BLE001
                _log.debug("关闭 ICMPv6 socket 失败: %s", e)


# ── 把 IPv6 邻居挂到已有 IPv4 资产上（按 MAC 关联，不新建资产） ──────────

def attach_ipv6(ndp_table: Dict[str, str], hosts) -> int:
    """把 NDP 缓存里的 IPv6 地址**按 MAC 关联**到已有 IPv4 资产上。

    Args:
        ndp_table: ``dump_ndp_cache()`` 的返回，``{ipv6: mac}``。
        hosts: 可迭代的 ``ScanResult``（或任何有 ``mac`` 属性 /
            ``ipv6_addresses`` 列表属性的对象）。

    Returns:
        实际挂上去的 IPv6 地址条数。

    关联规则：**MAC 完全相等**才挂。一台设备在 IPv4 侧记的是 ``c8:4d:44:xx``，
    NDP 里的邻居 MAC 完全一致 ⇒ 同一台机器的 IPv6 地址，追加到它的
    ``ipv6_addresses`` 里（去重、排序稳定）。

    **不新建资产**：NDP 里出现的、找不到对应 IPv4 MAC 的地址（纯 IPv6 设备）
    本条只记 debug —— 那正是本项边界外的东西，硬造一行出来会污染资产台账。
    """
    by_mac: Dict[str, list] = {}
    for host in hosts or ():
        mac = (getattr(host, "mac", "") or "").lower()
        if mac:
            by_mac.setdefault(mac, []).append(host)

    attached = 0
    unmatched = 0
    for addr, mac in (ndp_table or {}).items():
        targets = by_mac.get((mac or "").lower())
        if not targets:
            unmatched += 1
            continue
        for host in targets:
            existing = getattr(host, "ipv6_addresses", None)
            if existing is None:
                # 宿主对象不支持该字段（旧模型 / 第三方对象）→ 跳过，
                # 不能因为一个可选属性缺失就把整次挂靠弄挂。
                continue
            if addr not in existing:
                existing.append(addr)
                attached += 1
    if unmatched:
        _log.debug("NDP 里有 %d 个地址找不到匹配的 IPv4 资产（纯 IPv6 设备？）",
                   unmatched)
    return attached


def sort_ipv6(addrs) -> list:
    """IPv6 地址排序：先 link-local 后全局，组内按数值大小。

    UI / 导出照着这个顺序展示，读起来更像「先看本链路、再看全局」。
    """
    def _key(a):
        try:
            ip = ipaddress.IPv6Address(a)
            return (0 if ip.is_link_local else 1, int(ip))
        except ValueError:
            return (2, 0)
    return sorted(addrs, key=_key)
