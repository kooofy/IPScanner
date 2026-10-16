# -*- coding: utf-8 -*-
"""SNMP ARP 表（ipNetToMediaTable / ipNetToPhysicalTable）的纯解析。

**为什么需要它**
----------------
MAC 是二层概念，只能靠 ARP 在同一个广播域里学到。扫描机与目标不在同一
网段时，本机 ARP 表里永远只有网关的 MAC（ICMP 能通是因为经网关三层转发）。
出路是**换一台"看得见"这些设备的机器去读它的 ARP 表** —— 持有目标网段
三层接口的那台路由器 / 三层交换机（通常就是本机默认网关）。它要转发数据包，
就必须自己 ARP 出目标的 MAC，于是它的 ARP 表里有完整的 IP → MAC。

**两条 MIB**
------------
- ``ipNetToMediaPhysAddress``（RFC 1213，``1.3.6.1.2.1.4.22.1.2``）：老而广。
  🔴 **索引后缀自带 IP**（``<ifIndex>.<a>.<b>.<c>.<d>``），值是 6 字节
  OCTET STRING ⇒ **一次 walk 就同时拿到 IP 与 MAC**，不必再走
  ``ipNetToMediaNetAddress`` 那一列（省一整趟 walk）。
- ``ipNetToPhysicalPhysAddress``（RFC 4293，``1.3.6.1.2.1.4.35.1.4``）：新设备。
  索引是 ``<ifIndex>.<addrType>.<addrLen>.<addr…>.<addressType>``，要扫一遍
  才能挑出 IPv4 的那 4 个字节。

**边界**
--------
本模块**零网络、零 i18n**：``walk_fn`` 由调用方注入（``(base_oid) ->
{oid: (value_bytes, value_tag)}``），传输方式（v2c / v3）与用户可见文案留在
``arp_mapper.py``。这样解析逻辑可以完全离线单测 —— 不依赖真实设备。
"""
from typing import Callable, Dict, Tuple

#: ipNetToMediaPhysAddress（RFC 1213）：值 = MAC，索引后缀自带 IP
OID_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"
#: ipNetToPhysicalPhysAddress（RFC 4293）：新设备的等价物
OID_NET_TO_PHYSICAL_PHYS = "1.3.6.1.2.1.4.35.1.4"

#: 来源标记（**语言无关的规范值**，展示时才翻译 —— 与 SVC_* 同一套规矩）
SOURCE_NET_TO_MEDIA = "ipNetToMediaTable"
SOURCE_NET_TO_PHYSICAL = "ipNetToPhysicalTable"

_TAG_OCTET_STRING = 0x04

#: 一次 walk 的迭代上限。核心交换机的 ARP 表可以到几千条，
#: 默认 2000 会**静默截断**成"只有前半张表"——那比报错更难发现。
DEFAULT_MAX_ITERATIONS = 8000


def mac_from_octets(vbytes: bytes) -> str:
    """6 字节 OCTET STRING → ``"aa:bb:cc:dd:ee:ff"``；长度不符返回空串。

    🔴 **全零 MAC 返回空串**：部分设备用 ``00:00:00:00:00:00`` 表示
    "这条表项无效 / 未解析"。把它当成一个真实 MAC 收下来，会让这台设备
    在台账里和所有同样取不到 MAC 的设备**撞成同一个身份键**。
    """
    if not vbytes or len(vbytes) != 6:
        return ""
    if vbytes == b"\x00" * 6:
        return ""
    return ":".join(f"{b:02x}" for b in vbytes)


def is_usable_mac(mac: str) -> bool:
    """判断一个 MAC 字符串能不能当身份用（非空、6 段、非全零）。"""
    if not mac:
        return False
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    if all(p == "00" for p in parts):
        return False
    return all(len(p) == 2 for p in parts)


def _suffix_to_ip_v1213(suffix: str) -> str:
    """RFC 1213 的索引后缀 ``<ifIndex>.<a>.<b>.<c>.<d>`` → IP。

    取**最后 4 段**而不是按位置切：ifIndex 的位数不固定（1 位到 6 位都可能），
    定长切片会在 ifIndex 位数变化时错位。
    """
    parts = suffix.split(".")
    if len(parts) < 5:
        return ""
    try:
        octets = [int(p) for p in parts[-4:]]
    except ValueError:
        return ""
    if any(not 0 <= o < 256 for o in octets):
        return ""
    return ".".join(str(o) for o in octets)


def _suffix_to_ip_v4293(suffix: str) -> str:
    """RFC 4293 的索引后缀里挑出 IPv4 的 InetAddress 部分。

    形如 ``<ifIndex>.1.4.<a>.<b>.<c>.<d>.<addressType>``（addrType=1 为 ipv4，
    紧跟的长度字节为 4）。这里**扫描**而不是定长切片，容忍 ifIndex 位数变化。
    """
    parts = suffix.split(".")
    for i in range(len(parts) - 6):
        if parts[i + 1] != "1" or parts[i + 2] != "4":
            continue
        try:
            octets = [int(p) for p in parts[i + 3:i + 7]]
        except ValueError:
            continue
        if all(0 <= o < 256 for o in octets):
            return ".".join(str(o) for o in octets)
    return ""


def _collect(entries, base_oid: str, parse_suffix) -> Dict[str, str]:
    """把一次 walk 的原始结果转成 ``{ip: mac}``（只保留可用条目）。"""
    prefix = base_oid.rstrip(".") + "."
    table: Dict[str, str] = {}
    for oid, value in (entries or {}).items():
        if not oid.startswith(prefix):
            continue
        try:
            vbytes, vtag = value
        except (TypeError, ValueError):
            continue
        if vtag != _TAG_OCTET_STRING:
            continue
        ip = parse_suffix(oid[len(prefix):])
        mac = mac_from_octets(vbytes)
        if ip and mac:
            table[ip] = mac
    return table


def parse_net_to_media(entries) -> Dict[str, str]:
    """``ipNetToMediaPhysAddress`` 的 walk 结果 → ``{ip: mac}``。"""
    return _collect(entries, OID_NET_TO_MEDIA_PHYS, _suffix_to_ip_v1213)


def parse_net_to_physical(entries) -> Dict[str, str]:
    """``ipNetToPhysicalPhysAddress`` 的 walk 结果 → ``{ip: mac}``。"""
    return _collect(entries, OID_NET_TO_PHYSICAL_PHYS, _suffix_to_ip_v4293)


def walk_arp_table(walk_fn: Callable[[str, int], dict],
                   max_iterations: int = DEFAULT_MAX_ITERATIONS
                   ) -> Tuple[Dict[str, str], str]:
    """按 RFC 1213 → RFC 4293 的顺序取 ARP 表。

    Args:
        walk_fn: ``(base_oid, max_iterations) -> {oid: (value_bytes, value_tag)}``。
            由调用方注入 v2c / v3 的具体实现（见 ``arp_mapper``）。
        max_iterations: 单次 walk 的迭代上限。

    Returns:
        ``(table, source)``：``table`` 是 ``{ip: mac}``；``source`` 是命中的
        MIB 规范名（``SOURCE_*``），两者都取不到时 source 为空串。
    """
    for base_oid, parse, source in (
        (OID_NET_TO_MEDIA_PHYS, parse_net_to_media, SOURCE_NET_TO_MEDIA),
        (OID_NET_TO_PHYSICAL_PHYS, parse_net_to_physical, SOURCE_NET_TO_PHYSICAL),
    ):
        raw = walk_fn(base_oid, max_iterations)
        table = parse(raw)
        if table:
            return table, source
    return {}, ""
