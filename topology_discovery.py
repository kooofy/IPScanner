# -*- coding: utf-8 -*-
"""网络拓扑发现：通过 SNMP LLDP / CDP 发现交换机间真实链路。

LLDP (IEEE 802.1AB) — 多数厂商支持（HP/Aruba/Juniper/Dell/H3C 等）。
CDP (Cisco Discovery Protocol) — Cisco 专有。
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from scanner.snmp import snmp_walk, snmp_get_system


# ── OID constants (imported from snmp.py at runtime to avoid circular imports) ──
_LLDP_REM_LOCAL_PORT = None
_LLDP_REM_CHASSIS_ID = None
_LLDP_REM_PORT_ID = None
_LLDP_REM_PORT_DESC = None
_LLDP_REM_SYS_NAME = None
_CDP_CACHE_IFINDEX = None
_CDP_CACHE_ADDRESS = None
_CDP_CACHE_DEVICE_ID = None
_CDP_CACHE_DEVICE_PORT = None
_CDP_CACHE_PLATFORM = None


def _init_oids():
    global _LLDP_REM_LOCAL_PORT, _LLDP_REM_CHASSIS_ID, _LLDP_REM_PORT_ID
    global _LLDP_REM_PORT_DESC, _LLDP_REM_SYS_NAME
    global _CDP_CACHE_IFINDEX, _CDP_CACHE_ADDRESS, _CDP_CACHE_DEVICE_ID
    global _CDP_CACHE_DEVICE_PORT, _CDP_CACHE_PLATFORM
    if _LLDP_REM_LOCAL_PORT is not None:
        return
    from scanner.snmp import (
        _LLDP_REM_LOCAL_PORT as a, _LLDP_REM_CHASSIS_ID as b,
        _LLDP_REM_PORT_ID as c, _LLDP_REM_PORT_DESC as d,
        _LLDP_REM_SYS_NAME as e,
        _CDP_CACHE_IFINDEX as f, _CDP_CACHE_ADDRESS as g,
        _CDP_CACHE_DEVICE_ID as h, _CDP_CACHE_DEVICE_PORT as i,
        _CDP_CACHE_PLATFORM as j,
    )
    _LLDP_REM_LOCAL_PORT, _LLDP_REM_CHASSIS_ID = a, b
    _LLDP_REM_PORT_ID, _LLDP_REM_PORT_DESC = c, d
    _LLDP_REM_SYS_NAME = e
    _CDP_CACHE_IFINDEX, _CDP_CACHE_ADDRESS = f, g
    _CDP_CACHE_DEVICE_ID, _CDP_CACHE_DEVICE_PORT = h, i
    _CDP_CACHE_PLATFORM = j


@dataclass
class TopoNode:
    """拓扑节点：交换机或终端设备。"""
    id: str                          # 唯一标识 (IP 或 MAC)
    label: str                       # 显示名
    ip: str = ""
    mac: str = ""
    is_switch: bool = False
    vendor: str = ""
    model: str = ""


@dataclass
class TopoLink:
    """拓扑链路：两个节点间的连接。"""
    source_id: str
    target_id: str
    source_port: str = ""            # 源端口名
    target_port: str = ""            # 目标端口名
    protocol: str = ""               # "LLDP" / "CDP" / "ARP" / "scan"


@dataclass
class Topology:
    """完整拓扑。"""
    nodes: List[TopoNode] = field(default_factory=list)
    links: List[TopoLink] = field(default_factory=list)


def _find_switches(results) -> List:
    """从扫描结果中找出可能的交换机（有 SNMP 响应或 sysDescr 含 switch）。"""
    switches = []
    for r in results:
        if r.status != "online":
            continue
        is_switch = False
        sd = (r.snmp_sys_descr or "").lower()
        if any(kw in sd for kw in ("switch", "ios", "nx-os", "junos", "aruba",
                                     "procurve", "comware", "routeros")):
            is_switch = True
        if 161 in r.open_ports or "SNMP" in (r.services or []):
            is_switch = True
        if is_switch:
            switches.append(r)
    return switches


def _discover_lldp_neighbors(switch_ip: str, communities=None,
                              timeout: float = 1.0) -> List[dict]:
    """对一台交换机执行 LLDP 邻居发现。自动尝试多个 community 直到成功。"""
    _init_oids()
    if communities is None:
        communities = _default_communities()

    for community in communities:
        rem_entries = snmp_walk(switch_ip, _LLDP_REM_LOCAL_PORT + ".",
                                 community=community, timeout=timeout, max_iterations=500)
        if rem_entries:
            return _parse_lldp_entries(rem_entries)
    return []


def _parse_lldp_entries(rem_entries: dict) -> List[dict]:
    """解析 LLDP remTable walk 结果为邻居列表。"""
    neighbors = []
    port_neighbors: Dict[str, dict] = {}
    for oid, (vbytes, vtag) in rem_entries.items():
        parts = oid.split(".")
        if len(parts) < 2:
            continue
        local_port = parts[-2]
        entry = port_neighbors.setdefault(local_port, {"local_port": local_port})

        oid_prefix = ".".join(parts[:-2])
        if oid_prefix == _LLDP_REM_CHASSIS_ID:
            entry["chassis_id"] = _bytes_to_str(vbytes, vtag)
        elif oid_prefix == _LLDP_REM_PORT_ID:
            entry["remote_port"] = _bytes_to_str(vbytes, vtag)
        elif oid_prefix == _LLDP_REM_PORT_DESC:
            entry["port_desc"] = _bytes_to_str(vbytes, vtag)
        elif oid_prefix == _LLDP_REM_SYS_NAME:
            entry["sys_name"] = _bytes_to_str(vbytes, vtag)

    for local_port, entry in port_neighbors.items():
        neighbors.append({
            "local_port": local_port,
            "local_port_desc": entry.get("port_desc", f"Port {local_port}"),
            "remote_id": entry.get("chassis_id", ""),
            "remote_port": entry.get("remote_port", ""),
            "remote_name": entry.get("sys_name", ""),
            "protocol": "LLDP",
        })

    return neighbors


def _discover_cdp_neighbors(switch_ip: str, communities=None,
                             timeout: float = 1.0) -> List[dict]:
    """对一台 Cisco 交换机执行 CDP 邻居发现。自动尝试多个 community。"""
    _init_oids()
    if communities is None:
        communities = _default_communities()

    for community in communities:
        rem_entries = snmp_walk(switch_ip, _CDP_CACHE_DEVICE_ID + ".",
                                 community=community, timeout=timeout, max_iterations=500)
        if rem_entries:
            return _parse_cdp_entries(rem_entries)
    return []


def _parse_cdp_entries(rem_entries: dict) -> List[dict]:
    """解析 CDP cacheTable walk 结果为邻居列表。"""
    neighbors = []
    port_data: Dict[str, dict] = {}
    for oid, (vbytes, vtag) in rem_entries.items():
        parts = oid.split(".")
        if len(parts) < 2:
            continue
        local_ifindex = parts[-1]
        entry = port_data.setdefault(local_ifindex, {"local_ifindex": local_ifindex})

        oid_prefix = ".".join(parts[:-1])
        if oid_prefix == _CDP_CACHE_DEVICE_ID:
            entry["remote_name"] = vbytes.decode("utf-8", "replace").strip()
        elif oid_prefix == _CDP_CACHE_ADDRESS:
            if vtag == 0x40:  # IP address
                entry["remote_ip"] = ".".join(str(b) for b in vbytes)
            else:
                entry["remote_id"] = _bytes_to_hex(vbytes)
        elif oid_prefix == _CDP_CACHE_DEVICE_PORT:
            entry["remote_port"] = vbytes.decode("utf-8", "replace").strip()
        elif oid_prefix == _CDP_CACHE_PLATFORM:
            entry["platform"] = vbytes.decode("utf-8", "replace").strip()

    for ifindex, entry in port_data.items():
        neighbors.append({
            "local_port": ifindex,
            "local_port_desc": f"ifIndex {ifindex}",
            "remote_id": entry.get("remote_id", entry.get("remote_ip", "")),
            "remote_ip": entry.get("remote_ip", ""),
            "remote_port": entry.get("remote_port", ""),
            "remote_name": entry.get("remote_name", ""),
            "platform": entry.get("platform", ""),
            "protocol": "CDP",
        })

    return neighbors


def _default_communities() -> List[str]:
    """返回默认 SNMP community 尝试列表。"""
    return ["public", "private", ""]


def discover_topology(results, progress_callback=None) -> Topology:
    """
    从扫描结果中发现网络拓扑。

    Args:
        results: ScanResult 列表
        progress_callback(phase, current, total, message): 可选进度回调

    Returns:
        Topology 对象，含 nodes 和 links
    """
    topo = Topology()

    # 1) 收集所有扫描到的设备作为节点
    node_map: Dict[str, TopoNode] = {}  # ip -> node
    for r in results:
        node = TopoNode(
            id=r.ip,
            label=r.hostname or r.ip,
            ip=r.ip,
            mac=r.mac,
            vendor=r.vendor,
            model=r.device_model,
        )
        topo.nodes.append(node)
        node_map[r.ip] = node

    # 2) 找出交换机
    switches = _find_switches(results)
    if progress_callback:
        progress_callback("discover", 0, len(switches),
                          f"发现 {len(switches)} 台交换机")

    if not switches:
        return topo

    # 3) 对每台交换机做 LLDP / CDP 邻居发现
    all_neighbors: Dict[str, List[dict]] = {}  # switch_ip -> neighbors
    for idx, sw in enumerate(switches):
        if progress_callback:
            progress_callback("lldp", idx, len(switches),
                              f"LLDP 发现: {sw.ip} ({sw.hostname or sw.ip})")

        neighbors = _discover_lldp_neighbors(sw.ip)
        if not neighbors:
            neighbors = _discover_cdp_neighbors(sw.ip)

        all_neighbors[sw.ip] = neighbors

        # 标记为交换机
        if sw.ip in node_map:
            node_map[sw.ip].is_switch = True
            node_map[sw.ip].model = node_map[sw.ip].model or sw.snmp_sys_descr or "Switch"

    # 4) 构建链路
    for sw_ip, neighbors in all_neighbors.items():
        for nb in neighbors:
            remote_id = nb.get("remote_id", "") or nb.get("remote_ip", "")
            # 尝试在扫描结果中匹配邻居
            target_ip = _match_neighbor(remote_id, nb, results, node_map)

            if not target_ip:
                # 邻居不在扫描范围内，创建外部队列节点
                ext_label = nb.get("remote_name", "") or nb.get("remote_id", "") or remote_id
                if nb.get("platform"):
                    ext_label += f" ({nb['platform']})"
                ext_id = f"ext:{remote_id}" if remote_id else f"ext:{ext_label}"
                if ext_id not in node_map:
                    ext_node = TopoNode(
                        id=ext_id,
                        label=ext_label,
                        ip=nb.get("remote_ip", ""),
                        is_switch=("switch" in (nb.get("platform", "")).lower()),
                    )
                    topo.nodes.append(ext_node)
                    node_map[ext_id] = ext_node
                target_ip = ext_id

            link = TopoLink(
                source_id=sw_ip,
                target_id=target_ip,
                source_port=nb.get("local_port_desc", ""),
                target_port=nb.get("remote_port", ""),
                protocol=nb.get("protocol", ""),
            )
            topo.links.append(link)

    if progress_callback:
        progress_callback("done", len(switches), len(switches),
                          f"拓扑发现完成: {len(topo.nodes)} 节点, {len(topo.links)} 链路")

    return topo


def _match_neighbor(remote_id: str, nb: dict, results, node_map: dict) -> Optional[str]:
    """尝试将 LLDP/CDP 邻居匹配到扫描结果中的 IP。"""
    # 方法1: CDP 直接给了 IP
    remote_ip = nb.get("remote_ip", "")
    if remote_ip and remote_ip in node_map:
        return remote_ip

    # 方法2: 用 chassis ID (通常是 MAC) 匹配
    if remote_id:
        clean_id = remote_id.replace(":", "").replace("-", "").replace(".", "").lower()
        for r in results:
            if r.mac:
                clean_mac = r.mac.replace(":", "").lower()
                if clean_mac == clean_id:
                    return r.ip
                # 也匹配末尾 12 hex digits (有些厂商只给最后 6 字节)
                if len(clean_id) >= 12 and len(clean_mac) >= 12:
                    if clean_mac[-12:] == clean_id[-12:]:
                        return r.ip

    # 方法3: 用邻居系统名匹配
    remote_name = nb.get("remote_name", "").lower()
    if remote_name:
        for r in results:
            if r.hostname and r.hostname.lower() == remote_name:
                return r.ip

    return None


def _bytes_to_str(vbytes, vtag) -> str:
    """SNMP value bytes → 可读字符串。"""
    if vtag == 0x04:  # OCTET STRING
        return vbytes.decode("utf-8", "replace").strip()
    return _bytes_to_hex(vbytes)


def _bytes_to_hex(vbytes) -> str:
    """SNMP value bytes → hex:xx:xx 格式（MAC 地址风格）。"""
    return ":".join(f"{b:02x}" for b in vbytes)
