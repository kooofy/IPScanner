# -*- coding: utf-8 -*-
"""交换机端口映射：通过 SNMP 遍历交换机 MAC 转发表，建立 MAC → 物理端口 的对应关系。

核心 OID：
- dot1dTpFdbAddress  1.3.6.1.2.1.17.4.3.1.1  MAC 地址（OID 后缀 = 6 字节十进制）
- dot1dTpFdbPort     1.3.6.1.2.1.17.4.3.1.2  桥接端口号
- dot1dTpFdbStatus   1.3.6.1.2.1.17.4.3.1.3  状态（3=learned, 5=self）
- dot1dBasePortIfIndex 1.3.6.1.2.1.17.1.4.1.2 桥接端口 → ifIndex
- ifDescr            1.3.6.1.2.1.2.2.1.2      端口描述（如 GigabitEthernet0/1）
- ifName             1.3.6.1.2.1.31.1.1.1.1   端口短名（如 Gi0/1）

纯标准库 + 复用 scanner.snmp 的 BER 编解码，无第三方依赖。
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable

from scanner.snmp import snmp_walk, snmp_get_system
from scanner.snmp_v3 import snmp_v3_walk, snmp_v3_get_system
from app_logging import get_logger
from i18n import tr

_log = get_logger(__name__)


# ── OID 前缀 ──
_OID_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
_OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
_OID_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
_OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
_OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
_OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"


@dataclass
class PortMapping:
    """单条 MAC → 端口映射记录。"""
    mac: str                    # 格式化 MAC (AA:BB:CC:DD:EE:FF)
    port_name: str = ""         # 端口名称 (ifDescr 或 ifName)
    if_index: int = 0           # SNMP ifIndex
    bridge_port: int = 0        # 桥接端口号
    # port_name 是否来自**真实接口名**（ifName / ifDescr）。
    # 为 False 时 port_name 只是桥接端口号（如 "Port 5"）——**那不是端口名**，
    # 上层展示时必须标注不确定，不能把它当成 GigabitEthernet0/5 糊弄过去。
    port_is_real: bool = True
    # 以下为关联扫描结果后填充（可选）
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    device_class: str = ""


@dataclass
class SwitchInfo:
    """交换机基本信息 + 端口映射结果。"""
    ip: str
    sys_name: str = ""
    sys_descr: str = ""
    mappings: List[PortMapping] = field(default_factory=list)
    error: str = ""


def _oid_suffix_to_mac(suffix: str) -> str:
    """将 OID 后缀（6 个十进制数用 . 分隔）转为 MAC 地址字符串。"""
    parts = suffix.split(".")
    if len(parts) != 6:
        return ""
    try:
        return ":".join(f"{int(p):02X}" for p in parts)
    except ValueError:
        return ""


def _extract_suffix(oid: str, prefix: str) -> str:
    """提取 OID 中 prefix 之后的后缀部分。"""
    p = prefix.rstrip(".") + "."
    if oid.startswith(p):
        return oid[len(p):]
    return ""


def map_switch_ports(ip: str, community: str = "public", timeout: float = 1.5,
                     progress_cb: Optional[Callable[[str], None]] = None,
                     snmp_v3_user=None, port: int = 161) -> SwitchInfo:
    """对指定交换机执行 SNMP 端口映射。

    Args:
        ip: 交换机 IP 地址
        community: SNMP v2c 社区名（仅在未配置 SNMPv3 用户时使用）
        timeout: 每次 GETNEXT 的超时（秒）
        progress_cb: 进度回调（接收状态文本）
        snmp_v3_user: SnmpV3User 或 None。传入时改用 SNMPv3 认证/加密遍历
            （此时 `community` 被忽略）。
        port: SNMP 端口（默认 161；开放出来主要是为了可测试）

    Returns:
        SwitchInfo 对象，mappings 为 MAC→端口映射列表；出错时 error 非空。
    """
    info = SwitchInfo(ip=ip)
    use_v3 = snmp_v3_user is not None

    def _progress(msg):
        if progress_cb:
            progress_cb(msg)

    # 传输方式只在这一处分叉；下面整段映射组装逻辑对 v2c/v3 完全无感
    if use_v3:
        def _get_system():
            res = snmp_v3_get_system(ip, snmp_v3_user, timeout=timeout, port=port)
            return None if "error" in res else res

        def _walk(base_oid):
            return snmp_v3_walk(ip, snmp_v3_user, base_oid, timeout=timeout,
                                port=port)
    else:
        def _get_system():
            return snmp_get_system(ip, communities=[community], timeout=timeout,
                                   port=port)

        def _walk(base_oid):
            return snmp_walk(ip, base_oid, community=community, timeout=timeout,
                             port=port)

    # 0) 获取交换机基本信息
    _progress(tr("正在获取交换机信息..."))
    sys_info = _get_system()
    if sys_info:
        info.sys_name = sys_info.get("sys_name", "")
        info.sys_descr = sys_info.get("sys_descr", "")

    # 1) 遍历 MAC 转发表 (dot1dTpFdbTable)
    _progress(tr("正在遍历 MAC 转发表..."))
    fdb_port_raw = _walk(_OID_FDB_PORT)
    if not fdb_port_raw:
        info.error = (
            f"无法从 {ip} 获取 MAC 转发表。\n"
            + (tr("请确认：\n  1. 交换机已开启 SNMPv3 且用户名/口令正确\n")
               if use_v3 else
               tr("请确认：\n  1. 交换机已开启 SNMP 且社区名正确\n"))
            + tr("  2. 本机与交换机网络可达（UDP 161）\n"
                 "  3. 交换机支持 BRIDGE-MIB (dot1dTpFdbTable)")
        )
        return info

    # 2) 遍历 dot1dTpFdbStatus（过滤 self/管理地址）
    _progress(tr("正在读取转发表状态..."))
    fdb_status_raw = _walk(_OID_FDB_STATUS)

    # 3) 遍历 dot1dBasePortIfIndex（桥接端口 → ifIndex）
    _progress(tr("正在读取端口索引映射..."))
    base_port_raw = _walk(_OID_BASE_PORT_IFINDEX)

    # 4) 遍历 ifDescr / ifName（ifIndex → 端口名称）
    _progress(tr("正在读取端口名称..."))
    ifdescr_raw = _walk(_OID_IF_DESCR)
    ifname_raw = _walk(_OID_IF_NAME)

    # ── 组装映射 ──

    # 桥接端口 → ifIndex
    bp_to_if: Dict[int, int] = {}
    for oid, (vbytes, vtag) in base_port_raw.items():
        suffix = _extract_suffix(oid, _OID_BASE_PORT_IFINDEX)
        if suffix and vtag == 0x02:  # INTEGER
            try:
                bp_to_if[int(suffix)] = int.from_bytes(vbytes, "big")
            except ValueError as e:
                _log.debug("跳过非法的桥接端口索引 %r: %s", suffix, e)

    # ifIndex → 端口名称（优先 ifName，回退 ifDescr）
    if_to_name: Dict[int, str] = {}
    for oid, (vbytes, vtag) in ifdescr_raw.items():
        suffix = _extract_suffix(oid, _OID_IF_DESCR)
        if suffix and vtag == 0x04:  # OCTET STRING
            try:
                if_to_name[int(suffix)] = vbytes.decode("utf-8", "replace").strip()
            except ValueError as e:
                _log.debug("跳过非法的 ifDescr 索引 %r: %s", suffix, e)
    for oid, (vbytes, vtag) in ifname_raw.items():
        suffix = _extract_suffix(oid, _OID_IF_NAME)
        if suffix and vtag == 0x04:
            try:
                name = vbytes.decode("utf-8", "replace").strip()
                if name:
                    if_to_name[int(suffix)] = name
            except ValueError as e:
                _log.debug("跳过非法的 ifName 索引 %r: %s", suffix, e)

    # 状态过滤：仅保留 status=3 (learned) 和 status=5 (self)
    # 实际上 status=3 是动态学习到的终端 MAC，status=5 是交换机自身
    # 我们保留 3（终端），跳过 5（交换机自身 MAC）和其他
    status_map: Dict[str, int] = {}
    for oid, (vbytes, vtag) in fdb_status_raw.items():
        suffix = _extract_suffix(oid, _OID_FDB_STATUS)
        if suffix and vtag == 0x02:
            try:
                status_map[suffix] = int.from_bytes(vbytes, "big")
            except ValueError as e:
                _log.debug("跳过非法的转发表状态条目 %r: %s", suffix, e)

    # MAC → 桥接端口
    _progress(tr("正在组装映射结果..."))
    mappings: List[PortMapping] = []
    for oid, (vbytes, vtag) in fdb_port_raw.items():
        suffix = _extract_suffix(oid, _OID_FDB_PORT)
        if not suffix or vtag != 0x02:
            continue
        # 过滤：仅保留 learned (3) 状态的条目
        st = status_map.get(suffix, 3)
        if st not in (3,):
            continue

        mac = _oid_suffix_to_mac(suffix)
        if not mac:
            continue

        bridge_port = int.from_bytes(vbytes, "big")
        if_index = bp_to_if.get(bridge_port, 0)
        # ifName / ifDescr 里查不到这个 ifIndex 时，只能退回桥接端口号。
        # 那不是端口名 —— 用 port_is_real=False 标出来，让上层有机会如实展示。
        real_name = if_to_name.get(if_index)
        if real_name:
            port_name, port_is_real = real_name, True
        else:
            port_name, port_is_real = f"Port {bridge_port}", False

        mappings.append(PortMapping(
            mac=mac,
            port_name=port_name,
            if_index=if_index,
            bridge_port=bridge_port,
            port_is_real=port_is_real,
        ))

    # 按端口名称排序
    mappings.sort(key=lambda m: (m.port_name, m.mac))
    info.mappings = mappings
    _progress(f"完成：共 {len(mappings)} 条 MAC 映射")
    return info


def switch_info_to_dict(info: SwitchInfo) -> dict:
    """把 SwitchInfo 转成 ``history_store.save_port_map()`` 能吃的普通 dict。

    转换放在这里而不是 history_store：它需要知道 SwitchInfo / PortMapping 的字段，
    而 history_store 应保持与 switch_mapper 无耦合（它只认 dict）。

    只输出「事实」（`port_is_real`），不输出存储用的规范值字符串 ——
    事实到持久化编码的翻译由存储层负责，避免领域层反向依赖存储层。
    """
    return {
        "switch_ip": info.ip,
        # sys_name 为空时退回 IP：至少让上层有个能显示的标识，且这不是猜测
        # （IP 就是这台交换机的地址）。
        "switch_name": info.sys_name or info.ip,
        "error": info.error,
        "mappings": [
            {"mac": m.mac, "port_name": m.port_name, "port_is_real": m.port_is_real}
            for m in info.mappings
        ],
    }


def cross_reference(mappings: List[PortMapping], scan_results) -> List[PortMapping]:
    """将端口映射与扫描结果交叉关联，填充 IP/主机名/厂商/设备类型。

    Args:
        mappings: map_switch_ports 返回的映射列表
        scan_results: ScanResult 列表（当前扫描结果）

    Returns:
        同一 mappings 列表（就地修改），已填充关联字段。
    """
    # 建立 MAC → ScanResult 索引
    mac_index: Dict[str, object] = {}
    for r in scan_results:
        mac_upper = (r.mac or "").upper().strip()
        if mac_upper:
            mac_index[mac_upper] = r

    for m in mappings:
        r = mac_index.get(m.mac.upper())
        if r:
            m.ip = r.ip or ""
            m.hostname = r.hostname or ""
            m.vendor = r.vendor or ""
            m.device_class = getattr(r, "device_class", "") or getattr(r, "device_type", "") or ""

    return mappings
