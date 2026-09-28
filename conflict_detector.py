# -*- coding: utf-8 -*-
"""IP 冲突检测引擎。

分析扫描结果，识别以下冲突类型：
  - DUPLICATE_MAC   同一 MAC 出现在多个在线 IP 上（可能 IP 冲突或 ARP 欺骗）
  - DUPLICATE_HOSTNAME 同一主机名解析到多个在线 IP
  - UNKNOWN_DEVICE  在线设备不在地址库中（信息级）

纯逻辑模块，不依赖任何 UI 组件。
"""
from dataclasses import dataclass, field
from typing import List, Dict
from i18n import tr


# 冲突严重级别
SEVERITY_HIGH = "high"       # 明确冲突，需立即处理
SEVERITY_WARNING = "warning" # 疑似异常，建议排查
SEVERITY_INFO = "info"       # 仅供参考

# 冲突类型
CONFLICT_DUPLICATE_MAC = "duplicate_mac"
CONFLICT_DUPLICATE_HOSTNAME = "duplicate_hostname"
CONFLICT_UNKNOWN_DEVICE = "unknown_device"


# 冲突类型 / 严重级别的显示原文。
# 注意：这里存的是**未翻译的源串**，翻译在 type_label / severity_label 属性里
# 惰性进行。旧实现在模块级写 tr("MAC 地址重复")，tr() 在 import 期就被求值并
# 冻结，切换语言后这些标签不会跟着变（要重启进程才生效）。
_TYPE_TEXT = {
    CONFLICT_DUPLICATE_MAC: "MAC 地址重复",
    CONFLICT_DUPLICATE_HOSTNAME: "主机名重复",
    CONFLICT_UNKNOWN_DEVICE: "未知设备",
}

_SEVERITY_TEXT = {
    SEVERITY_HIGH: "严重",
    SEVERITY_WARNING: "警告",
    SEVERITY_INFO: "提示",
}


@dataclass
class Conflict:
    """单条冲突记录。"""
    conflict_type: str          # CONFLICT_* 常量
    severity: str               # SEVERITY_* 常量
    description: str            # 人类可读描述
    ips: List[str] = field(default_factory=list)       # 涉及的 IP 列表
    macs: List[str] = field(default_factory=list)      # 涉及的 MAC 列表
    hostnames: List[str] = field(default_factory=list) # 涉及的主机名
    detail: str = ""            # 补充细节

    @property
    def type_label(self) -> str:
        """当前语言下的冲突类型名（惰性翻译）。"""
        text = _TYPE_TEXT.get(self.conflict_type)
        return tr(text) if text else self.conflict_type

    @property
    def severity_label(self) -> str:
        """当前语言下的严重级别名（惰性翻译）。"""
        text = _SEVERITY_TEXT.get(self.severity)
        return tr(text) if text else self.severity


def detect_conflicts(results, library=None) -> List[Conflict]:
    """分析扫描结果，返回冲突列表。

    Args:
        results: ScanResult 列表（来自 all_results）
        library: MacLibrary 实例（可选，用于地址库比对）

    Returns:
        按严重级别降序排列的 Conflict 列表
    """
    conflicts: List[Conflict] = []
    online = [r for r in results if r.status == "online"]

    if not online:
        return conflicts

    # ── 1) 同 MAC 多 IP ──
    conflicts.extend(_detect_duplicate_mac(online))

    # ── 2) 同主机名多 IP ──
    conflicts.extend(_detect_duplicate_hostname(online))

    # ── 3) 地址库比对（需要 library）──
    if library is not None:
        conflicts.extend(_detect_unknown_devices(online, library))

    # 按严重级别排序：high > warning > info
    order = {SEVERITY_HIGH: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}
    conflicts.sort(key=lambda c: order.get(c.severity, 9))
    return conflicts


def _detect_duplicate_mac(online_results) -> List[Conflict]:
    """检测同一 MAC 出现在多个在线 IP 上的情况。"""
    mac_to_ips: Dict[str, List] = {}
    for r in online_results:
        mac = (r.mac or "").upper().strip()
        if mac:
            mac_to_ips.setdefault(mac, []).append(r)

    conflicts = []
    for mac, rs in mac_to_ips.items():
        if len(rs) < 2:
            continue
        ips = [r.ip for r in rs]
        hostnames = [r.hostname or "—" for r in rs]
        vendors = list({r.vendor for r in rs if r.vendor})
        vendor_str = vendors[0] if len(vendors) == 1 else ", ".join(vendors) if vendors else tr("未知")

        desc = f"MAC {mac} 同时出现在 {len(ips)} 个在线 IP 上"
        detail_parts = [f"IP: {', '.join(ips)}"]
        if any(h != "—" for h in hostnames):
            detail_parts.append(f"主机名: {', '.join(hostnames)}")
        detail_parts.append(f"厂商: {vendor_str}")

        conflicts.append(Conflict(
            conflict_type=CONFLICT_DUPLICATE_MAC,
            severity=SEVERITY_HIGH,
            description=desc,
            ips=ips,
            macs=[mac],
            hostnames=hostnames,
            detail=" · ".join(detail_parts),
        ))
    return conflicts


def _detect_duplicate_hostname(online_results) -> List[Conflict]:
    """检测同一主机名解析到多个在线 IP 的情况。"""
    name_to_ips: Dict[str, List] = {}
    for r in online_results:
        name = (r.hostname or "").strip()
        if name:
            name_to_ips.setdefault(name, []).append(r)

    conflicts = []
    for name, rs in name_to_ips.items():
        if len(rs) < 2:
            continue
        ips = [r.ip for r in rs]
        macs = [(r.mac or "—").upper() for r in rs]

        desc = f"主机名 \"{name}\" 解析到 {len(ips)} 个在线 IP"
        detail_parts = [f"IP: {', '.join(ips)}"]
        detail_parts.append(f"MAC: {', '.join(macs)}")

        conflicts.append(Conflict(
            conflict_type=CONFLICT_DUPLICATE_HOSTNAME,
            severity=SEVERITY_WARNING,
            description=desc,
            ips=ips,
            macs=macs,
            hostnames=[name],
            detail=" · ".join(detail_parts),
        ))
    return conflicts


def _detect_unknown_devices(online_results, library) -> List[Conflict]:
    """检测不在地址库中的在线设备（信息级）。"""
    # 构建地址库 MAC 集合用于快速查找
    lib_macs = set()
    lib_ips = set()
    try:
        all_entries = library.get_all() if hasattr(library, 'get_all') else []
        for e in all_entries:
            m = (e.get("mac") or "").upper().strip()
            if m:
                lib_macs.add(m)
            ip = (e.get("ip") or "").strip()
            if ip:
                lib_ips.add(ip)
    except Exception:
        return []

    if not lib_macs and not lib_ips:
        return []  # 地址库为空时不做未知设备检测

    unknown = []
    for r in online_results:
        mac = (r.mac or "").upper().strip()
        ip = r.ip.strip()
        # MAC 和 IP 都不在库中才算未知
        if mac and mac in lib_macs:
            continue
        if ip in lib_ips:
            continue
        unknown.append(r)

    if not unknown:
        return []

    # 合并为一条汇总冲突（避免大量单条刷屏）
    ips = [r.ip for r in unknown]
    macs = [(r.mac or "—").upper() for r in unknown]
    hostnames = [r.hostname or "—" for r in unknown]

    desc = f"发现 {len(unknown)} 台不在地址库中的在线设备"
    # 详情最多列前 10 台
    detail_lines = []
    for r in unknown[:10]:
        parts = [r.ip]
        if r.mac:
            parts.append(r.mac.upper())
        if r.hostname:
            parts.append(r.hostname)
        if r.vendor:
            parts.append(r.vendor)
        detail_lines.append(" ".join(parts))
    if len(unknown) > 10:
        detail_lines.append(f"... 及其他 {len(unknown) - 10} 台")

    return [Conflict(
        conflict_type=CONFLICT_UNKNOWN_DEVICE,
        severity=SEVERITY_INFO,
        description=desc,
        ips=ips,
        macs=macs,
        hostnames=hostnames,
        detail="\n".join(detail_lines),
    )]


def get_conflict_ips(conflicts: List[Conflict]) -> Dict[str, List[str]]:
    """提取冲突涉及的 IP → 冲突类型列表映射，用于树视图标记。

    仅包含 HIGH / WARNING 级别的冲突；INFO 级别（如未知设备）
    不在树视图中打标记，仅在冲突报告对话框中展示。

    Returns:
        {ip: [conflict_type, ...]}
    """
    ip_map: Dict[str, List[str]] = {}
    for c in conflicts:
        if c.severity == SEVERITY_INFO:
            continue
        for ip in c.ips:
            ip_map.setdefault(ip, []).append(c.conflict_type)
    return ip_map
