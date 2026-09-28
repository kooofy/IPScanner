# -*- coding: utf-8 -*-
"""资产变更检测：对比当前扫描结果与上一次快照，发现设备变动。

变更类型：
- 新增设备 (NEW_DEVICE)：本次在线但上次不存在
- 设备消失 (DEVICE_GONE)：上次在线但本次不存在
- MAC 变更 (MAC_CHANGED)：同一 IP 对应了不同 MAC（设备被替换）
- IP 变更 (IP_CHANGED)：同一 MAC 出现在不同 IP（设备换了地址）
- 主机名变更 (HOSTNAME_CHANGED)：同一 MAC 的主机名发生变化

纯标准库，无 PyQt 依赖，便于单元测试。
"""
from dataclasses import dataclass
from typing import List, Dict
from i18n import tr


# ── 变更类型 ──
CHANGE_NEW_DEVICE = "new_device"
CHANGE_DEVICE_GONE = "device_gone"
CHANGE_MAC_CHANGED = "mac_changed"
CHANGE_IP_CHANGED = "ip_changed"
CHANGE_HOSTNAME_CHANGED = "hostname_changed"

# ── 严重度 ──
SEVERITY_HIGH = "high"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"


@dataclass
class Change:
    """单条变更事件。"""
    change_type: str
    severity: str
    description: str
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    old_value: str = ""
    new_value: str = ""

    @property
    def type_label(self) -> str:
        return {
            CHANGE_NEW_DEVICE: tr("新增设备"),
            CHANGE_DEVICE_GONE: tr("设备消失"),
            CHANGE_MAC_CHANGED: tr("MAC 变更"),
            CHANGE_IP_CHANGED: tr("IP 变更"),
            CHANGE_HOSTNAME_CHANGED: tr("主机名变更"),
        }.get(self.change_type, self.change_type)

    @property
    def severity_label(self) -> str:
        return {
            SEVERITY_HIGH: tr("严重"),
            SEVERITY_WARNING: tr("警告"),
            SEVERITY_INFO: tr("提示"),
        }.get(self.severity, self.severity)


def detect_changes(current_results, previous_devices: List[dict]) -> List[Change]:
    """对比当前扫描结果与上次快照设备列表，返回变更事件列表。

    Args:
        current_results: 当前扫描的 ScanResult 列表（需有 ip, status, mac, hostname 属性）
        previous_devices: 上次快照的设备字典列表（来自 history_store，
                          每个字典含 ip, status, mac, hostname 等字段）

    Returns:
        按严重度降序排列的 Change 列表。
    """
    if not previous_devices:
        return []

    changes: List[Change] = []

    # ── 构建索引 ──
    # 当前在线设备（仅关注 online 状态）
    cur_online: Dict[str, object] = {}   # mac -> result
    cur_ip_mac: Dict[str, str] = {}      # ip -> mac
    cur_mac_ip: Dict[str, str] = {}      # mac -> ip
    for r in current_results:
        if r.status != "online":
            continue
        mac = (r.mac or "").upper().strip()
        if mac:
            cur_online[mac] = r
            cur_mac_ip[mac] = r.ip
        cur_ip_mac[r.ip] = mac

    # 上次在线设备
    prev_online: Dict[str, dict] = {}    # mac -> device dict
    prev_ip_mac: Dict[str, str] = {}     # ip -> mac
    prev_mac_ip: Dict[str, str] = {}     # mac -> ip
    for d in previous_devices:
        if d.get("status") != "online":
            continue
        mac = (d.get("mac") or "").upper().strip()
        ip = d.get("ip", "")
        if mac:
            prev_online[mac] = d
            prev_mac_ip[mac] = ip
        if ip:
            prev_ip_mac[ip] = mac

    # ── 1. MAC 变更：同一 IP 对应了不同 MAC（设备被替换）──
    checked_macs = set()
    for ip, cur_mac in cur_ip_mac.items():
        prev_mac = prev_ip_mac.get(ip, "")
        if prev_mac and cur_mac and prev_mac != cur_mac:
            prev_dev = prev_online.get(prev_mac, {})
            cur_res = cur_online.get(cur_mac)
            changes.append(Change(
                change_type=CHANGE_MAC_CHANGED,
                severity=SEVERITY_HIGH,
                description=f"{ip} 的设备被替换：{prev_mac} → {cur_mac}",
                ip=ip,
                mac=cur_mac,
                hostname=(cur_res.hostname if cur_res else "") or "",
                old_value=prev_mac,
                new_value=cur_mac,
            ))
            checked_macs.add(cur_mac)
            checked_macs.add(prev_mac)

    # ── 2. 新增设备：本次在线但上次不存在（按 MAC 判断）──
    for mac, r in cur_online.items():
        if mac in checked_macs:
            continue
        if mac not in prev_online:
            changes.append(Change(
                change_type=CHANGE_NEW_DEVICE,
                severity=SEVERITY_WARNING,
                description=f"新设备上线：{r.ip} ({mac})",
                ip=r.ip,
                mac=mac,
                hostname=r.hostname or "",
                new_value=r.ip,
            ))

    # ── 3. 设备消失：上次在线但本次不存在（按 MAC 判断）──
    for mac, d in prev_online.items():
        if mac in checked_macs:
            continue
        if mac not in cur_online:
            changes.append(Change(
                change_type=CHANGE_DEVICE_GONE,
                severity=SEVERITY_INFO,
                description=f"设备离线/消失：{d.get('ip', '?')} ({mac})",
                ip=d.get("ip", ""),
                mac=mac,
                hostname=d.get("hostname", ""),
                old_value=d.get("ip", ""),
            ))

    # ── 4. IP 变更：同一 MAC 出现在不同 IP ──
    for mac, cur_ip in cur_mac_ip.items():
        if mac in checked_macs:
            continue
        prev_ip = prev_mac_ip.get(mac, "")
        if prev_ip and cur_ip and prev_ip != cur_ip:
            r = cur_online.get(mac)
            changes.append(Change(
                change_type=CHANGE_IP_CHANGED,
                severity=SEVERITY_WARNING,
                description=f"设备 {mac} 的 IP 变更：{prev_ip} → {cur_ip}",
                ip=cur_ip,
                mac=mac,
                hostname=(r.hostname if r else "") or "",
                old_value=prev_ip,
                new_value=cur_ip,
            ))

    # ── 5. 主机名变更：同一 MAC 的主机名发生变化 ──
    for mac, r in cur_online.items():
        if mac in checked_macs:
            continue
        prev_dev = prev_online.get(mac)
        if not prev_dev:
            continue
        prev_hostname = (prev_dev.get("hostname") or "").strip()
        cur_hostname = (r.hostname or "").strip()
        # 仅当两者都非空且不同时才报告（避免扫描偶发解析失败导致误报）
        if prev_hostname and cur_hostname and prev_hostname != cur_hostname:
            changes.append(Change(
                change_type=CHANGE_HOSTNAME_CHANGED,
                severity=SEVERITY_INFO,
                description=f"设备 {mac} 主机名变更：{prev_hostname} → {cur_hostname}",
                ip=r.ip,
                mac=mac,
                hostname=cur_hostname,
                old_value=prev_hostname,
                new_value=cur_hostname,
            ))

    # 按严重度排序：high > warning > info
    _order = {SEVERITY_HIGH: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}
    changes.sort(key=lambda c: _order.get(c.severity, 9))
    return changes


def get_change_summary(changes: List[Change]) -> str:
    """生成变更摘要文本（用于状态栏/审计日志）。"""
    if not changes:
        return tr("无变更")
    high = sum(1 for c in changes if c.severity == SEVERITY_HIGH)
    warn = sum(1 for c in changes if c.severity == SEVERITY_WARNING)
    info = sum(1 for c in changes if c.severity == SEVERITY_INFO)
    parts = []
    if high:
        parts.append(f"{high} 严重")
    if warn:
        parts.append(f"{warn} 警告")
    if info:
        parts.append(f"{info} 提示")
    return " · ".join(parts)
