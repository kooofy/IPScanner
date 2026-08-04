# -*- coding: utf-8 -*-
"""从 MainWindow 提取的纯业务逻辑（无 PyQt5 / i18n 依赖，便于单元测试）。

这些函数原本内联在 main_window.py 的业务编排方法里，与 UI 控件耦合，
无法在无 PyQt5 环境下测试。提取到本模块后可独立覆盖业务规则：
- 子网/虚拟网卡判定
- WMI/NetBIOS 识别目标筛选
- 扫描结果状态统计
- 识别完成消息构造
- 冲突分级计数
- 历史快照构建
"""
import time

from conflict_detector import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_WARNING


def ip_mask_to_subnet(ip: str, mask: str):
    """由 IPv4 与子网掩码计算网段地址与前缀长度，失败返回 (None, 0)。"""
    try:
        ip_parts = list(map(int, ip.split(".")))
        mask_parts = list(map(int, mask.split(".")))
        net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
        prefix = sum(bin(m).count("1") for m in mask_parts)
        return ".".join(net_parts), prefix
    except Exception:
        return None, 0


def is_virtual_adapter_ip(ip: str) -> bool:
    """粗略判断是否为虚拟/容器网卡使用的私有网段（VirtualBox/Docker/链路本地等）。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 169 and b == 254:                          # 169.254.0.0/16 链路本地(APIPA)
        return True
    if a == 172 and 16 <= b <= 31:                     # 172.16.0.0/12 Docker 默认桥
        return True
    if a == 192 and b == 168 and int(parts[2]) == 56:  # 192.168.56.0/24 VirtualBox Host-Only
        return True
    return False


def select_identification_targets(results, explicit_targets=None, windows_label="Windows"):
    """从扫描结果筛选需要 WMI/NetBIOS 识别的目标 IP 列表。

    - explicit_targets=None：自动筛选在线且疑似 Windows 的设备
      （os_guess == windows_label 或开放 135/445 端口）
    - explicit_targets=[ip,...]：只保留其中在线的 IP

    返回目标 IP 列表（可能为空）。调用方据原 explicit_targets 是否为 None 决定空时的提示文案。
    """
    online_ips = {r.ip for r in results if r.status == "online"}
    if explicit_targets is None:
        return [
            r.ip for r in results
            if r.status == "online" and (
                r.os_guess == windows_label
                or 135 in r.open_ports
                or 445 in r.open_ports
            )
        ]
    return [t for t in explicit_targets if t in online_ips]


def count_scan_status(results) -> dict:
    """统计扫描结果的在线/离线/未知数量。"""
    total = len(results)
    online = sum(1 for r in results if r.status == "online")
    offline = sum(1 for r in results if r.status == "offline")
    return {"total": total, "online": online, "offline": offline, "unknown": total - online - offline}


def format_identify_summary(kind: str, ok: int, fail: int, total: int, fail_reason: str = "") -> str:
    """构造 WMI/NetBIOS 识别完成消息。

    kind: "WMI" / "NetBIOS"；fail_reason: 有失败时括号内原因说明。
    """
    msg = f"{kind} 识别完成：{total} 台，成功 {ok} 台"
    if fail:
        msg += f"，失败 {fail} 台（{fail_reason}）"
    return msg


def count_conflicts(conflicts) -> dict:
    """按严重级别统计冲突数量。"""
    return {
        "high": sum(1 for c in conflicts if c.severity == SEVERITY_HIGH),
        "warning": sum(1 for c in conflicts if c.severity == SEVERITY_WARNING),
        "info": sum(1 for c in conflicts if c.severity == SEVERITY_INFO),
    }


def build_snapshot(results, ts=None) -> dict:
    """把 ScanResult 列表转成历史快照 dict（与 history_store 存储结构一致）。"""
    if ts is None:
        ts = time.time()
    devices = []
    for r in results:
        devices.append({
            "ip": r.ip,
            "status": r.status,
            "mac": (r.mac or "").upper(),
            "hostname": r.hostname or "",
            "vendor": r.vendor or "",
            "device_class": r.device_class or "",
            "os_guess": r.os_guess or "",
            "open_ports": ",".join(str(p) for p in (r.open_ports or [])),
            "location": r.location or "",
            "user": r.user or "",
            "remark": r.remark or "",
            "wmi_identified": r.wmi_identified,
            "wmi_manufacturer": r.wmi_manufacturer or "",
            "wmi_model": r.wmi_model or "",
            "wmi_serial": r.wmi_serial or "",
            "wmi_os": r.wmi_os or "",
            "wmi_user": r.wmi_user or "",
            "wmi_domain": r.wmi_domain or "",
            "netbios_identified": r.netbios_identified,
            "netbios_name": r.netbios_name or "",
            "netbios_workgroup": r.netbios_workgroup or "",
            "netbios_user": r.netbios_user or "",
            "netbios_mac": r.netbios_mac or "",
        })
    return {"time": ts, "devices": devices}