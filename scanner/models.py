# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from typing import List, Dict
from i18n import tr
try:
    from oui_database import get_mac_vendor
except ImportError:
    def get_mac_vendor(mac: str) -> str:
        return ""
from .constants import device_class_label


@dataclass
class ScanResult:
    """单个 IP 的扫描结果"""
    ip: str = ""
    status: str = "offline"          # online / offline / scanning
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    response_time: float = 0.0       # ms
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    # Excel 匹配字段
    device_type: str = ""
    location: str = ""
    user: str = ""
    remark: str = ""
    excel_matched: bool = False
    # SNMP 设备识别 (sysDescr / sysName，用于识别交换机/AP/打印机等网络设备)
    snmp_sys_name: str = ""
    snmp_sys_descr: str = ""
    # 服务详细信息：每个元素为 {"proto": str, "port": int, "banner": str}
    # 用于 UI 子项跨列显示（HTTP/HTTPS banner 等）
    service_details: List[Dict] = field(default_factory=list)
    # 共享文件夹探测结果（SMB 共享名列表）
    shares: List[str] = field(default_factory=list)
    # 发现方式："ping" / "arp" / "mdns" / ""（离线），用于 UI 标记与导出
    discovery_method: str = ""
    # 扫描末尾的 mDNS 阶段是否**就地修改过**本结果（追加 mDNS 服务/主机名、或置为在线）。
    #
    # 结果对象在 enrich 完成时就已通过 result_callback 交给 UI 渲染过一轮；
    # mDNS（Phase 3）是**唯一**会在回调之后继续改动已渲染对象的地方
    # （Phase 2 的 ARP 只处理 status != online 的主机，那些从未被回调过）。
    # UI 靠这个标记决定"扫描结束后要不要重渲染这一行"，避免对全部结果做 O(n) 重渲染。
    mdns_updated: bool = False
    # 端口探测方式："connect" / "syn" / "udp"，用于 UI 标记与导出
    scan_method: str = "connect"
    # 操作系统探测：TTL 推测族 + banner 提取的版本信息
    ttl: int = 0                      # ICMP 回显 TTL（来自 ping）
    os_guess: str = ""                # 基于 TTL 推测：Windows / Linux/Unix / 网络设备
    os_detail: str = ""              # banner 提取的版本：如 OpenSSH_8.9p1、nginx/1.22
    # 设备指纹深度：纯被动综合推断的设备类别与型号（无需凭据）
    device_class: str = ""            # 设备类别：路由器/交换机/摄像头/打印机/NAS/电脑/...
    device_model: str = ""            # 设备型号：如 "群晖 DS920+", "海康威视摄像头", "HP LaserJet M104w"
    upnp_model: str = ""              # UPnP 设备描述提取的型号名（供指纹推断复用）
    http_brand: str = ""              # HTTP/HTTPS 页面识别出的品牌（如 HP、Canon、Epson）
    http_model: str = ""              # HTTP/HTTPS 页面识别出的型号（如 LaserJet M104w）
    # WMI/WinRM 远程识别（需 Windows 目标 + 管理员凭据；权威硬件/系统信息）
    wmi_identified: bool = False    # 是否成功取得 WMI 信息
    wmi_manufacturer: str = ""      # Win32_ComputerSystem.Manufacturer（如 Dell Inc.）
    wmi_model: str = ""             # Win32_ComputerSystem.Model（如 OptiPlex 7080）
    wmi_serial: str = ""            # Win32_BIOS.SerialNumber
    wmi_bios: str = ""              # Win32_BIOS.SMBIOSBIOSVersion
    wmi_os: str = ""                # Win32_OperatingSystem.Caption
    wmi_os_version: str = ""        # Win32_OperatingSystem.Version
    wmi_os_arch: str = ""           # Win32_OperatingSystem.OSArchitecture
    wmi_domain: str = ""            # 加入的域（WORKGROUP 表示工作组）
    wmi_user: str = ""              # 当前登录用户（域\\用户）
    wmi_cpu: str = ""               # Win32_Processor.Name
    wmi_ram_gb: float = 0.0         # 物理内存（GB）
    wmi_last_boot: str = ""         # 最近启动时间（可读字符串）
    wmi_transport: str = ""         # 实际生效的传输通路：""/"dcom"/"winrm"（语言无关）
    wmi_error: str = ""
    # NetBIOS 轻量识别（UDP/137 NBSTAT，零凭据，不需管理员；作为 WMI 轻量补充）
    netbios_identified: bool = False    # 是否成功取得 NetBIOS 信息
    netbios_name: str = ""              # 计算机名（NetBIOS 唯一 <00> 名）
    netbios_workgroup: str = ""         # 工作组 / 域（NetBIOS <00> 组名）
    netbios_user: str = ""              # 当前登录用户（NetBIOS <03> 名）
    netbios_mac: str = ""               # MAC 地址（NBSTAT 统计块，ARP 缺失时也能补到）
    netbios_error: str = ""             # 失败原因（成功时为空）             # 失败原因（成功时为空）
    # ── 零利用安全体检：TLS 证书事实（v1.9 #3 第一刀）────────────────────
    #
    # `scanner.x509.parse_certificate()` 的结果，键见该函数文档。**只存事实、
    # 不存结论** —— "过期 / 即将过期 / 自签名 / 弱算法"这些判定统一在
    # `risk_rules.score_risk()` 里做，这样阈值只有一处、也能纯函数式地单测。
    #
    # 空 dict = 没探到证书（端口没开 / 不是 TLS / 握手失败），与"探到了但字段为空"
    # 是两回事。多端口 HTTPS 时只保留**第一个**探到的证书：风险评分是"一台设备
    # 一条结论"，而每个端口一条会让同一台设备刷出多条同义理由。
    tls_cert: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        if self.discovery_method:
            discovered = {"arp": tr("ARP探测"), "mdns": tr("mDNS发现")}.get(
                self.discovery_method, tr("Ping")
            )
        elif self.status == "online":
            discovered = tr("Ping")
        else:
            discovered = ""
        _method_map = {"connect": tr("TCP全连接"), "syn": tr("TCP-SYN半开"), "udp": tr("UDP")}
        _os_label = ""
        if self.os_guess or self.os_detail:
            _os_label = (f"{self.os_guess} {self.os_detail}".strip())
        return {
            tr("IP地址"): self.ip,
            tr("状态"): tr("在线") if self.status == "online" else tr("离线"),
            tr("主机名"): self.hostname,
            tr("MAC地址"): self.mac,
            tr("厂商"): self.vendor,
            tr("设备类型"): device_class_label(self.device_class) or self.device_type,
            tr("设备型号"): self.device_model,
            tr("位置"): self.location,
            tr("使用者"): self.user,
            tr("响应时间(ms)"): round(self.response_time, 1) if self.response_time else "",
            tr("开放端口"): ", ".join(str(p) for p in self.open_ports) if self.open_ports else "",
            tr("共享文件夹"): ", ".join(self.shares) if self.shares else "",
            tr("发现方式"): discovered,
            tr("端口探测方式"): _method_map.get(self.scan_method, self.scan_method),
            tr("操作系统"): _os_label,
            tr("WMI厂商"): self.wmi_manufacturer,
            tr("WMI型号"): self.wmi_model,
            tr("WMI序列号"): self.wmi_serial,
            tr("WMI系统"): (f"{self.wmi_os} {self.wmi_os_version}".strip()
                        if (self.wmi_os or self.wmi_os_version) else ""),
            tr("WMI域/用户"): (f"{self.wmi_domain} / {self.wmi_user}".strip(" /")
                           if (self.wmi_domain or self.wmi_user) else ""),
            tr("NetBIOS名称"): self.netbios_name,
            tr("NetBIOS工作组"): self.netbios_workgroup,
            tr("NetBIOS用户"): self.netbios_user,
            tr("NetBIOS MAC"): self.netbios_mac,
            tr("备注"): self.remark,
        }
