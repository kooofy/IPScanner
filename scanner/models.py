# -*- coding: utf-8 -*-
import subprocess
import socket
import ssl
import struct
import threading
import concurrent.futures
import ipaddress
import re
import time
import platform
import os
import locale
import random
import ctypes
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
try:
    from oui_database import get_mac_vendor
except ImportError:
    def get_mac_vendor(mac: str) -> str:
        return ""


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

    def to_dict(self) -> dict:
        if self.discovery_method:
            discovered = {"arp": "ARP探测", "mdns": "mDNS发现"}.get(
                self.discovery_method, "Ping"
            )
        elif self.status == "online":
            discovered = "Ping"
        else:
            discovered = ""
        _method_map = {"connect": "TCP全连接", "syn": "TCP-SYN半开", "udp": "UDP"}
        _os_label = ""
        if self.os_guess or self.os_detail:
            _os_label = (f"{self.os_guess} {self.os_detail}".strip())
        return {
            "IP地址": self.ip,
            "状态": "在线" if self.status == "online" else "离线",
            "主机名": self.hostname,
            "MAC地址": self.mac,
            "厂商": self.vendor,
            "设备类型": self.device_class or self.device_type,
            "设备型号": self.device_model,
            "位置": self.location,
            "使用者": self.user,
            "响应时间(ms)": round(self.response_time, 1) if self.response_time else "",
            "开放端口": ", ".join(str(p) for p in self.open_ports) if self.open_ports else "",
            "共享文件夹": ", ".join(self.shares) if self.shares else "",
            "发现方式": discovered,
            "端口探测方式": _method_map.get(self.scan_method, self.scan_method),
            "操作系统": _os_label,
            "备注": self.remark,
        }
