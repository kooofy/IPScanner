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

from .models import ScanResult


"""
网络扫描引擎 — ICMP Ping + ARP + 主机名 + 端口探测
支持 CIDR (192.168.1.0/24)、范围 (192.168.1.1-254)、单 IP
"""


_IS_WINDOWS = platform.system() == "Windows"


_CMD_ENCODING = None


if _IS_WINDOWS:
    try:
        cp = ctypes.windll.kernel32.GetConsoleOutputCP()
        _CMD_ENCODING = "utf-8" if cp == 65001 else (f"cp{cp}" if cp else "gbk")
    except Exception:
        # 回退到 locale，并把"纯 utf-8"当作 GBK（兼容 Python 3.13 UTF-8 模式）
        try:
            enc = locale.getpreferredencoding(False)
            _CMD_ENCODING = enc if enc and enc.lower() not in ("utf-8", "utf8") else "gbk"
        except Exception:
            _CMD_ENCODING = "gbk"


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]


# ── 扫描级别：端口范围（对齐 nmap 的 -F / 默认 / -p- 精神） ──
#   quick   : 当前高频服务端口（最常用 21 个），日常巡检
#   standard: 1-1023 知名端口（≈ nmap top 1000 精神）
#   all     : 1-65535 全端口（安全评估，最慢）
SCAN_LEVELS = ("quick", "standard", "all")
SCAN_LEVEL_LABELS = {
    "quick": "快速 (21)",
    "standard": "标准 (1023)",
    "all": "全端口 (65535)",
}


def get_ports_for_level(level: str):
    """按扫描级别返回端口列表（按需生成，不常驻大列表）。

    quick（默认）/ 未识别级别 -> COMMON_PORTS（向后兼容当前行为）。
    standard -> 1-1023 知名端口；all -> 1-65535 全端口。
    """
    if level == "standard":
        return list(range(1, 1024))
    if level == "all":
        return list(range(1, 65536))
    # quick 与未识别：当前高频服务端口
    return COMMON_PORTS


# ── 开放端口列显示：Top N 合并，避免漏扫目标开几百端口撑爆表格 ──
PORT_DISPLAY_TOP_N = 20


def format_ports_display(ports, top_n: int = PORT_DISPLAY_TOP_N):
    """把开放端口列表格式化为 (显示文本, 完整文本)。

    端口数 <= top_n：显示文本 == 完整文本（逗号拼接）。
    超出：显示文本截断为前 top_n 个并追加 ", +N more"，完整文本仍为全部端口。
    空列表：返回 ("—", "—")。
    """
    if not ports:
        return "—", "—"
    sorted_ports = sorted(ports)
    full = ", ".join(str(p) for p in sorted_ports)
    if len(sorted_ports) <= top_n:
        return full, full
    shown = ", ".join(str(p) for p in sorted_ports[:top_n])
    return f"{shown}, +{len(sorted_ports) - top_n} more", full


UDP_PORTS = [53, 67, 69, 123, 137, 138, 161, 500, 514, 1900, 5353]


PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 500: "IKE",
    514: "Syslog", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5353: "mDNS", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


PROTOCOL_PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "FTP": 21,
    "RDP": 3389,
}


_LOCAL_MAC_CACHE = None


_resolve_executor = None


_resolve_executor_lock = threading.Lock()


_SNMP_GET_OIDS = [
    "1.3.6.1.2.1.1.1.0",   # sysDescr
    "1.3.6.1.2.1.1.5.0",   # sysName
    "1.3.6.1.2.1.1.2.0",   # sysObjectID
]


_SNMP_DEFAULT_COMMUNITIES = ("public", "")


_SYSTEM_SHARES = {"ADMIN$", "IPC$", "PRINT$"}


_PRINTER_BRANDS = [
    ("hp", "HP"), ("hewlett", "HP"), ("canon", "Canon"), ("epson", "Epson"),
    ("brother", "Brother"), ("xerox", "Xerox"), ("ricoh", "Ricoh"),
    ("konica", "Konica Minolta"), ("minolta", "Konica Minolta"),
    ("kyocera", "Kyocera"), ("lexmark", "Lexmark"), ("dell", "Dell"),
    ("samsung", "Samsung"), ("sharp", "Sharp"), ("toshiba", "Toshiba"),
    ("fuji", "Fuji Xerox"), ("xerox", "Fuji Xerox"), ("panasonic", "Panasonic"),
    ("oki", "OKI"), ("lenovo", "Lenovo"), ("pantum", "Pantum"),
    ("震旦", "Aurora"), ("奔图", "Pantum"), ("联想", "Lenovo"),
]


_PRINTER_MODEL_RE = re.compile(
    r"(?:hp\s+)?(laserjet\s+[^<\"]{2,40})|"
    r"(?:canon\s+)?(pixma\s+[^<\"]{2,40})|"
    r"(?:epson\s+)?(ecotank\s+[^<\"]{2,40}|workforce\s+[^<\"]{2,40})|"
    r"(?:brother\s+)?(hl-[^<\"]{2,40}|dcp-[^<\"]{2,40}|mfc-[^<\"]{2,40})|"
    r"(?:xerox\s+)?(phaser\s+[^<\"]{2,40}|versalink\s+[^<\"]{2,40})|"
    r"(?:ricoh\s+)?(mp\s+[^<\"]{2,40}|sp\s+[^<\"]{2,40})",
    re.IGNORECASE,
)


_raw_cap_cache = None


_syn_failed = False


_MDNS_GROUP = "224.0.0.251"


_MDNS_PORT = 5353


_OUI_CLASS_HINTS = [
    ("hikvision", "摄像头"),
    ("dahua", "摄像头"),
    ("axis", "摄像头"),
    ("tiandy", "摄像头"),
    ("uniview", "摄像头"),
    ("foscam", "摄像头"),
    ("reolink", "摄像头"),
    ("ezviz", "摄像头"),
    ("hi351", "摄像头"),               # 海思芯片，多见于摄像头
    ("synology", "NAS"),
    ("qnap", "NAS"),
    ("terramaster", "NAS"),
    ("western digital", "NAS/存储"),
    ("seagate", "NAS/存储"),
    ("cisco", "网络设备"),
    ("aruba", "AP/交换机"),
    ("juniper", "网络设备"),
    ("fortinet", "防火墙"),
    ("mikrotik", "路由器/防火墙"),
    ("ubiquiti", "AP/路由器"),
    ("ruijie", "路由器/交换机"),
    ("h3c", "路由器/交换机"),
    ("tp-link", "路由器"),
    ("tplink", "路由器"),
    ("netgear", "路由器"),
    ("d-link", "路由器"),
    ("dlink", "路由器"),
    ("asus", "路由器"),
    ("mercury", "路由器"),
    ("tenda", "路由器"),
    ("huawei", "路由器/手机"),
    ("xiaomi", "IoT/路由器"),
    ("apple", "手机/电脑/IoT"),
    ("samsung", "电视/手机/打印机"),
    ("lg", "电视"),
    ("sony", "电视/游戏机"),
    ("philips", "灯具/IoT"),
    ("sengled", "灯具/IoT"),
    ("yeelight", "灯具/IoT"),
    ("tuya", "IoT"),
    ("espressif", "IoT开发板"),
    ("raspberry", "开发板/IoT"),
    ("sonos", "音箱"),
    ("bose", "音箱"),
    ("google", "手机/音箱/Nest"),
    ("nest", "IoT/摄像头"),
    ("amazon", "音箱/路由器"),
    ("nintendo", "游戏机"),
    ("microsoft", "电脑/游戏机"),
    ("nvidia", "电脑/游戏机"),
    ("hp ", "打印机/电脑"),
    ("hewlett", "打印机/电脑"),
    ("canon", "打印机"),
    ("brother", "打印机"),
    ("epson", "打印机"),
    ("xerox", "打印机"),
    ("lexmark", "打印机"),
    ("intel", "电脑/网卡"),
    ("dell", "电脑"),
    ("lenovo", "电脑"),
    ("hon hai", "电脑/手机"),
    ("azurewave", "电脑/网卡"),
]

# 手机厂商 OUI 关键词：仅凭 MAC(OUI) 只能拿到厂商，无法区分手机/电脑/IoT，
# 故仅作为「多信号融合识别手机」的候选集，需结合端口/OS/主机名剔除非手机信号。
_PHONE_OUI_KEYWORDS = (
    "apple", "samsung", "xiaomi", "huawei", "oppo", "vivo", "google",
    "oneplus", "realme", "meizu", "honor", "motorola", "nokia", "lg",
    "sony", "tcl", "lenovo",
)

# 手机厂商 OUI 关键词 -> 友好中文/品牌名（用于「设备类型」列型号展示）
_PHONE_BRAND_DISPLAY = {
    "apple": "Apple", "samsung": "三星", "xiaomi": "小米", "huawei": "华为",
    "oppo": "OPPO", "vivo": "vivo", "google": "Google", "oneplus": "一加",
    "realme": "realme", "meizu": "魅族", "honor": "荣耀", "motorola": "Motorola",
    "nokia": "Nokia", "lg": "LG", "sony": "Sony", "tcl": "TCL", "lenovo": "Lenovo",
}

