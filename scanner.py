# -*- coding: utf-8 -*-
"""
网络扫描引擎 — ICMP Ping + ARP + 主机名 + 端口探测
支持 CIDR (192.168.1.0/24)、范围 (192.168.1.1-254)、单 IP
"""

import subprocess
import socket
import ssl
import struct
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

# Windows 中文系统命令输出编码处理
# Python 3.13 默认 UTF-8 模式，但 Windows 命令行输出为 GBK
_IS_WINDOWS = platform.system() == "Windows"
_CMD_ENCODING = None
if _IS_WINDOWS:
    try:
        # 尝试获取系统编码
        _CMD_ENCODING = locale.getpreferredencoding(False)
        # 如果是 UTF-8，说明是 Python 3.13 的 UTF-8 模式，需要改用 GBK
        if _CMD_ENCODING and _CMD_ENCODING.lower() in ("utf-8", "utf8"):
            _CMD_ENCODING = "gbk"
    except Exception:
        _CMD_ENCODING = "gbk"


def _run_cmd(cmd: list, timeout: float = 10) -> str:
    """执行命令并返回输出文本，自动处理 Windows 编码"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        raw = result.stdout
        if _CMD_ENCODING:
            return raw.decode(_CMD_ENCODING, errors="replace")
        return raw.decode("utf-8", errors="replace")
    except Exception:
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


# 常见 TCP 端口
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

# 常见 UDP 端口（用于 UDP 探测模式）
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


def parse_ip_range(range_str: str) -> List[str]:
    """
    解析 IP 范围字符串，返回 IP 列表。
    支持:
      192.168.1.0/24          (CIDR)
      192.168.1.1-254         (范围)
      192.168.1.1-192.168.1.254 (完整范围)
      192.168.1.1             (单 IP)
    """
    range_str = range_str.strip()
    if not range_str:
        return []

    ips = []

    # CIDR
    if "/" in range_str:
        try:
            net = ipaddress.ip_network(range_str, strict=False)
            for ip in net.hosts():
                ips.append(str(ip))
            # /31 和 /32 特殊处理
            if net.prefixlen >= 31:
                ips = [str(ip) for ip in net]
            return ips
        except ValueError:
            return []

    # 范围: 192.168.1.1-254 或 192.168.1.1-192.168.1.254
    if "-" in range_str:
        parts = range_str.split("-")
        if len(parts) == 2:
            start_str = parts[0].strip()
            end_str = parts[1].strip()
            try:
                # 短格式: 192.168.1.1-254
                if "." not in end_str:
                    prefix = start_str.rsplit(".", 1)[0]
                    end_str = f"{prefix}.{end_str}"
                start = ipaddress.ip_address(start_str)
                end = ipaddress.ip_address(end_str)
                # 确保 start <= end
                if int(start) > int(end):
                    start, end = end, start
                for i in range(int(start), int(end) + 1):
                    ips.append(str(ipaddress.ip_address(i)))
                return ips
            except (ValueError, IndexError):
                return []

    # 单 IP
    try:
        ipaddress.ip_address(range_str)
        return [range_str]
    except ValueError:
        return []


def ping_ip(ip: str, timeout_ms: int = 1000) -> Tuple[bool, float, int]:
    """
    Ping 单个 IP，返回 (是否在线, 响应时间ms, TTL)。
    Windows 使用系统 ping 命令。
    TTL 用于 OS 推测（Windows≈128 / Linux·macOS·BSD≈64 / 部分网络设备≈255）。
    """
    is_windows = platform.system() == "Windows"
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    try:
        output = _run_cmd(cmd, timeout=timeout_ms / 1000 + 2)

        # Windows: "来自 192.168.1.1 的回复: 字节=32 时间=1ms TTL=64"
        # Linux:   "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.123 ms"
        ttl = 0
        ttl_match = re.search(r"TTL[=:](\d+)", output, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
        if "TTL=" in output or "ttl=" in output:
            # 提取响应时间
            time_match = re.search(r"时间[=:](\d+)\s*ms", output)
            if not time_match:
                time_match = re.search(r"time[=:](\d+\.?\d*)\s*ms", output)
            if not time_match:
                time_match = re.search(r"<\s*(\d+)\s*ms", output)
            rtt = float(time_match.group(1)) if time_match else 0.0
            return True, rtt, ttl
        return False, 0.0, ttl
    except Exception:
        return False, 0.0, 0


def get_local_mac_map() -> Dict[str, str]:
    """
    获取本机所有网卡的 {ip: mac} 映射
    Windows 下使用 ipconfig /all，Linux 下使用 ifconfig/ip addr
    """
    mac_map = {}
    is_windows = platform.system() == "Windows"
    
    try:
        if is_windows:
            output = _run_cmd(["ipconfig", "/all"], timeout=10)
            # 解析 ipconfig /all 输出
            current_mac = None
            for line in output.splitlines():
                line = line.strip()
                # 匹配物理地址行
                mac_match = re.search(r"物理地址[ .]+: ([0-9a-fA-F\-]{17})", line)
                if not mac_match:
                    mac_match = re.search(r"Physical Address[ .]+: ([0-9a-fA-F\-]{17})", line)
                if mac_match:
                    current_mac = mac_match.group(1).replace("-", ":").lower()
                    continue
                # 匹配 IPv4 地址行
                ip_match = re.search(r"IPv4 地址[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
                if not ip_match:
                    ip_match = re.search(r"IPv4 Address[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match and current_mac:
                    ip = ip_match.group(1)
                    mac_map[ip] = current_mac
        else:
            # Linux: 使用 ip addr
            try:
                output = _run_cmd(["ip", "addr"], timeout=10)
                current_mac = None
                for line in output.splitlines():
                    line = line.strip()
                    if "link/ether" in line:
                        mac_match = re.search(r"link/ether ([0-9a-fA-F:]{17})", line)
                        if mac_match:
                            current_mac = mac_match.group(1).lower()
                    elif "inet " in line and current_mac:
                        ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not ip.startswith("127."):
                                mac_map[ip] = current_mac
            except Exception:
                pass
    except Exception:
        pass
    
    return mac_map


_LOCAL_MAC_CACHE = None

def get_local_mac_for_ip(ip: str) -> str:
    """获取本机指定IP对应的MAC地址"""
    global _LOCAL_MAC_CACHE
    if _LOCAL_MAC_CACHE is None:
        _LOCAL_MAC_CACHE = get_local_mac_map()
    return _LOCAL_MAC_CACHE.get(ip, "")


def arp_ping(ip: str) -> str:
    """
    通过 Windows SendARP 主动探测指定 IP 的 MAC 地址（ARP 主动探测）。

    与系统 ping 不同，SendARP 不依赖目标主机回应 ICMP，因此能发现
    “禁 Ping 但在线”的主机，补齐同网段静默主机的发现能力。
    无需管理员权限（走 iphlpapi 的 SendARP，非原始套接字）。
    命中返回 '' 分隔的小写 MAC，未命中/不支持返回空串。
    """
    if platform.system() != "Windows":
        return ""
    try:
        ws2 = ctypes.windll.ws2_32
        iphlp = ctypes.windll.iphlpapi
        # 设置 argtypes/restype 避免 ctypes 默认按 int 解析导致高位截断
        ws2.inet_addr.argtypes = [ctypes.c_char_p]
        ws2.inet_addr.restype = ctypes.c_uint32
        iphlp.SendARP.argtypes = [
            ctypes.c_uint32,                       # DestIP (网络字节序)
            ctypes.c_uint32,                       # SrcIP
            ctypes.POINTER(ctypes.c_ubyte * 6),    # pMacAddr
            ctypes.POINTER(ctypes.c_ulong),        # PhyAddrLen
        ]
        iphlp.SendARP.restype = ctypes.c_uint32    # DWORD 返回码

        dest = ws2.inet_addr(ip.encode("ascii"))
        src = ws2.inet_addr(b"0.0.0.0")
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        ret = iphlp.SendARP(dest, src, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if ret == 0 and mac_len.value >= 6:
            return ":".join(f"{b:02x}" for b in mac_buf[:6])
    except Exception:
        pass
    return ""


def get_local_subnets() -> List:
    """
    返回本机所有直连网段 (ipaddress.IPv4Network 列表)。
    仅 Windows 通过 ipconfig 解析 IPv4 + 子网掩码；非 Windows 返回空列表。
    用于约束 ARP 主动探测范围（只对同网段离线 IP 探测，避免路由范围浪费时间）。
    """
    nets = []
    if platform.system() != "Windows":
        return nets
    try:
        output = _run_cmd(["ipconfig"], timeout=10)
        cur_ip = None
        for line in output.splitlines():
            line = line.strip()
            m = re.search(r"IPv4 地址[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                m = re.search(r"IPv4 Address[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                cur_ip = m.group(1)
                continue
            sm = re.search(r"子网掩码[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
            if not sm:
                sm = re.search(r"Subnet Mask[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
            if sm and cur_ip:
                try:
                    net = ipaddress.ip_network(f"{cur_ip}/{sm.group(1)}", strict=False)
                    if net not in nets:
                        nets.append(net)
                except Exception:
                    pass
                cur_ip = None
    except Exception:
        pass
    return nets


def get_mac_for_ip(ip: str, arp_cache: Optional[Dict[str, str]] = None) -> str:
    """获取指定 IP 的 MAC 地址"""
    # 先检查是否是本机IP
    local_mac = get_local_mac_for_ip(ip)
    if local_mac:
        return local_mac
    
    if arp_cache and ip in arp_cache:
        return arp_cache[ip]

    # 单独查询
    try:
        output = _run_cmd(["arp", "-a", ip], timeout=5)
        for line in output.splitlines():
            match = re.search(r"([0-9a-fA-F\-:]{17})", line)
            if match and ip in line:
                return match.group(1).replace("-", ":").lower()
    except Exception:
        pass
    return ""


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """反向 DNS 解析主机名"""
    try:
        # 使用线程池设置超时
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(socket.gethostbyaddr, ip)
            try:
                hostname, _, _ = future.result(timeout=timeout)
                return hostname
            except concurrent.futures.TimeoutExpired:
                return ""
    except (socket.herror, socket.gaierror, Exception):
        return ""


def get_netbios_name(ip: str, timeout: float = 2.0) -> str:
    """通过 nbtstat 获取 NetBIOS 名称 (Windows)"""
    if platform.system() != "Windows":
        return ""
    try:
        output = _run_cmd(["nbtstat", "-A", ip], timeout=timeout)
        for line in output.splitlines():
            stripped = line.strip()
            if "<00>" not in stripped:
                continue
            if re.search(r"GROUP|组", stripped, re.IGNORECASE):
                continue
            m = re.match(r"^(\S+)\s+<00>", stripped)
            if m:
                name = m.group(1)
                if not name.startswith("IS~"):
                    return name
    except Exception:
        pass
    return ""


# ── SNMPv2c 设备识别 (零依赖，手写 ASN.1 BER 编解码) ──────────────
# 仅做最小 GET，用于识别交换机 / AP / 打印机等网络设备：
#   sysDescr(1.1) / sysName(1.5) / sysObjectID(1.2)
# 不引入 pysnmp 等第三方库，保持脚本零依赖部署。
_SNMP_GET_OIDS = [
    "1.3.6.1.2.1.1.1.0",   # sysDescr
    "1.3.6.1.2.1.1.5.0",   # sysName
    "1.3.6.1.2.1.1.2.0",   # sysObjectID
]
_SNMP_DEFAULT_COMMUNITIES = ("public", "")


def _ber_len(length: int) -> bytes:
    """BER 长度字段编码 (短形式 < 128，否则长形式)。"""
    if length < 0x80:
        return bytes([length])
    out = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    return bytes([0x80 | len(out)]) + out


def _snmp_enc_int(n: int) -> bytes:
    """BER INTEGER (有符号，最小字节)。"""
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big", signed=True)
        if n > 0 and (body[0] & 0x80):
            body = b"\x00" + body
        elif n < 0 and not (body[0] & 0x80):
            body = b"\xff" + body
    return b"\x02" + _ber_len(len(body)) + body


def _snmp_enc_str(s: str) -> bytes:
    """BER OCTET STRING。"""
    body = s.encode("utf-8", "replace")
    return b"\x04" + _ber_len(len(body)) + body


def _snmp_enc_oid(oid: str) -> bytes:
    """BER OBJECT IDENTIFIER。"""
    parts = [int(x) for x in oid.split(".") if x != ""]
    if len(parts) < 2:
        raise ValueError("invalid OID: " + oid)
    first, second = parts[0], parts[1]
    body = bytes([first * 40 + second])
    for p in parts[2:]:
        if p == 0:
            body += b"\x00"
            continue
        enc = bytearray()
        while p > 0:
            enc.insert(0, (p & 0x7F) | (0x80 if len(enc) > 0 else 0))
            p >>= 7
        body += bytes(enc)
    return b"\x06" + _ber_len(len(body)) + body


def _snmp_build_get(community: str, req_id: int, oids) -> bytes:
    """构造 SNMPv2c GetRequest 报文。"""
    varbinds = b""
    for oid in oids:
        vb = _snmp_enc_oid(oid) + b"\x05\x00"   # value = NULL
        varbinds += b"\x30" + _ber_len(len(vb)) + vb
    vblist = b"\x30" + _ber_len(len(varbinds)) + varbinds
    pdu = _snmp_enc_int(req_id) + _snmp_enc_int(0) + _snmp_enc_int(0) + vblist
    pdu_typed = b"\xa0" + _ber_len(len(pdu)) + pdu        # [0] GetRequest-PDU
    msg = _snmp_enc_int(1) + _snmp_enc_str(community) + pdu_typed  # version=1 (v2c)
    return b"\x30" + _ber_len(len(msg)) + msg             # SEQUENCE


def _snmp_read_tlv(data: bytes, pos: int):
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        num = length & 0x7F
        length = int.from_bytes(data[pos:pos + num], "big")
        pos += num
    return tag, length, pos


def _snmp_decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0] // 40
    second = data[0] % 40
    parts = [first, second]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _snmp_parse_response(data: bytes):
    """解析 SNMP GetResponse，返回 [(oid, value_bytes, value_tag), ...] 或 None。"""
    try:
        pos = 0
        tag, length, pos = _snmp_read_tlv(data, pos)
        if tag != 0x30:
            return None
        # version (INTEGER) — 跳过 value
        tag, length, pos = _snmp_read_tlv(data, pos)
        pos += length
        # community (OCTET STRING) — 跳过 value
        tag, length, pos = _snmp_read_tlv(data, pos)
        pos += length
        # PDU (GetResponse [2])
        pdu_tag, pdu_len, pos = _snmp_read_tlv(data, pos)
        if pdu_tag != 0xA2:
            return None
        # request-id — 跳过 value
        tag, length, pos = _snmp_read_tlv(data, pos)
        pos += length
        # error-status
        tag, length, pos = _snmp_read_tlv(data, pos)
        err_status = int.from_bytes(data[pos:pos + length], "big")
        if err_status != 0:
            return None
        pos += length
        # error-index — 跳过 value
        tag, length, pos = _snmp_read_tlv(data, pos)
        pos += length
        # varbind list (SEQUENCE OF)
        tag, length, pos = _snmp_read_tlv(data, pos)
        vbl_end = pos + length
        results = []
        while pos < vbl_end:
            tag, length, pos = _snmp_read_tlv(data, pos)   # varbind SEQUENCE
            vb_end = pos + length
            otag, olength, pos = _snmp_read_tlv(data, pos)  # oid
            oid = _snmp_decode_oid(data[pos:pos + olength])
            pos += olength
            vtag, vlength, pos = _snmp_read_tlv(data, pos)  # value
            vbytes = data[pos:pos + vlength]
            pos += vlength
            results.append((oid, vbytes, vtag))
            pos = vb_end
        return results
    except Exception:
        return None


def snmp_get_system(ip: str, communities=_SNMP_DEFAULT_COMMUNITIES,
                    timeout: float = 0.8, port: int = 161) -> dict:
    """
    对单个 IP 做 SNMPv2c GET，返回 {'sys_descr','sys_name','sys_objectid'} 或 None。
    零依赖（手写 BER 编解码）。仅对在线设备调用。
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for community in communities:
            try:
                req_id = random.randint(1, 0x7FFFFFFF)
                packet = _snmp_build_get(community, req_id, _SNMP_GET_OIDS)
                sock.sendto(packet, (ip, port))
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                resp = _snmp_parse_response(data)
                if not resp:
                    continue
                info = {}
                for oid, vbytes, vtag in resp:
                    if vtag == 0x04:                       # OCTET STRING
                        txt = vbytes.decode("utf-8", "replace").strip()
                    elif vtag == 0x06:                     # OID
                        txt = _snmp_decode_oid(vbytes)
                    elif vtag == 0x02:                     # INTEGER
                        txt = str(int.from_bytes(vbytes, "big"))
                    else:
                        txt = ""
                    if oid == "1.3.6.1.2.1.1.1.0":
                        info["sys_descr"] = txt
                    elif oid == "1.3.6.1.2.1.1.5.0":
                        info["sys_name"] = txt
                    elif oid == "1.3.6.1.2.1.1.2.0":
                        info["sys_objectid"] = txt
                if info.get("sys_descr") or info.get("sys_name"):
                    return info
            except Exception:
                continue
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return None


def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """检测指定端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# 系统保留/管理用共享，通常非用户自建，枚举时过滤以减少噪声
_SYSTEM_SHARES = {"ADMIN$", "IPC$", "PRINT$"}


def scan_shares(ip: str, timeout: float = 1.5) -> List[str]:
    """
    通过 `net view \\<ip>` 枚举目标的 SMB 共享文件夹，返回共享名列表。
    仅 Windows 可用；非 Windows 或探测失败返回空列表。
    过滤 ADMIN$/IPC$/PRINT$ 及 X$ 盘符类系统隐藏共享，仅保留用户共享。
    """
    if platform.system() != "Windows":
        return []
    try:
        output = _run_cmd(["net", "view", f"\\\\{ip}"], timeout=timeout)
        shares = []
        for line in output.splitlines():
            s = line.strip()
            if not s:
                continue
            # 跳过表头 / 分隔线 / 成功提示 / 错误提示
            if ("----" in s
                    or s.startswith("共享名") or s.startswith("Share name")
                    or s.startswith("命令成功") or "successfully" in s.lower()
                    or "找不到" in s or "找不到" in s or "系统错误" in s
                    or "System error" in s or "The command" in s):
                continue
            # 共享行首列为共享名，次列为类型 (Disk/Print/IPC/磁盘/打印/设备)
            m = re.match(
                r"^(\S+)\s+(Disk|Print|IPC|Device|磁盘|打印|设备)", s, re.IGNORECASE
            )
            if not m:
                continue
            name = m.group(1).strip()
            if not name:
                continue
            up = name.upper()
            if up in _SYSTEM_SHARES:
                continue
            # X$ 盘符类系统隐藏共享（C$/D$/E$ ...）
            if len(name) == 2 and name[1] == "$" and name[0].isalpha():
                continue
            shares.append(name)
        return shares
    except Exception:
        return []


def _read_http_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """对 HTTP 端口发送请求，尝试提取 Server 头或 <title>；失败返回空串。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: IPScanner/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode("utf-8"))
            data = b""
            while len(data) < 8192:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                except socket.timeout:
                    break
            text = data.decode("utf-8", errors="replace")
            # 1. Server 头
            m = re.search(r"Server:\s*(.+?)[\r\n]", text, re.IGNORECASE)
            if m:
                return m.group(1).strip()
            # 2. HTML title
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
                title = re.sub(r"[\s\r\n]+", " ", title)
                return title
            return ""
    except Exception:
        return ""


# 常见设备品牌关键字（用于从 HTTP 页面/标题中识别设备类型）
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

# 从页面文本里提取打印机型号的一些常见模式
# [^<\"]{2,40} 允许型号含空格/连字符，但碰到 HTML 标签开头或引号即停止
_PRINTER_MODEL_RE = re.compile(
    r"(?:hp\s+)?(laserjet\s+[^<\"]{2,40})|"
    r"(?:canon\s+)?(pixma\s+[^<\"]{2,40})|"
    r"(?:epson\s+)?(ecotank\s+[^<\"]{2,40}|workforce\s+[^<\"]{2,40})|"
    r"(?:brother\s+)?(hl-[^<\"]{2,40}|dcp-[^<\"]{2,40}|mfc-[^<\"]{2,40})|"
    r"(?:xerox\s+)?(phaser\s+[^<\"]{2,40}|versalink\s+[^<\"]{2,40})|"
    r"(?:ricoh\s+)?(mp\s+[^<\"]{2,40}|sp\s+[^<\"]{2,40})",
    re.IGNORECASE,
)


def _extract_http_brand(text: str) -> Tuple[str, str]:
    """
    从 HTTP 页面文本（Server 头、标题、正文）中推断设备品牌和型号。
    返回 (brand, model)，命中打印机品牌时 brand 非空。
    """
    if not text:
        return "", ""
    low = text.lower()

    # 1) 品牌关键字匹配
    brand = ""
    for key, display in _PRINTER_BRANDS:
        if key in low:
            brand = display
            break

    # 2) 尝试抓型号
    model = ""
    m = _PRINTER_MODEL_RE.search(text)
    if m:
        model = next((g for g in m.groups() if g), "")
        model = re.sub(r"[\s\r\n]+", " ", model).strip()
        # 首字母大写美化
        model = " ".join(w.capitalize() for w in model.split())

    # 3) 若正文里有明显"打印机"中文信号，但没命中国际品牌，给一个通用品牌提示
    if not brand and ("打印机" in text or "printer" in low or "laser" in low or "inkjet" in low):
        brand = "打印机"

    return brand, model


def _read_http_brand(ip: str, port: int = 80, timeout: float = 1.0) -> Tuple[str, str]:
    """
    对 HTTP 端口发送 GET /，读取页面内容，尝试识别设备品牌与型号。
    返回 (brand, model)，无法识别返回 ("", "")。
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: IPScanner/1.0\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode("utf-8"))
            data = b""
            while len(data) < 32768:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"</html>" in data.lower():
                        break
                except socket.timeout:
                    break
            text = data.decode("utf-8", errors="replace")
            return _extract_http_brand(text)
    except Exception:
        return "", ""


def _read_https_banner(ip: str, port: int, timeout: float = 1.2) -> str:
    """对 HTTPS 端口做 SSL 握手，返回 OpenSSL 隧道风格字符串。

    成功时: "Tunnel is OpenSSL <TLS版本>: <证书CN>"
    失败时: "Tunnel is OpenSSL <TLS版本>: unknown service" 或 "unknown service"
    与 Advanced IP Scanner 的 HTTPS 子项展示风格保持一致。
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version() or "TLS"
                cert = ssock.getpeercert()
                cn = ""
                if cert:
                    subject = cert.get("subject")
                    if subject:
                        for entry in subject:
                            for key, value in entry:
                                if key == "commonName":
                                    cn = value
                                    break
                            if cn:
                                break
                result = cn if cn else "unknown service"
                return f"Tunnel is OpenSSL {version}: {result}"
    except Exception:
        # 握手失败（超时/协议不兼容等）：保留 OpenSSL 隧道风格，
        # 若无法确定版本则统一返回 unknown service，避免空串导致子项回退成 "HTTPS, port 443"。
        return "unknown service"


def _parse_upnp_name(xml_text: str) -> str:
    """从 UPnP 设备描述 XML 中提取最可读的设备型号名。

    优先 manufacturer+modelName（与 AIP 展示的设备型号一致）；
    friendlyName 常含序列号/主机名后缀，次之；再退到 modelDescription。
    """
    def grab(tag: str) -> str:
        m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml_text,
                      re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1).strip())
        return ""

    model = grab("modelName")
    manu = grab("manufacturer")
    if model and manu:
        return f"{manu} {model}"
    if model:
        return model
    friendly = grab("friendlyName")
    if friendly:
        return friendly
    desc = grab("modelDescription")
    if desc:
        return desc
    return ""


def _read_upnp_device_name(ip: str, port: int, timeout: float = 0.8) -> str:
    """尝试常见 UPnP 设备描述路径，识别打印机/NAS/路由器等设备型号名。

    仅对 HTTP 端口开放的设备调用；每个路径使用较短超时以控制整体耗时。
    返回如 "HP LaserJet M104w" 的可读名，未识别返回空串。
    """
    paths = ["/rootDesc.xml", "/DeviceDescription.xml",
             "/device.xml", "/description.xml"]
    per_req = max(0.3, min(0.5, timeout))
    for path in paths:
        try:
            with socket.create_connection((ip, port), timeout=per_req) as sock:
                sock.settimeout(per_req)
                req = (
                    f"GET {path} HTTP/1.0\r\n"
                    f"Host: {ip}\r\n"
                    f"User-Agent: IPScanner/1.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(req.encode("utf-8"))
                data = b""
                while len(data) < 16384:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        low = data.lower()
                        if b"</root>" in low or b"</device>" in low:
                            break
                    except socket.timeout:
                        break
            text = data.decode("utf-8", errors="replace")
            if "<device" not in text.lower():
                continue
            name = _parse_upnp_name(text)
            if name:
                return name
        except Exception:
            continue
    return ""


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 0.5,
               mode: str = "connect") -> List[int]:
    """
    扫描多个端口，返回开放端口列表。

    mode:
      "connect" 全连接 TCP 扫描（默认，无需管理员，最稳定）
      "syn"     TCP SYN 半开扫描（需管理员；Windows 还需 Npcap，否则自动回退 connect）
      "udp"     仅扫描 UDP 端口（需管理员；不可用时回退为空）
    """
    if ports is None:
        ports = COMMON_PORTS
    if not ports:
        return []
    if mode == "syn":
        return _scan_ports_syn(ip, ports, timeout)
    if mode == "udp":
        return _scan_ports_udp(ip, ports, timeout)
    # connect
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(ports))) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


# ── 原始套接字能力检测（SYN / UDP 扫描依赖）────────────────────
_raw_cap_cache = None


def raw_capability() -> Tuple[bool, str]:
    """
    检测当前进程是否能创建原始套接字（SYN/UDP 扫描前提）。
    返回 (是否可用, 不可用原因)。
    注意：Windows 上即便能创建 IPPROTO_RAW 套接字，发送 TCP 报文仍可能被系统拦截
    （返回 WSAEINVAL），真正的收发能力需在发送时验证；此处仅做"能否创建"的初步判断。
    """
    global _raw_cap_cache
    if _raw_cap_cache is not None:
        return _raw_cap_cache
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        _raw_cap_cache = (True, "")
    except OSError:
        _raw_cap_cache = (False, "无权限创建原始套接字（需以管理员/root 运行）")
    except Exception as e:
        _raw_cap_cache = (False, f"原始套接字不可用: {e}")
    return _raw_cap_cache


# SYN/UDP 发送失败时置位：后续该进程内同次扫描自动回退全连接
_syn_failed = False


def _inet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _local_ip_for_dst(dst: str) -> str:
    """获取到达 dst 时使用的本机出口 IP。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int, seq: int) -> bytes:
    """构造 IP(TCP) 报文（含 SYN 标志）。"""
    tcp_off = 5
    tcp_flags = 0x02  # SYN
    window = socket.htons(64240)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0,
                             (tcp_off << 4), tcp_flags, window, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip), 0, 6, len(tcp_header))
    tcp_csum = _inet_checksum(pseudo + tcp_header)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0,
                             (tcp_off << 4), tcp_flags, window,
                             socket.htons(tcp_csum), 0)

    ihl = 5
    version_ihl = (4 << 4) | ihl
    total_len = ihl * 4 + len(tcp_header)
    ip_id = random.randint(0, 65535)
    ip_header = struct.pack("!BBHHHBBH4s4s", version_ihl, 0, total_len, ip_id,
                            0, 128, 6, 0,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_csum = _inet_checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s", version_ihl, 0, total_len, ip_id,
                            0, 128, 6, socket.htons(ip_csum),
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip_header + tcp_header


def syn_scan_port(dst_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    TCP SYN 半开扫描单个端口。
    返回: "open"(收到 SYN-ACK) / "closed"(收到 RST) / "filtered"(超时无响应)
    发送阶段需要原始套接字权限；无权限时抛 OSError，由调用方回退。
    """
    src_ip = _local_ip_for_dst(dst_ip)
    if src_ip == "0.0.0.0":
        return "filtered"
    src_port = random.randint(1025, 65535)
    seq = random.randint(0, 0xffffffff)
    packet = _build_syn_packet(src_ip, dst_ip, src_port, port, seq)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    send_sock.settimeout(timeout)
    send_sock.sendto(packet, (dst_ip, 0))
    send_sock.close()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock.settimeout(timeout)
    start = time.time()
    try:
        while time.time() - start < timeout:
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            if addr[0] != dst_ip:
                continue
            ihl = (data[0] & 0x0f) * 4
            tcp = data[ihl:]
            if len(tcp) < 4:
                continue
            r_src_port, r_dst_port = struct.unpack("!HH", tcp[0:4])
            if r_dst_port != src_port or r_src_port != port:
                continue
            flags = tcp[13]
            if flags & 0x12 == 0x12:   # SYN-ACK
                return "open"
            if flags & 0x04:           # RST
                return "closed"
    finally:
        recv_sock.close()
    return "filtered"


def _scan_ports_syn(ip: str, ports: List[int], timeout: float) -> List[int]:
    global _syn_failed
    if _syn_failed:
        return scan_ports(ip, ports, timeout, mode="connect")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(ports))) as ex:
        futs = {ex.submit(_syn_one, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            p = futs[f]
            try:
                state = f.result()
            except OSError:
                # 无原始套接字发送权限（典型 Windows）：标记失败并整体回退
                _syn_failed = True
                return scan_ports(ip, ports, timeout, mode="connect")
            except Exception:
                state = "error"
            if state == "open":
                open_ports.append(p)
    return sorted(open_ports)


def _syn_one(ip: str, port: int, timeout: float) -> str:
    return syn_scan_port(ip, port, timeout)


def udp_scan_port(dst_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    UDP 端口扫描：发送空 UDP 报文，监听 ICMP 端口不可达。
    返回: "open"(无响应，open|filtered) / "closed"(收到 ICMP 端口不可达)
    需要原始套接字接收 ICMP；无权限时抛 OSError，由调用方回退。
    """
    src_ip = _local_ip_for_dst(dst_ip)
    if src_ip == "0.0.0.0":
        return "open"  # 无法判断，保守当作 open|filtered
    src_port = random.randint(1025, 65535)
    payload = b""
    udp_header = struct.pack("!HHHH", src_port, port, 8 + len(payload), 0)
    packet = udp_header + payload

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    send_sock.settimeout(timeout)
    send_sock.sendto(packet, (dst_ip, 0))
    send_sock.close()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_sock.settimeout(timeout)
    start = time.time()
    try:
        while time.time() - start < timeout:
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            if addr[0] != dst_ip:
                continue
            # ICMP 头: type(1) code(1) csum(2) ... ; 端口不可达 type=3 code=3
            if len(data) < 8:
                continue
            icmp_type, icmp_code = data[0], data[1]
            if icmp_type == 3 and icmp_code == 3:
                # 校验内部携带的原 UDP 头部源端口是否匹配
                if len(data) >= 28:
                    inner_src = struct.unpack("!H", data[24:26])[0]
                    if inner_src == src_port:
                        return "closed"
    finally:
        recv_sock.close()
    return "open"  # 超时无响应 => open|filtered


def _scan_ports_udp(ip: str, ports: List[int], timeout: float) -> List[int]:
    global _syn_failed
    if not ports:
        return []
    if _syn_failed:
        return []  # UDP 也依赖原始套接字，失败则跳过（避免误报）
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(ports))) as ex:
        futs = {ex.submit(udp_scan_port, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            p = futs[f]
            try:
                state = f.result()
            except OSError:
                _syn_failed = True
                return []
            except Exception:
                state = "error"
            if state == "open":
                open_ports.append(p)
    return sorted(open_ports)



# ── mDNS 设备发现 (Bonjour / DNS-SD, 本地链路组播) ──────────────
# 向 224.0.0.251:5353 发送 DNS-SD 浏览查询，监听本地链路所有 mDNS
# 响应，解析 A 记录得到主机名、PTR/SRV 得到服务类型，返回
# {ip: {"names": set, "services": set}}。无需管理员权限（UDP 组播）。

_MDNS_GROUP = "224.0.0.251"
_MDNS_PORT = 5353


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        b = label.encode("utf-8")
        out += bytes([len(b)]) + b
    out += b"\x00"
    return out


def _build_dns_query(name: str, qtype: int, req_id: int, unicast: bool = True) -> bytes:
    """构造标准 DNS 查询报文（mDNS 用，flags=0x0100）。"""
    header = struct.pack("!HHHHHH", req_id, 0x0100, 1, 0, 0, 0)
    qname = _encode_dns_name(name)
    qclass = 0x0001 | (0x8000 if unicast else 0)   # QU 位：请求单播响应
    return header + qname + struct.pack("!HH", qtype, qclass)


def _parse_dns_name(data: bytes, pos: int):
    """解析域名（支持压缩指针 0xC0），返回 (name, 新位置)。"""
    labels = []
    jumped = False
    base = pos
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:   # 压缩指针
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                pos += 2
            name, _ = _parse_dns_name(data, ptr)
            labels.append(name)
            break
        label = data[pos + 1:pos + 1 + length].decode("utf-8", "replace")
        labels.append(label)
        pos += 1 + length
    return ".".join(labels), pos


def _parse_mdns_packet(data: bytes, by_ip: dict, src_ip: str):
    """解析一条 mDNS 响应，把主机名/服务类型归入 by_ip[src_ip]。"""
    try:
        if len(data) < 12:
            return
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
        pos = 12
        for _ in range(qd):
            _, pos = _parse_dns_name(data, pos)
            pos += 4   # qtype + qclass
        entry = by_ip.setdefault(src_ip, {"names": set(), "services": set()})
        for _ in range(an + ns + ar):
            name, pos = _parse_dns_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _rclass = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            pos += 4   # TTL
            rdlen = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1:   # A 记录：name -> IPv4
                if len(rdata) >= 4:
                    ip = socket.inet_ntoa(rdata[:4])
                    entry["names"].add(name)
                    if ip != src_ip:
                        by_ip.setdefault(ip, {"names": set(), "services": set()})["names"].add(name)
            elif rtype == 12:   # PTR：DNS-SD 服务类型枚举
                target = _parse_dns_name(rdata, 0)[0] if rdata else ""
                low = name.lower()
                if low.endswith("_tcp.local") or low.endswith("_udp.local"):
                    label = name[:-6] if name.endswith(".local") else name
                    entry["services"].add(label)
            # SRV(33)/TXT(16)/AAAA(28) 等暂不解析（本机链路单设备响应已含自身信息）
    except Exception:
        pass


def mdns_discover(timeout: float = 2.5) -> Dict[str, dict]:
    """
    mDNS / DNS-SD 网络发现：向本地组播组发送浏览查询，收集所有响应。

    返回 {ip: {"names": set(host名), "services": set(服务类型)} }。
    典型可发现：打印机、NAS、路由器、Apple 设备、IoT、投屏、SMB 等。
    端口被系统 mDNS 占用或组播不可达时返回空字典（不抛异常）。
    """
    by_ip: Dict[str, dict] = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", _MDNS_PORT))
        except OSError:
            # 端口已被系统 mDNS/Bonjour 占用，无法接收组播响应
            return by_ip
        try:
            mreq = socket.inet_aton(_MDNS_GROUP) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            return by_ip
        sock.settimeout(0.25)

        queries = [
            _build_dns_query("_services._dns-sd._udp.local", 12, random.randint(1, 65535)),
            _build_dns_query("local", 255, random.randint(1, 65535)),   # ANY
        ]
        for q in queries:
            try:
                sock.sendto(q, (_MDNS_GROUP, _MDNS_PORT))
            except OSError:
                pass

        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr:
                _parse_mdns_packet(data, by_ip, addr[0])
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return by_ip


# ── OS / 版本探测 ──────────────────────────────────────────────

def guess_os_from_ttl(ttl: int) -> str:
    """
    基于 ICMP 回显 TTL 推测操作系统族（经验推断，仅供参考）。

      初始 TTL 常见取值：Windows=128、Linux/macOS/BSD=64、部分网络设备=255。
      经 N 跳后 TTL = 初始 - N，故据剩余 TTL 反推：
        ≥250                -> 网络设备（Cisco/Solaris 等）
        ≥110                -> Windows
        ≥30                 -> Linux/Unix（含 macOS/BSD）
        <30                 -> 网络设备 / 嵌入式系统
    """
    if not ttl or ttl <= 0:
        return ""
    if ttl >= 250:
        return "网络设备"
    if ttl >= 110:
        return "Windows"
    if ttl >= 30:
        return "Linux/Unix"
    return "网络设备"


def _read_ssh_banner(ip: str, port: int = 22, timeout: float = 1.0) -> str:
    """读取 SSH 服务标识行，返回版本串如 'OpenSSH_8.9p1'（失败返回空）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            text = data.decode("utf-8", "replace").strip()
            m = re.search(r"SSH-\d\.\d-(.+)", text)
            if m:
                return m.group(1).strip()
            return text
    except Exception:
        return ""


def _read_ftp_banner(ip: str, port: int = 21, timeout: float = 1.0) -> str:
    """读取 FTP 欢迎横幅，返回原始 220 行（失败返回空）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            return data.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _os_detail_from_banners(service_details: List[Dict], extra: Dict[str, str]) -> str:
    """
    从服务 banner 中提取版本信息，用于"操作系统"列的版本部分。
    HTTP/HTTPS 取 Server 头；SSH/FTP 取 extra 中的 banner。
    返回分号分隔的版本串（去重）。
    """
    parts = []
    for sd in service_details or []:
        banner = sd.get("banner", "") or ""
        proto = (sd.get("proto", "") or "").upper()
        if proto in ("HTTP", "HTTPS"):
            m = re.search(r"Server:\s*([^\r\n]+)", banner)
            if m:
                parts.append(m.group(1).strip())
        elif proto == "FTP":
            m = re.search(r"220[-\s]*(.+)", banner)
            if m:
                parts.append("FTP: " + m.group(1).strip()[:60])
    if extra.get("ssh"):
        parts.append("SSH: " + extra["ssh"])
    if extra.get("ftp") and not any(p.startswith("FTP:") for p in parts):
        parts.append("FTP: " + extra["ftp"][:60])
    seen = set()
    out = []
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return "; ".join(out)


# ── 设备指纹深度 (device fingerprint) ──────────────────────────
# 纯被动(无需凭据)综合 MAC OUI 厂商 / 开放端口组合 / 服务类型
# (mDNS / UPnP / SNMP sysDescr / HTTP banner) 推断设备类别与型号。
# 对标 Fing 的"设备识别深度"：从"某台在线设备"精确到"这是谁的什么型号设备"。
# 另含 best-effort 的 TCP 协议栈指纹(需管理员权限)，细化 OS 推测。

# OUI 厂商关键字 -> 设备类别提示（粗粒度，作为兜底信号）
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


def _snmp_model(descr: str) -> str:
    """从 SNMP sysDescr 提取设备型号关键词（失败返回空串）。"""
    if not descr:
        return ""
    d = descr
    m = re.search(r"Cisco[^\n]*?(C\d{3,4}[A-Z]?)", d, re.IGNORECASE)
    if m:
        return "Cisco " + m.group(1)
    m = re.search(r"(HP|Aruba|ProCurve|H3C|Ruijie)[^\n]*?(\d{3,4}[A-Z]?)",
                  d, re.IGNORECASE)
    if m:
        return (m.group(1).title() + " " + m.group(2)).strip()
    # 通用：取首行，去掉明显的版本/时间噪声
    first = d.splitlines()[0] if d else d
    first = re.sub(r"\s*(Version|v)\s*[\d.]+.*$", "", first, flags=re.IGNORECASE)
    return first.strip()[:60]


def _parse_tcp_opts(options: bytes):
    """解析 TCP 选项，返回 (选项类型名列表, MSS)。"""
    kinds = []
    mss = 0
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:                       # End of option list
            break
        if kind == 1:                       # NOP
            kinds.append("NOP")
            i += 1
            continue
        if i + 1 >= len(options):
            break
        length = options[i + 1]
        if length < 2:
            break
        if kind == 2:                       # MSS
            if i + 4 <= len(options):
                mss = struct.unpack("!H", options[i + 2:i + 4])[0]
            kinds.append("MSS")
        elif kind == 3:                     # Window scale
            kinds.append("WScale")
        elif kind == 4:                     # SACK permitted
            kinds.append("SACK")
        elif kind == 5:                     # SACK
            kinds.append("SACK")
        elif kind == 8:                     # Timestamp
            kinds.append("TS")
        else:
            kinds.append("OPT%d" % kind)
        i += length
    return kinds, mss


def _tcp_stack_probe(ip: str, port: int, timeout: float = 1.0) -> Optional[dict]:
    """
    主动 TCP 栈指纹：发 SYN，抓 SYN-ACK，解析 IP TTL / DF / TCP 窗口 / 选项。
    需原始套接字权限(管理员/Npcap)，否则返回 None。任何失败一律返回 None。
    """
    try:
        avail, _ = raw_capability()
        if not avail:
            return None
        src_ip = _local_ip_for_dst(ip)
        if src_ip == "0.0.0.0":
            return None
        src_port = random.randint(1025, 65535)
        seq = random.randint(0, 0xffffffff)
        packet = _build_syn_packet(src_ip, ip, src_port, port, seq)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        send_sock.settimeout(timeout)
        send_sock.sendto(packet, (ip, 0))
        send_sock.close()
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
        start = time.time()
        try:
            while time.time() - start < timeout:
                try:
                    data, addr = recv_sock.recvfrom(65535)
                except socket.timeout:
                    break
                if addr[0] != ip:
                    continue
                ihl = (data[0] & 0x0f) * 4
                if ihl < 20 or len(data) < ihl + 20:
                    continue
                tcp = data[ihl:]
                if len(tcp) < 20:
                    continue
                r_src, r_dst = struct.unpack("!HH", tcp[0:4])
                if r_dst != src_port or r_src != port:
                    continue
                flags = tcp[13]
                if not (flags & 0x12 == 0x12):   # 仅取 SYN-ACK
                    continue
                ip_ttl = data[8]
                ip_flags = (data[6] >> 5) & 0x07
                df = bool(ip_flags & 0x02)
                window = struct.unpack("!H", tcp[14:16])[0]
                tcp_off = (tcp[12] >> 4) * 4
                opts, mss = _parse_tcp_opts(tcp[20:tcp_off] if tcp_off > 20 else b"")
                return {"ttl": ip_ttl, "df": df, "window": window,
                        "opts": opts, "mss": mss}
        finally:
            recv_sock.close()
    except Exception:
        return None
    return None


def _match_tcp_stack(sig: Optional[dict]) -> str:
    """将 TCP 栈特征映射到 OS 族（粗粒度，作为 ICMP TTL 的补充）。"""
    if not sig:
        return ""
    ttl = sig.get("ttl", 0)
    opts = sig.get("opts", [])
    if ttl >= 250:
        return "网络设备"
    if ttl >= 110:
        return "Windows"
    if ttl >= 30:
        if "TS" in opts:
            return "Linux/Unix"
        return "macOS/BSD"
    return "网络设备"


def infer_device(result: "ScanResult") -> Tuple[str, str]:
    """
    综合指纹推断设备类别与型号，返回 (device_class, device_model)。
    纯被动：仅基于已采集数据(厂商/端口/服务/mDNS/UPnP/SNMP/OS)推断，
    不发起新连接。TCP 栈指纹由调用方单独探测后写入 result.os_guess，
    本函数复用 os_guess 作为兜底信号。
    """
    ports = set(result.open_ports)
    vendor = (result.vendor or "").lower()
    hostname = (result.hostname or "").lower()
    mdns = []
    for sd in result.service_details or []:
        if sd.get("proto") == "mDNS":
            for s in (sd.get("banner") or "").split(","):
                s = s.strip()
                if s:
                    mdns.append(s)
    mdns_lower = [s.lower() for s in mdns]
    snmp_descr = result.snmp_sys_descr or ""
    upnp = result.upnp_model or ""
    http_brand = (result.http_brand or "").strip()
    http_model = (result.http_model or "").strip()
    http_is_printer = http_brand and (
        http_brand == "打印机" or
        any(display == http_brand for _, display in _PRINTER_BRANDS)
    )

    device_class = ""
    device_model = ""

    # 1) mDNS 服务类型强信号
    if any(("airplay" in s or "_raop" in s) for s in mdns_lower):
        device_class = "媒体设备"
        if "apple" in vendor or "apple" in hostname:
            device_model = "Apple TV / AirPlay"
    if any("googlecast" in s for s in mdns_lower):
        device_class = device_class or "投屏设备"
        device_model = device_model or "Chromecast"
    if any(("_printer" in s or "_ipp" in s) for s in mdns_lower):
        device_class = device_class or "打印机"
    if any("_homekit" in s for s in mdns_lower):
        device_class = device_class or "智能家居"
    if any("_adb" in s for s in mdns_lower):
        device_class = device_class or "Android/开发板"

    # 2) 端口组合规则
    if not device_class:
        if 554 in ports:                                   # RTSP 视频流
            device_class = "摄像头"
        elif bool({515, 631, 9100} & ports):               # 打印协议
            device_class = "打印机"
        elif (5000 in ports or 5001 in ports) or (8443 in ports and "nas" in hostname):
            device_class = "NAS"
        elif (23 in ports or 22 in ports) and 80 in ports and (53 in ports or 67 in ports):
            device_class = "路由器"
        elif 23 in ports and 161 in ports:                  # Telnet + SNMP：受管网络设备(交由 SNMP 细化)
            device_class = "网络设备"
        elif bool({5060, 5061} & ports):
            device_class = "电话/VoIP"

    # 3) SNMP sysDescr 信号（可细化端口组合得出的泛化类别）
    if snmp_descr:
        sd_low = snmp_descr.lower()
        if device_class in ("", "网络设备", "未知设备"):
            if "switch" in sd_low or ("ios" in sd_low and "cisco" in sd_low):
                device_class = "交换机"
            elif "router" in sd_low or "routeros" in sd_low:
                device_class = "路由器"
            elif "printer" in sd_low or "jetdirect" in sd_low:
                device_class = "打印机"
            elif "nas" in sd_low or "storage" in sd_low:
                device_class = "NAS"
            elif "ap" in sd_low and "aruba" in sd_low:
                device_class = "AP"
        if not device_model:
            device_model = _snmp_model(snmp_descr)

    # 4) UPnP / HTTP 型号信号
    # HTTP 页面识别出打印机品牌（对仅开 80/443 的现代网络打印机很关键）
    if http_is_printer and not device_class:
        device_class = "打印机"
        if http_model:
            device_model = f"{http_brand} {http_model}".strip()
        elif not device_model and http_brand != "打印机":
            device_model = f"{http_brand} 打印机"

    if upnp and not device_model:
        device_model = upnp
        if not device_class:
            ul = upnp.lower()
            if "print" in ul or "打印" in upnp or "laser" in ul:
                device_class = "打印机"
            elif "nas" in ul:
                device_class = "NAS"
            elif "router" in ul:
                device_class = "路由器"
            else:
                device_class = device_class or "网络设备"

    # 5) 仅凭 OS 推测兜底（优先于 OUI 泛化提示，给出更具体的类别）
    if not device_class:
        if result.os_guess == "Windows":
            device_class = "电脑/服务器" if (3389 in ports or (445 in ports and 139 in ports)) \
                else "Windows 设备"
        elif result.os_guess == "Linux/Unix":
            device_class = "Linux 设备/服务器" if 22 in ports else "Linux 设备"
        elif result.os_guess == "网络设备":
            device_class = "网络设备"
        else:
            device_class = "未知设备"

    # 6) OUI 厂商提示（弱信号，仅当上述均无结论时作为兜底）
    if not device_class:
        for key, cls in _OUI_CLASS_HINTS:
            if key in vendor:
                device_class = cls
                break
        if not device_class and any(k in hostname
                                    for k in ("apple", "iphone", "ipad", "macbook")):
            device_class = "手机/电脑/IoT"

    # 7) 型号兜底：厂商 + 类别
    if not device_model and device_class:
        if device_class == "摄像头" and "hikvision" in vendor:
            device_model = "海康威视摄像头"
        elif device_class == "摄像头" and "dahua" in vendor:
            device_model = "大华摄像头"
        elif device_class == "路由器" and "mikrotik" in vendor:
            device_model = "MikroTik 路由器"
        elif device_class == "NAS" and "synology" in vendor:
            device_model = "群晖 NAS"
        elif device_class == "NAS" and "qnap" in vendor:
            device_model = "威联通 NAS"

    return device_class, device_model


class NetworkScanner:
    """网络扫描器主类"""

    def __init__(self):
        self.is_scanning = False
        self._stop_flag = False

    def stop(self):
        """请求停止扫描"""
        self._stop_flag = True

    def scan(self, ip_ranges: List[str], timeout_ms: int = 1000,
             max_threads: int = 100, scan_ports_flag: bool = False,
             protocols: List[str] = None, tcp_scan_mode: str = "connect",
             mdns_discovery: bool = True,
             progress_callback=None, result_callback=None) -> List[ScanResult]:
        """
        扫描多个 IP 范围。

        Args:
            ip_ranges: IP 范围字符串列表
            timeout_ms: ping 超时(毫秒)
            max_threads: 最大并发线程数
            scan_ports_flag: 是否扫描端口
            protocols: 要检测的应用层协议列表 (HTTP, HTTPS, FTP, RDP 等)
            tcp_scan_mode: 端口探测方式 connect(全连接)/syn(SYN半开)/udp(仅UDP)
            mdns_discovery: 是否在扫描末尾做 mDNS 组播发现（发现网内 IoT/打印机/NAS 等）
            progress_callback: 进度回调 (current, total, current_ip)
            result_callback: 单个结果回调 (ScanResult)

        Returns:
            ScanResult 列表
        """
        self.is_scanning = True
        self._stop_flag = False
        self.warnings: List[str] = []  # 本次扫描的非致命告警（如 SYN 回退）

        # 解析 TCP 探测方式：syn/udp 需要原始套接字权限
        effective_tcp_mode = "connect"
        if tcp_scan_mode in ("syn", "udp"):
            avail, reason = raw_capability()
            if avail:
                effective_tcp_mode = tcp_scan_mode
                # 重新尝试发送（之前若失败则重置，便于本次重新验证）
                global _syn_failed
                _syn_failed = False
            else:
                self.warnings.append(
                    f"{'SYN' if tcp_scan_mode == 'syn' else 'UDP'} 探测需要管理员权限"
                    f"（Windows 还需 Npcap），已回退到 TCP 全连接扫描。{reason}"
                )

        # 解析所有 IP
        all_ips = []
        for r in ip_ranges:
            all_ips.extend(parse_ip_range(r))

        if not all_ips:
            self.is_scanning = False
            return []

        total = len(all_ips)
        results: Dict[str, ScanResult] = {ip: ScanResult(ip=ip) for ip in all_ips}
        completed = 0

        # Phase 1 + Phase 3 流水线：ping 与在线设备的富化(enrich)并发执行。
        # 富化阶段的 DNS / NetBIOS / 端口探测都是 I/O 密集型，可完全隐藏在 ping 等待时间内，
        # 整体扫描耗时从 "ping 耗时 + enrich 耗时" 降为 "max(ping 耗时, enrich 耗时)"。
        # 构建协议端口映射 (协议名 -> 端口号)；SNMP 为 UDP 设备识别，单独开关
        proto_port_map = {}
        snmp_enabled = False
        if protocols:
            for proto in protocols:
                proto_upper = proto.upper()
                if proto_upper == "SNMP":
                    snmp_enabled = True
                elif proto_upper in PROTOCOL_PORTS:
                    proto_port_map[proto_upper] = PROTOCOL_PORTS[proto_upper]

        # NetBIOS 解析共用线程池，使其与 DNS 解析并发而非串行等待
        _netbios_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(10, min(50, len(all_ips)))
        )

        def enrich_device(ip: str):
            """富化单个在线设备：MAC / 厂商 / 主机名 / 端口 / 服务。"""
            if self._stop_flag:
                return
            result = results[ip]

            # MAC 地址：优先保留已获取的 MAC（如 ARP 主动探测所得），
            # 否则 per-IP 查询 ARP 缓存（对刚 ping 通的在线主机可靠）
            if not result.mac:
                result.mac = get_mac_for_ip(ip)
            mac = result.mac

            # 厂商识别 (通过 MAC OUI)
            if mac:
                result.vendor = get_mac_vendor(mac)

            # 端口 & 服务探测 (与本机名解析并行执行)
            if scan_ports_flag:
                result.scan_method = effective_tcp_mode
                result.open_ports = scan_ports(
                    ip, timeout=0.5, mode=effective_tcp_mode
                )

            # OS / 版本探测：基于 TTL 推测族 + banner 提取版本
            result.os_guess = guess_os_from_ttl(result.ttl) if result.ttl else ""
            _os_extra = {}
            if 22 in result.open_ports:
                _ssh = _read_ssh_banner(ip, 22, 1.0)
                if _ssh:
                    _os_extra["ssh"] = _ssh
            if 21 in result.open_ports:
                _ftp = _read_ftp_banner(ip, 21, 1.0)
                if _ftp:
                    _os_extra["ftp"] = _ftp
            result.os_detail = _os_detail_from_banners(result.service_details, _os_extra)

            # TCP 栈指纹（深度 OS 探测）：best-effort，无权限/失败自动跳过
            if result.open_ports:
                _probe_port = next(
                    (p for p in (80, 443, 8080, 22, 21, 23, 135, 445, 139,
                                 3389, 5900, 53) if p in result.open_ports),
                    result.open_ports[0],
                )
                _sig = _tcp_stack_probe(ip, _probe_port, 1.0)
                if _sig:
                    _tcp_os = _match_tcp_stack(_sig)
                    # 仅在 ICMP 无结论或 TCP 识别为网络设备时覆盖，
                    # 避免与已较准确的 ICMP TTL 推测冲突
                    if _tcp_os and (not result.os_guess or _tcp_os == "网络设备"):
                        result.os_guess = _tcp_os

            svc_list = []
            svc_details = []
            if proto_port_map:
                proto_ports = list(proto_port_map.values())
                detected_proto_ports = scan_ports(ip, ports=proto_ports, timeout=0.5)
                for proto, port in proto_port_map.items():
                    if port in detected_proto_ports:
                        svc_list.append(proto)
                        detail = {"proto": proto, "port": port}
                        if proto == "HTTP":
                            http_banner = _read_http_banner(ip, port, 1.0)
                            upnp_name = _read_upnp_device_name(ip, port, 0.8)
                            result.upnp_model = upnp_name
                            # 额外从页面内容识别品牌/型号（对只有 80/443 的打印机很关键）
                            http_brand, http_model = _read_http_brand(ip, port, 1.2)
                            result.http_brand = http_brand
                            result.http_model = http_model
                            if upnp_name:
                                # 对齐 AIP 风格: "<设备型号> <IP> (<Server头>)"
                                disp = upnp_name if ip in upnp_name else f"{upnp_name} {ip}"
                                if http_banner:
                                    disp = f"{disp} ({http_banner})"
                                detail["banner"] = disp
                            else:
                                detail["banner"] = http_banner
                        elif proto == "HTTPS":
                            detail["banner"] = _read_https_banner(ip, port, 1.2)
                        svc_details.append(detail)
                        # 如果没开完整端口扫描，也把协议端口加入开放端口列表
                        if not scan_ports_flag and port not in result.open_ports:
                            result.open_ports.append(port)
                            result.open_ports.sort()
            result.services = svc_list
            result.service_details = svc_details

            # 主机名：DNS 解析 (resolve_hostname 自带 1-worker 线程池，在设备线程内执行)
            # 与 NetBIOS 解析 (_netbios_executor) 并发，任一命中即可
            hostname = resolve_hostname(ip, timeout=1.0)
            if not hostname:
                try:
                    hostname = _netbios_executor.submit(
                        get_netbios_name, ip, 2.0
                    ).result(timeout=2.0)
                except Exception:
                    pass
            result.hostname = hostname

            # SNMP 设备识别 (交换机/AP/打印机等)：取 sysDescr/sysName，
            # 作为主机名兜底，并把 "SNMP" 加入服务列表
            if snmp_enabled:
                snmp_info = snmp_get_system(ip)
                if snmp_info:
                    result.snmp_sys_name = snmp_info.get("sys_name", "")
                    result.snmp_sys_descr = snmp_info.get("sys_descr", "")
                    if not result.hostname and result.snmp_sys_name:
                        result.hostname = result.snmp_sys_name
                    if "SNMP" not in result.services:
                        result.services.append("SNMP")
                    result.service_details.append({
                        "proto": "SNMP",
                        "port": 161,
                        "banner": result.snmp_sys_descr or "SNMP 设备信息",
                    })

            # 共享文件夹探测 (SMB / 445)：对在线设备的 SMB 服务枚举共享目录
            smb_open = 445 in result.open_ports
            if not smb_open and not scan_ports_flag:
                # 未做完整端口扫描时，快速探测 445 是否开放（仅在线设备）
                smb_open = scan_port(ip, 445, 0.4)
            if smb_open:
                shares = scan_shares(ip, timeout=1.5)
                if shares:
                    result.shares = shares
                    if "SMB共享" not in result.services:
                        result.services.append("SMB共享")
                    result.service_details.append({
                        "proto": "SMB共享",
                        "port": 445,
                        "banner": f"{len(shares)} 个共享: " + ", ".join(shares),
                        "shares": shares,
                    })

            # 设备指纹深度：综合厂商/端口/服务(mDNS/UPnP/SNMP)/OS 推断设备类别与型号
            result.device_class, result.device_model = infer_device(result)

            if result_callback:
                result_callback(result)

        # enrich 并发度：主机名/NetBIOS/端口探测均为 I/O 密集，可安全提高到 50
        _enrich_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(50, max(1, len(all_ips)))
        )
        _enrich_futures = []

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ping_ex:
                futures = {}
                for ip in all_ips:
                    if self._stop_flag:
                        break
                    futures[ping_ex.submit(ping_ip, ip, timeout_ms)] = ip

                for future in concurrent.futures.as_completed(futures):
                    if self._stop_flag:
                        break
                    ip = futures[future]
                    try:
                        alive, rtt, ttl = future.result()
                    except Exception:
                        alive, rtt, ttl = False, 0.0, 0

                    result = results[ip]
                    result.response_time = rtt
                    result.ttl = ttl
                    result.status = "online" if alive else "offline"
                    if alive:
                        result.discovery_method = "ping"

                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total, ip)

                    # 在线设备一旦确认，立即交给 enrich 线程池，
                    # 与剩余 ping 并发执行 (流水线加速)
                    if alive and not self._stop_flag:
                        _enrich_futures.append(
                            _enrich_executor.submit(enrich_device, ip)
                        )

            # ── Phase 2: ARP 主动探测（仅本机直连网段）──
            # 发现“禁 Ping 但在线”的静默主机。SendARP 不依赖 ICMP，
            # 命中即视为在线，与 ping 命中的设备同样进入 enrich 流水线。
            if not self._stop_flag:
                local_subnets = get_local_subnets()
                if local_subnets:
                    offline_local = []
                    for ip in all_ips:
                        r = results[ip]
                        if r.status == "online":
                            continue
                        try:
                            if any(ipaddress.ip_address(ip) in net for net in local_subnets):
                                offline_local.append(ip)
                        except Exception:
                            pass

                    if offline_local:
                        arp_ex = concurrent.futures.ThreadPoolExecutor(
                            max_workers=min(50, len(offline_local))
                        )
                        arp_futs = {
                            arp_ex.submit(arp_ping, ip): ip for ip in offline_local
                        }
                        for f in concurrent.futures.as_completed(arp_futs):
                            if self._stop_flag:
                                break
                            ip = arp_futs[f]
                            try:
                                mac = f.result(timeout=2.0)
                            except Exception:
                                mac = ""
                            if mac:
                                r = results[ip]
                                r.status = "online"
                                r.discovery_method = "arp"
                                r.mac = mac
                                r.vendor = get_mac_vendor(mac) if mac else ""
                                r.response_time = 0.0
                                # 进入 enrich 流水线（与 ping 命中的设备一致）
                                _enrich_futures.append(
                                    _enrich_executor.submit(enrich_device, ip)
                                )
                        arp_ex.shutdown(wait=False)

            # ── Phase 3: mDNS 组播发现（本地链路）──
            # 发现网内"不响应 Ping/ARP"但支持 mDNS 的设备（打印机/NAS/路由器/
            # Apple 设备/IoT/投屏/SMB 等）。命中设备补充主机名(mDNS 名)与服务类型，
            # 扫描范围之外的新设备也并入结果（标记为 mDNS 发现）。
            if mdns_discovery and not self._stop_flag:
                try:
                    mdns_map = mdns_discover(timeout=2.5)
                except Exception:
                    mdns_map = {}
                for ip, info in mdns_map.items():
                    names = sorted(info.get("names", set()))
                    services = sorted(info.get("services", set()))
                    if ip in results:
                        r = results[ip]
                        if not r.hostname and names:
                            r.hostname = names[0].rstrip(".")
                        if services and "mDNS" not in r.services:
                            r.services.append("mDNS")
                            r.service_details.append({
                                "proto": "mDNS", "port": 0,
                                "banner": ", ".join(services),
                            })
                        if r.status != "online":
                            r.status = "online"
                            if not r.discovery_method:
                                r.discovery_method = "mdns"
                    else:
                        nr = ScanResult(ip=ip, status="online",
                                        discovery_method="mdns",
                                        hostname=names[0].rstrip(".") if names else "")
                        if services:
                            nr.services.append("mDNS")
                            nr.service_details.append({
                                "proto": "mDNS", "port": 0,
                                "banner": ", ".join(services),
                            })
                        results[ip] = nr
        finally:
            # 等待所有富化完成；停止扫描时不再等待，直接返回
            if not self._stop_flag:
                for f in _enrich_futures:
                    try:
                        f.result()
                    except Exception:
                        pass
            _enrich_executor.shutdown(wait=False)
            _netbios_executor.shutdown(wait=False)

        # 运行时原始套接字发送被系统拒绝（如 Windows 拦截 TCP 原始发送）的回退告警
        if effective_tcp_mode in ("syn", "udp") and _syn_failed:
            self.warnings.append(
                "SYN/UDP 探测在发送阶段被系统拒绝"
                "（Windows 需 Npcap 或以管理员运行），本次端口扫描已回退到 TCP 全连接。"
            )

        self.is_scanning = False
        return list(results.values())
