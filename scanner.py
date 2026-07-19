# -*- coding: utf-8 -*-
"""
网络扫描引擎 — ICMP Ping + ARP + 主机名 + 端口探测
支持 CIDR (192.168.1.0/24)、范围 (192.168.1.1-254)、单 IP
"""

import subprocess
import socket
import concurrent.futures
import ipaddress
import re
import time
import platform
import os
import locale
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

    def to_dict(self) -> dict:
        return {
            "IP地址": self.ip,
            "状态": "在线" if self.status == "online" else "离线",
            "主机名": self.hostname,
            "MAC地址": self.mac,
            "厂商": self.vendor,
            "设备类型": self.device_type,
            "位置": self.location,
            "使用者": self.user,
            "响应时间(ms)": round(self.response_time, 1) if self.response_time else "",
            "开放端口": ", ".join(str(p) for p in self.open_ports) if self.open_ports else "",
            "备注": self.remark,
        }


# 常见端口
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
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


def ping_ip(ip: str, timeout_ms: int = 1000) -> Tuple[bool, float]:
    """
    Ping 单个 IP，返回 (是否在线, 响应时间ms)。
    Windows 使用系统 ping 命令。
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
        if "TTL=" in output or "ttl=" in output:
            # 提取响应时间
            time_match = re.search(r"时间[=:](\d+)\s*ms", output)
            if not time_match:
                time_match = re.search(r"time[=:](\d+\.?\d*)\s*ms", output)
            if not time_match:
                time_match = re.search(r"<\s*(\d+)\s*ms", output)
            rtt = float(time_match.group(1)) if time_match else 0.0
            return True, rtt
        return False, 0.0
    except Exception:
        return False, 0.0


def get_arp_table() -> Dict[str, str]:
    """
    获取系统 ARP 表，返回 {ip: mac} 字典。
    """
    arp_table = {}
    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            output = _run_cmd(["arp", "-a"], timeout=10)
        else:
            output = _run_cmd(["arp", "-an"], timeout=10)

        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     动态"
            # 也匹配中文编码乱码的情况
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                arp_table[ip] = mac
            elif not is_windows:
                # Linux: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
                match = re.match(r"\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    arp_table[ip] = mac
    except Exception:
        pass

    return arp_table


def get_local_ips() -> List[str]:
    """获取本机所有网卡的IP地址"""
    ips = []
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip = addr[4][0]
            if ip and "." in ip and not ip.startswith("127."):
                if ip not in ips:
                    ips.append(ip)
    except Exception:
        pass
    return ips


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
        # 输出格式 (中文/英文 Windows):
        # "  WORKSTATION1   <00>  唯一/UNIQUE        已注册/Registered"
        # 找第一个带 <00> 标记且是唯一名称的条目
        for line in output.splitlines():
            line = line.strip()
            if "<00>" not in line:
                continue
            # 跳过组名称 (GROUP/组)
            if "组" in line or "GROUP" in line.upper():
                continue
            parts = line.split()
            if parts:
                name = parts[0]
                # 过滤掉 IS~ 开头的名称
                if not name.startswith("IS~"):
                    return name
    except Exception:
        pass
    return ""


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


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 0.5) -> List[int]:
    """扫描多个端口，返回开放端口列表"""
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


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
             protocols: List[str] = None,
             progress_callback=None, result_callback=None) -> List[ScanResult]:
        """
        扫描多个 IP 范围。

        Args:
            ip_ranges: IP 范围字符串列表
            timeout_ms: ping 超时(毫秒)
            max_threads: 最大并发线程数
            scan_ports_flag: 是否扫描端口
            protocols: 要检测的应用层协议列表 (HTTP, HTTPS, FTP, RDP 等)
            progress_callback: 进度回调 (current, total, current_ip)
            result_callback: 单个结果回调 (ScanResult)

        Returns:
            ScanResult 列表
        """
        self.is_scanning = True
        self._stop_flag = False

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

        # Phase 1: Ping 扫描 (只更新进度，不回调UI，避免分两批显示)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {}
            for ip in all_ips:
                if self._stop_flag:
                    break
                future = executor.submit(ping_ip, ip, timeout_ms)
                futures[future] = ip

            for future in concurrent.futures.as_completed(futures):
                if self._stop_flag:
                    break
                ip = futures[future]
                try:
                    alive, rtt = future.result()
                except Exception:
                    alive, rtt = False, 0.0

                result = results[ip]
                result.response_time = rtt
                if alive:
                    result.status = "online"
                else:
                    result.status = "offline"

                completed += 1
                if progress_callback:
                    progress_callback(completed, total, ip)

        if self._stop_flag:
            self.is_scanning = False
            return list(results.values())

        # Phase 2: 获取 ARP 表 (一次性)
        arp_table = get_arp_table()

        # Phase 3: 对在线设备补充信息 (MAC, 主机名, 端口, 服务)
        online_ips = [ip for ip in all_ips if results[ip].status == "online"]
        
        # 构建协议端口映射 (协议名 -> 端口号)
        proto_port_map = {}
        if protocols:
            for proto in protocols:
                proto_upper = proto.upper()
                if proto_upper in PROTOCOL_PORTS:
                    proto_port_map[proto_upper] = PROTOCOL_PORTS[proto_upper]

        def enrich_device(ip: str):
            if self._stop_flag:
                return
            result = results[ip]

            # MAC 地址
            mac = arp_table.get(ip, "")
            if not mac:
                mac = get_mac_for_ip(ip)
            result.mac = mac

            # 厂商识别 (通过 MAC OUI)
            if mac:
                result.vendor = get_mac_vendor(mac)

            # 主机名 (先试 DNS，再试 NetBIOS)
            hostname = resolve_hostname(ip, timeout=1.0)
            if not hostname:
                hostname = get_netbios_name(ip, timeout=2.0)
            result.hostname = hostname

            # 端口扫描
            if scan_ports_flag:
                result.open_ports = scan_ports(ip, timeout=0.5)
            
            # 服务检测 (独立于端口扫描，只要选了协议就探测对应端口)
            if proto_port_map:
                svc_list = []
                proto_ports = list(proto_port_map.values())
                # 探测协议端口
                detected_proto_ports = scan_ports(ip, ports=proto_ports, timeout=0.5)
                for proto, port in proto_port_map.items():
                    if port in detected_proto_ports:
                        svc_list.append(proto)
                        # 如果没开完整端口扫描，也把协议端口加入开放端口列表
                        if not scan_ports_flag and port not in result.open_ports:
                            result.open_ports.append(port)
                            result.open_ports.sort()
                result.services = svc_list

            if result_callback:
                result_callback(result)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, max(1, len(online_ips)))) as executor:
            list(executor.map(enrich_device, online_ips))

        self.is_scanning = False
        return list(results.values())
