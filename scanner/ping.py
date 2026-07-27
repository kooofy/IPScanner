# -*- coding: utf-8 -*-
import ctypes
import ipaddress
import platform
import re
from typing import Dict, List, Optional, Tuple

from .constants import _LOCAL_MAC_CACHE
from .util import _run_cmd
from i18n import tr


def ping_ip(ip: str, timeout_ms: int = 1000) -> Tuple[bool, float, int]:
    """
    Ping 单个 IP，返回 (是否在线, 响应时间ms, TTL)。
    Windows 使用系统 ping 命令。
    TTL 用于 OS 推测（Windows≈128 / Linux·macOS·BSD≈64 / 部分网络设备≈255）。
    """
    is_windows = platform.system() == tr("Windows")
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
            time_match = re.search(tr(r"时间[=:](\d+)\s*ms"), output)
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
    is_windows = platform.system() == tr("Windows")
    
    try:
        if is_windows:
            output = _run_cmd(["ipconfig", "/all"], timeout=10)
            # 解析 ipconfig /all 输出
            current_mac = None
            for line in output.splitlines():
                line = line.strip()
                # 匹配物理地址行
                mac_match = re.search(tr(r"物理地址[ .]+: ([0-9a-fA-F\-]{17})"), line)
                if not mac_match:
                    mac_match = re.search(r"Physical Address[ .]+: ([0-9a-fA-F\-]{17})", line)
                if mac_match:
                    current_mac = mac_match.group(1).replace("-", ":").lower()
                    continue
                # 匹配 IPv4 地址行
                ip_match = re.search(tr(r"IPv4 地址[ .]+: (\d+\.\d+\.\d+\.\d+)"), line)
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
    if platform.system() != tr("Windows"):
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
    if platform.system() != tr("Windows"):
        return nets
    try:
        output = _run_cmd(["ipconfig"], timeout=10)
        cur_ip = None
        for line in output.splitlines():
            line = line.strip()
            m = re.search(tr(r"IPv4 地址[ .]+: (\d+\.\d+\.\d+\.\d+)"), line)
            if not m:
                m = re.search(r"IPv4 Address[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                cur_ip = m.group(1)
                continue
            sm = re.search(tr(r"子网掩码[ .]+: (\d+\.\d+\.\d+\.\d+)"), line)
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
