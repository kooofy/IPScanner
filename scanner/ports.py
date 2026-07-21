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

from .constants import COMMON_PORTS, _SYSTEM_SHARES, _raw_cap_cache, _syn_failed
from .util import _inet_checksum, _local_ip_for_dst, _run_cmd

from .models import ScanResult


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
