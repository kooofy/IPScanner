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

from .constants import _MDNS_GROUP, _MDNS_PORT, _resolve_executor, _resolve_executor_lock
from .util import _run_cmd

from .models import ScanResult


def _get_resolve_executor():
    global _resolve_executor
    if _resolve_executor is None:
        with _resolve_executor_lock:
            if _resolve_executor is None:
                _resolve_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=8, thread_name_prefix="resolve-host"
                )
    return _resolve_executor


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """反向 DNS 解析主机名（复用进程级线程池）"""
    try:
        future = _get_resolve_executor().submit(socket.gethostbyaddr, ip)
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


def _parse_dns_name(data: bytes, pos: int, depth: int = 0):
    """解析域名（支持压缩指针 0xC0），返回 (name, 新位置)。

    限制压缩指针跳转深度（默认 10 层），防止畸形 / 循环压缩指针
    （如 A -> B -> A）导致无限递归与栈溢出。
    """
    labels = []
    jumped = False
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:   # 压缩指针
            if depth >= 10:         # 超过最大嵌套层数，视为畸形报文，安全终止
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                pos += 2
            name, _ = _parse_dns_name(data, ptr, depth + 1)
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
