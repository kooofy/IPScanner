# -*- coding: utf-8 -*-
import random
import re
import socket
import struct
import time
from typing import Dict, List, Optional

from .ports import _build_syn_packet, raw_capability
from .util import _local_ip_for_dst


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
