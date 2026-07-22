# -*- coding: utf-8 -*-
"""NetBIOS 轻量识别（UDP/137 NBSTAT 节点状态查询）。

零凭据、不需要管理员权限，对在线 Windows / Samba(SMB) 设备可获取：
- 计算机名（NetBIOS 唯一 <00> 名）
- 工作组 / 域（NetBIOS <00> 组名）
- 当前登录用户（NetBIOS <03> 唯一名，若与计算机名不同）
- MAC 地址（NBSTAT 统计块，即使 ARP 没拿到也能补到）

仅依赖标准库 socket，无第三方依赖、无需 Windows。

注意：UDP/137 常被主机防火墙拦截，跨网段 / 公网通常不通，仅同网段可靠
（与 Angry IP Scanner 的 NetBIOS fetcher 行为一致）。失败统一返回 error dict，
不抛异常，方便 UI 静默降级。
"""
import socket
import struct
from typing import Dict

NETBIOS_NS_PORT = 137


def _encode_nbname(name16: bytes) -> bytes:
    """将 16 字节 NetBIOS 名编码为 32 字节 NBT 名（每个半字节 + 'A'）。"""
    out = bytearray()
    for b in name16:
        out += bytes([0x41 + ((b >> 4) & 0x0F), 0x41 + (b & 0x0F)])
    return bytes(out)


def _build_nbstat_request(tid: int = 0x0000) -> bytes:
    """构造 NBSTAT 节点状态请求包（固定 * 名，查询所有注册名）。"""
    name16 = b"*" + b" " * 15  # "*" + 15 个空格，凑成 16 字节 NetBIOS 名
    enc = _encode_nbname(name16)
    pkt = bytearray()
    pkt += struct.pack(">H", tid)      # Transaction ID
    pkt += struct.pack(">H", 0x0000)   # Flags: 标准查询
    pkt += struct.pack(">H", 1)        # Questions = 1
    pkt += struct.pack(">H", 0)        # Answer RRs = 0
    pkt += struct.pack(">H", 0)        # Authority RRs = 0
    pkt += struct.pack(">H", 0)        # Additional RRs = 0
    # Question: 长度字节(0x20) + 32 字节编码名 + QTYPE(0x0021) + QCLASS(0x0001)
    pkt += bytes([0x20]) + enc
    pkt += struct.pack(">H", 0x0021)   # NBSTAT
    pkt += struct.pack(">H", 0x0001)   # IN
    return bytes(pkt)


def _decode_nbname(name16: bytes) -> str:
    """解码 NetBIOS 名为可读字符串（取前 15 个有效字符，去掉类型后缀与尾空格）。"""
    try:
        s = name16[:15].decode("latin-1")
    except Exception:
        s = name16[:15].decode("utf-8", "replace")
    return "".join(ch for ch in s if 0x20 <= ord(ch) <= 0x7E).rstrip()


def _skip_name(data: bytes, off: int) -> int:
    """跳过 DNS/NBT 名（长度前缀标签或 0xC0xx 压缩指针），返回新偏移。"""
    if off >= len(data):
        return off
    if data[off] & 0xC0 == 0xC0:   # 压缩指针，占 2 字节
        return off + 2
    length = data[off]             # 长度前缀标签
    return off + 1 + length


def _error_dict(msg: str) -> Dict[str, object]:
    """统一的错误结果结构。"""
    return {
        "netbios_name": "",
        "netbios_workgroup": "",
        "netbios_user": "",
        "netbios_mac": "",
        "netbios_identified": False,
        "netbios_error": msg,
    }


def _parse_nbstat_response(data: bytes, ip: str) -> Dict[str, object]:
    """解析 NBSTAT 节点状态响应，返回结构化 dict。

    RFC 1002 布局：12 字节头 → Question(回显) → Answer(NBSTAT) → RDATA。
    RDATA = NUM_NAMES(2) + N×(16 字节名 + 1 类型 + 1 标志) + 统计块(6 MAC + 40)。
    """
    try:
        if len(data) < 12:
            return _error_dict("响应过短，可能不是 NBSTAT 应答")
        off = 12
        # 跳过 Question 段（QNAME + QTYPE + QCLASS）
        off = _skip_name(data, off)
        if off + 4 > len(data):
            return _error_dict("Question 段解析越界")
        off += 4  # QTYPE(2) + QCLASS(2)
        # Answer 段
        off = _skip_name(data, off)  # Answer NAME（通常为压缩指针 0xC00C）
        if off + 10 > len(data):     # TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
            return _error_dict("Answer 头解析越界")
        ans_type = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        off += 2                      # CLASS
        off += 4                      # TTL
        rdlen = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        if ans_type != 0x0021:
            return _error_dict("应答类型非 NBSTAT")
        rdata_end = off + rdlen
        if off + 2 > rdata_end:
            return _error_dict("RDATA 越界")
        num_names = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        comp_name = None
        workgroup = None
        user = None
        for _ in range(num_names):
            if off + 18 > rdata_end:
                break
            raw = data[off:off + 16]
            ntype = data[off + 16]
            nflags = data[off + 17]
            off += 18
            name = _decode_nbname(raw)
            is_group = bool(nflags & 0x80)
            if ntype == 0x00 and not is_group:
                comp_name = name
            elif ntype == 0x00 and is_group:
                workgroup = name
            elif ntype == 0x03 and not is_group:
                # 当前登录用户名（Messenger 注册名）；与计算机名相同则视为无独立用户
                if name and name != comp_name:
                    user = name
        mac = ""
        if off + 6 <= rdata_end:
            mac = ":".join(f"{b:02X}" for b in data[off:off + 6])
        return {
            "netbios_name": comp_name or "",
            "netbios_workgroup": workgroup or "",
            "netbios_user": user or "",
            "netbios_mac": mac,
            "netbios_identified": True,
            "netbios_error": "",
        }
    except Exception as e:  # noqa: BLE001
        return _error_dict(f"NetBIOS 响应解析失败: {e}")


def netbios_query(ip: str, timeout: float = 2.0) -> Dict[str, object]:
    """对目标 IP 做 NetBIOS 节点状态查询。

    返回 dict：成功含 netbios_* 字段且 netbios_identified=True；
    失败含 netbios_error（超时 / 不可达 / 防火墙拦截等）。不会抛出异常。
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = _build_nbstat_request()
        sock.sendto(pkt, (ip, NETBIOS_NS_PORT))
        data, _ = sock.recvfrom(65535)
        return _parse_nbstat_response(data, ip)
    except socket.timeout:
        return _error_dict("NetBIOS 超时（目标可能未开放 UDP/137 或防火墙拦截）")
    except (ConnectionResetError, ConnectionRefusedError, OSError) as e:
        return _error_dict(f"NetBIOS 连接失败: {e}")
    except Exception as e:  # noqa: BLE001
        return _error_dict(f"NetBIOS 查询异常: {e}")
    finally:
        if sock is not None:
            sock.close()


def merge_netbios(result, d: Dict[str, object]) -> None:
    """将 NetBIOS 结果合并进 ScanResult，并用权威信息补全设备指纹。"""
    if d.get("netbios_error"):
        result.netbios_error = d["netbios_error"]
        return
    result.netbios_identified = True
    result.netbios_name = d.get("netbios_name", "") or ""
    result.netbios_workgroup = d.get("netbios_workgroup", "") or ""
    result.netbios_user = d.get("netbios_user", "") or ""
    result.netbios_mac = d.get("netbios_mac", "") or ""
    # NetBIOS 计算机名是 Windows 主机名的权威来源（仅当 DNS 未提供时补全）
    if not result.hostname and result.netbios_name:
        result.hostname = result.netbios_name
    # NetBIOS 也能拿到 MAC（即使 ARP 缺失），优先补全（不覆盖已有）
    if not result.mac and result.netbios_mac:
        result.mac = result.netbios_mac
