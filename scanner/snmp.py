# -*- coding: utf-8 -*-
import random
import re
import socket

from .constants import _SNMP_DEFAULT_COMMUNITIES, _SNMP_GET_OIDS


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


def _snmp_build_getnext(community: str, req_id: int, oids) -> bytes:
    """构造 SNMPv2c GetNextRequest 报文 (PDU tag 0xA1)。"""
    varbinds = b""
    for oid in oids:
        vb = _snmp_enc_oid(oid) + b"\x05\x00"   # value = NULL
        varbinds += b"\x30" + _ber_len(len(vb)) + vb
    vblist = b"\x30" + _ber_len(len(varbinds)) + varbinds
    pdu = _snmp_enc_int(req_id) + _snmp_enc_int(0) + _snmp_enc_int(0) + vblist
    pdu_typed = b"\xa1" + _ber_len(len(pdu)) + pdu        # [1] GetNextRequest-PDU
    msg = _snmp_enc_int(1) + _snmp_enc_str(community) + pdu_typed
    return b"\x30" + _ber_len(len(msg)) + msg


def snmp_walk(ip: str, base_oid: str, community: str = "public",
              timeout: float = 1.0, port: int = 161,
              max_iterations: int = 2000) -> dict:
    """SNMPv2c GETNEXT 遍历指定 OID 子树。

    返回 {oid: (value_bytes, value_tag)} 字典，仅包含 base_oid 下的条目。
    超时 / 出错 / 超出子树 / 达到迭代上限时停止。
    """
    results = {}
    current_oid = base_oid
    prefix = base_oid.rstrip(".") + "."
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for _ in range(max_iterations):
            req_id = random.randint(1, 0x7FFFFFFF)
            packet = _snmp_build_getnext(community, req_id, [current_oid])
            sock.sendto(packet, (ip, port))
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            resp = _snmp_parse_response(data)
            if not resp:
                break
            oid, vbytes, vtag = resp[0]
            # 超出子树或返回 endOfMibView (tag 0x82)
            if not oid.startswith(prefix) or vtag == 0x82:
                break
            results[oid] = (vbytes, vtag)
            current_oid = oid
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return results


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
