# -*- coding: utf-8 -*-
"""NetBIOS 轻量识别单元测试：请求构造 / 响应解析 / 合并 / 错误路径。"""
import struct
import unittest

from scanner.netbios import (
    _build_nbstat_request, _parse_nbstat_response, _encode_nbname,
    netbios_query, merge_netbios,
)
from scanner.models import ScanResult
from scanner import netbios_query as _api_netbios_query, merge_netbios as _api_merge


def _build_sample_response(comp_name, workgroup, user, mac_bytes):
    """构造一个合法的 NBSTAT 节点状态响应包，用于验证解析逻辑。"""
    pkt = bytearray()
    pkt += struct.pack(">H", 0x1234)   # TID
    pkt += struct.pack(">H", 0x8000)   # Flags: response
    pkt += struct.pack(">H", 1)        # QDCOUNT
    pkt += struct.pack(">H", 1)        # ANCOUNT
    pkt += struct.pack(">H", 0)        # NSCOUNT
    pkt += struct.pack(">H", 0)        # ARCOUNT
    # Question（回显）：0x20 + 32 字节编码名 + QTYPE + QCLASS
    pkt += bytes([0x20]) + _encode_nbname(b"*" + b" " * 15)
    pkt += struct.pack(">H", 0x0021)
    pkt += struct.pack(">H", 0x0001)
    # Answer：压缩指针 0xC00C
    pkt += struct.pack(">H", 0xC00C)
    pkt += struct.pack(">H", 0x0021)   # TYPE = NBSTAT
    pkt += struct.pack(">H", 0x0001)   # CLASS = IN
    pkt += struct.pack(">I", 0)        # TTL
    # RDATA： names + 统计块
    names = []

    def _add(n15, ntype, group):
        name16 = n15.ljust(15, " ")[:15].encode("latin-1") + bytes([ntype])
        names.append((name16, 0x80 if group else 0x00))

    _add(comp_name, 0x00, False)       # 计算机名（唯一）
    _add(workgroup, 0x00, True)        # 工作组（组）
    if user:
        _add(user, 0x03, False)        # 当前登录用户（唯一）
    rdata = bytearray()
    rdata += struct.pack(">H", len(names))
    for name16, flags in names:
        rdata += name16
        rdata += bytes([name16[15]])    # ntype（与 name16[15] 一致）
        rdata += bytes([flags])
    rdata += mac_bytes + b"\x00" * 40   # 统计块：6 MAC + 40
    pkt += struct.pack(">H", len(rdata))
    pkt += rdata
    return bytes(pkt)


class TestNetbiosRequest(unittest.TestCase):
    def test_request_packet_shape(self):
        pkt = _build_nbstat_request()
        # 12 头 + 1 长度 + 32 名 + 2 QTYPE + 2 QCLASS = 49
        self.assertEqual(len(pkt), 49)
        # "*" -> 0x2A -> "CK"，空格 -> 0x20 -> "CA"
        enc = _encode_nbname(b"*" + b" " * 15)
        self.assertTrue(enc.startswith(b"CK"))
        self.assertTrue(enc.endswith(b"CA"))


class TestNetbiosParse(unittest.TestCase):
    def test_parse_full(self):
        mac = bytes([0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22])
        data = _build_sample_response("PC-Alice", "WORKGROUP", "alice", mac)
        d = _parse_nbstat_response(data, "10.0.0.5")
        self.assertTrue(d["netbios_identified"])
        self.assertEqual(d["netbios_name"], "PC-Alice")
        self.assertEqual(d["netbios_workgroup"], "WORKGROUP")
        self.assertEqual(d["netbios_user"], "alice")
        self.assertEqual(d["netbios_mac"], "AA:BB:CC:00:11:22")
        self.assertEqual(d["netbios_error"], "")

    def test_parse_no_user(self):
        """未注册 <03> 名时，当前用户应为空。"""
        mac = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        data = _build_sample_response("SRV01", "DOMAIN", None, mac)
        d = _parse_nbstat_response(data, "10.0.0.9")
        self.assertTrue(d["netbios_identified"])
        self.assertEqual(d["netbios_name"], "SRV01")
        self.assertEqual(d["netbios_workgroup"], "DOMAIN")
        self.assertEqual(d["netbios_user"], "")

    def test_parse_user_same_as_compname_ignored(self):
        """<03> 名与计算机名相同视为无独立用户。"""
        mac = bytes(6)
        data = _build_sample_response("HOST", "WG", "HOST", mac)
        d = _parse_nbstat_response(data, "10.0.0.3")
        self.assertEqual(d["netbios_user"], "")

    def test_parse_short_packet(self):
        d = _parse_nbstat_response(b"\x00\x00", "1.2.3.4")
        self.assertFalse(d["netbios_identified"])
        self.assertIn("netbios_error", d)


class TestMergeNetbios(unittest.TestCase):
    def test_merge_success(self):
        r = ScanResult(ip="10.0.0.5")
        merge_netbios(r, {
            "netbios_name": "PC-Alice", "netbios_workgroup": "WORKGROUP",
            "netbios_user": "alice", "netbios_mac": "AA:BB:CC:00:11:22",
            "netbios_identified": True,
        })
        self.assertTrue(r.netbios_identified)
        self.assertEqual(r.netbios_name, "PC-Alice")
        # 补全：无 DNS 主机名时用 NetBIOS 计算机名；无 MAC 时补 MAC
        self.assertEqual(r.hostname, "PC-Alice")
        self.assertEqual(r.mac, "AA:BB:CC:00:11:22")

    def test_merge_error(self):
        r = ScanResult(ip="10.0.0.6")
        merge_netbios(r, {"netbios_error": "UDP/137 超时"})
        self.assertFalse(r.netbios_identified)
        self.assertEqual(r.netbios_error, "UDP/137 超时")

    def test_merge_keeps_existing_hostname(self):
        r = ScanResult(ip="10.0.0.7", hostname="existing.example")
        merge_netbios(r, {"netbios_name": "PC-X", "netbios_identified": True})
        self.assertEqual(r.hostname, "existing.example")


class TestScanResultDefaults(unittest.TestCase):
    def test_defaults(self):
        r = ScanResult(ip="10.0.0.8")
        self.assertFalse(r.netbios_identified)
        self.assertEqual(r.netbios_name, "")
        self.assertEqual(r.netbios_workgroup, "")
        self.assertEqual(r.netbios_user, "")
        self.assertEqual(r.netbios_mac, "")
        self.assertEqual(r.netbios_error, "")


class TestNetbiosQueryLive(unittest.TestCase):
    def test_query_localhost_returns_dict(self):
        """对无 NetBIOS 监听的回环地址查询，应返回 dict 且不抛异常。"""
        d = netbios_query("127.0.0.1", timeout=0.5)
        self.assertIsInstance(d, dict)
        self.assertIn("netbios_error", d)

    def test_query_unreachable_returns_error(self):
        d = netbios_query("10.255.255.254", timeout=0.3)
        self.assertIsInstance(d, dict)
        self.assertTrue(d["netbios_error"])


class TestApiExport(unittest.TestCase):
    def test_public_api_present(self):
        self.assertTrue(callable(_api_netbios_query))
        self.assertTrue(callable(_api_merge))


if __name__ == "__main__":
    unittest.main(verbosity=2)
