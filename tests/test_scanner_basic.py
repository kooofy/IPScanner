# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import parse_ip_range, ScanResult
from scanner.dns import _parse_dns_name
from ui_utils import _is_valid_ip


class TestParseIpRange(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_ip_range("192.168.1.1"), ["192.168.1.1"])

    def test_short_range(self):
        self.assertEqual(parse_ip_range("192.168.1.1-3"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_full_range(self):
        self.assertEqual(parse_ip_range("192.168.1.1-192.168.1.3"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_cidr(self):
        self.assertEqual(parse_ip_range("192.168.1.0/30"),
                         ["192.168.1.1", "192.168.1.2"])

    def test_cidr_24_count(self):
        self.assertEqual(len(parse_ip_range("192.168.1.0/24")), 254)

    def test_empty(self):
        self.assertEqual(parse_ip_range(""), [])

    def test_invalid(self):
        self.assertEqual(parse_ip_range("not an ip"), [])


class TestScanResult(unittest.TestCase):
    def test_construct_and_todict(self):
        r = ScanResult(ip="10.0.0.5", status="online")
        d = r.to_dict()
        self.assertEqual(d["IP地址"], "10.0.0.5")
        self.assertEqual(d["状态"], "在线")

    def test_defaults(self):
        r = ScanResult()
        self.assertEqual(r.status, "offline")
        self.assertEqual(r.open_ports, [])


class TestDnsName(unittest.TestCase):
    def test_normal(self):
        # foo.bar\0 占 index 0..8，终止符在 8，返回位置为终止符之后(9)
        data = bytes([3]) + b"foo" + bytes([3]) + b"bar" + bytes([0])
        name, pos = _parse_dns_name(data, 0)
        self.assertEqual(name, "foo.bar")
        self.assertEqual(pos, 9)

    def test_compression_pointer(self):
        # foo.bar\0 占 index 0..8；指针 0xC0 0x00 在 index 9..10 指向 0
        data = bytes([3]) + b"foo" + bytes([3]) + b"bar" + bytes([0]) + b"\xC0\x00"
        name, pos = _parse_dns_name(data, 9)
        self.assertEqual(name, "foo.bar")
        self.assertEqual(pos, 11)

    def test_cyclic_pointer_no_infinite_recursion(self):
        # A->B->A 循环压缩指针，必须安全终止而非无限递归
        data = b"\xC0\x02\xC0\x00"
        result = _parse_dns_name(data, 0)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


class TestIsValidIp(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(_is_valid_ip("192.168.1.1"))
        self.assertTrue(_is_valid_ip("0.0.0.0"))

    def test_invalid(self):
        self.assertFalse(_is_valid_ip("256.1.1.1"))
        self.assertFalse(_is_valid_ip("1.2.3"))
        self.assertFalse(_is_valid_ip("a.b.c.d"))
        self.assertFalse(_is_valid_ip("1.2.3.4.5"))


if __name__ == "__main__":
    unittest.main()
