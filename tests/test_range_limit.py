# -*- coding: utf-8 -*-
"""IP 范围规模上限测试（P0-2）。

核心回归点：`0.0.0.0/0` 这类超大范围必须在**构建列表之前**被拒绝，
而不是先 append 出 42.9 亿个字符串把进程撑爆。
"""
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner.range import (
    parse_ip_range, count_ip_range, is_valid_range, is_ipv6_range,
    RangeTooLarge, MAX_IPS_PER_RANGE, MAX_IPS_TOTAL,
)


class CountIpRangeTest(unittest.TestCase):

    def test_counts(self):
        self.assertEqual(count_ip_range("192.168.1.1"), 1)
        self.assertEqual(count_ip_range("192.168.1.0/24"), 254)
        self.assertEqual(count_ip_range("192.168.1.0/30"), 2)
        self.assertEqual(count_ip_range("192.168.1.0/31"), 2)
        self.assertEqual(count_ip_range("192.168.1.1/32"), 1)
        self.assertEqual(count_ip_range("192.168.1.1-3"), 3)
        self.assertEqual(count_ip_range("192.168.1.1-192.168.1.254"), 254)

    def test_invalid_returns_zero(self):
        for bad in ("", "   ", "not an ip", "192.168.1.0/33", "1.2.3.4-", "abc/24"):
            self.assertEqual(count_ip_range(bad), 0, msg=bad)

    def test_count_matches_parse(self):
        for spec in ("10.0.0.1", "10.0.0.0/28", "10.0.0.1-20", "10.0.0.0/31"):
            self.assertEqual(count_ip_range(spec), len(parse_ip_range(spec)), msg=spec)

    def test_reversed_range_count(self):
        """start > end 时自动交换，计数与解析一致。"""
        self.assertEqual(count_ip_range("10.0.0.9-1"), 9)
        self.assertEqual(len(parse_ip_range("10.0.0.9-1")), 9)


class RangeLimitTest(unittest.TestCase):

    def test_oversized_cidr_raises_fast(self):
        """0.0.0.0/0 必须立即抛异常（不构建列表），且耗时可忽略。"""
        t0 = time.monotonic()
        with self.assertRaises(RangeTooLarge) as ctx:
            parse_ip_range("0.0.0.0/0")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(ctx.exception.range_str, "0.0.0.0/0")
        self.assertEqual(ctx.exception.count, 2 ** 32 - 2)
        self.assertEqual(ctx.exception.limit, MAX_IPS_PER_RANGE)

    def test_private_slash8_raises(self):
        """10.0.0.0/8 是企业网常见误输入，同样必须拦下。"""
        with self.assertRaises(RangeTooLarge):
            parse_ip_range("10.0.0.0/8")

    def test_slash16_is_allowed(self):
        """/16（65534 个可用 IP）正好在上限内，应当放行。"""
        self.assertEqual(count_ip_range("10.0.0.0/16"), 65534)
        self.assertLessEqual(65534, MAX_IPS_PER_RANGE)
        ips = parse_ip_range("10.0.0.0/16")
        self.assertEqual(len(ips), 65534)
        self.assertEqual(ips[0], "10.0.0.1")
        self.assertEqual(ips[-1], "10.0.255.254")

    def test_slash15_is_rejected(self):
        with self.assertRaises(RangeTooLarge):
            parse_ip_range("10.0.0.0/15")

    def test_huge_ip_range_rejected(self):
        """1.0.0.0-255.255.255.254 这类范围写法同样受保护。"""
        with self.assertRaises(RangeTooLarge):
            parse_ip_range("1.0.0.0-255.255.255.254")

    def test_unlimited_mode_still_available(self):
        """max_ips=None 保留无限制模式，供测试/内部调用。"""
        self.assertEqual(len(parse_ip_range("10.0.0.0/30", max_ips=None)), 2)

    def test_error_message_is_readable(self):
        try:
            parse_ip_range("172.16.0.0/12")
        except RangeTooLarge as e:
            self.assertIn("172.16.0.0/12", str(e))
            self.assertIn(str(MAX_IPS_PER_RANGE), str(e))
        else:
            self.fail("应当抛出 RangeTooLarge")

    def test_total_cap_not_greater_than_per_range(self):
        """总量上限不应小于单范围上限，否则 /16 永远无法通过。"""
        self.assertGreaterEqual(MAX_IPS_TOTAL, MAX_IPS_PER_RANGE)


class IsValidRangeTest(unittest.TestCase):

    def test_valid(self):
        for s in ("192.168.1.1", "192.168.1.0/24", "192.168.1.1-254",
                  "192.168.1.1-192.168.1.9", "10.0.0.0/8"):
            self.assertTrue(is_valid_range(s), msg=s)

    def test_invalid(self):
        for s in ("", "hello", "192.168.1.0/33", "999.1.1.1"):
            self.assertFalse(is_valid_range(s), msg=s)

    def test_oversized_is_still_valid_syntax(self):
        """语法合法但规模超限 —— 校验与规模是两个独立维度。"""
        self.assertTrue(is_valid_range("0.0.0.0/0"))
        self.assertGreater(count_ip_range("0.0.0.0/0"), MAX_IPS_PER_RANGE)


class BackwardCompatibilityTest(unittest.TestCase):
    """既有行为不得回归（对照 tests/test_scanner_basic.py 的既有断言）。"""

    def test_existing_expectations(self):
        self.assertEqual(parse_ip_range("192.168.1.1"), ["192.168.1.1"])
        self.assertEqual(parse_ip_range("192.168.1.1-3"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])
        self.assertEqual(parse_ip_range("192.168.1.1-192.168.1.3"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])
        self.assertEqual(parse_ip_range("192.168.1.0/30"),
                         ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(len(parse_ip_range("192.168.1.0/24")), 254)
        self.assertEqual(parse_ip_range(""), [])
        self.assertEqual(parse_ip_range("not an ip"), [])


class Ipv6RejectionTest(unittest.TestCase):
    """IPv6 必须被**显式拒绝** —— 本工具只支持 IPv4。

    历史缺陷：`ipaddress.ip_network("2001:db8::/120")` 语法完全合法，会被正常
    解析并产出一串 IPv6 地址；但下游 ARP/SendARP、NetBIOS、WMI、SNMP 全部
    假设 IPv4，用户最终拿到一张"全部离线"的假结果表，且没有任何报错。
    """

    def test_ipv6_cidr_is_rejected(self):
        self.assertFalse(is_valid_range("2001:db8::/120"))
        self.assertEqual(count_ip_range("2001:db8::/120"), 0)
        self.assertEqual(parse_ip_range("2001:db8::/120"), [])

    def test_ipv6_single_is_rejected(self):
        for s in ("::1", "fe80::1", "2001:db8::1"):
            self.assertFalse(is_valid_range(s), msg=s)
            self.assertEqual(count_ip_range(s), 0, msg=s)
            self.assertEqual(parse_ip_range(s), [], msg=s)

    def test_ipv6_range_is_rejected(self):
        self.assertFalse(is_valid_range("2001:db8::1-2001:db8::ff"))
        self.assertEqual(count_ip_range("2001:db8::1-2001:db8::ff"), 0)

    def test_is_ipv6_range_distinguishes_from_garbage(self):
        """上层要靠它把"不支持 IPv6"和"格式写错了"分开提示。"""
        for s in ("::1", "fe80::1", "2001:db8::/120", "2001:db8::1-2001:db8::ff"):
            self.assertTrue(is_ipv6_range(s), msg=s)
        for s in ("", "hello", "192.168.1.0/33", "999.1.1.1", "192.168.1.1-",
                  "192.168.1.1", "192.168.1.0/24", "192.168.1.1-254"):
            self.assertFalse(is_ipv6_range(s), msg=s)

    def test_ipv4_is_not_affected(self):
        """版本闸门不能误伤 IPv4。"""
        self.assertTrue(is_valid_range("192.168.1.0/24"))
        self.assertTrue(is_valid_range("10.0.0.1-20"))
        self.assertTrue(is_valid_range("172.16.0.1"))
        self.assertEqual(parse_ip_range("192.168.1.0/30"),
                         ["192.168.1.1", "192.168.1.2"])


if __name__ == "__main__":
    unittest.main()
