# -*- coding: utf-8 -*-
"""SNMP ARP 表解析（`scanner/arp_mib.py`）测试。

只测**纯解析**：喂构造好的 walk 结果，断言 ``{ip: mac}``。不碰网络、
不依赖真实设备 —— 这正是把解析拆成独立模块的意义。

覆盖点，按重要性排序：
1. **RFC 1213 的索引后缀自带 IP** —— 这是"一次 walk 就够"的全部依据，算错就全错；
2. **全零 MAC 必须被丢掉** —— 收下来会让一堆设备在台账里撞成同一个身份键；
3. 两条 MIB 的回退顺序（1213 优先，取不到才 4293）；
4. ifIndex 位数变化时不错位（1 位和 5 位都要算对）。

断言一律与语言无关：只比 IP / MAC / 计数。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import arp_mib  # noqa: E402

_MEDIA = arp_mib.OID_NET_TO_MEDIA_PHYS
_PHYS = arp_mib.OID_NET_TO_PHYSICAL_PHYS
_MAC1 = bytes.fromhex("aabbcc112233")
_MAC2 = bytes.fromhex("deadbeef0001")


def _entry(vbytes, tag=0x04):
    return (vbytes, tag)


class MacFromOctetsTest(unittest.TestCase):
    """6 字节 → MAC 字符串，以及"不可用 MAC"的判定。"""

    def test_formats_lowercase_colon(self):
        self.assertEqual(arp_mib.mac_from_octets(_MAC1), "aa:bb:cc:11:22:33")

    def test_all_zero_is_rejected(self):
        """🔴 全零是"表项无效"的常见写法，绝不能当成一个真 MAC 收下来。"""
        self.assertEqual(arp_mib.mac_from_octets(b"\x00" * 6), "")

    def test_wrong_length_is_rejected(self):
        self.assertEqual(arp_mib.mac_from_octets(b"\xaa\xbb\xcc"), "")
        self.assertEqual(arp_mib.mac_from_octets(b"\xaa" * 8), "")
        self.assertEqual(arp_mib.mac_from_octets(b""), "")

    def test_is_usable_mac(self):
        self.assertTrue(arp_mib.is_usable_mac("aa:bb:cc:11:22:33"))
        self.assertTrue(arp_mib.is_usable_mac("AA-BB-CC-11-22-33"))
        self.assertFalse(arp_mib.is_usable_mac(""))
        self.assertFalse(arp_mib.is_usable_mac("00:00:00:00:00:00"))
        self.assertFalse(arp_mib.is_usable_mac("aa:bb:cc"))
        # 段长度不对（多一位 / 少一位）同样不可用
        self.assertFalse(arp_mib.is_usable_mac("aaa:bb:cc:11:22:33"))


class SuffixToIpTest(unittest.TestCase):
    """OID 索引后缀 → IP。**整个"一次 walk 就够"的设计都压在这上面。**"""

    def test_rfc1213_plain(self):
        self.assertEqual(arp_mib._suffix_to_ip_v1213("1.10.193.24.12"),
                         "10.193.24.12")

    def test_rfc1213_wide_ifindex_does_not_shift(self):
        """ifIndex 是 5 位数时，按"最后 4 段"取才不会被挤错位。"""
        self.assertEqual(arp_mib._suffix_to_ip_v1213("10001.192.168.1.1"),
                         "192.168.1.1")

    def test_rfc1213_rejects_short_and_out_of_range(self):
        self.assertEqual(arp_mib._suffix_to_ip_v1213("1.10.193.24"), "")
        self.assertEqual(arp_mib._suffix_to_ip_v1213(""), "")
        self.assertEqual(arp_mib._suffix_to_ip_v1213("1.10.193.24.300"), "")
        self.assertEqual(arp_mib._suffix_to_ip_v1213("1.a.b.c.d"), "")

    def test_rfc4293_plain(self):
        self.assertEqual(arp_mib._suffix_to_ip_v4293("101.1.4.10.193.24.12.1"),
                         "10.193.24.12")

    def test_rfc4293_wide_ifindex_does_not_shift(self):
        self.assertEqual(arp_mib._suffix_to_ip_v4293("10001.1.4.192.168.1.1.1"),
                         "192.168.1.1")

    def test_rfc4293_ignores_non_ipv4_address_types(self):
        """addrType=2 是 IPv6 —— 本模块只认 IPv4，不能把它的字节当 IP 读。"""
        self.assertEqual(
            arp_mib._suffix_to_ip_v4293("101.2.16.32.1.13.184.0.0.0.0.1.1"), "")

    def test_rfc4293_tolerates_non_numeric_segments(self):
        """候选位置上是非数字（畸形 OID）→ 跳过该位置，继续往后扫，不抛异常。

        扫描是**逐位置**的：`1.1.4.` 这个形状恰好也可能出现在 IP 字节里，
        所以在某个位置解不出数字是正常情况，不能就此放弃整条后缀。
        """
        self.assertEqual(
            arp_mib._suffix_to_ip_v4293("101.1.4.x.193.24.12.1"), "")
        # 前面有个假匹配、后面才是真的 —— 必须继续扫到真的那个
        self.assertEqual(
            arp_mib._suffix_to_ip_v4293("7.1.4.x.9.9.9.1.101.1.4.10.193.24.12.1"),
            "10.193.24.12")

    def test_rfc4293_short_suffix_is_safe(self):
        self.assertEqual(arp_mib._suffix_to_ip_v4293("1.1.4"), "")
        self.assertEqual(arp_mib._suffix_to_ip_v4293(""), "")


class ParseTableTest(unittest.TestCase):
    """整张表的解析：过滤规则 + 结果形状。"""

    def test_rfc1213_parses_and_filters(self):
        raw = {
            f"{_MEDIA}.101.10.193.24.12": _entry(_MAC1),
            f"{_MEDIA}.101.10.193.24.13": _entry(_MAC2),
            # 全零 MAC：必须丢掉
            f"{_MEDIA}.102.10.193.24.99": _entry(b"\x00" * 6),
            # 值不是 OCTET STRING（比如 INTEGER）：跳过
            f"{_MEDIA}.102.10.193.24.98": _entry(b"\x01", tag=0x02),
            # 不在子树里：跳过
            "1.3.6.1.2.1.4.22.1.3.101.10.193.24.12": _entry(b"\x0a\xc1\x18\x0c"),
        }
        table = arp_mib.parse_net_to_media(raw)
        self.assertEqual(table, {"10.193.24.12": "aa:bb:cc:11:22:33",
                                 "10.193.24.13": "de:ad:be:ef:00:01"})

    def test_rfc4293_parses(self):
        raw = {
            f"{_PHYS}.101.1.4.10.193.24.12.1": _entry(_MAC1),
            f"{_PHYS}.101.1.4.10.193.24.13.1": _entry(_MAC2),
        }
        self.assertEqual(arp_mib.parse_net_to_physical(raw),
                         {"10.193.24.12": "aa:bb:cc:11:22:33",
                          "10.193.24.13": "de:ad:be:ef:00:01"})

    def test_empty_and_none_are_safe(self):
        self.assertEqual(arp_mib.parse_net_to_media({}), {})
        self.assertEqual(arp_mib.parse_net_to_media(None), {})
        self.assertEqual(arp_mib.parse_net_to_physical(None), {})

    def test_malformed_values_are_skipped_not_raised(self):
        """值不是 ``(字节, tag)`` 二元组时只跳过那一条 —— 不能整表炸掉。

        SNMP 库换实现 / 返回形状变了都可能走到这里；此时"少几条"远好过
        "读表直接失败"（后者会让整次扫描的 MAC 补齐全空）。
        """
        raw = {
            f"{_MEDIA}.101.10.193.24.12": _entry(_MAC1),
            f"{_MEDIA}.101.10.193.24.13": b"\xaa\xbb\xcc\xdd\xee\xff",  # 裸 bytes
            f"{_MEDIA}.101.10.193.24.14": None,
            f"{_MEDIA}.101.10.193.24.15": (_MAC1, 0x04, "extra"),        # 三元组
        }
        self.assertEqual(arp_mib.parse_net_to_media(raw),
                         {"10.193.24.12": "aa:bb:cc:11:22:33"})


class WalkArpTableTest(unittest.TestCase):
    """回退顺序：RFC 1213 优先，取不到才试 RFC 4293。"""

    def _walker(self, per_oid):
        calls = []

        def _walk(base_oid, max_iterations):
            calls.append(base_oid)
            return per_oid.get(base_oid, {})

        return _walk, calls

    def test_prefers_rfc1213_and_does_not_probe_the_other(self):
        walk, calls = self._walker({
            _MEDIA: {f"{_MEDIA}.101.10.193.24.12": _entry(_MAC1)},
            _PHYS: {f"{_PHYS}.101.1.4.10.193.24.12.1": _entry(_MAC1)},
        })
        table, source = arp_mib.walk_arp_table(walk)
        self.assertEqual(table, {"10.193.24.12": "aa:bb:cc:11:22:33"})
        self.assertEqual(source, arp_mib.SOURCE_NET_TO_MEDIA)
        self.assertEqual(calls, [_MEDIA], "1213 已命中却还去走了 4293")

    def test_falls_back_to_rfc4293(self):
        walk, calls = self._walker({
            _PHYS: {f"{_PHYS}.101.1.4.10.193.24.12.1": _entry(_MAC1)},
        })
        table, source = arp_mib.walk_arp_table(walk)
        self.assertEqual(table, {"10.193.24.12": "aa:bb:cc:11:22:33"})
        self.assertEqual(source, arp_mib.SOURCE_NET_TO_PHYSICAL)
        self.assertEqual(calls, [_MEDIA, _PHYS])

    def test_both_empty_reports_no_source(self):
        walk, calls = self._walker({})
        table, source = arp_mib.walk_arp_table(walk)
        self.assertEqual(table, {})
        self.assertEqual(source, "")
        self.assertEqual(calls, [_MEDIA, _PHYS])

    def test_table_with_only_unusable_entries_still_falls_back(self):
        """整张表全是全零 MAC = 没拿到东西，必须继续试下一条 MIB。"""
        walk, calls = self._walker({
            _MEDIA: {f"{_MEDIA}.101.10.193.24.12": _entry(b"\x00" * 6)},
            _PHYS: {f"{_PHYS}.101.1.4.10.193.24.12.1": _entry(_MAC1)},
        })
        table, source = arp_mib.walk_arp_table(walk)
        self.assertEqual(table, {"10.193.24.12": "aa:bb:cc:11:22:33"})
        self.assertEqual(source, arp_mib.SOURCE_NET_TO_PHYSICAL)
        self.assertEqual(calls, [_MEDIA, _PHYS])

    def test_max_iterations_is_forwarded(self):
        seen = {}

        def _walk(base_oid, max_iterations):
            seen["max_iterations"] = max_iterations
            return {}

        arp_mib.walk_arp_table(_walk, max_iterations=123)
        self.assertEqual(seen["max_iterations"], 123)

    def test_default_iteration_cap_is_large_enough(self):
        """默认上限必须够大：核心交换机 ARP 表能到几千条，
        截断会静默变成"只有前半张表"，比报错更难发现。"""
        self.assertGreaterEqual(arp_mib.DEFAULT_MAX_ITERATIONS, 8000)


if __name__ == "__main__":
    unittest.main()
