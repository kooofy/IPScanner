# -*- coding: utf-8 -*-
"""P1-2 回归测试：ipconfig 解析必须中英文 Windows 通用。

历史缺陷
--------
`scan_mixin._get_local_subnet_windows()` 只用中文正则
（``IPv4[地址\\s]+`` / ``子网掩码``）解析 ipconfig 输出。
在英文 Windows 上两处都匹配不到，于是 ``len(ips) == len(masks)`` 为假，
代码静默退化成"取默认出口 IP 的前三段 + /24"的猜测值 —— 若真实网段不是
/24（例如 /16 的企业网），用户点「扫描本机网段」会扫错范围。

修复
----
解析逻辑统一收敛到 ``scanner.ping.parse_windows_ipconfig()``（中英双语、
按行配对），UI 与引擎共用 ``scanner.ping.windows_ipconfig_subnets()``。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from scanner import ping as ping_mod
from scanner.ping import parse_windows_ipconfig, windows_ipconfig_subnets


# ── ipconfig 真实输出样本 ────────────────────────────────────────────

IPCONFIG_ZH = """\
Windows IP 配置


以太网适配器 以太网:

   连接特定的 DNS 后缀 . . . . . . . :
   本地链接 IPv6 地址. . . . . . . . : fe80::1234:5678:9abc:def0%12
   IPv4 地址 . . . . . . . . . . . . : 192.168.1.100
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.1.1

无线局域网适配器 WLAN:

   媒体状态  . . . . . . . . . . . . : 媒体已断开连接
   连接特定的 DNS 后缀 . . . . . . . :
"""

IPCONFIG_EN = """\
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::1234:5678:9abc:def0%12
   IPv4 Address. . . . . . . . . . . : 10.20.30.40
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.20.0.1

Wireless LAN adapter Wi-Fi:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
"""

# 英文 Windows + 多网卡：虚拟网卡在前，真实网卡在后
IPCONFIG_EN_MULTI = """\
Windows IP Configuration


Ethernet adapter vEthernet (Default Switch):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::aaaa:bbbb:cccc:dddd%60
   IPv4 Address. . . . . . . . . . . : 172.17.0.1
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : corp.example.com
   IPv4 Address. . . . . . . . . . . : 10.5.6.7
   Subnet Mask . . . . . . . . . . . : 255.255.248.0
   Default Gateway . . . . . . . . . : 10.5.0.1
"""

# 只有一个 IPv4 地址行、没有掩码行（异常/截断输出）
IPCONFIG_EN_NO_MASK = """\
Windows IP Configuration


Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 192.168.50.20
"""


class ParseWindowsIpconfigTest(unittest.TestCase):
    """parse_windows_ipconfig() 的双语解析能力。"""

    def test_chinese_output(self):
        self.assertEqual(
            parse_windows_ipconfig(IPCONFIG_ZH),
            [("192.168.1.100", "255.255.255.0")],
        )

    def test_english_output(self):
        """核心回归：英文 Windows 必须能解析出 IP + 掩码。"""
        self.assertEqual(
            parse_windows_ipconfig(IPCONFIG_EN),
            [("10.20.30.40", "255.255.0.0")],
        )

    def test_english_multiple_adapters_keep_order(self):
        pairs = parse_windows_ipconfig(IPCONFIG_EN_MULTI)
        self.assertEqual(
            pairs,
            [("172.17.0.1", "255.255.0.0"), ("10.5.6.7", "255.255.248.0")],
        )

    def test_ip_without_mask_is_dropped(self):
        """未配成对的 IP 必须丢弃，绝不能拿去和别的网卡掩码错位配对。"""
        self.assertEqual(parse_windows_ipconfig(IPCONFIG_EN_NO_MASK), [])

    def test_second_ip_overwrites_unpaired_first(self):
        """连续两个 IP 行（前一个没有掩码）时，只保留后一个的配对。"""
        text = (
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.5\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.6\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
        )
        self.assertEqual(
            parse_windows_ipconfig(text), [("192.168.1.6", "255.255.255.0")]
        )

    def test_ipv6_lines_are_ignored(self):
        """IPv6 地址行不能被误当作 IPv4。"""
        text = (
            "   Link-local IPv6 Address . . . . . : fe80::1%12\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.9\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
        )
        self.assertEqual(
            parse_windows_ipconfig(text), [("192.168.1.9", "255.255.255.0")]
        )

    def test_gateway_ip_is_not_mistaken_for_interface_ip(self):
        """默认网关行出现在掩码之后，不应产生额外的配对。"""
        pairs = parse_windows_ipconfig(IPCONFIG_EN)
        self.assertNotIn("10.20.0.1", [ip for ip, _ in pairs])

    def test_empty_and_none_input(self):
        self.assertEqual(parse_windows_ipconfig(""), [])
        self.assertEqual(parse_windows_ipconfig(None), [])

    def test_gbk_mojibake_still_matches_english_keywords(self):
        """GBK 误码（例如以 utf-8 解码 GBK 输出）下英文关键词仍可命中。"""
        text = (
            "   IPv4 Address. . . . . . . . . . . : 192.168.7.7\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.128\n"
        )
        self.assertEqual(
            parse_windows_ipconfig(text), [("192.168.7.7", "255.255.255.128")]
        )


class WindowsIpconfigSubnetsTest(unittest.TestCase):
    """windows_ipconfig_subnets() 的平台判断与命令调用。"""

    def setUp(self):
        self._orig_is_windows = ping_mod._IS_WINDOWS
        self._orig_run_cmd = ping_mod._run_cmd

    def tearDown(self):
        ping_mod._IS_WINDOWS = self._orig_is_windows
        ping_mod._run_cmd = self._orig_run_cmd

    def test_returns_empty_on_non_windows(self):
        """非 Windows 平台不应尝试执行 ipconfig。"""
        called = []
        ping_mod._IS_WINDOWS = False
        ping_mod._run_cmd = lambda *a, **k: called.append(a) or ""

        self.assertEqual(windows_ipconfig_subnets(), [])
        self.assertEqual(called, [])

    def test_parses_command_output_on_windows(self):
        ping_mod._IS_WINDOWS = True
        ping_mod._run_cmd = lambda *a, **k: IPCONFIG_EN

        self.assertEqual(
            windows_ipconfig_subnets(), [("10.20.30.40", "255.255.0.0")]
        )

    def test_empty_when_command_fails(self):
        ping_mod._IS_WINDOWS = True
        ping_mod._run_cmd = lambda *a, **k: ""

        self.assertEqual(windows_ipconfig_subnets(), [])


class ScanMixinLocalSubnetTest(unittest.TestCase):
    """scan_mixin._get_local_subnet_windows() 端到端行为。

    重点：英文 Windows 上必须得到**真实前缀长度**，而不是 /24 兜底猜测。
    """

    @classmethod
    def setUpClass(cls):
        from scan_mixin import ScanMixin

        cls.ScanMixin = ScanMixin

    def _probe(self, pairs, default_ip):
        """构造一个只覆盖外部依赖的探针对象。"""

        class _Probe(self.ScanMixin):
            def _get_default_local_ip(self_inner):
                return default_ip

        import scan_mixin as sm

        orig = sm.windows_ipconfig_subnets
        sm.windows_ipconfig_subnets = lambda: pairs
        try:
            return _Probe()._get_local_subnet_windows()
        finally:
            sm.windows_ipconfig_subnets = orig

    def test_english_windows_uses_real_prefix_not_slash24(self):
        """回归：英文输出 + /16 网段 → 必须返回 /16，而不是 /24 猜测。"""
        pairs = parse_windows_ipconfig(IPCONFIG_EN)
        self.assertEqual(self._probe(pairs, "10.20.30.40"), "10.20.0.0/16")

    def test_chinese_windows_unchanged(self):
        pairs = parse_windows_ipconfig(IPCONFIG_ZH)
        self.assertEqual(self._probe(pairs, "192.168.1.100"), "192.168.1.0/24")

    def test_prefers_default_route_adapter(self):
        """多网卡时优先取默认出口 IP 所在网卡，跳过虚拟网卡。"""
        pairs = parse_windows_ipconfig(IPCONFIG_EN_MULTI)
        self.assertEqual(self._probe(pairs, "10.5.6.7"), "10.5.0.0/21")

    def test_skips_virtual_adapter_when_no_default_ip(self):
        """拿不到默认出口 IP 时，跳过 172.16/12 虚拟网卡取真实网卡。"""
        pairs = parse_windows_ipconfig(IPCONFIG_EN_MULTI)
        self.assertEqual(self._probe(pairs, None), "10.5.0.0/21")

    def test_falls_back_to_slash24_without_pairs(self):
        """完全解析不出掩码时才退化为 /24 猜测（保留原有兜底行为）。"""
        self.assertEqual(self._probe([], "192.168.3.77"), "192.168.3.0/24")

    def test_returns_none_without_any_info(self):
        self.assertIsNone(self._probe([], None))


if __name__ == "__main__":
    unittest.main()
