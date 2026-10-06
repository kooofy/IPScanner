# -*- coding: utf-8 -*-
"""原生 ICMP 存活探测的回归测试。

背景
----
旧实现每个 IP 起一个 ``ping`` 子进程：/24 是 254 次进程创建，/16（本项目
上限）是 65536 次。Windows 上单次进程创建约 10~20ms，这部分开销往往比真正的
网络等待还大 —— 这是与 Advanced IP Scanner / nmap 最主要的体感差距。

本文件锁死三件事：
1. 两条路径（原生 / 子进程）返回**结构完全一致**的三元组 —— TTL 是 OS 指纹的
   输入，字段错位或丢失会让识别率静默下降；
2. ICMP 校验和正确 —— 算错的表现是"永远收不到回包"，极难定位；
3. 原生不可用时能干净回退，功能不降级。
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import ping as P
from scanner.util import _inet_checksum

_IS_WINDOWS = sys.platform == "win32"


class IcmpPacketTest(unittest.TestCase):
    """ICMP Echo Request 构造（纯函数，任何平台都能跑）。"""

    def test_header_layout(self):
        payload = b"hello"
        pkt = P._build_icmp_echo_request(0x1234, 7, payload)
        self.assertEqual(len(pkt), 8 + len(payload))
        self.assertEqual(pkt[0], 8, "type 必须是 8 (Echo Request)")
        self.assertEqual(pkt[1], 0, "code 必须是 0")
        ident, seq = struct.unpack("!HH", pkt[4:8])
        self.assertEqual(ident, 0x1234)
        self.assertEqual(seq, 7)
        self.assertEqual(pkt[8:], payload)

    def test_checksum_is_valid(self):
        """校验和正确的报文，整体再算一次校验和应为 0。"""
        for payload in (b"", b"x", b"ipscanner-ping", bytes(range(32))):
            pkt = P._build_icmp_echo_request(1, 1, payload)
            self.assertEqual(_inet_checksum(pkt), 0, msg=repr(payload))

    def test_checksum_survives_odd_length_payload(self):
        """奇数长度载荷要在校验和里补零 —— 经典 off-by-one 位置。"""
        for n in (1, 3, 5, 7, 9):
            pkt = P._build_icmp_echo_request(2, 2, b"a" * n)
            self.assertEqual(_inet_checksum(pkt), 0, msg=f"len={n}")

    def test_ident_and_seq_are_masked_to_16_bits(self):
        pkt = P._build_icmp_echo_request(0x1_FFFF, 0x2_0001, b"")
        ident, seq = struct.unpack("!HH", pkt[4:8])
        self.assertEqual(ident, 0xFFFF)
        self.assertEqual(seq, 1)


class NativeAvailabilityTest(unittest.TestCase):

    def setUp(self):
        self._saved = P._native_ping_ok

    def tearDown(self):
        P._native_ping_ok = self._saved

    def test_probe_returns_bool(self):
        P.reset_native_ping_probe()
        self.assertIsInstance(P._probe_native_ping(), bool)

    def test_probe_is_cached(self):
        P.reset_native_ping_probe()
        P.ping_ip("127.0.0.1", 500)              # 触发一次探测并缓存
        cached = P._native_ping_ok
        self.assertIsNotNone(cached)
        P.ping_ip("127.0.0.1", 500)
        self.assertIs(P._native_ping_ok, cached, "可用性探测不应每次重做")

    def test_reset_clears_cache(self):
        P._native_ping_ok = True
        P.reset_native_ping_probe()
        self.assertIsNone(P._native_ping_ok)

    @unittest.skipUnless(_IS_WINDOWS, "IcmpSendEcho 仅 Windows 可用")
    def test_windows_native_is_available(self):
        """Windows 上 iphlpapi 一定存在，不该退化成子进程。"""
        self.assertTrue(P._init_icmp_windows())


class PingContractTest(unittest.TestCase):
    """两条路径必须返回同样形状、同样语义的结果。"""

    def setUp(self):
        self._saved = P._native_ping_ok

    def tearDown(self):
        P._native_ping_ok = self._saved

    def test_loopback_is_alive_via_default_path(self):
        P.reset_native_ping_probe()
        alive, rtt, ttl = P.ping_ip("127.0.0.1", 1000)
        self.assertTrue(alive)
        self.assertIsInstance(rtt, float)
        self.assertIsInstance(ttl, int)

    def test_loopback_is_alive_via_subprocess_fallback(self):
        P._native_ping_ok = False           # 强制走子进程回退
        alive, rtt, ttl = P.ping_ip("127.0.0.1", 1000)
        self.assertTrue(alive)
        self.assertIsInstance(rtt, float)
        self.assertIsInstance(ttl, int)

    def test_both_paths_agree_on_loopback(self):
        P.reset_native_ping_probe()
        native = P.ping_ip("127.0.0.1", 1000)
        P._native_ping_ok = False
        subprocess_ = P.ping_ip("127.0.0.1", 1000)
        self.assertEqual(native[0], subprocess_[0], "在线判定必须一致")
        # TTL 是 OS 指纹的输入，两条路径都必须拿到非零值
        self.assertGreater(native[2], 0)
        self.assertGreater(subprocess_[2], 0)

    @unittest.skipUnless(_IS_WINDOWS, "IcmpSendEcho 仅 Windows 可用")
    def test_windows_native_reports_ttl(self):
        """TTL 必须被填上 —— 丢了它 osfp.guess_os_from_ttl 就失效了。"""
        P._init_icmp_windows()
        alive, rtt, ttl = P._icmp_ping_windows("127.0.0.1", 1000)
        self.assertTrue(alive)
        self.assertGreater(ttl, 0, "回包 TTL 未填：OS 指纹会退化")

    @unittest.skipUnless(_IS_WINDOWS, "IcmpSendEcho 仅 Windows 可用")
    def test_windows_native_returns_none_for_non_literal(self):
        """非法 IPv4 字面量应返回 None，让上层回退而不是误报离线。"""
        P._init_icmp_windows()
        self.assertIsNone(P._icmp_ping_windows("not-an-ip", 200))

    def test_never_returns_none(self):
        """契约：ping_ip 永远返回三元组，绝不返回 None。"""
        P.reset_native_ping_probe()
        for ip in ("127.0.0.1", "192.0.2.1"):    # 192.0.2.0/24 是保留测试网段
            res = P.ping_ip(ip, 300)
            self.assertIsInstance(res, tuple)
            self.assertEqual(len(res), 3)
            self.assertIsInstance(res[0], bool)
            self.assertIsInstance(res[1], float)
            self.assertIsInstance(res[2], int)


if __name__ == "__main__":
    unittest.main()
