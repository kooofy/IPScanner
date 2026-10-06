# -*- coding: utf-8 -*-
"""跨模块共享状态的回归测试（_syn_failed / _raw_cap_cache）。

背景（真实缺陷，已实测复现）
--------------------------
`scanner/ports.py` 曾经这样引入状态::

    from .constants import _syn_failed, _raw_cap_cache

随后在探测函数里 ``global _syn_failed; _syn_failed = True``。

Python 的 ``from X import y`` 是**名字绑定**而不是引用别名，``global`` 又只作用
于本模块命名空间 —— 于是 ports 只是把 True 写进了自己的那份副本。结果是三份
互不相干的变量：

* ``constants._syn_failed`` 永远是 False（没有任何代码写它）
* ``ports._syn_failed`` 一旦置位就再没人复位 → 用户提权后仍静默回退 connect
* ``engine.py`` 里的 ``global _syn_failed`` 又凭空造出第三个 → 末尾那条
  "SYN 发送被系统拒绝，已回退" 的告警恒不触发（死代码）

本文件锁死"三处必须是同一个对象"，防止有人再改回 ``from .constants import``。
"""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import NetworkScanner, constants, engine, ports


class SharedStateIdentityTest(unittest.TestCase):
    """三个模块必须访问同一个状态对象，而不是各自的副本。"""

    def setUp(self):
        constants._syn_failed.clear()
        self._saved_cache = constants._raw_cap_cache

    def tearDown(self):
        constants._syn_failed.clear()
        constants._raw_cap_cache = self._saved_cache

    def test_ports_and_engine_reference_constants_module(self):
        self.assertIs(ports._C, constants)
        self.assertIs(engine._C, constants)

    def test_no_shadow_copy_in_ports_or_engine(self):
        """模块命名空间里不该再出现本地副本。

        旧写法 ``from .constants import _syn_failed`` 会在 ports 里绑一个同名
        名字；engine 里的 ``global _syn_failed`` 也会凭空造一个。这两个名字的
        存在本身就是缺陷，因此直接断言它们不存在。
        """
        self.assertFalse(hasattr(ports, "_syn_failed"),
                         "ports 又出现了 _syn_failed 的本地副本")
        self.assertFalse(hasattr(ports, "_raw_cap_cache"),
                         "ports 又出现了 _raw_cap_cache 的本地副本")
        self.assertFalse(hasattr(engine, "_syn_failed"),
                         "engine 又出现了 _syn_failed 的本地副本")

    def test_write_through_ports_is_visible_everywhere(self):
        ports._C._syn_failed.set()
        self.assertTrue(constants._syn_failed.is_set())
        self.assertTrue(engine._C._syn_failed.is_set())

    def test_syn_failed_is_thread_safe_event(self):
        """多探测线程会并发读写该标记，裸 bool 有竞态，必须是 Event。"""
        self.assertIsInstance(constants._syn_failed, threading.Event)

    def test_raw_capability_caches_into_constants(self):
        constants._raw_cap_cache = None
        first = ports.raw_capability()
        self.assertIsNotNone(constants._raw_cap_cache)
        self.assertIs(constants._raw_cap_cache, first)
        # 第二次必须命中缓存并返回同一个对象（不再重新探测）
        self.assertIs(ports.raw_capability(), first)

    def test_reset_raw_capability_cache(self):
        constants._raw_cap_cache = (True, "")
        ports.reset_raw_capability_cache()
        self.assertIsNone(constants._raw_cap_cache)


class SynFallbackBehaviourTest(unittest.TestCase):
    """_syn_failed 置位后，SYN / UDP 探测必须真的回退。"""

    def setUp(self):
        constants._syn_failed.clear()

    def tearDown(self):
        constants._syn_failed.clear()

    def test_syn_short_circuits_to_connect(self):
        calls = []
        original = ports.scan_ports

        def fake_scan_ports(ip, ports_=None, timeout=0.5, mode="connect",
                            rtt_callback=None):
            calls.append(mode)
            return []

        ports.scan_ports = fake_scan_ports
        try:
            constants._syn_failed.set()
            result = ports._scan_ports_syn("127.0.0.1", [80], 0.1)
        finally:
            ports.scan_ports = original

        self.assertEqual(result, [])
        self.assertEqual(calls, ["connect"],
                         "标记置位后 SYN 应回退到 TCP 全连接")

    def test_udp_skips_when_flagged(self):
        constants._syn_failed.set()
        self.assertEqual(ports._scan_ports_udp("127.0.0.1", [53], 0.1), [])


class EngineResetTest(unittest.TestCase):
    """每次扫描都必须复位标记 —— 否则提权后永远静默降级。"""

    def tearDown(self):
        constants._syn_failed.clear()

    def test_scan_clears_flag_even_when_range_is_rejected(self):
        """复位发生在范围校验**之前**，因此用超大范围也能验证。"""
        constants._syn_failed.set()
        # 0.0.0.0/0 会在校验阶段被拒绝并立刻返回，不会真的发探测包
        results = NetworkScanner().scan(["0.0.0.0/0"], tcp_scan_mode="syn")
        self.assertEqual(results, [])
        self.assertFalse(
            constants._syn_failed.is_set(),
            "scan() 未复位 _syn_failed：用户提权后仍会静默回退到 connect",
        )

    def test_scan_warns_on_ipv6_range(self):
        """IPv6 范围必须留下告警，而不是静默跳过。"""
        scanner = NetworkScanner()
        results = scanner.scan(["2001:db8::/120"])
        self.assertEqual(results, [])
        self.assertTrue(
            any("IPv6" in w for w in scanner.warnings),
            f"IPv6 范围未给出告警: {scanner.warnings}",
        )


if __name__ == "__main__":
    unittest.main()
