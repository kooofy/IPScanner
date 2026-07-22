# -*- coding: utf-8 -*-
"""RTT 自适应超时（仅 TCP connect）单元测试。"""
import unittest
from unittest.mock import patch, MagicMock

from scanner.engine import adaptive_timeout_from_samples
from scanner.ports import scan_ports


class TestAdaptiveTimeout(unittest.TestCase):
    def test_empty_samples_returns_default(self):
        self.assertEqual(adaptive_timeout_from_samples([]), 0.5)

    def test_lan_low_rtt_clamped_to_min(self):
        # 局域网 RTT 约 3ms，中位数*2=0.006 -> 夹紧到 0.15(下限)
        samples = [0.003, 0.002, 0.004, 0.003, 0.005]
        self.assertAlmostEqual(adaptive_timeout_from_samples(samples), 0.15, places=3)

    def test_moderate_rtt(self):
        samples = [0.1, 0.12, 0.11, 0.09, 0.1]
        self.assertAlmostEqual(adaptive_timeout_from_samples(samples), 0.2, places=3)

    def test_slow_rtt_clamped_to_max(self):
        # 高延迟网 RTT 2s，中位数*2=4.0 -> 夹紧到 1.5(上限)
        samples = [2.0, 1.8, 2.2]
        self.assertAlmostEqual(adaptive_timeout_from_samples(samples), 1.5, places=3)

    def test_custom_bounds(self):
        self.assertEqual(adaptive_timeout_from_samples([0.05], min_to=0.1, max_to=1.0), 0.1)
        self.assertEqual(adaptive_timeout_from_samples([5.0], min_to=0.1, max_to=1.0), 1.0)


class TestScanPortsRttCallback(unittest.TestCase):
    def test_connect_mode_invokes_callback_with_positive_elapsed(self):
        cb = MagicMock()
        with patch("scanner.ports.scan_port", return_value=True):
            open_ports = scan_ports("127.0.0.1", ports=[80], timeout=0.5,
                                    mode="connect", rtt_callback=cb)
        self.assertEqual(open_ports, [80])
        self.assertEqual(cb.call_count, 1)
        self.assertGreater(cb.call_args[0][0], 0)

    def test_no_open_port_no_callback(self):
        cb = MagicMock()
        with patch("scanner.ports.scan_port", return_value=False):
            open_ports = scan_ports("127.0.0.1", ports=[81, 82], timeout=0.5,
                                    mode="connect", rtt_callback=cb)
        self.assertEqual(open_ports, [])
        self.assertEqual(cb.call_count, 0)

    def test_udp_mode_does_not_invoke_callback(self):
        # rtt_callback 仅 connect 模式使用，UDP/SYN 分支不应触发
        cb = MagicMock()
        with patch("scanner.ports.udp_scan_port", return_value="open"):
            open_ports = scan_ports("127.0.0.1", ports=[53], timeout=0.5,
                                    mode="udp", rtt_callback=cb)
        self.assertEqual(cb.call_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
