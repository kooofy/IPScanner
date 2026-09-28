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
            scan_ports("127.0.0.1", ports=[53], timeout=0.5,
                       mode="udp", rtt_callback=cb)
        self.assertEqual(cb.call_count, 0)


class _CoarseMonotonicClock:
    """模拟 Windows 上 Python 3.12 及以前的 time.monotonic()。

    它是 GetTickCount64，分辨率 15.6ms（3.13 起才改为 QueryPerformanceCounter）。
    perf_counter 保持高分辨率——Windows 上它一直是 QPC。
    """

    def __init__(self, step: float = 0.005):
        self._now = 10.0
        self._step = step

    def monotonic(self) -> float:
        return 1000.0            # 同一 tick 内恒定 → 两次调用差值恒为 0

    def perf_counter(self) -> float:
        self._now += self._step
        return self._now


class CoarseClockRegressionTest(unittest.TestCase):
    """回归：RTT 计时不得依赖 time.monotonic()。

    用粗时钟测"几百微秒就结束"的 connect，两次调用会落在同一 tick、差值 0.0，
    被 `elapsed > 0` 守卫丢掉样本 → RTT 采样恒为空、自适应超时失效。
    这个缺陷只在 Python ≤3.12 上暴露（3.13 把 monotonic 换成 QPC 后自愈），
    所以必须用"替身时钟"来锁定，而不是靠某个特定版本的行为。
    """

    def test_rtt_sample_survives_coarse_monotonic_clock(self):
        cb = MagicMock()
        with patch("scanner.ports.scan_port", return_value=True), \
                patch("scanner.ports.time", _CoarseMonotonicClock()):
            open_ports = scan_ports("127.0.0.1", ports=[80], timeout=0.5,
                                    mode="connect", rtt_callback=cb)
        self.assertEqual(open_ports, [80])
        self.assertEqual(cb.call_count, 1, "粗时钟下 RTT 样本被丢弃")
        self.assertAlmostEqual(cb.call_args[0][0], 0.005, places=6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
