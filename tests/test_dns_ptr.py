# -*- coding: utf-8 -*-
"""``scanner.dns.resolve_hostname`` 的负缓存与「超时短路」测试。

**背景**（2026-10-16 实测）：内网客户端网段普遍没有反向 DNS 区。此时
``socket.gethostbyaddr()`` 不会立刻回 NXDOMAIN，而是走满 DNS 超时才失败
—— 实测 **4.67 秒**。``resolve_hostname`` 只等 1 秒就放弃，但 8 个 worker
的线程池会被这些 4.67 秒的调用**占满**，后面的设备连提交都要排队
⇒ /24 网段光这一项就是分钟级的收尾开销，而最终**一个主机名都拿不到**。

**这里怎么测**
全部用假线程池驱动，**不碰真实网络、不等真实 DNS 超时**（否则一条用例就是
几秒到几十秒）：

- ``_ScriptedFuture`` 按脚本依次给出「成功 / 超时 / 报错」，脚本只剩一条时重复它；
- ``_FakeExecutor`` 记录每次 ``submit``，用来断言「该跳过时**真的没提交**」——
  这是本组用例的核心：短路的价值就在于**不提交**，只断言返回值是测不出来的。
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import dns


def _ok(name):
    """``socket.gethostbyaddr`` 的成功返回：``(主机名, 别名表, 地址表)``。"""
    return ("ok", (name, [], [name]))


def _timeout():
    return ("timeout", None)


def _err():
    """DNS 给了确定答复（典型 NXDOMAIN → ``socket.herror``）。"""
    return ("error", OSError("herror 11004 host not found"))


class _ScriptedFuture:
    """按脚本依次返回行为；脚本只剩一条时**重复**它。"""

    def __init__(self, script):
        self._script = list(script)

    def result(self, timeout=None):
        if len(self._script) > 1:
            kind, payload = self._script.pop(0)
        else:
            kind, payload = self._script[0]
        if kind == "timeout":
            # 抛**内置 TimeoutError**（= 真实 ``future.result(timeout=...)`` 在
            # 超时那一刻抛的东西，见 ``concurrent.futures.TimeoutError``）。
            # 刻意不写 ``concurrent.futures.TimeoutExpired`` —— 那个名字在
            # ``concurrent.futures`` 里**不存在**（它是 ``subprocess`` 的），
            # 用了会让"源码 catch 了错误的名字"这类缺陷测不出来。
            raise TimeoutError("gethostbyaddr timed out")
        if kind == "error":
            raise payload
        return payload


class _FakeExecutor:
    """假线程池：``submit`` 永远返回同一个脚本化 future，并记录提交次数。"""

    def __init__(self, script):
        self.future = _ScriptedFuture(script)
        self.submitted = []

    def submit(self, fn, *args, **kwargs):
        self.submitted.append(args)
        return self.future


class _BrokenExecutor:
    """模拟「线程池已关闭」：``submit`` 直接抛异常。"""

    def submit(self, *args, **kwargs):
        raise RuntimeError("cannot schedule new futures after shutdown")


class _PtrTestCase(unittest.TestCase):
    def setUp(self):
        # 模块级状态（负缓存 / 超时计数）是全局的，用例之间必须隔离
        dns.reset_ptr_state()

    def tearDown(self):
        dns.reset_ptr_state()

    def _install(self, script):
        """装上假线程池，返回它以便断言提交次数。"""
        ex = _FakeExecutor(script)
        patcher = mock.patch.object(dns, "_get_resolve_executor",
                                    return_value=ex)
        patcher.start()
        self.addCleanup(patcher.stop)
        return ex

    def _install_broken(self):
        patcher = mock.patch.object(dns, "_get_resolve_executor",
                                    return_value=_BrokenExecutor())
        patcher.start()
        self.addCleanup(patcher.stop)


class NegativeCacheTest(_PtrTestCase):
    def test_timeout_miss_is_negative_cached(self):
        """🔴 超时未命中要缓存 —— 否则同一个 IP 每次扫描都白等满超时。"""
        ex = self._install([_timeout()])
        self.assertEqual(dns.resolve_hostname("10.193.24.11"), "")
        self.assertEqual(dns.resolve_hostname("10.193.24.11"), "")
        self.assertEqual(len(ex.submitted), 1,
                         "负缓存没生效：同一个 IP 被重复提交")

    def test_nxdomain_is_negative_cached(self):
        """DNS 明确回「没有这个名字」也要缓存，且**不计入超时**。"""
        ex = self._install([_err()])
        self.assertEqual(dns.resolve_hostname("10.193.24.12"), "")
        self.assertEqual(dns.resolve_hostname("10.193.24.12"), "")
        self.assertEqual(len(ex.submitted), 1)
        st = dns.ptr_state()
        self.assertEqual(st["timeout_streak"], 0.0,
                         "快速 NXDOMAIN 不该被当成超时（它没白等）")
        self.assertEqual(st["wasted_s"], 0.0)

    def test_empty_hostname_counts_as_miss(self):
        """返回空主机名 = 没拿到名字，同样要缓存，不能反复问。"""
        ex = self._install([_ok("")])
        self.assertEqual(dns.resolve_hostname("10.193.24.16"), "")
        self.assertEqual(dns.resolve_hostname("10.193.24.16"), "")
        self.assertEqual(len(ex.submitted), 1,
                         "空主机名没被当成未命中缓存起来")

    def test_negative_cache_is_per_ip(self):
        """负缓存按 IP 分别记 —— 一个 IP 没名字不影响别的 IP 继续问。"""
        ex = self._install([_err()])
        dns.resolve_hostname("10.193.24.17")
        dns.resolve_hostname("10.193.24.18")
        self.assertEqual(len(ex.submitted), 2)

    def test_different_timeout_does_not_bypass_cache(self):
        """换个 timeout 不该绕过负缓存（缓存键只该是 IP）。"""
        ex = self._install([_timeout()])
        dns.resolve_hostname("10.193.24.19", timeout=1.0)
        dns.resolve_hostname("10.193.24.19", timeout=3.0)
        self.assertEqual(len(ex.submitted), 1)


class SuccessPathTest(_PtrTestCase):
    def test_success_is_returned_and_resets_state(self):
        ex = self._install([_timeout(), _timeout(), _ok("nas.local")])
        self.assertEqual(dns.resolve_hostname("10.193.24.13"), "")
        self.assertEqual(dns.resolve_hostname("10.193.24.14"), "")
        self.assertEqual(dns.resolve_hostname("10.193.24.15"), "nas.local")
        st = dns.ptr_state()
        self.assertEqual(st["timeout_streak"], 0.0)
        self.assertEqual(st["wasted_s"], 0.0)
        self.assertEqual(st["disabled_until"], 0.0)
        self.assertEqual(len(ex.submitted), 3)

    def test_timeout_streak_resets_on_success(self):
        """🔴 有线有 PTR、无线没有的环境不能被"累计"打死：成功即清零。

        若成功不清零，连续超时数会在整个扫描里单调累加，
        混合网段下迟早误判成「本网没有反向区」。
        """
        ex = self._install([_timeout(), _timeout(), _timeout(),
                            _ok("sw-01"), _timeout()])
        for i in range(3):
            dns.resolve_hostname("10.193.27.%d" % (i + 1), timeout=1.5)
        self.assertEqual(dns.ptr_state()["timeout_streak"], 3.0)

        self.assertEqual(dns.resolve_hostname("10.193.27.9", timeout=1.5), "sw-01")
        self.assertEqual(dns.ptr_state()["timeout_streak"], 0.0,
                         "解析成功后超时计数没清零")

        dns.resolve_hostname("10.193.27.10", timeout=1.5)
        self.assertEqual(dns.ptr_state()["timeout_streak"], 1.0,
                         "成功之后没有从 1 重新计数")
        self.assertEqual(len(ex.submitted), 5)


class ShortCircuitTest(_PtrTestCase):
    def test_consecutive_timeouts_short_circuit_the_rest(self):
        """连续超时到阈值后，**全新 IP 连提交都不该提交**。"""
        ex = self._install([_timeout()])
        for i in range(8):
            dns.resolve_hostname("10.193.25.%d" % (i + 1), timeout=1.5)
        self.assertEqual(len(ex.submitted), 8)
        self.assertGreater(dns.ptr_state()["disabled_until"], 0.0,
                           "连续超时后没有进入短路")

        self.assertEqual(dns.resolve_hostname("10.193.25.200", timeout=1.5), "")
        self.assertEqual(len(ex.submitted), 8, "短路生效后仍在提交查询")

    def test_short_circuit_needs_both_streak_and_waste(self):
        """阈值是**双条件**：次数够但白等时间不够时不该短路。

        否则单次超时特别长、但只发生两三次的情况下会过早放弃整网。
        """
        ex = self._install([_timeout()])
        # 次数远够（20 ≥ 8），但每次只等 0.1 秒 ⇒ 累计 2.0 秒 < 10 秒
        for i in range(20):
            dns.resolve_hostname("10.193.25.%d" % (i + 100), timeout=0.1)
        self.assertEqual(dns.ptr_state()["disabled_until"], 0.0,
                         "白等时间没到阈值就短路了")
        self.assertEqual(len(ex.submitted), 20)

    def test_fast_nxdomain_never_short_circuits(self):
        """🔴 本组最重要的一条：快速 NXDOMAIN **不能**触发短路。

        反向区存在、只是没这条记录时，DNS 会很快回 NXDOMAIN。
        这种情况既不白等，也**不该**放弃后续查询 —— 否则一个网段里
        「多数 IP 无记录、少数有记录」时，有记录的那几台会被一起丢掉。
        """
        ex = self._install([_err()])
        for i in range(20):
            dns.resolve_hostname("10.193.26.%d" % (i + 1), timeout=1.5)
        self.assertEqual(len(ex.submitted), 20,
                         "快速 NXDOMAIN 被短路吃掉了")
        self.assertEqual(dns.ptr_state()["disabled_until"], 0.0)
        self.assertEqual(dns.ptr_state()["timeout_streak"], 0.0)

    def test_short_circuit_window_is_bounded(self):
        """短路是启发式优化：窗口必须短，否则会长时间丢主机名。"""
        self.assertGreater(dns._PTR_DISABLE_TTL, 0.0)
        self.assertLessEqual(dns._PTR_DISABLE_TTL, 600.0)
        self.assertGreaterEqual(dns._PTR_TIMEOUT_LIMIT, 1)


class RobustnessTest(_PtrTestCase):
    def test_submit_failure_never_raises_and_does_not_advance(self):
        """线程池已关闭 / 拒绝提交：与"查不到"同义，且**不**推进短路。

        不能把"提交不进去"算成"DNS 超时"，否则扫描收尾时（池正在关）
        会被误判成本网没有反向区。
        """
        self._install_broken()
        self.assertEqual(dns.resolve_hostname("10.193.24.20"), "")
        st = dns.ptr_state()
        self.assertEqual(st["timeout_streak"], 0.0)
        self.assertEqual(st["wasted_s"], 0.0)
        self.assertEqual(st["disabled_until"], 0.0)

    def test_unexpected_exception_from_pool_is_swallowed(self):
        """池里抛任意异常（不只是 herror）都只能导致"没拿到名字"。"""
        ex = self._install([("error", RuntimeError("worker crashed"))])
        self.assertEqual(dns.resolve_hostname("10.193.24.21"), "")
        self.assertEqual(len(ex.submitted), 1)

    def test_reset_ptr_state_clears_everything(self):
        ex = self._install([_timeout()])
        for i in range(8):
            dns.resolve_hostname("10.193.29.%d" % (i + 1), timeout=1.5)
        self.assertGreater(dns.ptr_state()["disabled_until"], 0.0)

        dns.reset_ptr_state()
        st = dns.ptr_state()
        self.assertEqual(st["disabled_until"], 0.0)
        self.assertEqual(st["timeout_streak"], 0.0)
        self.assertEqual(st["wasted_s"], 0.0)
        self.assertEqual(st["neg_cached"], 0.0)

        before = len(ex.submitted)
        dns.resolve_hostname("10.193.29.200", timeout=1.5)
        self.assertEqual(len(ex.submitted), before + 1,
                         "复位后应恢复查询")

    def test_ptr_state_snapshot_keys(self):
        """``ptr_state()`` 是诊断接口，键名属于对外契约（语言无关）。"""
        self.assertEqual(
            set(dns.ptr_state()),
            {"disabled_until", "timeout_streak", "wasted_s", "neg_cached"})


if __name__ == "__main__":
    unittest.main()
