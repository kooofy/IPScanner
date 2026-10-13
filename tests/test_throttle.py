# -*- coding: utf-8 -*-
"""`scanner.throttle`（v2.1 §2.4）的单测。

三件事分别测：并发上限（`deliver` + `InFlightCounter`）、顺序随机化
（`shuffled` 可复现且 ≠ 声明序）、令牌桶（**假时钟**推进，不真 sleep）。
外加「档位落审计是语言无关规范值」与「fast 档与改造前一致」两条验收。
"""
import argparse
import contextlib
import gc
import io
import json
import os
import random
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli
from scanner import ports, throttle
from scanner.throttle import (POLICIES, POLICY_BALANCED, POLICY_FAST,
                              POLICY_POLITE, POLICY_NAMES)


class FakeClock:
    """假时钟：`advance()` 就是"时间过去"。可直接当 `clock` 用。"""

    def __init__(self, start: float = 0.0):
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _ThrottleStateMixin(unittest.TestCase):
    """隔离进程级激活档：泄漏一个 polite 桶会让后续用例全部变慢/卡住。"""

    def setUp(self):
        throttle.reset_throttle()

    def tearDown(self):
        throttle.reset_throttle()


# ── 档位 ─────────────────────────────────────────────────────────────────

class PolicyTest(_ThrottleStateMixin):

    def test_policy_names_are_canonical(self):
        """档位名是规范值：纯 ascii 小写，可直接落库 / 跨语言比较。"""
        self.assertEqual(len(POLICY_NAMES), 3)
        for name in POLICY_NAMES:
            self.assertEqual(name, name.lower())
            self.assertTrue(name.isascii())

    def test_resolve_none_is_fast(self):
        self.assertIs(throttle.resolve_policy(None), POLICIES[POLICY_FAST])
        self.assertIs(throttle.resolve_policy(""), POLICIES[POLICY_FAST])

    def test_resolve_accepts_case_and_spaces(self):
        self.assertIs(throttle.resolve_policy(" Polite "), POLICIES[POLICY_POLITE])

    def test_resolve_unknown_raises(self):
        """未知档位必须炸，不能静默回退 —— 否则"以为在礼貌档其实全速扫"。"""
        with self.assertRaises(ValueError) as ctx:
            throttle.resolve_policy("turbo")
        for name in POLICY_NAMES:
            self.assertIn(name, str(ctx.exception))

    def test_fast_means_no_limit(self):
        """fast 三字段全不设限：这是"与改造前逐字节等价"的保证。"""
        p = POLICIES[POLICY_FAST]
        self.assertEqual(p.max_concurrency, 0)
        self.assertFalse(p.shuffle)
        self.assertEqual(p.packets_per_minute, 0)
        self.assertFalse(p.rate_limited)

    def test_tiers_are_progressively_stricter(self):
        bal = POLICIES[POLICY_BALANCED]
        pol = POLICIES[POLICY_POLITE]
        self.assertLess(pol.max_concurrency, bal.max_concurrency)
        self.assertLess(pol.packets_per_minute, bal.packets_per_minute)
        for p in (bal, pol):
            self.assertTrue(p.rate_limited)
            self.assertTrue(p.shuffle)
            self.assertLess(p.max_concurrency, 384)   # 低于端口池原值

    def test_audit_detail_is_canonical_and_serializable(self):
        for name in POLICY_NAMES:
            detail = POLICIES[name].audit_detail()
            # 可直接 json.dumps 进 audit_log 的 detail 列
            text = json.dumps(detail, ensure_ascii=False)
            self.assertIn(f'"policy": "{name}"', text)
            self.assertIsInstance(detail["max_concurrency"], int)
            self.assertIsInstance(detail["shuffle"], bool)
            self.assertIsInstance(detail["packets_per_minute"], int)

    def test_describe_covers_both_shapes(self):
        self.assertIn("不额外设限", POLICIES[POLICY_FAST].describe())
        polite = POLICIES[POLICY_POLITE].describe()
        for token in (POLICY_POLITE, "并发≤16", "随机化=开", "600 包/分"):
            self.assertIn(token, polite)

    def test_prepare_targets_defaults_to_current_policy(self):
        """``policy=None`` 走当前激活档；默认 fast ⇒ 顺序不变。"""
        items = list(range(10))
        self.assertEqual(throttle.prepare_targets(items), items)
        with throttle.active_policy(POLICIES[POLICY_POLITE]):
            self.assertEqual(
                sorted(throttle.prepare_targets(items, seed="s")), items)

    def test_shuffle_for_follows_active_policy(self):
        items = list(range(10))
        self.assertEqual(throttle.shuffle_for(items), items)     # fast
        with throttle.active_policy(POLICIES[POLICY_BALANCED]):
            self.assertEqual(sorted(throttle.shuffle_for(items, seed="s")),
                             items)

    def test_active_policy_without_explicit_argument(self):
        """``active_policy()`` 不传参 = 激活默认档（仍可安全嵌套）。"""
        with throttle.active_policy(POLICIES[POLICY_POLITE]):
            with throttle.active_policy():
                self.assertIs(throttle.current_policy(),
                              POLICIES[POLICY_FAST])
            self.assertIs(throttle.current_policy(), POLICIES[POLICY_POLITE])


# ── 顺序随机化 ────────────────────────────────────────────────────────────

class ShuffleTest(unittest.TestCase):

    def test_fast_does_not_reorder(self):
        items = list(range(20))
        self.assertEqual(throttle.prepare_targets(items, POLICIES[POLICY_FAST]),
                         items)

    def test_seed_is_reproducible(self):
        a = throttle.shuffled(range(50), seed="fixed-seed")
        b = throttle.shuffled(range(50), seed="fixed-seed")
        self.assertEqual(a, b)

    def test_shuffled_differs_from_declared_order(self):
        items = list(range(50))
        got = throttle.shuffled(items, seed=1234)
        self.assertNotEqual(got, items)
        self.assertEqual(sorted(got), items)

    def test_uses_isolated_rng(self):
        """绝不能摸全局 random 状态：否则别的模块的随机行为被静默改变。"""
        state_before = random.getstate()
        throttle.shuffled(range(30), seed="anything")
        self.assertEqual(random.getstate(), state_before)

    def test_accepts_random_instance(self):
        rng = random.Random(7)
        first = throttle.shuffled(range(10), seed=rng)
        second = throttle.shuffled(range(10), seed=random.Random(7))
        self.assertEqual(first, second)

    def test_empty(self):
        self.assertEqual(throttle.shuffled([], seed=1), [])
        self.assertEqual(throttle.prepare_targets([], POLICIES[POLICY_POLITE]), [])


# ── 令牌桶 ────────────────────────────────────────────────────────────────

class TokenBucketTest(unittest.TestCase):

    def test_first_token_is_free(self):
        b = throttle.TokenBucket(600, capacity=1.0, initial=1.0)
        self.assertTrue(b.try_acquire(1))
        self.assertFalse(b.try_acquire(1))

    def test_seconds_until_does_not_sleep_or_mutate(self):
        clk = FakeClock()
        b = throttle.TokenBucket(600, clock=clk, sleep=clk.advance)   # 10/s
        b.acquire(1)                     # 拿走初始令牌
        self.assertAlmostEqual(b.seconds_until(1), 0.1, places=9)
        # seconds_until 不该消耗令牌
        self.assertAlmostEqual(b.seconds_until(1), 0.1, places=9)

    def test_fake_clock_no_real_sleep(self):
        """核心可测性：速率上限按**假时钟**验证，不消耗真实时间。"""
        clk = FakeClock()
        b = throttle.TokenBucket(600, clock=clk, sleep=clk.advance)
        t0 = time.perf_counter()
        for _ in range(5):
            b.acquire(1)
        real = time.perf_counter() - t0
        # 第 1 次用初始令牌，后 4 次各等 0.1s → 假时钟正好前进 0.4s
        self.assertAlmostEqual(clk.now, 0.4, places=9)
        self.assertLess(real, 0.05, "假时钟下不应发生真实睡眠")

    def test_accumulated_float_error_does_not_starve(self):
        """🔴 回归：连续 acquire 会把假时钟停在"差 4e-16 就该补满"的位置。

        实测连取 5 次后：0.30000000000000004 + 0.1 → 0.4，补出的令牌是
        ``0.9999999999999996``。没有容差时这会算出 ``4.44e-17`` 秒的等待 ——
        比 0.4 的 ULP 还小，`now += 它` 时钟纹丝不动，于是防挂死护栏**误报**
        RuntimeError。所以这里连取 20 次：一次都不许抛，也必须真的在限速。
        """
        clk = FakeClock()
        b = throttle.TokenBucket(600, clock=clk, sleep=clk.advance)   # 10/s
        for _ in range(20):
            b.acquire(1)
        # 19 次等待 × 0.1s ⇒ 假时钟至少走过 1.9s（容差不许把速率打穿）
        self.assertGreaterEqual(clk.now, 1.9 - 1e-6)

    def test_refill_is_capped_at_capacity(self):
        clk = FakeClock()
        b = throttle.TokenBucket(6000, capacity=2.0, clock=clk,
                                 sleep=clk.advance)     # 100/s
        clk.advance(10)                                  # 本该补 1000 枚
        self.assertAlmostEqual(b.tokens, 2.0, places=9)

    def test_invalid_rate_and_capacity(self):
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                throttle.TokenBucket(bad)
        with self.assertRaises(ValueError):
            throttle.TokenBucket(600, capacity=0)

    def test_invalid_initial(self):
        with self.assertRaises(ValueError):
            throttle.TokenBucket(600, capacity=1.0, initial=2.0)

    def test_zero_or_negative_n_is_noop(self):
        b = throttle.TokenBucket(600)
        self.assertTrue(b.try_acquire(0))
        self.assertTrue(b.try_acquire(-5))
        self.assertAlmostEqual(b.seconds_until(0), 0.0)
        b.acquire(0)          # 不该抛

    def test_stalled_clock_raises_instead_of_spinning(self):
        """🔴 防挂死护栏：sleep 不推进时钟时必须报错，绝不能空转。

        这正是仓库里那次"CI 挂满 6 小时"的同型风险 —— 无限循环比失败恶劣得多。
        """
        clk = FakeClock()
        b = throttle.TokenBucket(600, clock=clk, sleep=lambda s: None)
        b.acquire(1)                      # 拿走初始令牌
        with self.assertRaises(RuntimeError):
            b.acquire(1)


class InFlightCounterTest(unittest.TestCase):

    def test_peak_tracks_maximum(self):
        c = throttle.InFlightCounter()
        with c:
            with c:
                self.assertEqual(c.current, 2)
                self.assertEqual(c.peak, 2)
        self.assertEqual(c.current, 0)
        self.assertEqual(c.peak, 2)

    def test_recovers_after_exception(self):
        c = throttle.InFlightCounter()
        with self.assertRaises(RuntimeError):
            with c:
                raise RuntimeError("boom")
        self.assertEqual(c.current, 0)
        self.assertEqual(c.peak, 1)


# ── 按档投递 ──────────────────────────────────────────────────────────────

class DeliverTest(_ThrottleStateMixin):

    def test_empty_targets(self):
        self.assertEqual(throttle.deliver(lambda k: k, []), [])
        self.assertEqual(
            throttle.deliver(lambda k: k, [], policy=POLICIES[POLICY_POLITE]), [])

    def test_fast_preserves_order(self):
        got = throttle.deliver(lambda k: k * 2, range(10),
                               policy=POLICIES[POLICY_FAST])
        self.assertEqual(got, [k * 2 for k in range(10)])

    def test_results_align_with_delivery_order(self):
        items = list(range(12))
        got = throttle.deliver(lambda k: k, items,
                               policy=POLICIES[POLICY_POLITE], seed="s")
        self.assertEqual(sorted(got), items)

    def test_max_concurrency_is_enforced(self):
        """上限真的生效：观测到的在飞峰值 ≤ 档位上限，且确实出现了并行。"""
        counter = throttle.InFlightCounter()

        def work(_key):
            time.sleep(0.03)
            return True

        throttle.deliver(work, range(40), policy=POLICIES[POLICY_POLITE],
                         counter=counter)
        self.assertLessEqual(counter.peak, POLICIES[POLICY_POLITE].max_concurrency)
        self.assertGreaterEqual(counter.peak, 2, "应当在现实中并行起来")

    def test_packet_rate_enforced_with_fake_clock(self):
        """令牌桶 + 假时钟：不真睡，但速率下限依然被尊重。"""
        clk = FakeClock()
        bucket = throttle.TokenBucket(600, clock=clk, sleep=clk.advance)
        t0 = time.perf_counter()
        got = throttle.deliver(lambda k: k, range(5),
                               policy=POLICIES[POLICY_POLITE], bucket=bucket)
        real = time.perf_counter() - t0
        self.assertEqual(sorted(got), list(range(5)))
        # 5 个包 / 10 每秒 ⇒ 至少要花掉 0.4s 的（假）时间
        self.assertGreaterEqual(clk.now, 0.4 - 1e-9)
        self.assertLess(real, 0.5, "假时钟下不应发生真实睡眠")

    def test_work_exception_propagates(self):
        def boom(_key):
            raise ValueError("探测失败")

        with self.assertRaises(ValueError):
            throttle.deliver(boom, range(4), policy=POLICIES[POLICY_POLITE])

    def test_counter_is_optional(self):
        self.assertEqual(throttle.deliver(lambda k: k, range(3)), [0, 1, 2])


# ── 进程内激活档 ──────────────────────────────────────────────────────────

class ActivePolicyTest(_ThrottleStateMixin):

    def test_default_is_fast(self):
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])

    def test_active_policy_context_sets_and_restores(self):
        with throttle.active_policy(POLICIES[POLICY_POLITE]) as p:
            self.assertIs(p, POLICIES[POLICY_POLITE])
            self.assertIs(throttle.current_policy(), POLICIES[POLICY_POLITE])
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])

    def test_active_policy_restores_on_exception(self):
        with self.assertRaises(RuntimeError):
            with throttle.active_policy(POLICIES[POLICY_POLITE]):
                raise RuntimeError("boom")
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])

    def test_nested_active_policy(self):
        with throttle.active_policy(POLICIES[POLICY_BALANCED]):
            with throttle.active_policy(POLICIES[POLICY_POLITE]):
                self.assertIs(throttle.current_policy(), POLICIES[POLICY_POLITE])
            self.assertIs(throttle.current_policy(), POLICIES[POLICY_BALANCED])
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])

    def test_gate_is_noop_when_fast(self):
        t0 = time.perf_counter()
        for _ in range(1000):
            throttle.throttle_gate()
        self.assertLess(time.perf_counter() - t0, 0.5)

    def test_gate_limits_when_polite(self):
        """闸门在 polite 档下真的会限速（用小速率 + 假时钟避免慢测试）。"""
        clk = FakeClock()
        with throttle.active_policy(POLICIES[POLICY_POLITE]):
            throttle._bucket = throttle.TokenBucket(
                POLICIES[POLICY_POLITE].packets_per_minute,
                clock=clk, sleep=clk.advance)
            try:
                for _ in range(3):
                    throttle.throttle_gate()
                self.assertGreater(clk.now, 0.0)
            finally:
                throttle._bucket = None

    def test_concurrency_for_passes_through_when_fast(self):
        self.assertEqual(throttle.concurrency_for(1024), 1024)
        self.assertEqual(throttle.concurrency_for(1), 1)

    def test_concurrency_for_clamps_when_polite(self):
        with throttle.active_policy(POLICIES[POLICY_POLITE]):
            self.assertEqual(throttle.concurrency_for(1024), 16)
            self.assertEqual(throttle.concurrency_for(4), 4)   # 已经更小

    def test_reset_restores_default_even_after_leak_attempt(self):
        with throttle.active_policy(POLICIES[POLICY_POLITE]):
            throttle.reset_throttle()
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])
        self.assertIsNone(throttle._active_bucket())

    def test_audit_detail_of_active_policy(self):
        with throttle.active_policy(POLICIES[POLICY_BALANCED]):
            detail = throttle.audit_detail()
        self.assertEqual(detail["policy"], POLICY_BALANCED)
        self.assertEqual(detail["max_concurrency"], 64)

    def test_audit_detail_survives_language_switch(self):
        """档位进审计必须是语言无关规范值：切语言后逐字节相同。"""
        import i18n
        detail_before = json.dumps(throttle.audit_detail(POLICIES[POLICY_POLITE]),
                                   sort_keys=True)
        for lang in ("zh-CN", "en-US"):
            i18n.init(lang)
            detail_after = json.dumps(
                throttle.audit_detail(POLICIES[POLICY_POLITE]), sort_keys=True)
            self.assertEqual(detail_before, detail_after,
                             f"切到 {lang} 后审计内容变了 —— 规范值被翻译污染了")


# ── 接进 CLI / 端口探测（否则模块等于白写） ──────────────────────────────

class CliIntegrationTest(_ThrottleStateMixin):
    """`--throttle` 真的接到了扫描上，且档位真的进了审计。"""

    def _scan_with_fake_engine(self, argv):
        """把 NetworkScanner.scan 换成记账桩，返回它看到的 (档位, max_threads)。"""
        seen = {}

        def fake_scan(self, **kwargs):
            seen["policy"] = throttle.current_policy().name
            seen["threads"] = kwargs.get("max_threads")
            return []

        with mock.patch("scanner.NetworkScanner.scan", fake_scan), \
             mock.patch.object(cli, "_audit_throttle"):
            cli.main(argv)
        return seen

    def test_throttle_flag_exists_on_scan_watch_diff(self):
        for argv in (["scan"], ["watch"], ["diff"]):
            with self.assertRaises(SystemExit):     # --help 走 SystemExit(0)
                with contextlib.redirect_stdout(io.StringIO()):
                    cli.main(argv + ["--help"])
        # 上面只证明"能打印帮助"，这里证明档位确实在帮助里。
        for argv in (["scan"], ["watch"], ["diff"]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), \
                 self.assertRaises(SystemExit):    # --help 以 SystemExit 收尾
                cli.main(argv + ["--help"])
            self.assertIn("--throttle", out.getvalue(), f"{argv} 缺 --throttle")

    def test_default_is_fast_and_threads_untouched(self):
        """🔴 回归防线：不传 --throttle 时 max_threads 必须原样透传。"""
        seen = self._scan_with_fake_engine(
            ["scan", "-r", "127.0.0.1/32", "--no-ports", "--no-mdns",
             "--threads", "137"])
        self.assertEqual(seen["policy"], POLICY_FAST)
        self.assertEqual(seen["threads"], 137)

    def test_polite_clamps_threads_and_activates_policy(self):
        seen = self._scan_with_fake_engine(
            ["scan", "-r", "127.0.0.1/32", "--no-ports", "--no-mdns",
             "--threads", "137", "--throttle", "polite"])
        self.assertEqual(seen["policy"], POLICY_POLITE)
        self.assertEqual(seen["threads"], 16)      # polite 档上限
        # 扫描结束后必须还原，否则限速桶漏到后续所有扫描上
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])

    def test_policy_is_restored_even_when_scan_raises(self):
        def boom(self, **kwargs):
            raise KeyboardInterrupt

        with mock.patch("scanner.NetworkScanner.scan", boom), \
             mock.patch.object(cli, "_audit_throttle"):
            cli.main(["scan", "-r", "127.0.0.1/32", "--no-ports", "--no-mdns",
                      "--throttle", "polite"])
        self.assertIs(throttle.current_policy(), POLICIES[POLICY_FAST])

    def test_resolve_throttle_rejects_unknown(self):
        namespace = argparse.Namespace(throttle="turbo")
        with self.assertRaises(ValueError):
            cli._resolve_throttle(namespace)

    def test_resolve_throttle_defaults_to_fast(self):
        namespace = argparse.Namespace(throttle=throttle.DEFAULT_POLICY)
        self.assertIs(cli._resolve_throttle(namespace), POLICIES[POLICY_FAST])


class PortsThrottleIntegrationTest(_ThrottleStateMixin):
    """礼貌档真的接到了 `scan_ports` 上（乱序 + 闸门）。"""

    def _force_threaded(self):
        return mock.patch.dict(os.environ,
                               {ports._ENGINE_ENV: "threaded"})

    def test_connect_path_consults_the_gate(self):
        """线程池路径每个端口都要过令牌桶闸门 —— 否则限速形同虚设。"""
        with self._force_threaded(), \
             mock.patch.object(ports, "scan_port", return_value=False), \
             mock.patch.object(throttle, "throttle_gate") as gate:
            ports.scan_ports("127.0.0.1", ports=[80, 81, 82], timeout=0.1)
        self.assertEqual(gate.call_count, 3)

    def test_connect_path_passes_ports_through_shuffle_for(self):
        """端口在投递前必须过一次 `shuffle_for`（档位的唯一顺序入口）。

        ⚠ 刻意**不断言投递/完成顺序**：`as_completed` 的顺序由线程调度决定，
        那是并发实现细节而非本模块的契约。断言"交给 shuffle_for 的正是原始
        端口列表"才既稳又有意义。
        """
        real = throttle.shuffle_for
        with self._force_threaded(), \
             mock.patch.object(ports, "scan_port", return_value=False), \
             mock.patch.object(throttle, "throttle_gate"), \
             mock.patch.object(throttle, "shuffle_for", wraps=real) as spy:
            ports.scan_ports("127.0.0.1", ports=[80, 81, 82], timeout=0.1)
        spy.assert_called_once_with([80, 81, 82])

    def test_fast_shuffle_for_is_identity(self):
        """fast 档下 `shuffle_for` 是恒等映射 —— 兼容旧行为的一部分。"""
        self.assertEqual(throttle.shuffle_for([80, 81, 82]), [80, 81, 82])

    def test_polite_shuffle_for_permutes(self):
        ports_list = list(range(1, 31))
        with throttle.active_policy(POLICIES[POLICY_POLITE]):
            out = throttle.shuffle_for(ports_list, seed="s")
        self.assertNotEqual(out, ports_list)
        self.assertEqual(sorted(out), ports_list)


class AuditDetailTest(_ThrottleStateMixin):
    """档位落审计：规范值、可 json 序列化、切语言不变。"""

    def test_audit_event_records_canonical_values(self):
        import audit_log
        # `ignore_cleanup_errors`：`audit_log._conn()` 的 `with conn:` 只包事务、
        # 不关连接，SQLite 文件句柄在 Windows 上会短暂残留，删目录可能失败。
        # 断言已在 with 内做完，清不干净不影响结论。
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db = os.path.join(tmp, "audit.db")
            cli._audit_throttle(POLICIES[POLICY_POLITE], db_path=db)
            rows = audit_log.query_logs(db_path=db)
        self.assertEqual(len(rows), 1)
        detail = json.loads(rows[0]["detail"])
        self.assertEqual(detail["policy"], POLICY_POLITE)
        self.assertEqual(detail["max_concurrency"], 16)
        self.assertEqual(detail["packets_per_minute"], 600)
        self.assertTrue(detail["shuffle"])

    def test_audit_failure_never_breaks_the_scan(self):
        """审计是旁路：写不进去只告警，绝不能把一次成功的扫描判成失败。"""
        with mock.patch("audit_log.log_event", side_effect=OSError("磁盘坏了")):
            # 不该抛
            cli._audit_throttle(POLICIES[POLICY_BALANCED], db_path=":memory:")
        gc.collect()      # 释放上面的桩，避免影响后续用例


if __name__ == "__main__":
    unittest.main()
