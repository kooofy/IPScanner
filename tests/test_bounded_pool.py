# -*- coding: utf-8 -*-
"""P1-3 回归测试：批量识别必须并发执行，而不是串行 for 循环。

历史缺陷
--------
``WmiThread.run()`` / ``NetbiosThread.run()`` 是纯串行循环：

    for i, ip in enumerate(self.targets, 1):
        d = wmi_query(ip, ..., timeout=8.0)     # 单台最多阻塞 8 秒

N 台设备最坏耗时 = N × 单台超时。对一批被防火墙拦截的主机（超时是常态），
20 台 WMI 要等约 160 秒，界面只有一句「WMI 识别进行中」，体感等同卡死。

修复
----
抽出 ``bounded_pool.run_bounded()`` 做有界并发，WMI 默认 4 路、NetBIOS 默认
16 路。本测试用「观测到的最大同时在跑任务数」来断言并发确实发生 ——
比断言墙钟耗时更稳定，也不会因 CI 机器慢而误报。
"""
import os
import sys
import threading
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import Qt

from bounded_pool import run_bounded
import scanner as scanner_pkg
from ui_threads import NetbiosThread, WmiThread

_app = None
try:
    # 必须用 QApplication（而不是 QCoreApplication）：同一进程里后续的
    # widget 类测试（如 test_tree_service_children）需要一个真正的 QApplication，
    # 而 Qt 不允许"先 QCoreApplication 再 QApplication"，混用会让进程直接 abort。
    # 详见 tests/_qt_app.py。
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()
except Exception:  # pragma: no cover - 无 Qt 环境时跳过线程类测试
    # 本测试的线程类断言依赖 QThread/QObject；没有 Qt 时上面那些用例会自行失败，
    # 此处无需额外处理（保留 _app = None 即可）。
    pass


class _Tracker:
    """记录并发峰值与调用顺序的线程安全探针。"""

    def __init__(self, delay=0.05):
        self.delay = delay
        self.lock = threading.Lock()
        self.inflight = 0
        self.peak = 0
        self.calls = []

    def enter(self, key):
        with self.lock:
            self.inflight += 1
            self.peak = max(self.peak, self.inflight)
            self.calls.append(key)
        time.sleep(self.delay)
        with self.lock:
            self.inflight -= 1


# ── run_bounded 本身 ────────────────────────────────────────────────

class RunBoundedTest(unittest.TestCase):

    def test_empty_targets(self):
        self.assertEqual(run_bounded([], lambda x: x), (0, 0))

    def test_results_are_delivered_for_every_target(self):
        seen = []
        done, skipped = run_bounded(
            [1, 2, 3, 4], lambda x: x * 10,
            max_workers=2,
            on_result=lambda item, res, exc: seen.append((item, res, exc)),
        )
        self.assertEqual((done, skipped), (4, 0))
        self.assertEqual(sorted(seen), [(1, 10, None), (2, 20, None),
                                        (3, 30, None), (4, 40, None)])

    def test_runs_concurrently(self):
        tr_ = _Tracker(delay=0.08)
        run_bounded(list(range(12)), lambda x: tr_.enter(x),
                    max_workers=4)
        self.assertGreater(tr_.peak, 1, "任务未并发执行（仍是串行）")
        self.assertLessEqual(tr_.peak, 4, "并发度超过 max_workers 上限")

    def test_max_workers_one_is_serial(self):
        tr_ = _Tracker(delay=0.02)
        run_bounded(list(range(5)), lambda x: tr_.enter(x), max_workers=1)
        self.assertEqual(tr_.peak, 1)

    def test_max_workers_clamped_to_target_count(self):
        tr_ = _Tracker(delay=0.05)
        run_bounded([1, 2], lambda x: tr_.enter(x), max_workers=64)
        self.assertLessEqual(tr_.peak, 2)

    def test_worker_exception_isolated(self):
        """单台抛异常必须只影响该台，不能中断整批。"""
        seen = []

        def worker(x):
            if x == 2:
                raise RuntimeError("boom")
            return x

        done, _ = run_bounded(
            [1, 2, 3], worker, max_workers=2,
            on_result=lambda item, res, exc: seen.append((item, res, exc)),
        )
        self.assertEqual(done, 3)
        by_item = {item: (res, exc) for item, res, exc in seen}
        self.assertIsNone(by_item[1][1])
        self.assertIsInstance(by_item[2][1], RuntimeError)
        self.assertIsNone(by_item[3][1])

    def test_cancel_event_skips_pending_targets(self):
        cancel = threading.Event()
        cancel.set()
        called = []
        done, skipped = run_bounded(
            [1, 2, 3], lambda x: called.append(x), max_workers=2,
            cancel_event=cancel,
        )
        self.assertEqual(done, 0)
        self.assertEqual(skipped, 3)
        self.assertEqual(called, [])

    def test_on_result_is_called_from_caller_thread(self):
        """回调必须发生在调用线程（QThread.run 线程），而非池内工作线程。"""
        caller = threading.get_ident()
        idents = []
        run_bounded(
            [1, 2, 3], lambda x: x, max_workers=3,
            on_result=lambda item, res, exc: idents.append(threading.get_ident()),
        )
        self.assertTrue(idents)
        self.assertTrue(all(i == caller for i in idents))


# ── WmiThread / NetbiosThread ───────────────────────────────────────

def _creds():
    return types.SimpleNamespace(username="u", password="p", domain="d")


class _ThreadHarness(unittest.TestCase):
    """把线程的 run() 同步跑一遍，用 DirectConnection 收集信号。"""

    def _run_thread(self, thread):
        results = []
        progress = []
        summary = []
        thread.result_signal.connect(
            lambda ip, d: results.append((ip, d)), Qt.DirectConnection
        )
        thread.progress_signal.connect(
            lambda i, t: progress.append((i, t)), Qt.DirectConnection
        )
        thread.finished_signal.connect(
            lambda s: summary.append(s), Qt.DirectConnection
        )
        thread.run()          # 直接调用，不开新线程
        return results, progress, summary


class WmiThreadConcurrencyTest(_ThreadHarness):

    def setUp(self):
        self._orig = scanner_pkg.wmi_query

    def tearDown(self):
        scanner_pkg.wmi_query = self._orig

    def _install(self, tracker=None, fail_on=()):
        def fake_query(ip, username, password, domain="", timeout=None, transport=None):
            if tracker is not None:
                tracker.enter(ip)
            else:
                time.sleep(0.01)
            if ip in fail_on:
                return {"wmi_error": "denied"}
            return {"wmi_error": "", "wmi_hostname": f"host-{ip}"}

        scanner_pkg.wmi_query = fake_query

    def test_wmi_runs_concurrently(self):
        tr_ = _Tracker(delay=0.08)
        self._install(tr_)
        targets = [f"10.0.0.{i}" for i in range(1, 13)]

        results, progress, summary = self._run_thread(WmiThread(targets, _creds()))

        self.assertGreater(tr_.peak, 1, "WMI 识别仍是串行")
        self.assertLessEqual(tr_.peak, WmiThread.WMI_MAX_WORKERS)
        self.assertEqual(len(results), 12)
        self.assertEqual(summary[0]["ok"], 12)
        self.assertEqual(summary[0]["fail"], 0)
        self.assertFalse(summary[0]["cancelled"])

    def test_wmi_progress_is_monotonic_up_to_total(self):
        self._install()
        targets = [f"10.0.1.{i}" for i in range(1, 8)]

        _, progress, _ = self._run_thread(WmiThread(targets, _creds()))

        self.assertEqual([i for i, _ in progress], list(range(1, 8)))
        self.assertTrue(all(t == 7 for _, t in progress))

    def test_wmi_counts_failures_without_stopping(self):
        self._install(fail_on={"10.0.2.3"})
        targets = [f"10.0.2.{i}" for i in range(1, 6)]

        results, _, summary = self._run_thread(WmiThread(targets, _creds()))

        self.assertEqual(len(results), 5)
        self.assertEqual(summary[0]["ok"], 4)
        self.assertEqual(summary[0]["fail"], 1)

    def test_wmi_survives_worker_exception(self):
        def boom(ip, username, password, domain="", timeout=None, transport=None):
            if ip.endswith(".2"):
                raise OSError("powershell not found")
            return {"wmi_error": ""}

        scanner_pkg.wmi_query = boom
        targets = [f"10.0.3.{i}" for i in range(1, 5)]

        results, _, summary = self._run_thread(WmiThread(targets, _creds()))

        self.assertEqual(len(results), 4)
        self.assertEqual(summary[0]["ok"], 3)
        self.assertEqual(summary[0]["fail"], 1)
        err = dict(results)["10.0.3.2"]["wmi_error"]
        self.assertIn("powershell not found", err)

    def test_wmi_cancel_marks_summary_and_skips_rest(self):
        tr_ = _Tracker(delay=0.05)
        self._install(tr_)
        targets = [f"10.0.4.{i}" for i in range(1, 21)]
        thread = WmiThread(targets, _creds(), max_workers=2)
        thread.stop()          # 开跑前就取消

        results, _, summary = self._run_thread(thread)

        self.assertEqual(results, [])
        self.assertEqual(summary[0]["ok"], 0)
        self.assertTrue(summary[0]["cancelled"])
        self.assertEqual(summary[0]["requested"], 20)
        self.assertEqual(summary[0]["total"], 0)

    def test_wmi_empty_targets(self):
        self._install()
        results, progress, summary = self._run_thread(WmiThread([], _creds()))
        self.assertEqual(results, [])
        self.assertEqual(progress, [])
        self.assertEqual(summary[0]["total"], 0)

    def test_stop_sets_cancel_event(self):
        thread = WmiThread(["10.0.0.1"], _creds())
        self.assertFalse(thread._cancel.is_set())
        thread.stop()
        self.assertTrue(thread._cancel.is_set())


class NetbiosThreadConcurrencyTest(_ThreadHarness):

    def setUp(self):
        self._orig = scanner_pkg.netbios_query

    def tearDown(self):
        scanner_pkg.netbios_query = self._orig

    def test_netbios_runs_concurrently(self):
        tr_ = _Tracker(delay=0.05)

        def fake_query(ip, timeout=None):
            tr_.enter(ip)
            return {"netbios_error": "", "netbios_name": f"pc-{ip}"}

        scanner_pkg.netbios_query = fake_query
        targets = [f"10.1.0.{i}" for i in range(1, 41)]

        results, progress, summary = self._run_thread(NetbiosThread(targets))

        self.assertGreater(tr_.peak, 1, "NetBIOS 识别仍是串行")
        self.assertLessEqual(tr_.peak, NetbiosThread.NETBIOS_MAX_WORKERS)
        self.assertEqual(len(results), 40)
        self.assertEqual(summary[0]["ok"], 40)
        self.assertEqual([i for i, _ in progress], list(range(1, 41)))

    def test_netbios_counts_failures(self):
        def fake_query(ip, timeout=None):
            return {"netbios_error": "timeout" if ip.endswith(".9") else ""}

        scanner_pkg.netbios_query = fake_query
        targets = [f"10.2.0.{i}" for i in range(1, 11)]

        _, _, summary = self._run_thread(NetbiosThread(targets))

        self.assertEqual(summary[0]["ok"], 9)
        self.assertEqual(summary[0]["fail"], 1)

    def test_netbios_timeout_is_passed_through(self):
        seen = {}

        def fake_query(ip, timeout=None):
            seen["timeout"] = timeout
            return {}

        scanner_pkg.netbios_query = fake_query
        self._run_thread(NetbiosThread(["10.3.0.1"], timeout=2.5))
        self.assertEqual(seen["timeout"], 2.5)


if __name__ == "__main__":
    unittest.main()
