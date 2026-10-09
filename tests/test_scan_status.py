# -*- coding: utf-8 -*-
"""扫描态摘要条（docs/reviews/UI_REVIEW.md P0-2 后半）。

覆盖四层，任何一层断了都能定位到具体环节：

1. **纯函数** —— `ui_logic.format_elapsed` 的边界（0 / 59 / 60 / 3599 / 3600 / 负值）；
2. **标签** —— `phase_label` 惰性翻译，且**规范值不随语言变**；
3. **引擎** —— `scan(phase_callback=...)` 真的按 `PHASES` 逐阶段回调，且回传的是
   语言无关的规范值（`ping`/`arp`/`mdns`），不是已翻译的文本；
4. **控件与接线** —— 真 `MainWindow` 里摘要条默认隐藏、三个信号都能推进它、
   点「停止」不会炸。

配置一律隔离到临时目录，不碰用户的 `ipscanner.ini`。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

import i18n
import main_window
from scanner import NetworkScanner, phase_label
from scanner.engine import PHASES
from scanner.models import ScanResult
from scan_status import ScanStatusBar
from ui_logic import format_elapsed

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


def _qss(name):
    path = os.path.join(ROOT, "assets", "styles", name)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class FormatElapsedTest(unittest.TestCase):
    """`mm:ss`，满一小时才升位到 `h:mm:ss`。"""

    def test_boundaries(self):
        cases = {
            0: "00:00",
            1: "00:01",
            59: "00:59",
            60: "01:00",
            61: "01:01",
            599: "09:59",
            3599: "59:59",
            3600: "1:00:00",
            3661: "1:01:01",
        }
        for seconds, expected in cases.items():
            with self.subTest(seconds=seconds):
                self.assertEqual(format_elapsed(seconds), expected)

    def test_bad_input_degrades_to_zero(self):
        """显示层不该因为一个异常值抛异常，把整条扫描流程带崩。"""
        for bad in (-1, -999, None, "abc"):
            with self.subTest(bad=bad):
                self.assertEqual(format_elapsed(bad), "00:00")


class PhaseLabelTest(unittest.TestCase):
    """阶段名：规范值语言无关，显示名惰性翻译。"""

    def test_translates_lazily(self):
        i18n.init("zh-CN")
        zh = phase_label("ping")
        i18n.init("en-US")
        en = phase_label("ping")
        i18n.init("zh-CN")
        self.assertNotEqual(zh, en, "阶段名被冻在导入期的语言上了")
        self.assertEqual(zh, "存活探测")
        self.assertEqual(en, "Liveness probe")

    def test_all_declared_phases_have_a_label(self):
        """`PHASES` 里每个阶段都要有中文显示名，否则摘要条会显示英文代码。"""
        for phase in PHASES:
            with self.subTest(phase=phase.name):
                self.assertNotEqual(phase_label(phase.name), phase.name)

    def test_unknown_phase_passes_through(self):
        """新增阶段忘了补词条时只显示原值，不崩 —— 也不该悄悄返回空串。"""
        self.assertEqual(phase_label("brand-new-phase"), "brand-new-phase")


class EnginePhaseCallbackTest(unittest.TestCase):
    """引擎真的逐阶段回调，且回传规范值。"""

    def test_callbacks_follow_phases(self):
        seen = []
        scanner = NetworkScanner()
        scanner.scan(
            ["127.0.0.1"],
            timeout_ms=200,
            max_threads=8,
            scan_ports_flag=False,
            mdns_discovery=False,
            phase_callback=lambda name, i, total: seen.append((name, i, total)),
        )
        self.assertEqual(
            [name for name, _i, _t in seen],
            [p.name for p in PHASES],
            "回调的阶段序列与 PHASES 不一致",
        )
        self.assertEqual([i for _n, i, _t in seen], [1, 2, 3])
        self.assertEqual({t for _n, _i, t in seen}, {len(PHASES)})

    def test_callback_is_optional(self):
        """不传 `phase_callback` 时扫描照常完成（老调用方不受影响）。"""
        scanner = NetworkScanner()
        results = scanner.scan(
            ["127.0.0.1"], timeout_ms=200, max_threads=8,
            scan_ports_flag=False, mdns_discovery=False,
        )
        self.assertIsInstance(results, list)


class ScanStatusBarTest(unittest.TestCase):
    """控件本身的显示逻辑（不需要引擎，直接推进它）。"""

    def setUp(self):
        self.bar = ScanStatusBar()

    def tearDown(self):
        self.bar.deleteLater()

    def test_hidden_until_started(self):
        self.assertTrue(self.bar.isHidden())

    def test_start_shows_and_resets(self):
        self.bar.start(254)
        snap = self.bar.snapshot()
        self.assertFalse(self.bar.isHidden())
        self.assertEqual(snap["total"], 254)
        self.assertEqual(snap["scanned"], 0)
        self.assertEqual(snap["online"], 0)
        self.assertEqual(snap["percent"], 0)

    def test_progress_updates_percent_and_scanned(self):
        self.bar.start(254)
        self.bar.set_progress(87, 254)
        snap = self.bar.snapshot()
        self.assertEqual(snap["scanned"], 87)
        self.assertEqual(snap["percent"], 34)   # 87/254 ≈ 34%

    def test_progress_is_clamped(self):
        self.bar.start(10)
        self.bar.set_progress(999, 10)
        self.assertEqual(self.bar.snapshot()["percent"], 100)

    def test_zero_total_does_not_divide_by_zero(self):
        self.bar.start(0)
        self.bar.set_progress(0, 0)
        self.assertEqual(self.bar.snapshot()["percent"], 0)

    def test_phase_uses_the_current_language(self):
        self.bar.set_phase("arp", 2, 3)
        self.assertIn("2/3", self.bar.lbl_phase.text())
        i18n.init("en-US")
        self.bar.set_phase("arp", 2, 3)
        en_text = self.bar.lbl_phase.text()
        i18n.init("zh-CN")
        self.assertIn("ARP", en_text)

    def test_counts_are_rendered(self):
        self.bar.start(10)
        self.bar.set_counts(3, 2)
        self.assertIn("3", self.bar.lbl_online.text())
        self.assertIn("2", self.bar.lbl_services.text())

    def test_tick_updates_elapsed_from_the_baseline(self):
        import time
        self.bar.start(10)
        self.bar._started_at = time.perf_counter() - 65
        self.bar.tick()
        self.assertEqual(self.bar.snapshot()["elapsed_s"], 65)
        self.assertIn("01:05", self.bar.lbl_elapsed.text())

    def test_tick_before_start_is_a_noop(self):
        self.bar.tick()          # 不应抛异常
        self.assertEqual(self.bar.snapshot()["elapsed_s"], 0)

    def test_finish_hides(self):
        self.bar.start(10)
        self.bar.finish()
        self.assertTrue(self.bar.isHidden())

    def test_stop_button_emits(self):
        got = []
        self.bar.stop_requested.connect(lambda: got.append(1))
        self.bar.stop_btn.click()
        self.assertEqual(got, [1])


class ScanStatusQssTest(unittest.TestCase):
    """新增的 objectName 必须在两套主题里都有样式，否则深色下漏白。"""

    OBJECT_NAMES = ("scanStatusBar", "scanPhase", "scanMetric",
                    "scanProgress", "scanStop")

    def test_every_object_name_is_styled_in_both_themes(self):
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for obj in self.OBJECT_NAMES:
                self.assertIn("#%s" % obj, src,
                              "%s 缺少 #%s 样式" % (name, obj))


class ScanWiringTest(unittest.TestCase):
    """真 `MainWindow`：摘要条默认隐藏，三个信号都能推进它。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_ss_")
        self._orig_data_dir = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig_data_dir
        i18n.init("zh-CN")

    def test_bar_is_hidden_before_any_scan(self):
        self.assertTrue(self.mw.scan_status.isHidden(),
                        "还没扫描就把扫描态摘要条显示出来了")

    def test_phase_slot_drives_the_bar(self):
        self.mw._on_scan_phase("mdns", 3, 3)
        self.assertIn("3/3", self.mw.scan_status.lbl_phase.text())

    def test_progress_slot_drives_the_bar(self):
        self.mw.scan_status.start(10)
        self.mw._on_scan_progress(4, 10, "10.0.0.4")
        self.assertEqual(self.mw.scan_status.snapshot()["percent"], 40)

    def test_result_slot_counts_online_and_services(self):
        self.mw.scan_status.start(10)
        self.mw._scan_online = 0
        self.mw._scan_services = 0
        self.mw._on_scan_result(
            ScanResult(ip="10.0.0.1", status="online", services=["HTTP"]))
        snap = self.mw.scan_status.snapshot()
        self.assertEqual(snap["online"], 1)
        self.assertEqual(snap["services"], 1)

    def test_offline_result_is_not_counted_as_online(self):
        self.mw.scan_status.start(10)
        self.mw._scan_online = 0
        self.mw._scan_services = 0
        self.mw._on_scan_result(ScanResult(ip="10.0.0.2", status="offline"))
        self.assertEqual(self.mw.scan_status.snapshot()["online"], 0)

    def test_stop_button_is_wired_to_stop_scan(self):
        """条上的「停止」要接到 `_stop_scan`；没有扫描线程时应当安全无操作。"""
        self.assertIsNone(self.mw.scan_thread)
        self.mw.scan_status.stop_btn.click()     # 不应抛异常
        self.assertIsNotNone(self.mw.scan_status)

    def test_thread_exposes_the_phase_signal(self):
        from ui_threads import ScanThread
        self.assertTrue(hasattr(ScanThread, "phase_changed"))


if __name__ == "__main__":
    unittest.main()
