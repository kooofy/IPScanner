# -*- coding: utf-8 -*-
"""「扫描本机所在子网」入口的行为（点击即开扫 + 防重复开扫）。

背景
----
改造前这个入口（空状态主 CTA / 工具栏「本机子网」/ 菜单项，共三个）**只把网段
填进输入框、不开始扫描**，而：

- 启动时 `_auto_detect_subnet()` 已经把同一个网段填好了，`setText()` 同样的
  文本不产生任何可见变化；
- 唯一的反馈写进 `range_list_label`，而它在创建时就是 `setVisible(False)`
  （"保留兼容，但控件已隐藏"）；
- 状态栏也不动。

于是点下去**界面上零变化** —— 而按钮文案是「扫描本机所在子网」、空状态副标题
写着"或**直接扫描**本机所在子网"。承诺与实现相反，用户只能以为程序坏了。

本文件钉住修好之后的两条不变量：

1. 三个入口都**真的开始扫描**（不是只填输入框）；
2. 扫描进行中再触发任何入口都**不会并发开第二个扫描**。
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

import i18n
import main_window

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


class _Signal:
    """替身信号的 `.connect()` —— 扫描线程的信号在测试里不需要真的送达。"""

    def connect(self, *args, **kwargs):
        pass


class _FakeScanThread:
    """替身 `ScanThread`：只记录"被启动过"，不真的开线程。"""

    def __init__(self, ranges, **kwargs):
        self.ranges = list(ranges)
        self.kwargs = kwargs
        self.progress = _Signal()
        self.phase_changed = _Signal()
        self.result_ready = _Signal()
        self.finished_signal = _Signal()
        self.log_signal = _Signal()
        self.scanner = None
        self.started = False

    def start(self):
        self.started = True

    def isRunning(self):
        return False


class _RunningThread:
    """"已经在跑"的替身：`isRunning()` 恒为 True。"""

    def __init__(self):
        self.stopped = False

    def isRunning(self):
        return True

    def stop(self):
        self.stopped = True

    def wait(self, _ms=None):
        return True


def _find_action(mw, text):
    """在菜单栏（含一层子菜单）里按文案找 `QAction`；找不到返回 None。"""
    for top in mw.menuBar().actions():
        menu = top.menu()
        if menu is None:
            continue
        for act in menu.actions():
            sub = act.menu()
            if sub is None:
                if act.text() == text:
                    return act
                continue
            for inner in sub.actions():
                if inner.text() == text:
                    return inner
    return None


class _WindowCase(unittest.TestCase):
    """每个用例一个真实 `MainWindow`，配置隔离到临时目录。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_lsub_")
        self._orig = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()
        self.started = []
        # 绝大多数用例只关心**是否**开扫，所以默认把真开扫换成记录调用；
        # 需要走真路径的用例用 `del self.mw._start_scan` 还原。
        self.mw._start_scan = lambda: self.started.append(1)

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig
        i18n.init("zh-CN")

    def _detect(self, subnet):
        self.mw._get_local_subnet = lambda: subnet


class EntryPointTest(_WindowCase):
    """三个入口都必须真的开扫 —— 这正是"点了没反应"的那个缺陷。"""

    def test_empty_state_primary_cta_starts_a_scan(self):
        self._detect("10.1.2.0/24")
        self.mw.empty_state.btn_local.click()
        QApplication.processEvents()
        self.assertEqual(self.started, [1], "空状态主 CTA 没有开始扫描")
        self.assertEqual(self.mw.ip_range_items, ["10.1.2.0/24"])
        self.assertEqual(self.mw.range_input.text(), "10.1.2.0/24")

    def test_toolbar_button_starts_a_scan(self):
        self._detect("10.1.2.0/24")
        self.mw.local_subnet_btn.click()
        QApplication.processEvents()
        self.assertEqual(self.started, [1], "工具栏「本机子网」没有开始扫描")
        self.assertEqual(self.mw.ip_range_items, ["10.1.2.0/24"])

    def test_menu_action_starts_a_scan(self):
        act = _find_action(self.mw, "扫描本机所在子网")
        self.assertIsNotNone(act, "菜单里找不到「扫描本机所在子网」")
        self._detect("10.1.2.0/24")
        act.trigger()
        QApplication.processEvents()
        self.assertEqual(self.started, [1], "菜单项没有开始扫描")

    def test_c_class_menu_action_starts_a_scan(self):
        act = _find_action(self.mw, "扫描 C 类子网")
        self.assertIsNotNone(act, "菜单里找不到「扫描 C 类子网」")
        self.mw._get_c_class_subnet = lambda: "10.1.2.0/24"
        act.trigger()
        QApplication.processEvents()
        self.assertEqual(self.started, [1], "「扫描 C 类子网」没有开始扫描")

    def test_clicking_twice_does_not_duplicate_the_range(self):
        self._detect("10.1.2.0/24")
        self.mw.empty_state.btn_local.click()
        self.mw.empty_state.btn_local.click()
        QApplication.processEvents()
        self.assertEqual(self.mw.ip_range_items, ["10.1.2.0/24"],
                         "同一个网段被重复加进了待扫列表")
        self.assertEqual(len(self.started), 2, "第二次点击也应重新开扫")

    def test_subnet_is_detected_with_a_real_mask_not_always_slash_24(self):
        """入口用的是 `_get_local_subnet()`（含真实前缀长度），不是硬拼 /24。"""
        self._detect("10.193.28.0/22")
        self.mw.empty_state.btn_local.click()
        QApplication.processEvents()
        self.assertEqual(self.mw.ip_range_items, ["10.193.28.0/22"])


class FailurePathTest(_WindowCase):
    """探测不到 / 网段超限 → 必须**明确提示**，且不开扫、不静默。"""

    def test_no_subnet_warns_and_does_not_scan(self):
        self._detect(None)
        with patch("scan_mixin.msg_warn") as warned:
            self.mw.empty_state.btn_local.click()
            QApplication.processEvents()
        self.assertEqual(self.started, [], "拿不到本机 IP 时不该开扫")
        self.assertEqual(warned.call_count, 1, "拿不到本机 IP 时必须提示")

    def test_oversized_subnet_warns_and_does_not_scan(self):
        self._detect("10.0.0.0/8")          # 16777214 个 IP，远超单次上限
        with patch("scan_mixin.msg_warn") as warned:
            self.mw.empty_state.btn_local.click()
            QApplication.processEvents()
        self.assertEqual(self.started, [], "超限网段不该开扫")
        self.assertEqual(warned.call_count, 1, "超限时该提示，且只提示一次")
        self.assertEqual(self.mw.ip_range_items, [], "超限网段不该进待扫列表")
        self.assertEqual(self.mw.range_input.text(), "10.0.0.0/8",
                         "网段仍应填进输入框，方便用户手工拆小后再扫")


class ScanReallyStartsTest(_WindowCase):
    """端到端：点一下 → 真的进入扫描态（这才是用户能看到的"反应"）。"""

    def setUp(self):
        super().setUp()
        del self.mw._start_scan               # 还原真实的开扫逻辑

    def test_click_enters_scan_state_and_shows_the_status_bar(self):
        self._detect("10.1.2.0/24")
        with patch("scan_mixin.ScanThread", _FakeScanThread):
            self.mw.empty_state.btn_local.click()
            QApplication.processEvents()

        thread = self.mw.scan_thread
        self.assertIsInstance(thread, _FakeScanThread, "没有创建扫描线程")
        self.assertTrue(thread.started, "ScanThread 没有被启动")
        self.assertEqual(thread.ranges, ["10.1.2.0/24"])
        self.assertFalse(self.mw.scan_btn.isEnabled(), "「扫描」按钮没有被禁用")
        self.assertTrue(self.mw.stop_btn.isEnabled(), "「停止」按钮没有启用")
        self.assertEqual(self.mw.result_stack.currentIndex(), 1,
                         "没有切到结果页 —— 用户看不到任何扫描反馈")
        self.assertTrue(self.mw.scan_status.isVisible(),
                        "扫描态摘要条没有显示")


class ReentryGuardTest(_WindowCase):
    """扫描进行中，任何入口都不得并发开第二个扫描。

    扫描期间**只有「扫描」按钮被禁用**，F5 / 菜单 / 工具栏「本机子网」/
    「C 类子网」都还点得到。改造前这些入口最多只是"填一下输入框"（无害），
    现在它们会真的开扫 —— 少了闸门就会两个 `ScanThread` 同时 upsert 同一张表。
    """

    def test_guard_sees_a_running_thread(self):
        self.mw.scan_thread = _RunningThread()
        self.assertTrue(self.mw._scan_in_progress())

    def test_none_thread_is_not_running(self):
        self.mw.scan_thread = None
        self.assertFalse(self.mw._scan_in_progress())

    def test_finished_thread_is_not_running(self):
        """`scan_thread` 扫完**不会置回 None**，所以不能只看它非空。"""
        self.mw.scan_thread = _FakeScanThread([])       # isRunning() -> False
        self.assertFalse(self.mw._scan_in_progress())

    def test_second_start_is_refused_while_running(self):
        del self.mw._start_scan
        running = _RunningThread()
        self.mw.scan_thread = running
        with patch("scan_mixin.ScanThread") as ctor:
            self.mw._start_scan()
            QApplication.processEvents()
        ctor.assert_not_called()
        self.assertIs(self.mw.scan_thread, running, "扫描在跑时被换了线程对象")
        self.assertIn("扫描正在进行中", self.mw.status_bar.currentMessage())

    def test_entry_point_is_refused_while_running(self):
        del self.mw._start_scan
        self._detect("10.1.2.0/24")
        self.mw.scan_thread = _RunningThread()
        with patch("scan_mixin.ScanThread") as ctor:
            self.mw.empty_state.btn_local.click()
            QApplication.processEvents()
        ctor.assert_not_called()

    def test_guard_lifts_after_the_scan_finishes(self):
        del self.mw._start_scan
        self.mw.scan_thread = _FakeScanThread([])       # 已结束
        self._detect("10.1.2.0/24")
        # 用真 `Mock` 做替身（`patch(target, new)` 直接给 new 时 `as` 拿到的
        # 就是那个 new 本身，没有 `call_count`），`side_effect` 让它仍然
        # 产出 `_FakeScanThread` 实例。
        with patch("scan_mixin.ScanThread") as ctor:
            ctor.side_effect = _FakeScanThread
            self.mw.empty_state.btn_local.click()
            QApplication.processEvents()
        self.assertEqual(ctor.call_count, 1, "上一轮扫完后应能正常再扫")
        self.assertIsInstance(self.mw.scan_thread, _FakeScanThread)


if __name__ == "__main__":
    unittest.main()
