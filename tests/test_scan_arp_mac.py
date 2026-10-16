# -*- coding: utf-8 -*-
"""「读取网关 ARP 表补齐 MAC」选项的接线与 `ScanThread` 语义。

**为什么单独一个文件**
沿用 `tests/test_scan_options.py` 的立场：这类"加了个勾选框，但忘了把它
传给 `ScanThread`"的静默失效最难查 —— 界面一切正常，用户勾了，结果里
一片「—」，且**没有任何报错**。本文件把三层都钉住：

1. **默认关** —— 读 ARP 表要 SNMP、且会在网络里产生额外流量，
   必须用户显式开启。
2. **接得到** —— 勾上后 `ScanThread(..., arp_gateway=GATEWAY_AUTO)`；
   没勾必须是空串（**不是** `None`/`False`），因为空串才是"不做"的哨兵。
3. **存得住** —— 预设与 QSettings 都带上它，且**空值要退化回 auto**
   （老配置文件里没这个键时不能把"自动探测"变成"查空地址"）。

另外钉两条 `ScanThread` 侧的红线：
- 读表失败**绝不能**让一次已经跑完的扫描失败；
- 探测不到默认网关时**如实跳过**，绝不退化成「本机网段 .1」的猜测。

⚠ 不写死界面文案（CI 是英文系统，写死中文会本地绿、CI 红）：
勾选框靠**对象属性**（`mw.arp_mac_check`）拿，不断言文案字面量；
日志断言一律用 `tr("…")` 推导。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests._qt_app import ensure_qt_app
ensure_qt_app()

from PyQt5.QtWidgets import QApplication                  # noqa: E402

import i18n                                          # noqa: E402
import main_window                                   # noqa: E402

from tests.test_scan_local_subnet import _FakeScanThread   # noqa: E402


class ArpMacOptionTest(unittest.TestCase):
    """`arp_mac_check`：默认关、接得到 ScanThread、存得住。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_arpmac_")
        self._orig = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        # 保存**原**语言再切中文，结束时还原 —— 不要像早期几个模块那样
        # 留成中文：`i18n` 是**进程级**状态，泄露出去会让字母序在后的模块
        # （即便自己写对了）在 CI（locale=en-US）上集体变红。
        self._lang = i18n.current_lang()
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()
        self.started = []
        self.mw._start_scan = lambda: self.started.append(1)

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig
        i18n.init(self._lang)

    # ── 默认关（最重要的一条） ──

    def test_defaults_to_off(self):
        """读 ARP 表要 SNMP 且会产生额外流量 —— 未经同意绝不能自动开。"""
        self.assertFalse(self.mw.arp_mac_check.isChecked(),
                         "读取网关 ARP 表默认必须是关的")

    def test_is_a_checkable_action_with_a_tooltip(self):
        self.assertTrue(self.mw.arp_mac_check.isCheckable())
        tip = self.mw.arp_mac_check.toolTip()
        self.assertTrue(tip, "没有 tooltip —— 用户不知道它需要 SNMP")
        self.assertNotEqual(tip, self.mw.arp_mac_check.text(),
                            "tooltip 与标签一样 = 等于没有解释")

    def test_is_in_the_settings_menu(self):
        """在菜单里真的能点到（只构造 QAction 而没 addAction 是常见疏漏）。"""
        found = []
        for top in self.mw.menuBar().actions():
            menu = top.menu()
            if menu is None:
                continue
            for act in menu.actions():
                found.append(act)
                sub = act.menu()
                if sub is not None:
                    found.extend(sub.actions())
        self.assertIn(self.mw.arp_mac_check, found)

    # ── 接得到 ScanThread ──

    def _launch_with(self, checked):
        """勾/不勾，然后走真开扫路径，返回传给 ScanThread 的 kwargs。"""
        del self.mw._start_scan                    # 还原真实的开扫逻辑
        self.mw.arp_mac_check.setChecked(checked)
        self.mw.ip_range_items = ["10.0.0.0/30"]
        captured = {}

        class _Recorder(_FakeScanThread):
            def __init__(self, ranges, **kwargs):
                super().__init__(ranges, **kwargs)
                captured.update(kwargs)

        import scan_mixin
        from unittest import mock
        with mock.patch.object(scan_mixin, "ScanThread", _Recorder):
            self.mw._start_scan()
        return captured

    def test_checked_state_reaches_the_scan_thread_as_auto(self):
        """勾上后传的必须是 `GATEWAY_AUTO`（自动探测），不是 `True`。"""
        from arp_mapper import GATEWAY_AUTO
        kwargs = self._launch_with(True)
        self.assertEqual(kwargs.get("arp_gateway"), GATEWAY_AUTO,
                         "勾了却没把网关传给 ScanThread —— 补 MAC 永远不会跑")

    def test_unchecked_state_reaches_the_scan_thread_as_empty(self):
        """没勾必须传空串（"不做"的哨兵），不能是 None/False。"""
        kwargs = self._launch_with(False)
        self.assertEqual(kwargs.get("arp_gateway"), "",
                         "没勾却传了非空值 —— 会在用户不知情时发 SNMP 查询")

    def test_explicit_gateway_is_passed_through(self):
        """用户填了具体 IP 时按原样透传（覆盖自动探测）。"""
        del self.mw._start_scan
        self.mw.arp_mac_check.setChecked(True)
        self.mw.arp_gateway = "10.0.0.254"
        self.mw.ip_range_items = ["10.0.0.0/30"]
        captured = {}

        class _Recorder(_FakeScanThread):
            def __init__(self, ranges, **kwargs):
                super().__init__(ranges, **kwargs)
                captured.update(kwargs)

        import scan_mixin
        from unittest import mock
        with mock.patch.object(scan_mixin, "ScanThread", _Recorder):
            self.mw._start_scan()
        self.assertEqual(captured.get("arp_gateway"), "10.0.0.254")

    # ── 存得住 ──

    def test_scan_preset_carries_it(self):
        from arp_mapper import GATEWAY_AUTO
        self.mw.arp_mac_check.setChecked(True)
        cfg = self.mw._current_scan_config()
        self.assertIs(cfg["arp_mac"], True)
        self.assertEqual(cfg["arp_gateway"], GATEWAY_AUTO)

    def test_scan_preset_restores_it(self):
        self.mw.arp_mac_check.setChecked(True)
        cfg = self.mw._current_scan_config()
        self.mw.arp_mac_check.setChecked(False)
        self.mw.scan_presets.put("t", cfg)
        self.mw._apply_scan_preset("t")
        self.assertTrue(self.mw.arp_mac_check.isChecked(),
                        "预设没恢复这个选项")

    def test_settings_survive_a_restart(self):
        self.mw.arp_mac_check.setChecked(True)
        self.mw._save_settings()
        again = main_window.MainWindow()
        self.addCleanup(again.close)
        self.assertTrue(again.arp_mac_check.isChecked(),
                        "重开软件后勾选状态丢了")

    def test_absent_setting_defaults_to_off_and_auto(self):
        """老配置文件里没有这些键 —— 必须退化成"关 + 自动探测"，不能崩。"""
        from arp_mapper import GATEWAY_AUTO
        self.mw._save_settings()
        from PyQt5.QtCore import QSettings
        s = QSettings(os.path.join(self.tmp, "config.ini"), QSettings.IniFormat)
        s.remove("scan/arp_mac")
        s.remove("scan/arp_gateway")
        s.sync()
        again = main_window.MainWindow()
        self.addCleanup(again.close)
        self.assertFalse(again.arp_mac_check.isChecked())
        self.assertEqual(again.arp_gateway, GATEWAY_AUTO,
                         "缺键时网关必须退化成 auto，不能是空串")

    def test_blank_gateway_falls_back_to_auto(self):
        """🔴 空 / 全空白的网关值必须退化成 auto。

        若原样存成空串，界面勾选态是"开"、但传进 ScanThread 的 `""` 是
        "不做"的哨兵 ⇒ 选项看着开了却永远不生效（静默失效）。
        """
        from arp_mapper import GATEWAY_AUTO
        self.mw.arp_gateway = "   "
        self.mw._save_settings()
        again = main_window.MainWindow()
        self.addCleanup(again.close)
        self.assertEqual(again.arp_gateway, GATEWAY_AUTO)

    def test_explicit_gateway_survives_a_restart(self):
        self.mw.arp_gateway = "10.0.0.254"
        self.mw._save_settings()
        again = main_window.MainWindow()
        self.addCleanup(again.close)
        self.assertEqual(again.arp_gateway, "10.0.0.254")


class ScanThreadArpOptionTest(unittest.TestCase):
    """`ScanThread` 侧的开关语义：默认不做，不做时**一次都不读表**。"""

    def test_thread_defaults_to_empty(self):
        import inspect
        import ui_threads
        sig = inspect.signature(ui_threads.ScanThread.__init__)
        self.assertEqual(sig.parameters["arp_gateway"].default, "",
                         "ScanThread 的 arp_gateway 默认必须是空串（不做）")

    def test_phase_name_is_registered(self):
        """阶段名是**规范值**，必须登记进 `_PHASE_TEXT`（否则摘要条没文案）。"""
        from scanner.constants import _PHASE_TEXT
        self.assertIn("arp_table", _PHASE_TEXT)

    def _stub_scanner(self, thread, results):
        from unittest import mock
        thread.scanner = mock.Mock()
        thread.scanner.scan.return_value = results
        thread.scanner.last_adaptive_timeout = None
        return thread.scanner

    def _run_thread(self, gateway, results):
        """跑一遍 `run()`，返回 `_collect_arp_table` 被调用的次数。"""
        from unittest import mock
        import ui_threads
        thread = ui_threads.ScanThread(["10.0.0.0/30"], arp_gateway=gateway)
        calls = []
        with mock.patch.object(ui_threads.ScanThread, "_collect_arp_table",
                               side_effect=lambda r: calls.append(1)):
            self._stub_scanner(thread, results)
            thread.run()
        return calls

    def test_disabled_does_not_read_the_table(self):
        """关着的时候**一次都不能被调用** —— 每调一次就是一轮 SNMP。"""
        calls = self._run_thread("", [_Result("10.0.0.1")])
        self.assertEqual(calls, [], "选项关着却仍然读了 ARP 表")

    def test_enabled_runs_exactly_once(self):
        """开了就**跑一次**（不是每台设备一次）—— 它是一整张表的 walk。"""
        calls = self._run_thread("auto", [_Result("10.0.0.1"),
                                          _Result("10.0.0.2")])
        self.assertEqual(len(calls), 1, "读表次数与设备数挂了钩")

    def test_no_results_means_no_read(self):
        """一台设备都没有时不读 —— 没有结果可回填，白跑一轮 SNMP。"""
        self.assertEqual(self._run_thread("auto", []), [])


class ScanThreadArpCollectTest(unittest.TestCase):
    """`_collect_arp_table` 的语义：不猜、不抛、失败只提示。"""

    def setUp(self):
        from scanner import throttle
        throttle.reset_throttle()
        self.logs = []
        self.phases = []

    def _thread(self, gateway):
        import ui_threads
        t = ui_threads.ScanThread(["10.0.0.0/30"], arp_gateway=gateway)
        t.log_signal.connect(self.logs.append)
        t.phase_changed.connect(lambda n, i, tot: self.phases.append(n))
        return t

    def _patches(self, detect="", fetch=None):
        """打上 `arp_mapper` 的两个出网点，返回 fetch 的 mock。"""
        from unittest import mock
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(mock.patch("arp_mapper.detect_default_gateway",
                                       return_value=detect))
        fm = mock.Mock(return_value=fetch)
        stack.enter_context(mock.patch("arp_mapper.fetch_arp_table", fm))
        # 厂商查询要读 OUI 库：钉成空串，让断言与库内容无关
        stack.enter_context(mock.patch("arp_mapper.get_mac_vendor",
                                       return_value=""))
        self.addCleanup(stack.close)
        return fm

    def test_auto_gateway_is_resolved_then_used(self):
        from arp_mapper import ArpTableResult
        fm = self._patches(detect="10.9.9.9",
                           fetch=ArpTableResult(host="10.9.9.9"))
        self._thread("auto")._collect_arp_table([_Result("10.0.0.1")])
        self.assertEqual(fm.call_args[0][0], "10.9.9.9",
                         "auto 没解析成默认网关")

    def test_auto_gateway_not_detected_skips_and_logs(self):
        """🔴 探测不到就**如实跳过**，绝不猜「本机网段 .1」。"""
        fm = self._patches(detect="", fetch=None)
        self._thread("auto")._collect_arp_table([_Result("10.0.0.1")])
        self.assertFalse(fm.called,
                         "没探测到网关却仍然发了 SNMP 查询（猜到别处去了）")
        self.assertIn(i18n.tr("未检测到默认网关，跳过 ARP 表补齐 MAC"),
                      self.logs, "跳过时没有任何提示 —— 用户以为功能坏了")

    def test_explicit_gateway_skips_detection(self):
        from arp_mapper import ArpTableResult
        fm = self._patches(detect="10.9.9.9",
                           fetch=ArpTableResult(host="10.0.0.254"))
        self._thread("10.0.0.254")._collect_arp_table([_Result("10.0.0.1")])
        self.assertEqual(fm.call_args[0][0], "10.0.0.254",
                         "填了具体 IP 却被自动探测覆盖了")

    def test_read_failure_does_not_break_the_scan(self):
        """🔴 读表抛异常只该告警 —— 缺的是 MAC，不是设备。"""
        from unittest import mock
        with mock.patch("arp_mapper.detect_default_gateway",
                        return_value="10.9.9.9"):
            with mock.patch("arp_mapper.fetch_arp_table",
                            side_effect=RuntimeError("boom")):
                results = [_Result("10.0.0.1")]
                self._thread("auto")._collect_arp_table(results)   # 不抛即通过
        self.assertTrue(self.logs, "读表异常没有任何痕迹")
        self.assertEqual(results[0].mac, "")

    def test_empty_table_logs_the_error_and_keeps_results(self):
        from arp_mapper import ArpTableResult
        self._patches(detect="10.9.9.9",
                      fetch=ArpTableResult(host="10.9.9.9", error="读不到"))
        results = [_Result("10.0.0.1")]
        self._thread("auto")._collect_arp_table(results)
        self.assertIn("读不到", " ".join(self.logs))
        self.assertEqual(results[0].mac, "")

    def test_successful_read_fills_mac_and_marks_the_row(self):
        from arp_mapper import MAC_SOURCE_SNMP_ARP, ArpTableResult
        self._patches(detect="10.9.9.9", fetch=ArpTableResult(
            host="10.9.9.9", entries={"10.0.0.1": "aa:bb:cc:dd:ee:ff"}))
        results = [_Result("10.0.0.1")]
        thread = self._thread("auto")
        thread._collect_arp_table(results)
        self.assertEqual(results[0].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(results[0].mac_source, MAC_SOURCE_SNMP_ARP)
        self.assertTrue(results[0].mac_updated,
                        "没标 mac_updated —— 界面不会重渲染这一行")
        self.assertIsNotNone(thread.arp_table_result)

    def test_phase_events_are_emitted(self):
        from arp_mapper import ArpTableResult
        self._patches(detect="10.9.9.9", fetch=ArpTableResult(host="10.9.9.9"))
        self._thread("auto")._collect_arp_table([_Result("10.0.0.1")])
        self.assertIn("arp_table", self.phases,
                      "没有发出阶段事件 —— 摘要条看不到这一步")


class _Result:
    """够用的 ScanResult 替身（`_collect_arp_table` 只用这几个字段）。"""

    def __init__(self, ip):
        self.ip = ip
        self.status = "online"
        self.mac = ""
        self.vendor = ""
        self.mac_source = ""
        self.mac_updated = False


if __name__ == "__main__":
    unittest.main()
