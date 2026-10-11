# -*- coding: utf-8 -*-
"""扫描选项的接线（v1.9 #3 第二刀）。

为什么单独一个文件
------------------
「加了个勾选框，但忘了把它传给 `ScanThread`」是这类功能最典型的静默失效：
界面看着一切正常，用户勾了，扫描结果里却什么都没有，而且**没有任何报错**。
`tests/test_scan_local_subnet.py` 已经用同样的手法守过"扫描闸门"，
这里沿用它的替身（`_FakeScanThread` 记录 kwargs）来守新选项。

本文件重点守三件事：

1. **默认关** —— 名字响应器探测会往网络里**发组播/广播包**，与"被动发现"
   的零发包原则冲突。默认必须是关的；哪天有人把它改成默认开，这里会红。
2. **接得到** —— 勾上之后 `ScanThread(..., name_responder=True)` 必须真的收到，
   否则探测永远不会跑（静默失效）。
3. **存得住** —— 预设与 QSettings 都要带上它。漏存的话用户每次重开软件
   都得重新勾，久而久之就没人用了。

⚠ 不写死界面文案（CI 是英文系统，写死中文会本地绿、CI 红）：
勾选框靠**对象属性**（`mw.responder_check`）拿，不靠菜单文案找。
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


class ResponderOptionTest(unittest.TestCase):
    """`responder_check`：默认关、接得到 ScanThread、存得住。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_opt_")
        self._orig = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()
        # 默认把"真开扫"换掉：绝大多数用例只关心参数有没有传对。
        self.started = []
        self.mw._start_scan = lambda: self.started.append(1)

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig
        i18n.init("zh-CN")

    # ── 默认关（最重要的一条） ──

    def test_defaults_to_off(self):
        """探测会发组播/广播包 —— 未经用户同意绝不能自动开。"""
        self.assertFalse(self.mw.responder_check.isChecked(),
                         "名字响应器探测默认必须是关的（它会往网络里发包）")

    def test_is_a_checkable_action_with_a_tooltip(self):
        self.assertTrue(self.mw.responder_check.isCheckable())
        tip = self.mw.responder_check.toolTip()
        self.assertTrue(tip, "没有 tooltip —— 用户不知道这个开关会发包")
        self.assertNotEqual(tip, self.mw.responder_check.text(),
                            "tooltip 与标签一样 = 等于没有解释")

    def test_is_in_the_settings_menu(self):
        """在菜单里真的能点到（只是构造了 QAction 而没 addAction 是常见疏漏）。"""
        texts = []
        for top in self.mw.menuBar().actions():
            menu = top.menu()
            if menu is None:
                continue
            for act in menu.actions():
                texts.append(act)
                sub = act.menu()
                if sub is not None:
                    texts.extend(sub.actions())
        self.assertIn(self.mw.responder_check, texts)

    # ── 接得到 ScanThread ──

    def _launch_with(self, checked):
        """勾/不勾，然后走真开扫路径，返回传给 ScanThread 的 kwargs。"""
        del self.mw._start_scan                    # 还原真实的开扫逻辑
        self.mw.responder_check.setChecked(checked)
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

    def test_checked_state_reaches_the_scan_thread(self):
        kwargs = self._launch_with(True)
        self.assertIs(kwargs.get("name_responder"), True,
                      "勾了却没传给 ScanThread —— 探测永远不会跑（静默失效）")

    def test_unchecked_state_reaches_the_scan_thread(self):
        kwargs = self._launch_with(False)
        self.assertIs(kwargs.get("name_responder"), False)

    # ── 存得住 ──

    def test_scan_preset_carries_it(self):
        self.mw.responder_check.setChecked(True)
        self.assertIs(self.mw._current_scan_config()["name_responder"], True)

    def test_scan_preset_restores_it(self):
        self.mw.responder_check.setChecked(True)
        cfg = self.mw._current_scan_config()
        self.mw.responder_check.setChecked(False)
        self.mw.scan_presets.put("t", cfg)
        self.mw._apply_scan_preset("t")
        self.assertTrue(self.mw.responder_check.isChecked(),
                        "预设没恢复这个选项")

    def test_settings_survive_a_restart(self):
        self.mw.responder_check.setChecked(True)
        self.mw._save_settings()
        again = main_window.MainWindow()
        self.addCleanup(again.close)
        self.assertTrue(again.responder_check.isChecked(),
                        "重开软件后勾选状态丢了")

    def test_absent_setting_defaults_to_off(self):
        """老配置文件里没有这个键 —— 必须退化成"关"，而不是崩或默认开。"""
        self.mw._save_settings()
        # 造一个"旧版本"留下的 QSettings（没有 scan/name_responder）
        from PyQt5.QtCore import QSettings
        s = QSettings(os.path.join(self.tmp, "config.ini"),
                      QSettings.IniFormat)
        s.remove("scan/name_responder")
        s.sync()
        again = main_window.MainWindow()
        self.addCleanup(again.close)
        self.assertFalse(again.responder_check.isChecked())


class ScanThreadResponderTest(unittest.TestCase):
    """`ScanThread` 侧的开关语义：默认关，关着时**一个包都不发**。"""

    def test_thread_defaults_to_off(self):
        import inspect
        import ui_threads
        sig = inspect.signature(ui_threads.ScanThread.__init__)
        self.assertIs(sig.parameters["name_responder"].default, False,
                      "ScanThread 的 name_responder 默认必须是 False")

    def _stub_scanner(self, thread, results):
        """把线程里的扫描器换成替身，并补齐 `run()` 会读的属性。

        ⚠ `last_adaptive_timeout` 必须给个真数字（或 None）：`run()` 会拿它
        跟 0.5 相减，留成 Mock 会在 `Mock - float` 上炸掉。
        """
        from unittest import mock
        thread.scanner = mock.Mock()
        thread.scanner.scan.return_value = results
        thread.scanner.last_adaptive_timeout = None
        return thread.scanner

    def _run_thread(self, enabled, results):
        """跑一遍 `run()`，扫描器换成替身；返回被调用的探测次数。"""
        from unittest import mock
        import ui_threads
        thread = ui_threads.ScanThread(["10.0.0.0/30"],
                                       name_responder=enabled)
        calls = []
        with mock.patch.object(ui_threads.ScanThread, "_collect_responders",
                               side_effect=lambda r: calls.append(1)):
            self._stub_scanner(thread, results)
            thread.run()
        return calls

    def test_disabled_sends_nothing(self):
        """关着的时候探测函数**一次都不能被调用** —— 它每调一次就发一个包。"""
        calls = self._run_thread(False, [_Result("10.0.0.1")])
        self.assertEqual(calls, [], "选项关着却仍然跑了探测")

    def test_enabled_runs_exactly_once(self):
        """开了就**跑一次**（不是每台设备一次）—— 它是一次全网组播/广播。"""
        calls = self._run_thread(True, [_Result("10.0.0.1"),
                                        _Result("10.0.0.2")])
        self.assertEqual(len(calls), 1, "探测次数与设备数挂了钩")

    def test_no_results_means_no_probe(self):
        """一台设备都没有时不探测 —— 没有 results 可挂，白发包。"""
        self.assertEqual(self._run_thread(True, []), [])

    def test_probe_failure_does_not_break_the_scan(self):
        """探测抛异常只该告警 —— 它不该让一次已经成功的扫描失败。

        同时断言**确实留了痕**：探测失败意味着"网络里有没有欺骗响应器"这个
        结论缺失，属于用户能感知的结果缺失，不能静默吞掉。
        ⚠ logger 名只取最后一段（`get_logger(__name__)` → `ipscanner.ui_threads`），
        写全路径抓不到。
        """
        from unittest import mock
        import ui_threads
        thread = ui_threads.ScanThread(["10.0.0.0/30"], name_responder=True)
        results = [_Result("10.0.0.1")]
        self._stub_scanner(thread, results)
        with mock.patch("scanner.llmnr_nbns.probe_responders",
                        side_effect=RuntimeError("boom")):
            with self.assertLogs("ipscanner.ui_threads", level="WARNING") as cap:
                thread.run()        # 不抛即通过
        self.assertTrue(any("boom" in m for m in cap.output),
                        "探测失败没有任何痕迹")
        self.assertEqual(len(results), 1)

    def test_apply_responders_attaches_to_results(self):
        """探测结果必须真的挂到 results 上 —— 否则快照里永远是空的。"""
        from unittest import mock
        import ui_threads
        thread = ui_threads.ScanThread(["10.0.0.0/30"], name_responder=True)
        results = [_Result("10.0.0.1")]
        self._stub_scanner(thread, results)
        with mock.patch("scanner.llmnr_nbns.probe_responders",
                        return_value={"10.0.0.1": {"llmnr": "ipscanner-x"}}):
            thread.run()
        self.assertEqual(results[0].name_responder, {"llmnr": "ipscanner-x"})


class _Result:
    """够用的 ScanResult 替身（`run()` 只用到 status / ip / name_responder）。"""

    def __init__(self, ip):
        self.ip = ip
        self.status = "online"
        self.name_responder = {}


if __name__ == "__main__":
    unittest.main()
