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


class ThrottlePolicyOptionTest(unittest.TestCase):
    """扫描礼貌档（v2.1 §2.4 GUI 露出）：默认 fast、接得到 ScanThread、存得住。

    守的还是同一类静默失效，只是代价更高：档位选了却没传进 `ScanThread`，
    界面一切正常、用户以为"已经在礼貌模式"，实际按全速扫 —— 在别人的生产
    网里，这正是"说好的低影响巡检"变成告警风暴的那条路。

    另一条同样重要：**默认必须是 fast**。改造前没有任何限速，默认档一变，
    所有老用户的下一次扫描就会莫名变慢（且没有任何提示）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_thr_")
        self._orig = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig
        i18n.init("zh-CN")

    # ── 默认档 ──

    def test_defaults_to_fast(self):
        from scanner import throttle
        self.assertEqual(self.mw.throttle_policy, throttle.DEFAULT_POLICY,
                         "默认档必须是 fast —— 不额外设限才与改造前逐字节等价")

    def test_menu_lists_every_policy_by_canonical_name(self):
        """子菜单项的 `data()` 必须是**规范名**（存库/比较/透传都靠它）。"""
        from scanner import throttle
        datas = [a.data() for a in self.mw.throttle_group.actions()]
        self.assertEqual(sorted(datas), sorted(throttle.POLICY_NAMES))
        self.assertTrue(all(isinstance(d, str) and d.isascii() for d in datas),
                        "档位不能拿显示文案当身份（换语言就找不到自己了）")

    # ── 接得到 ScanThread ──

    def test_policy_reaches_the_scan_thread(self):
        from unittest import mock
        import scan_mixin
        from tests.test_scan_local_subnet import _FakeScanThread
        self.mw._set_throttle_policy("polite")
        self.mw.ip_range_items = ["10.0.0.0/30"]
        captured = {}

        class _Recorder(_FakeScanThread):
            def __init__(self, ranges, **kwargs):
                super().__init__(ranges, **kwargs)
                captured.update(kwargs)

        with mock.patch.object(scan_mixin, "ScanThread", _Recorder):
            self.mw._start_scan()
        self.assertEqual(captured.get("throttle_policy"), "polite",
                         "档位没传给 ScanThread —— 礼貌模式永远不会生效")

    def test_audit_records_non_fast_policy_only(self):
        """非 fast 档必须进审计；fast 不记（记了就是每条历史一句废话）。

        口径与 CLI 的 `_audit_throttle` 一致：出了事要能从审计里还原
        "当时是什么档"。
        """
        from unittest import mock
        import scan_mixin
        from tests.test_scan_local_subnet import _FakeScanThread
        self.mw.ip_range_items = ["10.0.0.0/30"]
        seen = []
        with mock.patch.object(type(self.mw), "_audit",
                               side_effect=lambda *a, **k: seen.append(a)):
            with mock.patch.object(scan_mixin, "ScanThread", _FakeScanThread):
                self.mw._set_throttle_policy("fast")
                self.mw._start_scan()
                self.assertNotIn("polite", str(seen), "fast 档不该出现档位字样")
                seen.clear()
                self.mw._set_throttle_policy("polite")
                self.mw._start_scan()
        self.assertIn("polite", str(seen),
                      "非 fast 档没进审计 —— 事后无法还原当时的发包策略")

    # ── 存得住 ──

    def test_switching_persists_and_syncs_the_menu(self):
        self.mw._set_throttle_policy("balanced")
        self.assertEqual(self.mw.throttle_policy, "balanced")
        self.assertEqual(self.mw.settings.value("scan/throttle"), "balanced",
                         "档位没落盘 —— 重启就回到 fast，用户会以为设置坏了")
        checked = [a.data() for a in self.mw.throttle_group.actions()
                   if a.isChecked()]
        self.assertEqual(checked, ["balanced"], "菜单勾选态没跟着切换")

    def test_saved_policy_survives_a_reload(self):
        """重启后仍是用户选的档（读配置路径也要过一遍白名单）。"""
        self.mw._set_throttle_policy("polite")
        self.mw._load_settings()
        self.assertEqual(self.mw.throttle_policy, "polite")

    def test_invalid_stored_value_falls_back_to_fast(self):
        """手工改坏的 ini 不许把扫描卡在未知档上。"""
        from scanner import throttle
        self.mw.settings.setValue("scan/throttle", "turbo")
        self.mw.settings.sync()
        self.mw._load_settings()
        self.assertEqual(self.mw.throttle_policy, throttle.DEFAULT_POLICY)

    def test_invalid_argument_is_ignored(self):
        from scanner import throttle
        self.mw._set_throttle_policy("turbo")
        self.assertEqual(self.mw.throttle_policy, throttle.DEFAULT_POLICY)


class ScanThreadThrottleTest(unittest.TestCase):
    """`ScanThread` 真的把档装进进程，并且**扫描结束一定恢复**。

    为什么必须测"恢复"：`throttle.active_policy()` 装的是**进程级**状态。
    一次 polite 扫描结束后若不还原，后续所有扫描（含用户后来改回 fast 的）
    都会带着限速桶跑 —— 那是"悄悄把工具变慢"，比崩溃更难查。
    """

    def setUp(self):
        from scanner import throttle
        throttle.reset_throttle()

    def tearDown(self):
        from scanner import throttle
        throttle.reset_throttle()

    def _thread_with(self, policy, side_effect=None):
        from unittest import mock
        import ui_threads
        thread = ui_threads.ScanThread(["10.0.0.0/30"],
                                       throttle_policy=policy)
        thread.scanner = mock.Mock()
        thread.scanner.last_adaptive_timeout = None
        if side_effect is None:
            thread.scanner.scan.return_value = []
        else:
            thread.scanner.scan.side_effect = side_effect
        return thread

    def test_default_argument_is_none(self):
        import inspect
        import ui_threads
        sig = inspect.signature(ui_threads.ScanThread.__init__)
        self.assertIsNone(sig.parameters["throttle_policy"].default,
                          "默认必须是 None（= 不显式设档），否则会覆盖调用方的档")

    def test_policy_is_active_inside_the_scan(self):
        from scanner import throttle
        seen = {}
        thread = self._thread_with("polite")
        thread.scanner.scan.side_effect = lambda *a, **k: (
            seen.update(policy=throttle.current_policy().name) or [])
        thread.run()
        self.assertEqual(seen.get("policy"), "polite",
                         "扫描过程中当前档不是 polite —— 限速根本没生效")

    def test_fast_is_the_default_when_unspecified(self):
        from scanner import throttle
        seen = {}
        thread = self._thread_with(None)
        thread.scanner.scan.side_effect = lambda *a, **k: (
            seen.update(policy=throttle.current_policy().name) or [])
        thread.run()
        self.assertEqual(seen.get("policy"), throttle.DEFAULT_POLICY)

    def test_policy_is_restored_after_the_scan(self):
        from scanner import throttle
        self._thread_with("polite").run()
        self.assertEqual(throttle.current_policy().name, throttle.DEFAULT_POLICY,
                         "扫描结束后档位没还原 —— 限速会漏到后续所有扫描")

    def test_policy_is_restored_even_when_the_scan_explodes(self):
        from scanner import throttle
        thread = self._thread_with("polite",
                                   side_effect=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            thread.run()
        self.assertEqual(throttle.current_policy().name, throttle.DEFAULT_POLICY,
                         "扫描抛异常后档位没还原（漏得更隐蔽）")


class _Result:
    """够用的 ScanResult 替身（`run()` 只用到 status / ip / name_responder）。"""

    def __init__(self, ip):
        self.ip = ip
        self.status = "online"
        self.name_responder = {}


if __name__ == "__main__":
    unittest.main()
