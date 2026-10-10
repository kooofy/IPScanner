# -*- coding: utf-8 -*-
"""历史查询后台化：界面不冻结 + 取消真的能中断。

**为什么要真跑事件循环**：这一项修的是"GUI 冻结"。断言"线程对象被创建了"或
"信号连上了"都证明不了界面不卡 —— 只有让事件循环在查询进行期间**真的转过**
（定时器回调被触发），才说明主线程没被占住。所以这里数 QTimer 的触发次数，
而不是看代码结构。

对应 docs/ROADMAP_V1.8.md §1.3 的三条验收：
  ① /16 量级下查询期间主线程事件循环可响应；
  ② 查询带 LIMIT、翻页一致（翻页部分见 test_history_query.py）；
  ③ 取消能真正中断查询。
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests._qt_app import ensure_qt_app

ensure_qt_app()

from PyQt5.QtCore import QElapsedTimer, QTimer           # noqa: E402
from PyQt5.QtTest import QTest                           # noqa: E402

import db_util                                           # noqa: E402
import history_store                                     # noqa: E402
from ui_threads import HistoryQueryThread                # noqa: E402


def _dev(ip):
    return {"ip": ip, "status": "online", "mac": "", "hostname": "",
            "vendor": "", "device_class": "PC", "os_guess": "", "open_ports": "",
            "location": "", "user": "", "remark": ""}


def _seed(db, snapshots=20, per=4000):
    """铺一份"大库"：默认 20 份快照 × 4000 台 = 8 万行。

    不必真到 /16（65 万行）：测试要的是"查询明显跨过若干个事件循环周期"，
    8 万行已经稳定跨过，而 CI 上快得多。量级写在参数里，方便按机器调整。
    """
    for s in range(snapshots):
        history_store.save_snapshot(
            [_dev(f"10.{s % 250}.{i // 250}.{i % 250}") for i in range(per)],
            ts=1000.0 + s, db_path=db, max_keep=10 ** 9)


def _spin_until_idle(predicate, timeout_ms=120000):
    """转事件循环直到 predicate() 为真；返回 (定时器触发次数, 毫秒数)。"""
    ticks = {"n": 0}
    timer = QTimer()
    timer.setInterval(1)
    timer.timeout.connect(lambda: ticks.__setitem__("n", ticks["n"] + 1))
    timer.start()
    clock = QElapsedTimer()
    clock.start()
    while not predicate() and clock.elapsed() < timeout_ms:
        QTest.qWait(5)
    timer.stop()
    return ticks["n"], clock.elapsed()


class _BigDbTest(unittest.TestCase):
    """铺一份"大库"供整类共用。

    用 setUpClass 而不是 setUp：8 万行的写入本身就是秒级，每个用例各铺一次会
    让这几个测试比被测代码还慢。用例只读不写，共用是安全的。
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, "scan_history.db")
        _seed(cls.db)

    @classmethod
    def tearDownClass(cls):
        db_util.close_connection(cls.db)
        shutil.rmtree(cls.tmp, ignore_errors=True)


def _wait_for_idle(dlg, timeout_ms=120000):
    """转事件循环直到对话框这次查询结束；返回 (定时器触发次数, 毫秒数)。

    判据用 `btn_query.isEnabled()` 而**不是** `thread.isRunning()`：
    `_run_query` 里 `_set_busy(True)` 是同步执行的，所以调用后按钮一定是灰的；
    而 `isRunning()` 在 `start()` 之后有一小段窗口可能仍为 False，用它当判据会
    在查询还没跑起来时就"等到"了，测试变成看运气。
    """
    return _spin_until_idle(lambda: dlg.btn_query.isEnabled(), timeout_ms)


class HistoryQueryDialogResponsivenessTest(_BigDbTest):

    def test_query_is_dispatched_and_gui_stays_responsive(self):
        from ui_dialogs import HistoryQueryDialog

        dlg = HistoryQueryDialog(db_path=self.db)
        try:
            # ① 构造函数必须**立刻返回**：查询已被派发到后台线程，结果还没进表格。
            #    若有人把查询改回同步执行，_thread 会是 None（压根没建线程），
            #    且 rowCount 会已经 > 0 —— 这两条就是本测试真正的回归守卫。
            self.assertIsNotNone(
                dlg._thread,
                "查询没有走后台线程：构造函数里同步执行会冻住界面")
            self.assertEqual(
                dlg.table.rowCount(), 0,
                "构造函数返回时结果已填进表格 —— 说明查询是在调用方线程跑完的")

            # ② 查询进行期间，主线程的事件循环必须能继续跑。
            ticks, elapsed = _wait_for_idle(dlg)
            self.assertGreater(
                ticks, 0,
                f"查询期间事件循环一次都没转（耗时 {elapsed}ms）—— 界面是冻的")

            # ③ 结果最终落到表格上，且受 LIMIT 约束（分页）。
            self.assertEqual(dlg.table.rowCount(), dlg.PAGE_SIZE)
            self.assertTrue(dlg._has_more, "8 万行数据应当提示还有更多")
            self.assertTrue(dlg.btn_more.isEnabled(), "「加载更多」没有启用")
        finally:
            dlg._close()

    def test_load_more_appends_next_page(self):
        from ui_dialogs import HistoryQueryDialog

        dlg = HistoryQueryDialog(db_path=self.db)
        try:
            _wait_for_idle(dlg)
            first = [dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())]
            self.assertEqual(len(first), dlg.PAGE_SIZE)

            dlg._load_more()
            _wait_for_idle(dlg)

            self.assertEqual(dlg.table.rowCount(), dlg.PAGE_SIZE * 2)
            second = [dlg.table.item(r, 0).text()
                      for r in range(dlg.PAGE_SIZE, dlg.table.rowCount())]
            # 第二页不能是第一页的重复 —— 这正是 offset 传错时的典型症状
            self.assertFalse(set(first) & set(second), "翻页出现了重复行")
        finally:
            dlg._close()


class HistoryQueryThreadCancelTest(_BigDbTest):

    def test_stop_emits_cancelled_not_finished(self):
        t = HistoryQueryThread({}, db_path=self.db)
        got = []
        t.finished_signal.connect(lambda rows: got.append("rows"))
        t.cancelled_signal.connect(lambda: got.append("cancelled"))
        t.start()
        t.stop()                    # 立刻取消，不等它跑完
        self.assertTrue(t.wait(60000), "取消后线程未在 60s 内结束")
        QTest.qWait(50)             # 让跨线程排队的信号送达
        self.assertIn("cancelled", got, "取消没有发出 cancelled_signal")
        self.assertNotIn("rows", got, "取消后仍然回传了结果")

    def test_stop_returns_promptly(self):
        """取消要**中断读盘**，而不是等整张表读完再丢结果。"""
        t = HistoryQueryThread({}, db_path=self.db)
        t.start()
        QTest.qWait(30)             # 让它先真的读起来
        clock = QElapsedTimer()
        clock.start()
        t.stop()
        self.assertTrue(t.wait(30000))
        self.assertLess(
            clock.elapsed(), 20000,
            "取消耗时过长 —— 检查点大概没落在分块取数的循环里")


class HistoryCompareDialogLoadTest(unittest.TestCase):
    """对比对话框不得再把**全部**快照的设备明细读进来。

    旧实现在 `__init__` 里 `load_all()`：默认 20 份快照、每份几千台设备，
    打开对话框就要读几万行，而它其实只需要填两个下拉框。现在下拉框走
    `list_snapshots()`（每份一行元信息），明细等点「对比」时按需读两份。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")
        for s in range(3):
            history_store.save_snapshot(
                [_dev(f"10.0.0.{i}") for i in range(5)],
                ts=1000.0 + s, db_path=self.db, max_keep=10 ** 9)

    def tearDown(self):
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_open_does_not_load_all_device_rows(self):
        from ui_dialogs import HistoryCompareDialog

        calls = []
        orig = history_store.load_all

        def _spy(*a, **kw):
            calls.append(1)
            return orig(*a, **kw)

        history_store.load_all = _spy
        try:
            dlg = HistoryCompareDialog(db_path=self.db)
        finally:
            history_store.load_all = orig
        try:
            self.assertEqual(calls, [], "打开对比对话框又全量读了快照明细")
            self.assertEqual(dlg.base_combo.count(), 3)
            # itemData 必须是快照 id，不是列表下标 —— 对比是异步的，下标会失效
            self.assertEqual(dlg.base_combo.itemData(0), dlg.snaps[2]["id"])
        finally:
            dlg.close()


if __name__ == "__main__":
    unittest.main()
