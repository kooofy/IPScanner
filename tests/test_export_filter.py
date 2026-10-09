# -*- coding: utf-8 -*-
"""导出扫描结果必须跟随当前筛选（与「打印」同一口径）。

背景
----
`_export_results()` 以前把**全量** `all_results` 交给导出器，而界面默认筛选是
「仅在线」—— 离线行在表格里被隐藏，却照样出现在导出的文件里。实测一次
`10.193.28.0/22` 扫描：导出 1023 行，其中 **952 行是离线**，用户完全无从理解
（他的预期是"导出扫描到的（在线）终端"）。

而「打印」一直是"所见即所得"（`_print_results` 跳过 `item.isHidden()`）。
本文件钉住改造后的口径：

1. 导出 == 屏幕上看得见的那些行（四种格式一致）；
2. 被筛掉的行数要**如实告知**用户 —— 否则"导出 3 条"和"扫到 8 台"对不上，
   用户会以为程序丢了数据；
3. 一条都不可见时**不写文件**，也不弹保存对话框。

配置一律隔离到临时目录，不碰用户的 `ipscanner.ini`。
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
from scanner.models import ScanResult

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


class _WindowCase(unittest.TestCase):
    """真实 `MainWindow`，配置隔离到临时目录。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_export_")
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

    # ── 夹具 ────────────────────────────────────────────────

    def _add(self, ip, status, **kw):
        r = ScanResult(ip=ip, status=status, **kw)
        self.mw.all_results.append(r)
        self.mw._upsert_table_row(r)
        return r

    def _seed(self):
        """3 台在线 + 5 台离线（一次小网段扫描的样子）。"""
        self.online_ips = [f"10.1.2.{i}" for i in (10, 11, 12)]
        self.offline_ips = [f"10.1.2.{i}" for i in (1, 2, 3, 4, 5)]
        for ip in self.online_ips:
            self._add(ip, "online")
        for ip in self.offline_ips:
            self._add(ip, "offline")
        self.mw._filter_results()
        self.mw._refresh_filter_counts()

    def _export(self, fmt="xlsx", selected_filter="Excel 文件 (*.xlsx)"):
        """跑一次 `_export_results()`。

        返回 `(传给导出器的 results, 导出器 mock, msg_info mock)`。
        """
        captured = []

        def fake(results, path):
            captured.append(list(results))
            return True, f"已导出 {len(results)} 条记录"

        target = {
            "xlsx": "export_mixin.export_results",
            "csv": "export_mixin.export_csv",
            "html": "export_mixin.export_html",
            "json": "export_mixin.export_json",
        }[fmt]

        with patch("export_mixin.QFileDialog") as dlg, \
                patch(target, side_effect=fake) as exporter, \
                patch("export_mixin.msg_info") as info:
            dlg.getSaveFileName.return_value = (
                os.path.join(self.tmp, "out." + fmt), selected_filter)
            self.mw._export_results()
            QApplication.processEvents()

        return captured, exporter, info

    @staticmethod
    def _ips(results):
        return [r.ip for r in results]


class VisibleResultsTest(_WindowCase):
    """`_visible_results()` 是导出的取数口径，先钉住它本身。"""

    def test_default_filter_hides_offline_rows(self):
        self._seed()
        self.assertEqual(self.mw.filter_key, "online",
                         "默认筛选不再是「仅在线」，本文件的其余假设都要重审")
        hidden = sorted(ip for ip, it in self.mw._ip_item_map.items()
                        if it.isHidden())
        self.assertEqual(hidden, sorted(self.offline_ips),
                         "默认「仅在线」下离线行没有被隐藏")

    def test_visible_results_excludes_offline_under_default_filter(self):
        self._seed()
        self.assertEqual(sorted(self._ips(self.mw._visible_results())),
                         sorted(self.online_ips))

    def test_switching_to_all_restores_everything(self):
        self._seed()
        self.mw._set_filter("all")
        QApplication.processEvents()
        self.assertEqual(len(self.mw._visible_results()), 8)

    def test_offline_filter_yields_only_offline(self):
        self._seed()
        self.mw._set_filter("offline")
        QApplication.processEvents()
        self.assertEqual(sorted(self._ips(self.mw._visible_results())),
                         sorted(self.offline_ips))

    def test_search_box_narrows_the_visible_set(self):
        self._seed()
        self.mw._set_filter("all")
        self.mw.search_input.setText("10.1.2.11")
        self.mw._filter_results()
        QApplication.processEvents()
        self.assertEqual(self._ips(self.mw._visible_results()), ["10.1.2.11"])

    def test_visible_results_keep_scan_order(self):
        """顺序沿用 `all_results`，不跟表格当前的排序 —— 导出要的是稳定顺序。"""
        self._seed()
        self.mw._set_filter("all")
        QApplication.processEvents()
        self.assertEqual(self._ips(self.mw._visible_results()),
                         [r.ip for r in self.mw.all_results])


class ExportFollowsFilterTest(_WindowCase):
    """四种格式都必须只导出可见行 —— 这正是"点了没反应"之外的那个缺陷。"""

    def test_excel_export_excludes_hidden_rows(self):
        self._seed()
        captured, exporter, _ = self._export("xlsx")
        self.assertEqual(exporter.call_count, 1)
        self.assertEqual(sorted(self._ips(captured[0])), sorted(self.online_ips),
                         "导出把被隐藏的离线行也带出去了")

    def test_every_format_follows_the_filter(self):
        self._seed()
        for fmt in ("csv", "html", "json"):
            with self.subTest(fmt=fmt):
                captured, exporter, _ = self._export(fmt)
                self.assertEqual(exporter.call_count, 1, f"{fmt} 导出器没被调用")
                self.assertEqual(sorted(self._ips(captured[0])),
                                 sorted(self.online_ips), f"{fmt} 没有跟随筛选")

    def test_all_filter_exports_everything(self):
        self._seed()
        self.mw._set_filter("all")
        QApplication.processEvents()
        captured, _, _ = self._export("xlsx")
        self.assertEqual(len(captured[0]), 8)

    def test_nothing_visible_warns_and_never_calls_the_exporter(self):
        self._seed()
        # 搜一个不存在的串 → 一条都不可见（比用某个筛选键更稳，不依赖冲突表）
        self.mw.search_input.setText("no-such-host-zzz")
        self.mw._filter_results()
        QApplication.processEvents()

        with patch("export_mixin.QFileDialog") as dlg, \
                patch("export_mixin.export_results") as exporter, \
                patch("export_mixin.msg_warn") as warned:
            self.mw._export_results()
            QApplication.processEvents()

        exporter.assert_not_called()
        dlg.getSaveFileName.assert_not_called()   # 连保存对话框都不该弹
        self.assertEqual(warned.call_count, 1, "一条都不可见时必须提示，且只提示一次")


class ExportMessageTest(_WindowCase):
    """被筛掉的行数要如实告知，否则"导出 3 条"和"扫到 8 台"对不上。"""

    def test_success_message_reports_skipped_rows(self):
        self._seed()
        _, _, info = self._export("xlsx")
        text = info.call_args[0][2]
        self.assertIn("跳过 5 条", text, f"没有告知被跳过的 5 条离线记录：{text}")

    def test_no_note_when_nothing_was_filtered_out(self):
        self._seed()
        self.mw._set_filter("all")
        QApplication.processEvents()
        _, _, info = self._export("xlsx")
        self.assertNotIn("跳过", info.call_args[0][2])

    def test_audit_records_the_exported_count_not_the_total(self):
        self._seed()
        with patch.object(self.mw, "_audit") as audit:
            self._export("xlsx")
        self.assertEqual(audit.call_count, 1)
        detail = audit.call_args[0][2]
        self.assertIn("3 条", detail, f"审计记录的不是导出条数：{detail}")


if __name__ == "__main__":
    unittest.main()
