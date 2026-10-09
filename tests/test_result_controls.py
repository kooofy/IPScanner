# -*- coding: utf-8 -*-
"""空状态主次按钮 + 无结果时隐藏结果控件（批次 3 / docs/reviews/UI_REVIEW_ROUND2.md §5 第 9 项）。

两件事都是"第一屏"的问题：

1. 空状态的两个按钮此前**同为浅灰底**，"哪个才是推荐动作"完全看不出来 ——
   实测截图 `docs/ui-review-round2/04-空状态引导页-浅色.png` 里两个按钮一模一样；
2. 「视图切换 + 结果筛选条」在一条结果都没有时依然常驻：chip 的计数全是 0，
   视图切换也只能切到同一个空状态页，留着只会让人误以为"是筛选把结果藏起来了"。

第 2 条要真实 `MainWindow` 才能验证（涉及 QStackedWidget 与工具栏布局），
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
from empty_state import EmptyStatePanel
from scanner.models import ScanResult

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


class EmptyStateHierarchyTest(unittest.TestCase):
    """主 CTA 与次按钮必须用**不同**的 objectName，层级才存在。"""

    def setUp(self):
        self.panel = EmptyStatePanel()

    def tearDown(self):
        self.panel.deleteLater()

    def test_primary_cta_is_not_the_shared_neutral_button(self):
        self.assertEqual(self.panel.btn_local.objectName(), "emptyPrimary")
        self.assertEqual(self.panel.btn_scan.objectName(), "emptySecondary")

    def test_the_two_names_are_different(self):
        self.assertNotEqual(self.panel.btn_local.objectName(),
                            self.panel.btn_scan.objectName(),
                            "两个按钮共用样式 = 没有层级")

    def test_primary_is_filled_and_secondary_is_not(self):
        """主按钮是实心强调色，次按钮是描边/浅底 —— 用 QSS 里的
        `background-color` 是否存在来判定，避免把具体色值写死在测试里。"""
        light = _qss("light.qss")
        dark = _qss("dark.qss")
        for src, name in ((light, "light.qss"), (dark, "dark.qss")):
            for obj in ("emptyPrimary", "emptySecondary"):
                self.assertIn("#%s" % obj, src, "%s 缺少 #%s" % (name, obj))
        # 两套主题里主按钮都有实心底色，且与次按钮不同
        for src in (light, dark):
            self.assertIn("QPushButton#emptyPrimary {", src)


class ResultControlsVisibilityTest(unittest.TestCase):
    """无结果时隐藏「视图切换 + 筛选条」，有结果后恢复。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_rc_")
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

    def test_hidden_when_there_are_no_results(self):
        self.assertEqual(self.mw.all_results, [])
        self.assertTrue(self.mw.view_toggle.isHidden(),
                        "没有结果时视图切换仍显示")
        self.assertTrue(self.mw.filter_scroll.isHidden(),
                        "没有结果时筛选条仍显示（chip 计数全是 0）")

    def test_restored_once_results_exist(self):
        self.mw.all_results = [ScanResult(ip="10.0.0.1", status="online")]
        self.mw._apply_view_mode(save=False)
        QApplication.processEvents()
        self.assertFalse(self.mw.view_toggle.isHidden(),
                         "有结果后视图切换没有恢复")
        self.assertFalse(self.mw.filter_scroll.isHidden(),
                         "有结果后筛选条没有恢复")

    def test_hidden_again_when_results_are_cleared(self):
        self.mw.all_results = [ScanResult(ip="10.0.0.1", status="online")]
        self.mw._apply_view_mode(save=False)
        self.mw.all_results = []
        self.mw._show_results_page(False)
        QApplication.processEvents()
        self.assertTrue(self.mw.view_toggle.isHidden(),
                        "清空结果后视图切换没有重新隐藏")
        self.assertTrue(self.mw.filter_scroll.isHidden(),
                        "清空结果后筛选条没有重新隐藏")

    def test_empty_state_page_is_still_the_default(self):
        self.assertEqual(self.mw.result_stack.currentIndex(), 0)


if __name__ == "__main__":
    unittest.main()
