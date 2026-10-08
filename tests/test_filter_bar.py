# -*- coding: utf-8 -*-
"""筛选条的尺寸契约（UI_REVIEW P1-4 / P3-1）。

为什么这些测试值得存在
----------------------
筛选条的存在理由就是"一眼看清有多少条"。一旦 chip 被压窄，`Changes 104`
会被裁成 `Changes…`，功能等于失效 —— 而这种失效**不会抛异常、不会挂测试**，
只能靠人眼在特定窗口宽度 + 特定语言下才会撞见。

实测（修复前）：
- 中文界面 1024px 窗口：8 个 chip 全被压到 64px，`全部 254` 截断成 `全部 2…`；
- 英文界面 1024–1200px：同样截断，因为英文标签更长（约需 1200px）。

修复分两步：① 筛选条从「IP 范围 + 搜索」那一行挪到独占一行；
② chip 拒绝被压缩（`minimumSizeHint == sizeHint`），放不下时由
`FilterChipScroll` 提供横向滚动。这里把两条约束都固化下来。
"""
import io
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication, QWidget, QHBoxLayout

import i18n
from filter_bar import (
    FilterChipBar, FilterChipScroll, _ChipButton, CHIP_H_PADDING, FILTERS,
)

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()
    i18n.init("zh-CN")


def _qss(name: str) -> str:
    with io.open(os.path.join(ROOT, "assets", "styles", name),
                 encoding="utf-8") as fh:
        return fh.read()


class ChipSizeHintTest(unittest.TestCase):
    """chip 必须按文字宽度取尺寸，且不可被压缩。"""

    def setUp(self):
        self.host = QWidget()
        self.row = QHBoxLayout(self.host)
        self.chips = []
        for text in ("全部 254", "Changes 104", "Has Services 88"):
            c = _ChipButton(text)
            c.setObjectName("filterChip")
            self.row.addWidget(c)
            self.chips.append(c)
        self.host.show()
        QApplication.instance().processEvents()

    def tearDown(self):
        self.host.close()
        self.host.deleteLater()

    def test_minimum_size_hint_equals_size_hint(self):
        """核心回归：允许压缩就等于允许截断文字。"""
        for c in self.chips:
            self.assertEqual(c.minimumSizeHint(), c.sizeHint(),
                             f"{c.text()!r} 的 minimumSizeHint 比 sizeHint 小，会被压窄")

    def test_width_covers_text_plus_padding(self):
        for c in self.chips:
            c.ensurePolished()
            fm = c.fontMetrics()
            expected = fm.horizontalAdvance(c.text()) + 2 * CHIP_H_PADDING + 2
            self.assertEqual(c.sizeHint().width(), expected)

    def test_longer_text_needs_more_width(self):
        widths = [c.sizeHint().width() for c in self.chips]
        self.assertEqual(widths, sorted(widths),
                         "更长的文字必须要求更大的宽度")

    def test_padding_constant_matches_qss(self):
        """`CHIP_H_PADDING` 与 QSS 的 `padding: 2px Npx` 必须一致。

        不一致时 chip 要么文字被截断（常量偏小）、要么白白多占空间（偏大），
        而两者都不会报错 —— 所以用测试把这条耦合钉住。
        """
        for name in ("light.qss", "dark.qss"):
            m = re.search(r"QPushButton#filterChip\s*\{[^}]*padding:\s*\d+px\s+(\d+)px",
                          _qss(name))
            self.assertIsNotNone(m, f"{name} 里找不到 #filterChip 的 padding")
            self.assertEqual(
                int(m.group(1)), CHIP_H_PADDING,
                f"{name} 的 padding 与 filter_bar.CHIP_H_PADDING 不一致",
            )


class FilterChipScrollTest(unittest.TestCase):
    """放得下就平铺，放不下就滚动 —— 绝不允许压缩。"""

    def setUp(self):
        self.bar = FilterChipBar()
        self.scroll = FilterChipScroll(self.bar)
        self.scroll.resize(1000, 40)
        self.scroll.show()
        QApplication.instance().processEvents()

    def tearDown(self):
        self.scroll.close()
        self.scroll.deleteLater()

    def _settle(self):
        for _ in range(3):
            QApplication.instance().processEvents()

    def test_no_scrollbar_when_it_fits(self):
        self.bar.set_counts({})
        self.scroll.resize(1000, 40)
        self._settle()
        self.assertFalse(self.scroll.horizontalScrollBar().isVisible())
        self.assertEqual(self.scroll.height(), self.bar.sizeHint().height())

    def test_scrollbar_appears_and_reserves_height_when_too_narrow(self):
        self.bar.set_counts({k: 254 for k, _lbl in FILTERS})
        self.scroll.resize(200, 40)
        self._settle()
        self.assertTrue(self.scroll.horizontalScrollBar().isVisible())
        self.assertEqual(
            self.scroll.height(),
            self.bar.sizeHint().height() + FilterChipScroll._BAR_EXTENT,
            "滚动条出现时必须预留高度，否则会盖住 chip 文字",
        )

    def test_chips_never_shrink_below_their_size_hint(self):
        """无论窗口多窄，chip 都必须保持完整宽度（宁可溢出滚动）。"""
        self.bar.set_counts({k: 999 for k, _lbl in FILTERS})
        for width in (120, 200, 400, 1000):
            self.scroll.resize(width, 40)
            self._settle()
            for key, btn in self.bar._buttons.items():
                self.assertGreaterEqual(
                    btn.width(), btn.sizeHint().width(),
                    f"宽 {width} 时 {key} 被压窄了",
                )

    def test_bar_extent_matches_qss_scrollbar_height(self):
        """`_BAR_EXTENT` 与 QSS 的滚动条高度必须一致，否则预留高度不准。"""
        for name in ("light.qss", "dark.qss"):
            m = re.search(r"QScrollArea#filterScroll\s+QScrollBar:horizontal\s*\{[^}]*"
                          r"height:\s*(\d+)px", _qss(name))
            self.assertIsNotNone(m, f"{name} 里找不到 #filterScroll 滚动条高度")
            self.assertEqual(
                int(m.group(1)), FilterChipScroll._BAR_EXTENT,
                f"{name} 的滚动条高度与 FilterChipScroll._BAR_EXTENT 不一致",
            )

    def test_both_themes_style_the_scroll_area(self):
        for name in ("light.qss", "dark.qss"):
            self.assertIn("QScrollArea#filterScroll", _qss(name),
                          f"{name} 缺少筛选条滚动容器样式（深色下会露出白底）")


if __name__ == "__main__":
    unittest.main()
