# -*- coding: utf-8 -*-
"""列宽按语言分流 + 换语言重算（批次 2 / P0-5）。

背景
----
`table/header_state` 按**像素**持久化整份表头状态（列宽/列序/隐藏/排序指示）。
而有一部分列的**表头或单元格文本会随语言变化** —— 中文下够宽的列，英文下就被省略：

    中文「在线」68px 放得下 78px 的状态列；英文 `Online` 要 82px → 显示成 `Onl…`

所以本轮把默认列宽拆成「基线 + 按语言覆盖」，并在载入时**额外比对
`table/header_lang`**：语言对不上就按当前语言重算一次，然后写入新的语言戳。

⚠️ 为什么这里不断言绝对像素
------------------------
headless（`QT_QPA_PLATFORM=offscreen`）下 Qt 用的是回退字体，宽度比真机明显更大
（实测英文状态列 native 82px / **offscreen 120px**），断言绝对像素会假挂。
因此本文件只钉两件事：

1. **表本身** —— 基线取值、以及"英文确实比中文宽"这一关系；
2. **机制** —— 语言戳会写入；换语言触发重算；**同语言绝不重算**（否则每次启动都会
   把用户自己拖的列宽冲掉 —— 这正是批次 1 `_save_settings` 写成字面量那个坑的同类）。

「像素到底够不够」由实测探针（真实 MainWindow + 原生平台）负责，见
`main_window._COLUMN_WIDTH_OVERRIDES` 的注释。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication

import i18n
import main_window
from main_window import COLUMN_LABELS, column_widths_for

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


class ColumnWidthTableTest(unittest.TestCase):
    """默认列宽表本身。"""

    #: 中文基线 —— 与改造前逐字一致（中文用户的默认外观**不该**因为这次改动而变）。
    #: 13「风险」是 v5 新增列（P3-4），单元格是「高 65」这种短文本，78px 够用。
    ZH_BASELINE = {
        0: 130, 1: 78, 2: 140, 3: 220, 4: 100, 5: 120, 6: 90, 7: 90,
        8: 160, 9: 200, 10: 150, 11: 120, 12: 180, 13: 78,
    }

    def test_chinese_baseline_is_unchanged(self):
        self.assertEqual(column_widths_for("zh-CN"), self.ZH_BASELINE)

    def test_every_column_has_a_width(self):
        n = len(COLUMN_LABELS)
        for lang in ("zh-CN", "en-US"):
            self.assertEqual(sorted(column_widths_for(lang)), list(range(n)),
                             msg="%s 的列宽表没有覆盖全部 %d 列" % (lang, n))

    def test_english_is_wider_where_the_text_is_longer(self):
        zh = column_widths_for("zh-CN")
        en = column_widths_for("en-US")
        for col in main_window._COLUMN_WIDTH_OVERRIDES["en-US"]:
            self.assertGreater(
                en[col], zh[col],
                msg="col %d（%s）英文没有比中文宽，覆盖没意义" % (col, COLUMN_LABELS[col]))

    def test_status_column_covers_the_measured_english_need(self):
        """把实测值钉成数字：英文 `Online` 需要 82px，而中文基线只有 78px。

        78 < 82 就是 `Onl…` 的成因（证据见 docs/reviews/UI_REVIEW_ROUND2.md §3 与
        docs/ui-review-round2/10-英文-列表-状态列被截断.png）。
        """
        zh = column_widths_for("zh-CN")[1]
        en = column_widths_for("en-US")[1]
        self.assertLess(zh, 82, msg="中文基线不再复现该缺陷，测试前提已变")
        self.assertGreaterEqual(en, 82, msg="英文状态列仍然放不下 Online")

    def test_unknown_language_falls_back_to_baseline(self):
        self.assertEqual(column_widths_for("fr-FR"), self.ZH_BASELINE)

    def test_override_indices_are_valid_columns(self):
        for lang, overrides in main_window._COLUMN_WIDTH_OVERRIDES.items():
            for col in overrides:
                self.assertTrue(0 <= col < len(COLUMN_LABELS),
                                msg="%s 覆盖了不存在的列 %d" % (lang, col))


class LanguageStampedLayoutTest(unittest.TestCase):
    """载入/保存时语言戳的比对逻辑（用真实 MainWindow，配置隔离到临时目录）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_cw_")
        self._orig_data_dir = main_window.data_dir
        main_window.data_dir = lambda: self.tmp

    def tearDown(self):
        main_window.data_dir = self._orig_data_dir
        i18n.init("zh-CN")

    def _ini(self):
        return os.path.join(self.tmp, "ipscanner.ini")

    def _build(self, lang):
        i18n.init(lang)
        mw = main_window.MainWindow()
        mw.show()
        QApplication.processEvents()
        return mw

    def test_save_records_the_current_language(self):
        mw = self._build("en-US")
        try:
            mw._save_settings()
            s = QSettings(self._ini(), QSettings.IniFormat)
            self.assertEqual(str(s.value("table/header_lang", "")), "en-US")
        finally:
            mw.close()

    def test_language_change_reapplies_that_language_widths(self):
        mw = self._build("zh-CN")
        mw.table.header().resizeSection(2, 333)     # 模拟用户自定义
        mw._save_settings()
        mw.close()

        mw2 = self._build("en-US")                  # 语言变了 → 重算
        try:
            hdr = mw2.table.header()
            expect = column_widths_for("en-US")
            self.assertEqual(hdr.sectionSize(1), expect[1],
                             msg="换到英文后状态列没有按英文宽度重算")
            self.assertEqual(hdr.sectionSize(2), expect[2],
                             msg="换语言时列宽没有整体重算（自定义值应被覆盖，这是"
                                 "一次性代价）")
        finally:
            mw2.close()

    def test_same_language_keeps_the_users_custom_widths(self):
        """🔴 最关键的一条：语言没变时**绝不能**重算。

        否则每次启动都会把用户拖好的列宽冲回默认值 —— 与批次 1 那个
        `_save_settings` 把版本号写成字面量、导致"每次启动都重置布局"的坑同类。
        """
        mw = self._build("zh-CN")
        mw.table.header().resizeSection(2, 333)
        mw._save_settings()
        mw.close()

        mw2 = self._build("zh-CN")                  # 同语言 → 原样恢复
        try:
            self.assertEqual(mw2.table.header().sectionSize(2), 333,
                             msg="同语言重开把用户自定义列宽冲掉了")
        finally:
            mw2.close()

    def test_legacy_profile_without_stamp_keeps_chinese_layout(self):
        """1.7.1 及以前的老配置没有语言戳：中文用户应沿用其布局，不被重置。"""
        mw = self._build("zh-CN")
        mw.table.header().resizeSection(2, 333)
        mw._save_settings()
        mw.close()
        # 模拟老配置：抹掉语言戳
        s = QSettings(self._ini(), QSettings.IniFormat)
        s.remove("table/header_lang")
        s.sync()

        mw2 = self._build("zh-CN")
        try:
            self.assertEqual(mw2.table.header().sectionSize(2), 333,
                             msg="没有语言戳的老配置被误判成换语言而重置了")
        finally:
            mw2.close()


class NoWriteBackWhileLoadingTest(unittest.TestCase):
    """🔴 载入配置期间**绝不允许回写**。

    `_load_settings()` 会经 `_set_filter()` 间接调到 `_save_settings()`，而
    `view/mode`、`view/row_density` 排在 `_set_filter` **之后**才载入 —— 此时它们
    还停在 `_init_ui` 落的默认值。少了这道闸门，回写会把用户存的值覆盖成默认值：
    用户把视图切成「概览」、行高切成「紧凑」，重启后全变回默认，**且没有任何提示**。
    （2026-10-09 实测：存 `overview` 读回 `list`；存 `compact` 读回 `comfortable`。）
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_nwb_")
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

    def _ini(self):
        return os.path.join(self.tmp, "ipscanner.ini")

    def test_saved_values_survive_a_reload(self):
        from design_tokens import DENSITY_COMPACT

        self.mw.view_mode = "overview"
        self.mw._set_row_density(DENSITY_COMPACT)
        self.mw.settings.sync()

        mw2 = main_window.MainWindow()
        try:
            self.assertEqual(mw2.view_mode, "overview",
                             msg="重启后视图模式被重置成默认值（载入期回写了）")
            self.assertEqual(mw2.row_density, DENSITY_COMPACT,
                             msg="重启后行高档位被重置成默认值（载入期回写了）")
        finally:
            mw2.close()

    def test_loading_does_not_touch_the_ini(self):
        """载入前后 ini 逐字节一致 —— 直接钉住"载入期不回写"这条不变量。"""
        self.mw.view_mode = "overview"
        self.mw._save_settings()
        self.mw.settings.sync()
        with open(self._ini(), "rb") as fh:
            before = fh.read()

        mw2 = main_window.MainWindow()
        try:
            mw2.settings.sync()
            with open(self._ini(), "rb") as fh:
                after = fh.read()
            self.assertEqual(after, before, msg="载入配置时改写了 ini")
        finally:
            mw2.close()


class ColumnCountWiringTest(unittest.TestCase):
    """🔴 表格实际列数必须与 `COLUMN_LABELS` 一致 —— 这条守着一个**段错误**。

    背景（2026-10-09，v5 加「风险」列时实测）：`COLUMN_LABELS` 加到 14 项，
    但 `_init_ui` 里另写了一份字面量 `setColumnCount(13)` 和 13 项表头。于是
    `_apply_default_column_widths()` 对只有 13 节的表头调 `resizeSection(13, 78)`
    —— Qt **不报错，直接越界写坏堆**，症状是**随机**段错误：同一组用例有时第 1
    条崩、有时第 3 条崩，`faulthandler` 每次指在不同行（`isColumnHidden` /
    `setChecked` …），排查代价极高，而且 unittest **连 `Ran N tests` 汇总行都
    打不出来**（进程在汇总前就死了）。

    修法是让列数与表头都从 `COLUMN_LABELS` **派生**（不再有第二份字面量）；
    本测试把它钉住，另加 `_apply_default_column_widths()` 里的越界护栏兜底。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_cc_")
        self._orig_data_dir = main_window.data_dir
        main_window.data_dir = lambda: self.tmp

    def tearDown(self):
        main_window.data_dir = self._orig_data_dir
        i18n.init("zh-CN")

    def _build(self, lang):
        i18n.init(lang)
        mw = main_window.MainWindow()
        mw.show()
        QApplication.processEvents()
        return mw

    def test_column_count_matches_labels(self):
        mw = self._build("zh-CN")
        try:
            self.assertEqual(
                mw.table.columnCount(), len(COLUMN_LABELS),
                msg="表格列数与 COLUMN_LABELS 不一致 —— 列宽表会对不存在的列"
                    "调 resizeSection，越界写坏堆（随机段错误）")
            self.assertEqual(mw.table.header().count(), len(COLUMN_LABELS))
        finally:
            mw.close()

    def test_header_labels_are_exactly_the_labels_table(self):
        mw = self._build("zh-CN")
        try:
            got = tuple(mw.table.headerItem().text(i)
                        for i in range(mw.table.columnCount()))
            self.assertEqual(got, COLUMN_LABELS,
                             msg="表头与 COLUMN_LABELS 不是一一对应（列序或名称漂了）")
        finally:
            mw.close()

    def test_header_labels_follow_the_language(self):
        """表头必须**惰性**取自 `COLUMN_LABELS` 的 `tr()`，不能是又一份字面量。"""
        mw = self._build("en-US")
        try:
            got = tuple(mw.table.headerItem().text(i)
                        for i in range(mw.table.columnCount()))
            self.assertEqual(got, tuple(i18n.tr(n) for n in COLUMN_LABELS),
                             msg="英文界面下表头没有按语言翻译")
            self.assertNotEqual(got, COLUMN_LABELS,
                                msg="英文界面下表头仍是中文，翻译没生效")
        finally:
            mw.close()

    def test_risk_column_is_reachable_and_visible_in_security_preset(self):
        """v5 的「风险」列必须真能显示出来（列数对不上时它会静默消失）。"""
        from risk_rules import RISK_COLUMN

        mw = self._build("zh-CN")
        try:
            self.assertLess(RISK_COLUMN, mw.table.columnCount(),
                            msg="风险列的索引超出实际列数，单元格写不进去")
            mw._apply_column_preset("security")
            self.assertFalse(mw.table.isColumnHidden(RISK_COLUMN),
                             msg="「安全」预设里没有把风险列显示出来")
        finally:
            mw.close()


if __name__ == "__main__":
    unittest.main()
