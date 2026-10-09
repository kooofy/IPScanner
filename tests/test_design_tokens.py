# -*- coding: utf-8 -*-
"""设计令牌：圆角 / 间距 / 行高（UI_REVIEW.md 的 P2-1.1、P2-1.2、P2-1.4）。

改造前的问题（实测，不是估计）：

- **圆角五种值混用** —— 按钮 2px、输入框 1px、进度条 1px、列表 1px、卡片 4px、
  表格 0px。同一屏里"控件该多圆"没有统一答案，看起来像几个年代拼起来的。
- **行高写死 26px** —— `QTreeWidget::item { min-height: 26px }`，扫 /24 出 254 行
  时一屏只放得下二十来行，用户没法让它更紧凑。

QSS 不能 import Python，所以圆角与行高只能**手写**在 `assets/styles/*.qss` 里。
本文件的价值就在这：把"手写的值必须落在 `design_tokens` 的刻度内"变成可回归的断言，
否则这次统一迟早会被后续改动悄悄漂回去。
"""
import io
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

import design_tokens as dt
import i18n

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


def _qss(name):
    with io.open(os.path.join(ROOT, "assets", "styles", name),
                 encoding="utf-8") as fh:
        return fh.read()


def _radii(src):
    return [int(m) for m in re.findall(r"border-radius:\s*(\d+)px", src)]


def _radius_by_selector(src):
    """`{选择器: 圆角}`，用于比对"两套主题镜像"。

    逗号分隔的复合选择器按**单个**选择器展开：`dark.qss` 把
    `QPushButton#toolBtnGreen, QPushButton#toolBtnYellow` 写成一条规则，
    而 `light.qss` 写成两条 —— 规则条数天然差 1，所以只能比"每个选择器的圆角"，
    比 `border-radius` 出现次数的多重集会假挂。
    注释先剥掉，免得 `/* … */` 里的内容混进选择器文本。
    """
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    out = {}
    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", src):
        m = re.search(r"border-radius:\s*(\d+)px", block.group(2))
        if not m:
            continue
        radius = int(m.group(1))
        for sel in block.group(1).split(","):
            sel = " ".join(sel.split())
            if sel:
                out[sel] = radius
    return out


class RadiusScaleTest(unittest.TestCase):
    """两套 QSS 里的圆角必须全部落在统一刻度内，且两套主题对称。"""

    def test_scale_is_sane(self):
        self.assertEqual(sorted(set(dt.RADIUS_SCALE)), list(dt.RADIUS_SCALE),
                         "RADIUS_SCALE 必须是去重且升序的")
        self.assertIn(dt.RADIUS_CONTROL, dt.RADIUS_SCALE)

    def test_no_stray_radius_values(self):
        for name in ("light.qss", "dark.qss"):
            stray = sorted({r for r in _radii(_qss(name))
                            if r not in dt.RADIUS_SCALE})
            self.assertEqual(
                stray, [],
                "%s 里出现刻度外的圆角 %s（允许 %s）—— 请改到刻度内，"
                "或在 design_tokens 里补一档并写明理由"
                % (name, stray, list(dt.RADIUS_SCALE)))

    def test_both_themes_use_the_same_radius_values(self):
        """两套主题镜像：**同一选择器**的圆角必须一样，否则切换主题会"跳"一下。

        比的是「选择器 → 圆角」而不是 `border-radius` 出现次数的多重集：
        `dark.qss` 把 `#toolBtnGreen, #toolBtnYellow` 合并成一条规则，`light.qss`
        拆成两条 —— 条数天然差 1，比多重集会假挂（`_radius_by_selector` 会把复合
        选择器展开成两条，两边就都对齐了）。
        """
        light = _radius_by_selector(_qss("light.qss"))
        dark = _radius_by_selector(_qss("dark.qss"))
        self.assertEqual(sorted(set(light) - set(dark)), [],
                         "light.qss 独有的圆角规则（dark.qss 里没有）")
        self.assertEqual(sorted(set(dark) - set(light)), [],
                         "dark.qss 独有的圆角规则（light.qss 里没有）")
        mismatch = {k: (light[k], dark[k])
                    for k in sorted(light) if light[k] != dark[k]}
        self.assertEqual(
            mismatch, {},
            "同一选择器在两套主题里圆角不同（选择器: (light, dark)）：%s" % mismatch)

    def test_controls_are_unified_to_the_control_step(self):
        """按钮 / 输入框 / 下拉 / 进度条 / 列表外壳统一到 4px。

        这几类改造前分别是 2px / 1px / 1px / 1px / 1px —— 正是"五种值混用"的来源。
        """
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for selector in ("QPushButton", "QLineEdit", "QComboBox",
                             "QSpinBox", "QProgressBar", "QListWidget"):
                block = re.search(
                    r"^%s \{(.*?)\}" % re.escape(selector), src,
                    re.S | re.M)
                self.assertIsNotNone(block, "%s 里找不到 %s 规则" % (name, selector))
                m = re.search(r"border-radius:\s*(\d+)px", block.group(1))
                self.assertIsNotNone(m, "%s 的 %s 没有 border-radius" % (name, selector))
                self.assertEqual(
                    int(m.group(1)), dt.RADIUS_CONTROL,
                    "%s 的 %s 圆角是 %spx，应为 %dpx"
                    % (name, selector, m.group(1), dt.RADIUS_CONTROL))


class RowDensityTest(unittest.TestCase):
    """行高两档：规范值语言无关，显示名惰性翻译，QSS 数字与令牌一致。"""

    def test_canonical_values_are_language_free(self):
        for value in dt.DENSITIES:
            self.assertNotIn("\u4e00", value)
            self.assertEqual(value, value.lower())

    def test_default_is_the_comfortable_one(self):
        """默认档必须等于改造前的行高，老用户升级后外观不变。"""
        self.assertEqual(dt.DEFAULT_DENSITY, dt.DENSITY_COMFORTABLE)
        self.assertIn(dt.DEFAULT_DENSITY, dt.DENSITIES)
        self.assertEqual(dt.ROW_HEIGHT[dt.DEFAULT_DENSITY], 26)

    def test_every_density_has_height_and_label(self):
        for value in dt.DENSITIES:
            with self.subTest(value=value):
                self.assertIn(value, dt.ROW_HEIGHT)
                self.assertTrue(dt._DENSITY_TEXT.get(value),
                                "%s 没有显示名" % value)

    def test_label_follows_the_current_language(self):
        i18n.init("zh-CN")
        zh = dt.density_label(dt.DENSITY_COMPACT)
        i18n.init("en-US")
        en = dt.density_label(dt.DENSITY_COMPACT)
        i18n.init("zh-CN")
        self.assertEqual(zh, "紧凑")
        self.assertEqual(en, "Compact")

    def test_unknown_value_passes_through(self):
        self.assertEqual(dt.density_label("nope"), "nope")

    def test_qss_declares_both_densities_with_the_token_heights(self):
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            base = re.search(r"^QTreeWidget::item \{(.*?)\}", src, re.S | re.M)
            self.assertIsNotNone(base, "%s 缺少 QTreeWidget::item 基线规则" % name)
            pad_h = int(re.search(r"padding:\s*\d+px\s+(\d+)px",
                                  base.group(1)).group(1))
            for value in dt.DENSITIES:
                with self.subTest(theme=name, density=value):
                    m = re.search(
                        r'QTreeWidget#resultTable\[density="%s"\]::item\s*\{([^}]*)\}'
                        % re.escape(value), src, re.S)
                    self.assertIsNotNone(
                        m, "%s 缺少 [density=\"%s\"] 的行高规则" % (name, value))
                    body = m.group(1)
                    h = re.search(r"min-height:\s*(\d+)px", body)
                    self.assertIsNotNone(
                        h, "%s 的 %s 规则没有 min-height" % (name, value))
                    self.assertEqual(
                        int(h.group(1)), dt.ROW_HEIGHT[value],
                        "%s 的 %s min-height 与 design_tokens.ROW_HEIGHT 不一致"
                        % (name, value))
                    # padding 必须显式写：只改 min-height 会被字号行高兜住。
                    p = re.search(r"padding:\s*(\d+)px\s+(\d+)px", body)
                    self.assertIsNotNone(
                        p, "%s 的 %s 规则必须显式写 padding —— 只改 min-height "
                           "会被字号行高兜住，紧凑档降不下来" % (name, value))
                    self.assertEqual(
                        int(p.group(1)), dt.ROW_PADDING_V[value],
                        "%s 的 %s 上下 padding 与 design_tokens.ROW_PADDING_V 不一致"
                        % (name, value))
                    self.assertEqual(
                        int(p.group(2)), pad_h,
                        "%s 的 %s 左右 padding 与基线规则 %dpx 不一致"
                        % (name, value, pad_h))


class SpacingScaleTest(unittest.TestCase):
    """间距刻度本身要自洽。"""

    def test_scale_is_sane(self):
        self.assertEqual(sorted(set(dt.SPACING_SCALE)), list(dt.SPACING_SCALE))
        for value in dt.SPACING_SCALE:
            self.assertEqual(value % 2, 0, "%s 不是 2 的倍数" % value)

    def test_named_constants_are_in_the_scale(self):
        for value in (dt.SPACING_XS, dt.SPACING_SM, dt.SPACING_MD,
                      dt.SPACING_LG, dt.SPACING_XL):
            self.assertIn(value, dt.SPACING_SCALE)


class RowDensityWiringTest(unittest.TestCase):
    """真 `MainWindow`：档位落到动态属性上，且能持久化。"""

    def setUp(self):
        import main_window
        self.main_window = main_window
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_dt_")
        self._orig_data_dir = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()

    def tearDown(self):
        self.mw.close()
        self.main_window.data_dir = self._orig_data_dir
        i18n.init("zh-CN")

    def test_table_has_the_object_name_used_by_qss(self):
        self.assertEqual(self.mw.table.objectName(), "resultTable")

    def test_default_density_is_applied(self):
        self.assertEqual(self.mw.row_density, dt.DEFAULT_DENSITY)
        self.assertEqual(self.mw.table.property("density"), dt.DEFAULT_DENSITY)

    def test_switching_updates_the_property(self):
        self.mw._set_row_density(dt.DENSITY_COMPACT)
        self.assertEqual(self.mw.table.property("density"), dt.DENSITY_COMPACT)

    def test_switching_persists(self):
        self.mw._set_row_density(dt.DENSITY_COMPACT)
        self.assertEqual(
            self.mw.settings.value("view/row_density", "", type=str),
            dt.DENSITY_COMPACT)

    def test_invalid_value_is_rejected(self):
        self.mw._set_row_density("huge")
        self.assertEqual(self.mw.row_density, dt.DEFAULT_DENSITY)
        self.assertEqual(self.mw.table.property("density"), dt.DEFAULT_DENSITY)

    def test_menu_has_one_exclusive_action_per_density(self):
        self.assertEqual(set(self.mw._density_actions), set(dt.DENSITIES))
        checked = [k for k, a in self.mw._density_actions.items() if a.isChecked()]
        self.assertEqual(checked, [dt.DEFAULT_DENSITY])
        self.assertTrue(self.mw._density_group.isExclusive())

    def test_menu_action_updates_the_check_state(self):
        self.mw._set_row_density(dt.DENSITY_COMPACT)
        checked = [k for k, a in self.mw._density_actions.items() if a.isChecked()]
        self.assertEqual(checked, [dt.DENSITY_COMPACT])

    def test_saved_value_is_reloaded(self):
        """存进去的档位要在下次启动时读回来（存字面量会每次重置）。"""
        self.mw._set_row_density(dt.DENSITY_COMPACT)
        self.mw.settings.sync()
        mw2 = self.main_window.MainWindow()
        try:
            self.assertEqual(mw2.row_density, dt.DENSITY_COMPACT)
            self.assertEqual(mw2.table.property("density"), dt.DENSITY_COMPACT)
        finally:
            mw2.close()


if __name__ == "__main__":
    unittest.main()
