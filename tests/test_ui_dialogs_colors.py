# -*- coding: utf-8 -*-
"""对话框配色统一走语义色令牌 + 表头惰性翻译（批次 3 / docs/reviews/UI_REVIEW_ROUND2.md §5 第 8 项）。

背景
----
`theme_tokens.py` 早就建好了，但只有 2 个文件接它；`ui_dialogs.py` 里另有
约 40 处硬编码色，其中**没有随主题变**的那几处是真实缺陷：

    `setStyleSheet("color: #555555; …")` 的摘要文字 → 深色底上几乎不可见
    严重级别/利用率用的红橙                     → 深色底上约 2.5:1（AA 要 4.5:1）

本文件守三件事：

1. **结构** —— `ui_dialogs/` 包里不得再出现色值字面量（`#hex` 或不透明的
   `QColor(r, g, b)`）。带 alpha 的 4 参数 `QColor` 允许：那是半透明装饰
   （节点高光/描边），压在浅深两种画布上都只是"淡一点的边"，与主题无关，
   而令牌表刻意只存不透明色。
2. **有效性** —— 代码里引用的令牌名必须真的存在。拼错的名字会让
   `token()` 静默返回空串，颜色变成无效值 —— 这类错**不会报错**，
   只会表现为"某处颜色不对"。
3. **随主题变** —— 关键几处（拓扑画布、严重级别）在两套主题下取值必须不同。

另外顺手守住本次一并修掉的"类体 `tr()` 冻结"：对话框表头原先写成类属性，
导入时就被冻成中文，英文界面下永远显示中文表头。
"""
import inspect
import io
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import i18n
from theme_tokens import all_tokens, token

_APP = None


def setUpModule():
    global _APP
    from tests._qt_app import ensure_qt_app
    _APP = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


def _src(name):
    with io.open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def _pkg_src():
    """`ui_dialogs` 包内全部 `.py` 源码的拼接。

    本文件原先直接读单个 `ui_dialogs.py`。拆成 `ui_dialogs/` 包后，色值字面量
    与令牌引用散布在各子模块，只扫 `__init__.py`（门面）会让这些守卫**静默失效**，
    因此统一改成扫描整个包。
    """
    pkg = os.path.join(ROOT, "ui_dialogs")
    return "\n".join(
        _src(os.path.join("ui_dialogs", fn))
        for fn in sorted(os.listdir(pkg)) if fn.endswith(".py")
    )


def _qss(name):
    return _src(os.path.join("assets", "styles", name))


class NoColorLiteralTest(unittest.TestCase):
    """`ui_dialogs/` 包不得再出现色值字面量。"""

    def test_no_hex_literal(self):
        found = sorted(set(re.findall(r"#[0-9A-Fa-f]{3,8}\b", _pkg_src())))
        self.assertEqual(
            found, [],
            "ui_dialogs 包里仍有色值字面量 %s。自绘/单元格着色请用 "
            "theme_tokens.token()，普通控件请把配色收进 QSS。" % found)

    def test_no_opaque_qcolor_literal(self):
        found = sorted(set(re.findall(
            r"QColor\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)", _pkg_src())))
        self.assertEqual(
            found, [],
            "ui_dialogs 包里仍有不透明 QColor 字面量 %s，请改用 _theme_color()"
            % found)


class TokenReferenceTest(unittest.TestCase):
    """引用的令牌名必须存在（拼错会静默返回空串）。"""

    def test_every_referenced_token_exists(self):
        src = _pkg_src()
        names = set(re.findall(r"_theme_color\(\s*\"([a-z_]+)\"", src))
        names |= set(re.findall(r"\btoken\(\s*\"([a-z_]+)\"", src))
        unknown = sorted(n for n in names if n not in all_tokens())
        self.assertEqual(unknown, [], "引用了未定义的令牌：%s" % unknown)

    def test_every_token_has_both_theme_values(self):
        for name in all_tokens():
            for dark in (False, True):
                self.assertTrue(token(name, dark),
                                "%s 在 dark=%s 下取不到色值" % (name, dark))


class ThemeAwareTest(unittest.TestCase):
    """关键几处必须**随主题变** —— 这正是原来的缺陷。"""

    def test_severity_tables_store_token_names(self):
        """级别表存令牌名。存 QColor 会在 import 期把颜色冻死在浅色值上。"""
        import ui_dialogs
        for cls in (ui_dialogs.ConflictReportDialog,
                    ui_dialogs.ChangeReportDialog):
            self.assertTrue(cls._SEVERITY_TOKEN, "%s 的级别表为空" % cls.__name__)
            for key, value in cls._SEVERITY_TOKEN.items():
                self.assertIsInstance(
                    value, str, msg="%s 的 %r 不是令牌名" % (cls.__name__, key))
                self.assertIn(value, all_tokens())

    def test_danger_token_differs_between_themes(self):
        self.assertNotEqual(token("danger", False), token("danger", True),
                            "danger 在两套主题下相同，等于没随主题变")

    def test_topology_canvas_follows_the_theme(self):
        import ui_dialogs
        from scanner.models import ScanResult
        results = [ScanResult(ip="10.0.0.1", status="online")]
        light = ui_dialogs.TopologyDialog(results, "10.0.0.1", False)
        dark = ui_dialogs.TopologyDialog(results, "10.0.0.1", True)
        try:
            self.assertNotEqual(
                light.scene.backgroundBrush().color().name(),
                dark.scene.backgroundBrush().color().name(),
                "拓扑画布底色没有随主题变")
            self.assertNotEqual(light._text_color().name(),
                                dark._text_color().name(),
                                "拓扑文字色没有随主题变")
            self.assertNotEqual(light._link_blue().name(),
                                dark._link_blue().name(),
                                "拓扑链路色没有随主题变")
        finally:
            light.deleteLater()
            dark.deleteLater()

    def test_legend_keeps_the_colour_out_of_the_translation_key(self):
        """图例的色值不能再写进 `tr()` 的键 —— 否则改配色要同步改语言包。"""
        src = _pkg_src()
        self.assertNotIn("tr(\"<span", src,
                         "图例仍把 HTML/颜色塞进了 tr() 的词条")


class LazyTableHeaderTest(unittest.TestCase):
    """对话框表头必须是惰性的 —— 类体在 import 期求值，会把语言冻死。"""

    #: 曾经写成类属性的那几处（`COLS` / `FIELDS`）
    LAZY = (
        ("DeviceEditDialog", "FIELDS"),
        ("MacLibraryDialog", "COLS"),
        ("HistoryQueryDialog", "COLS"),
        ("ConflictReportDialog", "COLS"),
        ("SubnetUtilizationDialog", "COLS"),
        ("AuditLogDialog", "COLS"),
        ("SwitchPortDialog", "COLS"),
        ("ChangeReportDialog", "COLS"),
    )

    def test_they_are_properties(self):
        import ui_dialogs
        for cls_name, attr in self.LAZY:
            cls = getattr(ui_dialogs, cls_name)
            self.assertIsInstance(
                inspect.getattr_static(cls, attr), property,
                "%s.%s 不是 property —— 类属性会在 import 期把语言冻死"
                % (cls_name, attr))

    def test_translation_follows_the_current_language(self):
        """取值时翻译：切到英文后同一个 property 必须给出英文。

        property 不依赖 `self`，这里用 `__get__` 配一个空对象取值，
        免得为了断言去构造对话框（会读用户数据目录）。
        """
        import ui_dialogs

        class _Bare:
            pass

        probe = _Bare()
        i18n.init("zh-CN")
        zh = list(ui_dialogs.AuditLogDialog.COLS.__get__(probe))
        i18n.init("en-US")
        en = list(ui_dialogs.AuditLogDialog.COLS.__get__(probe))
        i18n.init("zh-CN")

        self.assertNotEqual(zh, en, "表头被冻在 import 期的语言上了")
        self.assertIn("Time", en, "英文界面下审计日志表头仍是中文")
        self.assertIn("时间", zh)


class DialogQssCoverageTest(unittest.TestCase):
    """新增的 objectName 必须在两套主题里都有样式，否则深色下漏白/串色。"""

    OBJECT_NAMES = ("dialogHint", "dialogHintSmall", "snmpTestResult",
                    "emptyPrimary")

    def test_every_object_name_is_styled_in_both_themes(self):
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for obj in self.OBJECT_NAMES:
                self.assertIn("#%s" % obj, src,
                              "%s 缺少 #%s 样式" % (name, obj))

    def test_snmp_result_has_both_outcomes(self):
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for ok in ("true", "false"):
                self.assertIn('[ok="%s"]' % ok, src,
                              "%s 缺少 snmpTestResult[ok=%s] 选择器" % (name, ok))


if __name__ == "__main__":
    unittest.main()
