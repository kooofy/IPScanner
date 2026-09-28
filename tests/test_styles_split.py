# -*- coding: utf-8 -*-
"""P2-3 回归测试：`styles.py` 的职责拆分与 QSS 资源化。

历史缺陷
--------
`styles.py` 曾把 4 类改动理由完全不同的东西塞在同一个 791 行文件里：
QSS 文本（换配色）、图标绘制（换图形）、字体常量、以及一个跟样式毫无关系的
`_ip_to_int`（IP 排序键）。任何一处改动都要在 791 行里翻找，且 QSS 以 Python
三引号字面量存在 —— 编辑器无法高亮，写错一个引号整个模块都 import 不了。

拆分为：QSS → `assets/styles/*.qss`；图标 → `ui_icons.py`；IP 排序键 →
`ui_utils.py`；字体常量留在 `styles.py`。

本测试固化三件事，防止后续回退或"悄悄合回去"：

1. QSS 资源文件存在、非空、大括号配平，且 `styles` 读到的内容与磁盘一致；
2. **打包配方覆盖**：`styles` 运行时读取的路径必须落在 GUI spec 的 `datas`
   里 —— 这是"打包漏了资源"这类缺陷唯一能在 CI 之外提前发现的地方；
3. 拆分边界：图标绘制只能在 `ui_icons`，IP 排序键只能在 `ui_utils`，
   `styles` 不得再暴露它们。
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _read(rel_path):
    with open(os.path.join(ROOT, rel_path), "r", encoding="utf-8") as fh:
        return fh.read()


class QssResourceTest(unittest.TestCase):
    """QSS 已资源化，且资源必须真的能被读到、被打进包。"""

    def test_qss_files_exist_and_are_not_empty(self):
        import styles
        for name in ("light.qss", "dark.qss"):
            with self.subTest(qss=name):
                rel = os.path.join(*styles._QSS_SUBDIR, name)
                path = os.path.join(ROOT, rel)
                self.assertTrue(os.path.isfile(path), f"缺少样式文件 {rel}")
                self.assertGreater(os.path.getsize(path), 500,
                                   f"{rel} 内容异常偏小，可能被误清空")

    def test_styles_module_loads_files_verbatim(self):
        """`styles.STYLE_SHEET` 必须与磁盘上的 .qss 逐字节一致。

        若这里失败，说明有人绕过 .qss 直接改了模块里的字符串（或反过来），
        两份"真相"会立刻分叉。
        """
        import styles
        for attr, name in (("STYLE_SHEET", "light.qss"),
                           ("DARK_STYLE_SHEET", "dark.qss")):
            with self.subTest(attr=attr):
                rel = os.path.join(*styles._QSS_SUBDIR, name)
                on_disk = _read(rel)
                self.assertEqual(getattr(styles, attr), on_disk,
                                 f"{attr} 与 {name} 不一致")

    def test_qss_braces_are_balanced(self):
        """大括号配平 —— 断掉一个 `}` 时 Qt 会静默忽略整段样式，界面只是"变丑"。"""
        import styles
        for attr in ("STYLE_SHEET", "DARK_STYLE_SHEET"):
            with self.subTest(attr=attr):
                qss = getattr(styles, attr)
                self.assertEqual(qss.count("{"), qss.count("}"),
                                 f"{attr} 大括号不配平")
                self.assertIn("QMainWindow", qss)

    def test_light_and_dark_are_actually_different(self):
        import styles
        self.assertNotEqual(styles.STYLE_SHEET, styles.DARK_STYLE_SHEET)
        self.assertIn("#F0F0F0", styles.STYLE_SHEET)      # 浅色主背景
        self.assertIn("#2B2B2B", styles.DARK_STYLE_SHEET)  # 深色主背景

    def test_missing_qss_raises_instead_of_silently_unstyled(self):
        """读不到样式必须报错，而不是退化成"无样式"。

        静默退化的表现是界面变成默认灰白，用户报"程序变丑了"，排查成本极高；
        fail-fast 能一眼定位到打包漏了 assets/styles。
        """
        import styles
        with self.assertRaises(RuntimeError) as ctx:
            styles._read_qss("__definitely_missing__.qss")
        self.assertIn("__definitely_missing__.qss", str(ctx.exception))


class QssIsBundledBySpecTest(unittest.TestCase):
    """系统性守卫：运行时读取的资源必须出现在打包配方里。

    这类缺陷（改了资源路径但没改 spec）在开发模式下**永远不会暴露** ——
    源码目录里文件就在那儿。只有装到别人机器上才发现，且表现为界面无样式。
    """

    def _spec_datas_sources(self, spec_rel):
        text = _read(spec_rel)
        m = re.search(r"datas\s*=\s*\[(.*?)\]", text, re.S)
        self.assertIsNotNone(m, f"{spec_rel} 里找不到 datas=[...]")
        pairs = re.findall(r"\(\s*'([^']+)'\s*,\s*'([^']+)'\s*\)", m.group(1))
        return [src for src, _dst in pairs]

    def test_gui_spec_covers_every_qss_file(self):
        import styles
        sources = self._spec_datas_sources("IPScanner.spec")
        for name in ("light.qss", "dark.qss"):
            with self.subTest(qss=name):
                rel = os.path.join(*styles._QSS_SUBDIR, name)
                covered = any(
                    rel == src or rel.startswith(src.rstrip("/\\") + os.sep)
                    for src in sources
                )
                self.assertTrue(
                    covered,
                    f"IPScanner.spec 的 datas 未覆盖 {rel}（当前 datas 源：{sources}）；"
                    f"打包后 styles.py 会因读不到样式而启动失败",
                )


class SplitBoundaryTest(unittest.TestCase):
    """拆分边界：各归其位，且 styles 不再暴露已迁出的符号。"""

    def test_icon_drawing_lives_in_ui_icons(self):
        import ui_icons
        for name in ("_gray_icon", "_make_tool_icon", "_make_pause_icon"):
            with self.subTest(fn=name):
                self.assertTrue(hasattr(ui_icons, name),
                                f"ui_icons 缺少 {name}")

    def test_ip_sort_key_lives_in_ui_utils(self):
        import ui_utils
        self.assertTrue(hasattr(ui_utils, "_ip_to_int"))
        self.assertEqual(ui_utils._ip_to_int("192.168.1.10"), 0xC0A8010A)
        self.assertEqual(ui_utils._ip_to_int("not-an-ip"), -1)

    def test_styles_no_longer_exposes_moved_symbols(self):
        import styles
        for name in ("_gray_icon", "_make_tool_icon", "_make_pause_icon",
                     "_ip_to_int"):
            with self.subTest(sym=name):
                self.assertFalse(
                    hasattr(styles, name),
                    f"styles 仍在暴露 {name} —— 拆分被合回去了",
                )

    def test_styles_does_not_draw(self):
        """`styles.py` 不该再出现绘制 API（QPainter/Pixmap），它只负责外观声明。"""
        src = _read("styles.py")
        for token in ("QPainter", "QPixmap", "drawLine", "drawRect"):
            with self.subTest(token=token):
                self.assertNotIn(token, src,
                                 f"styles.py 又出现了绘制代码 {token}")

    def test_styles_keeps_fonts_and_style_sheet_names(self):
        """调用方契约：`STYLE_SHEET` / `DARK_STYLE_SHEET` / 字体常量仍在 styles。"""
        import styles
        for name in ("STYLE_SHEET", "DARK_STYLE_SHEET",
                     "_FONT_CONSOLAS_10", "_FONT_CONSOLAS_9",
                     "_FONT_YAHEI_BOLD_9"):
            with self.subTest(sym=name):
                self.assertTrue(hasattr(styles, name),
                                f"styles 缺少对外契约 {name}")


if __name__ == "__main__":
    unittest.main()
