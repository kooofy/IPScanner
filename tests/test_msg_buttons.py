# -*- coding: utf-8 -*-
"""对话框按钮本地化回归（批次 2 / P0-4）。

背景
----
PyQt5 5.15.11 自带 195 个 `.qm`，其中 `qtbase_*` 覆盖 23 种语言，**唯独没有
`zh_CN`**（只有 `zh_TW`）。`QTranslator().load("qt_zh_CN")` 会返回 `True` 却翻译
不出任何东西 —— 中文界面下 `QMessageBox` / `QDialogButtonBox` 的按钮一直是
`OK` / `Cancel`。PyQt5 也**没有** `setButtonText`，只能在构造之后逐个 `setText()`。

本轮把这件事收敛进 `ui_msg`，并把全项目 83 处静态调用统一改走它。本文件守两件事：

1. **行为** —— `localize_buttons()` 在 `QMessageBox` 与 `QDialogButtonBox` 上都把
   标准按钮改成当前语言，且**不动**自定义按钮；
2. **结构** —— 项目里不再出现 `QMessageBox.<静态方法>` 调用。P0-4 能积累到 93 处，
   根因就是"没人拦着"：任何新加的对话框都会静默退回英文按钮。这条断言就是那道网。

（`ui_msg` 自己的 docstring 里会提到这些方法名，所以扫描时跳过该文件。）
"""
import ast
import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QDialogButtonBox, QMessageBox

import i18n
import ui_msg
from ui_msg import STANDARD_BUTTON_TEXT

_app = None


def setUpModule():
    # 统一走 ensure_qt_app()：保证进程里那个唯一的 application 对象是
    # QApplication 而不是 QCoreApplication，否则建 widget 会让进程直接 abort。
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


def _texts(box):
    """{int(标准按钮): 文案}；自定义按钮（standardButton==0）不参与。"""
    out = {}
    for btn in box.buttons():
        sb = int(box.standardButton(btn))
        if sb:
            out[sb] = btn.text()
    return out


class LocalizeButtonsTest(unittest.TestCase):

    def tearDown(self):
        i18n.init("zh-CN")

    def test_message_box_buttons_follow_language(self):
        box = QMessageBox()
        box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        i18n.init("zh-CN")
        ui_msg.localize_buttons(box)
        self.assertEqual(_texts(box),
                         {int(QMessageBox.Ok): "确定",
                          int(QMessageBox.Cancel): "取消"})
        i18n.init("en-US")
        ui_msg.localize_buttons(box)
        self.assertEqual(_texts(box),
                         {int(QMessageBox.Ok): "OK",
                          int(QMessageBox.Cancel): "Cancel"})

    def test_yes_no_are_localized(self):
        """Yes/No 是最容易漏的 —— Qt 英文默认就是 Yes/No，看着"像是对的"。"""
        box = QMessageBox()
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        i18n.init("zh-CN")
        ui_msg.localize_buttons(box)
        self.assertEqual(_texts(box),
                         {int(QMessageBox.Yes): "是", int(QMessageBox.No): "否"})

    def test_dialog_button_box_is_supported(self):
        """自定义对话框里的 Ok/Cancel 同样受影响（scan_mixin / ui_dialogs 共 4 处）。"""
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        i18n.init("zh-CN")
        ui_msg.localize_buttons(box)
        self.assertEqual(_texts(box),
                         {int(QDialogButtonBox.Ok): "确定",
                          int(QDialogButtonBox.Cancel): "取消"})

    def test_every_standard_button_has_a_translation(self):
        box = QMessageBox()
        for value in STANDARD_BUTTON_TEXT:
            box.setStandardButtons(QMessageBox.StandardButton(value))
            i18n.init("zh-CN")
            ui_msg.localize_buttons(box)
            for btn in box.buttons():
                self.assertTrue(btn.text().strip(),
                                "标准按钮 0x%X 没有中文文案" % value)

    def test_custom_buttons_are_left_alone(self):
        """自定义按钮的文案是调用方给的，不能被覆盖。"""
        box = QMessageBox()
        box.setStandardButtons(QMessageBox.Ok)
        custom = box.addButton("自定义动作", QMessageBox.ActionRole)
        i18n.init("zh-CN")
        ui_msg.localize_buttons(box)
        self.assertEqual(custom.text(), "自定义动作")
        self.assertEqual(_texts(box), {int(QMessageBox.Ok): "确定"})

    def test_empty_box_is_harmless(self):
        box = QMessageBox()
        ui_msg.localize_buttons(box)          # 不抛异常即可
        self.assertEqual(_texts(box), {})


class WrapperTest(unittest.TestCase):
    """包装函数的返回值与参数语义必须与 Qt 静态方法一致。

    `exec_()` 会阻塞，所以这里把它换成"记录对话框并返回固定值"的替身 ——
    这样既能断言返回值透传，又能拿到真实构造出来的 box 检查按钮文案。
    标题同样改成盯 `setWindowTitle()` 的**调用**而非 `windowTitle()` 属性：
    macOS 上 Qt 会清掉标题，读属性是平台相关的（见 test_msg_info_returns_exec_result）。
    """

    #: 替身返回的哨兵值 —— 用来验证包装函数把 exec_() 的结果原样透传
    SENTINEL = 424242

    def setUp(self):
        self._seen = []
        self._titles = []
        self._orig_exec = QMessageBox.exec_
        self._orig_set_title = QMessageBox.setWindowTitle
        sentinel = self.SENTINEL
        titles = self._titles
        orig_set_title = self._orig_set_title

        def fake_exec(box):
            self._seen.append(box)
            return sentinel

        def spy_set_title(box, title):
            titles.append(title)
            return orig_set_title(box, title)

        QMessageBox.exec_ = fake_exec
        QMessageBox.setWindowTitle = spy_set_title

    def tearDown(self):
        QMessageBox.exec_ = self._orig_exec
        QMessageBox.setWindowTitle = self._orig_set_title
        i18n.init("zh-CN")

    def test_msg_info_returns_exec_result(self):
        i18n.init("zh-CN")
        rc = ui_msg.msg_info(None, "标题", "内容")
        self.assertEqual(rc, self.SENTINEL)
        self.assertEqual(len(self._seen), 1)
        box = self._seen[0]
        # ⚠️ 不读 `box.windowTitle()`：macOS 的 QMessageBox 不显示标题栏，Qt 会把它
        # **清掉**（CI 实测 macOS 返回 `''`，其它平台返回 `'标题'`）—— 断言控件属性
        # 就成了平台相关的。这里改为盯"标题有没有被原样传下去"，三平台都成立。
        self.assertEqual(self._titles, ["标题"])
        self.assertEqual(box.text(), "内容")
        self.assertEqual(_texts(box), {int(QMessageBox.Ok): "确定"})

    def test_msg_warn_uses_warning_icon(self):
        ui_msg.msg_warn(None, "t", "x")
        self.assertEqual(self._seen[0].icon(), QMessageBox.Warning)

    def test_msg_error_uses_critical_icon(self):
        ui_msg.msg_error(None, "t", "x")
        self.assertEqual(self._seen[0].icon(), QMessageBox.Critical)

    def test_msg_ask_defaults_to_yes_no(self):
        i18n.init("zh-CN")
        ui_msg.msg_ask(None, "t", "x")
        self.assertEqual(_texts(self._seen[0]),
                         {int(QMessageBox.Yes): "是", int(QMessageBox.No): "否"})

    def test_msg_ask_honours_explicit_default_button(self):
        ui_msg.msg_ask(None, "t", "x", QMessageBox.Yes | QMessageBox.No,
                       QMessageBox.No)
        box = self._seen[0]
        # defaultButton() 返回的是按钮对象，要用 standardButton() 换算回枚举
        self.assertEqual(box.standardButton(box.defaultButton()), QMessageBox.No)

    def test_msg_about_has_single_ok(self):
        i18n.init("zh-CN")
        ui_msg.msg_about(None, "关于", "正文")
        self.assertEqual(_texts(self._seen[0]), {int(QMessageBox.Ok): "确定"})


class NoDirectStaticCallTest(unittest.TestCase):
    """项目里不得再出现 `QMessageBox.<静态方法>` —— 新增对话框必须走 ui_msg。

    这是结构性防线：P0-4 之所以有 93 处，是因为每一步都"只加了一处"，没人拦。
    """

    STATICS = {"information", "warning", "critical", "question", "about"}
    SKIP_DIRS = {"venv", "build", "dist", "dist_new", "__pycache__", ".git",
                 ".github", ".workbuddy", ".workbuddy-ai", ".codeartsdoer",
                 ".joycode", "tests"}

    def test_no_static_qmessagebox_calls_outside_ui_msg(self):
        offenders = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fn in sorted(filenames):
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
                if rel == "ui_msg.py":
                    continue
                with io.open(path, encoding="utf-8") as fh:
                    try:
                        tree = ast.parse(fh.read())
                    except SyntaxError:
                        continue
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    f = node.func
                    if (isinstance(f, ast.Attribute)
                            and isinstance(f.value, ast.Name)
                            and f.value.id == "QMessageBox"
                            and f.attr in self.STATICS):
                        offenders.append("%s:%d  QMessageBox.%s"
                                         % (rel, node.lineno, f.attr))
        self.assertEqual(
            offenders, [],
            "以下位置仍直接调用 QMessageBox 静态方法，按钮不会被本地化。\n"
            "请改走 ui_msg 的 msg_info / msg_warn / msg_error / msg_ask / msg_about：\n  "
            + "\n  ".join(offenders),
        )


class ButtonTextCoverageTest(unittest.TestCase):
    """按钮词条必须有英文翻译 —— 否则英文界面会显示中文按钮。"""

    def test_every_button_word_is_in_english_pack(self):
        import json
        with io.open(os.path.join(ROOT, "i18n", "en-US.json"),
                     encoding="utf-8") as f:
            pack = json.load(f)
        missing = sorted(w for w in STANDARD_BUTTON_TEXT.values()
                         if w not in pack)
        self.assertEqual(
            missing, [],
            "以下按钮文案缺少英文翻译，英文界面会显示中文：\n  "
            + "\n  ".join(repr(m) for m in missing),
        )


if __name__ == "__main__":
    unittest.main()
