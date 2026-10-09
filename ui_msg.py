# -*- coding: utf-8 -*-
"""统一的对话框入口 —— 顺带把 Qt 内置对话框的按钮文案本地化。

## 为什么需要这个模块

PyQt5 5.15.11 自带 195 个 `.qm`，其中 `qtbase_*` 覆盖 23 种语言，**唯独没有
`zh_CN`**（只有 `zh_TW`）。所以 `QTranslator().load("qt_zh_CN")` 会返回 `True`
却什么都翻译不出来 —— 中文界面下 `QMessageBox` 的按钮仍显示 `OK` / `Cancel`。
PyQt5 也**没有** `setButtonText`，只能在对话框构造**之后**逐个
`QAbstractButton.setText()`。

本模块把这件事收敛到一处：静态方法的语义与 Qt 完全一致（同名参数、同样返回值），
只是在 `exec_()` 之前补一次按钮本地化。**新增对话框一律走这里**，不要再直接调
`QMessageBox.information/warning/critical/question/about` —— 漏掉就会退回英文
按钮（由 `tests/test_msg_buttons.py` 守着）。

深色主题不需要在这里处理：`_set_dark_mode()` 已经用 `app.setPalette()` 全局
套了深色 QPalette，新建的对话框会自动继承。
"""
from PyQt5.QtWidgets import QMessageBox

from i18n import tr

#: 标准按钮 → 规范中文文案。
#:
#: 键用 **int** 而非枚举对象：`QMessageBox.StandardButton` 与
#: `QDialogButtonBox.StandardButton` 是两个不同的枚举类型，但数值完全相同
#: （`Ok` 都是 0x400），用 int 做键才能让同一个函数同时服务两者。
#:
#: 值是**字面量**而不是 `tr(...)`：① 模块顶层调 `tr()` 会被冻结成导入期的语言
#: （`NoImportTimeTrTest` 强制）；② 这批标签由
#: `tests/test_i18n_lazy.py::TableDrivenLabelCoverageTest` 逐项校验有英文翻译。
STANDARD_BUTTON_TEXT = {
    0x00000400: "确定",            # Ok
    0x00000800: "保存",            # Save
    0x00001000: "全部保存",         # SaveAll
    0x00002000: "打开",            # Open
    0x00004000: "是",              # Yes
    0x00008000: "全部是",           # YesToAll
    0x00010000: "否",              # No
    0x00020000: "全部否",           # NoToAll
    0x00040000: "中止",            # Abort
    0x00080000: "重试",            # Retry
    0x00100000: "忽略",            # Ignore
    0x00200000: "关闭",            # Close
    0x00400000: "取消",            # Cancel
    0x00800000: "放弃",            # Discard
    0x01000000: "帮助",            # Help
    0x02000000: "应用",            # Apply
    0x04000000: "重置",            # Reset
    0x08000000: "恢复默认",         # RestoreDefaults
}


def localize_buttons(box):
    """把对话框上的标准按钮文案改成当前语言。

    `QMessageBox` 与 `QDialogButtonBox` 通用 —— 两者都有 `buttons()` 与
    `standardButton(button)`，且标准按钮的数值一致。非标准按钮（自定义
    `addButton()` 加的）`standardButton()` 返回 `NoButton`(0)，查不到就不动它。
    """
    for btn in box.buttons():
        text = STANDARD_BUTTON_TEXT.get(int(box.standardButton(btn)))
        if text:
            btn.setText(tr(text))
    return box


def _show(icon, parent, title, text, buttons, default):
    """构造 → 本地化 → exec_。对应 Qt 那几个静态方法。"""
    box = QMessageBox(parent)
    box.setIcon(icon)
    box.setWindowTitle(title)
    box.setText(text)
    box.setStandardButtons(buttons)
    if default is not None and default != QMessageBox.NoButton:
        box.setDefaultButton(default)
    localize_buttons(box)
    return box.exec_()


def msg_info(parent, title, text, buttons=QMessageBox.Ok, default=None) -> int:
    """对应 `QMessageBox.information()`。"""
    return _show(QMessageBox.Information, parent, title, text, buttons, default)


def msg_warn(parent, title, text, buttons=QMessageBox.Ok, default=None) -> int:
    """对应 `QMessageBox.warning()`。"""
    return _show(QMessageBox.Warning, parent, title, text, buttons, default)


def msg_error(parent, title, text, buttons=QMessageBox.Ok, default=None) -> int:
    """对应 `QMessageBox.critical()`。"""
    return _show(QMessageBox.Critical, parent, title, text, buttons, default)


def msg_ask(parent, title, text, buttons=QMessageBox.Yes | QMessageBox.No,
            default=None) -> int:
    """对应 `QMessageBox.question()`。返回被点击的标准按钮。"""
    return _show(QMessageBox.Question, parent, title, text, buttons, default)


def msg_about(parent, title, text) -> int:
    """对应 `QMessageBox.about()`（无标准按钮可选，固定一个「确定」）。"""
    return _show(QMessageBox.Information, parent, title, text, QMessageBox.Ok, None)
