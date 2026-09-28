# -*- coding: utf-8 -*-
"""测试用的 Qt 应用对象工厂。

**为什么必须统一走这里**：Qt 不允许在进程里先创建 `QCoreApplication` 之后再
创建 `QApplication`。`QApplication.instance()` 会把已存在的 `QCoreApplication`
原样返回，而一旦拿它去构造任何 widget，进程会**直接 abort**（不是抛异常），
表现是 unittest 输出到一半戛然而止、没有任何汇总行。

真实踩坑：`test_bounded_pool` 原本用 `QCoreApplication`，`test_tree_service_children`
需要真正的 `QApplication`（要建 QTreeWidget）。单独跑各自都过，但
`unittest discover` 按字母序先跑前者、再跑后者时整个测试进程静默死掉 ——
而且退出码仍是 0，CI 上看不出任何异常。

所以所有需要 Qt 的测试统一调用 `ensure_qt_app()`，保证进程里那个唯一的
application 对象一定是 `QApplication`。
"""

_APP = None


def ensure_qt_app():
    """返回进程内唯一的 QApplication，不存在则创建。"""
    global _APP
    if _APP is not None:
        return _APP
    from PyQt5.QtWidgets import QApplication

    _APP = QApplication.instance()
    if _APP is None:
        _APP = QApplication([])
    return _APP
