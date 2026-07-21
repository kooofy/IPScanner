# -*- coding: utf-8 -*-
"""图标与调色板工具：PC 图标预渲染、深色 QPalette 构造。"""
from PyQt5.QtCore import Qt
from PyQt5.QtGui import (
    QColor, QPainter, QBrush, QPen, QPixmap, QIcon, QPalette
)

_PC_ICONS = None


def _build_dark_palette() -> QPalette:
    """构造深色 QPalette，用于原生对话框 (QMessageBox / QFileDialog / QInputDialog) 等
    未被自定义样式表覆盖的控件随主题上色。"""
    p = QPalette()
    p.setColor(QPalette.Window, QColor(43, 43, 43))
    p.setColor(QPalette.WindowText, QColor(224, 224, 224))
    p.setColor(QPalette.Base, QColor(30, 30, 30))
    p.setColor(QPalette.AlternateBase, QColor(45, 45, 48))
    p.setColor(QPalette.ToolTipBase, QColor(45, 45, 48))
    p.setColor(QPalette.ToolTipText, QColor(224, 224, 224))
    p.setColor(QPalette.Text, QColor(224, 224, 224))
    p.setColor(QPalette.Button, QColor(62, 62, 66))
    p.setColor(QPalette.ButtonText, QColor(224, 224, 224))
    p.setColor(QPalette.BrightText, QColor(255, 80, 80))
    p.setColor(QPalette.Link, QColor(77, 166, 255))
    p.setColor(QPalette.LinkVisited, QColor(120, 180, 255))
    p.setColor(QPalette.Highlight, QColor(14, 99, 156))
    p.setColor(QPalette.HighlightedText, Qt.white)
    return p


def _make_pc_pixmap(online: bool) -> QPixmap:
    """在安全的非 WM_PAINT 上下文中预渲染电脑图标 Pixmap。"""
    pm = QPixmap(28, 26)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    # 不启用抗锯齿 (部分环境下走 GDI+ 依赖 COM)
    w, h = 22, 17
    x0, y0 = 3, 1  # 居中偏移

    if online:
        screen = QColor(220, 252, 231)
        edge = QColor(22, 163, 74)
        base = QColor(22, 163, 74)
    else:
        screen = QColor(241, 245, 249)
        edge = QColor(148, 163, 184)
        base = QColor(148, 163, 184)

    # 显示器屏幕
    p.setPen(QPen(edge, 1.5))
    p.setBrush(QBrush(screen))
    p.drawRect(x0, y0, w, h)
    if online:
        p.setPen(QPen(QColor(134, 239, 172), 1))
        p.drawLine(x0 + 3, y0 + 4, x0 + w - 3, y0 + 4)
        p.drawLine(x0 + 3, y0 + 8, x0 + w - 6, y0 + 8)

    # 底座支架 + 底座
    cx = x0 + w // 2
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(base))
    p.drawRect(cx - 2, y0 + h, 4, 3)
    p.drawRect(cx - 7, y0 + h + 3, 14, 3)
    p.end()
    return pm


def get_pc_icons():
    """惰性返回 (在线图标, 离线图标)，首次调用时构造并缓存。"""
    global _PC_ICONS
    if _PC_ICONS is None:
        _PC_ICONS = (QIcon(_make_pc_pixmap(True)), QIcon(_make_pc_pixmap(False)))
    return _PC_ICONS
