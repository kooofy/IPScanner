# -*- coding: utf-8 -*-
"""图标与调色板工具：PC 图标预渲染、工具栏矢量图标、深色 QPalette 构造。"""
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import (
    QColor, QPainter, QBrush, QPen, QPixmap, QIcon, QPalette, QImage
)

from theme_tokens import token

#: {是否深色: (在线图标, 离线图标)} —— 按主题分别缓存
_PC_ICONS = {}


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


def current_dpr() -> float:
    """当前主屏的设备像素比。

    预渲染的位图图标必须按它放大后再 `setDevicePixelRatio`，否则在 150%/200%
    缩放下会被 Qt 拉伸插值，边缘发虚 —— `AA_UseHighDpiPixmaps` 只对"有对应
    高分变率资源的 QIcon"生效，自绘 Pixmap 不在其列。
    """
    from PyQt5.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        return 1.0
    screen = app.primaryScreen()
    if screen is None:
        return 1.0
    dpr = screen.devicePixelRatio()
    return float(dpr) if dpr else 1.0


def _make_pc_pixmap(online: bool, dark: bool = False, dpr: float = 1.0) -> QPixmap:
    """在安全的非 WM_PAINT 上下文中预渲染电脑图标 Pixmap。

    颜色取自语义色令牌：深色主题下若沿用浅色版的深绿/深灰，图标在深底上会
    糊成一团，因此按主题取不同色阶。dpr>1 时按物理像素渲染再标记 DPR。
    """
    pm = QPixmap(int(round(28 * dpr)), int(round(26 * dpr)))
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.scale(dpr, dpr)  # 之后一律用逻辑坐标绘制
    # 不启用抗锯齿 (部分环境下走 GDI+ 依赖 COM)
    w, h = 22, 17
    x0, y0 = 3, 1  # 居中偏移

    _edge = token("icon_online_edge" if online else "icon_offline_edge", dark)
    screen = QColor(token("icon_online_screen" if online else "icon_offline_screen", dark))
    edge = QColor(_edge)
    base = QColor(_edge)

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


def get_pc_icons(dark: bool = False, dpr: float = None):
    """惰性返回 (在线图标, 离线图标)，按 (主题, DPR) 分别缓存。

    主题切换后必须重取 —— 图标是预渲染位图，不会跟着 QSS 变色。
    DPR 变化（窗口被拖到另一块缩放不同的显示器）同理。
    """
    if dpr is None:
        dpr = current_dpr()
    key = (bool(dark), round(float(dpr), 2))
    icons = _PC_ICONS.get(key)
    if icons is None:
        icons = (QIcon(_make_pc_pixmap(True, dark, dpr)),
                 QIcon(_make_pc_pixmap(False, dark, dpr)))
        _PC_ICONS[key] = icons
    return icons


# ── 工具栏矢量图标（自 styles.py 迁入）─────────────────────────────
# 这些图形以 18x18 为设计基准，按 size/18 等比缩放，因此任意 size 都居中铺满。

def _gray_icon(base_icon):
    """将图标转为灰度，用于菜单左列（与黑色复选标记形成明显色差）。"""
    if not isinstance(base_icon, QIcon):
        return base_icon
    src = base_icon.pixmap(16, 16)
    img = src.toImage().convertToFormat(QImage.Format_ARGB32)
    for y in range(img.height()):
        for x in range(img.width()):
            c = img.pixelColor(x, y)
            if c.alpha() == 0:
                continue
            g = int(0.299 * c.red() + 0.587 * c.green() + 0.114 * c.blue())
            img.setPixelColor(x, y, QColor(g, g, g, c.alpha()))
    return QIcon(QPixmap.fromImage(img))


def _make_tool_icon(kind, color="#555555", size=18):
    """绘制工具栏小图标（IP/C/展开/收起），支持指定线条颜色以适配主题。"""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.scale(size / 18.0, size / 18.0)  # 18 基准 -> size，内容自动居中铺满
    pen = QPen(QColor(color))
    pen.setWidthF(1.5)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    if kind == "ip":
        p.drawRoundedRect(1, 1, 16, 16, 2, 2)
        font = p.font()
        font.setBold(True)
        font.setPointSize(6)
        p.setFont(font)
        p.drawText(QRect(1, 1, 16, 16), Qt.AlignCenter, "IP")
    elif kind == "c":
        p.drawRoundedRect(1, 1, 16, 16, 2, 2)
        font = p.font()
        font.setBold(True)
        font.setPointSize(7)
        p.setFont(font)
        p.drawText(QRect(1, 1, 16, 16), Qt.AlignCenter, "C")
    elif kind == "expand":
        p.drawRect(1, 1, 16, 16)
        p.drawLine(4, 7, 9, 12)
        p.drawLine(9, 12, 14, 7)
    elif kind == "collapse":
        p.drawRect(1, 1, 16, 16)
        p.drawLine(4, 10, 9, 5)
        p.drawLine(9, 5, 14, 10)
    p.end()
    return QIcon(pm)


def _make_pause_icon(color="#555555", size=18):
    """绘制暂停图标（两竖条），线条颜色随主题，与工具栏小工具一致。"""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.scale(size / 18.0, size / 18.0)
    pen = QPen(QColor(color))
    pen.setWidthF(2.5)
    pen.setCapStyle(Qt.FlatCap)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawLine(7, 3, 7, 15)
    p.drawLine(11, 3, 11, 15)
    p.end()
    return QIcon(pm)
