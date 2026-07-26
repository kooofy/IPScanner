# -*- coding: utf-8 -*-
"""样式表、图标工具、预渲染常量。从 main_window.py 拆分出来。"""
import ipaddress
from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import QColor, QFont, QIcon, QImage, QPainter, QPen, QPixmap

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
    """绘制工具栏小图标（IP/C/展开/收起），支持指定线条颜色以适配主题。
    以 18x18 为设计基准等比缩放，任意 size 都居中。"""
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


STYLE_SHEET = """
QMainWindow {
    background-color: #F0F0F0;
}
QGroupBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    font-weight: bold;
    color: #333333;
    border: 1px solid #CCCCCC;
    border-radius: 2px;
    margin-top: 8px;
    padding-top: 14px;
    background-color: #FFFFFF;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
}
QPushButton {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    padding: 4px 12px;
    border-radius: 2px;
    border: 1px solid #ADADAD;
    background-color: #E1E1E1;
    color: #333333;
    min-height: 22px;
}
QPushButton:hover {
    background-color: #D0D0D0;
    border-color: #0078D7;
}
QPushButton:pressed {
    background-color: #C0C0C0;
}
QPushButton#primaryBtn {
    background-color: #F5F5F5;
    color: #666666;
    font-size: 18px;
    padding: 4px 14px;
    border: 1px solid #CCCCCC;
    border-radius: 2px;
}
QPushButton#primaryBtn:hover {
    background-color: #EBEBEB;
}
QPushButton#primaryBtn:pressed {
    background-color: #DCDCDC;
}
QPushButton#primaryBtn:disabled {
    background-color: #FAFAFA;
    color: #DCDCDC;
    border-color: #EBEBEB;
}
QPushButton#stopBtn {
    background-color: #F5F5F5;
    color: #666666;
    font-weight: bold;
    font-size: 18px;
    letter-spacing: 2px;
    padding: 4px 12px;
    border: 1px solid #CCCCCC;
    border-radius: 2px;
}
QPushButton#stopBtn:hover {
    background-color: #EBEBEB;
}
QPushButton#stopBtn:pressed {
    background-color: #DCDCDC;
}
QPushButton#stopBtn:disabled {
    background-color: #FAFAFA;
    color: #DCDCDC;
    border-color: #EBEBEB;
}
QPushButton#toolBtnGreen {
    background-color: #E8F5E9;
    border: 1px solid #CCCCCC;
    border-radius: 2px;
}
QPushButton#toolBtnGreen:hover {
    background-color: #C8E6C9;
}
QPushButton#toolBtnGreen:pressed {
    background-color: #A5D6A7;
}
QPushButton#toolBtnYellow {
    background-color: #FFF9C4;
    border: 1px solid #CCCCCC;
    border-radius: 2px;
}
QPushButton#toolBtnYellow:hover {
    background-color: #FFF59D;
}
QPushButton#toolBtnYellow:pressed {
    background-color: #FFF176;
}
QPushButton#dangerBtn {
    background-color: #E8E8E8;
    color: #D32F2F;
    border: 1px solid #D32F2F;
}
QPushButton#dangerBtn:hover {
    background-color: #FFEBEE;
}
QPushButton#dangerBtn:disabled {
    color: #BDBDBD;
    border-color: #BDBDBD;
}
QPushButton#successBtn {
    background-color: #E8F5E9;
    color: #2E7D32;
    border: 1px solid #2E7D32;
}
QPushButton#successBtn:hover {
    background-color: #C8E6C9;
}
QLineEdit {
    font-family: "Consolas", "Microsoft YaHei";
    font-size: 12px;
    padding: 3px 6px;
    border: 1px solid #ABABAB;
    border-radius: 1px;
    background-color: #FFFFFF;
    selection-background-color: #0078D7;
    min-height: 20px;
}
QLineEdit:focus {
    border: 1px solid #0078D7;
}
QComboBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    padding: 3px 6px;
    border: 1px solid #ABABAB;
    border-radius: 1px;
    background-color: #FFFFFF;
    min-height: 20px;
}
QSpinBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    padding: 3px 6px;
    border: 1px solid #ABABAB;
    border-radius: 1px;
    background-color: #FFFFFF;
    min-height: 20px;
}
QCheckBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    color: #333333;
}
QLabel {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    color: #333333;
}
QTreeWidget {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    color: #000000;
    gridline-color: #E8E8E8;
    background-color: #FFFFFF;
    alternate-background-color: #F7F7F7;
    border: 1px solid #CCCCCC;
    border-radius: 0px;
    selection-background-color: #CCE8FF;
    selection-color: #000000;
    outline: 0;
}
QTreeWidget::item {
    padding: 3px 4px;
    border: none;
    min-height: 24px;
}
QTreeWidget::item:hover {
    background-color: #E5F3FF;
}
QTreeWidget::item:selected {
    background-color: #CCE8FF;
    color: #000000;
}
QTreeWidget::branch {
    width: 16px;
}
QHeaderView::section {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    font-weight: bold;
    color: #000000;
    background-color: #E8E8E8;
    border: none;
    border-right: 1px solid #CCCCCC;
    border-bottom: 1px solid #CCCCCC;
    padding: 4px 6px;
}
QHeaderView::section:hover {
    background-color: #D8D8D8;
}
QProgressBar {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 11px;
    border: 1px solid #CCCCCC;
    border-radius: 1px;
    background-color: #E8E8E8;
    text-align: center;
    color: #333333;
    height: 18px;
}
QProgressBar::chunk {
    background-color: #0078D7;
    border-radius: 0px;
}
QStatusBar {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 11px;
    color: #555555;
    background-color: #F0F0F0;
    border-top: 1px solid #CCCCCC;
}
QListWidget {
    font-family: "Consolas", "Microsoft YaHei";
    font-size: 12px;
    border: 1px solid #CCCCCC;
    border-radius: 1px;
    background-color: #FFFFFF;
    padding: 1px;
}
QListWidget::item {
    padding: 2px 4px;
    border-radius: 1px;
}
QListWidget::item:hover {
    background-color: #E5F3FF;
}
QMenuBar {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 13px;
    background-color: #F5F5F5;
    border-bottom: 1px solid #D0D0D0;
    padding: 2px 4px;
    spacing: 2px;
}
QMenuBar::item {
    padding: 5px 12px;
    background-color: transparent;
    border-radius: 3px;
}
QMenuBar::item:selected {
    background-color: #D0E8FF;
    border: 1px solid #B0D0F0;
}
QMenuBar::item:pressed {
    background-color: #B0D8FF;
    border: 1px solid #90C0F0;
}
QMenu {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 13px;
    border: 1px solid #D0D0D0;
    background-color: #FFFFFF;
    padding: 4px 0;
    border-radius: 4px;
}
QMenu::separator {
    height: 1px;
    background-color: #D0D0D0;
    margin: 4px 0;
}
QMenu::item {
    padding: 6px 24px 6px 10px;
    background-color: transparent;
    min-width: 200px;
    max-width: 320px;
}
QMenu::icon {
    margin-right: 8px;
}
QMenu::item:selected {
    background-color: #E8F4FD;
    color: #000000;
}
QMenu::item:disabled {
    color: #A0A0A0;
    background-color: transparent;
}
QMenu::indicator {
    width: 13px;
    height: 13px;
    margin-left: 2px;
}
QMenu::right-arrow {
    width: 12px;
    height: 12px;
    padding-right: 4px;
}
QScrollBar:vertical {
    border: none;
    background: #F0F0F0;
    width: 12px;
    border-radius: 0px;
}
QScrollBar::handle:vertical {
    background: #C0C0C0;
    border-radius: 0px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #A0A0A0;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    border: none;
    background: #F0F0F0;
    height: 12px;
    border-radius: 0px;
}
QScrollBar::handle:horizontal {
    background: #C0C0C0;
    border-radius: 0px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover {
    background: #A0A0A0;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QToolTip {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 11px;
    background-color: #FFFFCC;
    color: #333333;
    border: 1px solid #999999;
    padding: 2px 4px;
}
"""

DARK_STYLE_SHEET = """
QMainWindow {
    background-color: #2B2B2B;
}
QGroupBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    font-weight: bold;
    color: #D0D0D0;
    border: 1px solid #3F3F46;
    border-radius: 2px;
    margin-top: 8px;
    padding-top: 14px;
    background-color: #333333;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
}
QPushButton {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    padding: 4px 12px;
    border-radius: 2px;
    border: 1px solid #555555;
    background-color: #3E3E42;
    color: #E0E0E0;
    min-height: 22px;
}
QPushButton:hover {
    background-color: #4A4A4F;
    border-color: #0078D7;
}
QPushButton:pressed {
    background-color: #2D2D30;
}
QPushButton#primaryBtn {
    background-color: #3C3C3C;
    color: #E0E0E0;
    font-size: 18px;
    padding: 4px 14px;
    border: 1px solid #555555;
    border-radius: 2px;
}
QPushButton#primaryBtn:hover {
    background-color: #4A4A4A;
}
QPushButton#primaryBtn:pressed {
    background-color: #2A2A2A;
}
QPushButton#primaryBtn:disabled {
    background-color: #2D2D30;
    color: #555555;
    border-color: #3F3F46;
}
QPushButton#stopBtn {
    background-color: #3C3C3C;
    color: #E0E0E0;
    font-weight: bold;
    font-size: 18px;
    letter-spacing: 2px;
    padding: 4px 12px;
    border: 1px solid #555555;
    border-radius: 2px;
}
QPushButton#stopBtn:hover {
    background-color: #4A4A4A;
}
QPushButton#stopBtn:pressed {
    background-color: #2A2A2A;
}
QPushButton#stopBtn:disabled {
    background-color: #2D2D30;
    color: #555555;
    border-color: #3F3F46;
}
QPushButton#toolBtnGreen, QPushButton#toolBtnYellow {
    background-color: #3C3C3C;
    border: 1px solid #555555;
    border-radius: 2px;
}
QPushButton#toolBtnGreen:hover, QPushButton#toolBtnYellow:hover {
    background-color: #4A4A4A;
}
QPushButton#toolBtnGreen:pressed, QPushButton#toolBtnYellow:pressed {
    background-color: #2A2A2A;
}
QPushButton#dangerBtn {
    background-color: #3E3E42;
    color: #F48771;
    border: 1px solid #F48771;
}
QPushButton#dangerBtn:hover {
    background-color: #3A2A2A;
}
QPushButton#dangerBtn:disabled {
    color: #6B5B5B;
    border-color: #5B4B5B;
}
QPushButton#successBtn {
    background-color: #2A3A36;
    color: #4EC9B0;
    border: 1px solid #4EC9B0;
}
QPushButton#successBtn:hover {
    background-color: #314742;
}
QLineEdit {
    font-family: "Consolas", "Microsoft YaHei";
    font-size: 12px;
    padding: 3px 6px;
    border: 1px solid #3F3F46;
    border-radius: 1px;
    background-color: #1E1E1E;
    color: #E0E0E0;
    selection-background-color: #264F78;
    min-height: 20px;
}
QLineEdit:focus {
    border: 1px solid #0078D7;
}
QComboBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    padding: 3px 6px;
    border: 1px solid #3F3F46;
    border-radius: 1px;
    background-color: #1E1E1E;
    color: #E0E0E0;
    min-height: 20px;
}
QSpinBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    padding: 3px 6px;
    border: 1px solid #3F3F46;
    border-radius: 1px;
    background-color: #1E1E1E;
    color: #E0E0E0;
    min-height: 20px;
}
QCheckBox {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    color: #D0D0D0;
}
QLabel {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    color: #D0D0D0;
}
QTreeWidget {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    color: #E0E0E0;
    gridline-color: #3F3F46;
    background-color: #1E1E1E;
    alternate-background-color: #252526;
    border: 1px solid #3F3F46;
    border-radius: 0px;
    selection-background-color: #094771;
    selection-color: #FFFFFF;
    outline: 0;
}
QTreeWidget::item {
    padding: 3px 4px;
    border: none;
    min-height: 24px;
}
QTreeWidget::item:hover {
    background-color: #2A2D2E;
}
QTreeWidget::item:selected {
    background-color: #094771;
    color: #FFFFFF;
}
QTreeWidget::branch {
    width: 16px;
}
QHeaderView::section {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    font-weight: bold;
    color: #E0E0E0;
    background-color: #2D2D30;
    border: none;
    border-right: 1px solid #3F3F46;
    border-bottom: 1px solid #3F3F46;
    padding: 4px 6px;
}
QHeaderView::section:hover {
    background-color: #3A3A3F;
}
QProgressBar {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 11px;
    border: 1px solid #3F3F46;
    border-radius: 1px;
    background-color: #2D2D30;
    text-align: center;
    color: #D0D0D0;
    height: 18px;
}
QProgressBar::chunk {
    background-color: #0E639C;
    border-radius: 0px;
}
QStatusBar {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 11px;
    color: #AAAAAA;
    background-color: #2B2B2B;
    border-top: 1px solid #3F3F46;
}
QListWidget {
    font-family: "Consolas", "Microsoft YaHei";
    font-size: 12px;
    border: 1px solid #3F3F46;
    border-radius: 1px;
    background-color: #1E1E1E;
    color: #E0E0E0;
    padding: 1px;
}
QListWidget::item {
    padding: 2px 4px;
    border-radius: 1px;
}
QListWidget::item:hover {
    background-color: #2A2D2E;
}
QMenuBar {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 13px;
    background-color: #252526;
    border-bottom: 1px solid #3F3F46;
    padding: 2px 4px;
    spacing: 2px;
}
QMenuBar::item {
    padding: 5px 12px;
    background-color: transparent;
    border-radius: 3px;
}
QMenuBar::item:selected {
    background-color: #3D3D40;
    border: 1px solid #4D4D50;
}
QMenuBar::item:pressed {
    background-color: #094771;
    border: 1px solid #094771;
}
QMenu {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 13px;
    border: 1px solid #454545;
    background-color: #2D2D30;
    color: #E0E0E0;
    padding: 4px 0;
    border-radius: 4px;
}
QMenu::separator {
    height: 1px;
    background-color: #454545;
    margin: 4px 0;
}
QMenu::item {
    padding: 6px 24px 6px 10px;
    background-color: transparent;
    min-width: 200px;
    max-width: 320px;
}
QMenu::icon {
    margin-right: 8px;
}
QMenu::item:selected {
    background-color: #094771;
    color: #FFFFFF;
}
QMenu::item:disabled {
    color: #666666;
    background-color: transparent;
}
QMenu::indicator {
    width: 13px;
    height: 13px;
    margin-left: 2px;
}
QMenu::right-arrow {
    width: 12px;
    height: 12px;
    padding-right: 4px;
}
QScrollBar:vertical {
    border: none;
    background: #2B2B2B;
    width: 12px;
    border-radius: 0px;
}
QScrollBar::handle:vertical {
    background: #555555;
    border-radius: 0px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #666666;
}
QScrollBar:add-line:vertical, QScrollBar:sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    border: none;
    background: #2B2B2B;
    height: 12px;
    border-radius: 0px;
}
QScrollBar::handle:horizontal {
    background: #555555;
    border-radius: 0px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover {
    background: #666666;
}
QScrollBar:add-line:horizontal, QScrollBar:sub-line:horizontal {
    width: 0px;
}
QToolTip {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 11px;
    background-color: #2D2D30;
    color: #E0E0E0;
    border: 1px solid #555555;
    padding: 2px 4px;
}
"""

# ── 预渲染字体 / 图标常量 ─────────────────────────────────────
_FONT_CONSOLAS_10 = QFont("Consolas", 10)
_FONT_CONSOLAS_9 = QFont("Consolas", 9)
_FONT_YAHEI_BOLD_9 = QFont("Microsoft YaHei", 9, QFont.Bold)


def _ip_to_int(ip: str):
    """IP 地址转整数排序键；非法地址返回 -1（排最前）。

    使用 ipaddress 解析，IPv4/IPv6 统一为整数，保证与 __lt__ 比较时类型一致
    （不会出现 int 与 str 混比引发 TypeError）。
    """
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return -1

