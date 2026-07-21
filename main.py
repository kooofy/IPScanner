# -*- coding: utf-8 -*-
"""
局域网终端扫描工具 — GUI 主程序
基于 PyQt5，参考 Advanced IP Scanner / Angry IP Scanner 等工具的布局
"""

import sys
import os
import json
import time
import math
import re
import ipaddress
import platform
import socket
import subprocess
import shutil
import getpass
import locale

# ── 崩溃根因与修复说明 ──────────────────────────────────────────
# 此前"扫描闪退"是自定义委托 paint() 在 WM_PAINT 消息处理中触发 Windows 同步 COM
# 调用 (0x8001010d: RPC_E_CANTCALLOUT_ININPUTSYNCCALL) 所致。已彻底移除全部自定义委托
# paint：状态电脑图标改用 QTreeWidgetItem.setIcon + 模块加载期预渲染的 QPixmap，服务
# 链接改用树子项 + 标准图标 + 默认委托（见 _add_service_children）。paint 路径完全交给
# Qt 内部（纯光栅操作），不再执行任何自定义绘制代码，从根上规避该 COM 崩溃。
# 以下两个环境变量仅作为防御纵深保留（避免原生主题 / DirectWrite 路径意外触达 COM）：
#   QT_NO_DIRECTWRITE=1       → 文本渲染回退 GDI，不依赖 DirectWrite COM
#   QT_STYLE_OVERRIDE=Fusion  → 纯 Qt 自绘，不调用 Windows 原生主题 API
# 必须在 import PyQt5 之前设置才生效。
os.environ.setdefault("QT_NO_DIRECTWRITE", "1")
os.environ.setdefault("QT_STYLE_OVERRIDE", "Fusion")

import threading
from datetime import datetime
from typing import List, Dict

# 注意：faulthandler 在 Python 3.13 + PyQt5 环境下会导致 Windows COM 错误 (0x8001010d)，
# 表现为程序一启动就直接闪崩。原因是 faulthandler 注册的 SEH (结构化异常处理)
# 会干扰 Qt 内部的 DirectWrite / COM 调用链。
# 如需排查 C/C++ 级崩溃，可临时手动开启：import faulthandler; faulthandler.enable()
# 但在 Windows + Python 3.13 环境下默认保持关闭，以避免 0x8001010d 闪退。
# import faulthandler
# faulthandler.enable()

# 兜底：捕获事件循环之外、SafeApp.notify 覆盖不到的 Python 异常
def _global_except_hook(exc_type, exc_value, exc_tb):
    import traceback as _tb
    _err = "".join(_tb.format_exception(exc_type, exc_value, exc_tb))
    try:
        _log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash.log")
        with open(_log, "a", encoding="utf-8") as _f:
            _f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 未捕获异常(excepthook):\n{_err}\n{'=' * 60}\n")
    except Exception:
        pass
    sys.stderr.write(">>> [未捕获异常]\n" + _err)

sys.excepthook = _global_except_hook

_thread_hook_prev = threading.excepthook

def _thread_except_hook(args):
    import traceback as _tb
    _err = "".join(_tb.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
    try:
        _log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash.log")
        with open(_log, "a", encoding="utf-8") as _f:
            _f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 线程未捕获异常:\n{_err}\n{'=' * 60}\n")
    except Exception:
        pass
    sys.stderr.write(">>> [线程未捕获异常]\n" + _err)
    if _thread_hook_prev:
        _thread_hook_prev(args)

threading.excepthook = _thread_except_hook

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLineEdit, QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QProgressBar, QStatusBar, QFileDialog, QMessageBox, QCheckBox, QSpinBox,
    QComboBox, QGroupBox, QMenu, QAction, QAbstractItemView, QSplitter,
    QStyle, QTextEdit, QFrame, QToolButton, QSizePolicy,
    QDialog, QFormLayout, QDialogButtonBox, QActionGroup, QInputDialog,
    QTableWidget, QTableWidgetItem,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QGraphicsTextItem
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QSize, QTimer, QRect, QUrl, QProcess, QPoint,
    QSettings, QByteArray
)
from PyQt5.QtGui import (
    QColor, QFont, QIcon, QPainter, QBrush, QPen, QPixmap, QPalette,
    QCursor, QFontMetrics, QDesktopServices
)

from scanner import NetworkScanner, ScanResult, parse_ip_range, COMMON_PORTS, PORT_NAMES, PROTOCOL_PORTS

# (已移除自定义委托 paint 及配套的 paint_trace 诊断代码)

from excel_handler import export_results, export_csv, export_html, export_json, create_template, normalize_mac
from mac_library import MacLibrary


# ============================================================
# 样式表
# ============================================================
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
    background-color: #0078D7;
    color: white;
    font-weight: bold;
    border: 1px solid #005A9E;
}
QPushButton#primaryBtn:hover {
    background-color: #006CBE;
}
QPushButton#primaryBtn:pressed {
    background-color: #005A9E;
}
QPushButton#primaryBtn:disabled {
    background-color: #A0C4E8;
    border-color: #A0C4E8;
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
QMenu {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    border: 1px solid #CCCCCC;
    border-radius: 1px;
    background-color: #FFFFFF;
    padding: 2px;
}
QMenu::item {
    padding: 5px 20px;
    border-radius: 1px;
}
QMenu::item:selected {
    background-color: #CCE8FF;
    color: #000000;
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

# 深色模式样式表 (镜像 STYLE_SHEET，使用深色配色)。
# 配合 Fusion 样式 + 深色 QPalette 使用，原生对话框/未显式样式化的控件也随主题上色。
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
    background-color: #0E639C;
    color: #FFFFFF;
    font-weight: bold;
    border: 1px solid #0A4F7A;
}
QPushButton#primaryBtn:hover {
    background-color: #1177BB;
}
QPushButton#primaryBtn:pressed {
    background-color: #0A4F7A;
}
QPushButton#primaryBtn:disabled {
    background-color: #37373D;
    border-color: #37373D;
    color: #777777;
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
    border-color: #5B4B4B;
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
QMenu {
    font-family: "Microsoft YaHei", "Segoe UI";
    font-size: 12px;
    border: 1px solid #3F3F46;
    border-radius: 1px;
    background-color: #2D2D30;
    color: #E0E0E0;
    padding: 2px;
}
QMenu::item {
    padding: 5px 20px;
    border-radius: 1px;
    color: #E0E0E0;
}
QMenu::item:selected {
    background-color: #094771;
    color: #FFFFFF;
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


def _ip_to_int(ip: str):
    """IP 地址转整数排序键；非法地址返回 -1（排最前）。

    使用 ipaddress 解析，IPv4/IPv6 统一为整数，保证与 __lt__ 比较时类型一致
    （不会出现 int 与 str 混比引发 TypeError）。
    """
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return -1


class ResultTreeItem(QTreeWidgetItem):
    """结果树项：重写 < 以支持按列的数值排序（IP / 响应时间 / 序号）。

    排序键统一存放在各列的 Qt.UserRole；默认按字符串比较（含回退数值解析）。
    """

    def __lt__(self, other):
        tree = self.treeWidget()
        if tree is None:
            return QTreeWidgetItem.__lt__(self, other)
        col = tree.header().sortIndicatorSection()
        a = self.data(col, Qt.UserRole)
        b = other.data(col, Qt.UserRole)
        if a is not None and b is not None:
            return a < b
        # 回退：尝试数值比较，否则按字符串
        ta = self.text(col)
        tb = other.text(col)
        try:
            return float(ta) < float(tb)
        except (ValueError, TypeError):
            return ta < tb


def _detect_gateway() -> str:
    """推测默认网关 IP：优先解析系统路由表，失败则按本机网段 .1 推测。"""
    import subprocess as sp
    import socket as sock
    local_ip = ""
    try:
        local_ip = sock.gethostbyname(sock.gethostname())
    except Exception:
        pass
    gw_ip = None
    # Windows 路由表 (0.0.0.0/0 的下一跳)
    try:
        out = sp.run(["route", "print", "-4"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                cand = cols[2]
                if _is_valid_ip(cand):
                    gw_ip = cand
                    break
    except Exception:
        pass
    if not gw_ip and local_ip:
        parts = local_ip.split(".")
        if len(parts) == 4:
            gw_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return gw_ip or ""


def _build_dark_palette() -> "QPalette":
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


# ============================================================
# 扫描线程
# ============================================================
class ScanThread(QThread):
    progress = pyqtSignal(int, int, str)   # current, total, current_ip
    result_ready = pyqtSignal(object)       # ScanResult
    finished_signal = pyqtSignal(list)      # all results
    log_signal = pyqtSignal(str)            # log message

    def __init__(self, ip_ranges, timeout_ms=1000, max_threads=100, scan_ports=False,
                 protocols=None, tcp_scan_mode="connect", mdns_discovery=True):
        super().__init__()
        self.ip_ranges = ip_ranges
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports = scan_ports
        self.protocols = protocols or []
        self.tcp_scan_mode = tcp_scan_mode
        self.mdns_discovery = mdns_discovery
        self.scanner = NetworkScanner()

    def run(self):
        def on_progress(current, total, ip):
            self.progress.emit(current, total, ip)

        def on_result(result: ScanResult):
            self.result_ready.emit(result)

        self.log_signal.emit(f"开始扫描 {len(self.ip_ranges)} 个网段...")
        results =         self.scanner.scan(
            self.ip_ranges,
            timeout_ms=self.timeout_ms,
            max_threads=self.max_threads,
            scan_ports_flag=self.scan_ports,
            protocols=self.protocols,
            tcp_scan_mode=self.tcp_scan_mode,
            mdns_discovery=self.mdns_discovery,
            progress_callback=on_progress,
            result_callback=on_result,
        )

        online = sum(1 for r in results if r.status == "online")
        self.log_signal.emit(f"扫描完成: 共 {len(results)} 个IP, {online} 个在线")
        self.finished_signal.emit(results)

    def stop(self):
        self.scanner.stop()


class MdnsThread(QThread):
    """独立的 mDNS/DNS-SD 网络发现线程（不扫描也能量全网 mDNS 设备）。"""
    finished_signal = pyqtSignal(dict)   # {ip: {"names": set, "services": set}}
    log_signal = pyqtSignal(str)

    def __init__(self, timeout: float = 2.5):
        super().__init__()
        self.timeout = timeout

    def run(self):
        try:
            from scanner import mdns_discover
        except ImportError:
            try:
                from .scanner import mdns_discover
            except ImportError:
                mdns_discover = None
        if mdns_discover is None:
            self.log_signal.emit("mDNS 模块不可用")
            self.finished_signal.emit({})
            return
        self.log_signal.emit("正在做 mDNS 组播发现...")
        result = mdns_discover(timeout=self.timeout)
        self.log_signal.emit(f"mDNS 发现完成: {len(result)} 个设备")
        self.finished_signal.emit(result)


# ── 预创建字体与图标 ──────────────────────────────────────────
# 所有字体 / QPixmap 对象在模块加载期构造，绝不在委托 paint / WM_PAINT 中构造。
# 这样 paint 路径只剩 Qt 内部 drawPixmap (光栅操作)，不触发 COM。
_FONT_CONSOLAS_10 = QFont("Consolas", 10)
_FONT_CONSOLAS_9 = QFont("Consolas", 9)
_FONT_YAHEI_BOLD_9 = QFont("Microsoft YaHei", 9, QFont.Bold)


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


# 惰性初始化：QPixmap/QIcon 必须在 QApplication 创建之后才能构造，
# 因此不能在模块顶层 (import 时) 直接创建，否则会报
# "QPixmap: Must construct a QGuiApplication before a QPixmap"。
# 改为首次使用时 (此时 QApplication 已存在) 再构造并缓存。
_PC_ICONS = None


def get_pc_icons():
    """惰性返回 (在线图标, 离线图标)，首次调用时构造并缓存。"""
    global _PC_ICONS
    if _PC_ICONS is None:
        _PC_ICONS = (QIcon(_make_pc_pixmap(True)), QIcon(_make_pc_pixmap(False)))
    return _PC_ICONS


# ============================================================
# 主窗口
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("局域网终端扫描工具 — IP Scanner")
        self.setMinimumSize(1200, 750)
        self.resize(1300, 850)

        self.library = MacLibrary()  # 持久 MAC 地址库 (SQLite)
        self.selected_protocols = list(PROTOCOL_PORTS.keys())  # HTTP, HTTPS, FTP, RDP 默认开启
        self.tcp_scan_mode = "connect"  # 端口探测方式: connect / syn / udp
        self.mdns_discovery = True      # 扫描末尾做 mDNS 组播发现
        self.mdns_thread = None
        self.scan_thread = None
        self.all_results: list = []
        self.ip_range_items: list = []
        self._ip_item_map: dict = {}
        self.dark_mode = False  # 深色模式开关

        # 配置持久化 (QSettings, Ini 格式, 存于项目目录便于查看/重置)
        self.settings = QSettings(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ipscanner.ini"),
            QSettings.IniFormat
        )

        # 扫描历史快照 (JSON, 存于项目目录；含内部信息，已 gitignore)
        self.history_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "scan_history.json"
        )

        self._init_ui()
        self._init_menu()
        self._connect_signals()

        # 载入持久化配置 (主题/扫描参数/网段/窗口几何/列布局)
        self._load_settings()

        # 自动检测本机网段 (仅预填输入框，不影响已持久化的网段列表)
        self._auto_detect_subnet()
        # 载入地址库计数
        self._refresh_library_label()

        # 应用初始主题
        self._apply_theme(self.dark_mode)

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(2)
        main_layout.setContentsMargins(4, 4, 4, 4)

        # ── 工具栏 Row 1: 扫描按钮 + IP 范围 + 搜索 (仿 Advanced IP Scanner) ──
        tb1 = QHBoxLayout()
        tb1.setSpacing(4)
        tb1.setContentsMargins(2, 2, 2, 2)

        # 大按钮组：扫描 + 暂停（对齐 Advanced IP Scanner 左侧醒目工具栏）
        _BIG_BTN_H = 36
        _BIG_ICON = 32

        # 扫描按钮 - 白底 + 绿色播放图标（用图片资源替代绘制）
        _play_pm = QPixmap("assets/play_icon.png").scaled(
            _BIG_ICON, _BIG_ICON, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.scan_btn = QPushButton("扫描")
        self.scan_btn.setIcon(QIcon(_play_pm))
        self.scan_btn.setIconSize(QSize(_BIG_ICON, _BIG_ICON))
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.setFixedSize(100, _BIG_BTN_H)  # 固定宽高，避免被布局拉宽
        self.scan_btn.setStyleSheet(
            "QPushButton#primaryBtn { background-color: white; color: #333333; font-size: 18px; font-weight: normal; spacing: 20px; padding: 4px 14px; border: 1px solid #CCCCCC; border-radius: 2px; min-height: 36px; max-height: 36px; }"
            "QPushButton#primaryBtn:hover { background-color: #F5F5F5; }"
            "QPushButton#primaryBtn:pressed { background-color: #EBEBEB; }"
            "QPushButton#primaryBtn:disabled { background-color: #FAFAFA; color: #CCCCCC; border-color: #EBEBEB; }"
        )

        # 暂停/停止按钮 - 与扫描按钮同高的大按钮
        self.stop_btn = QPushButton("II")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setFixedSize(_BIG_BTN_H, _BIG_BTN_H)  # 正方形暂停按钮
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip("停止扫描")
        self.stop_btn.setStyleSheet(
            "QPushButton#stopBtn { background-color: #F5F5F5; color: #666666; font-weight: bold; font-size: 18px; letter-spacing: 2px; padding: 4px 12px; border: 1px solid #CCCCCC; border-radius: 2px; min-height: 36px; max-height: 36px; }"
            "QPushButton#stopBtn:hover { background-color: #EBEBEB; }"
            "QPushButton#stopBtn:pressed { background-color: #DCDCDC; }"
            "QPushButton#stopBtn:disabled { background-color: #FAFAFA; color: #DCDCDC; border-color: #EBEBEB; }"
        )

        tb1.addWidget(self.scan_btn)
        tb1.addWidget(self.stop_btn)

        # 四个快捷工具按钮（对齐 AIP 右侧工具栏）
        _SMALL_BTN = 30
        _ICON_SZ = 18

        def _make_tool_icon(kind):
            pm = QPixmap(_ICON_SZ, _ICON_SZ)
            pm.fill(Qt.transparent)
            p = QPainter(pm)
            p.setRenderHint(QPainter.Antialiasing, True)
            pen = QPen(QColor("#555555"))
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

        _green_style = (
            "QPushButton#toolBtnGreen { background-color: #E8F5E9; border: 1px solid #CCCCCC; border-radius: 2px; }"
            "QPushButton#toolBtnGreen:hover { background-color: #C8E6C9; }"
            "QPushButton#toolBtnGreen:pressed { background-color: #A5D6A7; }"
        )
        _yellow_style = (
            "QPushButton#toolBtnYellow { background-color: #FFF9C4; border: 1px solid #CCCCCC; border-radius: 2px; }"
            "QPushButton#toolBtnYellow:hover { background-color: #FFF59D; }"
            "QPushButton#toolBtnYellow:pressed { background-color: #FFF176; }"
        )

        self.local_subnet_btn = QPushButton()
        self.local_subnet_btn.setObjectName("toolBtnGreen")
        self.local_subnet_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.local_subnet_btn.setIcon(_make_tool_icon("ip"))
        self.local_subnet_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.local_subnet_btn.setToolTip("扫描本机所在子网")
        self.local_subnet_btn.setStyleSheet(_green_style)

        self.c_subnet_btn = QPushButton()
        self.c_subnet_btn.setObjectName("toolBtnGreen")
        self.c_subnet_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.c_subnet_btn.setIcon(_make_tool_icon("c"))
        self.c_subnet_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.c_subnet_btn.setToolTip("扫描 C 类子网")
        self.c_subnet_btn.setStyleSheet(_green_style)

        self.expand_btn = QPushButton()
        self.expand_btn.setObjectName("toolBtnYellow")
        self.expand_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.expand_btn.setIcon(_make_tool_icon("expand"))
        self.expand_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.expand_btn.setToolTip("全选并展开所有项")
        self.expand_btn.setStyleSheet(_yellow_style)

        self.collapse_btn = QPushButton()
        self.collapse_btn.setObjectName("toolBtnYellow")
        self.collapse_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.collapse_btn.setIcon(_make_tool_icon("collapse"))
        self.collapse_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.collapse_btn.setToolTip("收起所有项")
        self.collapse_btn.setStyleSheet(_yellow_style)

        tb1.addWidget(self.local_subnet_btn)
        tb1.addSpacing(2)
        tb1.addWidget(self.c_subnet_btn)
        tb1.addSpacing(2)
        tb1.addWidget(self.expand_btn)
        tb1.addSpacing(2)
        tb1.addWidget(self.collapse_btn)
        tb1.addSpacing(6)
        tb1.addStretch()  # 把第一行按钮全部压到左侧，右侧留白（对齐 AIP）

        # IP 范围输入
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText(
            "例如: 192.168.1.0/24, 192.168.2.0/24 (一行可写多个, 用逗号/空格/换行分隔)"
        )
        self.range_input.setMinimumWidth(280)
        self.range_input.returnPressed.connect(self._add_ip_range)

        # 已添加网段计数 (已移到底部状态栏，工具栏上不再显示)
        self.range_list_label = QLabel("")
        self.range_list_label.setStyleSheet("color: #0078D7; font-size: 11px; font-weight: bold;")
        self.range_list_label.setCursor(Qt.PointingHandCursor)
        self.range_list_label.setVisible(False)

        # 保留 range_list 作为内部存储 (不再显示)
        self.range_list = QTextEdit()
        self.range_list.setReadOnly(True)
        self.range_list.setVisible(False)

        # IP 范围输入框 / 搜索框 已移到第二行 (tb2)，第一行只保留动作按钮

        main_layout.addLayout(tb1)

        # ── 工具栏 Row 2: IP 范围 + 搜索（其余功能已移入菜单） ──
        tb2 = QHBoxLayout()
        tb2.setSpacing(8)
        tb2.setContentsMargins(2, 0, 2, 2)

        # IP 范围输入框（从第一行移来）
        tb2.addWidget(self.range_input, 1)

        tb2.addWidget(QLabel("搜索"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("IP / 主机名 / MAC ...")
        self.search_input.setFixedWidth(200)
        self.search_input.textChanged.connect(self._filter_results)
        tb2.addWidget(self.search_input)

        tb2.addStretch()

        main_layout.addLayout(tb2)

        # ── 原工具栏上的扫描参数 / 筛选：改为菜单驱动（保留实例供设置与扫描读取） ──
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 5000)
        self.timeout_spin.setValue(1000)
        self.timeout_spin.setSingleStep(100)

        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(100)
        self.threads_spin.setSingleStep(10)

        # 端口扫描：从复选框改为「扫描」菜单中的可勾选项
        self.port_scan_check = QAction("端口扫描", self, checkable=True)
        self.port_scan_check.setToolTip("对在线设备扫描常见端口")

        # mDNS 设备发现：扫描末尾做组播发现（发现 IoT/打印机/NAS 等）
        self.mdns_check = QAction("mDNS 设备发现", self, checkable=True)
        self.mdns_check.setToolTip("扫描末尾向本地组播组发现 mDNS/DNS-SD 设备")

        # 筛选：保留 ComboBox 作为值载体，由「视图 > 筛选」子菜单驱动
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["全部", "仅在线", "仅离线", "Excel已匹配", "有服务"])
        self.filter_combo.setCurrentText("仅在线")
        self.filter_combo.currentIndexChanged.connect(self._filter_results)

        # ── 分隔线 ──
        self.sep = QFrame()
        self.sep.setFrameShape(QFrame.HLine)
        self.sep.setFrameShadow(QFrame.Sunken)
        self.sep.setStyleSheet("color: #CCCCCC;")
        self.sep.setFixedHeight(2)
        main_layout.addWidget(self.sep)

        # ── 结果表格 (QTreeWidget, 13列, 支持展开/收起服务) ──
        self.table = QTreeWidget()
        self.table.setColumnCount(13)
        self.table.setHeaderLabels([
            "IP地址", "状态", "主机名", "MAC地址",
            "制造商", "位置", "使用者", "响应时间(ms)", "开放端口", "服务", "操作系统", "设备类型", "备注"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.setRootIsDecorated(True)
        self.table.setItemsExpandable(True)
        # PyQt5 5.15.x 的树列(tree column)固定为第 0 列。
        # IP地址 排在第 0 列，使展开三角自然落在 IP 列，
        # 子项 setFirstColumnSpanned(True) 也从 IP 列左缘开始跨列显示，仿 AIP 效果。
        self.table.setAllColumnsShowFocus(True)

        # 隐藏服务列（服务通过展开子项显示，仿 Advanced IP Scanner）
        self.table.hideColumn(9)

        # 列宽设置 (0=IP地址, 1=状态, 2=主机名, 3=MAC地址, 4=制造商, 5=位置, 6=使用者,
        #            7=响应时间, 8=开放端口, 9=服务, 10=操作系统, 11=设备类型, 12=备注)
        header = self.table.header()
        header.setStretchLastSection(False)
        _widths = {0: 130, 1: 78, 2: 140, 3: 220, 4: 100, 5: 120, 6: 90, 7: 90, 8: 160, 9: 200, 10: 150, 11: 120, 12: 180}
        for _col, _w in _widths.items():
            header.setSectionResizeMode(_col, QHeaderView.Interactive)
            header.resizeSection(_col, _w)
        # 状态电脑图标尺寸（预渲染 Pixmap 缩放到此尺寸，避免被压扁）
        self.table.setIconSize(QSize(18, 18))

        self.table.itemClicked.connect(self._on_item_clicked)
        # 右键上下文菜单：复制/重扫/WoL/地址库/内置工具（单连接，避免重复弹菜单）
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)

        main_layout.addWidget(self.table, 1)

        # ── 进度条 ──
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(18)
        main_layout.addWidget(self.progress_bar)

        # ── 状态栏 ──
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        self.status_label = QLabel("就绪")
        self.status_bar.addPermanentWidget(self.status_label)

        self.status_stats_label = QLabel("")
        self.status_stats_label.setStyleSheet("color: #333333; font-size: 12px;")
        self.status_bar.addPermanentWidget(self.status_stats_label)

        # 地址库状态（从工具栏移到底部状态栏）
        self.excel_label = QLabel("地址库: 空")
        self.excel_label.setStyleSheet("color: #888888; font-size: 11px;")
        self.status_bar.addPermanentWidget(self.excel_label)

    def _init_menu(self):
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu("文件(&F)")

        act_import = QAction("导入 Excel 到地址库", self)
        act_import.triggered.connect(self._import_excel)
        file_menu.addAction(act_import)

        act_template = QAction("生成 Excel 模板", self)
        act_template.triggered.connect(self._generate_template)
        file_menu.addAction(act_template)

        file_menu.addSeparator()

        self.act_export = QAction("导出扫描结果", self)
        self.act_export.triggered.connect(self._export_results)
        file_menu.addAction(self.act_export)

        file_menu.addSeparator()

        act_exit = QAction("退出", self)
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # MAC 地址库菜单
        lib_menu = menubar.addMenu("地址库(&L)")

        act_lib_manage = QAction("管理地址库...", self)
        act_lib_manage.triggered.connect(self._open_library_manager)
        lib_menu.addAction(act_lib_manage)

        act_lib_import = QAction("导入 Excel 到地址库", self)
        act_lib_import.triggered.connect(self._import_excel)
        lib_menu.addAction(act_lib_import)

        act_lib_export = QAction("导出地址库为 Excel", self)
        act_lib_export.triggered.connect(self._export_library)
        lib_menu.addAction(act_lib_export)

        # 扫描菜单
        scan_menu = menubar.addMenu("扫描(&S)")

        act_scan = QAction("开始扫描", self)
        act_scan.triggered.connect(self._start_scan)
        scan_menu.addAction(act_scan)

        act_stop = QAction("停止扫描", self)
        act_stop.triggered.connect(self._stop_scan)
        scan_menu.addAction(act_stop)

        scan_menu.addSeparator()

        act_scan_local = QAction("扫描本机所在子网", self)
        act_scan_local.triggered.connect(self._scan_local_subnet)
        scan_menu.addAction(act_scan_local)

        act_scan_c = QAction("扫描 C 类子网", self)
        act_scan_c.triggered.connect(self._scan_c_class_subnet)
        scan_menu.addAction(act_scan_c)

        scan_menu.addSeparator()

        self.act_clear = QAction("清空结果", self)
        self.act_clear.triggered.connect(self._clear_results)
        scan_menu.addAction(self.act_clear)

        act_history = QAction("历史对比...", self)
        act_history.triggered.connect(self._open_history_compare)
        scan_menu.addAction(act_history)

        scan_menu.addSeparator()

        # 端口扫描：原工具栏复选框，移入菜单
        scan_menu.addAction(self.port_scan_check)

        # mDNS 设备发现：扫描时默认开启，可关闭
        scan_menu.addAction(self.mdns_check)

        # 独立 mDNS 发现：不扫描也能量全网 mDNS 设备（合并进结果树）
        act_mdns = QAction("网络 mDNS 发现", self)
        act_mdns.setToolTip("对当前本地链路做 mDNS/DNS-SD 组播发现，发现打印机/NAS/Apple 设备等")
        act_mdns.triggered.connect(self._run_mdns_discovery)
        scan_menu.addAction(act_mdns)

        # 端口探测方式：全连接 / SYN 半开 / UDP（单选项）
        self.tcp_mode_group = QActionGroup(self)
        self.tcp_mode_group.setExclusive(True)
        mode_sub = scan_menu.addMenu("端口探测方式")
        for _m, _label in (("connect", "TCP 全连接"),
                           ("syn", "TCP SYN 半开"),
                           ("udp", "UDP 探测")):
            _a = QAction(_label, self, checkable=True)
            _a.setData(_m)
            _a.setActionGroup(self.tcp_mode_group)
            _a.setChecked(self.tcp_scan_mode == _m)
            _a.triggered.connect(
                lambda _checked, _mm=_m: self._set_tcp_mode(_mm)
            )
            mode_sub.addAction(_a)

        act_settings = QAction("扫描设置...", self)
        act_settings.triggered.connect(self._open_scan_settings)
        scan_menu.addAction(act_settings)

        scan_menu.addSeparator()

        act_add_range = QAction("添加网段", self)
        act_add_range.triggered.connect(self._add_ip_range)
        scan_menu.addAction(act_add_range)

        act_clear_ranges = QAction("清空网段", self)
        act_clear_ranges.triggered.connect(self._clear_ranges)
        scan_menu.addAction(act_clear_ranges)

        # 资源菜单 (应用层协议勾选)
        res_menu = menubar.addMenu("资源(&R)")
        for _proto in sorted(PROTOCOL_PORTS.keys()):
            _act = QAction(_proto, self, checkable=True)
            _act.setToolTip(f"扫描 {_proto} 服务")
            _act.setChecked(_proto in self.selected_protocols)
            _act.toggled.connect(
                lambda _checked, _p=_proto: self._toggle_protocol(_p, _checked)
            )
            res_menu.addAction(_act)

        # 工具菜单 (内置 Ping/Tracert/Telnet/SSH 等网络工具, P2)
        tool_menu = menubar.addMenu("工具(&T)")

        act_ping = QAction("Ping (持续)", self)
        act_ping.setToolTip("对目标执行持续 Ping (ping -t)")
        act_ping.triggered.connect(lambda: self._launch_network_tool("ping"))
        tool_menu.addAction(act_ping)

        act_tracert = QAction("Tracert (路由追踪)", self)
        act_tracert.setToolTip("对目标执行路由追踪 (tracert)")
        act_tracert.triggered.connect(lambda: self._launch_network_tool("tracert"))
        tool_menu.addAction(act_tracert)

        act_telnet = QAction("Telnet", self)
        act_telnet.setToolTip("对目标启动 Telnet 会话")
        act_telnet.triggered.connect(lambda: self._launch_network_tool("telnet"))
        tool_menu.addAction(act_telnet)

        act_ssh = QAction("SSH", self)
        act_ssh.setToolTip("对目标启动 SSH 会话 (需 OpenSSH 客户端)")
        act_ssh.triggered.connect(lambda: self._launch_network_tool("ssh"))
        tool_menu.addAction(act_ssh)

        tool_menu.addSeparator()

        act_rdp = QAction("远程桌面 (RDP)", self)
        act_rdp.setToolTip("用系统 mstsc 远程桌面连接目标")
        act_rdp.triggered.connect(lambda: self._launch_network_tool("rdp"))
        tool_menu.addAction(act_rdp)

        act_cmd = QAction("打开命令提示符", self)
        act_cmd.setToolTip("打开以目标命名的命令提示符窗口")
        act_cmd.triggered.connect(lambda: self._launch_network_tool("cmd"))
        tool_menu.addAction(act_cmd)

        tool_menu.addSeparator()

        act_shutdown = QAction("远程关机", self)
        act_shutdown.setToolTip("向目标发送关机指令 (shutdown /s /m)")
        act_shutdown.triggered.connect(lambda: self._remote_power("shutdown"))
        tool_menu.addAction(act_shutdown)

        act_reboot = QAction("远程重启", self)
        act_reboot.setToolTip("向目标发送重启指令 (shutdown /r /m)")
        act_reboot.triggered.connect(lambda: self._remote_power("reboot"))
        tool_menu.addAction(act_reboot)

        # 视图菜单
        view_menu = menubar.addMenu("视图(&V)")
        self.act_dark = QAction("深色模式", self)
        self.act_dark.setCheckable(True)
        self.act_dark.setChecked(self.dark_mode)
        self.act_dark.triggered.connect(self._toggle_dark_mode)
        view_menu.addAction(self.act_dark)

        # 显示列子菜单 (P2-3)
        col_menu = view_menu.addMenu("显示列")
        self._col_actions = {}
        _col_labels = [
            "IP地址", "状态", "主机名", "MAC地址", "制造商",
            "位置", "使用者", "响应时间(ms)", "开放端口", "服务", "操作系统", "设备类型", "备注"
        ]
        for _ci, _name in enumerate(_col_labels):
            _act = QAction(_name, self)
            _act.setCheckable(True)
            _act.setChecked(not self.table.isColumnHidden(_ci))
            _act.toggled.connect(
                lambda checked, c=_ci: self.table.setColumnHidden(c, not checked)
            )
            col_menu.addAction(_act)
            self._col_actions[_ci] = _act

        view_menu.addSeparator()

        act_expand = QAction("展开全部", self)
        act_expand.triggered.connect(self._expand_all_items)
        view_menu.addAction(act_expand)

        act_collapse = QAction("收起全部", self)
        act_collapse.triggered.connect(self._collapse_all_items)
        view_menu.addAction(act_collapse)

        view_menu.addSeparator()

        act_topology = QAction("拓扑视图...", self)
        act_topology.triggered.connect(self._open_topology)
        view_menu.addAction(act_topology)

        view_menu.addSeparator()

        # 筛选：原工具栏下拉框，移入菜单（单选项驱动 filter_combo）
        filter_menu = view_menu.addMenu("筛选")
        _filter_opts = ["全部", "仅在线", "仅离线", "Excel已匹配", "有服务"]
        _filter_group = QActionGroup(self)
        _filter_group.setExclusive(True)
        for _opt in _filter_opts:
            _fact = _filter_group.addAction(QAction(_opt, self, checkable=True))
            _fact.setChecked(self.filter_combo.currentText() == _opt)
            _fact.triggered.connect(
                lambda _checked, _o=_opt: self.filter_combo.setCurrentText(_o)
            )
            filter_menu.addAction(_fact)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")
        act_about = QAction("关于", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    # ── 深色模式 ──
    def _apply_theme(self, dark: bool):
        """应用/取消深色主题：切换 Fusion 深色 QPalette + 对应样式表，并刷新内联样式标签。"""
        app = QApplication.instance()
        if app is None:
            return
        # 首次调用时记录系统原始样式，供切换回浅色时恢复
        if not hasattr(self, "_original_style"):
            self._original_style = app.style().objectName()
        if dark:
            app.setStyle("Fusion")
            app.setPalette(_build_dark_palette())
            app.setStyleSheet(DARK_STYLE_SHEET)
        else:
            # 恢复系统默认样式与浅色样式表
            orig = getattr(self, "_original_style", None)
            if orig:
                app.setStyle(orig)
            app.setPalette(app.style().standardPalette())
            app.setStyleSheet(STYLE_SHEET)
        # 内联样式标签随主题重设颜色
        _blue = "#4DA6FF" if dark else "#0078D7"
        _muted = "#9AA0A6" if dark else "#888888"
        _stats = "#C8C8C8" if dark else "#555555"
        _sep = "#3F3F46" if dark else "#CCCCCC"
        if hasattr(self, "range_list_label"):
            self.range_list_label.setStyleSheet(f"color: {_blue}; font-size: 11px; font-weight: bold;")
        if hasattr(self, "excel_label"):
            self.excel_label.setStyleSheet(f"color: {_muted}; font-size: 11px;")
        if hasattr(self, "sep"):
            self.sep.setStyleSheet(f"color: {_sep};")

    def _toggle_dark_mode(self, checked: bool):
        self.dark_mode = checked
        self.act_dark.setChecked(checked)
        self._apply_theme(checked)
        self._save_settings()

    def _link_color(self) -> QColor:
        """服务链接/可点击文字颜色，随主题变化 (深色下提亮以保证对比度)。"""
        return QColor(77, 166, 255) if self.dark_mode else QColor(37, 99, 235)

    def _muted_color(self) -> QColor:
        """次要描述文字颜色，随主题变化。"""
        return QColor(150, 156, 166) if self.dark_mode else QColor(100, 116, 139)

    # ── 配置持久化 (P2-2) ──
    def _load_settings(self):
        """载入持久化配置：主题 / 扫描参数 / 网段 / 窗口几何 / 列布局。"""
        s = self.settings
        # 主题
        self.dark_mode = s.value("theme/dark", False, type=bool)
        self.act_dark.setChecked(self.dark_mode)
        # 扫描参数
        self.timeout_spin.setValue(s.value("scan/timeout_ms", 1000, type=int))
        self.threads_spin.setValue(s.value("scan/max_threads", 100, type=int))
        self.port_scan_check.setChecked(s.value("scan/port_scan", False, type=bool))
        self.mdns_discovery = s.value("scan/mdns", True, type=bool)
        self.mdns_check.setChecked(self.mdns_discovery)
        self.tcp_scan_mode = s.value("scan/tcp_mode", "connect", type=str)
        if self.tcp_scan_mode not in ("connect", "syn", "udp"):
            self.tcp_scan_mode = "connect"
        protos = s.value("scan/protocols", list(PROTOCOL_PORTS.keys()))
        if isinstance(protos, str):
            protos = [p.strip() for p in protos.split(",") if p.strip()]
        # 仅保留仍受支持的协议，剔除旧配置中的失效项
        self.selected_protocols = [p for p in protos if p in PROTOCOL_PORTS]
        if not self.selected_protocols:
            self.selected_protocols = list(PROTOCOL_PORTS.keys())
        # IP 网段
        ranges = s.value("scan/ip_ranges", [])
        if isinstance(ranges, str):
            ranges = [r.strip() for r in ranges.splitlines() if r.strip()]
        if ranges:
            self.ip_range_items = list(ranges)
            self._update_range_list()
        # 窗口几何 & 状态
        geom = s.value("window/geometry")
        if isinstance(geom, QByteArray):
            self.restoreGeometry(geom)
        state = s.value("window/state")
        if isinstance(state, QByteArray):
            self.restoreState(state)
        # 列布局 (宽度 / 顺序 / 隐藏 / 排序指示)
        # 仅在列布局版本一致时恢复 header_state，避免列序变更后旧状态错位
        _CUR_LAYOUT_VER = 3  # v2=IP/序号/状态…; v3=新增"设备类型"列(设备指纹深度)
        saved_ver = int(s.value("table/layout_ver", 0) or 0)
        hdr_state = s.value("table/header_state")
        if saved_ver == _CUR_LAYOUT_VER and isinstance(hdr_state, QByteArray):
            self.table.header().restoreState(hdr_state)
        # 同步"显示列"子菜单勾选态
        for _ci, _act in getattr(self, "_col_actions", {}).items():
            _act.setChecked(not self.table.isColumnHidden(_ci))

    def _save_settings(self):
        """保存当前配置到 ipscanner.ini。"""
        s = self.settings
        s.setValue("theme/dark", self.dark_mode)
        s.setValue("scan/timeout_ms", self.timeout_spin.value())
        s.setValue("scan/max_threads", self.threads_spin.value())
        s.setValue("scan/port_scan", self.port_scan_check.isChecked())
        s.setValue("scan/mdns", self.mdns_check.isChecked())
        s.setValue("scan/tcp_mode", self.tcp_scan_mode)
        s.setValue("scan/protocols", self.selected_protocols)
        s.setValue("scan/ip_ranges", self.ip_range_items)
        s.setValue("window/geometry", self.saveGeometry())
        s.setValue("window/state", self.saveState())
        s.setValue("table/header_state", self.table.header().saveState())
        s.setValue("table/layout_ver", 3)  # 列布局版本(v3=新增"设备类型"列)
        s.sync()

    def _connect_signals(self):
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.local_subnet_btn.clicked.connect(self._scan_local_subnet)
        self.c_subnet_btn.clicked.connect(self._scan_c_class_subnet)
        self.expand_btn.clicked.connect(self._expand_all_items)
        self.collapse_btn.clicked.connect(self._collapse_all_items)
        self.table.customContextMenuRequested.connect(self._show_context_menu)

    def _open_scan_settings(self):
        """弹出扫描设置对话框（超时 / 线程），由「扫描 > 扫描设置...」触发。"""
        dlg = QDialog(self)
        dlg.setWindowTitle("扫描设置")
        dlg.setMinimumWidth(240)
        _layout = QFormLayout(dlg)
        _to = QSpinBox(); _to.setRange(100, 5000); _to.setSingleStep(100)
        _to.setValue(self.timeout_spin.value())
        _th = QSpinBox(); _th.setRange(1, 500); _th.setSingleStep(10)
        _th.setValue(self.threads_spin.value())
        _layout.addRow("超时 (ms):", _to)
        _layout.addRow("线程数:", _th)
        _mode = QComboBox()
        _mode.addItems(["TCP 全连接", "TCP SYN 半开", "UDP 探测"])
        _mode_map = {"TCP 全连接": "connect", "TCP SYN 半开": "syn", "UDP 探测": "udp"}
        _mode.setCurrentText(
            {v: k for k, v in _mode_map.items()}.get(self.tcp_scan_mode, "TCP 全连接")
        )
        _layout.addRow("端口探测方式:", _mode)
        _btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        _btns.accepted.connect(dlg.accept)
        _btns.rejected.connect(dlg.reject)
        _layout.addRow(_btns)
        if dlg.exec_() == QDialog.Accepted:
            self.timeout_spin.setValue(_to.value())
            self.threads_spin.setValue(_th.value())
            self.tcp_scan_mode = _mode_map[_mode.currentText()]
            self._sync_tcp_mode_menu()
            self._save_settings()

    # --- IP 范围管理 ---

    def _auto_detect_subnet(self):
        """自动检测本机网段并填入"""
        import socket as sock
        try:
            hostname = sock.gethostname()
            local_ip = sock.gethostbyname(hostname)
            parts = local_ip.split(".")
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                self.range_input.setText(subnet)
                self.range_input.selectAll()
        except Exception:
            pass

    def _get_default_local_ip(self):
        """获取本机默认出口 IPv4 地址（非 127.0.0.1）。"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def _get_local_subnet(self):
        """根据 ipconfig 获取本机真实子网（含前缀长度），失败回退到 /24。"""
        try:
            out = subprocess.check_output(["ipconfig"], encoding="gbk", errors="ignore")
        except Exception:
            out = ""
        ips = re.findall(r"IPv4[地址\\s]+[\.:\s]+([\d.]+)", out)
        masks = re.findall(r"子网掩码[\.:\s]+([\d.]+)", out)
        if ips and masks and len(ips) == len(masks):
            for ip, mask in zip(ips, masks):
                if ip.startswith("127."):
                    continue
                try:
                    ip_parts = list(map(int, ip.split(".")))
                    mask_parts = list(map(int, mask.split(".")))
                    net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
                    prefix = sum(bin(m).count("1") for m in mask_parts)
                    return f"{'.'.join(net_parts)}/{prefix}"
                except Exception:
                    continue
        ip = self._get_default_local_ip()
        if ip:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def _get_c_class_subnet(self):
        """获取本机 IP 的 C 类子网 /24。"""
        ip = self._get_default_local_ip()
        if ip:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def _scan_local_subnet(self):
        """扫描本机所在子网：填充范围 -> 添加 -> 开始扫描。"""
        subnet = self._get_local_subnet()
        if subnet:
            self.range_input.setText(subnet)
            self._add_ip_range()
            self._start_scan()
        else:
            QMessageBox.warning(self, "提示", "无法获取本机 IP，请手动输入扫描范围。")

    def _scan_c_class_subnet(self):
        """扫描 C 类子网：填充范围 -> 添加 -> 开始扫描。"""
        subnet = self._get_c_class_subnet()
        if subnet:
            self.range_input.setText(subnet)
            self._add_ip_range()
            self._start_scan()
        else:
            QMessageBox.warning(self, "提示", "无法获取本机 IP，请手动输入扫描范围。")

    def _expand_all_items(self):
        """全选并展开所有结果项。"""
        self.table.selectAll()
        self.table.expandAll()

    def _collapse_all_items(self):
        """收起所有结果项。"""
        self.table.collapseAll()

    def _add_ip_range(self):
        text = self.range_input.text().strip()
        if not text:
            return

        # 一行内支持逗号 / 空格 / 换行 / 分号 / 制表符分隔多个网段 (类 Advanced IP Scanner)
        tokens = [t.strip() for t in re.split(r"[\s,;]+", text) if t.strip()]

        added, dup = 0, 0
        invalid = []
        for tok in tokens:
            if not parse_ip_range(tok):
                invalid.append(tok)
                continue
            if tok in self.ip_range_items:
                dup += 1
                continue
            self.ip_range_items.append(tok)
            added += 1

        if added > 0:
            self._update_range_list()
            self.range_input.clear()
            self.range_input.setFocus()

        if added == 0:
            # 全部无效或全部重复，未新增任何网段
            if invalid:
                QMessageBox.warning(
                    self, "格式错误",
                    "以下项无法解析:\n  " + "\n  ".join(invalid) +
                    "\n\n支持格式 (可一行多个, 用逗号/空格/换行分隔):\n"
                    "  192.168.1.0/24\n  192.168.1.1-254\n  192.168.1.1"
                )
            elif dup:
                QMessageBox.information(self, "提示", "这些网段都已添加过了")
            return

        # 有成功添加时，仅对"重复 / 无效"做补充提示，避免无效输入被静默吞掉
        if dup or invalid:
            msg = []
            if dup:
                msg.append(f"已跳过 {dup} 个重复网段")
            if invalid:
                msg.append("以下项无法解析, 已忽略:\n  " + "\n  ".join(invalid))
            QMessageBox.information(self, "提示", "\n".join(msg))

    def _clear_ranges(self):
        self.ip_range_items.clear()
        self._update_range_list()

    def _update_status_stats(self, total_ips=None):
        """在底部状态栏右侧汇总显示已添加网段/IP 与扫描结果统计。"""
        parts = []
        if self.ip_range_items:
            if total_ips is None:
                total_ips = sum(len(parse_ip_range(r)) for r in self.ip_range_items)
            parts.append(f"已添加: {len(self.ip_range_items)} 个网段, {total_ips} 个IP")
        if self.all_results:
            total = len(self.all_results)
            online = sum(1 for r in self.all_results if r.status == "online")
            offline = sum(1 for r in self.all_results if r.status == "offline")
            unknown = total - online - offline
            parts.append(f"{online} 开机状态, {offline} 关机状态, {unknown} 未知状态")
            matched = sum(1 for r in self.all_results if r.excel_matched)
            if self.library.is_loaded() and matched:
                parts.append(f"{matched} 已匹配")
        self.status_stats_label.setText("  |  ".join(parts))

    def _update_range_list(self):
        if self.ip_range_items:
            total_ips = sum(len(parse_ip_range(r)) for r in self.ip_range_items)
            # 紧凑显示: 网段数 + IP总数 (保留兼容，但控件已隐藏)
            self.range_list_label.setText(
                f"已添加: {len(self.ip_range_items)} 个网段, {total_ips} 个IP"
            )
            # Tooltip 显示完整列表
            tip = "\n".join(self.ip_range_items)
            self.range_list_label.setToolTip(tip)
            self.range_input.setToolTip(tip)
            # 内部存储 (保持兼容)
            display = "\n".join(self.ip_range_items)
            display += f"\n— 共 {len(self.ip_range_items)} 个网段, {total_ips} 个IP"
            self.range_list.setPlainText(display)
            self._update_status_stats(total_ips)
        else:
            self.range_list_label.setText("")
            self.range_list_label.setToolTip("")
            self.range_input.setToolTip("")
            self.range_list.clear()
            self._update_status_stats(0)

    # --- 扫描 ---

    def _start_scan(self):
        if not self.ip_range_items:
            text = self.range_input.text().strip()
            if text:
                self._add_ip_range()
            if not self.ip_range_items:
                QMessageBox.warning(self, "提示", "请先添加至少一个 IP 范围")
                return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.act_export.setEnabled(False)
        self.act_clear.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.table.setSortingEnabled(False)
        self.table.clear()
        self._ip_item_map.clear()

        self.scan_thread = ScanThread(
            self.ip_range_items,
            timeout_ms=self.timeout_spin.value(),
            max_threads=self.threads_spin.value(),
            scan_ports=self.port_scan_check.isChecked(),
            protocols=self.selected_protocols,
            tcp_scan_mode=self.tcp_scan_mode,
            mdns_discovery=self.mdns_check.isChecked(),
        )
        # 启动即持久化当前扫描参数与网段 (P2-2)
        self._save_settings()
        self.scan_thread.progress.connect(self._on_scan_progress, Qt.QueuedConnection)
        self.scan_thread.result_ready.connect(self._on_scan_result, Qt.QueuedConnection)
        self.scan_thread.finished_signal.connect(self._on_scan_finished, Qt.QueuedConnection)
        self.scan_thread.log_signal.connect(lambda msg: self.status_bar.showMessage(msg), Qt.QueuedConnection)
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_bar.showMessage("正在停止扫描...")
            self.scan_thread.wait(3000)

    def _toggle_protocol(self, proto, checked):
        """菜单勾选/取消协议，实时更新 selected_protocols 并提示。"""
        if checked:
            if proto not in self.selected_protocols:
                self.selected_protocols.append(proto)
        else:
            if proto in self.selected_protocols:
                self.selected_protocols.remove(proto)
        self.status_bar.showMessage(
            f"已选择协议: {', '.join(self.selected_protocols) if self.selected_protocols else '无'}"
        )

    def _set_tcp_mode(self, mode: str):
        """切换端口探测方式（全连接 / SYN 半开 / UDP）并持久化。"""
        self.tcp_scan_mode = mode
        self._sync_tcp_mode_menu()
        self._save_settings()
        _label = {"connect": "TCP 全连接", "syn": "TCP SYN 半开", "udp": "UDP 探测"}.get(mode, mode)
        _tip = ""
        if mode in ("syn", "udp"):
            _tip = "（需管理员权限；Windows 还需 Npcap，否则自动回退全连接）"
        self.status_bar.showMessage(f"端口探测方式: {_label}{_tip}")

    def _sync_tcp_mode_menu(self):
        """同步"端口探测方式"子菜单的勾选态到当前 tcp_scan_mode。"""
        for _a in self.tcp_mode_group.actions():
            _a.setChecked(_a.data() == self.tcp_scan_mode)

    def _on_scan_progress(self, current, total, ip):
        pct = int(current / total * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status_bar.showMessage(f"扫描中 [{current}/{total}] {ip} ...")

    def _on_scan_result(self, result: ScanResult):
        # 地址库匹配放在主线程执行 (SQLite 连接不能跨线程使用)
        if self.library and self.library.is_loaded():
            try:
                match = self.library.match(result.ip, result.mac)
                if match:
                    result.device_type = match.get("device_type", "")
                    result.location = match.get("location", "")
                    result.user = match.get("user", "")
                    result.remark = match.get("remark", "")
                    result.excel_matched = True
            except Exception as e:
                print("地址库匹配出错:", e)
        self._upsert_table_row(result)

    def _on_scan_finished(self, results):
        try:
            self.all_results = results
            # 保存历史快照用于对比 (P2-5)
            self._save_snapshot(results)
            
            # 先关闭排序，避免批量添加时的性能问题
            self.table.setSortingEnabled(False)
            
            # 全量刷新结果行：新设备入表，已有设备同步刷新
            # （扫描末尾的 mDNS 发现会为已有设备追加服务子项，需重渲染才能显示）
            for result in results:
                self._upsert_table_row(result)
            
            # 应用筛选（默认"仅在线"：扫描完成后隐藏离线终端）
            self._filter_results()

            # 端口探测方式回退告警（如 SYN/UDP 被系统拒绝后回退全连接）
            _warns = getattr(self.scan_thread.scanner, "warnings", []) if self.scan_thread else []
            if _warns:
                self.status_bar.showMessage("；".join(_warns))
                for _w in _warns:
                    print("[WARN]", _w)

            # 恢复排序
            self.table.setSortingEnabled(True)
            
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.act_export.setEnabled(True)
            self.act_clear.setEnabled(True)
            self.progress_bar.setVisible(False)
            self._update_stats()
            self.status_bar.showMessage("扫描完成")
        except Exception as e:
            sys.stderr.write(f"[ERR] _on_scan_finished 异常: {e}\n")
            import traceback
            traceback.print_exc()
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.act_export.setEnabled(True)
            self.act_clear.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage(f"扫描异常: {e}")

    def _run_mdns_discovery(self):
        """独立触发 mDNS/DNS-SD 组播发现（不依赖扫描），发现结果合并到树与 all_results。"""
        if self.mdns_thread and self.mdns_thread.isRunning():
            self.status_bar.showMessage("mDNS 发现进行中...")
            return
        self.mdns_thread = MdnsThread(timeout=2.5)
        self.mdns_thread.log_signal.connect(
            lambda m: self.status_bar.showMessage(m), Qt.QueuedConnection
        )
        self.mdns_thread.finished_signal.connect(
            self._on_mdns_finished, Qt.QueuedConnection
        )
        self.mdns_thread.start()

    def _on_mdns_finished(self, mdns_map: dict):
        """处理 mDNS 发现结果：合并到结果树与 all_results（去重）。"""
        try:
            self.table.setSortingEnabled(False)
            added = 0
            for ip, info in mdns_map.items():
                names = sorted(info.get("names", set()))
                services = sorted(info.get("services", set()))
                host = names[0].rstrip(".") if names else ""
                existing = next((r for r in self.all_results if r.ip == ip), None)
                if existing is None:
                    r = ScanResult(ip=ip, status="online",
                                   discovery_method="mdns", hostname=host)
                    self.all_results.append(r)
                else:
                    r = existing
                    r.status = "online"
                    if not r.discovery_method:
                        r.discovery_method = "mdns"
                    if not r.hostname and host:
                        r.hostname = host
                if services and "mDNS" not in r.services:
                    r.services.append("mDNS")
                    r.service_details.append({
                        "proto": "mDNS", "port": 0, "banner": ", ".join(services)
                    })
                self._upsert_table_row(r)
                added += 1
            self._filter_results()
            self.table.setSortingEnabled(True)
            self._update_stats()
            if added:
                self.status_bar.showMessage(f"mDNS 发现 {added} 个设备（已合并到结果）")
                self.act_export.setEnabled(True)
            else:
                self.status_bar.showMessage(
                    "mDNS 未发现新设备（可能网内无 mDNS 设备 / 组播端口被占用）"
                )
        except Exception as e:
            sys.stderr.write(f"[ERR] _on_mdns_finished: {e}\n")
            self.status_bar.showMessage(f"mDNS 处理异常: {e}")

    # --- 表格操作 ---

    def _upsert_table_row(self, result: ScanResult):
        """新增或更新指定 IP 的项，避免同一 IP 重复显示"""
        if result.ip in self._ip_item_map:
            item = self._ip_item_map[result.ip]
            self._update_item_data(item, result)
        else:
            item = self._add_top_level_item(result)
            self._ip_item_map[result.ip] = item
        # 增量应用筛选：离线终端边扫边隐藏（默认"仅在线"）
        item.setHidden(not self._item_matches_filter(item))

    def _add_top_level_item(self, result: ScanResult):
        item = ResultTreeItem()
        self.table.addTopLevelItem(item)
        self._set_item_data(item, result)
        self._add_service_children(item, result)
        return item

    def _update_item_data(self, item: QTreeWidgetItem, result: ScanResult):
        self._set_item_data(item, result)
        self._add_service_children(item, result)

    def _add_service_children(self, item: QTreeWidgetItem, result: ScanResult):
        """为设备项添加服务子项（展开后跨列显示），仿 Advanced IP Scanner 风格"""
        item.takeChildren()

        # 优先使用带 banner 的详细信息；旧结果无 details 时回退 services 列表
        details = result.service_details or []
        if not details and result.services:
            details = [{"proto": p, "port": PROTOCOL_PORTS.get(p.upper(), 0), "banner": ""}
                       for p in result.services]
        if not details:
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            return

        item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        parent_index = self.table.indexFromItem(item)
        for idx, detail in enumerate(details):
            proto = detail.get("proto", "")
            port = detail.get("port", 0)
            banner = detail.get("banner", "")
            proto_upper = proto.upper()

            child = QTreeWidgetItem()
            # UserRole 元数据固定存于第 0 列（IP/树列，点击逻辑从此读取）
            child.setData(0, Qt.UserRole, "service")
            child.setData(0, Qt.UserRole + 1, proto)
            child.setData(0, Qt.UserRole + 2, result.ip)
            child.setData(0, Qt.UserRole + 5, banner)

            # 第 0 列是 IP 地址列，也是树列(tree column)。
            # 服务子项的图标+文本放第 0 列，并通过 setFirstColumnSpanned
            # 让子项从 IP 列左缘起跨所有列显示，仿 AIP 效果。
            icon = self._service_icon(proto)
            if icon:
                child.setIcon(0, icon)

            if banner:
                # 保持与 AIP 一致的子项格式：proto, banner
                # 例如 HTTPS 会显示为 "HTTPS, Tunnel is OpenSSL TLSv1.2: xxx"
                display = f"{proto_upper}, {banner}"
            else:
                # 空 banner 时不再回退到 "port X"，与 AIP 保持一致：仅显示协议名
                display = proto_upper
            child.setText(0, display)
            child.setForeground(0, self._link_color())
            child.setToolTip(0, display)
            child.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)

            # 跨列显示：子项文本从第 0 列(IP列)起横跨整行。
            # 注意：必须使用 QTreeView.setFirstColumnSpanned(row, parent_index, True) 才能生效。

            # SNMP 保留 sysName/sysDescr 供点击弹窗展示
            if proto_upper == "SNMP":
                child.setData(0, Qt.UserRole + 3, result.snmp_sys_descr)
                child.setData(0, Qt.UserRole + 4, result.snmp_sys_name)

            item.addChild(child)
            self.table.setFirstColumnSpanned(idx, parent_index, True)

        # IP 地址列 (col 0) 按内容自适应宽度，避免 IP 被截断
        self.table.resizeColumnToContents(0)
        # MAC 地址列 (col 3) 按内容自适应宽度，保证默认状态完整显示终端 MAC
        self.table.resizeColumnToContents(3)

    def _service_icon(self, proto: str):
        proto_upper = proto.upper()
        if proto_upper in ("HTTP", "HTTPS"):
            return self._globe_icon()
        icon_map = {
            "FTP": QStyle.SP_DirIcon,
            "RDP": QStyle.SP_ComputerIcon,
            "SSH": QStyle.SP_CommandLink,
            "TELNET": QStyle.SP_CommandLink,
            "SNMP": QStyle.SP_DriveNetIcon,
            "SMB共享": QStyle.SP_DriveNetIcon,
            "mDNS": QStyle.SP_DriveNetIcon,
        }
        sp = icon_map.get(proto_upper)
        if sp:
            return self.style().standardIcon(sp)
        return self._globe_icon()

    def _globe_icon(self) -> QIcon:
        from PyQt5.QtGui import QPixmap, QPainter, QPen, QBrush, QColor
        pm = QPixmap(20, 20)
        pm.fill(Qt.transparent)
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.Antialiasing, True)

        # 地球底色
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor(59, 130, 246)))
        painter.drawEllipse(2, 2, 16, 16)

        # 经纬线
        painter.setPen(QPen(QColor(255, 255, 255, 180), 1))
        painter.setBrush(Qt.NoBrush)
        # 赤道
        painter.drawLine(2, 10, 18, 10)
        # 本初子午线
        painter.drawLine(10, 2, 10, 18)
        # 南北回归线
        painter.drawArc(4, 5, 12, 10, 0, 180 * 16)
        painter.drawArc(4, 5, 12, 10, 180 * 16, 180 * 16)

        painter.end()
        return QIcon(pm)

    def _service_desc(self, proto: str, ip: str) -> str:
        proto_upper = proto.upper()
        port = PROTOCOL_PORTS.get(proto_upper, "")
        if proto_upper == "HTTP":
            return f"HTTP服务, 端口 {port} ({ip}:{port})" if port else f"HTTP服务 ({ip})"
        elif proto_upper == "HTTPS":
            return f"HTTPS服务, 端口 {port} ({ip}:{port})" if port else f"HTTPS服务 ({ip})"
        elif proto_upper == "FTP":
            return f"FTP服务, 端口 {port}" if port else "FTP服务"
        elif proto_upper == "RDP":
            return f"远程桌面服务, 端口 {port}" if port else "远程桌面服务"
        else:
            return f"{proto_upper}服务"

    def _set_item_data(self, item: QTreeWidgetItem, result: ScanResult):
        """设置/更新指定项的所有列内容"""
        # ── 列布局: 0=IP地址, 1=状态, 2=主机名, 3=MAC, 4=制造商, 5=位置, 6=使用者, 7=响应时间, 8=开放端口, 9=服务, 10=备注 ──

        # IP地址列 (col 0) — 同时是树列(tree column)，展开三角在此列
        item.setText(0, result.ip)
        item.setData(0, Qt.UserRole, _ip_to_int(result.ip))  # IP 数值排序键
        item.setFont(0, _FONT_CONSOLAS_10)

        # 工具提示：标注发现方式（ARP 探测发现的静默主机）
        tip = result.ip
        if result.discovery_method == "arp":
            tip += " （ARP 主动探测发现 · 禁 Ping 但在线）"
        elif result.discovery_method == "mdns":
            tip += " （mDNS 发现 · 组播发现设备）"
        if result.os_guess:
            tip += f" · OS: {result.os_guess}"
            if result.os_detail:
                tip += f" ({result.os_detail})"
        if result.shares:
            tip += f" · 共享: {', '.join(result.shares)}"
        if result.device_class:
            tip += f" · 设备: {result.device_class}"
            if result.device_model:
                tip += f" ({result.device_model})"
        item.setToolTip(0, tip)

        # 状态列 (col 1)：预渲染电脑图标 (在线绿 / 离线灰) + 文字
        item.setData(1, Qt.UserRole, result.status)
        item.setData(1, Qt.DisplayRole, "在线" if result.status == "online" else "离线")
        item.setTextAlignment(1, Qt.AlignCenter)
        online_icon, offline_icon = get_pc_icons()
        if result.status == "online":
            item.setForeground(1, QColor(22, 163, 74))
            item.setIcon(1, online_icon)
        else:
            item.setForeground(1, QColor(220, 38, 38))
            item.setIcon(1, offline_icon)

        item.setText(2, result.hostname or "—")

        mac_text = result.mac.upper() if result.mac else "—"
        item.setText(3, mac_text)
        item.setFont(3, _FONT_CONSOLAS_10)

        manufacturer_text = "—"
        has_manufacturer = False
        if result.vendor:
            manufacturer_text = result.vendor
            has_manufacturer = True
        if result.device_type:
            if has_manufacturer:
                manufacturer_text = f"{manufacturer_text} · {result.device_type}"
            else:
                manufacturer_text = result.device_type
                has_manufacturer = True
        item.setText(4, manufacturer_text)
        if result.excel_matched and result.device_type:
            item.setForeground(4, self._link_color())
            item.setFont(4, _FONT_YAHEI_BOLD_9)

        item.setText(5, result.location or "—")

        item.setText(6, result.user or "—")

        if result.response_time > 0:
            item.setData(7, Qt.DisplayRole, round(result.response_time, 1))
            item.setData(7, Qt.UserRole, round(result.response_time, 1))  # 响应时间数值排序键
            item.setTextAlignment(7, Qt.AlignCenter)
        else:
            item.setText(7, "—")
            item.setData(7, Qt.UserRole, float("inf"))  # 无响应排最后
            item.setTextAlignment(7, Qt.AlignCenter)

        # 开放端口列：仅列出端口号。服务名称已由展开子项承担，避免冗余。
        ports_text = ", ".join(str(p) for p in result.open_ports) if result.open_ports else "—"
        item.setText(8, ports_text)
        item.setFont(8, _FONT_CONSOLAS_9)

        svc = result.services or []
        services_text = ", ".join(svc) if svc else "—"
        item.setText(9, services_text)
        item.setData(9, Qt.UserRole, list(svc))

        # 操作系统列 (col 10)：TTL 推测族 + banner 版本
        os_text = ""
        if result.os_guess or result.os_detail:
            os_text = (f"{result.os_guess} {result.os_detail}".strip())
        item.setText(10, os_text or "—")

        # 设备类型列 (col 11)：指纹推断的设备类别 + 型号，便于一眼识别具体设备
        if result.device_class:
            class_text = result.device_class
            if result.device_model:
                class_text = f"{class_text} · {result.device_model}"
            item.setText(11, class_text)
        else:
            item.setText(11, "—")

        item.setText(12, result.remark or "—")

    def _item_matches_filter(self, item):
        """判断单个顶层项是否满足当前搜索/筛选条件"""
        search_text = self.search_input.text().lower().strip()
        filter_type = self.filter_combo.currentText()

        show = True
        if filter_type == "仅在线":
            status = item.data(1, Qt.UserRole)
            show = show and (status == "online")
        elif filter_type == "仅离线":
            status = item.data(1, Qt.UserRole)
            show = show and (status == "offline")
        elif filter_type == "Excel已匹配":
            type_text = item.text(4)
            show = show and (type_text != "—")
        elif filter_type == "有服务":
            services_text = item.text(9)
            show = show and (services_text != "—")

        if show and search_text:
            row_text = ""
            for col in [0, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12]:
                row_text += item.text(col).lower() + " "
            show = search_text in row_text

        return show

    def _filter_results(self):
        """根据搜索和筛选条件显示/隐藏顶层项（默认"仅在线"：扫描时只显示在线终端）"""
        for i in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(i)
            item.setHidden(not self._item_matches_filter(item))

    def _on_item_clicked(self, item, col):
        """点击树形项 → 如果是服务子项，打开对应服务"""
        kind = item.data(0, Qt.UserRole)
        if kind == "service":
            proto = item.data(0, Qt.UserRole + 1)
            ip = item.data(0, Qt.UserRole + 2)
            if proto and ip:
                if proto == "SNMP":
                    descr = item.data(0, Qt.UserRole + 3) or ""
                    name = item.data(0, Qt.UserRole + 4) or ""
                    self._show_snmp_info(ip, name, descr)
                else:
                    self._open_service(proto, ip)

    # ── 内置网络工具 (P2) ──

    def _item_ip(self, item) -> str:
        """取树项对应的顶层设备 IP（服务子项上溯到父设备）。"""
        if item is None:
            return None
        while item.parent() is not None:
            item = item.parent()
        ip = item.text(0).strip()
        return ip or None

    def _selected_target(self) -> str:
        """当前选中设备 IP；无选中则返回 None。"""
        return self._item_ip(self.table.currentItem())

    def _launch_network_tool(self, tool: str, target: str = None):
        """
        启动内置网络工具。target 缺省时取当前选中设备 IP，否则弹窗询问。
        交互式工具 (ping/tracert/telnet/ssh) 在新控制台窗口中运行；
        RDP 直接调起 mstsc；cmd 打开以目标命名的命令提示符。
        """
        if not target:
            target = self._selected_target()
        if not target:
            text, ok = QInputDialog.getText(
                self, "选择目标", f"请输入要执行「{tool.upper()}」的目标 IP 或主机名:"
            )
            if not ok or not text.strip():
                return
            target = text.strip()

        # 构造命令
        if tool == "ping":
            cmd = f"ping -t {target}"
        elif tool == "tracert":
            cmd = f"tracert {target}"
        elif tool == "telnet":
            cmd = f"telnet {target}"
        elif tool == "ssh":
            user, ok = QInputDialog.getText(
                self, "SSH 连接", "请输入登录用户名:", text=getpass.getuser()
            )
            if not ok or not user.strip():
                return
            if not shutil.which("ssh"):
                QMessageBox.warning(
                    self, "未找到 ssh",
                    "系统未安装 OpenSSH 客户端（ssh.exe）。\n"
                    "请在“设置 → 应用 → 可选功能”中启用“OpenSSH 客户端”后重试。"
                )
                return
            cmd = f"ssh {user.strip()}@{target}"
        elif tool == "rdp":
            try:
                subprocess.Popen(["mstsc.exe", f"/v:{target}"])
                self.status_bar.showMessage(f"已启动 RDP: {target}")
            except Exception as e:
                QMessageBox.warning(self, "启动失败", f"无法启动远程桌面: {e}")
            return
        elif tool == "cmd":
            cmd = f"title IPScanner 已连接 {target}"
        else:
            return

        try:
            subprocess.Popen(
                ["cmd.exe", "/k", cmd],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            self.status_bar.showMessage(f"已启动 {tool.upper()}: {target}")
        except Exception as e:
            QMessageBox.warning(self, "启动失败", f"无法启动 {tool}: {e}")

    def _remote_power(self, action: str):
        """
        远程关机 / 重启：向目标发送 shutdown 指令。
        action: "shutdown" -> 关机；"reboot" -> 重启。
        需目标主机允许远程关机（本地管理员权限 + 远程注册表/足够权限），
        部分环境需在“本地安全策略”中授予“强制从远程系统关机”权限。
        """
        target = self._selected_target()
        if not target:
            text, ok = QInputDialog.getText(
                self, "远程" + ("关机" if action == "shutdown" else "重启"),
                "请输入目标 IP 或主机名:"
            )
            if not ok or not text.strip():
                return
            target = text.strip()

        _verb = "关机" if action == "shutdown" else "重启"
        reply = QMessageBox.question(
            self, f"确认远程{_verb}",
            f"确定要向 {target} 发送远程{_verb}指令吗？\n"
            f"（目标上将立即{_verb}，未保存的工作可能丢失）",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        # /f 强制关闭应用；/t 0 立即执行；/m 指定远程目标
        _flag = "/s" if action == "shutdown" else "/r"
        cmd = ["shutdown", _flag, "/m", f"\\\\{target}", "/f", "/t", "0"]
        try:
            _enc = locale.getpreferredencoding(False) or "gbk"
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                encoding=_enc, errors="replace"
            )
            if proc.returncode == 0:
                QMessageBox.information(
                    self, "指令已发送",
                    f"已向 {target} 发送远程{_verb}指令。"
                )
                self.status_bar.showMessage(f"已发送远程{_verb}: {target}")
            else:
                _err = (proc.stderr or proc.stdout or "").strip()
                QMessageBox.warning(
                    self, "远程" + _verb + "失败",
                    f"向 {target} 发送{_verb}指令失败 (退出码 {proc.returncode})。\n"
                    + (_err + "\n\n" if _err else "")
                    + "常见原因：目标未授权、网络不可达、缺少权限，\n"
                    + "或本地未以管理员身份运行本程序。"
                )
        except Exception as e:
            QMessageBox.warning(
                self, "远程" + _verb + "失败",
                f"执行远程{_verb}指令时出错: {e}"
            )

    def _show_snmp_info(self, ip, name, descr):
        """点击 SNMP 服务子项 → 弹窗展示设备识别信息"""
        text = f"IP 地址: {ip}\n"
        if name:
            text += f"系统名称 (sysName): {name}\n"
        if descr:
            text += f"\n系统描述 (sysDescr):\n{descr}"
        else:
            text += "\n(未获取到 sysDescr)"
        QMessageBox.information(self, "SNMP 设备信息", text)

    def _open_service(self, proto, ip):
        """根据协议打开浏览器 / 远程桌面。"""
        if proto == "HTTP":
            QDesktopServices.openUrl(QUrl(f"http://{ip}"))
        elif proto == "HTTPS":
            QDesktopServices.openUrl(QUrl(f"https://{ip}"))
        elif proto == "FTP":
            QDesktopServices.openUrl(QUrl(f"ftp://{ip}"))
        elif proto == "RDP":
            if not QProcess.startDetached("mstsc", [f"/v:{ip}"]):
                QMessageBox.information(
                    self, "远程桌面",
                    f"未能自动启动远程桌面连接。\n请手动运行：mstsc /v:{ip}"
                )

    def _update_stats(self):
        total = len(self.all_results)
        online = sum(1 for r in self.all_results if r.status == "online")
        offline = sum(1 for r in self.all_results if r.status == "offline")
        unknown = total - online - offline
        matched = sum(1 for r in self.all_results if r.excel_matched)
        parts = [f"{online} 开机状态", f"{offline} 关机状态", f"{unknown} 未知状态"]
        if self.library.is_loaded() and matched:
            parts.append(f"{matched} 已匹配")
        self._update_status_stats()

    def _clear_results(self):
        self.table.clear()
        self._ip_item_map.clear()
        self.all_results.clear()
        self._update_stats()
        self.act_export.setEnabled(False)
        self.act_clear.setEnabled(False)
        self.status_bar.showMessage("已清空结果")

    # ── 扫描历史 (P2-5) ──
    def _build_snapshot(self, results) -> dict:
        devices = []
        for r in results:
            devices.append({
                "ip": r.ip,
                "status": r.status,
                "mac": (r.mac or "").upper(),
                "hostname": r.hostname or "",
                "vendor": r.vendor or "",
            })
        return {"time": time.time(), "devices": devices}

    def _load_history(self) -> list:
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_snapshot(self, results, max_keep: int = 20):
        try:
            hist = self._load_history()
            hist.append(self._build_snapshot(results))
            if len(hist) > max_keep:
                hist = hist[-max_keep:]
            with open(self.history_path, "w", encoding="utf-8") as f:
                json.dump(hist, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("保存历史快照失败:", e)

    def _open_history_compare(self):
        dlg = HistoryCompareDialog(self.history_path, self)
        dlg.exec_()

    def _open_topology(self):
        if not self.all_results:
            QMessageBox.information(self, "拓扑视图", "请先完成一次扫描，再查看拓扑。")
            return
        gw_ip = _detect_gateway()
        dlg = TopologyDialog(self.all_results, gw_ip, self.dark_mode, self)
        dlg.exec_()

    # --- 右键菜单 ---

    def _show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return

        top_item = item
        while top_item and top_item.parent():
            top_item = top_item.parent()
        if not top_item:
            return

        # 提前计算关键信息 (供复制 / 唤醒 / 地址库操作复用)
        ip = self._item_text(top_item, 0)   # col 0 = IP地址
        mac = self._item_text(top_item, 3)  # col 3 = MAC地址
        lib_dev = self.library.match(ip, mac)
        if not mac and lib_dev:
            mac = (lib_dev.get("mac") or "").strip()

        menu = QMenu(self)

        act_copy_ip = QAction("复制 IP", self)
        act_copy_ip.triggered.connect(lambda: self._copy_item_cell(top_item, 0))
        menu.addAction(act_copy_ip)

        act_copy_mac = QAction("复制 MAC", self)
        act_copy_mac.triggered.connect(lambda: self._copy_item_cell(top_item, 3))
        menu.addAction(act_copy_mac)

        act_copy_host = QAction("复制主机名", self)
        act_copy_host.triggered.connect(lambda: self._copy_item_cell(top_item, 2))
        menu.addAction(act_copy_host)

        menu.addSeparator()

        act_copy_row = QAction("复制整行", self)
        act_copy_row.triggered.connect(lambda: self._copy_item_row(top_item))
        menu.addAction(act_copy_row)

        menu.addSeparator()

        act_rescan = QAction("重新扫描此 IP", self)
        act_rescan.triggered.connect(lambda: self._rescan_single_item(top_item))
        menu.addAction(act_rescan)

        if mac:
            act_wol = QAction("唤醒 (WoL)", self)
            act_wol.triggered.connect(lambda: self._wake_on_lan(mac))
            menu.addAction(act_wol)

        # 工具子菜单：快速启动内置网络工具
        tool_menu = menu.addMenu("工具")
        for label, tool in [
            ("Ping (持续)", "ping"),
            ("Tracert (路由追踪)", "tracert"),
            ("Telnet", "telnet"),
            ("SSH", "ssh"),
            ("远程桌面 (RDP)", "rdp"),
            ("打开命令提示符", "cmd"),
            ("远程关机", "shutdown"),
            ("远程重启", "reboot"),
        ]:
            tool_menu.addAction(label).triggered.connect(
                lambda _checked=False, t=tool: (
                    self._remote_power(t) if t in ("shutdown", "reboot")
                    else self._launch_network_tool(t, ip)
                )
            )

        menu.addSeparator()

        if lib_dev:
            act_edit_lib = QAction("编辑地址库条目", self)
            act_edit_lib.triggered.connect(lambda: self._edit_library_entry(lib_dev["id"]))
            menu.addAction(act_edit_lib)

            act_del_lib = QAction("从地址库删除", self)
            act_del_lib.triggered.connect(lambda: self._delete_library_entry(lib_dev["id"]))
            menu.addAction(act_del_lib)
        else:
            act_add_lib = QAction("加入地址库...", self)
            act_add_lib.triggered.connect(lambda: self._add_to_library(ip, mac))
            menu.addAction(act_add_lib)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _item_text(self, item, col: int) -> str:
        t = item.text(col).strip()
        return "" if t == "—" else t

    def _copy_item_cell(self, item, col):
        text = item.text(col)
        if text and text != "—":
            QApplication.clipboard().setText(text)
            self.status_bar.showMessage(f"已复制: {text}")

    def _copy_item_row(self, item):
        texts = []
        for col in range(self.table.columnCount()):
            texts.append(item.text(col))
        QApplication.clipboard().setText("\t".join(texts))
        self.status_bar.showMessage("已复制整行")

    def _rescan_single_item(self, item):
        ip = item.text(0)  # col 0 = IP地址
        if not ip:
            return
        self.range_input.setText(ip)
        self.ip_range_items = [ip]
        self._update_range_list()
        self._start_scan()

    def _wake_on_lan(self, mac: str):
        """发送 Wake-on-LAN 魔术包 (6×0xFF + 16×MAC) 到广播地址。"""
        import socket as sock
        mac_clean = mac.replace("-", "").replace(":", "").replace(".", "").strip().upper()
        if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
            QMessageBox.warning(self, "WoL 唤醒", f"MAC 地址格式无效，无法唤醒：\n{mac}")
            return
        try:
            mac_bytes = bytes.fromhex(mac_clean)
            packet = b"\xff" * 6 + mac_bytes * 16
            s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
            s.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)
            s.sendto(packet, ("255.255.255.255", 9))
            s.close()
            self.status_bar.showMessage(f"已向 {mac} 发送 WoL 魔术包")
            QMessageBox.information(
                self, "WoL 唤醒",
                f"已向 {mac} 发送唤醒魔术包。\n\n请确保目标设备已开启 WOL：\n"
                "• BIOS/UEFI 中启用 Wake on LAN\n"
                "• 网卡属性中允许「允许此设备唤醒计算机」"
            )
        except Exception as e:
            QMessageBox.warning(self, "WoL 唤醒", f"发送失败：{e}")

    def _open_library_manager(self):
        dlg = MacLibraryDialog(self.library, self)
        dlg.exec_()
        self._refresh_library_label()
        if self.all_results:
            self._refresh_matches_from_library()

    def _add_to_library(self, ip: str = "", mac: str = ""):
        dlg = DeviceEditDialog(self.library, parent=self, ip=ip, mac=mac)
        if dlg.exec_() == QDialog.Accepted:
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self.status_bar.showMessage("已加入地址库")

    def _edit_library_entry(self, device_id: int):
        dlg = DeviceEditDialog(self.library, parent=self, device_id=device_id)
        if dlg.exec_() == QDialog.Accepted:
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()

    def _delete_library_entry(self, device_id: int):
        dev = self.library.get_by_id(device_id)
        if not dev:
            return
        label = dev.get("mac") or dev.get("ip") or f"#{device_id}"
        reply = QMessageBox.question(
            self, "确认删除",
            f"确定从地址库删除该设备吗？\n\n{label}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.library.delete(device_id)
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self.status_bar.showMessage("已从地址库删除")

    # --- Excel ---

    def _import_excel(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "选择 Excel 文件（可多选，自动合并进地址库）", "",
            "Excel 文件 (*.xlsx *.xls);;所有文件 (*.*)"
        )
        if not files:
            return

        ok_files = 0
        errs = []
        for f in files:
            success, msg = self.library.merge_from_excel(f)
            if success:
                ok_files += 1
                self.status_bar.showMessage(msg)
            else:
                errs.append(f"{os.path.basename(f)}: {msg}")

        self._refresh_library_label()

        # 若已有扫描结果，按新地址库重新匹配标注
        if self.all_results:
            self._refresh_matches_from_library()

        if errs:
            QMessageBox.warning(self, "部分文件导入失败", "\n".join(errs))
        elif ok_files:
            QMessageBox.information(
                self, "导入成功",
                f"已合并 {ok_files} 个文件到地址库，共 {self.library.count()} 条。\n"
                f"扫描联网设备后将自动按 MAC 匹配。"
            )

    def _refresh_library_label(self):
        n = self.library.count()
        if n > 0:
            self.excel_label.setText(f"地址库: {n} 条")
            self.excel_label.setStyleSheet("color: #2E7D32; font-size: 11px; font-weight: bold;")
        else:
            self.excel_label.setText("地址库: 空")
            self.excel_label.setStyleSheet("color: #888888; font-size: 11px;")

    def _refresh_matches_from_library(self):
        """用当前地址库重新标注已有扫描结果 (导入/编辑地址库后调用)"""
        if not self.library.is_loaded():
            return
        for r in self.all_results:
            m = self.library.match(r.ip, r.mac)
            if m:
                r.device_type = m.get("device_type", "")
                r.location = m.get("location", "")
                r.user = m.get("user", "")
                r.remark = m.get("remark", "")
                r.excel_matched = True
            self._upsert_table_row(r)
        self._update_stats()

    def _export_library(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出地址库", default_name, "Excel 文件 (*.xlsx)"
        )
        if not file_path:
            return
        success, msg = self.library.export_to_excel(file_path)
        if success:
            self.status_bar.showMessage(msg)
            QMessageBox.information(self, "导出成功", msg)
        else:
            QMessageBox.warning(self, "导出失败", msg)

    def _generate_template(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存 Excel 模板", "设备清单模板.xlsx",
            "Excel 文件 (*.xlsx)"
        )
        if not file_path:
            return
        success, msg = create_template(file_path)
        if success:
            QMessageBox.information(self, "成功", msg)
        else:
            QMessageBox.warning(self, "失败", msg)

    def _export_results(self):
        if not self.all_results:
            QMessageBox.warning(self, "提示", "没有可导出的结果")
            return

        default_name = f"扫描结果_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "导出扫描结果", default_name,
            "Excel 文件 (*.xlsx);;CSV 文件 (*.csv);;HTML 文件 (*.html);;JSON 文件 (*.json)"
        )
        if not file_path:
            return

        # 依据过滤器/后缀决定导出格式（用户未手动加后缀时按过滤器补上）
        path = file_path
        low = path.lower()
        if not (low.endswith(".xlsx") or low.endswith(".csv")
                or low.endswith(".html") or low.endswith(".json")):
            if "CSV" in selected_filter:
                path += ".csv"
            elif "HTML" in selected_filter:
                path += ".html"
            elif "JSON" in selected_filter:
                path += ".json"
            else:
                path += ".xlsx"

        if path.lower().endswith(".csv"):
            success, msg = export_csv(self.all_results, path)
        elif path.lower().endswith(".html"):
            success, msg = export_html(self.all_results, path)
        elif path.lower().endswith(".json"):
            success, msg = export_json(self.all_results, path)
        else:
            success, msg = export_results(self.all_results, path)

        if success:
            self.status_bar.showMessage(msg)
            QMessageBox.information(self, "导出成功", msg)
        else:
            QMessageBox.warning(self, "导出失败", msg)

    # --- 关于 ---

    def _show_about(self):
        QMessageBox.about(self, "关于", (
            "<h3>局域网终端扫描工具</h3>"
            "<p>版本 1.0</p>"
        "<p>功能：</p>"
        "<ul>"
        "<li>支持 CIDR / IP 范围 / 跨网段扫描</li>"
        "<li>ICMP Ping + ARP 主动探测（发现禁 Ping 主机）+ 主机名 + 端口探测</li>"
        "<li>端口探测方式：TCP 全连接 / SYN 半开 / UDP（可切换）</li>"
        "<li>共享文件夹探测（SMB 共享枚举）</li>"
        "<li>Excel 设备信息导入与自动匹配</li>"
        "<li>结果导出为 Excel / CSV / HTML / JSON</li>"
        "<li>mDNS 设备发现（组播发现打印机 / NAS / Apple 设备 / IoT 等）</li>"
        "<li>操作系统探测（TTL 推测 + 服务 banner 提取版本）</li>"
        "<li>设备指纹深度（端口/服务/mDNS/UPnP/SNMP 综合推断设备类型与型号）</li>"
        "<li>内置网络工具：Ping / Tracert / Telnet / SSH / RDP / 命令提示符 / 远程关机 / 远程重启</li>"
        "</ul>"
            "<p style='color: #94A3B8;'>基于 PyQt5 开发</p>"
        ))

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(3000)
        self._save_settings()
        event.accept()


# ============================================================
# MAC 地址库管理对话框
# ============================================================
class DeviceEditDialog(QDialog):
    """新增 / 编辑单条设备"""

    FIELDS = [
        ("ip", "IP 地址", "例如 192.168.1.10"),
        ("mac", "MAC 地址", "例如 AA:BB:CC:DD:EE:FF"),
        ("device_type", "设备类型", "例如 PC / 打印机 / 一体机"),
        ("location", "位置", "例如 3楼-301办公室"),
        ("user", "使用者", "例如 张三 / 财务科"),
        ("remark", "备注", "选填"),
        ("vendor", "厂商", "选填"),
    ]

    def __init__(self, library: MacLibrary, parent=None, device_id=None, ip="", mac=""):
        super().__init__(parent)
        self.library = library
        self.device_id = device_id
        self.setWindowTitle("编辑设备" if device_id else "新增设备")
        self.setMinimumWidth(420)

        existing = library.get_by_id(device_id) if device_id else {}
        prefill = {"ip": ip, "mac": mac}

        layout = QFormLayout(self)
        self.edits = {}
        for key, label, ph in self.FIELDS:
            le = QLineEdit()
            le.setPlaceholderText(ph)
            val = existing.get(key, "") if existing else prefill.get(key, "")
            le.setText(val if val is not None else "")
            self.edits[key] = le
            layout.addRow(label, le)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _on_accept(self):
        data = {k: self.edits[k].text().strip() for k, _, _ in self.FIELDS}
        # MAC 校验 (允许为空，但填了要像 MAC)
        if data["mac"]:
            norm = normalize_mac(data["mac"])
            if not norm:
                QMessageBox.warning(self, "格式错误", "MAC 地址格式不正确，请检查后重试。")
                return
            data["mac"] = norm
        if self.device_id:
            self.library.update(self.device_id, **data)
        else:
            self.library.add(**data)
        self.accept()


class MacLibraryDialog(QDialog):
    """地址库管理：浏览 / 搜索 / 增 / 删 / 改 / 导出"""

    COLS = ["ID", "IP地址", "MAC地址", "设备类型", "位置", "使用者", "备注", "来源文件"]

    def __init__(self, library: MacLibrary, parent=None):
        super().__init__(parent)
        self.library = library
        self.setWindowTitle("MAC 地址库管理")
        self.resize(1000, 620)

        vbox = QVBoxLayout(self)

        # 工具条
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("搜索:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("按 IP / MAC / 类型 / 位置 / 使用者 搜索")
        self.search_edit.textChanged.connect(self._reload)
        toolbar.addWidget(self.search_edit)

        toolbar.addStretch()
        btn_add = QPushButton("新增")
        btn_add.clicked.connect(self._add)
        btn_edit = QPushButton("编辑")
        btn_edit.clicked.connect(self._edit)
        btn_del = QPushButton("删除")
        btn_del.clicked.connect(self._delete)
        btn_export = QPushButton("导出")
        btn_export.clicked.connect(self._export)
        btn_refresh = QPushButton("刷新")
        btn_refresh.clicked.connect(self._reload)
        for b in (btn_add, btn_edit, btn_del, btn_export, btn_refresh):
            toolbar.addWidget(b)
        vbox.addLayout(toolbar)

        # 表格
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(self._edit)
        hdr = self.table.horizontalHeader()
        # 所有列均可手动拖动调整宽度
        hdr.setStretchLastSection(False)
        _lib_widths = {0: 45, 1: 130, 2: 150, 3: 110, 4: 160, 5: 110, 6: 160, 7: 220}
        for _col, _w in _lib_widths.items():
            hdr.setSectionResizeMode(_col, QHeaderView.Interactive)
            hdr.resizeSection(_col, _w)
        vbox.addWidget(self.table)

        # 底部状态
        self.status = QLabel("")
        vbox.addWidget(self.status)

        self._reload()

    def _reload(self):
        q = self.search_edit.text().strip()
        rows = self.library.search(q) if q else self.library.get_all()
        self.table.setRowCount(len(rows))
        for r, dev in enumerate(rows):
            vals = [str(dev["id"]), dev["ip"], dev["mac"], dev["device_type"],
                    dev["location"], dev["user"], dev["remark"], dev["source_file"]]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(r, c, item)
        self.status.setText(f"共 {len(rows)} 条")

    def _selected_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return int(item.text()) if item else None

    def _add(self):
        dlg = DeviceEditDialog(self.library, parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self._reload()

    def _edit(self):
        did = self._selected_id()
        if did is None:
            QMessageBox.information(self, "提示", "请先选中一行")
            return
        dlg = DeviceEditDialog(self.library, parent=self, device_id=did)
        if dlg.exec_() == QDialog.Accepted:
            self._reload()

    def _delete(self):
        did = self._selected_id()
        if did is None:
            QMessageBox.information(self, "提示", "请先选中一行")
            return
        dev = self.library.get_by_id(did)
        label = (dev.get("mac") or dev.get("ip") or f"#{did}")
        reply = QMessageBox.question(
            self, "确认删除", f"确定删除该设备吗？\n\n{label}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.library.delete(did)
            self._reload()

    def _export(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出地址库", default_name, "Excel 文件 (*.xlsx)"
        )
        if not path:
            return
        success, msg = self.library.export_to_excel(path)
        QMessageBox.information(self, "导出成功" if success else "导出失败", msg)


# ============================================================
# 扫描历史对比 (P2-5)
# ============================================================
def _compare_snapshots(base: dict, target: dict) -> list:
    """对比两个快照，返回差异行列表：{ip, change, old, new}。"""
    base_map = {d["ip"]: d for d in base.get("devices", [])}
    target_map = {d["ip"]: d for d in target.get("devices", [])}
    diffs = []

    def _fmt(d):
        return f"{d.get('status', '?')} / {d.get('hostname') or '—'} / {d.get('mac') or '—'}"

    for ip, td in target_map.items():
        if ip not in base_map:
            diffs.append({"ip": ip, "change": "新增设备", "old": "—", "new": _fmt(td)})
    for ip, bd in base_map.items():
        if ip not in target_map:
            diffs.append({"ip": ip, "change": "消失设备", "old": _fmt(bd), "new": "—"})
    for ip in base_map:
        if ip in target_map:
            bd, td = base_map[ip], target_map[ip]
            if bd.get("status") != td.get("status"):
                diffs.append({"ip": ip, "change": "状态变更",
                              "old": bd.get("status", "—"), "new": td.get("status", "—")})
            if (bd.get("mac") or "") != (td.get("mac") or ""):
                diffs.append({"ip": ip, "change": "MAC 变更",
                              "old": bd.get("mac") or "—", "new": td.get("mac") or "—"})
            if (bd.get("hostname") or "") != (td.get("hostname") or ""):
                diffs.append({"ip": ip, "change": "主机名变更",
                              "old": bd.get("hostname") or "—", "new": td.get("hostname") or "—"})
    return diffs


class HistoryCompareDialog(QDialog):
    """选择两次历史快照进行差异对比。"""

    def __init__(self, history_path: str, parent=None):
        super().__init__(parent)
        self.history_path = history_path
        self.setWindowTitle("扫描历史对比")
        self.setMinimumSize(720, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.hist = self._load_history()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        tip = QLabel("选择基准与对比快照，查看两次扫描之间网络中设备的变化。")
        layout.addWidget(tip)

        sel_row = QHBoxLayout()
        sel_row.setSpacing(8)
        sel_row.addWidget(QLabel("基准快照:"))
        self.base_combo = QComboBox()
        self.target_combo = QComboBox()
        sel_row.addWidget(self.base_combo, 1)
        sel_row.addWidget(QLabel("对比快照:"))
        sel_row.addWidget(self.target_combo, 1)
        cmp_btn = QPushButton("对比")
        cmp_btn.setObjectName("primaryBtn")
        cmp_btn.clicked.connect(self._do_compare)
        sel_row.addWidget(cmp_btn)
        layout.addLayout(sel_row)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP 地址", "变化类型", "旧值", "新值"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #555555; font-size: 11px;")
        layout.addWidget(self.summary_label)

        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

        self.setLayout(layout)
        self._populate_combos()

    def _load_history(self):
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @staticmethod
    def _fmt_time(ts):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def _populate_combos(self):
        self.base_combo.clear()
        self.target_combo.clear()
        if not self.hist:
            self.base_combo.addItem("(无历史快照)")
            self.target_combo.addItem("(无历史快照)")
            self.base_combo.setEnabled(False)
            self.target_combo.setEnabled(False)
            return
        # 最新在末尾，倒序展示
        for idx in range(len(self.hist) - 1, -1, -1):
            snap = self.hist[idx]
            label = f"{self._fmt_time(snap['time'])}  ({len(snap['devices'])} 台)"
            self.base_combo.addItem(label, idx)
            self.target_combo.addItem(label, idx)
        # 默认：基准=上上次，对比=最近一次
        if len(self.hist) >= 2:
            self.base_combo.setCurrentIndex(1)
            self.target_combo.setCurrentIndex(0)
        elif len(self.hist) == 1:
            self.base_combo.setCurrentIndex(0)
            self.target_combo.setCurrentIndex(0)

    def _do_compare(self):
        if not self.hist:
            self.summary_label.setText("尚无历史快照，请先完成至少两次扫描。")
            return
        bi = self.base_combo.currentData()
        ti = self.target_combo.currentData()
        if bi is None or ti is None:
            return
        base = self.hist[bi]
        target = self.hist[ti]
        diffs = _compare_snapshots(base, target)
        self.table.setRowCount(len(diffs))
        for row, d in enumerate(diffs):
            self.table.setItem(row, 0, QTableWidgetItem(d["ip"]))
            self.table.setItem(row, 1, QTableWidgetItem(d["change"]))
            self.table.setItem(row, 2, QTableWidgetItem(d["old"]))
            self.table.setItem(row, 3, QTableWidgetItem(d["new"]))
        added = sum(1 for d in diffs if d["change"] == "新增设备")
        removed = sum(1 for d in diffs if d["change"] == "消失设备")
        changed = len(diffs) - added - removed
        self.summary_label.setText(
            f"共 {len(diffs)} 处变化：新增 {added} · 消失 {removed} · 其他变更 {changed}   "
            f"(基准 {self._fmt_time(base['time'])} → 对比 {self._fmt_time(target['time'])})"
        )


# ============================================================
# 网络拓扑视图 (P2-6)
# ============================================================
def _is_valid_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class TopologyDialog(QDialog):
    """以中心网关 + 辐射主机的星型拓扑展示当前扫描结果。"""

    def __init__(self, results, gateway_ip, dark, parent=None):
        super().__init__(parent)
        self.setWindowTitle("网络拓扑视图")
        self.setMinimumSize(820, 600)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.results = list(results)
        self.gateway_ip = gateway_ip
        self.dark = dark

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)

        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing, True)
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QBrush(QColor(30, 30, 30) if dark else QColor(248, 248, 248)))
        self.view.setScene(self.scene)
        layout.addWidget(self.view, 1)

        self.legend = QLabel()
        self._update_legend()
        layout.addWidget(self.legend)

        self.setLayout(layout)
        self._build_topology()

    def _update_legend(self):
        self.legend.setText(
            "<span style='color:#E69500;'>●</span> 网关   "
            "<span style='color:#22A34A;'>●</span> 在线   "
            "<span style='color:#B4B4B4;'>●</span> 离线"
        )
        self.legend.setStyleSheet("font-size: 12px; padding: 4px;")

    def _text_color(self):
        return QColor(224, 224, 224) if self.dark else QColor(40, 40, 40)

    def _build_topology(self):
        cx, cy = 0, 0
        hosts = self.results
        n = len(hosts)
        R = max(200, 50 + n * 7)
        edge_pen = QPen(QColor(150, 156, 166) if self.dark else QColor(170, 170, 170), 1)

        for i, r in enumerate(hosts):
            ang = 2 * math.pi * i / n if n else 0
            x = cx + R * math.cos(ang)
            y = cy + R * math.sin(ang)
            self.scene.addLine(cx, cy, x, y, edge_pen)
            self._add_host_node(x, y, r)

        self._add_gateway_node(cx, cy)

        if self.scene.itemsBoundingRect().isValid():
            self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))

    def _add_host_node(self, x, y, r):
        online = r.status == "online"
        color = QColor(34, 163, 74) if online else QColor(180, 180, 180)
        node = QGraphicsEllipseItem(x - 14, y - 14, 28, 28)
        node.setBrush(QBrush(color))
        node.setPen(QPen(QColor(0, 0, 0, 60), 1))
        self.scene.addItem(node)
        label = r.ip + (("\n" + r.hostname) if r.hostname else "")
        txt = QGraphicsTextItem(label)
        txt.setDefaultTextColor(self._text_color())
        txt.setPos(x - 55, y + 16)
        self.scene.addItem(txt)

    def _add_gateway_node(self, x, y):
        # 若网关 IP 命中扫描结果，展示其主机名 / MAC
        sub = self.gateway_ip or "未知"
        for r in self.results:
            if r.ip == self.gateway_ip:
                if r.hostname:
                    sub = f"{self.gateway_ip}\n{r.hostname}"
                break
        color = QColor(230, 149, 0)
        node = QGraphicsEllipseItem(x - 24, y - 24, 48, 48)
        node.setBrush(QBrush(color))
        node.setPen(QPen(QColor(0, 0, 0, 80), 2))
        self.scene.addItem(node)
        txt = QGraphicsTextItem("网关\n" + sub)
        txt.setDefaultTextColor(self._text_color())
        txt.setPos(x - 45, y + 28)
        self.scene.addItem(txt)


# ============================================================
# 入口
# ============================================================
class SafeApp(QApplication):
    """捕获所有事件/槽/绘制中的未处理异常，避免 PyQt5 直接 abort 导致闪退。"""

    _last_popup = 0.0

    def notify(self, receiver, event):
        try:
            return super().notify(receiver, event)
        except Exception:
            import traceback as _tb
            err = _tb.format_exc()
            try:
                _ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                _log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash.log")
                with open(_log, "a", encoding="utf-8") as _f:
                    _f.write(f"[{_ts}] 未捕获异常:\n{err}\n{'=' * 60}\n")
            except Exception:
                pass
            # 节流弹窗，避免高频绘制异常刷屏 (3 秒内同种不再弹)
            _now = datetime.now().timestamp()
            if _now - SafeApp._last_popup > 3:
                SafeApp._last_popup = _now
                try:
                    QMessageBox.critical(
                        None, "运行时错误（已捕获，未崩溃）",
                        "程序捕获到一个错误，已写入 crash.log：\n\n" + err[-1500:]
                    )
                except Exception:
                    pass
            return False


def main():
    # 高 DPI 必须在 QApplication 实例创建之前设置，否则 Qt 会打印警告
    # 并在某些 Windows 环境导致事件循环里 access violation 闪退。
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = SafeApp(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    app.setFont(QFont("Microsoft YaHei", 9))

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
