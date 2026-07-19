# -*- coding: utf-8 -*-
"""
局域网终端扫描工具 — GUI 主程序
基于 PyQt5，参考 Advanced IP Scanner / Angry IP Scanner 等工具的布局
"""

import sys
import os
import platform

# 禁用 Qt 的 DirectWrite 字体引擎，回退到 GDI (TextOut) 文本渲染。
# 关键修复：Qt 在委托 paint() 中用 DirectWrite 渲染文本时，会在 WM_PAINT 消息处理
# 上下文中触发同步 COM 调用 (0x8001010d: 在输入同步调用期间无法发起 COM 调用)，
# 直接导致进程崩溃 ("扫描闪退")。GDI 文本渲染不依赖 COM，可彻底规避该问题。
# 必须在 import PyQt5 之前设置才生效。
os.environ.setdefault("QT_NO_DIRECTWRITE", "1")

# 强制使用 Fusion 样式（纯 Qt 自绘，不调用 Windows 原生主题 API uxtheme / Direct2D）。
# 双保险：即使文本后端已回退 GDI，默认的 QWindowsVistaStyle 在绘制选中态/项背景时
# 仍会走原生主题 API，同样在 WM_PAINT 期间触发同步 COM 调用 (0x8001010d) 导致崩溃。
# Fusion 完全用 Qt raster 引擎绘制，不触达任何 Windows 原生 COM 路径，从根上规避。
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
    QStyledItemDelegate, QStyle, QTextEdit, QFrame, QToolButton, QSizePolicy,
    QDialog, QFormLayout, QDialogButtonBox
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QSize, QTimer, QRect, QUrl, QProcess
)
from PyQt5.QtGui import (
    QColor, QFont, QIcon, QPainter, QBrush, QPen, QPixmap, QPalette,
    QCursor, QFontMetrics, QDesktopServices
)

from scanner import NetworkScanner, ScanResult, parse_ip_range, COMMON_PORTS, PORT_NAMES, PROTOCOL_PORTS

_PAINT_TRACE_ENABLED = os.environ.get("IPSCANNER_PAINT_TRACE", "0") == "1"
_PAINT_TRACE_F = None

if _PAINT_TRACE_ENABLED:
    _PAINT_TRACE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "paint_trace.log")
    def _ptruncate():
        global _PAINT_TRACE_F
        try:
            _PAINT_TRACE_F = open(_PAINT_TRACE_PATH, "w", encoding="utf-8", buffering=1)
        except Exception:
            _PAINT_TRACE_F = None
    def _ptrace(op: str):
        if _PAINT_TRACE_F is not None:
            try:
                _PAINT_TRACE_F.write(op + "\n")
                _PAINT_TRACE_F.flush()
            except Exception:
                pass
else:
    def _ptruncate():
        pass
    def _ptrace(op: str):
        pass

from excel_handler import export_results, create_template, normalize_mac
from mac_library import MacLibrary


# ============================================================
# 样式表
# ============================================================
STYLE_SHEET = """
QMainWindow {
    background-color: #F1F5F9;
}
QGroupBox {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    font-weight: bold;
    color: #334155;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 18px;
    background-color: #FFFFFF;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QPushButton {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    padding: 6px 16px;
    border-radius: 5px;
    border: none;
    background-color: #E2E8F0;
    color: #334155;
}
QPushButton:hover {
    background-color: #CBD5E1;
}
QPushButton:pressed {
    background-color: #94A3B8;
}
QPushButton#primaryBtn {
    background-color: #2563EB;
    color: white;
    font-weight: bold;
}
QPushButton#primaryBtn:hover {
    background-color: #1D4ED8;
}
QPushButton#primaryBtn:pressed {
    background-color: #1E40AF;
}
QPushButton#primaryBtn:disabled {
    background-color: #93C5FD;
}
QPushButton#dangerBtn {
    background-color: #FEE2E2;
    color: #DC2626;
}
QPushButton#dangerBtn:hover {
    background-color: #FECACA;
}
QPushButton#successBtn {
    background-color: #DCFCE7;
    color: #16A34A;
}
QPushButton#successBtn:hover {
    background-color: #BBF7D0;
}
QLineEdit {
    font-family: "Consolas", "Microsoft YaHei";
    font-size: 13px;
    padding: 5px 8px;
    border: 1px solid #CBD5E1;
    border-radius: 4px;
    background-color: #FFFFFF;
    selection-background-color: #2563EB;
}
QLineEdit:focus {
    border: 2px solid #2563EB;
    padding: 4px 7px;
}
QComboBox {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    padding: 4px 8px;
    border: 1px solid #CBD5E1;
    border-radius: 4px;
    background-color: #FFFFFF;
}
QSpinBox {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    padding: 4px 8px;
    border: 1px solid #CBD5E1;
    border-radius: 4px;
    background-color: #FFFFFF;
}
QCheckBox {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    color: #475569;
}
QLabel {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    color: #475569;
}
QTreeWidget {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    gridline-color: #F1F5F9;
    background-color: #FFFFFF;
    alternate-background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    selection-background-color: #DBEAFE;
    selection-color: #1E40AF;
    padding-top: 4px;
    padding-bottom: 4px;
    outline: 0;
}
QTreeWidget::item {
    padding: 6px 8px;
    border: none;
    min-height: 32px;
}
QTreeWidget::item:hover {
    background-color: #EFF6FF;
}
QTreeWidget::item:selected {
    background-color: #DBEAFE;
    color: #1E40AF;
}
QTreeWidget::branch {
    width: 20px;
}
QHeaderView::section {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    font-weight: bold;
    color: #000000;
    background-color: #F1F5F9;
    border: none;
    border-right: 1px solid #E2E8F0;
    border-bottom: 1px solid #E2E8F0;
    padding: 6px 8px;
}
QHeaderView::section:hover {
    background-color: #E2E8F0;
}
QProgressBar {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 12px;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    background-color: #F1F5F9;
    text-align: center;
    color: #475569;
    height: 22px;
}
QProgressBar::chunk {
    background-color: #2563EB;
    border-radius: 3px;
}
QStatusBar {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 12px;
    color: #64748B;
    background-color: #F1F5F9;
}
QListWidget {
    font-family: "Consolas", "Microsoft YaHei";
    font-size: 13px;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    background-color: #FFFFFF;
    padding: 2px;
}
QListWidget::item {
    padding: 3px 6px;
    border-radius: 3px;
}
QListWidget::item:hover {
    background-color: #F1F5F9;
}
QMenu {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    background-color: #FFFFFF;
    padding: 4px;
}
QMenu::item {
    padding: 6px 24px;
    border-radius: 3px;
}
QMenu::item:selected {
    background-color: #DBEAFE;
    color: #1E40AF;
}
QScrollBar:vertical {
    border: none;
    background: #F1F5F9;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #CBD5E1;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #94A3B8;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    border: none;
    background: #F1F5F9;
    height: 10px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background: #CBD5E1;
    border-radius: 5px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover {
    background: #94A3B8;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""


# ============================================================
# 扫描线程
# ============================================================
class ScanThread(QThread):
    progress = pyqtSignal(int, int, str)   # current, total, current_ip
    result_ready = pyqtSignal(object)       # ScanResult
    finished_signal = pyqtSignal(list)      # all results
    log_signal = pyqtSignal(str)            # log message

    def __init__(self, ip_ranges, timeout_ms=1000, max_threads=100, scan_ports=False,
                 protocols=None):
        super().__init__()
        self.ip_ranges = ip_ranges
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports = scan_ports
        self.protocols = protocols or []
        self.scanner = NetworkScanner()

    def run(self):
        import sys as _sys
        print("[DBG] ScanThread.run begin", file=_sys.stderr, flush=True)
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
            progress_callback=on_progress,
            result_callback=on_result,
        )

        online = sum(1 for r in results if r.status == "online")
        self.log_signal.emit(f"扫描完成: 共 {len(results)} 个IP, {online} 个在线")
        self.finished_signal.emit(results)

    def stop(self):
        self.scanner.stop()


# ============================================================
# 状态指示器委托 (绘制圆点)
# ============================================================
class StatusDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option, index):
        _ptruncate()
        _ptrace("Status.paint begin")
        painter.save()
        try:
            # 背景
            if option.state & QStyle.State_Selected:
                _ptrace("Status fillRect selected")
                painter.fillRect(option.rect, QColor(219, 234, 254))
            elif option.state & QStyle.State_MouseOver:
                _ptrace("Status fillRect hover")
                painter.fillRect(option.rect, QColor(241, 245, 249))

            status = index.data(Qt.UserRole)
            # 如果不是设备行（没有 online/offline 状态），走默认绘制（显示图标等）
            if status not in ("online", "offline"):
                painter.restore()
                super().paint(painter, option, index)
                return

            # 画电脑小图标 (在线=绿色, 离线=灰色)
            rect = option.rect
            cx = rect.center().x()
            cy = rect.center().y()
            w, h = 22, 17
            x0 = int(cx - w / 2)
            y0 = int(cy - h / 2 - 2)

            if status == "online":
                screen = QColor(220, 252, 231)
                edge = QColor(22, 163, 74)
                base = QColor(22, 163, 74)
            else:
                screen = QColor(241, 245, 249)
                edge = QColor(148, 163, 184)
                base = QColor(148, 163, 184)

            # 显示器屏幕
            _ptrace("Status setPen edge")
            painter.setPen(QPen(edge, 1.5))
            _ptrace("Status setBrush screen")
            painter.setBrush(QBrush(screen))
            _ptrace("Status drawRect monitor")
            painter.drawRect(x0, y0, w, h)
            if status == "online":
                _ptrace("Status drawLine")
                painter.setPen(QPen(QColor(134, 239, 172), 1))
                painter.drawLine(x0 + 3, y0 + 4, x0 + w - 3, y0 + 4)
                painter.drawLine(x0 + 3, y0 + 8, x0 + w - 6, y0 + 8)

            # 底座支架 + 底座
            _ptrace("Status drawRect base")
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(base))
            painter.drawRect(cx - 2, y0 + h, 4, 3)
            painter.drawRect(cx - 7, y0 + h + 3, 14, 3)
        except Exception:
            import traceback
            traceback.print_exc()
        finally:
            painter.restore()


# ============================================================
# 服务列：可点击协议资源链接 (Advanced IP Scanner 风格)
# ============================================================
PROTO_ICON_COLORS = {
    "HTTP": QColor(37, 99, 235),
    "HTTPS": QColor(37, 99, 235),
    "FTP": QColor(234, 88, 12),
    "RDP": QColor(124, 58, 237),
}
PROTO_LABELS = {
    "HTTP": "Http",
    "HTTPS": "Https",
    "FTP": "Ftp",
    "RDP": "远程桌面",
}

# 预创建字体对象：绝不可在委托 paint 内现构造 QFont / QFontMetrics，
# 否则会在 WM_PAINT 消息处理期间触发 Windows DirectWrite 的同步 COM 调用
# (0x8001010D：在输入同步调用期间无法发起 COM 调用) 而直接崩溃进程。
# 模块级构造发生在程序启动早期，不在任何 WM_PAINT 上下文中，安全。
_DELEGATE_FONT = QFont("Microsoft YaHei", 9)
_DELEGATE_FM = QFontMetrics(_DELEGATE_FONT)

# 单元格字体也预创建，避免扫描大量 IP 时反复构造 QFont 对象
_FONT_CONSOLAS_10 = QFont("Consolas", 10)
_FONT_CONSOLAS_9 = QFont("Consolas", 9)
_FONT_YAHEI_BOLD_9 = QFont("Microsoft YaHei", 9, QFont.Bold)


def compute_service_layout(rect: QRect, services: list) -> list:
    """计算服务列内各协议链接的矩形区域 (图标 + 文字)，供绘制与点击命中判断共用。"""
    result = []
    x = rect.x() + 6
    y = rect.y()
    h = rect.height()
    fm = _DELEGATE_FM
    for proto in services:
        _ptrace("compute width " + str(proto))
        label = PROTO_LABELS.get(proto, proto)
        tw = fm.width(label)
        total_w = 16 + 4 + tw + 10   # 图标 + 间距 + 文字 + 右间隙
        item_rect = QRect(x, y, total_w, h)
        icon_rect = QRect(x, y + (h - 14) // 2, 14, 14)
        result.append((proto, item_rect, icon_rect))
        x += total_w
    return result


class ServiceDelegate(QStyledItemDelegate):
    """服务列委托：绘制带小图标的蓝色可点击资源链接。"""

    def paint(self, painter: QPainter, option, index):
        _ptruncate()
        _ptrace("Service.paint begin")
        painter.save()
        try:
            if option.state & QStyle.State_Selected:
                _ptrace("Service fillRect selected")
                painter.fillRect(option.rect, QColor(219, 234, 254))
            elif option.state & QStyle.State_MouseOver:
                _ptrace("Service fillRect hover")
                painter.fillRect(option.rect, QColor(241, 245, 249))

            services = index.data(Qt.UserRole) or []
            if not services:
                _ptrace("Service drawText dash")
                painter.setPen(QColor(148, 163, 184))
                painter.setFont(_DELEGATE_FONT)
                painter.drawText(option.rect.adjusted(6, 0, 0, 0),
                                 Qt.AlignLeft | Qt.AlignVCenter, "—")
                return

            for proto, item_rect, icon_rect in compute_service_layout(option.rect, services):
                color = PROTO_ICON_COLORS.get(proto, QColor(37, 99, 235))
                _ptrace("Service draw_icon " + str(proto))
                self._draw_icon(painter, proto, icon_rect, color)
                _ptrace("Service drawText label " + str(proto))
                painter.setPen(color)
                painter.setFont(_DELEGATE_FONT)
                painter.drawText(item_rect.adjusted(20, 0, 0, 0),
                                 Qt.AlignLeft | Qt.AlignVCenter,
                                 PROTO_LABELS.get(proto, proto))
        except Exception:
            import traceback
            traceback.print_exc()
        finally:
            painter.restore()

    def _draw_icon(self, painter, proto, rect, color):
        # 不开启抗锯齿：Qt 抗锯齿在部分环境下走 GDI+，其初始化依赖 COM，
        # 在 WM_PAINT 委托绘制期间同样可能触发 0x8001010d 崩溃。
        if proto in ("HTTP", "HTTPS"):
            _ptrace("  draw_icon HTTP ellipse1")
            cx, cy, r = rect.center().x(), rect.center().y(), 6
            painter.setPen(QPen(color, 1.3))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(cx - r, cy - r, r * 2, r * 2)
            _ptrace("  draw_icon HTTP line")
            painter.drawLine(cx - r, cy, cx + r, cy)
            _ptrace("  draw_icon HTTP ellipse2")
            painter.drawEllipse(cx - r, cy - 3, r * 2, 6)
        elif proto == "FTP":
            _ptrace("  draw_icon FTP")
            painter.setPen(QPen(color, 1.2))
            painter.setBrush(QBrush(color))
            painter.drawEllipse(rect.x() + 1, rect.y() + 1, 12, 4)
            painter.drawRect(rect.x() + 1, rect.y() + 3, 12, 9)
            painter.setBrush(QBrush(QColor(255, 255, 255)))
            painter.drawEllipse(rect.x() + 1, rect.y() + 9, 12, 4)
        elif proto == "RDP":
            _ptrace("  draw_icon RDP")
            painter.setPen(QPen(color, 1.3))
            painter.setBrush(QBrush(color))
            painter.drawRect(rect.x() + 1, rect.y() + 2, 12, 9)
            painter.setBrush(QBrush(QColor(255, 255, 255)))
            painter.drawRect(rect.x() + 3, rect.y() + 4, 8, 4)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawRect(rect.x() + 5, rect.y() + 11, 4, 2)
            painter.drawRect(rect.x() + 3, rect.y() + 13, 8, 1)


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
        self.scan_thread = None
        self.all_results: list = []
        self.ip_range_items: list = []
        self._ip_item_map: dict = {}

        self._init_ui()
        self._init_menu()
        self._connect_signals()

        # 自动检测本机网段
        self._auto_detect_subnet()
        # 载入地址库计数
        self._refresh_library_label()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # --- 顶部: 扫描配置 ---
        config_group = QGroupBox("扫描配置")
        config_layout = QGridLayout(config_group)
        config_layout.setSpacing(8)
        config_layout.setContentsMargins(12, 22, 12, 12)

        # IP 范围输入
        lbl_range = QLabel("IP 范围:")
        lbl_range.setFixedWidth(70)
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("输入 IP 范围，如 192.168.1.0/24 或 192.168.1.1-254，回车添加")
        self.range_input.returnPressed.connect(self._add_ip_range)

        self.add_range_btn = QPushButton("+ 添加")
        self.add_range_btn.setFixedWidth(70)

        self.range_list_label = QLabel("已添加网段:")
        self.range_list_label.setFixedWidth(70)

        self.range_list = QTextEdit()
        self.range_list.setReadOnly(True)
        self.range_list.setMaximumHeight(60)
        self.range_list.setStyleSheet("""
            QTextEdit {
                font-family: "Consolas", "Microsoft YaHei";
                font-size: 12px;
                border: 1px solid #E2E8F0;
                border-radius: 4px;
                background-color: #F8FAFC;
                padding: 4px;
            }
        """)

        self.clear_range_btn = QPushButton("清空网段")
        self.clear_range_btn.setFixedWidth(80)
        self.clear_range_btn.setObjectName("dangerBtn")

        config_layout.addWidget(lbl_range, 0, 0)
        config_layout.addWidget(self.range_input, 0, 1)
        config_layout.addWidget(self.add_range_btn, 0, 2)
        config_layout.addWidget(self.range_list_label, 1, 0)
        config_layout.addWidget(self.range_list, 1, 1)
        config_layout.addWidget(self.clear_range_btn, 1, 2)

        # 扫描参数
        params_layout = QHBoxLayout()
        params_layout.setSpacing(12)

        params_layout.addWidget(QLabel("超时(ms):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 5000)
        self.timeout_spin.setValue(1000)
        self.timeout_spin.setSingleStep(100)
        self.timeout_spin.setFixedWidth(80)

        params_layout.addWidget(QLabel("并发线程:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(100)
        self.threads_spin.setSingleStep(10)
        self.threads_spin.setFixedWidth(80)

        self.port_scan_check = QCheckBox("扫描端口")
        self.port_scan_check.setToolTip("对在线设备扫描常见端口")

        self.protocol_btn = QPushButton("资源...")
        self.protocol_btn.setToolTip("选择要扫描的应用层协议 (HTTP / HTTPS / FTP / RDP)")
        self.protocol_btn.setFixedWidth(60)
        self.protocol_btn.clicked.connect(self._open_protocol_options)

        params_layout.addWidget(self.timeout_spin)
        params_layout.addSpacing(8)
        params_layout.addWidget(QLabel("并发线程:"))
        params_layout.addWidget(self.threads_spin)
        params_layout.addSpacing(8)
        params_layout.addWidget(self.port_scan_check)
        params_layout.addWidget(self.protocol_btn)

        params_layout.addStretch()

        # Excel
        self.excel_btn = QPushButton("导入 Excel")
        self.excel_btn.setFixedWidth(100)
        self.excel_label = QLabel("未加载设备信息")
        self.excel_label.setStyleSheet("color: #94A3B8; font-size: 12px;")

        params_layout.addWidget(self.excel_btn)
        params_layout.addWidget(self.excel_label)

        params_layout.addSpacing(8)

        # 按钮
        self.scan_btn = QPushButton("▶ 开始扫描")
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.setFixedWidth(110)

        self.stop_btn = QPushButton("■ 停止")
        self.stop_btn.setObjectName("dangerBtn")
        self.stop_btn.setFixedWidth(80)
        self.stop_btn.setEnabled(False)

        self.export_btn = QPushButton("导出结果")
        self.export_btn.setFixedWidth(90)
        self.export_btn.setEnabled(False)

        self.clear_btn = QPushButton("清空结果")
        self.clear_btn.setFixedWidth(90)
        self.clear_btn.setEnabled(False)

        params_layout.addWidget(self.scan_btn)
        params_layout.addWidget(self.stop_btn)
        params_layout.addWidget(self.export_btn)
        params_layout.addWidget(self.clear_btn)

        config_layout.addLayout(params_layout, 2, 0, 1, 3)

        main_layout.addWidget(config_group)

        # --- 中部: 搜索 + 筛选 ---
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索 IP / 主机名 / MAC / 使用者...")
        self.search_input.setFixedHeight(32)
        self.search_input.setMaximumWidth(320)
        self.search_input.textChanged.connect(self._filter_results)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["全部", "仅在线", "仅离线", "Excel已匹配", "有服务"])
        # 默认“仅在线”：扫描结果只显示在线终端，离线终端不显示（可切回“全部”查看）
        self.filter_combo.setCurrentText("仅在线")
        self.filter_combo.setFixedHeight(32)
        self.filter_combo.setFixedWidth(120)
        self.filter_combo.currentIndexChanged.connect(self._filter_results)

        filter_layout.addWidget(QLabel("搜索:"))
        filter_layout.addWidget(self.search_input)
        filter_layout.addSpacing(8)
        filter_layout.addWidget(QLabel("筛选:"))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addStretch()

        self.stats_label = QLabel("总计: 0 | 在线: 0 | 离线: 0")
        self.stats_label.setStyleSheet("font-size: 13px; color: #64748B; font-weight: bold;")

        filter_layout.addWidget(self.stats_label)

        main_layout.addLayout(filter_layout)

        # --- 结果表格 (QTreeWidget，支持展开/收起服务) ---
        self.table = QTreeWidget()
        self.table.setColumnCount(12)
        self.table.setHeaderLabels([
            "序号", "状态", "IP地址", "主机名", "MAC地址",
            "制造商", "位置", "使用者", "响应时间(ms)", "开放端口", "服务", "备注"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.setRootIsDecorated(True)
        self.table.setItemsExpandable(True)
        self.table.setAllColumnsShowFocus(True)

        # 隐藏服务列（服务通过展开子项显示，仿 Advanced IP Scanner）
        self.table.hideColumn(10)

        # 列宽设置
        header = self.table.header()
        header.setStretchLastSection(False)
        _widths = {0: 50, 1: 60, 2: 130, 3: 150, 4: 210, 5: 100, 6: 140, 7: 100, 8: 100, 9: 180, 10: 230, 11: 200}
        for _col, _w in _widths.items():
            header.setSectionResizeMode(_col, QHeaderView.Interactive)
            header.resizeSection(_col, _w)

        # 状态列委托 (小电脑图标)
        self.table.setItemDelegateForColumn(1, StatusDelegate())
        self.table.itemClicked.connect(self._on_item_clicked)

        main_layout.addWidget(self.table, 1)

        # --- 进度条 ---
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(22)
        main_layout.addWidget(self.progress_bar)

        # --- 状态栏 ---
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        self.status_label = QLabel("就绪")
        self.status_bar.addPermanentWidget(self.status_label)

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

        act_export = QAction("导出扫描结果", self)
        act_export.triggered.connect(self._export_results)
        file_menu.addAction(act_export)

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

        act_clear = QAction("清空结果", self)
        act_clear.triggered.connect(self._clear_results)
        scan_menu.addAction(act_clear)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")
        act_about = QAction("关于", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _connect_signals(self):
        self.add_range_btn.clicked.connect(self._add_ip_range)
        self.clear_range_btn.clicked.connect(self._clear_ranges)
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.export_btn.clicked.connect(self._export_results)
        self.clear_btn.clicked.connect(self._clear_results)
        self.excel_btn.clicked.connect(self._import_excel)
        self.table.customContextMenuRequested.connect(self._show_context_menu)

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

    def _add_ip_range(self):
        text = self.range_input.text().strip()
        if not text:
            return

        # 验证
        ips = parse_ip_range(text)
        if not ips:
            QMessageBox.warning(self, "格式错误", f"无法解析 IP 范围: {text}\n\n支持格式:\n  192.168.1.0/24\n  192.168.1.1-254\n  192.168.1.1")
            return

        if text not in self.ip_range_items:
            self.ip_range_items.append(text)
            self._update_range_list()
            self.range_input.clear()
            self.range_input.setFocus()
        else:
            QMessageBox.information(self, "提示", "该网段已添加")

    def _clear_ranges(self):
        self.ip_range_items.clear()
        self._update_range_list()

    def _update_range_list(self):
        if self.ip_range_items:
            total_ips = sum(len(parse_ip_range(r)) for r in self.ip_range_items)
            display = "\n".join(self.ip_range_items)
            display += f"\n— 共 {len(self.ip_range_items)} 个网段, {total_ips} 个IP"
            self.range_list.setPlainText(display)
        else:
            self.range_list.clear()

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
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
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
        )
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

    def _open_protocol_options(self):
        """打开协议扫描选项对话框"""
        dlg = ProtocolOptionsDialog(self.selected_protocols, self)
        if dlg.exec_() == QDialog.Accepted:
            self.selected_protocols = dlg.selected_protocols()
            self.status_bar.showMessage(
                f"已选择协议: {', '.join(self.selected_protocols) if self.selected_protocols else '无'}"
            )

    def _on_scan_progress(self, current, total, ip):
        pct = int(current / total * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status_bar.showMessage(f"扫描中 [{current}/{total}] {ip} ...")

    def _on_scan_result(self, result: ScanResult):
        import sys as _sys
        print(f"[DBG] on_scan_result ip={result.ip} status={result.status}", file=_sys.stderr, flush=True)
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
        import sys as _sys
        try:
            print(f"[DBG] _on_scan_finished: 共 {len(results)} 个结果", file=_sys.stderr, flush=True)
            self.all_results = results
            
            # 先关闭排序，避免批量添加时的性能问题
            self.table.setSortingEnabled(False)
            
            # 找出所有还没有添加到表格的设备（主要是离线设备）
            existing_ips = set(self._ip_item_map.keys())
            print(f"[DBG] 已存在的IP数: {len(existing_ips)}", file=_sys.stderr, flush=True)
            
            items_to_add = []
            map_updates = []
            for result in results:
                if result.ip not in existing_ips:
                    item = QTreeWidgetItem()
                    self._set_item_data(item, result, 0)
                    self._add_service_children(item, result)
                    items_to_add.append(item)
                    map_updates.append((result.ip, item))
            
            print(f"[DBG] 待添加的新项数: {len(items_to_add)}", file=_sys.stderr, flush=True)
            
            if items_to_add:
                self.table.addTopLevelItems(items_to_add)
                for ip, item in map_updates:
                    self._ip_item_map[ip] = item
            
            # 应用筛选（默认“仅在线”：扫描完成后隐藏离线终端）
            self._filter_results()

            # 更新序号（仅对可见项连续编号，隐藏的离线项不计）
            n = 0
            for i in range(self.table.topLevelItemCount()):
                item = self.table.topLevelItem(i)
                if not item.isHidden():
                    n += 1
                    item.setData(0, Qt.DisplayRole, n)

            # 恢复排序
            self.table.setSortingEnabled(True)
            
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.export_btn.setEnabled(True)
            self.clear_btn.setEnabled(True)
            self.progress_bar.setVisible(False)
            self._update_stats()
            self.status_bar.showMessage("扫描完成")
            print(f"[DBG] _on_scan_finished 完成, 表格项数: {self.table.topLevelItemCount()}", file=_sys.stderr, flush=True)
        except Exception as e:
            print(f"[ERR] _on_scan_finished 异常: {e}", file=_sys.stderr, flush=True)
            import traceback
            traceback.print_exc()
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.export_btn.setEnabled(True)
            self.clear_btn.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage(f"扫描异常: {e}")

    # --- 表格操作 ---

    def _upsert_table_row(self, result: ScanResult):
        """新增或更新指定 IP 的项，避免同一 IP 重复显示"""
        if result.ip in self._ip_item_map:
            item = self._ip_item_map[result.ip]
            self._update_item_data(item, result)
        else:
            item = self._add_top_level_item(result)
            self._ip_item_map[result.ip] = item
        # 增量应用筛选：离线终端边扫边隐藏（默认“仅在线”）
        item.setHidden(not self._item_matches_filter(item))

    def _add_top_level_item(self, result: ScanResult):
        item = QTreeWidgetItem()
        self.table.addTopLevelItem(item)
        self._set_item_data(item, result, self.table.topLevelItemCount())
        self._add_service_children(item, result)
        return item

    def _update_item_data(self, item: QTreeWidgetItem, result: ScanResult):
        idx = self.table.indexOfTopLevelItem(item)
        self._set_item_data(item, result, idx + 1 if idx >= 0 else 0)
        self._add_service_children(item, result)

    def _add_service_children(self, item: QTreeWidgetItem, result: ScanResult):
        """为设备项添加服务子项（展开三角后可见），仿 Advanced IP Scanner 风格"""
        item.takeChildren()
        svc = result.services or []
        if not svc:
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            return
        item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        for proto in svc:
            child = QTreeWidgetItem()
            child.setData(0, Qt.UserRole, "service")
            child.setData(0, Qt.UserRole + 1, proto)
            child.setData(0, Qt.UserRole + 2, result.ip)

            icon = self._service_icon(proto)
            if icon:
                child.setIcon(1, icon)

            proto_upper = proto.upper()
            child.setText(3, proto_upper)
            child.setForeground(3, QColor(37, 99, 235))

            desc = self._service_desc(proto, result.ip)
            if desc:
                child.setText(4, desc)
                child.setForeground(4, QColor(100, 116, 139))

            item.addChild(child)

    def _service_icon(self, proto: str):
        proto_upper = proto.upper()
        if proto_upper in ("HTTP", "HTTPS"):
            return self._globe_icon()
        icon_map = {
            "FTP": QStyle.SP_DirIcon,
            "RDP": QStyle.SP_ComputerIcon,
            "SSH": QStyle.SP_CommandLink,
            "TELNET": QStyle.SP_CommandLink,
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

    def _set_item_data(self, item: QTreeWidgetItem, result: ScanResult, idx: int):
        """设置/更新指定项的所有列内容"""
        import sys as _sys
        print(f"[DBG] set_item_data idx={idx} ip={result.ip}", file=_sys.stderr, flush=True)

        item.setData(0, Qt.DisplayRole, idx if idx > 0 else "")
        item.setTextAlignment(0, Qt.AlignCenter)

        item.setData(1, Qt.UserRole, result.status)
        item.setData(1, Qt.DisplayRole, "在线" if result.status == "online" else "离线")
        item.setTextAlignment(1, Qt.AlignCenter)
        if result.status == "online":
            item.setForeground(1, QColor(22, 163, 74))
        else:
            item.setForeground(1, QColor(220, 38, 38))

        item.setText(2, result.ip)
        item.setFont(2, _FONT_CONSOLAS_10)

        item.setText(3, result.hostname or "—")

        mac_text = result.mac.upper() if result.mac else "—"
        item.setText(4, mac_text)
        item.setFont(4, _FONT_CONSOLAS_10)

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
        item.setText(5, manufacturer_text)
        if result.excel_matched and result.device_type:
            item.setForeground(5, QColor(37, 99, 235))
            item.setFont(5, _FONT_YAHEI_BOLD_9)

        item.setText(6, result.location or "—")

        item.setText(7, result.user or "—")

        if result.response_time > 0:
            item.setData(8, Qt.DisplayRole, round(result.response_time, 1))
            item.setTextAlignment(8, Qt.AlignCenter)
        else:
            item.setText(8, "—")
            item.setTextAlignment(8, Qt.AlignCenter)

        if result.open_ports:
            port_strs = []
            for p in result.open_ports:
                name = PORT_NAMES.get(p, "")
                port_strs.append(f"{p}({name})" if name else str(p))
            ports_text = ", ".join(port_strs)
        else:
            ports_text = "—"
        item.setText(9, ports_text)
        item.setFont(9, _FONT_CONSOLAS_9)

        svc = result.services or []
        services_text = ", ".join(svc) if svc else "—"
        item.setText(10, services_text)
        item.setData(10, Qt.UserRole, list(svc))

        item.setText(11, result.remark or "—")

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
            type_text = item.text(5)
            show = show and (type_text != "—")
        elif filter_type == "有服务":
            services_text = item.text(10)
            show = show and (services_text != "—")

        if show and search_text:
            row_text = ""
            for col in [2, 3, 4, 5, 6, 7, 9, 10, 11]:
                row_text += item.text(col).lower() + " "
            show = search_text in row_text

        return show

    def _filter_results(self):
        """根据搜索和筛选条件显示/隐藏顶层项（默认“仅在线”：扫描时只显示在线终端）"""
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
                self._open_service(proto, ip)

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
        offline = total - online
        matched = sum(1 for r in self.all_results if r.excel_matched)
        self.stats_label.setText(
            f"总计: {total} | 在线: {online} | 离线: {offline}"
            + (f" | 已匹配: {matched}" if self.library.is_loaded() else "")
        )

    def _clear_results(self):
        self.table.clear()
        self._ip_item_map.clear()
        self.all_results.clear()
        self._update_stats()
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.status_bar.showMessage("已清空结果")

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

        menu = QMenu(self)

        act_copy_ip = QAction("复制 IP", self)
        act_copy_ip.triggered.connect(lambda: self._copy_item_cell(top_item, 2))
        menu.addAction(act_copy_ip)

        act_copy_mac = QAction("复制 MAC", self)
        act_copy_mac.triggered.connect(lambda: self._copy_item_cell(top_item, 4))
        menu.addAction(act_copy_mac)

        act_copy_host = QAction("复制主机名", self)
        act_copy_host.triggered.connect(lambda: self._copy_item_cell(top_item, 3))
        menu.addAction(act_copy_host)

        menu.addSeparator()

        act_copy_row = QAction("复制整行", self)
        act_copy_row.triggered.connect(lambda: self._copy_item_row(top_item))
        menu.addAction(act_copy_row)

        menu.addSeparator()

        act_rescan = QAction("重新扫描此 IP", self)
        act_rescan.triggered.connect(lambda: self._rescan_single_item(top_item))
        menu.addAction(act_rescan)

        menu.addSeparator()

        ip = self._item_text(top_item, 2)
        mac = self._item_text(top_item, 4)
        lib_dev = self.library.match(ip, mac)

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
        ip = item.text(2)
        if not ip:
            return
        self.range_input.setText(ip)
        self.ip_range_items = [ip]
        self._update_range_list()
        self._start_scan()

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
            self.excel_label.setText(f"地址库: {n} 条设备")
            self.excel_label.setStyleSheet("color: #16A34A; font-size: 12px; font-weight: bold;")
        else:
            self.excel_label.setText("地址库: 空（点\"导入\"或\"管理\"）")
            self.excel_label.setStyleSheet("color: #94A3B8; font-size: 12px;")

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
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出扫描结果", default_name,
            "Excel 文件 (*.xlsx)"
        )
        if not file_path:
            return

        success, msg = export_results(self.all_results, file_path)
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
            "<li>ICMP Ping + ARP + 主机名 + 端口探测</li>"
            "<li>Excel 设备信息导入与自动匹配</li>"
            "<li>结果导出为 Excel</li>"
            "</ul>"
            "<p style='color: #94A3B8;'>基于 PyQt5 开发</p>"
        ))

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(3000)
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
# 协议扫描选项对话框 (HTTP / HTTPS / FTP / RDP)
# ============================================================
class ProtocolOptionsDialog(QDialog):
    """选择要扫描的应用层协议"""

    def __init__(self, selected_protocols: List[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("扫描资源 / 协议")
        self.setMinimumWidth(280)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        info = QLabel("勾选扫描时要检测的应用层协议：")
        layout.addWidget(info)

        self.checks: Dict[str, QCheckBox] = {}
        for name, port in PROTOCOL_PORTS.items():
            cb = QCheckBox(f"{name}  (端口 {port})")
            cb.setChecked(name in selected_protocols)
            self.checks[name] = cb
            layout.addWidget(cb)

        layout.addSpacing(10)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def selected_protocols(self) -> List[str]:
        return [name for name, cb in self.checks.items() if cb.isChecked()]


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
