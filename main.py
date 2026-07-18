# -*- coding: utf-8 -*-
"""
局域网终端扫描工具 — GUI 主程序
基于 PyQt5，参考 Advanced IP Scanner / Angry IP Scanner 等工具的布局
"""

import sys
import os
import platform
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QStatusBar, QFileDialog, QMessageBox, QCheckBox, QSpinBox,
    QComboBox, QGroupBox, QMenu, QAction, QAbstractItemView, QSplitter,
    QStyledItemDelegate, QStyle, QTextEdit, QFrame, QToolButton, QSizePolicy,
    QDialog, QFormLayout, QDialogButtonBox
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QSize, QTimer, QRect
)
from PyQt5.QtGui import (
    QColor, QFont, QIcon, QPainter, QBrush, QPen, QPixmap, QPalette
)

from scanner import NetworkScanner, ScanResult, parse_ip_range, COMMON_PORTS, PORT_NAMES
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
QTableWidget {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    gridline-color: #F1F5F9;
    background-color: #FFFFFF;
    alternate-background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    selection-background-color: #DBEAFE;
    selection-color: #1E40AF;
}
QTableWidget::item {
    padding: 4px 8px;
    border: none;
}
QHeaderView::section {
    font-family: "Microsoft YaHei", "微软雅黑";
    font-size: 13px;
    font-weight: bold;
    color: #475569;
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

    def __init__(self, ip_ranges, timeout_ms=1000, max_threads=100, scan_ports=False, library=None):
        super().__init__()
        self.ip_ranges = ip_ranges
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports = scan_ports
        self.library = library
        self.scanner = NetworkScanner()

    def run(self):
        def on_progress(current, total, ip):
            self.progress.emit(current, total, ip)

        def on_result(result: ScanResult):
            # 地址库匹配
            if self.library and self.library.is_loaded():
                match = self.library.match(result.ip, result.mac)
                if match:
                    result.device_type = match.get("device_type", "")
                    result.location = match.get("location", "")
                    result.user = match.get("user", "")
                    result.remark = match.get("remark", "")
                    result.excel_matched = True
            self.result_ready.emit(result)

        self.log_signal.emit(f"开始扫描 {len(self.ip_ranges)} 个网段...")
        results = self.scanner.scan(
            self.ip_ranges,
            timeout_ms=self.timeout_ms,
            max_threads=self.max_threads,
            scan_ports_flag=self.scan_ports,
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
        painter.save()

        # 背景
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor(219, 234, 254))
        elif option.state & QStyle.State_MouseOver:
            painter.fillRect(option.rect, QColor(241, 245, 249))

        status = index.data(Qt.UserRole)
        if status is None:
            text = index.data(Qt.DisplayRole)
            if text:
                status = "online" if "在线" in str(text) else "offline"
            else:
                status = "offline"

        # 画圆点
        dot_size = 10
        dot_x = option.rect.center().x() - dot_size // 2
        dot_y = option.rect.center().y() - dot_size // 2

        if status == "online":
            color = QColor(34, 197, 94)   # green
            # 外圈光晕
            painter.setBrush(QBrush(QColor(34, 197, 94, 40)))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(dot_x - 3, dot_y - 3, dot_size + 6, dot_size + 6)
        else:
            color = QColor(239, 68, 68)   # red

        painter.setBrush(QBrush(color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(dot_x, dot_y, dot_size, dot_size)

        painter.restore()


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
        self.scan_thread = None
        self.all_results: list = []
        self.ip_range_items: list = []
        self._ip_row_map: dict = {}

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

        params_layout.addWidget(self.timeout_spin)
        params_layout.addSpacing(8)
        params_layout.addWidget(QLabel("并发线程:"))
        params_layout.addWidget(self.threads_spin)
        params_layout.addSpacing(8)
        params_layout.addWidget(self.port_scan_check)

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
        self.filter_combo.addItems(["全部", "仅在线", "仅离线", "Excel已匹配"])
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

        # --- 结果表格 ---
        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "序号", "状态", "IP地址", "主机名", "MAC地址",
            "设备类型", "位置", "使用者", "响应时间(ms)", "开放端口", "备注"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)

        # 列宽：序号/状态/IP/响应时间固定；其余列允许用户手动拖动调整
        header = self.table.horizontalHeader()
        # 所有列均可手动拖动调整宽度
        header.setStretchLastSection(False)
        _widths = {0: 50, 1: 60, 2: 130, 3: 150, 4: 210, 5: 100, 6: 140, 7: 100, 8: 100, 9: 180, 10: 200}
        for _col, _w in _widths.items():
            header.setSectionResizeMode(_col, QHeaderView.Interactive)
            header.resizeSection(_col, _w)

        # 状态列使用自定义委托
        self.table.setItemDelegateForColumn(1, StatusDelegate())

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
        self.table.setRowCount(0)
        self._ip_row_map.clear()

        self.scan_thread = ScanThread(
            self.ip_range_items,
            timeout_ms=self.timeout_spin.value(),
            max_threads=self.threads_spin.value(),
            scan_ports=self.port_scan_check.isChecked(),
            library=self.library if self.library.is_loaded() else None,
        )
        self.scan_thread.progress.connect(self._on_scan_progress)
        self.scan_thread.result_ready.connect(self._on_scan_result)
        self.scan_thread.finished_signal.connect(self._on_scan_finished)
        self.scan_thread.log_signal.connect(lambda msg: self.status_bar.showMessage(msg))
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_bar.showMessage("正在停止扫描...")
            self.scan_thread.wait(3000)

    def _on_scan_progress(self, current, total, ip):
        pct = int(current / total * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status_bar.showMessage(f"扫描中 [{current}/{total}] {ip} ...")

    def _on_scan_result(self, result: ScanResult):
        self._upsert_table_row(result)

    def _on_scan_finished(self, results):
        self.all_results = results
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.table.setSortingEnabled(True)
        self._update_stats()
        self.status_bar.showMessage("扫描完成")

    # --- 表格操作 ---

    def _upsert_table_row(self, result: ScanResult):
        """新增或更新指定 IP 的行，避免同一 IP 重复显示"""
        if result.ip in self._ip_row_map:
            row = self._ip_row_map[result.ip]
            self._update_table_row(row, result)
        else:
            row = self.table.rowCount()
            self._add_table_row(result)
            self._ip_row_map[result.ip] = row

    def _add_table_row(self, result: ScanResult):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._set_row_data(row, result)

    def _update_table_row(self, row: int, result: ScanResult):
        self._set_row_data(row, result)

    def _set_row_data(self, row: int, result: ScanResult):
        """设置/更新指定行的所有列内容"""
        # 序号
        idx_item = QTableWidgetItem()
        idx_item.setData(Qt.DisplayRole, row + 1)
        idx_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 0, idx_item)

        # 状态 (使用委托绘制圆点)
        status_item = QTableWidgetItem()
        status_item.setData(Qt.UserRole, result.status)
        status_item.setData(Qt.DisplayRole, "在线" if result.status == "online" else "离线")
        status_item.setTextAlignment(Qt.AlignCenter)
        if result.status == "online":
            status_item.setForeground(QColor(22, 163, 74))
        else:
            status_item.setForeground(QColor(220, 38, 38))
        self.table.setItem(row, 1, status_item)

        # IP
        ip_item = QTableWidgetItem(result.ip)
        ip_item.setFont(QFont("Consolas", 10))
        self.table.setItem(row, 2, ip_item)

        # 主机名
        host_item = QTableWidgetItem(result.hostname or "—")
        self.table.setItem(row, 3, host_item)

        # MAC
        mac_item = QTableWidgetItem(result.mac.upper() if result.mac else "—")
        mac_item.setFont(QFont("Consolas", 10))
        if not result.mac:
            mac_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 4, mac_item)

        # 设备类型
        type_item = QTableWidgetItem(result.device_type or "—")
        if result.excel_matched and result.device_type:
            type_item.setForeground(QColor(37, 99, 235))
            type_item.setFont(QFont("Microsoft YaHei", 9, QFont.Bold))
        elif not result.device_type:
            type_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 5, type_item)

        # 位置
        loc_item = QTableWidgetItem(result.location or "—")
        if not result.location:
            loc_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 6, loc_item)

        # 使用者
        user_item = QTableWidgetItem(result.user or "—")
        if not result.user:
            user_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 7, user_item)

        # 响应时间
        rtt_item = QTableWidgetItem()
        if result.response_time > 0:
            rtt_item.setData(Qt.DisplayRole, round(result.response_time, 1))
            rtt_item.setTextAlignment(Qt.AlignCenter)
        else:
            rtt_item.setData(Qt.DisplayRole, "—")
            rtt_item.setTextAlignment(Qt.AlignCenter)
            rtt_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 8, rtt_item)

        # 开放端口
        if result.open_ports:
            port_strs = []
            for p in result.open_ports:
                name = PORT_NAMES.get(p, "")
                port_strs.append(f"{p}({name})" if name else str(p))
            ports_text = ", ".join(port_strs)
        else:
            ports_text = "—"
        port_item = QTableWidgetItem(ports_text)
        port_item.setFont(QFont("Consolas", 9))
        if not result.open_ports:
            port_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 9, port_item)

        # 备注
        remark_item = QTableWidgetItem(result.remark or "—")
        if not result.remark:
            remark_item.setForeground(QColor(148, 163, 184))
        self.table.setItem(row, 10, remark_item)

    def _filter_results(self):
        """根据搜索和筛选条件显示/隐藏行"""
        search_text = self.search_input.text().lower().strip()
        filter_type = self.filter_combo.currentText()

        for row in range(self.table.rowCount()):
            show = True

            # 筛选
            if filter_type == "仅在线":
                status = self.table.item(row, 1).data(Qt.UserRole)
                show = show and (status == "online")
            elif filter_type == "仅离线":
                status = self.table.item(row, 1).data(Qt.UserRole)
                show = show and (status == "offline")
            elif filter_type == "Excel已匹配":
                type_text = self.table.item(row, 5).text()
                show = show and (type_text != "—")

            # 搜索
            if show and search_text:
                row_text = ""
                for col in [2, 3, 4, 5, 6, 7, 9, 10]:
                    item = self.table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "
                show = search_text in row_text

            self.table.setRowHidden(row, not show)

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
        self.table.setRowCount(0)
        self._ip_row_map.clear()
        self.all_results.clear()
        self._update_stats()
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.status_bar.showMessage("已清空结果")

    # --- 右键菜单 ---

    def _show_context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return

        menu = QMenu(self)

        act_copy_ip = QAction("复制 IP", self)
        act_copy_ip.triggered.connect(lambda: self._copy_cell(row, 2))
        menu.addAction(act_copy_ip)

        act_copy_mac = QAction("复制 MAC", self)
        act_copy_mac.triggered.connect(lambda: self._copy_cell(row, 4))
        menu.addAction(act_copy_mac)

        act_copy_host = QAction("复制主机名", self)
        act_copy_host.triggered.connect(lambda: self._copy_cell(row, 3))
        menu.addAction(act_copy_host)

        menu.addSeparator()

        act_copy_row = QAction("复制整行", self)
        act_copy_row.triggered.connect(lambda: self._copy_row(row))
        menu.addAction(act_copy_row)

        menu.addSeparator()

        act_rescan = QAction("重新扫描此 IP", self)
        act_rescan.triggered.connect(lambda: self._rescan_single(row))
        menu.addAction(act_rescan)

        menu.addSeparator()

        # 地址库操作
        ip = self._row_text(row, 2)
        mac = self._row_text(row, 4)
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

    def _row_text(self, row: int, col: int) -> str:
        item = self.table.item(row, col)
        if not item:
            return ""
        t = item.text().strip()
        return "" if t == "—" else t

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

    def _copy_cell(self, row, col):
        item = self.table.item(row, col)
        if item:
            text = item.text()
            if text and text != "—":
                QApplication.clipboard().setText(text)
                self.status_bar.showMessage(f"已复制: {text}")

    def _copy_row(self, row):
        texts = []
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            texts.append(item.text() if item else "")
        QApplication.clipboard().setText("\t".join(texts))
        self.status_bar.showMessage("已复制整行")

    def _rescan_single(self, row):
        ip_item = self.table.item(row, 2)
        if not ip_item:
            return
        ip = ip_item.text()
        self.range_input.setText(ip)
        self.ip_range_items = [ip]
        self._update_range_list()
        self._start_scan()

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
# 入口
# ============================================================
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    app.setFont(QFont("Microsoft YaHei", 9))

    # 高 DPI
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
