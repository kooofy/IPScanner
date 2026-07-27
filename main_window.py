# -*- coding: utf-8 -*-
import sys
import os
from app_paths import data_dir, resource_dir
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
import threading
from datetime import datetime
from typing import List, Dict
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
    QColor, QFont, QIcon, QPainter, QBrush, QPen, QPixmap, QImage, QPalette,
    QCursor, QFontMetrics, QDesktopServices, QTextDocument, QPageLayout, QPageSize
)
from PyQt5.QtGui import QKeySequence
from PyQt5.QtPrintSupport import QPrinter, QPrintPreviewDialog
from scanner import (NetworkScanner, ScanResult, parse_ip_range, COMMON_PORTS,
                      PORT_NAMES, PROTOCOL_PORTS, WmiCredentialStore, wmi_device_class,
                      merge_wmi, netbios_query, merge_netbios, get_ports_for_level,
                      format_ports_display, SCAN_LEVEL_LABELS)
from excel_handler import export_results, export_csv, export_html, export_json, create_template, normalize_mac
from mac_library import MacLibrary
import history_store
import audit_log

from ui_dialogs import DeviceEditDialog, HistoryCompareDialog, HistoryQueryDialog, MacLibraryDialog, TopologyDialog, WmiCredentialDialog, ConflictReportDialog, SubnetUtilizationDialog, AuditLogDialog, SwitchPortDialog, ChangeReportDialog
from ui_icons import _build_dark_palette, get_pc_icons
from ui_threads import MdnsThread, ScanThread, WmiThread, NetbiosThread
from ui_utils import _detect_gateway
from conflict_detector import detect_conflicts, get_conflict_ips, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO


from styles import (STYLE_SHEET, DARK_STYLE_SHEET, _gray_icon, _make_tool_icon,
                     _make_pause_icon, _ip_to_int,
                     _FONT_CONSOLAS_10, _FONT_CONSOLAS_9, _FONT_YAHEI_BOLD_9)
from main_window_tree import ResultTreeItem, TreeMixin
from i18n import tr

class MainWindow(TreeMixin, QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(tr("局域网终端扫描工具 — IP Scanner"))
        self.setMinimumSize(1200, 750)
        self.resize(1300, 850)

        self.library = MacLibrary()  # 持久 MAC 地址库 (SQLite)
        self.selected_protocols = list(PROTOCOL_PORTS.keys())  # HTTP, HTTPS, FTP, RDP 默认开启
        self.tcp_scan_mode = "connect"  # 端口探测方式: connect / syn / udp
        self.scan_level = "quick"  # 扫描级别: quick / standard / all（默认快速，向后兼容）
        self.mdns_discovery = True      # 扫描末尾做 mDNS 组播发现
        self.mdns_thread = None
        self.scan_thread = None
        self.all_results: list = []
        self.ip_range_items: list = []
        self._ip_item_map: dict = {}
        self.dark_mode = False  # 深色模式开关
        self.auto_time = False  # 是否跟随时间自动切换深色/浅色主题
        self._conflicts: list = []       # 最近一次冲突检测结果
        self._conflict_ips: dict = {}    # {ip: [conflict_type, ...]} 用于树视图标记
        self._changes: list = []         # 最近一次资产变更检测结果

        # 配置持久化 (QSettings, Ini 格式, 存于项目目录便于查看/重置)
        self.settings = QSettings(
            os.path.join(data_dir(), "ipscanner.ini"),
            QSettings.IniFormat
        )

        # WMI 识别凭据：从配置解密载入（DPAPI，仅本机当前用户可读）
        self.wmi_creds = WmiCredentialStore()
        self.wmi_creds.load_from(self.settings)
        self.wmi_thread = None
        self.netbios_thread = None

        # 扫描历史快照 (SQLite, 存于项目目录；含内部信息，已 gitignore)
        self.history_db = os.path.join(
            data_dir(), "scan_history.db"
        )
        self.history_json = os.path.join(
            data_dir(), "scan_history.json"
        )
        # 首次启动若已有旧 JSON 历史，自动迁入 SQLite（幂等，可重复调用）
        history_store.ensure_migrated(self.history_db, self.history_json)

        self._init_ui()
        self._init_menu()
        self._connect_signals()

        # 载入持久化配置 (主题/扫描参数/网段/窗口几何/列布局)
        self._load_settings()

        # 自动检测本机网段 (仅预填输入框，不影响已持久化的网段列表)
        self._auto_detect_subnet()
        # 载入地址库计数
        self._refresh_library_label()

        # 应用初始主题（若开启跟随时间自动切换，则先按当前时间决定深/浅色）
        if self.auto_time:
            self.dark_mode = self._should_be_dark_now()
        self._apply_theme(self.dark_mode)
        # 按时间自动切换主题：每分钟检查一次时间边界（自动模式下跨过阈值即切换）
        self._theme_timer = QTimer(self)
        self._theme_timer.setInterval(60 * 1000)
        self._theme_timer.timeout.connect(self._check_theme_by_time)
        self._theme_timer.start()

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
        _play_pm = QPixmap(os.path.join(resource_dir(), "assets", "play_icon.png")).scaled(
            _BIG_ICON, _BIG_ICON, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.scan_btn = QPushButton(tr("扫描"))
        self.scan_btn.setIcon(QIcon(_play_pm))
        self.scan_btn.setIconSize(QSize(_BIG_ICON, _BIG_ICON))
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.setFixedSize(100, _BIG_BTN_H)  # 固定宽高，避免被布局拉宽

        # 暂停/停止按钮 - 与扫描按钮同高的大按钮
        self.stop_btn = QPushButton()
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setFixedSize(_BIG_BTN_H, _BIG_BTN_H)  # 正方形暂停按钮
        self.stop_btn.setIcon(_make_pause_icon())
        self.stop_btn.setIconSize(QSize(_BIG_BTN_H - 6, _BIG_BTN_H - 6))
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip(tr("停止扫描"))

        tb1.addWidget(self.scan_btn)
        tb1.addWidget(self.stop_btn)

        # 四个快捷工具按钮（对齐 AIP 右侧工具栏），高度与扫描/暂停等大
        _SMALL_BTN = _BIG_BTN_H  # 36，与扫描/暂停按钮等高
        _ICON_SZ = 22            # 按 36/30 比例放大图标（18 -> 22）

        _icon_color = "#FFFFFF" if self.dark_mode else "#555555"

        self.local_subnet_btn = QPushButton()
        self.local_subnet_btn.setObjectName("toolBtnGreen")
        self.local_subnet_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.local_subnet_btn.setIcon(_make_tool_icon("ip", _icon_color, _ICON_SZ))
        self.local_subnet_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.local_subnet_btn.setToolTip(tr("扫描本机所在子网"))

        self.c_subnet_btn = QPushButton()
        self.c_subnet_btn.setObjectName("toolBtnGreen")
        self.c_subnet_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.c_subnet_btn.setIcon(_make_tool_icon("c", _icon_color, _ICON_SZ))
        self.c_subnet_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.c_subnet_btn.setToolTip(tr("扫描 C 类子网"))

        self.expand_btn = QPushButton()
        self.expand_btn.setObjectName("toolBtnYellow")
        self.expand_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.expand_btn.setIcon(_make_tool_icon("expand", _icon_color, _ICON_SZ))
        self.expand_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.expand_btn.setToolTip(tr("全选并展开所有项"))

        self.collapse_btn = QPushButton()
        self.collapse_btn.setObjectName("toolBtnYellow")
        self.collapse_btn.setFixedSize(_SMALL_BTN, _SMALL_BTN)
        self.collapse_btn.setIcon(_make_tool_icon("collapse", _icon_color, _ICON_SZ))
        self.collapse_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.collapse_btn.setToolTip(tr("收起所有项"))

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
            tr("例如: 192.168.1.0/24, 192.168.2.0/24 (一行可写多个, 用逗号/空格/换行分隔)")
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

        tb2.addWidget(QLabel(tr("搜索")))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(tr("IP / 主机名 / MAC ..."))
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
        self.port_scan_check = QAction(tr("端口扫描"), self, checkable=True)
        self.port_scan_check.setToolTip(tr("对在线设备扫描常见端口"))

        # mDNS 设备发现：扫描末尾做组播发现（发现 IoT/打印机/NAS 等）
        self.mdns_check = QAction(tr("mDNS 设备发现"), self, checkable=True)
        self.mdns_check.setToolTip(tr("扫描末尾向本地组播组发现 mDNS/DNS-SD 设备"))

        # 筛选：保留 ComboBox 作为值载体，由「视图 > 筛选」子菜单驱动
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([tr("全部"), tr("仅在线"), tr("仅离线"), tr("Excel已匹配"), tr("有服务")])
        self.filter_combo.setCurrentText(tr("仅在线"))
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
            tr("IP地址"), tr("状态"), tr("主机名"), tr("MAC地址"),
            tr("制造商"), tr("位置"), tr("使用者"), tr("响应时间(ms)"), tr("开放端口"), tr("服务"), tr("操作系统"), tr("设备类型"), tr("备注")
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
        self.status_bar.showMessage(tr("就绪"))
        self.status_label = QLabel(tr("就绪"))
        self.status_bar.addPermanentWidget(self.status_label)

        self.status_stats_label = QLabel("")
        self.status_stats_label.setStyleSheet("color: #333333; font-size: 12px;")
        self.status_bar.addPermanentWidget(self.status_stats_label)

        # 地址库状态（从工具栏移到底部状态栏）
        self.excel_label = QLabel(tr("地址库: 空"))
        self.excel_label.setStyleSheet("color: #888888; font-size: 11px;")
        self.status_bar.addPermanentWidget(self.excel_label)

    def _init_menu(self):
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu(tr("文件(&F)"))

        self.act_export = QAction(tr("导出扫描结果"), self)
        self.act_export.setShortcut(QKeySequence("Ctrl+E"))
        self.act_export.triggered.connect(self._export_results)
        file_menu.addAction(self.act_export)

        act_print = QAction(tr("打印..."), self)
        act_print.setShortcut(QKeySequence("Ctrl+P"))
        act_print.triggered.connect(self._print_results)
        file_menu.addAction(act_print)

        file_menu.addSeparator()

        act_exit = QAction(tr("退出"), self)
        act_exit.setShortcut(QKeySequence("Alt+F4"))
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # MAC 地址库菜单
        lib_menu = menubar.addMenu(tr("地址库(&L)"))

        act_lib_manage = QAction(tr("管理地址库..."), self)
        act_lib_manage.setShortcut(QKeySequence("Ctrl+Shift+M"))
        act_lib_manage.triggered.connect(self._open_library_manager)
        lib_menu.addAction(act_lib_manage)

        act_lib_import = QAction(tr("导入地址库"), self)
        act_lib_import.setShortcut(QKeySequence("Ctrl+I"))
        act_lib_import.triggered.connect(self._import_excel)
        lib_menu.addAction(act_lib_import)

        act_lib_export = QAction(tr("导出地址库"), self)
        act_lib_export.setShortcut(QKeySequence("Ctrl+Shift+I"))
        act_lib_export.triggered.connect(self._export_library)
        lib_menu.addAction(act_lib_export)

        # 扫描菜单
        scan_menu = menubar.addMenu(tr("扫描(&S)"))

        act_scan = QAction(tr("开始扫描"), self)
        act_scan.setShortcut(QKeySequence("F5"))
        act_scan.triggered.connect(self._start_scan)
        scan_menu.addAction(act_scan)

        act_stop = QAction(tr("停止扫描"), self)
        act_stop.setShortcut(QKeySequence("Esc"))
        act_stop.triggered.connect(self._stop_scan)
        scan_menu.addAction(act_stop)

        scan_menu.addSeparator()

        act_add_range = QAction(tr("添加网段"), self)
        act_add_range.setShortcut(QKeySequence("Ctrl+Shift+R"))
        act_add_range.triggered.connect(self._add_ip_range)
        scan_menu.addAction(act_add_range)

        act_clear_ranges = QAction(tr("清空网段"), self)
        act_clear_ranges.setShortcut(QKeySequence("Ctrl+Shift+L"))
        act_clear_ranges.triggered.connect(self._clear_ranges)
        scan_menu.addAction(act_clear_ranges)

        self.act_clear = QAction(tr("清空结果"), self)
        self.act_clear.setShortcut(QKeySequence("Ctrl+Shift+K"))
        self.act_clear.triggered.connect(self._clear_results)
        scan_menu.addAction(self.act_clear)

        scan_menu.addSeparator()

        # 发现子菜单：子网扫描 + 独立 mDNS 发现
        discover_sub = scan_menu.addMenu(tr("发现"))
        act_scan_local = QAction(tr("扫描本机所在子网"), self)
        act_scan_local.setShortcut(QKeySequence("Ctrl+1"))
        act_scan_local.triggered.connect(self._scan_local_subnet)
        discover_sub.addAction(act_scan_local)

        act_scan_c = QAction(tr("扫描 C 类子网"), self)
        act_scan_c.setShortcut(QKeySequence("Ctrl+2"))
        act_scan_c.triggered.connect(self._scan_c_class_subnet)
        discover_sub.addAction(act_scan_c)

        act_mdns = QAction(tr("网络 mDNS 发现"), self)
        act_mdns.setShortcut(QKeySequence("Ctrl+3"))
        act_mdns.setToolTip(tr("对当前本地链路做 mDNS/DNS-SD 组播发现，发现打印机/NAS/Apple 设备等"))
        act_mdns.triggered.connect(self._run_mdns_discovery)
        discover_sub.addAction(act_mdns)

        scan_menu.addSeparator()

        # 端口扫描：原工具栏复选框，移入菜单
        scan_menu.addAction(self.port_scan_check)

        # mDNS 设备发现：扫描时默认开启，可关闭
        scan_menu.addAction(self.mdns_check)

        # 端口探测方式：全连接 / SYN 半开 / UDP（单选项）
        self.tcp_mode_group = QActionGroup(self)
        self.tcp_mode_group.setExclusive(True)
        mode_sub = scan_menu.addMenu(tr("端口探测方式"))
        for _m, _label in (("connect", tr("TCP 全连接")),
                           ("syn", tr("TCP SYN 半开")),
                           ("udp", tr("UDP 探测"))):
            _a = QAction(_label, self, checkable=True)
            _a.setData(_m)
            _a.setActionGroup(self.tcp_mode_group)
            _a.setChecked(self.tcp_scan_mode == _m)
            _a.triggered.connect(
                lambda _checked, _mm=_m: self._set_tcp_mode(_mm)
            )
            mode_sub.addAction(_a)

        # 扫描级别：快速 / 标准 / 全端口（单选项，决定端口探测范围）
        self.scan_level_group = QActionGroup(self)
        self.scan_level_group.setExclusive(True)
        level_sub = scan_menu.addMenu(tr("扫描级别"))
        level_sub.setToolTip(tr("控制端口探测的端口范围（快速日常巡检 / 标准深度 / 全端口安全评估）"))
        for _lv in ("quick", "standard", "all"):
            _a = QAction(SCAN_LEVEL_LABELS.get(_lv, _lv), self, checkable=True)
            _a.setData(_lv)
            _a.setActionGroup(self.scan_level_group)
            _a.setChecked(getattr(self, "scan_level", "quick") == _lv)
            _a.triggered.connect(
                lambda _checked, _ll=_lv: self._set_scan_level(_ll)
            )
            level_sub.addAction(_a)

        settings_sub = scan_menu.addMenu(tr("扫描设置"))
        act_open_settings = QAction(tr("打开扫描设置对话框..."), self)
        act_open_settings.triggered.connect(self._open_scan_settings)
        settings_sub.addAction(act_open_settings)
        settings_sub.addSeparator()
        for _proto in sorted(PROTOCOL_PORTS.keys()):
            _act = QAction(_proto, self, checkable=True)
            _act.setToolTip(f"扫描 {_proto} 服务")
            _act.setChecked(_proto in self.selected_protocols)
            _act.toggled.connect(
                lambda _checked, _p=_proto: self._toggle_protocol(_p, _checked)
            )
            settings_sub.addAction(_act)

        # 分析菜单（顶级菜单，从扫描子菜单提升）
        analysis_menu = menubar.addMenu(tr("分析(&A)"))

        act_history = QAction(tr("历史对比..."), self)
        act_history.setShortcut(QKeySequence("Ctrl+H"))
        act_history.triggered.connect(self._open_history_compare)
        analysis_menu.addAction(act_history)

        act_history_query = QAction(tr("历史检索..."), self)
        act_history_query.setShortcut(QKeySequence("Ctrl+Shift+H"))
        act_history_query.setToolTip(tr("跨快照按类型/网段/首见时间/IP 检索历史设备"))
        act_history_query.triggered.connect(self._open_history_query)
        analysis_menu.addAction(act_history_query)

        analysis_menu.addSeparator()

        self.act_conflict = QAction(tr("冲突检测"), self)
        self.act_conflict.setShortcut(QKeySequence("Ctrl+Shift+C"))
        self.act_conflict.setToolTip(tr("检测 IP/MAC 冲突、未知设备等异常"))
        self.act_conflict.triggered.connect(self._run_conflict_detection)
        analysis_menu.addAction(self.act_conflict)

        self.act_change = QAction(tr("变更检测"), self)
        self.act_change.setShortcut(QKeySequence("Ctrl+Shift+V"))
        self.act_change.setToolTip(tr("对比上次扫描快照，发现新增/消失/替换/改址等设备变动"))
        self.act_change.triggered.connect(lambda: self._run_change_detection(silent=False))
        analysis_menu.addAction(self.act_change)

        analysis_menu.addSeparator()

        act_subnet_util = QAction(tr("子网利用率..."), self)
        act_subnet_util.setShortcut(QKeySequence("Ctrl+U"))
        act_subnet_util.setToolTip(tr("按 /24 子网聚合，查看各网段在线占比与设备分布"))
        act_subnet_util.triggered.connect(self._show_subnet_utilization)
        analysis_menu.addAction(act_subnet_util)

        act_audit_log = QAction(tr("审计日志..."), self)
        act_audit_log.setShortcut(QKeySequence("Ctrl+Shift+A"))
        act_audit_log.setToolTip(tr("查看扫描活动记录（开始/停止/完成、冲突检测等）"))
        act_audit_log.triggered.connect(self._show_audit_log)
        analysis_menu.addAction(act_audit_log)

        # 工具菜单 (内置 Ping/Tracert/Telnet/SSH 等网络工具, P2)
        tool_menu = menubar.addMenu(tr("工具(&T)"))

        act_ping = QAction(tr("Ping (持续)"), self)
        act_ping.setShortcut(QKeySequence("Ctrl+P"))
        act_ping.setToolTip(tr("对目标执行持续 Ping (ping -t)"))
        act_ping.triggered.connect(lambda: self._launch_network_tool("ping"))
        tool_menu.addAction(act_ping)

        act_tracert = QAction(tr("Tracert (路由追踪)"), self)
        act_tracert.setShortcut(QKeySequence("Ctrl+R"))
        act_tracert.setToolTip(tr("对目标执行路由追踪 (tracert)"))
        act_tracert.triggered.connect(lambda: self._launch_network_tool("tracert"))
        tool_menu.addAction(act_tracert)

        act_telnet = QAction(tr("Telnet"), self)
        act_telnet.setShortcut(QKeySequence("Ctrl+N"))
        act_telnet.setToolTip(tr("对目标启动 Telnet 会话"))
        act_telnet.triggered.connect(lambda: self._launch_network_tool("telnet"))
        tool_menu.addAction(act_telnet)

        act_ssh = QAction(tr("SSH"), self)
        act_ssh.setShortcut(QKeySequence("Ctrl+Shift+S"))
        act_ssh.setToolTip(tr("对目标启动 SSH 会话 (需 OpenSSH 客户端)"))
        act_ssh.triggered.connect(lambda: self._launch_network_tool("ssh"))
        tool_menu.addAction(act_ssh)

        tool_menu.addSeparator()

        act_rdp = QAction(tr("远程桌面 (RDP)"), self)
        act_rdp.setShortcut(QKeySequence("Ctrl+M"))
        act_rdp.setToolTip(tr("用系统 mstsc 远程桌面连接目标"))
        act_rdp.triggered.connect(lambda: self._launch_network_tool("rdp"))
        tool_menu.addAction(act_rdp)

        act_cmd = QAction(tr("打开命令提示符"), self)
        act_cmd.setShortcut(QKeySequence("Ctrl+J"))
        act_cmd.setToolTip(tr("打开以目标命名的命令提示符窗口"))
        act_cmd.triggered.connect(lambda: self._launch_network_tool("cmd"))
        tool_menu.addAction(act_cmd)

        tool_menu.addSeparator()

        act_shutdown = QAction(tr("远程关机"), self)
        act_shutdown.setToolTip(tr("向目标发送关机指令 (shutdown /s /m)"))
        act_shutdown.triggered.connect(lambda: self._remote_power("shutdown"))
        tool_menu.addAction(act_shutdown)

        act_reboot = QAction(tr("远程重启"), self)
        act_reboot.setToolTip(tr("向目标发送重启指令 (shutdown /r /m)"))
        act_reboot.triggered.connect(lambda: self._remote_power("reboot"))
        tool_menu.addAction(act_reboot)

        tool_menu.addSeparator()
        act_wmi = QAction(tr("WMI 设备识别 (需管理员)..."), self)
        act_wmi.setShortcut(QKeySequence("Ctrl+Shift+W"))
        act_wmi.setToolTip(tr("对在线疑似 Windows 设备做 WMI 远程识别（厂商/型号/序列号/系统），需管理员凭据"))
        act_wmi.triggered.connect(lambda: self._run_wmi_identification())
        tool_menu.addAction(act_wmi)

        act_netbios = QAction(tr("NetBIOS 识别（轻量）"), self)
        act_netbios.setToolTip(tr("零凭据、不需管理员：获取计算机名/工作组/当前用户/MAC（同网段 UDP/137）"))
        act_netbios.triggered.connect(lambda: self._run_netbios_identification())
        tool_menu.addAction(act_netbios)

        act_switch_map = QAction(tr("交换机端口映射..."), self)
        act_switch_map.setToolTip(tr("通过 SNMP 获取交换机 MAC 转发表，映射 MAC → 物理端口"))
        act_switch_map.triggered.connect(self._show_switch_port_mapping)
        tool_menu.addAction(act_switch_map)

        # 视图菜单（仿 Advanced IP Scanner「查看」菜单：左列复选/图标，右列文字）
        view_menu = menubar.addMenu(tr("查看(&V)"))
        # 主题仅由「跟随时间自动切换」控制，不再提供手动切换入口

        self.act_auto_theme = QAction(tr("跟随时间自动切换主题"), self)
        self.act_auto_theme.setCheckable(True)
        self.act_auto_theme.setChecked(self.auto_time)
        self.act_auto_theme.triggered.connect(self._toggle_auto_theme)
        view_menu.addAction(self.act_auto_theme)

        view_menu.addSeparator()

        lang_menu = view_menu.addMenu(tr("语言 / Language"))
        self.act_lang_zh = QAction(tr("中文"), self)
        self.act_lang_zh.setCheckable(True)
        self.act_lang_zh.triggered.connect(lambda: self._switch_language("zh-CN"))
        lang_menu.addAction(self.act_lang_zh)

        self.act_lang_en = QAction(tr("English"), self)
        self.act_lang_en.setCheckable(True)
        self.act_lang_en.triggered.connect(lambda: self._switch_language("en-US"))
        lang_menu.addAction(self.act_lang_en)

        # 显示列子菜单 (P2-3)
        col_menu = view_menu.addMenu(tr("显示列"))
        self._col_actions = {}
        _col_labels = [
            tr("IP地址"), tr("状态"), tr("主机名"), tr("MAC地址"), tr("制造商"),
            tr("位置"), tr("使用者"), tr("响应时间(ms)"), tr("开放端口"), tr("服务"), tr("操作系统"), tr("设备类型"), tr("备注")
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

        act_expand = QAction(tr("展开全部"), self)
        act_expand.setIcon(_gray_icon(self.style().standardIcon(QStyle.SP_ArrowDown)))
        act_expand.setShortcut(QKeySequence("Ctrl++"))
        act_expand.triggered.connect(self._expand_all_items)
        view_menu.addAction(act_expand)

        act_collapse = QAction(tr("收起全部"), self)
        act_collapse.setIcon(_gray_icon(self.style().standardIcon(QStyle.SP_ArrowUp)))
        act_collapse.setShortcut(QKeySequence("Ctrl+-"))
        act_collapse.triggered.connect(self._collapse_all_items)
        view_menu.addAction(act_collapse)

        view_menu.addSeparator()

        act_topology = QAction(tr("拓扑视图..."), self)
        act_topology.setIcon(_gray_icon(self.style().standardIcon(QStyle.SP_DriveNetIcon)))
        act_topology.setShortcut(QKeySequence("Ctrl+T"))
        act_topology.triggered.connect(self._open_topology)
        view_menu.addAction(act_topology)

        view_menu.addSeparator()

        # 筛选：原工具栏下拉框，移入菜单（单选项驱动 filter_combo）
        filter_menu = view_menu.addMenu(tr("筛选"))
        _filter_opts = [tr("全部"), tr("仅在线"), tr("仅离线"), tr("Excel已匹配"), tr("有服务")]
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
        help_menu = menubar.addMenu(tr("帮助(&H)"))
        act_about = QAction(tr("关于"), self)
        act_about.setShortcut(QKeySequence("F1"))
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
        # 工具栏小图标随主题重绘线条颜色
        _icon_color = "#FFFFFF" if dark else "#555555"
        if hasattr(self, "local_subnet_btn"):
            _sz = self.local_subnet_btn.iconSize().width()
            self.local_subnet_btn.setIcon(_make_tool_icon("ip", _icon_color, _sz))
            self.c_subnet_btn.setIcon(_make_tool_icon("c", _icon_color, _sz))
            self.expand_btn.setIcon(_make_tool_icon("expand", _icon_color, _sz))
            self.collapse_btn.setIcon(_make_tool_icon("collapse", _icon_color, _sz))
            self.stop_btn.setIcon(_make_pause_icon(_icon_color, self.stop_btn.iconSize().width()))
        # 已存在表格项的 IP 列前景色随主题刷新（冲突标记保持原色）
        if hasattr(self, "_ip_item_map"):
            _fg = self._default_fg_color()
            for ip, item in self._ip_item_map.items():
                if ip not in getattr(self, "_conflict_ips", {}):
                    item.setForeground(0, _fg)

    def _should_be_dark_now(self) -> bool:
        """按时间判断当前是否应为深色：18:00–次日 06:00 视为深色时段。"""
        _h = datetime.now().hour
        return _h >= 18 or _h < 6

    def _set_dark_mode(self, dark: bool, save: bool = True):
        """底层设定主题并刷新 UI；save=True 时持久化到配置。"""
        self.dark_mode = dark
        self._apply_theme(dark)
        if save:
            self._save_settings()

    def _check_theme_by_time(self):
        """定时器回调：开启自动模式且跨越时间边界时切换主题。"""
        if not getattr(self, "auto_time", False):
            return
        _target = self._should_be_dark_now()
        if _target != self.dark_mode:
            self._set_dark_mode(_target, save=True)

    def _toggle_auto_theme(self, checked: bool):
        """勾选「跟随时间自动切换」：开启时立即按当前时间校正一次主题。"""
        self.auto_time = checked
        if checked:
            _target = self._should_be_dark_now()
            if _target != self.dark_mode:
                self._set_dark_mode(_target, save=True)
            else:
                self._save_settings()
        else:
            self._save_settings()

    def _switch_language(self, lang: str):
        """切换界面语言，保存偏好并提示重启。"""
        import i18n
        if i18n.current_lang() == lang:
            return
        self.settings.setValue("ui/language", lang)
        self.settings.sync()
        QMessageBox.information(
            self, tr("语言切换"),
            tr("语言设置已保存，重启程序后生效。")
        )

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
        self.auto_time = s.value("theme/auto_time", False, type=bool)
        if hasattr(self, "act_auto_theme"):
            self.act_auto_theme.setChecked(self.auto_time)
        # 语言
        _lang = s.value("ui/language", "")
        if hasattr(self, "act_lang_zh"):
            self.act_lang_zh.setChecked(_lang == "zh-CN" or not _lang)
            self.act_lang_en.setChecked(_lang == "en-US")
        # 扫描参数
        self.timeout_spin.setValue(s.value("scan/timeout_ms", 1000, type=int))
        self.threads_spin.setValue(s.value("scan/max_threads", 100, type=int))
        self.port_scan_check.setChecked(s.value("scan/port_scan", False, type=bool))
        self.mdns_discovery = s.value("scan/mdns", True, type=bool)
        self.mdns_check.setChecked(self.mdns_discovery)
        self.tcp_scan_mode = s.value("scan/tcp_mode", "connect", type=str)
        if self.tcp_scan_mode not in ("connect", "syn", "udp"):
            self.tcp_scan_mode = "connect"
        self.scan_level = s.value("scan/level", "quick", type=str)
        if self.scan_level not in ("quick", "standard", "all"):
            self.scan_level = "quick"
        self._sync_scan_level_menu()
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
        s.setValue("theme/auto_time", self.auto_time)
        s.setValue("scan/timeout_ms", self.timeout_spin.value())
        s.setValue("scan/max_threads", self.threads_spin.value())
        s.setValue("scan/port_scan", self.port_scan_check.isChecked())
        s.setValue("scan/mdns", self.mdns_check.isChecked())
        s.setValue("scan/tcp_mode", self.tcp_scan_mode)
        s.setValue("scan/level", self.scan_level)
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
        dlg.setWindowTitle(tr("扫描设置"))
        dlg.setMinimumWidth(240)
        _layout = QFormLayout(dlg)
        _to = QSpinBox(); _to.setRange(100, 5000); _to.setSingleStep(100)
        _to.setValue(self.timeout_spin.value())
        _th = QSpinBox(); _th.setRange(1, 500); _th.setSingleStep(10)
        _th.setValue(self.threads_spin.value())
        _layout.addRow(tr("超时 (ms):"), _to)
        _layout.addRow(tr("线程数:"), _th)
        _mode = QComboBox()
        _mode.addItems([tr("TCP 全连接"), tr("TCP SYN 半开"), tr("UDP 探测")])
        _mode_map = {tr("TCP 全连接"): "connect", tr("TCP SYN 半开"): "syn", tr("UDP 探测"): "udp"}
        _mode.setCurrentText(
            {v: k for k, v in _mode_map.items()}.get(self.tcp_scan_mode, tr("TCP 全连接"))
        )
        _layout.addRow(tr("端口探测方式:"), _mode)
        _btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        _btns.accepted.connect(dlg.accept)
        _btns.rejected.connect(dlg.reject)
        _layout.addRow(_btns)
        if dlg.exec_() == QDialog.Accepted:
            _old_to = self.timeout_spin.value()
            _old_th = self.threads_spin.value()
            _old_mode = self.tcp_scan_mode
            self.timeout_spin.setValue(_to.value())
            self.threads_spin.setValue(_th.value())
            self.tcp_scan_mode = _mode_map[_mode.currentText()]
            self._sync_tcp_mode_menu()
            self._save_settings()
            # 审计：记录设置变更
            _changes = []
            if _old_to != _to.value():
                _changes.append(f"超时 {_old_to}→{_to.value()}ms")
            if _old_th != _th.value():
                _changes.append(f"线程 {_old_th}→{_th.value()}")
            if _old_mode != self.tcp_scan_mode:
                _changes.append(f"探测方式 {_old_mode}→{self.tcp_scan_mode}")
            self._audit(
                audit_log.CAT_SYSTEM, tr("修改扫描设置"),
                " · ".join(_changes) if _changes else tr("无变化"),
            )

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
            out = subprocess.check_output(
                ["ipconfig"], encoding="gbk", errors="ignore",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            out = ""
        ips = re.findall(tr(r"IPv4[地址\\s]+[\.:\s]+([\d.]+)"), out)
        masks = re.findall(tr(r"子网掩码[\.:\s]+([\d.]+)"), out)
        default_ip = self._get_default_local_ip()
        if ips and masks and len(ips) == len(masks):
            # 1) 优先：默认出口 IP 在 ipconfig 中的 (ip, mask) 配对 -> 真实前缀长度
            if default_ip:
                for ip, mask in zip(ips, masks):
                    if ip == default_ip:
                        net, prefix = self._ip_mask_to_subnet(ip, mask)
                        if net:
                            return f"{net}/{prefix}"
            # 2) 回退：跳过回环/虚拟网卡，取第一张「真实」网卡
            for ip, mask in zip(ips, masks):
                if ip.startswith("127.") or self._is_virtual_adapter_ip(ip):
                    continue
                net, prefix = self._ip_mask_to_subnet(ip, mask)
                if net:
                    return f"{net}/{prefix}"
        if default_ip:
            parts = default_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    @staticmethod
    def _ip_mask_to_subnet(ip: str, mask: str):
        """由 IPv4 与子网掩码计算网段地址与前缀长度，失败返回 (None, 0)。"""
        try:
            ip_parts = list(map(int, ip.split(".")))
            mask_parts = list(map(int, mask.split(".")))
            net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
            prefix = sum(bin(m).count("1") for m in mask_parts)
            return ".".join(net_parts), prefix
        except Exception:
            return None, 0

    @staticmethod
    def _is_virtual_adapter_ip(ip: str) -> bool:
        """粗略判断是否为虚拟/容器网卡使用的私有网段（VirtualBox/Docker/链路本地等）。"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        if a == 169 and b == 254:                        # 169.254.0.0/16 链路本地(APIPA)
            return True
        if a == 172 and 16 <= b <= 31:                   # 172.16.0.0/12 Docker 默认桥
            return True
        if a == 192 and b == 168 and int(parts[2]) == 56:  # 192.168.56.0/24 VirtualBox Host-Only
            return True
        return False

    def _get_c_class_subnet(self):
        """获取本机 IP 的 C 类子网 /24。"""
        ip = self._get_default_local_ip()
        if ip:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def _scan_local_subnet(self):
        """扫描本机所在子网：仅填充范围并加入待扫列表（仿 AIP），不自动开始扫描。"""
        subnet = self._get_local_subnet()
        if subnet:
            self._fill_subnet_range(subnet)
        else:
            QMessageBox.warning(self, tr("提示"), tr("无法获取本机 IP，请手动输入扫描范围。"))

    def _scan_c_class_subnet(self):
        """扫描 C 类子网：仅填充范围并加入待扫列表（仿 AIP），不自动开始扫描。"""
        subnet = self._get_c_class_subnet()
        if subnet:
            self._fill_subnet_range(subnet)
        else:
            QMessageBox.warning(self, tr("提示"), tr("无法获取本机 IP，请手动输入扫描范围。"))

    def _fill_subnet_range(self, subnet: str):
        """将网段填入范围输入框并静默加入待扫列表（不弹重复提示、不自动扫描）。

        仿 Advanced IP Scanner：点击快捷按钮只是把 IP 范围放进输入框，
        用户确认后再点"扫描"按钮才开始。
        """
        self.range_input.setText(subnet)
        # 若尚未在列表中则静默添加；已存在则不重复添加、不弹窗
        if subnet not in self.ip_range_items and parse_ip_range(subnet):
            self.ip_range_items.append(subnet)
            self._update_range_list()
        self.range_input.setFocus()


    def _add_ip_range(self):
        text = self.range_input.text().strip()
        if not text:
            return

        # 一行内支持逗号 / 空格 / 换行 / 分号 / 制表符分隔多个网段 (类 Advanced IP Scanner)
        tokens = [t.strip() for t in re.split(r"[\s,;]+", text) if t.strip()]

        added, dup = 0, 0
        invalid = []
        added_tokens = []
        for tok in tokens:
            if not parse_ip_range(tok):
                invalid.append(tok)
                continue
            if tok in self.ip_range_items:
                dup += 1
                continue
            self.ip_range_items.append(tok)
            added_tokens.append(tok)
            added += 1

        if added > 0:
            self._update_range_list()
            self.range_input.clear()
            self.range_input.setFocus()
            # 审计：记录添加网段
            self._audit(audit_log.CAT_RANGE, tr("添加网段"), ", ".join(added_tokens))

        if added == 0:
            # 全部无效或全部重复，未新增任何网段
            if invalid:
                QMessageBox.warning(
                    self, tr("格式错误"),
                    tr("以下项无法解析:\n  ") + "\n  ".join(invalid) +
                    tr("\n\n支持格式 (可一行多个, 用逗号/空格/换行分隔):\n") + "  192.168.1.0/24\n  192.168.1.1-254\n  192.168.1.1"
                )
            elif dup:
                QMessageBox.information(self, tr("提示"), tr("这些网段都已添加过了"))
            return

        # 有成功添加时，仅对"重复 / 无效"做补充提示，避免无效输入被静默吞掉
        if dup or invalid:
            msg = []
            if dup:
                msg.append(f"已跳过 {dup} 个重复网段")
            if invalid:
                msg.append(tr("以下项无法解析, 已忽略:\n  ") + "\n  ".join(invalid))
            QMessageBox.information(self, tr("提示"), "\n".join(msg))

    def _clear_ranges(self):
        if self.ip_range_items:
            self._audit(audit_log.CAT_RANGE, tr("清空网段"), f"移除 {len(self.ip_range_items)} 个网段")
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
            # 冲突计数
            high = sum(1 for c in self._conflicts if c.severity == SEVERITY_HIGH)
            warn = sum(1 for c in self._conflicts if c.severity == SEVERITY_WARNING)
            if high:
                parts.append(f"⚠ {high} 冲突")
            elif warn:
                parts.append(f"⚠ {warn} 警告")
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
                QMessageBox.warning(self, tr("提示"), tr("请先添加至少一个 IP 范围"))
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
            ports=get_ports_for_level(self.scan_level) if self.port_scan_check.isChecked() else None,
        )
        # 启动即持久化当前扫描参数与网段 (P2-2)
        self._save_settings()
        self.scan_thread.progress.connect(self._on_scan_progress, Qt.QueuedConnection)
        self.scan_thread.result_ready.connect(self._on_scan_result, Qt.QueuedConnection)
        self.scan_thread.finished_signal.connect(self._on_scan_finished, Qt.QueuedConnection)
        self.scan_thread.log_signal.connect(lambda msg: self.status_bar.showMessage(msg), Qt.QueuedConnection)
        # 审计：记录扫描开始
        total_ips = sum(len(parse_ip_range(r)) for r in self.ip_range_items)
        self._audit(
            audit_log.CAT_SCAN, tr("开始扫描"),
            f"范围: {', '.join(self.ip_range_items)} ({total_ips} 个IP) | "
            f"超时 {self.timeout_spin.value()}ms · 线程 {self.threads_spin.value()} · "
            f"端口扫描 {'开' if self.port_scan_check.isChecked() else '关'}"
            f"{tr(' · 级别 ') + SCAN_LEVEL_LABELS.get(self.scan_level, self.scan_level) if self.port_scan_check.isChecked() else ''}",
        )
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_bar.showMessage(tr("正在停止扫描..."))
            self._audit(audit_log.CAT_SCAN, tr("停止扫描"), tr("用户手动中止扫描"))
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
            f"已选择协议: {', '.join(self.selected_protocols) if self.selected_protocols else tr('无')}"
        )

    def _set_tcp_mode(self, mode: str):
        """切换端口探测方式（全连接 / SYN 半开 / UDP）并持久化。"""
        self.tcp_scan_mode = mode
        self._sync_tcp_mode_menu()
        self._save_settings()
        _label = {"connect": tr("TCP 全连接"), "syn": tr("TCP SYN 半开"), "udp": tr("UDP 探测")}.get(mode, mode)
        _tip = ""
        if mode in ("syn", "udp"):
            _tip = tr("（需管理员权限；Windows 还需 Npcap，否则自动回退全连接）")
        self.status_bar.showMessage(f"端口探测方式: {_label}{_tip}")

    def _sync_tcp_mode_menu(self):
        """同步"端口探测方式"子菜单的勾选态到当前 tcp_scan_mode。"""
        for _a in self.tcp_mode_group.actions():
            _a.setChecked(_a.data() == self.tcp_scan_mode)

    def _set_scan_level(self, level: str):
        """切换扫描级别（快速/标准/全端口）并持久化，决定端口探测范围。"""
        if level not in ("quick", "standard", "all"):
            level = "quick"
        self.scan_level = level
        self._sync_scan_level_menu()
        self._save_settings()
        _label = SCAN_LEVEL_LABELS.get(level, level)
        _n = len(get_ports_for_level(level))
        self.status_bar.showMessage(f"扫描级别: {_label} · 端口数 {_n}")

    def _sync_scan_level_menu(self):
        """同步"扫描级别"子菜单的勾选态到当前 scan_level。"""
        for _a in self.scan_level_group.actions():
            _a.setChecked(_a.data() == self.scan_level)

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
                print(tr("地址库匹配出错:"), e)
        self._upsert_table_row(result)

    def _on_scan_finished(self, results):
        try:
            self.all_results = results
            # 变更检测：在保存新快照前，对比上一次快照
            self._run_change_detection(silent=True)
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
            # 审计：记录扫描完成
            _total = len(results)
            _online = sum(1 for r in results if r.status == "online")
            _offline = sum(1 for r in results if r.status == "offline")
            self._audit(
                audit_log.CAT_SCAN, tr("扫描完成"),
                f"共 {_total} 个IP · 在线 {_online} · 离线 {_offline} · "
                f"未知 {_total - _online - _offline}",
            )
            # 扫描完成后自动执行冲突检测（静默，仅更新标记和状态栏）
            self._run_conflict_detection(silent=True)
            self.status_bar.showMessage(tr("扫描完成"))
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

    def _run_conflict_detection(self, silent=False):
        """执行 IP 冲突检测。

        Args:
            silent: True 时仅更新树视图标记和状态栏，不弹对话框（扫描后自动调用）；
                    False 时弹出冲突报告对话框（菜单手动触发）。
        """
        if not self.all_results:
            if not silent:
                QMessageBox.information(self, tr("冲突检测"), tr("暂无扫描结果，请先执行扫描。"))
            return

        library = self.library if self.library.is_loaded() else None
        self._conflicts = detect_conflicts(self.all_results, library)
        self._conflict_ips = get_conflict_ips(self._conflicts)

        # 刷新树视图中所有行的冲突标记
        self._refresh_conflict_marks()

        # 更新统计栏
        self._update_stats()

        # 审计：记录冲突检测结果
        _high = sum(1 for c in self._conflicts if c.severity == SEVERITY_HIGH)
        _warn = sum(1 for c in self._conflicts if c.severity == SEVERITY_WARNING)
        _info = sum(1 for c in self._conflicts if c.severity == SEVERITY_INFO)
        self._audit(
            audit_log.CAT_CONFLICT, tr("冲突检测"),
            f"严重 {_high} · 警告 {_warn} · 提示 {_info}"
            + (tr("（未发现冲突）") if not self._conflicts else ""),
        )

        if silent:
            # 静默模式：仅在状态栏提示冲突数量
            high = sum(1 for c in self._conflicts if c.severity == SEVERITY_HIGH)
            warn = sum(1 for c in self._conflicts if c.severity == SEVERITY_WARNING)
            if high or warn:
                parts = []
                if high:
                    parts.append(f"{high} 严重")
                if warn:
                    parts.append(f"{warn} 警告")
                self.status_bar.showMessage(f"冲突检测完成：{' · '.join(parts)}（菜单 → 扫描 → 冲突检测 查看详情）")
            return

        # 手动触发：弹出报告对话框
        if not self._conflicts:
            QMessageBox.information(self, tr("冲突检测"), tr("未检测到任何冲突，网络状态良好。"))
            return
        dlg = ConflictReportDialog(self._conflicts, parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _run_change_detection(self, silent=False):
        """执行资产变更检测：对比当前扫描结果与上一次快照。

        Args:
            silent: True 时仅更新状态栏（扫描后自动调用）；
                    False 时弹出变更报告对话框（菜单手动触发）。
        """
        if not self.all_results:
            if not silent:
                QMessageBox.information(self, tr("变更检测"), tr("暂无扫描结果，请先执行扫描。"))
            return

        # 加载最近一次快照作为"上次"基准
        try:
            snapshots = history_store.list_snapshots(self.history_db)
            if not snapshots:
                self._changes = []
                if not silent:
                    QMessageBox.information(self, tr("变更检测"), tr("没有历史快照可供对比（首次扫描）。"))
                return
            last_snap = history_store.get_snapshot(snapshots[-1]["id"], self.history_db)
            prev_devices = last_snap["devices"] if last_snap else []
        except Exception:
            prev_devices = []

        if not prev_devices:
            self._changes = []
            if not silent:
                QMessageBox.information(self, tr("变更检测"), tr("上次快照为空，无法对比。"))
            return

        self._changes = detect_changes(self.all_results, prev_devices)

        # 审计：记录变更检测
        summary = get_change_summary(self._changes)
        self._audit(audit_log.CAT_SCAN, tr("变更检测"), summary)

        if silent:
            # 静默模式：有严重/警告变更时在状态栏提示
            high = sum(1 for c in self._changes if c.severity == "high")
            warn = sum(1 for c in self._changes if c.severity == "warning")
            if high or warn:
                parts = []
                if high:
                    parts.append(f"{high} 严重")
                if warn:
                    parts.append(f"{warn} 警告")
                self.status_bar.showMessage(
                    f"资产变更：{' · '.join(parts)}（菜单 → 扫描 → 变更检测 查看详情）"
                )
            return

        # 手动触发：弹出报告对话框
        if not self._changes:
            QMessageBox.information(self, tr("变更检测"), tr("与上次扫描相比无任何变更，网络状态稳定。"))
            return
        dlg = ChangeReportDialog(self._changes, parent=self, dark=self.dark_mode)
        dlg.exec_()


    def _show_subnet_utilization(self):
        """弹出子网利用率对话框。"""
        if not self.all_results:
            QMessageBox.information(self, tr("子网利用率"), tr("暂无扫描结果，请先执行扫描。"))
            return
        dlg = SubnetUtilizationDialog(self.all_results, parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _show_audit_log(self):
        """弹出审计日志查看器。"""
        dlg = AuditLogDialog(parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _audit(self, category, action, detail=""):
        """安全地记录一条审计日志：任何异常都不应中断主流程。"""
        try:
            audit_log.log_event(category, action, detail)
        except Exception:
            pass

    def _show_switch_port_mapping(self):
        """弹出交换机端口映射对话框。"""
        self._audit(audit_log.CAT_DEVICE, tr("交换机端口映射"), tr("打开端口映射工具"))
        dlg = SwitchPortDialog(
            scan_results=self.all_results, parent=self, dark=self.dark_mode
        )
        dlg.exec_()

    def _run_mdns_discovery(self):
        """独立触发 mDNS/DNS-SD 组播发现（不依赖扫描），发现结果合并到树与 all_results。"""
        if self.mdns_thread and self.mdns_thread.isRunning():
            self.status_bar.showMessage(tr("mDNS 发现进行中..."))
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
                if services and tr("mDNS") not in r.services:
                    r.services.append(tr("mDNS"))
                    r.service_details.append({
                        "proto": tr("mDNS"), "port": 0, "banner": ", ".join(services)
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
                    tr("mDNS 未发现新设备（可能网内无 mDNS 设备 / 组播端口被占用）")
                )
        except Exception as e:
            sys.stderr.write(f"[ERR] _on_mdns_finished: {e}\n")
            self.status_bar.showMessage(f"mDNS 处理异常: {e}")

    # --- WMI 设备识别 ---
    def _run_wmi_identification(self, targets=None):
        """对目标 Windows 设备执行 WMI 识别。

        targets: IP 列表；为 None 时对全部在线、疑似 Windows 的设备批量识别。
        无凭据时弹窗采集；勾选保存则用 DPAPI 加密持久化到 ipscanner.ini。
        """
        # 1) 凭据采集（仅当内存中尚无有效凭据）
        if not self.wmi_creds.has_creds():
            dlg = WmiCredentialDialog(
                self, saved_username=self.wmi_creds.username,
                saved_domain=self.wmi_creds.domain,
            )
            if dlg.exec_() != QDialog.Accepted:
                return
            user, pwd, domain, save = dlg.get_credentials()
            if not user or not pwd:
                QMessageBox.warning(self, tr("WMI 识别"), tr("用户名和密码不能为空"))
                return
            self.wmi_creds.set(user, pwd, domain)
            if save:
                self.wmi_creds.save_to(self.settings)

        # 2) 确定目标
        online_ips = {r.ip for r in self.all_results if r.status == "online"}
        if targets is None:
            targets = [
                r.ip for r in self.all_results
                if r.status == "online" and (
                    r.os_guess == tr("Windows")
                    or 135 in r.open_ports
                    or 445 in r.open_ports
                )
            ]
            if not targets:
                QMessageBox.information(
                    self, tr("WMI 识别"),
                    tr("没有发现在线且疑似 Windows 的设备（需开放 135/445，或 TTL 推测为 Windows）。\n" "可先用普通扫描发现设备，再对选中设备执行 WMI 识别。")
                )
                return
        else:
            targets = [t for t in targets if t in online_ips]
            if not targets:
                QMessageBox.information(self, tr("WMI 识别"), tr("所选设备不在线，无法识别。"))
                return

        # 3) 后台线程逐台识别
        if self.wmi_thread and self.wmi_thread.isRunning():
            self.status_bar.showMessage(tr("WMI 识别进行中，请稍候..."))
            return
        self.status_bar.showMessage(f"WMI 识别启动：共 {len(targets)} 台设备...")
        self.wmi_thread = WmiThread(targets, self.wmi_creds)
        self.wmi_thread.progress_signal.connect(
            lambda i, t: self.status_bar.showMessage(f"WMI 识别 [{i}/{t}] ...")
        )
        self.wmi_thread.result_signal.connect(self._on_wmi_result)
        self.wmi_thread.finished_signal.connect(self._on_wmi_finished)
        self.wmi_thread.start()

    def _on_wmi_result(self, ip: str, wmi_dict: dict):
        """单台设备 WMI 结果回传：合并信息并刷新表格行。"""
        result = next((r for r in self.all_results if r.ip == ip), None)
        if result is None:
            return
        self._apply_wmi(result, wmi_dict)
        self._upsert_table_row(result)

    def _on_wmi_finished(self, summary: dict):
        ok = summary.get("ok", 0)
        fail = summary.get("fail", 0)
        total = summary.get("total", 0)
        msg = f"WMI 识别完成：{total} 台，成功 {ok} 台"
        if fail:
            msg += f"，失败 {fail} 台（权限/防火墙/非 Windows 等）"
        self._audit(
            audit_log.CAT_DEVICE, tr("WMI 识别"),
            f"共 {total} 台 · 成功 {ok} · 失败 {fail}",
        )
        self.status_bar.showMessage(msg)
        self._update_stats()

    @staticmethod
    def _wmi_device_class(manufacturer: str, model: str) -> str:
        """根据 WMI 厂商/型号粗略归类设备类别（仅作归类兜底，逻辑在 engine 层）。"""
        return wmi_device_class(manufacturer, model)

    def _apply_wmi(self, result: ScanResult, d: dict):
        """把 WMI 查询结果合并进 ScanResult，并用权威信息补全设备指纹。"""
        merge_wmi(result, d)

    # --- NetBIOS 轻量识别（零凭据、不需管理员，作为 WMI 的轻量补充）---

    def _run_netbios_identification(self, targets=None):
        """对目标设备执行 NetBIOS 轻量识别（UDP/137 NBSTAT，零凭据、不需管理员）。

        targets: IP 列表；为 None 时对全部在线、疑似 Windows 的设备批量识别。
        无需凭据，直接启动后台线程逐台查询。
        """
        online_ips = {r.ip for r in self.all_results if r.status == "online"}
        if targets is None:
            targets = [
                r.ip for r in self.all_results
                if r.status == "online" and (
                    r.os_guess == tr("Windows")
                    or 135 in r.open_ports
                    or 445 in r.open_ports
                )
            ]
            if not targets:
                QMessageBox.information(
                    self, tr("NetBIOS 识别"),
                    tr("没有发现在线且疑似 Windows 的设备（需开放 135/445，或 TTL 推测为 Windows）。\n" "可先扫描发现设备，再对选中设备执行 NetBIOS 识别。")
                )
                return
        else:
            targets = [t for t in targets if t in online_ips]
            if not targets:
                QMessageBox.information(self, tr("NetBIOS 识别"), tr("所选设备不在线，无法识别。"))
                return

        if self.netbios_thread and self.netbios_thread.isRunning():
            self.status_bar.showMessage(tr("NetBIOS 识别进行中，请稍候..."))
            return
        self.status_bar.showMessage(f"NetBIOS 识别启动：共 {len(targets)} 台设备...")
        self.netbios_thread = NetbiosThread(targets, timeout=1.5)
        self.netbios_thread.progress_signal.connect(
            lambda i, t: self.status_bar.showMessage(f"NetBIOS 识别 [{i}/{t}] ...")
        )
        self.netbios_thread.result_signal.connect(self._on_netbios_result)
        self.netbios_thread.finished_signal.connect(self._on_netbios_finished)
        self.netbios_thread.start()

    def _on_netbios_result(self, ip: str, d: dict):
        """单台设备 NetBIOS 结果回传：合并信息并刷新表格行。"""
        result = next((r for r in self.all_results if r.ip == ip), None)
        if result is None:
            return
        self._apply_netbios(result, d)
        self._upsert_table_row(result)

    def _on_netbios_finished(self, summary: dict):
        ok = summary.get("ok", 0)
        fail = summary.get("fail", 0)
        total = summary.get("total", 0)
        msg = f"NetBIOS 识别完成：{total} 台，成功 {ok} 台"
        if fail:
            msg += f"，失败 {fail} 台（防火墙/非 Windows/未开放 137 等）"
        self._audit(
            audit_log.CAT_DEVICE, tr("NetBIOS 识别"),
            f"共 {total} 台 · 成功 {ok} · 失败 {fail}",
        )
        self.status_bar.showMessage(msg)
        self._update_stats()

    def _apply_netbios(self, result: ScanResult, d: dict):
        """把 NetBIOS 查询结果合并进 ScanResult，并用权威信息补全设备指纹。"""
        merge_netbios(result, d)



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
                self, tr("选择目标"), f"请输入要执行「{tool.upper()}」的目标 IP 或主机名:"
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
                self, tr("SSH 连接"), tr("请输入登录用户名:"), text=getpass.getuser()
            )
            if not ok or not user.strip():
                return
            if not shutil.which("ssh"):
                QMessageBox.warning(
                    self, tr("未找到 ssh"),
                    tr("系统未安装 OpenSSH 客户端（ssh.exe）。\n" "请在“设置 → 应用 → 可选功能”中启用“OpenSSH 客户端”后重试。")
                )
                return
            cmd = f"ssh {user.strip()}@{target}"
        elif tool == "rdp":
            try:
                subprocess.Popen(["mstsc.exe", f"/v:{target}"])
                self._audit(audit_log.CAT_DEVICE, tr("启动网络工具"), f"RDP · 目标 {target}")
                self.status_bar.showMessage(f"已启动 RDP: {target}")
            except Exception as e:
                QMessageBox.warning(self, tr("启动失败"), f"无法启动远程桌面: {e}")
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
            self._audit(audit_log.CAT_DEVICE, tr("启动网络工具"), f"{tool.upper()} · 目标 {target}")
            self.status_bar.showMessage(f"已启动 {tool.upper()}: {target}")
        except Exception as e:
            QMessageBox.warning(self, tr("启动失败"), f"无法启动 {tool}: {e}")

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
                self, tr("远程") + (tr("关机") if action == "shutdown" else tr("重启")),
                tr("请输入目标 IP 或主机名:")
            )
            if not ok or not text.strip():
                return
            target = text.strip()

        _verb = tr("关机") if action == "shutdown" else tr("重启")
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
                encoding=_enc, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                self._audit(
                    audit_log.CAT_DEVICE, f"远程{_verb}",
                    f"目标 {target} · 指令已发送",
                )
                QMessageBox.information(
                    self, tr("指令已发送"),
                    f"已向 {target} 发送远程{_verb}指令。"
                )
                self.status_bar.showMessage(f"已发送远程{_verb}: {target}")
            else:
                _err = (proc.stderr or proc.stdout or "").strip()
                self._audit(
                    audit_log.CAT_DEVICE, f"远程{_verb}失败",
                    f"目标 {target} · 退出码 {proc.returncode}",
                )
                QMessageBox.warning(
                    self, tr("远程") + _verb + tr("失败"),
                    f"向 {target} 发送{_verb}指令失败 (退出码 {proc.returncode})。\n"
                    + (_err + "\n\n" if _err else "")
                    + tr("常见原因：目标未授权、网络不可达、缺少权限，\n")
                    + tr("或本地未以管理员身份运行本程序。")
                )
        except Exception as e:
            QMessageBox.warning(
                self, tr("远程") + _verb + tr("失败"),
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
            text += tr("\n(未获取到 sysDescr)")
        QMessageBox.information(self, tr("SNMP 设备信息"), text)

    def _open_service(self, proto, ip):
        """根据协议打开浏览器 / 远程桌面。"""
        if proto == tr("HTTP"):
            QDesktopServices.openUrl(QUrl(f"http://{ip}"))
        elif proto == tr("HTTPS"):
            QDesktopServices.openUrl(QUrl(f"https://{ip}"))
        elif proto == tr("FTP"):
            QDesktopServices.openUrl(QUrl(f"ftp://{ip}"))
        elif proto == tr("RDP"):
            if not QProcess.startDetached("mstsc", [f"/v:{ip}"]):
                QMessageBox.information(
                    self, tr("远程桌面"),
                    f"未能自动启动远程桌面连接。\n请手动运行：mstsc /v:{ip}"
                )

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
                "device_class": r.device_class or "",
                "os_guess": r.os_guess or "",
                "open_ports": ",".join(str(p) for p in (r.open_ports or [])),
                "location": r.location or "",
                "user": r.user or "",
                "remark": r.remark or "",
                "wmi_identified": r.wmi_identified,
                "wmi_manufacturer": r.wmi_manufacturer or "",
                "wmi_model": r.wmi_model or "",
                "wmi_serial": r.wmi_serial or "",
                "wmi_os": r.wmi_os or "",
                "wmi_user": r.wmi_user or "",
                "wmi_domain": r.wmi_domain or "",
                "netbios_identified": r.netbios_identified,
                "netbios_name": r.netbios_name or "",
                "netbios_workgroup": r.netbios_workgroup or "",
                "netbios_user": r.netbios_user or "",
                "netbios_mac": r.netbios_mac or "",
            })
        return {"time": time.time(), "devices": devices}

    def _load_history(self) -> list:
        try:
            return history_store.load_all(self.history_db)
        except Exception:
            return []

    def _save_snapshot(self, results, max_keep: int = 20):
        try:
            snap = self._build_snapshot(results)
            history_store.save_snapshot(
                snap["devices"], ts=snap["time"], max_keep=max_keep,
                db_path=self.history_db,
            )
        except Exception as e:
            print(tr("保存历史快照失败:"), e)

    def _open_history_compare(self):
        dlg = HistoryCompareDialog(self, db_path=self.history_db)
        dlg.exec_()

    def _open_history_query(self):
        dlg = HistoryQueryDialog(self, db_path=self.history_db)
        dlg.exec_()

    def _open_topology(self):
        if not self.all_results:
            QMessageBox.information(self, tr("拓扑视图"), tr("请先完成一次扫描，再查看拓扑。"))
            return
        gw_ip = _detect_gateway()
        dlg = TopologyDialog(self.all_results, gw_ip, self.dark_mode, self)
        dlg.exec_()

    # --- 右键菜单 ---

    def _wake_on_lan(self, mac: str):
        """发送 Wake-on-LAN 魔术包 (6×0xFF + 16×MAC) 到广播地址。"""
        import socket as sock
        mac_clean = mac.replace("-", "").replace(":", "").replace(".", "").strip().upper()
        if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
            QMessageBox.warning(self, tr("WoL 唤醒"), f"MAC 地址格式无效，无法唤醒：\n{mac}")
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
                self, tr("WoL 唤醒"),
                f"已向 {mac} 发送唤醒魔术包。\n\n请确保目标设备已开启 WOL：\n"
                + tr("• BIOS/UEFI 中启用 Wake on LAN\n"
                     "• 网卡属性中允许「允许此设备唤醒计算机」")
            )
        except Exception as e:
            QMessageBox.warning(self, tr("WoL 唤醒"), f"发送失败：{e}")

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
            self._audit(
                audit_log.CAT_LIBRARY, tr("新增设备"),
                f"IP {ip or '—'} · MAC {mac or '—'} · 地址库共 {self.library.count()} 条",
            )
            self.status_bar.showMessage(tr("已加入地址库"))

    def _edit_library_entry(self, device_id: int):
        dlg = DeviceEditDialog(self.library, parent=self, device_id=device_id)
        if dlg.exec_() == QDialog.Accepted:
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self._audit(audit_log.CAT_LIBRARY, tr("编辑设备"), f"设备 #{device_id}")

    def _delete_library_entry(self, device_id: int):
        dev = self.library.get_by_id(device_id)
        if not dev:
            return
        label = dev.get("mac") or dev.get("ip") or f"#{device_id}"
        reply = QMessageBox.question(
            self, tr("确认删除"),
            f"确定从地址库删除该设备吗？\n\n{label}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.library.delete(device_id)
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self._audit(
                audit_log.CAT_LIBRARY, tr("删除设备"),
                f"{label} · 地址库余 {self.library.count()} 条",
            )
            self.status_bar.showMessage(tr("已从地址库删除"))

    # --- Excel ---

    def _import_excel(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, tr("选择 Excel 文件（可多选，自动合并进地址库）"), "",
            tr("Excel 文件 (*.xlsx *.xls);;所有文件 (*.*)")
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

        # 审计：记录地址库导入
        if ok_files:
            self._audit(
                audit_log.CAT_LIBRARY, tr("导入地址库"),
                f"合并 {ok_files} 个文件 · 地址库共 {self.library.count()} 条"
                + (f" · 失败 {len(errs)} 个" if errs else ""),
            )

        # 若已有扫描结果，按新地址库重新匹配标注
        if self.all_results:
            self._refresh_matches_from_library()

        if errs:
            QMessageBox.warning(self, tr("部分文件导入失败"), "\n".join(errs))
        elif ok_files:
            QMessageBox.information(
                self, tr("导入成功"),
                f"已合并 {ok_files} 个文件到地址库，共 {self.library.count()} 条。\n"
                f"扫描联网设备后将自动按 MAC 匹配。"
            )

    def _refresh_library_label(self):
        n = self.library.count()
        if n > 0:
            self.excel_label.setText(f"地址库: {n} 条")
            self.excel_label.setStyleSheet("color: #2E7D32; font-size: 11px; font-weight: bold;")
        else:
            self.excel_label.setText(tr("地址库: 空"))
            self.excel_label.setStyleSheet("color: #888888; font-size: 11px;")

    def _export_library(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        file_path, _ = QFileDialog.getSaveFileName(
            self, tr("导出地址库"), default_name, tr("Excel 文件 (*.xlsx)")
        )
        if not file_path:
            return
        success, msg = self.library.export_to_excel(file_path)
        if success:
            self._audit(
                audit_log.CAT_EXPORT, tr("导出地址库"),
                f"{self.library.count()} 条 · {os.path.basename(file_path)}",
            )
            self.status_bar.showMessage(msg)
            QMessageBox.information(self, tr("导出成功"), msg)
        else:
            QMessageBox.warning(self, tr("导出失败"), msg)

    def _generate_template(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, tr("保存 Excel 模板"), tr("设备清单模板.xlsx"),
            tr("Excel 文件 (*.xlsx)")
        )
        if not file_path:
            return
        success, msg = create_template(file_path)
        if success:
            self._audit(
                audit_log.CAT_EXPORT, tr("生成 Excel 模板"),
                os.path.basename(file_path),
            )
            QMessageBox.information(self, tr("成功"), msg)
        else:
            QMessageBox.warning(self, tr("失败"), msg)

    def _export_results(self):
        if not self.all_results:
            QMessageBox.warning(self, tr("提示"), tr("没有可导出的结果"))
            return

        default_name = f"扫描结果_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, tr("导出扫描结果"), default_name,
            tr("Excel 文件 (*.xlsx);;CSV 文件 (*.csv);;HTML 文件 (*.html);;JSON 文件 (*.json)")
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
            _fmt = "CSV"
        elif path.lower().endswith(".html"):
            success, msg = export_html(self.all_results, path)
            _fmt = "HTML"
        elif path.lower().endswith(".json"):
            success, msg = export_json(self.all_results, path)
            _fmt = "JSON"
        else:
            success, msg = export_results(self.all_results, path)
            _fmt = "Excel"

        if success:
            self._audit(
                audit_log.CAT_EXPORT, tr("导出扫描结果"),
                f"{_fmt} · {len(self.all_results)} 条 · {os.path.basename(path)}",
            )
            self.status_bar.showMessage(msg)
            QMessageBox.information(self, tr("导出成功"), msg)
        else:
            QMessageBox.warning(self, tr("导出失败"), msg)

    def _print_results(self):
        """将当前扫描结果表格打印 / 导出为 PDF（先弹打印预览对话框）。"""
        if self.table.topLevelItemCount() == 0:
            QMessageBox.information(self, tr("提示"), tr("当前没有可打印的扫描结果，请先执行扫描。"))
            return

        # 仅取可见列（服务列默认隐藏，跳过），只打印设备顶层行
        cols = [c for c in range(self.table.columnCount())
                if not self.table.isColumnHidden(c)]
        headers = [self.table.headerItem().text(c) for c in cols]
        rows = []
        for r in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(r)
            if item.isHidden():   # 跳过被筛选隐藏的行（如"仅在线"下的离线设备），实现所见即所得
                continue
            rows.append([item.text(c) for c in cols])

        doc = QTextDocument()
        doc.setHtml(self._build_results_print_html(headers, rows))

        printer = QPrinter(QPrinter.HighResolution)
        printer.setPageSize(QPageSize(QPageSize.A4))
        printer.setPageOrientation(QPageLayout.Landscape)

        preview = QPrintPreviewDialog(printer, self)
        preview.setWindowTitle(tr("打印预览 - 扫描结果"))
        preview.paintRequested.connect(lambda p: doc.print_(p))
        preview.exec_()

    @staticmethod
    def _build_results_print_html(headers, rows):
        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = ""
        for i, row in enumerate(rows):
            bg = "#F2F2F2" if i % 2 else "#FFFFFF"
            tds = "".join(f"<td>{esc(c)}</td>" for c in row)
            body += f"<tr style='background:{bg};'>{tds}</tr>"
        title = f"局域网扫描结果 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        return (
            "<html><head><meta charset='utf-8'>"
            "<style>"
            "table{border-collapse:collapse;width:100%;font-size:9pt;"
            "font-family:'Microsoft YaHei',SimSun,sans-serif;}"
            "th,td{border:1px solid #999;padding:3px 5px;text-align:left;}"
            "th{background:#2C3E50;color:#FFFFFF;}"
            "</style></head><body>"
            f"<h3 style='margin:0 0 6px 0;'>{esc(title)}</h3>"
            "<table>" + f"<tr>{th}</tr>" + body + "</table></body></html>"
        )

    # --- 关于 ---

    def _show_about(self):
        QMessageBox.about(self, tr("关于"), (
            tr("<h3>局域网终端扫描工具</h3>" "<p>版本 1.0</p>")
            + tr("<p>功能：</p>") + "<ul>"
            + tr("<li>支持 CIDR / IP 范围 / 跨网段扫描</li>"
                 "<li>ICMP Ping + ARP 主动探测（发现禁 Ping 主机）+ 主机名 + 端口探测</li>")
            + tr("<li>端口探测方式：TCP 全连接 / SYN 半开 / UDP（可切换）</li>"
                 "<li>共享文件夹探测（SMB 共享枚举）</li>")
            + tr("<li>Excel 设备信息导入与自动匹配</li>"
                 "<li>结果导出为 Excel / CSV / HTML / JSON</li>")
            + tr("<li>mDNS 设备发现（组播发现打印机 / NAS / Apple 设备 / IoT 等）</li>"
                 "<li>操作系统探测（TTL 推测 + 服务 banner 提取版本）</li>")
            + tr("<li>设备指纹深度（端口/服务/mDNS/UPnP/SNMP 综合推断设备类型与型号）</li>"
                 "<li>内置网络工具：Ping / Tracert / Telnet / SSH / RDP / 命令提示符 / 远程关机 / 远程重启</li>")
            + "</ul>" + tr("<p style='color: #94A3B8;'>基于 PyQt5 开发</p>")
        ))

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(3000)
        self._save_settings()
        event.accept()
