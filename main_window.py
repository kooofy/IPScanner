# -*- coding: utf-8 -*-
import os
from app_paths import data_dir, resource_dir
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QTreeWidget, QHeaderView,
    QProgressBar, QMessageBox, QSpinBox, QComboBox, QAction,
    QAbstractItemView, QStyle, QTextEdit, QFrame, QActionGroup,
)
from PyQt5.QtCore import Qt, QSize, QTimer, QSettings, QByteArray
from PyQt5.QtGui import QColor, QIcon, QPixmap, QKeySequence
from scanner import parse_ip_range, PROTOCOL_PORTS, WmiCredentialStore, SCAN_LEVEL_LABELS
from mac_library import MacLibrary
import history_store

from ui_icons import _build_dark_palette
from conflict_detector import SEVERITY_HIGH, SEVERITY_WARNING

from styles import STYLE_SHEET, DARK_STYLE_SHEET, _gray_icon, _make_tool_icon, _make_pause_icon
from main_window_tree import TreeMixin
from i18n import tr
from scan_mixin import ScanMixin
from export_mixin import ExportMixin
from history_mixin import HistoryMixin
from library_mixin import LibraryMixin
from network_tool_mixin import NetworkToolMixin
from oui_mixin import OuiMixin

class MainWindow(TreeMixin, ScanMixin, ExportMixin, HistoryMixin, LibraryMixin, NetworkToolMixin, OuiMixin, QMainWindow):
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

        act_oui_update = QAction(tr("检查 OUI 更新..."), self)
        act_oui_update.setToolTip(tr("从 IEEE 官网下载最新 MAC 厂商数据库"))
        act_oui_update.triggered.connect(self._update_oui_db)
        help_menu.addAction(act_oui_update)

        help_menu.addSeparator()

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
