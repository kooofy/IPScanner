# -*- coding: utf-8 -*-
import os
import app_logging
from app_paths import data_dir, resource_dir, data_dir_label, data_dir_source
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QTreeWidget, QHeaderView,
    QSpinBox, QAction, QAbstractItemView, QStyle, QTextEdit, QFrame, QActionGroup,
    QSplitter, QStackedWidget, QToolButton, QMenu, QInputDialog, QButtonGroup,
)
from PyQt5.QtCore import Qt, QSize, QTimer, QSettings, QByteArray
from PyQt5.QtGui import QColor, QIcon, QPixmap, QKeySequence
from scanner import (
    PROTOCOL_PORTS, WmiCredentialStore, SnmpV3CredentialStore,
    scan_level_label, service_label, get_ports_for_level,
    count_ip_range, MAX_IPS_PER_RANGE, MAX_IPS_TOTAL,
)
from scanner import throttle
from mac_library import MacLibrary
import history_store
import trend_store

from ui_icons import (
    _build_dark_palette, _gray_icon, _make_tool_icon, _make_pause_icon,
)
from version import __version__
from conflict_detector import SEVERITY_HIGH, SEVERITY_WARNING
import ui_logic
from arp_mapper import GATEWAY_AUTO

from styles import STYLE_SHEET, DARK_STYLE_SHEET
from theme_tokens import token
from design_tokens import (
    DEFAULT_DENSITY, DENSITIES, density_label,
)
from main_window_tree import TreeMixin
from detail_panel import DeviceDetailPanel
from empty_state import EmptyStatePanel
from overview import OverviewPanel
from filter_bar import FilterChipBar, FilterChipScroll, FILTERS
from scan_status import ScanStatusBar
from favorites import FavoriteStore
from scan_presets import ScanPresetStore, PresetError, validate_name
import system_theme
from ui_msg import msg_about, msg_consent, msg_info, msg_warn
from i18n import current_lang, tr
from scan_mixin import ScanMixin
from export_mixin import ExportMixin
from history_mixin import HistoryMixin
from library_mixin import LibraryMixin
from network_tool_mixin import NetworkToolMixin
from oui_mixin import OuiMixin
from cve_status_mixin import CveStatusMixin
from watch_mixin import WatchMixin

#: 列索引 → 规范中文名（顺序即表格列序，勿改）。
COLUMN_LABELS = (
    "IP地址", "状态", "主机名", "MAC地址", "制造商", "位置", "使用者",
    "响应时间(ms)", "开放端口", "服务", "操作系统", "设备类型", "备注",
    "风险",
)

#: 列预设：key → (规范中文标签, 可见列索引)。
#:
#: 标签存**规范中文**、构建菜单时才 `tr()` —— 模块级调用 tr() 会因语言包
#: 尚未加载而被冻结成中文（见 i18n 的惰性翻译约定）。
#:
#: 14 列同时铺开在 1366 宽的屏幕上必然横向滚动，而"哪几列该一起看"是有
#: 场景答案的：巡检看连通性、资产看归属、安全看暴露面。预设把这层知识
#: 固化下来，用户不必自己拼 14 个 checkbox。
COLUMN_PRESETS = (
    ("inspect", "巡检", (0, 1, 2, 3, 4, 7)),
    ("asset", "资产", (0, 1, 2, 3, 4, 5, 6, 11, 12)),
    # 「安全」= 暴露面视角：端口 / 服务 / 系统 / **风险**（P3-4）。
    # 风险列必须跟着这一档，否则"看暴露面"的预设里恰恰缺了那句结论。
    ("security", "安全", (0, 1, 8, 9, 10, 13)),
    ("all", "全量", tuple(range(len(COLUMN_LABELS)))),
)

#: 列布局版本。**改动默认列布局（列序 / 默认可见列 / 默认列宽）时必须 +1。**
#:
#: `table/header_state` 是按**像素**持久化的整份表头状态（列宽、列序、隐藏列、
#: 排序指示），载入时只在版本号一致时才恢复。版本号不跟着变的话，老用户会永远
#: 沿用自己 ini 里那份旧状态 —— 新装的默认值对他们**完全无效**。P0-3 就是这么
#: 来的：新装 6 列共 730px 放得下，老配置 10 列共 1264px 在 1024 宽的窗口里溢出
#: 262px。代价是用户的自定义列宽会被重置一次，值得。
#:
#: v2=IP/序号/状态…; v3=新增「设备类型」列（设备指纹深度）;
#: v4=新增「巡检」默认列宽预设;
#: v5=新增「风险」列（P3-4），并把它加进「安全」列预设。
#:
#: ⚠️ 列宽还跟**语言**有关（见 `_COLUMN_WIDTH_OVERRIDES`），所以载入时除了版本号
#: 还要比对 `table/header_lang`。语言变化**不需要** bump 版本号 —— 单独比对语言键
#: 就够了，这样不会让所有老用户再被重置一次列布局。
CURRENT_LAYOUT_VER = 5

#: 默认列宽基线（中文）。索引对应 COLUMN_LABELS。
_BASE_COLUMN_WIDTHS = {
    0: 130, 1: 78, 2: 140, 3: 220, 4: 100, 5: 120, 6: 90, 7: 90,
    8: 160, 9: 200, 10: 150, 11: 120, 12: 180,
    # 13「风险」：单元格是「高 65」这种短文本，78px 够放下中英文两档。
    13: 78,
}

#: 按语言覆盖的列宽 —— 只列**需要变**的列，其余沿用基线。
#:
#: 为什么：这些列的**表头或单元格文本会随语言变化**，而列宽是按像素持久化的。
#: 实测口径是 `table.sizeHintForColumn()`（含图标 18px 与 QSS `padding: 4px 6px`），
#: **不是** `QFontMetrics` 的文本宽度：
#:
#:   col 1  状态 / Status         单元格「在线」68px → `Online` **82px**
#:                                （默认 78px 放不下 → 英文界面显示 `Onl…`）
#:   col 4  制造商 / Manufacturer  表头 72px → **131px**
#:   col 7  响应时间 / Response Time (ms)  表头 121px → **178px**
#:   col 8  开放端口 / Open Ports  单元格 162px → 175px
#:   col 9  服务 / Services        单元格 192px → 215px
#:   col 10 操作系统 / Operating System  单元格 176px → 200px
#:
#: 数值来自真实 MainWindow 的多行样本实测（`probe_widths`），并留了余量。
#: ⚠️ 这些宽度**不能用单测断言绝对像素** —— headless（`QT_QPA_PLATFORM=offscreen`）
#: 下 Qt 用的是回退字体，宽度明显更大（实测英文状态列 native 82px / offscreen 120px），
#: 断言会假挂。所以 `tests/test_column_widths.py` 只钉「机制」与「表本身」，
#: 「像素到底够不够」由实测探针负责。
_COLUMN_WIDTH_OVERRIDES = {
    "en-US": {1: 92, 4: 140, 7: 190, 8: 175, 9: 215, 10: 200},
}


def column_widths_for(lang: str) -> dict:
    """该语言下的默认列宽（基线 + 语言覆盖）。"""
    widths = dict(_BASE_COLUMN_WIDTHS)
    widths.update(_COLUMN_WIDTH_OVERRIDES.get(lang, {}))
    return widths


#: 主题模式：key → 规范中文标签。
#:
#: 与列预设同理，标签存规范中文、构建菜单时才 tr()。
#:
#: 为什么把「跟随系统」放第一位并作为新装默认：Windows 10/11 的
#: 个性化设置是用户表达明暗偏好的标准入口，工具理应尊重它；而旧版的
#: 「18:00 后自动转深色」是个拍脑袋的猜测，做夜间运维的人白天也想深色。
#: 所以跟随系统升为默认，按时间降级为可选项（见 docs/reviews/UI_REVIEW.md P3-3）。
#:
#: key 复用 system_theme 的常量，避免两处各写一份字符串字面量。
THEME_MODES = (
    (system_theme.MODE_SYSTEM, "跟随系统"),
    (system_theme.MODE_LIGHT, "浅色"),
    (system_theme.MODE_DARK, "深色"),
    (system_theme.MODE_TIME, "按时间自动切换（18:00–06:00 深色）"),
)

#: 主题模式默认值（新装 / 配置损坏时）
DEFAULT_THEME_MODE = system_theme.DEFAULT_MODE

#: 结果视图模式：key → 规范中文标签（docs/reviews/UI_REVIEW.md P3-2）。
#:
#: 「列表」是原来的表格视图，「概览」是本次新增的仪表盘。两者共用同一份
#: 扫描结果，切换不重新扫描、也不改变筛选条件。
VIEW_MODES = (
    ("list", "列表"),
    ("overview", "概览"),
)

#: 结果视图默认值
DEFAULT_VIEW_MODE = "list"


def _vsep() -> QFrame:
    """工具栏分组用的竖直分隔线（颜色走 QSS，不在此硬编码）。"""
    sep = QFrame()
    sep.setObjectName("toolSep")
    sep.setFrameShape(QFrame.VLine)
    sep.setFixedWidth(1)
    return sep


class MainWindow(TreeMixin, ScanMixin, ExportMixin, HistoryMixin, LibraryMixin,
                 NetworkToolMixin, OuiMixin, CveStatusMixin, WatchMixin,
                 QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(tr("局域网终端扫描工具 — IP Scanner"))
        # 1200x750 在 1366x768 的笔记本上会顶满整屏（连任务栏都盖住），
        # 降到 1024x640；列多时靠横向滚动兜底，而不是强迫用户换屏。
        self.setMinimumSize(1024, 640)
        self.resize(1300, 850)

        self.library = MacLibrary()  # 持久 MAC 地址库 (SQLite)
        self.selected_protocols = list(PROTOCOL_PORTS.keys())  # HTTP, HTTPS, FTP, RDP 默认开启
        self.tcp_scan_mode = "connect"  # 端口探测方式: connect / syn / udp
        self.scan_level = "quick"  # 扫描级别: quick / standard / all（默认快速，向后兼容）
        # 扫描礼貌档（v2.1 §2.4 GUI 露出）：`throttle.POLICY_NAMES` 里的规范名。
        # 默认 fast = 不额外设限，与改造前逐字节等价；由 scan/throttle 持久化。
        self.throttle_policy = throttle.DEFAULT_POLICY
        self.mdns_discovery = True      # 扫描末尾做 mDNS 组播发现
        self.mdns_thread = None
        self.scan_thread = None
        self.all_results: list = []
        self.ip_range_items: list = []
        self._ip_item_map: dict = {}
        self._result_map: dict = {}      # {ip: ScanResult} 供详情面板 O(1) 取回
        self.dark_mode = False  # 解析后的实际主题（所有取色方只看这个）
        self.theme_mode = DEFAULT_THEME_MODE  # 用户选择：system/light/dark/time
        self.auto_time = False  # 兼容旧字段：是否处于「按时间」模式
        self.view_mode = DEFAULT_VIEW_MODE  # 结果视图：list / overview
        self._conflicts: list = []       # 最近一次冲突检测结果
        self._conflict_ips: dict = {}    # {ip: [conflict_type, ...]} 用于树视图标记
        self._changes: list = []         # 最近一次资产变更检测结果
        self._change_map: dict = {}      # {ip: [变更类型, ...]} 供行内角标与「变更」筛选
        self._timeline_cache: dict = {}  # {设备键: 历史轨迹} 写入新快照后失效
        self._exposure_cache: dict = {}  # {设备键: 端口暴露行} 同一时刻失效
        # {设备键: 台账行}（v2.3 §3.4）—— 除写入新快照外，用户**编辑台账**后也要
        # 单独失效（见 `library_mixin._edit_asset`）。
        self._asset_cache: dict = {}

        # 配置持久化 (QSettings, Ini 格式, 存于项目目录便于查看/重置)
        self.settings = QSettings(
            os.path.join(data_dir(), "ipscanner.ini"),
            QSettings.IniFormat
        )

        # 设备收藏（docs/reviews/UI_REVIEW.md P1-3）：轻量"常看这几台"标记，与 MAC 地址库
        # （资产台账）职责不同，故分开存储。
        self.favorites = FavoriteStore(self.settings)
        # 命名扫描预设：网段 + 级别 + 协议集 + 探测方式 的组合
        self.scan_presets = ScanPresetStore(self.settings)

        # WMI 识别凭据：从配置解密载入（DPAPI，仅本机当前用户可读）
        self.wmi_creds = WmiCredentialStore()
        self.wmi_creds.load_from(self.settings)
        self.wmi_thread = None
        self.netbios_thread = None

        # SNMPv3 USM 用户：口令同样经 DPAPI 加密落盘；未配置时扫描走 v2c 团体字
        self.snmp_v3_creds = SnmpV3CredentialStore()
        self.snmp_v3_creds.load_from(self.settings)

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

        # 持续发现的定时器/线程状态。**必须在 `_load_settings()` 之前**：
        # 信号已经接上，载入时 `setChecked(True)` 会立刻触发 `_on_watch_toggled`，
        # 那时定时器与 watcher 字段必须已经存在。
        self._init_watch()

        # 载入持久化配置 (主题/扫描参数/网段/窗口几何/列布局)
        self._load_settings()

        # 自动检测本机网段 (仅预填输入框，不影响已持久化的网段列表)
        self._auto_detect_subnet()
        # 载入地址库计数
        self._refresh_library_label()
        # CVE 快照状态徽标（v2.1 §2.3 GUI 露出）：启动时读一次快照健康度。
        # 放在 `_load_settings()` 之后 —— 主题已解析，徽标取色才对得上。
        self._refresh_cve_badge()

        # 启动提示（合并为一条状态栏消息）：
        # 1) 数据目录回退 —— exe 目录不可写（如装在 Program Files）时数据改存用户目录
        # 2) 旧配置中被丢弃的超限网段
        _notices = []
        _src = data_dir_source()
        if _src in ("user", "temp"):
            _msg = tr("程序目录不可写，数据已改存：{path}").format(path=data_dir())
            _notices.append(_msg)
            app_logging.get_logger(__name__).warning(
                "程序目录不可写，数据目录回退到 %s (source=%s)", data_dir(), _src
            )
        if getattr(self, "_dropped_ranges", 0):
            _notices.append(
                tr("已忽略 {n} 个无效或超出规模上限的历史网段").format(
                    n=self._dropped_ranges)
            )
        if _notices:
            self.status_bar.showMessage(" | ".join(_notices), 15000)

        # 应用初始主题：按用户选择的模式解析出实际明暗
        self.dark_mode = self._resolve_dark()
        self._apply_theme(self.dark_mode)
        # 主题巡检：每分钟一次。既用于「按时间」模式的跨阈值切换，也用于
        # 「跟随系统」模式 —— Qt5 在 Windows 上并不总会投递主题变更事件，
        # 轮询是跨平台最省心的兜底（代价是 1 分钟粒度，用户可接受）。
        self._theme_timer = QTimer(self)
        self._theme_timer.setInterval(60 * 1000)
        self._theme_timer.timeout.connect(self._check_theme_change)
        self._theme_timer.start()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(2)
        main_layout.setContentsMargins(4, 4, 4, 4)

        # ── 工具栏 Row 1：按语义分组的动作区（docs/reviews/UI_REVIEW.md P1-1）──
        #
        # 原实现是 6 个纯图标按钮平铺，三个真实问题：
        #   1. 自绘图标语义模糊 —— "ip" 与 "c" 两个绿方块不 hover 分不清；
        #   2. 动作语义混杂 —— "展开/收起"是视图操作，却和"扫描"并排；
        #   3. `setFixedSize(100, 36)` 写死像素，高 DPI 下与
        #      AA_EnableHighDpiScaling 冲突，控件会错位/糊。
        # 现在：按钮一律「图标 + 文字」，按语义分两组，用竖线隔开，
        # 展开/收起移交「查看」菜单（那里本就有 Ctrl++ / Ctrl+- 两个动作）。
        tb1 = QHBoxLayout()
        tb1.setSpacing(6)
        tb1.setContentsMargins(2, 2, 2, 2)

        _ICON_SZ = 16
        _icon_color = token("tool_icon", self.dark_mode)

        _play_pm = QPixmap(os.path.join(resource_dir(), "assets", "play_icon.png")).scaled(
            22, 22, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.scan_btn = QPushButton(tr("扫描"))
        self.scan_btn.setIcon(QIcon(_play_pm))
        self.scan_btn.setIconSize(QSize(22, 22))
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.setToolTip(tr("开始扫描 (F5)"))
        self.scan_btn.setMinimumSize(96, 32)

        self.stop_btn = QPushButton(tr("停止"))
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setIcon(_make_pause_icon(_icon_color, _ICON_SZ))
        self.stop_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip(tr("停止扫描 (Esc)"))
        self.stop_btn.setMinimumSize(84, 32)

        tb1.addWidget(self.scan_btn)
        tb1.addWidget(self.stop_btn)
        tb1.addWidget(_vsep())

        self.local_subnet_btn = QPushButton(tr("本机子网"))
        self.local_subnet_btn.setObjectName("toolBtnGreen")
        self.local_subnet_btn.setIcon(_make_tool_icon("ip", _icon_color, _ICON_SZ))
        self.local_subnet_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.local_subnet_btn.setToolTip(tr("扫描本机所在子网"))
        self.local_subnet_btn.setMinimumHeight(32)

        self.c_subnet_btn = QPushButton(tr("C 类网段"))
        self.c_subnet_btn.setObjectName("toolBtnGreen")
        self.c_subnet_btn.setIcon(_make_tool_icon("c", _icon_color, _ICON_SZ))
        self.c_subnet_btn.setIconSize(QSize(_ICON_SZ, _ICON_SZ))
        self.c_subnet_btn.setToolTip(tr("扫描 C 类子网"))
        self.c_subnet_btn.setMinimumHeight(32)

        tb1.addWidget(self.local_subnet_btn)
        tb1.addWidget(self.c_subnet_btn)

        # 扫描预设（docs/reviews/UI_REVIEW.md P1-3）：网段 + 级别 + 协议集 的命名组合。
        # 网段虽然会持久化，但只有一份 —— 今天扫办公网、明天扫机房就得来回改。
        tb1.addWidget(_vsep())
        self.preset_btn = QToolButton()
        self.preset_btn.setObjectName("presetBtn")
        self.preset_btn.setText(tr("预设"))
        self.preset_btn.setToolTip(tr("保存 / 切换扫描预设（网段 + 级别 + 协议）"))
        self.preset_btn.setPopupMode(QToolButton.InstantPopup)
        self.preset_btn.setMinimumHeight(32)
        self._preset_menu = QMenu(self)
        self.preset_btn.setMenu(self._preset_menu)
        tb1.addWidget(self.preset_btn)

        tb1.addStretch()  # 动作按钮压左，右侧留白

        # IP 范围输入
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText(
            tr("例如: 192.168.1.0/24, 192.168.2.0/24 (一行可写多个, 用逗号/空格/换行分隔)")
        )
        self.range_input.setMinimumWidth(280)
        self.range_input.returnPressed.connect(self._add_ip_range)

        # 已添加网段计数 (已移到底部状态栏，工具栏上不再显示)
        self.range_list_label = QLabel("")
        self.range_list_label.setObjectName("rangeCountLabel")
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
        # 用 min/max 而非 setFixedWidth：固定像素在高 DPI 下不会随字体放大，
        # 文字会被裁掉。
        self.search_input.setMinimumWidth(140)
        self.search_input.setMaximumWidth(240)
        self.search_input.textChanged.connect(self._filter_results)
        tb2.addWidget(self.search_input)

        # 结果筛选条（docs/reviews/UI_REVIEW.md P1-4）：常驻可见 + 带计数。
        # 旧实现把筛选藏在「视图 > 筛选」菜单里，工具栏只留一个隐藏的 combo
        # 当值载体 —— 用户扫 /24 出 254 条却只看到 12 条时无从得知原因。
        self.filter_bar = FilterChipBar()
        self.filter_key = self.filter_bar.current_key()
        self.filter_bar.filter_changed.connect(self._set_filter)

        main_layout.addLayout(tb2)

        # ── 工具栏 Row 3: 结果筛选条（独占一行 + 横向滚动兜底）──
        #
        # 为什么不和「IP 范围 + 搜索」挤同一行：那一行光最小宽度就是
        # 范围框 280 + 标签 + 搜索框 140 = 460px，而 8 个 chip 带 3 位计数时
        # 中文约需 700px、英文约需 1200px —— 1024px 的最小窗口下根本放不下，
        # Qt 会把每个 chip 压到 64px，`全部 254` 一律被截断成 `全部 2…`（实测）。
        # 筛选条的价值全在"一眼看清有多少条"，截断就完全失去意义，
        # 所以让它独占一行拿满宽度；万一仍然放不下（英文界面 + 窄窗口），
        # 由 FilterChipScroll 提供横向滚动，而不是把文字压掉。
        tb3 = QHBoxLayout()
        tb3.setSpacing(8)
        tb3.setContentsMargins(2, 0, 2, 2)
        # 视图切换：概览 / 列表（docs/reviews/UI_REVIEW.md P3-2）。放在筛选条左侧、与它同一行，
        # 因为两者是同一件事的两面 —— "换个角度看这批结果"。
        # 两个控件都存成属性：无结果时整行要隐藏（见 `_update_result_controls`）。
        self.view_toggle = self._build_view_toggle()
        tb3.addWidget(self.view_toggle)
        self.tb3_sep = _vsep()
        tb3.addWidget(self.tb3_sep)
        # stretch=1：让滚动容器吃满整行宽度。若改成"容器 + 末尾 addStretch"，
        # 容器只会拿到自己的 sizeHint（很窄），于是**永远**显示滚动条。
        self.filter_scroll = FilterChipScroll(self.filter_bar)
        tb3.addWidget(self.filter_scroll, 1)
        main_layout.addLayout(tb3)

        # ── 扫描态摘要条（docs/reviews/UI_REVIEW.md P0-2 后半）──
        # 放在工具栏与内容之间：扫描期间它是"现在在干嘛"的唯一出口
        # （阶段 / 已扫 / 在线 / 有服务 / 用时 / 停止）。
        # 默认隐藏，扫描结束后整体收起 —— 结果已经在表格里，再占一行是噪声。
        self.scan_status = ScanStatusBar()
        self.scan_status.stop_requested.connect(self._stop_scan)
        main_layout.addWidget(self.scan_status)

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

        # 读取交换机转发表：扫描末尾经 SNMP 读 BRIDGE-MIB，记下"哪台设备在哪个口"。
        # **默认关**：每台交换机 5 次 SNMP walk，且会在网络里产生额外 SNMP 流量，
        # 所以要用户显式开启（采集到的数据供「定位查询」使用）。
        self.switch_map_check = QAction(tr("读取交换机转发表"), self, checkable=True)
        self.switch_map_check.setToolTip(
            tr("扫描末尾读取各交换机转发表，记录设备与端口的对应关系（需要 SNMP）"))

        # 持续发现：打开界面后周期性地「被动」发现设备（读本机 ARP 表 + 监听 mDNS，
        # **不发任何网络包**），新出现的设备自动并入列表。
        # **默认关**：它会在后台占住 mDNS 的 5353 端口并持续改动表格，
        # 只想跑一次扫描的用户不该被它打扰。与「读取交换机转发表」同一处理。
        self.watch_check = QAction(tr("持续发现"), self, checkable=True)
        self.watch_check.setToolTip(
            tr("周期读取本机 ARP 表并监听 mDNS，把新出现的设备并入列表"
               "（被动，不发包；默认关）"))

        # 名字响应器探测：编一个不可能存在的主机名查一次 LLMNR / NBNS，
        # 看谁给**肯定应答**（应答自己不拥有的名字 = 欺骗响应器或安全工具）。
        # **默认关**：与上面两个选项不同，它**会往网络里发组播/广播包**，
        # 与「被动发现」的零发包原则冲突，必须用户显式开启。
        # 红线：只发一个查询包，不应答、不注册名字、绝不投毒（见 scanner/llmnr_nbns.py）。
        self.responder_check = QAction(tr("探测名字响应器"), self, checkable=True)
        self.responder_check.setToolTip(
            tr("扫描末尾编一个不存在的主机名，查一次 LLMNR/NBNS，"
               "记录谁给肯定应答（会发送组播/广播包；默认关）"))

        # 跨网段补齐 MAC：扫描末尾用 SNMP 读**三层设备**的 ARP 表，给「在线但
        # 拿不到 MAC」的设备回填。为什么需要：MAC 是二层概念，本机与目标不在
        # 同一网段时本机 ARP 表里只有网关的 MAC（ICMP 能通是经网关三层转发）。
        # **默认关**：需要 SNMP，且会在网络里产生额外 SNMP 流量。
        # 查哪台设备由 `self.arp_gateway` 决定：GATEWAY_AUTO = 自动探测本机默认
        # 网关；也可以填一个具体 IP（探测不到时**不猜**，见 arp_mapper）。
        self.arp_gateway = GATEWAY_AUTO
        self.arp_mac_check = QAction(tr("读取网关 ARP 表补齐 MAC"), self, checkable=True)
        self.arp_mac_check.setToolTip(
            tr("扫描末尾用 SNMP 读三层设备（默认本机网关）的 ARP 表，"
               "给跨网段「在线但拿不到 MAC」的设备回填（需要 SNMP；默认关）"))

        # 筛选已由常驻的 FilterChipBar 承担（见上方 tb2），
        # 「视图 > 筛选」菜单与 chip 共用 _set_filter() 这一个入口。

        # ── 分隔线 ──
        self.sep = QFrame()
        self.sep.setObjectName("hSep")
        self.sep.setFrameShape(QFrame.HLine)
        self.sep.setFrameShadow(QFrame.Sunken)
        self.sep.setFixedHeight(2)
        main_layout.addWidget(self.sep)

        # ── 结果表格 (QTreeWidget, 支持展开/收起服务) ──
        self.table = QTreeWidget()
        # objectName 供 QSS 按行高档位选中它（见 design_tokens.ROW_HEIGHT）
        self.table.setObjectName("resultTable")
        # 行高档位（docs/reviews/UI_REVIEW.md P2-1.2）。规范值语言无关，显示名走 density_label()；
        # 这里先落默认值，真正的用户配置在 `_load_settings` 里读取并重新应用。
        self.row_density = DEFAULT_DENSITY
        self._apply_row_density()
        # 🔴 列数与表头**必须**从 `COLUMN_LABELS` 派生，不要再写一份字面量。
        # 曾经两处各写一份 13 列表头，v5 加「风险」列时只改了 `COLUMN_LABELS` ——
        # 于是列宽表（14 项）去 `resizeSection(13, 78)`，而表头只有 13 节，
        # Qt 越界写直接搞坏堆：**表现为随机的段错误**（同一组用例有时第 1 个崩、
        # 有时第 3 个崩，堆栈每次都指在不同行），排查代价极高。
        # 派生之后这类不一致在结构上不可能再发生；`test_column_widths` 的
        # `test_column_count_matches_labels` 会把它钉住。
        self.table.setColumnCount(len(COLUMN_LABELS))
        self.table.setHeaderLabels([tr(_name) for _name in COLUMN_LABELS])
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

        # 列宽设置（列索引见 `COLUMN_LABELS`：0=IP地址 … 12=备注, 13=风险）
        header = self.table.header()
        header.setStretchLastSection(False)
        # 宽度**按语言分流** —— 中文下够宽的列在英文下会省略（见
        # `_COLUMN_WIDTH_OVERRIDES`）。
        self._apply_default_column_widths()
        # 状态电脑图标尺寸（预渲染 Pixmap 缩放到此尺寸，避免被压扁）
        self.table.setIconSize(QSize(18, 18))

        self.table.itemClicked.connect(self._on_item_clicked)
        # 右键上下文菜单：复制/重扫/WoL/地址库/内置工具（单连接，避免重复弹菜单）
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)

        # ── 结果区：空状态 ⇄ (表格 + 详情面板) 双页切换 (docs/reviews/UI_REVIEW.md P0-1 / P0-2) ──
        #
        # 原实现是"工具栏 + 一张宽表格"的单面板结构，有两个真实缺陷：
        #   1. 没有详情区域 —— WMI/NetBIOS/SNMP/共享 等富信息只能塞进 tooltip
        #      和跨列子项，IP 列的 tip 会拼到 10 段以上，实际不可读；
        #   2. 启动后是一张全空白表格 —— 没有引导、没有主 CTA。
        # 这里用 QStackedWidget 分三页解决：
        #   page 0 = EmptyStatePanel（无结果时的引导）
        #   page 1 = QSplitter(表格 / 详情面板)，垂直可拖拽、可折叠
        #   page 2 = OverviewPanel（概览仪表盘，docs/reviews/UI_REVIEW.md P3-2）
        self.detail_panel = DeviceDetailPanel()
        self.detail_splitter = QSplitter(Qt.Vertical)
        self.detail_splitter.setObjectName("detailSplitter")
        self.detail_splitter.setChildrenCollapsible(True)
        self.detail_splitter.addWidget(self.table)
        self.detail_splitter.addWidget(self.detail_panel)
        self.detail_splitter.setStretchFactor(0, 1)
        self.detail_splitter.setStretchFactor(1, 0)
        self.detail_splitter.setSizes([620, 168])

        self.empty_state = EmptyStatePanel()
        self.empty_state.scan_local_requested.connect(self._scan_local_subnet)
        self.empty_state.scan_requested.connect(self._start_scan)

        self.overview = OverviewPanel()

        self.result_stack = QStackedWidget()
        self.result_stack.addWidget(self.empty_state)       # index 0
        self.result_stack.addWidget(self.detail_splitter)   # index 1
        self.result_stack.addWidget(self.overview)          # index 2
        self.result_stack.setCurrentIndex(0)

        main_layout.addWidget(self.result_stack, 1)
        # 启动时还没有结果：把「视图切换 + 筛选条」整行收起来
        self._update_result_controls()

        # ── 状态栏 ──
        self.status_bar = self.statusBar()
        self.status_bar.showMessage(tr("就绪"))
        self.status_label = QLabel(tr("就绪"))
        self.status_bar.addPermanentWidget(self.status_label)

        self.status_stats_label = QLabel("")
        self.status_stats_label.setObjectName("statsLabel")
        self.status_bar.addPermanentWidget(self.status_stats_label)

        # 地址库状态（从工具栏移到底部状态栏）
        self.excel_label = QLabel(tr("地址库: 空"))
        self.excel_label.setObjectName("libraryLabel")
        self.status_bar.addPermanentWidget(self.excel_label)

        # CVE 快照状态徽标（v2.1 §2.3 GUI 露出）：永久区最右一格。
        # 文案与取色都在 `CveStatusMixin._refresh_cve_badge()`（QSS 只兜字体），
        # 换主题时随 `_apply_theme` 一起刷新，深色下不会漏白。
        self.cve_label = QLabel("")
        self.cve_label.setObjectName("cveLabel")
        self.status_bar.addPermanentWidget(self.cve_label)

    def _init_menu(self):
        menubar = self.menuBar()
        menubar.setStyleSheet("")
        _mi = lambda sp: _gray_icon(self.style().standardIcon(sp))

        # ── 文件菜单 ──
        file_menu = menubar.addMenu(tr("文件(&F)"))
        file_menu.setStyleSheet("")

        self.act_export = QAction(tr("导出扫描结果"), self)
        self.act_export.setIcon(_mi(QStyle.SP_DialogSaveButton))
        self.act_export.setShortcut(QKeySequence("Ctrl+E"))
        self.act_export.triggered.connect(self._export_results)
        file_menu.addAction(self.act_export)

        # v1.9 §1.2：资产表互操作导出（Nmap XML / Zabbix LLD / NetBox CSV / Oxidized）
        self.act_export_assets = QAction(tr("导出资产（互操作）..."), self)
        self.act_export_assets.setIcon(_mi(QStyle.SP_DialogSaveButton))
        self.act_export_assets.triggered.connect(self._export_assets_interop)
        file_menu.addAction(self.act_export_assets)

        act_print = QAction(tr("打印..."), self)
        act_print.setIcon(_mi(QStyle.SP_FileDialogContentsView))
        act_print.setShortcut(QKeySequence("Ctrl+P"))
        act_print.triggered.connect(self._print_results)
        file_menu.addAction(act_print)

        file_menu.addSeparator()

        act_lib_manage = QAction(tr("管理地址库..."), self)
        act_lib_manage.setIcon(_mi(QStyle.SP_DirOpenIcon))
        act_lib_manage.setShortcut(QKeySequence("Ctrl+Shift+M"))
        act_lib_manage.triggered.connect(self._open_library_manager)
        file_menu.addAction(act_lib_manage)

        act_lib_import = QAction(tr("导入地址库"), self)
        act_lib_import.setIcon(_mi(QStyle.SP_ArrowDown))
        act_lib_import.setShortcut(QKeySequence("Ctrl+I"))
        act_lib_import.triggered.connect(self._import_excel)
        file_menu.addAction(act_lib_import)

        act_lib_export = QAction(tr("导出地址库"), self)
        act_lib_export.setIcon(_mi(QStyle.SP_ArrowUp))
        act_lib_export.setShortcut(QKeySequence("Ctrl+Shift+I"))
        act_lib_export.triggered.connect(self._export_library)
        file_menu.addAction(act_lib_export)

        file_menu.addSeparator()

        act_exit = QAction(tr("退出"), self)
        act_exit.setIcon(_mi(QStyle.SP_DialogCloseButton))
        act_exit.setShortcut(QKeySequence("Alt+F4"))
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # ── 扫描菜单 ──
        scan_menu = menubar.addMenu(tr("扫描(&S)"))
        scan_menu.setStyleSheet("")

        act_scan = QAction(tr("开始扫描"), self)
        act_scan.setIcon(_mi(QStyle.SP_MediaPlay))
        act_scan.setShortcut(QKeySequence("F5"))
        act_scan.triggered.connect(self._start_scan)
        scan_menu.addAction(act_scan)

        act_stop = QAction(tr("停止扫描"), self)
        act_stop.setIcon(_mi(QStyle.SP_MediaStop))
        act_stop.setShortcut(QKeySequence("Esc"))
        act_stop.triggered.connect(self._stop_scan)
        scan_menu.addAction(act_stop)

        scan_menu.addSeparator()

        act_add_range = QAction(tr("添加网段"), self)
        act_add_range.setIcon(_mi(QStyle.SP_FileDialogNewFolder))
        act_add_range.setShortcut(QKeySequence("Ctrl+Shift+R"))
        act_add_range.triggered.connect(self._add_ip_range)
        scan_menu.addAction(act_add_range)

        act_clear_ranges = QAction(tr("清空网段"), self)
        act_clear_ranges.setIcon(_mi(QStyle.SP_TrashIcon))
        act_clear_ranges.setShortcut(QKeySequence("Ctrl+Shift+L"))
        act_clear_ranges.triggered.connect(self._clear_ranges)
        scan_menu.addAction(act_clear_ranges)

        self.act_clear = QAction(tr("清空结果"), self)
        self.act_clear.setIcon(_mi(QStyle.SP_DialogDiscardButton))
        self.act_clear.setShortcut(QKeySequence("Ctrl+Shift+K"))
        self.act_clear.triggered.connect(self._clear_results)
        scan_menu.addAction(self.act_clear)

        scan_menu.addSeparator()

        discover_sub = scan_menu.addMenu(tr("发现"))
        discover_sub.setStyleSheet("")
        discover_sub.setIcon(_mi(QStyle.SP_DriveNetIcon))
        act_scan_local = QAction(tr("扫描本机所在子网"), self)
        act_scan_local.setIcon(_mi(QStyle.SP_DriveHDIcon))
        act_scan_local.setShortcut(QKeySequence("Ctrl+1"))
        act_scan_local.triggered.connect(self._scan_local_subnet)
        discover_sub.addAction(act_scan_local)
        act_scan_c = QAction(tr("扫描 C 类子网"), self)
        act_scan_c.setIcon(_mi(QStyle.SP_DriveNetIcon))
        act_scan_c.setShortcut(QKeySequence("Ctrl+2"))
        act_scan_c.triggered.connect(self._scan_c_class_subnet)
        discover_sub.addAction(act_scan_c)
        act_mdns = QAction(tr("网络 mDNS 发现"), self)
        act_mdns.setIcon(_mi(QStyle.SP_BrowserReload))
        act_mdns.setShortcut(QKeySequence("Ctrl+3"))
        act_mdns.setToolTip(tr("对当前本地链路做 mDNS/DNS-SD 组播发现，发现打印机/NAS/Apple 设备等"))
        act_mdns.triggered.connect(self._run_mdns_discovery)
        discover_sub.addAction(act_mdns)

        scan_menu.addSeparator()

        act_shutdown = QAction(tr("远程关机"), self)
        act_shutdown.setIcon(_mi(QStyle.SP_DialogCancelButton))
        act_shutdown.setToolTip(tr("向目标发送关机指令 (shutdown /s /m)"))
        act_shutdown.triggered.connect(lambda: self._remote_power("shutdown"))
        scan_menu.addAction(act_shutdown)

        act_reboot = QAction(tr("远程重启"), self)
        act_reboot.setIcon(_mi(QStyle.SP_BrowserReload))
        act_reboot.setToolTip(tr("向目标发送重启指令 (shutdown /r /m)"))
        act_reboot.triggered.connect(lambda: self._remote_power("reboot"))
        scan_menu.addAction(act_reboot)

        # ── 分析菜单 ──
        analysis_menu = menubar.addMenu(tr("分析(&A)"))
        analysis_menu.setStyleSheet("")

        act_history = QAction(tr("历史对比..."), self)
        act_history.setIcon(_mi(QStyle.SP_ArrowBack))
        act_history.setShortcut(QKeySequence("Ctrl+H"))
        act_history.triggered.connect(self._open_history_compare)
        analysis_menu.addAction(act_history)

        act_history_query = QAction(tr("历史检索..."), self)
        act_history_query.setIcon(_mi(QStyle.SP_FileDialogListView))
        act_history_query.setShortcut(QKeySequence("Ctrl+Shift+H"))
        act_history_query.setToolTip(tr("跨快照按类型/网段/首见时间/IP 检索历史设备"))
        act_history_query.triggered.connect(self._open_history_query)
        analysis_menu.addAction(act_history_query)

        act_locate = QAction(tr("设备定位..."), self)
        act_locate.setIcon(_mi(QStyle.SP_ComputerIcon))
        act_locate.setShortcut(QKeySequence("Ctrl+L"))
        act_locate.setToolTip(tr("按 MAC / IP / 主机名查出它接在哪台交换机的哪个端口"))
        act_locate.triggered.connect(self._open_locate_dialog)
        analysis_menu.addAction(act_locate)

        analysis_menu.addSeparator()

        self.act_conflict = QAction(tr("冲突检测"), self)
        self.act_conflict.setIcon(_mi(QStyle.SP_MessageBoxWarning))
        self.act_conflict.setShortcut(QKeySequence("Ctrl+Shift+C"))
        self.act_conflict.setToolTip(tr("检测 IP/MAC 冲突、未知设备等异常"))
        self.act_conflict.triggered.connect(self._run_conflict_detection)
        analysis_menu.addAction(self.act_conflict)

        self.act_change = QAction(tr("变更检测"), self)
        self.act_change.setIcon(_mi(QStyle.SP_BrowserReload))
        self.act_change.setShortcut(QKeySequence("Ctrl+Shift+V"))
        self.act_change.setToolTip(tr("对比上次扫描快照，发现新增/消失/替换/改址等设备变动"))
        self.act_change.triggered.connect(lambda: self._run_change_detection(silent=False))
        analysis_menu.addAction(self.act_change)

        analysis_menu.addSeparator()

        act_wmi = QAction(tr("WMI 设备识别 (需管理员)..."), self)
        act_wmi.setIcon(_mi(QStyle.SP_MessageBoxInformation))
        act_wmi.setShortcut(QKeySequence("Ctrl+Shift+W"))
        act_wmi.setToolTip(tr("对在线疑似 Windows 设备做 WMI 远程识别（厂商/型号/序列号/系统），需管理员凭据"))
        act_wmi.triggered.connect(lambda: self._run_wmi_identification())
        analysis_menu.addAction(act_wmi)

        act_snmpv3 = QAction(tr("SNMPv3 用户配置..."), self)
        act_snmpv3.setIcon(_mi(QStyle.SP_DriveNetIcon))
        act_snmpv3.setToolTip(tr("配置 SNMPv3 USM 用户（认证/加密）用于设备识别；未配置时回退到 v2c 团体字"))
        act_snmpv3.triggered.connect(self._configure_snmp_v3)
        analysis_menu.addAction(act_snmpv3)

        act_netbios = QAction(tr("NetBIOS 识别（轻量）"), self)
        act_netbios.setIcon(_mi(QStyle.SP_MessageBoxInformation))
        act_netbios.setToolTip(tr("零凭据、不需管理员：获取计算机名/工作组/当前用户/MAC（同网段 UDP/137）"))
        act_netbios.triggered.connect(lambda: self._run_netbios_identification())
        analysis_menu.addAction(act_netbios)

        act_switch_map = QAction(tr("交换机端口映射..."), self)
        act_switch_map.setIcon(_mi(QStyle.SP_DriveNetIcon))
        act_switch_map.setToolTip(tr("通过 SNMP 获取交换机 MAC 转发表，映射 MAC → 物理端口"))
        act_switch_map.triggered.connect(self._show_switch_port_mapping)
        analysis_menu.addAction(act_switch_map)

        act_wifi = QAction(tr("无线切片..."), self)
        act_wifi.setIcon(_mi(QStyle.SP_ComputerIcon))
        act_wifi.setToolTip(tr(
            "本机无线状态：当前关联的 AP、周围 AP 的信道拥塞、漫游/断开时间线、"
            "以及该 SSID 对应的网段（只读系统缓存，不主动扫射频）"))
        act_wifi.triggered.connect(self._show_wifi_slice)
        analysis_menu.addAction(act_wifi)

        analysis_menu.addSeparator()

        act_subnet_util = QAction(tr("子网利用率..."), self)
        act_subnet_util.setIcon(_mi(QStyle.SP_FileDialogDetailedView))
        act_subnet_util.setShortcut(QKeySequence("Ctrl+U"))
        act_subnet_util.setToolTip(tr("按 /24 子网聚合，查看各网段在线占比与设备分布"))
        act_subnet_util.triggered.connect(self._show_subnet_utilization)
        analysis_menu.addAction(act_subnet_util)

        act_audit_log = QAction(tr("审计日志..."), self)
        act_audit_log.setIcon(_mi(QStyle.SP_FileDialogContentsView))
        act_audit_log.setShortcut(QKeySequence("Ctrl+Shift+A"))
        act_audit_log.setToolTip(tr("查看扫描活动记录（开始/停止/完成、冲突检测等）"))
        act_audit_log.triggered.connect(self._show_audit_log)
        analysis_menu.addAction(act_audit_log)

        act_audit_activity = QAction(tr("扫描活动自查..."), self)
        act_audit_activity.setIcon(_mi(QStyle.SP_FileDialogListView))
        act_audit_activity.setToolTip(tr(
            "过去这段时间向哪些网段发起过多少次扫描（按时间窗聚合，只读审计库）"))
        act_audit_activity.triggered.connect(self._show_audit_activity)
        analysis_menu.addAction(act_audit_activity)

        act_trend = QAction(tr("在线率趋势..."), self)
        act_trend.setIcon(_mi(QStyle.SP_FileDialogDetailedView))
        act_trend.setToolTip(tr(
            "过去这段时间的在线率曲线与稳定性（MTBF / 抖动 / 首现设备）"))
        act_trend.triggered.connect(self._show_trend_view)
        analysis_menu.addAction(act_trend)

        # ── 设置菜单 ──
        settings_menu = menubar.addMenu(tr("设置(&O)"))
        settings_menu.setStyleSheet("")

        self.port_scan_check.setIcon(_mi(QStyle.SP_FileDialogContentsView))
        settings_menu.addAction(self.port_scan_check)

        self.mdns_check.setIcon(_mi(QStyle.SP_FileDialogInfoView))
        settings_menu.addAction(self.mdns_check)

        self.switch_map_check.setIcon(_mi(QStyle.SP_DriveNetIcon))
        settings_menu.addAction(self.switch_map_check)

        # 持续发现：与上面两项并列 —— 三者都是"会碰网络的采集行为"，
        # 且都默认关，放一起用户一眼能看出这是一组需要自己开的东西。
        self.watch_check.setIcon(_mi(QStyle.SP_BrowserReload))
        settings_menu.addAction(self.watch_check)

        # 名字响应器探测：同属"会碰网络的采集行为"这一组（它比上面三项更主动，
        # 会发组播/广播，见 responder_check 的注释），所以也放这里。
        self.responder_check.setIcon(_mi(QStyle.SP_MessageBoxQuestion))
        settings_menu.addAction(self.responder_check)

        # 跨网段补齐 MAC：同属"会碰网络的采集行为"这一组（需要 SNMP）。
        # 排在最末是因为它针对的场景（跨网段看不到 MAC）比前几项更专门。
        self.arp_mac_check.setIcon(_mi(QStyle.SP_DriveNetIcon))
        settings_menu.addAction(self.arp_mac_check)

        settings_menu.addSeparator()

        self.tcp_mode_group = QActionGroup(self)
        self.tcp_mode_group.setExclusive(True)
        mode_sub = settings_menu.addMenu(tr("端口探测方式"))
        mode_sub.setStyleSheet("")
        mode_sub.setIcon(_mi(QStyle.SP_FileDialogDetailedView))
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

        self.scan_level_group = QActionGroup(self)
        self.scan_level_group.setExclusive(True)
        level_sub = settings_menu.addMenu(tr("扫描级别"))
        level_sub.setStyleSheet("")
        level_sub.setIcon(_mi(QStyle.SP_FileDialogListView))
        level_sub.setToolTip(tr("控制端口探测的端口范围（快速日常巡检 / 标准深度 / 全端口安全评估）"))
        for _lv in ("quick", "standard", "all"):
            _a = QAction(scan_level_label(_lv), self, checkable=True)
            _a.setData(_lv)
            _a.setActionGroup(self.scan_level_group)
            _a.setChecked(getattr(self, "scan_level", "quick") == _lv)
            _a.triggered.connect(
                lambda _checked, _ll=_lv: self._set_scan_level(_ll)
            )
            level_sub.addAction(_a)

        # 扫描礼貌档（v2.1 §2.4 GUI 露出）：与「扫描级别」并列 ——
        # 一个管「扫多深」，一个管「对网络多客气」。勾选存的是**规范名**
        # （fast/balanced/polite，语言无关，见 scanner.throttle），
        # 显示名在这里运行时 tr()（字面量表放模块级会被冻成中文）。
        self.throttle_group = QActionGroup(self)
        self.throttle_group.setExclusive(True)
        polite_sub = settings_menu.addMenu(tr("扫描礼貌档"))
        polite_sub.setStyleSheet("")
        polite_sub.setIcon(_mi(QStyle.SP_MediaSeekForward))
        polite_sub.setToolTip(
            tr("控制发包速率、并发上限与投递顺序随机化（默认快速 = 不额外设限）"))
        for _tp, _tl in ((throttle.POLICY_FAST, tr("快速（不额外设限）")),
                         (throttle.POLICY_BALANCED, tr("均衡（温和限速）")),
                         (throttle.POLICY_POLITE, tr("礼貌（低速低并发）"))):
            _a = QAction(_tl, self, checkable=True)
            _a.setData(_tp)
            _a.setActionGroup(self.throttle_group)
            _a.setChecked(self.throttle_policy == _tp)
            _a.triggered.connect(
                lambda _checked, _pp=_tp: self._set_throttle_policy(_pp)
            )
            polite_sub.addAction(_a)

        scan_settings_sub = settings_menu.addMenu(tr("扫描设置"))
        scan_settings_sub.setStyleSheet("")
        scan_settings_sub.setIcon(_mi(QStyle.SP_FileDialogListView))
        act_open_settings = QAction(tr("打开扫描设置对话框..."), self)
        act_open_settings.setIcon(_mi(QStyle.SP_FileDialogListView))
        act_open_settings.triggered.connect(self._open_scan_settings)
        scan_settings_sub.addAction(act_open_settings)
        for _proto in sorted(PROTOCOL_PORTS.keys()):
            # 菜单显示本地化名称，但 setData/勾选逻辑一律用规范代码
            _act = QAction(service_label(_proto), self, checkable=True)
            _act.setData(_proto)
            _act.setToolTip(f"扫描 {service_label(_proto)} 服务")
            _act.setChecked(_proto in self.selected_protocols)
            _act.toggled.connect(
                lambda _checked, _p=_proto: self._toggle_protocol(_p, _checked)
            )
            scan_settings_sub.addAction(_act)

        # CVE 快照详情（v2.1 §2.3 GUI 露出）：状态栏徽标的展开入口。
        # 挨着「扫描设置」放 —— 两者都是「采集/数据面」的系统信息。
        act_cve_status = QAction(tr("CVE 数据快照..."), self)
        act_cve_status.setIcon(_mi(QStyle.SP_FileDialogInfoView))
        act_cve_status.setToolTip(tr("查看离线 CVE 数据快照的状态、来源与下一步"))
        act_cve_status.triggered.connect(self._show_cve_status)
        settings_menu.addAction(act_cve_status)

        # CVE 快照**在线更新**（v2.2 §3.1）：本程序唯一联网的 CVE 动作。
        # 🔴 只做菜单项，**绝不**在 __init__ 里调用（同意框会挂住无头测试）。
        act_cve_update = QAction(tr("在线更新 CVE 数据快照..."), self)
        act_cve_update.setIcon(_mi(QStyle.SP_ArrowDown))
        act_cve_update.setToolTip(tr("从配置的地址下载并校验 CVE 数据快照"
                                     "（唯一联网的 CVE 操作，需手动触发）"))
        act_cve_update.triggered.connect(self._update_cve_snapshot)
        settings_menu.addAction(act_cve_update)

        settings_menu.addSeparator()

        # ── 主题：单选（跟随系统 / 浅色 / 深色 / 按时间）──
        # 旧版是一个「跟随时间自动切换」的裸 checkbox，用户既看不出当前
        # 到底是深色还是浅色，也无法显式指定 —— 只会在某天 18:00 突然变脸。
        theme_menu = settings_menu.addMenu(tr("主题"))
        theme_menu.setStyleSheet("")
        theme_menu.setIcon(_mi(QStyle.SP_DesktopIcon))
        self._theme_group = QActionGroup(self)
        self._theme_group.setExclusive(True)
        self._theme_actions = {}
        for _tkey, _tlabel in THEME_MODES:
            _tact = QAction(tr(_tlabel), self, checkable=True)
            _tact.setData(_tkey)
            _tact.setChecked(_tkey == self.theme_mode)
            _tact.triggered.connect(lambda _c, k=_tkey: self._set_theme_mode(k))
            self._theme_group.addAction(_tact)
            theme_menu.addAction(_tact)
            self._theme_actions[_tkey] = _tact

        lang_menu = settings_menu.addMenu(tr("语言 / Language"))
        lang_menu.setStyleSheet("")
        lang_menu.setIcon(_mi(QStyle.SP_FileDialogListView))
        self.act_lang_zh = QAction(tr("中文"), self)
        self.act_lang_zh.setCheckable(True)
        self.act_lang_zh.triggered.connect(lambda: self._switch_language("zh-CN"))
        lang_menu.addAction(self.act_lang_zh)
        self.act_lang_en = QAction(tr("English"), self)
        self.act_lang_en.setCheckable(True)
        self.act_lang_en.triggered.connect(lambda: self._switch_language("en-US"))
        lang_menu.addAction(self.act_lang_en)

        # ── 查看菜单 ──
        view_menu = menubar.addMenu(tr("查看(&V)"))
        view_menu.setStyleSheet("")

        # ── 显示列：预设 + 自定义（docs/reviews/UI_REVIEW.md P1-2）──
        col_menu = view_menu.addMenu(tr("显示列"))
        col_menu.setStyleSheet("")
        col_menu.setIcon(_mi(QStyle.SP_FileDialogDetailedView))

        # 预设（单选）：一键切到常见视图
        self._col_preset_group = QActionGroup(self)
        self._col_preset_group.setExclusive(True)
        self._col_preset_actions = {}
        for _key, _label, _cols in COLUMN_PRESETS:
            _pact = QAction(tr(_label), self, checkable=True)
            _pact.setData(_key)
            _pact.setToolTip(tr("显示 {n} 列").format(n=len(_cols)))
            _pact.triggered.connect(lambda _c, k=_key: self._apply_column_preset(k))
            self._col_preset_group.addAction(_pact)
            col_menu.addAction(_pact)
            self._col_preset_actions[_key] = _pact

        col_menu.addSeparator()

        # 自定义（多选）：保留原有的逐列开关
        self._col_actions = {}
        for _ci, _name in enumerate(COLUMN_LABELS):
            _act = QAction(tr(_name), self)
            _act.setCheckable(True)
            _act.setChecked(not self.table.isColumnHidden(_ci))
            _act.toggled.connect(
                lambda checked, c=_ci: self._on_column_toggled(c, checked)
            )
            col_menu.addAction(_act)
            self._col_actions[_ci] = _act

        filter_menu = view_menu.addMenu(tr("筛选"))
        filter_menu.setStyleSheet("")
        filter_menu.setIcon(_mi(QStyle.SP_FileDialogContentsView))
        self._filter_group = QActionGroup(self)
        self._filter_group.setExclusive(True)
        self._filter_actions = {}
        for _fkey, _flabel in FILTERS:
            _fact = QAction(tr(_flabel), self, checkable=True)
            _fact.setData(_fkey)
            _fact.setChecked(_fkey == self.filter_key)
            _fact.triggered.connect(lambda _checked, k=_fkey: self._set_filter(k))
            self._filter_group.addAction(_fact)
            filter_menu.addAction(_fact)
            self._filter_actions[_fkey] = _fact

        # ── 行高：舒适 / 紧凑（docs/reviews/UI_REVIEW.md P2-1.2）──
        # 扫 /24 出 254 行时一屏只放得下二十来行。紧凑档把 min-height 收到 20px
        # 并收窄上下 padding，实测行高 34px → 25px（可见行数约 +36%）。
        density_menu = view_menu.addMenu(tr("行高"))
        density_menu.setStyleSheet("")
        density_menu.setIcon(_mi(QStyle.SP_FileDialogListView))
        self._density_group = QActionGroup(self)
        self._density_group.setExclusive(True)
        self._density_actions = {}
        for _dkey in DENSITIES:
            _dact = QAction(density_label(_dkey), self, checkable=True)
            _dact.setData(_dkey)
            _dact.setChecked(_dkey == self.row_density)
            _dact.triggered.connect(lambda _c, k=_dkey: self._set_row_density(k))
            self._density_group.addAction(_dact)
            density_menu.addAction(_dact)
            self._density_actions[_dkey] = _dact

        view_menu.addSeparator()

        act_expand = QAction(tr("展开全部"), self)
        act_expand.setIcon(_mi(QStyle.SP_ArrowDown))
        act_expand.setShortcut(QKeySequence("Ctrl++"))
        act_expand.triggered.connect(self._expand_all_items)
        view_menu.addAction(act_expand)

        act_collapse = QAction(tr("收起全部"), self)
        act_collapse.setIcon(_mi(QStyle.SP_ArrowUp))
        act_collapse.setShortcut(QKeySequence("Ctrl+-"))
        act_collapse.triggered.connect(self._collapse_all_items)
        view_menu.addAction(act_collapse)

        act_topology = QAction(tr("拓扑视图..."), self)
        act_topology.setIcon(_mi(QStyle.SP_DriveNetIcon))
        act_topology.setShortcut(QKeySequence("Ctrl+T"))
        act_topology.triggered.connect(self._open_topology)
        view_menu.addAction(act_topology)

        # ── 工具菜单 ──
        tool_menu = menubar.addMenu(tr("工具(&T)"))
        tool_menu.setStyleSheet("")

        act_ping = QAction(tr("Ping (持续)"), self)
        act_ping.setIcon(_mi(QStyle.SP_MediaSeekForward))
        act_ping.setShortcut(QKeySequence("Ctrl+G"))
        act_ping.setToolTip(tr("对目标执行持续 Ping (ping -t)"))
        act_ping.triggered.connect(lambda: self._launch_network_tool("ping"))
        tool_menu.addAction(act_ping)

        act_tracert = QAction(tr("Tracert (路由追踪)"), self)
        act_tracert.setIcon(_mi(QStyle.SP_MediaSkipForward))
        act_tracert.setShortcut(QKeySequence("Ctrl+R"))
        act_tracert.setToolTip(tr("对目标执行路由追踪 (tracert)"))
        act_tracert.triggered.connect(lambda: self._launch_network_tool("tracert"))
        tool_menu.addAction(act_tracert)

        tool_menu.addSeparator()

        act_telnet = QAction(tr("Telnet"), self)
        act_telnet.setIcon(_mi(QStyle.SP_DialogOpenButton))
        act_telnet.setShortcut(QKeySequence("Ctrl+N"))
        act_telnet.setToolTip(tr("对目标启动 Telnet 会话"))
        act_telnet.triggered.connect(lambda: self._launch_network_tool("telnet"))
        tool_menu.addAction(act_telnet)

        act_ssh = QAction(tr("SSH"), self)
        act_ssh.setIcon(_mi(QStyle.SP_DialogOpenButton))
        act_ssh.setShortcut(QKeySequence("Ctrl+Shift+S"))
        act_ssh.setToolTip(tr("对目标启动 SSH 会话 (需 OpenSSH 客户端)"))
        act_ssh.triggered.connect(lambda: self._launch_network_tool("ssh"))
        tool_menu.addAction(act_ssh)

        act_rdp = QAction(tr("远程桌面 (RDP)"), self)
        act_rdp.setIcon(_mi(QStyle.SP_DriveHDIcon))
        act_rdp.setShortcut(QKeySequence("Ctrl+M"))
        act_rdp.setToolTip(tr("用系统 mstsc 远程桌面连接目标"))
        act_rdp.triggered.connect(lambda: self._launch_network_tool("rdp"))
        tool_menu.addAction(act_rdp)

        act_cmd = QAction(tr("打开命令提示符"), self)
        act_cmd.setIcon(_mi(QStyle.SP_CommandLink))
        act_cmd.setShortcut(QKeySequence("Ctrl+J"))
        act_cmd.setToolTip(tr("打开以目标命名的命令提示符窗口"))
        act_cmd.triggered.connect(lambda: self._launch_network_tool("cmd"))
        tool_menu.addAction(act_cmd)

        # ── 帮助菜单 ──
        help_menu = menubar.addMenu(tr("帮助(&H)"))
        help_menu.setStyleSheet("")

        act_oui_update = QAction(tr("检查 OUI 更新..."), self)
        act_oui_update.setIcon(_mi(QStyle.SP_BrowserReload))
        act_oui_update.setToolTip(tr("从 IEEE 官网下载最新 MAC 厂商数据库"))
        act_oui_update.triggered.connect(self._update_oui_db)
        help_menu.addAction(act_oui_update)

        act_about = QAction(tr("关于"), self)
        act_about.setIcon(_mi(QStyle.SP_DialogHelpButton))
        act_about.setShortcut(QKeySequence("F1"))
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

        # 扫描预设菜单（内容随预设增删重建）
        self._rebuild_preset_menu()

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
        # 标签与分隔线的颜色已全部下沉到 QSS（objectName 选择器），
        # 这里不再逐控件改色 —— 否则主题色会同时存在于 .qss 与本函数两处，
        # 新增一个内联样式就会在深色下"漏白"（见 docs/reviews/UI_REVIEW.md P2-2）。
        # 工具栏小图标随主题重绘线条颜色（色值与建按钮时同源：token("tool_icon")）
        _icon_color = token("tool_icon", dark)
        if hasattr(self, "local_subnet_btn"):
            _sz = self.local_subnet_btn.iconSize().width()
            self.local_subnet_btn.setIcon(_make_tool_icon("ip", _icon_color, _sz))
            self.c_subnet_btn.setIcon(_make_tool_icon("c", _icon_color, _sz))
            self.stop_btn.setIcon(_make_pause_icon(_icon_color, self.stop_btn.iconSize().width()))
        # 树项上由 Python 设色的部分随主题刷新（QSS 覆盖不到）：
        # IP 列前景、状态列前景与预渲染图标、收藏星标
        if hasattr(self, "_ip_item_map"):
            self._refresh_theme_marks()
        # CVE 徽标的颜色同样由 Python 按主题取（theme_tokens 语义色）——
        # 不跟着刷的话，切到深色还是浅色主题下那只绿灯/红灯不换。
        if hasattr(self, "cve_label"):
            self._refresh_cve_badge()

    def _should_be_dark_now(self) -> bool:
        """按时间判断当前是否应为深色：18:00–次日 06:00 视为深色时段。"""
        return system_theme.is_time_dark(datetime.now().hour)

    def _resolve_dark(self) -> bool:
        """把用户选择的 `theme_mode` 解析成"现在到底是不是深色"。

        解析规则本身是纯函数（`system_theme.resolve_dark`），这里只负责
        把当前状态喂进去 —— 这样"四种模式各自该出什么颜色"可以脱离 Qt 单测。
        """
        return system_theme.resolve_dark(
            getattr(self, "theme_mode", DEFAULT_THEME_MODE),
            current=getattr(self, "dark_mode", False),
        )

    def _set_theme_mode(self, mode: str, save: bool = True):
        """切换主题模式并立即生效；save=True 时持久化。"""
        if mode not in system_theme.VALID_MODES:
            mode = DEFAULT_THEME_MODE
        self.theme_mode = mode
        self.auto_time = (mode == system_theme.MODE_TIME)  # 兼容旧字段
        self._sync_theme_menu()
        self._set_dark_mode(self._resolve_dark(), save=save)

    def _set_dark_mode(self, dark: bool, save: bool = True):
        """底层设定实际明暗并刷新 UI；save=True 时持久化到配置。"""
        self.dark_mode = dark
        self._apply_theme(dark)
        if save:
            self._save_settings()

    def _check_theme_change(self):
        """定时器回调：system/time 模式下偏好发生变化时跟随切换。

        light / dark 是用户显式选择，不做任何自动干预。
        """
        mode = getattr(self, "theme_mode", DEFAULT_THEME_MODE)
        if mode not in (system_theme.MODE_SYSTEM, system_theme.MODE_TIME):
            return
        _target = self._resolve_dark()
        if _target != self.dark_mode:
            app_logging.get_logger(__name__).info(
                "主题随 %s 模式切换：%s → %s",
                mode, "深色" if self.dark_mode else "浅色",
                "深色" if _target else "浅色",
            )
            self._set_dark_mode(_target, save=False)

    def _sync_theme_menu(self):
        """把菜单勾选态同步到当前 theme_mode（构建期与载入配置后都要调）。"""
        group = getattr(self, "_theme_group", None)
        if group is None:
            return
        _act = self._theme_actions.get(getattr(self, "theme_mode", ""))
        if _act is not None and not _act.isChecked():
            _act.setChecked(True)

    def _switch_language(self, lang: str):
        """切换界面语言，保存偏好并提示重启。"""
        import i18n
        if i18n.current_lang() == lang:
            return
        self.settings.setValue("ui/language", lang)
        self.settings.sync()
        msg_info(
            self, tr("语言切换"),
            tr("语言设置已保存，重启程序后生效。")
        )

    def _link_color(self) -> QColor:
        """服务链接/可点击文字颜色，随主题变化。

        取值一律来自语义色令牌（`theme_tokens`），不要再写字面量 —— 这套蓝此前在
        `main_window.py` / `main_window_tree.py` / `ui_icons.py` 里各硬编码了一份，
        改一处漏一处就是"深色下某个标签还是浅色"。

        深色下必须换成更亮的蓝：浅色蓝 `#2563EB` 在深色树底 `#252526` 上只有
        2.96:1，低于 WCAG AA 的 4.5:1；`#4DA6FF` 是 5.99:1。这条量化口径由
        `tests/test_theme_marks.py::LinkColorContrastTest` 守着。
        """
        return QColor(token("link", self.dark_mode))

    # ── 扫描预设 (docs/reviews/UI_REVIEW.md P1-3) ──

    def _current_scan_config(self) -> dict:
        """把当前扫描参数打包成可保存的预设内容。"""
        return {
            "ranges": list(self.ip_range_items),
            "level": self.scan_level,
            "protocols": list(self.selected_protocols),
            "tcp_mode": self.tcp_scan_mode,
            "port_scan": self.port_scan_check.isChecked(),
            "mdns": self.mdns_check.isChecked(),
            "switch_map": self.switch_map_check.isChecked(),
            "name_responder": self.responder_check.isChecked(),
            "arp_mac": self.arp_mac_check.isChecked(),
            # 预设里连**查哪台三层设备**一起存：换了网段往往就要换设备，
            # 只存开关不存地址的话每次套预设都得再手动改一遍。
            "arp_gateway": getattr(self, "arp_gateway", GATEWAY_AUTO),
        }

    def _apply_scan_preset(self, name: str):
        """套用一个命名预设。逐项做白名单校验，避免旧配置里的失效值被塞进控件。"""
        cfg = self.scan_presets.get(name)
        if cfg is None:
            return
        ranges = [r for r in (cfg.get("ranges") or [])
                  if isinstance(r, str) and r.strip()]
        if ranges:
            self.ip_range_items = list(ranges)
            self.range_input.clear()
            self._update_range_list()
        level = cfg.get("level", "quick")
        if level in ("quick", "standard", "all"):
            self.scan_level = level
            self._sync_scan_level_menu()
        mode = cfg.get("tcp_mode", "connect")
        if mode in ("connect", "syn", "udp"):
            self.tcp_scan_mode = mode
            self._sync_tcp_mode_menu()
        self.port_scan_check.setChecked(bool(cfg.get("port_scan", False)))
        self.mdns_check.setChecked(bool(cfg.get("mdns", True)))
        self.switch_map_check.setChecked(bool(cfg.get("switch_map", False)))
        self.responder_check.setChecked(bool(cfg.get("name_responder", False)))
        self.arp_mac_check.setChecked(bool(cfg.get("arp_mac", False)))
        # 空串是**非法值**（在 ScanThread 里表示"不做补齐"），回落 AUTO
        _pg = str(cfg.get("arp_gateway", GATEWAY_AUTO) or "").strip()
        self.arp_gateway = _pg or GATEWAY_AUTO
        protos = [p for p in (cfg.get("protocols") or []) if p in PROTOCOL_PORTS]
        if protos:
            self.selected_protocols = protos
        self._save_settings()
        self._update_empty_hint()
        self.status_bar.showMessage(tr("已应用预设") + ": " + name)

    def _save_current_as_preset(self):
        name, ok = QInputDialog.getText(self, tr("保存扫描预设"), tr("预设名称："))
        if not ok:
            return
        try:
            name = validate_name(name)
            self.scan_presets.put(name, self._current_scan_config())
        except PresetError as e:
            msg_warn(self, tr("保存扫描预设"), str(e))
            return
        self._rebuild_preset_menu()
        self.status_bar.showMessage(tr("已保存预设") + ": " + name)

    def _delete_preset(self, name: str):
        if self.scan_presets.delete(name):
            self._rebuild_preset_menu()
            self.status_bar.showMessage(tr("已删除预设") + ": " + name)

    def _rebuild_preset_menu(self):
        """重建预设下拉菜单（预设增删后调用）。"""
        m = self._preset_menu
        m.clear()
        names = self.scan_presets.names()
        if not names:
            _empty = m.addAction(tr("（暂无预设）"))
            _empty.setEnabled(False)
        else:
            for name in names:
                m.addAction(name).triggered.connect(
                    lambda _checked=False, n=name: self._apply_scan_preset(n)
                )
        m.addSeparator()
        m.addAction(tr("保存当前设置为预设...")).triggered.connect(
            self._save_current_as_preset
        )
        if names:
            del_menu = m.addMenu(tr("删除预设"))
            for name in names:
                del_menu.addAction(name).triggered.connect(
                    lambda _checked=False, n=name: self._delete_preset(n)
                )

    # ── 设备收藏 (docs/reviews/UI_REVIEW.md P1-3) ──

    def _toggle_favorite(self, result):
        """切换设备收藏状态，并同步星标 / 计数 / 当前筛选。"""
        if result is None:
            return
        now = self.favorites.toggle(result)
        item = self._ip_item_map.get(result.ip)
        if item is not None:
            self._apply_favorite_mark(item, result)
        self._refresh_filter_counts()
        if self.filter_key == "favorite":
            self._filter_results()
        self.status_bar.showMessage(tr("已加入收藏") if now else tr("已取消收藏"))

    # ── 结果筛选 (docs/reviews/UI_REVIEW.md P1-4) ──

    def _set_filter(self, key: str):
        """切换结果筛选。筛选条 chip 与「视图 > 筛选」菜单共用这一个入口。"""
        self.filter_key = key
        if hasattr(self, "filter_bar"):
            self.filter_bar.set_key(key)
        self._sync_filter_menu()
        self._filter_results()
        self._save_settings()
        # 筛选只对列表视图有意义：在概览页点「在线 112」的语义是"我要看这 112 台"，
        # 而不是"把概览也过滤一遍"（概览本身就是全量统计）。所以顺带切回列表。
        # 注意 `_load_settings` 也会调本函数，但那时 all_results 还是空的，
        # 因此不会误触发切换。
        if self.all_results and getattr(self, "view_mode", DEFAULT_VIEW_MODE) != "list":
            self._set_view_mode("list", save=False)

    def _sync_filter_menu(self):
        """同步「视图 > 筛选」菜单的单选态到当前 filter_key。"""
        for key, act in getattr(self, "_filter_actions", {}).items():
            act.blockSignals(True)
            act.setChecked(key == self.filter_key)
            act.blockSignals(False)

    # ── 列预设 (docs/reviews/UI_REVIEW.md P1-2) ──

    def _apply_default_column_widths(self):
        """按**当前语言**套用默认列宽（不动可见性与列序）。

        载入时若发现老布局是另一种语言下存的，就调它重算一次 —— 列宽是按像素
        持久化的，语言变了旧像素值就不再合适（中文 78px 的状态列放不下英文
        `Online`，会省略成 `Onl…`）。
        """
        header = self.table.header()
        count = self.table.columnCount()
        for _col, _w in column_widths_for(current_lang()).items():
            # 🔴 越界护栏。`QHeaderView.resizeSection()` / `setSectionResizeMode()`
            # 拿到超出列数的索引时**不报错，而是越界写坏堆** —— 症状是"随机某条
            # 无关用例段错误"，堆栈每次都不一样（v5 加「风险」列时实测：同一组
            # 用例有时第 1 条崩、有时第 3 条崩）。宁可少设一列宽度并告警，也不要
            # 让整个进程随机崩掉。真正的护栏是
            # `tests/test_column_widths.py::test_column_count_matches_labels`。
            if _col >= count:
                app_logging.get_logger(__name__).warning(
                    "列宽表含不存在的列 %d（当前 %d 列），已跳过", _col, count)
                continue
            header.setSectionResizeMode(_col, QHeaderView.Interactive)
            header.resizeSection(_col, _w)

    def _apply_column_preset(self, key: str):
        """按预设切换可见列，并同步自定义勾选态。"""
        preset = next((p for p in COLUMN_PRESETS if p[0] == key), None)
        if preset is None:
            return
        _key, _label, cols = preset
        visible = set(cols)
        for ci in range(self.table.columnCount()):
            self.table.setColumnHidden(ci, ci not in visible)
        self._sync_col_actions()
        self._sync_preset_selection()
        self.status_bar.showMessage(tr("已应用列预设") + ": " + tr(_label))

    def _on_column_toggled(self, col: int, checked: bool):
        """自定义列勾选。手动改动后取消预设的单选态（已不再对应任何预设）。"""
        self.table.setColumnHidden(col, not checked)
        self._sync_preset_selection()

    def _detect_active_preset(self):
        """当前可见列恰好等于某个预设时返回其 key，否则 None。"""
        visible = frozenset(
            ci for ci in range(self.table.columnCount())
            if not self.table.isColumnHidden(ci)
        )
        for key, _label, cols in COLUMN_PRESETS:
            if frozenset(cols) == visible:
                return key
        return None

    def _sync_col_actions(self):
        """把 13 个自定义勾选框同步到当前隐藏状态（静默，避免递归触发）。"""
        for _ci, _act in getattr(self, "_col_actions", {}).items():
            _act.blockSignals(True)
            _act.setChecked(not self.table.isColumnHidden(_ci))
            _act.blockSignals(False)

    def _sync_preset_selection(self):
        """把预设单选态同步到当前可见列（不匹配任何预设时全部取消勾选）。"""
        active = self._detect_active_preset()
        for key, act in getattr(self, "_col_preset_actions", {}).items():
            act.blockSignals(True)
            act.setChecked(key == active)
            act.blockSignals(False)

    # ── 行高 (docs/reviews/UI_REVIEW.md P2-1.2) ──

    def _apply_row_density(self):
        """把行高档位写进表格的动态属性，由 QSS 决定 `min-height`。

        ⚠️ 动态属性改完**必须** `unpolish` / `polish` 才会重绘 —— 这是 Qt 的已知
        行为，`overview.set_tone()` 那处踩过同一个坑。少了这两行，切档位毫无反应。

        行高的具体数字在 `assets/styles/*.qss`（`[density="..."]::item` 的
        `min-height` 与 `padding`），与 `design_tokens.ROW_HEIGHT` /
        `ROW_PADDING_V` 由 `test_design_tokens` 保证一致。
        """
        value = getattr(self, "row_density", DEFAULT_DENSITY)
        if value not in DENSITIES:
            value = DEFAULT_DENSITY
            self.row_density = value
        self.table.setProperty("density", value)
        self.table.style().unpolish(self.table)
        self.table.style().polish(self.table)
        self.table.viewport().update()

    def _set_row_density(self, value: str):
        """切换行高（菜单触发）：立即生效并持久化。"""
        if value not in DENSITIES:
            self._sync_density_actions()
            return
        if value == getattr(self, "row_density", DEFAULT_DENSITY):
            self._sync_density_actions()
            return
        self.row_density = value
        self._apply_row_density()
        self._sync_density_actions()
        self._save_settings()

    def _sync_density_actions(self):
        """把行高单选态同步到当前值（静默，避免递归触发）。"""
        for key, act in getattr(self, "_density_actions", {}).items():
            act.blockSignals(True)
            act.setChecked(key == self.row_density)
            act.blockSignals(False)

    # ── 配置持久化 (P2-2) ──
    def _load_settings(self):
        """载入持久化配置：主题 / 扫描参数 / 网段 / 窗口几何 / 列布局。

        本方法只负责"载入期不许回写"这一层，实际内容在 `_load_settings_values`。
        拆开是因为必须用 `try/finally` 把整段载入包住，而直接缩进 100 多行会让
        这个 diff 完全没法读。见 `_save_settings` 里那道闸门的说明。
        """
        self._loading_settings = True
        try:
            self._load_settings_values()
        finally:
            self._loading_settings = False

    def _load_settings_values(self):
        s = self.settings
        # 主题：优先读新的 theme/mode；旧配置只有 theme/dark + theme/auto_time，
        # 迁移规则见 system_theme.migrate_mode（原则是"外观不变"）。
        _mode = system_theme.migrate_mode(
            s.value("theme/mode", "", type=str),
            has_legacy_dark=s.contains("theme/dark"),
            legacy_dark=s.value("theme/dark", False, type=bool),
            legacy_auto=s.value("theme/auto_time", False, type=bool),
        )
        self.theme_mode = _mode
        self.auto_time = (_mode == system_theme.MODE_TIME)
        self.dark_mode = self._resolve_dark()
        self._sync_theme_menu()
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
        # 默认关：需要 SNMP，且会在网络里产生额外流量（见控件创建处注释）
        self.switch_map_check.setChecked(
            s.value("scan/switch_map", False, type=bool))
        # 持续发现同样默认关（见控件创建处注释）
        self.watch_check.setChecked(s.value("scan/watch", False, type=bool))
        self.responder_check.setChecked(
            s.value("scan/name_responder", False, type=bool))
        # 跨网段补齐 MAC：同样默认关（见控件创建处注释）
        self.arp_mac_check.setChecked(
            s.value("scan/arp_mac", False, type=bool))
        # 三层设备地址：GATEWAY_AUTO = 扫描时自动探测本机默认网关，也可填具体 IP。
        # ⚠ 空串在这里是**非法值**（它在 ScanThread 里表示"不做补齐"），所以必须
        # 回落到 AUTO —— 否则用户把配置清空一次，这个选项就永久静默失效了。
        _arp_gw = (s.value("scan/arp_gateway", GATEWAY_AUTO, type=str) or "").strip()
        self.arp_gateway = _arp_gw or GATEWAY_AUTO
        self.tcp_scan_mode = s.value("scan/tcp_mode", "connect", type=str)
        if self.tcp_scan_mode not in ("connect", "syn", "udp"):
            self.tcp_scan_mode = "connect"
        # 扫描礼貌档（v2.1 §2.4）：规范名。旧配置没这个键 → fast，
        # 与改造前逐字节等价（验收项「兼容旧行为」）。
        _tp = s.value("scan/throttle", throttle.DEFAULT_POLICY, type=str)
        self.throttle_policy = (_tp if _tp in throttle.POLICY_NAMES
                                else throttle.DEFAULT_POLICY)
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
        # IP 网段：过滤掉无法解析 / 超过规模上限的旧配置，
        # 否则升级前的 ini 里若存了超大网段，一扫描就会耗尽内存。
        self._dropped_ranges = 0
        ranges = s.value("scan/ip_ranges", [])
        if isinstance(ranges, str):
            ranges = [r.strip() for r in ranges.splitlines() if r.strip()]
        if ranges:
            kept, total = [], 0
            for r in ranges:
                n = count_ip_range(r)
                if n <= 0 or n > MAX_IPS_PER_RANGE or total + n > MAX_IPS_TOTAL:
                    self._dropped_ranges += 1
                    continue
                kept.append(r)
                total += n
            self.ip_range_items = kept
            self._update_range_list()
        # 窗口几何 & 状态
        geom = s.value("window/geometry")
        if isinstance(geom, QByteArray):
            self.restoreGeometry(geom)
        state = s.value("window/state")
        if isinstance(state, QByteArray):
            self.restoreState(state)
        # 详情面板高度
        _split = s.value("ui/detail_splitter")
        if isinstance(_split, QByteArray):
            self.detail_splitter.restoreState(_split)
        # 列布局 (宽度 / 顺序 / 隐藏 / 排序指示)
        # 仅在列布局版本一致时恢复 header_state，避免列序变更后旧状态错位。
        # 版本号的含义与"为什么改动默认布局必须 +1"见 CURRENT_LAYOUT_VER 的定义。
        saved_ver = int(s.value("table/layout_ver", 0) or 0)
        hdr_state = s.value("table/header_state")
        # 语言也要对得上：列宽按**像素**存，而部分列的表头/单元格文本随语言变化。
        # 老配置（1.7.1 及以前）没有这个键 —— 中文用户沿用其布局（当时就是中文），
        # 英文用户则重算一次英文列宽。
        _cur_lang = current_lang()
        _saved_lang = str(s.value("table/header_lang", "") or "")
        _lang_ok = (_saved_lang == _cur_lang
                    or (not _saved_lang and _cur_lang == "zh-CN"))
        if (saved_ver == CURRENT_LAYOUT_VER and _lang_ok
                and isinstance(hdr_state, QByteArray)):
            self.table.header().restoreState(hdr_state)
        else:
            # 首次运行（或列布局版本已变）：套用「巡检」预设。默认把全部列
            # 全铺出来会立刻横向滚动，且多数列在第一次扫描时都是空的。
            self._apply_column_preset("inspect")
            self._apply_default_column_widths()
            # 排序指示也要显式定死。`QHeaderView` 的默认排序方向是**降序**，
            # 而恢复出来的 header_state 里存的是用户上次点的方向 —— 于是同一个
            # 版本会出现"新装 IP 从大到小、老配置从小到大"的行为不一致。
            # 只在没有可恢复状态时才设，避免覆盖用户自己的排序选择。
            self.table.sortByColumn(0, Qt.AscendingOrder)
        # 同步"显示列"菜单：自定义勾选态 + 预设单选态
        self._sync_col_actions()
        self._sync_preset_selection()
        # 结果筛选（规范 key，与界面语言无关）
        _fk = s.value("view/filter_key", "online", type=str)
        self._set_filter(_fk if _fk in dict(FILTERS) else "online")
        # 结果视图（列表 / 概览）
        _vm = s.value("view/mode", DEFAULT_VIEW_MODE, type=str)
        self.view_mode = _vm if _vm in dict(VIEW_MODES) else DEFAULT_VIEW_MODE
        if hasattr(self, "_view_buttons"):
            _btn = self._view_buttons.get(self.view_mode)
            if _btn is not None:
                _btn.setChecked(True)
        # 行高档位（规范值 compact / comfortable）。旧配置里没有这个键 →
        # 落到默认的「舒适」，与改造前的 26px 行高**逐像素一致**。
        _rd = s.value("view/row_density", DEFAULT_DENSITY, type=str)
        self.row_density = _rd if _rd in DENSITIES else DEFAULT_DENSITY
        self._apply_row_density()
        self._sync_density_actions()
        # 首次启动授权声明（docs/reviews/CODE_REVIEW.md P2-14）。0 = 从没确认过。
        self.authorization_notice_ack = s.value("legal/notice_ack", 0, type=int)

    def _save_settings(self):
        """保存当前配置到 ipscanner.ini。"""
        # 🔴 载入期间**禁止回写**。`_load_settings()` 会经 `_set_filter()` 间接调到
        # 这里，而排在 `_set_filter` **之后**才载入的键（`view/mode`、
        # `view/row_density`）此时还停在 `_init_ui` 落的默认值 —— 一旦回写就把用户
        # 存的值覆盖成默认值，且**没有任何提示**（表现为"改了设置重启就重置"）。
        # 闸门由 `_load_settings` 置位、`finally` 还原。
        if getattr(self, "_loading_settings", False):
            return
        s = self.settings
        s.setValue("theme/mode", self.theme_mode)
        s.setValue("legal/notice_ack",
                   getattr(self, "authorization_notice_ack", 0))
        # 保留旧键：① 旧版本回退时行为可预期；② 外部脚本/文档仍可能读它
        s.setValue("theme/dark", self.dark_mode)
        s.setValue("theme/auto_time", self.auto_time)
        s.setValue("scan/timeout_ms", self.timeout_spin.value())
        s.setValue("scan/max_threads", self.threads_spin.value())
        s.setValue("scan/port_scan", self.port_scan_check.isChecked())
        s.setValue("scan/mdns", self.mdns_check.isChecked())
        s.setValue("scan/switch_map", self.switch_map_check.isChecked())
        s.setValue("scan/watch", self.watch_check.isChecked())
        s.setValue("scan/name_responder", self.responder_check.isChecked())
        s.setValue("scan/arp_mac", self.arp_mac_check.isChecked())
        # 存**当前值**而不是字面量 GATEWAY_AUTO —— 写字面量会把用户填的三层设备
        # IP 每次启动重置掉（列布局 / view/row_density 都踩过这个坑）。
        s.setValue("scan/arp_gateway", getattr(self, "arp_gateway", GATEWAY_AUTO))
        s.setValue("scan/tcp_mode", self.tcp_scan_mode)
        # 存**当前值**而不是字面量 fast：写成字面量会把用户选的档位每次启动
        # 重置掉（列布局那次就是这么静默重置的）。
        s.setValue("scan/throttle",
                   getattr(self, "throttle_policy", throttle.DEFAULT_POLICY))
        s.setValue("scan/level", self.scan_level)
        s.setValue("scan/protocols", self.selected_protocols)
        s.setValue("scan/ip_ranges", self.ip_range_items)
        s.setValue("window/geometry", self.saveGeometry())
        s.setValue("window/state", self.saveState())
        s.setValue("table/header_state", self.table.header().saveState())
        s.setValue("table/layout_ver", CURRENT_LAYOUT_VER)
        # 列宽与语言相关：记下这份布局是在哪种语言下调的（见载入处的比对）
        s.setValue("table/header_lang", current_lang())
        # 详情面板高度（用户拖动分隔条后应保持）
        s.setValue("ui/detail_splitter", self.detail_splitter.saveState())
        s.setValue("view/filter_key", getattr(self, "filter_key", "online"))
        s.setValue("view/mode", getattr(self, "view_mode", DEFAULT_VIEW_MODE))
        # 存**当前值**而不是字面量 —— 写成字面量会导致每次启动都把用户的
        # 选择重置掉（批次 1 踩过这个坑：列布局被反复重置）。
        s.setValue("view/row_density",
                   getattr(self, "row_density", DEFAULT_DENSITY))
        s.sync()

    def _connect_signals(self):
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.local_subnet_btn.clicked.connect(self._scan_local_subnet)
        self.c_subnet_btn.clicked.connect(self._scan_c_class_subnet)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        # 详情面板随选区刷新（含键盘上下键切换）
        self.table.currentItemChanged.connect(self._on_current_item_changed)
        self.detail_panel.rescan_requested.connect(self._rescan_ip)
        self.detail_panel.copy_requested.connect(self._copy_to_clipboard)
        # 「编辑资产信息…」（v2.3 §3.4）：面板只发身份键，弹窗与写库在 Mixin 里。
        self.detail_panel.asset_edit_requested.connect(self._edit_asset)
        # 扫描参数变化时刷新空状态页的配置摘要
        self.port_scan_check.toggled.connect(lambda _c: self._update_empty_hint())
        self.mdns_check.toggled.connect(lambda _c: self._update_empty_hint())
        # 持续发现：勾上/取消 = 起停后台轮询（详见 watch_mixin.py）
        self.watch_check.toggled.connect(self._on_watch_toggled)

    def _build_view_toggle(self) -> QWidget:
        """构建「列表 / 概览」视图切换控件（docs/reviews/UI_REVIEW.md P3-2）。"""
        box = QWidget()
        box.setObjectName("viewToggle")
        lay = QHBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        self._view_group = QButtonGroup(self)
        self._view_group.setExclusive(True)
        self._view_buttons = {}
        for key, label in VIEW_MODES:
            btn = QPushButton(tr(label))
            btn.setObjectName("viewBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFocusPolicy(Qt.TabFocus)
            btn.setChecked(key == self.view_mode)
            btn.clicked.connect(lambda _c, k=key: self._set_view_mode(k))
            self._view_group.addButton(btn)
            lay.addWidget(btn)
            self._view_buttons[key] = btn
        return box

    # ── 结果视图：列表 / 概览 (docs/reviews/UI_REVIEW.md P3-2) ──

    def _set_view_mode(self, key: str, save: bool = True):
        """切换结果视图（列表 / 概览）。"""
        if key not in dict(VIEW_MODES):
            key = DEFAULT_VIEW_MODE
        self.view_mode = key
        btn = getattr(self, "_view_buttons", {}).get(key)
        if btn is not None and not btn.isChecked():
            btn.setChecked(True)
        self._apply_view_mode(save=save)

    def _update_result_controls(self):
        """无结果时隐藏「视图切换 + 筛选条」整行（docs/reviews/UI_REVIEW_ROUND2.md §5 第 9 项）。

        它们都是"对已有结果做筛选 / 换视角"的控件：一条结果都没有时，chip 上的
        计数全是 0，视图切换也只能切到同一个空状态页 —— 留着只会让人误以为
        "是筛选把结果藏起来了"。扫描出结果后立即恢复。

        用 `getattr(..., None)` 取值：`_load_settings` 可能在构造途中就调到本
        函数，那时这几个控件还没建出来。
        """
        visible = bool(self.all_results)
        for widget in (getattr(self, "view_toggle", None),
                       getattr(self, "tb3_sep", None),
                       getattr(self, "filter_scroll", None)):
            if widget is not None:
                widget.setVisible(visible)

    def _apply_view_mode(self, save: bool = True):
        """按当前 view_mode 切到对应页面；无结果时一律回到空状态引导页。"""
        self._update_result_controls()
        if not self.all_results:
            self.result_stack.setCurrentIndex(0)
            self._update_empty_hint()
            return
        if self.view_mode == "overview":
            self._refresh_overview()
            self.result_stack.setCurrentIndex(2)
        else:
            self.result_stack.setCurrentIndex(1)
        if save:
            self._save_settings()

    def _refresh_overview(self):
        """把最新结果推给概览页（统计逻辑在 ui_logic.build_overview）。"""
        self.overview.set_data(ui_logic.build_overview(
            self.all_results, self._changes, self._conflicts))

    def _refresh_overview_if_visible(self):
        """仅当概览页**正在显示**时刷新。

        刻意做成惰性：概览统计要遍历全部结果（/16 网段是 6.5 万条），
        而绝大多数用户根本不会打开概览 —— 每次扫描都白算一遍是纯浪费。
        切到概览时 `_apply_view_mode` 会重新计算，所以不会看到旧数据。
        """
        if getattr(self, "view_mode", DEFAULT_VIEW_MODE) != "overview":
            return
        if self.result_stack.currentIndex() != 2:
            return
        self._refresh_overview()

    # ── 空状态 / 结果页切换 (docs/reviews/UI_REVIEW.md P0-2) ──

    def _show_results_page(self, show_results: bool):
        """在「空状态引导页」与「结果页」之间切换。

        结果页有两张：列表（表格 + 详情面板）与概览，具体切到哪张由
        `view_mode` 决定 —— 扫描开始时不该把正在看概览的用户硬拽回列表。
        """
        self._update_result_controls()
        if not show_results:
            self.result_stack.setCurrentIndex(0)
            self._update_empty_hint()
            return
        self.result_stack.setCurrentIndex(
            2 if getattr(self, "view_mode", DEFAULT_VIEW_MODE) == "overview" else 1)

    def _update_empty_hint(self):
        """刷新空状态页底部的「当前扫描配置」摘要 —— 让用户按下扫描前就知道会扫什么。"""
        parts = []
        if self.port_scan_check.isChecked():
            parts.append(tr("级别") + " " + scan_level_label(self.scan_level))
            parts.append(tr("端口数") + f" {len(get_ports_for_level(self.scan_level))}")
        else:
            parts.append(tr("未开启端口扫描"))
        parts.append(tr("超时") + f" {self.timeout_spin.value()} ms")
        if self.mdns_check.isChecked():
            parts.append(tr("mDNS 发现已开启"))
        self.empty_state.set_scan_hint(" · ".join(parts))

    def _on_current_item_changed(self, current, _previous):
        self._refresh_detail_panel(current)

    def _refresh_detail_panel(self, item):
        """把选中设备（服务子项会上溯到父设备）的完整信息推给详情面板。"""
        if item is None:
            self.detail_panel.clear()
            return
        ip = self._item_ip(item)
        result = self._result_map.get(ip) if ip else None
        if result is None:
            self.detail_panel.clear()
            return
        self.detail_panel.set_device(
            result,
            self._conflict_notes_for(ip),
            self._change_notes_for(ip),
            self._device_timeline_for(result),
            self._port_exposure_for(result),
            self._asset_for(result),
        )

    def _asset_for(self, result) -> dict:
        """该设备的**台账行**（v2.3 §3.4）；没有台账行时返回 `{}`。

        与 `_device_timeline_for()` / `_port_exposure_for()` 同款缓存：详情面板
        「每选中一行」就刷新，而台账只在**写入新快照**（回填可能补出新行）或
        **用户编辑**后才变（`_timeline_cache` / `_asset_cache` 同点失效）。

        🔴 身份键用 `asset_identity_key()`（在库里已有的键上找），**不能**
           `identity_key(mac, ip)` 现算 —— 真键由写入端的 `resolve_identity()`
           决定（LAA 随机 MAC 走指纹降级），现算会对不上，详情面板永远是空的
           （v2.3 §3.3 踩过同款）。
        """
        if result is None:
            return {}
        key = (result.mac or "").upper().strip() or f"ip:{(result.ip or '')}"
        if not key:
            return {}
        cache = getattr(self, "_asset_cache", None)
        if cache is None:
            cache = self._asset_cache = {}
        if key in cache:
            return cache[key]
        rec = {}
        try:
            ident = history_store.asset_identity_key(
                mac=result.mac, ip=result.ip, db_path=self.history_db)
            if ident:
                rec = history_store.get_asset(ident, db_path=self.history_db) or {}
        except Exception as exc:
            # 台账是"锦上添花"：历史库损坏 / 被占用不该让详情面板整体打不开
            # （与 `_device_timeline_for()` 同一条）。
            app_logging.get_logger(__name__).warning(
                "读取资产台账失败（%s）: %s", result.ip, exc)
            rec = {}
        cache[key] = rec
        return rec

    def _port_exposure_for(self, result, limit: int = 8) -> list:
        """该设备**当前仍开放**的端口暴露行（v2.3 §3.3）。

        数据源是 `asset_events` 的 `port_open` / `port_close` ——
        `assets.open_ports` 只存"此刻开放的端口"，答不出
        「这个 23 端口是昨天开的还是开了两年」。

        与 `_device_timeline_for()` 同款缓存：同一台设备常被反复点开，
        而事件流只在**写入新快照后**才可能变（`_timeline_cache` 同点失效，
        见 `history_mixin._save_snapshot`）。
        """
        if result is None:
            return []
        key = (result.mac or "").upper().strip() or f"ip:{(result.ip or '')}"
        if not key:
            return []
        cache = getattr(self, "_exposure_cache", None)
        if cache is None:
            cache = self._exposure_cache = {}
        if key in cache:
            return cache[key]
        rows = []
        try:
            ident = history_store.asset_identity_key(
                mac=result.mac, ip=result.ip, db_path=self.history_db)
            if ident:
                events = history_store.read_asset_events(
                    identity_key=ident, db_path=self.history_db)
                rows = trend_store.port_exposure(
                    events, identity_key=ident)["open"][:limit]
        except Exception as exc:
            # 暴露时长是"锦上添花"：历史库损坏/被占用不该让详情面板整体打不开
            # （与 `_device_timeline_for()` 同一条）。
            app_logging.get_logger(__name__).warning(
                "读取端口暴露时长失败（%s）: %s", result.ip, exc)
            rows = []
        cache[key] = rows
        return rows

    def _conflict_notes_for(self, ip) -> list:
        """该 IP 命中的冲突描述（供详情面板「风险」分区展示）。"""
        notes = []
        for c in getattr(self, "_conflicts", []):
            if ip in c.ips:
                notes.append(f"[{c.severity_label}] {c.description}")
        return notes

    def _change_notes_for(self, ip) -> list:
        """该 IP 命中的变更描述（供详情面板「变更」分区展示）。"""
        notes = []
        for c in getattr(self, "_changes", []):
            if ip and c.ip == ip:
                notes.append(f"[{c.type_label}] {c.description}")
        return notes

    # ── 变更索引 / 历史轨迹 (docs/reviews/UI_REVIEW.md P3-1) ──

    def _rebuild_change_index(self) -> dict:
        """把 `self._changes` 折叠成 `{ip: [变更类型, ...]}` 并缓存。

        折叠规则本身是纯函数（`ui_logic.build_change_index`），这里只负责
        把当前状态喂进去并记到 `self._change_map`。
        """
        self._change_map = ui_logic.build_change_index(
            self._changes, self.all_results)
        return self._change_map

    def _device_timeline_for(self, result, limit: int = 6) -> list:
        """该设备在历史快照中的出现轨迹（最近 `limit` 次）。

        结果按 (MAC 或 IP) 缓存：详情面板在"每选中一行"时刷新，而同一台设备
        常被反复点开（看服务、看变更）。缓存只在**写入新快照后**失效 ——
        快照没变，轨迹就不可能变。
        """
        if result is None:
            return []
        key = (result.mac or "").upper().strip() or f"ip:{(result.ip or '')}"
        if not key:
            return []
        cache = getattr(self, "_timeline_cache", None)
        if cache is None:
            cache = self._timeline_cache = {}
        if key in cache:
            return cache[key]
        try:
            entries = history_store.device_timeline(
                mac=result.mac, ip=result.ip,
                db_path=self.history_db, limit=limit,
            )
        except Exception as exc:
            # 轨迹是"锦上添花"：历史库损坏/被占用不应让详情面板整体打不开。
            app_logging.get_logger(__name__).warning(
                "读取设备历史轨迹失败（%s）: %s", result.ip, exc)
            entries = []
        cache[key] = entries
        return entries

    def _rescan_ip(self, ip: str):
        """仅重扫指定 IP（详情面板「重新扫描」按钮）。"""
        if not ip:
            return
        self.range_input.setText(ip)
        self.ip_range_items = [ip]
        self._update_range_list()
        self._start_scan()

    def _copy_to_clipboard(self, text: str):
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.status_bar.showMessage(tr("已复制设备详情"))

    def _update_status_stats(self, total_ips=None):
        """在底部状态栏右侧汇总显示已添加网段/IP 与扫描结果统计。

        每条统计都走 `tr()`。此前这里是裸 f-string —— f-string 天然躲过
        `LanguagePackCompletenessTest`（它只收 `tr("…")` 的字面量参数），于是英文
        界面下状态栏整段是中文，测试却全绿。参数化文案统一用 `{占位符}` 模板 +
        `.format()`，与项目里其它带参数的文案保持一致。
        """
        parts = []
        if self.ip_range_items:
            if total_ips is None:
                total_ips = self._total_ips()
            parts.append(tr("已添加: {ranges} 个网段, {ips} 个IP").format(
                ranges=len(self.ip_range_items), ips=total_ips))
        if self.all_results:
            total = len(self.all_results)
            online = sum(1 for r in self.all_results if r.status == "online")
            offline = sum(1 for r in self.all_results if r.status == "offline")
            unknown = total - online - offline
            parts.append(
                tr("{online} 开机状态, {offline} 关机状态, {unknown} 未知状态").format(
                    online=online, offline=offline, unknown=unknown))
            matched = sum(1 for r in self.all_results if r.excel_matched)
            if self.library.is_loaded() and matched:
                parts.append(tr("{n} 已匹配").format(n=matched))
            # 冲突计数
            high = sum(1 for c in self._conflicts if c.severity == SEVERITY_HIGH)
            warn = sum(1 for c in self._conflicts if c.severity == SEVERITY_WARNING)
            if high:
                parts.append(tr("⚠ {n} 冲突").format(n=high))
            elif warn:
                parts.append(tr("⚠ {n} 警告").format(n=warn))
        self.status_stats_label.setText("  |  ".join(parts))

    def _update_range_list(self):
        if self.ip_range_items:
            total_ips = self._total_ips()
            # 紧凑显示: 网段数 + IP总数 (保留兼容，但控件已隐藏)
            self.range_list_label.setText(
                tr("已添加: {ranges} 个网段, {ips} 个IP").format(
                    ranges=len(self.ip_range_items), ips=total_ips)
            )
            # Tooltip 显示完整列表
            tip = "\n".join(self.ip_range_items)
            self.range_list_label.setToolTip(tip)
            self.range_input.setToolTip(tip)
            # 内部存储 (保持兼容)
            display = "\n".join(self.ip_range_items)
            display += tr("\n— 共 {ranges} 个网段, {ips} 个IP").format(
                ranges=len(self.ip_range_items), ips=total_ips)
            self.range_list.setPlainText(display)
            self._update_status_stats(total_ips)
        else:
            self.range_list_label.setText("")
            self.range_list_label.setToolTip("")
            self.range_input.setToolTip("")
            self.range_list.clear()
            self._update_status_stats(0)

    # --- 扫描 ---


    # ── 首次启动授权声明（docs/reviews/CODE_REVIEW.md P2-14）──

    def _authorization_notice_text(self) -> str:
        """授权声明的正文（HTML）。

        单独抽成方法而不是内联在弹窗里：`test_authorization_notice` 要断言
        「授权 / 法律责任 / 你自己拥有」这些合规要点**还在**。文案漏掉"授权"
        二字，这个弹窗就白弹了，而那种退化**不会有任何测试失败**。
        """
        return (
            tr("<h3>使用前请确认授权范围</h3>")
            + tr("<p>本工具会主动向目标主机发送 ICMP、ARP、TCP、UDP 报文并进行服务探测。</p>")
            + tr("<p><b>请仅对你自己拥有、或已获得明确书面授权的网络使用。</b></p>")
            + tr("<p>未经授权扫描他人网络在多数国家和地区属于违法行为（例如中国《网络安全法》"
                 "《刑法》第 285 条、美国《计算机欺诈与滥用法》CFAA、英国《计算机滥用法》）。"
                 "使用者需自行承担全部法律责任，作者不对任何误用或由此造成的损失负责。</p>")
        )

    def maybe_show_authorization_notice(self) -> bool:
        """首次启动弹一次授权声明；返回 False = 用户未同意（调用方应退出）。

        ⚠️ **故意不在 `__init__` 里调用**：`msg_consent()` 内部是模态 `exec_()`，
        会一直阻塞到用户点按钮为止。放进构造函数，所有"建一个 MainWindow 看行为"
        的测试都会在无头环境（没人点按钮）里**永久挂死** —— 表现为 CI 卡住而不是
        失败，是最难查的一类故障。改由 `main.py` 在 `show()` 之后显式调用；测试
        可以单独调它。

        确认后写 `legal/notice_ack = NOTICE_VERSION`，之后不再弹。改声明文案必须
        同步把 `ui_logic.NOTICE_VERSION` +1（见那里的说明），否则新增条款对已装
        用户永远不可见。
        """
        acked = getattr(self, "authorization_notice_ack", 0)
        if not ui_logic.needs_authorization_notice(acked):
            return True
        if not msg_consent(
            self,
            tr("使用前请确认授权范围"),
            self._authorization_notice_text(),
            tr("我已获得授权，继续使用"),
            tr("退出"),
        ):
            return False
        self.authorization_notice_ack = ui_logic.NOTICE_VERSION
        self._save_settings()
        return True

    def _show_about(self):
        _data_info = tr("数据目录：") + data_dir() + "\n" + tr("存放方式：") + data_dir_label()
        # 小字配色按主题取，且**不能写进 tr() 的键** —— 否则改一次配色就要同步改
        # 两个语言包（同 ui_dialogs 图例那条，见 tests/test_ui_dialogs_colors.py
        # 的 `test_legend_keeps_the_colour_out_of_the_translation_key`）。
        _muted = token("gray", self.dark_mode)
        msg_about(self, tr("关于"), (
            tr("<h3>局域网终端扫描工具</h3>")
            # 版本号从可翻译串里拆出来：它不需要翻译，混进去会导致
            # 每次发版都要同步改语言包，且漏改时英文界面回退成中文。
            + f"<p>{tr('版本')} {__version__}</p>"
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
            + "</ul>"
            # `font-size` 只能内联：这是 QMessageBox 的富文本，QSS 选择器够不到它。
            + f"<p style='color:{_muted}; font-size:11px;'>{_data_info}</p>"
            + f"<p style='color:{_muted};'>{tr('基于 PyQt5 开发')}</p>"
        ))

    def closeEvent(self, event):
        # 退出前必须停掉所有在跑的后台线程：
        # QThread 对象若在 run() 未返回时被销毁，PyQt 会直接 abort 进程
        # （"QThread: Destroyed while thread is still running"）。
        for _thread in (self.scan_thread, self.wmi_thread, self.netbios_thread):
            if _thread and _thread.isRunning():
                _thread.stop()
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.wait(3000)
        # WMI 单次查询超时 8s，等待上限给到略大一点；取消后未开始的任务会被跳过
        if self.wmi_thread and self.wmi_thread.isRunning():
            self.wmi_thread.wait(10000)
        if self.netbios_thread and self.netbios_thread.isRunning():
            self.netbios_thread.wait(3000)
        self._save_settings()
        event.accept()
