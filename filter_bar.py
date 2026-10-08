# -*- coding: utf-8 -*-
"""结果筛选条（对应 UI_REVIEW.md 的 P1-4）。

设计动机
--------
原实现的筛选控件是「视图 > 筛选」菜单里的一组单选，工具栏上只留了一个
`setVisible(False)` 的 QComboBox 当值载体。两个真实问题：

1. **筛选不可见**。默认筛选是「仅在线」，用户扫一个 /24 得到 254 条结果、
   界面只显示 12 条时，第一反应是"程序坏了 / 这个网段没设备"。
2. **没有量级感**。"242 台离线"本身是有价值的信息，藏在菜单里就丢了。

本控件把筛选项做成常驻的 chip，并带上实时计数。

语言无关约定
------------
chip 的身份是**规范 key**（`all` / `online` / …），不是显示文本。显示文本
经 `tr()` 惰性翻译。这样切换界面语言不会影响筛选逻辑 —— 旧实现拿
`tr("仅在线")` 的**翻译结果**做比较，英文界面下每次比较都要重新翻译一遍，
且一旦语言包缺词条就会静默失配。
"""
from PyQt5.QtCore import Qt, QSize, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QHBoxLayout, QPushButton, QScrollArea, QFrame, QSizePolicy,
)

from i18n import tr

#: 筛选项：规范 key → 规范中文标签。标签在构建控件时才 tr()。
#:
#: 「变更」放在「冲突」之后：两者都是"需要人看一眼"的异常类结果，相邻更易扫读。
#: 它**始终显示**（哪怕计数为 0），不做"有变更才出现"的动态显隐 ——
#: chip 忽隐忽现会让用户每次都要重新找位置，而固定位置本身就是可发现性。
FILTERS = (
    ("all", "全部"),
    ("online", "在线"),
    ("offline", "离线"),
    ("favorite", "收藏"),
    ("services", "有服务"),
    ("conflict", "冲突"),
    ("change", "变更"),
    ("library", "已匹配"),
)

DEFAULT_FILTER = "online"

#: chip 的左右内边距（px），**必须与 QSS 里 `#filterChip { padding: 2px 6px }`
#: 的第二个值一致** —— `_ChipButton.sizeHint()` 靠它把文字宽度换算成控件宽度。
#: 不一致会导致 chip 要么文字被截断、要么白白多占空间。
#: `tests/test_change_timeline.py::ChipSizeHintTest` 会校验两者同步。
CHIP_H_PADDING = 6


class _ChipButton(QPushButton):
    """拒绝被压缩的 chip 按钮。

    Qt 默认的 `QPushButton.minimumSizeHint()` 比 `sizeHint()` 小得多，于是当
    一行放不下时，布局会把每个 chip 压窄，按钮文字被裁成 `Changes…`。
    对筛选条来说这恰好毁掉了它存在的理由 —— 用户要的就是"一眼看清有多少条"。

    这里把 `minimumSizeHint` 提升为与 `sizeHint` 相同（尺寸算法与 Qt 原生
    一致：文字宽 + QSS 内边距 + 边框），于是放不下时布局**不能再压缩**，
    改由外层的 `FilterChipScroll` 提供横向滚动 —— 宁可让用户滚一下，
    也不要给出读不出数字的标签。
    """

    #: 边框宽度（QSS 里是 1px 实线，左右各一）
    _BORDER = 2
    #: 与 QSS 的 min-height 对齐，避免只有短文字时被压扁
    _MIN_HEIGHT = 20

    def sizeHint(self) -> QSize:
        fm = self.fontMetrics()
        width = fm.horizontalAdvance(self.text()) + 2 * CHIP_H_PADDING + self._BORDER
        height = max(self._MIN_HEIGHT, fm.height() + 6)
        return QSize(width, height)

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()


class FilterChipScroll(QScrollArea):
    """筛选条的横向滚动容器：放得下时与直接摆放无异，放不下时可滚动。

    为什么需要：8 个 chip 带 3 位计数时中文约需 700px、英文约需 1200px，
    而窗口最小宽度是 1024px。不给滚动就只能压缩 chip，压缩就意味着截断。
    中文界面在最小窗口下本来就放得下，因此**多数情况下根本不会出现滚动条**，
    这个容器是纯粹的兜底。
    """

    #: 横向滚动条出现时额外占用的高度（与 QSS 里 `#filterScroll QScrollBar`
    #: 的 height 保持一致）。不预留的话滚动条会盖住 chip 文字。
    _BAR_EXTENT = 10

    def __init__(self, bar, parent=None):
        super().__init__(parent)
        self.setObjectName("filterScroll")
        self._bar = bar
        self.setWidget(bar)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self._sync_height()

    def _needs_scroll(self) -> bool:
        return self._bar.sizeHint().width() > self.viewport().width()

    def _sync_height(self):
        """按"当前是否需要滚动条"调整高度，避免无谓地多占一行空白。"""
        want = self._bar.sizeHint().height() + (
            self._BAR_EXTENT if self._needs_scroll() else 0)
        if self.height() != want or self.minimumHeight() != want:
            self.setFixedHeight(want)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_height()


class FilterChipBar(QWidget):
    """一组可勾选的筛选 chip，带计数。"""

    #: 选中项变化，携带规范 key
    filter_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("filterBar")
        self._key = DEFAULT_FILTER
        self._labels = {}
        self._counts = {}
        self._buttons = {}
        self._build()

    def _build(self):
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)
        for key, label in FILTERS:
            self._labels[key] = label
            btn = _ChipButton(tr(label))
            btn.setObjectName("filterChip")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFocusPolicy(Qt.TabFocus)
            btn.clicked.connect(lambda _checked, k=key: self.set_key(k, emit=True))
            self._buttons[key] = btn
            row.addWidget(btn)
        self._sync_checked()
        self._sync_text()

    # ── 对外接口 ──────────────────────────────────────────

    def current_key(self) -> str:
        return self._key

    def set_key(self, key: str, emit: bool = False):
        """设置当前筛选。emit=True 时对外发信号（用户点击）。"""
        if key not in self._buttons:
            return
        changed = key != self._key
        self._key = key
        self._sync_checked()
        if emit and changed:
            self.filter_changed.emit(key)

    def set_counts(self, counts: dict):
        """更新各筛选项的计数。缺失的 key 不显示数字。"""
        self._counts = dict(counts or {})
        self._sync_text()

    def set_counts_visible(self, visible: bool):
        """结果为空时隐藏计数，避免满屏 "0"。"""
        self._counts_visible = visible
        self._sync_text()

    # ── 内部 ──────────────────────────────────────────────

    def _sync_checked(self):
        for key, btn in self._buttons.items():
            btn.setChecked(key == self._key)

    def _sync_text(self):
        show_counts = getattr(self, "_counts_visible", True)
        for key, btn in self._buttons.items():
            label = tr(self._labels[key])
            count = self._counts.get(key)
            if show_counts and count is not None:
                btn.setText(f"{label} {count}")
            else:
                btn.setText(label)
