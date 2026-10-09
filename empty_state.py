# -*- coding: utf-8 -*-
"""空状态面板（对应 docs/reviews/UI_REVIEW.md 的 P0-2）。

设计动机
--------
原实现启动后就是一张**全空白表格**：没有引导、没有上一步提示、没有可点的
主操作。新用户的第一反应是"是不是坏了 / 我该点哪"。同类产品（Advanced IP
Scanner、Fing、SoftPerfect）在无结果时都会给一块引导区。

本面板提供三样东西：
1. 一句明确的当前状态说明；
2. 一个主 CTA（填入本机网段并立即开扫）与一个次 CTA（用输入框里的网段开扫）；
3. 当前扫描配置摘要 —— 让用户在按下扫描前就知道"会扫什么、扫多深"。

配色一律走 QSS（objectName 选择器），不在 Python 里硬编码颜色。
"""
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
)

from i18n import tr


class EmptyStatePanel(QWidget):
    """无扫描结果时的引导页。"""

    #: 点击「扫描本机所在子网」
    scan_local_requested = pyqtSignal()
    #: 点击「开始扫描」（用当前输入框里的网段）
    scan_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("emptyState")
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(8)
        root.addStretch(1)

        self.title = QLabel(tr("还没有扫描结果"))
        self.title.setObjectName("emptyTitle")
        self.title.setAlignment(Qt.AlignCenter)
        root.addWidget(self.title)

        self.subtitle = QLabel(tr("输入网段后点击「扫描」，或直接扫描本机所在子网。"))
        self.subtitle.setObjectName("emptySubtitle")
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setWordWrap(True)
        root.addWidget(self.subtitle)

        root.addSpacing(4)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        btns.addStretch(1)
        self.btn_local = QPushButton(tr("扫描本机所在子网"))
        # 主 CTA 用实心强调色（`#emptyPrimary`），与次按钮（`#emptySecondary`）
        # 拉开层级 —— 两者同为浅灰底时，"哪个才是推荐动作"完全看不出来。
        # 这里刻意**不复用** `#primaryBtn`：那是全应用共用的浅灰按钮样式，
        # 改它会把工具栏的「扫描」和两个对话框按钮一起改掉。
        self.btn_local.setObjectName("emptyPrimary")
        self.btn_local.setMinimumHeight(32)
        self.btn_local.clicked.connect(self.scan_local_requested.emit)
        btns.addWidget(self.btn_local)

        self.btn_scan = QPushButton(tr("开始扫描"))
        self.btn_scan.setObjectName("emptySecondary")
        self.btn_scan.setMinimumHeight(32)
        self.btn_scan.clicked.connect(self.scan_requested.emit)
        btns.addWidget(self.btn_scan)
        btns.addStretch(1)
        root.addLayout(btns)

        root.addSpacing(2)

        self.hint = QLabel("")
        self.hint.setObjectName("emptyHint")
        self.hint.setAlignment(Qt.AlignCenter)
        self.hint.setWordWrap(True)
        root.addWidget(self.hint)

        root.addStretch(1)

    def set_scan_hint(self, text: str):
        """更新底部「当前扫描配置」摘要。"""
        self.hint.setText(text or "")
        self.hint.setVisible(bool(text))

    def set_summary(self, text: str):
        """用最近一次扫描摘要替换引导副标题（有历史时）。"""
        if text:
            self.subtitle.setText(text)
