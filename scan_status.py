# -*- coding: utf-8 -*-
"""扫描进行中的「扫描态摘要条」：阶段 / 已扫 / 在线 / 有服务 / 用时 / [停止]。

对应 `docs/reviews/UI_REVIEW.md` 的 **P0-2 后半**（「扫描态」）。

为什么要单独一条
----------------
旧实现只有一个 `QProgressBar` 加状态栏一行文字，用户看得到「87%」，但看不到
**在干什么阶段、扫到几台、扫出东西没有、还要多久**。本项目是「三阶段发现管线
（存活探测 → ARP 补全 → mDNS 组播发现）+ 并发富化」，阶段信息在界面上完全不可见。

本模块只管**显示**：所有数值都由外部推进（`scan_mixin` 把线程信号转过来），
它不自己拉数据、不碰引擎 —— 因此可以在无网络、无引擎的环境下直接单测。
"""
import time

from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton

from design_tokens import SPACING_LG, SPACING_SM, SPACING_XS
from i18n import tr
from scanner.constants import phase_label
from ui_logic import format_elapsed


class ScanStatusBar(QFrame):
    """扫描态摘要条（默认隐藏，仅在扫描期间显示）。

    用法（见 `scan_mixin._start_scan` / `_on_scan_*`）：:

        bar.start(total_ips)                 # 显示 + 复位 + 开始计时
        bar.set_phase(name, index, total)    # 阶段切换
        bar.set_progress(current, total)     # 进度推进
        bar.set_counts(online, services)     # 实时计数
        bar.finish()                         # 停表 + 隐藏
    """

    #: 用户点了条上的「停止」
    stop_requested = pyqtSignal()

    #: 计时刷新间隔（毫秒）。1s 足够 —— 显示精度就是秒。
    TICK_MS = 1000

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("scanStatusBar")
        self.setVisible(False)

        self._started_at = None
        self._elapsed_s = 0
        self._current = 0
        self._total = 0
        self._online = 0
        self._services = 0

        row = QHBoxLayout(self)
        # 间距一律取设计令牌（`design_tokens.SPACING_*`），不再写字面量 ——
        # 本模块是间距令牌的首个接入方。
        row.setContentsMargins(SPACING_SM, SPACING_XS, SPACING_SM, SPACING_XS)
        row.setSpacing(SPACING_LG)

        self.lbl_phase = QLabel("")
        self.lbl_phase.setObjectName("scanPhase")

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setFixedHeight(16)
        self.progress_bar.setTextVisible(False)

        self.lbl_scanned = QLabel("")
        self.lbl_scanned.setObjectName("scanMetric")
        self.lbl_online = QLabel("")
        self.lbl_online.setObjectName("scanMetric")
        self.lbl_services = QLabel("")
        self.lbl_services.setObjectName("scanMetric")
        self.lbl_elapsed = QLabel("")
        self.lbl_elapsed.setObjectName("scanMetric")

        self.stop_btn = QPushButton(tr("停止"))
        self.stop_btn.setObjectName("scanStop")
        self.stop_btn.setMinimumHeight(22)
        self.stop_btn.clicked.connect(self.stop_requested.emit)

        row.addWidget(self.lbl_phase)
        row.addWidget(self.progress_bar, 1)
        for _w in (self.lbl_scanned, self.lbl_online,
                   self.lbl_services, self.lbl_elapsed):
            row.addWidget(_w)
        row.addWidget(self.stop_btn)

        self._timer = QTimer(self)
        self._timer.setInterval(self.TICK_MS)
        self._timer.timeout.connect(self.tick)

    # ── 生命周期 ──────────────────────────────────────────────

    def start(self, total_ips: int):
        """进入扫描态：复位所有计数、启动计时并显示自身。"""
        # ⚠️ 计时基线用 `time.perf_counter()` 而不是 `time.monotonic()`：
        # Windows 上 ≤3.12 的 monotonic 是 GetTickCount64，分辨率仅 15.6ms，
        # 秒级显示虽然看不出来，但测试里把基线往回拨一点点就会取到 0。
        # 详见 tests/test_rtt.py::CoarseClockRegressionTest 记的那个坑。
        self._started_at = time.perf_counter()
        self._elapsed_s = 0
        self._current = 0
        self._total = int(total_ips or 0)
        self._online = 0
        self._services = 0

        self.lbl_phase.setText(tr("准备中..."))
        self.progress_bar.setValue(0)
        self._refresh_scanned()
        self._refresh_counts()
        self._refresh_elapsed()
        self._timer.start()
        self.setVisible(True)

    def finish(self):
        """退出扫描态：停表并隐藏。

        隐藏而不是保留，与旧实现的 `progress_bar.setVisible(False)` 一致 ——
        结果已经在表格里了，再占一行只是噪声。
        """
        self._timer.stop()
        if self._started_at is not None:
            self._elapsed_s = int(time.perf_counter() - self._started_at)
            self._refresh_elapsed()
        self._started_at = None
        self.setVisible(False)

    # ── 由扫描信号驱动 ─────────────────────────────────────────

    def set_phase(self, name: str, index: int, total: int):
        """阶段切换。`name` 是语言无关的规范值，这里才翻译。"""
        self.lbl_phase.setText(
            tr("阶段: {name} ({i}/{n})").format(
                name=phase_label(name), i=index, n=total)
        )

    def set_progress(self, current: int, total: int):
        """进度推进（已扫 n / 总数 N）。"""
        self._current = int(current)
        if total:
            self._total = int(total)
        pct = int(self._current / self._total * 100) if self._total else 0
        self.progress_bar.setValue(max(0, min(100, pct)))
        self._refresh_scanned()

    def set_counts(self, online: int, services: int):
        """实时计数：在线台数、有服务台数。"""
        self._online = int(online)
        self._services = int(services)
        self._refresh_counts()

    def tick(self):
        """计时刷新（也供测试直接调用，免得等真实的 QTimer）。"""
        if self._started_at is None:
            return
        self._elapsed_s = int(time.perf_counter() - self._started_at)
        self._refresh_elapsed()

    # ── 内部刷新 ──────────────────────────────────────────────

    def _refresh_scanned(self):
        self.lbl_scanned.setText(
            tr("已扫 {c}/{t}").format(c=self._current, t=self._total))

    def _refresh_counts(self):
        self.lbl_online.setText(tr("在线 {n}").format(n=self._online))
        self.lbl_services.setText(tr("有服务 {n}").format(n=self._services))

    def _refresh_elapsed(self):
        self.lbl_elapsed.setText(
            tr("用时 {t}").format(t=format_elapsed(self._elapsed_s)))

    # ── 只读快照（测试与外部读取用） ────────────────────────────

    def snapshot(self) -> dict:
        """当前显示值的结构化快照。"""
        return {
            "phase": self.lbl_phase.text(),
            "scanned": self._current,
            "total": self._total,
            "online": self._online,
            "services": self._services,
            "elapsed_s": self._elapsed_s,
            "percent": self.progress_bar.value(),
        }
