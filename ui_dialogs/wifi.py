# -*- coding: utf-8 -*-
"""无线切片对话框（v2.1 §2.2）：当前关联 / 信道拥塞 / 可见 AP / 漫游时间线。

界面只消费 `scanner.wifi.snapshot()` 的产物 —— 取数在后台线程里做（`netsh`
是子进程、`refresh=True` 还要等射频扫完），界面只负责把**四个问题**的答案摊开：

1. 我现在连的是哪个 AP / 哪个 SSID；
2. 我周围有哪些 AP、挤在哪几个信道（含"最空信道"建议）；
3. 这台机器的无线什么时候连过、断过、连失败过；
4. 这个 SSID/BSSID 对应哪个网段。

🔴 三条界面口径：
* **`refresh` 默认关**：打开对话框只读系统缓存，**不扰动射频**；想真扫一圈要
  用户点「重新扫描（主动扰动射频）」—— 按钮文案里就把代价说清楚。
* **拿不到就说拿不到**：`notes` 里每一项都翻成人话显示在底部；没有数据的地方
  显示「—」而不是编一个值。
* **色值只从 `theme_tokens` 取**（`tests/test_ui_dialogs_colors.py` 禁止字面量）。
"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView, QDialog, QGridLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from i18n import tr
from scanner import wifi
from ui_threads import WifiSnapshotThread

from ._shared import _theme_color

# ── 规范值 → 文案（**待翻译字面量**，取用时必须过 `tr()`） ──────────────
#
# 🔴 这三张是**字面量标签表**：AST 收集不到，必须登记进
# `tests/test_i18n_lazy.py::_label_tables()`，否则漏翻**无告警**。

_REASON_TEXT = {
    wifi.REASON_OK: "可用",
    wifi.REASON_NOT_WINDOWS: "本平台无此能力（无线切片是 Windows 独占项，不做跨平台等价）",
    wifi.REASON_NO_WLANAPI: "缺少 wlanapi.dll（精简版 / 老系统）—— 本项不可用，其余功能不受影响",
    wifi.REASON_SERVICE_STOPPED: "无线服务（WLAN AutoConfig）未运行 —— 启动该服务后重试",
    wifi.REASON_NO_ADAPTER: "没有无线网卡 —— 台式机 / 虚拟机属正常情况",
    wifi.REASON_QUERY_FAILED: "查询无线状态失败 —— 可能是权限或驱动问题，可稍后重试",
}

_NOTE_TEXT = {
    wifi.NOTE_NO_INTERFACE: "读不到当前关联的网卡信息",
    wifi.NOTE_DISCONNECTED: "无线网卡未连接",
    wifi.NOTE_NO_BSS: "没有扫到任何可见 AP（无线电可能被关闭）",
    wifi.NOTE_NO_ROAMING_LOG: "读不到漫游事件日志（需要 WLAN-AutoConfig 日志的读取权限）",
    wifi.NOTE_NO_SUBNET: "网卡与网段没关联上（见「当前关联」里的本机网段）",
}

#: `WifiSnapshot.notes` 里可能出现的**两类**规范值：`NOTE_*`（各项没拿到）
#: 与 `REASON_*`（能力不可用时整条快照只带这一个）。查文案要两张表都看。
_NOTES_LOOKUP = dict(_NOTE_TEXT)
_NOTES_LOOKUP.update(_REASON_TEXT)

_ROAM_TEXT = {
    wifi.ROAM_ATTEMPT: "开始关联",
    wifi.ROAM_ASSOCIATED: "关联成功",
    wifi.ROAM_FAILED: "关联失败",
    wifi.ROAM_DISCONNECTED: "断开",
}

_SOURCE_TEXT = {
    wifi.SOURCE_WLANAPI: "结构化 API",
    wifi.SOURCE_NETSH: "netsh 文本",
    wifi.SOURCE_WEVTUTIL: "事件日志",
    wifi.SOURCE_NONE: "无",
}

_MATCH_TEXT = {
    wifi.MATCH_BY_NAME: "按网卡名匹配",
    wifi.MATCH_BY_KEYWORD: "按「无线适配器」特征词匹配",
    wifi.MATCH_BY_NONE: "未关联上",
}

#: 「当前关联」页签的字段表：`(字段名, 取值函数)`，顺序即显示顺序。
#: 🔴 字段名是**字面量表**（取用时 `tr()`），必须登记进
#: `test_i18n_lazy._label_tables()` —— 放模块级是为了让那个测试能直接读它，
#: 不必构造对话框（构造需要 QApplication）。
_CURRENT_FIELDS = (
    ("适配器", lambda s: s.interface.display_name if s.interface else "—"),
    ("适配器描述",
     lambda s: (s.interface.description if s.interface else "") or "—"),
    ("状态", lambda s: (tr("已连接") if s.interface and s.interface.connected
                      else tr("未连接")) if s.interface else "—"),
    ("SSID", lambda s: (s.interface.ssid or tr("（隐藏）")) if s.interface else "—"),
    ("BSSID", lambda s: (s.interface.bssid or "—") if s.interface else "—"),
    ("波段", lambda s: (s.interface.band if s.interface else "") or "—"),
    ("信道", lambda s: (str(s.interface.channel)
                      if s.interface and s.interface.channel else "—")),
    ("信号", lambda s: ("%d%%" % s.interface.signal_percent
                      if s.interface and s.interface.signal_percent is not None
                      else "—")),
    ("RSSI", lambda s: ("%d dBm" % s.interface.rssi_dbm
                       if s.interface and s.interface.rssi_dbm is not None
                       else "—")),
    ("收发速率", lambda s: _rate_text(s.interface) if s.interface else "—"),
    ("无线电类型", lambda s: (s.interface.radio_type if s.interface else "") or "—"),
    ("身份验证", lambda s: (s.interface.auth if s.interface else "") or "—"),
    ("加密", lambda s: (s.interface.cipher if s.interface else "") or "—"),
    ("配置文件", lambda s: (s.interface.profile if s.interface else "") or "—"),
    ("数据来源", lambda s: _label(_SOURCE_TEXT, s.interface_source)),
    ("关联网段", lambda s: ", ".join(s.subnets) if s.subnets else tr("未关联上")),
    ("本机全部网段", lambda s: ", ".join(s.all_subnets) if s.all_subnets else "—"),
    ("关联依据", lambda s: _label(_MATCH_TEXT, s.subnet_match)),
)


def _rate_text(iface):
    """`接收 / 发送 Mbps`；两个都拿不到就 `—`（不编一个 0）。"""
    if iface.rx_mbps is None and iface.tx_mbps is None:
        return "—"
    return "%s / %s Mbps" % (iface.rx_mbps if iface.rx_mbps is not None else "—",
                             iface.tx_mbps if iface.tx_mbps is not None else "—")


def _label(table, value, fallback=""):
    """表驱动文案：**先 `tr()` 再返回**（表里存的是待翻译字面量）。"""
    tpl = table.get(value)
    if tpl is None:
        return fallback or tr("未知")
    return tr(tpl)


class WifiDialog(QDialog):
    """无线切片：四个问题的答案 + 「哪些没拿到、为什么」。"""

    @property
    def AP_COLS(self):
        """表头**每次读取时翻译** —— 类属性会在 import 期求值。"""
        return [tr("SSID"), tr("BSSID"), tr("波段"), tr("信道"), tr("信号"),
                tr("无线电类型"), tr("身份验证"), tr("加密")]

    @property
    def LOAD_COLS(self):
        return [tr("信道"), tr("AP 数"), tr("干扰源"), tr("最强信号"), tr("当前")]

    @property
    def ROAM_COLS(self):
        return [tr("时间"), tr("事件"), tr("SSID"), tr("原因")]

    def __init__(self, parent=None, dark=False, refresh=False, snapshot=None):
        super().__init__(parent)
        self.dark = dark
        self._thread = None
        self.snapshot = None
        self.setWindowTitle(tr("无线切片"))
        self.setMinimumSize(900, 620)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部：当前网卡一行 + 两个按钮 ──
        top = QHBoxLayout()
        top.setSpacing(8)
        self.head_label = QLabel(tr("正在读取无线状态..."))
        self.head_label.setObjectName("dialogHint")
        self.head_label.setWordWrap(True)
        top.addWidget(self.head_label, 1)

        self.btn_rescan = QPushButton(tr("重新扫描（主动扰动射频）"))
        self.btn_rescan.setToolTip(
            tr("让无线网卡真的扫一圈（WlanScan）。默认只读系统缓存，不会打扰射频；"
               "主动扫描会让无线短暂忙于扫描，可能影响当前连接质量。"))
        self.btn_rescan.clicked.connect(lambda: self.reload(refresh=True))
        top.addWidget(self.btn_rescan)
        layout.addLayout(top)

        # ── 四个页签 ──
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_current_tab(), tr("当前关联"))
        self.tabs.addTab(self._build_load_tab(), tr("信道拥塞"))
        self.tabs.addTab(self._build_ap_tab(), tr("可见 AP"))
        self.tabs.addTab(self._build_roam_tab(), tr("漫游时间线"))
        layout.addWidget(self.tabs, 1)

        # ── 底部：notes + 关闭 ──
        bottom = QHBoxLayout()
        self.notes_label = QLabel("")
        self.notes_label.setObjectName("dialogHint")
        self.notes_label.setWordWrap(True)
        bottom.addWidget(self.notes_label, 1)
        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        bottom.addWidget(btn_close)
        layout.addLayout(bottom)
        self.setLayout(layout)

        if snapshot is not None:              # 测试/调用方已经取好数 → 直接渲染
            self._render(snapshot)
        else:
            self.reload(refresh=refresh)

    # ── 四个页签的骨架 ──

    def _make_table(self, cols):
        table = QTableWidget()
        table.setColumnCount(len(cols))
        table.setHorizontalHeaderLabels(cols)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setAlternatingRowColors(not self.dark)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _build_current_tab(self):
        page = QWidget()
        grid = QGridLayout(page)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        self._current_values = []
        for row, (name, _getter) in enumerate(_CURRENT_FIELDS):
            key = QLabel(tr(name) + ":")
            key.setObjectName("dialogHint")
            value = QLabel("—")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(key, row, 0, Qt.AlignRight | Qt.AlignTop)
            grid.addWidget(value, row, 1)
            self._current_values.append(value)
        grid.setRowStretch(len(_CURRENT_FIELDS), 1)
        grid.setColumnStretch(1, 1)
        return page

    def _build_load_tab(self):
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(8, 8, 8, 8)
        box.setSpacing(6)
        self.load_hint = QLabel("")
        self.load_hint.setObjectName("dialogHint")
        self.load_hint.setWordWrap(True)
        box.addWidget(self.load_hint)
        self.load_table = self._make_table(self.LOAD_COLS)
        box.addWidget(self.load_table, 1)
        return page

    def _build_ap_tab(self):
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(8, 8, 8, 8)
        box.setSpacing(6)
        self.ap_hint = QLabel("")
        self.ap_hint.setObjectName("dialogHint")
        box.addWidget(self.ap_hint)
        self.ap_table = self._make_table(self.AP_COLS)
        box.addWidget(self.ap_table, 1)
        return page

    def _build_roam_tab(self):
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(8, 8, 8, 8)
        box.setSpacing(6)
        self.roam_hint = QLabel("")
        self.roam_hint.setObjectName("dialogHint")
        self.roam_hint.setWordWrap(True)
        box.addWidget(self.roam_hint)
        self.roam_table = self._make_table(self.ROAM_COLS)
        box.addWidget(self.roam_table, 1)
        return page

    # ── 取数 ──

    def reload(self, refresh=False):
        """在后台线程里取一次数据（不冻界面）。"""
        if self._thread is not None and self._thread.isRunning():
            return
        self.btn_rescan.setEnabled(False)
        self.head_label.setText(tr("正在读取无线状态..."))
        self._thread = WifiSnapshotThread(refresh=refresh)
        self._thread.finished_signal.connect(self._on_snapshot)
        self._thread.start()

    def _on_snapshot(self, snapshot):
        self._thread = None
        self.btn_rescan.setEnabled(True)
        self._render(snapshot)

    # ── 渲染 ──

    def _render(self, snapshot):
        self.snapshot = snapshot
        self._render_head(snapshot)
        self._render_current(snapshot)
        self._render_loads(snapshot)
        self._render_aps(snapshot)
        self._render_roam(snapshot)
        self._render_notes(snapshot)

    def _render_head(self, snap):
        cap = snap.capability
        if not cap.supported:
            self.head_label.setText(
                "%s — %s" % (tr("无线切片不可用"),
                             _label(_REASON_TEXT, cap.reason)))
            return
        iface = snap.interface
        if iface is None:
            self.head_label.setText(tr("无线切片：读不到当前网卡信息"))
            return
        state = tr("已连接") if iface.connected else tr("未连接")
        ssid = iface.ssid or tr("（隐藏）")
        self.head_label.setText(
            "%s · %s · %s · %s" % (iface.display_name, state, ssid,
                                   tr("共 %d 个可见 AP") % len(snap.bss_list)))

    def _render_current(self, snap):
        for (_name, getter), label in zip(_CURRENT_FIELDS, self._current_values):
            try:
                label.setText(str(getter(snap)))
            except Exception as e:              # noqa: BLE001 — 单行渲染失败不该整页崩
                label.setText("—")
                label.setToolTip(str(e))

    def _render_loads(self, snap):
        loads = snap.channel_loads()
        self.load_table.setRowCount(len(loads))
        for row, load in enumerate(loads):
            cells = [str(load.channel), str(load.ap_count),
                     str(load.overlapping) if load.band == wifi.BAND_24 else "—",
                     ("%d%%" % load.strongest_signal
                      if load.strongest_signal is not None else "—"),
                     tr("是") if load.is_current else ""]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col in (0, 1, 2, 4):
                    item.setTextAlignment(Qt.AlignCenter)
                if load.is_current:
                    item.setForeground(_theme_color("online", self.dark))
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                self.load_table.setItem(row, col, item)
        band = loads[0].band if loads else wifi.BAND_24
        best = wifi.quietest_channel(loads, band=band)
        if best is None:
            self.load_hint.setText(tr("没有可用的信道统计（没扫到带信道的 AP）。"))
        elif band == wifi.BAND_24:
            self.load_hint.setText(
                tr("当前波段 %s：建议 %d 信道（2.4 GHz 只看互不重叠的 1/6/11）。")
                % (band, best))
        else:
            self.load_hint.setText(
                tr("当前波段 %s：建议 %d 信道（AP 数最少）。") % (band, best))

    def _render_aps(self, snap):
        bss = snap.bss_list
        self.ap_table.setRowCount(len(bss))
        for row, b in enumerate(bss):
            cells = [b.ssid if b.ssid_known else tr("（隐藏 SSID）"), b.bssid,
                     b.band, str(b.channel) if b.channel else "—",
                     ("%d%%" % b.signal_percent if b.signal_percent is not None
                      else "—"),
                     b.radio_type or "—", b.auth or "—", b.cipher or "—"]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col in (3, 4):
                    item.setTextAlignment(Qt.AlignCenter)
                self.ap_table.setItem(row, col, item)
        hidden = sum(1 for b in bss if not b.ssid_known)
        hint = tr("共 %d 个可见 AP。") % len(bss)
        if hidden:
            hint += tr("其中 %d 个是隐藏 SSID。") % hidden
        self.ap_hint.setText(hint)

    def _render_roam(self, snap):
        events = snap.roam_events
        self.roam_table.setRowCount(len(events))
        for row, e in enumerate(events):
            when = (e.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                    if e.timestamp else "—")
            reason = e.reason_text or e.reason_code or ""
            cells = [when, _label(_ROAM_TEXT, e.kind), e.ssid or "—", reason]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if e.kind == wifi.ROAM_FAILED:
                    item.setForeground(_theme_color("danger", self.dark))
                self.roam_table.setItem(row, col, item)
        if events:
            self.roam_hint.setText(
                tr("共 %d 条关联/断开事件（来源：%s）。时间线是 SSID 粒度 —— "
                   "AutoConfig 这几条事件不带 BSSID，不能标成「漫游到某个 AP」。")
                % (len(events), _label(_SOURCE_TEXT, snap.roam_source)))
        else:
            self.roam_hint.setText(
                tr("没有读到关联/断开事件（来源：%s）。")
                % _label(_SOURCE_TEXT, snap.roam_source))

    def _render_notes(self, snap):
        if not snap.notes:
            self.notes_label.setText("")
            return
        parts = [_label(_NOTES_LOOKUP, n) for n in snap.notes]
        self.notes_label.setText(tr("说明：") + " · ".join(parts))

    # ── 收尾 ──

    def closeEvent(self, event):                # noqa: N802 — Qt 命名
        # 别让 QThread 在还跑着的时候被析构（会 abort）
        if self._thread is not None and self._thread.isRunning():
            self._thread.wait(3000)
        super().closeEvent(event)


__all__ = ["WifiDialog"]
