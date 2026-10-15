# -*- coding: utf-8 -*-
"""在线率趋势与稳定性对话框（v2.3 §3.2）：「这段时间的在线率是怎么变的」。

与 `AuditActivityDialog`（合规自查）分工明确：那个看**我向谁发了包**，
这个看**网络自己变成了什么样**。

🔴 数据源两张表，都**不参与 `prune()`**（这是趋势能跨过 20 份快照上限存活的
唯一原因，见 `docs/ROADMAP_V2.3.md` §4）：
* 曲线 → `history_store.read_scan_trend()`（`trend_observations`）；
* 稳定性 / 首现 → `history_store.read_asset_events()`（`asset_events`）。

🔴 三条界面口径：
* **没有记录必须说清原因 + 给下一步** —— 只说「没有数据」会让用户以为
  「这段时间网络没变化」，而真相可能只是「趋势自 v2.3 起才开始写」。
* **MTBF / MTTR 是采样近似，不是连续监控**：真实掉线发生在两次扫描之间，
  精度下限就是扫描间隔。短于扫描间隔的抖动**根本看不到** ——
  「翻转 0 次」只说明没看见，不等于稳定。样本不足给「样本不足」，
  🔴 **不显示 0 冒充结果**。
* **切换时间窗 / 粒度不重扫**：只换 SQL 的 `since` 与聚合方式，纯本地读库。
"""
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

import history_store
import trend_store
from i18n import tr
from ui_msg import msg_warn

# ── 规范值 → 文案（**待翻译字面量**，取用时必须过 `tr()`） ──────────────
#
# 🔴 这些是**字面量标签表**：AST 收集不到，必须登记进
# `tests/test_i18n_lazy.py::_label_tables()`，否则漏翻**无告警**。

#: 时间窗：combo 的 data 是 `trend_store.WINDOW_*` 字符串（不是小时数 ——
#: 小时数的换算只有一处，在 `trend_store.WINDOW_HOURS` 里）。
_WINDOW_TEXT = {
    "24h": "过去 24 小时",
    "7d": "过去 7 天",
    "30d": "过去 30 天",
    "all": "全部历史",
}

#: 粒度：raw = 每次观测一个点，day = 按自然日聚合。
_GRANULARITY_TEXT = {
    "raw": "每次观测",
    "day": "按天聚合",
}

#: 「没有数据」的原因 → (说明, 下一步)。🔴 每条都必须带下一步动作。
_REASON_TEXT = {
    trend_store.REASON_NO_RECORDS: (
        "所选时间窗内没有任何趋势观测记录。",
        "趋势观测自 v2.3 起才随每次扫描自动写入，更早的扫描不在其内。"
        "先跑一次扫描，再回来查就有数据了。",
    ),
    trend_store.REASON_OUT_OF_WINDOW: (
        "库里有趋势记录，但都不在所选时间窗内。",
        "把时间窗放大到「过去 30 天」或「全部历史」，或先跑一次扫描。",
    ),
    trend_store.REASON_NO_RANGE_DATA: (
        "所选网段在这个时间窗内没有按网段计数。",
        "网段名可能写错了，或这些数据来自 v2.3 §3.2 之前（那时不记每网段计数）。"
        "把范围切回「全部网段」看全局曲线，或换个网段。",
    ),
}

#: 范围下拉的「全部」项（网段名本身是取值，不需要翻译）。
_RANGE_ALL_TEXT = "全部网段"

#: 时长单位（`trend_store.DURATION_UNIT_*`）→ 后缀。`insufficient` 单独处理。
_UNIT_TEXT = {
    trend_store.DURATION_UNIT_SECOND: "秒",
    trend_store.DURATION_UNIT_MINUTE: "分钟",
    trend_store.DURATION_UNIT_HOUR: "小时",
    trend_store.DURATION_UNIT_DAY: "天",
}
_UNIT_INSUFFICIENT = "样本不足"

#: 曲线表列名。**列数与本表长度必须一致**（自本表派生，不写第二份字面量 ——
#: 第二份字面量会导致 `resizeSection` 越界，进而写坏堆）。
_COLUMN_LABELS = ("时间", "总数", "在线", "在线率")

#: 采样近似的就地声明（不冒充连续监控）。
_HINT_SAMPLING = ("⚠ MTBF / MTTR 是**扫描采样**近似：只看到扫描那一刻的状态，"
                  "短于扫描间隔的抖动看不到。「翻转 0 次」= 没看见，不等于稳定。")


def _label(table, value, fallback=""):
    """表驱动文案：**先 `tr()` 再返回**（表里存的是待翻译字面量）。"""
    text = table.get(value, fallback or value)
    return tr(text)


def _fmt_duration(seconds):
    """秒 → 人话。`None` / 非法一律说「样本不足」，🔴 不拿 0 冒充结果。

    分档逻辑在 `trend_store.duration_parts()`（**只有一份**），
    避免 CLI 与这里各写一套而漂移。
    """
    value, unit = trend_store.duration_parts(seconds)
    if unit == trend_store.DURATION_UNIT_NONE:
        return tr(_UNIT_INSUFFICIENT)
    if unit == trend_store.DURATION_UNIT_SECOND:
        return "%.0f %s" % (value, _label(_UNIT_TEXT, unit))
    return "%.1f %s" % (value, _label(_UNIT_TEXT, unit))


class TrendViewDialog(QDialog):
    """在线率趋势 + 稳定性（只读）。切换时间窗 / 粒度不触发任何扫描。"""

    def __init__(self, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.setWindowTitle(tr("在线率趋势"))
        self.setMinimumSize(660, 460)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部：时间窗 + 粒度 + 刷新 ──
        top = QHBoxLayout()
        top.setSpacing(6)
        top.addWidget(QLabel(tr("时间窗:")))
        self.window_combo = QComboBox()
        for key in trend_store.WINDOW_CHOICES:
            self.window_combo.addItem(_label(_WINDOW_TEXT, key), key)
        self.window_combo.setMinimumWidth(120)
        self.window_combo.currentIndexChanged.connect(self._reload)
        top.addWidget(self.window_combo)

        top.addWidget(QLabel(tr("粒度:")))
        self.gran_combo = QComboBox()
        for key in trend_store.GRANULARITY_CHOICES:
            self.gran_combo.addItem(_label(_GRANULARITY_TEXT, key), key)
        self.gran_combo.setMinimumWidth(110)
        self.gran_combo.currentIndexChanged.connect(self._reload)
        top.addWidget(self.gran_combo)

        top.addWidget(QLabel(tr("范围:")))
        self.range_combo = QComboBox()
        # 项在 `_reload()` 里按当前窗口出现过的网段重建（首项恒为「全部网段」）。
        self.range_combo.setMinimumWidth(150)
        self.range_combo.currentIndexChanged.connect(self._reload)
        top.addWidget(self.range_combo)

        top.addStretch()
        btn_refresh = QPushButton(tr("刷新"))
        btn_refresh.clicked.connect(self._reload)
        top.addWidget(btn_refresh)
        layout.addLayout(top)

        # ── 汇总区 ──
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.summary_label)

        self.next_label = QLabel("")
        self.next_label.setWordWrap(True)
        self.next_label.setObjectName("dialogHint")
        self.next_label.setVisible(False)
        layout.addWidget(self.next_label)

        # ── 曲线表 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(_COLUMN_LABELS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in _COLUMN_LABELS])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(not dark)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.hint_label = QLabel("")
        self.hint_label.setWordWrap(True)
        self.hint_label.setObjectName("dialogHint")
        layout.addWidget(self.hint_label)

        # ── 底部 ──
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

        self.setLayout(layout)
        self._reload()

    # ── 数据加载 ──

    def _sync_range_combo(self, names):
        """把网段下拉重建为「全部网段」+ 当前窗口出现过的网段。

        🔴 重建时必须 `blockSignals` —— 否则 `clear()` / `addItem()` 会触发
        `currentIndexChanged` → 再次 `_reload()`，无限递归。
        保留用户当前选择（还在列表里就用它，否则回到「全部网段」）。
        """
        wanted = self.range_combo.currentData()
        names = list(names)
        # 用户已选的网段若在当前窗口没出现，**保留它**（而不是悄悄切回「全部」）：
        # 这样用户能看到"这个网段在这个窗口内没有数据"的说明，而不是选择被无声抹掉。
        if wanted is not None and wanted not in names:
            names.append(wanted)
        items = [(tr(_RANGE_ALL_TEXT), None)] + [(n, n) for n in names]
        current = [(self.range_combo.itemText(i), self.range_combo.itemData(i))
                   for i in range(self.range_combo.count())]
        if current == items:
            return
        blocked = self.range_combo.blockSignals(True)
        self.range_combo.clear()
        for label, data in items:
            self.range_combo.addItem(label, data)
        idx = self.range_combo.findData(wanted)
        self.range_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.range_combo.blockSignals(blocked)

    def _reload(self):
        window = self.window_combo.currentData()
        granularity = self.gran_combo.currentData()
        try:
            since = trend_store.window_start(window=window)
            rows = history_store.read_scan_trend(since_ts=since)
            events = history_store.read_asset_events(since_ts=since)
        except Exception as e:  # noqa: BLE001
            msg_warn(self, tr("读取失败"), str(e))
            return

        self._sync_range_combo(trend_store.range_names(rows))
        range_name = self.range_combo.currentData()
        series = trend_store.online_ratio_series(rows, granularity=granularity,
                                                 range_name=range_name)
        if not rows:
            reason = trend_store.REASON_OUT_OF_WINDOW
            if not history_store.read_scan_trend():
                reason = trend_store.REASON_NO_RECORDS
        elif not series:
            # 有行没点：要么全在窗外，要么（选了网段时）该网段没有每网段计数。
            reason = (trend_store.REASON_NO_RANGE_DATA if range_name
                      else trend_store.REASON_OUT_OF_WINDOW)
        else:
            reason = None

        if reason:
            hint, action = _REASON_TEXT.get(
                reason, ("没有可用的趋势数据。", ""))
            self.summary_label.setText(tr(hint))
            self.next_label.setText(tr("下一步：") + tr(action))
            self.next_label.setVisible(bool(action))
            self.table.setRowCount(0)
            self.hint_label.setText("")
            return

        self.next_label.setVisible(False)
        ratios = [p["ratio"] for p in series]
        stab = trend_store.stability(events)
        self.summary_label.setText(
            tr("观测 {n} 次 · 当前 {cur} · 均值 {avg} · 最低 {lo} · 最高 {hi}").format(
                n=len(series), cur="%.1f%%" % (ratios[-1] * 100.0),
                avg="%.1f%%" % (sum(ratios) / len(ratios) * 100.0),
                lo="%.1f%%" % (min(ratios) * 100.0),
                hi="%.1f%%" % (max(ratios) * 100.0))
            + "\n"
            + tr("稳定性：翻转 {flips} 次 · 掉线 {fails} 次 · MTBF {mtbf}"
                 "（样本 {n}）· MTTR {mttr}（样本 {m}）").format(
                     flips=stab["flips"], fails=stab["failures"],
                     mtbf=_fmt_duration(stab["mtbf_seconds"]),
                     n=stab["mtbf_samples"],
                     mttr=_fmt_duration(stab["mttr_seconds"]),
                     m=stab["mttr_samples"])
            + "\n"
            + tr("时间窗：{win} · 粒度：{gran} · 范围：{scope}").format(
                win=_label(_WINDOW_TEXT, window),
                gran=_label(_GRANULARITY_TEXT, granularity),
                scope=(range_name if range_name else tr(_RANGE_ALL_TEXT))))

        self.table.setRowCount(len(series))
        for row, p in enumerate(series):
            stamp = datetime.fromtimestamp(p["time"])
            fmt = "%Y-%m-%d" if granularity == "day" else "%Y-%m-%d %H:%M"
            self.table.setItem(row, 0, QTableWidgetItem(stamp.strftime(fmt)))
            for col, value in ((1, str(p["total"])), (2, str(p["online"]))):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)
            ratio_item = QTableWidgetItem("%.1f%%" % (p["ratio"] * 100.0))
            ratio_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, ratio_item)
        self.table.resizeColumnsToContents()
        self.hint_label.setText(tr(_HINT_SAMPLING))
