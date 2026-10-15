# -*- coding: utf-8 -*-
"""扫描活动自查对话框（v2.2 §3.3）：「过去这段时间我向哪些网段发起过多少次扫描」。

与 `AuditLogDialog`（人话流水）分工明确：那个看**事件**，这个看**聚合**。
数据源只有一处 —— `audit_log.activity_summary()`（SQL 侧时间窗过滤），
而聚合的输入是**结构化**扫描汇总（`action=SUM_ACTION`，detail 是语言无关
JSON），不是给人看的自由文本：后者的 action/detail 是 `tr()` 结果，拿它
聚合等于拿 `tr()` 结果作比较，切一次界面语言结论就漂移。

🔴 三条界面口径：
* **没有记录必须说清原因 + 给下一步**（照 `history_store.port_utilization()`
  的教训）—— 只说「没有记录」会让用户以为「这段时间没扫过网」，而真相可能
  只是「结构化汇总自 v2.2 起才开始写」。
* **发包数是估算下限**（主机发现 + 在线设备端口探测），界面上就地标注，
  不冒充包计数器读数。
* **时间窗切换不重扫**：只换 SQL 的 `since` 条件，纯本地读库。
"""
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

import audit_log
from i18n import tr
from ui_msg import msg_warn

# ── 规范值 → 文案（**待翻译字面量**，取用时必须过 `tr()`） ──────────────
#
# 🔴 这些是**字面量标签表**：AST 收集不到，必须登记进
# `tests/test_i18n_lazy.py::_label_tables()`，否则漏翻**无告警**。

#: 时间窗选项：combo 的 data 是 `activity_summary()` 的 window_hours 实参
#: （24 / 168 / None=全部），显示名才是要翻译的东西。
_WINDOW_TEXT = {
    24: "过去 24 小时",
    168: "过去 7 天",
    None: "全部历史",
}

#: 「没有数据」的原因（`audit_log.REASON_NO_RECORDS`，语言无关）→ (说明, 下一步)。
#: 🔴 每条都必须带下一步动作。
_REASON_TEXT = {
    "no_records": (
        "所选时间窗内没有任何扫描汇总记录。",
        "结构化汇总自 v2.2 起才随每次扫描自动写入，更早的扫描不在其内。"
        "先跑一次扫描，再回来查就有数据了。",
    ),
}

#: 网段表的列名。**列数与本表长度必须一致**（自既有布局派生，不写第二份字面量）。
_COLUMN_LABELS = ("网段", "扫描次数", "累计地址", "最近一次")

_HINT_ESTIMATE = ("⚠ 发包数是估算下限（主机发现 + 在线设备端口探测），"
                  "不含 ARP / mDNS / 按需 enrich，不是包计数器读数。")

#: 视图定位：这是**合规与自我保护**用的自查，不是告警，也**不给**"你在扫描别人"
#: 的暗示（路线图 §3.3 的措辞硬约束）。本机扫描本机所在网段是运维日常动作。
_HINT_SCOPE = ("本视图只读本机审计库，用于自查（合规与自我保护），"
               "不含任何远端探测结果。")


def _label(table, value, fallback=""):
    """表驱动文案：**先 `tr()` 再返回**（表里存的是待翻译字面量）。"""
    text = table.get(value, fallback or value)
    return tr(text)


class AuditActivityDialog(QDialog):
    """扫描活动自查（只读）。窗口切换 = 换 SQL 时间窗，不触发任何扫描。"""

    def __init__(self, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.setWindowTitle(tr("扫描活动自查"))
        self.setMinimumSize(620, 420)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部：时间窗 + 刷新 ──
        top = QHBoxLayout()
        top.setSpacing(6)
        top.addWidget(QLabel(tr("时间窗:")))
        self.window_combo = QComboBox()
        for hours, text in _WINDOW_TEXT.items():
            self.window_combo.addItem(tr(text), hours)
        self.window_combo.setMinimumWidth(130)
        self.window_combo.currentIndexChanged.connect(self._reload)
        top.addWidget(self.window_combo)
        top.addStretch()
        btn_refresh = QPushButton(tr("刷新"))
        btn_refresh.clicked.connect(self._reload)
        top.addWidget(btn_refresh)
        layout.addLayout(top)

        # ── 汇总区 ──
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse)
        layout.addWidget(self.summary_label)

        self.next_label = QLabel("")
        self.next_label.setWordWrap(True)
        self.next_label.setObjectName("dialogHint")
        self.next_label.setVisible(False)
        layout.addWidget(self.next_label)

        # ── 网段表 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(_COLUMN_LABELS))
        self.table.setHorizontalHeaderLabels(
            [tr(c) for c in _COLUMN_LABELS])
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

        scope_label = QLabel(tr(_HINT_SCOPE))
        scope_label.setWordWrap(True)
        scope_label.setObjectName("dialogHint")
        layout.addWidget(scope_label)

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

    def _reload(self):
        window_hours = self.window_combo.currentData()
        try:
            s = audit_log.activity_summary(window_hours)
        except Exception as e:  # noqa: BLE001
            msg_warn(self, tr("读取失败"), str(e))
            return

        if s["reason"]:
            hint, action = _REASON_TEXT.get(
                s["reason"], ("没有可用的扫描活动数据。", ""))
            self.summary_label.setText(tr(hint))
            self.next_label.setText(tr("下一步：") + tr(action))
            self.next_label.setVisible(bool(action))
            self.table.setRowCount(0)
            self.hint_label.setText("")
            return

        self.next_label.setVisible(False)
        win = _label(_WINDOW_TEXT, s["window_hours"])
        self.summary_label.setText(
            tr("扫描 {n} 次 · 涉及 {m} 个网段").format(
                n=s["scan_count"], m=s["range_count"])
            + "\n" + tr("累计覆盖 {n} 个地址 · 在线设备 {m} 台次").format(
                n=s["total_ips"], m=s["total_online"])
            + "\n" + tr("其中扫了端口 {n} 次 · 发包估算约 {m} 个（下限）").format(
                n=s["port_scan_count"], m=s["estimated_probes"])
            + "\n" + tr("协议：") + self._chips(s["protocols"],
                                              tr("均未指定（只做默认主机发现）"))
            + "\n" + tr("礼貌档：") + self._chips(s["throttles"], tr("未记录"))
            + "\n" + tr("时间窗：") + win)

        self.table.setRowCount(len(s["ranges"]))
        for row, a in enumerate(s["ranges"]):
            self.table.setItem(row, 0, QTableWidgetItem(a["range"]))
            self.table.setItem(row, 1, QTableWidgetItem(str(a["scans"])))
            self.table.setItem(row, 2, QTableWidgetItem(str(a["ips"])))
            last = datetime.fromtimestamp(a["last_scan_ts"])
            item = QTableWidgetItem(last.strftime("%Y-%m-%d %H:%M"))
            item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, item)
        self.table.resizeColumnsToContents()
        self.hint_label.setText(tr(_HINT_ESTIMATE))

    @staticmethod
    def _chips(counts, empty_text):
        """`{"HTTP": 3}` → `HTTP ×3`（按次数倒序）；空表返回 `empty_text`。"""
        if not counts:
            return empty_text
        return "、".join(
            "%s ×%d" % (name, n) for name, n in sorted(
                counts.items(), key=lambda kv: (-kv[1], kv[0])))
