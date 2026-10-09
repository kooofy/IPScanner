# -*- coding: utf-8 -*-
"""历史快照对话框：两次快照差异对比、跨快照的历史设备条件查询。"""
from datetime import datetime

from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QLineEdit, QCheckBox, QDateTimeEdit, QFileDialog,
)

import history_store
from i18n import tr
from scanner.constants import device_class_label
from ui_msg import msg_info, msg_warn
from ui_utils import _compare_snapshots

from ._shared import _theme_color


class HistoryCompareDialog(QDialog):
    """选择两次历史快照进行差异对比。"""

    def __init__(self, parent=None, db_path=None):
        super().__init__(parent)
        self.db_path = db_path
        self.setWindowTitle(tr("扫描历史对比"))
        self.setMinimumSize(720, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.hist = self._load_history()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        tip = QLabel(tr("选择基准与对比快照，查看两次扫描之间网络中设备的变化。"))
        layout.addWidget(tip)

        sel_row = QHBoxLayout()
        sel_row.setSpacing(8)
        sel_row.addWidget(QLabel(tr("基准快照:")))
        self.base_combo = QComboBox()
        self.target_combo = QComboBox()
        sel_row.addWidget(self.base_combo, 1)
        sel_row.addWidget(QLabel(tr("对比快照:")))
        sel_row.addWidget(self.target_combo, 1)
        cmp_btn = QPushButton(tr("对比"))
        cmp_btn.setObjectName("primaryBtn")
        cmp_btn.clicked.connect(self._do_compare)
        sel_row.addWidget(cmp_btn)
        layout.addLayout(sel_row)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels([tr("IP 地址"), tr("变化类型"), tr("旧值"), tr("新值")])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        # 配色交给 QSS（`QLabel#dialogHintSmall`）—— 本对话框拿不到主题标志，
        # 而硬编码的深灰在深色底上几乎不可见。
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("dialogHintSmall")
        layout.addWidget(self.summary_label)

        close_btn = QPushButton(tr("关闭"))
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

        self.setLayout(layout)
        self._populate_combos()

    def _load_history(self):
        try:
            return history_store.load_all(self.db_path)
        except Exception:
            return []

    @staticmethod
    def _fmt_time(ts):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def _populate_combos(self):
        self.base_combo.clear()
        self.target_combo.clear()
        if not self.hist:
            self.base_combo.addItem(tr("(无历史快照)"))
            self.target_combo.addItem(tr("(无历史快照)"))
            self.base_combo.setEnabled(False)
            self.target_combo.setEnabled(False)
            return
        # 最新在末尾，倒序展示
        for idx in range(len(self.hist) - 1, -1, -1):
            snap = self.hist[idx]
            label = f"{self._fmt_time(snap['time'])}  ({len(snap['devices'])} 台)"
            self.base_combo.addItem(label, idx)
            self.target_combo.addItem(label, idx)
        # 默认：基准=上上次，对比=最近一次
        if len(self.hist) >= 2:
            self.base_combo.setCurrentIndex(1)
            self.target_combo.setCurrentIndex(0)
        elif len(self.hist) == 1:
            self.base_combo.setCurrentIndex(0)
            self.target_combo.setCurrentIndex(0)

    def _do_compare(self):
        if not self.hist:
            self.summary_label.setText(tr("尚无历史快照，请先完成至少两次扫描。"))
            return
        bi = self.base_combo.currentData()
        ti = self.target_combo.currentData()
        if bi is None or ti is None:
            return
        base = self.hist[bi]
        target = self.hist[ti]
        diffs = _compare_snapshots(base, target)
        self.table.setRowCount(len(diffs))
        for row, d in enumerate(diffs):
            self.table.setItem(row, 0, QTableWidgetItem(d["ip"]))
            self.table.setItem(row, 1, QTableWidgetItem(d["change"]))
            self.table.setItem(row, 2, QTableWidgetItem(d["old"]))
            self.table.setItem(row, 3, QTableWidgetItem(d["new"]))
        added = sum(1 for d in diffs if d["change"] == tr("新增设备"))
        removed = sum(1 for d in diffs if d["change"] == tr("消失设备"))
        changed = len(diffs) - added - removed
        self.summary_label.setText(
            f"共 {len(diffs)} 处变化：新增 {added} · 消失 {removed} · 其他变更 {changed}   "
            f"(基准 {self._fmt_time(base['time'])} → 对比 {self._fmt_time(target['time'])})"
        )


class HistoryQueryDialog(QDialog):
    """历史条件查询：按类型 / 网段 / 首见时间 / IP 关键字跨快照聚合检索历史设备。

    结果展示每台设备的「当前已知属性」（最近一次出现且非空为准）、
    首见时间与末见时间，按末见时间降序。
    """

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return [tr("IP 地址"), tr("状态"), tr("类型"), tr("主机名"), "MAC",
                tr("首见"), tr("末见")]

    def __init__(self, parent=None, db_path=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.db_path = db_path
        self.setWindowTitle(tr("历史条件查询"))
        self.setMinimumSize(900, 540)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(12, 12, 12, 12)
        vbox.setSpacing(8)

        # ── 筛选栏 ──
        form = QFormLayout()
        form.setSpacing(6)

        self.class_edit = QLineEdit()
        self.class_edit.setPlaceholderText(tr("设备类型子串，如 路由器 / PC / 打印机（留空=不限）"))
        form.addRow(tr("设备类型:"), self.class_edit)

        self.net_edit = QLineEdit()
        self.net_edit.setPlaceholderText(tr("网段，如 192.168.1.0/24 或 10.0.0（留空=不限）"))
        form.addRow(tr("网段:"), self.net_edit)

        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText(tr("IP 关键字，如 192.168.1.（留空=不限）"))
        form.addRow(tr("IP 关键字:"), self.ip_edit)

        time_row = QHBoxLayout()
        time_row.setSpacing(6)
        self.date_from = QDateTimeEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))
        self.date_to = QDateTimeEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.date_to.setDateTime(QDateTime.currentDateTime())
        self.time_unlimited = QCheckBox(tr("不限时间"))
        self.time_unlimited.setChecked(True)
        self.time_unlimited.toggled.connect(self._on_time_toggle)
        time_row.addWidget(QLabel(tr("首见起:")))
        time_row.addWidget(self.date_from)
        time_row.addWidget(QLabel(tr("止:")))
        time_row.addWidget(self.date_to)
        time_row.addWidget(self.time_unlimited)
        form.addRow(tr("首见时间:"), time_row)
        self._on_time_toggle(True)

        vbox.addLayout(form)

        # ── 按钮行 ──
        btn_row = QHBoxLayout()
        btn_query = QPushButton(tr("查询"))
        btn_query.setObjectName("primaryBtn")
        btn_query.clicked.connect(self._run_query)
        btn_row.addWidget(btn_query)
        btn_reset = QPushButton(tr("重置"))
        btn_reset.clicked.connect(self._reset)
        btn_row.addWidget(btn_reset)
        btn_row.addStretch()
        self.count_label = QLabel("")
        self.count_label.setObjectName("dialogHint")
        btn_row.addWidget(self.count_label)
        vbox.addLayout(btn_row)

        # ── 结果表 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        hdr = self.table.horizontalHeader()
        _w = {0: 130, 1: 60, 2: 110, 3: 140, 4: 150, 5: 150, 6: 150}
        for c, w in _w.items():
            hdr.setSectionResizeMode(c, QHeaderView.Interactive)
            hdr.resizeSection(c, w)
        vbox.addWidget(self.table, 1)

        # ── 底部 ──
        bottom = QHBoxLayout()
        bottom.addStretch()
        btn_export = QPushButton(tr("导出 CSV"))
        btn_export.clicked.connect(self._export_csv)
        bottom.addWidget(btn_export)
        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        bottom.addWidget(btn_close)
        vbox.addLayout(bottom)

        # 打开即展示全部历史设备
        self._run_query()

    @staticmethod
    def _fmt(ts):
        if not ts:
            return "—"
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    def _on_time_toggle(self, checked):
        self.date_from.setEnabled(not checked)
        self.date_to.setEnabled(not checked)

    def _reset(self):
        self.class_edit.clear()
        self.net_edit.clear()
        self.ip_edit.clear()
        self.time_unlimited.setChecked(True)
        self._run_query()

    def _run_query(self):
        device_class = self.class_edit.text().strip() or None
        network = self.net_edit.text().strip() or None
        ip_substr = self.ip_edit.text().strip() or None
        if self.time_unlimited.isChecked():
            f_after = f_before = None
        else:
            f_after = self.date_from.dateTime().toSecsSinceEpoch()
            f_before = self.date_to.dateTime().toSecsSinceEpoch()
        try:
            rows = history_store.query_history(
                device_class=device_class, network=network,
                first_seen_after=f_after, first_seen_before=f_before,
                ip_substr=ip_substr, db_path=self.db_path,
            )
        except Exception as e:
            msg_warn(self, tr("查询失败"), str(e))
            return
        self._fill_table(rows)
        self.count_label.setText(f"共 {len(rows)} 台设备")

    def _fill_table(self, rows):
        self.table.setRowCount(len(rows))
        for r, d in enumerate(rows):
            self.table.setItem(r, 0, QTableWidgetItem(d.get("ip", "")))
            st = d.get("status", "")
            st_item = QTableWidgetItem(st)
            if st == "online":
                st_item.setForeground(_theme_color("online", self.dark))
            elif st == "offline":
                st_item.setForeground(_theme_color("muted", self.dark))
            st_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(r, 1, st_item)
            self.table.setItem(r, 2, QTableWidgetItem(
                device_class_label(d.get("device_class", "")) or "—"))
            self.table.setItem(r, 3, QTableWidgetItem(d.get("hostname", "") or "—"))
            self.table.setItem(r, 4, QTableWidgetItem(d.get("mac", "") or "—"))
            self.table.setItem(r, 5, QTableWidgetItem(self._fmt(d.get("first_seen"))))
            self.table.setItem(r, 6, QTableWidgetItem(self._fmt(d.get("last_seen"))))

    def _export_csv(self):
        if self.table.rowCount() == 0:
            msg_info(self, tr("提示"), tr("暂无数据可导出。"))
            return
        default_name = f"历史查询_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出查询结果"), default_name, tr("CSV 文件 (*.csv)")
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.COLS)
                for r in range(self.table.rowCount()):
                    writer.writerow([
                        self._cell(r, 0), self._cell(r, 1), self._cell(r, 2),
                        self._cell(r, 3), self._cell(r, 4),
                        self._cell(r, 5), self._cell(r, 6),
                    ])
            msg_info(self, tr("导出成功"), f"已保存到：\n{path}")
        except Exception as e:
            msg_warn(self, tr("导出失败"), str(e))

    def _cell(self, row, col):
        item = self.table.item(row, col)
        return item.text() if item else ""
