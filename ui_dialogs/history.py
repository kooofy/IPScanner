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
from ui_threads import HistoryQueryThread, SnapshotCompareThread

from ._shared import _theme_color


class HistoryCompareDialog(QDialog):
    """选择两次历史快照进行差异对比。"""

    def __init__(self, parent=None, db_path=None):
        super().__init__(parent)
        self.db_path = db_path
        self.setWindowTitle(tr("扫描历史对比"))
        self.setMinimumSize(720, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.snaps = self._load_snapshot_meta()
        self._thread = None
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
        self.cmp_btn = QPushButton(tr("对比"))
        self.cmp_btn.setObjectName("primaryBtn")
        self.cmp_btn.clicked.connect(self._do_compare)
        sel_row.addWidget(self.cmp_btn)
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

    def _load_snapshot_meta(self):
        """只取快照**元信息**（每份一行：id / 时间 / 设备数 / 备注）。

        刻意不调 `load_all()` —— 那会把每份快照的设备明细全读进来。默认保留
        20 份快照、/16 网段下这是百万行级读盘，而这里只需要填两个下拉框。
        真正要对比的那两份，等用户点「对比」时再按需读（见 ui_threads）。
        """
        try:
            return history_store.list_snapshots(self.db_path)
        except Exception:
            return []

    @staticmethod
    def _fmt_time(ts):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def _populate_combos(self):
        self.base_combo.clear()
        self.target_combo.clear()
        if not self.snaps:
            self.base_combo.addItem(tr("(无历史快照)"))
            self.target_combo.addItem(tr("(无历史快照)"))
            self.base_combo.setEnabled(False)
            self.target_combo.setEnabled(False)
            return
        # 最新在末尾，倒序展示。itemData 存**快照 id**（而不是下标）：
        # 对比是异步的，下标会在列表变化时失效，id 不会。
        for idx in range(len(self.snaps) - 1, -1, -1):
            snap = self.snaps[idx]
            label = f"{self._fmt_time(snap['time'])}  ({snap.get('device_count', 0)} 台)"
            self.base_combo.addItem(label, snap["id"])
            self.target_combo.addItem(label, snap["id"])
        # 默认：基准=上上次，对比=最近一次
        if len(self.snaps) >= 2:
            self.base_combo.setCurrentIndex(1)
            self.target_combo.setCurrentIndex(0)
        elif len(self.snaps) == 1:
            self.base_combo.setCurrentIndex(0)
            self.target_combo.setCurrentIndex(0)

    def _do_compare(self):
        if not self.snaps:
            self.summary_label.setText(tr("尚无历史快照，请先完成至少两次扫描。"))
            return
        bi = self.base_combo.currentData()
        ti = self.target_combo.currentData()
        if bi is None or ti is None:
            return
        if self._thread is not None and self._thread.isRunning():
            return
        # 读两份快照 + 算 diff 都可能到百毫秒级（/16 网段），放后台线程。
        self.cmp_btn.setEnabled(False)
        self.summary_label.setText(tr("正在对比…"))
        self._thread = SnapshotCompareThread(bi, ti, db_path=self.db_path)
        self._thread.finished_signal.connect(self._on_compare_done)
        self._thread.failed.connect(self._on_compare_failed)
        self._thread.start()

    def _on_compare_done(self, diffs, base_time, target_time):
        self.cmp_btn.setEnabled(True)
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
            f"(基准 {self._fmt_time(base_time)} → 对比 {self._fmt_time(target_time)})"
        )

    def _on_compare_failed(self, message):
        self.cmp_btn.setEnabled(True)
        self.summary_label.setText("")
        msg_warn(self, tr("对比失败"), message)

    def _stop_thread(self):
        t = self._thread
        if t is not None and t.isRunning():
            t.stop()
            t.wait(5000)
        self._thread = None

    def closeEvent(self, event):
        # 对话框关掉后线程若还在跑，它的 finished 信号会回调到一个已销毁的窗口。
        self._stop_thread()
        super().closeEvent(event)


class HistoryQueryDialog(QDialog):
    """历史条件查询：按类型 / 网段 / 首见时间 / IP 关键字跨快照聚合检索历史设备。

    结果展示每台设备的「当前已知属性」（最近一次出现且非空为准）、
    首见时间与末见时间，按末见时间降序。

    **查询跑在后台线程**（见 `ui_threads.HistoryQueryThread`）：`query_history`
    要把所有快照的所有设备行取回来聚合，大库上是秒级操作，同步执行会冻住界面。
    结果按页展示（每次 `PAGE_SIZE` 条 + 「加载更多」）—— 一次往 QTableWidget 塞
    几万行，光逐格建 item 就要好几秒，分页比"查得更快"更直接地解决卡顿。
    """

    #: 每页行数。表格是 QTableWidget、逐格建 item，行数一大填充本身就卡；
    #: 500 行是"一屏放不完、但翻两下能看完"的量级。
    PAGE_SIZE = 500

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

        self._thread = None
        self._export_thread = None
        self._offset = 0        # 下一页的起始行号
        self._has_more = False  # 上一页多取了一条 → 说明还有更多

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
        self.btn_query = QPushButton(tr("查询"))
        self.btn_query.setObjectName("primaryBtn")
        # 用 lambda 而不是直接连 _run_query：clicked 会带一个 bool，
        # 直接连会把它塞进 _run_query 的 reset 形参 —— 点「查询」变成"追加"。
        self.btn_query.clicked.connect(lambda: self._run_query(reset=True))
        btn_row.addWidget(self.btn_query)
        self.btn_stop = QPushButton(tr("停止"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        btn_row.addWidget(self.btn_stop)
        self.btn_reset = QPushButton(tr("重置"))
        self.btn_reset.clicked.connect(self._reset)
        btn_row.addWidget(self.btn_reset)
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
        self.btn_more = QPushButton(tr("加载更多"))
        self.btn_more.setEnabled(False)
        self.btn_more.clicked.connect(lambda: self._load_more())
        bottom.addWidget(self.btn_more)
        bottom.addStretch()
        self.btn_export = QPushButton(tr("导出 CSV"))
        self.btn_export.clicked.connect(lambda: self._export_csv())
        bottom.addWidget(self.btn_export)
        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self._close)
        bottom.addWidget(btn_close)
        vbox.addLayout(bottom)

        # 打开即查询。放在后台线程里跑，所以构造函数立刻返回 —— 旧实现在这里
        # 同步查一次，打开对话框本身就是一次界面冻结。
        self._run_query(reset=True)

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
        self._run_query(reset=True)

    # ── 查询 ────────────────────────────────────────────────────────────────

    def _collect_filters(self):
        """把筛选栏读成 `query_history` 的关键字参数。

        单独抽出来是因为它被两处用：表格查询、以及「导出完整结果」（导出不受
        分页限制，要按同一组条件重跑一次）。
        """
        if self.time_unlimited.isChecked():
            f_after = f_before = None
        else:
            f_after = self.date_from.dateTime().toSecsSinceEpoch()
            f_before = self.date_to.dateTime().toSecsSinceEpoch()
        return {
            "device_class": self.class_edit.text().strip() or None,
            "network": self.net_edit.text().strip() or None,
            "ip_substr": self.ip_edit.text().strip() or None,
            "first_seen_after": f_after,
            "first_seen_before": f_before,
        }

    def _run_query(self, reset=True):
        if self._thread is not None and self._thread.isRunning():
            return          # 已有查询在跑：忽略重复点击，避免两份结果互相覆盖
        if reset:
            self._offset = 0
            self._has_more = False
        self._set_busy(True)
        self.btn_more.setEnabled(False)
        # 多取一条用来判断"还有没有下一页"：比额外跑一次 COUNT 便宜，而且天然
        # 与分页共用同一份排序，不会出现"提示有更多、翻页却是空的"。
        self._thread = HistoryQueryThread(
            self._collect_filters(), db_path=self.db_path,
            limit=self.PAGE_SIZE + 1, offset=self._offset)
        self._thread.finished_signal.connect(self._on_rows)
        self._thread.failed.connect(self._on_failed)
        self._thread.cancelled_signal.connect(self._on_cancelled)
        self._thread.start()

    def _load_more(self):
        if self._has_more:
            self._run_query(reset=False)

    def _on_stop(self):
        if self._thread is not None:
            self._thread.stop()
            self.count_label.setText(tr("正在取消…"))

    def _on_rows(self, rows):
        self._set_busy(False)
        self._has_more = len(rows) > self.PAGE_SIZE
        page = rows[:self.PAGE_SIZE]
        self._fill_table(page, append=self._offset > 0)
        self._offset += len(page)
        self.btn_more.setEnabled(self._has_more)
        self._update_count()

    def _on_failed(self, message):
        self._set_busy(False)
        self.btn_more.setEnabled(self._has_more)
        self._update_count()
        msg_warn(self, tr("查询失败"), message)

    def _on_cancelled(self):
        self._set_busy(False)
        self.btn_more.setEnabled(self._has_more)
        # 明确写"已取消"：不能让它看起来像"查完了、只是没结果"。
        self.count_label.setText(tr("已取消查询"))

    def _set_busy(self, busy):
        self.btn_query.setEnabled(not busy)
        self.btn_reset.setEnabled(not busy)
        self.btn_stop.setEnabled(busy)
        self.btn_export.setEnabled(not busy)
        if busy:
            self.count_label.setText(tr("正在查询…"))

    def _update_count(self):
        text = f"已显示 {self.table.rowCount()} 台设备"
        if self._has_more:
            text += "（还有更多，可继续加载）"
        self.count_label.setText(text)

    # ── 表格 ────────────────────────────────────────────────────────────────

    def _fill_table(self, rows, append=False):
        if not append:
            self.table.setRowCount(0)
        start = self.table.rowCount()
        self.table.setRowCount(start + len(rows))
        for i, d in enumerate(rows):
            self._fill_row(start + i, d)

    def _fill_row(self, r, d):
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

    # ── 导出 ────────────────────────────────────────────────────────────────

    def _export_csv(self):
        """导出**完整**查询结果，而不是表格里已显示的那几页。

        表格是分页的；直接导出表格内容会让人以为拿到了全部。所以这里按同一组
        条件另跑一次不设上限的查询（同样在后台线程 —— 否则大库上又冻一次界面）。
        """
        if self._export_thread is not None and self._export_thread.isRunning():
            return
        if self.table.rowCount() == 0 and not self._has_more:
            msg_info(self, tr("提示"), tr("暂无数据可导出。"))
            return
        self.btn_export.setEnabled(False)
        self.count_label.setText(tr("正在准备完整结果…"))
        self._export_thread = HistoryQueryThread(
            self._collect_filters(), db_path=self.db_path)
        self._export_thread.finished_signal.connect(self._write_csv)
        self._export_thread.failed.connect(self._on_export_failed)
        self._export_thread.start()

    def _on_export_failed(self, message):
        self.btn_export.setEnabled(True)
        self._export_thread = None
        self._update_count()
        msg_warn(self, tr("导出失败"), message)

    def _write_csv(self, rows):
        self.btn_export.setEnabled(True)
        self._export_thread = None
        if not rows:
            self._update_count()
            msg_info(self, tr("提示"), tr("暂无数据可导出。"))
            return
        default_name = f"历史查询_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出查询结果"), default_name, tr("CSV 文件 (*.csv)")
        )
        if not path:
            self._update_count()
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.COLS)
                for d in rows:
                    writer.writerow([
                        d.get("ip", ""), d.get("status", ""),
                        device_class_label(d.get("device_class", "")) or "—",
                        d.get("hostname", "") or "—", d.get("mac", "") or "—",
                        self._fmt(d.get("first_seen")), self._fmt(d.get("last_seen")),
                    ])
            msg_info(self, tr("导出成功"), f"已保存到：\n{path}")
        except Exception as e:
            msg_warn(self, tr("导出失败"), str(e))
        self._update_count()

    # ── 生命周期 ────────────────────────────────────────────────────────────

    def _close(self):
        self._stop_threads()
        self.accept()

    def _stop_threads(self):
        for attr in ("_thread", "_export_thread"):
            t = getattr(self, attr, None)
            if t is not None and t.isRunning():
                t.stop()
                t.wait(5000)    # 取消按块检查，正常几十毫秒内返回
            setattr(self, attr, None)

    def closeEvent(self, event):
        # 对话框关掉后线程若还在跑，回调会打到已销毁的窗口上。
        self._stop_threads()
        super().closeEvent(event)
