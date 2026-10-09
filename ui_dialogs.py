# -*- coding: utf-8 -*-
"""对话框集合：设备编辑、地址库管理、历史对比、网络拓扑、冲突报告、子网利用率、审计日志。"""
import os
import math
from datetime import datetime

from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QLineEdit, QLabel, QPushButton,
    QHBoxLayout, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QFileDialog, QMessageBox, QComboBox, QCheckBox,
    QDateTimeEdit,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
    QGraphicsRectItem,
    QProgressBar, QSizePolicy,
)
from PyQt5.QtGui import QPainter, QBrush, QPen, QColor

from excel_handler import normalize_mac
from mac_library import MacLibrary
from ui_utils import _compare_snapshots
from conflict_detector import SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO
from change_detector import SEVERITY_HIGH as CHG_HIGH, SEVERITY_WARNING as CHG_WARNING, SEVERITY_INFO as CHG_INFO
import history_store
import audit_log
from ui_threads import SwitchMapThread
from scanner.constants import device_class_label
from scanner.wmi import (TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM,
                         transport_label)
from scanner.snmp_v3 import (AUTH_NONE, AUTH_MD5, AUTH_SHA, PRIV_NONE, PRIV_AES,
                             SnmpV3User, auth_label, priv_label,
                             snmp_v3_get_system)
from app_logging import get_logger
from ui_msg import localize_buttons, msg_ask, msg_info, msg_warn
from i18n import tr
import ui_logic

_log = get_logger(__name__)


class DeviceEditDialog(QDialog):
    """新增 / 编辑单条设备"""

    FIELDS = [
        ("ip", tr("IP 地址"), tr("例如 192.168.1.10")),
        ("mac", tr("MAC 地址"), tr("例如 AA:BB:CC:DD:EE:FF")),
        ("device_type", tr("设备类型"), tr("例如 PC / 打印机 / 一体机")),
        ("location", tr("位置"), tr("例如 3楼-301办公室")),
        ("user", tr("使用者"), tr("例如 张三 / 财务科")),
        ("remark", tr("备注"), tr("选填")),
        ("vendor", tr("厂商"), tr("选填")),
    ]

    def __init__(self, library: MacLibrary, parent=None, device_id=None, ip="", mac=""):
        super().__init__(parent)
        self.library = library
        self.device_id = device_id
        self.setWindowTitle(tr("编辑设备") if device_id else tr("新增设备"))
        self.setMinimumWidth(420)

        existing = library.get_by_id(device_id) if device_id else {}
        prefill = {"ip": ip, "mac": mac}

        layout = QFormLayout(self)
        self.edits = {}
        for key, label, ph in self.FIELDS:
            le = QLineEdit()
            le.setPlaceholderText(ph)
            val = existing.get(key, "") if existing else prefill.get(key, "")
            le.setText(val if val is not None else "")
            self.edits[key] = le
            layout.addRow(label, le)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        localize_buttons(btns)
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _on_accept(self):
        data = {k: self.edits[k].text().strip() for k, _, _ in self.FIELDS}
        # MAC 校验 (允许为空，但填了要像 MAC)
        if data["mac"]:
            norm = normalize_mac(data["mac"])
            if not norm:
                msg_warn(self, tr("格式错误"), tr("MAC 地址格式不正确，请检查后重试。"))
                return
            data["mac"] = norm
        if self.device_id:
            self.library.update(self.device_id, **data)
        else:
            self.library.add(**data)
        self.accept()


class MacLibraryDialog(QDialog):
    """地址库管理：浏览 / 搜索 / 增 / 删 / 改 / 导出"""

    COLS = ["ID", tr("IP地址"), tr("MAC地址"), tr("设备类型"), tr("位置"), tr("使用者"), tr("备注"), tr("来源文件")]

    def __init__(self, library: MacLibrary, parent=None):
        super().__init__(parent)
        self.library = library
        self.setWindowTitle(tr("MAC 地址库管理"))
        self.resize(1000, 620)

        vbox = QVBoxLayout(self)

        # 工具条
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel(tr("搜索:")))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("按 IP / MAC / 类型 / 位置 / 使用者 搜索"))
        self.search_edit.textChanged.connect(self._reload)
        toolbar.addWidget(self.search_edit)

        toolbar.addStretch()
        btn_add = QPushButton(tr("新增"))
        btn_add.clicked.connect(self._add)
        btn_edit = QPushButton(tr("编辑"))
        btn_edit.clicked.connect(self._edit)
        btn_del = QPushButton(tr("删除"))
        btn_del.clicked.connect(self._delete)
        btn_export = QPushButton(tr("导出"))
        btn_export.clicked.connect(self._export)
        btn_refresh = QPushButton(tr("刷新"))
        btn_refresh.clicked.connect(self._reload)
        for b in (btn_add, btn_edit, btn_del, btn_export, btn_refresh):
            toolbar.addWidget(b)
        vbox.addLayout(toolbar)

        # 表格
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(self._edit)
        hdr = self.table.horizontalHeader()
        # 所有列均可手动拖动调整宽度
        hdr.setStretchLastSection(False)
        _lib_widths = {0: 45, 1: 130, 2: 150, 3: 110, 4: 160, 5: 110, 6: 160, 7: 220}
        for _col, _w in _lib_widths.items():
            hdr.setSectionResizeMode(_col, QHeaderView.Interactive)
            hdr.resizeSection(_col, _w)
        vbox.addWidget(self.table)

        # 底部状态
        self.status = QLabel("")
        vbox.addWidget(self.status)

        self._reload()

    def _reload(self):
        q = self.search_edit.text().strip()
        rows = self.library.search(q) if q else self.library.get_all()
        self.table.setRowCount(len(rows))
        for r, dev in enumerate(rows):
            vals = [str(dev["id"]), dev["ip"], dev["mac"], dev["device_type"],
                    dev["location"], dev["user"], dev["remark"], dev["source_file"]]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(r, c, item)
        self.status.setText(f"共 {len(rows)} 条")

    def _selected_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return int(item.text()) if item else None

    def _add(self):
        dlg = DeviceEditDialog(self.library, parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self._reload()
            self._audit(tr("新增设备"), f"地址库共 {self.library.count()} 条")

    def _edit(self):
        did = self._selected_id()
        if did is None:
            msg_info(self, tr("提示"), tr("请先选中一行"))
            return
        dlg = DeviceEditDialog(self.library, parent=self, device_id=did)
        if dlg.exec_() == QDialog.Accepted:
            self._reload()
            self._audit(tr("编辑设备"), f"设备 #{did}")

    def _delete(self):
        did = self._selected_id()
        if did is None:
            msg_info(self, tr("提示"), tr("请先选中一行"))
            return
        dev = self.library.get_by_id(did)
        label = (dev.get("mac") or dev.get("ip") or f"#{did}")
        reply = msg_ask(
            self, tr("确认删除"), f"确定删除该设备吗？\n\n{label}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.library.delete(did)
            self._reload()
            self._audit(tr("删除设备"), f"{label} · 地址库余 {self.library.count()} 条")

    def _export(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出地址库"), default_name, tr("Excel 文件 (*.xlsx)")
        )
        if not path:
            return
        success, msg = self.library.export_to_excel(path)
        if success:
            self._audit(tr("导出地址库"), f"{self.library.count()} 条 · {os.path.basename(path)}")
        msg_info(self, tr("导出成功") if success else tr("导出失败"), msg)

    @staticmethod
    def _audit(action, detail=""):
        """安全记录地址库审计日志，异常不影响对话框。"""
        try:
            audit_log.log_event(audit_log.CAT_LIBRARY, action, detail)
        except Exception as e:  # noqa: BLE001
            # 审计失败不能打断地址库编辑操作，但要留痕（审计缺失需可追溯）
            _log.warning("写入地址库审计日志失败（动作 %s）: %s", action, e)


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

        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #555555; font-size: 11px;")
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

    COLS = [tr("IP 地址"), tr("状态"), tr("类型"), tr("主机名"), "MAC", tr("首见"), tr("末见")]

    def __init__(self, parent=None, db_path=None):
        super().__init__(parent)
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
        self.count_label.setStyleSheet("font-size: 12px; color: #666;")
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
                st_item.setForeground(QColor(34, 163, 74))
            elif st == "offline":
                st_item.setForeground(QColor(150, 150, 150))
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


class TopologyDialog(QDialog):
    """网络拓扑视图：LLDP/CDP 真实链路 + 终端设备。

    若提供了 topology（含 LLDP/CDP 链路），展示真实拓扑；
    否则回退到网关为中心的星型拓扑。
    """

    def __init__(self, results, gateway_ip, dark, parent=None, topology=None):
        super().__init__(parent)
        self.setWindowTitle(tr("网络拓扑视图"))
        self.setMinimumSize(900, 680)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.results = list(results)
        self.gateway_ip = gateway_ip
        self.dark = dark
        self.topology = topology  # Topology 对象，None = 回退星型

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)

        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing, True)
        self.scene = QGraphicsScene()
        bg = QColor(30, 30, 30) if dark else QColor(248, 248, 248)
        self.scene.setBackgroundBrush(QBrush(bg))
        self.view.setScene(self.scene)
        layout.addWidget(self.view, 1)

        self.legend = QLabel()
        self._update_legend()
        layout.addWidget(self.legend)

        self.setLayout(layout)

        if self.topology and self.topology.links:
            self._build_real_topology()
        else:
            self._build_star_topology()

    def _update_legend(self):
        items = [
            tr("<span style='color:#E69500;'>●</span> 网关"),
            tr("<span style='color:#22A34A;'>●</span> 在线"),
            tr("<span style='color:#B4B4B4;'>●</span> 离线"),
        ]
        if self.topology and self.topology.links:
            items += [
                tr("<span style='color:#4DA6FF;'>━</span> LLDP"),
                tr("<span style='color:#22C55E;'>━</span> CDP"),
            ]
        self.legend.setText("   ".join(items))
        self.legend.setStyleSheet("font-size: 12px; padding: 4px;")

    def _text_color(self):
        return QColor(224, 224, 224) if self.dark else QColor(40, 40, 40)

    # ── 真实拓扑 (LLDP/CDP) ──

    def _build_real_topology(self):
        topo = self.topology
        node_pos = {}          # node_id -> (x, y)
        switch_nodes = [n for n in topo.nodes if n.is_switch]
        host_nodes = [n for n in topo.nodes if not n.is_switch]

        # 布局：交换机水平排列，主机围绕其连接的交换机
        n_sw = len(switch_nodes)
        sw_spacing = 250
        sw_y = -100

        for i, sw in enumerate(switch_nodes):
            x = (i - (n_sw - 1) / 2) * sw_spacing
            node_pos[sw.id] = (x, sw_y)

        # 主机按连接交换机分组
        host_by_switch = {}  # switch_id -> [node, ...]
        unassigned = list(host_nodes)
        for link in topo.links:
            if link.source_id in node_pos and link.target_id not in node_pos:
                host_by_switch.setdefault(link.source_id, []).append(link.target_id)

        # 放置主机
        for sw_id, connected in host_by_switch.items():
            sx, sy = node_pos.get(sw_id, (0, sw_y))
            n = len(connected)
            for i, hid in enumerate(connected):
                host = next((n for n in topo.nodes if n.id == hid), None)
                if host and hid in unassigned:
                    unassigned.remove(hid)
                ang = math.pi * (i / max(n, 1) - 0.5) + math.pi / 2
                r = 120 + (n * 4)
                x = sx + r * math.cos(ang)
                y = sy + r * math.sin(ang)
                node_pos[hid] = (x, y)

        # 剩余未分配主机：圈在中心
        cx, cy = 0, 200
        for i, hid in enumerate(unassigned):
            ang = 2 * math.pi * i / max(len(unassigned), 1)
            r = 300
            node_pos[hid] = (cx + r * math.cos(ang), cy + r * math.sin(ang))

        # 绘制链路
        for link in topo.links:
            if link.source_id in node_pos and link.target_id in node_pos:
                x1, y1 = node_pos[link.source_id]
                x2, y2 = node_pos[link.target_id]
                if link.protocol == "LLDP":
                    pen = QPen(QColor(77, 166, 255), 2)
                elif link.protocol == "CDP":
                    pen = QPen(QColor(34, 197, 94), 2)
                else:
                    pen = QPen(self._muted(), 1)
                self.scene.addLine(x1, y1, x2, y2, pen)
                # 端口标签
                mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
                if link.source_port:
                    lbl = QGraphicsTextItem(link.source_port)
                    lbl.setDefaultTextColor(self._muted())
                    lbl.setScale(0.6)
                    lbl.setPos(mid_x - 20, mid_y - 12)
                    self.scene.addItem(lbl)

        # 绘制节点
        for node in topo.nodes:
            if node.id in node_pos:
                x, y = node_pos[node.id]
                if node.is_switch:
                    self._add_switch_node(x, y, node)
                else:
                    self._add_device_node(x, y, node)

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60))

    def _add_switch_node(self, x, y, node):
        """绘制交换机节点（方形）。"""
        w, h = 50, 30
        color = QColor(14, 99, 156)
        rect = QGraphicsRectItem(x - w / 2, y - h / 2, w, h)
        rect.setBrush(QBrush(color))
        rect.setPen(QPen(QColor(255, 255, 255, 80), 1.5))
        self.scene.addItem(rect)
        parts = [node.label]
        if node.model:
            parts.append(node.model[:20])
        txt = QGraphicsTextItem("\n".join(parts))
        txt.setDefaultTextColor(self._link_blue())
        txt.setPos(x - 45, y + h / 2 + 4)
        txt.setScale(0.75)
        self.scene.addItem(txt)

    def _add_device_node(self, x, y, node):
        """绘制终端设备节点（圆形）。"""
        # 从 results 取在线状态
        online = True
        for r in self.results:
            if r.ip == node.ip or r.ip == node.id:
                online = r.status == "online"
                break
        color = QColor(34, 163, 74) if online else QColor(180, 180, 180)
        dot = QGraphicsEllipseItem(x - 10, y - 10, 20, 20)
        dot.setBrush(QBrush(color))
        dot.setPen(QPen(QColor(0, 0, 0, 60), 1))
        self.scene.addItem(dot)
        label = node.label
        txt = QGraphicsTextItem(label)
        txt.setDefaultTextColor(self._text_color())
        txt.setScale(0.7)
        txt.setPos(x - 35, y + 12)
        self.scene.addItem(txt)

    # ── 回退星型拓扑 ──

    def _build_star_topology(self):
        cx, cy = 0, 0
        hosts = self.results
        n = len(hosts)
        R = max(200, 50 + n * 7)
        edge_pen = QPen(self._muted(), 1)

        for i, r in enumerate(hosts):
            ang = 2 * math.pi * i / n if n else 0
            x = cx + R * math.cos(ang)
            y = cy + R * math.sin(ang)
            self.scene.addLine(cx, cy, x, y, edge_pen)
            self._add_host_node(x, y, r)

        self._add_gateway_node(cx, cy)

        if self.scene.itemsBoundingRect().isValid():
            self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))

    def _add_host_node(self, x, y, r):
        online = r.status == "online"
        color = QColor(34, 163, 74) if online else QColor(180, 180, 180)
        node = QGraphicsEllipseItem(x - 14, y - 14, 28, 28)
        node.setBrush(QBrush(color))
        node.setPen(QPen(QColor(0, 0, 0, 60), 1))
        self.scene.addItem(node)
        label = r.ip + (("\n" + r.hostname) if r.hostname else "")
        txt = QGraphicsTextItem(label)
        txt.setDefaultTextColor(self._text_color())
        txt.setPos(x - 55, y + 16)
        self.scene.addItem(txt)

    def _add_gateway_node(self, x, y):
        sub = self.gateway_ip or tr("未知")
        for r in self.results:
            if r.ip == self.gateway_ip:
                if r.hostname:
                    sub = f"{self.gateway_ip}\n{r.hostname}"
                break
        color = QColor(230, 149, 0)
        node = QGraphicsEllipseItem(x - 24, y - 24, 48, 48)
        node.setBrush(QBrush(color))
        node.setPen(QPen(QColor(0, 0, 0, 80), 2))
        self.scene.addItem(node)
        txt = QGraphicsTextItem(tr("网关\n") + sub)
        txt.setDefaultTextColor(self._text_color())
        txt.setPos(x - 45, y + 28)
        self.scene.addItem(txt)

    def _muted(self):
        return QColor(150, 156, 166) if self.dark else QColor(170, 170, 170)

    def _link_blue(self):
        return QColor(77, 166, 255) if self.dark else QColor(14, 99, 156)


class WmiCredentialDialog(QDialog):
    """采集 WMI 识别所需的管理员凭据与传输方式。

    密码以 QLineEdit(Password) 显示；勾选"保存凭据(加密)"后由调用方用 DPAPI 加密
    存入 ipscanner.ini。本对话框不负责持久化，只回传明文凭据。

    传输方式默认"自动"（先 DCOM，失败再试 WinRM）。若已知目标只开放 WinRM，
    选"仅 WinRM"可省掉一次必然失败的 DCOM 尝试（反之亦然），从而少等一个超时。
    """

    def __init__(self, parent=None, saved_username: str = "", saved_domain: str = "",
                 saved_transport: str = TRANSPORT_AUTO):
        super().__init__(parent)
        self.setWindowTitle(tr("WMI 设备识别 — 管理员凭据"))
        self.setMinimumWidth(400)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QFormLayout(self)

        self.user_edit = QLineEdit(saved_username)
        self.user_edit.setPlaceholderText(tr("如 administrator 或 user（不含域）"))
        layout.addRow(tr("用户名:"), self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText(tr("目标主机管理员密码"))
        layout.addRow(tr("密码:"), self.pass_edit)

        self.domain_edit = QLineEdit(saved_domain)
        self.domain_edit.setPlaceholderText(tr("域（可选，工作组可留空）"))
        layout.addRow(tr("域:"), self.domain_edit)

        # 传输方式：显示文本经 transport_label() 惰性翻译，
        # 用户数据（currentData）存语言无关的规范值 auto/dcom/winrm。
        self.transport_combo = QComboBox()
        for value in (TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM):
            self.transport_combo.addItem(transport_label(value), value)
        idx = self.transport_combo.findData(saved_transport)
        if idx < 0:
            idx = self.transport_combo.findData(TRANSPORT_AUTO)
        if idx >= 0:
            self.transport_combo.setCurrentIndex(idx)
        layout.addRow(tr("传输方式:"), self.transport_combo)

        self.save_check = QCheckBox(tr("保存凭据（DPAPI 加密到本机配置）"))
        layout.addRow(self.save_check)

        hint = QLabel(tr(
            "WMI 识别仅对 Windows 目标有效，且当前凭据需具管理员权限。\n"
            "DCOM 需开放 135 及动态 RPC 端口；WinRM 只需 5985/5986 单端口，跨网段更易通过。\n"
            "非域环境请填目标本机管理员账号。"
        ))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #888; font-size: 11px;")
        layout.addRow(hint)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        localize_buttons(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_credentials(self):
        """返回 (username, password, domain, save, transport)。"""
        return (
            self.user_edit.text().strip(),
            self.pass_edit.text(),
            self.domain_edit.text().strip(),
            self.save_check.isChecked(),
            self.transport_combo.currentData() or TRANSPORT_AUTO,
        )


class SnmpV3CredentialDialog(QDialog):
    """采集 SNMPv3 USM 用户参数（用户名 / 认证 / 加密）。

    v3 相比 v2c 的价值就在于口令不再明文上网：团体字（community）等价于
    把密码写在信封外面，任何抓包的人都能直接看到。目标支持就该用 v3。

    口令以 QLineEdit(Password) 显示；勾选"保存配置"后由调用方用 DPAPI 加密
    存入 ipscanner.ini。本对话框不负责持久化，只回传明文口令。

    "测试"按钮会用当前参数对指定 IP 做一次真实 GET，把失败原因（用户名错 /
    口令错 / 目标没开 SNMP）直接显示出来 —— 比扫完一整段再猜原因快得多。
    """

    def __init__(self, parent=None, saved=None, saved_target: str = ""):
        super().__init__(parent)
        self.setWindowTitle(tr("SNMPv3 识别 — USM 用户"))
        self.setMinimumWidth(440)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        saved = saved or {}
        layout = QFormLayout(self)

        self.user_edit = QLineEdit(saved.get("username", ""))
        self.user_edit.setPlaceholderText(tr("如 snmpuser"))
        layout.addRow(tr("用户名:"), self.user_edit)

        # 协议下拉的显示文本经 auth_label()/priv_label() 惰性翻译，
        # 用户数据（currentData）存语言无关的规范值，绝不拿译文当依据。
        self.auth_combo = QComboBox()
        for value in (AUTH_NONE, AUTH_MD5, AUTH_SHA):
            self.auth_combo.addItem(auth_label(value), value)
        self.auth_combo.setCurrentIndex(max(
            0, self.auth_combo.findData(saved.get("auth_proto", AUTH_NONE))))
        layout.addRow(tr("认证协议:"), self.auth_combo)

        self.auth_edit = QLineEdit(saved.get("auth_key", ""))
        self.auth_edit.setEchoMode(QLineEdit.Password)
        self.auth_edit.setPlaceholderText(tr("认证口令，建议至少 8 位"))
        layout.addRow(tr("认证密码:"), self.auth_edit)

        self.priv_combo = QComboBox()
        for value in (PRIV_NONE, PRIV_AES):
            self.priv_combo.addItem(priv_label(value), value)
        self.priv_combo.setCurrentIndex(max(
            0, self.priv_combo.findData(saved.get("priv_proto", PRIV_NONE))))
        layout.addRow(tr("加密协议:"), self.priv_combo)

        self.priv_edit = QLineEdit(saved.get("priv_key", ""))
        self.priv_edit.setEchoMode(QLineEdit.Password)
        self.priv_edit.setPlaceholderText(tr("加密口令（可与认证口令相同）"))
        layout.addRow(tr("加密密码:"), self.priv_edit)

        # 加密必须建立在认证之上（RFC 3414）；没选认证就直接禁用加密，
        # 免得用户填完才发现用不上
        self.auth_combo.currentIndexChanged.connect(self._sync_priv_enabled)
        self._sync_priv_enabled()

        # ── 测试连接 ──
        test_row = QHBoxLayout()
        self.target_edit = QLineEdit(saved_target)
        self.target_edit.setPlaceholderText(tr("目标 IP，如 192.168.1.1"))
        test_row.addWidget(self.target_edit, 1)
        self.test_btn = QPushButton(tr("测试"))
        self.test_btn.clicked.connect(self._on_test)
        test_row.addWidget(self.test_btn)
        layout.addRow(tr("测试目标:"), test_row)

        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        self.result_label.setStyleSheet("font-size: 11px;")
        layout.addRow(self.result_label)

        self.save_check = QCheckBox(tr("保存配置（DPAPI 加密口令到本机配置）"))
        layout.addRow(self.save_check)

        hint = QLabel(tr(
            "SNMPv3 用用户级认证/加密替代明文团体字，口令不再被中间人直接看到。\n"
            "认证支持 HMAC-MD5-96 / HMAC-SHA-96；加密仅支持 AES-128（不支持已废弃的 DES）。\n"
            "口令不足 8 位时部分设备会拒绝本地化密钥，建议至少 8 位。"
        ))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #888; font-size: 11px;")
        layout.addRow(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        localize_buttons(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _sync_priv_enabled(self):
        """没启用认证就不能启用加密（RFC 3414）。"""
        auth_on = bool(self.auth_combo.currentData())
        self.priv_combo.setEnabled(auth_on)
        self.priv_edit.setEnabled(auth_on)
        if not auth_on:
            self.priv_combo.setCurrentIndex(0)
            self.priv_edit.clear()

    def _current_user(self) -> SnmpV3User:
        return SnmpV3User(
            username=self.user_edit.text().strip(),
            auth_proto=self.auth_combo.currentData() or AUTH_NONE,
            auth_key=self.auth_edit.text(),
            priv_proto=self.priv_combo.currentData() or PRIV_NONE,
            priv_key=self.priv_edit.text(),
        )

    def _on_test(self):
        """用当前参数对目标做一次真实 GET，把结论直接显示出来。"""
        ip = self.target_edit.text().strip()
        if not ip:
            self._set_result(tr("请先填写测试目标 IP"), ok=False)
            return
        user = self._current_user()
        err = user.validate()
        if err:
            self._set_result(err, ok=False)
            return

        self.result_label.setText(tr("测试中…"))
        self.result_label.setStyleSheet("color: #888; font-size: 11px;")
        # 单次 GET 最长 1.5s；模态对话框里短暂等待可以接受，
        # 换成线程反而要额外处理"测试还没回来、对话框已被关闭"的竞态
        self.setCursor(Qt.WaitCursor)
        try:
            info = snmp_v3_get_system(ip, user, timeout=1.5)
        finally:
            self.unsetCursor()

        if "error" in info:
            self._set_result(tr("测试失败：%s") % info["error"], ok=False)
        else:
            self._set_result(
                tr("连接成功：%s") % (info.get("sys_name")
                                     or info.get("sys_descr") or ip), ok=True)

    def _set_result(self, text: str, ok: bool):
        color = "#16A34A" if ok else "#DC2626"
        self.result_label.setStyleSheet(f"color: {color}; font-size: 11px;")
        self.result_label.setText(text)

    def get_config(self):
        """返回 (username, auth_proto, auth_key, priv_proto, priv_key, save)。"""
        return (
            self.user_edit.text().strip(),
            self.auth_combo.currentData() or AUTH_NONE,
            self.auth_edit.text(),
            self.priv_combo.currentData() or PRIV_NONE,
            self.priv_edit.text(),
            self.save_check.isChecked(),
        )


class ConflictReportDialog(QDialog):
    """IP 冲突检测报告对话框。

    以表格展示所有检测到的冲突，按严重级别着色，
    支持选中行高亮对应 IP（通过回调通知主窗口）。
    """

    COLS = [tr("严重级别"), tr("冲突类型"), tr("描述"), tr("涉及 IP"), tr("涉及 MAC"), tr("详情")]
    _SEVERITY_COLORS = {
        SEVERITY_HIGH: QColor(220, 38, 38),     # 红
        SEVERITY_WARNING: QColor(217, 119, 6),   # 橙
        SEVERITY_INFO: QColor(37, 99, 235),      # 蓝
    }
    _SEVERITY_BG = {
        SEVERITY_HIGH: QColor(254, 226, 226),    # 浅红底
        SEVERITY_WARNING: QColor(254, 243, 199), # 浅橙底
        SEVERITY_INFO: QColor(219, 234, 254),    # 浅蓝底
    }

    def __init__(self, conflicts, parent=None, dark=False):
        super().__init__(parent)
        self.conflicts = conflicts
        self.dark = dark
        self.setWindowTitle(tr("IP 冲突检测报告"))
        self.setMinimumSize(900, 520)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 摘要行 ──
        high = sum(1 for c in conflicts if c.severity == SEVERITY_HIGH)
        warn = sum(1 for c in conflicts if c.severity == SEVERITY_WARNING)
        info = sum(1 for c in conflicts if c.severity == SEVERITY_INFO)
        summary_parts = []
        if high:
            summary_parts.append(f"<span style='color:#DC2626;font-weight:bold;'>{high} 严重</span>")
        if warn:
            summary_parts.append(f"<span style='color:#D97706;font-weight:bold;'>{warn} 警告</span>")
        if info:
            summary_parts.append(f"<span style='color:#2563EB;font-weight:bold;'>{info} 提示</span>")
        summary_text = " · ".join(summary_parts) if summary_parts else tr("无冲突")
        self.summary_label = QLabel(f"共检测到 {len(conflicts)} 条冲突：{summary_text}")
        self.summary_label.setTextFormat(Qt.RichText)
        self.summary_label.setStyleSheet("font-size: 13px; padding: 4px 0;")
        layout.addWidget(self.summary_label)

        # ── 冲突表格 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(not dark)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        hdr = self.table.horizontalHeader()
        _col_widths = {0: 70, 1: 110, 2: 260, 3: 160, 4: 180, 5: 200}
        for col, w in _col_widths.items():
            hdr.setSectionResizeMode(col, QHeaderView.Interactive)
            hdr.resizeSection(col, w)

        self.table.setRowCount(len(conflicts))
        for row, c in enumerate(conflicts):
            # 严重级别
            sev_item = QTableWidgetItem(c.severity_label)
            sev_item.setTextAlignment(Qt.AlignCenter)
            fg = self._SEVERITY_COLORS.get(c.severity, QColor(100, 100, 100))
            sev_item.setForeground(fg)
            font = sev_item.font()
            font.setBold(True)
            sev_item.setFont(font)
            self.table.setItem(row, 0, sev_item)

            # 冲突类型
            self.table.setItem(row, 1, QTableWidgetItem(c.type_label))

            # 描述
            self.table.setItem(row, 2, QTableWidgetItem(c.description))

            # 涉及 IP
            self.table.setItem(row, 3, QTableWidgetItem(", ".join(c.ips)))

            # 涉及 MAC
            self.table.setItem(row, 4, QTableWidgetItem(", ".join(c.macs)))

            # 详情
            detail_item = QTableWidgetItem(c.detail.replace("\n", " | "))
            detail_item.setToolTip(c.detail)
            self.table.setItem(row, 5, detail_item)

            # 行背景色
            bg = self._SEVERITY_BG.get(c.severity)
            if bg and not self.dark:
                for col in range(len(self.COLS)):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(bg)

        layout.addWidget(self.table, 1)

        # ── 底部按钮 ──
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_export = QPushButton(tr("导出报告"))
        btn_export.setToolTip(tr("将冲突报告导出为 CSV 文件"))
        btn_export.clicked.connect(self._export_csv)
        btn_row.addWidget(btn_export)

        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    def _export_csv(self):
        default_name = f"IP冲突报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出冲突报告"), default_name, tr("CSV 文件 (*.csv)")
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.COLS)
                for c in self.conflicts:
                    writer.writerow([
                        c.severity_label, c.type_label, c.description,
                        ", ".join(c.ips), ", ".join(c.macs),
                        c.detail.replace("\n", " | "),
                    ])
            msg_info(self, tr("导出成功"), f"报告已保存到：\n{path}")
        except Exception as e:
            msg_warn(self, tr("导出失败"), str(e))


class SubnetUtilizationDialog(QDialog):
    """子网利用率视图：按 /24 聚合扫描结果，展示各子网的在线占比与设备分布。"""

    COLS = [tr("子网"), tr("扫描 IP 数"), tr("在线"), tr("离线"), tr("利用率"), tr("设备类型分布")]

    # 利用率色阶
    _COLOR_LOW = QColor(34, 163, 74)      # 绿 <60%
    _COLOR_MID = QColor(217, 119, 6)      # 橙 60-85%
    _COLOR_HIGH = QColor(220, 38, 38)     # 红 >85%

    def __init__(self, results, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.setWindowTitle(tr("子网利用率"))
        self.setMinimumSize(860, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.subnets = self._analyze(results)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 摘要 ──
        total_ips = sum(s["total"] for s in self.subnets)
        total_online = sum(s["online"] for s in self.subnets)
        avg_util = (total_online / total_ips * 100) if total_ips else 0
        self.summary_label = QLabel(
            f"共 {len(self.subnets)} 个子网 · {total_ips} 个 IP · "
            f"{total_online} 在线 · 平均利用率 {avg_util:.1f}%"
        )
        self.summary_label.setStyleSheet("font-size: 13px; padding: 4px 0;")
        layout.addWidget(self.summary_label)

        # ── 表格 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(not dark)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)

        hdr = self.table.horizontalHeader()
        _col_widths = {0: 150, 1: 90, 2: 70, 3: 70, 4: 180, 5: 220}
        for col, w in _col_widths.items():
            hdr.setSectionResizeMode(col, QHeaderView.Interactive)
            hdr.resizeSection(col, w)

        self.table.setRowCount(len(self.subnets))
        for row, s in enumerate(self.subnets):
            # 子网
            sub_item = QTableWidgetItem(s["subnet"])
            sub_font = sub_item.font()
            sub_font.setFamily("Consolas")
            sub_item.setFont(sub_font)
            self.table.setItem(row, 0, sub_item)

            # 扫描 IP 数
            total_item = QTableWidgetItem(str(s["total"]))
            total_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, total_item)

            # 在线
            on_item = QTableWidgetItem(str(s["online"]))
            on_item.setTextAlignment(Qt.AlignCenter)
            on_item.setForeground(self._COLOR_LOW)
            on_font = on_item.font()
            on_font.setBold(True)
            on_item.setFont(on_font)
            self.table.setItem(row, 2, on_item)

            # 离线
            off_item = QTableWidgetItem(str(s["offline"]))
            off_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, off_item)

            # 利用率 — 用 QProgressBar 作为单元格控件，撑满整个单元格
            pct = s["utilization"]
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(int(pct))
            bar.setFormat(f"{pct:.1f}%")
            bar.setAlignment(Qt.AlignCenter)
            # 关键：让进度条随单元格大小伸缩，填满整格
            bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            bar.setMinimumHeight(18)
            color = self._util_color(pct)
            bar.setStyleSheet(
                f"QProgressBar {{ border: 1px solid #999; border-radius: 2px; "
                f"background: {'#333' if dark else '#eee'}; font-size: 11px; margin: 1px; }}"
                f"QProgressBar::chunk {{ background: {color.name()}; border-radius: 1px; }}"
            )
            self.table.setCellWidget(row, 4, bar)

            # 设备类型分布
            dist_text = s["device_dist"]
            self.table.setItem(row, 5, QTableWidgetItem(dist_text))
            self.table.item(row, 5).setToolTip(dist_text)

        layout.addWidget(self.table, 1)

        # ── 底部按钮 ──
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_export = QPushButton(tr("导出 CSV"))
        btn_export.clicked.connect(self._export_csv)
        btn_row.addWidget(btn_export)

        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    # ── 分析逻辑 ──

    @staticmethod
    def _analyze(results) -> list:
        """按 /24 聚合扫描结果（按利用率降序）。

        逻辑已提到 `ui_logic.build_subnet_stats` —— 概览页（`overview.py`）
        要用同一份数据，留两份实现迟早会跑偏。这里保留薄封装是为了不改动
        既有的调用点与测试。
        """
        return ui_logic.build_subnet_stats(results)

    def _util_color(self, pct: float) -> QColor:
        if pct > 85:
            return self._COLOR_HIGH
        if pct >= 60:
            return self._COLOR_MID
        return self._COLOR_LOW

    def _export_csv(self):
        default_name = f"子网利用率_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出子网利用率"), default_name, tr("CSV 文件 (*.csv)")
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.COLS)
                for s in self.subnets:
                    writer.writerow([
                        s["subnet"], s["total"], s["online"], s["offline"],
                        f"{s['utilization']:.1f}%", s["device_dist"],
                    ])
            msg_info(self, tr("导出成功"), f"已保存到：\n{path}")
        except Exception as e:
            msg_warn(self, tr("导出失败"), str(e))


class AuditLogDialog(QDialog):
    """审计日志查看器：按分类筛选 + 关键词搜索，展示扫描活动记录。"""

    COLS = [tr("时间"), tr("分类"), tr("操作"), tr("详情")]

    def __init__(self, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.setWindowTitle(tr("审计日志"))
        self.setMinimumSize(820, 500)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部筛选栏 ──
        filter_row = QHBoxLayout()
        filter_row.setSpacing(6)

        filter_row.addWidget(QLabel(tr("分类:")))
        self.cat_combo = QComboBox()
        self.cat_combo.addItem(tr("全部"), "")
        for cat in audit_log.CATEGORIES:
            # 显示翻译后的名称，但携带的 data 始终是语言无关的分类代码
            self.cat_combo.addItem(audit_log.category_label(cat), cat)
        self.cat_combo.setMinimumWidth(110)
        self.cat_combo.currentIndexChanged.connect(self._reload)
        filter_row.addWidget(self.cat_combo)

        filter_row.addWidget(QLabel(tr("搜索:")))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(tr("在操作 / 详情中查找关键词..."))
        self.search_input.setClearButtonEnabled(True)
        self.search_input.returnPressed.connect(self._reload)
        filter_row.addWidget(self.search_input, 1)

        btn_search = QPushButton(tr("查询"))
        btn_search.clicked.connect(self._reload)
        filter_row.addWidget(btn_search)

        btn_refresh = QPushButton(tr("刷新"))
        btn_refresh.clicked.connect(self._reload)
        filter_row.addWidget(btn_refresh)

        layout.addLayout(filter_row)

        # ── 表格 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(not dark)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)

        hdr = self.table.horizontalHeader()
        _col_widths = {0: 150, 1: 90, 2: 130, 3: 320}
        for col, w in _col_widths.items():
            hdr.setSectionResizeMode(col, QHeaderView.Interactive)
            hdr.resizeSection(col, w)

        layout.addWidget(self.table, 1)

        # ── 底部 ──
        btn_row = QHBoxLayout()
        self.count_label = QLabel("")
        self.count_label.setStyleSheet("font-size: 12px; color: #666;")
        btn_row.addWidget(self.count_label)
        btn_row.addStretch()

        btn_clear = QPushButton(tr("清空日志"))
        btn_clear.clicked.connect(self._clear_logs)
        btn_row.addWidget(btn_clear)

        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

        self._reload()

    # ── 数据加载 ──

    def _reload(self):
        category = self.cat_combo.currentData() or None
        keyword = self.search_input.text().strip() or None
        try:
            logs = audit_log.query_logs(category=category, keyword=keyword)
        except Exception as e:
            msg_warn(self, tr("读取失败"), str(e))
            return

        self.table.setRowCount(len(logs))
        for row, log in enumerate(logs):
            ts_item = QTableWidgetItem(
                datetime.fromtimestamp(log["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            )
            ts_font = ts_item.font()
            ts_font.setFamily("Consolas")
            ts_item.setFont(ts_font)
            self.table.setItem(row, 0, ts_item)

            cat_item = QTableWidgetItem(audit_log.category_label(log["category"]))
            cat_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, cat_item)

            self.table.setItem(row, 2, QTableWidgetItem(log["action"]))

            detail_item = QTableWidgetItem(log["detail"])
            detail_item.setToolTip(log["detail"])
            self.table.setItem(row, 3, detail_item)

        self.count_label.setText(f"共 {len(logs)} 条记录")

    def _clear_logs(self):
        reply = msg_ask(
            self, tr("确认清空"), tr("确定要清空全部审计日志吗？此操作不可恢复。"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            audit_log.clear_logs()
        except Exception as e:
            msg_warn(self, tr("清空失败"), str(e))
            return
        self._reload()


class SwitchPortDialog(QDialog):
    """交换机端口映射：通过 SNMP 获取 MAC 转发表，展示 MAC → 物理端口对应关系。"""

    COLS = [tr("MAC 地址"), tr("端口"), "ifIndex", "IP", tr("主机名"), tr("厂商"), tr("设备类型")]

    def __init__(self, scan_results=None, parent=None, dark=False, snmp_v3_user=None):
        super().__init__(parent)
        self.dark = dark
        self.scan_results = scan_results or []
        self._thread = None
        # SnmpV3User 或 None：非 None 时用 v3 遍历转发表，团体字输入框直接禁用
        self.snmp_v3_user = snmp_v3_user
        self.setWindowTitle(tr("交换机端口映射"))
        self.setMinimumSize(900, 520)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部：交换机 IP + 社区名 + 开始按钮 ──
        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        top_row.addWidget(QLabel(tr("交换机 IP:")))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText(tr("例如 192.168.1.1"))
        self.ip_input.setMinimumWidth(140)
        top_row.addWidget(self.ip_input)

        top_row.addWidget(QLabel(tr("社区名:")))
        self.community_input = QLineEdit("public")
        self.community_input.setMinimumWidth(80)
        self.community_input.setMaximumWidth(120)
        if self.snmp_v3_user is not None:
            # 已配置 SNMPv3：团体字不再参与，直接禁用避免用户误以为还要填
            self.community_input.clear()
            self.community_input.setEnabled(False)
            self.community_input.setPlaceholderText(tr("已启用 SNMPv3"))
        top_row.addWidget(self.community_input)

        self.btn_start = QPushButton(tr("开始映射"))
        self.btn_start.clicked.connect(self._start_mapping)
        top_row.addWidget(self.btn_start)

        top_row.addStretch()
        layout.addLayout(top_row)

        # ── 交换机信息标签 ──
        self.info_label = QLabel("")
        self.info_label.setStyleSheet("font-size: 12px; color: #555; padding: 2px 0;")
        layout.addWidget(self.info_label)

        # ── 表格 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(not dark)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)

        hdr = self.table.horizontalHeader()
        _col_widths = {0: 140, 1: 160, 2: 60, 3: 120, 4: 130, 5: 120, 6: 90}
        for col, w in _col_widths.items():
            hdr.setSectionResizeMode(col, QHeaderView.Interactive)
            hdr.resizeSection(col, w)

        layout.addWidget(self.table, 1)

        # ── 底部 ──
        btn_row = QHBoxLayout()
        self.status_label = QLabel(tr("就绪"))
        self.status_label.setStyleSheet("font-size: 12px; color: #666;")
        btn_row.addWidget(self.status_label)
        btn_row.addStretch()

        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    # ── 映射操作 ──

    def _start_mapping(self):
        ip = self.ip_input.text().strip()
        if not ip:
            msg_info(self, tr("提示"), tr("请输入交换机 IP 地址。"))
            return
        community = self.community_input.text().strip() or "public"

        self.btn_start.setEnabled(False)
        self.table.setRowCount(0)
        self.info_label.setText("")
        self.status_label.setText(tr("正在连接交换机..."))

        self._thread = SwitchMapThread(ip, community,
                                       snmp_v3_user=self.snmp_v3_user)
        self._thread.log_signal.connect(self._on_progress)
        self._thread.finished_signal.connect(self._on_finished)
        self._thread.start()

    def _on_progress(self, msg: str):
        self.status_label.setText(msg)

    def _on_finished(self, info):
        self.btn_start.setEnabled(True)
        self._thread = None

        if info.error:
            self.status_label.setText(tr("映射失败"))
            msg_warn(self, tr("映射失败"), info.error)
            return

        # 交换机信息
        name_part = info.sys_name or tr("未知")
        self.info_label.setText(
            f"交换机: {name_part} ({info.ip}) · 共 {len(info.mappings)} 条 MAC 映射"
        )

        # 交叉关联扫描结果
        from switch_mapper import cross_reference
        cross_reference(info.mappings, self.scan_results)

        # 填充表格
        self.table.setRowCount(len(info.mappings))
        for row, m in enumerate(info.mappings):
            mac_item = QTableWidgetItem(m.mac)
            mac_font = mac_item.font()
            mac_font.setFamily("Consolas")
            mac_item.setFont(mac_font)
            self.table.setItem(row, 0, mac_item)

            self.table.setItem(row, 1, QTableWidgetItem(m.port_name))

            idx_item = QTableWidgetItem(str(m.if_index) if m.if_index else "—")
            idx_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, idx_item)

            ip_item = QTableWidgetItem(m.ip or "—")
            ip_font = ip_item.font()
            ip_font.setFamily("Consolas")
            ip_item.setFont(ip_font)
            self.table.setItem(row, 3, ip_item)

            self.table.setItem(row, 4, QTableWidgetItem(m.hostname or "—"))
            self.table.setItem(row, 5, QTableWidgetItem(m.vendor or "—"))
            self.table.setItem(row, 6, QTableWidgetItem(
                device_class_label(m.device_class) or "—"))

        self.status_label.setText(f"完成：{len(info.mappings)} 条映射")


class ChangeReportDialog(QDialog):
    """资产变更报告：展示本次扫描与上次快照之间的设备变动。"""

    COLS = [tr("严重度"), tr("变更类型"), "IP", "MAC", tr("主机名"), tr("变更详情")]

    _COLOR_HIGH = QColor(220, 38, 38)     # 红
    _COLOR_WARN = QColor(217, 119, 6)     # 橙
    _COLOR_INFO = QColor(107, 114, 128)   # 灰

    def __init__(self, changes, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.changes = changes
        self.setWindowTitle(tr("资产变更报告"))
        self.setMinimumSize(880, 460)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 摘要 ──
        high = sum(1 for c in changes if c.severity == CHG_HIGH)
        warn = sum(1 for c in changes if c.severity == CHG_WARNING)
        info = sum(1 for c in changes if c.severity == CHG_INFO)
        self.summary_label = QLabel(
            f"共 {len(changes)} 项变更：{high} 严重 · {warn} 警告 · {info} 提示"
        )
        self.summary_label.setStyleSheet("font-size: 13px; padding: 4px 0;")
        layout.addWidget(self.summary_label)

        # ── 表格 ──
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(not dark)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)

        hdr = self.table.horizontalHeader()
        _col_widths = {0: 60, 1: 90, 2: 120, 3: 140, 4: 120, 5: 300}
        for col, w in _col_widths.items():
            hdr.setSectionResizeMode(col, QHeaderView.Interactive)
            hdr.resizeSection(col, w)

        self.table.setRowCount(len(changes))
        for row, c in enumerate(changes):
            # 严重度
            sev_item = QTableWidgetItem(c.severity_label)
            sev_item.setTextAlignment(Qt.AlignCenter)
            color = self._severity_color(c.severity)
            sev_item.setForeground(color)
            sev_font = sev_item.font()
            sev_font.setBold(True)
            sev_item.setFont(sev_font)
            self.table.setItem(row, 0, sev_item)

            # 变更类型
            type_item = QTableWidgetItem(c.type_label)
            type_item.setForeground(color)
            self.table.setItem(row, 1, type_item)

            # IP
            ip_item = QTableWidgetItem(c.ip or "—")
            ip_font = ip_item.font()
            ip_font.setFamily("Consolas")
            ip_item.setFont(ip_font)
            self.table.setItem(row, 2, ip_item)

            # MAC
            mac_item = QTableWidgetItem(c.mac or "—")
            mac_font = mac_item.font()
            mac_font.setFamily("Consolas")
            mac_item.setFont(mac_font)
            self.table.setItem(row, 3, mac_item)

            # 主机名
            self.table.setItem(row, 4, QTableWidgetItem(c.hostname or "—"))

            # 变更详情
            detail = c.description
            if c.old_value and c.new_value:
                detail += f"\n  {c.old_value} → {c.new_value}"
            detail_item = QTableWidgetItem(detail)
            detail_item.setToolTip(detail)
            self.table.setItem(row, 5, detail_item)

        layout.addWidget(self.table, 1)

        # ── 底部按钮 ──
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_export = QPushButton(tr("导出 CSV"))
        btn_export.clicked.connect(self._export_csv)
        btn_row.addWidget(btn_export)

        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    def _severity_color(self, severity) -> QColor:
        if severity == CHG_HIGH:
            return self._COLOR_HIGH
        if severity == CHG_WARNING:
            return self._COLOR_WARN
        return self._COLOR_INFO

    def _export_csv(self):
        default_name = f"资产变更报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出变更报告"), default_name, tr("CSV 文件 (*.csv)")
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.COLS)
                for c in self.changes:
                    writer.writerow([
                        c.severity_label, c.type_label, c.ip, c.mac,
                        c.hostname, c.description,
                    ])
            msg_info(self, tr("导出成功"), f"报告已保存到：\n{path}")
        except Exception as e:
            msg_warn(self, tr("导出失败"), str(e))

