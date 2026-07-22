# -*- coding: utf-8 -*-
"""对话框集合：设备编辑、地址库管理、历史对比、网络拓扑。"""
import json
import math
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QLineEdit, QLabel, QPushButton,
    QHBoxLayout, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QFileDialog, QMessageBox, QComboBox, QCheckBox,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
)
from PyQt5.QtGui import QPainter, QBrush, QPen, QColor

from excel_handler import normalize_mac
from mac_library import MacLibrary
from ui_utils import _compare_snapshots
import history_store


class DeviceEditDialog(QDialog):
    """新增 / 编辑单条设备"""

    FIELDS = [
        ("ip", "IP 地址", "例如 192.168.1.10"),
        ("mac", "MAC 地址", "例如 AA:BB:CC:DD:EE:FF"),
        ("device_type", "设备类型", "例如 PC / 打印机 / 一体机"),
        ("location", "位置", "例如 3楼-301办公室"),
        ("user", "使用者", "例如 张三 / 财务科"),
        ("remark", "备注", "选填"),
        ("vendor", "厂商", "选填"),
    ]

    def __init__(self, library: MacLibrary, parent=None, device_id=None, ip="", mac=""):
        super().__init__(parent)
        self.library = library
        self.device_id = device_id
        self.setWindowTitle("编辑设备" if device_id else "新增设备")
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
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _on_accept(self):
        data = {k: self.edits[k].text().strip() for k, _, _ in self.FIELDS}
        # MAC 校验 (允许为空，但填了要像 MAC)
        if data["mac"]:
            norm = normalize_mac(data["mac"])
            if not norm:
                QMessageBox.warning(self, "格式错误", "MAC 地址格式不正确，请检查后重试。")
                return
            data["mac"] = norm
        if self.device_id:
            self.library.update(self.device_id, **data)
        else:
            self.library.add(**data)
        self.accept()


class MacLibraryDialog(QDialog):
    """地址库管理：浏览 / 搜索 / 增 / 删 / 改 / 导出"""

    COLS = ["ID", "IP地址", "MAC地址", "设备类型", "位置", "使用者", "备注", "来源文件"]

    def __init__(self, library: MacLibrary, parent=None):
        super().__init__(parent)
        self.library = library
        self.setWindowTitle("MAC 地址库管理")
        self.resize(1000, 620)

        vbox = QVBoxLayout(self)

        # 工具条
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("搜索:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("按 IP / MAC / 类型 / 位置 / 使用者 搜索")
        self.search_edit.textChanged.connect(self._reload)
        toolbar.addWidget(self.search_edit)

        toolbar.addStretch()
        btn_add = QPushButton("新增")
        btn_add.clicked.connect(self._add)
        btn_edit = QPushButton("编辑")
        btn_edit.clicked.connect(self._edit)
        btn_del = QPushButton("删除")
        btn_del.clicked.connect(self._delete)
        btn_export = QPushButton("导出")
        btn_export.clicked.connect(self._export)
        btn_refresh = QPushButton("刷新")
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

    def _edit(self):
        did = self._selected_id()
        if did is None:
            QMessageBox.information(self, "提示", "请先选中一行")
            return
        dlg = DeviceEditDialog(self.library, parent=self, device_id=did)
        if dlg.exec_() == QDialog.Accepted:
            self._reload()

    def _delete(self):
        did = self._selected_id()
        if did is None:
            QMessageBox.information(self, "提示", "请先选中一行")
            return
        dev = self.library.get_by_id(did)
        label = (dev.get("mac") or dev.get("ip") or f"#{did}")
        reply = QMessageBox.question(
            self, "确认删除", f"确定删除该设备吗？\n\n{label}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.library.delete(did)
            self._reload()

    def _export(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出地址库", default_name, "Excel 文件 (*.xlsx)"
        )
        if not path:
            return
        success, msg = self.library.export_to_excel(path)
        QMessageBox.information(self, "导出成功" if success else "导出失败", msg)


class HistoryCompareDialog(QDialog):
    """选择两次历史快照进行差异对比。"""

    def __init__(self, parent=None, db_path=None):
        super().__init__(parent)
        self.db_path = db_path
        self.setWindowTitle("扫描历史对比")
        self.setMinimumSize(720, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.hist = self._load_history()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        tip = QLabel("选择基准与对比快照，查看两次扫描之间网络中设备的变化。")
        layout.addWidget(tip)

        sel_row = QHBoxLayout()
        sel_row.setSpacing(8)
        sel_row.addWidget(QLabel("基准快照:"))
        self.base_combo = QComboBox()
        self.target_combo = QComboBox()
        sel_row.addWidget(self.base_combo, 1)
        sel_row.addWidget(QLabel("对比快照:"))
        sel_row.addWidget(self.target_combo, 1)
        cmp_btn = QPushButton("对比")
        cmp_btn.setObjectName("primaryBtn")
        cmp_btn.clicked.connect(self._do_compare)
        sel_row.addWidget(cmp_btn)
        layout.addLayout(sel_row)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP 地址", "变化类型", "旧值", "新值"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #555555; font-size: 11px;")
        layout.addWidget(self.summary_label)

        close_btn = QPushButton("关闭")
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
            self.base_combo.addItem("(无历史快照)")
            self.target_combo.addItem("(无历史快照)")
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
            self.summary_label.setText("尚无历史快照，请先完成至少两次扫描。")
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
        added = sum(1 for d in diffs if d["change"] == "新增设备")
        removed = sum(1 for d in diffs if d["change"] == "消失设备")
        changed = len(diffs) - added - removed
        self.summary_label.setText(
            f"共 {len(diffs)} 处变化：新增 {added} · 消失 {removed} · 其他变更 {changed}   "
            f"(基准 {self._fmt_time(base['time'])} → 对比 {self._fmt_time(target['time'])})"
        )


class TopologyDialog(QDialog):
    """以中心网关 + 辐射主机的星型拓扑展示当前扫描结果。"""

    def __init__(self, results, gateway_ip, dark, parent=None):
        super().__init__(parent)
        self.setWindowTitle("网络拓扑视图")
        self.setMinimumSize(820, 600)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.results = list(results)
        self.gateway_ip = gateway_ip
        self.dark = dark

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)

        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing, True)
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QBrush(QColor(30, 30, 30) if dark else QColor(248, 248, 248)))
        self.view.setScene(self.scene)
        layout.addWidget(self.view, 1)

        self.legend = QLabel()
        self._update_legend()
        layout.addWidget(self.legend)

        self.setLayout(layout)
        self._build_topology()

    def _update_legend(self):
        self.legend.setText(
            "<span style='color:#E69500;'>●</span> 网关   "
            "<span style='color:#22A34A;'>●</span> 在线   "
            "<span style='color:#B4B4B4;'>●</span> 离线"
        )
        self.legend.setStyleSheet("font-size: 12px; padding: 4px;")

    def _text_color(self):
        return QColor(224, 224, 224) if self.dark else QColor(40, 40, 40)

    def _build_topology(self):
        cx, cy = 0, 0
        hosts = self.results
        n = len(hosts)
        R = max(200, 50 + n * 7)
        edge_pen = QPen(QColor(150, 156, 166) if self.dark else QColor(170, 170, 170), 1)

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
        # 若网关 IP 命中扫描结果，展示其主机名 / MAC
        sub = self.gateway_ip or "未知"
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
        txt = QGraphicsTextItem("网关\n" + sub)
        txt.setDefaultTextColor(self._text_color())
        txt.setPos(x - 45, y + 28)
        self.scene.addItem(txt)


class WmiCredentialDialog(QDialog):
    """采集 WMI 识别所需的管理员凭据。

    密码以 QLineEdit(Password) 显示；勾选"保存凭据(加密)"后由调用方用 DPAPI 加密
    存入 ipscanner.ini。本对话框不负责持久化，只回传明文凭据。
    """

    def __init__(self, parent=None, saved_username: str = "", saved_domain: str = ""):
        super().__init__(parent)
        self.setWindowTitle("WMI 设备识别 — 管理员凭据")
        self.setMinimumWidth(380)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QFormLayout(self)

        self.user_edit = QLineEdit(saved_username)
        self.user_edit.setPlaceholderText("如 administrator 或 user（不含域）")
        layout.addRow("用户名:", self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText("目标主机管理员密码")
        layout.addRow("密码:", self.pass_edit)

        self.domain_edit = QLineEdit(saved_domain)
        self.domain_edit.setPlaceholderText("域（可选，工作组可留空）")
        layout.addRow("域:", self.domain_edit)

        self.save_check = QCheckBox("保存凭据（DPAPI 加密到本机配置）")
        layout.addRow(self.save_check)

        hint = QLabel(
            "WMI 识别仅对 Windows 目标有效，需目标开放 DCOM/WMI（通常 135 端口）"
            "且当前凭据具管理员权限。\n非域环境请填目标本机管理员账号。"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #888; font-size: 11px;")
        layout.addRow(hint)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_credentials(self):
        """返回 (username, password, domain, save)。"""
        return (
            self.user_edit.text().strip(),
            self.pass_edit.text(),
            self.domain_edit.text().strip(),
            self.save_check.isChecked(),
        )

