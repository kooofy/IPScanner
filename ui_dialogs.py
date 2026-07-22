# -*- coding: utf-8 -*-
"""对话框集合：设备编辑、地址库管理、历史对比、网络拓扑、冲突报告、子网利用率、审计日志。"""
import os
import json
import math
import ipaddress
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QLineEdit, QLabel, QPushButton,
    QHBoxLayout, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QFileDialog, QMessageBox, QComboBox, QCheckBox,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
    QProgressBar, QSizePolicy,
)
from PyQt5.QtGui import QPainter, QBrush, QPen, QColor, QFont

from excel_handler import normalize_mac
from mac_library import MacLibrary
from ui_utils import _compare_snapshots
from conflict_detector import Conflict, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO
import history_store
import audit_log
from ui_threads import SwitchMapThread


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
            self._audit("新增设备", f"地址库共 {self.library.count()} 条")

    def _edit(self):
        did = self._selected_id()
        if did is None:
            QMessageBox.information(self, "提示", "请先选中一行")
            return
        dlg = DeviceEditDialog(self.library, parent=self, device_id=did)
        if dlg.exec_() == QDialog.Accepted:
            self._reload()
            self._audit("编辑设备", f"设备 #{did}")

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
            self._audit("删除设备", f"{label} · 地址库余 {self.library.count()} 条")

    def _export(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出地址库", default_name, "Excel 文件 (*.xlsx)"
        )
        if not path:
            return
        success, msg = self.library.export_to_excel(path)
        if success:
            self._audit("导出地址库", f"{self.library.count()} 条 · {os.path.basename(path)}")
        QMessageBox.information(self, "导出成功" if success else "导出失败", msg)

    @staticmethod
    def _audit(action, detail=""):
        """安全记录地址库审计日志，异常不影响对话框。"""
        try:
            audit_log.log_event(audit_log.CAT_LIBRARY, action, detail)
        except Exception:
            pass


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


class ConflictReportDialog(QDialog):
    """IP 冲突检测报告对话框。

    以表格展示所有检测到的冲突，按严重级别着色，
    支持选中行高亮对应 IP（通过回调通知主窗口）。
    """

    COLS = ["严重级别", "冲突类型", "描述", "涉及 IP", "涉及 MAC", "详情"]
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
        self.setWindowTitle("IP 冲突检测报告")
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
        summary_text = " · ".join(summary_parts) if summary_parts else "无冲突"
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

        btn_export = QPushButton("导出报告")
        btn_export.setToolTip("将冲突报告导出为 CSV 文件")
        btn_export.clicked.connect(self._export_csv)
        btn_row.addWidget(btn_export)

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    def _export_csv(self):
        default_name = f"IP冲突报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出冲突报告", default_name, "CSV 文件 (*.csv)"
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
            QMessageBox.information(self, "导出成功", f"报告已保存到：\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "导出失败", str(e))


class SubnetUtilizationDialog(QDialog):
    """子网利用率视图：按 /24 聚合扫描结果，展示各子网的在线占比与设备分布。"""

    COLS = ["子网", "扫描 IP 数", "在线", "离线", "利用率", "设备类型分布"]

    # 利用率色阶
    _COLOR_LOW = QColor(34, 163, 74)      # 绿 <60%
    _COLOR_MID = QColor(217, 119, 6)      # 橙 60-85%
    _COLOR_HIGH = QColor(220, 38, 38)     # 红 >85%

    def __init__(self, results, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.setWindowTitle("子网利用率")
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

        btn_export = QPushButton("导出 CSV")
        btn_export.clicked.connect(self._export_csv)
        btn_row.addWidget(btn_export)

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    # ── 分析逻辑 ──

    @staticmethod
    def _analyze(results) -> list:
        """按 /24 聚合扫描结果，返回子网统计列表（按利用率降序）。"""
        # 按 /24 分组
        groups: dict = {}  # subnet_str -> {"ips": set, "online": int, "offline": int, "devices": {}}
        for r in results:
            try:
                addr = ipaddress.ip_address(r.ip)
                net = ipaddress.ip_network(f"{r.ip}/24", strict=False)
                key = str(net)
            except ValueError:
                continue
            g = groups.setdefault(key, {
                "ips": set(), "online": 0, "offline": 0, "devices": {}
            })
            g["ips"].add(r.ip)
            if r.status == "online":
                g["online"] += 1
                # 设备类型统计
                dtype = getattr(r, "device_class", "") or getattr(r, "device_type", "") or "未识别"
                g["devices"][dtype] = g["devices"].get(dtype, 0) + 1
            else:
                g["offline"] += 1

        subnets = []
        for subnet_str, g in groups.items():
            total = len(g["ips"])
            online = g["online"]
            offline = g["offline"]
            pct = (online / total * 100) if total else 0
            # 设备分布文本
            dev_parts = [f"{k}×{v}" for k, v in
                         sorted(g["devices"].items(), key=lambda x: -x[1])]
            subnets.append({
                "subnet": subnet_str,
                "total": total,
                "online": online,
                "offline": offline,
                "utilization": pct,
                "device_dist": ", ".join(dev_parts) if dev_parts else "—",
            })

        # 按利用率降序
        subnets.sort(key=lambda s: -s["utilization"])
        return subnets

    def _util_color(self, pct: float) -> QColor:
        if pct > 85:
            return self._COLOR_HIGH
        if pct >= 60:
            return self._COLOR_MID
        return self._COLOR_LOW

    def _export_csv(self):
        default_name = f"子网利用率_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出子网利用率", default_name, "CSV 文件 (*.csv)"
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
            QMessageBox.information(self, "导出成功", f"已保存到：\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "导出失败", str(e))


class AuditLogDialog(QDialog):
    """审计日志查看器：按分类筛选 + 关键词搜索，展示扫描活动记录。"""

    COLS = ["时间", "分类", "操作", "详情"]

    def __init__(self, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.setWindowTitle("审计日志")
        self.setMinimumSize(820, 500)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部筛选栏 ──
        filter_row = QHBoxLayout()
        filter_row.setSpacing(6)

        filter_row.addWidget(QLabel("分类:"))
        self.cat_combo = QComboBox()
        self.cat_combo.addItem("全部", "")
        for cat in audit_log.CATEGORIES:
            self.cat_combo.addItem(cat, cat)
        self.cat_combo.setMinimumWidth(110)
        self.cat_combo.currentIndexChanged.connect(self._reload)
        filter_row.addWidget(self.cat_combo)

        filter_row.addWidget(QLabel("搜索:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("在操作 / 详情中查找关键词...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.returnPressed.connect(self._reload)
        filter_row.addWidget(self.search_input, 1)

        btn_search = QPushButton("查询")
        btn_search.clicked.connect(self._reload)
        filter_row.addWidget(btn_search)

        btn_refresh = QPushButton("刷新")
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

        btn_clear = QPushButton("清空日志")
        btn_clear.clicked.connect(self._clear_logs)
        btn_row.addWidget(btn_clear)

        btn_close = QPushButton("关闭")
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
            QMessageBox.warning(self, "读取失败", str(e))
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

            cat_item = QTableWidgetItem(log["category"])
            cat_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, cat_item)

            self.table.setItem(row, 2, QTableWidgetItem(log["action"]))

            detail_item = QTableWidgetItem(log["detail"])
            detail_item.setToolTip(log["detail"])
            self.table.setItem(row, 3, detail_item)

        self.count_label.setText(f"共 {len(logs)} 条记录")

    def _clear_logs(self):
        reply = QMessageBox.question(
            self, "确认清空", "确定要清空全部审计日志吗？此操作不可恢复。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            audit_log.clear_logs()
        except Exception as e:
            QMessageBox.warning(self, "清空失败", str(e))
            return
        self._reload()


class SwitchPortDialog(QDialog):
    """交换机端口映射：通过 SNMP 获取 MAC 转发表，展示 MAC → 物理端口对应关系。"""

    COLS = ["MAC 地址", "端口", "ifIndex", "IP", "主机名", "厂商", "设备类型"]

    def __init__(self, scan_results=None, parent=None, dark=False):
        super().__init__(parent)
        self.dark = dark
        self.scan_results = scan_results or []
        self._thread = None
        self.setWindowTitle("交换机端口映射")
        self.setMinimumSize(900, 520)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部：交换机 IP + 社区名 + 开始按钮 ──
        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        top_row.addWidget(QLabel("交换机 IP:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("例如 192.168.1.1")
        self.ip_input.setMinimumWidth(140)
        top_row.addWidget(self.ip_input)

        top_row.addWidget(QLabel("社区名:"))
        self.community_input = QLineEdit("public")
        self.community_input.setMinimumWidth(80)
        self.community_input.setMaximumWidth(120)
        top_row.addWidget(self.community_input)

        self.btn_start = QPushButton("开始映射")
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
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("font-size: 12px; color: #666;")
        btn_row.addWidget(self.status_label)
        btn_row.addStretch()

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    # ── 映射操作 ──

    def _start_mapping(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.information(self, "提示", "请输入交换机 IP 地址。")
            return
        community = self.community_input.text().strip() or "public"

        self.btn_start.setEnabled(False)
        self.table.setRowCount(0)
        self.info_label.setText("")
        self.status_label.setText("正在连接交换机...")

        self._thread = SwitchMapThread(ip, community)
        self._thread.log_signal.connect(self._on_progress)
        self._thread.finished_signal.connect(self._on_finished)
        self._thread.start()

    def _on_progress(self, msg: str):
        self.status_label.setText(msg)

    def _on_finished(self, info):
        self.btn_start.setEnabled(True)
        self._thread = None

        if info.error:
            self.status_label.setText("映射失败")
            QMessageBox.warning(self, "映射失败", info.error)
            return

        # 交换机信息
        name_part = info.sys_name or "未知"
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
            self.table.setItem(row, 6, QTableWidgetItem(m.device_class or "—"))

        self.status_label.setText(f"完成：{len(info.mappings)} 条映射")

