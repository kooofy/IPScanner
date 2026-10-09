# -*- coding: utf-8 -*-
"""地址库对话框：单条设备的新增/编辑，以及地址库的浏览/搜索/增删改/导出。"""
import os
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QLineEdit, QLabel, QPushButton,
    QHBoxLayout, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QFileDialog, QMessageBox,
)

import audit_log
from app_logging import get_logger
from excel_handler import normalize_mac
from i18n import tr
from mac_library import MacLibrary
from ui_msg import localize_buttons, msg_ask, msg_info, msg_warn

_log = get_logger(__name__)


class DeviceEditDialog(QDialog):
    """新增 / 编辑单条设备"""

    @property
    def FIELDS(self):
        """表单字段 (key, 标签, 占位提示)。

        ⚠️ 必须写成 property：类体在 **import 期**求值，那时语言包还没加载，
        写成类属性会把中文永久冻住（英文界面下表单标签仍是中文）。
        """
        return [
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

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return ["ID", tr("IP地址"), tr("MAC地址"), tr("设备类型"), tr("位置"),
                tr("使用者"), tr("备注"), tr("来源文件")]

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
