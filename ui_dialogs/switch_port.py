# -*- coding: utf-8 -*-
"""交换机端口映射对话框：通过 SNMP 取 BRIDGE-MIB 转发表，展示 MAC -> 端口。"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
)

from i18n import tr
from scanner.constants import device_class_label
from ui_msg import msg_info, msg_warn
from ui_threads import SwitchMapThread


class SwitchPortDialog(QDialog):
    """交换机端口映射：通过 SNMP 获取 MAC 转发表，展示 MAC → 物理端口对应关系。"""

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return [tr("MAC 地址"), tr("端口"), "ifIndex", "IP", tr("主机名"),
                tr("厂商"), tr("设备类型")]

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
        self.info_label.setObjectName("dialogHint")
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
        self.status_label.setObjectName("dialogHint")
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
