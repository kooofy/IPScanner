# -*- coding: utf-8 -*-
"""审计日志查看器：按分类筛选 + 关键词搜索，展示扫描活动记录。"""
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMessageBox,
)

import audit_log
from i18n import tr
from ui_msg import msg_ask, msg_warn


class AuditLogDialog(QDialog):
    """审计日志查看器：按分类筛选 + 关键词搜索，展示扫描活动记录。"""

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return [tr("时间"), tr("分类"), tr("操作"), tr("详情")]

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
        self.count_label.setObjectName("dialogHint")
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
