# -*- coding: utf-8 -*-
"""报表型对话框：IP 冲突报告、子网利用率、资产变更报告。

三者形态同构 —— 摘要行 + 带严重度/利用率着色的表格 + CSV 导出。
"""
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QFileDialog,
    QProgressBar, QSizePolicy,
)

from change_detector import (SEVERITY_HIGH as CHG_HIGH,
                             SEVERITY_WARNING as CHG_WARNING,
                             SEVERITY_INFO as CHG_INFO)
from conflict_detector import SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO
from i18n import tr
from theme_tokens import token
import ui_logic
from ui_msg import msg_info, msg_warn

from ._shared import _theme_color


class ConflictReportDialog(QDialog):
    """IP 冲突检测报告对话框。

    以表格展示所有检测到的冲突，按严重级别着色，
    支持选中行高亮对应 IP（通过回调通知主窗口）。
    """

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return [tr("严重级别"), tr("冲突类型"), tr("描述"), tr("涉及 IP"),
                tr("涉及 MAC"), tr("详情")]
    # 级别 → 语义色**令牌名**。存名字而不是 `QColor`：类体在 import 期求值，
    # 那时还不知道用户选的是浅色还是深色主题，存 QColor 就等于把颜色冻死。
    _SEVERITY_TOKEN = {
        SEVERITY_HIGH: "danger",     # 红
        SEVERITY_WARNING: "warn",    # 橙
        SEVERITY_INFO: "link",       # 蓝
    }
    _SEVERITY_BG_TOKEN = {
        SEVERITY_HIGH: "sev_bg_high",     # 淡红底 / 深红底
        SEVERITY_WARNING: "sev_bg_warn",  # 淡橙底 / 深橙底
        SEVERITY_INFO: "sev_bg_info",     # 淡蓝底 / 深蓝底
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
            summary_parts.append(self._summary_span("danger", high, "严重"))
        if warn:
            summary_parts.append(self._summary_span("warn", warn, "警告"))
        if info:
            summary_parts.append(self._summary_span("link", info, "提示"))
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

        # 表头是 property（每次读取都翻译）；行循环里要用列数，先算一次
        n_cols = len(self.COLS)
        self.table.setRowCount(len(conflicts))
        for row, c in enumerate(conflicts):
            # 严重级别
            sev_item = QTableWidgetItem(c.severity_label)
            sev_item.setTextAlignment(Qt.AlignCenter)
            fg = _theme_color(self._SEVERITY_TOKEN.get(c.severity, "gray"),
                              self.dark)
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
            # 行底色两套主题都铺：深色下用同色系的深底，"按级别着色"这条
            # 信息在深色主题里才不会丢（旧实现直接 `not self.dark` 跳过）。
            bg_name = self._SEVERITY_BG_TOKEN.get(c.severity)
            if bg_name:
                bg = _theme_color(bg_name, self.dark)
                for col in range(n_cols):
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

    def _summary_span(self, token_name: str, count: int, word: str) -> str:
        """摘要行里的一个彩色片段（色值随主题，与单元格着色同源）。"""
        return ("<span style='color:%s;font-weight:bold;'>%d %s</span>"
                % (token(token_name, self.dark), count, word))

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

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return [tr("子网"), tr("扫描 IP 数"), tr("在线"), tr("离线"),
                tr("利用率"), tr("设备类型分布")]

    # 利用率色阶 → 令牌名（同上：类体在 import 期求值，不能存 QColor）
    _UTIL_TOKEN_LOW = "online"     # 绿 <60%
    _UTIL_TOKEN_MID = "warn"       # 橙 60-85%
    _UTIL_TOKEN_HIGH = "danger"    # 红 >85%

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
            on_item.setForeground(_theme_color(self._UTIL_TOKEN_LOW, self.dark))
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
                "QProgressBar { border: 1px solid %s; border-radius: 2px; "
                "background: %s; font-size: 11px; margin: 1px; }"
                "QProgressBar::chunk { background: %s; border-radius: 1px; }"
                % (token("sep", dark), token("surface_alt", dark), color.name())
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
            return _theme_color(self._UTIL_TOKEN_HIGH, self.dark)
        if pct >= 60:
            return _theme_color(self._UTIL_TOKEN_MID, self.dark)
        return _theme_color(self._UTIL_TOKEN_LOW, self.dark)

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


class ChangeReportDialog(QDialog):
    """资产变更报告：展示本次扫描与上次快照之间的设备变动。"""

    @property
    def COLS(self):
        """表头文案。**每次读取时翻译** —— 写成类属性会在 import 期求值，英文界面下永远是中文表头。"""
        return [tr("严重度"), tr("变更类型"), "IP", "MAC", tr("主机名"),
                tr("变更详情")]

    # 严重度 → 令牌名（同上：类体在 import 期求值，不能存 QColor）
    _SEVERITY_TOKEN = {
        CHG_HIGH: "danger",      # 红
        CHG_WARNING: "warn",     # 橙
        CHG_INFO: "gray",        # 灰
    }

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
        return _theme_color(self._SEVERITY_TOKEN.get(severity, "gray"), self.dark)

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
