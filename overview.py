# -*- coding: utf-8 -*-
"""扫描结果概览仪表盘（对应 docs/reviews/UI_REVIEW.md 的 P3-2）。

设计动机
--------
本项目的统计能力其实早就有 —— `SubnetUtilizationDialog` 会算子网在线率、
`conflict_detector` 会算冲突、`change_detector` 会算变更 —— 但**全都只活在
弹窗里**：用户必须先想到"我该去看看子网利用率"，再点开一个对话框。

Fing 这类产品出圈靠的正是打开即见的那块概览：设备总数、在线率、新增、异常、
Top 厂商。这里把散落在各处的统计提升为**常驻页面**，让"网络现在什么状况"
变成零点击就能回答的问题。

分工约定
--------
- 指标计算全在 `ui_logic.build_overview`（纯函数，可脱离 Qt 单测）；
- 本模块**只负责渲染**，不做任何统计；
- 配色一律走 QSS（objectName / 动态属性选择器），不在 Python 里硬编码颜色 ——
  否则深色主题下会"漏白"（见 docs/reviews/UI_REVIEW.md P2-2）。
"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame,
    QProgressBar, QSizePolicy,
)

from change_detector import (
    CHANGE_NEW_DEVICE, CHANGE_DEVICE_GONE, CHANGE_IP_CHANGED,
    CHANGE_MAC_CHANGED, CHANGE_HOSTNAME_CHANGED, CHANGE_MAC_RANDOMIZED,
)
from conflict_detector import SEVERITY_HIGH, SEVERITY_WARNING
from scanner import device_class_label
from i18n import tr


def set_tone(widget, tone: str):
    """给控件打上语义色调（QSS 用 `[tone="…"]` 属性选择器取色）。

    动态属性不会自动触发重绘，必须 unpolish/polish 一次 —— 少了这两行，
    色调会在第一次设置后"卡住"不变，而这种问题不会报错、只能靠肉眼发现。
    """
    if widget.property("tone") == tone:
        return
    widget.setProperty("tone", tone)
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)


def _utilization_tone(pct: float) -> str:
    """利用率色阶：<60% 宽松、60–85% 偏紧、>85% 拥挤。"""
    if pct > 85:
        return "bad"
    if pct >= 60:
        return "warn"
    return "good"


class _StatCard(QFrame):
    """一张 KPI 卡片：大号数值 + 小号说明。"""

    def __init__(self, label: str, tone: str = "neutral", parent=None):
        super().__init__(parent)
        self.setObjectName("statCard")
        self.setFrameShape(QFrame.NoFrame)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(1)
        self.value = QLabel("—")
        self.value.setObjectName("statValue")
        set_tone(self.value, tone)
        self.caption = QLabel(label)
        self.caption.setObjectName("statLabel")
        lay.addWidget(self.value)
        lay.addWidget(self.caption)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    def set_value(self, text: str):
        self.value.setText(text)


class OverviewPanel(QWidget):
    """概览页：KPI 卡片 + 变更/风险摘要 + Top 厂商/设备类型/子网利用率。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("overviewPanel")
        self._build()

    # ── 构建 ──────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(8)
        title = QLabel(tr("概览"))
        title.setObjectName("overviewTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.scope = QLabel("")
        self.scope.setObjectName("overviewScope")
        head.addWidget(self.scope)
        root.addLayout(head)

        # ── KPI 卡片 ──
        cards = QGridLayout()
        cards.setContentsMargins(0, 0, 0, 0)
        cards.setHorizontalSpacing(8)
        cards.setVerticalSpacing(8)
        self.card_total = _StatCard(tr("设备总数"), "neutral")
        self.card_online = _StatCard(tr("在线"), "online")
        self.card_offline = _StatCard(tr("离线"), "offline")
        self.card_ratio = _StatCard(tr("在线率"), "accent")
        for col, card in enumerate((self.card_total, self.card_online,
                                    self.card_offline, self.card_ratio)):
            cards.addWidget(card, 0, col)
            cards.setColumnStretch(col, 1)
        root.addLayout(cards)

        # ── 变更 / 风险 / 服务 摘要 ──
        self.summary_row = QHBoxLayout()
        self.summary_row.setSpacing(8)
        self.block_changes = self._make_block(tr("变更"))
        self.block_risks = self._make_block(tr("风险"))
        self.block_services = self._make_block(tr("服务暴露"))
        for block, _body in (self.block_changes, self.block_risks,
                             self.block_services):
            self.summary_row.addWidget(block, 1)
        # stretch=1：让这两行按比例吃满剩余高度。旧实现在末尾留了一个
        # `addStretch(1)`，于是 1080×660 的窗口下概览只占上半屏、下半屏整片空白
        # （见 docs/reviews/UI_REVIEW_ROUND2.md §5 第 9 项）。KPI 卡片行不参与拉伸 —— 它的
        # 高度是 Fixed，拉伸只会把空白塞进卡片内部。
        root.addLayout(self.summary_row, 1)

        # ── 分布列表 ──
        self.list_row = QHBoxLayout()
        self.list_row.setSpacing(8)
        self.block_vendors = self._make_block(tr("Top 厂商"))
        self.block_classes = self._make_block(tr("设备类型"))
        self.block_subnets = self._make_block(tr("子网利用率"))
        for block, _body in (self.block_vendors, self.block_classes,
                             self.block_subnets):
            self.list_row.addWidget(block, 1)
        root.addLayout(self.list_row, 1)

    def _make_block(self, title: str):
        """一个带标题的区块，返回 (QFrame, 用于放内容的 QVBoxLayout)。"""
        box = QFrame()
        box.setObjectName("overviewBlock")
        box.setFrameShape(QFrame.NoFrame)
        lay = QVBoxLayout(box)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(4)
        head = QLabel(title)
        head.setObjectName("overviewBlockTitle")
        lay.addWidget(head)
        body = QVBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(3)
        lay.addLayout(body)
        lay.addStretch(1)
        return box, body

    # ── 对外接口 ──────────────────────────────────────────

    def clear(self):
        """无数据：清空所有指标，回到"未扫描"状态。"""
        for card in (self.card_total, self.card_online, self.card_offline,
                     self.card_ratio):
            card.set_value("—")
        self.scope.setText("")
        for _block, body in (self.block_changes, self.block_risks,
                             self.block_services, self.block_vendors,
                             self.block_classes, self.block_subnets):
            self._fill(body, [self._hint(tr("暂无数据"))])

    def set_data(self, data: dict):
        """渲染一份 `ui_logic.build_overview` 的输出。"""
        data = data or {}
        total = data.get("total", 0)
        if not total:
            self.clear()
            return

        online = data.get("online", 0)
        self.card_total.set_value(str(total))
        self.card_online.set_value(str(online))
        self.card_offline.set_value(str(data.get("offline", 0)))
        self.card_ratio.set_value(f"{data.get('online_ratio', 0.0):.1f}%")
        self.scope.setText(
            tr("本次扫描共 {n} 个 IP").format(n=total)
            + (f" · {tr('未知')} {data['unknown']}" if data.get("unknown") else "")
        )

        self._render_changes(data)
        self._render_risks(data)
        self._render_services(data)
        self._render_counter(self.block_vendors, data.get("vendors") or [],
                             data.get("vendor_kinds", 0))
        # 设备类别存的是**语言无关的规范值**（如「电脑」），必须在展示层才翻译 ——
        # 少了这一步，英文界面会直接印出「电脑/打印机」。这与表格列、导出的做法一致。
        self._render_counter(self.block_classes, data.get("device_classes") or [],
                             data.get("class_kinds", 0),
                             label_fn=device_class_label)
        self._render_subnets(data.get("subnets") or [])

    # ── 内部：各区块渲染 ──────────────────────────────────

    def _render_changes(self, data):
        counts = data.get("changes") or {}
        if not counts:
            self._fill(self.block_changes[1],
                       [self._hint(tr("与上次扫描相比无变更"))])
            return
        rows = []
        # 顺序固定，便于"每次看同一个位置"；缺失的类型不显示
        for ctype in (CHANGE_NEW_DEVICE, CHANGE_IP_CHANGED, CHANGE_MAC_CHANGED,
                      CHANGE_HOSTNAME_CHANGED, CHANGE_MAC_RANDOMIZED,
                      CHANGE_DEVICE_GONE):
            n = counts.get(ctype, 0)
            if n:
                rows.append(self._kv(self._change_label(ctype), str(n)))
        self._fill(self.block_changes[1], rows)

    def _render_risks(self, data):
        conf = data.get("conflicts") or {}
        high = conf.get(SEVERITY_HIGH, 0)
        warn = conf.get(SEVERITY_WARNING, 0)
        rows = []
        if high:
            rows.append(self._kv(tr("严重冲突"), str(high), tone="bad"))
        if warn:
            rows.append(self._kv(tr("警告"), str(warn), tone="warn"))
        if not rows:
            rows.append(self._hint(tr("未发现冲突")))
        self._fill(self.block_risks[1], rows)

    def _render_services(self, data):
        rows = [self._kv(tr("有开放端口"), str(data.get("services", 0))),
                self._kv(tr("开放端口总数"), str(data.get("ports", 0)))]
        self._fill(self.block_services[1], rows)

    def _render_counter(self, block, pairs, kinds, label_fn=None):
        """渲染「名称 + 比例条 + 台数」列表。

        `label_fn` 用于把规范值转成显示名（如设备类别）；厂商名本身已是
        显示名，故默认 None 表示原样展示。
        """
        if not pairs:
            self._fill(block[1], [self._hint(tr("未识别"))])
            return
        top = pairs[0][1] or 1
        rows = []
        for name, count in pairs:
            shown = label_fn(name) if label_fn else name
            rows.append(self._bar_row(shown, str(count), count / top))
        if kinds > len(pairs):
            rows.append(self._hint(
                tr("另有 {n} 项未列出").format(n=kinds - len(pairs))))
        self._fill(block[1], rows)

    def _render_subnets(self, subnets):
        if not subnets:
            self._fill(self.block_subnets[1], [self._hint(tr("暂无数据"))])
            return
        rows = []
        for s in subnets:
            pct = s.get("utilization", 0.0)
            rows.append(self._bar_row(
                f"{s.get('subnet', '')}   {s.get('online', 0)}/{s.get('total', 0)}",
                f"{pct:.0f}%", pct / 100.0, tone=_utilization_tone(pct)))
        self._fill(self.block_subnets[1], rows)

    # ── 内部：小控件 ──────────────────────────────────────

    @staticmethod
    def _change_label(ctype: str) -> str:
        return {
            CHANGE_NEW_DEVICE: tr("新增设备"),
            CHANGE_IP_CHANGED: tr("IP 变更"),
            CHANGE_MAC_CHANGED: tr("MAC 变更"),
            CHANGE_HOSTNAME_CHANGED: tr("主机名变更"),
            CHANGE_DEVICE_GONE: tr("设备消失"),
            CHANGE_MAC_RANDOMIZED: tr("随机 MAC 重现"),
        }.get(ctype, ctype)

    def _kv(self, name: str, value: str, tone: str = "") -> QWidget:
        """一行「名称 …… 数值」。"""
        value = str(value)  # QLabel 只接受 str；调用方传 int 会直接 TypeError
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        lab = QLabel(name)
        lab.setObjectName("overviewName")
        lay.addWidget(lab)
        lay.addStretch(1)
        val = QLabel(value)
        val.setObjectName("overviewCount")
        if tone:
            set_tone(val, tone)
        lay.addWidget(val)
        return w

    def _bar_row(self, name: str, value: str, ratio: float,
                 tone: str = "") -> QWidget:
        """一行「名称 + 比例条 + 数值」。

        比例条用 `QProgressBar`（0–100 整数）而不是自绘：QSS 能直接给
        `::chunk` 上色，高 DPI 下也不会像手绘那样需要自己处理缩放。
        """
        value = str(value)  # QLabel 只接受 str；调用方传 int 会直接 TypeError
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        lab = QLabel(name)
        lab.setObjectName("overviewName")
        lab.setMinimumWidth(60)
        lay.addWidget(lab, 3)
        bar = QProgressBar()
        bar.setObjectName("overviewBar")
        bar.setRange(0, 100)
        bar.setValue(max(0, min(100, int(round(ratio * 100)))))
        bar.setTextVisible(False)
        bar.setFixedHeight(8)
        if tone:
            set_tone(bar, tone)
        lay.addWidget(bar, 4)
        val = QLabel(value)
        val.setObjectName("overviewCount")
        val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        val.setMinimumWidth(34)
        lay.addWidget(val, 0)
        return w

    def _hint(self, text: str) -> QWidget:
        lab = QLabel(text)
        lab.setObjectName("overviewHint")
        lab.setWordWrap(True)
        return lab

    @staticmethod
    def _fill(body, widgets):
        """清空并重填一个区块的内容。"""
        while body.count():
            item = body.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        for w in widgets:
            body.addWidget(w)
