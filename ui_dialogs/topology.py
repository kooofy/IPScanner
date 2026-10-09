# -*- coding: utf-8 -*-
"""网络拓扑视图对话框：LLDP/CDP/转发表发现的真实链路 + 终端设备。

布局由 `topology_discovery.layout_real_topology`（纯函数、可单测）给出；
本文件只负责绘制 —— QGraphicsScene 自绘，QSS 覆盖不到，取色一律走 `_shared`。
"""
import math

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPainter, QBrush, QPen, QColor
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
    QGraphicsRectItem,
)

from i18n import tr
from scanner.constants import device_class_label
from theme_tokens import token

from ._shared import _ellipsize, _faded, _theme_color


class TopologyDialog(QDialog):
    """网络拓扑视图：LLDP/CDP/转发表发现的真实链路 + 终端设备。

    若提供了带链路的 topology，展示真实拓扑（分层骨干 + 每台网络设备下方的
    终端网格）；否则回退到网关为中心的星型拓扑，并把"为什么没有真实链路"
    写进图例 —— 一张不说原因的假星型图，用户只会以为工具"识别不出交换机"。
    """

    #: 星型拓扑最多画多少个**在线**节点，超出的只计数不画。
    _MAX_STAR_NODES = 400

    #: 节点数超过这个值就不画辐条 —— 几百条 1px 细线汇聚圆心，缩小后会退化成
    #: 摩尔纹（2026-10-09 用户实测：1023 台时整个视图完全无法阅读）。
    _MAX_STAR_EDGES = 150

    #: 在线节点超过这个数量就不再逐点标注 IP（信息改走悬停提示），
    #: 否则文字会糊成一片，反而比不标更难读。同心环的环内间距是常数 92px，
    #: 所以到一两百台时标 IP 仍然压不到字，再往上就没意义了（整图已被缩放）。
    _MAX_LABELLED_NODES = 150

    def __init__(self, results, gateway_ip, dark, parent=None, topology=None):
        super().__init__(parent)
        self.setWindowTitle(tr("网络拓扑视图"))
        self.setMinimumSize(900, 680)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.results = list(results)
        self.gateway_ip = gateway_ip
        self.dark = dark
        self.topology = topology  # Topology 对象，None = 回退星型
        self._topo_note = ""      # 图例尾部的一句补充（隐藏了多少台等）
        self._real_rendered = False   # 是否真的画出了真实拓扑（可能退化回星型）

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)

        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing, True)
        # 画布始终按 fitInView 自适应铺满，滚动条只会是残留噪声。
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QBrush(_theme_color("topo_bg", dark)))
        self.view.setScene(self.scene)
        layout.addWidget(self.view, 1)

        self.legend = QLabel()
        layout.addWidget(self.legend)

        self.setLayout(layout)

        if self.topology and self.topology.links:
            self._build_real_topology()
        if not self._real_rendered:
            self._build_star_topology()
            if self.topology is not None and self.topology.note:
                # 星型回退时把"为什么没有真实链路"一并说明：否则用户只看到一张
                # 假的星型图，不知道差在哪一步（通常是交换机没开 SNMP）。
                self._topo_note = "；".join(
                    p for p in (self._topo_note, self.topology.note) if p)
        # 图例放在构建**之后**：星型拓扑要往里补"已隐藏 N 台离线设备"。
        self._update_legend()

    # ── 视口自适应 ──

    def showEvent(self, event):
        super().showEvent(event)
        self._fit_view()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit_view()

    def _fit_view(self):
        """把整个场景缩放到刚好放进视口，且**只缩不放**。

        老实现从头到尾没有 `fitInView`：`view.transform().m11()` 恒为 1.0，而
        场景在千台规模下是 14000px 见方 —— 用户只看得到左上角一小块，几百条
        辐条线挤成摩尔纹（见 TRAPS「拓扑视图」）。这里补上自适应，同时挡掉
        "放大"：三五个节点时不该被糊成一屏。
        """
        rect = self.scene.itemsBoundingRect()
        if rect.isEmpty():
            return
        self.view.fitInView(rect.adjusted(-40, -40, 40, 40), Qt.KeepAspectRatio)
        if self.view.transform().m11() > 1.0:
            self.view.resetTransform()
            self.view.centerOn(rect.center())

    def _update_legend(self):
        # ⚠️ 色值**不写进 `tr()` 的键**：旧写法把"颜色"和"文案"焊死在同一个
        # 词条里（形如 `"<span style='color:…'>●</span> 网关"`），改一次配色
        # 就要同步改语言包，而且那个颜色根本不随主题变。现在先取色、再拼 HTML，
        # 文案本身照常可译。
        items = [
            self._legend_item("gateway", "●", tr("网关")),
            self._legend_item("online", "●", tr("在线")),
        ]
        if self._real_rendered:
            # 图例只列**真的出现过**的链路种类：画着 FDB 的线却在图例里写 LLDP，
            # 比没有图例更误导。
            protocols = {link.protocol for link in self.topology.links}
            for proto, token_name, text in (
                    ("LLDP", "topo_link", "LLDP"),
                    ("CDP", "cdp", "CDP"),
                    ("FDB", "fdb", tr("转发表")),
                    ("subnet", "topo_muted", tr("网段"))):
                if proto in protocols:
                    items.append(self._legend_item(token_name, "━", text))
            if any(not n.online and not n.is_infra for n in self.topology.nodes):
                items.append(self._legend_item("topo_offline", "●", tr("离线")))
            if self.topology.note:
                items.append(self.topology.note)
        elif self._topo_note:
            items.append(self._topo_note)
        self.legend.setText("   ".join(items))
        self.legend.setStyleSheet("font-size: 12px; padding: 4px;")

    def _legend_item(self, token_name: str, glyph: str, text: str) -> str:
        return ("<span style='color:%s;'>%s</span> %s"
                % (token(token_name, self.dark), glyph, text))

    def _text_color(self):
        return _theme_color("topo_fg", self.dark)

    @staticmethod
    def _ring_layout(n: int, first_radius: float = 150.0,
                     ring_gap: float = 92.0, spacing: float = 92.0):
        """把 n 个点铺在同心环上，返回 `[(x, y), ...]`。

        半径按 **√n** 量级增长（每个环的容量随周长增长），而不是老实现的
        `R = max(200, 50 + n*7)` 那种**线性**增长 —— 后者在 1000 台时把画布
        撑到 14000px 见方，任何视图都读不了。环间距与环内间距都是常数，
        所以每个点的横向余量始终约等于 `spacing`，标注 IP 不会互相压字。
        """
        out = []
        ring = 0
        while len(out) < n:
            r = first_radius + ring * ring_gap
            cap = max(6, int(2 * math.pi * r / spacing))
            take = min(cap, n - len(out))
            # 奇数环错开半个间隔，避免内外环的点连成一条半径
            offset = 0.5 if ring % 2 else 0.0
            for i in range(take):
                ang = 2 * math.pi * (i + offset) / cap - math.pi / 2
                out.append((r * math.cos(ang), r * math.sin(ang)))
            ring += 1
        return out

    def _host_tooltip(self, r) -> str:
        """节点悬停提示。逐点标主机名会压字，完整信息改放这里。"""
        parts = [r.ip]
        if r.hostname:
            parts.append(r.hostname)
        parts.append(tr("在线") if r.status == "online" else tr("离线"))
        if r.mac:
            parts.append(r.mac.upper())
        if r.vendor:
            parts.append(r.vendor)
        return "\n".join(parts)

    # ── 真实拓扑 (LLDP / CDP / 转发表) ──

    #: 骨干链路的端口标注上限：几百条链路时端口名会糊成一团，反而比不标更难读
    _MAX_LINK_LABELS = 80

    def _topo_tooltip(self, node) -> str:
        """真实拓扑节点的悬停提示（含设备类别/型号/接入端口）。"""
        # 局部 import：`topology_discovery` 会拉起 scanner 的一串依赖，
        # 而本文件在 import 期只需要 Qt；节点种类用常量比较，别写字符串字面量。
        from topology_discovery import (KIND_GATEWAY, KIND_ROUTER, KIND_SUBNET)

        parts = []
        if node.ip:
            parts.append(node.ip)
        if node.label and node.label != node.ip:
            parts.append(node.label)
        if node.device_class:
            parts.append(device_class_label(node.device_class))
        if node.model and node.model != node.label:
            parts.append(node.model)
        if node.port:
            parts.append(tr("端口") + ": " + node.port)
        if node.is_gateway or node.kind == KIND_GATEWAY:
            parts.append(tr("网关"))
        elif node.kind == KIND_SUBNET:
            parts.append(tr("网段"))
        elif node.is_switch:
            parts.append(tr("路由器") if node.kind == KIND_ROUTER else tr("交换机"))
        elif not node.online:
            parts.append(tr("离线"))
        if node.mac:
            parts.append(node.mac.upper())
        return "\n".join(p for p in parts if p)

    def _build_real_topology(self):
        """按 LLDP/CDP/转发表发现的真实链路绘制。

        坐标全部来自 `topology_discovery.layout_real_topology`（纯函数、可单测）：
        骨干层是网关在上的分层树，接入层是每台交换机正下方的紧凑网格。
        历史实现把布局写在对话框里，而且 `unassigned` 混用了节点对象与 id，
        任何一台"没挂在交换机上"的设备都会让它抛 TypeError 崩掉整个视图。
        """
        from topology_discovery import layout_real_topology

        topo = self.topology
        positions = layout_real_topology(topo, self.gateway_ip or "")
        if not positions:
            # 布局退化（不该发生）→ 老老实实回退星型，别给用户一个空画布
            return
        self._real_rendered = True

        host_nodes = [n for n in topo.nodes if not n.is_infra and n.id in positions]
        show_labels = len(host_nodes) <= self._MAX_LABELLED_NODES
        label_positions = set()

        for link in topo.links:
            if link.source_id not in positions or link.target_id not in positions:
                continue
            x1, y1 = positions[link.source_id]
            x2, y2 = positions[link.target_id]
            self.scene.addLine(x1, y1, x2, y2, self._link_pen(link.protocol))

            # 端口标注只画在**骨干链路**（LLDP/CDP）上：那几条线又长又疏，
            # 标注落在各自的中点上很清楚。转发表的端口已经进了节点悬停提示，
            # 几十条虚线挤在同一台交换机正下方，再标就是一团糊字。
            if (not link.source_port or link.protocol in ("FDB", "subnet")
                    or len(topo.links) > self._MAX_LINK_LABELS):
                continue
            # 同一对节点只标一次端口（双向发现的链路合并后不会重复，但同一条
            # 链路上的多个 MAC 可能产生相同中点）
            mid = (round((x1 + x2) / 2, 1), round((y1 + y2) / 2, 1))
            if mid in label_positions:
                continue
            label_positions.add(mid)
            lbl = QGraphicsTextItem(link.source_port)
            lbl.setDefaultTextColor(self._muted())
            lbl.setScale(0.6)
            lbl.setPos(mid[0] - 20, mid[1] - 12)
            self.scene.addItem(lbl)

        for node in topo.nodes:
            if node.id not in positions:
                continue
            x, y = positions[node.id]
            if node.is_infra:
                self._add_switch_node(x, y, node)
            else:
                self._add_device_node(x, y, node, show_label=show_labels)

        self.scene.setSceneRect(
            self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60))

    def _link_pen(self, protocol: str):
        """链路画笔。

        线型与浓度都带语义：LLDP/CDP 是交换机**主动通告**的邻居（实线、饱和色），
        转发表/网段是**反推**出来的（虚线、降透明度）—— 后者成百条汇向同一台
        交换机，全浓度会把设备名糊掉，也容易让人把推测当成事实。
        """
        if protocol == "CDP":
            return QPen(_theme_color("cdp", self.dark), 2)
        if protocol == "FDB":
            return QPen(_faded(_theme_color("fdb", self.dark), 165), 1, Qt.DashLine)
        if protocol == "subnet":
            return QPen(_faded(self._muted(), 165), 1, Qt.DashLine)
        return QPen(_theme_color("topo_link", self.dark), 2)

    def _add_switch_node(self, x, y, node):
        """绘制网络设备节点（方形）。

        颜色按种类区分：网关用主题里的"网关色"，普通交换机/路由器用链路蓝，
        网段中继（`subnet:` 节点）用中性灰 —— 它是我们合成出来的分组框，
        不该看起来和真实设备一样。
        """
        from topology_discovery import KIND_GATEWAY, KIND_ROUTER, KIND_SUBNET

        w, h = 54, 32
        if node.kind == KIND_SUBNET:
            color = self._muted()
            pen = QPen(QColor(0, 0, 0, 70), 1, Qt.DashLine)
        elif node.is_gateway or node.kind == KIND_GATEWAY:
            color = _theme_color("gateway", self.dark)
            pen = QPen(QColor(255, 255, 255, 80), 1.5)
        elif node.kind == KIND_ROUTER:
            color = _theme_color("cdp", self.dark)
            pen = QPen(QColor(255, 255, 255, 80), 1.5)
        else:
            color = _theme_color("topo_link", self.dark)
            pen = QPen(QColor(255, 255, 255, 80), 1.5)

        rect = QGraphicsRectItem(x - w / 2, y - h / 2, w, h)
        rect.setBrush(QBrush(color))
        rect.setPen(pen)
        rect.setToolTip(self._topo_tooltip(node))
        self.scene.addItem(rect)

        parts = [node.label or node.ip]
        model = _ellipsize(node.model, 30)
        if model:
            parts.append(model)
        txt = QGraphicsTextItem("\n".join(p for p in parts if p))
        txt.setDefaultTextColor(self._text_color())
        txt.setScale(0.75)
        # 居中于方块下方：写死 `x - 45` 时，短名字（sw1）和长名字（access-sw-1）
        # 的视觉重心完全不同，看图时会以为是两个不同的东西
        txt.setPos(x - txt.boundingRect().width() * 0.75 / 2, y + h / 2 + 4)
        txt.setToolTip(self._topo_tooltip(node))
        self.scene.addItem(txt)

    def _add_device_node(self, x, y, node, show_label: bool = True):
        """绘制终端设备节点（圆形）。"""
        # 从 results 取在线状态
        online = True
        for r in self.results:
            if r.ip == node.ip or r.ip == node.id:
                online = r.status == "online"
                break
        color = _theme_color("online" if online else "topo_offline", self.dark)
        dot = QGraphicsEllipseItem(x - 10, y - 10, 20, 20)
        dot.setBrush(QBrush(color))
        dot.setPen(QPen(QColor(0, 0, 0, 60), 1))
        dot.setToolTip(self._topo_tooltip(node))
        self.scene.addItem(dot)
        if not show_label:
            return
        txt = QGraphicsTextItem(_ellipsize(node.label or node.ip, 16))
        txt.setDefaultTextColor(self._text_color())
        txt.setScale(0.7)
        txt.setPos(x - txt.boundingRect().width() * 0.7 / 2, y + 12)
        txt.setToolTip(self._topo_tooltip(node))
        self.scene.addItem(txt)

    # ── 回退星型拓扑 ──

    def _build_star_topology(self):
        """网关居中 + **在线**设备同心环（离线默认不画）。

        离线设备常占九成以上（2026-10-09 实测 1023 台里 952 台离线），画出来
        只是把圆心糊成一团噪声。隐藏了多少台写进图例，不静默丢数据。
        """
        online = [r for r in self.results if r.status == "online"]
        hidden = len(self.results) - len(online)
        hosts = online[:self._MAX_STAR_NODES]
        over = len(online) - len(hosts)

        if hosts:
            # 几百条 1px 辐条缩到一屏就会退化成摩尔纹；设备多时干脆不画线。
            draw_edges = len(hosts) <= self._MAX_STAR_EDGES
            show_labels = len(hosts) <= self._MAX_LABELLED_NODES
            edge_pen = QPen(self._muted(), 1)
            for (x, y), r in zip(self._ring_layout(len(hosts)), hosts):
                if draw_edges:
                    self.scene.addLine(0, 0, x, y, edge_pen)
                self._add_host_node(x, y, r, show_labels)

        self._add_gateway_node(0, 0)

        notes = []
        if hidden:
            notes.append(tr("已隐藏 {n} 台离线设备").format(n=hidden))
        if over:
            notes.append(tr("另有 {n} 台在线设备未显示").format(n=over))
        self._topo_note = "；".join(notes)

        rect = self.scene.itemsBoundingRect()
        if not rect.isEmpty():
            self.scene.setSceneRect(rect.adjusted(-60, -60, 60, 60))

    def _add_host_node(self, x, y, r, show_label: bool = True):
        """画一个在线终端节点；标签只在设备不多时画，完整信息一律进悬停提示。"""
        node = QGraphicsEllipseItem(x - 14, y - 14, 28, 28)
        node.setBrush(QBrush(_theme_color("online", self.dark)))
        node.setPen(QPen(QColor(0, 0, 0, 60), 1))
        node.setToolTip(self._host_tooltip(r))
        self.scene.addItem(node)
        if not show_label:
            return
        # 只标 IP：主机名重复时（实测 8 台同名）标上去反而误导，改放悬停提示。
        txt = QGraphicsTextItem(r.ip)
        txt.setDefaultTextColor(self._text_color())
        txt.setScale(0.75)
        txt.setPos(x - 28, y + 16)
        txt.setToolTip(self._host_tooltip(r))
        self.scene.addItem(txt)

    def _add_gateway_node(self, x, y):
        gw = self.gateway_ip or tr("未知")
        host = ""
        for r in self.results:
            if r.ip == self.gateway_ip:
                host = r.hostname or ""
                break
        tip = "\n".join(p for p in (gw, host) if p)
        node = QGraphicsEllipseItem(x - 24, y - 24, 48, 48)
        node.setBrush(QBrush(_theme_color("gateway", self.dark)))
        node.setPen(QPen(QColor(0, 0, 0, 80), 2))
        node.setToolTip(tip)
        self.scene.addItem(node)
        txt = QGraphicsTextItem(tr("网关\n") + tip)
        txt.setDefaultTextColor(self._text_color())
        txt.setPos(x - 45, y + 34)
        self.scene.addItem(txt)

    def _muted(self):
        return _theme_color("topo_muted", self.dark)

    def _link_blue(self):
        return _theme_color("topo_link", self.dark)
