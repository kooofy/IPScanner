# -*- coding: utf-8 -*-
"""网络拓扑视图对话框：LLDP/CDP/转发表发现的真实链路 + 终端设备。

布局由 `topology_discovery.layout_real_topology`（纯函数、可单测）给出；
本文件只负责绘制 —— QGraphicsScene 自绘，QSS 覆盖不到，取色一律走 `_shared`。
"""
import math

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPainter, QBrush, QPen, QColor, QPainterPath, QPainterPathStroker
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
    QGraphicsRectItem, QGraphicsLineItem, QMenu, QInputDialog,
)

from app_logging import get_logger
from i18n import tr
from scanner.constants import device_class_label
from theme_tokens import token
import ui_msg

from ._shared import _ellipsize, _faded, _theme_color

_log = get_logger(__name__)

#: 图元上挂"这是哪个节点"的键（`QVariant` 用 Python 对象即可）。
#: 拖动结束/右键时要靠它倒推该改哪条校正，所以必须是**跨扫描稳定**的身份键
#: （`topology_overrides.node_scene_key`），不能用场景坐标或图元索引。
_NODE_ID_ROLE = Qt.UserRole + 1
#: 链路的身份对（`(a, b)` 两个稳定键）挂在线上，供"隐藏此链路"用。
_LINK_ID_ROLE = Qt.UserRole + 2


def _localize_input_dialog(dlg: QInputDialog):
    """Qt 内置按钮无中文翻译 → 构造后手工 `setText`。

    与 `ui_msg.localize_buttons` 同一手法（见该函数注释）；`QInputDialog`
    不走 `QMessageBox`，所以这里单独处理。
    """
    dlg.setOkButtonText(tr("确定"))
    dlg.setCancelButtonText(tr("取消"))
    return dlg


class _DragMixin:
    """给节点图元加"拖动 → 回报对话框"的行为。

    用**混入**而不是继承某个具体图元类：网络设备画成方形（`QGraphicsRectItem`）、
    终端画成圆形（`QGraphicsEllipseItem`），形状不同但拖动逻辑完全一样 ——
    混入让两者共享同一段代码。真实继承链在下面按形状各拼一次。
    """

    #: 子类在 `__init__` 里设置
    _dialog = None
    _node_key = ""

    def _drag_init(self, dialog, node_key):
        self._dialog = dialog
        self._node_key = node_key
        self.setData(_NODE_ID_ROLE, node_key)
        self.setFlag(QGraphicsRectItem.ItemIsMovable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)
        self._press_pos = None

    def mousePressEvent(self, event):
        self._press_pos = self.scenePos()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        # 只有真的动了才记钉住：单击（选中）不该把节点钉在原地，
        # 否则用户随手一点就把一个"自动排的"节点变成了"手工固定"。
        if self._press_pos is not None and self._dialog is not None:
            moved = (self.scenePos() - self._press_pos).manhattanLength()
            if moved > 2:
                self._dialog.on_node_dragged(self._node_key, self.scenePos())


class _DraggableNodeItem(_DragMixin, QGraphicsRectItem):
    """可拖动的**方形**节点（网络设备）。``(x, y, w, h)`` 为左上角坐标与尺寸。"""

    def __init__(self, x, y, w, h, dialog, node_key):
        super().__init__(x, y, w, h)
        self._drag_init(dialog, node_key)


class _DraggableDotItem(_DragMixin, QGraphicsEllipseItem):
    """可拖动的**圆形**节点（终端设备）。"""

    def __init__(self, x, y, w, h, dialog, node_key):
        super().__init__(x, y, w, h)
        self._drag_init(dialog, node_key)


class _SelectableLinkItem(QGraphicsLineItem):
    """可点选的链路。

    `QGraphicsLineItem.shape()` 默认只算 0 宽笔迹，1px 虚线几乎点不中。
    这里覆盖 `shape()` 把命中区域撑到笔宽 + 6px，右键"隐藏此链路"才点得到。
    """

    def shape(self):
        stroker = QPainterPathStroker()
        stroker.setWidth(max(self.pen().widthF(), 1.0) + 6.0)
        path = QPainterPath(self.line().p1())
        path.lineTo(self.line().p2())
        return stroker.createStroke(path)



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

    def __init__(self, results, gateway_ip, dark, parent=None, topology=None,
                 overrides_path=None, no_overrides=False):
        super().__init__(parent)
        self.setWindowTitle(tr("网络拓扑视图"))
        self.setMinimumSize(900, 680)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.results = list(results)
        self.gateway_ip = gateway_ip
        self.dark = dark
        self.topology = topology  # Topology 对象，None = 回退星型
        self.overrides_path = overrides_path  # 校正文件路径；None = 数据目录默认
        self.no_overrides = no_overrides      # True = 忽略校正层
        self._topo_note = ""      # 图例尾部的一句补充（隐藏了多少台等）
        self._real_rendered = False   # 是否真的画出了真实拓扑（可能退化回星型）

        # 手工校正（钉住 / 隐藏 / 备注）：与扫描结果解耦，可缺省。
        # 读失败 = 没有校正，绝不让对话框崩（`topology_overrides.load` 自身容错）。
        self._pinned = {}
        #: 落到场景里的**原始**拓扑（未经校正裁剪）—— 拖动/隐藏/恢复都以它为准，
        #: 而 `self.topology` 是应用校正后的投影。两者分开，才能"恢复默认"。
        self._base_topology = topology
        self._ov = None            # TopologyOverrides（可变，编辑就地改它）
        self._dirty = False        # 是否有未保存的校正改动
        self._saved_hint = ""      # 最近一次保存的提示（非模态反馈）
        if self.topology is not None and not self.no_overrides:
            try:
                import topology_overrides as tov
                self._ov = tov.load(self.overrides_path)
                if not self._ov.is_empty():
                    self.topology, self._pinned = tov.apply_overrides(
                        self.topology, self._ov)
                    self._topo_note = tr("已应用手工校正")
            except Exception as e:      # noqa: BLE001 - 校正层故障不该挡住看图
                _log.debug("拓扑手工校正加载失败: %s", e)

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
        # 右键菜单（隐藏/备注/恢复）只在真实拓扑下有意义
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._on_context_menu)
        layout.addWidget(self.view, 1)

        # ── 底部：图例 + 校正操作按钮 ──
        self.legend = QLabel()
        layout.addWidget(self.legend)

        self.tools = QHBoxLayout()
        self.tools.addStretch(1)
        self._btn_reload = QPushButton(tr("重新布局"))
        self._btn_reload.setToolTip(tr("丢弃当前手工改动，按自动布局重画"))
        self._btn_reload.clicked.connect(self._on_reload_layout)
        self._btn_save = QPushButton(tr("保存校正"))
        self._btn_save.setToolTip(tr("把钉住/隐藏/备注写入 topology_overrides.json"))
        self._btn_save.clicked.connect(self._on_save_overrides)
        self.tools.addWidget(self._btn_reload)
        self.tools.addWidget(self._btn_save)
        layout.addLayout(self.tools)

        self.setLayout(layout)

        self._render()

    # ── 渲染（可反复调用：拖拽/隐藏/恢复后重画）──

    def _render(self):
        """清空场景并按当前状态重画。

        拖拽钉住、隐藏节点/链路、恢复默认之后都会调它 —— 与其"就地挪图元"，
        不如整场重画：节点带着标签、旁边连着线，手工同步这些关联极易漏，
        重画一次既简单又保证不错位（几十到几百个图元的重建开销可忽略）。
        """
        self.scene.clear()
        self._real_rendered = False
        self._topo_note = tr("已应用手工校正") if self._has_overrides() else ""
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
        self._update_tools_visible()
        self._fit_view()

    def _has_overrides(self) -> bool:
        return self._ov is not None and not self._ov.is_empty()

    def _update_tools_visible(self):
        """校正按钮只在**真实拓扑**下显示：星型回退没有可钉的坐标。"""
        usable = self._ov is not None and (self._base_topology is not None
                                           and bool(self._base_topology.links))
        for btn in (getattr(self, "_btn_reload", None),
                    getattr(self, "_btn_save", None)):
            if btn is not None:
                btn.setVisible(usable)
        if usable and hasattr(self, "_btn_save"):
            self._btn_save.setEnabled(self._dirty)
            self._btn_save.setText(tr("保存校正") + (" *" if self._dirty else ""))

    # ── 手工校正：拖拽 / 右键 / 保存 ──

    def _require_overrides(self):
        """确保 `self._ov` 是个可写的校正对象；不可用时返回 None。"""
        if self._ov is not None:
            return self._ov
        if self.no_overrides or self._base_topology is None:
            return None
        try:
            import topology_overrides as tov
            self._ov = tov.TopologyOverrides()
            return self._ov
        except Exception as e:      # noqa: BLE001
            _log.debug("无法创建校正对象: %s", e)
            return None

    def _reproject(self, defer: bool = True, mark_dirty: bool = True):
        """把当前校正重新投影到拓扑上并重画（编辑动作的统一收尾）。

        ⚠️ 默认**延迟到下一轮事件循环**：这些调用多半发生在图元的事件处理
        之中（拖动松手、右键菜单动作），当场 `scene.clear()` 会在 Qt 仍持有
        该图元时把它删掉 —— 悬垂指针，表现为随机崩溃。`defer=False` 仅供
        非事件上下文的调用方（如"重新布局"按钮）使用。

        ``mark_dirty=False``：本次投影来自"丢弃未保存改动"（重新布局），
        不该把状态又标成"有改动"。
        """
        if defer:
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(0, lambda: self._reproject(defer=False,
                                                         mark_dirty=mark_dirty))
            return
        import topology_overrides as tov
        try:
            self.topology, self._pinned = tov.apply_overrides(
                self._base_topology, self._ov)
        except Exception as e:      # noqa: BLE001
            _log.warning("应用拓扑校正失败: %s", e)
            return
        if mark_dirty:
            self._dirty = True
            self._saved_hint = ""  # 又有新改动 → 上次"已保存"的提示不再成立
        self._render()

    def on_node_dragged(self, node_key, scene_pos):
        """节点被拖到新位置 → 记成钉住坐标并重画。"""
        ov = self._require_overrides()
        if ov is None or not node_key:
            return
        ov.upsert_node(node_key, pin=(scene_pos.x(), scene_pos.y()))
        self._reproject()

    def _node_by_key(self, node_key):
        if self._base_topology is None:
            return None
        for node in self._base_topology.nodes:
            import topology_overrides as tov
            if tov.node_scene_key(node) == node_key:
                return node
        return None

    def _on_context_menu(self, pos):
        """右键菜单：对点到的节点/链路做隐藏、备注、恢复。"""
        if not self._real_rendered or self._require_overrides() is None:
            return
        item = self.view.itemAt(pos)
        node_key = item.data(_NODE_ID_ROLE) if item is not None else None
        link_key = item.data(_LINK_ID_ROLE) if item is not None else None
        menu = QMenu(self)
        if node_key:
            menu.addAction(tr("钉住在此位置"),
                           lambda: self._pin_here(node_key))
            menu.addAction(tr("编辑备注…"), lambda: self._edit_note(node_key))
            menu.addAction(tr("隐藏此节点"), lambda: self._hide_node(node_key))
            menu.addAction(tr("恢复此节点"), lambda: self._restore_node(node_key))
        elif link_key:
            a, b = link_key
            menu.addAction(tr("隐藏此链路"),
                           lambda: self._hide_link(a, b))
            menu.addAction(tr("恢复此链路"),
                           lambda: self._restore_link(a, b))
        else:
            menu.addAction(tr("恢复全部手工校正"), self._restore_all)
        if menu.isEmpty():
            return
        menu.exec_(self.view.mapToGlobal(pos))

    def _pin_here(self, node_key):
        """把节点钉在它**当前自动排出的位置**（用户只是想固定它，不想挪）。"""
        node = self._node_by_key(node_key)
        if node is None:
            return
        from topology_discovery import layout_real_topology
        positions = layout_real_topology(self.topology, self.gateway_ip or "")
        xy = positions.get(node.id)
        if xy is None:
            return
        self._require_overrides().upsert_node(node_key, pin=xy)
        self._reproject()

    def _edit_note(self, node_key):
        node = self._node_by_key(node_key)
        current = ""
        if self._ov is not None:
            found = self._ov._find_node([node_key])
            current = found.note if found is not None else ""
        dlg = QInputDialog(self)
        dlg.setWindowTitle(tr("节点备注"))
        dlg.setLabelText(tr("为 {name} 添加备注：").format(
            name=(node.label or node.ip) if node is not None else node_key))
        dlg.setTextValue(current)
        _localize_input_dialog(dlg)
        if dlg.exec_() == QInputDialog.Accepted:
            self._require_overrides().upsert_node(
                node_key, note=dlg.textValue().strip())
            self._reproject()

    def _hide_node(self, node_key):
        self._require_overrides().upsert_node(node_key, hidden=True)
        self._reproject()

    def _restore_node(self, node_key):
        ov = self._require_overrides()
        ov.remove_node([node_key])
        self._prune_and_reproject(ov)

    def _hide_link(self, a, b):
        self._require_overrides().upsert_link(a, b, hidden=True)
        self._reproject()

    def _restore_link(self, a, b):
        ov = self._require_overrides()
        ov.remove_link(a, b)
        self._prune_and_reproject(ov)

    def _restore_all(self):
        if not ui_msg.msg_ask(self, tr("恢复全部手工校正"),
                              tr("将丢弃所有钉住、隐藏与备注，确定吗？")):
            return
        import topology_overrides as tov
        self._ov = tov.TopologyOverrides()
        self._reproject()

    def _prune_and_reproject(self, ov):
        """删除后清掉空壳条目：界面里"恢复"一个只剩空键的条目不该留在文件里。"""
        ov.prune()
        self._reproject()

    def _on_reload_layout(self):
        """丢弃当前**未保存**的改动，回到磁盘上的校正 + 自动布局。"""
        import topology_overrides as tov
        try:
            self._ov = tov.load(self.overrides_path)
        except Exception as e:      # noqa: BLE001
            _log.debug("重新载入校正失败: %s", e)
            self._ov = tov.TopologyOverrides()
        self._dirty = False
        self._saved_hint = ""
        self._reproject(mark_dirty=False)

    def _on_save_overrides(self):
        """写回 `topology_overrides.json`。

        成功**不弹模态框**：用户往往要连续"拖一下、存一下"，每存一次弹一次
        "已保存"是干扰；同时模态弹窗会让无头测试永久挂住（本项目的既有教训）。
        反馈放在按钮文字与图例里；只有**失败**才弹窗（那需要用户知道）。
        """
        import topology_overrides as tov
        ov = self._require_overrides()
        if ov is None:
            return
        ov.prune()
        path = self.overrides_path or tov.default_path()
        ok, err = tov.save(ov, path)
        if ok:
            self._dirty = False
            self._saved_hint = tr("已保存到 {path}").format(path=path)
            self._render()
        else:
            ui_msg.msg_warn(self, tr("保存校正"),
                            tr("写入失败：{err}").format(err=err))

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
        if self._saved_hint:
            items.append(self._saved_hint)
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
        positions = layout_real_topology(topo, self.gateway_ip or "",
                                         pinned=self._pinned)
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
            line = self._link_item(x1, y1, x2, y2, link.protocol,
                                   self._scene_key_of(link.source_id),
                                   self._scene_key_of(link.target_id))
            # 线太细不好点中 → 加宽选中区域，让"隐藏此链路"能右键到
            line.setFlag(QGraphicsRectItem.ItemIsSelectable, True)
            self.scene.addItem(line)

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

    def _scene_key_of(self, node_id: str) -> str:
        """拓扑节点 id → **场景稳定键**（与 `_DraggableNodeItem` 上挂的一致）。

        链路两端也要挂这种键（而不是 id），才能和节点的身份键对上 ——
        节点 id 可能是 IP，而节点的稳定键在有 MAC 时是 MAC。
        """
        for node in self.topology.nodes:
            if node.id == node_id:
                return self._scene_key(node)
        return node_id

    @staticmethod
    def _scene_key(node) -> str:
        import topology_overrides as tov
        return tov.node_scene_key(node)

    def _link_item(self, x1, y1, x2, y2, protocol, key_a, key_b):
        """一条可点选的链路（QGraphicsLineItem + 身份对）。

        Qt 的 `QGraphicsLineItem` 判定命中用的是 0 宽笔迹 —— 1px 的虚线几乎
        点不中。所以这里用一个自定义子类把命中区域按画笔宽度放宽。
        """
        pen = self._link_pen(protocol)
        item = _SelectableLinkItem(x1, y1, x2, y2)
        item.setPen(pen)
        item.setData(_LINK_ID_ROLE, (key_a, key_b))
        item.setZValue(0)
        return item

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

        rect = _DraggableNodeItem(x - w / 2, y - h / 2, w, h,
                                  self, self._scene_key(node))
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
        dot = _DraggableDotItem(x - 10, y - 10, 20, 20,
                                self, self._scene_key(node))
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
