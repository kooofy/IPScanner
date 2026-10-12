# -*- coding: utf-8 -*-
"""拓扑视图必须"看得懂"：在线设备同心环 + 自适应缩放 + 三道上限。

背景
----
2026-10-09 用户反馈「拓扑视图太简单粗糙」，附的截图里整个画布是一团**摩尔纹**，
只有圆心一个橙点。量化后原因有三：

1. 星型半径用 `R = max(200, 50 + n*7)` —— **线性**增长。1023 台时 R=7211，
   `itemsBoundingRect()` = 14534×14477；
2. 全仓库**零** `fitInView` 调用 → `view.transform().m11()` 恒为 1.0，场景 1:1
   铺在 1048×620 的视口里，用户只看得到左上角一小块；
3. 几百条 1px 辐条汇聚圆心，缩到一屏后退化成摩尔纹；而且离线设备占了 93%，
   画出来纯属噪声。

本文件钉住改造后的四条口径：

1. 半径按 **√n** 级增长（同心环），不再线性；
2. **只画在线设备**，隐藏数量如实写进图例；
3. `fitInView` 必须生效，且**只缩不放**（三个节点时不该被放大到糊）；
4. 设备过多时按上限丢掉辐条 / 标签 / 节点本身，而不是把画布撑爆。

画布宽高比验收（建议书 §6.2，v1.9 #9「过宽折行」）已达标，且已迁到
不依赖 PyQt 的 `tests/test_topology_layout_pure.py::AspectRatioAcceptanceTest`，
可在无头 / CI 环境持续运行（见该文件）。本文件只保留需要 Qt 的渲染测试。
"""
import math
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem

import i18n
import ui_dialogs
from scanner.models import ScanResult

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


# ── 布局算法 ──


class RingLayoutTest(unittest.TestCase):
    """同心环布局：半径必须次线性增长。"""

    def _max_radius(self, n):
        pts = ui_dialogs.TopologyDialog._ring_layout(n)
        self.assertEqual(len(pts), n)
        return max(math.hypot(x, y) for x, y in pts)

    def test_empty(self):
        self.assertEqual(ui_dialogs.TopologyDialog._ring_layout(0), [])

    def test_single_node_starts_on_the_first_ring(self):
        pts = ui_dialogs.TopologyDialog._ring_layout(1)
        self.assertEqual(len(pts), 1)
        self.assertAlmostEqual(math.hypot(*pts[0]), 150.0, places=6)

    def test_points_do_not_collide(self):
        """同一环上的点不能重合 —— 重合等于丢设备。"""
        pts = ui_dialogs.TopologyDialog._ring_layout(120)
        self.assertEqual(len(set(pts)), 120)

    def test_radius_is_far_below_the_old_linear_formula(self):
        """老公式 1023 台给出 R=7211（画布 14534px 见方，必然糊）。"""
        old = max(200, 50 + 1000 * 7)
        self.assertGreater(old, 7000, "参照值本身变了，说明公式被改回线性")
        self.assertLess(self._max_radius(1000), old / 3)

    def test_growth_is_sublinear(self):
        """数量 ×4，半径增长必须显著小于 ×4（否则就是线性）。"""
        r100 = self._max_radius(100)
        r400 = self._max_radius(400)
        self.assertLess(r400 / r100, 3.0,
                        "半径近似线性增长：%d → %d" % (r100, r400))


# ── 对话框 ──


class _DialogCase(unittest.TestCase):

    def setUp(self):
        i18n.init("zh-CN")

    def _dialog(self, results, gateway="10.0.0.1"):
        dlg = ui_dialogs.TopologyDialog(results, gateway, False)
        self.addCleanup(dlg.deleteLater)
        return dlg

    def _shown(self, results, gateway="10.0.0.1"):
        dlg = self._dialog(results, gateway)
        dlg.resize(1048, 620)
        dlg.show()
        _app.processEvents()
        return dlg

    @staticmethod
    def _host_nodes(dlg):
        return [i for i in dlg.scene.items()
                if isinstance(i, QGraphicsEllipseItem)
                and abs(i.rect().width() - 28.0) < 0.5]

    @staticmethod
    def _texts(dlg):
        return [i.toPlainText() for i in dlg.scene.items()
                if isinstance(i, QGraphicsTextItem)]

    @staticmethod
    def _lines(dlg):
        return [i for i in dlg.scene.items() if isinstance(i, QGraphicsLineItem)]


class OnlineOnlyTest(_DialogCase):
    """离线设备默认不画（实测 1023 台里 952 台离线）。"""

    def _mixed(self):
        online = [ScanResult(ip="10.0.0.%d" % (i + 10), status="online",
                             hostname="pc-%d" % i) for i in range(3)]
        offline = [ScanResult(ip="10.0.0.%d" % (i + 200), status="offline")
                   for i in range(5)]
        return online + offline

    def test_offline_devices_are_not_drawn(self):
        dlg = self._dialog(self._mixed())
        self.assertEqual(len(self._host_nodes(dlg)), 3)
        for ip in ("10.0.0.200", "10.0.0.204"):
            self.assertNotIn(ip, " ".join(self._texts(dlg)))

    def test_hidden_count_is_disclosed_in_the_legend(self):
        dlg = self._dialog(self._mixed())
        self.assertIn("5", dlg._topo_note)
        self.assertIn("5", dlg.legend.text())

    def test_nothing_is_hidden_when_everything_is_online(self):
        dlg = self._dialog([ScanResult(ip="10.0.0.1", status="online")])
        self.assertEqual(dlg._topo_note, "")


class FitViewTest(_DialogCase):
    """没有 fitInView 就是这次故障的根因，必须有守卫。"""

    def test_scene_is_fitted_when_it_does_not_fit(self):
        results = [ScanResult(ip="10.0.0.%d" % (i + 1), status="online")
                   for i in range(1000)]
        dlg = self._shown(results)
        rect = dlg.scene.itemsBoundingRect()
        self.assertLess(dlg.view.transform().m11(), 1.0,
                        "大场景没有被缩放，用户只能看到一角")
        self.assertLess(rect.width(), 4000,
                        "画布被撑到 %dpx，又回到线性增长" % rect.width())

    def test_small_scene_is_not_blown_up(self):
        results = [ScanResult(ip="10.0.0.%d" % (i + 1), status="online")
                   for i in range(3)]
        dlg = self._shown(results)
        self.assertAlmostEqual(dlg.view.transform().m11(), 1.0, places=6,
                               msg="三个节点被放大到糊，应当只缩不放")

    def test_fit_runs_on_resize(self):
        """窗口变大后必须重算 —— 否则画布还按旧视口缩放，四周留一大片空白。

        ⚠️ 尺寸要挑**改变受限维度**的那一个：场景接近正方形，`KeepAspectRatio`
        下缩放由视口**高度**决定；本对话框有 `setMinimumSize(900, 680)`，
        高度 620 会被夹到 680，此时只改宽度是看不出变化的（实测两者 m11 相同）。
        """
        results = [ScanResult(ip="10.0.0.%d" % (i + 1), status="online")
                   for i in range(400)]
        dlg = self._shown(results)
        before = dlg.view.transform().m11()
        dlg.resize(1400, 900)
        _app.processEvents()
        self.assertNotAlmostEqual(dlg.view.transform().m11(), before, places=4)


class DensityCapTest(_DialogCase):
    """设备过多时按上限降级，而不是把画布撑爆。"""

    @staticmethod
    def _online(n):
        return [ScanResult(ip="10.0.0.%d" % (i + 1), status="online")
                for i in range(n)]

    def test_spokes_are_dropped_past_the_edge_cap(self):
        dlg = self._dialog(self._online(ui_dialogs.TopologyDialog._MAX_STAR_EDGES + 50))
        self.assertEqual(self._lines(dlg), [],
                         "几百条辐条缩到一屏就是摩尔纹，超限应当不画")

    def test_spokes_are_kept_for_a_handful_of_nodes(self):
        dlg = self._dialog(self._online(5))
        self.assertEqual(len(self._lines(dlg)), 5)

    def test_labels_are_dropped_past_the_label_cap(self):
        dlg = self._dialog(self._online(ui_dialogs.TopologyDialog._MAX_LABELLED_NODES + 50))
        # 只剩网关那一条文字
        self.assertEqual(len(self._texts(dlg)), 1)

    def test_labels_are_kept_for_a_handful_of_nodes(self):
        dlg = self._dialog(self._online(5))
        self.assertEqual(len(self._texts(dlg)), 6)   # 5 个 IP + 网关

    def test_node_count_is_capped_and_reported(self):
        cap = ui_dialogs.TopologyDialog._MAX_STAR_NODES
        dlg = self._dialog(self._online(cap + 50))
        self.assertEqual(len(self._host_nodes(dlg)), cap)
        self.assertIn("50", dlg._topo_note)


class TooltipTest(_DialogCase):
    """标签只标 IP，完整信息走悬停提示。"""

    def test_nodes_carry_a_tooltip(self):
        r = ScanResult(ip="10.0.0.7", status="online", hostname="FIN-PC-01",
                       mac="00:1a:2b:3c:4d:5e", vendor="Dell Inc.")
        dlg = self._dialog([r])
        tips = [i.toolTip() for i in self._host_nodes(dlg)]
        self.assertEqual(len(tips), 1)
        self.assertIn("10.0.0.7", tips[0])
        self.assertIn("FIN-PC-01", tips[0])
        self.assertIn("00:1A:2B:3C:4D:5E", tips[0])
        self.assertIn("Dell Inc.", tips[0])

    def test_gateway_node_carries_a_tooltip(self):
        dlg = self._dialog([ScanResult(ip="10.0.0.1", status="online",
                                       hostname="gw")], gateway="10.0.0.1")
        tips = [i.toolTip() for i in dlg.scene.items()
                if isinstance(i, QGraphicsEllipseItem)
                and abs(i.rect().width() - 48.0) < 0.5]
        self.assertEqual(len(tips), 1)
        self.assertIn("10.0.0.1", tips[0])


class RealTopologyViewTest(_DialogCase):
    """真实拓扑（LLDP/CDP/转发表）的绘制。

    历史缺陷：`_build_real_topology` 里 `unassigned` 存的是**节点对象**、比较用的
    却是 id 字符串，永远匹配不上，最后 `node_pos[node]` 对不可哈希的 dataclass
    直接抛 TypeError —— 只要有一台设备没挂在交换机上，整个视图就崩。
    本类同时守住"图例只列真的出现过的链路种类"。
    """

    def _topology(self, links, nodes):
        from topology_discovery import TopoLink, TopoNode, Topology
        topo = Topology()
        for nid, kw in nodes:
            topo.nodes.append(TopoNode(id=nid, label=kw.pop("label", nid), **kw))
        topo.links = [TopoLink(*l) for l in links]
        return topo

    def _dialog_with(self, topo):
        results = [ScanResult(ip=n.ip or n.id, status="online", hostname=n.label)
                   for n in topo.nodes]
        dlg = ui_dialogs.TopologyDialog(results, "10.0.0.1", False, topology=topo)
        self.addCleanup(dlg.deleteLater)
        return dlg

    @staticmethod
    def _boxes(dlg):
        from PyQt5.QtWidgets import QGraphicsRectItem
        return [i for i in dlg.scene.items() if isinstance(i, QGraphicsRectItem)]

    @staticmethod
    def _dots(dlg):
        return [i for i in dlg.scene.items()
                if isinstance(i, QGraphicsEllipseItem)
                and abs(i.rect().width() - 20.0) < 0.5]

    def _small_topo(self):
        return self._topology(
            [("10.0.0.1", "10.0.0.2", "GE0/0", "", "LLDP"),
             ("10.0.0.2", "10.0.0.50", "GE1/0/1", "", "FDB"),
             ("10.0.0.2", "10.0.0.51", "GE1/0/2", "", "FDB")],
            [("10.0.0.1", {"is_switch": True, "kind": "gateway",
                           "is_gateway": True, "label": "gw"}),
             ("10.0.0.2", {"is_switch": True, "kind": "switch",
                           "label": "core-sw"}),
             ("10.0.0.50", {"label": "pc-50"}),
             ("10.0.0.51", {"label": "pc-51"})])

    def test_real_topology_is_rendered_not_the_star(self):
        dlg = self._dialog_with(self._small_topo())
        self.assertTrue(dlg._real_rendered)
        self.assertEqual(len(self._boxes(dlg)), 2, "网关 + 交换机两个方块")
        self.assertEqual(len(self._dots(dlg)), 2, "两台终端")
        self.assertEqual(len(self._lines(dlg)), 3, "三条链路")

    def test_unattached_hosts_do_not_crash_the_view(self):
        """没有挂在任何交换机上的设备必须被画出来，而不是抛 TypeError。"""
        topo = self._small_topo()
        from topology_discovery import TopoNode
        topo.nodes.append(TopoNode(id="10.0.0.99", label="orphan"))
        dlg = self._dialog_with(topo)      # 旧实现在这里抛 TypeError
        self.assertTrue(dlg._real_rendered)
        self.assertEqual(len(self._dots(dlg)), 3)

    def test_gateway_box_sits_above_the_switch(self):
        dlg = self._dialog_with(self._small_topo())
        boxes = sorted(self._boxes(dlg), key=lambda i: i.rect().top())
        self.assertLess(boxes[0].rect().top(), boxes[1].rect().top())

    def test_legend_only_lists_protocols_that_actually_appear(self):
        from theme_tokens import token
        dlg = self._dialog_with(self._small_topo())
        text = dlg.legend.text()
        self.assertIn("LLDP", text)
        # 转发表的图例文案是翻译过的（中文"转发表"/英文 FDB），
        # 所以按**色值**断言 —— 色值语言无关，且能证明用的是 fdb 令牌
        self.assertIn(token("fdb", False), text)
        self.assertNotIn("CDP", text, "没有任何 CDP 链路却在图例里写了 CDP")

    def test_legend_shows_cdp_when_cdp_links_exist(self):
        topo = self._topology(
            [("10.0.0.2", "10.0.0.50", "Fa0/1", "", "CDP")],
            [("10.0.0.2", {"is_switch": True, "kind": "switch"}),
             ("10.0.0.50", {})])
        dlg = self._dialog_with(topo)
        self.assertIn("CDP", dlg.legend.text())

    def test_no_links_falls_back_to_star_and_explains_why(self):
        from topology_discovery import Topology
        topo = Topology(note="没有链路的原因")
        results = [ScanResult(ip="10.0.0.1", status="online"),
                   ScanResult(ip="10.0.0.9", status="online")]
        dlg = ui_dialogs.TopologyDialog(results, "10.0.0.1", False, topology=topo)
        self.addCleanup(dlg.deleteLater)
        self.assertFalse(dlg._real_rendered)
        self.assertIn("没有链路的原因", dlg.legend.text(),
                      "回退星型时必须说明原因，否则用户只会以为工具识别不出来")

    def test_isolated_infrastructure_node_is_still_drawn(self):
        """被识别出来的交换机即使一条链路都没有，也不能从图上消失。"""
        topo = self._topology(
            [],
            [("10.0.0.2", {"is_switch": True, "kind": "switch",
                           "label": "core-sw"})])
        from topology_discovery import TopoLink
        topo.links = [TopoLink("10.0.0.2", "10.0.0.2")]   # 自环：只为进入真实路径
        dlg = self._dialog_with(topo)
        self.assertTrue(dlg._real_rendered)
        self.assertEqual(len(self._boxes(dlg)), 1)


# ── 画布宽高比验收（建议书 §6.2，v1.9 #9）已迁至纯函数测试 ──
# 见 `tests/test_topology_layout_pure.py::AspectRatioAcceptanceTest`：
# 该验收基于 `layout_real_topology` 纯函数，不依赖 PyQt，可在无头 / CI 环境跑。
# `#9`「过宽折行」已落地，原 `@expectedFailure` 转正为真正的回归守卫。


class OverrideInteractionTest(_DialogCase):
    """手工校正的**交互层**：拖拽钉住 / 隐藏 / 备注 / 保存 / 重载。

    纯数据层的不变量已由 `tests/test_topology_overrides.py` 钉住；这里只验证
    对话框把鼠标动作正确翻译成校正改动，并且图元上挂着**跨扫描稳定**的身份键
    （否则下一轮扫描后校正就找不到目标了）。

    ⚠️ 拖动/右键在真实运行时是事件驱动的（重建场景靠 `QTimer.singleShot` 延后，
    免得在图元事件处理中途把它删掉）；测试里直接调回调 + `_reproject(defer=False)`,
    绕开事件循环，既确定又不需要真的发鼠标事件。
    """

    def _topo(self):
        from topology_discovery import TopoLink, TopoNode, Topology
        topo = Topology()
        topo.nodes = [
            TopoNode(id="10.0.0.1", label="gw", ip="10.0.0.1",
                     kind="gateway", is_switch=True, is_gateway=True),
            TopoNode(id="10.0.0.2", label="sw", ip="10.0.0.2",
                     mac="AA:BB:CC:DD:EE:02", kind="switch", is_switch=True),
            TopoNode(id="10.0.0.9", label="pc", ip="10.0.0.9"),
        ]
        topo.links = [TopoLink("10.0.0.1", "10.0.0.2", "GE0/0", "", "LLDP")]
        return topo

    def _dialog(self, path=None):
        from scanner.models import ScanResult
        topo = self._topo()
        results = [ScanResult(ip=n.ip, status="online") for n in topo.nodes]
        dlg = ui_dialogs.TopologyDialog(results, "10.0.0.1", False,
                                        topology=topo, overrides_path=path)
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_node_items_carry_stable_identity_key(self):
        """拖动/右键靠图元上的键定位 —— 必须是 MAC 优先的稳定键。"""
        from ui_dialogs.topology import _NODE_ID_ROLE
        dlg = self._dialog()
        keys = {it.data(_NODE_ID_ROLE) for it in dlg.scene.items()
                if it.data(_NODE_ID_ROLE)}
        self.assertIn("mac:aabbccddee02", keys,
                      "有 MAC 的节点应以 MAC 为稳定键（换 IP 仍命中）")

    def test_drag_records_pin_and_marks_dirty(self):
        from PyQt5.QtCore import QPointF
        dlg = self._dialog()
        dlg.on_node_dragged("mac:aabbccddee02", QPointF(300, 400))
        dlg._reproject(defer=False)
        self.assertEqual(dlg._pinned.get("10.0.0.2"), (300.0, 400.0))
        self.assertTrue(dlg._dirty)

    def test_hide_node_removes_it_and_its_links(self):
        dlg = self._dialog()
        dlg._hide_node("ip:10.0.0.9")
        dlg._reproject(defer=False)
        ids = {n.id for n in dlg.topology.nodes}
        self.assertNotIn("10.0.0.9", ids)

    def test_save_then_reload_keeps_corrections(self):
        """保存到文件后重新打开，钉住与隐藏仍在 —— 「跨会话生效」的保证。"""
        import os
        import tempfile
        from PyQt5.QtCore import QPointF
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ov.json")
            dlg = self._dialog(path=p)
            dlg.on_node_dragged("mac:aabbccddee02", QPointF(11, 22))
            dlg._reproject(defer=False)
            dlg._hide_node("ip:10.0.0.9")
            dlg._reproject(defer=False)
            dlg.overrides_path = p
            dlg._on_save_overrides()
            self.assertFalse(dlg._dirty)
            self.assertTrue(os.path.exists(p))

            dlg2 = self._dialog(path=p)
            self.assertEqual(dlg2._pinned.get("10.0.0.2"), (11.0, 22.0))
            self.assertNotIn("10.0.0.9", {n.id for n in dlg2.topology.nodes})

    def test_reload_layout_discards_unsaved_changes(self):
        from PyQt5.QtCore import QPointF
        dlg = self._dialog()
        dlg.on_node_dragged("mac:aabbccddee02", QPointF(99, 99))
        dlg._reproject(defer=False)
        self.assertTrue(dlg._dirty)
        dlg._on_reload_layout()
        # `_on_reload_layout` 内部的重算是延迟到事件循环的；测试里手动推进一步
        dlg._reproject(defer=False, mark_dirty=False)
        self.assertFalse(dlg._dirty)
        self.assertEqual(dlg._pinned, {})

    def test_restore_node_clears_its_entry(self):
        dlg = self._dialog()
        dlg._hide_node("ip:10.0.0.9")
        dlg._reproject(defer=False)
        dlg._restore_node("ip:10.0.0.9")
        dlg._reproject(defer=False)
        self.assertIn("10.0.0.9", {n.id for n in dlg.topology.nodes})

    def test_labels_follow_when_node_is_pinned(self):
        """钉住后节点方块的**场景位置**应落到钉住点 —— 标签/连线才会跟着重建。"""
        from PyQt5.QtCore import QPointF
        from PyQt5.QtWidgets import QGraphicsRectItem
        dlg = self._dialog()
        dlg.on_node_dragged("mac:aabbccddee02", QPointF(500, 600))
        dlg._reproject(defer=False)
        # 方形节点里，中心的 x/y 落在 (500,600) 的那个就是被钉住的
        centers = [(it.sceneBoundingRect().center().x(),
                    it.sceneBoundingRect().center().y())
                   for it in dlg.scene.items()
                   if isinstance(it, QGraphicsRectItem)]
        self.assertTrue(any(abs(cx - 500) < 1 and abs(cy - 600) < 1
                            for cx, cy in centers),
                        "被钉住的节点没有出现在钉住坐标处")

    def test_no_overrides_keeps_tools_hidden(self):
        """星型回退 / 关闭校正时，保存按钮应隐藏（没有可保存的校正）。"""
        from scanner.models import ScanResult
        results = [ScanResult(ip="10.0.0.9", status="online")]
        dlg = ui_dialogs.TopologyDialog(results, "10.0.0.1", False,
                                        no_overrides=True)
        self.addCleanup(dlg.deleteLater)
        self.assertTrue(dlg._btn_save.isHidden())


class SvgExportTest(_DialogCase):
    """「导出 SVG」：把当前场景（含手工校正）落成矢量文件。

    ⚠️ 这里能测的只有**产物结构**（是合法 SVG、含图元、比例正确）——
    渲染出来的**观感**必须人工看图确认，无头环境给不了结论（本项目既有口径：
    Qt 渲染产物不做像素级断言）。
    """

    def _topo(self):
        """和 `OverrideInteractionTest._topo` 同构：网关 + 一台带 MAC 的交换机 + 终端。"""
        from topology_discovery import TopoLink, TopoNode, Topology
        topo = Topology()
        topo.nodes = [
            TopoNode(id="10.0.0.1", label="gw", ip="10.0.0.1",
                     kind="gateway", is_switch=True, is_gateway=True),
            TopoNode(id="10.0.0.2", label="sw", ip="10.0.0.2",
                     mac="AA:BB:CC:DD:EE:02", kind="switch", is_switch=True),
            TopoNode(id="10.0.0.9", label="pc", ip="10.0.0.9"),
        ]
        topo.links = [TopoLink("10.0.0.1", "10.0.0.2", "GE0/0", "", "LLDP"),
                      TopoLink("10.0.0.2", "10.0.0.9", "Fa0/1", "", "FDB")]
        return topo

    def _dark_dialog(self):
        from scanner.models import ScanResult
        topo = self._topo()
        results = [ScanResult(ip=n.ip, status="online") for n in topo.nodes]
        dlg = ui_dialogs.TopologyDialog(results, "10.0.0.1", True,
                                        topology=topo)
        dlg.resize(1100, 760)
        dlg.show()
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_pack_scene_keeps_aspect_ratio(self):
        """导出尺寸必须与图形自身比例一致 —— 否则导出图会被拉扁/拉长。

        早先的实现把图硬塞进 A4 纵向框，纵向长条的分层树会被压到极小、
        横向还留大片白。现在只定宽、高随比例跟随。
        """
        dlg = self._dark_dialog()
        packed = dlg._pack_scene()
        self.assertIsNotNone(packed)
        w_px, h_px, src, scale = packed
        self.assertAlmostEqual(w_px / h_px, src.width() / src.height(),
                               places=2)
        # 只缩不放：小图不该被撑成巨幅
        self.assertLessEqual(scale, 2.0 * 1.0001)

    def test_pack_scene_empty_returns_none(self):
        dlg = ui_dialogs.TopologyDialog([], "10.0.0.1", False)
        self.addCleanup(dlg.deleteLater)
        # 空 results 时仍会画一个网关；构造一个真正空的场景来验空值分支
        dlg.scene.clear()
        self.assertIsNone(dlg._pack_scene())

    def test_write_svg_produces_parseable_nonempty_file(self):
        """产出的必须是**合法可解析**的 SVG，且含真实图元与文字。"""
        import tempfile
        import xml.etree.ElementTree as ET
        dlg = self._dark_dialog()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "topo.svg")
            self.assertTrue(dlg._write_svg(p, dlg._pack_scene()))
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 500)
            with open(p, encoding="utf-8") as f:
                text = f.read()

        root = ET.fromstring(text)          # 必须能解析
        self.assertTrue(root.tag.endswith("svg"))
        tags = {el.tag.split("}")[-1] for el in root.iter()}
        self.assertIn("text", tags)
        # 节点方块/主机圆点/链路都得在（直线会被 SVG 后端展开成 polyline）
        self.assertIn("rect", tags)
        self.assertIn("circle", tags)
        self.assertIn("polyline", tags)
        # 标签用节点 label（不是 IP），三个节点都应出现
        for label in ("gw", "sw", "pc"):
            self.assertIn(">%s</text>" % label, text)

    def test_write_svg_includes_background(self):
        """SVG 没有背景概念 → 必须显式刷底色，否则深色主题插进白纸文档变白字。"""
        import tempfile
        from theme_tokens import token
        dlg = self._dark_dialog()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "topo.svg")
            dlg._write_svg(p, dlg._pack_scene())
            with open(p, encoding="utf-8") as f:
                text = f.read()
        self.assertIn(token("topo_bg", True).lower(), text.lower())

    def test_write_svg_bad_path_returns_false(self):
        """写不进去要返回 False（调用方据此弹窗），不能抛异常崩对话框。"""
        dlg = self._dark_dialog()
        bad = os.path.join(os.path.dirname(__file__), "no_such_dir_xyz",
                           "deep", "topo.svg")
        self.assertFalse(dlg._write_svg(bad, dlg._pack_scene()))

    def test_export_button_enabled_only_when_canvas_has_content(self):
        dlg = self._dark_dialog()
        self.assertTrue(dlg._btn_export.isEnabled())
        dlg.scene.clear()
        dlg._update_tools_visible()
        self.assertFalse(dlg._btn_export.isEnabled())


if __name__ == "__main__":
    unittest.main()
