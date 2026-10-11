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

另有一条**尚未达标**的验收标准（建议书 §6.2，v1.9 #9 的前置）：
真实拓扑的画布宽高比在交换机多于一排时会失控（50 台 → 37:1）。见
`AspectRatioAcceptanceTest` —— 那里明确标了 `expectedFailure`。
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


# ── 画布宽高比验收（建议书 §6.2，v1.9 #9 的前置） ──


_GATEWAY = "10.0.0.1"


def _build_topology(n_switches, hosts_per_switch):
    """造一个规整拓扑：网关 → N 台交换机 → 每台 M 个终端。

    这是建议书 §4.4 量化「宽网络不可读」时用的同一种形状 —— 交换机都在
    网关下面一层，因此骨干层会被排成**一行**，宽度随台数线性增长。
    """
    from topology_discovery import (KIND_GATEWAY, KIND_SWITCH, TopoLink,
                                    TopoNode, Topology)
    topo = Topology()
    topo.nodes.append(TopoNode(id=_GATEWAY, label="gw", ip=_GATEWAY,
                               is_switch=True, kind=KIND_GATEWAY,
                               is_gateway=True))
    for s in range(n_switches):
        sid = "10.%d.0.1" % (s + 1)
        topo.nodes.append(TopoNode(id=sid, label="sw-%d" % s, ip=sid,
                                   is_switch=True, kind=KIND_SWITCH))
        topo.links.append(TopoLink(_GATEWAY, sid, "GE0/%d" % (s + 1),
                                   "GE0/1", "LLDP"))
        for h in range(hosts_per_switch):
            hid = "10.%d.0.%d" % (s + 1, h + 10)
            topo.nodes.append(TopoNode(id=hid, label="pc", ip=hid))
            topo.links.append(TopoLink(sid, hid, "GE1/0/%d" % (h + 1), "", "FDB"))
    return topo


class AspectRatioAcceptanceTest(unittest.TestCase):
    """拓扑画布宽高比的验收标准（建议书 §6.2）。

    `[实测]` 现状 —— 骨干层把同一层的交换机排成**一行**，于是画布宽度随
    交换机台数线性增长，而高度几乎不变（约 990px）：

        1 交换机 /   100 终端  →     666 ×  990   比 0.7   ✓
        4 交换机 /   400 终端  →   2 886 ×  990   比 2.9   ✓
       10 交换机 / 1 000 终端  →   7 326 ×  990   比 7.4   ✗
       50 交换机 / 5 000 终端  →  36 926 ×  990   比 37.3  ✗

    建议书 §6.2 给的验收标准是「50 台设备以内，画布宽高比 ≤ 3:1；1000 台以内
    最长边 ≤ 4000px 且最短边 ≥ 600px」。修法是 v1.9 #9 的「过宽折行」。

    **本类刻意现在就写、现在就会失败** —— 建议书 §10 第 8 件原话是
    「现在写会失败，这正是它该成为待办的理由」：先有验收标准，再有实现。
    为了让 CI 保持绿色，未达标的用例标了 `@unittest.expectedFailure`；
    一旦 #9 落地，它会变成「意外成功」而报错，逼着把装饰器摘掉并把它并进
    上面的回归守卫 —— 不会悄悄变成一条永远不执行的摆设。
    """

    #: 建议书 §6.2 的验收阈值
    MAX_ASPECT = 3.0
    MAX_EDGE = 4000.0
    MIN_EDGE = 600.0

    def _canvas(self, n_switches, hosts_per_switch):
        """画布尺寸 = 所有节点坐标的外接矩形。

        口径与建议书附录 A 一致（那边量出的 666×990、2 886×990 与本函数
        完全吻合），所以这里可以直接用纯函数、不必起 Qt。
        """
        from topology_discovery import layout_real_topology
        positions = layout_real_topology(
            _build_topology(n_switches, hosts_per_switch), _GATEWAY)
        xs = [x for x, _ in positions.values()]
        ys = [y for _, y in positions.values()]
        return max(xs) - min(xs), max(ys) - min(ys)

    def _aspect(self, n_switches, hosts_per_switch):
        width, height = self._canvas(n_switches, hosts_per_switch)
        return width / height if height else float("inf")

    def test_scales_that_already_fit_stay_within_target(self):
        """今天已经达标的几档必须继续达标 —— 防止 #9 修过头或修坏。

        这几档的共同点是**交换机 ≤ 4 台**：骨干层还是一行，但那一行不够宽，
        画布仍是竖长或接近方形。（元组是「交换机台数, 每台终端数」；
        建议书里的「4 / 400」指 4 台交换机 / **合计** 400 台终端。）
        """
        for n_sw, hosts in ((1, 100), (1, 1000), (2, 20), (3, 30), (4, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                aspect = self._aspect(n_sw, hosts)
                self.assertLessEqual(
                    aspect, self.MAX_ASPECT,
                    f"{n_sw} 交换机 / {hosts} 终端 的宽高比 {aspect:.2f} 超过 "
                    f"{self.MAX_ASPECT}（这一档本来是达标的，被改坏了）")

    @unittest.expectedFailure
    def test_target_scales_are_within_acceptance(self):
        """v1.9 #9 的验收标准 —— 现在**必然失败**（见类 docstring 的实测表）。

        #9 落地后这条会报「意外成功」，请摘掉 `@expectedFailure`，并把它并进
        `test_scales_that_already_fit_stay_within_target`。
        """
        for n_sw, hosts in ((6, 30), (10, 100), (50, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                aspect = self._aspect(n_sw, hosts)
                self.assertLessEqual(
                    aspect, self.MAX_ASPECT,
                    f"{n_sw} 交换机 / {hosts} 终端 的宽高比 {aspect:.2f} "
                    f"超过 {self.MAX_ASPECT}（v1.9 #9「过宽折行」）")

    @unittest.expectedFailure
    def test_canvas_stays_within_pixel_budget(self):
        """建议书 §6.2 的第二条：1000 台设备以内，最长边 ≤ 4000px、最短边 ≥ 600px。

        高度那一边是"别被压成一条线"，宽度那一边是"别把画布撑爆"。
        """
        for n_sw, hosts in ((1, 1000), (4, 100), (10, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                width, height = self._canvas(n_sw, hosts)
                self.assertLessEqual(
                    max(width, height), self.MAX_EDGE,
                    f"{n_sw} 交换机 / {hosts} 终端 的画布最长边 "
                    f"{max(width, height):.0f}px 超过 {self.MAX_EDGE:.0f}px")
                self.assertGreaterEqual(
                    min(width, height), self.MIN_EDGE,
                    f"{n_sw} 交换机 / {hosts} 终端 的画布最短边 "
                    f"{min(width, height):.0f}px 低于 {self.MIN_EDGE:.0f}px")


if __name__ == "__main__":
    unittest.main()
