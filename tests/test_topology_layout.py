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


if __name__ == "__main__":
    unittest.main()
