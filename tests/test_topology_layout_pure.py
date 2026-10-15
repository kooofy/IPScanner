# -*- coding: utf-8 -*-
"""拓扑布局 / 文本导出的**纯函数**验收（不依赖 PyQt，可无头运行）。

把 `AspectRatioAcceptanceTest` 与 v1.9 #9 文本导出验收放在一起：
两者都只调 `topology_discovery` 的纯函数（`layout_real_topology` /
`render_topology_text` 等），不碰 Qt，因此既能在沙箱 / CI 无头跑，
也能在桌面环境跑。

原 `test_topology_layout.py` 只保留需要 Qt 的渲染测试；验收守卫迁到这里后，
原来标着 `@unittest.expectedFailure` 的两条会「意外成功」而报错，于是装饰器
被摘掉、转正为真正的回归守卫。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from topology_discovery import (KIND_GATEWAY, KIND_SWITCH, TopoLink, TopoNode,
                                Topology, layout_real_topology,
                                render_topology_ascii, render_topology_markdown,
                                render_topology_text, render_topology_tree)

_GATEWAY = "10.0.0.1"


def _build_topology(n_switches, hosts_per_switch):
    """网关 → N 台交换机 → 每台 M 个终端（与建议书 §4.4 同形）。

    交换机都在网关下面一层，骨干层被排成**一行**，宽度随台数线性增长 ——
    这正是 v1.9 #9「过宽折行」要解决的形状。
    """
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
    """拓扑画布宽高比验收（建议书 §6.2，v1.9 #9「过宽折行」）。

    原来这条标了 `@unittest.expectedFailure`，#9 落地后会「意外成功」而报错，
    逼着把装饰器摘掉。现已转正为真正的回归守卫，放在 PyQt 无关的测试文件里，
    使其能在无头环境持续运行。
    """
    MAX_ASPECT = 3.0
    MAX_EDGE = 4000.0
    MIN_EDGE = 600.0

    def _canvas(self, n_switches, hosts_per_switch):
        positions = layout_real_topology(
            _build_topology(n_switches, hosts_per_switch), _GATEWAY)
        xs = [x for x, _ in positions.values()]
        ys = [y for _, y in positions.values()]
        return max(xs) - min(xs), max(ys) - min(ys)

    def _aspect(self, n_switches, hosts_per_switch):
        width, height = self._canvas(n_switches, hosts_per_switch)
        return width / height if height else float("inf")

    def test_scales_are_within_acceptance(self):
        """≤4 交换机（本来就达标）与 6/10/50 交换机（原超标）都必须 ≤ 3:1。

        合并了原 `test_target_scales_are_within_acceptance`：#9 落地后那两条
        不再「预期失败」，一并并进这里的回归守卫（见建议书 §10 第 8 件）。
        """
        for n_sw, hosts in ((1, 100), (1, 1000), (2, 20), (3, 30), (4, 100),
                             (6, 30), (10, 100), (50, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                self.assertLessEqual(
                    self._aspect(n_sw, hosts), self.MAX_ASPECT,
                    f"{n_sw} 交换机 / {hosts} 终端 的宽高比超标（v1.9 #9）")

    def test_fifty_devices_stay_within_three_to_one(self):
        """路线图 v2.2 §3.4-d 字面要求：**50 台设备以内，画布宽高比 ≤ 3:1**。

        与上面的 `test_scales_are_within_acceptance` 是**同一条不变量的字面
        可追溯版**：那个用例按「交换机台数 × 终端数」铺开（最大 50×100 =
        5050 个节点），没有一条正好落在「50 台设备以内」这个区间，验收时没法
        直接指着某一行说"这条就是建议书 §10 第 8 件"。

        ⚠️ 节点数 = 1 网关 + N 交换机 + N×M 终端（见 `_build_topology`）。
        """
        for n_sw, hosts in ((2, 9), (3, 9), (5, 8)):     # 19 / 28 / 46 台
            with self.subTest(switches=n_sw, hosts=hosts):
                topo = _build_topology(n_sw, hosts)
                self.assertLessEqual(len(topo.nodes), 50)
                positions = layout_real_topology(topo, _GATEWAY)
                xs = [x for x, _ in positions.values()]
                ys = [y for _, y in positions.values()]
                width, height = max(xs) - min(xs), max(ys) - min(ys)
                self.assertGreater(height, 0)
                self.assertLessEqual(
                    width / height, self.MAX_ASPECT,
                    f"{len(topo.nodes)} 台设备（{n_sw} 交换机 / {hosts} 终端）"
                    f"的画布宽高比 {width / height:.2f} 超过 "
                    f"{self.MAX_ASPECT}:1")

    def test_canvas_stays_within_pixel_budget(self):
        """1000 台以内：最长边 ≤ 4000px、最短边 ≥ 600px。"""
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


class TopologyTextExportTest(unittest.TestCase):
    """v1.9 #9 可读性包（二）：拓扑文本导出三格式，且**不丢节点**。

    验收（建议书 §1.3）：tree / markdown / ascii 三种格式都包含
    **每一台交换机与它的每个下游节点** —— 不许因为图形折行/分栏而丢节点。
    文本导出不依赖坐标，是整棵树遍历，这里只验证「覆盖完整」。
    """

    def _assert_covers(self, text, topo):
        ids = [n.ip or n.id for n in topo.nodes]
        labels = [n.label for n in topo.nodes if n.label]
        for i in ids:
            self.assertIn(i, text, "文本导出漏掉了节点 %r" % i)
        for lb in labels:
            self.assertIn(lb, text, "文本导出漏掉了节点名 %r" % lb)

    def test_tree_covers_all_nodes(self):
        for n_sw, hosts in ((6, 30), (10, 100), (50, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                topo = _build_topology(n_sw, hosts)
                self._assert_covers(render_topology_tree(topo, _GATEWAY), topo)

    def test_markdown_covers_all_nodes(self):
        for n_sw, hosts in ((6, 30), (10, 100), (50, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                topo = _build_topology(n_sw, hosts)
                self._assert_covers(render_topology_markdown(topo, _GATEWAY), topo)

    def test_ascii_covers_all_nodes(self):
        for n_sw, hosts in ((6, 30), (10, 100), (50, 100)):
            with self.subTest(switches=n_sw, hosts=hosts):
                topo = _build_topology(n_sw, hosts)
                self._assert_covers(render_topology_ascii(topo, _GATEWAY), topo)

    def test_includes_ports_and_protocols(self):
        """含端口与协议（建议书 §1.3 明确要求）。"""
        topo = _build_topology(2, 3)
        for fmt in ("tree", "markdown", "ascii"):
            with self.subTest(fmt=fmt):
                text = render_topology_text(topo, fmt, _GATEWAY)
                self.assertIn("GE0/1", text, "缺上联端口（%s）" % fmt)
                self.assertIn("LLDP", text, "缺交换机间协议（%s）" % fmt)
                self.assertIn("FDB", text, "缺终端接入协议（%s）" % fmt)

    def test_dispatcher_rejects_unknown_format(self):
        topo = _build_topology(2, 3)
        with self.assertRaises(ValueError):
            render_topology_text(topo, "pdf", _GATEWAY)

    def test_markdown_has_header_and_separator(self):
        topo = _build_topology(2, 3)
        text = render_topology_markdown(topo, _GATEWAY)
        self.assertIn("| 节点 |", text)
        self.assertIn("| --- |", text)

    def test_empty_topology_renders_empty(self):
        for fmt in ("tree", "markdown", "ascii"):
            with self.subTest(fmt=fmt):
                self.assertEqual(render_topology_text(Topology(), fmt), "")


if __name__ == "__main__":
    unittest.main()
