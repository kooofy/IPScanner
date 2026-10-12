# -*- coding: utf-8 -*-
"""拓扑手工校正（钉住 / 隐藏 / 备注）的**纯函数**验收。

覆盖 `topology_overrides`（数据层 + `apply_overrides` 投影）与
`topology_discovery.layout_real_topology` 的 `pinned` 覆盖行为。
全程不碰 PyQt / 不联网，因此沙箱与 CI 都能无头跑。

验收口径对应建议书 §4.4「手工校正 + 节点固定」的最小可用版：
允许「把某节点钉在某坐标」「隐藏某条链路/某节点」「给节点加备注」，
做成 `topology_overrides.json`，**与扫描结果解耦**。
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import topology_overrides as tov
from topology_discovery import (KIND_GATEWAY, KIND_SWITCH, TopoLink, TopoNode,
                                Topology, layout_real_topology)

# MAC 归一必须与 topology_discovery 同口径（否则校正匹配不上）；
# 这里用同一批样本对拍两处实现，防止日后一处改了另一处没改。
from topology_discovery import _normalize_mac as _disp_normalize_mac

_GW = "192.168.1.1"
_SW = "192.168.1.10"
_PC = "192.168.1.50"
_SW_MAC = "AA:BB:CC:00:00:01"


def _sample_topology() -> Topology:
    """网关 → 交换机 → 一台终端，外加一条孤立终端。"""
    return Topology(
        nodes=[
            TopoNode(id=_GW, label="gw", ip=_GW, kind=KIND_GATEWAY,
                     is_switch=True, is_gateway=True),
            TopoNode(id=_SW, label="sw1", ip=_SW, mac=_SW_MAC,
                     kind=KIND_SWITCH, is_switch=True),
            TopoNode(id=_PC, label="pc1", ip=_PC, mac="aa-bb-cc-00-00-50"),
            TopoNode(id="192.168.1.99", label="lone", ip="192.168.1.99"),
        ],
        links=[
            TopoLink(source_id=_GW, target_id=_SW, protocol="LLDP"),
            TopoLink(source_id=_SW, target_id=_PC, protocol="FDB"),
        ],
        note="示例", infra_count=2,
    )


class NormalizeMacTest(unittest.TestCase):
    """MAC 归一：本模块与 topology_discovery 必须逐字段同口径。"""

    def test_matches_topology_discovery(self):
        for sample in ("AA:BB:CC:DD:EE:FF", "aabb.ccdd.eeff", "aa-bb-cc-dd-ee-ff",
                       "aabbccddeeff", "host-1", "", "zz:zz"):
            self.assertEqual(tov.normalize_mac(sample),
                             _disp_normalize_mac(sample),
                             msg="样本 %r 两处归一结果不一致" % sample)

    def test_lowercases_and_strips_separators(self):
        self.assertEqual(tov.normalize_mac("AA:BB:CC:DD:EE:FF"),
                         "aabbccddeeff")
        self.assertEqual(tov.normalize_mac("aabb.ccdd.eeff"),
                         "aabbccddeeff")

    def test_rejects_non_mac(self):
        self.assertEqual(tov.normalize_mac("sw-1"), "")
        self.assertEqual(tov.normalize_mac(""), "")
        self.assertEqual(tov.normalize_mac(None), "")


class RoundTripTest(unittest.TestCase):
    """JSON 往返：save → load 后语义完全一致。"""

    def test_roundtrip_preserves_everything(self):
        ovs = tov.TopologyOverrides(
            nodes=[
                tov.NodeOverride(mac="aabbcc000001", pin=(11.0, 22.0),
                                 note="核心", key="core"),
                tov.NodeOverride(ip=_PC, hidden=True),
            ],
            links=[tov.LinkOverride(source=_GW, target=_SW, hidden=True,
                                    note="实际直连")],
        )
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ov.json")
            ok, err = tov.save(ovs, p)
            self.assertTrue(ok, err)
            back = tov.load(p)
        self.assertEqual(len(back.nodes), 2)
        self.assertEqual(len(back.links), 1)
        self.assertEqual(back.nodes[0].pin, (11.0, 22.0))
        self.assertEqual(back.nodes[0].note, "核心")
        self.assertTrue(back.nodes[1].hidden)
        self.assertTrue(back.links[0].hidden)
        self.assertEqual(back.links[0].note, "实际直连")

    def test_saved_json_is_human_editable(self):
        """写出的文件必须是整洁的 UTF-8 JSON（用户要手改）。"""
        ovs = tov.TopologyOverrides(nodes=[tov.NodeOverride(ip=_PC, note="备注")])
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ov.json")
            tov.save(ovs, p)
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data["version"], tov.SCHEMA_VERSION)
        self.assertEqual(data["nodes"][0]["note"], "备注")


class ToleranceTest(unittest.TestCase):
    """容错：空文件 / 损坏文件 / 局部坏数据都不该让校正整体失效或抛异常。"""

    def test_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ovs = tov.load(os.path.join(d, "nope.json"))
        self.assertTrue(ovs.is_empty())

    def test_corrupt_json_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{ this is not json ]")
            ovs = tov.load(p)
        self.assertTrue(ovs.is_empty())

    def test_empty_object_is_empty(self):
        self.assertTrue(tov.parse({}).is_empty())
        self.assertTrue(tov.parse(None).is_empty())
        self.assertTrue(tov.parse([]).is_empty())

    def test_partial_bad_entries_are_skipped(self):
        """坏条目被丢弃，好条目照常生效（用户手改时写错一条不该全废）。"""
        ovs = tov.parse({
            "nodes": [
                {"ip": _PC, "hidden": True},     # 好
                {"nokey": 1},                    # 无任何标识 → 丢
                "not-a-dict",                    # 类型错 → 丢
                {"ip": _SW, "pin": [1, 2, 3]},   # pin 长度不对 → 丢 pin 留节点
            ],
            "links": [
                {"source": _GW, "target": _SW, "hidden": True},  # 好
                {"source": _GW},                                  # 缺端 → 丢
            ],
        })
        self.assertEqual(len(ovs.nodes), 2)
        self.assertEqual(len(ovs.links), 1)
        self.assertIsNone(ovs.nodes[1].pin)

    def test_write_failure_is_reported_not_raised(self):
        """写到不可能的位置 → 返回 (False, 错误)，不抛。"""
        ok, err = tov.save(tov.TopologyOverrides(),
                           os.path.join("\0invalid", "x.json"))
        self.assertFalse(ok)
        self.assertTrue(err)


class ApplyOverridesTest(unittest.TestCase):
    """`apply_overrides` 投影：隐藏节点/链路、备注、钉住，且不改入参。"""

    def test_empty_overrides_is_identity(self):
        topo = _sample_topology()
        new, pinned = tov.apply_overrides(topo, tov.TopologyOverrides())
        self.assertIs(new, topo)
        self.assertEqual(pinned, {})

    def test_hide_node_removes_its_links(self):
        topo = _sample_topology()
        ovs = tov.parse({"nodes": [{"ip": _PC, "hidden": True}]})
        new, _ = tov.apply_overrides(topo, ovs)
        ids = {n.id for n in new.nodes}
        self.assertNotIn(_PC, ids)
        # 以被隐藏节点为端点的链路必须一起消失（否则留悬空线）
        self.assertEqual(len(new.links), 1)
        self.assertEqual(new.links[0].target_id, _SW)

    def test_hide_link_by_mac_and_ip_mixed(self):
        """链路两端可以一端写 MAC、一端写 IP（用户不会记得哪个是 source）。"""
        topo = _sample_topology()
        ovs = tov.parse({"links": [
            {"source": _SW_MAC, "target": _GW, "hidden": True}]})
        new, _ = tov.apply_overrides(topo, ovs)
        self.assertEqual(len(new.links), 1)
        self.assertEqual(new.links[0].target_id, _PC)

    def test_hide_link_is_direction_agnostic(self):
        topo = _sample_topology()
        # 故意把 source/target 写反
        ovs = tov.parse({"links": [
            {"source": _SW, "target": _GW, "hidden": True}]})
        new, _ = tov.apply_overrides(topo, ovs)
        self.assertEqual(len(new.links), 1)

    def test_pin_captured_by_mac(self):
        topo = _sample_topology()
        ovs = tov.parse({"nodes": [
            {"mac": "aa:bb:cc:00:00:01", "pin": [100, 200]}]})
        _new, pinned = tov.apply_overrides(topo, ovs)
        self.assertEqual(pinned, {_SW: (100.0, 200.0)})

    def test_note_attached_without_touching_dataclass(self):
        topo = _sample_topology()
        ovs = tov.parse({"nodes": [{"ip": _SW, "note": "机房 A"}]})
        new, _ = tov.apply_overrides(topo, ovs)
        node = next(n for n in new.nodes if n.id == _SW)
        self.assertEqual(node.manual_note, "机房 A")

    def test_pinned_hidden_node_is_dropped(self):
        """被隐藏的节点不该再出现在 pinned 里（否则布局层会为幽灵节点留位）。"""
        topo = _sample_topology()
        ovs = tov.parse({"nodes": [
            {"ip": _PC, "hidden": True, "pin": [1, 2]}]})
        _new, pinned = tov.apply_overrides(topo, ovs)
        self.assertEqual(pinned, {})

    def test_does_not_mutate_input(self):
        topo = _sample_topology()
        n_before, l_before = len(topo.nodes), len(topo.links)
        ovs = tov.parse({
            "nodes": [{"ip": _PC, "hidden": True},
                      {"ip": _SW, "note": "x", "pin": [1, 2]}],
            "links": [{"source": _GW, "target": _SW, "hidden": True}],
        })
        tov.apply_overrides(topo, ovs)
        self.assertEqual(len(topo.nodes), n_before)
        self.assertEqual(len(topo.links), l_before)
        # 原节点对象没有被动过
        sw = next(n for n in topo.nodes if n.id == _SW)
        self.assertFalse(hasattr(sw, "manual_note"))

    def test_note_survives_copy_of_other_node(self):
        """给 A 加备注不能让 B 被误标（浅拷贝按需进行）。"""
        topo = _sample_topology()
        ovs = tov.parse({"nodes": [{"ip": _SW, "note": "x"}]})
        new, _ = tov.apply_overrides(topo, ovs)
        gw = next(n for n in new.nodes if n.id == _GW)
        self.assertFalse(hasattr(gw, "manual_note"))

    def test_unmatched_override_is_ignored(self):
        """校正里的节点这轮没扫到 → 静默忽略，不影响其余。"""
        topo = _sample_topology()
        ovs = tov.parse({
            "nodes": [{"mac": "de:ad:be:ef:00:00", "hidden": True},
                      {"ip": _PC, "hidden": True}]})
        new, _ = tov.apply_overrides(topo, ovs)
        ids = {n.id for n in new.nodes}
        self.assertNotIn(_PC, ids)
        self.assertIn(_GW, ids)

    def test_decoupled_from_scan_results(self):
        """同一份校正，套到"换了 IP 但 MAC 不变"的新扫描结果上，依然命中。"""
        ovs = tov.parse({"nodes": [{"mac": _SW_MAC, "note": "仍生效"}]})
        topo = _sample_topology()
        # 交换机 IP 变了（DHCP 重新分配），MAC 不变
        for node in topo.nodes:
            if node.id == _SW:
                node.ip = "192.168.1.200"
        new, _ = tov.apply_overrides(topo, ovs)
        node = next(n for n in new.nodes if n.id == _SW)
        self.assertEqual(node.manual_note, "仍生效")


class LayoutPinnedTest(unittest.TestCase):
    """`layout_real_topology(pinned=...)`：钉住坐标压过自动布局。"""

    def _topo(self):
        return Topology(
            nodes=[
                TopoNode(id=_GW, label="gw", ip=_GW, kind=KIND_GATEWAY,
                         is_switch=True, is_gateway=True),
                TopoNode(id=_SW, label="sw1", ip=_SW, mac=_SW_MAC,
                         kind=KIND_SWITCH, is_switch=True),
                TopoNode(id=_PC, label="pc1", ip=_PC),
            ],
            links=[TopoLink(source_id=_GW, target_id=_SW, protocol="LLDP")],
        )

    def test_pin_overrides_auto_position(self):
        topo = self._topo()
        auto = layout_real_topology(topo, _GW)["192.168.1.10"]
        placed = layout_real_topology(topo, _GW,
                                      pinned={_SW: (777.0, 555.0)})
        self.assertEqual(placed[_SW], (777.0, 555.0))
        self.assertNotEqual(auto, (777.0, 555.0))

    def test_pin_does_not_disturb_other_nodes(self):
        topo = self._topo()
        base = layout_real_topology(topo, _GW)
        placed = layout_real_topology(topo, _GW,
                                      pinned={_SW: (777.0, 555.0)})
        self.assertEqual(base[_PC], placed[_PC])

    def test_pin_unknown_and_bad_coords_tolerated(self):
        topo = self._topo()
        # 不存在节点 + 非数值坐标 → 都不能让布局崩
        placed = layout_real_topology(
            topo, _GW,
            pinned={"ghost": (1.0, 2.0), _PC: "not-a-coord"})
        self.assertIn(_PC, placed)
        self.assertNotIn("ghost", placed)

    def test_pin_keeps_orphan_node_visible(self):
        """孤立节点没有链路、会被单独排到底部；钉住后应保留在结果里。"""
        topo = self._topo()
        lone = TopoNode(id="192.168.1.99", label="lone", ip="192.168.1.99")
        topo.nodes.append(lone)
        placed = layout_real_topology(topo, _GW,
                                      pinned={"192.168.1.99": (5.0, 6.0)})
        self.assertEqual(placed["192.168.1.99"], (5.0, 6.0))

    def test_no_pinned_param_is_backward_compatible(self):
        """不传 pinned 时行为与旧调用完全一致（既有调用方零改动）。"""
        topo = self._topo()
        self.assertEqual(layout_real_topology(topo, _GW),
                         layout_real_topology(topo, _GW, pinned=None))


class EndToEndProjectionTest(unittest.TestCase):
    """从 JSON 文件到布局坐标的整链：隐藏 + 钉住一起生效。"""

    def test_load_apply_then_layout(self):
        topo = _sample_topology()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "topology_overrides.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({
                    "version": 1,
                    "nodes": [
                        {"mac": _SW_MAC, "pin": [400, 50], "note": "核心"},
                        {"ip": _PC, "hidden": True},
                    ],
                    "links": [],
                }, f, ensure_ascii=False)
            ovs = tov.load(p)
        projected, pinned = tov.apply_overrides(topo, ovs)
        positions = layout_real_topology(projected, _GW, pinned=pinned)

        self.assertNotIn(_PC, {n.id for n in projected.nodes})
        self.assertEqual(positions[_SW], (400.0, 50.0))


class EditableApiTest(unittest.TestCase):
    """GUI 编辑用到的可变 API：upsert / remove / prune / 工厂。

    这些是拖拽、右键"隐藏/备注/恢复"的底层 —— 交互层只是把鼠标动作翻译成
    对这里的调用，所以把不变量钉在这一层，GUI 才能做薄。
    """

    def _node(self, **kw):
        base = dict(id="10.0.0.2", label="sw", ip="10.0.0.2",
                    mac="AA:BB:CC:DD:EE:02", kind=KIND_SWITCH, is_switch=True)
        base.update(kw)
        return TopoNode(**base)

    def test_factory_fills_identity_keys_in_priority_order(self):
        ov = tov.make_node_override(self._node())
        keys = tov._override_keys(ov)
        self.assertEqual(keys[0], "mac:aabbccddee02")
        self.assertIn("ip:10.0.0.2", keys)
        self.assertIn("name:sw", keys)

    def test_factory_skips_name_when_label_equals_ip(self):
        """标签与 IP 相同时 `name` 字段留空（不重复登记）。

        注意 `key` 字段仍是节点 id（兜底标识），它有自己的一组键 —— 这里只
        断言 `name` 字段本身为空，而不是"键列表里没有 name: 前缀"。
        """
        ov = tov.make_node_override(self._node(label="10.0.0.2"))
        self.assertEqual(ov.name, "")

    def test_upsert_pin_then_note_does_not_duplicate(self):
        ovs = tov.TopologyOverrides()
        ovs.upsert_node("mac:aabbccddee02", pin=(10, 20))
        ovs.upsert_node(["mac:aabbccddee02", "ip:10.0.0.2"], note="机房 A")
        self.assertEqual(len(ovs.nodes), 1)
        self.assertEqual(ovs.nodes[0].pin, (10.0, 20.0))
        self.assertEqual(ovs.nodes[0].note, "机房 A")

    def test_upsert_node_none_means_leave_unchanged(self):
        """`hidden=None` 是"别动"，不是"设为 False" —— 否则编辑备注会清掉隐藏。"""
        ovs = tov.TopologyOverrides()
        ovs.upsert_node("ip:10.0.0.9", hidden=True)
        ovs.upsert_node("ip:10.0.0.9", note="x")
        self.assertEqual(len(ovs.nodes), 1)
        self.assertTrue(ovs.nodes[0].hidden)
        self.assertEqual(ovs.nodes[0].note, "x")

    def test_upsert_node_accepts_node_object(self):
        ovs = tov.TopologyOverrides()
        ovs.upsert_node(self._node(), pin=(1, 2))
        self.assertEqual(tov._override_keys(ovs.nodes[0])[0], "mac:aabbccddee02")

    def test_link_upsert_is_direction_and_form_agnostic(self):
        ovs = tov.TopologyOverrides()
        ovs.upsert_link("AA:BB:CC:DD:EE:02", "10.0.0.1", hidden=True)
        ovs.upsert_link("10.0.0.1", "aabbccddee02", note="直连")
        self.assertEqual(len(ovs.links), 1)
        self.assertTrue(ovs.links[0].hidden)
        self.assertEqual(ovs.links[0].note, "直连")

    def test_remove_node_and_link(self):
        ovs = tov.TopologyOverrides()
        ovs.upsert_node("ip:10.0.0.9", hidden=True)
        ovs.upsert_link("10.0.0.1", "10.0.0.9", hidden=True)
        self.assertTrue(ovs.remove_node(["ip:10.0.0.9"]))
        self.assertTrue(ovs.remove_link("10.0.0.1", "10.0.0.9"))
        self.assertTrue(ovs.is_empty())
        # 再删一次返回 False（不抛）
        self.assertFalse(ovs.remove_node(["ip:10.0.0.9"]))

    def test_prune_drops_empty_entries(self):
        ovs = tov.TopologyOverrides()
        ovs.upsert_node("ip:10.0.0.9")          # 空白条目
        ovs.upsert_node("ip:10.0.0.8", note="keep")
        ovs.upsert_link("10.0.0.1", "10.0.0.2")  # 空白链路
        ovs.prune()
        self.assertEqual(len(ovs.nodes), 1)
        self.assertEqual(ovs.nodes[0].ip, "10.0.0.8")
        self.assertEqual(len(ovs.links), 0)

    def test_upsert_bad_identity_does_not_crash(self):
        ovs = tov.TopologyOverrides()
        ovs.upsert_node("", pin=(1, 2))
        ovs.upsert_link("", "", hidden=True)
        # 空身份不该抛；产生的空壳由 prune 收掉
        ovs.prune()
        self.assertTrue(ovs.is_empty())

    def test_node_scene_key_matches_first_identity_key(self):
        node = self._node()
        self.assertEqual(tov.node_scene_key(node),
                         tov.node_identity_keys(node)[0])

    def test_edited_overrides_roundtrip_to_json(self):
        """编辑后的集合能存能读，且语义不变（GUI 保存路径的保证）。"""
        ovs = tov.TopologyOverrides()
        ovs.upsert_node("mac:aabbccddee02", pin=(300, 400), note="核心")
        ovs.upsert_node("ip:10.0.0.9", hidden=True)
        ovs.upsert_link("mac:aabbccddee02", "10.0.0.1", hidden=True)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ov.json")
            ok, err = tov.save(ovs, p)
            self.assertTrue(ok, err)
            back = tov.load(p)
        self.assertEqual(len(back.nodes), 2)
        self.assertEqual(back.nodes[0].pin, (300.0, 400.0))
        self.assertTrue(back.nodes[1].hidden)
        self.assertTrue(back.links[0].hidden)


if __name__ == "__main__":
    unittest.main(verbosity=2)
