# -*- coding: utf-8 -*-
"""拓扑发现（LLDP/CDP/转发表）必须真的解出链路。

背景（V1.7.4 用户反馈）
----------------------
「拓扑视图无法识别交换机/路由器，不能形成真实的拓扑」。根因是 LLDP 走错了
子树 —— `_LLDP_REM_LOCAL_PORT` 是 lldpRemTable 的**第 2 列**
（lldpRemLocalPortNum，值只是一个 INTEGER），只走这一列永远拿不到
chassisId / portId / sysName，于是每个邻居都成了空壳，
`discover_topology` 再把它们全部折叠成一个 `ext:` 节点。

本文件用**真实的 LLDP-MIB / CISCO-CDP-MIB 实例 OID** 喂给解析器，锁死列号与
索引语义；再用假的 SNMP / 交换机对象跑通整条发现链路。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import topology_discovery as td  # noqa: E402
from scanner.models import ScanResult  # noqa: E402


# lldpRemTable = 1.0.8802.1.1.2.1.4.1.1
# 索引 = lldpRemTimeMark . lldpRemLocalPortNum . lldpRemIndex
_LLDP = "1.0.8802.1.1.2.1.4.1.1"
# cdpCacheTable = 1.3.6.1.4.1.9.9.23.1.2.1.1
# 索引 = cdpCacheIfIndex . cdpCacheDeviceIndex
_CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"

_MAC_A = bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01])


def _lldp_table(rows):
    """把 [(timeMark, localPort, remIndex, {col: (bytes, tag)})] 铺平成 walk 字典。"""
    out = {}
    for tm, lp, ri, cols in rows:
        for col, val in cols.items():
            out[f"{_LLDP}.{col}.{tm}.{lp}.{ri}"] = val
    return out


class LldpParseTest(unittest.TestCase):
    """LLDP remTable 解析：列号 + 三元索引。"""

    def test_real_lldp_columns_are_parsed(self):
        walk = _lldp_table([
            (0, 5, 1, {
                2: (b"\x05", 0x02),                                       # localPortNum
                4: (b"\x03", 0x02),                                       # chassisIdSubtype=mac
                5: (_MAC_A, 0x04),                                        # chassisId
                6: (b"\x05", 0x02),                                       # portIdSubtype=interfaceName
                7: (b"GigabitEthernet0/2", 0x04),                          # portId
                8: (b"GigabitEthernet0/1", 0x04),                          # portDesc
                9: (b"core-sw-2", 0x04),                                   # sysName
                10: (b"Cisco IOS Software, C2960", 0x04),                  # sysDesc
            }),
        ])
        nb = td._parse_lldp_entries(walk)
        self.assertEqual(len(nb), 1, f"应解析出 1 个邻居，实际 {nb!r}")
        n = nb[0]
        self.assertEqual(n["local_port"], "5")
        self.assertEqual(n["remote_id"], "aa:bb:cc:00:00:01")
        self.assertEqual(n["remote_port"], "GigabitEthernet0/2")
        self.assertEqual(n["remote_name"], "core-sw-2")
        self.assertEqual(n["protocol"], "LLDP")
        self.assertEqual(n["remote_role"], "switch",
                         "sysDesc 里的 Cisco IOS / C2960 应判为交换机")

    def test_multiple_remotes_on_one_port_do_not_overwrite(self):
        """同一端口上挂多台邻居（remIndex>1）必须各自成条，不能互相覆盖。"""
        walk = _lldp_table([
            (0, 3, 1, {5: (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), 0x04),
                       7: (b"eth0", 0x04), 9: (b"ap-1", 0x04)}),
            (0, 3, 2, {5: (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]), 0x04),
                       7: (b"eth0", 0x04), 9: (b"ap-2", 0x04)}),
        ])
        nb = td._parse_lldp_entries(walk)
        self.assertEqual(len(nb), 2, f"同端口的两个邻居被折叠了: {nb!r}")
        self.assertEqual({n["remote_name"] for n in nb}, {"ap-1", "ap-2"})

    def test_network_address_chassis_id_is_decoded_as_ip(self):
        """chassisId 子类型 4 = networkAddress：第 1 字节是地址族，不能当成 MAC。"""
        walk = _lldp_table([
            (0, 7, 1, {4: (b"\x04", 0x02),
                       5: (bytes([1, 10, 0, 0, 254]), 0x04),
                       9: (b"gw", 0x04)}),
        ])
        nb = td._parse_lldp_entries(walk)
        self.assertEqual(len(nb), 1)
        self.assertEqual(nb[0]["remote_id"], "10.0.0.254")
        self.assertEqual(nb[0]["remote_ip"], "10.0.0.254")

    def test_text_chassis_id_is_kept_readable(self):
        """子类型 5 = interfaceName，值是文本，别去 hex 化。"""
        walk = _lldp_table([(0, 1, 1, {4: (b"\x05", 0x02),
                                       5: (b"edge-sw-9", 0x04)})])
        nb = td._parse_lldp_entries(walk)
        self.assertEqual(nb[0]["remote_id"], "edge-sw-9")

    def test_missing_subtype_column_falls_back_to_length(self):
        """对端没送 chassisIdSubtype 时：6 字节按 MAC 解，不能 UTF-8 解成乱码。

        乱码的 remote_id 匹配不上扫描结果的 MAC，图上就会多出一个 id 是乱码的
        "外部设备"，而真实的那台交换机被画成两个节点。
        """
        walk = _lldp_table([(0, 4, 1, {5: (_MAC_A, 0x04)})])
        nb = td._parse_lldp_entries(walk)
        self.assertEqual(nb[0]["remote_id"], "aa:bb:cc:00:00:01")

    def test_binary_value_without_subtype_is_hex_not_mojibake(self):
        walk = _lldp_table([(0, 4, 1, {5: (bytes([0xFF, 0xFE, 0x80]), 0x04)})])
        nb = td._parse_lldp_entries(walk)
        self.assertEqual(nb[0]["remote_id"], "ff:fe:80")

    def test_empty_walk_yields_no_neighbors(self):
        self.assertEqual(td._parse_lldp_entries({}), [])
        self.assertEqual(td._parse_lldp_entries(None), [])

    def test_foreign_subtree_is_ignored(self):
        """别的表（比如 lldpLocPortTable）混进来不能当成邻居。"""
        walk = {"1.0.8802.1.1.2.1.3.7.1.4.1": (b"eth0", 0x04)}
        self.assertEqual(td._parse_lldp_entries(walk), [])


class LldpWalkTest(unittest.TestCase):
    """LLDP 发现必须走**整张表**，而不是某一列。"""

    def test_walk_covers_the_whole_rem_table(self):
        seen = {}

        def fake_walk(ip, base_oid, **kw):
            # 端口名反查（ifName/ifDescr）也会 walk，只记 LLDP 那次
            if base_oid == _LLDP:
                seen["base"] = base_oid
                return _lldp_table([
                    (0, 1, 1, {5: (bytes([1, 2, 3, 4, 5, 6]), 0x04),
                               7: (b"port1", 0x04), 9: (b"sw-b", 0x04)}),
                ])
            return {}

        with mock.patch.object(td, "snmp_walk", fake_walk):
            nb = td._discover_lldp_neighbors("10.0.0.1", communities=["public"])
        self.assertTrue(nb, "走整表时应当拿到邻居")
        self.assertEqual(seen["base"].rstrip("."), _LLDP,
                         "LLDP walk 必须从 lldpRemEntry 起，不能只走单列")
        self.assertEqual(nb[0]["remote_name"], "sw-b")

    def test_local_port_number_is_resolved_to_a_port_name(self):
        """走整表之后还要把 localPortNum 换成 ifName —— 否则端口列只有数字。"""

        def fake_walk(ip, base_oid, **kw):
            if base_oid == td._OID_IF_NAME:
                return {f"{td._OID_IF_NAME}.5": (b"Gi0/5", 0x04)}
            if base_oid == td._OID_IF_DESCR:
                return {f"{td._OID_IF_DESCR}.5": (b"GigabitEthernet0/5", 0x04)}
            return _lldp_table([(0, 5, 1, {5: (_MAC_A, 0x04), 9: (b"sw", 0x04)})])

        with mock.patch.object(td, "snmp_walk", fake_walk):
            nb = td._discover_lldp_neighbors("10.0.0.1", communities=["public"])
        self.assertEqual(nb[0]["local_port_name"], "Gi0/5")
        self.assertEqual(nb[0]["local_port_desc"], "Gi0/5")


class CdpParseTest(unittest.TestCase):
    """CDP cacheTable 解析：索引是二元 (ifIndex.deviceIndex)。"""

    def test_real_cdp_columns_are_parsed(self):
        walk = {
            f"{_CDP}.6.1.1": (b"core-sw-1", 0x04),                 # deviceId
            f"{_CDP}.4.1.1": (bytes([10, 0, 0, 1]), 0x40),         # address (IpAddress)
            f"{_CDP}.7.1.1": (b"FastEthernet0/3", 0x04),           # devicePort
            f"{_CDP}.8.1.1": (b"cisco WS-C2960", 0x04),            # platform
            f"{_CDP}.9.1.1": (b"\x00\x00\x00\x08", 0x04),          # capabilities=switch
        }
        nb = td._parse_cdp_entries(walk)
        self.assertEqual(len(nb), 1, f"应解析出 1 个 CDP 邻居，实际 {nb!r}")
        n = nb[0]
        self.assertEqual(n["local_port"], "1")
        self.assertEqual(n["remote_name"], "core-sw-1")
        self.assertEqual(n["remote_ip"], "10.0.0.1")
        self.assertEqual(n["remote_port"], "FastEthernet0/3")
        self.assertEqual(n["remote_role"], "switch")
        self.assertEqual(n["protocol"], "CDP")

    def test_capabilities_tell_router_apart_from_switch(self):
        walk = {f"{_CDP}.6.1.2": (b"edge-rtr", 0x04),
                f"{_CDP}.9.1.2": (b"\x00\x00\x00\x01", 0x04)}   # router bit
        nb = td._parse_cdp_entries(walk)
        self.assertEqual(nb[0]["remote_role"], "router")

    def test_multiple_neighbors_on_one_interface_are_kept(self):
        walk = {f"{_CDP}.6.1.1": (b"a", 0x04), f"{_CDP}.6.1.2": (b"b", 0x04)}
        nb = td._parse_cdp_entries(walk)
        self.assertEqual({n["remote_name"] for n in nb}, {"a", "b"})

    def test_cdp_walk_covers_device_id_column(self):
        seen = {}

        def fake_walk(ip, base_oid, **kw):
            # 端口名反查（ifName/ifDescr）也会 walk，只记 CDP 那次
            if base_oid.startswith(_CDP):
                seen["base"] = base_oid
                return {f"{_CDP}.6.1.1": (b"sw", 0x04)}
            return {}

        with mock.patch.object(td, "snmp_walk", fake_walk):
            nb = td._discover_cdp_neighbors("10.0.0.1", communities=["public"])
        self.assertEqual(seen["base"].rstrip("."), _CDP)
        self.assertEqual(nb[0]["remote_name"], "sw")


class _FakeSwitch:
    """一台假交换机：LLDP / CDP / ifName 的 walk 结果全部按需返回。"""

    def __init__(self, lldp=None, cdp=None, ifnames=None):
        self.lldp = lldp or {}
        self.cdp = cdp or {}
        self.ifnames = ifnames or {}

    def walk(self, base_oid, max_iterations=2000):
        if base_oid == td._LLDP_REM_ENTRY:
            return self.lldp
        if base_oid == td._CDP_CACHE_ENTRY:
            return self.cdp
        if base_oid in (td._OID_IF_NAME, td._OID_IF_DESCR):
            return {f"{base_oid}.{k}": (v, 0x04) for k, v in self.ifnames.items()}
        return {}


class DiscoverTopologyTest(unittest.TestCase):
    """整条发现链：候选选择 → SNMP 定性 → 邻居 → 链路。"""

    def setUp(self):
        # 用真实的 sysDescr 让角色判定走真实分支
        self.sw = ScanResult(ip="10.0.0.2", status="online", mac="00:11:22:33:44:55",
                             hostname="core-sw", device_class="交换机",
                             vendor="Cisco", snmp_sys_descr="Cisco IOS Software C2960")
        self.pc = ScanResult(ip="10.0.0.50", status="online",
                             mac="AA:BB:CC:00:00:01", hostname="pc-50")
        self.gw = ScanResult(ip="10.0.0.1", status="online",
                             mac="00:11:22:33:44:00", hostname="gw")

    def _patch(self, fake, sysinfo=None):
        """把 SNMP 访问层整体换成假实现（不发任何包）。"""
        sysinfo = sysinfo if sysinfo is not None else {}

        def _get_system(self):
            self.working_community = "public"
            return sysinfo.get(self.ip, {})

        return [
            mock.patch.object(td._SnmpClient, "get_system", _get_system),
            mock.patch.object(td._SnmpClient, "walk",
                              lambda self, base, max_iterations=2000:
                              fake.get(self.ip, _FakeSwitch()).walk(base)),
        ]

    def _run(self, results, fake, sysinfo=None, **kw):
        # 默认关掉转发表兜底：它要么发真实 UDP（拖慢测试、结果随网络变化），
        # 要么被各测试单独 mock —— 需要它的用例自己覆盖这个开关。
        kw.setdefault("enable_fdb", False)
        patches = self._patch(fake, sysinfo)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return td.discover_topology(results, gateway_ip="10.0.0.1", **kw)

    def test_lldp_neighbor_becomes_a_real_link(self):
        sysinfo = {"10.0.0.2": {"sys_descr": "Cisco IOS Software C2960",
                                "sys_name": "core-sw"}}
        fake = {"10.0.0.2": _FakeSwitch(
            lldp=_lldp_table([(0, 5, 1, {
                4: (b"\x03", 0x02),
                5: (bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]), 0x04),  # pc 的 MAC
                7: (b"Gi0/5", 0x04),
                9: (b"pc-50", 0x04)})]),
            ifnames={"5": b"Gi0/5"})}
        topo = self._run([self.sw, self.pc], fake, sysinfo)
        self.assertEqual(len(topo.links), 1, f"应有一条链路，实际 {topo.links!r}")
        link = topo.links[0]
        self.assertEqual({link.source_id, link.target_id}, {"10.0.0.2", "10.0.0.50"})
        self.assertEqual(link.protocol, "LLDP")
        self.assertEqual(link.source_port, "Gi0/5")
        node = next(n for n in topo.nodes if n.id == "10.0.0.2")
        self.assertTrue(node.is_switch)
        self.assertEqual(node.kind, td.KIND_SWITCH)

    def test_switch_is_recognised_without_the_snmp_protocol_ticked(self):
        """扫描没勾 SNMP 协议（sysDescr 为空）时，也要靠主动探测认出来。

        这正是用户遇到的场景：默认协议是 HTTP/HTTPS/FTP/RDP，交换机在扫描结果里
        既没有 SNMP 服务、也没有 sysDescr。
        """
        sw = ScanResult(ip="10.0.0.2", status="online",
                        mac="00:11:22:33:44:55", hostname="sw1", vendor="Cisco")
        sysinfo = {"10.0.0.2": {"sys_descr": "Cisco IOS Software C2960",
                                "sys_name": "sw1"}}
        fake = {"10.0.0.2": _FakeSwitch(lldp=_lldp_table([
            (0, 3, 1, {5: (bytes([0xAA, 0xBB, 0xCC, 0, 0, 1]), 0x04),
                       9: (b"pc", 0x04)})]))}
        topo = self._run([sw, self.pc], fake, sysinfo)
        self.assertEqual(topo.infra_count, 1)
        self.assertEqual(len(topo.links), 1)

    def test_unknown_neighbor_becomes_an_external_switch_node(self):
        """对端不在扫描范围内时，按 CDP platform 建一个"外部交换机"节点。"""
        sysinfo = {"10.0.0.2": {"sys_descr": "Cisco IOS Software C2960"}}
        fake = {"10.0.0.2": _FakeSwitch(cdp={
            f"{_CDP}.6.1.1": (b"core-1", 0x04),
            f"{_CDP}.8.1.1": (b"cisco WS-C4500", 0x04),
            f"{_CDP}.9.1.1": (b"\x00\x00\x00\x08", 0x04)})}
        topo = self._run([self.sw], fake, sysinfo)
        self.assertEqual(len(topo.links), 1)
        peer = next(n for n in topo.nodes if n.id.startswith("ext:"))
        self.assertTrue(peer.is_switch, "CDP 说对端是交换机，节点就该画成交换机")
        self.assertEqual(peer.kind, td.KIND_SWITCH)

    def test_identityless_neighbor_does_not_create_a_phantom_node(self):
        """没有任何身份信息的邻居必须丢弃，不能挤成一个空标签节点。"""
        sysinfo = {"10.0.0.2": {"sys_descr": "Cisco IOS Software C2960"}}
        fake = {"10.0.0.2": _FakeSwitch(lldp=_lldp_table([
            (0, 5, 1, {2: (b"\x05", 0x02)})]))}       # 只有 localPortNum
        topo = self._run([self.sw], fake, sysinfo)
        self.assertEqual(topo.links, [])
        self.assertEqual([n for n in topo.nodes if n.id.startswith("ext:")], [])

    def test_both_directions_of_a_link_are_merged(self):
        """两台交换机互相看到对方时，只画一条线。"""
        sw2 = ScanResult(ip="10.0.0.3", status="online",
                         mac="00:11:22:33:44:66", hostname="sw2",
                         device_class="交换机")
        sysinfo = {
            "10.0.0.2": {"sys_descr": "Cisco IOS Software C2960", "sys_name": "sw1"},
            "10.0.0.3": {"sys_descr": "Cisco IOS Software C2960", "sys_name": "sw2"},
        }
        fake = {
            "10.0.0.2": _FakeSwitch(lldp=_lldp_table([
                (0, 1, 1, {5: (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]), 0x04),
                           9: (b"sw2", 0x04)})])),
            "10.0.0.3": _FakeSwitch(lldp=_lldp_table([
                (0, 2, 1, {5: (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), 0x04),
                           9: (b"sw1", 0x04)})])),
        }
        topo = self._run([self.sw, sw2], fake, sysinfo)
        self.assertEqual(len(topo.links), 1, f"双向邻居应合并成一条: {topo.links!r}")

    def test_no_switch_means_no_links_and_an_honest_note(self):
        """一台可管理设备都没有时：不编造链路，但要把原因说出来。"""
        topo = self._run([self.pc, self.gw], {}, {})
        self.assertEqual(topo.links, [])
        self.assertTrue(topo.note, "为空拓扑必须给出原因，否则用户只能猜")
        self.assertIn("SNMP", topo.note)

    def test_snmp_works_but_no_neighbours_gives_a_different_note(self):
        """SNMP 通了却没有任何邻居时，提示要指向 LLDP/CDP，而不是再去查 SNMP。

        这两种"没链路"要用户做的事完全不同，写成同一句话等于把排查方向带偏。
        """
        sysinfo = {"10.0.0.2": {"sys_descr": "Cisco IOS Software C2960"}}
        topo = self._run([self.sw, self.pc], {"10.0.0.2": _FakeSwitch()},
                         sysinfo)
        self.assertEqual(topo.links, [])
        self.assertEqual(topo.infra_count, 1)
        self.assertIn("LLDP/CDP", topo.note)

    def test_results_are_not_mutated(self):
        """发现过程跑在后台线程，绝不能就地改主线程正在显示的扫描结果。"""
        sysinfo = {"10.0.0.2": {"sys_descr": "Cisco IOS Software C2960",
                                "sys_name": "core-sw"}}
        before = (self.sw.snmp_sys_descr, self.sw.snmp_sys_name,
                  list(self.sw.services), self.sw.hostname)
        self._run([self.sw, self.pc],
                  {"10.0.0.2": _FakeSwitch()}, sysinfo)
        after = (self.sw.snmp_sys_descr, self.sw.snmp_sys_name,
                 list(self.sw.services), self.sw.hostname)
        self.assertEqual(before, after)

    def test_multi_subnet_fallback_layers_by_segment(self):
        """没有任何 SNMP 时，多网段扫描按 /24 分层（真实数据，不编造链路）。"""
        results = [ScanResult(ip=f"10.0.0.{i}", status="online") for i in (1, 10, 11)]
        results += [ScanResult(ip=f"10.9.9.{i}", status="online") for i in (10, 11)]
        topo = self._run(results, {}, {})
        self.assertTrue(topo.links, "两个网段应给出层次结构")
        hubs = [n for n in topo.nodes if n.kind == td.KIND_SUBNET]
        self.assertEqual(len(hubs), 2)
        self.assertIn("/24", topo.note)

    def test_single_subnet_fallback_stays_empty(self):
        """单网段时分层没有价值，应当让界面走原来的星型视图。"""
        results = [ScanResult(ip=f"10.0.0.{i}", status="online") for i in (1, 10, 11)]
        topo = self._run(results, {}, {})
        self.assertEqual(topo.links, [])


class _FakeFdb:
    """假的 switch_mapper.SwitchInfo。"""

    def __init__(self, sys_name="", mappings=(), error=""):
        self.sys_name = sys_name
        self.mappings = list(mappings)
        self.error = error


class FdbFallbackTest(unittest.TestCase):
    """LLDP/CDP 都没开时，BRIDGE-MIB 转发表必须兜住接入关系。"""

    def _mapping(self, mac, port):
        from switch_mapper import PortMapping
        return PortMapping(mac=mac, port_name=port, if_index=1, bridge_port=1)

    def _run(self, results, switches, fdb_map, gateway="10.0.0.1", **kw):
        """switches: {ip: _FakeSwitch}；fdb_map: {ip: _FakeFdb 或 callable}。"""
        def fake_map(ip, **kw2):
            value = fdb_map.get(ip)
            return value(ip) if callable(value) else (value or _FakeFdb())

        patches = [
            mock.patch.object(td._SnmpClient, "get_system",
                              lambda self: switches.get(self.ip, {}).get("sys", {})),
            mock.patch.object(td._SnmpClient, "walk",
                              lambda self, base, max_iterations=2000:
                              switches.get(self.ip, {}).get("fake", _FakeSwitch())
                              .walk(base)),
            mock.patch("switch_mapper.map_switch_ports", side_effect=fake_map),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return td.discover_topology(results, gateway_ip=gateway, **kw)

    def test_fdb_links_attach_devices_to_the_switch_port(self):
        sw = ScanResult(ip="10.0.0.2", status="online",
                        mac="00:11:22:33:44:55", device_class="交换机")
        pc1 = ScanResult(ip="10.0.0.50", status="online", mac="AA:BB:CC:00:00:01")
        pc2 = ScanResult(ip="10.0.0.51", status="online", mac="AA:BB:CC:00:00:02")
        switches = {"10.0.0.2": {"sys": {"sys_descr": "H3C Comware Software S5130",
                                         "sys_name": "access-sw"}}}
        fdb = {"10.0.0.2": _FakeFdb("access-sw", [
            self._mapping("AA:BB:CC:00:00:01", "GE1/0/1"),
            self._mapping("AA:BB:CC:00:00:02", "GE1/0/2"),
            self._mapping("DE:AD:BE:EF:00:99", "GE1/0/3"),
        ])}
        topo = self._run([sw, pc1, pc2], switches, fdb)
        ports = {l.target_id: l.source_port for l in topo.links}
        self.assertEqual(ports.get("10.0.0.50"), "GE1/0/1")
        self.assertEqual(ports.get("10.0.0.51"), "GE1/0/2")
        self.assertTrue(all(l.protocol == "FDB" for l in topo.links))
        self.assertEqual(topo.unplaced, 1, "扫描范围外的 MAC 应只计数不画点")

    def test_uplink_port_does_not_swallow_downstream_devices(self):
        """核心交换机从"通往下游交换机的口"学到的设备，不该算它的接入设备。"""
        core = ScanResult(ip="10.0.0.2", status="online",
                          mac="00:11:22:33:44:55", device_class="交换机")
        edge = ScanResult(ip="10.0.0.3", status="online",
                          mac="00:11:22:33:44:66", device_class="交换机")
        pc = ScanResult(ip="10.0.0.50", status="online", mac="AA:BB:CC:00:00:01")
        switches = {
            "10.0.0.2": {"sys": {"sys_descr": "Cisco IOS Software C4500"}},
            "10.0.0.3": {"sys": {"sys_descr": "Cisco IOS Software C2960"}},
        }

        def per_switch(ip):
            if ip == "10.0.0.2":
                # 核心：Gi1/0/1 是通往下游交换机的上联口，也从它学到了 PC
                return _FakeFdb(mappings=[
                    self._mapping("00:11:22:33:44:66", "Gi1/0/1"),
                    self._mapping("AA:BB:CC:00:00:01", "Gi1/0/1"),
                ])
            return _FakeFdb(mappings=[self._mapping("AA:BB:CC:00:00:01", "Gi0/5")])

        topo = self._run([core, edge, pc], switches, {"10.0.0.2": per_switch,
                                                     "10.0.0.3": per_switch})
        pairs = {frozenset((l.source_id, l.target_id)): l.source_port
                 for l in topo.links}
        self.assertEqual(pairs.get(frozenset({"10.0.0.2", "10.0.0.3"})), "Gi1/0/1",
                         "上联口应识别成交换机之间的链路")
        self.assertEqual(pairs.get(frozenset({"10.0.0.3", "10.0.0.50"})), "Gi0/5",
                         "设备的真正接入点是下游交换机")

    def test_fdb_completes_the_lldp_backbone(self):
        """LLDP 给骨干、转发表给接入 —— 两者必须**同时**生效。

        普通终端不说 LLDP，LLDP 只知道交换机之间怎么连。历史实现的转发表兜底
        是"LLDP 有结果就整个跳过"，于是所有 PC 都落到根节点下（图上看起来像
        全都直接挂在网关上），接入关系全丢。
        """
        core = ScanResult(ip="10.0.0.2", status="online",
                          mac="00:11:22:33:44:55", device_class="交换机")
        access = ScanResult(ip="10.0.0.10", status="online",
                            mac="00:11:22:33:44:0A", device_class="交换机")
        pc = ScanResult(ip="10.0.0.50", status="online", mac="AA:BB:CC:00:00:01")
        switches = {
            "10.0.0.2": {"sys": {"sys_descr": "Cisco IOS Software C4500"},
                         "fake": _FakeSwitch(lldp=_lldp_table([
                             (0, 1, 1, {5: (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x0A]),
                                         0x04), 9: (b"access-sw", 0x04)})]))},
            "10.0.0.10": {"sys": {"sys_descr": "Cisco IOS Software C2960"},
                          "fake": _FakeSwitch()},
        }
        fdb = {"10.0.0.10": _FakeFdb(mappings=[
            self._mapping("AA:BB:CC:00:00:01", "GE1/0/5")])}
        topo = self._run([core, access, pc], switches, fdb)
        pairs = {frozenset((l.source_id, l.target_id)): l.protocol
                 for l in topo.links}
        self.assertEqual(pairs.get(frozenset({"10.0.0.2", "10.0.0.10"})), "LLDP")
        self.assertEqual(pairs.get(frozenset({"10.0.0.10", "10.0.0.50"})), "FDB",
                         "LLDP 命中后仍必须用转发表把终端接上")
        node = next(n for n in topo.nodes if n.id == "10.0.0.50")
        self.assertEqual(node.port, "GE1/0/5", "接入端口要落到节点上供悬停提示")

    def test_lldp_peer_is_promoted_even_if_it_never_answered_snmp(self):
        """SNMP 只在核心上开着时，LLDP 看到的接入交换机也必须画成网络设备。

        否则它只是个"未知设备"，在图上被画成终端圆点 —— 明明拿到了权威的邻居
        信息（sysDesc 说它是 Catalyst）却不用。
        """
        core = ScanResult(ip="10.0.0.2", status="online",
                          mac="00:11:22:33:44:55", device_class="交换机")
        edge = ScanResult(ip="10.0.0.10", status="online",
                          mac="00:11:22:33:44:0A", hostname="edge-sw")
        switches = {"10.0.0.2": {
            "sys": {"sys_descr": "Cisco IOS Software C4500"},
            "fake": _FakeSwitch(lldp=_lldp_table([
                (0, 1, 1, {5: (bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x0A]), 0x04),
                           9: (b"edge-sw", 0x04),
                           10: (b"Cisco IOS Software, C2960 Software", 0x04)})]))}}
        topo = self._run([core, edge], switches, {})
        node = next(n for n in topo.nodes if n.id == "10.0.0.10")
        self.assertTrue(node.is_switch, "LLDP 说是交换机，就该画成交换机")
        self.assertEqual(node.kind, td.KIND_SWITCH)
        self.assertIn("C2960", node.model)

    def test_fdb_is_skipped_when_every_host_is_already_localised(self):
        """所有终端都已被 LLDP/CDP 定位时，不再白读一遍转发表（每台 5 次 walk）。"""
        sw = ScanResult(ip="10.0.0.2", status="online",
                        mac="00:11:22:33:44:55", device_class="交换机")
        pc = ScanResult(ip="10.0.0.50", status="online", mac="AA:BB:CC:00:00:01")
        switches = {"10.0.0.2": {
            "sys": {"sys_descr": "Cisco IOS Software C2960"},
            "fake": _FakeSwitch(lldp=_lldp_table([
                (0, 1, 1, {5: (bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]), 0x04),
                           9: (b"pc-50", 0x04)})]))}}
        with mock.patch("switch_mapper.map_switch_ports") as m:
            topo = self._run([sw, pc], switches, {})
        m.assert_not_called()
        self.assertEqual(len(topo.links), 1)


class LayoutTest(unittest.TestCase):
    """布局是纯函数：不能崩、不能重叠、网关在最高层。"""

    def _topo(self, links, nodes):
        topo = td.Topology()
        for nid, kw in nodes:
            topo.nodes.append(td.TopoNode(id=nid, label=nid, **kw))
        topo.links = [td.TopoLink(*l) for l in links]
        return topo

    def _no_overlap(self, pos):
        seen = {}
        for nid, (x, y) in pos.items():
            key = (round(x, 3), round(y, 3))
            self.assertNotIn(key, seen, f"{nid} 与 {seen.get(key)} 坐标重合")
            seen[key] = nid

    def test_unassigned_hosts_do_not_crash_the_layout(self):
        """旧实现在这里抛 TypeError（对不可哈希的 dataclass 取下标）。"""
        topo = self._topo(
            [("10.0.0.1", "10.0.0.2", "", "", "LLDP")],
            [("10.0.0.1", {"is_switch": True, "kind": td.KIND_GATEWAY,
                           "is_gateway": True}),
             ("10.0.0.2", {"is_switch": True, "kind": td.KIND_SWITCH}),
             ("10.0.0.50", {}), ("10.0.0.51", {})])
        pos = td.layout_real_topology(topo, "10.0.0.1")
        self.assertEqual(set(pos), {n.id for n in topo.nodes},
                         "没有归属的设备也必须出现在布局里，不能凭空消失")
        self._no_overlap(pos)

    def test_gateway_sits_above_the_switch(self):
        topo = self._topo(
            [("10.0.0.1", "10.0.0.2", "", "", "LLDP")],
            [("10.0.0.1", {"is_switch": True, "kind": td.KIND_GATEWAY,
                           "is_gateway": True}),
             ("10.0.0.2", {"is_switch": True, "kind": td.KIND_SWITCH})])
        pos = td.layout_real_topology(topo, "10.0.0.1")
        self.assertLess(pos["10.0.0.1"][1], pos["10.0.0.2"][1])

    def test_host_block_is_compact_for_hundreds_of_devices(self):
        """几百台终端必须排成紧凑网格，而不是一条两万像素的长线。"""
        links = [("10.0.0.2", f"10.0.1.{i}", "GE0/1", "", "FDB")
                 for i in range(1, 401)]
        nodes = [("10.0.0.2", {"is_switch": True, "kind": td.KIND_SWITCH})]
        nodes += [(f"10.0.1.{i}", {}) for i in range(1, 401)]
        topo = self._topo(links, nodes)
        pos = td.layout_real_topology(topo)
        xs = [x for x, _ in pos.values()]
        ys = [y for _, y in pos.values()]
        self.assertLess(max(xs) - min(xs), 2500, "块被拉成了一条长线")
        self.assertLess(max(ys) - min(ys), 2500)
        self._no_overlap(pos)

    def test_two_switches_with_hosts_do_not_overlap(self):
        links = [("10.0.0.1", "10.0.0.2", "", "", "LLDP"),
                 ("10.0.0.1", "10.0.0.3", "", "", "LLDP")]
        links += [("10.0.0.2", f"10.0.2.{i}", "GE1/0/1", "", "FDB")
                  for i in range(1, 30)]
        links += [("10.0.0.3", f"10.0.3.{i}", "GE1/0/1", "", "FDB")
                  for i in range(1, 30)]
        nodes = [("10.0.0.1", {"is_switch": True, "kind": td.KIND_GATEWAY,
                               "is_gateway": True}),
                 ("10.0.0.2", {"is_switch": True, "kind": td.KIND_SWITCH}),
                 ("10.0.0.3", {"is_switch": True, "kind": td.KIND_SWITCH})]
        nodes += [(f"10.0.2.{i}", {}) for i in range(1, 30)]
        nodes += [(f"10.0.3.{i}", {}) for i in range(1, 30)]
        pos = td.layout_real_topology(self._topo(links, nodes), "10.0.0.1")
        self._no_overlap(pos)

    def test_cycles_and_self_loops_do_not_hang(self):
        topo = self._topo(
            [("a", "b", "", "", "FDB"), ("b", "c", "", "", "FDB"),
             ("c", "a", "", "", "FDB"), ("a", "a", "", "", "FDB")],
            [("a", {"is_switch": True, "kind": td.KIND_SWITCH}),
             ("b", {"is_switch": True, "kind": td.KIND_SWITCH}),
             ("c", {"is_switch": True, "kind": td.KIND_SWITCH})])
        pos = td.layout_real_topology(topo)
        self.assertEqual(set(pos), {"a", "b", "c"})

    def test_deep_chain_does_not_blow_the_stack(self):
        """800 层深的链不能触发 RecursionError（布局是迭代实现）。"""
        nodes = [(f"sw{i}", {"is_switch": True, "kind": td.KIND_SWITCH})
                 for i in range(800)]
        links = [(f"sw{i}", f"sw{i + 1}", "", "", "FDB") for i in range(799)]
        pos = td.layout_real_topology(self._topo(links, nodes))
        self.assertEqual(len(pos), 800)

    def test_empty_topology(self):
        self.assertEqual(td.layout_real_topology(td.Topology()), {})
        self.assertEqual(
            td.layout_real_topology(self._topo([], [("a", {})])), {"a": (0.0, 0.0)})


if __name__ == "__main__":
    unittest.main()
