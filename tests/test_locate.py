# -*- coding: utf-8 -*-
"""定位查询（locate_device / save_port_map）单元测试。

对应 `docs/ROADMAP_V1.8.md` §1.1 的三条验收标准：
  ① 3 台交换机 + 1 个终端 MAC，locate(mac) 返回 (switch_name, port_name)；
  ② 同一 MAC 在两次快照间换了端口，返回「上次在 X 口，本次在 Y 口」；
  ③ 交换机不支持 BRIDGE-MIB 时明确标注「位置未知」，不猜。

外加「诚实降级」的细节：端口名只有桥接端口号时要标 `index_only`；
以及 prune 级联、按 IP / 主机名定位、MAC 大小写不敏感。

使用临时文件 DB，避免污染项目内 scan_history.db。
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history_store


def _dev(ip, **kw):
    base = {"ip": ip, "status": "online", "mac": "", "hostname": "",
            "vendor": "", "device_class": "", "os_guess": "", "open_ports": "",
            "location": "", "user": "", "remark": ""}
    base.update(kw)
    return base


def _sw(ip, name, mappings=None, error=""):
    """构造 save_port_map() 认的交换机 dict。"""
    return {"switch_ip": ip, "switch_name": name, "error": error,
            "mappings": mappings or []}


def _pm(mac, port, real=True):
    """构造一条端口映射 dict。real=False 表示 port 只是桥接端口号。"""
    return {"mac": mac, "port_name": port, "port_is_real": real}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _snap(self, ts, devices):
        """存一条快照，max_keep 抬高避免被裁剪。返回快照 id。"""
        return history_store.save_snapshot(
            devices, ts=ts, db_path=self.db, max_keep=10 ** 9)


class LocateAcceptanceTest(_Base):
    """路线图 §1.1 的三条验收标准，逐条钉住。"""

    MAC = "AA:BB:CC:DD:EE:FF"

    def test_01_three_switches_one_terminal_returns_switch_and_port(self):
        """① 3 台交换机 + 1 个终端 MAC → 返回它挂在哪台交换机的哪个口。"""
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(sid, [
            _sw("10.0.0.1", "core-sw", [_pm("11:11:11:11:11:11", "Gi0/1")]),
            _sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/24")]),
            _sw("10.0.0.3", "access-sw-2", [_pm("22:22:22:22:22:22", "Gi0/7")]),
        ], db_path=self.db)

        r = history_store.locate_device(mac=self.MAC, db_path=self.db)

        self.assertTrue(r["found"])
        self.assertEqual(r["current"]["switch_name"], "access-sw-1")
        self.assertEqual(r["current"]["port_name"], "Gi0/24")
        self.assertEqual(r["port_confidence"], "named")
        self.assertFalse(r["moved"])
        self.assertIsNone(r["previous"])
        self.assertEqual(r["switch_count"], 3)

    def test_02_mac_moved_between_snapshots_reports_both_ports(self):
        """② 同一 MAC 两次快照间换端口 → 「上次在 X 口，本次在 Y 口」。"""
        s1 = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(
            s1, [_sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/24")])],
            db_path=self.db)
        s2 = self._snap(2000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(
            s2, [_sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/9")])],
            db_path=self.db)

        r = history_store.locate_device(mac=self.MAC, db_path=self.db)

        self.assertTrue(r["moved"])
        self.assertEqual(r["current"]["snapshot_id"], s2)
        self.assertEqual(r["current"]["port_name"], "Gi0/9")
        self.assertEqual(r["previous"]["snapshot_id"], s1)
        self.assertEqual(r["previous"]["port_name"], "Gi0/24")

    def test_03_switch_without_bridge_mib_says_unknown_not_guess(self):
        """③ 交换机不支持 BRIDGE-MIB → 明确「位置未知」，且说明是哪种未知。"""
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "access-sw-1", [],
                error="无法从 10.0.0.2 获取 MAC 转发表。"),
        ], db_path=self.db)

        r = history_store.locate_device(mac=self.MAC, db_path=self.db)

        self.assertFalse(r["found"])
        self.assertIsNone(r["current"])
        # 关键：扫过交换机（switch_count=1）但取不到表 —— 与「从未扫过」必须区分开
        self.assertEqual(r["reason"], history_store.LOCATE_SWITCH_SCAN_FAILED)
        self.assertEqual(r["switch_count"], 1)


class LocateDegradationTest(_Base):
    """「诚实降级」：说不清就如实说，不编。"""

    MAC = "AA:BB:CC:DD:EE:FF"

    def test_never_scanned_switches_is_distinct_from_failed_scan(self):
        self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        r = history_store.locate_device(mac=self.MAC, db_path=self.db)
        self.assertFalse(r["found"])
        self.assertEqual(r["reason"], history_store.LOCATE_NO_SWITCH_DATA)
        self.assertEqual(r["switch_count"], 0)

    def test_switch_ok_but_mac_absent_is_distinct_from_failed_scan(self):
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(
            sid, [_sw("10.0.0.2", "access-sw-1",
                      [_pm("99:99:99:99:99:99", "Gi0/1")])], db_path=self.db)
        r = history_store.locate_device(mac=self.MAC, db_path=self.db)
        self.assertFalse(r["found"])
        self.assertEqual(r["reason"], history_store.LOCATE_MAC_NOT_IN_FDB)

    def test_unknown_device_reports_no_device(self):
        r = history_store.locate_device(mac="FF:FF:FF:FF:FF:FF", db_path=self.db)
        self.assertFalse(r["found"])
        self.assertEqual(r["reason"], history_store.LOCATE_NO_DEVICE)

    def test_empty_query_returns_no_device_without_touching_db(self):
        r = history_store.locate_device(db_path=self.db)
        self.assertFalse(r["found"])
        self.assertEqual(r["reason"], history_store.LOCATE_NO_DEVICE)

    def test_bridge_port_number_is_flagged_index_only(self):
        """端口名解析不出来时只剩桥接端口号 —— 必须标注，不能当端口名。"""
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(
            sid, [_sw("10.0.0.2", "access-sw-1",
                      [_pm(self.MAC, "Port 5", real=False)])], db_path=self.db)

        r = history_store.locate_device(mac=self.MAC, db_path=self.db)

        self.assertTrue(r["found"])          # 找到了，但…
        self.assertEqual(r["port_confidence"], "index_only")   # …可信度要标出来
        self.assertEqual(r["current"]["port_source"],
                         history_store.PORT_SOURCE_BRIDGE_PORT)


class LocateLookupTest(_Base):
    """按 IP / 主机名定位，以及 MAC 大小写。"""

    MAC = "AA:BB:CC:DD:EE:FF"

    def _seed(self):
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC,
                                       hostname="FIN-PC-01")])
        history_store.save_port_map(
            sid, [_sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/24")])],
            db_path=self.db)

    def test_locate_by_ip_resolves_mac(self):
        self._seed()
        r = history_store.locate_device(ip="192.168.1.50", db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["mac"], self.MAC)
        self.assertEqual(r["current"]["port_name"], "Gi0/24")

    def test_locate_by_hostname_resolves_mac(self):
        self._seed()
        r = history_store.locate_device(hostname="FIN-PC-01", db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["mac"], self.MAC)

    def test_mac_lookup_is_case_insensitive(self):
        self._seed()
        r = history_store.locate_device(mac="aa:bb:cc:dd:ee:ff", db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["current"]["port_name"], "Gi0/24")

    def test_mac_takes_priority_over_ip(self):
        """MAC 才是设备身份：IP 会被 DHCP 回收后换台机器（同 device_timeline）。"""
        self._seed()
        r = history_store.locate_device(mac=self.MAC, ip="10.99.99.99",
                                        db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["mac"], self.MAC)

    def test_mac_query_backfills_ip_and_hostname(self):
        """只给 MAC 也要把 IP / 主机名补出来 —— 否则展示层只能显示一排「—」。"""
        self._seed()
        r = history_store.locate_device(mac=self.MAC, db_path=self.db)
        self.assertEqual(r["ip"], "192.168.1.50")
        self.assertEqual(r["hostname"], "FIN-PC-01")

    def test_unknown_mac_leaves_ip_and_hostname_empty(self):
        """库里查不到就别硬填 —— 空串就是「不知道」。"""
        self._seed()
        r = history_store.locate_device(mac="FF:FF:FF:FF:FF:FF", db_path=self.db)
        self.assertEqual(r["ip"], "")
        self.assertEqual(r["hostname"], "")


class LocateReasonLabelTest(_Base):
    """展示层的原因映射必须与存储层的规范值一一对应（漏一个就显示原始代码）。"""

    def test_label_table_covers_every_reason_code(self):
        from scanner.constants import (_LOCATE_REASON_HINT, _LOCATE_REASON_TEXT,
                                       locate_reason_hint, locate_reason_label)
        codes = {
            history_store.LOCATE_NO_DEVICE,
            history_store.LOCATE_NO_SWITCH_DATA,
            history_store.LOCATE_SWITCH_SCAN_FAILED,
            history_store.LOCATE_MAC_NOT_IN_FDB,
        }
        self.assertEqual(set(_LOCATE_REASON_TEXT), codes)
        self.assertEqual(set(_LOCATE_REASON_HINT), codes)
        # 翻译表未就绪时也得返回非空文本（不崩、不返回 None）
        for code in codes:
            self.assertTrue(locate_reason_label(code))
            self.assertTrue(locate_reason_hint(code))

    def test_unknown_reason_passes_through(self):
        from scanner.constants import locate_reason_hint, locate_reason_label
        self.assertEqual(locate_reason_label("whatever"), "whatever")
        self.assertEqual(locate_reason_hint("whatever"), "")


class PortMapPersistenceTest(_Base):
    """落库与裁剪。"""

    MAC = "AA:BB:CC:DD:EE:FF"

    def test_save_port_map_returns_mapping_row_count(self):
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        n = history_store.save_port_map(sid, [
            _sw("10.0.0.1", "core-sw", [_pm("11:11:11:11:11:11", "Gi0/1"),
                                         _pm("22:22:22:22:22:22", "Gi0/2")]),
            _sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/24")]),
        ], db_path=self.db)
        self.assertEqual(n, 3)

    def test_failed_switch_writes_no_port_rows(self):
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        n = history_store.save_port_map(
            sid, [_sw("10.0.0.2", "sw", [_pm(self.MAC, "Gi0/1")], error="超时")],
            db_path=self.db)
        self.assertEqual(n, 0)      # 失败的交换机不该产生端口行

    def test_empty_switches_writes_nothing(self):
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        self.assertEqual(history_store.save_port_map(sid, [], db_path=self.db), 0)
        self.assertEqual(
            history_store.save_port_map(sid, None, db_path=self.db), 0)

    def test_resaving_same_snapshot_replaces_not_appends(self):
        """同一快照重读一次转发表 —— 必须替换，否则端口记录翻倍、假报「换过端口」。"""
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        sw = [_sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/24")])]

        self.assertEqual(history_store.save_port_map(sid, sw, db_path=self.db), 1)
        self.assertEqual(history_store.save_port_map(sid, sw, db_path=self.db), 1)

        r = history_store.locate_device(mac=self.MAC, db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["current"]["port_name"], "Gi0/24")
        # 只有一条记录 → 没有「上一次」，也就不能报「换过端口」
        self.assertIsNone(r["previous"])
        self.assertFalse(r["moved"])
        self.assertEqual(r["switch_count"], 1)

    def test_resaving_can_shrink_to_new_state(self):
        """重读后端口变了 —— 旧记录要被清掉，不能留下两条互相矛盾的当前端口。"""
        sid = self._snap(1000.0, [_dev("192.168.1.50", mac=self.MAC)])
        history_store.save_port_map(
            sid, [_sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/24")])],
            db_path=self.db)
        history_store.save_port_map(
            sid, [_sw("10.0.0.2", "access-sw-1", [_pm(self.MAC, "Gi0/9")])],
            db_path=self.db)

        r = history_store.locate_device(mac=self.MAC, db_path=self.db)
        self.assertEqual(r["current"]["port_name"], "Gi0/9")
        self.assertIsNone(r["previous"])

    def test_prune_cascades_to_port_map_and_switch_map(self):
        """prune() 删旧快照时，端口映射必须跟着走（外键 CASCADE）。"""
        for i in range(3):
            sid = self._snap(float(1000 + i), [_dev("192.168.1.50", mac=self.MAC)])
            history_store.save_port_map(
                sid, [_sw("10.0.0.2", "access-sw-1",
                          [_pm(self.MAC, f"Gi0/{i}")])], db_path=self.db)

        history_store.prune(max_keep=1, db_path=self.db)

        # 只剩最后一条快照 → 只剩它那条端口记录
        r = history_store.locate_device(mac=self.MAC, db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["current"]["port_name"], "Gi0/2")
        self.assertIsNone(r["previous"])   # 旧记录已随快照删除，不该残留


class SwitchInfoBridgeTest(_Base):
    """switch_mapper → history_store 的接缝。"""

    def test_switch_info_to_dict_feeds_save_port_map(self):
        from switch_mapper import (PortMapping, SwitchInfo,
                                   switch_info_to_dict)
        info = SwitchInfo(ip="10.0.0.2", sys_name="access-sw-1", mappings=[
            PortMapping(mac="AA:BB:CC:DD:EE:FF", port_name="Gi0/24",
                        if_index=24, bridge_port=24),
            PortMapping(mac="11:22:33:44:55:66", port_name="Port 7",
                        if_index=0, bridge_port=7, port_is_real=False),
        ])
        sid = self._snap(1000.0, [_dev("192.168.1.50",
                                       mac="AA:BB:CC:DD:EE:FF")])
        n = history_store.save_port_map(
            sid, [switch_info_to_dict(info)], db_path=self.db)
        self.assertEqual(n, 2)

        real = history_store.locate_device(mac="AA:BB:CC:DD:EE:FF", db_path=self.db)
        self.assertEqual(real["port_confidence"], "named")
        only_num = history_store.locate_device(mac="11:22:33:44:55:66",
                                              db_path=self.db)
        self.assertEqual(only_num["port_confidence"], "index_only")

    def test_switch_name_falls_back_to_ip_when_sysname_missing(self):
        from switch_mapper import SwitchInfo, switch_info_to_dict
        d = switch_info_to_dict(SwitchInfo(ip="10.0.0.9"))
        self.assertEqual(d["switch_name"], "10.0.0.9")

    def test_failed_switch_info_carries_error(self):
        from switch_mapper import SwitchInfo, switch_info_to_dict
        d = switch_info_to_dict(SwitchInfo(ip="10.0.0.9", error="超时"))
        self.assertEqual(d["error"], "超时")

    def test_port_mapping_defaults_to_real(self):
        from switch_mapper import PortMapping
        self.assertTrue(PortMapping(mac="AA:BB:CC:DD:EE:FF").port_is_real)


class CollectSwitchPortMapsTest(_Base):
    """扫描末尾的按需采集：`topology_discovery.collect_switch_port_maps`。

    不发起真实 SNMP —— mock 掉 `_SnmpClient.get_system`（探测）与
    `switch_mapper.map_switch_ports`（读转发表），只验证编排与降级语义。
    """

    PC_MAC = "AA:BB:CC:00:00:01"
    SW_IP = "10.0.0.2"

    def _switch_result(self, ip=SW_IP):
        from scanner.models import ScanResult
        return ScanResult(ip=ip, status="online", mac="00:11:22:33:44:55",
                          device_class="交换机")

    def _pc_result(self, ip="10.0.0.50"):
        from scanner.models import ScanResult
        return ScanResult(ip=ip, status="online", mac=self.PC_MAC,
                          device_class="电脑")

    def _run(self, results, fdb_map, snmp=None, **kw):
        """fdb_map: {ip: SwitchInfo | Exception}；snmp: {ip: get_system 返回值}。

        patch 对象记在 `self._map_mock` 上供断言 —— **不要再在 `with mock.patch(...)`
        里调用本方法**：嵌套 patch 的 start/stop 顺序会错乱，把 `map_switch_ports`
        永久替换成 MagicMock 泄漏给后续测试（曾把 test_snmp_v3 的两个用例打红）。
        """
        import topology_discovery as td
        from switch_mapper import SwitchInfo

        snmp = snmp if snmp is not None else {
            self.SW_IP: {"sys_descr": "H3C Comware Software S5130",
                         "sys_name": "access-sw-1"}}

        def fake_map(ip, **_kw):
            v = fdb_map.get(ip)
            if isinstance(v, Exception):
                raise v
            return v if v is not None else SwitchInfo(ip=ip)

        map_patch = mock.patch("switch_mapper.map_switch_ports",
                               side_effect=fake_map)
        self._map_mock = map_patch.start()
        self.addCleanup(map_patch.stop)
        for p in (mock.patch.object(td._SnmpClient, "get_system",
                                    lambda self: snmp.get(self.ip, {})),):
            p.start()
            self.addCleanup(p.stop)
        return td.collect_switch_port_maps(results, **kw)

    def test_end_to_end_collect_then_save_then_locate(self):
        """采集 → 落库 → 定位，整条链路一次跑通（本项功能的真正验收）。"""
        from switch_mapper import PortMapping, SwitchInfo
        info = SwitchInfo(ip=self.SW_IP, sys_name="access-sw-1", mappings=[
            PortMapping(mac=self.PC_MAC, port_name="GE1/0/7",
                        if_index=7, bridge_port=7),
        ])
        maps = self._run([self._switch_result(), self._pc_result()],
                         {self.SW_IP: info})

        self.assertEqual(len(maps), 1)
        self.assertEqual(maps[0]["switch_name"], "access-sw-1")
        self.assertTrue(maps[0]["mappings"][0]["port_is_real"])

        sid = self._snap(1000.0, [_dev("10.0.0.50", mac=self.PC_MAC)])
        history_store.save_port_map(sid, maps, db_path=self.db)

        r = history_store.locate_device(mac=self.PC_MAC, db_path=self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["current"]["switch_name"], "access-sw-1")
        self.assertEqual(r["current"]["port_name"], "GE1/0/7")
        self.assertEqual(r["port_confidence"], "named")

    def test_failed_switch_is_reported_not_dropped(self):
        """读不到转发表的交换机必须**带 error 返回**，否则库里查不到它、
        locate 会把「读取失败」误报成「从未采集过」。"""
        from switch_mapper import SwitchInfo
        maps = self._run([self._switch_result()], {
            self.SW_IP: SwitchInfo(ip=self.SW_IP, error="无法获取 MAC 转发表。")})

        self.assertEqual(len(maps), 1)
        self.assertEqual(maps[0]["error"], "无法获取 MAC 转发表。")
        self.assertEqual(maps[0]["mappings"], [])

        sid = self._snap(1000.0, [_dev("10.0.0.50", mac=self.PC_MAC)])
        history_store.save_port_map(sid, maps, db_path=self.db)
        r = history_store.locate_device(mac=self.PC_MAC, db_path=self.db)
        self.assertEqual(r["reason"], history_store.LOCATE_SWITCH_SCAN_FAILED)

    def test_exception_while_reading_table_becomes_error_entry(self):
        maps = self._run([self._switch_result()],
                         {self.SW_IP: RuntimeError("boom")})
        self.assertEqual(len(maps), 1)
        self.assertIn("boom", maps[0]["error"])
        self.assertEqual(maps[0]["mappings"], [])

    def test_no_candidate_returns_empty_without_probing(self):
        """只有普通终端 → 连 SNMP 都不探，直接返回空（零网络开销）。"""
        maps = self._run([self._pc_result()], {})
        self.assertEqual(maps, [])
        self._map_mock.assert_not_called()

    def test_candidate_without_snmp_response_is_skipped(self):
        """像交换机但 SNMP 不响应 → 读不了转发表，跳过而不是硬试。"""
        maps = self._run([self._switch_result()], {}, snmp={})
        self.assertEqual(maps, [])
        self._map_mock.assert_not_called()

    def test_offline_switch_is_not_a_candidate(self):
        from scanner.models import ScanResult
        off = ScanResult(ip=self.SW_IP, status="offline",
                         mac="00:11:22:33:44:55", device_class="交换机")
        maps = self._run([off], {})
        self.assertEqual(maps, [])
        self._map_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class PortUtilizationTest(_Base):
    """端口利用率：每台交换机各端口的接入设备数 / 空闲口。

    🔴 本项的核心风险**不是统计**，而是「数据从哪来」：采集转发表需要显式
    `scan --switch-map`（**默认关**）。绝大多数用户从没开过 —— 此时给一张空表
    会让用户得出「我的交换机一个口都没用」，与事实（「我们从没读过转发表」）
    完全相反。所以这里把**四种「没有数据」的区分**逐条钉住。
    """

    def test_ok_path_groups_port_devices_and_counts(self):
        """有数据时：按端口分组、给出设备数、按设备数降序、带设备明细。"""
        sid = self._snap(1000.0, [
            _dev("10.0.0.11", mac="AA:BB:CC:00:00:01", hostname="pc1"),
            _dev("10.0.0.12", mac="AA:BB:CC:00:00:02", hostname="pc2"),
            _dev("10.0.0.13", mac="AA:BB:CC:00:00:03"),
            _dev("10.0.0.14", mac="AA:BB:CC:00:00:04", hostname="printer"),
        ])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "sw-core", [
                _pm("AA:BB:CC:00:00:01", "GE0/1"),
                _pm("AA:BB:CC:00:00:02", "GE0/1"),      # 同一口两台（级联/AP）
                _pm("AA:BB:CC:00:00:03", "GE0/2"),
                _pm("AA:BB:CC:00:00:04", "GE0/3"),
            ]),
        ], db_path=self.db)

        u = history_store.port_utilization(db_path=self.db)

        self.assertEqual(u["reason"], "")
        self.assertEqual(len(u["switches"]), 1)
        sw = u["switches"][0]
        self.assertEqual(sw["status"], "ok")
        self.assertEqual(sw["device_count"], 4)
        self.assertEqual(sw["used_port_count"], 3)
        # 设备多的口排最前
        self.assertEqual(sw["ports"][0]["port_name"], "GE0/1")
        self.assertEqual(sw["ports"][0]["device_count"], 2)
        # 明细带 IP / 主机名（从同一快照的设备表取）
        ips = {d["ip"] for d in sw["ports"][0]["devices"]}
        self.assertEqual(ips, {"10.0.0.11", "10.0.0.12"})

    def test_port_name_confidence_is_preserved(self):
        """桥接端口号（不确）必须原样带出 —— 展示层要据此加标注。"""
        sid = self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "sw", [
                _pm("AA:BB:CC:00:00:01", "GE0/1", real=True),
                _pm("AA:BB:CC:00:00:02", "Port 5", real=False),
            ]),
        ], db_path=self.db)
        u = history_store.port_utilization(db_path=self.db)
        sources = {p["port_name"]: p["port_source"] for p in u["switches"][0]["ports"]}
        self.assertEqual(sources["GE0/1"], history_store.PORT_SOURCE_IF_NAME)
        self.assertEqual(sources["Port 5"], history_store.PORT_SOURCE_BRIDGE_PORT)

    def test_empty_db_reports_no_snapshot(self):
        """空库 → no_snapshot（连设备都没见过），不是 no_switch_data。"""
        u = history_store.port_utilization(db_path=self.db)
        self.assertEqual(u["reason"], history_store.LOCATE_NO_SNAPSHOT)
        self.assertEqual(u["switches"], [])
        self.assertIsNone(u["snapshot_id"])

    def test_snapshot_without_switch_map_reports_no_switch_data(self):
        """🔴 有快照但没开 --switch-map → no_switch_data。

        这是**最常见**的情况（默认关），必须与「交换机一个口都没用」分开。
        """
        self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        u = history_store.port_utilization(db_path=self.db)
        self.assertEqual(u["reason"], history_store.LOCATE_NO_SWITCH_DATA)
        self.assertEqual(u["switches"], [])
        self.assertEqual(u["snapshot_id"], 1)

    def test_all_switches_failed_reports_scan_failed(self):
        """扫了但全失败 → switch_scan_failed，且失败原因仍可见（不隐藏故障）。"""
        sid = self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "sw-a", [], error="SNMP 超时"),
            _sw("10.0.0.3", "sw-b", [], error="community 拒绝"),
        ], db_path=self.db)
        u = history_store.port_utilization(db_path=self.db)
        self.assertEqual(u["reason"], history_store.LOCATE_SWITCH_SCAN_FAILED)
        self.assertEqual(len(u["switches"]), 2)
        self.assertTrue(all(s["status"] == "error" for s in u["switches"]))
        self.assertEqual({s["error"] for s in u["switches"]},
                         {"SNMP 超时", "community 拒绝"})

    def test_partial_failure_keeps_reason_empty_but_shows_error(self):
        """一台成功一台失败 → reason 为空（有数据），但失败那台照样列出。"""
        sid = self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "sw-ok", [_pm("AA:BB:CC:00:00:01", "GE0/1")]),
            _sw("10.0.0.3", "sw-bad", [], error="SNMP 超时"),
        ], db_path=self.db)
        u = history_store.port_utilization(db_path=self.db)
        self.assertEqual(u["reason"], "")
        self.assertEqual(len(u["switches"]), 2)
        self.assertEqual(u["switches"][0]["status"], "ok")   # ok 排前面
        self.assertEqual(u["switches"][1]["status"], "error")
        self.assertEqual(u["switches"][1]["error"], "SNMP 超时")

    def test_only_reads_the_latest_snapshot(self):
        """只统计**最近一次**快照 —— 端口会变，混着算毫无意义。"""
        sid1 = self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        history_store.save_port_map(sid1, [
            _sw("10.0.0.2", "sw", [_pm("AA:BB:CC:00:00:01", "GE0/1")]),
        ], db_path=self.db)
        sid2 = self._snap(2000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01"),
                                   _dev("10.0.0.12", mac="AA:BB:CC:00:00:02")])
        history_store.save_port_map(sid2, [
            _sw("10.0.0.2", "sw", [_pm("AA:BB:CC:00:00:01", "GE0/9"),
                                   _pm("AA:BB:CC:00:00:02", "GE0/9")]),
        ], db_path=self.db)

        u = history_store.port_utilization(db_path=self.db)
        self.assertEqual(u["snapshot_id"], sid2)
        self.assertEqual(u["switches"][0]["used_port_count"], 1)
        self.assertEqual(u["switches"][0]["ports"][0]["port_name"], "GE0/9")

    def test_does_not_invent_utilization_percent(self):
        """🔴 不编造「利用率 %」：转发表没有空闲口，物理口数无法从 FDB 得出。"""
        sid = self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "sw", [_pm("AA:BB:CC:00:00:01", "GE0/1")]),
        ], db_path=self.db)
        u = history_store.port_utilization(db_path=self.db)
        sw = u["switches"][0]
        self.assertNotIn("utilization", sw)
        self.assertNotIn("total_ports", sw)
        self.assertNotIn("free_ports", sw)
        self.assertEqual(sw["used_port_count"], 1)   # 只报下限

    def test_mac_matching_is_case_insensitive(self):
        """FDB 里的 MAC 大小写不定，明细要能对上设备表的 IP / 主机名。"""
        sid = self._snap(1000.0, [_dev("10.0.0.11", mac="aa:bb:cc:00:00:01",
                                       hostname="pc1")])
        history_store.save_port_map(sid, [
            _sw("10.0.0.2", "sw", [_pm("AA:BB:CC:00:00:01", "GE0/1")]),
        ], db_path=self.db)
        u = history_store.port_utilization(db_path=self.db)
        dev = u["switches"][0]["ports"][0]["devices"][0]
        self.assertEqual(dev["ip"], "10.0.0.11")
        self.assertEqual(dev["hostname"], "pc1")

    def test_prune_cascades_to_port_data(self):
        """prune 掉旧快照后，利用率仍只反映剩下的那一次。"""
        sid1 = self._snap(1000.0, [_dev("10.0.0.11", mac="AA:BB:CC:00:00:01")])
        history_store.save_port_map(sid1, [
            _sw("10.0.0.2", "sw", [_pm("AA:BB:CC:00:00:01", "GE0/1")]),
        ], db_path=self.db)
        sid2 = self._snap(2000.0, [_dev("10.0.0.12", mac="AA:BB:CC:00:00:02")])
        history_store.save_port_map(sid2, [
            _sw("10.0.0.2", "sw", [_pm("AA:BB:CC:00:00:02", "GE0/2")]),
        ], db_path=self.db)
        history_store.prune(max_keep=1, db_path=self.db)

        u = history_store.port_utilization(db_path=self.db)
        self.assertEqual(u["snapshot_id"], sid2)
        self.assertEqual(u["switches"][0]["ports"][0]["port_name"], "GE0/2")
        self.assertEqual(u["switches"][0]["device_count"], 1)
