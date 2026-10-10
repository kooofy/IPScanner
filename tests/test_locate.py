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
