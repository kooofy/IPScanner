# -*- coding: utf-8 -*-
"""历史条件查询（query_history）单元测试。

覆盖：跨快照首见/末见推导、最新属性优先、类型/网段/IP/首见时间过滤、排序、组合过滤。
使用临时文件 DB，避免污染项目内 scan_history.db。
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history_store


def _dev(ip, **kw):
    base = {"ip": ip, "status": "online", "mac": "", "hostname": "",
            "vendor": "", "device_class": "", "os_guess": "", "open_ports": "",
            "location": "", "user": "", "remark": ""}
    base.update(kw)
    return base


def _save_many(snapshots, db):
    """snapshots: list of (ts, [device_dicts])；max_keep 抬高避免裁剪。"""
    for ts, devs in snapshots:
        history_store.save_snapshot(devs, ts=ts, db_path=db, max_keep=10 ** 9)


class TestHistoryQuery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import shutil
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty(self):
        self.assertEqual(history_store.query_history(db_path=self.db), [])

    def test_first_last_seen(self):
        _save_many([
            (1000.0, [_dev("192.168.1.10", device_class="PC")]),
            (2000.0, [_dev("192.168.1.10", device_class="PC")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        self.assertEqual(len(res), 1)
        self.assertAlmostEqual(res[0]["first_seen"], 1000.0)
        self.assertAlmostEqual(res[0]["last_seen"], 2000.0)

    def test_latest_nonempty_attr_wins(self):
        _save_many([
            (1000.0, [_dev("10.0.0.5", device_class="路由器", hostname="gw-old")]),
            (2000.0, [_dev("10.0.0.5", device_class="路由", hostname="gw-new", status="offline")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        self.assertEqual(res[0]["hostname"], "gw-new")
        self.assertEqual(res[0]["status"], "offline")
        self.assertEqual(res[0]["device_class"], "路由")

    def test_filter_device_class_substr(self):
        _save_many([
            (1000.0, [
                _dev("192.168.1.10", device_class="PC"),
                _dev("192.168.1.1", device_class="路由器"),
                _dev("192.168.1.20", device_class="打印机"),
            ]),
        ], self.db)
        res = history_store.query_history(device_class="路由", db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.1"])

    def test_filter_network_cidr(self):
        _save_many([
            (1000.0, [
                _dev("192.168.1.10", device_class="PC"),
                _dev("10.0.0.5", device_class="路由器"),
            ]),
        ], self.db)
        res = history_store.query_history(network="192.168.1.0/24", db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.10"])

    def test_filter_network_invalid_treated_as_no_filter(self):
        _save_many([(1000.0, [_dev("192.168.1.10")])], self.db)
        res = history_store.query_history(network="not-a-net", db_path=self.db)
        self.assertEqual(len(res), 1)

    def test_filter_ip_substr(self):
        _save_many([
            (1000.0, [
                _dev("192.168.1.10"),
                _dev("192.168.1.20"),
                _dev("10.0.0.5"),
            ]),
        ], self.db)
        res = history_store.query_history(ip_substr="192.168.1.2", db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.20"])

    def test_filter_first_seen_after(self):
        _save_many([
            (1000.0, [_dev("192.168.1.1")]),
            (5000.0, [_dev("192.168.1.2")]),
        ], self.db)
        res = history_store.query_history(first_seen_after=3000.0, db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.2"])

    def test_filter_first_seen_before(self):
        _save_many([
            (1000.0, [_dev("192.168.1.1")]),
            (5000.0, [_dev("192.168.1.2")]),
        ], self.db)
        res = history_store.query_history(first_seen_before=3000.0, db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.1"])

    def test_sort_by_last_seen_desc(self):
        _save_many([
            (1000.0, [_dev("192.168.1.1")]),
            (3000.0, [_dev("192.168.1.2")]),
            (2000.0, [_dev("192.168.1.3")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        self.assertEqual(
            [r["ip"] for r in res],
            ["192.168.1.2", "192.168.1.3", "192.168.1.1"]
        )

    def test_combined_filters(self):
        _save_many([
            (1000.0, [_dev("192.168.1.10", device_class="PC")]),
            (5000.0, [_dev("192.168.1.20", device_class="路由器")]),
            (2000.0, [_dev("10.0.0.5", device_class="路由器")]),
        ], self.db)
        res = history_store.query_history(
            device_class="路由", network="192.168.1.0/24",
            first_seen_after=3000.0, db_path=self.db,
        )
        self.assertEqual([r["ip"] for r in res], ["192.168.1.20"])

    def test_disappeared_device_still_listed(self):
        # 设备只在早期快照出现，后期消失，首见/末见应锁定其活跃区间
        _save_many([
            (1000.0, [_dev("192.168.1.99", device_class="PC")]),
            (2000.0, [_dev("192.168.1.1")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        ips = [r["ip"] for r in res]
        self.assertIn("192.168.1.99", ips)
        rec = next(r for r in res if r["ip"] == "192.168.1.99")
        self.assertAlmostEqual(rec["first_seen"], 1000.0)
        self.assertAlmostEqual(rec["last_seen"], 1000.0)


if __name__ == "__main__":
    unittest.main()
