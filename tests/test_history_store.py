# -*- coding: utf-8 -*-
import json
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


class TestHistoryStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _save_two(self):
        history_store.save_snapshot([_dev("1.1.1.1", mac="AA:BB")], ts=1000.0, db_path=self.db)
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB", user="李四"), _dev("1.1.1.2")],
            ts=2000.0, db_path=self.db)

    def test_roundtrip(self):
        self._save_two()
        all_snaps = history_store.load_all(self.db)
        self.assertEqual(len(all_snaps), 2)
        self.assertEqual(all_snaps[0]["time"], 1000.0)
        self.assertEqual(len(all_snaps[1]["devices"]), 2)
        self.assertEqual(all_snaps[1]["devices"][1]["ip"], "1.1.1.2")

    def test_device_fields_preserved(self):
        history_store.save_snapshot(
            [_dev("1.1.1.1", open_ports="80,443", device_class="打印机")], db_path=self.db)
        snap = history_store.load_all(self.db)[0]
        d = snap["devices"][0]
        self.assertEqual(d["open_ports"], "80,443")
        self.assertEqual(d["device_class"], "打印机")

    def test_list_snapshots_meta(self):
        self._save_two()
        metas = history_store.list_snapshots(self.db)
        self.assertEqual([m["device_count"] for m in metas], [1, 2])
        self.assertEqual(metas[0]["time"], 1000.0)

    def test_get_snapshot(self):
        sid = history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        snap = history_store.get_snapshot(sid, self.db)
        self.assertEqual(snap["devices"][0]["ip"], "1.1.1.1")
        self.assertIsNone(history_store.get_snapshot(99999, self.db))

    def test_prune_keeps_recent(self):
        for i in range(25):
            history_store.save_snapshot([_dev("1.1.1.%d" % (i % 250))],
                                        db_path=self.db, max_keep=20)
        self.assertEqual(len(history_store.list_snapshots(self.db)), 20)

    def test_migrate_from_json_idempotent(self):
        json_path = os.path.join(self.tmp, "scan_history.json")
        data = [
            {"time": 1.0, "devices": [_dev("1.1.1.1")]},
            {"time": 2.0, "devices": [_dev("1.1.1.1", user="王五"), _dev("1.1.1.2")]},
        ]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        self.assertEqual(history_store.migrate_from_json(json_path, self.db), 2)
        self.assertEqual(len(history_store.load_all(self.db)), 2)
        # 再次迁移应为 0（已存在快照，幂等）
        self.assertEqual(history_store.migrate_from_json(json_path, self.db), 0)


if __name__ == "__main__":
    unittest.main()
