# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mac_library import MacLibrary


class TestMacLibrary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "mac_library.db")
        self.lib = MacLibrary(self.db)

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def test_add_and_get(self):
        self.lib.add(ip="1.1.1.1", mac="AA:BB:CC:DD:EE:FF", device_type="电脑")
        rows = self.lib.get_all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["device_type"], "电脑")
        # normalize_mac 会将 MAC 归一化为小写
        self.assertEqual(rows[0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_upsert_by_mac(self):
        self.lib.add(ip="1.1.1.1", mac="AA:BB:CC:DD:EE:FF", device_type="电脑")
        self.lib.add(ip="1.1.1.1", mac="AA:BB:CC:DD:EE:FF", device_type="服务器")
        rows = self.lib.get_all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["device_type"], "服务器")


if __name__ == "__main__":
    unittest.main()
