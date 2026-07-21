# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui_utils import _compare_snapshots


def _snap(devices, t=1000.0):
    return {"time": t, "devices": devices}


def _dev(ip, **kw):
    base = {"ip": ip, "status": "online", "mac": "", "hostname": "",
            "vendor": "", "device_class": "", "os_guess": "", "open_ports": "",
            "location": "", "user": "", "remark": ""}
    base.update(kw)
    return base


class TestCompareSnapshots(unittest.TestCase):
    def test_added(self):
        base = _snap([_dev("1.1.1.1")])
        target = _snap([_dev("1.1.1.1"), _dev("1.1.1.2")])
        diffs = _compare_snapshots(base, target)
        changes = {d["ip"]: d["change"] for d in diffs}
        self.assertEqual(changes.get("1.1.1.2"), "新增设备")

    def test_removed(self):
        base = _snap([_dev("1.1.1.1"), _dev("1.1.1.2")])
        target = _snap([_dev("1.1.1.1")])
        diffs = _compare_snapshots(base, target)
        changes = {d["ip"]: d["change"] for d in diffs}
        self.assertEqual(changes.get("1.1.1.2"), "消失设备")

    def test_status_change(self):
        base = _snap([_dev("1.1.1.1", status="online")])
        target = _snap([_dev("1.1.1.1", status="offline")])
        diffs = _compare_snapshots(base, target)
        self.assertTrue(
            any(d["change"] == "状态变更" and d["ip"] == "1.1.1.1" for d in diffs))

    def test_field_change(self):
        base = _snap([_dev("1.1.1.1", device_class="电脑")])
        target = _snap([_dev("1.1.1.1", device_class="打印机")])
        diffs = _compare_snapshots(base, target)
        self.assertTrue(any(d["change"] == "设备类型变更" for d in diffs))

    def test_backward_compat_missing_fields(self):
        # 旧快照缺新字段时不应报错
        base = {"time": 1.0, "devices": [{"ip": "1.1.1.1", "status": "online"}]}
        target = _snap([_dev("1.1.1.1", user="张三")])
        diffs = _compare_snapshots(base, target)
        self.assertTrue(any(d["change"] == "使用者变更" for d in diffs))


if __name__ == "__main__":
    unittest.main()
