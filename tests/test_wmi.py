# -*- coding: utf-8 -*-
"""WMI 设备识别单元测试（不依赖真实 PowerShell / 远程主机）。"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.wmi import wmi_query, wmi_device_class, merge_wmi, _error_dict
from scanner.models import ScanResult
from scanner.cred_store import WmiCredentialStore, _HAS_DPAPI


class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


_OK_JSON = json.dumps({
    "ok": True,
    "ComputerSystem": {
        "Manufacturer": "Dell Inc.", "Model": "OptiPlex 7080",
        "Domain": "CORP", "UserName": "CORP\\alice", "Name": "PC01",
        "TotalPhysicalMemory": 17179869184,
    },
    "BIOS": {"SerialNumber": "ABC123", "SMBIOSBIOSVersion": "1.2.3"},
    "OS": {
        "Caption": "Microsoft Windows 11 专业版", "Version": "10.0.22631",
        "OSArchitecture": "64-bit", "LastBootUpTime": "20260721080000.000000+480",
    },
    "CPU": {"Name": "Intel(R) Core(TM) i7", "NumberOfCores": 8},
})


class TestWmiDeviceClass(unittest.TestCase):
    def test_pc_vendor(self):
        self.assertEqual(wmi_device_class("Dell Inc.", "OptiPlex 7080"), "电脑")
        self.assertEqual(wmi_device_class("Lenovo", "ThinkCentre M70"), "电脑")
        self.assertEqual(wmi_device_class("Hewlett-Packard", "EliteDesk"), "电脑")

    def test_server_keyword(self):
        self.assertEqual(wmi_device_class("Dell Inc.", "PowerEdge R740"), "服务器")
        self.assertEqual(wmi_device_class("", "ProLiant DL380 Gen10"), "服务器")

    def test_unknown(self):
        self.assertEqual(wmi_device_class("Cisco", "C2960"), "")
        self.assertEqual(wmi_device_class("", ""), "")


class TestWmiQueryParse(unittest.TestCase):
    @mock.patch("scanner.wmi.subprocess.run", return_value=_FakeProc(stdout=_OK_JSON))
    def test_parse_success(self, _m):
        d = wmi_query("10.0.0.5", "admin", "pwd", domain="CORP")
        self.assertEqual(d["wmi_error"], "")
        self.assertEqual(d["wmi_manufacturer"], "Dell Inc.")
        self.assertEqual(d["wmi_model"], "OptiPlex 7080")
        self.assertEqual(d["wmi_serial"], "ABC123")
        self.assertIn("Windows 11", d["wmi_os"])
        self.assertEqual(d["wmi_os_version"], "10.0.22631")
        self.assertEqual(d["wmi_user"], "CORP\\alice")
        self.assertEqual(d["wmi_domain"], "CORP")
        self.assertEqual(d["wmi_cpu"], "Intel(R) Core(TM) i7")
        self.assertAlmostEqual(d["wmi_ram_gb"], 16.0, places=1)
        self.assertEqual(d["wmi_last_boot"], "2026-07-21 08:00:00")

    def test_missing_creds(self):
        d = wmi_query("", "admin", "pwd")
        self.assertTrue(d["wmi_error"])
        d2 = wmi_query("1.2.3.4", "", "")
        self.assertTrue(d2["wmi_error"])

    @mock.patch("scanner.wmi.subprocess.run",
                return_value=_FakeProc(stdout="", stderr="boom", returncode=1))
    def test_no_output(self, _m):
        d = wmi_query("10.0.0.6", "admin", "pwd")
        self.assertTrue(d["wmi_error"])

    @mock.patch("scanner.wmi.subprocess.run",
                side_effect=_FakeProc())  # 用 AttributeError 模拟 timeout 较繁，这里用 return_value
    def test_empty_object_treated_as_error(self, _m):
        # PowerShell 返回 ok=true 但各字段为空对象 -> flatten 判为空
        empty = json.dumps({
            "ok": True, "ComputerSystem": {}, "BIOS": {}, "OS": {}, "CPU": {},
        })
        _m.return_value = _FakeProc(stdout=empty)
        d = wmi_query("10.0.0.7", "admin", "pwd")
        self.assertTrue(d["wmi_error"])


class TestMergeWmi(unittest.TestCase):
    def test_merge_success(self):
        r = ScanResult(ip="10.0.0.5")
        d = {
            "wmi_manufacturer": "Dell Inc.", "wmi_model": "OptiPlex 7080",
            "wmi_serial": "ABC123", "wmi_os": "Microsoft Windows 11 专业版",
            "wmi_user": "CORP\\alice", "wmi_domain": "CORP", "wmi_ram_gb": 16.0,
            "wmi_error": "",
        }
        merge_wmi(r, d)
        self.assertTrue(r.wmi_identified)
        self.assertEqual(r.wmi_manufacturer, "Dell Inc.")
        self.assertEqual(r.device_model, "OptiPlex 7080")
        self.assertEqual(r.device_class, "电脑")

    def test_merge_error(self):
        r = ScanResult(ip="10.0.0.8", device_class="路由器")
        merge_wmi(r, _error_dict("权限不足"))
        self.assertFalse(r.wmi_identified)
        # 原指纹不被覆盖
        self.assertEqual(r.device_class, "路由器")

    def test_merge_keeps_existing_model(self):
        r = ScanResult(ip="10.0.0.9", device_model="HP LaserJet M104w")
        merge_wmi(r, {"wmi_model": "OptiPlex 7080", "wmi_error": ""})
        self.assertEqual(r.device_model, "HP LaserJet M104w")


class TestCredStore(unittest.TestCase):
    def test_memory_only(self):
        store = WmiCredentialStore()
        self.assertFalse(store.has_creds())
        store.set("admin", "s3cret", "CORP")
        self.assertTrue(store.has_creds())
        self.assertEqual(store.username, "admin")
        self.assertEqual(store.password, "s3cret")
        self.assertEqual(store.domain, "CORP")

    @unittest.skipIf(not _HAS_DPAPI, "非 Windows 平台无 DPAPI，跳过加密往返测试")
    def test_dpapi_roundtrip(self):
        import tempfile, os
        from PyQt5.QtCore import QSettings
        fd, path = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        try:
            s1 = QSettings(path, QSettings.IniFormat)
            store = WmiCredentialStore()
            store.set("admin", "s3cret", "CORP")
            store.save_to(s1)
            s1.sync()

            s2 = QSettings(path, QSettings.IniFormat)
            loaded = WmiCredentialStore()
            loaded.load_from(s2)
            self.assertTrue(loaded.has_creds())
            self.assertEqual(loaded.password, "s3cret")
            self.assertEqual(loaded.username, "admin")
            self.assertEqual(loaded.domain, "CORP")
            # ini 中不应出现明文密码
            with open(path, encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("s3cret", content)
        finally:
            os.remove(path)

    @unittest.skipIf(not _HAS_DPAPI, "非 Windows 平台无 DPAPI")
    def test_dpapi_encrypt_decrypt(self):
        from scanner.cred_store import _protect, _unprotect
        blob = _protect("hello")
        self.assertIsInstance(blob, bytes)
        self.assertEqual(_unprotect(blob), "hello")


if __name__ == "__main__":
    unittest.main()
