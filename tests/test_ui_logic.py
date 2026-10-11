# -*- coding: utf-8 -*-
"""ui_logic 单元测试：覆盖从 MainWindow 提取的纯业务逻辑。

不依赖 PyQt5，可在纯 Python 环境运行。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ui_logic
from scanner.models import ScanResult
from conflict_detector import Conflict, SEVERITY_HIGH, SEVERITY_WARNING, SEVERITY_INFO


class TestIpMaskToSubnet(unittest.TestCase):
    def test_24_mask(self):
        net, prefix = ui_logic.ip_mask_to_subnet("192.168.1.100", "255.255.255.0")
        self.assertEqual(net, "192.168.1.0")
        self.assertEqual(prefix, 24)

    def test_16_mask(self):
        net, prefix = ui_logic.ip_mask_to_subnet("10.20.30.40", "255.255.0.0")
        self.assertEqual(net, "10.20.0.0")
        self.assertEqual(prefix, 16)

    def test_zero_mask(self):
        net, prefix = ui_logic.ip_mask_to_subnet("192.168.1.1", "0.0.0.0")
        self.assertEqual(net, "0.0.0.0")
        self.assertEqual(prefix, 0)

    def test_invalid_ip(self):
        self.assertEqual(ui_logic.ip_mask_to_subnet("invalid", "255.255.255.0"), (None, 0))

    def test_invalid_mask(self):
        self.assertEqual(ui_logic.ip_mask_to_subnet("192.168.1.1", "bad"), (None, 0))


class TestIsVirtualAdapterIp(unittest.TestCase):
    def test_apipa_link_local(self):
        self.assertTrue(ui_logic.is_virtual_adapter_ip("169.254.1.1"))

    def test_docker_range(self):
        self.assertTrue(ui_logic.is_virtual_adapter_ip("172.17.0.1"))
        self.assertTrue(ui_logic.is_virtual_adapter_ip("172.31.0.1"))

    def test_docker_boundary_excluded(self):
        self.assertFalse(ui_logic.is_virtual_adapter_ip("172.32.0.1"))
        self.assertFalse(ui_logic.is_virtual_adapter_ip("172.15.0.1"))

    def test_virtualbox_hostonly(self):
        self.assertTrue(ui_logic.is_virtual_adapter_ip("192.168.56.1"))

    def test_normal_private_not_virtual(self):
        self.assertFalse(ui_logic.is_virtual_adapter_ip("192.168.1.1"))
        self.assertFalse(ui_logic.is_virtual_adapter_ip("192.168.55.1"))
        self.assertFalse(ui_logic.is_virtual_adapter_ip("10.0.0.1"))

    def test_invalid_format(self):
        self.assertFalse(ui_logic.is_virtual_adapter_ip("1.2.3"))
        self.assertFalse(ui_logic.is_virtual_adapter_ip("abc.def.ghi.jkl"))


class TestSelectIdentificationTargets(unittest.TestCase):
    def setUp(self):
        self.results = [
            ScanResult(ip="1.1.1.1", status="online", os_guess="Windows"),
            ScanResult(ip="1.1.1.2", status="online", open_ports=[135, 445]),
            ScanResult(ip="1.1.1.3", status="online", os_guess="Linux/Unix"),
            ScanResult(ip="1.1.1.4", status="offline", os_guess="Windows"),
            ScanResult(ip="1.1.1.5", status="online", open_ports=[445]),
        ]

    def test_auto_select_windows_and_port_135_445(self):
        targets = ui_logic.select_identification_targets(self.results, None, "Windows")
        self.assertEqual(targets, ["1.1.1.1", "1.1.1.2", "1.1.1.5"])

    def test_auto_select_excludes_offline_and_non_windows(self):
        targets = ui_logic.select_identification_targets(self.results, None, "Windows")
        self.assertNotIn("1.1.1.3", targets)  # Linux
        self.assertNotIn("1.1.1.4", targets)  # offline

    def test_explicit_filters_to_online_only(self):
        targets = ui_logic.select_identification_targets(self.results, ["1.1.1.1", "1.1.1.4"], "Windows")
        self.assertEqual(targets, ["1.1.1.1"])

    def test_explicit_all_offline_returns_empty(self):
        targets = ui_logic.select_identification_targets(self.results, ["9.9.9.9"], "Windows")
        self.assertEqual(targets, [])

    def test_empty_results(self):
        self.assertEqual(ui_logic.select_identification_targets([], None, "Windows"), [])

    def test_port_135_alone_qualifies(self):
        results = [ScanResult(ip="2.2.2.2", status="online", open_ports=[135])]
        self.assertEqual(ui_logic.select_identification_targets(results, None, "Windows"), ["2.2.2.2"])


class TestCountScanStatus(unittest.TestCase):
    def test_mixed(self):
        results = [
            ScanResult(status="online"),
            ScanResult(status="offline"),
            ScanResult(status="online"),
            ScanResult(status="scanning"),
        ]
        s = ui_logic.count_scan_status(results)
        self.assertEqual(s, {"total": 4, "online": 2, "offline": 1, "unknown": 1})

    def test_empty(self):
        self.assertEqual(ui_logic.count_scan_status([]), {"total": 0, "online": 0, "offline": 0, "unknown": 0})

    def test_all_online(self):
        results = [ScanResult(status="online") for _ in range(3)]
        s = ui_logic.count_scan_status(results)
        self.assertEqual(s, {"total": 3, "online": 3, "offline": 0, "unknown": 0})


class TestFormatIdentifySummary(unittest.TestCase):
    def test_wmi_no_fail(self):
        self.assertEqual(
            ui_logic.format_identify_summary("WMI", 3, 0, 3, "权限/防火墙/非 Windows 等"),
            "WMI 识别完成：3 台，成功 3 台",
        )

    def test_wmi_with_fail(self):
        self.assertEqual(
            ui_logic.format_identify_summary("WMI", 2, 1, 3, "权限/防火墙/非 Windows 等"),
            "WMI 识别完成：3 台，成功 2 台，失败 1 台（权限/防火墙/非 Windows 等）",
        )

    def test_netbios_with_fail(self):
        self.assertEqual(
            ui_logic.format_identify_summary("NetBIOS", 1, 2, 3, "防火墙/非 Windows/未开放 137 等"),
            "NetBIOS 识别完成：3 台，成功 1 台，失败 2 台（防火墙/非 Windows/未开放 137 等）",
        )


class TestCountConflicts(unittest.TestCase):
    def _conf(self, sev):
        return Conflict(conflict_type="test", severity=sev, description="d")

    def test_mixed(self):
        conflicts = [
            self._conf(SEVERITY_HIGH),
            self._conf(SEVERITY_WARNING),
            self._conf(SEVERITY_HIGH),
            self._conf(SEVERITY_INFO),
        ]
        c = ui_logic.count_conflicts(conflicts)
        self.assertEqual(c, {"high": 2, "warning": 1, "info": 1})

    def test_empty(self):
        self.assertEqual(ui_logic.count_conflicts([]), {"high": 0, "warning": 0, "info": 0})


class TestBuildSnapshot(unittest.TestCase):
    def test_full_conversion(self):
        r = ScanResult(
            ip="1.1.1.1", status="online", mac="aa:bb:cc:dd:ee:ff",
            hostname="host1", vendor="Vendor", open_ports=[80, 443],
            os_guess="Windows", location="3F", user="admin", remark="note",
        )
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertEqual(snap["time"], 1000.0)
        d = snap["devices"][0]
        self.assertEqual(d["ip"], "1.1.1.1")
        self.assertEqual(d["status"], "online")
        self.assertEqual(d["mac"], "AA:BB:CC:DD:EE:FF")  # 大写
        self.assertEqual(d["hostname"], "host1")
        self.assertEqual(d["open_ports"], "80,443")  # 逗号拼接
        self.assertEqual(d["os_guess"], "Windows")
        self.assertEqual(d["location"], "3F")

    def test_empty_fields_filled(self):
        r = ScanResult(ip="1.1.1.2", status="offline")
        snap = ui_logic.build_snapshot([r], ts=2000.0)
        d = snap["devices"][0]
        self.assertEqual(d["mac"], "")
        self.assertEqual(d["open_ports"], "")
        self.assertEqual(d["hostname"], "")
        self.assertEqual(d["wmi_identified"], False)
        self.assertEqual(d["netbios_identified"], False)

    def test_multiple_devices(self):
        results = [ScanResult(ip="1.1.1.%d" % i, status="online") for i in range(3)]
        snap = ui_logic.build_snapshot(results, ts=0.0)
        self.assertEqual(len(snap["devices"]), 3)
        self.assertEqual([d["ip"] for d in snap["devices"]], ["1.1.1.0", "1.1.1.1", "1.1.1.2"])

    def test_ts_defaults_to_now(self):
        import time as _time
        before = _time.time()
        snap = ui_logic.build_snapshot([])
        after = _time.time()
        self.assertTrue(before <= snap["time"] <= after)
        self.assertEqual(snap["devices"], [])

    def test_tls_facts_are_carried_into_the_snapshot(self):
        """v1.9 #3：探到的证书事实要跟着快照落库。

        这条链路是 GUI 侧唯一的落库入口（`history_mixin._save_snapshot` →
        `build_snapshot` → `history_store.save_snapshot`）；漏了这一环，证书
        事实就永远进不了库，而风险列却照常显示 —— 最难查的那种"一半对"。
        """
        r = ScanResult(ip="10.0.0.9", status="online", open_ports=[443])
        r.tls_cert = {"cn": "router.local", "issuer_cn": "router.local",
                      "not_before": "2025-01-01T00:00:00",
                      "not_after": "2027-01-01T00:00:00",
                      "self_signed": True, "sig_alg": "sha256_rsa",
                      "key_alg": "rsa", "key_bits": 2048, "curve": ""}
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertEqual(dict(snap["devices"][0]["security_findings"]), {
            "tls_cn": "router.local",
            "tls_not_before": "2025-01-01T00:00:00",
            "tls_not_after": "2027-01-01T00:00:00",
            "tls_sig_alg": "sha256_rsa",
            "tls_key": "rsa/2048",
            "tls_self_signed": "1",
        })

    def test_no_certificate_means_no_key(self):
        """没探到证书时**不**给这个键 —— 消费方不该把"没探到"当成"探到但为空"。"""
        r = ScanResult(ip="10.0.0.10", status="online", open_ports=[80])
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertNotIn("security_findings", snap["devices"][0])

    def test_empty_certificate_means_no_key(self):
        r = ScanResult(ip="10.0.0.11", status="online")
        r.tls_cert = {}
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertNotIn("security_findings", snap["devices"][0])

    def test_result_without_the_attribute_is_tolerated(self):
        """老对象（或测试替身）没有 `tls_cert` 属性时不能炸。"""
        class _Bare:
            ip = "10.0.0.12"
            status = "online"
            mac = hostname = vendor = device_class = os_guess = ""
            open_ports = []
            location = user = remark = ""
            wmi_identified = netbios_identified = False
            wmi_manufacturer = wmi_model = wmi_serial = ""
            wmi_os = wmi_user = wmi_domain = ""
            netbios_name = netbios_workgroup = netbios_user = netbios_mac = ""

        snap = ui_logic.build_snapshot([_Bare()], ts=1000.0)
        self.assertNotIn("security_findings", snap["devices"][0])

    def test_responder_facts_are_carried_into_the_snapshot(self):
        """v1.9 #3 第二刀：名字响应器事实走**同一条**落库路径。

        与 TLS 一样，漏了 `build_snapshot` 这一环，风险列照常显示、库里却是空的。
        """
        r = ScanResult(ip="10.0.0.9", status="online")
        r.name_responder = {"llmnr": "ipscanner-a1b2c"}
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertEqual(dict(snap["devices"][0]["security_findings"]),
                         {"llmnr_responder": "ipscanner-a1b2c"})

    def test_tls_and_responder_facts_are_merged_into_one_key(self):
        """两者都探到时**合并**进同一个 `security_findings` —— 不是一个键各写一份。"""
        r = ScanResult(ip="10.0.0.9", status="online")
        r.tls_cert = {"cn": "router.local"}
        r.name_responder = {"nbns": "ipscanner-a1b2c"}
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertEqual(dict(snap["devices"][0]["security_findings"]),
                         {"tls_cn": "router.local",
                          "nbns_responder": "ipscanner-a1b2c"})

    def test_no_responder_means_no_key(self):
        r = ScanResult(ip="10.0.0.10", status="online")
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertNotIn("security_findings", snap["devices"][0])

    def test_empty_responder_means_no_key(self):
        r = ScanResult(ip="10.0.0.11", status="online")
        r.name_responder = {}
        snap = ui_logic.build_snapshot([r], ts=1000.0)
        self.assertNotIn("security_findings", snap["devices"][0])

    def test_result_without_the_responder_attribute_is_tolerated(self):
        """老对象没有 `name_responder` 属性时不能炸。"""
        class _Bare:
            ip = "10.0.0.13"
            status = "online"
            mac = hostname = vendor = device_class = os_guess = ""
            open_ports = []
            location = user = remark = ""
            wmi_identified = netbios_identified = False
            wmi_manufacturer = wmi_model = wmi_serial = ""
            wmi_os = wmi_user = wmi_domain = ""
            netbios_name = netbios_workgroup = netbios_user = netbios_mac = ""

        snap = ui_logic.build_snapshot([_Bare()], ts=1000.0)
        self.assertNotIn("security_findings", snap["devices"][0])


if __name__ == "__main__":
    unittest.main()