# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.classify import infer_device
from scanner.models import ScanResult


def mk(**kw):
    return ScanResult(**kw)


class TestClassifyPhoneRecognition(unittest.TestCase):
    # 方案 A：mDNS Continuity 信号识别 Apple 移动设备（MAC 随机化时 OUI 不可查）
    def test_mdns_companion_link_is_phone(self):
        r = mk(service_details=[{"proto": "mDNS", "banner": "_companion-link._tcp.local"}])
        cls, model = infer_device(r)
        self.assertEqual(cls, "手机")
        self.assertIn("Apple", model)

    def test_mdns_airdrop_is_phone(self):
        r = mk(service_details=[{"proto": "mDNS", "banner": "_airdrop._tcp.local"}])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    def test_mdns_airplay_only_is_media_not_phone(self):
        # 仅有 airplay（无 companion-link）保持「媒体设备」，避免误把投屏当手机
        r = mk(service_details=[{"proto": "mDNS", "banner": "_airplay._tcp.local"}])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "媒体设备")

    def test_mdns_companion_overrides_airplay(self):
        # 同时有 airplay 和 companion-link 时，移动设备优先级更高
        r = mk(service_details=[{"proto": "mDNS",
                                 "banner": "_airplay._tcp.local,_companion-link._tcp.local"}])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    # 已有逻辑：OUI 厂商关键字命中且无 PC/TV 信号
    def test_oui_phone_keyword_no_signals_is_phone(self):
        r = mk(vendor="Apple", open_ports=[])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    def test_oui_phone_keyword_with_smb_is_not_phone(self):
        # OUI 命中手机但开放 445 → 视为 PC/服务器信号，不判手机
        r = mk(vendor="Apple", open_ports=[445])
        cls, _ = infer_device(r)
        self.assertNotEqual(cls, "手机")

    # 方案 B：随机 MAC（vendor 空）+ 无开放端口 + Linux/Unix TTL → 手机/IoT
    def test_random_mac_linux_no_ports_is_mobile_iot(self):
        r = mk(vendor="", os_guess="Linux/Unix", open_ports=[], hostname="")
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机/IoT")

    def test_linux_with_ssh_port_still_linux_device(self):
        # 有 22 端口说明可能有 SSH 服务，保留「Linux 设备」而非手机/IoT
        r = mk(vendor="", os_guess="Linux/Unix", open_ports=[22], hostname="")
        cls, _ = infer_device(r)
        self.assertIn("Linux 设备", cls)

    def test_random_mac_linux_pc_hostname_not_mobile(self):
        # 主机名含 server 等 PC 信号，不应归手机/IoT
        r = mk(vendor="", os_guess="Linux/Unix", open_ports=[], hostname="nas-server")
        cls, _ = infer_device(r)
        self.assertNotIn("手机", cls)

    # 方案 A 补充：主机名含手机品牌关键字
    def test_hostname_iphone_is_phone(self):
        r = mk(vendor="", hostname="iphone-12", os_guess="Linux/Unix", open_ports=[])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    def test_hostname_galaxy_is_phone(self):
        r = mk(vendor="", hostname="galaxy-s21", os_guess="Linux/Unix", open_ports=[])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    def test_hostname_xiaomi_is_phone(self):
        r = mk(vendor="", hostname="xiaomi-redmi", os_guess="Linux/Unix", open_ports=[])
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    # 回归：Windows 仍正确
    def test_windows_os_guess(self):
        r = mk(vendor="", os_guess="Windows", open_ports=[])
        cls, _ = infer_device(r)
        self.assertIn("Windows", cls)

    # 回归：真正 Linux 服务器（有 22 + 主机名带 server）保持准确
    def test_real_linux_server(self):
        r = mk(vendor="", os_guess="Linux/Unix", open_ports=[22, 80], hostname="web-server")
        cls, _ = infer_device(r)
        self.assertIn("Linux 设备", cls)

    # ── A 增强：已知 IoT/家电厂商不应误报为「手机/IoT」 ──
    def test_roborock_vendor_is_smart_home_not_mobile(self):
        # 石头扫地机器人：vendor 已知 + Linux/Unix + 无端口，应判智能家居/IoT
        r = mk(vendor="Beijing Roborock Technology", os_guess="Linux/Unix",
               open_ports=[], hostname="")
        cls, _ = infer_device(r)
        self.assertEqual(cls, "智能家居/IoT")

    def test_iot_vendor_linux_no_ports_is_smart_home(self):
        r = mk(vendor="Xiaomi Communications Co Ltd", os_guess="Linux/Unix",
               open_ports=[], hostname="")
        # 小米同时是手机厂商；无 PC/TV 信号时应判「手机」而非智能家居/IoT
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机")

    def test_iot_network_vendor_linux_no_ports_is_smart_home(self):
        # TP-Link 等网络/IoT 厂商：vendor 已知 + 无端口 → 智能家居/IoT
        r = mk(vendor="TP-Link Corporation", os_guess="Linux/Unix",
               open_ports=[], hostname="")
        cls, _ = infer_device(r)
        self.assertEqual(cls, "智能家居/IoT")

    def test_random_mac_linux_no_ports_without_iot_vendor_still_mobile_iot(self):
        # vendor 为空（随机 MAC、OUI 查不到）仍走「手机/IoT」兜底
        r = mk(vendor="", os_guess="Linux/Unix", open_ports=[], hostname="")
        cls, _ = infer_device(r)
        self.assertEqual(cls, "手机/IoT")


if __name__ == "__main__":
    unittest.main()
