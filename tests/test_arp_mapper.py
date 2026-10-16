# -*- coding: utf-8 -*-
"""跨网段补齐 MAC 的接入层（`arp_mapper.py`）测试。

不碰真实网络：SNMP 的四个入口（v2c / v3 的 get_system 与 walk）全部打桩。
这样才测得到"设备不回话""只支持二层""v3 凭据写错"这些**分支**——真机
上很难凑齐这些条件。

覆盖点，按重要性排序：
1. **读表失败绝不能升级成扫描失败** —— 它只该导致"补不到 MAC"；
2. **只补在线且 MAC 为空的设备** —— 把可能已老化的 MAC 挂到离线行上，
   会让台账把两台不同时期的设备当成同一台（MAC 就是身份键）；
3. **失败说明要能区分两种原因** —— "没开 SNMP"和"这是纯二层交换机"
   的下一步动作完全不同，混成一句会让人白折腾；
4. v3 凭据错**不回落** v2c（否则"密码写错"会被伪装成"不支持 SNMP"）；
5. 探测不到默认网关时**不猜**「本机网段 .1」。

断言与语言无关：只比 MAC / 计数 / 布尔 / 来源规范值。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import arp_mapper  # noqa: E402
from scanner import ScanResult  # noqa: E402
from scanner import arp_mib  # noqa: E402

_MEDIA = arp_mib.OID_NET_TO_MEDIA_PHYS
_PHYS = arp_mib.OID_NET_TO_PHYSICAL_PHYS
_MAC = "aa:bb:cc:11:22:33"


def _media_table(ip="10.193.24.12"):
    return {f"{_MEDIA}.101.{ip.replace('.', '.')}": (bytes.fromhex("aabbcc112233"), 0x04)}


class ApplyArpTableTest(unittest.TestCase):
    """回填规则：只动"在线 + MAC 为空"的行。"""

    def setUp(self):
        p = mock.patch.object(arp_mapper, "get_mac_vendor", return_value="ACME")
        p.start()
        self.addCleanup(p.stop)

    def test_fills_online_device_without_mac(self):
        r = ScanResult(ip="10.193.24.12", status="online")
        n = arp_mapper.apply_arp_table([r], {"10.193.24.12": _MAC})
        self.assertEqual(n, 1)
        self.assertEqual(r.mac, _MAC)
        self.assertEqual(r.vendor, "ACME")
        self.assertEqual(r.mac_source, arp_mapper.MAC_SOURCE_SNMP_ARP)
        self.assertTrue(r.mac_updated, "没打 mac_updated，UI 不会重渲染那一行")

    def test_offline_device_is_never_touched(self):
        """🔴 网关 ARP 表里的条目可能已老化。挂到"本次没扫到"的行上，
        会让台账把两台不同时期的设备当成同一台（MAC 是身份键）。"""
        r = ScanResult(ip="10.193.24.12", status="offline")
        n = arp_mapper.apply_arp_table([r], {"10.193.24.12": _MAC})
        self.assertEqual(n, 0)
        self.assertEqual(r.mac, "")
        self.assertEqual(r.mac_source, "")
        self.assertFalse(r.mac_updated)

    def test_existing_mac_is_never_overwritten(self):
        """本机 ARP / NBSTAT 拿到的 MAC 更接近"此刻"，不能被网关的表覆盖。"""
        r = ScanResult(ip="10.193.24.12", status="online", mac="11:22:33:44:55:66")
        n = arp_mapper.apply_arp_table([r], {"10.193.24.12": _MAC})
        self.assertEqual(n, 0)
        self.assertEqual(r.mac, "11:22:33:44:55:66")
        self.assertEqual(r.mac_source, "")

    def test_existing_vendor_is_kept(self):
        r = ScanResult(ip="10.193.24.12", status="online", vendor="原有厂商")
        arp_mapper.apply_arp_table([r], {"10.193.24.12": _MAC})
        self.assertEqual(r.vendor, "原有厂商")

    def test_ip_not_in_table_is_skipped(self):
        r = ScanResult(ip="10.193.24.99", status="online")
        self.assertEqual(arp_mapper.apply_arp_table([r], {"10.193.24.12": _MAC}), 0)
        self.assertEqual(r.mac, "")

    def test_discovery_method_is_not_reused(self):
        """`discovery_method` 的语义是"这台设备是怎么被发现的"，不能被 MAC 来源污染。"""
        r = ScanResult(ip="10.193.24.12", status="online",
                       discovery_method="ping")
        arp_mapper.apply_arp_table([r], {"10.193.24.12": _MAC})
        self.assertEqual(r.discovery_method, "ping")

    def test_empty_inputs_are_safe(self):
        self.assertEqual(arp_mapper.apply_arp_table([], {}), 0)
        self.assertEqual(arp_mapper.apply_arp_table(None, {"10.0.0.1": _MAC}), 0)

    def test_counts_only_what_it_filled(self):
        results = [
            ScanResult(ip="10.193.24.12", status="online"),
            ScanResult(ip="10.193.24.13", status="offline"),
            ScanResult(ip="10.193.24.14", status="online", mac="11:22:33:44:55:66"),
        ]
        entries = {"10.193.24.12": _MAC, "10.193.24.13": _MAC,
                   "10.193.24.14": _MAC}
        self.assertEqual(arp_mapper.apply_arp_table(results, entries), 1)


class DetectDefaultGatewayTest(unittest.TestCase):
    """默认网关探测：**只认真正的默认路由，绝不猜**。"""

    WIN_TABLE = (
        "===========================================================================\n"
        "IPv4 Route Table\n"
        "===========================================================================\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0     10.193.31.254     10.193.28.52     25\n"
        "        10.193.28.0    255.255.252.0         On-link      10.193.28.52    281\n"
    )

    def _run_with(self, text, system="Windows"):
        proc = mock.Mock()
        proc.stdout = text.encode("utf-8")
        with mock.patch.object(arp_mapper.platform, "system", return_value=system), \
                mock.patch.object(arp_mapper.subprocess, "run", return_value=proc):
            return arp_mapper.detect_default_gateway()

    def test_parses_the_default_route(self):
        self.assertEqual(self._run_with(self.WIN_TABLE), "10.193.31.254")

    def test_no_default_route_returns_empty_and_never_guesses(self):
        """🔴 只有网段路由时**不能**退化成「本机网段 .1」。

        猜出来的地址会静默查一台不相干的设备，然后把结果说成
        「网关不支持 SNMP」—— 比直接报"没检测到默认网关"难查得多。
        """
        only_subnet = (
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "        10.193.28.0    255.255.252.0         On-link      10.193.28.52    281\n"
        )
        self.assertEqual(self._run_with(only_subnet), "")

    def test_command_failure_returns_empty(self):
        with mock.patch.object(arp_mapper.platform, "system", return_value="Windows"), \
                mock.patch.object(arp_mapper.subprocess, "run",
                                  side_effect=OSError("no route")):
            self.assertEqual(arp_mapper.detect_default_gateway(), "")

    def test_is_ipv4_helper(self):
        self.assertTrue(arp_mapper._is_ipv4("10.0.0.1"))
        self.assertFalse(arp_mapper._is_ipv4("On-link"))
        self.assertFalse(arp_mapper._is_ipv4(""))
        self.assertFalse(arp_mapper._is_ipv4("fe80::1"))

    # ── POSIX 分支 ──
    #
    # ⚠ 本机是 Windows，不打桩 `platform.system` 就**永远走不到**这里 ⇒
    # 那段代码里写错了本机也测不出来，要等 CI 的 ubuntu job 才暴露。
    # 所以显式打桩跑一遍（并把 `_run_cmd` 换掉，不真的执行 ip/route 命令）。

    def _run_posix(self, text):
        with mock.patch.object(arp_mapper.platform, "system",
                               return_value="Linux"), \
                mock.patch("scanner.util._run_cmd", return_value=text):
            return arp_mapper.detect_default_gateway()

    def test_posix_ip_route_show_default(self):
        self.assertEqual(
            self._run_posix("default via 10.193.31.254 dev eth0 proto static\n"),
            "10.193.31.254")

    def test_posix_route_n_table(self):
        """`route -n` 的表格形式（老系统 / 精简镜像里往往只有它）。"""
        self.assertEqual(
            self._run_posix(
                "Kernel IP routing table\n"
                "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
                "\n"
                "0.0.0.0         10.193.31.254   0.0.0.0         UG    100    0        0 eth0\n"),
            "10.193.31.254")

    def test_posix_without_a_default_route_returns_empty(self):
        """只有链路路由时同样**不猜**。"""
        self.assertEqual(
            self._run_posix(
                "10.193.28.0/22 dev eth0 proto kernel scope link src 10.193.28.52\n"),
            "")


class FetchArpTableTest(unittest.TestCase):
    """`fetch_arp_table` 的各条分支 —— 全部靠打桩，不碰网络。"""

    def _patch(self, name, **kw):
        p = mock.patch.object(arp_mapper, name, **kw)
        p.start()
        self.addCleanup(p.stop)

    def _patch_walk(self, table_by_oid, calls=None):
        def _walk(ip, base_oid, **kwargs):
            if calls is not None:
                calls.append((base_oid, kwargs.get("community")))
            return dict(table_by_oid.get(base_oid, {}))

        self._patch("snmp_walk", side_effect=_walk)

    def test_happy_path_v2c(self):
        self._patch("snmp_get_system", return_value={"sys_name": "core-sw",
                                                     "sys_descr": "X"})
        self._patch_walk({_MEDIA: _media_table()})
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertTrue(res.ok)
        self.assertEqual(res.entries, {"10.193.24.12": _MAC})
        self.assertEqual(res.source, arp_mib.SOURCE_NET_TO_MEDIA)
        self.assertEqual(res.sys_name, "core-sw")
        self.assertEqual(res.error, "")

    def test_falls_back_to_rfc4293(self):
        self._patch("snmp_get_system", return_value={"sys_name": "core-sw"})
        self._patch_walk({
            _PHYS: {f"{_PHYS}.101.1.4.10.193.24.12.1":
                    (bytes.fromhex("aabbcc112233"), 0x04)},
        })
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertTrue(res.ok)
        self.assertEqual(res.source, arp_mib.SOURCE_NET_TO_PHYSICAL)

    def test_community_candidates_are_tried_in_order(self):
        self._patch("snmp_get_system", return_value={"sys_name": "core-sw"})
        calls = []
        # 只有第二个候选团体字有数据
        self._patch_walk({_MEDIA: _media_table()}, calls=calls)
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertTrue(res.ok)
        self.assertEqual(calls[0][1], "public", "第一个候选团体字没被先试")

    def test_no_response_says_snmp_is_not_answering(self):
        """设备完全不应答 → 说明必须指向"没开 SNMP / 团体字不对"。"""
        self._patch("snmp_get_system", return_value=None)
        self._patch_walk({})
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertFalse(res.ok)
        self.assertIn("SNMP", res.error)
        self.assertIn("161", res.error)

    def test_has_sysinfo_but_no_table_points_at_layer2(self):
        """🔴 能取到 sysDescr 却取不到 ARP 表 → 提示"可能是纯二层交换机"。

        这两种原因的下一步动作完全不同（换团体字 vs 换设备），
        混成一句会让用户在一台二层交换机上白试半天团体字。
        """
        self._patch("snmp_get_system", return_value={"sys_name": "sw-01"})
        self._patch_walk({})
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertFalse(res.ok)
        self.assertIn("BRIDGE-MIB", res.error)

    def test_walker_exception_never_propagates(self):
        """🔴 读表炸了也只该是"补不到 MAC"，**绝不能**让扫描失败。"""
        self._patch("snmp_get_system", return_value={"sys_name": "sw-01"})
        self._patch("snmp_walk", side_effect=RuntimeError("boom"))
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertFalse(res.ok)
        self.assertTrue(res.error)

    def test_sysinfo_exception_never_propagates(self):
        self._patch("snmp_get_system", side_effect=RuntimeError("boom"))
        self._patch("snmp_walk", return_value={})
        res = arp_mapper.fetch_arp_table("10.193.31.254")
        self.assertFalse(res.ok)

    # ── SNMPv3 分支 ──

    def test_v3_is_used_first(self):
        self._patch("snmp_v3_get_system", return_value={"sys_name": "v3sw"})
        self._patch("snmp_v3_walk", return_value={
            f"{_MEDIA}.101.10.193.24.12": (bytes.fromhex("aabbcc112233"), 0x04)})
        self._patch("snmp_walk", side_effect=AssertionError("不该回退 v2c"))
        res = arp_mapper.fetch_arp_table("10.193.31.254", snmp_v3_user=object())
        self.assertTrue(res.ok)
        self.assertEqual(res.sys_name, "v3sw")

    def test_v3_credential_error_does_not_fall_back(self):
        """🔴 凭据类错误不回落 v2c —— 否则"密码写错了"会被伪装成
        "这台设备不支持 SNMP"，用户会去查设备而不是查配置。"""
        self._patch("snmp_v3_get_system", return_value={
            "error": "auth failed", "error_kind": "auth"})
        self._patch("snmp_walk", side_effect=AssertionError("不该回退 v2c"))
        res = arp_mapper.fetch_arp_table("10.193.31.254", snmp_v3_user=object())
        self.assertFalse(res.ok)
        self.assertIn("SNMPv3", res.error)

    def test_v3_no_response_falls_back_to_v2c(self):
        from scanner.snmp_v3 import ERR_NO_RESPONSE
        self._patch("snmp_v3_get_system", return_value={
            "error": "timeout", "error_kind": ERR_NO_RESPONSE})
        self._patch("snmp_v3_walk", return_value={})
        self._patch("snmp_get_system", return_value={"sys_name": "v2sw"})
        self._patch_walk({_MEDIA: _media_table()})
        res = arp_mapper.fetch_arp_table("10.193.31.254", snmp_v3_user=object())
        self.assertTrue(res.ok)
        self.assertEqual(res.sys_name, "v2sw")

    def test_v3_walker_exception_never_propagates(self):
        """v3 的 walk 炸了同样只该是"补不到 MAC"（与 v2c 同一条底线）。"""
        self._patch("snmp_v3_get_system", return_value={"sys_name": "v3sw"})
        self._patch("snmp_v3_walk", side_effect=RuntimeError("boom"))
        self._patch("snmp_walk", return_value={})
        res = arp_mapper.fetch_arp_table("10.193.31.254", snmp_v3_user=object())
        self.assertFalse(res.ok)
        self.assertTrue(res.error)

    # ── 进度回调 ──

    def test_progress_callback_is_invoked(self):
        """进度回调必须真的被调用 —— 界面靠它显示"正在读网关 ARP 表"。

        ⚠ 断言用 `tr()` 推导而不是中文字面量：CI 的 locale 是 en-US，
        `i18n.init(None)` 在那边解析成英文，写死中文会本地绿、CI 红。
        """
        from i18n import tr
        self._patch("snmp_get_system", return_value={"sys_name": "sw-01"})
        self._patch_walk({_MEDIA: _media_table()})
        msgs = []
        res = arp_mapper.fetch_arp_table("10.193.31.254", progress_cb=msgs.append)
        self.assertTrue(res.ok)
        self.assertIn(tr("正在读取网关 ARP 表..."), msgs)
        self.assertIn(tr("ARP 表读取完成：{n} 条").format(n=1), msgs)

    def test_missing_progress_callback_is_tolerated(self):
        """没传回调时不能炸（CLI / 测试都靠这条）。"""
        self._patch("snmp_get_system", return_value={"sys_name": "sw-01"})
        self._patch_walk({_MEDIA: _media_table()})
        self.assertTrue(arp_mapper.fetch_arp_table("10.193.31.254").ok)


class LabelTest(unittest.TestCase):
    """来源显示名：规范值 → 文案；未知值原样透出（不吞、不猜）。"""

    def setUp(self):
        import i18n
        self._orig = i18n.current_lang()
        i18n.init("zh-CN")
        self.addCleanup(lambda: i18n.init(self._orig))

    def test_mac_source_label(self):
        self.assertEqual(arp_mapper.mac_source_label(""), "")
        self.assertTrue(arp_mapper.mac_source_label(arp_mapper.MAC_SOURCE_SNMP_ARP))
        self.assertEqual(arp_mapper.mac_source_label("weird"), "weird")

    def test_source_label(self):
        self.assertTrue(arp_mapper.source_label(arp_mib.SOURCE_NET_TO_MEDIA))
        self.assertTrue(arp_mapper.source_label(arp_mib.SOURCE_NET_TO_PHYSICAL))
        self.assertEqual(arp_mapper.source_label(""), "")

    def test_source_values_are_language_independent(self):
        """规范值绝不能是中文 —— 它们会被写进结果对象与 JSON。"""
        for val in (arp_mapper.MAC_SOURCE_SNMP_ARP, arp_mib.SOURCE_NET_TO_MEDIA,
                    arp_mib.SOURCE_NET_TO_PHYSICAL, arp_mapper.GATEWAY_AUTO):
            self.assertTrue(all(ord(ch) < 128 for ch in val), val)


if __name__ == "__main__":
    unittest.main()
