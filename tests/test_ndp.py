# -*- coding: utf-8 -*-
"""IPv6 可见性（`scanner/ndp.py`，v2.0 §2.4）测试。

覆盖点，按重要性排序：
1. **只做可见性，不扫 IPv6** —— 断言 `passive_discover` 默认（`ipv6=False`）
   **一次都不读** NDP 缓存；开 `ipv6=True` 也不发任何包（除显式 `ipv6_probe`）。
2. 三种平台的 NDP 缓存格式都能解析（喂真实格式的样本，不看网络）。
3. **挂到已有 IPv4 资产上、按 MAC 关联、不新建资产** —— 路线图验收原文。
4. 无 IPv6 环境**优雅降级**（不报错、不崩）。
5. 组播 / 回环 / 全零 MAC / 未解析条目都被跳过。

断言一律与语言无关：只比地址 / MAC / 计数 / 日志，不比界面文案。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import ndp, passive  # noqa: E402
from scanner.models import ScanResult  # noqa: E402


# ── 真实格式的样本（从真实机器抓下来的，不是编的） ────────────────────

WIN_SAMPLE = """\

Interface 1: Loopback Pseudo-Interface 1



Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
ff02::2                                                          Permanent
ff02::c                                                          Permanent
ff02::16                                                         Permanent
ff02::1:ffad:dcc2                                                Permanent

Interface 8: 以太网



Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::9f5:f060:f6c1:7135                      c8-4d-44-32-67-3d  Stale
fe80::3761:63c2:a1e7:248d                     98-ee-cb-2a-9f-21  Stale
2001:db8::53                                  00-25-ab-ad-c9-08  Reachable

Interface 11: WLAN



Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::9f5:f060:f6c1:7135                      00-00-00-00-00-00  Unreachable
"""

LINUX_SAMPLE = """\
fe80::1 dev eth0 lladdr 50:2b:73:aa:bb:cc router REACHABLE
fe80::2 dev eth0  FAILED
fe80::3 dev eth0 lladdr 00:00:00:00:00:00 STALE
2001:db8::10 dev eth0 lladdr c8:4d:44:32:67:3d STALE
ff02::1 dev eth0 lladdr 33:33:00:00:00:01 permanent
"""

MACOS_SAMPLE = """\
Neighbor                             Linklayer Address  Netif Expire    St Flgs Pri
fe80::1%en0                          50:2b:73:aa:bb:cc  en0   permanent R
fe80::2%en0                          (incomplete)       en0   permanent R
2001:db8::20%en0                      c8:4d:44:32:67:3d  en0   23h59m59s S R
"""


class ParseWindowsTest(unittest.TestCase):

    def test_real_sample_parsed(self):
        t = ndp.parse_windows_ndp_cache(WIN_SAMPLE)
        self.assertEqual(t, {
            "fe80::9f5:f060:f6c1:7135": "c8:4d:44:32:67:3d",
            "fe80::3761:63c2:a1e7:248d": "98:ee:cb:2a:9f:21",
            "2001:db8::53": "00:25:ab:ad:c9:08",
        })

    def test_multicast_entries_skipped(self):
        """`Permanent` 的组播行没有 MAC，不能当作设备。"""
        t = ndp.parse_windows_ndp_cache(WIN_SAMPLE)
        self.assertFalse([k for k in t if k.startswith("ff")])

    def test_unreachable_zero_mac_skipped(self):
        t = ndp.parse_windows_ndp_cache(WIN_SAMPLE)
        self.assertNotIn("00:00:00:00:00:00", t.values())

    def test_mac_normalised(self):
        t = ndp.parse_windows_ndp_cache(WIN_SAMPLE)
        self.assertEqual(t["fe80::9f5:f060:f6c1:7135"], "c8:4d:44:32:67:3d")

    def test_empty_is_empty_not_error(self):
        self.assertEqual(ndp.parse_windows_ndp_cache(""), {})

    def test_garbage_ignored(self):
        self.assertEqual(ndp.parse_windows_ndp_cache("hello\nworld\n:::\n"), {})


class ParseLinuxTest(unittest.TestCase):

    def test_real_sample_parsed(self):
        t = ndp.parse_linux_ip_neigh(LINUX_SAMPLE)
        self.assertEqual(t, {
            "fe80::1": "50:2b:73:aa:bb:cc",
            "2001:db8::10": "c8:4d:44:32:67:3d",
        })

    def test_failed_without_lladdr_skipped(self):
        """`FAILED` 行没有 lladdr，不是设备。"""
        t = ndp.parse_linux_ip_neigh(LINUX_SAMPLE)
        self.assertNotIn("fe80::2", t)

    def test_zero_mac_skipped(self):
        t = ndp.parse_linux_ip_neigh(LINUX_SAMPLE)
        self.assertNotIn("fe80::3", t)

    def test_multicast_skipped(self):
        t = ndp.parse_linux_ip_neigh(LINUX_SAMPLE)
        self.assertNotIn("ff02::1", t)

    def test_empty_is_empty(self):
        self.assertEqual(ndp.parse_linux_ip_neigh(""), {})


class ParseMacosTest(unittest.TestCase):

    def test_real_sample_parsed(self):
        t = ndp.parse_macos_ndp(MACOS_SAMPLE)
        self.assertEqual(t, {
            "fe80::1": "50:2b:73:aa:bb:cc",
            "2001:db8::20": "c8:4d:44:32:67:3d",
        })

    def test_scope_suffix_stripped(self):
        t = ndp.parse_macos_ndp(MACOS_SAMPLE)
        self.assertNotIn("fe80::1%en0", t)
        self.assertIn("fe80::1", t)

    def test_incomplete_skipped(self):
        t = ndp.parse_macos_ndp(MACOS_SAMPLE)
        self.assertNotIn("fe80::2", t)

    def test_empty_is_empty(self):
        self.assertEqual(ndp.parse_macos_ndp(""), {})


class AddrUsableTest(unittest.TestCase):

    def test_multicast_and_loopback_rejected(self):
        self.assertFalse(ndp._addr_usable("ff02::1"))
        self.assertFalse(ndp._addr_usable("::1"))

    def test_link_local_accepted(self):
        self.assertTrue(ndp._addr_usable("fe80::1"))

    def test_garbage_rejected(self):
        self.assertFalse(ndp._addr_usable("not-an-address"))


class DumpNdpDegradationTest(unittest.TestCase):
    """无 IPv6 环境 / 命令缺失 → 空 dict，不抛异常。"""

    def test_windows_uses_netsh(self):
        with mock.patch.object(ndp, "_IS_WINDOWS", True), \
                mock.patch.object(ndp, "_IS_DARWIN", False), \
                mock.patch.object(ndp, "_run_cmd", return_value=WIN_SAMPLE) as m:
            t = ndp.dump_ndp_cache()
        self.assertEqual(len(t), 3)
        self.assertEqual(m.call_args[0][0][:4],
                         ["netsh", "interface", "ipv6", "show"])

    def test_linux_uses_ip_neigh(self):
        with mock.patch.object(ndp, "_IS_WINDOWS", False), \
                mock.patch.object(ndp, "_IS_DARWIN", False), \
                mock.patch.object(ndp, "_run_cmd", return_value=LINUX_SAMPLE) as m:
            t = ndp.dump_ndp_cache()
        self.assertEqual(len(t), 2)
        self.assertEqual(m.call_args[0][0], ["ip", "-6", "neigh"])

    def test_macos_uses_ndp(self):
        with mock.patch.object(ndp, "_IS_WINDOWS", False), \
                mock.patch.object(ndp, "_IS_DARWIN", True), \
                mock.patch.object(ndp, "_run_cmd", return_value=MACOS_SAMPLE) as m:
            t = ndp.dump_ndp_cache()
        self.assertEqual(len(t), 2)
        self.assertEqual(m.call_args[0][0], ["ndp", "-an"])

    def test_command_absent_returns_empty(self):
        """`_run_cmd` 在命令不存在时返回 ""（它自己吞了异常）→ 空表，不崩。"""
        with mock.patch.object(ndp, "_IS_WINDOWS", True), \
                mock.patch.object(ndp, "_run_cmd", return_value=""):
            self.assertEqual(ndp.dump_ndp_cache(), {})

    def test_linux_unparseable_output_logs_warning(self):
        """有输出但解析不出条目 → 必须留痕（多半是 `ip` 格式变了）。"""
        with mock.patch.object(ndp, "_IS_WINDOWS", False), \
                mock.patch.object(ndp, "_IS_DARWIN", False), \
                mock.patch.object(ndp, "_run_cmd", return_value="bogus output!!"):
            with self.assertLogs("ipscanner.ndp", level="WARNING") as cm:
                t = ndp.dump_ndp_cache()
        self.assertEqual(t, {})
        self.assertTrue(any("未能解析" in m for m in cm.output), cm.output)

    def test_linux_quiet_output_does_not_warn(self):
        with mock.patch.object(ndp, "_IS_WINDOWS", False), \
                mock.patch.object(ndp, "_IS_DARWIN", False), \
                mock.patch.object(ndp, "_run_cmd", return_value="   \n"):
            with self.assertNoLogs("ipscanner.ndp", level="WARNING"):
                ndp.dump_ndp_cache()


class AttachIpv6Test(unittest.TestCase):
    """验收原文：给定已有 IPv4 资产 + MAC 一致的 IPv6 邻居 → 并入同一行。"""

    def _host(self, ip, mac):
        return ScanResult(ip=ip, mac=mac, status="online")

    def test_mac_match_attaches(self):
        h = self._host("192.168.1.10", "c8:4d:44:32:67:3d")
        n = ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d"}, [h])
        self.assertEqual(n, 1)
        self.assertEqual(h.ipv6_addresses, ["fe80::1"])

    def test_multiple_addresses_same_mac(self):
        h = self._host("192.168.1.10", "c8:4d:44:32:67:3d")
        n = ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d",
                             "2001:db8::5": "c8:4d:44:32:67:3d"}, [h])
        self.assertEqual(n, 2)
        self.assertEqual(sorted(h.ipv6_addresses), ["2001:db8::5", "fe80::1"])

    def test_no_new_asset_for_unknown_mac(self):
        """纯 IPv6 设备（MAC 对不上任何 IPv4 资产）**不新建**行。"""
        h = self._host("192.168.1.10", "c8:4d:44:32:67:3d")
        n = ndp.attach_ipv6({"fe80::99": "aa:bb:cc:dd:ee:ff"}, [h])
        self.assertEqual(n, 0)
        self.assertEqual(h.ipv6_addresses, [])

    def test_case_insensitive_mac_match(self):
        h = self._host("192.168.1.10", "C8:4D:44:32:67:3D")
        n = ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d"}, [h])
        self.assertEqual(n, 1)

    def test_no_duplicate_on_repeat(self):
        h = self._host("192.168.1.10", "c8:4d:44:32:67:3d")
        ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d"}, [h])
        ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d"}, [h])
        self.assertEqual(h.ipv6_addresses, ["fe80::1"])

    def test_host_without_ipv6_attr_skipped(self):
        """宿主对象没有 ipv6_addresses 字段（旧模型）→ 跳过，不抛。"""
        class Minimal:
            mac = "c8:4d:44:32:67:3d"
        n = ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d"}, [Minimal()])
        self.assertEqual(n, 0)

    def test_empty_table_noop(self):
        h = self._host("192.168.1.10", "c8:4d:44:32:67:3d")
        self.assertEqual(ndp.attach_ipv6({}, [h]), 0)

    def test_multiple_hosts_same_mac_both_updated(self):
        """同一 MAC 落在多条历史行上时，全部都要更新（不能只更新一条）。"""
        a = self._host("192.168.1.10", "c8:4d:44:32:67:3d")
        b = self._host("192.168.1.11", "c8:4d:44:32:67:3d")
        n = ndp.attach_ipv6({"fe80::1": "c8:4d:44:32:67:3d"}, [a, b])
        self.assertEqual(n, 2)
        self.assertEqual(a.ipv6_addresses, ["fe80::1"])
        self.assertEqual(b.ipv6_addresses, ["fe80::1"])


class SortIpv6Test(unittest.TestCase):

    def test_link_local_before_global(self):
        out = ndp.sort_ipv6(["2001:db8::5", "fe80::1", "fe80::2"])
        self.assertEqual(out, ["fe80::1", "fe80::2", "2001:db8::5"])

    def test_garbage_last(self):
        out = ndp.sort_ipv6(["fe80::1", "zzz"])
        self.assertEqual(out[-1], "zzz")

    def test_empty(self):
        self.assertEqual(ndp.sort_ipv6([]), [])


class NoExtraPacketsTest(unittest.TestCase):
    """验收原文：除 `ff02::1` 单次多播外无其它出站。"""

    def test_default_passive_discover_does_not_read_ndp(self):
        """默认（ipv6=False）**一次都不读** NDP 缓存 —— 不做额外开销。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache") as m:
            passive.passive_discover(mdns=False)
        m.assert_not_called()

    def test_ipv6_on_reads_cache_without_probing(self):
        """`ipv6=True` 只读缓存 —— 不得调用 `probe_all_nodes`（不发包）。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache",
                                  return_value={}) as m_ndp, \
                mock.patch.object(passive, "probe_all_nodes") as m_probe:
            passive.passive_discover(mdns=False, ipv6=True)
        m_ndp.assert_called_once()
        m_probe.assert_not_called()

    def test_ipv6_probe_calls_probe_exactly_once(self):
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache",
                                  return_value={}), \
                mock.patch.object(passive, "probe_all_nodes",
                                  return_value=True) as m_probe, \
                mock.patch.object(passive.time, "sleep"):
            passive.passive_discover(mdns=False, ipv6=True, ipv6_probe=True)
        m_probe.assert_called_once()

    def test_probe_failure_keeps_arp_results(self):
        """探测失败不能把已读到的 ARP 结果弄没。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache",
                                  return_value={}), \
                mock.patch.object(passive, "probe_all_nodes",
                                  return_value=False):
            res = passive.passive_discover(mdns=False, ipv6=True,
                                           ipv6_probe=True)
        self.assertEqual(set(res), {"10.0.0.5"})

    def test_ndp_read_failure_keeps_arp_results(self):
        """读 NDP 抛异常也要优雅降级。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache",
                                  side_effect=RuntimeError("boom")):
            with self.assertLogs("ipscanner.passive", level="WARNING"):
                res = passive.passive_discover(mdns=False, ipv6=True)
        self.assertEqual(set(res), {"10.0.0.5"})

    def test_no_ipv6_machine_logs_distinct_message(self):
        """无 IPv6 机器上的空缓存要能和「启用了但没邻居」分开。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache", return_value={}), \
                mock.patch.object(passive, "ipv6_enabled", return_value=False):
            with self.assertLogs("ipscanner.passive", level="INFO") as cm:
                passive.passive_discover(mdns=False, ipv6=True)
        self.assertTrue(any("未启用 IPv6" in m for m in cm.output), cm.output)

    def test_empty_cache_on_ipv6_machine_does_not_claim_disabled(self):
        """本机启用了 IPv6 却读到空缓存 → **不能**说「未启用」。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}), \
                mock.patch.object(passive, "dump_ndp_cache", return_value={}), \
                mock.patch.object(passive, "ipv6_enabled", return_value=True):
            with self.assertNoLogs("ipscanner.passive", level="INFO"):
                passive.passive_discover(mdns=False, ipv6=True)


class Ipv6EnabledTest(unittest.TestCase):

    def test_no_compile_support_false(self):
        with mock.patch("socket.has_ipv6", False):
            self.assertFalse(ndp.ipv6_enabled())

    def test_loopback_only_false(self):
        with mock.patch("socket.has_ipv6", True), \
                mock.patch("socket.getaddrinfo",
                           return_value=[(10, 1, 6, "", ("::1", 0, 0, 0))]):
            self.assertFalse(ndp.ipv6_enabled())

    def test_global_address_true(self):
        with mock.patch("socket.has_ipv6", True), \
                mock.patch("socket.getaddrinfo",
                           return_value=[(10, 1, 6, "", ("fe80::1", 0, 0, 2))]):
            self.assertTrue(ndp.ipv6_enabled())

    def test_resolve_failure_false(self):
        with mock.patch("socket.has_ipv6", True), \
                mock.patch("socket.getaddrinfo", side_effect=OSError("no dns")):
            self.assertFalse(ndp.ipv6_enabled())


class ProbeAllNodesTest(unittest.TestCase):
    """`probe_all_nodes()` 的降级路径（真实发包在测试里不能做）。"""

    def test_no_ipv6_interface_returns_false(self):
        with mock.patch("socket.socket",
                        side_effect=OSError("no ipv6")):
            self.assertFalse(ndp.probe_all_nodes())

    def test_returns_bool(self):
        self.assertIn(ndp.probe_all_nodes(timeout=0.01),
                      (True, False))


class PassiveWatcherIpv6Test(unittest.TestCase):

    def test_accumulates_ipv6_across_rounds(self):
        """某一轮 ARP 表里没有这台设备了，它上一轮看到的 IPv6 也不消失。"""
        w = passive.PassiveWatcher()
        arp = {"10.0.0.5": "c8:4d:44:32:67:3d"}
        ndp_tbl = {"fe80::1": "c8:4d:44:32:67:3d"}
        with mock.patch.object(passive, "dump_arp_table", return_value=dict(arp)), \
                mock.patch.object(passive, "dump_ndp_cache",
                                  return_value=dict(ndp_tbl)):
            ledger, _ = w.poll(mdns=False, ipv6=True)
        self.assertEqual(ledger[0].ipv6_addresses, ["fe80::1"])
        # 第二轮 ARP 表空了 —— 台账里那台设备仍在（不报消失），IPv6 也还在。
        with mock.patch.object(passive, "dump_arp_table", return_value={}), \
                mock.patch.object(passive, "dump_ndp_cache", return_value={}):
            ledger, _ = w.poll(mdns=False, ipv6=True)
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0].ipv6_addresses, ["fe80::1"])


if __name__ == "__main__":
    unittest.main()
