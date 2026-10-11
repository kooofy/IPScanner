# -*- coding: utf-8 -*-
"""``NetworkScanner.scan()`` 端到端行为测试（P1-3 重构的"护栏"）。

为什么要先写这个：``scan()`` 是一个约 400 行的编排函数，三个发现阶段
（ping / ARP / mDNS）与富化流水线交织在一起，而**原有的测试只覆盖被抽出的
纯函数**（``_merge_mdns`` / ``adaptive_timeout_from_samples`` …），
没有任何一条测试真正跑过完整的 ``scan()``。这意味着任何对编排的改动都
可能在无人察觉的情况下改变行为。

本文件把**所有 I/O 边界**（ping / ARP / DNS / NetBIOS / 端口 / mDNS / 指纹）
都替换为可控的假实现，只验证 scan() 的**可观察契约**：
结果状态、发现方式、回调时序、告警、中止语义。

这些用例在重构前后都必须保持全绿 —— 它们是"行为不变"的证明。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import engine as E


def _patch_io(**overrides):
    """把所有网络 I/O 替换为假实现；用 overrides 覆盖单个函数。

    默认语义：ping 全部失败、无 ARP、无 mDNS、无端口、无主机名 ——
    即"一个全离线的干净网段"，便于各用例只改动自己关心的那一项。
    """
    defaults = {
        "ping_ip": lambda ip, timeout_ms=1000: (False, 0.0, 0),
        "arp_ping": lambda ip: "",
        "get_local_subnets": lambda: [],
        "get_mac_for_ip": lambda ip: "",
        "get_mac_vendor": lambda mac: "",
        "resolve_hostname": lambda ip, timeout=1.0: "",
        "get_netbios_name": lambda ip, timeout=2.0: "",
        "scan_ports": lambda ip, ports=None, timeout=0.5, mode="connect",
                          rtt_callback=None: [],
        "scan_port": lambda ip, port, timeout=0.5: False,
        "scan_shares": lambda ip, timeout=1.5: [],
        "infer_device": lambda r: ("", ""),
        "guess_os_from_ttl": lambda ttl: "",
        "_read_ssh_banner": lambda ip, port, t: "",
        "_read_ftp_banner": lambda ip, port, t: "",
        "_read_http": lambda ip, port, t: ("", "", ""),
        "read_https": lambda ip, port, t: ("", {}),
        "_read_upnp_device_name": lambda ip, port, t: "",
        "_os_detail_from_banners": lambda details, extra: "",
        "_tcp_stack_probe": lambda ip, port, t: None,
        "_match_tcp_stack": lambda sig: "",
        "mdns_discover": lambda timeout=2.5: {},
        "snmp_get_system": lambda ip: {},
        "snmp_v3_get_system": lambda ip, user: {},
        # 扩展服务探测在 import 期就绑定了函数引用，patch 单个函数无效；
        # 这里整表清空，避免完整扫描用例真的去连 3389/6379 等端口。
        # 探测逻辑本身由 ExtraServiceProbeTest 与 test_banners 覆盖。
        "_SERVICE_PROBES": (),
    }
    defaults.update(overrides)
    return [mock.patch.object(E, name, value) for name, value in defaults.items()]


class _Base(unittest.TestCase):

    def scan(self, ranges, patchers, **kwargs):
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        return E.NetworkScanner().scan(ranges, **kwargs)

    def by_ip(self, results):
        return {r.ip: r for r in results}


class PingPhaseTest(_Base):

    def test_alive_host_is_online_via_ping(self):
        patches = _patch_io(ping_ip=lambda ip, timeout_ms=1000: (ip == "10.0.0.2", 1.5, 64))
        results = self.scan(["10.0.0.1-10.0.0.3"], patches, mdns_discovery=False)
        r = self.by_ip(results)
        self.assertEqual(len(results), 3)
        self.assertEqual(r["10.0.0.2"].status, "online")
        self.assertEqual(r["10.0.0.2"].discovery_method, "ping")
        self.assertEqual(r["10.0.0.2"].response_time, 1.5)
        self.assertEqual(r["10.0.0.2"].ttl, 64)
        self.assertEqual(r["10.0.0.1"].status, "offline")
        self.assertEqual(r["10.0.0.3"].status, "offline")

    def test_progress_callback_covers_every_ip(self):
        seen = []
        patches = _patch_io()
        self.scan(["10.0.0.1-10.0.0.3"], patches, mdns_discovery=False,
                  progress_callback=lambda cur, total, ip: seen.append((cur, total, ip)))
        self.assertEqual([s[0] for s in seen], [1, 2, 3])
        self.assertTrue(all(s[1] == 3 for s in seen))
        self.assertEqual(sorted(s[2] for s in seen),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_result_callback_only_for_alive(self):
        got = []
        patches = _patch_io(ping_ip=lambda ip, timeout_ms=1000: (ip == "10.0.0.2", 1.0, 64))
        self.scan(["10.0.0.1-10.0.0.3"], patches, mdns_discovery=False,
                  result_callback=lambda r: got.append(r.ip))
        self.assertEqual(got, ["10.0.0.2"])


class PortPhaseTest(_Base):

    def test_ports_scanned_when_flag_on(self):
        def fake_scan_ports(ip, ports=None, timeout=0.5, mode="connect", rtt_callback=None):
            return [80, 443]
        patches = _patch_io(
            ping_ip=lambda ip, timeout_ms=1000: (True, 1.0, 64),
            scan_ports=fake_scan_ports,
        )
        results = self.scan(["10.0.0.5"], patches, mdns_discovery=False,
                            scan_ports_flag=True)
        self.assertEqual(self.by_ip(results)["10.0.0.5"].open_ports, [80, 443])

    def test_protocol_ports_reused_not_rescanned(self):
        """完整端口扫描已覆盖协议端口 → 不应再调一次 scan_ports。"""
        calls = []

        def fake_scan_ports(ip, ports=None, timeout=0.5, mode="connect", rtt_callback=None):
            calls.append(list(ports) if ports else None)
            # 返回包含全部协议端口的开放端口
            return [21, 80, 443, 3389]

        patches = _patch_io(
            ping_ip=lambda ip, timeout_ms=1000: (True, 1.0, 64),
            scan_ports=fake_scan_ports,
        )
        results = self.scan(["10.0.0.5"], patches, mdns_discovery=False,
                            scan_ports_flag=True, protocols=["HTTP", "HTTPS", "FTP", "RDP"])
        r = self.by_ip(results)["10.0.0.5"]
        self.assertEqual(len(calls), 1, "协议端口被重复扫描了")
        self.assertIn("HTTP", r.services)
        self.assertIn("HTTPS", r.services)

    def test_protocol_ports_scanned_when_not_covered(self):
        """未做完整端口扫描时，协议端口仍需单独扫一遍。"""
        calls = []

        def fake_scan_ports(ip, ports=None, timeout=0.5, mode="connect", rtt_callback=None):
            calls.append(list(ports) if ports else None)
            return [80]

        patches = _patch_io(
            ping_ip=lambda ip, timeout_ms=1000: (True, 1.0, 64),
            scan_ports=fake_scan_ports,
        )
        results = self.scan(["10.0.0.5"], patches, mdns_discovery=False,
                            scan_ports_flag=False, protocols=["HTTP"])
        r = self.by_ip(results)["10.0.0.5"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], [80])          # 只扫了协议端口
        self.assertIn(80, r.open_ports)           # 未做完整扫描时补进开放端口
        self.assertIn("HTTP", r.services)


class TlsCertWiringTest(_Base):
    """HTTPS 分支：一次握手同时产出 banner 与证书事实（v1.9 #3）。

    证书**不是新开的探测** —— 复用扫描本就要做的那次 TLS 握手，只是顺便把
    DER 也读出来（见 `scanner/http.read_https`）。所以这里的断言只有两条：
    banner 进了 `service_details`，事实进了 `ScanResult.tls_cert`。
    """

    _CERT = {"cn": "router.local", "issuer_cn": "router.local",
             "not_before": "2025-01-01T00:00:00",
             "not_after": "2027-01-01T00:00:00",
             "self_signed": True, "sig_alg": "sha256_rsa",
             "key_alg": "rsa", "key_bits": 2048, "curve": ""}

    def _https_scan(self, **extra):
        patches = _patch_io(
            ping_ip=lambda ip, timeout_ms=1000: (True, 1.0, 64),
            scan_ports=lambda ip, ports=None, timeout=0.5, mode="connect",
                              rtt_callback=None: [443],
        )
        patches += extra.pop("patchers", [])
        return self.scan(["10.0.0.5"], patches, mdns_discovery=False,
                         protocols=["HTTPS"], **extra)

    def test_banner_and_certificate_land_on_the_result(self):
        patches = [mock.patch.object(
            E, "read_https",
            lambda ip, port, t: ("Tunnel is OpenSSL TLSv1.3: router.local",
                                 dict(self._CERT)))]
        results = self._https_scan(patchers=patches)
        r = self.by_ip(results)["10.0.0.5"]
        self.assertEqual(r.tls_cert, self._CERT)
        details = [d for d in r.service_details if d.get("proto") == "HTTPS"]
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]["banner"],
                         "Tunnel is OpenSSL TLSv1.3: router.local")

    def test_empty_certificate_leaves_the_field_empty(self):
        """握手成功但读不到证书（老服务端 / 非 TLS）→ 保持空 dict，不瞎填。"""
        patches = [mock.patch.object(
            E, "read_https", lambda ip, port, t: ("unknown service", {}))]
        results = self._https_scan(patchers=patches)
        self.assertEqual(self.by_ip(results)["10.0.0.5"].tls_cert, {})

    def test_a_fresh_result_starts_with_an_empty_certificate(self):
        """默认值必须是 `{}`（空 dict = 没探到），不能是 None —— 消费方会 `.get()`。"""
        results = self._https_scan()
        self.assertEqual(self.by_ip(results)["10.0.0.5"].tls_cert, {})

    def test_only_the_first_certificate_is_kept(self):
        """多端口时只留第一个 —— 风险评分是"一台设备一条结论"。

        `PROTOCOL_PORTS` 目前一个协议只映射一个端口，正常路径够不到这条守卫，
        所以这里用一个**能给出重复键**的映射把它逼出来（dict 做不到，故自定义）。
        """
        seen = []

        def fake_read(ip, port, t):
            seen.append(port)
            cert = dict(self._CERT, cn="port-%d.local" % port)
            return "Tunnel is OpenSSL TLSv1.3: port-%d.local" % port, cert

        mapping = _RepeatedMap([("HTTPS", 443), ("HTTPS", 8443)])
        patches = [
            mock.patch.object(E, "_build_proto_map",
                              lambda protocols: (mapping, False)),
            mock.patch.object(E, "read_https", fake_read),
            mock.patch.object(
                E, "scan_ports",
                lambda ip, ports=None, timeout=0.5, mode="connect",
                     rtt_callback=None: [443, 8443]),
        ]
        results = self._https_scan(patchers=patches)
        r = self.by_ip(results)["10.0.0.5"]
        self.assertEqual(seen, [443, 8443], "两个 HTTPS 端口都该被探")
        self.assertEqual(r.tls_cert["cn"], "port-443.local",
                         "只保留第一个探到的证书")
        self.assertEqual(len([d for d in r.service_details
                              if d.get("proto") == "HTTPS"]), 2,
                         "banner 两条都要留，只有证书去重")


class _RepeatedMap:
    """能给出**重复键**的 proto→port 映射（dict 做不到，见上一条测试）。

    只需要 `__bool__` / `values()` / `items()` 三个口子 —— 引擎就用这三个。
    """

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def __bool__(self):
        return bool(self._pairs)

    def values(self):
        return [port for _proto, port in self._pairs]

    def items(self):
        return list(self._pairs)


class ArpPhaseTest(_Base):

    def test_arp_discovers_silent_host(self):
        import ipaddress
        patches = _patch_io(
            ping_ip=lambda ip, timeout_ms=1000: (False, 0.0, 0),
            get_local_subnets=lambda: [ipaddress.ip_network("10.0.0.0/24")],
            arp_ping=lambda ip: "AA:BB:CC:DD:EE:FF" if ip == "10.0.0.9" else "",
            get_mac_vendor=lambda mac: "测试厂商" if mac else "",
        )
        results = self.scan(["10.0.0.9"], patches, mdns_discovery=False)
        r = self.by_ip(results)["10.0.0.9"]
        self.assertEqual(r.status, "online")
        self.assertEqual(r.discovery_method, "arp")
        self.assertEqual(r.mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(r.vendor, "测试厂商")

    def test_arp_only_for_local_subnet(self):
        import ipaddress
        arp_calls = []

        def fake_arp(ip):
            arp_calls.append(ip)
            return ""

        patches = _patch_io(
            get_local_subnets=lambda: [ipaddress.ip_network("10.0.0.0/24")],
            arp_ping=fake_arp,
        )
        self.scan(["10.0.0.5", "192.168.5.5"], patches, mdns_discovery=False)
        self.assertIn("10.0.0.5", arp_calls)
        self.assertNotIn("192.168.5.5", arp_calls)


class MdnsPhaseTest(_Base):

    def test_mdns_adds_new_device(self):
        patches = _patch_io(
            mdns_discover=lambda timeout=2.5: {
                "10.0.0.77": {"names": {"printer.local"}, "services": {"ipp"}}
            },
        )
        results = self.scan(["10.0.0.1"], patches, mdns_discovery=True)
        r = self.by_ip(results)
        self.assertIn("10.0.0.77", r)
        self.assertEqual(r["10.0.0.77"].status, "online")
        self.assertEqual(r["10.0.0.77"].discovery_method, "mdns")

    def test_mdns_disabled_skips(self):
        patches = _patch_io(
            mdns_discover=lambda timeout=2.5: {
                "10.0.0.77": {"names": {"x.local"}, "services": set()}
            },
        )
        results = self.scan(["10.0.0.1"], patches, mdns_discovery=False)
        self.assertNotIn("10.0.0.77", self.by_ip(results))


class GuardTest(_Base):

    def test_ipv6_range_warns_and_skips(self):
        patches = _patch_io()
        scanner = E.NetworkScanner()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        results = scanner.scan(["2001:db8::/126", "10.0.0.1"], mdns_discovery=False)
        self.assertEqual([r.ip for r in results], ["10.0.0.1"])
        self.assertTrue(any("IPv6" in w for w in scanner.warnings))

    def test_oversize_range_aborts(self):
        patches = _patch_io()
        scanner = E.NetworkScanner()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        # 10.0.0.0/8 有 1600 万+ 地址，必然超过单范围上限 → 应整体中止
        results = scanner.scan(["10.0.0.0/8"], mdns_discovery=False)
        self.assertEqual(results, [])
        self.assertTrue(scanner.warnings)

    def test_syn_unavailable_falls_back_with_warning(self):
        patches = _patch_io(ping_ip=lambda ip, timeout_ms=1000: (True, 1.0, 64))
        scanner = E.NetworkScanner()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with mock.patch.object(E, "raw_capability", return_value=(False, "无权限")):
            scanner.scan(["10.0.0.1"], mdns_discovery=False, tcp_scan_mode="syn")
        self.assertTrue(any("回退" in w for w in scanner.warnings))

    def test_empty_ranges_returns_empty(self):
        patches = _patch_io()
        results = self.scan(["not-an-ip"], patches, mdns_discovery=False)
        self.assertEqual(results, [])


class StopTest(_Base):

    def test_stop_flag_halts_pipeline(self):
        scanner = E.NetworkScanner()
        patches = _patch_io()

        def fake_ping(ip, timeout_ms=1000):
            scanner.stop()          # 第一个 IP 就请求停止
            return (True, 1.0, 64)

        patches = _patch_io(ping_ip=fake_ping)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        scanner.scan(["10.0.0.1-10.0.0.20"], mdns_discovery=False)
        self.assertFalse(scanner.is_scanning)


class ExtraServiceProbeTest(_Base):
    """P2-2：开放端口上的服务 banner 探测 + 指纹解析。"""

    def _result(self, ports, services=None):
        from scanner.models import ScanResult
        r = ScanResult(ip="10.0.0.1", status="online")
        r.open_ports = list(ports)
        if services:
            r.services = list(services)
        return r

    def _patched_probes(self, *entries):
        """用自定义的 (端口, 服务代码, 探测函数) 替换真实探测表。

        ``_SERVICE_PROBES`` 在 import 期就绑定了函数引用，直接 patch
        ``E.read_redis_banner`` 不会影响它，因此这里替换整张表。
        """
        return mock.patch.object(E, "_SERVICE_PROBES", tuple(entries))

    def test_wiring_covers_expected_ports(self):
        """端口 → 探测函数的接线必须是真实函数，不能写错。"""
        mapping = {port: fn for port, _code, fn in E._SERVICE_PROBES}
        self.assertIs(mapping[6379], E.read_redis_banner)
        self.assertIs(mapping[3306], E.read_mysql_banner)
        self.assertIs(mapping[5900], E.read_vnc_banner)
        self.assertIs(mapping[5432], E.read_postgresql_banner)
        self.assertIs(mapping[27017], E.read_mongodb_banner)
        self.assertIs(mapping[3389], E.read_rdp_banner)
        self.assertIs(mapping[23], E.read_greeting)

    def test_adds_fingerprint_for_open_service_port(self):
        r = self._result([6379])
        with self._patched_probes((6379, "Redis", lambda ip, p, t: "+PONG")):
            E._probe_extra_services(r, "10.0.0.1", 0.5)
        self.assertIn("Redis", r.services)
        self.assertEqual(r.service_details[0]["port"], 6379)
        self.assertIn("Redis", r.service_details[0]["banner"])

    def test_skips_ports_without_probe(self):
        r = self._result([12345, 8443])
        with self._patched_probes((6379, "Redis", lambda ip, p, t: "+PONG")):
            E._probe_extra_services(r, "10.0.0.1", 0.5)
        self.assertEqual(r.services, [])
        self.assertEqual(r.service_details, [])

    def test_skips_service_already_present(self):
        """端口已由协议识别标过 RDP 时，不再重复探测。"""
        r = self._result([3389], services=["RDP"])
        spy = mock.Mock(return_value="RDP")
        with self._patched_probes((3389, "RDP", spy)):
            E._probe_extra_services(r, "10.0.0.1", 0.5)
        spy.assert_not_called()
        self.assertEqual(r.services, ["RDP"])
        self.assertEqual(r.service_details, [])

    def test_empty_banner_is_ignored(self):
        r = self._result([3306])
        with self._patched_probes((3306, "MySQL", lambda ip, p, t: "")):
            E._probe_extra_services(r, "10.0.0.1", 0.5)
        self.assertEqual(r.services, [])

    def test_probe_exception_is_swallowed(self):
        """探测抛异常只应跳过该服务，绝不能冒泡到富化流程。"""
        def boom(ip, p, t):
            raise RuntimeError("boom")

        r = self._result([6379])
        with self._patched_probes((6379, "Redis", boom)):
            E._probe_extra_services(r, "10.0.0.1", 0.5)   # 不应抛
        self.assertEqual(r.services, [])

    def test_no_open_ports_is_noop(self):
        r = self._result([])
        E._probe_extra_services(r, "10.0.0.1", 0.5)
        self.assertEqual(r.services, [])


class PhaseExtensionTest(_Base):
    """重构的核心收益：新增发现方式 = 新增一个 Phase 并登记，无需改 scan()。"""

    def test_default_phases_and_order(self):
        self.assertEqual([p.name for p in E.PHASES], ["ping", "arp", "mdns"])

    def test_custom_phase_is_executed(self):
        ran = []

        class FakePhase(E.DiscoveryPhase):
            name = "fake"

            def run(self, ctx):
                ran.append(ctx.total)

        patches = _patch_io()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with mock.patch.object(E, "PHASES", tuple(E.PHASES) + (FakePhase(),)):
            E.NetworkScanner().scan(["10.0.0.1-10.0.0.2"], mdns_discovery=False)
        self.assertEqual(ran, [2], "自定义阶段没有被编排执行")


if __name__ == "__main__":
    unittest.main()
