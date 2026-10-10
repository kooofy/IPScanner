# -*- coding: utf-8 -*-
"""随机化 MAC 识别（设备指纹）单元测试。

对应 `docs/ROADMAP_V1.8.md` §3 耦合提示 #11：纯 MAC 身份在开了
「私有 Wi-Fi 地址」的设备上会把同一台机器反复报成新设备，
噪声会把台账可信度吃掉。

覆盖三层：
  ① `device_fingerprint`：LAA 判定与指纹配对规则（纯逻辑）；
  ② `change_detector`：指纹配对如何抑制「新增 + 消失 + 被替换」三连假阳性；
  ③ `scanner.passive.PassiveWatcher`：被动发现按指纹去重。

**断言一律语言无关**：只比规范值（`change_type` / `severity` / MAC / IP），
不写死界面文案 —— CI runner 是英文系统，写死中文的断言本地绿、CI 必挂。
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history_store
from change_detector import (
    CHANGE_DEVICE_GONE, CHANGE_MAC_CHANGED, CHANGE_MAC_RANDOMIZED,
    CHANGE_NEW_DEVICE, SEVERITY_HIGH, SEVERITY_INFO, detect_changes,
)
from device_fingerprint import (
    fingerprint, fingerprint_tokens, is_randomized_mac, same_device,
)
from scanner.models import ScanResult


# ── 造数助手 ──────────────────────────────────────────────────────────

#: 真实厂商 OUI 的 MAC（首字节 LAA 位为 0）—— 不能用 AA/DE/02/06 开头，
#: 那些首字节的 LAA 位是 1，会被判成"疑似随机 MAC"。
REAL_MAC_A = "3C:22:FB:00:00:01"
REAL_MAC_B = "F0:18:98:00:00:02"
#: 随机 MAC（首字节 LAA 位为 1）。
RAND_MAC_A = "02:11:22:33:44:55"
RAND_MAC_B = "06:99:88:77:66:55"


def _res(ip, mac="", hostname="", vendor="", status="online", **kw):
    r = ScanResult(ip=ip, mac=mac, hostname=hostname, vendor=vendor)
    r.status = status
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _dev(ip, mac="", hostname="", vendor="", status="online", **kw):
    """快照 dict（字段集与 `history_store` 的 devices 表一致）。"""
    base = {"ip": ip, "status": status, "mac": mac, "hostname": hostname,
            "vendor": vendor, "device_class": "", "os_guess": "",
            "open_ports": "", "location": "", "user": "", "remark": ""}
    base.update(kw)
    return base


# ── ① LAA 判定 ────────────────────────────────────────────────────────

class IsRandomizedMacTest(unittest.TestCase):
    """随机 MAC 的硬信号是首字节的 LAA 位（0x02）。"""

    def test_laa_bit_set_is_randomized(self):
        for mac in ("02:11:22:33:44:55", "06:99:88:77:66:55",
                    "0A:00:00:00:00:01", "AA:BB:CC:DD:EE:FF"):
            self.assertTrue(is_randomized_mac(mac), mac)

    def test_global_oui_is_not_randomized(self):
        for mac in (REAL_MAC_A, REAL_MAC_B, "50:2B:73:11:22:33",
                    "00:1A:2B:00:00:01"):
            self.assertFalse(is_randomized_mac(mac), mac)

    def test_separator_and_case_do_not_matter(self):
        for mac in ("02-11-22-33-44-55", "021122334455", "02:11:22:33:44:55"):
            self.assertTrue(is_randomized_mac(mac), mac)
        self.assertFalse(is_randomized_mac("3C22FB000001"))

    def test_invalid_input_is_false_not_exception(self):
        """形状不对是**正常分支**（空 MAC / 半截 MAC / 垃圾），返回 False。"""
        for bad in ("", None, "not-a-mac", "02:11:22", "GG:11:22:33:44:55"):
            self.assertFalse(is_randomized_mac(bad), bad)


# ── ② 指纹构造 ────────────────────────────────────────────────────────

class FingerprintTokensTest(unittest.TestCase):

    def test_hostname_is_normalized(self):
        """大小写、`.local` 后缀、结尾的点都不该影响身份。"""
        base = fingerprint_tokens(_res("10.0.0.1", hostname="iPhone"))
        for variant in ("iphone", "IPHONE", "iphone.local", "iPhone.local."):
            self.assertEqual(
                fingerprint_tokens(_res("10.0.0.1", hostname=variant)), base,
                variant)

    def test_vendor_and_model_are_collected(self):
        toks = fingerprint_tokens(_res(
            "10.0.0.1", hostname="nas", vendor="Synology",
            device_model="DS920+"))
        self.assertEqual(toks, frozenset(
            {"host=nas", "vendor=synology", "model=ds920+"}))

    def test_empty_device_has_no_tokens(self):
        """没有任何身份字段 → 空集（表示"信号不足，不做身份判定"）。"""
        self.assertEqual(fingerprint_tokens(_res("10.0.0.1")), frozenset())
        self.assertEqual(fingerprint_tokens(_dev("10.0.0.1")), frozenset())

    def test_snapshot_dict_and_scanresult_agree(self):
        """快照 dict 与 ScanResult 走同一套字段名，token 必须一致。"""
        r = _res("10.0.0.1", hostname="nas", vendor="Synology")
        d = _dev("10.0.0.1", hostname="nas", vendor="Synology")
        self.assertEqual(fingerprint_tokens(r), fingerprint_tokens(d))
        self.assertEqual(fingerprint(r), fingerprint(d))

    def test_netbios_name_serves_as_hostname(self):
        """没探到主机名时，NetBIOS 名可以顶上。"""
        r = _res("10.0.0.1")
        r.netbios_name = "DESKTOP-1"
        self.assertIn("host=desktop-1", fingerprint_tokens(r))

    def test_fingerprint_string_is_stable_and_empty_when_signalless(self):
        r = _res("10.0.0.1", hostname="nas", vendor="Synology")
        self.assertEqual(fingerprint(r), "host=nas|vendor=synology")
        self.assertEqual(fingerprint(_res("10.0.0.1")), "")


# ── ③ 配对规则 ────────────────────────────────────────────────────────

class SameDeviceTest(unittest.TestCase):

    def test_same_hostname_is_same_device(self):
        self.assertTrue(same_device(
            _res("10.0.0.5", hostname="nas"),
            _dev("10.0.0.9", hostname="NAS.local", vendor="Synology")))

    def test_hostname_conflict_is_never_same_device(self):
        """同类字段两边都有值却不同 → 铁定不是同一台（即使别的字段相同）。"""
        self.assertFalse(same_device(
            _res("10.0.0.5", hostname="alpha", vendor="Dell"),
            _dev("10.0.0.5", hostname="beta", vendor="Dell")))

    def test_vendor_alone_is_not_enough(self):
        """同厂商设备太多，只靠 vendor 相同不算同一台。"""
        self.assertFalse(same_device(
            _res("10.0.0.5", vendor="Dell"),
            _dev("10.0.0.9", vendor="dell")))

    def test_vendor_conflict_blocks_hostname_match(self):
        """主机名相同但厂商明确不同 → 否决（主机名可能被两台设备复用）。"""
        self.assertFalse(same_device(
            _res("10.0.0.5", hostname="pc", vendor="Dell"),
            _dev("10.0.0.5", hostname="pc", vendor="HP")))

    def test_model_needs_a_second_token(self):
        """同型号可能有多台，光靠 model 不够；再有一项佐证才认。"""
        a = _res("10.0.0.5", device_model="iPhone 15")
        b = _dev("10.0.0.9", device_model="iPhone 15")
        self.assertFalse(same_device(a, b))
        b["vendor"] = "Apple"
        a.vendor = "Apple"
        self.assertTrue(same_device(a, b))

    def test_serial_is_a_strong_anchor(self):
        a = _res("10.0.0.5")
        a.wmi_serial = "SN-12345"
        b = _dev("10.0.0.9", vendor="Dell")
        b["wmi_serial"] = "sn-12345"
        self.assertTrue(same_device(a, b))

    def test_signal_less_device_never_matches(self):
        self.assertFalse(same_device(_res("10.0.0.5"), _dev("10.0.0.5")))
        self.assertFalse(same_device(_res("10.0.0.5"), _res("10.0.0.5")))


# ── ④ 变更检测：指纹配对抑制三连假阳性 ────────────────────────────────

class DetectChangesRandomizedMacTest(unittest.TestCase):
    """`detect_changes` 里「随机 MAC 重现」这一条。"""

    def _types(self, changes):
        return sorted(c.change_type for c in changes)

    def test_same_ip_random_mac_with_hostname_is_one_info_change(self):
        """核心场景：同 IP + 换了随机 MAC + 主机名一致 → 只报一条 info。"""
        changes = detect_changes(
            [_res("192.168.1.50", RAND_MAC_A, hostname="Johns-iPhone")],
            [_dev("192.168.1.50", REAL_MAC_A, hostname="Johns-iPhone.local",
                  vendor="Apple")])
        self.assertEqual(self._types(changes), [CHANGE_MAC_RANDOMIZED])
        self.assertEqual(changes[0].severity, SEVERITY_INFO)
        self.assertEqual(changes[0].old_value, REAL_MAC_A)
        self.assertEqual(changes[0].new_value, RAND_MAC_A)
        self.assertEqual(changes[0].ip, "192.168.1.50")

    def test_different_ip_random_mac_is_matched_and_ip_change_is_noted(self):
        changes = detect_changes(
            [_res("192.168.1.77", RAND_MAC_B, hostname="ipad")],
            [_dev("192.168.1.51", REAL_MAC_A, hostname="ipad", vendor="Apple")])
        self.assertEqual(self._types(changes), [CHANGE_MAC_RANDOMIZED])
        # IP 同时变了要写进描述里，否则这条提示会丢信息
        self.assertIn("192.168.1.51", changes[0].description)
        self.assertIn("192.168.1.77", changes[0].description)

    def test_real_mac_replacement_is_still_high_severity(self):
        """两侧都是真实 MAC 却不同 → 那是换了台设备，不能被指纹并掉。"""
        changes = detect_changes(
            [_res("192.168.1.50", REAL_MAC_B, hostname="pc")],
            [_dev("192.168.1.50", REAL_MAC_A, hostname="pc", vendor="Dell")])
        self.assertIn(CHANGE_MAC_CHANGED, self._types(changes))
        self.assertNotIn(CHANGE_MAC_RANDOMIZED, self._types(changes))
        mac_changed = [c for c in changes if c.change_type == CHANGE_MAC_CHANGED]
        self.assertEqual(mac_changed[0].severity, SEVERITY_HIGH)

    def test_random_mac_with_different_hostname_reports_new_and_gone(self):
        """指纹对不上就如实报「新增 + 消失」—— 宁可漏认，不可错认。"""
        changes = detect_changes(
            [_res("192.168.1.51", RAND_MAC_A, hostname="phone-b")],
            [_dev("192.168.1.50", REAL_MAC_A, hostname="phone-a")])
        self.assertEqual(self._types(changes),
                         [CHANGE_DEVICE_GONE, CHANGE_NEW_DEVICE])

    def test_same_ip_two_random_macs_is_downgraded_to_info(self):
        """同一 IP 上换成另一个随机 MAC、又没指纹 → 不能说"设备被替换"。"""
        changes = detect_changes(
            [_res("192.168.1.50", RAND_MAC_A)],
            [_dev("192.168.1.50", RAND_MAC_B)])
        self.assertEqual(self._types(changes), [CHANGE_MAC_RANDOMIZED])
        self.assertEqual(changes[0].severity, SEVERITY_INFO)

    def test_same_ip_real_to_random_without_fingerprint_stays_high(self):
        """旧 MAC 是真实 OUI 时不能轻描淡写：那确实可能是换了台设备。"""
        changes = detect_changes(
            [_res("192.168.1.50", RAND_MAC_A)],
            [_dev("192.168.1.50", REAL_MAC_A)])
        self.assertEqual(self._types(changes), [CHANGE_MAC_CHANGED])
        self.assertEqual(changes[0].severity, SEVERITY_HIGH)

    def test_two_devices_rotate_without_cross_matching(self):
        """两台设备同时换随机 MAC，不能互相串台（贪心 1:1 配对）。"""
        changes = detect_changes(
            [_res("192.168.1.60", RAND_MAC_A, hostname="alpha"),
             _res("192.168.1.61", RAND_MAC_B, hostname="beta")],
            [_dev("192.168.1.60", REAL_MAC_A, hostname="alpha", vendor="X"),
             _dev("192.168.1.61", REAL_MAC_B, hostname="beta", vendor="Y")])
        self.assertEqual(self._types(changes),
                         [CHANGE_MAC_RANDOMIZED, CHANGE_MAC_RANDOMIZED])
        by_new = {c.new_value: c.old_value for c in changes}
        self.assertEqual(by_new, {RAND_MAC_A: REAL_MAC_A,
                                  RAND_MAC_B: REAL_MAC_B})

    def test_matched_device_is_not_also_reported_gone(self):
        """回归：配对后两侧 MAC 都要抑制，不能再冒出一条「设备消失」。"""
        changes = detect_changes(
            [_res("192.168.1.50", RAND_MAC_A, hostname="phone")],
            [_dev("192.168.1.50", REAL_MAC_A, hostname="phone")])
        self.assertNotIn(CHANGE_DEVICE_GONE, self._types(changes))
        self.assertNotIn(CHANGE_NEW_DEVICE, self._types(changes))

    def test_no_previous_devices_is_noop(self):
        self.assertEqual(
            detect_changes([_res("10.0.0.1", RAND_MAC_A)], []), [])


# ── ⑤ 被动发现按指纹去重 ──────────────────────────────────────────────

class PassiveWatcherFingerprintTest(unittest.TestCase):
    """`PassiveWatcher` 的「新出现」要同时过 IP 与指纹两道关。"""

    def _watcher(self, **kw):
        import scanner.passive as passive
        return passive.PassiveWatcher(**kw)

    def _poll(self, watcher, found):
        import scanner.passive as passive
        with mock.patch.object(passive, "passive_discover",
                               return_value=dict(found)):
            return watcher.poll(mdns=False)

    def test_known_device_at_new_ip_is_not_fresh(self):
        """基线里有这台设备（靠主机名认出来），换了 IP 也不该报"新"。"""
        w = self._watcher(known_devices=[
            _dev("10.0.0.2", REAL_MAC_A, hostname="nas")])
        _ledger, fresh = self._poll(w, {
            "10.0.0.9": _res("10.0.0.9", RAND_MAC_A, hostname="nas.local")})
        self.assertEqual(fresh, [])

    def test_known_ip_is_not_fresh(self):
        w = self._watcher(known_ips={"10.0.0.2"})
        _ledger, fresh = self._poll(w, {"10.0.0.2": _res("10.0.0.2")})
        self.assertEqual(fresh, [])

    def test_genuinely_new_device_is_fresh(self):
        w = self._watcher(known_devices=[
            _dev("10.0.0.2", REAL_MAC_A, hostname="nas")])
        _ledger, fresh = self._poll(w, {
            "10.0.0.9": _res("10.0.0.9", RAND_MAC_A, hostname="brand-new")})
        self.assertEqual([r.ip for r in fresh], ["10.0.0.9"])

    def test_signal_less_device_at_new_ip_is_fresh(self):
        """指纹认不出来就如实报新 —— 不猜。"""
        w = self._watcher(known_devices=[
            _dev("10.0.0.2", REAL_MAC_A, hostname="nas")])
        _ledger, fresh = self._poll(w, {"10.0.0.9": _res("10.0.0.9")})
        self.assertEqual([r.ip for r in fresh], ["10.0.0.9"])

    def test_fingerprint_accumulates_across_rounds(self):
        """第一轮发现过的设备，第二轮换了 IP 不该再报一次。"""
        w = self._watcher()
        _ledger, fresh = self._poll(w, {
            "10.0.0.5": _res("10.0.0.5", RAND_MAC_A, hostname="phone")})
        self.assertEqual([r.ip for r in fresh], ["10.0.0.5"])
        _ledger, fresh = self._poll(w, {
            "10.0.0.6": _res("10.0.0.6", RAND_MAC_B, hostname="phone")})
        self.assertEqual(fresh, [])

    def test_known_fingerprints_exposed_for_inspection(self):
        w = self._watcher(known_devices=[
            _dev("10.0.0.2", REAL_MAC_A, hostname="nas")])
        self.assertEqual(w.known_fingerprints, {"host=nas"})

    def test_same_fingerprint_in_one_round_reports_both(self):
        """同一轮里指纹相同的两台设备都要报出来（累积必须在判断之后）。

        否则同一台机器的两个网卡、或快照里主机名重复时，第二台会被
        第一台刚加进 `known_fingerprints` 的指纹压掉 —— 白白漏报一台设备。
        """
        w = self._watcher()
        _ledger, fresh = self._poll(w, {
            "10.0.0.5": _res("10.0.0.5", RAND_MAC_A, hostname="dual-homed"),
            "10.0.0.6": _res("10.0.0.6", RAND_MAC_B, hostname="dual-homed")})
        self.assertEqual(sorted(r.ip for r in fresh),
                         ["10.0.0.5", "10.0.0.6"])


# ── ⑥ 基线助手 ────────────────────────────────────────────────────────

class LatestDevicesTest(unittest.TestCase):
    """`history_store.latest_devices()` —— 被动发现基线的来源。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "h.db")

    def test_empty_db_returns_empty_list(self):
        self.assertEqual(history_store.latest_devices(db_path=self.db), [])

    def test_returns_only_the_latest_snapshot(self):
        history_store.save_snapshot(
            [_dev("10.0.0.1", REAL_MAC_A, hostname="old")], db_path=self.db)
        history_store.save_snapshot(
            [_dev("10.0.0.2", REAL_MAC_B, hostname="new")], db_path=self.db)
        devs = history_store.latest_devices(db_path=self.db)
        self.assertEqual([d["ip"] for d in devs], ["10.0.0.2"])

    def test_ips_helper_derives_from_devices(self):
        history_store.save_snapshot(
            [_dev("10.0.0.1", REAL_MAC_A), _dev("10.0.0.2", REAL_MAC_B)],
            db_path=self.db)
        self.assertEqual(history_store.latest_device_ips(db_path=self.db),
                         {"10.0.0.1", "10.0.0.2"})


if __name__ == "__main__":
    unittest.main()
