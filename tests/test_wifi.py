# -*- coding: utf-8 -*-
"""`scanner.wifi`（v2.1 §2.2 无线切片）的单测。

验收口径（照 `docs/ROADMAP_V2.1.md` §2.2 逐条）：

1. **解析对拍**：`wlanapi` 结构体解析 + `netsh` 文本解析，用**真机抓的样本**
   （`tests/fixtures/wifi/`，来源见同目录 `PROVENANCE.md`）覆盖。
2. **切列不脆**：列宽被系统改过的样本照样切得对（**不按列宽切片**）。
3. **非 Windows 降级可测**：说「本平台无此能力」，**不抛异常**。
4. **漫游日志解析**：EventID 8000–8003 → 关联/失败/断开时间线。
5. `refresh` **默认关**：不显式要求就不发 `WlanScan`（不主动扰动射频）。

外加两条本项目的硬约定：
* `scanner/` 不许 import `i18n`；`wifi.py` 还不许 import `socket`（"数据不出网"）。
* 标签表是**匹配表**，不进 i18n。
"""
import ast
import ctypes
import io
import os
import subprocess
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import wifi  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "wifi")

#: 本机真样本里的当前关联（`interfaces.txt`）。
REAL_SSID = "QZTJXX"
REAL_BSSID = "a8:0c:ca:9c:7f:ff"
REAL_GUID = "53bf544a-bddd-49c7-8f56-caa950e05580"


def fixture(name):
    """读一个样本；`utf-8-sig` 兼容带/不带 BOM 两种文件。"""
    with io.open(os.path.join(FIXTURES, name), encoding="utf-8-sig",
                 errors="replace") as fh:
        return fh.read()


def imported_modules(source):
    """源码里 import 到的**完整模块名**集合（`import a.b` 与 `from a import b` 都算）。

    ⚠️ 必须走 AST，**不能对源码做子串匹配**：`wifi.py` 的注释里就写着
    「刻意不 import scanner.util」—— 子串匹配会把这句注释当成真 import 报红。
    """
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            found.add(base)
            for alias in node.names:      # `from scanner import ping` → scanner.ping
                found.add("%s.%s" % (base, alias.name) if base else alias.name)
    return found


def imported_roots(source):
    """`imported_modules` 的顶层模块名集合（判「有没有 import socket / i18n」）。"""
    return {m.split(".")[0] for m in imported_modules(source)}


def module_source(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# ── 解码 ────────────────────────────────────────────────────────────────

class DecodeOutputTest(unittest.TestCase):
    """同一台机器上 `netsh` 是 UTF-8、`wevtutil` 是 cp936 —— 两种都要认。"""

    def test_utf8(self):
        self.assertEqual(wifi.decode_output("无线切片".encode("utf-8")), "无线切片")

    def test_cp936(self):
        self.assertEqual(wifi.decode_output("无线切片".encode("cp936")), "无线切片")

    def test_empty_is_empty_string(self):
        self.assertEqual(wifi.decode_output(b""), "")

    def test_never_raises_on_arbitrary_bytes(self):
        """任意字节都不能抛 —— 命令输出是外部数据，抛出去就是整个功能挂掉。"""
        for i in range(256):
            out = wifi.decode_output(bytes([i]))
            self.assertIsInstance(out, str)
        self.assertIsInstance(wifi.decode_output(b"\xff\xfe\x00\x80\x81"), str)

    def test_garbage_falls_back_to_cp1252_not_exception(self):
        # utf-8 与 cp936 都解不了 → cp1252 兜底（单字节全映射）
        self.assertEqual(wifi.decode_output(b"\xff\xfe"), "ÿþ")


# ── 标签表 / 键名归一 ───────────────────────────────────────────────────

class NormKeyAndLabelTableTest(unittest.TestCase):

    def test_strips_all_whitespace_including_fullwidth(self):
        # 真样本里同一个键有 `接收速率(Mbps)` 与 `传输速率 (Mbps)` 两种写法
        self.assertEqual(wifi._norm_key(" 传输速率 (Mbps) "), "传输速率(mbps)")
        self.assertEqual(wifi._norm_key("已配置\u3000QoS"), "已配置qos")

    def test_english_and_chinese_labels_both_resolve(self):
        self.assertEqual(wifi._field_of("Transmit rate (Mbps)"), "tx_mbps")
        self.assertEqual(wifi._field_of("传输速率 (Mbps)"), "tx_mbps")
        self.assertEqual(wifi._field_of("Receive rate (Mbps)"), "rx_mbps")
        self.assertEqual(wifi._field_of("接收速率(Mbps)"), "rx_mbps")

    def test_unknown_key_returns_none_and_does_not_raise(self):
        # 换系统语言/换版本会带来一堆不需要的键，忽略是**正常路径**
        for key in ("QoS MSCS", "已配置 QoS 映射", "", "Connected Akm-cipher"):
            self.assertIsNone(wifi._field_of(key))

    def test_label_table_keys_are_normalized_and_unique(self):
        """标签表的键必须**已归一**（否则 `_field_of` 查不到 = 静默漏字段）。"""
        for table in (wifi._IFACE_KEYS, wifi._IFACE_KEYS_ZH):
            for key in table:
                self.assertEqual(key, wifi._norm_key(key), key)
        self.assertEqual(len(wifi._IFACE_KEYS), len(set(wifi._IFACE_KEYS)))

    def test_label_tables_are_matching_tables_not_display_tables(self):
        """匹配表不能进 i18n：表里的键是 netsh 的**原文**。"""
        self.assertIn("transmitrate(mbps)", wifi._IFACE_KEYS)
        self.assertIn("传输速率(mbps)", wifi._IFACE_KEYS_ZH_NORM)


# ── netsh: show interfaces ──────────────────────────────────────────────

class ParseInterfacesTest(unittest.TestCase):

    def setUp(self):
        self.ifaces = wifi.parse_interfaces(fixture("interfaces.txt"))

    def test_single_adapter_parsed(self):
        self.assertEqual(len(self.ifaces), 1)

    def test_every_field_of_the_connected_sample(self):
        i = self.ifaces[0]
        self.assertEqual(i.name, "WLAN")
        self.assertEqual(i.description, "Intel(R) Wi-Fi 6 AX201 160MHz")
        self.assertEqual(i.guid, REAL_GUID)
        self.assertEqual(i.mac, "9e:f5:32:fa:3d:42")
        self.assertEqual(i.state, wifi.STATE_CONNECTED)
        self.assertTrue(i.connected)
        self.assertEqual(i.ssid, REAL_SSID)
        self.assertEqual(i.bssid, REAL_BSSID)
        self.assertEqual(i.band, wifi.BAND_5)
        self.assertEqual(i.channel, 157)
        self.assertEqual(i.radio_type, "802.11ac")
        self.assertEqual(i.auth, "WPA2 - 个人")
        self.assertEqual(i.cipher, "CCMP")
        self.assertEqual(i.rx_mbps, 400)
        self.assertEqual(i.tx_mbps, 200)
        self.assertEqual(i.signal_percent, 87)
        self.assertEqual(i.rssi_dbm, -49)
        self.assertEqual(i.profile, REAL_SSID)

    def test_parsing_does_not_claim_a_source(self):
        """来源由取数层（`query_interface`）标记 —— 纯解析不该冒认 `wlanapi`。"""
        self.assertEqual(self.ifaces[0].source, wifi.SOURCE_NONE)

    def test_radio_state_defaults_to_unknown_when_absent(self):
        """真样本（已连接）里 netsh **不打印**无线电状态 → 如实留 None。"""
        self.assertIsNone(self.ifaces[0].radio_hardware_on)
        self.assertIsNone(self.ifaces[0].radio_software_on)

    def test_display_name_prefers_the_connection_name(self):
        self.assertEqual(self.ifaces[0].display_name, "WLAN")
        self.assertEqual(self.ifaces[0].to_dict()["display_name"], "WLAN")


class ParseInterfacesLabelIndependenceTest(unittest.TestCase):
    """同一块网卡：中文样本与英文样本必须解析出**同一份数据**。"""

    def _pairs(self, name):
        i = wifi.parse_interfaces(fixture(name))[0]
        return {k: v for k, v in i.to_dict().items() if k != "auth"}

    def test_english_sample_matches_chinese_sample(self):
        zh = self._pairs("interfaces.txt")
        en = self._pairs("interfaces_en.txt")
        for key in ("name", "guid", "mac", "state", "ssid", "bssid", "band",
                    "channel", "radio_type", "cipher", "rx_mbps", "tx_mbps",
                    "signal_percent", "rssi_dbm", "profile"):
            self.assertEqual(zh[key], en[key], key)

    def test_english_auth_text_is_kept_verbatim(self):
        """`auth` 是**设备给的原文**（随语言变），本模块不翻译、不归一。"""
        en = wifi.parse_interfaces(fixture("interfaces_en.txt"))[0]
        self.assertEqual(en.auth, "WPA2-Personal")


class ParseInterfacesColumnWidthTest(unittest.TestCase):
    """**不按列宽切片**：分隔空白被系统改过（变宽 / 换制表符）也要切对。"""

    def test_wide_padding_and_tabs_still_parse(self):
        padded = wifi.parse_interfaces(fixture("interfaces_wide_pad.txt"))
        real = wifi.parse_interfaces(fixture("interfaces.txt"))
        self.assertEqual(len(padded), 1)
        self.assertEqual(padded[0].to_dict(), real[0].to_dict())

    def test_value_containing_many_spaces_is_kept_intact(self):
        """反例：如果按列宽切片，`Intel(R) Wi-Fi 6 AX201 160MHz` 会被切碎。"""
        i = wifi.parse_interfaces(fixture("interfaces_wide_pad.txt"))[0]
        self.assertEqual(i.description, "Intel(R) Wi-Fi 6 AX201 160MHz")

    def test_split_is_on_the_first_colon_only(self):
        """`Connected Akm-cipher ： [ akm = 00-0f-ac：02 ]` 里有全角冒号与多个冒号。"""
        text = "    名称 : WLAN\n    配置文件 : a:b:c\n"
        i = wifi.parse_interfaces(text)[0]
        self.assertEqual(i.profile, "a:b:c")


class ParseInterfacesRobustnessTest(unittest.TestCase):

    def test_disconnected_sample(self):
        i = wifi.parse_interfaces(fixture("interfaces_disconnected.txt"))[0]
        self.assertEqual(i.state, wifi.STATE_DISCONNECTED)
        self.assertFalse(i.connected)
        self.assertEqual(i.ssid, "")
        self.assertIsNone(i.channel)
        self.assertEqual(i.band, wifi.BAND_UNKNOWN)

    def test_radio_state_continuation_line_merges_into_previous_key(self):
        """`无线电状态: 硬件 开` + 无冒号的续行 `软件 开` → 两个布尔。"""
        i = wifi.parse_interfaces(fixture("interfaces_disconnected.txt"))[0]
        self.assertTrue(i.radio_hardware_on)
        self.assertTrue(i.radio_software_on)

    def test_radio_off_text_yields_no_interfaces(self):
        """radio 关时 `show interfaces` 是报错文本 → 空列表，不是异常。"""
        self.assertEqual(wifi.parse_interfaces(fixture("networks_radio_off.txt")), [])

    def test_empty_and_garbage_input(self):
        for text in ("", "\n\n", "完全无关的一行", "a: b\nc: d"):
            self.assertEqual(wifi.parse_interfaces(text), [])

    def test_accepts_bytes_and_none(self):
        raw = fixture("interfaces.txt").encode("utf-8")
        self.assertEqual(len(wifi.parse_interfaces(raw)), 1)
        self.assertEqual(wifi.parse_interfaces(None), [])

    def test_multiple_adapters_start_a_new_record_on_name(self):
        text = ("    名称 : WLAN\n    状态 : 已连接\n"
                "    名称 : 以太网\n    状态 : 已断开连接\n")
        out = wifi.parse_interfaces(text)
        self.assertEqual([i.name for i in out], ["WLAN", "以太网"])

    def test_keys_before_the_first_name_are_ignored(self):
        text = "系统上有 1 个接口:\n    状态 : 已连接\n    名称 : WLAN\n"
        out = wifi.parse_interfaces(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].name, "WLAN")


# ── netsh: show networks mode=bssid ─────────────────────────────────────

class ParseNetworksTest(unittest.TestCase):

    def setUp(self):
        self.bss = wifi.parse_networks(fixture("networks_bssid.txt"))

    def test_bss_count_and_ssid_groups(self):
        self.assertEqual(len(self.bss), 78)
        self.assertEqual(len({b.ssid for b in self.bss}), 5)

    def test_every_entry_has_a_bssid_and_no_entry_was_dropped(self):
        self.assertTrue(all(b.bssid for b in self.bss))
        for b in self.bss:
            self.assertRegex(b.bssid, r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")

    def test_group_level_attributes_are_inherited_by_every_bss(self):
        """身份验证/加密在 `SSID n` 组级，每个 BSSID 必须继承到。"""
        self.assertTrue(all(b.auth == "WPA2 - 个人" for b in self.bss))
        self.assertTrue(all(b.cipher == "CCMP" for b in self.bss))

    def test_bss_level_attributes_are_per_entry(self):
        by_bssid = {b.bssid: b for b in self.bss}
        a = by_bssid["a8:0c:ca:1c:80:16"]      # 2.4 GHz / ch 11 / 83%
        b = by_bssid["a8:0c:ca:9c:82:03"]      # 5 GHz   / ch 36 / 18%
        self.assertEqual((a.band, a.channel, a.signal_percent), (wifi.BAND_24, 11, 83))
        self.assertEqual((b.band, b.channel, b.signal_percent), (wifi.BAND_5, 36, 18))

    def test_currently_associated_bssid_is_present(self):
        self.assertIn(REAL_BSSID, {b.bssid for b in self.bss})

    def test_hidden_ssid_is_not_a_parse_failure(self):
        """构造样本：空 SSID 组要标 `ssid_known=False`，而不是当成"没解析到"。"""
        text = ("SSID 1 : \n    身份验证 : 开放式\n    加密 : 无\n"
                "    BSSID 1 : 02:00:00:00:00:01\n         信号 : 60%\n"
                "         波段 : 2.4 GHz\n         通道 : 6\n"
                "SSID 2 : Home\n    身份验证 : WPA2 - 个人\n    加密 : CCMP\n"
                "    BSSID 1 : 02:00:00:00:00:02\n         信号 : 70%\n"
                "         波段 : 5 GHz\n         通道 : 44\n")
        out = wifi.parse_networks(text)
        self.assertEqual(len(out), 2)
        hidden, home = out
        self.assertEqual(hidden.ssid, "")
        self.assertFalse(hidden.ssid_known)
        self.assertEqual(hidden.auth, "开放式")
        self.assertEqual(home.ssid, "Home")
        self.assertTrue(home.ssid_known)
        self.assertEqual((home.band, home.channel), (wifi.BAND_5, 44))

    def test_english_sample(self):
        out = wifi.parse_networks(fixture("networks_bssid_en.txt"))
        self.assertEqual(len(out), 3)
        first = out[0]
        self.assertEqual(first.ssid, REAL_SSID)
        self.assertEqual(first.bssid, "a8:0c:ca:1c:80:16")
        self.assertEqual(first.auth, "WPA2-Personal")
        self.assertEqual(first.cipher, "CCMP")
        self.assertEqual((first.band, first.channel, first.signal_percent),
                         (wifi.BAND_24, 11, 83))
        self.assertEqual(first.radio_type, "802.11n")

    def test_radio_off_text_yields_no_bss(self):
        self.assertEqual(wifi.parse_networks(fixture("networks_radio_off.txt")), [])

    def test_empty_and_garbage_input(self):
        for text in ("", "接口名称 : WLAN", "随便一行"):
            self.assertEqual(wifi.parse_networks(text), [])

    def test_group_header_regex_is_anchored_at_line_start(self):
        """`名称 : SSID 1:xxx` 不能被误判成组头（正则锚在行首）。"""
        text = ("SSID 1 : Real\n    名称 : SSID 9:fake\n"
                "    BSSID 1 : 02:00:00:00:00:09\n")
        out = wifi.parse_networks(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].ssid, "Real")


class ParseNetworksBssLevelTest(unittest.TestCase):
    """BSS 级属性要**覆盖**组级打底值（两级结构里最容易写反的一处）。"""

    def test_bss_level_auth_and_cipher_override_the_group(self):
        text = ("SSID 1 : Group\n    身份验证 : 开放式\n    加密 : 无\n"
                "    BSSID 1 : 02:00:00:00:00:01\n"
                "         身份验证 : WPA2 - 个人\n         加密 : CCMP\n"
                "         信号 : 50%\n")
        out = wifi.parse_networks(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].auth, "WPA2 - 个人")
        self.assertEqual(out[0].cipher, "CCMP")
        self.assertEqual(out[0].signal_percent, 50)

    def test_plain_bssid_line_inside_a_bss_overrides(self):
        text = ("SSID 1 : G\n    BSSID 1 : 02:00:00:00:00:01\n"
                "         BSSID : 02:00:00:00:00:0a\n")
        self.assertEqual(wifi.parse_networks(text)[0].bssid, "02:00:00:00:00:0a")

    def test_non_mac_bssid_value_is_ignored(self):
        """隐藏 SSID 组里可能出现空行/异常行 —— 不能把垃圾写成 BSSID。"""
        text = ("SSID 1 : G\n    BSSID 1 : 02:00:00:00:00:01\n"
                "         BSSID : 不是 MAC\n")
        self.assertEqual(wifi.parse_networks(text)[0].bssid, "02:00:00:00:00:01")


class ScalarHelpersTest(unittest.TestCase):

    def test_to_state_accepts_both_languages(self):
        for text, want in (("已连接", wifi.STATE_CONNECTED),
                           ("connected", wifi.STATE_CONNECTED),
                           ("已断开连接", wifi.STATE_DISCONNECTED),
                           ("disconnected", wifi.STATE_DISCONNECTED),
                           ("", wifi.STATE_UNKNOWN), ("???", wifi.STATE_UNKNOWN)):
            self.assertEqual(wifi._to_state(text), want, text)

    def test_transition_states_are_not_treated_as_connected(self):
        """过渡态时 SSID 可能还是上一次的 —— 当成"已连接"会显示错 AP。"""
        for text in ("正在连接", "正在断开连接", "authenticating", "associating",
                     "disconnecting", "discovering"):
            self.assertEqual(wifi._to_state(text), wifi.STATE_DISCONNECTED, text)

    def test_to_int(self):
        for text, want in (("157", 157), (" -49 ", -49), ("", None),
                           ("x", None), ("1.5", None), ("400", 400)):
            self.assertEqual(wifi._to_int(text), want, text)

    def test_to_percent_rejects_out_of_range(self):
        for text, want in (("87%", 87), ("87 %", 87), ("100%", 100),
                           ("120%", None), ("x", None), ("", None)):
            self.assertEqual(wifi._to_percent(text), want, text)

    def test_band_of_text_out_of_range(self):
        for text in ("9 GHz", "3 GHz", "1 GHz"):
            self.assertEqual(wifi.band_of_text(text), wifi.BAND_UNKNOWN, text)

    def test_mac_text(self):
        self.assertEqual(wifi._mac_text((0xA8, 0x0C, 0xCA, 0x9C, 0x7F, 0xFF)),
                         REAL_BSSID)

    def test_phy_type_table(self):
        self.assertEqual(wifi._PHY_TYPES[8], "802.11ac")
        self.assertEqual(wifi._PHY_TYPES[10], "802.11ax")


# ── 频率 / 波段换算（纯函数） ───────────────────────────────────────────

class FrequencyTest(unittest.TestCase):

    def test_band_for_frequency(self):
        cases = [(2412000, wifi.BAND_24), (2484000, wifi.BAND_24),
                 (5180000, wifi.BAND_5), (5745000, wifi.BAND_5),
                 (5955000, wifi.BAND_6), (0, wifi.BAND_UNKNOWN),
                 (900000, wifi.BAND_UNKNOWN)]
        for khz, want in cases:
            self.assertEqual(wifi.band_for_frequency_khz(khz), want, khz)

    def test_channel_for_frequency_uses_the_three_standard_formulas(self):
        cases = [(2412000, 1), (2437000, 6), (2462000, 11), (2484000, 14),
                 (5180000, 36), (5745000, 149), (5955000, 1)]
        for khz, want in cases:
            self.assertEqual(wifi.channel_for_frequency_khz(khz), want, khz)

    def test_channel_is_none_when_it_cannot_be_derived(self):
        """算不出来就返回 `None` —— **不猜**一个看起来合理的信道号。"""
        self.assertIsNone(wifi.channel_for_frequency_khz(0))
        self.assertIsNone(wifi.channel_for_frequency_khz(900000))

    def test_band_of_text(self):
        cases = [("5 GHz", wifi.BAND_5), ("2.4 GHz", wifi.BAND_24),
                 ("5GHz", wifi.BAND_5), ("6 GHz", wifi.BAND_6),
                 ("", wifi.BAND_UNKNOWN), ("未知", wifi.BAND_UNKNOWN)]
        for text, want in cases:
            self.assertEqual(wifi.band_of_text(text), want, text)

    def test_band_for_channel_is_the_inverse(self):
        self.assertEqual(wifi._band_for_channel(1), wifi.BAND_24)
        self.assertEqual(wifi._band_for_channel(14), wifi.BAND_24)
        self.assertEqual(wifi._band_for_channel(36), wifi.BAND_5)
        self.assertEqual(wifi._band_for_channel(177), wifi.BAND_5)
        self.assertEqual(wifi._band_for_channel(200), wifi.BAND_6)
        self.assertEqual(wifi._band_for_channel(0), wifi.BAND_UNKNOWN)


# ── 信道拥塞（纯函数） ──────────────────────────────────────────────────

class ChannelLoadsTest(unittest.TestCase):

    def setUp(self):
        self.bss = wifi.parse_networks(fixture("networks_bssid.txt"))

    def test_band_defaults_to_the_most_populated_one(self):
        loads = wifi.channel_loads(self.bss)
        self.assertTrue(loads)
        self.assertEqual({c.band for c in loads}, {wifi.BAND_24})

    def test_explicit_band_5g(self):
        loads = wifi.channel_loads(self.bss, band=wifi.BAND_5)
        self.assertEqual(sorted(c.channel for c in loads), [36, 44, 149, 157])
        self.assertEqual({c.band for c in loads}, {wifi.BAND_5})

    def test_ap_count_matches_the_sample(self):
        loads = {c.channel: c.ap_count
                 for c in wifi.channel_loads(self.bss, band=wifi.BAND_24)}
        self.assertEqual(loads, {1: 13, 6: 17, 11: 17})

    def test_current_channel_is_marked(self):
        loads = wifi.channel_loads(self.bss, band=wifi.BAND_5, current_channel=157)
        marked = [c.channel for c in loads if c.is_current]
        self.assertEqual(marked, [157])

    def test_2g_overlapping_counts_neighbour_channels(self):
        """`overlapping` 是"同频 + 邻频干扰源总数"，所以必然 ≥ 本信道 AP 数。"""
        loads = wifi.channel_loads(self.bss, band=wifi.BAND_24)
        for c in loads:
            self.assertGreaterEqual(c.overlapping, c.ap_count)

    def test_2g_overlapping_is_actually_wider_when_neighbours_exist(self):
        """构造：信道 1 与 3 只差 2 → 互相算进 `overlapping`（同信道统计看不出来）。"""
        bss = [wifi.WifiBss(bssid="02:00:00:00:00:01", band=wifi.BAND_24, channel=1),
               wifi.WifiBss(bssid="02:00:00:00:00:02", band=wifi.BAND_24, channel=3),
               wifi.WifiBss(bssid="02:00:00:00:00:03", band=wifi.BAND_24, channel=11)]
        loads = {c.channel: c for c in wifi.channel_loads(bss, band=wifi.BAND_24)}
        self.assertEqual(loads[1].ap_count, 1)
        self.assertEqual(loads[1].overlapping, 2)   # 自己 + 信道 3
        self.assertEqual(loads[11].overlapping, 1)  # 只有自己

    def test_5g_has_no_overlap_concept(self):
        loads = wifi.channel_loads(self.bss, band=wifi.BAND_5)
        self.assertTrue(all(c.overlapping == 0 for c in loads))

    def test_strongest_signal(self):
        bss = [wifi.WifiBss(bssid="02:00:00:00:00:01", band=wifi.BAND_5,
                            channel=36, signal_percent=10),
               wifi.WifiBss(bssid="02:00:00:00:00:02", band=wifi.BAND_5,
                            channel=36, signal_percent=90)]
        load = wifi.channel_loads(bss, band=wifi.BAND_5)[0]
        self.assertEqual(load.strongest_signal, 90)

    def test_entries_without_a_channel_are_skipped(self):
        bss = [wifi.WifiBss(bssid="02:00:00:00:00:01", band=wifi.BAND_5, channel=None)]
        self.assertEqual(wifi.channel_loads(bss, band=wifi.BAND_5), [])

    def test_empty_input(self):
        self.assertEqual(wifi.channel_loads([], band=wifi.BAND_5), [])

    def test_quietest_2g_only_considers_1_6_11(self):
        """在一个 1–13 全重叠的波段里推荐信道 3 是**错**的建议。"""
        loads = [wifi.ChannelLoad(band=wifi.BAND_24, channel=3, ap_count=0),
                 wifi.ChannelLoad(band=wifi.BAND_24, channel=6, ap_count=5),
                 wifi.ChannelLoad(band=wifi.BAND_24, channel=1, ap_count=9),
                 wifi.ChannelLoad(band=wifi.BAND_24, channel=11, ap_count=7)]
        self.assertEqual(wifi.quietest_channel(loads, band=wifi.BAND_24), 6)

    def test_quietest_2g_without_1_6_11_says_none(self):
        loads = [wifi.ChannelLoad(band=wifi.BAND_24, channel=3, ap_count=0)]
        self.assertIsNone(wifi.quietest_channel(loads, band=wifi.BAND_24))

    def test_quietest_5g_is_plain_minimum(self):
        loads = [wifi.ChannelLoad(band=wifi.BAND_5, channel=36, ap_count=12),
                 wifi.ChannelLoad(band=wifi.BAND_5, channel=149, ap_count=3)]
        self.assertEqual(wifi.quietest_channel(loads, band=wifi.BAND_5), 149)

    def test_quietest_ties_break_on_lower_channel(self):
        loads = [wifi.ChannelLoad(band=wifi.BAND_5, channel=44, ap_count=3),
                 wifi.ChannelLoad(band=wifi.BAND_5, channel=36, ap_count=3)]
        self.assertEqual(wifi.quietest_channel(loads, band=wifi.BAND_5), 36)

    def test_quietest_empty(self):
        self.assertIsNone(wifi.quietest_channel([], band=wifi.BAND_5))

    def test_snapshot_channel_loads_follows_the_current_connection(self):
        snap = wifi.WifiSnapshot(capability=wifi.WifiCapability(True),
                                 interface=wifi.WifiInterface(
                                     state=wifi.STATE_CONNECTED, band=wifi.BAND_5,
                                     channel=157),
                                 bss_list=self.bss)
        self.assertEqual({c.band for c in snap.channel_loads()}, {wifi.BAND_5})
        self.assertEqual([c.channel for c in snap.channel_loads() if c.is_current],
                         [157])


# ── 漫游时间线 ──────────────────────────────────────────────────────────

class ParseRoamingXmlTest(unittest.TestCase):

    def setUp(self):
        self.events = wifi.parse_roaming_xml(fixture("roaming_events.xml"))

    def test_only_association_level_event_ids_are_kept(self):
        self.assertEqual({e.event_id for e in self.events},
                         {"8000", "8001", "8002", "8003"})

    def test_counts(self):
        kinds = [e.kind for e in self.events]
        self.assertEqual(kinds.count(wifi.ROAM_ATTEMPT), 3)
        self.assertEqual(kinds.count(wifi.ROAM_ASSOCIATED), 3)
        self.assertEqual(kinds.count(wifi.ROAM_FAILED), 1)
        self.assertEqual(kinds.count(wifi.ROAM_DISCONNECTED), 1)

    def test_sorted_ascending_by_time(self):
        stamps = [e.timestamp for e in self.events]
        self.assertEqual(stamps, sorted(stamps))

    def test_timestamps_are_timezone_aware_utc(self):
        for e in self.events:
            self.assertIsNotNone(e.timestamp)
            self.assertIsNotNone(e.timestamp.tzinfo)
            self.assertEqual(e.timestamp.utcoffset().total_seconds(), 0)

    def test_failed_event_carries_the_reason(self):
        failed = [e for e in self.events if e.kind == wifi.ROAM_FAILED]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].ssid, REAL_SSID)
        self.assertTrue(failed[0].reason_code)
        self.assertTrue(failed[0].reason_text)

    def test_timeline_is_ssid_granular_not_ap_granular(self):
        """AutoConfig 的这几条事件**不带 BSSID** —— 不能标成"漫游到某个 AP"。"""
        for e in self.events:
            self.assertNotIn("bssid", e.to_dict())
        self.assertTrue(all(e.ssid for e in self.events))

    def test_internal_11xxx_events_are_skipped(self):
        raw = fixture("roaming_events.xml")
        self.assertIn("11005", raw)          # 样本里确实有
        self.assertNotIn("11005", {e.event_id for e in self.events})

    def test_garbage_and_empty_input(self):
        for xml in ("", "not xml at all", "<Event></Event>",
                    "<Event><EventID>9999</EventID></Event>"):
            self.assertEqual(wifi.parse_roaming_xml(xml), [])

    def test_event_without_timestamp_is_kept_but_sorted_last(self):
        xml = ("<Event><EventID>8000</EventID>"
               "<EventData><Data Name='SSID'>X</Data></EventData></Event>"
               "<Event><EventID>8001</EventID>"
               "<TimeCreated SystemTime='2026-01-01T00:00:00.0000000Z'/>"
               "<EventData><Data Name='SSID'>X</Data></EventData></Event>")
        out = wifi.parse_roaming_xml(xml)
        self.assertEqual([e.timestamp is None for e in out], [False, True])


class SystemTimeTest(unittest.TestCase):
    """事件日志的时间戳小数位是 **7 位**（100ns），`fromisoformat` 只认 3/6 位。"""

    def test_seven_digit_fraction_with_z(self):
        dt = wifi._parse_system_time("2026-10-13T06:37:30.1875366Z")
        self.assertEqual(dt.year, 2026)
        self.assertEqual((dt.hour, dt.minute, dt.second), (6, 37, 30))
        self.assertEqual(dt.microsecond, 187536)
        self.assertEqual(dt.utcoffset().total_seconds(), 0)

    def test_explicit_offset_is_normalized_to_utc(self):
        dt = wifi._parse_system_time("2026-10-13T14:37:30.1875366+08:00")
        self.assertEqual(dt.hour, 6)

    def test_naive_value_is_assumed_utc(self):
        dt = wifi._parse_system_time("2026-10-13T06:37:30.1875366")
        self.assertEqual(dt.utcoffset().total_seconds(), 0)

    def test_empty_and_garbage(self):
        for value in ("", "   ", "not a time", "2026-13-45T99:99:99"):
            self.assertIsNone(wifi._parse_system_time(value))

    def test_value_without_fraction_or_offset(self):
        """既没有小数位也没有时区后缀 → `fromisoformat` 给 naive，按 UTC 补齐。"""
        dt = wifi._parse_system_time("2026-10-13T06:37:30")
        self.assertEqual(dt.utcoffset().total_seconds(), 0)


class RoamingEventsTest(unittest.TestCase):

    def test_injected_xml_uses_the_wevtutil_source(self):
        events, source = wifi.roaming_events(xml_text=fixture("roaming_events.xml"))
        self.assertEqual(source, wifi.SOURCE_WEVTUTIL)
        self.assertTrue(events)

    def test_empty_log_is_reported_as_no_source(self):
        events, source = wifi.roaming_events(xml_text="")
        self.assertEqual((events, source), ([], wifi.SOURCE_NONE))

    def test_non_windows_without_injection_returns_nothing(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", False):
            events, source = wifi.roaming_events()
        self.assertEqual((events, source), ([], wifi.SOURCE_NONE))

    def test_limit_keeps_the_newest_events(self):
        xml = "".join(
            "<Event><EventID>8000</EventID>"
            "<TimeCreated SystemTime='2026-01-0%dT00:00:00.0000000Z'/>"
            "<EventData><Data Name='SSID'>S%d</Data></EventData></Event>" % (i, i)
            for i in range(1, 6))
        events, _ = wifi.roaming_events(limit=2, xml_text=xml)
        self.assertEqual([e.ssid for e in events], ["S4", "S5"])

    def test_real_path_calls_wevtutil_read_only(self):
        """**只读**：`qe` + `/rd:true`（新→旧）+ `/f:xml`，不改任何日志设置。"""
        with mock.patch.object(wifi, "_IS_WINDOWS", True), \
                mock.patch.object(wifi, "_run", return_value="") as runner:
            wifi.roaming_events(limit=50)
        args, kwargs = runner.call_args
        self.assertEqual(args[0], ["wevtutil", "qe", wifi.ROAM_CHANNEL,
                                   "/c:50", "/rd:true", "/f:xml"])
        self.assertEqual(kwargs["timeout"], 20)


# ── SSID ↔ 网段关联（纯投影） ───────────────────────────────────────────

class LinkSubnetsTest(unittest.TestCase):

    def setUp(self):
        self.iface = wifi.parse_interfaces(fixture("interfaces.txt"))[0]

    def test_match_by_adapter_name(self):
        out = wifi.link_subnets(self.iface, [("无线局域网适配器 WLAN", "192.168.1.0/24"),
                                             ("以太网", "10.0.0.0/8")])
        self.assertEqual(out["matched"], ["192.168.1.0/24"])
        self.assertEqual(out["all"], ["10.0.0.0/8", "192.168.1.0/24"])
        self.assertEqual(out["matched_by"], wifi.MATCH_BY_NAME)

    def test_match_by_keyword_when_the_name_does_not_contain_it(self):
        """`Intel(R) Wi-Fi 6 AX201` 这种描述靠特征词命中。"""
        iface = wifi.WifiInterface(name="", description="Intel(R) Wi-Fi 6 AX201 160MHz")
        out = wifi.link_subnets(iface, [("Wi-Fi", "192.168.1.0/24")])
        self.assertEqual(out["matched"], ["192.168.1.0/24"])
        self.assertEqual(out["matched_by"], wifi.MATCH_BY_KEYWORD)

    def test_no_match_is_reported_honestly(self):
        out = wifi.link_subnets(self.iface, [("以太网", "10.0.0.0/8")])
        self.assertEqual(out["matched"], [])
        self.assertEqual(out["all"], ["10.0.0.0/8"])
        self.assertEqual(out["matched_by"], wifi.MATCH_BY_NONE)

    def test_does_not_pass_off_all_subnets_as_wireless_subnets(self):
        out = wifi.link_subnets(self.iface, [("以太网", "10.0.0.0/8")])
        self.assertNotEqual(out["matched"], out["all"])

    def test_no_pairs_and_no_interface(self):
        self.assertEqual(wifi.link_subnets(self.iface, [])["matched_by"],
                         wifi.MATCH_BY_NONE)
        self.assertEqual(wifi.link_subnets(None, [("Wi-Fi", "1.2.3.0/24")])["matched"],
                         [])

    def test_all_cidrs_are_deduped_and_sorted(self):
        out = wifi.link_subnets(self.iface, [("以太网", "10.0.0.0/8"),
                                             ("以太网 2", "10.0.0.0/8"),
                                             ("以太网 3", "1.0.0.0/8")])
        self.assertEqual(out["all"], ["1.0.0.0/8", "10.0.0.0/8"])

    def test_module_does_not_import_socket_holders(self):
        """`link_subnets` 是纯投影 —— 网段必须由调用方给（见 docstring）。

        一旦 import 了 `scanner.ping` / `scanner.util`，本模块就间接持有
        `socket`，「数据不出网」再也**证明不了**。
        """
        mods = imported_modules(module_source("scanner/wifi.py"))
        for banned in ("scanner.util", "scanner.ping", "scanner.netif", "socket"):
            self.assertNotIn(banned, mods, "wifi.py 不该 import %s" % banned)


class AdapterSubnetParseTest(unittest.TestCase):
    """`ipconfig` → `[(适配器名, CIDR)]`。

    🔴 这份解析是**故意**与 `scanner/ping.py` 重复的（那个模块 `import socket`，
    本模块不能依赖它）—— 所以这里必须**对拍**：同一份文本，两份实现给出的
    (ip, 掩码) 必须逐条一致。否则两条路径会悄悄分叉。
    """

    def test_real_chinese_sample(self):
        self.assertEqual(
            wifi.parse_adapter_subnets(fixture("ipconfig.txt")),
            [("无线局域网适配器 WLAN", "10.193.27.0/24"),
             ("以太网适配器 vEthernet (WSL (Hyper-V firewall))", "172.28.80.0/20")])

    def test_english_sample(self):
        self.assertEqual(
            wifi.parse_adapter_subnets(fixture("ipconfig_en.txt")),
            [("Wireless LAN adapter WLAN", "192.168.1.0/24"),
             ("Ethernet adapter vEthernet (WSL (Hyper-V firewall))", "172.28.80.0/20")])

    def test_adapter_name_with_nested_parens_and_colons(self):
        """`vEthernet (WSL (Hyper-V firewall)):` 里有两层括号，名字不能切错。"""
        names = [n for n, _c in wifi.parse_adapter_subnets(fixture("ipconfig.txt"))]
        self.assertIn("以太网适配器 vEthernet (WSL (Hyper-V firewall))", names)

    def test_disconnected_adapters_contribute_nothing(self):
        """`媒体已断开连接` 的适配器没有 IPv4 → 不该产出条目。"""
        names = [n for n, _c in wifi.parse_adapter_subnets(fixture("ipconfig.txt"))]
        self.assertNotIn("以太网适配器 以太网", names)
        self.assertNotIn("无线局域网适配器 本地连接* 1", names)

    def test_matches_the_scanner_side_parser_pair_for_pair(self):
        """🔴 交叉对拍：两条实现必须给出同一批 (ip, 掩码)（顺序也一致）。"""
        from scanner.ping import parse_windows_ipconfig
        import ipaddress
        for name in ("ipconfig.txt", "ipconfig_en.txt"):
            text = fixture(name)
            mine = wifi.parse_adapter_subnets(text)
            theirs = parse_windows_ipconfig(text)
            self.assertEqual(len(mine), len(theirs), name)
            for (_adapter, cidr), (ip, mask) in zip(mine, theirs):
                self.assertEqual(
                    str(ipaddress.ip_network("%s/%s" % (ip, mask), strict=False)),
                    cidr, name)

    def test_ip_must_come_before_mask_to_pair(self):
        """先掩码后地址不该成对（多网卡场景会错位配对）。"""
        text = ("以太网适配器 以太网:\n"
                "   子网掩码  . . . . . . : 255.255.255.0\n"
                "   IPv4 地址 . . . . . . : 10.0.0.5\n")
        self.assertEqual(wifi.parse_adapter_subnets(text), [])

    def test_invalid_mask_is_dropped_not_guessed(self):
        """非连续掩码（`255.0.255.0`）不是合法掩码 → 丢掉这一对，不猜网段。

        ⚠️ 别拿 `0.0.0.0` 当反例：它是**合法**掩码（前缀长度 0），
        `ip_network(strict=False)` 会给出 `0.0.0.0/0`。
        """
        text = ("以太网适配器 以太网:\n"
                "   IPv4 地址 . . . . . . : 10.0.0.5\n"
                "   子网掩码  . . . . . . : 255.0.255.0\n")
        self.assertEqual(wifi.parse_adapter_subnets(text), [])

    def test_empty_and_garbage(self):
        for text in ("", "\n\n", "Windows IP 配置", "IPv4 地址 : 1.2.3.4", None):
            self.assertEqual(wifi.parse_adapter_subnets(text), [])

    def test_accepts_bytes(self):
        raw = fixture("ipconfig.txt").encode("utf-8")
        self.assertEqual(len(wifi.parse_adapter_subnets(raw)), 2)

    def test_local_adapter_subnets_is_windows_only(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", False):
            self.assertEqual(wifi.local_adapter_subnets(), [])

    def test_local_adapter_subnets_runs_ipconfig(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", True), \
                mock.patch.object(wifi, "_run",
                                  return_value=fixture("ipconfig.txt")) as runner:
            out = wifi.local_adapter_subnets()
        self.assertEqual(runner.call_args[0][0], ["ipconfig"])
        self.assertEqual(out[0], ("无线局域网适配器 WLAN", "10.193.27.0/24"))

    def test_snapshot_autodetects_adapter_subnets_when_not_given(self):
        """不给 `adapter_subnets` → 自动跑 `ipconfig`；显式给 `[]` → 就是不关联。

        ⚠️ 必须连 `_IS_WINDOWS` 一起 patch：`local_adapter_subnets()` 自己有一道
        平台闸门（非 Windows 直接返回 `[]`，免得去跑 macOS 那个**同名但语义不同**的
        `ipconfig`）。不 patch 的话这条用例在 CI 的 Linux / macOS job 上会退化成
        `subnet_match == none` —— 本机 Windows 上照样绿，本地看不出来。
        """
        api = connected_stub()
        with mock.patch.object(wifi, "_IS_WINDOWS", True), \
                mock.patch.object(wifi, "_run",
                                  return_value=fixture("ipconfig.txt")):
            snap = wifi.snapshot(api, netsh_interfaces=fixture("interfaces.txt"),
                                 netsh_networks="", roaming_xml="")
        self.assertEqual(snap.subnet_match, wifi.MATCH_BY_NAME)
        self.assertEqual(snap.subnets, ["10.193.27.0/24"])

    def test_explicit_empty_list_means_no_association(self):
        snap = wifi.snapshot(connected_stub(),
                             netsh_interfaces=fixture("interfaces.txt"),
                             netsh_networks="", roaming_xml="",
                             adapter_subnets=[])
        self.assertEqual(snap.subnet_match, wifi.MATCH_BY_NONE)
        self.assertIn(wifi.NOTE_NO_SUBNET, snap.notes)


# ── 能力探测与取数（替身注入） ──────────────────────────────────────────

class StubApi:
    """`_WlanApi` 的替身：只覆盖公开方法（那是设计好的注入点）。"""

    def __init__(self, *, ifaces=None, conn=None, channel=None, entries=None,
                 open_error=None, bss_error=None, scan_error=None):
        self._ifaces = ifaces
        self._conn = conn
        self._channel = channel
        self._entries = entries if entries is not None else []
        self._open_error = open_error
        self._bss_error = bss_error
        self._scan_error = scan_error
        self.scan_calls = []
        self.closed = 0

    def open(self):
        if self._open_error is not None:
            raise self._open_error
        return "handle"

    def close(self, handle):
        self.closed += 1

    def interfaces(self, handle):
        return self._ifaces if self._ifaces is not None else [self.default_iface()]

    @staticmethod
    def default_iface():
        return {"guid": object(), "guid_text": "{stub-guid}",
                "description": "Intel(R) Wi-Fi 6 AX201 160MHz",
                "state": wifi.STATE_CONNECTED}

    def current_connection(self, handle, guid):
        return self._conn

    def channel_number(self, handle, guid):
        return self._channel

    def bss_list(self, handle, guid):
        if self._bss_error is not None:
            raise self._bss_error
        return self._entries

    def scan(self, handle, guid):
        if self._scan_error is not None:
            raise self._scan_error
        self.scan_calls.append(guid)


def connected_stub(**kw):
    """一块"已连上 QZTJXX / 5 GHz / ch157"的替身网卡。"""
    kw.setdefault("conn", {"ssid": REAL_SSID, "bssid": REAL_BSSID,
                           "radio_type": "802.11ac", "signal_percent": 87,
                           "rx_mbps": 400, "tx_mbps": 200, "profile": REAL_SSID})
    kw.setdefault("channel", 157)
    return StubApi(**kw)


class CapabilityTest(unittest.TestCase):

    def test_non_windows_says_so_without_raising(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", False):
            cap = wifi.capability()
        self.assertFalse(cap.supported)
        self.assertEqual(cap.reason, wifi.REASON_NOT_WINDOWS)
        self.assertTrue(cap.detail)

    def test_injected_api_wins_even_on_a_non_windows_platform(self):
        """🔴 注入即硬覆盖：`_IS_WINDOWS` 只管"要不要自己去加载 dll"。

        没有这条，整条 `snapshot()` 流水线在 CI 的 Linux / macOS job 上会被
        `not-windows` 直接短路 —— 18 条用例集体失败（2026-10-13 就是这么红的，
        而本机 Windows 上**全绿**，本地根本看不出来）。
        """
        api = connected_stub()
        with mock.patch.object(wifi, "_IS_WINDOWS", False):
            cap = wifi.capability(api)
        self.assertTrue(cap.supported)
        self.assertEqual(cap.reason, wifi.REASON_OK)

    def test_no_wlanapi(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", True), \
                mock.patch.object(wifi, "_load_wlanapi", return_value=None):
            cap = wifi.capability()
        self.assertFalse(cap.supported)
        self.assertEqual(cap.reason, wifi.REASON_NO_WLANAPI)

    def test_service_stopped_is_distinguished_from_generic_failure(self):
        api = StubApi(open_error=OSError(1062, "service not running"))
        cap = wifi.capability(api)
        self.assertEqual(cap.reason, wifi.REASON_SERVICE_STOPPED)

    def test_generic_open_failure(self):
        cap = wifi.capability(StubApi(open_error=OSError(5, "access denied")))
        self.assertEqual(cap.reason, wifi.REASON_QUERY_FAILED)

    def test_no_adapter(self):
        cap = wifi.capability(StubApi(ifaces=[]))
        self.assertFalse(cap.supported)
        self.assertEqual(cap.reason, wifi.REASON_NO_ADAPTER)

    def test_ok_and_handle_is_closed(self):
        api = connected_stub()
        cap = wifi.capability(api)
        self.assertTrue(cap.supported)
        self.assertEqual(cap.reason, wifi.REASON_OK)
        self.assertEqual(api.closed, 1)

    def test_interface_enumeration_failure_is_a_query_failure(self):
        class Api(StubApi):
            def interfaces(self, handle):
                raise OSError(5, "denied")
        cap = wifi.capability(Api())
        self.assertFalse(cap.supported)
        self.assertEqual(cap.reason, wifi.REASON_QUERY_FAILED)


class QueryInterfaceTest(unittest.TestCase):

    def test_netsh_text_is_a_hard_override(self):
        """🔴 真机上 wlanapi 永远可用 —— 不给硬覆盖就永远测不到降级分支。"""
        iface, source = wifi.query_interface(netsh_text=fixture("interfaces.txt"))
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(iface.ssid, REAL_SSID)
        self.assertEqual(iface.source, wifi.SOURCE_NETSH)

    def test_wlanapi_path_fills_everything_from_the_connection(self):
        api = connected_stub()
        iface, source = wifi.query_interface(api)
        self.assertEqual(source, wifi.SOURCE_WLANAPI)
        self.assertEqual(iface.state, wifi.STATE_CONNECTED)
        self.assertEqual(iface.ssid, REAL_SSID)
        self.assertEqual(iface.bssid, REAL_BSSID)
        self.assertEqual(iface.signal_percent, 87)
        self.assertEqual(iface.rx_mbps, 400)
        self.assertEqual(iface.tx_mbps, 200)
        self.assertEqual(iface.channel, 157)
        self.assertEqual(iface.band, wifi.BAND_5)   # 由信道号反推
        self.assertEqual(api.closed, 1)

    def test_wlanapi_does_not_pretend_the_description_is_the_name(self):
        """wlanapi 给不出 netsh 的连接名（"WLAN"）→ 留空，别拿描述冒充。"""
        iface, _ = wifi.query_interface(connected_stub())
        self.assertEqual(iface.name, "")
        self.assertEqual(iface.display_name, "Intel(R) Wi-Fi 6 AX201 160MHz")

    def test_disconnected_adapter_skips_the_connection_query(self):
        api = StubApi(ifaces=[{"guid": object(), "guid_text": "{g}",
                               "description": "Intel", "state": wifi.STATE_DISCONNECTED}])
        iface, source = wifi.query_interface(api)
        self.assertEqual(source, wifi.SOURCE_WLANAPI)
        self.assertFalse(iface.connected)
        self.assertEqual(iface.ssid, "")

    def test_open_failure_falls_back_to_netsh(self):
        """⚠️ 这里**不能**给 `netsh_text`：给了就整段跳过 wlanapi，反而测不到这条降级。"""
        api = StubApi(open_error=OSError(5, "denied"))
        with mock.patch.object(wifi, "_run", return_value=fixture("interfaces.txt")):
            iface, source = wifi.query_interface(api)
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(iface.ssid, REAL_SSID)

    def test_interface_query_failure_falls_back_to_netsh(self):
        api = StubApi(ifaces=[])
        with mock.patch.object(wifi, "_run", return_value=fixture("interfaces.txt")):
            iface, source = wifi.query_interface(api)
        self.assertEqual(source, wifi.SOURCE_NETSH)

    def test_everything_fails_returns_none(self):
        api = StubApi(open_error=OSError(5, "denied"))
        iface, source = wifi.query_interface(api, netsh_text="")
        self.assertIsNone(iface)
        self.assertEqual(source, wifi.SOURCE_NONE)

    def test_no_wlanapi_and_no_netsh(self):
        with mock.patch.object(wifi, "_load_wlanapi", return_value=None):
            iface, source = wifi.query_interface(netsh_text="")
        self.assertIsNone(iface)
        self.assertEqual(source, wifi.SOURCE_NONE)

    def test_interface_enumeration_failure_falls_back_to_netsh(self):
        class Api(StubApi):
            def interfaces(self, handle):
                raise OSError(5, "denied")
        with mock.patch.object(wifi, "_run", return_value=fixture("interfaces.txt")):
            iface, source = wifi.query_interface(Api())
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(iface.ssid, REAL_SSID)

    def test_connection_query_failure_leaves_the_fields_empty(self):
        api = connected_stub()
        api.current_connection = mock.Mock(side_effect=OSError(5, "denied"))
        iface, source = wifi.query_interface(api)
        self.assertEqual(source, wifi.SOURCE_WLANAPI)
        self.assertEqual(iface.state, wifi.STATE_CONNECTED)
        self.assertEqual(iface.ssid, "")          # 拿不到就留空，不编
        self.assertIsNone(iface.channel)

    def test_connection_query_returning_nothing_leaves_the_fields_empty(self):
        api = connected_stub(conn=None, channel=None)
        iface, source = wifi.query_interface(api)
        self.assertEqual(source, wifi.SOURCE_WLANAPI)
        self.assertEqual(iface.ssid, "")

    def test_channel_query_failure_leaves_the_channel_unknown(self):
        api = connected_stub()
        api.channel_number = mock.Mock(side_effect=OSError(5, "denied"))
        iface, _ = wifi.query_interface(api)
        self.assertEqual(iface.ssid, REAL_SSID)   # 其它字段照样有
        self.assertIsNone(iface.channel)
        self.assertEqual(iface.band, wifi.BAND_UNKNOWN)


class ScanNetworksTest(unittest.TestCase):

    def test_netsh_text_is_a_hard_override(self):
        bss, source = wifi.scan_networks(netsh_text=fixture("networks_bssid.txt"))
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(len(bss), 78)
        self.assertTrue(all(b.source == wifi.SOURCE_NETSH for b in bss))

    def test_refresh_defaults_to_off(self):
        """🔴 `WlanScan` 是**主动扰动射频**，与 mDNS listen_only / LLMNR 同口径：默认不发。"""
        api = connected_stub(entries=[{"ssid": "X", "bssid": "02:00:00:00:00:01",
                                       "signal_percent": 50, "freq_khz": 2412000,
                                       "radio_type": "802.11n"}])
        with mock.patch.object(wifi, "_sleep") as sleeper:
            bss, source = wifi.scan_networks(api)
        self.assertEqual(api.scan_calls, [])
        sleeper.assert_not_called()
        self.assertEqual(source, wifi.SOURCE_WLANAPI)
        self.assertEqual(len(bss), 1)

    def test_refresh_true_does_call_scan_and_waits(self):
        api = connected_stub(entries=[{"ssid": "X", "bssid": "02:00:00:00:00:01",
                                       "signal_percent": 50, "freq_khz": 2412000,
                                       "radio_type": "802.11n"}])
        with mock.patch.object(wifi, "_sleep") as sleeper:
            wifi.scan_networks(api, refresh=True, wait_seconds=0.25)
        self.assertEqual(len(api.scan_calls), 1)
        sleeper.assert_called_once_with(0.25)

    def test_scan_failure_still_returns_the_cache(self):
        api = connected_stub(scan_error=OSError(5, "denied"),
                             entries=[{"ssid": "X", "bssid": "02:00:00:00:00:01",
                                       "signal_percent": 50, "freq_khz": 2412000,
                                       "radio_type": "802.11n"}])
        with mock.patch.object(wifi, "_sleep"):
            bss, source = wifi.scan_networks(api, refresh=True)
        self.assertEqual(source, wifi.SOURCE_WLANAPI)
        self.assertEqual(len(bss), 1)

    def test_wlanapi_entries_get_band_and_channel_from_the_center_frequency(self):
        api = connected_stub(entries=[
            {"ssid": "A", "bssid": "02:00:00:00:00:01", "signal_percent": 50,
             "freq_khz": 2412000, "radio_type": "802.11n"},
            {"ssid": "B", "bssid": "02:00:00:00:00:02", "signal_percent": 70,
             "freq_khz": 5745000, "radio_type": "802.11ac"}])
        bss, _ = wifi.scan_networks(api)
        self.assertEqual((bss[0].band, bss[0].channel), (wifi.BAND_24, 1))
        self.assertEqual((bss[1].band, bss[1].channel), (wifi.BAND_5, 149))

    def test_entries_without_a_bssid_are_dropped(self):
        api = connected_stub(entries=[{"ssid": "A", "bssid": "",
                                       "signal_percent": 50, "freq_khz": 2412000,
                                       "radio_type": ""}])
        # ⚠️ 必须显式给 `netsh_text`：不给的话会真去跑本机 `netsh`，
        #    在开发机（有无线网卡）与 CI（没有）上结果不一样。
        bss, source = wifi.scan_networks(api, netsh_text="")
        self.assertEqual(bss, [])
        self.assertEqual(source, wifi.SOURCE_NONE)

    def test_bss_list_failure_falls_back_to_netsh(self):
        """⚠️ 不能给 `netsh_text`（给了就跳过 wlanapi），所以 patch `_run` 顶替。"""
        api = connected_stub(bss_error=OSError(5, "denied"))
        with mock.patch.object(wifi, "_run",
                               return_value=fixture("networks_bssid_en.txt")):
            bss, source = wifi.scan_networks(api)
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(len(bss), 3)

    def test_empty_netsh_text(self):
        bss, source = wifi.scan_networks(netsh_text="")
        self.assertEqual((bss, source), ([], wifi.SOURCE_NONE))

    def test_open_failure_falls_back_to_netsh(self):
        api = connected_stub(open_error=OSError(1062, "service not running"))
        with mock.patch.object(wifi, "_run",
                               return_value=fixture("networks_bssid_en.txt")):
            bss, source = wifi.scan_networks(api)
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(len(bss), 3)

    def test_no_adapter_falls_back_to_netsh(self):
        api = connected_stub(ifaces=[])
        with mock.patch.object(wifi, "_run",
                               return_value=fixture("networks_bssid_en.txt")):
            bss, source = wifi.scan_networks(api)
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(len(bss), 3)

    def test_no_wlanapi_uses_netsh(self):
        with mock.patch.object(wifi, "_load_wlanapi", return_value=None):
            bss, source = wifi.scan_networks(netsh_text=fixture("networks_bssid_en.txt"))
        self.assertEqual(source, wifi.SOURCE_NETSH)
        self.assertEqual(len(bss), 3)


# ── 聚合 ────────────────────────────────────────────────────────────────

class SnapshotTest(unittest.TestCase):
    """⚠️ 每个用例都要么传替身 `api`、要么 patch `_IS_WINDOWS`。

    否则 `capability()` 会去探测**本机**的无线网卡 —— 开发机（有 Wi-Fi）与
    CI runner（没有）结果不同，测试就变成"在我这儿是绿的"。
    """

    def _full(self, **kw):
        kw.setdefault("api", connected_stub())
        return wifi.snapshot(
            netsh_interfaces=fixture("interfaces.txt"),
            netsh_networks=fixture("networks_bssid.txt"),
            roaming_xml=fixture("roaming_events.xml"),
            adapter_subnets=[("无线局域网适配器 WLAN", "192.168.1.0/24")],
            **kw)

    def test_every_item_carries_its_own_source(self):
        d = self._full().to_dict()
        self.assertEqual(d["interface_source"], wifi.SOURCE_NETSH)
        self.assertEqual(d["bss_source"], wifi.SOURCE_NETSH)
        self.assertEqual(d["roam_source"], wifi.SOURCE_WEVTUTIL)

    def test_no_notes_when_everything_is_available(self):
        self.assertEqual(self._full().notes, [])

    def test_subnet_association(self):
        d = self._full().to_dict()
        self.assertEqual(d["subnet_match"], wifi.MATCH_BY_NAME)
        self.assertEqual(d["subnets"], ["192.168.1.0/24"])

    def test_channel_loads_hang_off_the_current_connection(self):
        loads = self._full().channel_loads()
        self.assertEqual({c.band for c in loads}, {wifi.BAND_5})
        self.assertIn(157, [c.channel for c in loads])

    def test_each_failure_is_reported_separately_in_notes(self):
        snap = wifi.snapshot(connected_stub(), netsh_interfaces="",
                             netsh_networks="", roaming_xml="")
        self.assertEqual(snap.notes, [wifi.NOTE_NO_INTERFACE, wifi.NOTE_NO_BSS,
                                      wifi.NOTE_NO_ROAMING_LOG])

    def test_disconnected_adapter_is_noted(self):
        snap = wifi.snapshot(connected_stub(),
                             netsh_interfaces=fixture("interfaces_disconnected.txt"),
                             netsh_networks="", roaming_xml="",
                             adapter_subnets=[("以太网", "10.0.0.0/8")])
        self.assertIn(wifi.NOTE_DISCONNECTED, snap.notes)
        self.assertIn(wifi.NOTE_NO_BSS, snap.notes)

    def test_connected_but_unlinked_subnet_is_noted(self):
        snap = wifi.snapshot(connected_stub(),
                             netsh_interfaces=fixture("interfaces.txt"),
                             netsh_networks="", roaming_xml="",
                             adapter_subnets=[("以太网", "10.0.0.0/8")])
        self.assertIn(wifi.NOTE_NO_SUBNET, snap.notes)
        self.assertEqual(snap.subnet_match, wifi.MATCH_BY_NONE)
        # 关联不上也要把"本机全部网段"带出来，否则用户不知道该手工核对什么
        self.assertEqual(snap.all_subnets, ["10.0.0.0/8"])

    def test_include_roaming_false_skips_the_event_log(self):
        with mock.patch.object(wifi, "roaming_events") as fake:
            snap = self._full(include_roaming=False)
        fake.assert_not_called()
        self.assertEqual(snap.roam_events, [])
        self.assertEqual(snap.roam_source, wifi.SOURCE_NONE)

    def test_unsupported_platform_short_circuits(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", False):
            snap = wifi.snapshot(netsh_interfaces=fixture("interfaces.txt"))
        self.assertFalse(snap.capability.supported)
        self.assertEqual(snap.notes, [wifi.REASON_NOT_WINDOWS])
        self.assertIsNone(snap.interface)
        self.assertEqual(snap.bss_list, [])
        # 关键：**不抛异常**，而且 JSON 化得出来（界面要能显示这段）
        self.assertIn("capability", snap.to_dict())

    def test_wlanapi_path_through_the_stub(self):
        api = connected_stub(entries=[{"ssid": REAL_SSID, "bssid": REAL_BSSID,
                                       "signal_percent": 87, "freq_khz": 5745000,
                                       "radio_type": "802.11ac"}])
        snap = wifi.snapshot(api, roaming_xml="",
                             adapter_subnets=[("Wi-Fi", "192.168.1.0/24")])
        self.assertEqual(snap.interface_source, wifi.SOURCE_WLANAPI)
        self.assertEqual(snap.bss_source, wifi.SOURCE_WLANAPI)
        self.assertEqual(snap.interface.ssid, REAL_SSID)
        self.assertEqual(snap.bss_list[0].channel, 149)
        self.assertEqual(snap.subnets, ["192.168.1.0/24"])

    def test_notes_are_all_registered_canonical_values(self):
        """`notes` 是**规范值**，界面靠它查文案 —— 不能塞自由文本。"""
        snap = wifi.snapshot(connected_stub(), netsh_interfaces="",
                             netsh_networks="", roaming_xml="")
        for note in snap.notes:
            self.assertIn(note, wifi.ALL_NOTES)
        # 反过来：每个登记项都要有对应的常量，别漏登记
        self.assertEqual(len(wifi.ALL_NOTES), len(set(wifi.ALL_NOTES)))

    def test_to_dict_is_json_serializable(self):
        import json
        payload = json.dumps(self._full().to_dict(), ensure_ascii=False)
        self.assertIn(REAL_SSID, payload)


# ── wlanapi 结构体（字节级） ────────────────────────────────────────────

def _point_at(ref, buf):
    """让 ctypes 的 `POINTER(T)()` 出参指向我们预造的缓冲区。

    ⚠️ 不能写 `ctypes.cast(ptr, POINTER(c_void_p))[0] = addr`：`ptr` 初始是
    **NULL**，cast 出来还是 NULL，赋值直接抛 `ValueError: NULL pointer access`。
    """
    ctypes.cast(ctypes.pointer(ref._obj),
                ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)


class FakeDll:
    """只为 `bss_list` / `interfaces` 的**字节级**解析服务。"""

    def __init__(self, *, bss_buf=None, iface_buf=None, rc=0):
        self._bss_buf = bss_buf
        self._iface_buf = iface_buf
        self._rc = rc
        self.calls = []

    def WlanGetNetworkBssList(self, handle, guid, ssid, bss_type, security,
                              reserved, out_ref):
        self.calls.append("bss")
        if self._rc:
            return self._rc
        _point_at(out_ref, self._bss_buf)
        return 0

    def WlanEnumInterfaces(self, handle, reserved, out_ref):
        self.calls.append("ifaces")
        if self._rc:
            return self._rc
        _point_at(out_ref, self._iface_buf)
        return 0

    def WlanFreeMemory(self, ptr):
        self.calls.append("free")


def build_bss_buffer(entries):
    """`entries` = `[(ssid, mac, quality, freq_khz, ie_size), ...]`。

    每条后面挂 `ie_size` 个字节的 IE —— 这正是**变长**的来源。
    """
    stride = ctypes.sizeof(wifi._WLAN_BSS_ENTRY)
    total = (wifi._WLAN_BSS_LIST.wlanBssEntries.offset
             + stride * len(entries) + sum(e[4] for e in entries))
    buf = ctypes.create_string_buffer(total)
    head = ctypes.cast(buf, ctypes.POINTER(wifi._WLAN_BSS_LIST)).contents
    head.dwNumberOfItems = len(entries)
    base = ctypes.addressof(head) + wifi._WLAN_BSS_LIST.wlanBssEntries.offset
    offset = 0
    for ssid, mac, quality, freq, ie_size in entries:
        entry = wifi._WLAN_BSS_ENTRY.from_address(base + offset)
        raw = ssid.encode("utf-8")
        entry.dot11Ssid.uSSIDLength = len(raw)
        for i, byte in enumerate(raw):
            entry.dot11Ssid.ucSSID[i] = byte
        for i, byte in enumerate(bytes.fromhex(mac.replace(":", ""))):
            entry.dot11Bssid[i] = byte
        entry.wlanSignalQuality = quality
        entry.ulChCenterFrequency = freq
        entry.dot11PhyType = 8                      # 802.11ac
        entry.ulIeSize = ie_size
        offset += stride + ie_size
    return buf


def build_iface_buffer(items):
    """`items` = `[(description, interface_state), ...]`。"""
    stride = ctypes.sizeof(wifi._WLAN_INTERFACE_INFO)
    total = (wifi._WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
             + stride * len(items))
    buf = ctypes.create_string_buffer(total)
    head = ctypes.cast(buf, ctypes.POINTER(wifi._WLAN_INTERFACE_INFO_LIST)).contents
    head.dwNumberOfItems = len(items)
    base = ctypes.addressof(head) + wifi._WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
    for i, (desc, state) in enumerate(items):
        info = wifi._WLAN_INTERFACE_INFO.from_address(base + i * stride)
        info.strInterfaceDescription = desc
        info.isState = state
        info.InterfaceGuid.Data1 = 0x53BF544A
    return buf


def build_connection_buffer(*, ssid=REAL_SSID, mac=REAL_BSSID, phy=8, quality=87,
                            rx_kbps=400000, tx_kbps=200000, profile=REAL_SSID,
                            state=1):
    """一块 `WLAN_CONNECTION_ATTRIBUTES`（`WlanQueryInterface(opcode=7)` 的返回）。"""
    buf = ctypes.create_string_buffer(ctypes.sizeof(wifi._WLAN_CONNECTION_ATTRIBUTES))
    attrs = ctypes.cast(buf,
                        ctypes.POINTER(wifi._WLAN_CONNECTION_ATTRIBUTES)).contents
    attrs.isState = state
    attrs.wlanConnectionMode = 0
    attrs.strProfileName = profile
    assoc = attrs.wlanAssociationAttributes       # 嵌套结构共享内存 → 写进去即写进 buf
    raw = ssid.encode("utf-8")
    assoc.dot11Ssid.uSSIDLength = len(raw)
    for i, byte in enumerate(raw):
        assoc.dot11Ssid.ucSSID[i] = byte
    for i, byte in enumerate(bytes.fromhex(mac.replace(":", ""))):
        assoc.dot11Bssid[i] = byte
    assoc.dot11PhyType = phy
    assoc.wlanSignalQuality = quality
    assoc.ulRxRate = rx_kbps
    assoc.ulTxRate = tx_kbps
    return buf


class FakeQueryDll:
    """按 opcode 返回预造缓冲的替身 DLL（覆盖 `_query` 的两条查询）。"""

    def __init__(self, buffers, rc=0):
        self.buffers = buffers
        self.rc = rc
        self.calls = []

    def WlanQueryInterface(self, handle, guid, opcode, reserved, size, data, ptype):
        self.calls.append(opcode)
        if self.rc:
            return self.rc
        buf = self.buffers[opcode]
        ctypes.cast(ctypes.pointer(data._obj),
                    ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)
        ctypes.cast(ctypes.pointer(size._obj),
                    ctypes.POINTER(ctypes.c_uint32))[0] = ctypes.sizeof(buf)
        return 0

    @staticmethod
    def WlanFreeMemory(_ptr):
        pass


class WlanApiStructTest(unittest.TestCase):

    def test_rate_set_is_256_bytes(self):
        """🔴 省掉它会**静默**读错每条 BSS 的 IE 尺寸，后续条目全是垃圾。"""
        self.assertEqual(ctypes.sizeof(wifi._WLAN_RATE_SET), 256)

    def test_struct_sizes_are_platform_independent(self):
        """🔴 结构体描述的是 **Windows ABI 的字节布局**，尺寸不能随平台变。

        用 `c_ulong` 写字段时，Linux / macOS（LP64）上 `unsigned long` 是 8 字节
        ⇒ `_WLAN_RATE_SET` 变 **264**、`_WLAN_BSS_ENTRY` 跟着变 —— 而**步长正是从
        `sizeof()` 推出来的**。本机（Windows，LLP64）永远是 4 字节，所以这个
        偏差**只在跨平台 CI 上暴露**。固定宽度类型（`c_uint32` / `c_uint16`）之后，
        这几个数字在哪个平台都成立。
        """
        self.assertEqual(ctypes.sizeof(wifi._DOT11_SSID), 36)
        self.assertEqual(ctypes.sizeof(wifi._WLAN_RATE_SET), 256)
        self.assertEqual(ctypes.sizeof(wifi._WLAN_BSS_ENTRY), 352)
        self.assertEqual(ctypes.sizeof(wifi._WLAN_BSS_LIST), 360)

    def test_bss_list_steps_by_ie_size_not_by_fixed_stride(self):
        entries = [("QZTJXX", "a8:0c:ca:1c:80:16", 83, 2412000, 12),
                   ("ChinaNet-C6C7-5G", "3c:cd:5d:aa:bb:01", 41, 5745000, 0),
                   ("", "02:00:00:00:00:03", 7, 5180000, 200)]
        api = wifi._WlanApi(dll=FakeDll(bss_buf=build_bss_buffer(entries)))
        out = api.bss_list(None, wifi._GUID())
        self.assertEqual([e["ssid"] for e in out], ["QZTJXX", "ChinaNet-C6C7-5G", ""])
        self.assertEqual([e["bssid"] for e in out],
                         ["a8:0c:ca:1c:80:16", "3c:cd:5d:aa:bb:01",
                          "02:00:00:00:00:03"])
        self.assertEqual([e["signal_percent"] for e in out], [83, 41, 7])
        self.assertEqual([e["freq_khz"] for e in out], [2412000, 5745000, 5180000])
        self.assertTrue(all(e["radio_type"] == "802.11ac" for e in out))

    def test_fixed_stride_reading_would_have_been_wrong(self):
        """反证：若按固定 `sizeof(entry)` 递增，第二条开始就读串了。"""
        entries = [("QZTJXX", "a8:0c:ca:1c:80:16", 83, 2412000, 12),
                   ("Second", "02:00:00:00:00:02", 41, 5745000, 0)]
        buf = build_bss_buffer(entries)
        stride = ctypes.sizeof(wifi._WLAN_BSS_ENTRY)
        base = ctypes.addressof(
            ctypes.cast(buf, ctypes.POINTER(wifi._WLAN_BSS_LIST)).contents
        ) + wifi._WLAN_BSS_LIST.wlanBssEntries.offset
        naive = wifi._WLAN_BSS_ENTRY.from_address(base + stride).dot11Ssid.text()
        self.assertNotEqual(naive, "Second")   # 固定步长读出来是错的

    def test_bss_list_error_code_raises_oserror(self):
        api = wifi._WlanApi(dll=FakeDll(bss_buf=build_bss_buffer([]), rc=87))
        with self.assertRaises(OSError) as ctx:
            api.bss_list(None, wifi._GUID())
        self.assertEqual(ctx.exception.errno, 87)

    def test_bss_list_frees_the_buffer(self):
        api = wifi._WlanApi(dll=FakeDll(bss_buf=build_bss_buffer(
            [("A", "02:00:00:00:00:01", 1, 2412000, 0)])))
        api.bss_list(None, wifi._GUID())
        self.assertIn("free", api._dll.calls)

    def test_interface_list_uses_the_per_item_stride(self):
        api = wifi._WlanApi(dll=FakeDll(iface_buf=build_iface_buffer(
            [("Intel(R) Wi-Fi 6 AX201 160MHz", 1), ("Second Adapter", 4)])))
        out = api.interfaces(None)
        self.assertEqual([i["description"] for i in out],
                         ["Intel(R) Wi-Fi 6 AX201 160MHz", "Second Adapter"])
        self.assertEqual([i["state"] for i in out],
                         [wifi.STATE_CONNECTED, wifi.STATE_DISCONNECTED])
        self.assertEqual(out[0]["guid_text"], "{53bf544a-0000-0000-0000-000000000000}")

    def test_interface_list_error_code_raises_oserror(self):
        api = wifi._WlanApi(dll=FakeDll(iface_buf=build_iface_buffer([]), rc=5))
        with self.assertRaises(OSError):
            api.interfaces(None)

    def test_open_failure_carries_the_error_code(self):
        class Dll:
            @staticmethod
            def WlanOpenHandle(*_a):
                return 1062
        with self.assertRaises(OSError) as ctx:
            wifi._WlanApi(dll=Dll()).open()
        self.assertEqual(ctx.exception.errno, 1062)

    def test_open_success_returns_the_handle(self):
        class Dll:
            @staticmethod
            def WlanOpenHandle(_ver, _res, _neg, out):
                ctypes.cast(ctypes.pointer(out._obj),
                            ctypes.POINTER(ctypes.c_void_p))[0] = 0x1234
                return 0
        self.assertIsNotNone(wifi._WlanApi(dll=Dll()).open())

    def test_close_swallows_failures(self):
        class Dll:
            @staticmethod
            def WlanCloseHandle(*_a):
                raise OSError(5, "denied")
        wifi._WlanApi(dll=Dll()).close("handle")   # 不抛

    def test_query_uses_the_opcode_and_returns_the_buffer(self):
        holder = ctypes.create_string_buffer(8)

        class Dll:
            calls = []

            @classmethod
            def WlanQueryInterface(cls, handle, guid, opcode, res, size, data, ptype):
                cls.calls.append(opcode)
                ctypes.cast(ctypes.pointer(data._obj),
                            ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(holder)
                ctypes.cast(ctypes.pointer(size._obj),
                            ctypes.POINTER(ctypes.c_ulong))[0] = 8
                return 0

            @staticmethod
            def WlanFreeMemory(_p):
                pass
        api = wifi._WlanApi(dll=Dll())
        data, size = api._query("h", wifi._GUID(), 7)
        self.assertEqual(Dll.calls, [7])
        self.assertIsNotNone(data)

    def test_load_wlanapi_is_cached_and_resettable(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", False):
            wifi.reset_wlanapi_cache()
            self.assertIsNone(wifi._load_wlanapi())
            self.assertIsNone(wifi._load_wlanapi())
            wifi.reset_wlanapi_cache()

    def test_load_wlanapi_swallows_missing_dll(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", True), \
                mock.patch.object(wifi, "_WlanApi", side_effect=OSError(126, "no dll")):
            wifi.reset_wlanapi_cache()
            self.assertIsNone(wifi._load_wlanapi())
        wifi.reset_wlanapi_cache()

    def test_load_wlanapi_swallows_missing_exports(self):
        with mock.patch.object(wifi, "_IS_WINDOWS", True), \
                mock.patch.object(wifi, "_WlanApi", side_effect=AttributeError("nope")):
            wifi.reset_wlanapi_cache()
            self.assertIsNone(wifi._load_wlanapi())
        wifi.reset_wlanapi_cache()

    def test_current_connection_parses_the_attributes_struct(self):
        """`WlanQueryInterface(opcode=7)` → 当前关联的 SSID/BSSID/速率/信号。"""
        api = wifi._WlanApi(dll=FakeQueryDll({7: build_connection_buffer()}))
        conn = api.current_connection("h", wifi._GUID())
        self.assertEqual(conn["state"], wifi.STATE_CONNECTED)
        self.assertEqual(conn["ssid"], REAL_SSID)
        self.assertEqual(conn["bssid"], REAL_BSSID)
        self.assertEqual(conn["radio_type"], "802.11ac")
        self.assertEqual(conn["signal_percent"], 87)
        self.assertEqual(conn["rx_mbps"], 400)      # kbps → Mbps
        self.assertEqual(conn["tx_mbps"], 200)
        self.assertEqual(conn["profile"], REAL_SSID)

    def test_current_connection_uses_opcode_7(self):
        dll = FakeQueryDll({7: build_connection_buffer()})
        wifi._WlanApi(dll=dll).current_connection("h", wifi._GUID())
        self.assertEqual(dll.calls, [7])

    def test_channel_number_uses_opcode_8(self):
        channel = ctypes.c_ulong(157)
        dll = FakeQueryDll({8: channel})
        api = wifi._WlanApi(dll=dll)
        self.assertEqual(api.channel_number("h", wifi._GUID()), 157)
        self.assertEqual(dll.calls, [8])

    def test_query_failure_raises_oserror_with_the_code(self):
        api = wifi._WlanApi(dll=FakeQueryDll({}, rc=87))
        with self.assertRaises(OSError) as ctx:
            api.current_connection("h", wifi._GUID())
        self.assertEqual(ctx.exception.errno, 87)

    def test_scan_returns_normally_and_reports_failure(self):
        class Dll:
            def __init__(self, rc):
                self.rc = rc
                self.calls = 0

            def WlanScan(self, *_a):
                self.calls += 1
                return self.rc
        ok = Dll(0)
        wifi._WlanApi(dll=ok).scan("h", wifi._GUID())
        self.assertEqual(ok.calls, 1)
        bad = Dll(87)
        with self.assertRaises(OSError) as ctx:
            wifi._WlanApi(dll=bad).scan("h", wifi._GUID())
        self.assertEqual(ctx.exception.errno, 87)

    def test_sleep_really_sleeps(self):
        """`_sleep` 是可注入点；这里只确认默认实现真的会睡（传 0 不拖慢测试）。"""
        wifi._sleep(0)


class RunCommandTest(unittest.TestCase):

    def test_failure_returns_empty_string_and_does_not_raise(self):
        with mock.patch.object(wifi.subprocess, "run",
                               side_effect=OSError(2, "not found")):
            self.assertEqual(wifi._run(["netsh"]), "")

    def test_output_is_decoded(self):
        proc = mock.Mock(stdout="无线".encode("utf-8"))
        with mock.patch.object(wifi.subprocess, "run", return_value=proc):
            self.assertEqual(wifi._run(["netsh"]), "无线")

    def test_timeout_is_swallowed(self):
        with mock.patch.object(wifi.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("netsh", 1)):
            self.assertEqual(wifi._run(["netsh"]), "")


# ── 项目硬约定 ──────────────────────────────────────────────────────────

class NoNetworkAndNoI18nTest(unittest.TestCase):

    #: import 到这些就是把「数据不出网」或「scanner 零 i18n」破了。
    FORBIDDEN = ("urllib", "requests", "socket", "http", "ssl", "ftplib",
                 "smtplib", "telnetlib", "asyncio", "xmlrpc", "webbrowser",
                 "i18n")

    def test_source_does_not_import_network_libs_or_i18n(self):
        roots = imported_roots(module_source("scanner/wifi.py"))
        self.assertEqual(roots & set(self.FORBIDDEN), set())

    def test_runtime_process_gains_no_network_module(self):
        code = (
            "import sys; import scanner;"
            "base = set(sys.modules);"
            "import scanner.wifi;"
            "new = set(sys.modules) - base;"
            "print(sorted(m for m in ('urllib','requests','socket','http','ssl',"
            "'ftplib','smtplib','telnetlib','asyncio') if m in new))"
        )
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]",
                         "import scanner.wifi 新增了网络库")

    def test_no_print_or_stderr_write(self):
        """日志一律 `get_logger(__name__)`；`scanner/` 由测试强制。"""
        source = module_source("scanner/wifi.py")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotEqual(node.func.id, "print")
        self.assertNotIn("stderr.write", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
