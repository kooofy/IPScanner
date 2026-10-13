# -*- coding: utf-8 -*-
"""无线切片对话框（v2.1 §2.2 的 GUI 露出）。

为什么单独一个文件
------------------
`scanner/wifi.py` 的取数与解析由 `tests/test_wifi.py` 守着（175 条），但界面
层多出四件取数层管不到的事：

1. **`refresh` 默认必须是关的** —— 打开对话框只读系统缓存，**不扰动射频**；
   唯一的主动扫描入口是「重新扫描（主动扰动射频）」按钮。这条最容易在重构
   里被"顺手"改成默认扫，而它是有物理代价的（无线会短暂忙于扫描）。
2. **拿不到就说拿不到** —— `notes` 里两类规范值（`NOTE_*` 各项没拿到、
   `REASON_*` 能力不可用）都要翻成人话；没有数据的地方显示「—」，
   **不能编一个 0**。
3. **配色随主题** —— 「当前信道」行与「关联失败」行由 Python 取
   `theme_tokens` 语义色（QSS 覆盖不到表格单元格），切主题不重取就会在
   深色底上留浅色主题的字。
4. **降级不许崩** —— 单行取值函数抛异常只该让那一行变「—」，不该整页崩。

⚠️ 所有用例都用 `snapshot=` 注入造好的快照（不碰真网卡、不跑 `netsh`）；
只有 `RefreshContractTest` 会真的起线程，那里用 `mock.patch.object` 把
`wifi.snapshot` 换掉并断言它收到的 `refresh` 实参。
"""
import os
import sys
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests._qt_app import ensure_qt_app                      # noqa: E402

ensure_qt_app()

from PyQt5.QtGui import QColor                               # noqa: E402
from PyQt5.QtWidgets import QApplication                     # noqa: E402
from unittest import mock                                    # noqa: E402

import i18n                                                  # noqa: E402
from i18n import tr                                          # noqa: E402
from scanner import wifi                                     # noqa: E402
from theme_tokens import token                               # noqa: E402
from ui_dialogs.wifi import (                                # noqa: E402
    _CURRENT_FIELDS, _label, _rate_text,
)

UNSUPPORTED_REASONS = (
    wifi.REASON_NOT_WINDOWS, wifi.REASON_NO_WLANAPI,
    wifi.REASON_SERVICE_STOPPED, wifi.REASON_NO_ADAPTER,
    wifi.REASON_QUERY_FAILED,
)

#: 「用默认值」与「显式给 None」必须分开 —— `_snap(iface=None)` 的意思是
#: **没有网卡**，不是"给我那个默认网卡"（这个坑第一版就踩了）。
_UNSET = object()


# ── 造数 ──────────────────────────────────────────────────────────────

def _iface(**kw) -> wifi.WifiInterface:
    base = dict(
        name="WLAN", description="Intel(R) Wi-Fi 6 AX201 160MHz",
        guid="{2e5b1f0a-0000-0000-0000-000000000001}",
        mac="aa:bb:cc:dd:ee:ff", state=wifi.STATE_CONNECTED, ssid="QZTJXX",
        bssid="f0:2f:74:11:22:33", band=wifi.BAND_5, channel=157,
        radio_type="802.11ac", auth="WPA2-Personal", cipher="CCMP",
        rx_mbps=866, tx_mbps=780, signal_percent=72, rssi_dbm=-58,
        profile="QZTJXX", source=wifi.SOURCE_WLANAPI,
    )
    base.update(kw)
    return wifi.WifiInterface(**base)


def _bss(ssid, channel, band, signal=60, **kw) -> wifi.WifiBss:
    base = dict(
        ssid=ssid, ssid_known=bool(ssid),
        bssid="aa:bb:cc:%02x:%02x:%02x" % (channel or 0, signal, 7),
        band=band, channel=channel, signal_percent=signal,
        radio_type="802.11ac", auth="WPA2-Personal", cipher="CCMP",
        source=wifi.SOURCE_WLANAPI,
    )
    base.update(kw)
    return wifi.WifiBss(**base)


def _bss_5g():
    """5GHz：157 上有两个 BSS（一个就是当前连的那个），另有 36/149/161。"""
    return [
        _bss("QZTJXX", 157, wifi.BAND_5, 72),
        _bss("QZTJXX", 157, wifi.BAND_5, 40),
        _bss("Neighbor-5G", 149, wifi.BAND_5, 55),
        _bss("Office-5G", 36, wifi.BAND_5, 30),
        _bss("", 161, wifi.BAND_5, 20),          # 隐藏 SSID
    ]


def _bss_24g():
    """2.4GHz：1/3/6/11 各一台 —— 用来验证 ±4 邻频重叠统计。"""
    return [
        _bss("Home-2.4", 1, wifi.BAND_24, 80),
        _bss("Home-2.4", 3, wifi.BAND_24, 50),
        _bss("Neighbor-2.4", 6, wifi.BAND_24, 45),
        _bss("Far-2.4", 11, wifi.BAND_24, 25),
    ]


def _events():
    return [
        wifi.RoamEvent(
            timestamp=datetime(2026, 10, 13, 6, 37, 30, 187536,
                               tzinfo=timezone.utc),
            kind=wifi.ROAM_ATTEMPT, ssid="QZTJXX", event_id="8000"),
        wifi.RoamEvent(
            timestamp=datetime(2026, 10, 13, 6, 37, 33, tzinfo=timezone.utc),
            kind=wifi.ROAM_ASSOCIATED, ssid="QZTJXX", event_id="8001"),
        wifi.RoamEvent(
            timestamp=datetime(2026, 10, 13, 7, 1, 5, tzinfo=timezone.utc),
            kind=wifi.ROAM_FAILED, ssid="Guest", reason_code="0x00028002",
            reason_text="", event_id="8002"),
        wifi.RoamEvent(timestamp=None, kind=wifi.ROAM_DISCONNECTED,
                       ssid="QZTJXX", event_id="8003"),
    ]


def _snap(bss=_UNSET, iface=_UNSET, notes=None, subnets=None,
          all_subnets=None, match=wifi.MATCH_BY_NAME, events=None,
          roam_source=wifi.SOURCE_WEVTUTIL) -> wifi.WifiSnapshot:
    """一份「一切正常」的快照；传参可只改关心的那几项。"""
    return wifi.WifiSnapshot(
        capability=wifi.WifiCapability(True),
        interface=_iface() if iface is _UNSET else iface,
        interface_source=wifi.SOURCE_WLANAPI,
        bss_list=_bss_5g() if bss is _UNSET else bss,
        bss_source=wifi.SOURCE_WLANAPI,
        roam_events=[] if events is None else events,
        roam_source=roam_source,
        subnets=["10.193.27.0/24"] if subnets is None else subnets,
        all_subnets=(["10.193.27.0/24", "172.28.80.0/20"]
                     if all_subnets is None else all_subnets),
        subnet_match=match,
        notes=list(notes or []),
    )


def _unsupported(reason):
    return wifi.WifiSnapshot(
        capability=wifi.WifiCapability(False, reason, "detail"),
        notes=[reason],
    )


class _DialogCase(unittest.TestCase):
    """统一：中文语言包 + 注入快照（不碰真网卡）。"""

    def setUp(self):
        i18n.init("zh-CN")
        self._made = []

    def tearDown(self):
        for dlg in self._made:
            dlg.deleteLater()
        QApplication.processEvents()
        i18n.init("zh-CN")

    def make(self, snapshot, dark=False, **kw):
        from ui_dialogs.wifi import WifiDialog
        dlg = WifiDialog(dark=dark, snapshot=snapshot, **kw)
        self._made.append(dlg)
        return dlg

    @staticmethod
    def cell(table, row, col):
        item = table.item(row, col)
        assert item is not None, "(%d, %d) 没有单元格" % (row, col)
        return item.text()

    @staticmethod
    def fg(table, row, col):
        item = table.item(row, col)
        assert item is not None
        return item.foreground().color().name()

    def values(self, dlg):
        """「当前关联」页签：字段名 → 显示值。"""
        return dict(zip([lbl for lbl, _g in _CURRENT_FIELDS],
                        [lbl.text() for lbl in dlg._current_values]))


# ── 纯函数 ────────────────────────────────────────────────────────────

class LabelHelperTest(unittest.TestCase):
    """`_label()`：表驱动文案**先 `tr()` 再返回**。"""

    def setUp(self):
        i18n.init("zh-CN")

    def tearDown(self):
        i18n.init("zh-CN")

    def test_known_value_is_translated(self):
        from ui_dialogs.wifi import _SOURCE_TEXT
        self.assertEqual(_label(_SOURCE_TEXT, wifi.SOURCE_NETSH),
                         tr("netsh 文本"))
        self.assertEqual(_label(_SOURCE_TEXT, wifi.SOURCE_NONE), tr("无"))

    def test_unknown_value_falls_back_to_unknown(self):
        from ui_dialogs.wifi import _SOURCE_TEXT
        self.assertEqual(_label(_SOURCE_TEXT, "no-such-source"), tr("未知"))

    def test_unknown_value_can_use_a_custom_fallback(self):
        from ui_dialogs.wifi import _SOURCE_TEXT
        self.assertEqual(_label(_SOURCE_TEXT, "x", fallback="—"), "—")

    def test_every_reason_and_note_has_a_sentence(self):
        from ui_dialogs.wifi import _NOTE_TEXT, _REASON_TEXT
        for reason in UNSUPPORTED_REASONS + (wifi.REASON_OK,):
            self.assertIn(reason, _REASON_TEXT, reason)
        for note in wifi.ALL_NOTES:
            self.assertIn(note, _NOTE_TEXT, note)


class RateTextTest(unittest.TestCase):
    def test_both_missing_is_a_dash_not_zero(self):
        self.assertEqual(_rate_text(wifi.WifiInterface()), "—")

    def test_one_missing_keeps_the_other(self):
        self.assertEqual(_rate_text(wifi.WifiInterface(tx_mbps=780)),
                         "— / 780 Mbps")

    def test_both_present(self):
        self.assertEqual(_rate_text(wifi.WifiInterface(rx_mbps=866,
                                                       tx_mbps=780)),
                         "866 / 780 Mbps")


class CurrentFieldTableTest(unittest.TestCase):
    def test_field_table_shape_is_stable(self):
        """界面行数与 `_CURRENT_FIELDS` 一一对应（改表要同步改测试）。"""
        labels = [lbl for lbl, _get in _CURRENT_FIELDS]
        self.assertEqual(len(labels), 18)
        for must in ("适配器", "状态", "SSID", "BSSID", "信道", "关联网段",
                     "本机全部网段", "关联依据"):
            self.assertIn(must, labels)


# ── 顶部一句话 ────────────────────────────────────────────────────────

class HeadTest(_DialogCase):
    def test_each_unsupported_reason_is_spelled_out(self):
        from ui_dialogs.wifi import _REASON_TEXT
        for reason in UNSUPPORTED_REASONS:
            dlg = self.make(_unsupported(reason))
            text = dlg.head_label.text()
            self.assertIn(tr("无线切片不可用"), text)
            self.assertIn(tr(_REASON_TEXT[reason]), text)

    def test_ok_but_no_interface_says_so(self):
        dlg = self.make(_snap(iface=None))
        self.assertEqual(dlg.head_label.text(),
                         tr("无线切片：读不到当前网卡信息"))

    def test_connected_shows_adapter_state_ssid_and_ap_count(self):
        dlg = self.make(_snap())
        text = dlg.head_label.text()
        self.assertIn("WLAN", text)
        self.assertIn(tr("已连接"), text)
        self.assertIn("QZTJXX", text)
        self.assertIn(tr("共 %d 个可见 AP") % 5, text)

    def test_disconnected_says_not_connected(self):
        dlg = self.make(_snap(iface=_iface(state=wifi.STATE_DISCONNECTED,
                                           ssid="", channel=None)))
        text = dlg.head_label.text()
        self.assertIn(tr("未连接"), text)
        self.assertIn(tr("（隐藏）"), text)

    def test_display_name_falls_back_to_description(self):
        """走 wlanapi 时 `.name` 是空串 —— 顶部不能显示空白。"""
        dlg = self.make(_snap(iface=_iface(name="")))
        self.assertIn("Intel(R) Wi-Fi 6 AX201 160MHz", dlg.head_label.text())


# ── 页签一：当前关联 ──────────────────────────────────────────────────

class CurrentTabTest(_DialogCase):
    def test_every_field_is_filled_from_a_connected_adapter(self):
        dlg = self.make(_snap())
        values = self.values(dlg)
        self.assertEqual(values["适配器"], "WLAN")
        self.assertEqual(values["状态"], tr("已连接"))
        self.assertEqual(values["SSID"], "QZTJXX")
        self.assertEqual(values["BSSID"], "f0:2f:74:11:22:33")
        self.assertEqual(values["信道"], "157")
        self.assertEqual(values["信号"], "72%")
        self.assertEqual(values["RSSI"], "-58 dBm")
        self.assertEqual(values["收发速率"], "866 / 780 Mbps")
        self.assertEqual(values["数据来源"], tr("结构化 API"))

    def test_missing_numbers_render_as_dash_not_zero(self):
        dlg = self.make(_snap(iface=_iface(
            state=wifi.STATE_DISCONNECTED, ssid="", bssid="", channel=None,
            signal_percent=None, rssi_dbm=None, rx_mbps=None, tx_mbps=None)))
        values = self.values(dlg)
        for field in ("BSSID", "信道", "信号", "RSSI", "收发速率"):
            self.assertEqual(values[field], "—", field)
        self.assertNotIn("0", values["收发速率"])

    def test_subnets_show_both_the_link_and_the_full_local_list(self):
        dlg = self.make(_snap())
        values = self.values(dlg)
        self.assertEqual(values["关联网段"], "10.193.27.0/24")
        self.assertEqual(values["本机全部网段"],
                         "10.193.27.0/24, 172.28.80.0/20")
        self.assertEqual(values["关联依据"], tr("按网卡名匹配"))

    def test_unlinked_subnet_is_reported_honestly(self):
        dlg = self.make(_snap(subnets=[], match=wifi.MATCH_BY_NONE))
        values = self.values(dlg)
        self.assertEqual(values["关联网段"], tr("未关联上"))
        self.assertEqual(values["关联依据"], tr("未关联上"))
        self.assertEqual(values["本机全部网段"],
                         "10.193.27.0/24, 172.28.80.0/20")

    def test_a_broken_getter_only_blanks_its_own_row(self):
        """单行取值炸了不该整页崩 —— 那一行退化成「—」，别的行照常。"""
        dlg = self.make(_snap())
        boom = mock.Mock(side_effect=RuntimeError("boom"))
        patched = (("坏字段", boom),) + tuple(_CURRENT_FIELDS[1:])
        with mock.patch("ui_dialogs.wifi._CURRENT_FIELDS", patched):
            dlg._render_current(dlg.snapshot)
        self.assertEqual(dlg._current_values[0].text(), "—")
        self.assertIn("boom", dlg._current_values[0].toolTip())
        self.assertEqual(dlg._current_values[1].text(),
                         "Intel(R) Wi-Fi 6 AX201 160MHz")
        self.assertEqual(dlg._current_values[2].text(), tr("已连接"))


# ── 页签二：信道拥塞 ──────────────────────────────────────────────────

class LoadTabTest(_DialogCase):
    def test_rows_are_one_per_channel_of_the_current_band(self):
        dlg = self.make(_snap())
        self.assertEqual(dlg.load_table.rowCount(), 4)     # 36 / 149 / 157 / 161
        self.assertEqual(self.cell(dlg.load_table, 0, 0), "36")
        self.assertEqual(self.cell(dlg.load_table, 3, 0), "161")
        self.assertEqual(self.cell(dlg.load_table, 2, 1), "2")   # 157 有两台

    def test_other_bands_are_not_mixed_in(self):
        """连的是 5GHz —— 2.4GHz 的 AP 不该出现在这张表里。"""
        dlg = self.make(_snap(bss=_bss_5g() + _bss_24g()))
        self.assertEqual(dlg.load_table.rowCount(), 4)

    def test_current_channel_is_flagged(self):
        dlg = self.make(_snap())
        self.assertEqual(self.cell(dlg.load_table, 2, 4), tr("是"))
        self.assertEqual(self.cell(dlg.load_table, 0, 4), "")

    def test_24ghz_counts_overlapping_neighbours(self):
        """2.4GHz 要看 ±4 邻频：ch1 的干扰源 = ch1 + ch3。"""
        dlg = self.make(_snap(bss=_bss_24g(),
                              iface=_iface(band=wifi.BAND_24, channel=1)))
        self.assertEqual(self.cell(dlg.load_table, 0, 0), "1")
        self.assertEqual(self.cell(dlg.load_table, 0, 2), "2")
        # ch6 的 ±4 覆盖 3 与 6（11 差 5，不算）
        self.assertEqual(self.cell(dlg.load_table, 2, 2), "2")

    def test_5ghz_leaves_the_overlap_column_empty(self):
        dlg = self.make(_snap())
        for row in range(dlg.load_table.rowCount()):
            self.assertEqual(self.cell(dlg.load_table, row, 2), "—")

    def test_24ghz_hint_only_considers_the_non_overlapping_trio(self):
        dlg = self.make(_snap(bss=_bss_24g(),
                              iface=_iface(band=wifi.BAND_24, channel=1)))
        self.assertIn("1/6/11", dlg.load_hint.text())
        self.assertIn("建议 1 信道", dlg.load_hint.text())

    def test_5ghz_hint_picks_the_emptiest_channel(self):
        dlg = self.make(_snap())
        self.assertIn(tr("当前波段 %s：建议 %d 信道（AP 数最少）。")
                      % (wifi.BAND_5, 36), dlg.load_hint.text())

    def test_no_ap_means_no_channel_statistics(self):
        dlg = self.make(_snap(bss=[]))
        self.assertEqual(dlg.load_table.rowCount(), 0)
        self.assertEqual(dlg.load_hint.text(),
                         tr("没有可用的信道统计（没扫到带信道的 AP）。"))

    def test_strongest_signal_is_a_percentage(self):
        dlg = self.make(_snap())
        self.assertEqual(self.cell(dlg.load_table, 2, 3), "72%")


# ── 页签三：可见 AP ──────────────────────────────────────────────────

class ApTabTest(_DialogCase):
    def test_one_row_per_visible_ap(self):
        dlg = self.make(_snap())
        self.assertEqual(dlg.ap_table.rowCount(), 5)
        self.assertEqual(dlg.ap_table.columnCount(), 8)
        self.assertEqual(self.cell(dlg.ap_table, 0, 0), "QZTJXX")
        self.assertEqual(self.cell(dlg.ap_table, 0, 3), "157")
        self.assertEqual(self.cell(dlg.ap_table, 0, 4), "72%")

    def test_hidden_ssid_is_labelled_not_blank(self):
        dlg = self.make(_snap())
        self.assertEqual(self.cell(dlg.ap_table, 4, 0), tr("（隐藏 SSID）"))

    def test_hint_counts_hidden_ssids(self):
        dlg = self.make(_snap())
        hint = dlg.ap_hint.text()
        self.assertIn(tr("共 %d 个可见 AP。") % 5, hint)
        self.assertIn(tr("其中 %d 个是隐藏 SSID。") % 1, hint)

    def test_hint_omits_the_hidden_clause_when_there_are_none(self):
        dlg = self.make(_snap(bss=_bss_24g()))
        hint = dlg.ap_hint.text()
        self.assertIn(tr("共 %d 个可见 AP。") % 4, hint)
        self.assertNotIn(tr("其中 %d 个是隐藏 SSID。") % 1, hint)

    def test_missing_channel_renders_as_dash(self):
        dlg = self.make(_snap(bss=[_bss("X", None, wifi.BAND_5, 10)]))
        self.assertEqual(self.cell(dlg.ap_table, 0, 3), "—")


# ── 页签四：漫游时间线 ────────────────────────────────────────────────

class RoamTabTest(_DialogCase):
    def test_rows_render_time_kind_ssid_and_reason(self):
        dlg = self.make(_snap(events=_events()))
        self.assertEqual(dlg.roam_table.rowCount(), 4)
        self.assertEqual(self.cell(dlg.roam_table, 0, 1), tr("开始关联"))
        self.assertEqual(self.cell(dlg.roam_table, 1, 1), tr("关联成功"))
        self.assertEqual(self.cell(dlg.roam_table, 2, 1), tr("关联失败"))
        self.assertEqual(self.cell(dlg.roam_table, 3, 1), tr("断开"))
        self.assertEqual(self.cell(dlg.roam_table, 2, 2), "Guest")
        self.assertEqual(self.cell(dlg.roam_table, 2, 3), "0x00028002")

    def test_timestamp_is_rendered_in_local_time(self):
        """⚠️ 断言必须**同时区推导** —— 硬编码字符串在 CI（UTC）必挂。"""
        events = _events()
        dlg = self.make(_snap(events=events))
        expected = events[0].timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(self.cell(dlg.roam_table, 0, 0), expected)
        self.assertRegex(self.cell(dlg.roam_table, 0, 0),
                         r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")

    def test_missing_timestamp_is_a_dash(self):
        dlg = self.make(_snap(events=_events()))
        self.assertEqual(self.cell(dlg.roam_table, 3, 0), "—")

    def test_hint_states_the_ssid_granularity_caveat(self):
        dlg = self.make(_snap(events=_events()))
        hint = dlg.roam_hint.text()
        self.assertIn(tr("共 %d 条关联/断开事件（来源：%s）。时间线是 SSID 粒度 —— "
                         "AutoConfig 这几条事件不带 BSSID，不能标成「漫游到某个 AP」。")
                      % (4, tr("事件日志")), hint)

    def test_no_events_hint_names_the_source(self):
        dlg = self.make(_snap(events=[]))
        self.assertEqual(dlg.roam_hint.text(),
                         tr("没有读到关联/断开事件（来源：%s）。") % tr("事件日志"))

    def test_unknown_roam_source_still_renders(self):
        dlg = self.make(_snap(events=[], roam_source="weird"))
        self.assertIn(tr("未知"), dlg.roam_hint.text())


# ── 底部说明 ──────────────────────────────────────────────────────────

class NotesTest(_DialogCase):
    def test_note_values_become_sentences(self):
        from ui_dialogs.wifi import _NOTE_TEXT
        dlg = self.make(_snap(notes=[wifi.NOTE_NO_BSS, wifi.NOTE_NO_SUBNET]))
        text = dlg.notes_label.text()
        self.assertTrue(text.startswith(tr("说明：")))
        self.assertIn(tr(_NOTE_TEXT[wifi.NOTE_NO_BSS]), text)
        self.assertIn(tr(_NOTE_TEXT[wifi.NOTE_NO_SUBNET]), text)

    def test_reason_values_are_looked_up_too(self):
        """能力不可用时整条快照只带一个 `REASON_*` —— 不能显示成「未知」。"""
        from ui_dialogs.wifi import _REASON_TEXT
        dlg = self.make(_unsupported(wifi.REASON_NOT_WINDOWS))
        text = dlg.notes_label.text()
        self.assertIn(tr(_REASON_TEXT[wifi.REASON_NOT_WINDOWS]), text)
        self.assertNotIn(tr("未知"), text)

    def test_no_notes_means_no_text(self):
        dlg = self.make(_snap(notes=[]))
        self.assertEqual(dlg.notes_label.text(), "")

    def test_unknown_note_is_shown_as_unknown_not_dropped(self):
        dlg = self.make(_snap(notes=["something-new"]))
        self.assertIn(tr("未知"), dlg.notes_label.text())


# ── 结构与文案 ────────────────────────────────────────────────────────

class TabsTest(_DialogCase):
    def test_four_tabs_in_order(self):
        dlg = self.make(_snap())
        titles = [dlg.tabs.tabText(i) for i in range(dlg.tabs.count())]
        self.assertEqual(titles, [tr("当前关联"), tr("信道拥塞"),
                                  tr("可见 AP"), tr("漫游时间线")])

    def test_rescan_button_says_what_it_costs(self):
        dlg = self.make(_snap())
        self.assertEqual(dlg.btn_rescan.text(), tr("重新扫描（主动扰动射频）"))
        tip = dlg.btn_rescan.toolTip()
        self.assertIn("WlanScan", tip)
        # ⚠️ 这里**不要**写 `tr("主动扫描会让无线短暂忙于扫描…")`：那会在测试文件里
        # 引入一个新的 `tr()` 字面量，`test_i18n_lazy` 会把它当成"界面文案缺译文"
        # 报红（工具提示在 wifi.py 里是**隐式拼接的整串**，碎片并不单独存在）。
        self.assertIn("主动扫描", tip)

    def test_tables_are_read_only(self):
        from PyQt5.QtWidgets import QAbstractItemView
        dlg = self.make(_snap())
        for table in (dlg.load_table, dlg.ap_table, dlg.roam_table):
            self.assertEqual(table.editTriggers(),
                             QAbstractItemView.NoEditTriggers)

    def test_english_interface_gets_english_headers(self):
        """表头是 `@property`（每次读取时翻译）—— 换成英文必须跟着变。"""
        dlg = self.make(_snap())
        i18n.init("en-US")
        try:
            self.assertIn("Channel", dlg.AP_COLS)
            self.assertIn("Band", dlg.AP_COLS)
            self.assertIn("APs", dlg.LOAD_COLS)
            self.assertIn("Time", dlg.ROAM_COLS)
        finally:
            i18n.init("zh-CN")


# ── 配色随主题 ────────────────────────────────────────────────────────

class ThemeColorTest(_DialogCase):
    def test_current_channel_row_uses_the_online_token(self):
        snap = _snap()
        light = self.make(snap, dark=False)
        dark = self.make(snap, dark=True)
        self.assertNotEqual(token("online", False), token("online", True),
                            "前提：该令牌两套主题取值不同")
        # 157 是当前信道 → 第 3 行（36 / 149 / 157 / 161）
        self.assertEqual(self.fg(light.load_table, 2, 0),
                         QColor(token("online", False)).name())
        self.assertEqual(self.fg(dark.load_table, 2, 0),
                         QColor(token("online", True)).name())

    def test_current_channel_row_is_bold(self):
        dlg = self.make(_snap())
        self.assertTrue(dlg.load_table.item(2, 0).font().bold())
        self.assertFalse(dlg.load_table.item(0, 0).font().bold())

    def test_other_rows_are_not_recoloured(self):
        """非当前行不该被顺手染成 online 色（否则"当前"就没区分度了）。"""
        dlg = self.make(_snap())
        self.assertNotEqual(self.fg(dlg.load_table, 0, 0),
                            QColor(token("online", False)).name())

    def test_failed_association_row_uses_the_danger_token(self):
        snap = _snap(events=_events())
        light = self.make(snap, dark=False)
        dark = self.make(snap, dark=True)
        self.assertNotEqual(token("danger", False), token("danger", True),
                            "前提：该令牌两套主题取值不同")
        self.assertEqual(self.fg(light.roam_table, 2, 0),
                         QColor(token("danger", False)).name())
        self.assertEqual(self.fg(dark.roam_table, 2, 0),
                         QColor(token("danger", True)).name())


# ── `refresh` 默认关：唯一的主动扫描入口是那个按钮 ────────────────────

class RefreshContractTest(_DialogCase):
    """这一组会真的起线程，但把 `wifi.snapshot` 换成了记录实参的假函数。"""

    def _wait(self, dlg, ms=8000):
        thread = dlg._thread
        self.assertIsNotNone(thread, "应当已经起了取数线程")
        self.assertTrue(thread.wait(ms), "取数线程没在 %d ms 内结束" % ms)
        for _ in range(20):                 # 让跨线程信号派发到 _on_snapshot
            QApplication.processEvents()

    def test_injecting_a_snapshot_starts_no_thread(self):
        with mock.patch.object(wifi, "snapshot") as patched:
            dlg = self.make(_snap())
        self.assertIsNone(dlg._thread)
        patched.assert_not_called()

    def test_default_open_reads_the_cache_only(self):
        calls = []

        def fake(**kw):
            calls.append(kw)
            return _snap()

        with mock.patch.object(wifi, "snapshot", side_effect=fake):
            from ui_dialogs.wifi import WifiDialog
            dlg = WifiDialog()
            self._made.append(dlg)
            self._wait(dlg)
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0].get("refresh", False),
                         "默认打开**不能**扰动射频")

    def test_rescan_button_is_the_only_active_sweep(self):
        calls = []

        def fake(**kw):
            calls.append(kw)
            return _snap()

        with mock.patch.object(wifi, "snapshot", side_effect=fake):
            from ui_dialogs.wifi import WifiDialog
            dlg = WifiDialog(snapshot=_snap())      # 先注入，不起线程
            self._made.append(dlg)
            self.assertEqual(calls, [])
            dlg.btn_rescan.click()
            self._wait(dlg)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].get("refresh"), "按钮必须真的请求主动扫描")

    def test_button_is_disabled_while_fetching(self):
        from ui_dialogs.wifi import WifiDialog

        def fake(**kw):
            return _snap()

        with mock.patch.object(wifi, "snapshot", side_effect=fake):
            dlg = WifiDialog()
            self._made.append(dlg)
            self.assertFalse(dlg.btn_rescan.isEnabled(),
                             "取数期间按钮应当禁用（避免连点）")
            self._wait(dlg)
            self.assertTrue(dlg.btn_rescan.isEnabled())

    def test_thread_default_is_no_sweep(self):
        from ui_threads import WifiSnapshotThread
        self.assertFalse(WifiSnapshotThread().refresh)

    def test_reload_is_ignored_while_a_fetch_is_running(self):
        """取数还没回来时再点一次，不该起第二个线程（否则会连跑两遍 netsh）。"""
        from ui_dialogs.wifi import WifiDialog
        dlg = WifiDialog(snapshot=_snap())
        self._made.append(dlg)
        running = mock.Mock()
        running.isRunning.return_value = True
        dlg._thread = running
        with mock.patch.object(wifi, "snapshot") as patched:
            dlg.reload(refresh=True)
        patched.assert_not_called()
        self.assertIs(dlg._thread, running, "不该把在跑的线程换掉")

    def test_a_failing_fetch_degrades_instead_of_raising(self):
        """取数炸了要把异常变成"不可用"快照，不能让线程吞了异常还留个空界面。"""
        from ui_dialogs.wifi import WifiDialog

        def boom(**kw):
            raise OSError("netsh 不见了")

        with mock.patch.object(wifi, "snapshot", side_effect=boom):
            dlg = WifiDialog()
            self._made.append(dlg)
            self._wait(dlg)
        self.assertIsNotNone(dlg.snapshot)
        self.assertFalse(dlg.snapshot.capability.supported)
        self.assertEqual(dlg.snapshot.capability.reason,
                         wifi.REASON_QUERY_FAILED)
        self.assertIn(tr("无线切片不可用"), dlg.head_label.text())

    def test_close_waits_for_the_thread_instead_of_aborting(self):
        """QThread 还在跑的时候被析构会 abort —— `closeEvent` 必须先 wait。

        ⚠️ 这里**不能**断言 `dlg._thread is None`：`_thread` 是 `_on_snapshot`
        清的，而 `closeEvent` 不走事件循环。只断言"不再运行"。
        """
        from PyQt5.QtGui import QCloseEvent
        from ui_dialogs.wifi import WifiDialog

        def fake(**kw):
            return _snap()

        with mock.patch.object(wifi, "snapshot", side_effect=fake):
            dlg = WifiDialog()
            self._made.append(dlg)
            dlg.closeEvent(QCloseEvent())       # 不该抛、也不该 abort
        self.assertTrue(dlg._thread is None or not dlg._thread.isRunning(),
                        "closeEvent 返回后线程不该还在跑")


if __name__ == "__main__":
    unittest.main()
