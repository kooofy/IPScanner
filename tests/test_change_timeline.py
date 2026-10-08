# -*- coding: utf-8 -*-
"""P3-1 回归测试：变更时间线（行内角标 / 变更筛选 / 历史轨迹）。

历史缺陷（本次改动修掉的）
--------------------------
1. **冲突标记与变更角标互相覆盖**。两者都要改第 0 列文本：冲突加 `"⚠ "`
   前缀、变更加 `"↑"` 后缀。旧实现各自 `setText`，后调用的那个把前一个的
   结果整个覆盖 —— 一台设备同时"有冲突"又"IP 变了"时必然丢一个标记。
   现在由 `_apply_row_marks()` 从 role 读标记一次性合成。
2. **tooltip 靠字符串剥离**。旧实现用 `tip.split(tr(" | 冲突:"))[0]` 反向
   去掉自己追加过的段落，文案一改或多方都想追加就会切掉别人的内容。
   现在基础 tooltip 存在 role 里，每次整体重算。
3. **「设备消失」角标可能错贴到别的设备**。消失的设备本次没有行，若按它的
   旧 IP 归并、而该 IP 已被新设备占用，角标就会贴到那台在线的新设备上。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QTreeWidget

import i18n
import history_store
import ui_logic
from change_detector import (
    Change, CHANGE_NEW_DEVICE, CHANGE_DEVICE_GONE, CHANGE_IP_CHANGED,
    CHANGE_MAC_CHANGED, CHANGE_HOSTNAME_CHANGED, SEVERITY_WARNING,
)
from conflict_detector import Conflict, SEVERITY_HIGH
from detail_panel import DeviceDetailPanel
from main_window_tree import (
    ResultTreeItem, TreeMixin, _ROLE_DEV_IP, _ROLE_CHANGE, _ROLE_BASE_TIP,
    _CHANGE_GLYPH,
)
from scanner.models import ScanResult

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()
    i18n.init("zh-CN")


class _Harness(TreeMixin, QTreeWidget):
    """承载 `_apply_row_marks` / `_item_matches_key` 的最小宿主。"""

    def __init__(self):
        QTreeWidget.__init__(self)
        self.table = self
        self._ip_item_map = {}
        self._result_map = {}
        self._conflict_ips = {}
        self._conflicts = []
        self._change_map = {}
        self.dark_mode = False
        self.favorites = None


def dev(ip, mac="", status="online", hostname=""):
    r = ScanResult(ip=ip)
    r.status = status
    r.mac = mac
    r.hostname = hostname
    return r


# ── 1. 历史轨迹查询 ───────────────────────────────────────

class DeviceTimelineTest(unittest.TestCase):
    """history_store.device_timeline 的匹配与截断语义。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "h.db")

    def _snap(self, devices, ts=None):
        return history_store.save_snapshot(devices, ts=ts, db_path=self.db)

    def test_returns_records_in_chronological_order(self):
        for i in range(3):
            self._snap([{"ip": "10.0.0.5", "status": "online",
                         "mac": "AA:BB:CC:DD:EE:01", "hostname": "pc"}],
                       ts=1000 + i)
        tl = history_store.device_timeline(mac="AA:BB:CC:DD:EE:01", db_path=self.db)
        self.assertEqual(len(tl), 3)
        times = [e["time"] for e in tl]
        self.assertEqual(times, sorted(times), "应按快照 id 升序（旧 → 新）")

    def test_mac_match_is_case_insensitive(self):
        """MAC 写入时未归一化，查询必须大小写不敏感，否则查不到。"""
        self._snap([{"ip": "10.0.0.5", "status": "online",
                     "mac": "aa:bb:cc:dd:ee:01", "hostname": "pc"}])
        self.assertEqual(
            len(history_store.device_timeline(
                mac="AA:BB:CC:DD:EE:01", db_path=self.db)), 1)

    def test_mac_takes_priority_over_ip(self):
        """MAC 优先：IP 会被 DHCP 回收，按 IP 追溯会把两台设备串在一起。"""
        self._snap([{"ip": "10.0.0.5", "status": "online",
                     "mac": "AA:BB:CC:DD:EE:01", "hostname": "old"}])
        self._snap([{"ip": "10.0.0.5", "status": "online",
                     "mac": "AA:BB:CC:DD:EE:99", "hostname": "new"}])
        tl = history_store.device_timeline(
            mac="AA:BB:CC:DD:EE:99", ip="10.0.0.5", db_path=self.db)
        self.assertEqual(len(tl), 1, "应只返回该 MAC 自己的记录")
        self.assertEqual(tl[0]["hostname"], "new")

    def test_ip_fallback_when_mac_missing(self):
        self._snap([{"ip": "10.0.0.7", "status": "online", "mac": "",
                     "hostname": "x"}])
        self.assertEqual(
            len(history_store.device_timeline(ip="10.0.0.7", db_path=self.db)), 1)

    def test_limit_keeps_most_recent(self):
        for i in range(5):
            self._snap([{"ip": "10.0.0.5", "status": "online",
                         "mac": "AA:BB:CC:DD:EE:01", "hostname": f"h{i}"}])
        tl = history_store.device_timeline(
            mac="AA:BB:CC:DD:EE:01", db_path=self.db, limit=2)
        self.assertEqual([e["hostname"] for e in tl], ["h3", "h4"])

    def test_empty_arguments_return_empty(self):
        self.assertEqual(history_store.device_timeline(db_path=self.db), [])
        self.assertEqual(
            history_store.device_timeline(mac="", ip="", db_path=self.db), [])

    def test_unknown_device_returns_empty(self):
        self._snap([{"ip": "10.0.0.5", "status": "online",
                     "mac": "AA:BB:CC:DD:EE:01"}])
        self.assertEqual(
            history_store.device_timeline(mac="FF:FF:FF:FF:FF:FF", db_path=self.db), [])

    def test_status_is_preserved(self):
        """轨迹要能看出"上次在线、这次离线"，所以 status 必须原样返回。"""
        self._snap([{"ip": "10.0.0.5", "status": "offline",
                     "mac": "AA:BB:CC:DD:EE:01"}])
        tl = history_store.device_timeline(mac="AA:BB:CC:DD:EE:01", db_path=self.db)
        self.assertEqual(tl[0]["status"], "offline")


# ── 2. 变更索引折叠 ───────────────────────────────────────

class BuildChangeIndexTest(unittest.TestCase):
    """ui_logic.build_change_index 的归并与「消失」把关。"""

    def test_keys_by_ip(self):
        idx = ui_logic.build_change_index(
            [Change(change_type=CHANGE_NEW_DEVICE, severity=SEVERITY_WARNING,
                    description="x", ip="10.0.0.3", mac="AA:00:00:00:00:03")],
            [dev("10.0.0.3", "AA:00:00:00:00:03")],
        )
        self.assertEqual(idx, {"10.0.0.3": [CHANGE_NEW_DEVICE]})

    def test_multiple_changes_on_same_ip_are_kept_in_order(self):
        idx = ui_logic.build_change_index(
            [
                Change(change_type=CHANGE_IP_CHANGED, severity=SEVERITY_WARNING,
                       description="a", ip="10.0.0.9", mac="AA:00:00:00:00:09"),
                Change(change_type=CHANGE_HOSTNAME_CHANGED, severity=SEVERITY_WARNING,
                       description="b", ip="10.0.0.9", mac="AA:00:00:00:00:09"),
            ],
            [dev("10.0.0.9", "AA:00:00:00:00:09")],
        )
        self.assertEqual(idx["10.0.0.9"],
                         [CHANGE_IP_CHANGED, CHANGE_HOSTNAME_CHANGED])

    def test_duplicate_types_are_deduped(self):
        idx = ui_logic.build_change_index(
            [
                Change(change_type=CHANGE_MAC_CHANGED, severity=SEVERITY_HIGH,
                       description="a", ip="10.0.0.9", mac="AA:00:00:00:00:09"),
                Change(change_type=CHANGE_MAC_CHANGED, severity=SEVERITY_HIGH,
                       description="b", ip="10.0.0.9", mac="AA:00:00:00:00:09"),
            ],
            [dev("10.0.0.9", "AA:00:00:00:00:09")],
        )
        self.assertEqual(idx["10.0.0.9"], [CHANGE_MAC_CHANGED])

    def test_gone_device_keeps_badge_when_row_still_matches(self):
        """设备掉线：行还在（离线），角标应保留 —— 这正是最有用的提示。"""
        idx = ui_logic.build_change_index(
            [Change(change_type=CHANGE_DEVICE_GONE, severity=SEVERITY_WARNING,
                    description="x", ip="10.0.0.2", mac="AA:00:00:00:00:02")],
            [dev("10.0.0.2", "AA:00:00:00:00:02", status="offline")],
        )
        self.assertEqual(idx, {"10.0.0.2": [CHANGE_DEVICE_GONE]})

    def test_gone_badge_is_suppressed_when_ip_taken_by_other_mac(self):
        """核心回归：IP 被别的设备顶替时，不能把「消失」贴到新设备上。"""
        idx = ui_logic.build_change_index(
            [Change(change_type=CHANGE_DEVICE_GONE, severity=SEVERITY_WARNING,
                    description="旧设备走了", ip="10.0.0.2",
                    mac="AA:00:00:00:00:02")],
            [dev("10.0.0.2", "BB:00:00:00:00:99")],   # 换了台设备占这个 IP
        )
        self.assertEqual(idx, {})

    def test_gone_badge_kept_when_current_mac_unknown(self):
        """当前设备没探到 MAC 时无从判断，宁可保留也不误删。"""
        idx = ui_logic.build_change_index(
            [Change(change_type=CHANGE_DEVICE_GONE, severity=SEVERITY_WARNING,
                    description="x", ip="10.0.0.2", mac="AA:00:00:00:00:02")],
            [dev("10.0.0.2", "")],
        )
        self.assertEqual(idx, {"10.0.0.2": [CHANGE_DEVICE_GONE]})

    def test_changes_without_ip_are_skipped(self):
        idx = ui_logic.build_change_index(
            [Change(change_type=CHANGE_NEW_DEVICE, severity=SEVERITY_WARNING,
                    description="x", ip="", mac="AA:00:00:00:00:03")],
            [],
        )
        self.assertEqual(idx, {})

    def test_empty_inputs_are_safe(self):
        self.assertEqual(ui_logic.build_change_index([], []), {})
        self.assertEqual(ui_logic.build_change_index(None, None), {})


# ── 3. 行内角标渲染 ───────────────────────────────────────

class RowMarkTest(unittest.TestCase):
    """第 0 列文本 / 前景色 / tooltip 的合成。"""

    def setUp(self):
        self.h = _Harness()
        self.item = ResultTreeItem()
        self.h.addTopLevelItem(self.item)
        self.item.setData(0, _ROLE_DEV_IP, "10.0.0.5")
        self.item.setData(0, _ROLE_BASE_TIP, "10.0.0.5 基础提示")

    def tearDown(self):
        self.h.clear()
        self.h.deleteLater()

    def _mark(self, ip="10.0.0.5"):
        self.h._apply_row_marks(self.item, ip)

    def test_plain_row_shows_bare_ip(self):
        self._mark()
        self.assertEqual(self.item.text(0), "10.0.0.5")

    def test_change_appends_glyph_suffix(self):
        self.h._change_map = {"10.0.0.5": [CHANGE_IP_CHANGED]}
        self._mark()
        self.assertEqual(self.item.text(0), f"10.0.0.5 {_CHANGE_GLYPH[CHANGE_IP_CHANGED]}")

    def test_conflict_and_change_coexist(self):
        """核心回归：两者曾互相覆盖，现在必须同时出现在同一行。"""
        self.h._change_map = {"10.0.0.5": [CHANGE_IP_CHANGED]}
        self.h._conflict_ips = {"10.0.0.5": ["duplicate_ip"]}
        self.h._conflicts = [Conflict(conflict_type="duplicate_ip",
                                      severity=SEVERITY_HIGH,
                                      description="IP 冲突", ips=["10.0.0.5"])]
        self._mark()
        text = self.item.text(0)
        self.assertIn("⚠", text)
        self.assertIn(_CHANGE_GLYPH[CHANGE_IP_CHANGED], text)
        self.assertIn("10.0.0.5", text)

    def test_tooltip_contains_both_segments(self):
        self.h._change_map = {"10.0.0.5": [CHANGE_IP_CHANGED]}
        self.h._conflict_ips = {"10.0.0.5": ["duplicate_ip"]}
        self.h._conflicts = [Conflict(conflict_type="duplicate_ip",
                                      severity=SEVERITY_HIGH,
                                      description="IP 冲突", ips=["10.0.0.5"])]
        self._mark()
        tip = self.item.toolTip(0)
        self.assertIn("10.0.0.5 基础提示", tip)
        self.assertIn(i18n.tr("冲突"), tip)
        self.assertIn(i18n.tr("变更"), tip)

    def test_marks_are_cleared_when_change_map_empties(self):
        """检测无变更时必须能清掉旧角标，否则会一直挂着上次的标记。"""
        self.h._change_map = {"10.0.0.5": [CHANGE_IP_CHANGED]}
        self._mark()
        self.assertNotEqual(self.item.text(0), "10.0.0.5")
        self.h._change_map = {}
        self._mark()
        self.assertEqual(self.item.text(0), "10.0.0.5")

    def test_tooltip_returns_to_base_after_clearing(self):
        self.h._change_map = {"10.0.0.5": [CHANGE_IP_CHANGED]}
        self._mark()
        self.h._change_map = {}
        self._mark()
        self.assertEqual(self.item.toolTip(0), "10.0.0.5 基础提示")

    def test_multiple_change_types_render_multiple_glyphs(self):
        self.h._change_map = {"10.0.0.5": [CHANGE_IP_CHANGED,
                                           CHANGE_HOSTNAME_CHANGED]}
        self._mark()
        self.assertEqual(
            self.item.text(0),
            "10.0.0.5 " + _CHANGE_GLYPH[CHANGE_IP_CHANGED]
            + _CHANGE_GLYPH[CHANGE_HOSTNAME_CHANGED],
        )

    def test_row_without_ip_role_is_untouched(self):
        blank = ResultTreeItem()
        self.h.addTopLevelItem(blank)
        blank.setText(0, "占位")
        self.h._apply_row_marks(blank, "")
        self.assertEqual(blank.text(0), "占位")


class ChangeFilterMatchTest(unittest.TestCase):
    """「变更」筛选取自 role，不依赖渲染出来的字形。"""

    def setUp(self):
        self.h = _Harness()
        self.item = ResultTreeItem()
        self.h.addTopLevelItem(self.item)
        self.item.setData(0, _ROLE_DEV_IP, "10.0.0.5")

    def tearDown(self):
        self.h.clear()
        self.h.deleteLater()

    def test_matches_when_change_role_set(self):
        self.item.setData(0, _ROLE_CHANGE, [CHANGE_NEW_DEVICE])
        self.assertTrue(self.h._item_matches_key(self.item, "change"))

    def test_does_not_match_when_role_empty(self):
        self.assertFalse(self.h._item_matches_key(self.item, "change"))

    def test_match_is_independent_of_displayed_text(self):
        """即便文本被改成任意内容，筛选结果只由 role 决定。"""
        self.item.setData(0, _ROLE_CHANGE, [CHANGE_DEVICE_GONE])
        self.item.setText(0, "完全无关的文本")
        self.assertTrue(self.h._item_matches_key(self.item, "change"))

    def test_change_is_a_registered_filter_key(self):
        from filter_bar import FILTERS
        keys = [k for k, _lbl in FILTERS]
        self.assertIn("change", keys)

    def test_change_count_is_reported(self):
        self.item.setData(0, _ROLE_CHANGE, [CHANGE_NEW_DEVICE])
        counts = self.h._compute_filter_counts()
        self.assertEqual(counts["change"], 1)
        self.assertEqual(counts["all"], 1)


# ── 4. 详情面板的「变更」「历史轨迹」分区 ─────────────────

class DetailPanelChangeTest(unittest.TestCase):

    def setUp(self):
        self.p = DeviceDetailPanel()

    def tearDown(self):
        self.p.deleteLater()

    def _text(self):
        return self.p._plain_text()

    def test_change_section_is_rendered(self):
        r = dev("10.0.0.5", "AA:00:00:00:00:05")
        self.p.set_device(r, change_notes=["[IP 变更] 10.0.0.4 → 10.0.0.5"])
        text = self._text()
        self.assertIn(i18n.tr("变更"), text)
        self.assertIn("10.0.0.4 → 10.0.0.5", text)

    def test_change_section_absent_when_no_changes(self):
        r = dev("10.0.0.5", "AA:00:00:00:00:05")
        self.p.set_device(r)
        self.assertNotIn(i18n.tr("历史轨迹"), self._text())

    def test_timeline_is_rendered_newest_first(self):
        r = dev("10.0.0.5", "AA:00:00:00:00:05")
        self.p.set_device(r, timeline=[
            {"time": 1700000000, "status": "online", "ip": "10.0.0.4"},
            {"time": 1700003600, "status": "offline", "ip": "10.0.0.5"},
        ])
        text = self._text()
        self.assertIn(i18n.tr("历史轨迹"), text)
        self.assertLess(text.index("10.0.0.5"), text.index("10.0.0.4"),
                        "最近的记录应排在上面")

    def test_timeline_entry_shows_state_and_ip(self):
        line = DeviceDetailPanel._format_timeline_entry(
            {"time": 1700000000, "status": "online", "ip": "10.0.0.4"})
        self.assertIn(i18n.tr("在线"), line)
        self.assertIn("10.0.0.4", line)
        self.assertIn("2023-11-15", line)

    def test_timeline_entry_survives_bad_timestamp(self):
        """时间戳坏了只丢时间，不该整行消失 —— 状态和 IP 仍有价值。"""
        line = DeviceDetailPanel._format_timeline_entry(
            {"time": "not-a-number", "status": "offline", "ip": "10.0.0.4"})
        self.assertIn(i18n.tr("离线"), line)
        self.assertIn("10.0.0.4", line)

    def test_timeline_entry_rejects_non_dict(self):
        self.assertEqual(DeviceDetailPanel._format_timeline_entry("x"), "")
        self.assertEqual(DeviceDetailPanel._format_timeline_entry(None), "")

    def test_clear_resets_change_and_timeline(self):
        r = dev("10.0.0.5", "AA:00:00:00:00:05")
        self.p.set_device(r, change_notes=["x"], timeline=[
            {"time": 1700000000, "status": "online", "ip": "10.0.0.5"}])
        self.p.clear()
        self.p.set_device(r)
        text = self._text()
        self.assertNotIn(i18n.tr("变更"), text)
        self.assertNotIn(i18n.tr("历史轨迹"), text)


if __name__ == "__main__":
    unittest.main()
