# -*- coding: utf-8 -*-
"""告警策略（维护窗口 / 静音 / 通知去重）的单元测试。

锁死四件事：
1. **时段边界**：``[start, end)`` 半开区间、跨午夜按**起始日**算、空窗口不抑制；
2. **作用域**：网段 / 设备 / 变更类型三个维度是**与**关系，空 = 不限；
3. **去重状态必须落盘**（定时扫描是独立进程，内存状态活不过一次运行），
   且 ``evaluate()`` **只读** —— 记账必须等发送成功；
4. **失败安全**：配置写错时**不抑制**（宁可多报，不可漏报）。
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import alert_policy as ap
from change_detector import (Change, CHANGE_DEVICE_GONE, CHANGE_NEW_DEVICE,
                             CHANGE_MAC_CHANGED, SEVERITY_INFO)

# 2026-10-12 是星期一（weekday()==0）
MON = datetime(2026, 10, 12, 2, 0)          # 周一 02:00
TUE = datetime(2026, 10, 13, 2, 0)          # 周二 02:00
FRI_LATE = datetime(2026, 10, 16, 23, 30)   # 周五 23:30
SAT_EARLY = datetime(2026, 10, 17, 1, 0)    # 周六 01:00
SAT_LATE = datetime(2026, 10, 17, 23, 30)   # 周六 23:30


def _change(ctype=CHANGE_DEVICE_GONE, ip="10.0.0.5",
            mac="AA:BB:CC:00:00:01", hostname="prn-1"):
    return Change(change_type=ctype, severity=SEVERITY_INFO, description="d",
                  ip=ip, mac=mac, hostname=hostname)


class HelpersTest(unittest.TestCase):

    def test_normalize_mac_accepts_common_formats(self):
        for raw in ("aa:bb:cc:00:00:01", "AA-BB-CC-00-00-01",
                    "aabb.cc00.0001", "AABBCC000001"):
            self.assertEqual(ap.normalize_mac(raw), "aa:bb:cc:00:00:01", raw)

    def test_normalize_mac_rejects_garbage(self):
        self.assertEqual(ap.normalize_mac(""), "")
        self.assertEqual(ap.normalize_mac(None), "")
        self.assertEqual(ap.normalize_mac("zzz"), "")

    def test_as_list_variants(self):
        self.assertEqual(ap._as_list(None), [])
        self.assertEqual(ap._as_list(""), [])
        self.assertEqual(ap._as_list("a"), ["a"])
        self.assertEqual(ap._as_list(["a", " b "]), ["a", "b"])
        self.assertEqual(ap._as_list("a,b , c"), ["a", "b", "c"])

    def test_parse_hhmm(self):
        self.assertEqual(ap._parse_hhmm("01:30"), 90)
        self.assertEqual(ap._parse_hhmm("1:30"), 90)
        self.assertEqual(ap._parse_hhmm("00:00"), 0)
        self.assertIsNone(ap._parse_hhmm("24:00"))
        self.assertIsNone(ap._parse_hhmm("01:60"))
        self.assertIsNone(ap._parse_hhmm(""))
        self.assertIsNone(ap._parse_hhmm("abc"))

    def test_parse_days_variants(self):
        self.assertIsNone(ap._parse_days(None))
        self.assertIsNone(ap._parse_days([]))
        self.assertEqual(ap._parse_days(["mon"]), frozenset({0}))
        self.assertEqual(ap._parse_days(["Monday"]), frozenset({0}))
        self.assertEqual(ap._parse_days(["周一"]), frozenset({0}))
        self.assertEqual(ap._parse_days(["星期一"]), frozenset({0}))
        self.assertEqual(ap._parse_days([0]), frozenset({0}))
        self.assertEqual(ap._parse_days(["工作日"]), frozenset({0, 1, 2, 3, 4}))
        self.assertEqual(ap._parse_days(["weekend"]), frozenset({5, 6}))

    def test_parse_days_unknown_token_is_ignored(self):
        self.assertEqual(ap._parse_days(["mon", "bogus"]), frozenset({0}))

    def test_parse_days_all_unknown_returns_none(self):
        self.assertIsNone(ap._parse_days(["bogus"]))

    def test_parse_until_date_only_means_end_of_day(self):
        got = ap._parse_until("2026-11-01")
        self.assertEqual(got, datetime(2026, 11, 1, 23, 59, 59))

    def test_parse_until_with_time(self):
        self.assertEqual(ap._parse_until("2026-11-01T09:30"),
                         datetime(2026, 11, 1, 9, 30))
        self.assertEqual(ap._parse_until("2026-11-01 09:30:15"),
                         datetime(2026, 11, 1, 9, 30, 15))

    def test_parse_until_invalid(self):
        self.assertIsNone(ap._parse_until(""))
        self.assertIsNone(ap._parse_until("tomorrow"))

    def test_suppress_reason_label_passthrough_unknown(self):
        self.assertEqual(ap.suppress_reason_label("weird"), "weird")

    def test_suppress_reason_label_is_canonical_aware(self):
        """展示名随语言变化，但规范值本身不变（i18n 铁律）。"""
        import i18n
        prev = i18n.current_lang()
        try:
            i18n.init("zh-CN")
            zh = ap.suppress_reason_label(ap.SUPPRESS_MUTED)
            i18n.init("en-US")
            en = ap.suppress_reason_label(ap.SUPPRESS_MUTED)
        finally:
            i18n.init(prev)
        self.assertNotEqual(zh, en)


class WindowTest(unittest.TestCase):

    def test_active_inside_range(self):
        w = ap._build_window({"start": "01:00", "end": "04:00"})
        self.assertTrue(w.active(MON))

    def test_end_is_exclusive(self):
        w = ap._build_window({"start": "01:00", "end": "04:00"})
        self.assertTrue(w.active(datetime(2026, 10, 12, 3, 59)))
        self.assertFalse(w.active(datetime(2026, 10, 12, 4, 0)))

    def test_start_is_inclusive(self):
        w = ap._build_window({"start": "01:00", "end": "04:00"})
        self.assertTrue(w.active(datetime(2026, 10, 12, 1, 0)))
        self.assertFalse(w.active(datetime(2026, 10, 12, 0, 59)))

    def test_day_filter(self):
        w = ap._build_window({"start": "01:00", "end": "04:00",
                              "days": ["mon"]})
        self.assertTrue(w.active(MON))
        self.assertFalse(w.active(TUE))

    def test_no_days_means_every_day(self):
        w = ap._build_window({"start": "01:00", "end": "04:00"})
        self.assertTrue(w.active(MON))
        self.assertTrue(w.active(TUE))

    def test_cross_midnight_uses_start_day(self):
        w = ap._build_window({"start": "23:00", "end": "02:00",
                              "days": ["fri"]})
        self.assertTrue(w.active(FRI_LATE), "周五 23:30 应在窗口内")
        self.assertTrue(w.active(SAT_EARLY), "周六 01:00 属于周五开始的那一段")
        self.assertFalse(w.active(SAT_LATE), "周六 23:30 不是周五的窗口")
        self.assertFalse(w.active(datetime(2026, 10, 16, 22, 0)))

    def test_cross_midnight_every_day(self):
        w = ap._build_window({"start": "23:00", "end": "02:00"})
        self.assertTrue(w.active(FRI_LATE))
        self.assertTrue(w.active(SAT_EARLY))
        self.assertTrue(w.active(SAT_LATE))
        self.assertFalse(w.active(datetime(2026, 10, 12, 12, 0)))

    def test_empty_window_never_active(self):
        """start == end 视为空窗口：fail-open，不抑制任何告警。"""
        w = ap._build_window({"start": "02:00", "end": "02:00"})
        self.assertFalse(w.active(MON))

    def test_invalid_window_is_dropped(self):
        self.assertIsNone(ap._build_window({"start": "25:00", "end": "04:00"}))
        self.assertIsNone(ap._build_window({"start": "01:00"}))
        self.assertIsNone(ap._build_window("not-a-dict"))

    def test_scope_types_filter(self):
        w = ap._build_window({"start": "01:00", "end": "04:00",
                              "types": [CHANGE_DEVICE_GONE]})
        self.assertTrue(w.scope.matches(_change(CHANGE_DEVICE_GONE)))
        self.assertFalse(w.scope.matches(_change(CHANGE_NEW_DEVICE)))

    def test_scope_range(self):
        w = ap._build_window({"start": "01:00", "end": "04:00",
                              "ranges": ["10.0.0.0/24"]})
        self.assertTrue(w.scope.matches(_change(ip="10.0.0.7")))
        self.assertFalse(w.scope.matches(_change(ip="10.0.1.7")))

    def test_scope_devices_accepts_various_mac_formats(self):
        w = ap._build_window({"start": "01:00", "end": "04:00",
                              "devices": ["AA-BB-CC-00-00-01"]})
        self.assertTrue(w.scope.matches(_change(mac="aa:bb:cc:00:00:01")))
        self.assertFalse(w.scope.matches(_change(mac="aa:bb:cc:00:00:02")))

    def test_scope_identity_dimensions_are_or_but_types_are_and(self):
        """网段/设备之间是「或」，与「类型」之间是「与」。"""
        w = ap._build_window({"start": "01:00", "end": "04:00",
                              "ranges": ["10.0.0.0/24"],
                              "devices": ["AA:BB:CC:00:00:01"],
                              "types": [CHANGE_DEVICE_GONE]})
        # 命中网段 + 命中类型 → 抑制
        self.assertTrue(w.scope.matches(
            _change(CHANGE_DEVICE_GONE, ip="10.0.0.9")))
        # 命中设备 + 命中类型 → 抑制
        self.assertTrue(w.scope.matches(
            _change(CHANGE_DEVICE_GONE, ip="192.168.9.9")))
        # 命中网段但类型不符 → 不抑制
        self.assertFalse(w.scope.matches(
            _change(CHANGE_NEW_DEVICE, ip="10.0.0.9")))
        # 类型符合但身份都不命中 → 不抑制
        self.assertFalse(w.scope.matches(
            _change(CHANGE_DEVICE_GONE, ip="192.168.9.9",
                    mac="AA:BB:CC:00:00:99")))

    def test_bad_range_is_ignored_not_fatal(self):
        w = ap._build_window({"start": "01:00", "end": "04:00",
                              "ranges": ["not-a-cidr", "10.0.0.0/24"]})
        self.assertEqual(len(w.scope.ranges), 1)


class MuteTest(unittest.TestCase):

    def test_match_by_mac(self):
        m = ap._build_mute({"mac": "AA:BB:CC:00:00:01"})
        self.assertTrue(m.matches(_change(mac="aa:bb:cc:00:00:01"), MON))
        self.assertFalse(m.matches(_change(mac="aa:bb:cc:00:00:02"), MON))

    def test_match_by_ip(self):
        m = ap._build_mute({"ip": "10.0.0.5"})
        self.assertTrue(m.matches(_change(ip="10.0.0.5"), MON))
        self.assertFalse(m.matches(_change(ip="10.0.0.6"), MON))

    def test_match_by_range(self):
        m = ap._build_mute({"range": "10.9.0.0/16"})
        self.assertTrue(m.matches(_change(ip="10.9.3.4"), MON))
        self.assertFalse(m.matches(_change(ip="10.10.3.4"), MON))

    def test_type_restriction(self):
        m = ap._build_mute({"mac": "AA:BB:CC:00:00:01",
                            "types": [CHANGE_DEVICE_GONE]})
        self.assertTrue(m.matches(_change(CHANGE_DEVICE_GONE), MON))
        self.assertFalse(m.matches(_change(CHANGE_NEW_DEVICE), MON))

    def test_expired_mute_is_ignored(self):
        m = ap._build_mute({"mac": "AA:BB:CC:00:00:01",
                            "until": "2026-10-01"})
        self.assertFalse(m.matches(_change(), MON))

    def test_until_boundary_is_exclusive(self):
        m = ap._build_mute({"mac": "AA:BB:CC:00:00:01", "until": "2026-10-12"})
        # until = 2026-10-12 23:59:59；到点即失效
        self.assertTrue(m.matches(_change(), datetime(2026, 10, 12, 23, 0)))
        self.assertFalse(m.matches(_change(), datetime(2026, 10, 13, 0, 0)))

    def test_mute_without_identity_or_types_is_ignored(self):
        """没写设备/网段、也没写类型 → 会静音一切，几乎肯定是漏字段。"""
        self.assertIsNone(ap._build_mute({"name": "手滑"}))
        self.assertIsNone(ap._build_mute({"mac": "", "ranges": []}))

    def test_mute_by_types_only_is_allowed(self):
        m = ap._build_mute({"name": "全局忽略离线", "types": [CHANGE_DEVICE_GONE]})
        self.assertIsNotNone(m)
        self.assertTrue(m.matches(_change(CHANGE_DEVICE_GONE), MON))
        self.assertFalse(m.matches(_change(CHANGE_NEW_DEVICE), MON))

    def test_non_dict_mute_is_ignored(self):
        self.assertIsNone(ap._build_mute("nope"))


class DedupStoreTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "alert_dedup.json")

    def _store(self, **kw):
        kw.setdefault("path", self.path)
        kw.setdefault("window_minutes", 60)
        return ap.DedupStore(**kw)

    def test_first_time_not_suppressed(self):
        s = self._store()
        self.assertFalse(s.is_suppressed(_change(), MON))

    def test_record_then_suppressed_within_window(self):
        s = self._store()
        s.record([_change()], MON)
        self.assertTrue(s.is_suppressed(_change(), MON + timedelta(minutes=30)))

    def test_not_suppressed_after_window(self):
        s = self._store()
        s.record([_change()], MON)
        self.assertFalse(s.is_suppressed(_change(),
                                         MON + timedelta(minutes=61)))

    def test_state_persists_across_instances(self):
        """**关键**：定时扫描是独立进程，去重必须跨进程生效。"""
        s1 = self._store()
        s1.record([_change()], MON)
        s1.save()
        self.assertTrue(os.path.exists(self.path))

        s2 = self._store()
        self.assertTrue(s2.is_suppressed(_change(), MON + timedelta(minutes=5)))

    def test_save_is_noop_when_nothing_recorded(self):
        s = self._store()
        s.save()
        self.assertFalse(os.path.exists(self.path))

    def test_different_change_type_not_suppressed(self):
        s = self._store()
        s.record([_change(CHANGE_DEVICE_GONE)], MON)
        self.assertFalse(s.is_suppressed(_change(CHANGE_NEW_DEVICE), MON))

    def test_different_device_not_suppressed(self):
        s = self._store()
        s.record([_change(mac="AA:BB:CC:00:00:01")], MON)
        self.assertFalse(s.is_suppressed(_change(mac="AA:BB:CC:00:00:02"), MON))

    def test_key_type_groups_all_devices(self):
        s = self._store(key=ap.DEDUP_KEY_TYPE)
        s.record([_change(mac="AA:BB:CC:00:00:01")], MON)
        self.assertTrue(s.is_suppressed(_change(mac="AA:BB:CC:00:00:02"), MON))

    def test_key_device_ignores_change_type(self):
        s = self._store(key=ap.DEDUP_KEY_DEVICE)
        s.record([_change(CHANGE_DEVICE_GONE)], MON)
        self.assertTrue(s.is_suppressed(_change(CHANGE_NEW_DEVICE), MON))

    def test_key_ip_uses_ip(self):
        s = self._store(key=ap.DEDUP_KEY_IP)
        s.record([_change(ip="10.0.0.5", mac="AA:BB:CC:00:00:01")], MON)
        self.assertTrue(s.is_suppressed(
            _change(ip="10.0.0.5", mac="AA:BB:CC:00:00:02"), MON))
        self.assertFalse(s.is_suppressed(
            _change(ip="10.0.0.6", mac="AA:BB:CC:00:00:01"), MON))

    def test_invalid_key_falls_back_to_default(self):
        s = self._store(key="bogus")
        self.assertEqual(s.key, ap.DEDUP_KEY_DEVICE_TYPE)

    def test_window_zero_disables_dedup(self):
        s = self._store(window_minutes=0)
        s.record([_change()], MON)
        self.assertFalse(s.is_suppressed(_change(), MON))
        s.save()
        self.assertFalse(os.path.exists(self.path))

    def test_corrupt_state_file_does_not_raise(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{ this is not json")
        s = self._store()
        self.assertFalse(s.is_suppressed(_change(), MON))

    def test_non_dict_seen_entries_are_skipped(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('{"seen": {"k": "not-a-number", "k2": 1.0}}')
        s = self._store()
        s.load()
        self.assertIn("k2", s._seen)
        self.assertNotIn("k", s._seen)

    def test_prune_drops_stale_signatures(self):
        s = self._store(window_minutes=1)
        s.record([_change()], MON - timedelta(hours=5))
        s.prune(MON)
        self.assertEqual(s._seen, {})

    def test_prune_keeps_recent(self):
        s = self._store(window_minutes=60)
        s.record([_change()], MON)
        s.prune(MON + timedelta(minutes=1))
        self.assertEqual(len(s._seen), 1)

    def test_remaining_seconds_reported(self):
        s = self._store(window_minutes=60)
        s.record([_change()], MON)
        left = s.remaining_seconds(_change(), MON + timedelta(minutes=10))
        self.assertAlmostEqual(left, 50 * 60, delta=5)


class EvaluateTest(unittest.TestCase):

    def test_no_rules_lets_everything_through(self):
        policy = ap.AlertPolicy()
        self.assertFalse(policy.enabled)
        res = policy.evaluate([_change(), _change(CHANGE_NEW_DEVICE)])
        self.assertEqual(len(res.notify), 2)
        self.assertEqual(res.suppressed, [])

    def test_all_suppressed_flag(self):
        policy = ap.AlertPolicy(windows=[ap._build_window(
            {"start": "00:00", "end": "23:59"})])
        res = policy.evaluate([_change()], now=MON)
        self.assertEqual(res.notify, [])
        self.assertTrue(res.all_suppressed)

    def test_partial_suppression(self):
        policy = ap.AlertPolicy(mutes=[ap._build_mute(
            {"mac": "AA:BB:CC:00:00:01"})])
        res = policy.evaluate(
            [_change(mac="AA:BB:CC:00:00:01"), _change(mac="AA:BB:CC:00:00:02")],
            now=MON)
        self.assertEqual(len(res.notify), 1)
        self.assertEqual(len(res.suppressed), 1)
        self.assertFalse(res.all_suppressed)

    def test_maintenance_window_wins_over_mute(self):
        """判定顺序固定：维护窗口 → 静音 → 去重。"""
        policy = ap.AlertPolicy(
            windows=[ap._build_window({"name": "备份", "start": "00:00",
                                       "end": "23:59"})],
            mutes=[ap._build_mute({"name": "检修",
                                   "mac": "AA:BB:CC:00:00:01"})])
        res = policy.evaluate([_change()], now=MON)
        self.assertEqual(res.suppressed[0].reason, ap.SUPPRESS_MAINTENANCE)
        self.assertEqual(res.suppressed[0].detail, "备份")

    def test_count_by_reason(self):
        policy = ap.AlertPolicy(
            windows=[ap._build_window({"start": "00:00", "end": "23:59"})],
            mutes=[ap._build_mute({"mac": "AA:BB:CC:00:00:01"})])
        res = policy.evaluate(
            [_change(mac="AA:BB:CC:00:00:01"), _change(mac="AA:BB:CC:00:00:02")],
            now=MON)
        self.assertEqual(res.count_by_reason(), {ap.SUPPRESS_MAINTENANCE: 2})

    def test_evaluate_is_read_only_on_store(self):
        """evaluate() 不能记账 —— 记账必须等发送成功（否则失败即静默丢失）。"""
        tmp = tempfile.mkdtemp()
        store = ap.DedupStore(path=os.path.join(tmp, "d.json"),
                              window_minutes=60)
        policy = ap.AlertPolicy(dedup_window_minutes=60)
        res = policy.evaluate([_change()], now=MON, store=store)
        self.assertEqual(len(res.notify), 1)
        self.assertEqual(store._seen, {})
        self.assertFalse(os.path.exists(store.path))

    def test_dedup_suppresses_after_record(self):
        tmp = tempfile.mkdtemp()
        store = ap.DedupStore(path=os.path.join(tmp, "d.json"),
                              window_minutes=60)
        policy = ap.AlertPolicy(dedup_window_minutes=60)
        store.record([_change()], MON)
        res = policy.evaluate([_change()], now=MON + timedelta(minutes=5),
                              store=store)
        self.assertEqual(res.notify, [])
        self.assertEqual(res.suppressed[0].reason, ap.SUPPRESS_DEDUPED)

    def test_default_now_is_used_when_omitted(self):
        policy = ap.AlertPolicy()
        self.assertEqual(len(policy.evaluate([_change()]).notify), 1)


class ConfigTest(unittest.TestCase):

    def test_empty_config_is_not_enabled(self):
        policy = ap.AlertPolicy.from_config({})
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.windows, [])
        self.assertEqual(policy.mutes, [])
        self.assertEqual(policy.dedup_window_minutes, 0)

    def test_none_and_garbage_config_fail_open(self):
        for cfg in (None, "nope", 42, []):
            policy = ap.AlertPolicy.from_config(cfg)
            self.assertFalse(policy.enabled, msg=repr(cfg))

    def test_full_config(self):
        policy = ap.AlertPolicy.from_config({
            "maintenance_windows": [
                {"name": "备份", "days": ["mon"], "start": "01:00",
                 "end": "04:00"}],
            "mutes": [{"name": "检修", "mac": "AA:BB:CC:00:00:01"}],
            "dedup": {"window_minutes": 30, "key": "device"},
        })
        self.assertTrue(policy.enabled)
        self.assertEqual(len(policy.windows), 1)
        self.assertEqual(len(policy.mutes), 1)
        self.assertEqual(policy.dedup_window_minutes, 30)
        self.assertEqual(policy.dedup_key, ap.DEDUP_KEY_DEVICE)

    def test_bad_entries_are_skipped_not_fatal(self):
        policy = ap.AlertPolicy.from_config({
            "maintenance_windows": [
                {"start": "01:00", "end": "04:00"},     # 合法
                {"start": "99:00", "end": "04:00"},     # 非法
                "not-a-dict",                            # 非法
            ],
            "mutes": [{"name": "手滑"},                    # 会被忽略
                      {"mac": "AA:BB:CC:00:00:01"}],      # 合法
        })
        self.assertEqual(len(policy.windows), 1)
        self.assertEqual(len(policy.mutes), 1)

    def test_dedup_true_uses_default_window(self):
        policy = ap.AlertPolicy.from_config({"dedup": True})
        self.assertEqual(policy.dedup_window_minutes,
                         ap.DEFAULT_DEDUP_WINDOW_MINUTES)

    def test_dedup_bad_minutes_disables(self):
        policy = ap.AlertPolicy.from_config({"dedup": {"window_minutes": "x"}})
        self.assertEqual(policy.dedup_window_minutes, 0)

    def test_dedup_missing_key_uses_default(self):
        policy = ap.AlertPolicy.from_config({"dedup": {"window_minutes": 10}})
        self.assertEqual(policy.dedup_key, ap.DEFAULT_DEDUP_KEY)

    def test_make_store_carries_settings(self):
        policy = ap.AlertPolicy.from_config({
            "dedup": {"window_minutes": 15, "key": "ip"}})
        store = policy.make_store()
        self.assertEqual(store.window, 15 * 60)
        self.assertEqual(store.key, ap.DEDUP_KEY_IP)


class SuppressionNoteTest(unittest.TestCase):

    def test_empty_note(self):
        self.assertEqual(ap.render_suppression_note([]), "")

    def test_note_lists_entries(self):
        res = ap.AlertPolicy(mutes=[ap._build_mute(
            {"mac": "AA:BB:CC:00:00:01"})]).evaluate(
                [_change(ip="10.0.0.5")], now=MON)
        note = ap.render_suppression_note(res.suppressed)
        self.assertIn("10.0.0.5", note)
        self.assertIn("prn-1", note)

    def test_note_truncates(self):
        changes = [_change(ip=f"10.0.0.{i}", mac=f"AA:BB:CC:00:00:{i:02X}")
                   for i in range(1, 16)]
        policy = ap.AlertPolicy(mutes=[ap._build_mute({"range": "10.0.0.0/24"})])
        res = policy.evaluate(changes, now=MON)
        self.assertEqual(len(res.suppressed), 15)
        note = ap.render_suppression_note(res.suppressed, max_items=10)
        bullets = [ln for ln in note.splitlines() if ln.startswith("- ")]
        self.assertEqual(len(bullets), 10)

    def test_note_does_not_leak_change_type_labels_untranslated(self):
        """附注里的类型/原因都走 tr()，不会出现规范值。"""
        c = _change(CHANGE_MAC_CHANGED)
        res = ap.AlertPolicy(mutes=[ap._build_mute(
            {"mac": "AA:BB:CC:00:00:01"})]).evaluate([c], now=MON)
        note = ap.render_suppression_note(res.suppressed)
        self.assertNotIn(CHANGE_MAC_CHANGED, note)


if __name__ == "__main__":
    unittest.main()
