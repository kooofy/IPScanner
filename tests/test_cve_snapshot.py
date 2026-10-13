# -*- coding: utf-8 -*-
"""`scanner.cve_snapshot`（v2.1 §2.3）的单测。

对应路线图「可测验收」逐条挂号：
* 稳健加载：缺失 / JSON 坏 / 结构不符 / 未知 schema / 单条坏记录 / 0 条
  —— **全部降级不抛**（模型文档 §3.3）；
* 新鲜度：`generated_at` + `max_age_days` 判定 ok / stale / unknown-age（§3.1）；
* 验签：SHA256 通过 / 不匹配（拒绝加载）/ 清单缺失（不阻断）（§3.4）；
* 排序：KEV 优先、组内 EPSS 降序，`epss=None` 置后**且不等于 0**（§4）；
* 无数据 ≠ 无漏洞：`state` 三态可区分；
* 零网络：模块不 import 任何网络库（§1 原则 1）；
* 内置种子：规模硬上限 + 永远显示过期（§9.1）。
"""
import ast
import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import cve_snapshot as cs

FIXED_NOW = dt.datetime(2026, 10, 13, tzinfo=dt.timezone.utc)


def _write(directory, name, payload):
    """写一份快照（或别的文件），返回绝对路径。"""
    path = os.path.join(directory, name)
    if isinstance(payload, (dict, list)):
        text = json.dumps(payload, ensure_ascii=False, indent=1)
    else:
        text = payload
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def _doc(cves, generated_at="2026-10-01T00:00:00Z", max_age_days=30,
         schema=None):
    return {
        "schema": schema if schema is not None else cs.SCHEMA,
        "generated_at": generated_at,
        "max_age_days": max_age_days,
        "sources": {"nvd": "2026-10-01", "kev": "2026-09-30"},
        "cves": cves,
    }


def _entry(cve_id, cpe="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
           kev=True, epss=None):
    return {"cve_id": cve_id, "cpe": [cpe], "kev": kev, "epss": epss,
            "summary": "test"}


class _TmpDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()


# ── 加载 / 降级 ──────────────────────────────────────────────────────────

class LoadDegradationTest(_TmpDirTest):

    def test_missing_file_reports_missing_not_exception(self):
        """两个路径都没有文件 → state=missing，**绝不抛**。"""
        snap = cs.load_snapshot(os.path.join(self.dir, "nope.json"))
        self.assertEqual(snap.state, cs.STATE_MISSING)
        self.assertEqual(snap.source, cs.SOURCE_NONE)
        self.assertEqual(snap.entries, [])
        self.assertFalse(snap.usable)

    def test_broken_json_degrades_to_corrupt(self):
        path = _write(self.dir, "cve_snapshot.json", "{ not json at all")
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.state, cs.STATE_CORRUPT)
        self.assertEqual(snap.entries, [])

    def test_top_level_not_object_degrades_to_corrupt(self):
        path = _write(self.dir, "cve_snapshot.json", [1, 2, 3])
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.state, cs.STATE_CORRUPT)

    def test_cves_not_a_list_yields_empty_state(self):
        path = _write(self.dir, "cve_snapshot.json",
                      _doc("not-a-list"))
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.state, cs.STATE_EMPTY)
        self.assertEqual(snap.entries, [])

    def test_unknown_schema_still_parses(self):
        """未知 schema：不拒绝，按 v1 尽力解析 + 留痕（§4 向前兼容）。"""
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")], schema="ipscanner.cve_snapshot/9"))
        snap = cs.load_snapshot(path)
        self.assertEqual(len(snap.entries), 1)
        self.assertEqual(snap.schema, "ipscanner.cve_snapshot/9")

    def test_bad_records_are_skipped_not_fatal(self):
        """单条坏（cve_id 不像 CVE / cpe 是数字 / epss 是"高"）→ 跳过并计数。"""
        good = _entry("CVE-2021-44228")
        bad_id = {"cve_id": "not-a-cve", "cpe": ["cpe:2.3:a:x:y"], "kev": True}
        bad_cpe = {"cve_id": "CVE-2020-1111", "cpe": 42, "kev": True}
        bad_epss = {"cve_id": "CVE-2020-2222", "cpe": ["cpe:2.3:a:x:y"],
                    "kev": True, "epss": "很高"}
        dup = _entry("CVE-2021-44228", epss=0.5)
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([good, bad_id, bad_cpe, bad_epss, dup]))
        snap = cs.load_snapshot(path)
        self.assertEqual(len(snap.entries), 1)
        self.assertEqual(snap.skipped, 4)

    def test_epss_out_of_range_is_dropped(self):
        """EPSS 越界（>1 / 负数 / NaN）→ 视为无该信号，**不当 0**。"""
        path = _write(self.dir, "cve_snapshot.json", _doc([
            _entry("CVE-2020-0001", epss=1.5),
            _entry("CVE-2020-0002", epss=-0.2),
            _entry("CVE-2020-0003", epss="nan"),
            _entry("CVE-2020-0004", epss=0.25),
        ]))
        snap = cs.load_snapshot(path)
        epss = {e.cve_id: e.epss for e in snap.entries}
        self.assertEqual(epss["CVE-2020-0001"], None)
        self.assertEqual(epss["CVE-2020-0002"], None)
        self.assertEqual(epss["CVE-2020-0003"], None)
        self.assertEqual(epss["CVE-2020-0004"], 0.25)

    def test_kev_missing_is_none_not_false(self):
        """`kev` 缺失 → None（无该信号），与「查了、KEV 为 false」可区分。"""
        path = _write(self.dir, "cve_snapshot.json", _doc([
            {"cve_id": "CVE-2020-0001",
             "cpe": ["cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"]},
            {"cve_id": "CVE-2020-0002",
             "cpe": ["cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"], "kev": False},
        ]))
        snap = cs.load_snapshot(path)
        by_id = {e.cve_id: e.kev for e in snap.entries}
        self.assertEqual(len(by_id), 2)
        self.assertIsNone(by_id["CVE-2020-0001"])
        self.assertIs(by_id["CVE-2020-0002"], False)


# ── 新鲜度（§3.1） ──────────────────────────────────────────────────────

class FreshnessTest(_TmpDirTest):

    def test_fresh_snapshot_is_ok(self):
        path = _write(self.dir, "cve_snapshot.json", _doc([_entry("CVE-2021-44228")]))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(snap.state, cs.STATE_OK)
        self.assertEqual(snap.age_days, 12)
        self.assertTrue(snap.fresh)

    def test_expired_snapshot_is_stale_but_still_usable(self):
        """过期：仍可用（用户自己选的），但状态必须显式说出来。"""
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")], generated_at="2026-01-01T00:00:00Z"))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(snap.state, cs.STATE_STALE)
        self.assertGreaterEqual(snap.age_days, 30)
        self.assertTrue(snap.usable)
        self.assertFalse(snap.fresh)

    def test_missing_generated_at_is_unknown_age_not_fresh(self):
        """freshness 缺失 → 未知新鲜度，与过期同级告警，**不假设新鲜**。"""
        path = _write(self.dir, "cve_snapshot.json", _doc([_entry("CVE-2021-44228")],
                                                          generated_at=None))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(snap.state, cs.STATE_UNKNOWN_AGE)
        self.assertIsNone(snap.age_days)

    def test_unparseable_generated_at_is_unknown_age(self):
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")], generated_at="去年某天"))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(snap.state, cs.STATE_UNKNOWN_AGE)

    def test_unknown_age_with_entries_is_usable(self):
        """🔴 回归：新鲜度未知但**有条目**时必须算能查。

        曾经 `usable` 只放行 ok/stale，于是 `exposure.match_results()`
        提前返回空 hits，而 `verdict` 不把 unknown-age 归到 no-data ——
        用户看到的是「查了、没有匹配」这个**与事实相反**的结论。
        """
        path = _write(self.dir, "cve_snapshot.json", _doc(
            [_entry("CVE-2021-44228")], generated_at=None))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(snap.state, cs.STATE_UNKNOWN_AGE)
        self.assertTrue(snap.usable)
        self.assertFalse(snap.fresh)

    def test_missing_max_age_days_falls_back_to_30(self):
        doc = _doc([_entry("CVE-2021-44228")])
        doc.pop("max_age_days")
        path = _write(self.dir, "cve_snapshot.json", doc)
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(snap.max_age_days, 30)
        self.assertEqual(snap.state, cs.STATE_OK)


# ── 验签（§3.4） ────────────────────────────────────────────────────────

class ChecksumTest(_TmpDirTest):

    def _snap_with_sums(self, *, tamper=False, sums_name="cve_snapshot.sha256",
                        sums_body=None):
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")]))
        import hashlib
        with io.open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        if tamper:
            digest = "0" * 64
        body = sums_body if sums_body is not None else "%s  cve_snapshot.json\n" % digest
        with io.open(os.path.join(self.dir, sums_name), "w",
                     encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        return path

    def test_matching_checksum_loads(self):
        path = self._snap_with_sums()
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.state, cs.STATE_OK)
        self.assertIs(snap.checksum_verified, True)

    def test_mismatched_checksum_refuses_to_load(self):
        """摘要不匹配 → **拒绝加载**（下载损坏 / 半截文件 / 被改动）。"""
        path = self._snap_with_sums(tamper=True)
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.state, cs.STATE_CORRUPT)
        self.assertEqual(snap.entries, [])
        self.assertFalse(snap.usable)

    def test_missing_sums_does_not_block(self):
        """清单缺失 → **不阻断**，按原样加载并标「未校验」（§3.4 尾注）。"""
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")]))
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.state, cs.STATE_OK)
        self.assertIsNone(snap.checksum_verified)

    def test_single_entry_sums_with_other_filename_matches(self):
        """清单只有一条、文件名对不上 → 按单条目比对（用户手工裁剪过的清单）。"""
        path = self._snap_with_sums(
            sums_body=None, sums_name="SHA256SUMS")
        snap = cs.load_snapshot(path)
        self.assertIs(snap.checksum_verified, True)

    def test_sha256sum_binary_marker_and_comments_are_tolerated(self):
        path = self._snap_with_sums(sums_name="cve_snapshot.sha256",
                                    sums_body=None)
        import hashlib
        with io.open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        with io.open(os.path.join(self.dir, "cve_snapshot.sha256"), "w",
                     encoding="utf-8", newline="\n") as fh:
            fh.write("# hand made by user\n%s *cve_snapshot.json\n" % digest)
        snap = cs.load_snapshot(path)
        self.assertIs(snap.checksum_verified, True)


# ── 排序（验收：KEV 优先、同组 EPSS 降序） ────────────────────────────────

class SortTest(_TmpDirTest):

    def _ordered(self, entries):
        path = _write(self.dir, "cve_snapshot.json", _doc(entries))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        return [e.cve_id for e in cs.sort_candidates(snap.entries)]

    def test_kev_first_then_epss_desc(self):
        """KEV 组在最前，组内按 EPSS 降序。"""
        order = self._ordered([
            _entry("CVE-2020-0001", kev=False, epss=0.9),     # 非 KEV 高 EPSS
            _entry("CVE-2020-0002", kev=True, epss=0.2),
            _entry("CVE-2020-0003", kev=True, epss=0.8),
            _entry("CVE-2020-0004", kev=False, epss=None),    # 无 EPSS
        ])
        self.assertEqual(order, ["CVE-2020-0003", "CVE-2020-0002",
                                 "CVE-2020-0001", "CVE-2020-0004"])

    def test_missing_epss_sorts_last_inside_group_not_as_zero(self):
        """🔴 `epss=None` 置后，**不是**当 0 —— 0 会排在有 0.01 的后面，
        而「没有分值」不是「分值为 0」。"""
        order = self._ordered([
            _entry("CVE-2020-0001", kev=False, epss=None),
            _entry("CVE-2020-0002", kev=False, epss=0.01),
        ])
        self.assertEqual(order, ["CVE-2020-0002", "CVE-2020-0001"])

    def test_order_is_reproducible(self):
        rows = [_entry("CVE-2020-000%d" % i, kev=(i % 2 == 0),
                       epss=(i % 5) / 10.0) for i in range(1, 8)]
        first = self._ordered(rows)
        second = self._ordered(list(reversed(rows)))
        self.assertEqual(first, second)

    def test_find_candidates_matches_coarse_cpe_only(self):
        """版本区间在快照里也不参与匹配：同一产品的不同版本收敛到同一 key。"""
        entries = [
            {"cve_id": "CVE-2021-44228",
             "cpe": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
             "kev": True},
            {"cve_id": "CVE-2021-45046",
             "cpe": ["cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*"],
             "kev": True, "epss": 0.4},
        ]
        path = _write(self.dir, "cve_snapshot.json", _doc(entries))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        hits = cs.find_candidates(snap, "cpe:2.3:a:apache:log4j:9.9.9:*:*:*:*:*:*:*")
        # 两条都是 KEV；45046 有 EPSS 0.4、44228 没有分值 → 有分的在前
        self.assertEqual([h.cve_id for h in hits],
                         ["CVE-2021-45046", "CVE-2021-44228"])

    def test_find_candidates_on_unusable_snapshot_returns_empty(self):
        snap = cs.CveSnapshot(state=cs.STATE_MISSING)
        self.assertEqual(cs.find_candidates(snap, "cpe:2.3:a:apache:log4j:*"), [])


# ── 搜索路径 / 诊断出口 ────────────────────────────────────────────────

class DataPathTest(_TmpDirTest):
    """`data_path()` 的选取顺序与「两个都没有」的空串出口。"""

    def _two_empty_dirs(self):
        a = os.path.join(self.dir, "a")
        b = os.path.join(self.dir, "b")
        os.makedirs(a)
        os.makedirs(b)
        return a, b

    def test_user_dir_wins_over_seed(self):
        expected = _write(self.dir, "cve_snapshot.json", _doc([_entry("CVE-1")]))
        _a, b = self._two_empty_dirs()          # b = 种子目录（空的）
        with mock.patch.object(cs, "data_dir", return_value=self.dir), \
                mock.patch.object(cs, "resource_dir", return_value=b):
            self.assertEqual(cs.data_path(), expected)

    def test_seed_used_when_user_dir_has_none(self):
        user, seed = self._two_empty_dirs()
        expected = _write(seed, "cve_snapshot.json", _doc([_entry("CVE-1")]))
        with mock.patch.object(cs, "data_dir", return_value=user), \
                mock.patch.object(cs, "resource_dir", return_value=seed):
            self.assertEqual(cs.data_path(), expected)

    def test_empty_string_when_neither_exists(self):
        a, b = self._two_empty_dirs()
        with mock.patch.object(cs, "data_dir", return_value=a), \
                mock.patch.object(cs, "resource_dir", return_value=b):
            self.assertEqual(cs.data_path(), "")


class StatsExportTest(_TmpDirTest):
    """`stats()` / `to_dict()` / `stats_for()`：诊断出口必须齐全且同源。"""

    def _two_empty_dirs(self):
        a = os.path.join(self.dir, "s_a")
        b = os.path.join(self.dir, "s_b")
        os.makedirs(a)
        os.makedirs(b)
        return a, b

    def test_to_dict_adds_sources_block(self):
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")]))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        payload = snap.to_dict()
        self.assertEqual(payload["sources"],
                         {"nvd": "2026-10-01", "kev": "2026-09-30"})
        self.assertEqual(payload["entry_count"], 1)

    def test_stats_for_is_an_alias_of_stats(self):
        path = _write(self.dir, "cve_snapshot.json",
                      _doc([_entry("CVE-2021-44228")]))
        snap = cs.load_snapshot(path, now=FIXED_NOW)
        self.assertEqual(cs.stats_for(snap), snap.stats())

    def test_missing_in_both_dirs_reports_missing_without_raising(self):
        """两个搜索路径都没有文件 → `missing`，且**不抛**。"""
        a, b = self._two_empty_dirs()
        with mock.patch.object(cs, "data_dir", return_value=a), \
                mock.patch.object(cs, "resource_dir", return_value=b):
            snap = cs.load_snapshot(now=FIXED_NOW)
        self.assertEqual(snap.state, cs.STATE_MISSING)
        self.assertEqual(snap.source, cs.SOURCE_NONE)
        self.assertFalse(snap.usable)


# ── CPE 收敛 / summary 清洗（纯函数） ────────────────────────────────────

class CoarsenTest(unittest.TestCase):

    def test_full_23_form_is_coarsened(self):
        self.assertEqual(
            cs.coarsen_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
            "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")

    def test_legacy_22_uri_form_is_coarsened(self):
        self.assertEqual(
            cs.coarsen_cpe("cpe:/a:apache:log4j:2.14.1"),
            "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")

    def test_os_part_is_preserved(self):
        """o / h 段必须保留：把 Cisco IOS 降级成 a: 会让网络设备 CVE 永远匹配不上。"""
        self.assertEqual(
            cs.coarsen_cpe("cpe:2.3:o:cisco:ios:15.2:*:*:*:*:*:*:*"),
            "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*")

    def test_garbage_returns_none(self):
        for bad in ("", None, "not-a-cpe", "cpe:2.3:a:apache", 42,
                    "cpe:2.3:x:apache:log4j:*", "cpe:2.3:a::log4j:*"):
            self.assertIsNone(cs.coarsen_cpe(bad), bad)


class SummarySanitizeTest(unittest.TestCase):

    def test_html_tags_and_controls_are_stripped(self):
        raw = "<b>Log4Shell</b>\r\n<script>alert(1)</script>影响面\x00很大"
        cleaned = cs.sanitize_summary(raw)
        self.assertNotIn("<", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertIn("Log4Shell", cleaned)

    def test_long_summary_is_truncated(self):
        self.assertEqual(len(cs.sanitize_summary("x" * 500)),
                         cs.SUMMARY_MAX_CHARS)


class TimestampTest(unittest.TestCase):

    def test_iso_z_and_fractional_digits(self):
        got = cs.parse_timestamp("2022-10-27T04:37:47.1583133Z")
        self.assertEqual(got, dt.datetime(2022, 10, 27, 4, 37, 47, 158313,
                                          tzinfo=dt.timezone.utc))

    def test_naive_timestamp_is_read_as_utc(self):
        got = cs.parse_timestamp("2026-10-01T00:00:00")
        self.assertEqual(got, dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc))

    def test_garbage_returns_none(self):
        self.assertIsNone(cs.parse_timestamp("not-a-time"))
        self.assertIsNone(cs.parse_timestamp(None))
        self.assertIsNone(cs.parse_timestamp(""))


# ── 内置种子（§9.1） ─────────────────────────────────────────────────────

class SeedSnapshotTest(unittest.TestCase):

    SEED_PATH = os.path.join(ROOT, "cve_snapshot.json")

    def test_seed_file_exists(self):
        self.assertTrue(os.path.isfile(self.SEED_PATH),
                        "内置种子 cve_snapshot.json 必须随仓库分发")

    def test_seed_is_small_enough(self):
        """硬上限：≤ 32 KiB / ≤ 20 条 —— 不许长成 mini-NVD。"""
        size = os.path.getsize(self.SEED_PATH)
        with io.open(self.SEED_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertLessEqual(size, 32 * 1024, "种子快照超过 32 KiB")
        self.assertLessEqual(len(doc.get("cves", [])), 20,
                             "种子快照超过 20 条")

    def test_seed_always_looks_expired(self):
        """🔴 种子的 generated_at 固定为旧日期 → **永远显示过期**：
        让用户看到「该去更新了」，而不是误以为手里这份是最新的。"""
        snap = cs.load_snapshot(self.SEED_PATH, now=FIXED_NOW)
        self.assertGreater(snap.age_days, 365)
        self.assertIn(snap.state, (cs.STATE_STALE, cs.STATE_OK))
        self.assertNotEqual(snap.state, cs.STATE_OK)

    def test_seed_entries_are_all_kev_with_nullable_epss(self):
        with io.open(self.SEED_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
        rows = doc.get("cves", [])
        self.assertTrue(rows)
        for row in rows:
            self.assertIs(row.get("kev"), True, row.get("cve_id"))
            self.assertIn("epss", row)          # 允许 null，但键要在


# ── 零网络（§1 原则 1） ─────────────────────────────────────────────────

class NoNetworkTest(unittest.TestCase):

    #: 这些模块一旦被 import 就是把「数据不出网」这条铁律破了。
    FORBIDDEN = ("urllib", "requests", "socket", "http", "ssl", "ftplib",
                 "smtplib", "telnetlib", "asyncio", "xmlrpc", "webbrowser")

    def _imported_network_modules(self, source):
        tree = ast.parse(source)
        found = set()
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                root = (name or "").split(".")[0]
                if root in self.FORBIDDEN:
                    found.add(root)
        return found

    def test_sources_do_not_import_network_libraries(self):
        for rel in ("scanner/cve_snapshot.py", "scanner/exposure.py",
                    "tools/build_cve_snapshot.py"):
            with io.open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                found = self._imported_network_modules(fh.read())
            self.assertEqual(found, set(), "%s import 了网络库" % rel)

    def test_runtime_process_does_not_load_network_modules(self):
        """import 之后进程里**新增**的网络库必须是空的。

        不能直接查 `sys.modules` 全量 —— `scanner/__init__.py` 会连带 import
        十几个真发网卡的模块（ports / http / snmp…），它们在**本次改动之前**
        就依赖 socket / ssl。所以这里先整体暖场，再看「import 我的两个模块」
        有没有**新增**任何网络库 —— 那才是「数据不出网」的可判定口径。
        """
        code = (
            "import sys; import scanner;"
            "base = set(sys.modules);"
            "import scanner.cve_snapshot, scanner.exposure;"
            "new = set(sys.modules) - base;"
            "print(sorted(m for m in ('urllib','requests','socket','http','ssl',"
            "'ftplib','smtplib','telnetlib','asyncio') if m in new))"
        )
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]",
                         "import cve_snapshot/exposure 新增了网络库")
