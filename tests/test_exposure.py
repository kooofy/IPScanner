# -*- coding: utf-8 -*-
"""`scanner.exposure`（v2.1 §2.3）的单测。

验收锚点（`docs/ROADMAP_V2.1.md` §2.3）：
* **排序正确**：KEV 命中的排最前、同组内 EPSS 降序；
* **诚实降级**：断言模块自己的文案里**从不**出现「已验证 / 可利用 / 存在漏洞」；
* **无数据 ≠ 无漏洞**：`verdict` 三态可区分，快照坏时不是「查了没问题」；
* 粗粒度匹配：版本区间丢弃、OS 段的 part 保留、别名带词边界。
"""
import ast
import datetime as dt
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import cve_snapshot as cs
from scanner import exposure
from scanner.models import ScanResult

FIXED_NOW = dt.datetime(2026, 10, 13, tzinfo=dt.timezone.utc)
LOG4J = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
TOMCAT = "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"


def _write(directory, doc):
    path = os.path.join(directory, "cve_snapshot.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False, indent=1))
    return path


def _snapshot(directory, cves=None):
    doc = {
        "schema": cs.SCHEMA,
        "generated_at": "2026-10-01T00:00:00Z",
        "max_age_days": 30,
        "cves": cves if cves is not None else [
            {"cve_id": "CVE-2021-44228", "cpe": [LOG4J], "kev": True,
             "epss": 0.97, "summary": "Log4Shell"},
            {"cve_id": "CVE-2020-1938", "cpe": [TOMCAT], "kev": True,
             "epss": None, "summary": "Ghostcat"},
        ],
    }
    return cs.load_snapshot(_write(directory, doc), now=FIXED_NOW)


def _result(ip="10.0.0.5", banners=(), sys_descr=""):
    r = ScanResult(ip=ip, mac="aa:bb:cc:dd:ee:ff")
    r.service_details = [{"proto": "HTTP", "port": 80, "banner": b}
                         for b in banners]
    r.snmp_sys_descr = sys_descr
    return r


class _TmpDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()


# ── 产品识别 ────────────────────────────────────────────────────────────

class ProductExtractionTest(unittest.TestCase):

    def test_banner_product_and_version_are_split(self):
        hits = exposure.products_from_result(
            _result(banners=["Apache httpd 2.4.41", "OpenSSH 8.4"]))
        by_product = {h.product: h for h in hits}
        self.assertEqual(by_product["Apache httpd"].version, "2.4.41")
        self.assertEqual(by_product["OpenSSH"].version, "8.4")
        self.assertEqual(by_product["Apache httpd"].cpe,
                         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        self.assertEqual(by_product["Apache httpd"].evidence,
                         exposure.EVIDENCE_BANNER)
        # 证据原文要留着：启发式结论必须能回看
        self.assertEqual(by_product["Apache httpd"].source_text,
                         "Apache httpd 2.4.41")

    def test_unknown_product_is_silently_skipped(self):
        hits = exposure.products_from_result(
            _result(banners=["SomeVendor Thing 1.0"]))
        self.assertEqual(hits, [])

    def test_alias_requires_word_boundary(self):
        """🔴 "radios" 里含 "ios" 但不是 Cisco IOS —— 裸子串会稳定误报。"""
        hits = exposure.products_from_result(
            _result(sys_descr="Acme Switch with two radios, Version 1.0"))
        self.assertEqual(hits, [])

    def test_longer_alias_wins(self):
        """"Cisco IOS XE" 必须先命中 ios_xe，不能被 "ios" 抢走。"""
        hits = exposure.products_from_result(
            _result(sys_descr="Cisco IOS XE Software, Version 17.3.4"))
        self.assertEqual(hits[0].cpe,
                         "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*")
        self.assertEqual(hits[0].evidence, exposure.EVIDENCE_SNMP)
        self.assertEqual(hits[0].version, "17.3.4")

    def test_os_part_is_preserved(self):
        """网络设备的 CVE 在 o: 段 —— 降级成 a: 就永远匹配不上。"""
        hits = exposure.products_from_result(
            _result(sys_descr="Cisco IOS Software, C2960, Version 12.2(55)SE"))
        self.assertTrue(hits[0].cpe.startswith("cpe:2.3:o:"))

    def test_same_cpe_is_deduped_across_evidence(self):
        hits = exposure.products_from_result(
            _result(banners=["OpenSSH 8.4"],
                    sys_descr="OpenSSH 8.4 on Linux"))
        self.assertEqual(len(hits), 1)


# ── 匹配与排序 ──────────────────────────────────────────────────────────

class MatchingTest(_TmpDirTest):

    def test_kev_hits_sort_before_epss(self):
        snap = _snapshot(self.dir)
        report = exposure.match_results([_result(banners=["Apache Tomcat 9.0.54"])], snap)
        self.assertEqual(report.verdict, exposure.VERDICT_MATCHED)
        hit = report.hits[0]
        self.assertEqual(hit.product, "Apache Tomcat")
        self.assertEqual([c.cve_id for c in hit.candidates], ["CVE-2020-1938"])

    def test_epss_desc_within_group(self):
        cves = [
            {"cve_id": "CVE-2021-0001", "cpe": [LOG4J], "kev": True, "epss": 0.3},
            {"cve_id": "CVE-2021-0002", "cpe": [LOG4J], "kev": True, "epss": 0.9},
            {"cve_id": "CVE-2021-0003", "cpe": [LOG4J], "kev": False, "epss": 0.99},
            {"cve_id": "CVE-2021-0004", "cpe": [LOG4J], "kev": False, "epss": None},
        ]
        snap = _snapshot(self.dir, cves)
        report = exposure.match_results(
            [_result(banners=["Apache Log4j 2.14.1"])], snap)
        self.assertEqual([c.cve_id for c in report.hits[0].candidates],
                         ["CVE-2021-0002", "CVE-2021-0001", "CVE-2021-0003",
                          "CVE-2021-0004"])

    def test_hits_are_ordered_by_worst_candidate(self):
        """多产品命中时，最该看的排在最前。"""
        cves = [
            {"cve_id": "CVE-2021-44228", "cpe": [LOG4J], "kev": True, "epss": 0.9},
            {"cve_id": "CVE-2020-1938", "cpe": [TOMCAT], "kev": False, "epss": 0.1},
        ]
        snap = _snapshot(self.dir, cves)
        report = exposure.match_results(
            [_result(banners=["Apache Tomcat 9.0.54", "Apache Log4j 2.14.1"])],
            snap)
        self.assertEqual(report.hits[0].top.cve_id, "CVE-2021-44228")

    def test_no_match_returns_none_verdict(self):
        snap = _snapshot(self.dir)
        report = exposure.match_results(
            [_result(banners=["nginx 1.18.0"], ip="10.0.0.9")], snap)
        self.assertEqual(report.verdict, exposure.VERDICT_NONE)
        self.assertEqual(report.hits, ())
        self.assertEqual(report.matched_hosts, ())

    def test_unusable_snapshot_is_no_data_not_none(self):
        """🔴 快照坏 ≠ 查了没问题：空 hits 必须来自 verdict=no-data。"""
        broken = cs.CveSnapshot(state=cs.STATE_MISSING, source=cs.SOURCE_NONE)
        report = exposure.match_results([_result(banners=["nginx 1.18.0"])], broken)
        self.assertEqual(report.verdict, exposure.VERDICT_NO_DATA)
        self.assertEqual(report.hits, ())

    def test_stale_snapshot_still_matches_but_reports_state(self):
        stale = cs.CveSnapshot(state=cs.STATE_STALE, source=cs.SOURCE_SEED,
                               age_days=1768, entries=[
                                   cs.CveEntry("CVE-2021-44228", (LOG4J,),
                                               kev=True)])
        report = exposure.match_results([_result(banners=["Apache Log4j 2.14.1"])],
                                        stale)
        self.assertEqual(report.verdict, exposure.VERDICT_MATCHED)
        self.assertEqual(report.snapshot_state, cs.STATE_STALE)
        self.assertEqual(report.age_days, 1768)

    def test_builtin_seed_actually_matches_log4j(self):
        """端到端：用仓库里的内置种子匹配一个 Log4j banner。"""
        snap = cs.load_snapshot(os.path.join(ROOT, "cve_snapshot.json"),
                               now=FIXED_NOW)
        report = exposure.match_results(
            [_result(banners=["Apache Log4j 2.14.1"], ip="10.0.0.7")], snap)
        self.assertEqual(report.verdict, exposure.VERDICT_MATCHED)
        self.assertEqual(report.matched_hosts, ("10.0.0.7",))
        self.assertIs(report.hits[0].top.kev, True)

    def test_unknown_age_snapshot_matches_and_is_not_reported_none(self):
        """🔴 回归：新鲜度未知（没有 generated_at）但有条目的快照，
        结论必须是 `matched`/`none` 之一，**不能**是 `none` 冒充"查过没有"。

        曾经的坑：`usable` 不放行 unknown-age → `match_results()` 提前返回
        空 hits，而 `verdict` 又不把 unknown-age 归到 no-data，用户读到的是
        「查了、没有匹配」——与事实相反。
        """
        unknown = cs.CveSnapshot(state=cs.STATE_UNKNOWN_AGE,
                                 source=cs.SOURCE_SEED, age_days=None,
                                 entries=[cs.CveEntry("CVE-2021-44228",
                                                      (LOG4J,), kev=True)])
        report = exposure.match_results(
            [_result(banners=["Apache Log4j 2.14.1"])], unknown)
        self.assertEqual(report.verdict, exposure.VERDICT_MATCHED)
        self.assertEqual(report.snapshot_state, cs.STATE_UNKNOWN_AGE)
        self.assertIsNone(report.age_days)


# ── 输出结构 / 措辞 ─────────────────────────────────────────────────────

class ReportShapeTest(_TmpDirTest):

    def test_to_dict_keys_are_language_independent(self):
        snap = _snapshot(self.dir)
        payload = exposure.match_results(
            [_result(banners=["Apache Log4j 2.14.1"])], snap).to_dict()
        for key in ("verdict", "snapshot", "matched_hosts", "hits"):
            self.assertIn(key, payload)
        for key in ("state", "source", "age_days", "entry_count"):
            self.assertIn(key, payload["snapshot"])
        hit = payload["hits"][0]
        for key in ("ip", "mac", "product", "version", "cpe", "evidence",
                    "source_text", "candidates"):
            self.assertIn(key, hit)
        for key in ("cve_id", "cpe", "kev", "epss", "epss_percentile",
                    "summary"):
            self.assertIn(key, hit["candidates"][0])

    def test_verdict_constants_are_ascii_canonical(self):
        for value in (exposure.VERDICT_MATCHED, exposure.VERDICT_NONE,
                      exposure.VERDICT_NO_DATA):
            self.assertRegex(value, r"^[a-z-]+$")

    def test_runtime_strings_never_claim_verification(self):
        """诚实降级（措辞硬约束）：模块自己的字符串里不允许出现
        「已验证 / 可利用 / 存在漏洞」这类把启发式升级成事实的措辞。

        只查**非 docstring** 的字符串常量 —— docstring 里出现这些词是在
        *解释* 为什么不许这么写。

        `cli.py` 一并纳入：CLI 的暴露面段与 `cve` 子命令是同一个结论的
        另一张嘴，它把「候选」说成「事实」同样是误导（§2.3 验收项）。
        """
        forbidden = ("已验证", "可利用", "存在漏洞", "已确认", "正在被利用",
                     "已验证过", "确认存在")
        for rel in ("scanner/exposure.py", "scanner/cve_snapshot.py",
                    "cli.py"):
            path = os.path.join(ROOT, rel)
            with io.open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            docs = set()
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if not isinstance(body, list) or not body:
                    continue
                first = body[0]
                if (isinstance(first, ast.Expr)
                        and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    docs.add(id(first.value))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docs:
                        continue
                    for word in forbidden:
                        self.assertNotIn(word, node.value,
                                         "%s 的字符串 %r 出现禁止措辞 %s"
                                         % (rel, node.value[:40], word))


if __name__ == "__main__":
    unittest.main()
