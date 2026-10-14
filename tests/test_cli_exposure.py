# -*- coding: utf-8 -*-
"""CLI 的 CVE 快照 / 暴露面接线测试（v2.1 §2.3）。

覆盖点（`docs/ROADMAP_V2.1.md` §2.3 第 3 条 + 可测验收）：
1. `cve --status`：文本/JSON 两种形态，快照状态与条目数如实呈现；
2. 快照不可用 → **退出码非 0** 且文案说「无数据可查」
   （与「查了、没有匹配」区分 —— 无数据 ≠ 无漏洞）；
3. `cve --product`：与扫描同一识别口径（`exposure.cpe_for_product()`），
   认不出来 / 没匹配 / 有匹配三条分支各自的退出码与文案；
4. `scan --exposure`：文本段与 JSON 字段都跟随**当前筛选**（不另读全量）；
5. `--format csv` 下**明确拒绝**输出暴露面段（不静默丢弃）。
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli
import i18n
from scanner import cve_snapshot as cs
from scanner.models import ScanResult

LOG4J = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
TOMCAT = "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"


def _run_main(argv):
    """运行 cli.main，返回 (exit_code, stdout, stderr)；退出后还原语言。

    与 tests/test_cli.py 同一套理由：`cli.main()` 会 `i18n.init(None)`
    重载语言包，不还原会污染进程内语言状态。
    """
    out, err = io.StringIO(), io.StringIO()
    lang = i18n.current_lang()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
    finally:
        i18n.init(lang)
    return code, out.getvalue(), err.getvalue()


class _TmpDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _snapshot(self, cves=None, generated_at="2026-10-01T00:00:00Z",
                  max_age_days=30):
        doc = {
            "schema": cs.SCHEMA,
            "generated_at": generated_at,
            "max_age_days": max_age_days,
            "cves": cves if cves is not None else [
                {"cve_id": "CVE-2021-44228", "cpe": [LOG4J], "kev": True,
                 "epss": 0.97, "summary": "Log4Shell"},
                {"cve_id": "CVE-2020-1938", "cpe": [TOMCAT], "kev": False,
                 "epss": None, "summary": "Ghostcat"},
            ],
        }
        path = os.path.join(self.dir, "cve_snapshot.json")
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(doc, ensure_ascii=False))
        return cs.load_snapshot(path, now=cs.parse_timestamp("2026-10-13T00:00:00Z"))


def _scan_results():
    """两台在线设备：一台带 Log4j banner，一台什么都认不出来。"""
    a = ScanResult(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01")
    a.service_details = [{"proto": "HTTP", "port": 80,
                          "banner": "Apache Log4j 2.14.1"}]
    b = ScanResult(ip="192.168.1.30", mac="aa:bb:cc:dd:ee:03")
    return [a, b]


class CveStatusTest(_TmpDirTest):
    """`cve --status`：如实呈现快照健康状况。"""

    def test_text_reports_state_and_counts(self):
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(["cve", "--status"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("快照可用且新鲜", out)
        self.assertIn("条目：2 条", out)
        self.assertIn("KEV 1 条", out)
        self.assertIn("有 EPSS 分值 1 条", out)
        # 新鲜快照不该出现"下一步：更新…"
        self.assertNotIn("下一步", out)

    def test_json_keys_are_language_independent(self):
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(["cve", "--status", "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        payload = json.loads(out)
        for key in ("state", "source", "schema", "entry_count", "kev_count",
                    "epss_scored_count", "checksum_verified",
                    "skipped_records", "max_age_days", "age_days"):
            self.assertIn(key, payload)
        self.assertEqual(payload["schema"], cs.SCHEMA)
        self.assertEqual(payload["entry_count"], 2)

    def test_stale_snapshot_still_succeeds_and_warns(self):
        """过期 = 能查、只是旧：退出码仍为 0，但必须说清且给下一步。"""
        snap = self._snapshot(generated_at="2021-12-10T00:00:00Z")
        self.assertEqual(snap.state, cs.STATE_STALE)
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(["cve", "--status"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("已过期", out)
        self.assertIn("下一步", out)

    def test_missing_snapshot_fails_and_says_no_data(self):
        """🔴 无数据 ≠ 无漏洞：没有快照时**不能**说成"没有匹配"。"""
        snap = cs.CveSnapshot(state=cs.STATE_MISSING, source=cs.SOURCE_NONE)
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(["cve", "--status"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("没有 CVE 快照", out)
        self.assertNotIn("没有匹配", out)

    def test_corrupt_snapshot_fails(self):
        snap = cs.CveSnapshot(state=cs.STATE_CORRUPT, source=cs.SOURCE_DATA)
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(["cve", "--status"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("读不出来", out)

    def test_builtin_seed_file_loads(self):
        """仓库根的内置种子必须真的能加载（打包进资源目录的那份）。"""
        seed = os.path.join(ROOT, "cve_snapshot.json")
        if not os.path.exists(seed):
            self.skipTest("仓库里没有内置种子")
        snap = cs.load_snapshot(seed)
        self.assertEqual(snap.schema, cs.SCHEMA)
        self.assertTrue(snap.entries)
        # 种子的 generated_at 是写死的旧日期 → 永远是过期态（设计如此）
        self.assertEqual(snap.state, cs.STATE_STALE)


class CveProductTest(_TmpDirTest):
    """`cve --product`：手工查询与扫描同一条识别口径。"""

    def test_matched_product_lists_candidates(self):
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(
                ["cve", "--product", "Apache Log4j 2.14.1", "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        payload = json.loads(out)
        self.assertTrue(payload["matched"])
        self.assertEqual(payload["version"], "2.14.1")
        self.assertEqual(payload["cpe"], LOG4J)
        ids = [c["cve_id"] for c in payload["candidates"]]
        # KEV 的那条排最前；非 KEV 的 Ghostcat 不在这个 CPE 下
        self.assertEqual(ids, ["CVE-2021-44228"])
        self.assertTrue(payload["candidates"][0]["kev"])

    def test_no_candidates_is_not_a_vulnerability_claim(self):
        """查了没有匹配 → 退出码 0，且文案必须写"不等于没有漏洞"。"""
        snap = self._snapshot(cves=[
            {"cve_id": "CVE-2020-1938", "cpe": [TOMCAT], "kev": False,
             "summary": "Ghostcat"},
        ])
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = _run_main(
                ["cve", "--product", "Apache httpd 2.4.41"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("没有匹配到", out)
        self.assertIn("不等于没有漏洞", out)

    def test_unrecognized_product_says_so(self):
        """认不出来就说认不出来 —— 绝不猜一个 CPE 给用户一个空列表。"""
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, _out, err = _run_main(
                ["cve", "--product", "Acme Widget 9.9"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("认不出", err)

    def test_missing_snapshot_blocks_lookup(self):
        snap = cs.CveSnapshot(state=cs.STATE_MISSING, source=cs.SOURCE_NONE)
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, _out, err = _run_main(
                ["cve", "--product", "Apache Log4j 2.14.1"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("没有可用的 CVE 数据", err)
        self.assertIn("下一步", err)


class ScanExposureTest(_TmpDirTest):
    """`scan --exposure`：附加段跟随当前筛选，csv 明确不输出。"""

    def _scan(self, extra_argv, results=None):
        argv = ["scan", "-r", "192.168.1.0/24"] + extra_argv
        with mock.patch.object(cli, "_run_scan",
                               return_value=(results or _scan_results(), None)):
            return _run_main(argv)

    def test_table_appends_section(self):
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = self._scan(["--exposure"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("暴露面", out)
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("192.168.1.10", out)
        # 认不出产品的那台不该出现在暴露面段里
        self.assertNotIn("192.168.1.30", out.split("暴露面", 1)[1])

    def test_json_payload_shape(self):
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = self._scan(["--exposure", "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        payload = json.loads(out)
        self.assertIn("exposure", payload)
        exp = payload["exposure"]
        self.assertEqual(exp["verdict"], "matched")
        self.assertEqual(exp["matched_hosts"], ["192.168.1.10"])
        self.assertEqual(exp["snapshot"]["state"], "ok")
        self.assertEqual(exp["hits"][0]["product"], "log4j")
        self.assertEqual(exp["hits"][0]["evidence"], "banner")

    def test_no_exposure_flag_means_no_section(self):
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = self._scan(["--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("exposure", json.loads(out))

    def test_csv_refuses_loudly(self):
        """CSV 是给程序读的：不静默丢弃，也不污染结构。"""
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, err = self._scan(["--exposure", "--format", "csv"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("暴露面", out)
        self.assertIn("--exposure", err)
        # CSV 仍然可解析（带 BOM 的表头行）
        rows = list(io.StringIO(out))
        self.assertTrue(rows[0].startswith("\ufeffip,"))

    def test_offline_devices_are_not_matched(self):
        """离线设备没有 banner/sysDescr，暴露面段里不该出现它。"""
        only_offline = [ScanResult(ip="192.168.1.99", mac="aa:bb:cc:dd:ee:99",
                                   status="offline")]
        snap = self._snapshot()
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = self._scan(
                ["--exposure", "--format", "json"], results=only_offline)
        self.assertEqual(code, cli.EXIT_OK)
        exp = json.loads(out)["exposure"]
        self.assertEqual(exp["verdict"], "none")
        self.assertEqual(exp["matched_hosts"], [])

    def test_no_data_verdict_when_snapshot_missing(self):
        snap = cs.CveSnapshot(state=cs.STATE_MISSING, source=cs.SOURCE_NONE)
        with mock.patch.object(cs, "load_snapshot", return_value=snap):
            code, out, _err = self._scan(["--exposure", "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        exp = json.loads(out)["exposure"]
        self.assertEqual(exp["verdict"], "no-data")
        self.assertEqual(exp["hits"], [])


class ParserWiringTest(unittest.TestCase):
    """参数面：`--exposure` / `cve` 子命令真的接上了。"""

    def test_scan_has_exposure_flag(self):
        p = cli.build_parser()
        args = p.parse_args(["scan", "-r", "10.0.0.0/24", "--exposure"])
        self.assertTrue(args.exposure)
        self.assertFalse(p.parse_args(
            ["scan", "-r", "10.0.0.0/24"]).exposure)

    def test_cve_subcommand_defaults_to_status(self):
        p = cli.build_parser()
        args = p.parse_args(["cve"])
        self.assertEqual(args.func, cli.cmd_cve)
        self.assertFalse(args.status)      # 不显式给也是同一个动作
        self.assertEqual(args.format, "table")

    def test_cve_update_flag_defaults_off(self):
        """v2.2 §3.1：`--update` 默认关 —— 不给它就绝不联网。"""
        p = cli.build_parser()
        self.assertFalse(p.parse_args(["cve"]).update)
        self.assertFalse(p.parse_args(["cve", "--status"]).update)
        self.assertFalse(p.parse_args(["cve", "--product", "x"]).update)
        self.assertTrue(p.parse_args(["cve", "--update"]).update)


class CveUpdateCommandTest(unittest.TestCase):
    """`cve --update`（v2.2 §3.1）：联网**只此一枝**，且失败不升级退出码语义。

    🔴 全程 mock 掉 `update_snapshot`：CLI 测试绝不能真发包。
    """

    def test_update_uses_placeholder_url_by_default(self):
        """默认地址是占位符 → no-url，退出非 0，且**不**发请求。

        （`update_snapshot` 自己会因为占位符短路 —— 这里 mock 掉它，
        只验证 CLI 把它当失败处理、退出码正确。）
        """
        fake = {"ok": False, "reason": "no-url", "path": "",
                "entry_count": 0, "checksum_verified": False, "bytes": 0}
        with mock.patch("cve_updater.update_snapshot", return_value=fake) as m:
            code, out, _err = _run_main(["cve", "--update"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("尚未配置下载地址", out)
        m.assert_called_once()             # 只有这一处会调，且是显式 --update

    def test_update_success_exits_zero(self):
        fake = {"ok": True, "reason": "ok", "path": "C:/tmp/cve_snapshot.json",
                "entry_count": 42, "checksum_verified": True, "bytes": 12345}
        with mock.patch("cve_updater.update_snapshot", return_value=fake):
            code, out, _err = _run_main(["cve", "--update", "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["entry_count"], 42)

    def test_update_failure_reports_but_is_not_environment_error(self):
        """失败必须是 EXIT_ERROR(1)，**不是** EXIT_ENV(3) 或 CHANGES(2)。"""
        fake = {"ok": False, "reason": "download-failed", "path": "",
                "entry_count": 0, "checksum_verified": False, "bytes": 0}
        with mock.patch("cve_updater.update_snapshot", return_value=fake):
            code, _out, err = _run_main(["cve", "--update"])
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_update_url_override_forwarded(self):
        fake = {"ok": True, "reason": "ok", "path": "x", "entry_count": 1,
                "checksum_verified": True, "bytes": 1}
        with mock.patch("cve_updater.update_snapshot",
                        return_value=fake) as m:
            _run_main(["cve", "--update",
                       "--url", "https://mirror.invalid/x.json"])
        self.assertEqual(m.call_args.args[0], "https://mirror.invalid/x.json")

    def test_no_checksum_flag_forwarded(self):
        fake = {"ok": True, "reason": "ok", "path": "x", "entry_count": 1,
                "checksum_verified": False, "bytes": 1}
        with mock.patch("cve_updater.update_snapshot",
                        return_value=fake) as m:
            _run_main(["cve", "--update", "--no-checksum"])
        self.assertFalse(m.call_args.kwargs.get("require_checksum", True))

    def test_status_does_not_touch_network_module(self):
        """🔴 `cve --status` **绝不能**碰 `cve_updater` —— 这条是身份边界。"""
        with mock.patch("cve_updater.update_snapshot") as m:
            _run_main(["cve", "--status"])
        m.assert_not_called()


if __name__ == "__main__":
    unittest.main()
