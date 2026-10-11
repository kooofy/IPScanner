# -*- coding: utf-8 -*-
"""IPScanner CLI 测试（P0-5）。

覆盖点：
1. 输出渲染（table / csv / json）与 CJK 宽度对齐；
2. JSON 字段名稳定为英文（不受界面语言影响，自动化可依赖）；
3. 参数校验（非法端口 / 非法范围 / 超大规模范围快速失败且不 OOM）；
4. history / diff 子命令与退出码语义（尤其 --fail-on-change → 2）；
5. CLI 不引入 PyQt 依赖（无头可运行）。
注意：除"规模校验"外，本测试**不发起真实网络扫描**，全部走本地 SQLite 与纯函数。
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli
import history_store
import i18n
from scanner.models import ScanResult


def _run_main(argv):
    """运行 cli.main，返回 (exit_code, stdout, stderr)。

    cli.main() 内部会调用 ``i18n.init(None)``，按**系统语言**重新加载语言包。
    在本进程里直接调用它会污染全局语言状态，使后续测试的断言随开发机 / CI 的
    系统语言漂移 —— 英文 runner 上 test_compare 曾因此挂掉 5 个。
    这里显式还原（与其他测试文件 test_i18n_lazy / test_snmp_v3 … 的做法一致）。
    """
    out, err = io.StringIO(), io.StringIO()
    lang = i18n.current_lang()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
    finally:
        i18n.init(lang)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def _lang(code):
    """临时把界面语言切成 ``code``，退出时还原。

    给「断言渲染后文案」的测试用：CLI 的语言由 ``--lang`` / 系统语言决定，
    与调用前的环境语言**可能不同**，所以期望值必须在**同一个**语言下算出来。
    配合在命令行里显式写死 ``--lang``，断言就与 runner 的系统语言无关。
    """
    prev = i18n.current_lang()
    i18n.init(code)
    try:
        yield
    finally:
        i18n.init(prev)


class RenderTest(unittest.TestCase):

    def test_table_basic(self):
        rows = [{"a": "1", "b": "x"}, {"a": "2", "b": "y"}]
        text = cli.render_table(rows, ("a", "b"))
        lines = text.splitlines()
        self.assertEqual(len(lines), 4)          # 表头 + 分隔线 + 2 行
        self.assertIn("a", lines[0])
        self.assertIn("1", lines[2])

    def test_table_empty(self):
        self.assertEqual(cli.render_table([], ("a",)), "(empty)")

    def test_table_list_cell_joined(self):
        rows = [{"ports": [80, 443]}]
        self.assertIn("80, 443", cli.render_table(rows, ("ports",)))

    def test_table_cjk_alignment(self):
        """含中文的单元格不能把表格挤歪（按显示宽度补空格）。"""
        rows = [{"n": "设备"}, {"n": "ab"}]
        text = cli.render_table(rows, ("n",))
        lines = text.splitlines()
        # 两行数据的显示宽度应一致
        self.assertEqual(cli._disp_width(lines[1]), cli._disp_width(lines[2]))

    def test_truncate_marks_ellipsis(self):
        self.assertTrue(cli._truncate("a" * 100, 10).endswith("…"))

    def test_csv_has_bom_and_header(self):
        text = cli.render_csv([{"a": "1", "b": "2"}], ("a", "b"))
        self.assertTrue(text.startswith("\ufeff"))
        self.assertIn("a,b", text)
        self.assertIn("1,2", text)

    def test_csv_joins_list_cells(self):
        text = cli.render_csv([{"ports": [80, 443]}], ("ports",))
        self.assertIn("80;443", text)

    def test_json_unicode_not_escaped(self):
        text = cli.render_json({"name": "打印机"})
        self.assertIn("打印机", text)


class RecordFieldTest(unittest.TestCase):
    """JSON/CSV 字段名必须是稳定英文键，供自动化消费。"""

    def test_keys_are_english_and_complete(self):
        r = ScanResult(ip="192.168.1.1", status="online", mac="AA:BB:CC:00:00:01")
        rec = cli.result_to_record(r)
        for key in ("ip", "status", "hostname", "mac", "vendor",
                    "response_time_ms", "open_ports", "services",
                    "device_class", "device_model", "os", "location",
                    "user", "remark", "discovery_method", "scan_method",
                    "shares", "matched"):
            self.assertIn(key, rec)
        # 不允许出现中文字段名
        for key in rec:
            self.assertTrue(key.isascii(), msg=f"字段名不是 ASCII: {key!r}")

    def test_status_not_localized(self):
        """状态必须是 online/offline，不能是"在线/离线"。"""
        r = ScanResult(ip="1.1.1.1", status="online")
        self.assertEqual(cli.result_to_record(r)["status"], "online")

    def test_open_ports_is_list(self):
        r = ScanResult(ip="1.1.1.1", open_ports=[22, 80])
        self.assertEqual(cli.result_to_record(r)["open_ports"], [22, 80])

    def test_result_columns_match_record_keys(self):
        r = ScanResult(ip="1.1.1.1")
        self.assertEqual(set(cli._RESULT_COLUMNS), set(cli.result_to_record(r)))


class SortKeyTest(unittest.TestCase):

    def test_natural_ip_order(self):
        ips = ["192.168.1.10", "192.168.1.9", "192.168.1.100", "10.0.0.1"]
        got = sorted(ips, key=cli._ip_sort_key)
        self.assertEqual(got, ["10.0.0.1", "192.168.1.9",
                               "192.168.1.10", "192.168.1.100"])

    def test_non_ip_sorts_last(self):
        self.assertLess(cli._ip_sort_key("1.1.1.1"), cli._ip_sort_key("bad"))


class PortResolutionTest(unittest.TestCase):

    def _args(self, **kw):
        import argparse
        base = {"no_ports": False, "ports": None, "level": "quick"}
        base.update(kw)
        return argparse.Namespace(**base)

    def test_no_ports_returns_none(self):
        self.assertIsNone(cli._resolve_ports(self._args(no_ports=True)))

    def test_custom_ports_parsed_and_deduped(self):
        got = cli._resolve_ports(self._args(ports="80,443,80"))
        self.assertEqual(got, [80, 443])

    def test_level_quick(self):
        from scanner.constants import COMMON_PORTS
        self.assertEqual(cli._resolve_ports(self._args(level="quick")),
                         list(COMMON_PORTS))

    def test_level_standard(self):
        self.assertEqual(len(cli._resolve_ports(self._args(level="standard"))),
                         1023)

    def test_rejects_non_numeric(self):
        with self.assertRaises(ValueError):
            cli._resolve_ports(self._args(ports="80,abc"))

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            cli._resolve_ports(self._args(ports="0"))
        with self.assertRaises(ValueError):
            cli._resolve_ports(self._args(ports="65536"))

    def test_rejects_empty_list(self):
        with self.assertRaises(ValueError):
            cli._resolve_ports(self._args(ports=",,,"))


class SnapshotDeviceTest(unittest.TestCase):
    """`_snapshot_devices()` —— CLI 侧的落库字典构造（v1.9 #3）。

    GUI 与 CLI 走的是**同一条**落库路径（`history_store.save_snapshot`），
    所以证书事实也必须在这里带上；否则"命令行存的快照没有安全事实"，
    而界面上又看不出差别 —— 这类不一致最难发现。
    """

    _CERT = {"cn": "router.local", "issuer_cn": "router.local",
             "not_before": "2025-01-01T00:00:00",
             "not_after": "2027-01-01T00:00:00",
             "self_signed": True, "sig_alg": "sha256_rsa",
             "key_alg": "rsa", "key_bits": 2048, "curve": ""}

    def test_certificate_facts_are_included(self):
        r = ScanResult(ip="10.0.0.9", status="online", open_ports=[443])
        r.tls_cert = dict(self._CERT)
        dev = cli._snapshot_devices([r])[0]
        self.assertEqual(dict(dev["security_findings"]), {
            "tls_cn": "router.local",
            "tls_not_before": "2025-01-01T00:00:00",
            "tls_not_after": "2027-01-01T00:00:00",
            "tls_sig_alg": "sha256_rsa",
            "tls_key": "rsa/2048",
            "tls_self_signed": "1",
        })

    def test_no_certificate_means_no_key(self):
        r = ScanResult(ip="10.0.0.10", status="online", open_ports=[80])
        dev = cli._snapshot_devices([r])[0]
        self.assertNotIn("security_findings", dev)

    def test_matches_the_gui_path(self):
        """与 `ui_logic.build_snapshot` 的产出必须一致 —— 两条路一份真相。"""
        import ui_logic
        r = ScanResult(ip="10.0.0.9", status="online", open_ports=[443])
        r.tls_cert = dict(self._CERT)
        cli_dev = cli._snapshot_devices([r])[0]
        gui_dev = ui_logic.build_snapshot([r], ts=0.0)["devices"][0]
        self.assertEqual(cli_dev["security_findings"], gui_dev["security_findings"])

    def test_roundtrips_through_the_database(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = os.path.join(tmp, "hist.db")
        self.addCleanup(lambda: __import__("db_util").close_connection(db))
        r = ScanResult(ip="10.0.0.9", status="online", open_ports=[443])
        r.tls_cert = dict(self._CERT)
        sid = history_store.save_snapshot(cli._snapshot_devices([r]),
                                          ts=1000.0, db_path=db)
        got = history_store.get_security_findings(sid, db_path=db)
        self.assertEqual(got["10.0.0.9"]["tls_cn"], "router.local")

    # ── 名字响应器（v1.9 #3 第二刀）──

    def test_responder_facts_are_included(self):
        r = ScanResult(ip="10.0.0.9", status="online")
        r.name_responder = {"llmnr": "ipscanner-a1b2c"}
        dev = cli._snapshot_devices([r])[0]
        self.assertEqual(dict(dev["security_findings"]),
                         {"llmnr_responder": "ipscanner-a1b2c"})

    def test_no_responder_means_no_key(self):
        r = ScanResult(ip="10.0.0.10", status="online")
        self.assertNotIn("security_findings", cli._snapshot_devices([r])[0])

    def test_responder_matches_the_gui_path(self):
        import ui_logic
        r = ScanResult(ip="10.0.0.9", status="online")
        r.tls_cert = dict(self._CERT)
        r.name_responder = {"nbns": "ipscanner-a1b2c"}
        cli_dev = cli._snapshot_devices([r])[0]
        gui_dev = ui_logic.build_snapshot([r], ts=0.0)["devices"][0]
        self.assertEqual(cli_dev["security_findings"], gui_dev["security_findings"])

    def test_responder_roundtrips_through_the_database(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = os.path.join(tmp, "hist.db")
        self.addCleanup(lambda: __import__("db_util").close_connection(db))
        r = ScanResult(ip="10.0.0.9", status="online")
        r.name_responder = {"llmnr": "ipscanner-a1b2c", "nbns": "ipscanner-a1b2c"}
        sid = history_store.save_snapshot(cli._snapshot_devices([r]),
                                          ts=1000.0, db_path=db)
        got = history_store.get_security_findings(sid, db_path=db)
        self.assertEqual(got["10.0.0.9"], {"llmnr_responder": "ipscanner-a1b2c",
                                           "nbns_responder": "ipscanner-a1b2c"})

    # ── SMB 方言 / 签名（v1.9 #3 第四刀）──

    def test_smb_facts_are_included(self):
        r = ScanResult(ip="10.0.0.9", status="online")
        r.smb = {"dialect": "3.1.1", "signing": "required", "smb1": "1"}
        dev = cli._snapshot_devices([r])[0]
        self.assertEqual(dict(dev["security_findings"]),
                         {"smb_dialect": "3.1.1",
                          "smb_signing": "required",
                          "smb1": "1"})

    def test_no_smb_means_no_key(self):
        r = ScanResult(ip="10.0.0.10", status="online")
        self.assertNotIn("security_findings", cli._snapshot_devices([r])[0])

    def test_smb_matches_the_gui_path(self):
        import ui_logic
        r = ScanResult(ip="10.0.0.9", status="online")
        r.tls_cert = dict(self._CERT)
        r.name_responder = {"nbns": "ipscanner-a1b2c"}
        r.smb = {"dialect": "2.1", "signing": "off"}
        cli_dev = cli._snapshot_devices([r])[0]
        gui_dev = ui_logic.build_snapshot([r], ts=0.0)["devices"][0]
        self.assertEqual(cli_dev["security_findings"], gui_dev["security_findings"])

    def test_smb_roundtrips_through_the_database(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = os.path.join(tmp, "hist.db")
        self.addCleanup(lambda: __import__("db_util").close_connection(db))
        r = ScanResult(ip="10.0.0.9", status="online")
        r.smb = {"dialect": "3.1.1", "signing": "enabled", "smb1": "1"}
        sid = history_store.save_snapshot(cli._snapshot_devices([r]),
                                          ts=1000.0, db_path=db)
        got = history_store.get_security_findings(sid, db_path=db)
        self.assertEqual(got["10.0.0.9"], {"smb_dialect": "3.1.1",
                                           "smb_signing": "enabled",
                                           "smb1": "1"})

    def test_smb_does_not_leak_into_the_result_columns(self):
        """⚠ `tests/test_cli.py` 有一条不变量：`result_to_record()` 的键集合
        必须**恰好**等于 `_RESULT_COLUMNS`。SMB 事实是落库用的，不该跑进
        表格列 —— 这条守住那个边界。
        """
        r = ScanResult(ip="10.0.0.9", status="online")
        r.smb = {"dialect": "3.1.1", "signing": "off", "smb1": "1"}
        self.assertEqual(set(cli._RESULT_COLUMNS), set(cli.result_to_record(r)))


class CollectRespondersTest(unittest.TestCase):
    """CLI 侧的 `_collect_responders()` —— 探测结果分发（v1.9 #3 第二刀）。

    这里只测**分发**：真发包的部分由 `tests/test_llmnr_nbns.py` 用回环假响应器
    覆盖。CLI 测试绝不往真实组播/广播地址发包。
    """

    def _run(self, found, ips=("10.0.0.1", "10.0.0.2")):
        """跑一遍 `_collect_responders`，返回 (results, stderr)。

        ⚠ `cli.log()` 写的是 **stderr**（stdout 只承载结果数据，便于管道），
        所以这里必须捕 stderr —— 捕 stdout 会得到一个空串。
        """
        from unittest import mock
        results = [ScanResult(ip=ip, status="online") for ip in ips]
        err = io.StringIO()
        with mock.patch("scanner.llmnr_nbns.probe_responders",
                        return_value=found):
            with contextlib.redirect_stderr(err):
                cli._collect_responders(None, results)
        return results, err.getvalue()

    def test_in_scope_responder_is_attached(self):
        results, _out = self._run({"10.0.0.1": {"llmnr": "ipscanner-a"}})
        self.assertEqual(results[0].name_responder, {"llmnr": "ipscanner-a"})
        self.assertEqual(results[1].name_responder, {})

    def test_findings_are_printed(self):
        """CLI 用户看不到界面，结论只能靠日志 —— 这条是它的唯一出口。"""
        _results, out = self._run({"10.0.0.1": {"llmnr": "ipscanner-a",
                                                "nbns": "ipscanner-a"}})
        self.assertIn("10.0.0.1", out)
        self.assertIn("LLMNR", out)
        self.assertIn("NBNS", out)

    def test_clean_network_says_so(self):
        """空结果也要说一句 —— 否则用户分不清"没发现"和"功能没生效"。"""
        _results, out = self._run({})
        self.assertTrue(out.strip(), "干净网络下什么都没输出")

    def test_out_of_scope_responder_is_reported_but_not_invented(self):
        results, out = self._run({"10.0.0.99": {"llmnr": "ipscanner-a"}})
        self.assertEqual(len(results), 2, "不能凭空多出一台设备")
        self.assertIn("10.0.0.99", out)
        self.assertTrue(all(not r.name_responder for r in results))

    def test_probe_failure_does_not_raise(self):
        from unittest import mock
        results = [ScanResult(ip="10.0.0.1", status="online")]
        with mock.patch("scanner.llmnr_nbns.probe_responders",
                        side_effect=RuntimeError("boom")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                cli._collect_responders(None, results)   # 不抛即通过
        self.assertIn("boom", err.getvalue())

    def test_flag_is_parsed(self):
        """`--name-responder` 必须真的存在 —— 打错字的话 argparse 会直接退出。"""
        parser_args = cli.build_parser().parse_args(
            ["scan", "-r", "10.0.0.0/30", "--name-responder"])
        self.assertTrue(parser_args.name_responder)

    def test_flag_defaults_to_off(self):
        """默认必须是关的：它会往网络里发组播/广播包。"""
        parser_args = cli.build_parser().parse_args(
            ["scan", "-r", "10.0.0.0/30"])
        self.assertFalse(parser_args.name_responder)


class SizeGuardTest(unittest.TestCase):
    """超大规模范围必须在联网之前被拒绝（P0-2 在 CLI 侧的表现）。"""

    def test_huge_range_rejected_fast(self):
        code, out, err = _run_main(["scan", "-r", "0.0.0.0/0", "--no-ports", "-q"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("超过单次上限", err)

    def test_cumulative_limit_rejected(self):
        code, _out, err = _run_main([
            "scan", "-r", "10.0.0.0/16", "-r", "10.1.0.0/16",
            "-r", "10.2.0.0/16", "--no-ports", "-q",
        ])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("合计", err)

    def test_invalid_range_rejected(self):
        code, _out, err = _run_main(["scan", "-r", "not-an-ip", "--no-ports", "-q"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("无法解析", err)

    def test_invalid_port_rejected(self):
        code, _out, err = _run_main([
            "scan", "-r", "127.0.0.1", "--ports", "80,abc", "-q",
        ])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("端口号非法", err)


class HistoryAndDiffTest(unittest.TestCase):
    """history / diff 走本地 SQLite，不发网络请求。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "hist.db")
        import history_store
        self.hs = history_store
        self.hs.save_snapshot([
            {"ip": "192.168.1.10", "status": "online",
             "mac": "AA:BB:CC:00:00:01", "hostname": "pc-a", "device_class": "电脑"},
            {"ip": "192.168.1.11", "status": "online",
             "mac": "AA:BB:CC:00:00:02", "hostname": "printer", "device_class": "打印机"},
        ], note="基线", db_path=self.db)

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def test_history_list(self):
        code, out, _err = _run_main(["history", "--list", "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("基线", out)

    def test_history_list_json(self):
        code, out, _err = _run_main(["history", "--list", "-f", "json",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn('"device_count"', out)

    def test_history_show_missing_snapshot(self):
        code, _out, err = _run_main(["history", "--show", "999", "--db", self.db])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("不存在", err)

    def test_history_query_by_ip(self):
        code, out, _err = _run_main(["history", "--query", "--ip", "192.168.1.1",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("192.168.1.10", out)
        self.assertIn("192.168.1.11", out)

    def test_history_query_by_device_class(self):
        code, out, _err = _run_main(["history", "--query", "--device-class", "打印机",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("printer", out)
        self.assertNotIn("pc-a", out)

    def test_history_query_no_match(self):
        code, out, _err = _run_main(["history", "--query", "--ip", "10.9.9.9",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("无匹配", out)

    def test_diff_identical_snapshots_no_change(self):
        code, out, _err = _run_main(["diff", "--from", "1", "--to", "1",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("无变更", out)

    def test_diff_detects_new_device_and_exit_code(self):
        self.hs.save_snapshot([
            {"ip": "192.168.1.10", "status": "online",
             "mac": "AA:BB:CC:00:00:01", "hostname": "pc-a"},
            {"ip": "192.168.1.99", "status": "online",
             "mac": "AA:BB:CC:00:00:99", "hostname": "new-box"},
        ], note="变更后", db_path=self.db)

        # 不带 --fail-on-change：正常返回 0，但应报告新增设备
        code, out, _err = _run_main(["diff", "--from", "1", "--to", "2",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("new_device", out)
        self.assertIn("192.168.1.99", out)

        # 带 --fail-on-change：返回 2，便于计划任务告警
        code2, _out2, _err2 = _run_main(["diff", "--from", "1", "--to", "2",
                                         "--fail-on-change", "--db", self.db])
        self.assertEqual(code2, cli.EXIT_CHANGES)

    def test_diff_json_output(self):
        self.hs.save_snapshot([
            {"ip": "192.168.1.99", "status": "online",
             "mac": "AA:BB:CC:00:00:99", "hostname": "new-box"},
        ], note="变更后", db_path=self.db)
        code, out, _err = _run_main(["diff", "--from", "1", "--to", "2",
                                     "-f", "json", "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn('"changes"', out)
        self.assertIn('"severity"', out)

    def test_diff_requires_range_or_snapshot_ids(self):
        code, _out, err = _run_main(["diff", "--db", self.db])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("--range", err)


class EmitTest(unittest.TestCase):
    """回归：写文件时尾部补换行必须在 with 块内完成。

    曾出现 `f.write("\\n")` 落在 with 之外，导致文件句柄已关闭 →
    ValueError("I/O operation on closed file")，命令返回退出码 1。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_write_file_without_trailing_newline(self):
        path = os.path.join(self.tmp, "out.json")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cli.emit('{"a": 1}', path)          # 故意不带结尾换行
        with io.open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content, '{"a": 1}\n')
        self.assertNotIn("错误", err.getvalue())

    def test_write_file_keeps_existing_newline(self):
        path = os.path.join(self.tmp, "out.txt")
        with contextlib.redirect_stderr(io.StringIO()):
            cli.emit("line\n", path)
        with io.open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), "line\n")

    def test_csv_written_with_bom(self):
        path = os.path.join(self.tmp, "out.csv")
        with contextlib.redirect_stderr(io.StringIO()):
            cli.emit(cli.render_csv([{"a": "1"}], ("a",)), path)
        with io.open(path, "rb") as f:
            self.assertTrue(f.read().startswith(b"\xef\xbb\xbf"))

    def test_json_file_has_no_bom(self):
        path = os.path.join(self.tmp, "out.json")
        with contextlib.redirect_stderr(io.StringIO()):
            cli.emit('{"a": 1}', path)
        with io.open(path, "rb") as f:
            self.assertFalse(f.read().startswith(b"\xef\xbb\xbf"))

    def test_stdout_when_no_output_path(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.emit("hello")
        self.assertEqual(out.getvalue(), "hello\n")


class ParserTest(unittest.TestCase):

    def test_scan_requires_range(self):
        p = cli.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                p.parse_args(["scan"])

    def test_command_required(self):
        p = cli.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                p.parse_args([])

    def test_lang_before_subcommand_survives(self):
        """--lang 放在子命令之前不应被子解析器的默认值覆盖。"""
        p = cli.build_parser()
        args = p.parse_args(["--lang", "en-US", "scan", "-r", "127.0.0.1"])
        self.assertEqual(args.lang, "en-US")

    def test_lang_after_subcommand(self):
        p = cli.build_parser()
        args = p.parse_args(["scan", "-r", "127.0.0.1", "--lang", "en-US"])
        self.assertEqual(args.lang, "en-US")

    def test_defaults(self):
        p = cli.build_parser()
        args = p.parse_args(["scan", "-r", "127.0.0.1"])
        self.assertEqual(args.level, "quick")
        self.assertEqual(args.tcp_mode, "connect")
        self.assertEqual(args.format, "table")
        self.assertEqual(args.timeout, 1000)
        self.assertFalse(args.no_mdns)


class NoGuiDependencyTest(unittest.TestCase):

    def test_cli_imports_without_pyqt(self):
        """在干净子进程中导入 cli，确认没有拉入任何 PyQt 模块。"""
        code = ("import sys; sys.path.insert(0, %r); import cli; "
                "bad=[m for m in sys.modules if m.startswith('PyQt')]; "
                "print('FAIL' if bad else 'OK')" % ROOT)
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.strip(), "OK")


class LegacyCodepageTest(unittest.TestCase):
    """CLI 必须在非 UTF-8 代码页下也能正常输出中文。

    背景：Windows 上 stdout 被重定向到管道/文件时，Python 用**系统 ANSI
    代码页**编码（英文系统是 cp1252），而 stdout 默认 ``errors='strict'`` ——
    只要输出里有中文就直接抛 ``UnicodeEncodeError`` 并以退出码 1 结束。
    CI 的 CLI 冒烟测试（`IPScanner_cli.exe scan ... --format json`）就是这么挂的：
    `--version` 是 ASCII 能过，`scan` 一写「设备」就崩。

    stderr 默认 ``backslashreplace`` 不崩，但中文会变成 ``\\u51c6...`` 转义垃圾，
    所以这里两个流都要断言。
    """

    def _run_cli(self, argv):
        """在 PYTHONIOENCODING=cp1252 的子进程里跑 CLI，返回 CompletedProcess(bytes)。"""
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "cp1252"
        return subprocess.run([sys.executable, "cli.py", *argv],
                              cwd=ROOT, env=env, capture_output=True)

    def test_stdout_chinese_survives_legacy_codepage(self):
        """空历史库必输出中文「没有历史快照」—— 断言它没把进程搞崩。

        这是**确定性**的中文 stdout 输出，不依赖网络与设备探测结果。
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "history.db")
            proc = self._run_cli(["history", "--list", "--db", db])
        self.assertEqual(proc.returncode, 0,
                         msg=proc.stderr.decode("utf-8", "replace"))
        # 必须是 UTF-8 字节；若仍是 cp1252 会解码失败或得到乱码
        self.assertIn("没有历史快照", proc.stdout.decode("utf-8"))

    def test_scan_json_survives_legacy_codepage(self):
        """CI 冒烟测试里失败的那条命令，逐字复现。"""
        proc = self._run_cli(["scan", "-r", "127.0.0.1/32",
                              "--no-ports", "--no-mdns", "--format", "json"])
        self.assertEqual(proc.returncode, 0,
                         msg=proc.stderr.decode("utf-8", "replace"))
        payload = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(payload["device_count"], 1)

    def test_stderr_is_real_utf8_not_backslash_escaped(self):
        """stderr 的中文不能被转义成 \\uXXXX —— 那样 CI 日志没法看。"""
        proc = self._run_cli(["scan", "-r", "127.0.0.1/32",
                              "--no-ports", "--no-mdns", "--format", "json"])
        err = proc.stderr.decode("utf-8")
        self.assertIn("准备扫描", err)
        self.assertNotIn("\\u51c6", err)

    def test_help_survives_legacy_codepage(self):
        """--help 的 metavar 含中文（如「用户名」），也必须能打印出来。"""
        proc = self._run_cli(["scan", "--help"])
        self.assertEqual(proc.returncode, 0,
                         msg=proc.stderr.decode("utf-8", "replace"))
        self.assertIn("用户名", proc.stdout.decode("utf-8"))

    def test_force_utf8_stdio_tolerates_streams_without_reconfigure(self):
        """单测的 redirect_stdout 用 StringIO —— 没有 reconfigure，不能因此报错。"""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            cli._force_utf8_stdio()          # 不应抛异常
        buf.write("仍然可写")
        self.assertEqual(buf.getvalue(), "仍然可写")

    def test_force_utf8_stdio_requests_utf8_on_both_streams(self):
        calls = []

        class _S:
            def reconfigure(self, **kw):
                calls.append(kw)

        saved_out, saved_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = _S(), _S()
            cli._force_utf8_stdio()
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        self.assertEqual(len(calls), 2, "stdout 与 stderr 都要切换")
        for kw in calls:
            self.assertEqual(kw["encoding"], "utf-8")


class LocateCommandTest(unittest.TestCase):
    """`locate` 子命令：文本可读、JSON 语言无关、退出码 4 表示「没定位到」。"""

    MAC = "AA:BB:CC:DD:EE:FF"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "locate.db")
        import history_store
        self.hs = history_store

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _seed(self, with_switch_data=True):
        sid = self.hs.save_snapshot(
            [{"ip": "192.168.1.50", "status": "online", "mac": self.MAC,
              "hostname": "FIN-PC-01"}], db_path=self.db)
        if with_switch_data:
            self.hs.save_port_map(sid, [{
                "switch_ip": "10.0.0.2", "switch_name": "access-sw-1", "error": "",
                "mappings": [{"mac": self.MAC, "port_name": "Gi0/24",
                              "port_is_real": True}],
            }], db_path=self.db)
        return sid

    def test_found_text_shows_switch_and_port(self):
        self._seed()
        code, out, _err = _run_main(["locate", "--mac", self.MAC, "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("access-sw-1", out)
        self.assertIn("Gi0/24", out)
        self.assertIn("FIN-PC-01", out)          # 只给 MAC 也要补齐主机名

    def test_found_json_is_language_neutral(self):
        """JSON 里必须是规范值（reason / port_source），不能是中文文案。"""
        self._seed()
        code, out, _err = _run_main(["locate", "--mac", self.MAC, "-f", "json",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        data = json.loads(out)
        self.assertTrue(data["found"])
        self.assertEqual(data["port_confidence"], "named")
        self.assertEqual(data["current"]["port_source"], "if_name")
        self.assertEqual(data["reason"], "")

    def test_locate_by_ip(self):
        self._seed()
        code, out, _err = _run_main(["locate", "--ip", "192.168.1.50",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn(self.MAC, out)

    def test_not_found_exits_4_with_reason_and_hint(self):
        """有快照但没采集过转发表 → 退出码 4（不是 1），且要给出下一步动作。

        原因/提示文案由 `locate_reason_label()` / `locate_reason_hint()` 渲染
        （与 GUI 共用同一份映射，随 `--lang` / 系统语言变），所以：
        ① 命令行**显式写死 `--lang zh-CN`**，去掉对 runner 系统语言的依赖；
        ② 期望值用**同一个**渲染函数在 zh-CN 下算出来 —— 不写死中文字面量。
        """
        self._seed(with_switch_data=False)
        code, out, _err = _run_main(["locate", "--mac", self.MAC, "--db", self.db,
                                     "--lang", "zh-CN"])
        self.assertEqual(code, cli.EXIT_NOT_FOUND)
        self.assertNotEqual(code, cli.EXIT_ERROR)
        from scanner.constants import locate_reason_hint, locate_reason_label
        with _lang("zh-CN"):
            self.assertIn(locate_reason_label(self.hs.LOCATE_NO_SWITCH_DATA), out)
            self.assertIn(locate_reason_hint(self.hs.LOCATE_NO_SWITCH_DATA), out)
        self.assertIn("--switch-map", out)       # 提示里必须告诉用户怎么开

    def test_mac_not_in_fdb_reason(self):
        self._seed()
        code, out, _err = _run_main(["locate", "--mac", "FF:FF:FF:FF:FF:FF",
                                     "-f", "json", "--db", self.db])
        self.assertEqual(code, cli.EXIT_NOT_FOUND)
        data = json.loads(out)
        self.assertFalse(data["found"])
        self.assertEqual(data["reason"], "mac_not_in_fdb")

    def test_empty_db_reports_no_device(self):
        """空库必须报 no_device，不能拿 no_switch_data 搪塞（两者含义不同）。"""
        code, out, _err = _run_main(["locate", "--mac", self.MAC, "-f", "json",
                                     "--db", self.db])
        self.assertEqual(code, cli.EXIT_NOT_FOUND)
        self.assertEqual(json.loads(out)["reason"], "no_device")

    def test_requires_exactly_one_selector(self):
        """--mac / --ip / --hostname 互斥且必填 —— 三者都不给应直接报参数错误。"""
        with self.assertRaises(SystemExit) as cm:
            cli.build_parser().parse_args(["locate"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["locate", "--mac", "a", "--ip", "b"])

    def test_switch_map_flag_is_accepted_by_scan(self):
        """--switch-map 必须在 scan 上可解析（真扫网段不在此测，见 test_locate 的采集测试）。"""
        args = cli.build_parser().parse_args(
            ["scan", "-r", "192.168.1.0/24", "--switch-map", "--save-snapshot"])
        self.assertTrue(args.switch_map)


class WatchCommandTest(unittest.TestCase):
    """`watch` 子命令：被动发现（默认不发包、默认不写快照）。

    全程 mock 掉 `dump_arp_table` —— 真去读本机 ARP 表的话，断言会随
    跑测试的机器而变（每台机器的邻居都不一样），等于没测。
    """

    ARP = {"10.0.0.1": "aa:bb:cc:00:00:01",
           "10.0.0.2": "aa:bb:cc:00:00:02",
           "10.0.0.3": "aa:bb:cc:00:00:03"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "watch.db")
        import scanner.passive as passive
        p = mock.patch.object(passive, "dump_arp_table",
                              return_value=dict(self.ARP))
        self._arp = p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── 输出 ──

    def test_once_lists_all_devices_as_new_when_db_is_empty(self):
        code, out, _err = _run_main(["watch", "--no-mdns", "--db", self.db])
        self.assertEqual(code, cli.EXIT_OK)
        for ip in self.ARP:
            self.assertIn(ip, out)
        self.assertIn("3", out)          # 台账 3 台

    def test_json_is_language_neutral(self):
        """JSON 字段名与取值都语言无关，脚本可依赖（与 locate 同一约定）。"""
        _c, out, _e = _run_main(["watch", "--no-mdns", "--db", self.db,
                                 "-f", "json"])
        data = json.loads(out)
        self.assertEqual(data["device_count"], 3)
        self.assertEqual(data["new_count"], 3)
        self.assertEqual(sorted(d["ip"] for d in data["devices"]),
                         sorted(self.ARP))
        self.assertEqual(data["devices"][0]["discovery_method"], "arp")
        self.assertEqual(data["devices"][0]["status"], "online")

    def test_baseline_from_latest_snapshot_suppresses_known(self):
        """基线里已有的 IP 不该被报成"新出现"。"""
        history_store.save_snapshot(
            [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}], db_path=self.db)
        _c, out, _e = _run_main(["watch", "--no-mdns", "--db", self.db,
                                 "-f", "json"])
        data = json.loads(out)
        self.assertEqual(data["device_count"], 3)
        self.assertEqual(data["new_count"], 1)
        self.assertEqual([d["ip"] for d in data["new_devices"]], ["10.0.0.3"])

    # ── 退出码 ──

    def test_fail_on_change_exits_2(self):
        code, _out, _err = _run_main(["watch", "--no-mdns", "--db", self.db,
                                      "--fail-on-change"])
        self.assertEqual(code, cli.EXIT_CHANGES)
        self.assertNotEqual(code, cli.EXIT_ERROR)

    def test_fail_on_change_exits_0_when_nothing_new(self):
        history_store.save_snapshot(
            [{"ip": ip} for ip in self.ARP], db_path=self.db)
        code, _out, _err = _run_main(["watch", "--no-mdns", "--db", self.db,
                                      "--fail-on-change"])
        self.assertEqual(code, cli.EXIT_OK)

    # ── 落库策略 ──

    def test_does_not_write_snapshot_by_default(self):
        """默认**不写快照** —— 否则持续轮询会在十分钟内冲掉全部历史。"""
        before = len(history_store.list_snapshots(db_path=self.db))
        _run_main(["watch", "--no-mdns", "--db", self.db])
        self.assertEqual(len(history_store.list_snapshots(db_path=self.db)),
                         before)

    def test_save_snapshot_writes_exactly_one(self):
        code, _out, _err = _run_main(["watch", "--no-mdns", "--db", self.db,
                                      "--save-snapshot", "--note", "冒烟"])
        self.assertEqual(code, cli.EXIT_OK)
        snaps = history_store.list_snapshots(db_path=self.db)
        self.assertEqual(len(snaps), 1)
        self.assertEqual(snaps[0]["device_count"], 3)

    def test_interval_with_save_snapshot_is_rejected(self):
        """持续轮询 + 每周期落库必然冲掉历史 —— 直接拒绝，不留坑。"""
        code, _out, err = _run_main(["watch", "--no-mdns", "--db", self.db,
                                     "--interval", "1", "--save-snapshot"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("--save-snapshot", err)
        self.assertEqual(history_store.list_snapshots(db_path=self.db), [])

    def test_interval_loops_the_given_number_of_rounds(self):
        code, out, _err = _run_main(["watch", "--no-mdns", "--db", self.db,
                                     "--interval", "0.01", "--count", "2"])
        self.assertEqual(code, cli.EXIT_OK)
        # 每轮一行标题；第二轮不该再报新设备
        self.assertEqual(out.count("[第 1 轮]"), 1)
        self.assertEqual(out.count("[第 2 轮]"), 1)

    # ── 参数 ──

    def test_once_and_interval_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit) as cm:
            cli.build_parser().parse_args(["watch", "--once", "--interval", "5"])
        self.assertEqual(cm.exception.code, 2)

    def test_mdns_flags_parse(self):
        args = cli.build_parser().parse_args(["watch", "--no-mdns"])
        self.assertTrue(args.no_mdns)
        args = cli.build_parser().parse_args(["watch", "--mdns-active"])
        self.assertTrue(args.mdns_active)


class _FakeNotifier:
    """记录调用的假渠道（不发起任何真实请求）。"""

    def __init__(self, name="fake", fail=False):
        self.name = name
        self.fail = fail
        self.sent = []

    def send(self, subject, body):
        if self.fail:
            raise RuntimeError("channel down")
        self.sent.append((subject, body))


class NotifyPolicyTest(unittest.TestCase):
    """`scan --notify` 与告警策略（维护窗口 / 静音 / 去重）的接线。

    这里直接调 `cli._notify_changes`：它才是"要不要发"的决策点，
    比走 `main()` 更容易把基线、配置、假渠道摆好。
    """

    GONE_MAC = "AA:BB:CC:00:00:01"      # 上次在线、本次消失
    NEW_MAC = "AA:BB:CC:00:00:02"       # 本次新出现
    GONE_IP = "10.0.0.5"
    NEW_IP = "10.0.0.6"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = os.path.join(self.tmp, "hist.db")
        self.state = os.path.join(self.tmp, "dedup.json")
        history_store.save_snapshot([
            {"ip": self.GONE_IP, "status": "online", "mac": self.GONE_MAC,
             "hostname": "prn-1"},
        ], note="基线", db_path=self.db)
        self.baseline_id = history_store.list_snapshots(
            db_path=self.db)[-1]["id"]

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _args(self, *extra):
        return cli.build_parser().parse_args(
            ["scan", "-r", "10.0.0.0/24", "--notify", "--db", self.db,
             *extra])

    def _results(self):
        # 只保留"新设备"—— 消失的那台由基线提供
        return [ScanResult(ip=self.NEW_IP, status="online",
                           mac=self.NEW_MAC, hostname="nb-1")]

    def _run(self, config, notifiers, *extra):
        with contextlib.redirect_stderr(io.StringIO()):
            cli._notify_changes(self._results(), self.baseline_id,
                                notifiers, self._args(*extra), config)

    # ── 基本接线 ──

    def test_without_policy_everything_is_sent(self):
        n = _FakeNotifier()
        self._run({}, [n])
        self.assertEqual(len(n.sent), 1)
        body = n.sent[0][1]
        self.assertIn(self.GONE_IP, body)     # 设备消失
        self.assertIn(self.NEW_IP, body)      # 新增设备

    def test_empty_config_is_a_noop(self):
        policy, store = cli._load_alert_policy(self._args(), {})
        self.assertIsNone(policy)
        self.assertIsNone(store)

    def test_no_policy_flag_bypasses_everything(self):
        cfg = {"mutes": [{"name": "全静音", "range": "10.0.0.0/24"}]}
        n = _FakeNotifier()
        self._run(cfg, [n], "--no-policy")
        self.assertEqual(len(n.sent), 1)
        self.assertIn(self.NEW_IP, n.sent[0][1])

    def test_no_policy_flag_parses(self):
        args = cli.build_parser().parse_args(["scan", "-r", "10.0.0.0/24"])
        self.assertFalse(args.no_policy)

    # ── 静音 ──

    def test_mute_suppresses_only_that_device(self):
        cfg = {"mutes": [{"name": "已知新增", "mac": self.NEW_MAC}]}
        n = _FakeNotifier()
        self._run(cfg, [n])
        self.assertEqual(len(n.sent), 1)
        body = n.sent[0][1]
        self.assertIn(self.GONE_IP, body)
        # 被抑制的那条要在正文里留痕（不静默）
        self.assertIn(self.NEW_IP, body)

    def test_all_suppressed_sends_nothing(self):
        cfg = {"mutes": [{"name": "整段静音", "range": "10.0.0.0/24"}]}
        n = _FakeNotifier()
        self._run(cfg, [n])
        self.assertEqual(n.sent, [])

    # ── 维护窗口 ──

    def test_maintenance_window_suppresses(self):
        # 覆盖"现在"的整日窗口（00:00–23:59），与运行时刻无关
        cfg = {"maintenance_windows": [
            {"name": "全天维护", "start": "00:00", "end": "23:59"}]}
        n = _FakeNotifier()
        self._run(cfg, [n])
        self.assertEqual(n.sent, [])

    def test_window_scoped_to_other_subnet_does_not_suppress(self):
        cfg = {"maintenance_windows": [
            {"name": "别的网段", "start": "00:00", "end": "23:59",
             "ranges": ["192.168.0.0/16"]}]}
        n = _FakeNotifier()
        self._run(cfg, [n])
        self.assertEqual(len(n.sent), 1)

    # ── 去重 ──

    def test_dedup_records_state_after_successful_send(self):
        cfg = {"dedup": {"window_minutes": 60, "path": self.state}}
        n = _FakeNotifier()
        self._run(cfg, [n])
        self.assertEqual(len(n.sent), 1)
        self.assertTrue(os.path.exists(self.state),
                        "发送成功后应写下去重状态（定时扫描是独立进程）")

    def test_dedup_second_run_is_suppressed(self):
        cfg = {"dedup": {"window_minutes": 60, "path": self.state}}
        first = _FakeNotifier()
        self._run(cfg, [first])
        self.assertEqual(len(first.sent), 1)

        second = _FakeNotifier()
        self._run(cfg, [second])
        self.assertEqual(second.sent, [], "冷却窗口内不该重复告警")

    def test_dedup_does_not_record_when_send_fails(self):
        """发送失败不记账 —— 否则一次网络抖动会让这条变更永远沉默。"""
        cfg = {"dedup": {"window_minutes": 60, "path": self.state}}
        self._run(cfg, [_FakeNotifier(fail=True)])
        self.assertFalse(os.path.exists(self.state))

    def test_dedup_records_when_at_least_one_channel_succeeds(self):
        cfg = {"dedup": {"window_minutes": 60, "path": self.state}}
        self._run(cfg, [_FakeNotifier("bad", fail=True), _FakeNotifier("ok")])
        self.assertTrue(os.path.exists(self.state))


if __name__ == "__main__":
    unittest.main()
