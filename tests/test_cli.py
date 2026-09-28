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
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli
from scanner.models import ScanResult


def _run_main(argv):
    """运行 cli.main，返回 (exit_code, stdout, stderr)。"""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


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


if __name__ == "__main__":
    unittest.main()
