# -*- coding: utf-8 -*-
"""CLI `arp-mac` 子命令（跨网段取 MAC）的参数面与输出契约。

**它解决什么**：MAC 是二层概念，扫描机与目标不同网段时本机 ARP 表里只有网关
的 MAC。出路是读**持有目标网段三层接口**那台设备（通常就是本机默认网关）的
ARP 表 —— 本命令就是这条路的命令行入口。

覆盖点（都围绕"静默给错答案"这类失效）：

1. **参数面**：不写 `--host` 时自动探测默认网关；探测不到必须 **EXIT_ENV(3)**
   并指出用 `--host`，**绝不**退化成猜「本机网段 .1」。
2. **JSON 键固定英文**（与其它子命令一致）：CLI 输出恒为中文，键不能随语言漂。
3. **数值序排序**：`10.0.0.10` 必须排在 `10.0.0.2` 后面（字符串序会把运维看晕）。
4. **区分「表是空的」与「表有内容但都不在范围内」** —— 两者下一步动作不同
   （换设备查 vs 改 `--range`），混成一句会让人白折腾。

⚠ `cli.main()` 会 `i18n.init(None)` 切走**整个进程**的语言（CI 的 locale 是
en-US），所以每次调用都必须保存并还原 —— 否则字母序在后的测试模块会集体变红。
本文件的 `_run` 照 `tests/test_audit_activity.py` 的写法处理。

⚠ 本文件**不发起任何真实网络访问**：`fetch_arp_table` / `detect_default_gateway`
一律打桩。
"""
import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli                                              # noqa: E402
import i18n                                             # noqa: E402
from arp_mapper import ArpTableResult                    # noqa: E402


class _CliCase(unittest.TestCase):
    def _run(self, argv):
        """运行 `cli.main`，返回 (exit_code, stdout, stderr)，并还原语言。"""
        out, err = io.StringIO(), io.StringIO()
        lang = i18n.current_lang()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        finally:
            i18n.init(lang)
        return code, out.getvalue(), err.getvalue()

    def _patch(self, *, detect="", result=None, raises=None):
        """打上两个出网点；返回 `fetch_arp_table` 的 mock。"""
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(mock.patch("arp_mapper.detect_default_gateway",
                                       return_value=detect))
        fm = mock.Mock(return_value=result)
        if raises is not None:
            fm.side_effect = raises
        stack.enter_context(mock.patch("arp_mapper.fetch_arp_table", fm))
        self.addCleanup(stack.close)
        return fm


class ArgSurfaceTest(_CliCase):
    def test_parser_defaults(self):
        args = cli.build_parser().parse_args(["arp-mac"])
        self.assertEqual(args.host, "")
        self.assertIsNone(args.ranges)
        self.assertIsNone(args.community)
        self.assertAlmostEqual(args.timeout, 1.5)
        self.assertEqual(args.format, "table")
        self.assertIsNone(args.output)
        self.assertIs(args.func, cli.cmd_arp_mac)

    def test_accepts_host_range_and_format(self):
        args = cli.build_parser().parse_args(
            ["arp-mac", "--host", "10.0.0.254", "-r", "10.193.24.0/24",
             "-c", "public", "-f", "json"])
        self.assertEqual(args.host, "10.0.0.254")
        self.assertEqual(args.ranges, ["10.193.24.0/24"])
        self.assertEqual(args.community, ["public"])
        self.assertEqual(args.format, "json")

    def test_accepts_snmpv3_switches(self):
        """v3 参数要能被 arp-mac 解析 —— 它和 scan/diff/topology 共用同一批选项。

        漏加的话会在 `parse_args` 阶段直接 `unrecognized arguments` 崩掉，
        而且**只有真的用 v3 的人才会碰到**（v2c 用户永远发现不了）。
        """
        args = cli.build_parser().parse_args(
            ["arp-mac", "--snmpv3-user", "monitor",
             "--snmpv3-auth", "sha", "--snmpv3-priv", "aes"])
        self.assertEqual(args.snmpv3_user, "monitor")
        self.assertEqual(args.snmpv3_auth, "sha")
        self.assertEqual(args.snmpv3_priv, "aes")

    def test_no_option_carries_a_password(self):
        """口令只走环境变量 —— argv 里不允许出现任何承载口令的选项。"""
        opts = set()
        for act in cli.build_parser()._subparsers._group_actions[0].choices[
                "arp-mac"]._actions:
            opts.update(act.option_strings)
        for bad in ("--snmpv3-auth-pass", "--snmpv3-priv-pass", "--password"):
            self.assertNotIn(bad, opts)


class GatewayResolutionTest(_CliCase):
    def test_missing_host_and_no_gateway_returns_env_error(self):
        """🔴 探测不到网关 → EXIT_ENV(3)，并指出用 `--host`，**绝不猜**。"""
        fm = self._patch(detect="")
        code, out, err = self._run(["arp-mac"])
        self.assertEqual(code, cli.EXIT_ENV)
        self.assertFalse(fm.called, "没探测到网关却仍然发了 SNMP 查询")
        self.assertIn("--host", err)

    def test_auto_gateway_is_used_when_host_omitted(self):
        fm = self._patch(detect="10.9.9.9",
                         result=ArpTableResult(host="10.9.9.9", entries={
                             "10.193.24.11": "aa:bb:cc:dd:ee:ff"}))
        code, out, _ = self._run(["arp-mac", "-f", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(fm.call_args[0][0], "10.9.9.9")
        self.assertEqual(json.loads(out)["host"], "10.9.9.9")

    def test_explicit_host_skips_detection(self):
        fm = self._patch(detect="10.9.9.9",
                         result=ArpTableResult(host="10.0.0.254"))
        self._run(["arp-mac", "--host", "10.0.0.254", "-f", "json"])
        self.assertEqual(fm.call_args[0][0], "10.0.0.254")

    def test_blank_host_is_treated_as_omitted(self):
        """`--host ""` / 只有空格 → 与不写等价，走自动探测。"""
        fm = self._patch(detect="10.9.9.9",
                         result=ArpTableResult(host="10.9.9.9"))
        self._run(["arp-mac", "--host", "   ", "-f", "json"])
        self.assertEqual(fm.call_args[0][0], "10.9.9.9")

    def test_communities_are_forwarded(self):
        fm = self._patch(detect="10.9.9.9",
                         result=ArpTableResult(host="10.9.9.9"))
        self._run(["arp-mac", "-c", "public", "-c", "private", "-f", "json"])
        self.assertEqual(fm.call_args[1]["communities"], ["public", "private"])


class JsonContractTest(_CliCase):
    def _entries(self):
        return {
            "10.193.24.11": "aa:bb:cc:dd:ee:ff",
            "10.193.24.2": "aa:bb:cc:dd:ee:02",
            "10.193.24.10": "aa:bb:cc:dd:ee:10",
        }

    def test_json_keys_are_fixed_english(self):
        self._patch(detect="10.9.9.9", result=ArpTableResult(
            host="10.9.9.9", sys_name="sw", sys_descr="d",
            source="ipNetToMediaTable", entries=self._entries()))
        code, out, _ = self._run(["arp-mac", "-f", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        data = json.loads(out)
        self.assertEqual(set(data), {
            "host", "sys_name", "sys_descr", "source", "count",
            "total_entries", "entries", "error"})
        self.assertEqual(set(data["entries"][0]), {"ip", "mac"})

    def test_entries_are_sorted_numerically(self):
        """`10.193.24.10` 必须排在 `10.193.24.2` 之后（字符串序会看晕）。"""
        self._patch(detect="10.9.9.9",
                    result=ArpTableResult(host="10.9.9.9", entries=self._entries()))
        _, out, _ = self._run(["arp-mac", "-f", "json"])
        ips = [e["ip"] for e in json.loads(out)["entries"]]
        self.assertEqual(ips, ["10.193.24.2", "10.193.24.10", "10.193.24.11"])

    def test_range_filters_entries_but_keeps_the_total(self):
        self._patch(detect="10.9.9.9",
                    result=ArpTableResult(host="10.9.9.9", entries=self._entries()))
        _, out, _ = self._run(["arp-mac", "-f", "json",
                               "-r", "10.193.24.0/28"])
        data = json.loads(out)
        self.assertEqual(data["count"], 3)          # /28 覆盖 .2/.10/.11
        self.assertEqual(data["total_entries"], 3)

        _, out, _ = self._run(["arp-mac", "-f", "json", "-r", "10.193.99.0/24"])
        data = json.loads(out)
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["total_entries"], 3,
                         "过滤后把总条数也丢了 —— 用户无法判断是表空还是范围错")

    def test_invalid_range_fails_fast(self):
        fm = self._patch(detect="10.9.9.9")
        code, _, err = self._run(["arp-mac", "-r", "不是范围"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("不是范围", err)
        self.assertFalse(fm.called, "范围都解析不了却已经去查设备了")


class ErrorAndOutputTest(_CliCase):
    def test_read_failure_returns_error_code(self):
        self._patch(detect="10.9.9.9", result=ArpTableResult(
            host="10.9.9.9", error="该设备对 SNMP 查询没有响应。"))
        code, out, _ = self._run(["arp-mac", "-f", "json"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("没有响应", json.loads(out)["error"])

    def test_unexpected_exception_never_returns_success(self):
        """出网点抛异常时必须**非 0** 退出 —— 返回 0 会让脚本以为拿到了数据。

        `cli.main` 统一把未预期异常收成 `EXIT_ERROR`（并写 stderr），
        这里钉住这个契约：ARP 表这条路出问题也绝不能"成功退出 + 空结果"。
        """
        self._patch(detect="10.9.9.9", raises=RuntimeError("boom"))
        code, out, err = self._run(["arp-mac", "-f", "json"])
        self.assertNotEqual(code, cli.EXIT_OK)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("boom", err)
        self.assertEqual(out, "", "失败时 stdout 不该有任何结果数据")

    def test_empty_table_and_out_of_range_say_different_things(self):
        """🔴 两种"空"必须分开说 —— 下一步动作完全不同。"""
        # 表本身是空的
        self._patch(detect="10.9.9.9", result=ArpTableResult(host="10.9.9.9"))
        code, out, _ = self._run(["arp-mac"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("0 条 ARP 记录", out)

        # 表有内容，但都不在范围内
        self._patch(detect="10.9.9.9", result=ArpTableResult(
            host="10.9.9.9", entries={"10.193.24.11": "aa:bb:cc:dd:ee:ff"}))
        code, out, _ = self._run(["arp-mac", "-r", "10.193.99.0/24"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("1 条 ARP 记录", out)
        self.assertIn("--range", out)

    def test_table_output_carries_the_aging_warning(self):
        """表项会老化 —— 不提醒的话用户会拿几小时前的 MAC 当"此刻在线"。"""
        self._patch(detect="10.9.9.9", result=ArpTableResult(
            host="10.9.9.9", source="ipNetToMediaTable",
            entries={"10.193.24.11": "aa:bb:cc:dd:ee:ff"}))
        _, out, _ = self._run(["arp-mac"])
        self.assertIn("老化", out)
        self.assertIn("10.193.24.11", out)
        self.assertIn("aa:bb:cc:dd:ee:ff", out)

    def test_csv_output_has_a_header(self):
        self._patch(detect="10.9.9.9", result=ArpTableResult(
            host="10.9.9.9", entries={"10.193.24.11": "aa:bb:cc:dd:ee:ff"}))
        _, out, _ = self._run(["arp-mac", "-f", "csv"])
        self.assertEqual(out.splitlines()[0].strip(), "ip,mac")
        self.assertIn("10.193.24.11,aa:bb:cc:dd:ee:ff", out)

    def test_diagnostics_go_to_stderr_not_stdout(self):
        """stdout 只承载结果数据（便于管道），提示走 stderr。"""
        self._patch(detect="10.9.9.9", result=ArpTableResult(
            host="10.9.9.9", entries={"10.193.24.11": "aa:bb:cc:dd:ee:ff"}))
        _, out, err = self._run(["arp-mac", "-f", "csv"])
        self.assertNotIn("未指定 --host", out)
        self.assertIn("未指定 --host", err)


if __name__ == "__main__":
    unittest.main()
