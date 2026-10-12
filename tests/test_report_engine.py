# -*- coding: utf-8 -*-
"""``report_engine`` 与 ``cli.py report`` 测试（v2.0 §2.2 报表引擎）。

覆盖点（对应 `docs/ROADMAP_V2.0.md` §3 2.2 的验收栏）：

1. 用内置模板生成报表，**产出可解析的 HTML** 且含全部资产行（计数断言）；
2. **换模板文件即换版式**：同一份数据喂两个模板，产出不同且都合法；
3. 语言切换下产出的**资产值**仍是规范值（``online``/``offline``），
   仅**模板文案**随语言变（i18n 铁律）——
   本项的实现是「报表值语言无关、模板文案不进语言包」，所以这条体现为：
   报表值不随语言变；
4. 定时链路：给定 argv，``build_task_command`` 产出与 2.2 前**逐字节一致**
   （不破坏既有定时）—— 投递是**新增**，不是改旧的。

额外钉住的稳健性点：
- 模板缺失 → 回退内置兜底模板（不崩、仍出可解析 HTML）；
- 占位符注入：主机名/厂商含 ``<script>`` 必须被转义（安全）；
- 未知模板名 → ``ValueError``（不静默出空文档）。
"""
import contextlib
import io
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli
import i18n
import report_engine
import scheduler


def _run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    lang = i18n.current_lang()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
    finally:
        i18n.init(lang)
    return code, out.getvalue(), err.getvalue()


def _asset(ip, **kw):
    base = {"identity_key": "mac:" + ip, "ip": ip, "status": "online",
            "hostname": "host-" + ip, "mac": "00:11:22:33:44:55",
            "vendor": "Acme", "device_class": "PC", "os_guess": "",
            "open_ports": "", "services": "", "location": "", "user": "",
            "remark": "", "first_seen": 1000.0, "last_seen": 2000.0,
            "seen_count": 1, "fingerprint": ""}
    base.update(kw)
    return base


def _is_parseable_html(text: str) -> bool:
    """粗验 HTML 结构：标签成对 + 可被 HTMLParser 消费不抛。"""
    from html.parser import HTMLParser

    class _P(HTMLParser):
        pass

    _P().feed(text)   # 畸形标签不会抛，但能挡住明显截断的空串
    return bool(text.strip()) and text.count("<table") == text.count("</table>")


# ─────────────────────── 纯逻辑层 ───────────────────────

class TemplateLoadTest(unittest.TestCase):
    """模板加载策略：data_dir 优先 → resource_dir → 内置兜底。"""

    def test_builtin_templates_load_from_disk(self):
        """仓库里三个内置模板都要能读到（且不是兜底）。"""
        for name in report_engine.REPORT_TEMPLATES:
            text = report_engine.load_template(name)
            self.assertTrue(text.strip(), "模板 %s 读不到" % name)
            self.assertIn("{{rows}}", text, "模板 %s 缺主表占位符" % name)

    def test_missing_template_falls_back_to_builtin_text(self):
        """模板文件缺失 → 回退模块内兜底模板（不崩、仍是合法 HTML）。"""
        with mock.patch.object(report_engine, "template_path",
                               return_value="/nonexistent/nope.html"):
            text = report_engine.load_template("assets")
        self.assertIn("{{rows}}", text)

    def test_unknown_template_name_returns_empty(self):
        self.assertEqual(report_engine.load_template("bogus"), "")

    def test_template_path_falls_back_to_resource_dir(self):
        """用户数据目录里没有该模板 → 路径落到 resource_dir（内置目录）。"""
        with mock.patch.object(report_engine, "data_dir", return_value="/nonexistent"):
            p = report_engine.template_path("assets")
        self.assertTrue(p.endswith(os.path.join("assets", "report_templates", "assets.html")))
        self.assertNotIn("nonexistent", p.replace("\\", "/"))

    def test_load_text_handles_unreadable_file(self):
        """OSError（非 FileNotFoundError）也要被吞成空串 + warning。"""
        with mock.patch("builtins.open", side_effect=OSError("boom")):
            with mock.patch.object(report_engine._log, "warning") as w:
                self.assertEqual(report_engine._load_text("/x/y.html"), "")
        self.assertTrue(w.called)

    def test_available_templates_lists_three(self):
        self.assertEqual(report_engine.available_templates(),
                         ["assets", "changes", "exposure"])


class AssetReportTest(unittest.TestCase):
    """资产清单报表：可解析、含全部行。"""

    def test_all_assets_appear(self):
        rows = [_asset("10.0.0.%d" % i) for i in range(1, 6)]
        html = report_engine.render_report("assets", assets=rows,
                                           generated_at="2026-10-12T14:00:00")
        self.assertTrue(_is_parseable_html(html))
        for i in range(1, 6):
            self.assertIn("host-10.0.0.%d" % i, html)
        # 每行 8 个 <td>
        self.assertEqual(html.count("<td"), 40)
        # 概要含 5 assets / 5 online
        self.assertIn("5 assets", html)
        self.assertIn("5 online", html)

    def test_online_offline_status_are_canonical_values(self):
        """status 落 online/offline 规范值；``up``/``down`` 等价写法也被规范。"""
        rows = [_asset("10.0.0.1", status="online"),
                _asset("10.0.0.2", status="offline"),
                _asset("10.0.0.3", status="up"),
                _asset("10.0.0.4", status="down")]
        html = report_engine.render_report("assets", assets=rows,
                                           generated_at="x")
        self.assertEqual(html.count(">online<"), 2)
        self.assertEqual(html.count(">offline<"), 2)

    def test_unknown_status_is_not_silently_blanked(self):
        """认不出的状态**原样保留**，不静默抹成空单元格。

        `status` 的规范值是英文 `online`/`offline`；中文「在线」只该出现在
        `tr()` 的显示层、从不入库。若真收到一个认不出的值，报表要**如实显示**
        它（暴露上游问题），而不是把它擦掉让报表"看起来正常"。
        """
        rows = [_asset("10.0.0.1", status="在线")]
        html = report_engine.render_report("assets", assets=rows, generated_at="x")
        self.assertIn("在线", html)

    def test_norm_status_table(self):
        self.assertEqual(report_engine._norm_status("online"), "online")
        self.assertEqual(report_engine._norm_status("UP"), "online")
        self.assertEqual(report_engine._norm_status("offline"), "offline")
        self.assertEqual(report_engine._norm_status("down"), "offline")
        self.assertEqual(report_engine._norm_status(""), "")
        self.assertEqual(report_engine._norm_status(None), "")
        self.assertEqual(report_engine._norm_status("weird"), "weird")

    def test_zero_assets_still_valid(self):
        html = report_engine.render_report("assets", assets=[],
                                           generated_at="x")
        self.assertTrue(_is_parseable_html(html))
        self.assertIn("0 assets", html)


class ChangeReportTest(unittest.TestCase):
    """变更摘要报表：severity/type 落规范值。"""

    def test_changes_rendered_with_canonical_values(self):
        changes = [
            {"severity": "high", "change_type": "new_device", "ip": "10.0.0.9",
             "mac": "aa:bb", "hostname": "new", "old_value": "", "new_value": ""},
            {"severity": "info", "change_type": "device_gone", "ip": "10.0.0.2",
             "mac": "cc:dd", "hostname": "old", "old_value": "", "new_value": ""},
        ]
        html = report_engine.render_report("changes", changes=changes,
                                           generated_at="x")
        self.assertTrue(_is_parseable_html(html))
        self.assertIn("new_device", html)
        self.assertIn("device_gone", html)
        self.assertIn("2 changes", html)
        self.assertIn("1 high", html)

    def test_change_objects_from_detector_work(self):
        """直接喂 `change_detector.Change` 对象也能渲染（attr 取值分支）。"""
        import change_detector as cd
        c = cd.Change(change_type=cd.CHANGE_NEW_DEVICE, severity=cd.SEVERITY_HIGH,
                      description="x", ip="10.0.0.1", mac="aa", hostname="h")
        html = report_engine.render_report("changes", changes=[c], generated_at="x")
        self.assertIn("new_device", html)
        self.assertIn("10.0.0.1", html)

    def test_zero_changes_says_zero(self):
        html = report_engine.render_report("changes", changes=[], generated_at="x")
        self.assertIn("0 changes", html)


class ExposureReportTest(unittest.TestCase):
    """暴露面报表：按「端口 + 服务」聚合。"""

    def test_ports_aggregated_by_port_and_service(self):
        rows = [
            _asset("10.0.0.1", open_ports="80;443", services="80=http;443=https"),
            _asset("10.0.0.2", open_ports="80;22", services="80=http;22=ssh"),
            _asset("10.0.0.3", open_ports="80", services="80=http"),
        ]
        html = report_engine.render_report("exposure", assets=rows,
                                           generated_at="x")
        self.assertTrue(_is_parseable_html(html))
        # 端口 80/http 被 3 台设备开着
        self.assertIn(">80<", html)
        self.assertIn(">3<", html)
        # 端口 443 / 22 各 1 台
        self.assertIn(">443<", html)
        self.assertIn(">22<", html)

    def test_port_parsing_tolerates_forms(self):
        self.assertEqual(report_engine._split_ports("80,443"), [80, 443])
        self.assertEqual(report_engine._split_ports("80;443"), [80, 443])
        self.assertEqual(report_engine._split_ports("80/tcp;443/tcp"), [80, 443])
        self.assertEqual(report_engine._split_ports([80, "443"]), [80, 443])
        self.assertEqual(report_engine._split_ports(""), [])
        self.assertEqual(report_engine._split_ports(None), [])

    def test_services_parsing_tolerates_forms(self):
        self.assertEqual(report_engine._services_by_port("80=http;443=https"),
                         {80: "http", 443: "https"})
        self.assertEqual(report_engine._services_by_port([{"port": 22, "service": "ssh"}]),
                         {22: "ssh"})
        self.assertEqual(report_engine._services_by_port(""), {})

    def test_services_by_port_json_form(self):
        """`services` 若是 JSON 串（interop 侧的存法）也要能解析。"""
        self.assertEqual(report_engine._services_by_port('{"80": "http"}'),
                         {80: "http"})
        self.assertEqual(report_engine._services_by_port("[{\"port\": 443, \"name\": \"https\"}]"),
                         {443: "https"})

    def test_services_by_port_broken_json_returns_empty(self):
        """坏 JSON 不能抛 —— 服务名只是锦上添花，解析不出就留空。"""
        self.assertEqual(report_engine._services_by_port("[not valid json"), {})
        self.assertEqual(report_engine._services_by_port('{"x": "y"}'), {})

    def test_services_by_port_slash_form(self):
        self.assertEqual(report_engine._services_by_port("80/tcp,443"), {80: "", 443: ""})

    def test_ports_with_non_numeric_tokens_skipped(self):
        self.assertEqual(report_engine._split_ports("80,tcp,443"), [80, 443])
        # 空 token（连续分隔符 / 首尾分隔符）要跳过，不能当成 0
        self.assertEqual(report_engine._split_ports("80,,443,"), [80, 443])

    def test_more_than_twenty_devices_truncated(self):
        """>20 台设备共用一个端口时列表要截断并标 (+N)，避免报表被撑爆。"""
        rows = [_asset("10.0.0.%d" % i, open_ports="80", services="80=http")
                for i in range(1, 26)]
        html = report_engine.render_report("exposure", assets=rows, generated_at="x")
        self.assertIn("(+5)", html)

    def test_exposure_summary_counts_devices(self):
        rows = [
            _asset("10.0.0.1", open_ports="80", services="80=http"),
            _asset("10.0.0.2", open_ports="80", services="80=http"),
        ]
        html = report_engine.render_report("exposure", assets=rows,
                                           generated_at="x")
        self.assertIn("across 2 devices", html)


# ─────────────────────── 安全 / 稳健性 ───────────────────────

class EscapingTest(unittest.TestCase):
    """报表值是外部输入（主机名/厂商可能是任意字节）—— 必须转义。"""

    def test_hostname_with_script_is_escaped(self):
        rows = [_asset("10.0.0.1", hostname="<script>alert(1)</script>")]
        html = report_engine.render_report("assets", assets=rows, generated_at="x")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_quotes_and_ampersand_escaped(self):
        rows = [_asset("10.0.0.1", vendor='A&B "C" <D>')]
        html = report_engine.render_report("assets", assets=rows, generated_at="x")
        self.assertIn("&amp;", html)
        self.assertIn("&quot;", html)
        self.assertIn("&lt;D&gt;", html)

    def test_escape_helper_handles_none(self):
        self.assertEqual(report_engine._esc(None), "")


class BuildReportEdgeTest(unittest.TestCase):

    def test_empty_template_returns_empty(self):
        self.assertEqual(report_engine.build_report("assets", [], "s", "t", ""), "")

    def test_render_unknown_kind_raises(self):
        with self.assertRaises(ValueError):
            report_engine.render_report("bogus", assets=[], generated_at="x")

    def test_render_unavailable_template_raises(self):
        """模板连兜底都取不到 → ValueError（不静默出空文档）。"""
        with mock.patch.object(report_engine, "load_template", return_value=""):
            with self.assertRaises(ValueError):
                report_engine.render_report("assets", assets=[], generated_at="x")

    def test_generated_at_defaults_to_now(self):
        html = report_engine.render_report("assets", assets=[])
        self.assertNotIn("{{generated_at}}", html)


class SwapTemplateTest(unittest.TestCase):
    """验收 2：换模板文件即换版式 —— 同数据喂两个模板，产出不同且都合法。"""

    def test_two_templates_produce_different_valid_output(self):
        rows = [_asset("10.0.0.1", hostname="h1")]
        t_a = "<html><body><h1>AAA</h1><table><tbody>{{rows}}</tbody></table></body></html>"
        t_b = ("<html><body><h1>BBB</h1>"
               "<table><tbody>{{rows}}</tbody></table></body></html>")
        out_a = report_engine.render_report("assets", assets=rows,
                                            template_text=t_a, generated_at="x")
        out_b = report_engine.render_report("assets", assets=rows,
                                            template_text=t_b, generated_at="x")
        self.assertNotEqual(out_a, out_b)
        self.assertIn("AAA", out_a)
        self.assertIn("BBB", out_b)
        # 两份都含同一台设备的同一行（证明换的只是版式，不是数据）
        self.assertIn("h1", out_a)
        self.assertIn("h1", out_b)


# ─────────────────────── i18n：值语言无关 ───────────────────────

class ReportLanguageIndependenceTest(unittest.TestCase):
    """验收 3：报表**值**不随语言变（规范值），模板文案由模板文件承载。"""

    def test_values_do_not_change_with_language(self):
        rows = [_asset("10.0.0.1", status="online", device_class="打印机")]
        orig = i18n.current_lang()
        try:
            i18n.init("zh-CN")
            zh = report_engine.render_report("assets", assets=rows, generated_at="x")
            i18n.init("en-US")
            en = report_engine.render_report("assets", assets=rows, generated_at="x")
        finally:
            i18n.init(orig)
        self.assertEqual(zh, en)
        self.assertIn("online", zh)


# ─────────────────────── CLI report 子命令 ───────────────────────

class ReportCommandTest(unittest.TestCase):
    """``cli report`` 端到端（真实临时库）。"""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")
        self._seed()

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _seed(self):
        import history_store
        history_store.save_snapshot([
            {"ip": "10.0.0.1", "status": "online", "mac": "00:1A:2B:3C:4D:01",
             "hostname": "gw", "vendor": "Cisco", "device_class": "路由器",
             "open_ports": "80;443", "services": "80=http;443=https"},
            {"ip": "10.0.0.2", "status": "online", "mac": "00:1A:2B:3C:4D:02",
             "hostname": "web", "vendor": "Dell", "device_class": "服务器",
             "open_ports": "80", "services": "80=http"},
        ], ts=1000.0, db_path=self.db)
        history_store.save_snapshot([
            {"ip": "10.0.0.9", "status": "online", "mac": "00:1A:2B:3C:4D:09",
             "hostname": "new", "vendor": "Apple", "device_class": "手机"},
        ], ts=2000.0, db_path=self.db)
        db_util = __import__("db_util")
        db_util.close_connection(self.db)

    def test_assets_report_to_stdout(self):
        code, out, _err = _run_main(
            ["report", "--db", self.db, "-t", "assets",
             "--generated-at", "2026-10-12T14:00:00"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(_is_parseable_html(out))
        self.assertIn("gw", out)
        self.assertIn("web", out)

    def test_report_to_file(self):
        out_path = os.path.join(self.tmp, "r.html")
        code, _out, err = _run_main(
            ["report", "--db", self.db, "-t", "assets", "-o", out_path,
             "--generated-at", "x"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(os.path.exists(out_path))
        self.assertIn("已生成报表", err)

    def test_changes_report_between_snapshots(self):
        code, out, _err = _run_main(
            ["report", "--db", self.db, "-t", "changes",
             "--from", "1", "--to", "2", "--generated-at", "x"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("new_device", out)
        self.assertIn("device_gone", out)

    def test_exposure_report(self):
        code, out, _err = _run_main(
            ["report", "--db", self.db, "-t", "exposure", "--generated-at", "x"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn(">80<", out)

    def test_custom_template_file(self):
        tpl = os.path.join(self.tmp, "t.html")
        with open(tpl, "w", encoding="utf-8") as f:
            f.write("<html><body><h1>MYCUSTOM</h1><table><tbody>{{rows}}"
                    "</tbody></table></body></html>")
        code, out, _err = _run_main(
            ["report", "--db", self.db, "-t", "assets", "--template-file", tpl,
             "--generated-at", "x"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("MYCUSTOM", out)

    def test_missing_template_file_exit_error(self):
        code, _out, err = _run_main(
            ["report", "--db", self.db, "-t", "assets",
             "--template-file", os.path.join(self.tmp, "nope.html")])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("无法读取模板文件", err)

    def test_changes_report_without_snapshots(self):
        empty_db = os.path.join(self.tmp, "empty.db")
        code, _out, err = _run_main(["report", "--db", empty_db, "-t", "changes"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("没有任何历史快照", err)


# ─────────────────────── 定时投递链路 ───────────────────────

class DeliveryArgvTest(unittest.TestCase):
    """验收 4：投递参数是纯新增，不破坏既有 `build_*` 输出。"""

    def test_no_report_returns_empty(self):
        self.assertEqual(scheduler.build_delivery_argv(), [])
        self.assertEqual(scheduler.build_delivery_argv(None), [])
        self.assertEqual(scheduler.build_delivery_argv(""), [])

    def test_report_and_output(self):
        self.assertEqual(scheduler.build_delivery_argv("assets"),
                         ["--report", "assets"])
        self.assertEqual(
            scheduler.build_delivery_argv("changes", "D:/r.html"),
            ["--report", "changes", "--report-output", "D:/r.html"])

    def test_unknown_report_rejected(self):
        with self.assertRaises(ValueError):
            scheduler.build_delivery_argv("bogus")

    def test_existing_task_command_is_byte_identical_without_report(self):
        """**核心**：不投递报表时，命令行与 2.2 之前逐字节一致。"""
        argv = scheduler.build_scan_argv(
            ["192.168.1.0/24"], level="quick", save_snapshot=True,
            note="n", notify=True)
        cmd = scheduler.build_task_command("python", ["cli.py"], argv)
        self.assertEqual(
            cmd,
            "python cli.py scan -r 192.168.1.0/24 --level quick "
            "--save-snapshot --note n --notify")

    def test_report_appended_for_scheduled_task(self):
        argv = scheduler.build_scan_argv(["10.0.0.0/24"], notify=False)
        argv += scheduler.build_delivery_argv("exposure")
        cmd = scheduler.build_task_command("python", ["cli.py"], argv)
        self.assertTrue(cmd.endswith("--report exposure"))


class DeliverReportOnScanTest(unittest.TestCase):
    """``scan --report`` 收尾动作：生成报表且**绝不影响扫描退出码**。"""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _args(self, **kw):
        base = {"report": "assets", "report_output": "",
                "db": self.db, "notify": False, "notify_config": None}
        base.update(kw)
        return type("A", (), base)()

    def test_report_generated_after_scan(self):
        out_path = os.path.join(self.tmp, "out.html")
        args = self._args(report_output=out_path)
        cli._deliver_report(args, None)
        self.assertTrue(os.path.exists(out_path))
        with open(out_path, encoding="utf-8") as f:
            self.assertTrue(_is_parseable_html(f.read()))

    def test_no_report_is_noop(self):
        args = self._args(report="")
        cli._deliver_report(args, None)   # 不该抛、也不该建文件
        self.assertEqual(os.listdir(self.tmp), [])

    def test_report_failure_does_not_raise(self):
        """报表生成炸了也必须被吞成 warn（扫描本身不受影响）。"""
        args = self._args(report="assets", report_output=self.tmp)  # 目录当文件写 → 失败
        with mock.patch.object(cli, "warn") as w:
            cli._deliver_report(args, None)   # 不抛
        self.assertTrue(w.called)


if __name__ == "__main__":
    unittest.main()
