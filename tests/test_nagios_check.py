# -*- coding: utf-8 -*-
"""Nagios 插件契约（v2.2 §3.4-a）测试。

验收要求（路线图 §3.4 表）：「drop-in 到 Nagios 能跑出 OK/WARN/CRIT 三态；有测试」。

覆盖：
* 四态齐全（OK / WARNING / CRITICAL / UNKNOWN）与退出码 0/1/2/3；
* **无法判断时报 UNKNOWN，绝不猜成 OK**（没有快照 / 快照过期）；
* 阈值语义（`--crit-new` 优先于 `--warn-new`）；
* 消失设备**只计数不告警**（ARP / 快照间隔会造成假阳性）；
* perfdata 格式 `'label'=value[UOM];warn;crit;min;max`（空字段保留分号）；
* 插件行是**单行 ASCII**（NMS 会解析 / 短信会截断，非 ASCII 会乱码）；
* CLI 子命令的退出码就是插件退出码（与其它子命令语义不同，见模块文档）。
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import cli  # noqa: E402
import db_util  # noqa: E402
import history_store  # noqa: E402
import i18n  # noqa: E402
import nagios_check as nc  # noqa: E402

HOUR = 3600.0


def _dev(ip, mac, hostname="", status="online"):
    return {"ip": ip, "mac": mac, "hostname": hostname, "status": status}


def _snap(db, devices, ts=None):
    return history_store.save_snapshot(devices, ts=ts, db_path=db)


class StateTest(unittest.TestCase):
    """四态与阈值。"""

    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(prefix="nagios_"), "h.db")

    def test_no_snapshot_is_unknown_not_ok(self):
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_UNKNOWN)
        self.assertEqual(r["code"], 3)
        self.assertEqual(r["reason"], nc.REASON_NO_SNAPSHOT)
        self.assertTrue(r["next_step"])          # 必须告诉监控该做什么
        self.assertEqual(r["perfdata"], "")      # 没数据就不给 perfdata
        self.assertIn("|", nc.render_plugin_line(r) + "|")

    def test_stale_data_is_unknown(self):
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01")],
              ts=time.time() - 25 * HOUR)
        r = nc.check_once(db_path=self.db, max_age_hours=24)
        self.assertEqual(r["status"], nc.STATUS_UNKNOWN)
        self.assertEqual(r["reason"], nc.REASON_STALE)
        self.assertIn("25.0h", r["message"])
        self.assertGreaterEqual(r["metrics"]["age"], 25 * HOUR - 60)

    def test_single_snapshot_is_ok_without_baseline(self):
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01")])
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_OK)      # 新部署不该一上线就告警
        self.assertEqual(r["reason"], nc.REASON_NO_BASELINE)
        self.assertEqual(r["metrics"]["devices"], 1)
        self.assertEqual(r["metrics"]["new"], 0)

    def test_no_change_is_ok(self):
        devs = [_dev("10.0.0.1", "AA:BB:CC:00:00:01", "pc1"),
                _dev("10.0.0.2", "AA:BB:CC:00:00:02", "pc2")]
        _snap(self.db, devs, ts=time.time() - 2 * HOUR)
        _snap(self.db, devs)
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_OK)
        self.assertEqual(r["code"], 0)
        self.assertEqual(r["metrics"]["new"], 0)

    def test_new_device_warning_then_critical(self):
        base = [_dev("10.0.0.1", "AA:BB:CC:00:00:01", "pc1")]
        _snap(self.db, base, ts=time.time() - 2 * HOUR)
        _snap(self.db, base + [_dev("10.0.0.2", "AA:BB:CC:00:00:02", "pc2")])
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_WARNING)
        self.assertEqual(r["code"], 1)

        _snap(self.db, base + [
            _dev("10.0.0.%d" % i, "AA:BB:CC:00:00:%02d" % i) for i in range(3, 8)])
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_CRITICAL)
        self.assertEqual(r["code"], 2)
        self.assertIn("crit 5", r["message"])

    def test_thresholds_are_configurable(self):
        base = [_dev("10.0.0.1", "AA:BB:CC:00:00:01")]
        _snap(self.db, base, ts=time.time() - 2 * HOUR)
        _snap(self.db, base + [_dev("10.0.0.2", "AA:BB:CC:00:00:02")])
        # 提高 warn 阈值 ⇒ 1 台新增不算事
        r = nc.check_once(db_path=self.db, warn_new=2, crit_new=9)
        self.assertEqual(r["status"], nc.STATUS_OK)
        # 降低 crit 阈值 ⇒ 直接 CRITICAL
        r = nc.check_once(db_path=self.db, warn_new=1, crit_new=1)
        self.assertEqual(r["status"], nc.STATUS_CRITICAL)

    def test_identity_change_alerts(self):
        base = [_dev("10.0.0.1", "AA:BB:CC:00:00:01", "pc1"),
                _dev("10.0.0.2", "AA:BB:CC:00:00:02", "pc2")]
        _snap(self.db, base, ts=time.time() - 2 * HOUR)
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01", "pc1"),
                        _dev("10.0.0.2", "AA:BB:CC:00:00:99", "pc2")])
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_WARNING)
        self.assertEqual(r["metrics"]["new"], 0)
        self.assertGreaterEqual(r["metrics"]["identity"], 1)

    def test_gone_devices_do_not_alert(self):
        """只消失、无新增 ⇒ 仍 OK（报"设备没了"在快照间隔下必然假阳性）。"""
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01"),
                        _dev("10.0.0.2", "AA:BB:CC:00:00:02")],
              ts=time.time() - 2 * HOUR)
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01")])
        r = nc.check_once(db_path=self.db)
        self.assertEqual(r["status"], nc.STATUS_OK)
        self.assertEqual(r["metrics"]["gone"], 1)

    def test_exit_codes_follow_nagios_convention(self):
        self.assertEqual(nc.EXIT_CODES, {
            nc.STATUS_OK: 0, nc.STATUS_WARNING: 1,
            nc.STATUS_CRITICAL: 2, nc.STATUS_UNKNOWN: 3})


class PerfdataTest(unittest.TestCase):
    """perfdata 是给 NMS 画图用的，格式错一个分号就画错。"""

    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(prefix="nagios_"), "h.db")

    def test_perfdata_keeps_empty_fields(self):
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01")])
        r = nc.check_once(db_path=self.db)
        self.assertIn("'devices'=1;;;0;", r["perfdata"])
        self.assertIn("'age'=0s;;;0;", r["perfdata"])   # UOM = 秒

    def test_thresholds_land_in_the_right_slots(self):
        base = [_dev("10.0.0.1", "AA:BB:CC:00:00:01")]
        _snap(self.db, base, ts=time.time() - 2 * HOUR)
        _snap(self.db, base + [_dev("10.0.0.2", "AA:BB:CC:00:00:02")])
        r = nc.check_once(db_path=self.db, warn_new=2, crit_new=4,
                          warn_identity=1, crit_identity=3)
        self.assertIn("'new'=1;2;4;0;", r["perfdata"])
        self.assertIn("'identity'=0;1;3;0;", r["perfdata"])

    def test_plugin_line_is_single_line_ascii(self):
        """插件行必须单行、纯 ASCII —— NMS 解析 / 短信网关都会截断非 ASCII。"""
        base = [_dev("10.0.0.1", "AA:BB:CC:00:00:01")]
        _snap(self.db, base, ts=time.time() - 2 * HOUR)
        _snap(self.db, base + [_dev("10.0.0.2", "AA:BB:CC:00:00:02")])
        line = nc.render_plugin_line(nc.check_once(db_path=self.db))
        self.assertNotIn("\n", line)
        self.assertTrue(all(ord(ch) < 128 for ch in line), line)

    def test_plugin_line_has_status_and_pipe(self):
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01")])
        line = nc.render_plugin_line(nc.check_once(db_path=self.db))
        self.assertTrue(line.startswith("OK - "), line)
        self.assertIn(" | ", line)

    def test_next_step_is_appended_to_the_line(self):
        line = nc.render_plugin_line(nc.check_once(db_path=self.db))
        self.assertTrue(line.startswith("UNKNOWN - "), line)
        self.assertIn("[next:", line)
        self.assertNotIn(" | ", line)      # 无数据 ⇒ 无 perfdata ⇒ 无竖线


class CliNagiosTest(unittest.TestCase):
    """CLI 子命令：退出码就是插件退出码（本子命令专用语义）。"""

    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(prefix="nagios_cli_"), "h.db")

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        lang = i18n.current_lang()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        finally:
            i18n.init(lang)
        return code, out.getvalue()

    def test_parser_defaults(self):
        args = cli.build_parser().parse_args(["nagios"])
        self.assertEqual(args.max_age_hours, 24.0)
        self.assertEqual((args.warn_new, args.crit_new), (1, 5))
        self.assertEqual((args.warn_identity, args.crit_identity), (1, 3))
        self.assertEqual(args.format, "plugin")
        self.assertIs(args.func, cli.cmd_nagios)

    def test_exit_code_is_the_plugin_code(self):
        code, out = self._run(["nagios", "--db", self.db])
        self.assertEqual(code, 3)                 # UNKNOWN：没有快照
        self.assertTrue(out.startswith("UNKNOWN - "), out)

        base = [_dev("10.0.0.1", "AA:BB:CC:00:00:01")]
        _snap(self.db, base, ts=time.time() - 2 * HOUR)
        _snap(self.db, base + [_dev("10.0.0.2", "AA:BB:CC:00:00:02")])
        code, out = self._run(["nagios", "--db", self.db])
        self.assertEqual(code, 1)                 # WARNING
        self.assertTrue(out.startswith("WARNING - "), out)

        code, out = self._run(["nagios", "--db", self.db, "--crit-new", "1"])
        self.assertEqual(code, 2)                 # CRITICAL
        self.assertTrue(out.startswith("CRITICAL - "), out)

    def test_json_format_keys_are_english(self):
        _snap(self.db, [_dev("10.0.0.1", "AA:BB:CC:00:00:01")])
        code, out = self._run(["nagios", "--db", self.db, "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        for key in ("status", "code", "reason", "message", "perfdata", "metrics"):
            self.assertIn(key, data)
        self.assertEqual(data["code"], 0)
        self.assertEqual(set(data["metrics"]),
                         {"devices", "new", "gone", "identity", "age"})

    def test_output_file(self):
        path = os.path.join(tempfile.mkdtemp(), "plugin.txt")
        code, _ = self._run(["nagios", "--db", self.db, "-o", path])
        self.assertEqual(code, 3)
        with io.open(path, encoding="utf-8") as f:
            self.assertTrue(f.read().startswith("UNKNOWN - "))


def tearDownModule():
    """收尾关掉单例连接（每个用例一个临时库，否则退出时刷 ResourceWarning）。"""
    db_util.close_all()


if __name__ == "__main__":
    unittest.main()
