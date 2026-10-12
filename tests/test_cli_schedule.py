# -*- coding: utf-8 -*-
"""``cli.py schedule`` 子命令测试。

覆盖点：
1. 三种动作（register / unregister / status）的分派与退出码；
2. **参数校验必须发生在触碰系统调度器之前**（非法时间/频率不能把命令
   带到 schtasks 才失败）—— 用 mock 断言 register 未被调用；
3. 计划任务的命令行要把范围、级别、快照、告警、db 等参数**如实固化**进去，
   否则定时任务运行时用的默认数据目录会与用户手动扫描的库对不上；
4. 平台不支持时给出干净的错误（退出码 1），而不是异常。

本测试全程 mock ``scheduler`` 的外部动作，**绝不真的注册/删除系统计划任务**。
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


class ScheduleDispatchTest(unittest.TestCase):

    def test_status_registered(self):
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "query", return_value=(True, "TaskName: X")):
            code, _out, err = _run_main(["schedule", "--status"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("已注册", err)

    def test_status_not_registered(self):
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "query", return_value=(False, "")):
            code, _out, err = _run_main(["schedule", "--status"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("未注册", err)

    def test_unregister_success(self):
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "unregister", return_value=(True, "")) as m:
            code, _out, err = _run_main(["schedule", "--unregister"])
        self.assertEqual(code, cli.EXIT_OK)
        m.assert_called_once()
        self.assertIn("已卸载", err)

    def test_unregister_failure_exit_1(self):
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "unregister", return_value=(False, "拒绝访问")):
            code, _out, err = _run_main(["schedule", "--unregister"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("拒绝访问", err)

    def test_unsupported_platform(self):
        with mock.patch.object(scheduler, "is_supported", return_value=False):
            code, _out, err = _run_main(["schedule", "--status"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("未找到可用的调度命令", err)

    def test_action_is_required(self):
        """三个动作互斥且必选：一个都不给时 argparse 直接退出。"""
        with self.assertRaises(SystemExit):
            _run_main(["schedule"])


class ScheduleRegisterTest(unittest.TestCase):

    def _register(self, extra):
        argv = ["schedule", "--register", "-r", "192.168.1.0/24"] + extra
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "default_executable",
                               return_value=("python", ["cli.py"])), \
             mock.patch.object(scheduler, "register",
                               return_value=(True, "")) as m:
            code, _out, err = _run_main(argv)
        return code, err, m

    def test_requires_range(self):
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "register") as m:
            code, _out, err = _run_main(["schedule", "--register"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("需要至少一个", err)
        m.assert_not_called()

    def test_invalid_time_rejected_before_register(self):
        """非法 --at 必须在本机就拦下，绝不把命令带到 schtasks 才失败。"""
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "register") as m:
            code, _out, err = _run_main(
                ["schedule", "--register", "-r", "10.0.0.0/24",
                 "--freq", "daily", "--at", "25:99"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("HH:MM", err)
        m.assert_not_called()

    def test_register_builds_command_with_all_args(self):
        code, err, m = self._register(
            ["--level", "standard", "--note", "夜间巡检",
             "--db", "D:/data/h.db", "--quiet", "--highest"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("已注册计划任务", err)

        args, kwargs = m.call_args
        name, command = args[0], args[1]
        self.assertEqual(name, scheduler.DEFAULT_TASK_NAME)
        # 范围 / 级别 / 快照 / 告警 / db / 静默 都要固化进命令行
        self.assertIn("192.168.1.0/24", command)
        self.assertIn("--level standard", command)
        self.assertIn("--save-snapshot", command)
        self.assertIn("--notify", command)
        self.assertIn("D:/data/h.db", command)
        self.assertIn("--quiet", command)
        self.assertTrue(kwargs.get("run_highest"))

    def test_register_no_notify(self):
        _code, _err, m = self._register(["--no-notify"])
        command = m.call_args[0][1]
        self.assertNotIn("--notify", command)
        self.assertIn("--save-snapshot", command)

    def test_register_failure_exit_1(self):
        with mock.patch.object(scheduler, "is_supported", return_value=True), \
             mock.patch.object(scheduler, "default_executable",
                               return_value=("python", ["cli.py"])), \
             mock.patch.object(scheduler, "register",
                               return_value=(False, "拒绝访问")):
            code, _out, err = _run_main(
                ["schedule", "--register", "-r", "10.0.0.0/24"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("注册计划任务失败", err)

    def test_custom_name(self):
        _code, _err, m = self._register(["--name", "夜班巡检"])
        self.assertEqual(m.call_args[0][0], "夜班巡检")

    # ── 报表投递（v2.0 §2.2）：纯追加，不破坏既有命令行 ──
    def test_report_flag_appended_to_command(self):
        _code, _err, m = self._register(
            ["--report", "changes", "--report-output", "D:/r/chg.html"])
        command = m.call_args[0][1]
        self.assertIn("--report changes", command)
        self.assertIn("--report-output D:/r/chg.html", command)
        # 扫描本身仍在（报表是收尾动作，不取代扫描）
        self.assertIn("--save-snapshot", command)

    def test_no_report_by_default_keeps_command_unchanged(self):
        """不指定 --report 时命令行里**不能**出现报表参数（老行为逐字节不变）。"""
        _code, _err, m = self._register([])
        self.assertNotIn("--report", m.call_args[0][1])


class DescribeScheduleTest(unittest.TestCase):

    def _args(self, **kw):
        base = {"freq": "daily", "interval": 1, "at": "09:00"}
        base.update(kw)
        return type("A", (), base)()

    def test_daily(self):
        self.assertIn("每天", cli._describe_schedule(self._args(freq="daily", at="08:30")))

    def test_hourly(self):
        self.assertIn("小时", cli._describe_schedule(self._args(freq="hourly", interval=2)))

    def test_minute(self):
        self.assertIn("分钟", cli._describe_schedule(self._args(freq="minute", interval=30)))


if __name__ == "__main__":
    unittest.main()
