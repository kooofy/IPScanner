# -*- coding: utf-8 -*-
"""定时扫描调度的单元测试。

只测**纯函数**（命令构造）：真正去改系统计划任务 / crontab 是难以在 CI 里
验证、也难以回滚的操作，因此 register/unregister 的实际执行不进测试，
但"它们会执行什么命令"必须被逐字锁死 —— 这是最容易写错、
又最难在事后发现的地方（比如把 /MO 写成 /M，schtasks 会静默用默认频率）。
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scheduler as S


class ValidateTimeTest(unittest.TestCase):

    def test_default(self):
        self.assertEqual(S._validate_time(""), "09:00")
        self.assertEqual(S._validate_time(None), "09:00")

    def test_normalizes(self):
        self.assertEqual(S._validate_time("9:5"), "09:05")
        self.assertEqual(S._validate_time(" 23:59 "), "23:59")

    def test_rejects_garbage(self):
        for bad in ("9", "9:5:1", "abc", "25:00", "09:60", "-1:00"):
            with self.assertRaises(S.ScheduleError, msg=bad):
                S._validate_time(bad)


class SchtasksCreateTest(unittest.TestCase):

    def test_daily_uses_start_time(self):
        argv = S.build_schtasks_create("T", "cmd /x", S.FREQ_DAILY, at="07:30")
        self.assertEqual(argv[:2], ["schtasks", "/Create"])
        self.assertIn("/TN", argv)
        self.assertEqual(argv[argv.index("/TN") + 1], "T")
        self.assertEqual(argv[argv.index("/TR") + 1], "cmd /x")
        self.assertEqual(argv[argv.index("/SC") + 1], "DAILY")
        self.assertEqual(argv[argv.index("/ST") + 1], "07:30")
        self.assertNotIn("/MO", argv)

    def test_minute_uses_interval(self):
        argv = S.build_schtasks_create("T", "c", S.FREQ_MINUTE, interval=30)
        self.assertEqual(argv[argv.index("/SC") + 1], "MINUTE")
        self.assertEqual(argv[argv.index("/MO") + 1], "30")
        self.assertNotIn("/ST", argv)

    def test_hourly_uses_interval(self):
        argv = S.build_schtasks_create("T", "c", S.FREQ_HOURLY, interval=6)
        self.assertEqual(argv[argv.index("/SC") + 1], "HOURLY")
        self.assertEqual(argv[argv.index("/MO") + 1], "6")

    def test_interval_is_clamped_to_schtasks_limits(self):
        """schtasks 对 /MO 有硬性范围，越界会直接报错而不是取默认值。"""
        self.assertEqual(
            S.build_schtasks_create("T", "c", S.FREQ_MINUTE, interval=99999)
            [S.build_schtasks_create("T", "c", S.FREQ_MINUTE).index("/MO") + 1], "1439")
        self.assertEqual(
            S.build_schtasks_create("T", "c", S.FREQ_HOURLY, interval=0)
            [S.build_schtasks_create("T", "c", S.FREQ_HOURLY).index("/MO") + 1], "1")

    def test_run_highest_adds_privilege_flag(self):
        """SYN 扫描需要管理员，否则计划任务会静默回退 connect。"""
        argv = S.build_schtasks_create("T", "c", S.FREQ_DAILY, run_highest=True)
        self.assertEqual(argv[argv.index("/RL") + 1], "HIGHEST")
        self.assertNotIn("/RL",
                         S.build_schtasks_create("T", "c", S.FREQ_DAILY))

    def test_force_flag_present(self):
        """/F 让重复注册成为幂等的"覆盖"，而不是弹交互式确认。"""
        self.assertIn("/F", S.build_schtasks_create("T", "c", S.FREQ_DAILY))

    def test_rejects_bad_input(self):
        with self.assertRaises(S.ScheduleError):
            S.build_schtasks_create("", "c", S.FREQ_DAILY)
        with self.assertRaises(S.ScheduleError):
            S.build_schtasks_create("T", "  ", S.FREQ_DAILY)
        with self.assertRaises(S.ScheduleError):
            S.build_schtasks_create("T", "c", "fortnightly")

    def test_delete_and_query(self):
        self.assertEqual(S.build_schtasks_delete("T"),
                         ["schtasks", "/Delete", "/TN", "T", "/F"])
        self.assertEqual(S.build_schtasks_query("T"),
                         ["schtasks", "/Query", "/TN", "T"])


class CronLineTest(unittest.TestCase):

    def test_minute(self):
        self.assertEqual(S.build_cron_line("CMD", S.FREQ_MINUTE, 30),
                         "*/30 * * * * CMD")

    def test_hourly(self):
        self.assertEqual(S.build_cron_line("CMD", S.FREQ_HOURLY, 6),
                         "0 */6 * * * CMD")

    def test_daily_strips_leading_zeros(self):
        """cron 的分钟/小时字段不认前导零之外的写法，但 09 在某些实现里有歧义，
        统一输出无前导零的数值最稳。"""
        self.assertEqual(S.build_cron_line("CMD", S.FREQ_DAILY, at="09:05"),
                         "5 9 * * * CMD")

    def test_rejects_bad_input(self):
        with self.assertRaises(S.ScheduleError):
            S.build_cron_line("", S.FREQ_DAILY)
        with self.assertRaises(S.ScheduleError):
            S.build_cron_line("CMD", "yearly")

    def test_block_has_matching_markers(self):
        block = S.build_cron_block("CMD", S.FREQ_DAILY, tag="MyTask")
        self.assertIn("# >>> MyTask >>>", block)
        self.assertIn("# <<< MyTask <<<", block)
        self.assertIn("CMD", block)


class TaskCommandTest(unittest.TestCase):

    def test_quotes_executable_with_spaces(self):
        cmd = S.build_task_command(r"C:\Program Files\IPScanner\cli.exe", [],
                                   ["scan", "-r", "10.0.0.0/24"])
        self.assertTrue(cmd.startswith('"C:\\Program Files\\IPScanner\\cli.exe"'))
        self.assertIn("scan", cmd)

    def test_no_quotes_when_not_needed(self):
        cmd = S.build_task_command("/usr/bin/python3", ["cli.py"], ["scan"])
        self.assertTrue(cmd.startswith("/usr/bin/python3"))

    def test_prefix_is_kept(self):
        cmd = S.build_task_command("/usr/bin/python3", ["/opt/ip/cli.py"], ["scan"])
        self.assertIn("/opt/ip/cli.py", cmd)


class ScanArgvTest(unittest.TestCase):

    def test_includes_ranges_and_snapshot(self):
        argv = S.build_scan_argv(["10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual(argv.count("-r"), 2)
        self.assertIn("--save-snapshot", argv)
        self.assertIn("--notify", argv)
        self.assertIn("--level", argv)

    def test_blank_ranges_are_dropped(self):
        argv = S.build_scan_argv(["10.0.0.0/24", "", "   "])
        self.assertEqual(argv.count("-r"), 1)

    def test_note_is_passed(self):
        argv = S.build_scan_argv(["10.0.0.0/24"], note="夜间巡检")
        self.assertIn("夜间巡检", argv)

    def test_notify_can_be_disabled(self):
        argv = S.build_scan_argv(["10.0.0.0/24"], notify=False)
        self.assertNotIn("--notify", argv)


class DefaultExecutableTest(unittest.TestCase):

    def test_returns_pair(self):
        exe, prefix = S.default_executable()
        self.assertTrue(exe)
        self.assertIsInstance(prefix, list)

    def test_source_mode_points_at_cli_py(self):
        if getattr(sys, "frozen", False):
            self.skipTest("打包态下不适用")
        _, prefix = S.default_executable()
        self.assertEqual(len(prefix), 1)
        self.assertTrue(prefix[0].endswith("cli.py"))

    def test_is_supported_returns_bool(self):
        self.assertIsInstance(S.is_supported(), bool)


class ValidateScheduleTest(unittest.TestCase):
    """``validate_schedule`` 是 CLI 触碰系统调度器前的统一闸门。"""

    def test_accepts_valid(self):
        S.validate_schedule(S.FREQ_DAILY, at="09:00")
        S.validate_schedule(S.FREQ_HOURLY, interval=2)
        S.validate_schedule(S.FREQ_MINUTE, interval=30)

    def test_rejects_bad_freq(self):
        with self.assertRaises(S.ScheduleError):
            S.validate_schedule("weekly")

    def test_rejects_bad_time_only_for_daily(self):
        with self.assertRaises(S.ScheduleError):
            S.validate_schedule(S.FREQ_DAILY, at="99:00")
        # 非 daily 不看 --at：给了个坏值也不应误报
        S.validate_schedule(S.FREQ_HOURLY, interval=1, at="garbage")


class RunResilienceTest(unittest.TestCase):
    """``_run`` 必须把"命令起不来"转成 (False, 原因)，而不是抛异常。

    真机上最常见的两种起不来：被安全策略/组策略拦截（PermissionError）、
    命令不存在（FileNotFoundError）。二者都是 OSError 家族。
    """

    def test_oserror_is_swallowed(self):
        import subprocess
        with mock.patch.object(
                subprocess, "run",
                side_effect=PermissionError("[WinError 5] 拒绝访问")):
            ok, msg = S._run(["schtasks", "/Query", "/TN", "x"])
        self.assertFalse(ok)
        self.assertIn("拒绝访问", msg)

    def test_file_not_found(self):
        import subprocess
        with mock.patch.object(
                subprocess, "run", side_effect=FileNotFoundError()):
            ok, msg = S._run(["schtasks"])
        self.assertFalse(ok)
        self.assertTrue(msg)


if __name__ == "__main__":
    unittest.main()
