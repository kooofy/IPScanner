# -*- coding: utf-8 -*-
"""CLI 的 SNMPv3 参数测试。

覆盖点：
1. 口令**只从环境变量读取** —— argv 里不存在任何接受口令的选项；
2. 参数组装（"none" → 空串、自定义环境变量名）；
3. 非法组合快速失败并返回退出码 1，且**不发起扫描**；
4. 错误提示不得指错方向（priv 没配 auth ≠ priv 口令缺失）；
5. 指定 --snmpv3-user 会自动把 SNMP 加进协议列表（否则引擎根本不走 SNMP）。

注意：除协议列表外，本测试**不发起真实网络扫描** —— NetworkScanner 被打桩。
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
import scanner
from scanner.snmp_v3 import SnmpV3User


def _parse(argv):
    return cli.build_parser().parse_args(argv)


def _run_main(argv):
    """运行 cli.main，返回 (exit_code, stdout, stderr)。"""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class _FakeScanner:
    """记录 scan() 收到的关键字参数，不联网。"""

    last_kwargs = None

    def __init__(self):
        self.warnings = []

    def scan(self, **kwargs):
        _FakeScanner.last_kwargs = kwargs
        return []

    def stop(self):
        pass


class ArgSurfaceTest(unittest.TestCase):
    """argv 里不允许出现任何承载口令的选项。"""

    def test_scan_accepts_snmpv3_switches(self):
        args = _parse(["scan", "-r", "10.0.0.0/24",
                       "--snmpv3-user", "monitor",
                       "--snmpv3-auth", "sha", "--snmpv3-priv", "aes"])
        self.assertEqual(args.snmpv3_user, "monitor")
        self.assertEqual(args.snmpv3_auth, "sha")
        self.assertEqual(args.snmpv3_priv, "aes")

    def test_diff_also_accepts_snmpv3_switches(self):
        """diff 会自己发起扫描，因此同样需要 v3 参数。"""
        args = _parse(["diff", "-r", "10.0.0.0/24", "--snmpv3-user", "monitor"])
        self.assertEqual(args.snmpv3_user, "monitor")

    def test_no_option_accepts_a_passphrase(self):
        """回归守卫：口令绝不能有命令行入口 —— argv 会出现在进程列表里。

        一旦有人为了"方便"加上 --snmpv3-auth-key，这条会立刻失败。
        """
        for bad in ("--snmpv3-auth-key", "--snmpv3-priv-key",
                    "--snmpv3-password", "--snmpv3-key"):
            with self.subTest(option=bad):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    with self.assertRaises(SystemExit):
                        _parse(["scan", "-r", "10.0.0.0/24", bad, "secret"])

    def test_history_does_not_offer_snmpv3(self):
        """history 不发起扫描，不应挂 v3 参数（避免误导）。"""
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit):
                _parse(["history", "--snmpv3-user", "monitor"])

    def test_default_key_env_names(self):
        args = _parse(["scan", "-r", "10.0.0.0/24"])
        self.assertEqual(args.snmpv3_auth_env, cli.SNMPV3_AUTH_KEY_ENV)
        self.assertEqual(args.snmpv3_priv_env, cli.SNMPV3_PRIV_KEY_ENV)


class ResolveSnmpV3Test(unittest.TestCase):

    def test_not_enabled_returns_none(self):
        args = _parse(["scan", "-r", "10.0.0.0/24"])
        self.assertEqual(cli._resolve_snmp_v3(args), (None, None))

    def test_none_maps_to_empty_protocol(self):
        """CLI 上写 none，内部必须是空串（语言无关的规范值）。"""
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "u"])
        user, err = cli._resolve_snmp_v3(args)
        self.assertEqual(err, None)
        self.assertEqual(user.auth_proto, "")
        self.assertEqual(user.priv_proto, "")
        self.assertEqual(user.security_level(), "noAuthNoPriv")

    def test_keys_read_from_environment(self):
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "monitor",
                       "--snmpv3-auth", "sha", "--snmpv3-priv", "aes"])
        env = {cli.SNMPV3_AUTH_KEY_ENV: "auth-secret",
               cli.SNMPV3_PRIV_KEY_ENV: "priv-secret"}
        with mock.patch.dict(os.environ, env, clear=False):
            user, err = cli._resolve_snmp_v3(args)
        self.assertEqual(err, None)
        self.assertIsInstance(user, SnmpV3User)
        self.assertEqual(user.username, "monitor")
        self.assertEqual(user.auth_proto, "sha")
        self.assertEqual(user.auth_key, "auth-secret")
        self.assertEqual(user.priv_proto, "aes")
        self.assertEqual(user.priv_key, "priv-secret")
        self.assertEqual(user.security_level(), "authPriv")

    def test_custom_env_var_names(self):
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "u",
                       "--snmpv3-auth", "md5",
                       "--snmpv3-auth-env", "MY_AUTH_KEY"])
        with mock.patch.dict(os.environ, {"MY_AUTH_KEY": "hunter2"}, clear=False):
            user, err = cli._resolve_snmp_v3(args)
        self.assertEqual(err, None)
        self.assertEqual(user.auth_key, "hunter2")

    def test_missing_auth_key_names_the_env_var(self):
        """只报「必须提供认证密码」不够 —— 要告诉用户去翻哪个变量。"""
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "u",
                       "--snmpv3-auth", "sha"])
        with mock.patch.dict(os.environ, {cli.SNMPV3_AUTH_KEY_ENV: ""}, clear=False):
            user, err = cli._resolve_snmp_v3(args)
        self.assertIsNone(user)
        self.assertIn(cli.SNMPV3_AUTH_KEY_ENV, err)

    def test_priv_without_auth_does_not_blame_the_priv_key(self):
        """回归守卫：结构性错误不得被误报成「口令缺失」。

        `--snmpv3-priv aes` 而不给 auth 时，priv_key 也是空的；
        早期实现会追加「环境变量 IPSCANNER_SNMPV3_PRIV_KEY 为空」，
        把用户引向环境变量，而真正的问题是 priv 必须建立在 auth 之上。
        """
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "u",
                       "--snmpv3-priv", "aes"])
        with mock.patch.dict(os.environ, {cli.SNMPV3_PRIV_KEY_ENV: ""}, clear=False):
            user, err = cli._resolve_snmp_v3(args)
        self.assertIsNone(user)
        self.assertNotIn(cli.SNMPV3_PRIV_KEY_ENV, err)
        self.assertNotIn("口令", err)

    def test_des_is_rejected_with_a_reason(self):
        """DES 保留在候选里，是为了给出「为什么不行」，而不是 argparse 的 invalid choice。"""
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "u",
                       "--snmpv3-auth", "sha", "--snmpv3-priv", "des"])
        env = {cli.SNMPV3_AUTH_KEY_ENV: "a", cli.SNMPV3_PRIV_KEY_ENV: "b"}
        with mock.patch.dict(os.environ, env, clear=False):
            user, err = cli._resolve_snmp_v3(args)
        self.assertIsNone(user)
        self.assertIn("AES", err)


class ProtocolEnablingTest(unittest.TestCase):
    """配了 v3 就必须真的走 SNMP —— 否则是「静默无效」。"""

    def setUp(self):
        _FakeScanner.last_kwargs = None
        self._patch = mock.patch.object(scanner, "NetworkScanner", _FakeScanner)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_snmpv3_user_auto_enables_snmp_protocol(self):
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "monitor"])
        with mock.patch.dict(os.environ, {}, clear=False):
            cli._run_scan(args)
        protos = [p.upper() for p in (_FakeScanner.last_kwargs["protocols"] or [])]
        self.assertIn("SNMP", protos)

    def test_existing_protocols_are_preserved(self):
        """追加而不是替换 —— 用户写的 HTTP 不能被吞掉。"""
        args = _parse(["scan", "-r", "10.0.0.0/24", "--protocols", "HTTP",
                       "--snmpv3-user", "monitor"])
        with mock.patch.dict(os.environ, {}, clear=False):
            cli._run_scan(args)
        protos = [p.upper() for p in (_FakeScanner.last_kwargs["protocols"] or [])]
        self.assertIn("HTTP", protos)
        self.assertIn("SNMP", protos)

    def test_user_object_reaches_the_engine(self):
        args = _parse(["scan", "-r", "10.0.0.0/24", "--snmpv3-user", "monitor",
                       "--snmpv3-auth", "sha"])
        env = {cli.SNMPV3_AUTH_KEY_ENV: "secret"}
        with mock.patch.dict(os.environ, env, clear=False):
            cli._run_scan(args)
        user = _FakeScanner.last_kwargs["snmp_v3_user"]
        self.assertIsInstance(user, SnmpV3User)
        self.assertEqual(user.username, "monitor")

    def test_no_v3_user_means_no_snmp_and_none_user(self):
        """不配 v3 时行为不变：不擅自打开 SNMP，且 user 为 None。"""
        args = _parse(["scan", "-r", "10.0.0.0/24", "--protocols", "HTTP"])
        cli._run_scan(args)
        self.assertIsNone(_FakeScanner.last_kwargs["snmp_v3_user"])
        protos = [p.upper() for p in (_FakeScanner.last_kwargs["protocols"] or [])]
        self.assertNotIn("SNMP", protos)


class ExitCodeTest(unittest.TestCase):
    """参数非法必须在**扫描之前**失败，并返回退出码 1。"""

    def test_bad_credentials_exit_1_without_scanning(self):
        called = []

        class _Boom:
            def __init__(self):
                called.append(True)

        with mock.patch.object(scanner, "NetworkScanner", _Boom):
            with mock.patch.dict(os.environ, {cli.SNMPV3_AUTH_KEY_ENV: ""}, clear=False):
                code, _out, err = _run_main(
                    ["scan", "-r", "127.0.0.1", "--snmpv3-user", "u",
                     "--snmpv3-auth", "sha", "-q"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(called, [], "参数非法时不应创建扫描器")
        self.assertIn(cli.SNMPV3_AUTH_KEY_ENV, err)


if __name__ == "__main__":
    unittest.main()
