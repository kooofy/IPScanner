# -*- coding: utf-8 -*-
"""凭据配置档（v2.0 §2.3）验收测试。

覆盖点（对应 ROADMAP §3 2.3 验收清单）：
1. ``for_target()`` 的**最长前缀匹配**（更具体的网段优先）；
2. 无匹配 → 返回 ``None``，**绝不回落 ``public``**（本项的核心承诺）；
3. ``env:VAR`` 间接引用能解析，且**配置文件里不含明文口令**（文本断言）；
4. **单档 / 无档配置下行为与现状逐字节一致**（老用户零感知）。

另覆盖：配置读写容错（缺失/损坏不抛）、协议过滤、多网段作用域、
坏 CIDR 跳过并留痕、``cli credentials`` 子命令输出（不回显明文）。
"""
import contextlib
import io
import ipaddress
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
import credentials
import i18n
import scanner.engine as engine


def _run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    lang = i18n.current_lang()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
    finally:
        i18n.init(lang)
    return code, out.getvalue(), err.getvalue()


class LongestPrefixTest(unittest.TestCase):
    """"最长前缀匹配"是 §2.3 的核心语义。"""

    def setUp(self):
        self.profiles = [
            credentials.Credential(name="broad", scope=["10.1.0.0/16"],
                                   protocol="snmp_v2c", community="broad"),
            credentials.Credential(name="narrow", scope=["10.1.2.0/24"],
                                   protocol="snmp_v2c", community="narrow"),
        ]

    def test_specific_network_wins(self):
        # 10.1.2.5 同时落在 /16 与 /24 内，必须命中更具体的 /24
        cred, err = credentials.select_for_target("10.1.2.5", self.profiles)
        self.assertIsNotNone(cred)
        self.assertEqual(cred.name, "narrow")
        self.assertIsNone(err)

    def test_only_broad_matches_when_outside_narrow(self):
        cred, _ = credentials.select_for_target("10.1.9.9", self.profiles)
        self.assertEqual(cred.name, "broad")

    def test_order_independent(self):
        # 反过来排，结果不变（选的是前缀长度，不是"第一个命中"）
        rev = list(reversed(self.profiles))
        cred, _ = credentials.select_for_target("10.1.2.5", rev)
        self.assertEqual(cred.name, "narrow")

    def test_multi_scope_matches_any(self):
        cred = credentials.Credential(name="m", scope=["10.5.0.0/16", "172.16.0.0/12"],
                                      protocol="snmp_v2c", community="x")
        self.assertEqual(cred.match_prefixlen(
            ipaddress.ip_address("172.20.1.1")), 12)
        self.assertEqual(cred.match_prefixlen(
            ipaddress.ip_address("10.5.9.9")), 16)


class NoMatchNoFallbackTest(unittest.TestCase):
    """无匹配必须返回 None —— 绝不回落 public。"""

    def test_uncovered_returns_none(self):
        profiles = [credentials.Credential(name="p", scope=["10.0.0.0/8"],
                                           protocol="snmp_v2c", community="x")]
        cred, reason = credentials.select_for_target("192.168.1.1", profiles)
        self.assertIsNone(cred)
        self.assertIn("没有凭据档覆盖", reason)

    def test_empty_book_returns_none(self):
        cred, reason = credentials.select_for_target("10.0.0.1", [])
        self.assertIsNone(cred)
        self.assertTrue(reason)

    def test_invalid_ip_returns_none(self):
        cred, reason = credentials.select_for_target("not-an-ip", [])
        self.assertIsNone(cred)
        self.assertIn("无效", reason)

    def test_engine_does_not_fall_back_to_public(self):
        """引擎层：档册存在但未覆盖目标 → 明确报错，不去撞 public。"""
        book = credentials.CredentialBook([
            credentials.Credential(name="only10", scope=["10.0.0.0/8"],
                                   protocol="snmp_v2c", community="x")])
        with mock.patch.object(engine, "snmp_get_system") as m:
            info, err = engine._identify_snmp("192.168.1.5", None, book)
        self.assertIsNone(info)
        self.assertIn("没有凭据档覆盖", err)
        # 关键：**没有发起任何 SNMP 请求**
        m.assert_not_called()

    def test_engine_empty_book_reports(self):
        with mock.patch.object(engine, "snmp_get_system") as m:
            info, err = engine._identify_snmp("10.0.0.1", None,
                                              credentials.CredentialBook([]))
        self.assertIsNone(info)
        self.assertIn("没有配置任何凭据档", err)
        m.assert_not_called()

    def test_protocol_filter_no_match(self):
        profiles = [credentials.Credential(name="w", scope=["10.0.0.0/8"],
                                           protocol="wmi", username="a")]
        cred, reason = credentials.select_for_target("10.0.0.1", profiles,
                                                     protocol="snmp_v2c")
        self.assertIsNone(cred)
        self.assertIn("SNMP v2c", reason)


class EnvIndirectionTest(unittest.TestCase):
    """env:VAR 间接引用必须能解析，且明文不落盘。"""

    def test_resolve_env(self):
        with mock.patch.dict(os.environ, {"TEST_COMM": "s3cret"}):
            cred = credentials.Credential(name="a", scope=["10.0.0.0/8"],
                                          protocol="snmp_v2c",
                                          community="env:TEST_COMM")
            self.assertEqual(cred.resolved_community(), "s3cret")

    def test_env_missing_is_empty(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            cred = credentials.Credential(name="a", scope=["10.0.0.0/8"],
                                          protocol="snmp_v2c",
                                          community="env:NOPE_MISSING")
            self.assertEqual(cred.resolved_community(), "")

    def test_plaintext_passthrough(self):
        cred = credentials.Credential(name="a", scope=["10.0.0.0/8"],
                                      protocol="snmp_v2c", community="plain")
        self.assertEqual(cred.resolved_community(), "plain")

    def test_config_file_has_no_plaintext_when_using_env(self):
        """写盘后文件文本里**不得**出现真实口令。"""
        secret = "TOP_SECRET_VALUE_XYZ"
        with mock.patch.dict(os.environ, {"CRED_ENV_REF": secret}):
            profiles = [credentials.Credential(
                name="a", scope=["10.0.0.0/8"], protocol="snmp_v2c",
                community="env:CRED_ENV_REF")]
            with tempfile.TemporaryDirectory() as td:
                p = os.path.join(td, "credentials.json")
                ok, err = credentials.save_profiles(profiles, p)
                self.assertTrue(ok, err)
                with io.open(p, encoding="utf-8") as f:
                    text = f.read()
        self.assertNotIn(secret, text)          # 明文绝不落盘
        self.assertIn("env:CRED_ENV_REF", text)  # 引用原样保留


class ReadWriteRoundTripTest(unittest.TestCase):

    def test_round_trip(self):
        profiles = [
            credentials.Credential(name="a", scope=["10.0.0.0/8"],
                                   protocol="snmp_v2c", community="env:X"),
            credentials.Credential(name="b", scope=["10.1.0.0/16", "10.2.0.0/16"],
                                   protocol="snmp_v3", username="u",
                                   auth_proto="sha", auth_key="env:A",
                                   priv_proto="aes", priv_key="env:P"),
        ]
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            ok, err = credentials.save_profiles(profiles, p)
            self.assertTrue(ok, err)
            loaded = credentials.load_profiles(p)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].name, "a")
        self.assertEqual(loaded[0].community, "env:X")   # 引用未被解析
        self.assertEqual(loaded[1].scope, ["10.1.0.0/16", "10.2.0.0/16"])
        self.assertEqual(loaded[1].protocol, "snmp_v3")
        self.assertEqual(loaded[1].auth_key, "env:A")

    def test_missing_file_returns_empty(self):
        self.assertEqual(
            credentials.load_profiles("/nonexistent/path/credentials.json"), [])

    def test_corrupt_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                f.write("{not valid json")
            self.assertEqual(credentials.load_profiles(p), [])

    def test_wrong_structure_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": "not-a-list"}, f)
            self.assertEqual(credentials.load_profiles(p), [])

    def test_bad_cidr_skipped_not_fatal(self):
        profiles = [credentials.Credential(
            name="p", scope=["10.0.0.0/8", "garbage", "10.1.0.0/16"],
            protocol="snmp_v2c", community="x")]
        # 坏 CIDR 被跳过，好网段照常可匹配
        self.assertEqual(len(profiles[0].nets), 2)
        cred, _ = credentials.select_for_target("10.0.1.1", profiles)
        self.assertIsNotNone(cred)


class SnmpV3UserBuildTest(unittest.TestCase):

    def test_to_snmp_v3_user_resolves_env(self):
        with mock.patch.dict(os.environ, {"V3A": "auth", "V3P": "priv"}):
            cred = credentials.Credential(
                name="v3", scope=["10.0.0.0/8"], protocol="snmp_v3",
                username="monitor", auth_proto="sha", auth_key="env:V3A",
                priv_proto="aes", priv_key="env:V3P")
            user = cred.to_snmp_v3_user()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "monitor")
        self.assertEqual(user.auth_key, "auth")
        self.assertEqual(user.priv_key, "priv")

    def test_non_v3_returns_none(self):
        cred = credentials.Credential(name="c", scope=["10.0.0.0/8"],
                                      protocol="snmp_v2c", community="x")
        self.assertIsNone(cred.to_snmp_v3_user())


class ByteIdenticalWhenAbsentTest(unittest.TestCase):
    """无档册时，引擎行为必须与历史逐字节一致。"""

    def test_no_book_uses_default_path(self):
        # 无 book、无 v3 用户 → 走 snmp_get_system(ip)，不加 communities
        with mock.patch.object(engine, "snmp_get_system",
                               return_value={"sys_name": "sw"}) as m:
            info, err = engine._identify_snmp("10.0.0.1")
        self.assertEqual(info, {"sys_name": "sw"})
        self.assertIsNone(err)
        m.assert_called_once_with("10.0.0.1")

    def test_book_none_matches_signature_default(self):
        import inspect
        sig = inspect.signature(engine._identify_snmp)
        self.assertIsNone(sig.parameters["credential_book"].default)

    def test_v2c_profile_passes_explicit_community(self):
        book = credentials.CredentialBook([
            credentials.Credential(name="p", scope=["10.0.0.0/8"],
                                   protocol="snmp_v2c", community="mycomm")])
        with mock.patch.object(engine, "snmp_get_system",
                               return_value={"sys_name": "sw"}) as m:
            info, err = engine._identify_snmp("10.0.0.5", None, book)
        self.assertEqual(info, {"sys_name": "sw"})
        self.assertIsNone(err)
        # 必须带**该目标专属**团体字
        m.assert_called_once_with("10.0.0.5", communities=["mycomm"])

    def test_communities_for_helper(self):
        book = credentials.CredentialBook([
            credentials.Credential(name="p", scope=["10.0.0.0/8"],
                                   protocol="snmp_v2c", community="c1")])
        self.assertEqual(book.communities_for("10.0.0.1"), ["c1"])
        self.assertEqual(book.communities_for("192.168.1.1"), [])


class CredentialsCommandTest(unittest.TestCase):

    def _write(self, td, payload):
        p = os.path.join(td, "credentials.json")
        with io.open(p, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        return p

    def test_list_table(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, {"profiles": [
                {"name": "office", "scope": ["10.1.0.0/16"],
                 "protocol": "snmp_v2c", "community": "env:OFFICE"}]})
            code, out, _ = _run_main(["credentials", "--file", p])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("office", out)
        self.assertIn("env:OFFICE", out)

    def test_list_json_no_plaintext(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, {"profiles": [
                {"name": "a", "scope": ["10.0.0.0/8"],
                 "protocol": "snmp_v2c", "community": "PLAINTEXT_COMM"}]})
            code, out, _ = _run_main(["credentials", "--file", p, "-f", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("PLAINTEXT_COMM", out)     # 明文绝不回显
        self.assertIn('"env": false', out)

    def test_missing_file_exits_error(self):
        code, _out, err = _run_main(
            ["credentials", "--file", "/nonexistent/x.json"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("不存在", err)

    def test_proto_filter(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, {"profiles": [
                {"name": "a", "scope": ["10.0.0.0/8"], "protocol": "snmp_v2c",
                 "community": "x"},
                {"name": "b", "scope": ["10.1.0.0/16"], "protocol": "wmi",
                 "username": "u"}]})
            code, out, _ = _run_main(["credentials", "--file", p, "--proto", "wmi"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("b", out)
        self.assertNotIn("a ", out)


class ScanIntegrationTest(unittest.TestCase):
    """``scan --credentials`` 把档册传进引擎（用 mock 断言接线）。"""

    def test_credentials_flag_reaches_engine(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": [
                    {"name": "p", "scope": ["127.0.0.0/8"],
                     "protocol": "snmp_v2c", "community": "c"}]}, f)
            from scanner import NetworkScanner
            with mock.patch.object(NetworkScanner, "scan",
                                   return_value=[]) as m:
                cli.main(["scan", "-r", "127.0.0.1", "--protocols", "SNMP",
                          "--credentials", p, "--no-mdns", "-q"])
        # 关键：credential_book 非 None 且被传给了 scan()
        self.assertTrue(m.called)
        kwargs = m.call_args.kwargs
        self.assertIsNotNone(kwargs.get("credential_book"))
        self.assertEqual(len(kwargs["credential_book"]), 1)

    def test_missing_credentials_file_is_hard_error(self):
        with mock.patch("scanner.NetworkScanner.scan") as m:
            code, _out, err = _run_main(
                ["scan", "-r", "127.0.0.1", "--credentials", "/nope.json", "-q"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("不存在", err)
        m.assert_not_called()

    def test_no_credentials_flag_keeps_book_none(self):
        from scanner import NetworkScanner
        with mock.patch.object(NetworkScanner, "scan", return_value=[]) as m:
            cli.main(["scan", "-r", "127.0.0.1", "--no-mdns", "-q"])
        kwargs = m.call_args.kwargs
        self.assertIsNone(kwargs.get("credential_book"))


class ParityAndCoverageTest(unittest.TestCase):
    """补齐边角分支：默认路径、密码解析、写盘失败、多形态防御分支。"""

    def test_default_config_path_in_data_dir(self):
        import app_paths
        p = credentials.default_config_path()
        self.assertEqual(os.path.basename(p), "credentials.json")
        self.assertEqual(os.path.dirname(p), app_paths.data_dir())

    def test_resolved_password_env(self):
        with mock.patch.dict(os.environ, {"WMI_PW": "pw"}):
            cred = credentials.Credential(name="w", scope=["10.0.0.0/8"],
                                          protocol="wmi", username="u",
                                          password="env:WMI_PW")
            self.assertEqual(cred.resolved_password(), "pw")

    def test_resolved_keys_env(self):
        with mock.patch.dict(os.environ, {"AK": "a", "PK": "p"}):
            cred = credentials.Credential(name="v", scope=["10.0.0.0/8"],
                                          protocol="snmp_v3", username="u",
                                          auth_key="env:AK", priv_key="env:PK")
            self.assertEqual(cred.resolved_auth_key(), "a")
            self.assertEqual(cred.resolved_priv_key(), "p")

    def test_save_to_bad_path_returns_false(self):
        # 写到一个不可能创建的路径（把文件当目录用）
        with tempfile.NamedTemporaryFile(delete=False) as f:
            blocker = f.name
        try:
            bad = os.path.join(blocker, "sub", "credentials.json")
            ok, err = credentials.save_profiles([], bad)
            self.assertFalse(ok)
            self.assertTrue(err)
        finally:
            os.remove(blocker)

    def test_load_skips_non_dict_profile_entries(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": ["oops", 42, {"name": "ok",
                                                     "scope": ["10.0.0.0/8"],
                                                     "protocol": "snmp_v2c",
                                                     "community": "x"}]}, f)
            loaded = credentials.load_profiles(p)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].name, "ok")

    def test_load_non_dict_toplevel_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump(["not", "a", "dict"], f)
            self.assertEqual(credentials.load_profiles(p), [])

    def test_v4_address_vs_v6_network_not_matched(self):
        # 一台 IPv6-only 设备 + 只覆盖 IPv4 网段的档 → 不匹配（版本不同）
        cred = credentials.Credential(name="v4", scope=["10.0.0.0/8"],
                                      protocol="snmp_v2c", community="x")
        self.assertEqual(cred.match_prefixlen(
            ipaddress.ip_address("fe80::1")), -1)

    def test_empty_scope_entries_skipped(self):
        cred = credentials.Credential(name="p", scope=["", "  ", "10.0.0.0/8"],
                                      protocol="snmp_v2c", community="x")
        self.assertEqual(len(cred.nets), 1)

    def test_book_from_path_constructor(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": [
                    {"name": "p", "scope": ["10.0.0.0/8"],
                     "protocol": "snmp_v2c", "community": "x"}]}, f)
            book = credentials.CredentialBook(path=p)
        self.assertEqual(len(book), 1)
        self.assertTrue(book.has_any())

    def test_book_communities_for_empty_community(self):
        book = credentials.CredentialBook([
            credentials.Credential(name="p", scope=["10.0.0.0/8"],
                                   protocol="snmp_v2c", community="")])
        self.assertEqual(book.communities_for("10.0.0.1"), [])

    def test_book_communities_for_v3_returns_empty(self):
        book = credentials.CredentialBook([
            credentials.Credential(name="v", scope=["10.0.0.0/8"],
                                   protocol="snmp_v3", username="u")])
        self.assertEqual(book.communities_for("10.0.0.1"), [])

    def test_protocol_label_unknown_passthrough(self):
        self.assertEqual(credentials.protocol_label("weird"), "weird")

    def test_v3_profile_empty_community_error(self):
        # v3 档但团体字为空：不该当 v1/v2c 处理而报"团体字为空"
        book = credentials.CredentialBook([
            credentials.Credential(name="v", scope=["10.0.0.0/8"],
                                   protocol="snmp_v3", username="monitor",
                                   auth_proto="sha", auth_key="k")])
        with mock.patch.object(engine, "snmp_v3_get_system",
                               return_value={"sys_name": "sw"}) as m:
            info, err = engine._identify_snmp("10.0.0.5", None, book)
        self.assertEqual(info, {"sys_name": "sw"})
        self.assertIsNone(err)
        m.assert_called_once()

    def test_v2c_profile_empty_community_reports(self):
        book = credentials.CredentialBook([
            credentials.Credential(name="p", scope=["10.0.0.0/8"],
                                   protocol="snmp_v2c", community="")])
        info, err = engine._identify_snmp("10.0.0.5", None, book)
        self.assertIsNone(info)
        self.assertIn("团体字为空", err)

    def test_credentials_table_shows_plaintext_warning(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": [
                    {"name": "a", "scope": ["10.0.0.0/8"],
                     "protocol": "snmp_v2c", "community": "PLAIN"}]}, f)
            code, out, _ = _run_main(["credentials", "--file", p])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("PLAIN", out)      # 明文不回显
        self.assertIn("明文", out)          # 但提示"建议改用 env:"

    def test_credentials_table_username_with_domain(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": [
                    {"name": "w", "scope": ["10.0.0.0/8"], "protocol": "wmi",
                     "username": "ro", "domain": "CORP"}]}, f)
            code, out, _ = _run_main(["credentials", "--file", p])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("CORP\\ro", out)

    def test_credentials_proto_filter_empty(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": [
                    {"name": "a", "scope": ["10.0.0.0/8"],
                     "protocol": "snmp_v2c", "community": "x"}]}, f)
            code, _out, err = _run_main(
                ["credentials", "--file", p, "--proto", "wmi"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("没有", err)

    def test_credentials_write_to_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "credentials.json")
            with io.open(p, "w", encoding="utf-8") as f:
                json.dump({"profiles": [
                    {"name": "a", "scope": ["10.0.0.0/8"],
                     "protocol": "snmp_v2c", "community": "x"}]}, f)
            out_path = os.path.join(td, "list.txt")
            code, _out, _ = _run_main(
                ["credentials", "--file", p, "-o", out_path])
            self.assertEqual(code, cli.EXIT_OK)
            self.assertTrue(os.path.exists(out_path))
            with io.open(out_path, encoding="utf-8") as f:
                self.assertIn("a", f.read())


if __name__ == "__main__":
    unittest.main()
