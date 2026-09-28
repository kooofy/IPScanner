# -*- coding: utf-8 -*-
"""网络工具目标校验测试（P0-4：命令注入防护）。

回归点：ping/tracert/telnet/ssh 的目标会被拼进 `cmd /k "<cmd>"` 或终端命令行，
因此目标里出现 shell 元字符就等于宿主上任意命令执行。这里穷举常见注入载荷，
确保全部被拒绝，同时保证正常的 IP / 主机名不被误杀。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from network_tool_mixin import validate_target, validate_user


class ValidateTargetTest(unittest.TestCase):

    # ---------- 正常目标必须放行 ----------

    def test_accepts_ipv4(self):
        for ip in ("192.168.1.1", "10.0.0.254", "255.255.255.255", "0.0.0.0"):
            ok, cleaned, reason = validate_target(ip)
            self.assertTrue(ok, msg=f"{ip} 应被接受（{reason}）")
            self.assertEqual(cleaned, ip)

    def test_accepts_ipv6(self):
        for ip in ("::1", "fe80::1", "2001:db8::1", "2001:db8:0:0:0:0:0:1"):
            ok, _c, reason = validate_target(ip)
            self.assertTrue(ok, msg=f"{ip} 应被接受（{reason}）")

    def test_accepts_hostnames(self):
        for h in ("localhost", "server-01", "dc01.corp.local",
                  "my_host.example.com", "a", "PC-2024"):
            ok, _c, reason = validate_target(h)
            self.assertTrue(ok, msg=f"{h} 应被接受（{reason}）")

    def test_strips_surrounding_whitespace(self):
        ok, cleaned, _ = validate_target("  192.168.1.1  ")
        self.assertTrue(ok)
        self.assertEqual(cleaned, "192.168.1.1")

    # ---------- 注入载荷必须全部拒绝 ----------

    def test_rejects_command_chaining(self):
        payloads = [
            "1.1.1.1 & calc",
            "1.1.1.1&calc",
            "1.1.1.1 && calc",
            "1.1.1.1 | calc",
            "1.1.1.1||calc",
            "1.1.1.1; rm -rf /",
            "1.1.1.1 ; calc",
            "1.1.1.1 ^& calc",
            "1.1.1.1 ^| calc",
            "1.1.1.1\ncalc",
            "1.1.1.1\r\ncalc",
            "1.1.1.1\tcalc",
        ]
        for p in payloads:
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"注入载荷未被拒绝: {p!r}")

    def test_rejects_shell_metacharacters(self):
        payloads = [
            '1.1.1.1" & calc',
            "1.1.1.1' & calc",
            "1.1.1.1`calc`",
            "1.1.1.1$(calc)",
            "1.1.1.1$(id)",
            "1.1.1.1>out.txt",
            "1.1.1.1<in.txt",
            "1.1.1.1%PATH%",
            "1.1.1.1%COMSPEC%",
            "1.1.1.1{calc}",
            "1.1.1.1(calc)",
            "1.1.1.1!calc!",
            "1.1.1.1*",
            "1.1.1.1?",
            "1.1.1.1~",
            "1.1.1.1=1",
            "1.1.1.1\\calc",
            "1.1.1.1#calc",
            "1.1.1.1@calc",
            "1.1.1.1,calc",
        ]
        for p in payloads:
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"元字符未被拒绝: {p!r}")

    def test_rejects_option_injection(self):
        for p in ("-s", "-oProxyCommand=calc", "--help", "-"):
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"选项注入未被拒绝: {p!r}")

    # ---------- 边界与畸形输入 ----------

    def test_rejects_empty(self):
        for p in (None, "", "   ", "\t", "\n"):
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"空目标未被拒绝: {p!r}")

    def test_rejects_too_long(self):
        ok, _c, _r = validate_target("a" * 254)
        self.assertFalse(ok)
        ok2, _c2, _r2 = validate_target("a" * 253)
        self.assertTrue(ok2)

    def test_rejects_non_ascii(self):
        for p in ("中文主机", "服务器.内网", "café.local"):
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"非 ASCII 未被拒绝: {p!r}")

    def test_rejects_malformed_hostname(self):
        for p in ("..", "host..name", "host.", ".host", "1..2"):
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"畸形主机名未被拒绝: {p!r}")

    def test_rejects_pure_digits(self):
        """纯数字既不是合法 IP 也不是合法主机名，容易被 ping 误解。"""
        for p in ("12345", "999", "1"):
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"纯数字未被拒绝: {p!r}")

    def test_rejects_control_characters(self):
        for p in ("1.1.1.1\x00", "1.1.1.1\x07", "1.1.1.1\x1b[31m"):
            ok, _c, _r = validate_target(p)
            self.assertFalse(ok, msg=f"控制字符未被拒绝: {p!r}")

    def test_reason_is_human_readable(self):
        ok, _c, reason = validate_target("1.1.1.1 & calc")
        self.assertFalse(ok)
        self.assertTrue(reason)


class ValidateUserTest(unittest.TestCase):

    def test_accepts_normal_users(self):
        for u in ("root", "administrator", "john.doe", "user-1", "a_b"):
            ok, cleaned, reason = validate_user(u)
            self.assertTrue(ok, msg=f"{u} 应被接受（{reason}）")
            self.assertEqual(cleaned, u)

    def test_strips_whitespace(self):
        ok, cleaned, _ = validate_user("  root  ")
        self.assertTrue(ok)
        self.assertEqual(cleaned, "root")

    def test_rejects_injection(self):
        for u in ("root & calc", "root;calc", "root|calc", "root`calc`",
                  'root"x', "root$(id)", "root%PATH%", "root\ncalc", "-root"):
            ok, _c, _r = validate_user(u)
            self.assertFalse(ok, msg=f"用户名注入未被拒绝: {u!r}")

    def test_rejects_empty(self):
        for u in (None, "", "   "):
            ok, _c, _r = validate_user(u)
            self.assertFalse(ok)

    def test_rejects_at_sign(self):
        """用户名里带 @ 会破坏 user@host 的语义。"""
        ok, _c, _r = validate_user("root@evil")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
