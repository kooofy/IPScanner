# -*- coding: utf-8 -*-
"""服务版本指纹库测试（P2-2）。

覆盖三件事：
1. **数据文件本身**是合法 JSON、每条规则可编译、字段齐全 —— 打包漏了文件、
   正则写错，都要在这里被拦住，而不是等用户发现"版本识别不出来"。
2. **匹配语义**：产品专属规则优先于通用规则、端口专属规则只在声明端口生效
   （FTP/SMTP 的 "220" 欢迎行、POP3/IMAP 的 "Dovecot ready" 都靠端口区分）。
3. **稳健性**：数据文件缺失/损坏/单条正则非法时，都不能让指纹库整体失效，
   更不能把异常抛给扫描流程。
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import service_fingerprints as SF


class DataFileTest(unittest.TestCase):
    """数据文件必须在仓库里、且内容合法 —— 它是要被 PyInstaller 打包的。"""

    def test_data_file_exists_at_repo_root(self):
        self.assertTrue(
            os.path.exists(os.path.join(ROOT, SF.DATA_FILENAME)),
            "service_fingerprints.json 不在仓库根目录，打包时会漏掉",
        )

    def test_data_file_is_valid_and_rules_compile(self):
        path = os.path.join(ROOT, SF.DATA_FILENAME)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data.get("version"), str)
        rules = data.get("rules")
        self.assertTrue(rules)
        for item in rules:
            self.assertIn("service", item)
            self.assertIn("pattern", item)
        compiled = SF._compile(rules)
        self.assertEqual(len(compiled), len(rules), "有规则正则编译失败")

    def test_service_codes_are_ascii(self):
        """service 必须是语言无关的 ASCII 代码，不能是翻译后的中文。"""
        for rule in SF.load_rules():
            self.assertTrue(rule.service.isascii(),
                            msg=f"服务代码不是 ASCII: {rule.service!r}")


class MatchTest(unittest.TestCase):

    def tearDown(self):
        SF.reload()

    def _fp(self, banner, port=None):
        return SF.fingerprint_banner(banner, port=port)

    def test_openssh(self):
        fp = self._fp("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", 22)
        self.assertEqual((fp.service, fp.product, fp.version),
                         ("SSH", "OpenSSH", "8.9p1"))

    def test_dropbear(self):
        fp = self._fp("SSH-2.0-dropbear_2022.83", 22)
        self.assertEqual(fp.product, "Dropbear")

    def test_apache_and_nginx(self):
        self.assertEqual(self._fp("Server: Apache/2.4.52 (Ubuntu)", 80).product,
                         "Apache httpd")
        self.assertEqual(self._fp("Server: nginx/1.24.0", 80).version, "1.24.0")

    def test_mariadb_before_mysql(self):
        """MariaDB 的版本串里也有 'MySQL' 的兼容前缀，必须优先识别为 MariaDB。"""
        fp = self._fp("5.5.5-10.6.4-MariaDB-1:10.6.4+maria~ubu2004", 3306)
        self.assertEqual(fp.product, "MariaDB")
        self.assertEqual(fp.version, "10.6.4")

    def test_mysql_plain(self):
        fp = self._fp("8.0.36", 3306)
        self.assertEqual((fp.product, fp.version), ("MySQL", "8.0.36"))

    def test_vnc(self):
        fp = self._fp("RFB 003.008", 5900)
        self.assertEqual((fp.service, fp.version), ("VNC", "003.008"))

    def test_ftp_smtp_220_disambiguated_by_port(self):
        """'220' 欢迎行 FTP 与 SMTP 一模一样，只能靠端口区分。"""
        ftp = self._fp("220 Service ready for new user.", 21)
        smtp = self._fp("220 Service ready for new user.", 25)
        self.assertEqual(ftp.service, "FTP")
        self.assertEqual(smtp.service, "SMTP")

    def test_smtp_product_beats_generic_220(self):
        fp = self._fp("220 mail.example.com ESMTP Postfix", 25)
        self.assertEqual((fp.service, fp.product), ("SMTP", "Postfix"))

    def test_pop3_imap_dovecot_disambiguated_by_port(self):
        pop = self._fp("+OK Dovecot ready.", 110)
        imap = self._fp("* OK [CAPABILITY IMAP4rev1] Dovecot ready.", 143)
        self.assertEqual(pop.service, "POP3")
        self.assertEqual(imap.service, "IMAP")

    def test_port_gated_rule_not_applied_on_other_port(self):
        """端口专属规则不得在别的端口上误命中。"""
        # Redis 规则只在 6379 生效：同样文本换个端口就不该识别成 Redis
        self.assertEqual(self._fp("+PONG", 6379).service, "Redis")
        self.assertIsNone(self._fp("+PONG", 9999))

    def test_postgresql_mongodb_rdp_telnet(self):
        self.assertEqual(self._fp("PostgreSQL", 5432).service, "PostgreSQL")
        self.assertEqual(self._fp("MongoDB", 27017).service, "MongoDB")
        self.assertEqual(self._fp("RDP", 3389).service, "RDP")
        self.assertEqual(self._fp("Welcome to Ubuntu 22.04", 23).service, "Telnet")

    def test_unknown_banner_returns_none(self):
        self.assertIsNone(self._fp("some totally unknown protocol"))
        self.assertIsNone(self._fp(""))

    def test_display_falls_back_to_service(self):
        self.assertEqual(SF.Fingerprint("Redis").display, "Redis")
        self.assertEqual(SF.Fingerprint("SSH", "OpenSSH", "9.0").display, "OpenSSH 9.0")

    def test_bad_version_group_does_not_raise(self):
        """规则里写了不存在的捕获组：只丢版本号，不能抛异常。"""
        rules = [{"service": "X", "product": "P", "pattern": "hello", "version": 9}]
        with mock.patch.object(SF, "_read_raw_rules", return_value=rules):
            SF.reload()
            fp = SF.fingerprint_banner("hello", port=None)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.version, "")
        SF.reload()


class RobustnessTest(unittest.TestCase):

    def tearDown(self):
        SF.reload()

    def test_fallback_when_file_missing(self):
        with mock.patch.object(SF, "data_path", return_value=os.path.join(
                tempfile.gettempdir(), "no_such_fingerprints_xyz.json")):
            SF.reload()
            self.assertGreater(SF.rule_count(), 0, "缺文件时应回退到内置规则")
            fp = SF.fingerprint_banner("SSH-2.0-OpenSSH_8.9p1", port=22)
            self.assertEqual(fp.product, "OpenSSH")

    def test_fallback_when_json_corrupt(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write("{ this is not json ")
        try:
            with mock.patch.object(SF, "data_path", return_value=path):
                SF.reload()
                self.assertGreater(SF.rule_count(), 0)
        finally:
            os.unlink(path)

    def test_invalid_regex_rule_is_skipped_others_survive(self):
        rules = [
            {"service": "Bad", "pattern": "([unclosed"},
            {"service": "Good", "product": "Prod", "pattern": "hello world"},
        ]
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"rules": rules}, f)
        try:
            with mock.patch.object(SF, "data_path", return_value=path):
                SF.reload()
                self.assertEqual(SF.rule_count(), 1)
                fp = SF.fingerprint_banner("hello world")
                self.assertEqual(fp.service, "Good")
        finally:
            os.unlink(path)

    def test_reload_refreshes_cache(self):
        first = SF.load_rules()
        self.assertIs(first, SF.load_rules(), "应命中缓存")
        SF.reload()
        self.assertIsNot(first, SF.load_rules(), "reload 后应重建")


if __name__ == "__main__":
    unittest.main()
