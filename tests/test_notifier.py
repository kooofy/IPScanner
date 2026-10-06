# -*- coding: utf-8 -*-
"""变更告警通知渠道的单元测试（不发起任何真实网络请求）。

锁死三件事：
1. **敏感值不落盘** —— ``env:VAR`` 间接引用必须真的读环境变量；
2. **业务错误算失败** —— 企业微信/钉钉用 HTTP 200 + errcode 表示失败，
   只看状态码会把"机器人被禁用"当成发送成功，告警静默丢失；
3. **失败隔离** —— 多渠道里挂掉一个不能影响其余，否则等于全或无。
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import notifier
from change_detector import (Change, CHANGE_NEW_DEVICE, CHANGE_DEVICE_GONE,
                             SEVERITY_HIGH, SEVERITY_INFO)


class ResolveSecretTest(unittest.TestCase):

    def test_plain_value_passes_through(self):
        self.assertEqual(notifier.resolve_secret("https://x/y"), "https://x/y")

    def test_env_indirection(self):
        with mock.patch.dict(os.environ, {"MY_HOOK": "https://secret/y"}):
            self.assertEqual(notifier.resolve_secret("env:MY_HOOK"),
                             "https://secret/y")

    def test_env_missing_returns_empty(self):
        os.environ.pop("NO_SUCH_VAR_XYZ", None)
        self.assertEqual(notifier.resolve_secret("env:NO_SUCH_VAR_XYZ"), "")

    def test_empty(self):
        self.assertEqual(notifier.resolve_secret(""), "")
        self.assertEqual(notifier.resolve_secret(None), "")


class BusinessErrorTest(unittest.TestCase):
    """企业微信/钉钉即使失败也返回 HTTP 200，必须解析 body 里的 errcode。"""

    def test_errcode_zero_is_success(self):
        notifier._raise_if_business_error(b'{"errcode":0,"errmsg":"ok"}')

    def test_nonzero_errcode_raises(self):
        with self.assertRaises(RuntimeError) as ctx:
            notifier._raise_if_business_error(b'{"errcode":93000,"errmsg":"invalid webhook"}')
        self.assertIn("93000", str(ctx.exception))

    def test_dingtalk_code_field(self):
        with self.assertRaises(RuntimeError):
            notifier._raise_if_business_error(b'{"code":310000,"message":"sign not match"}')

    def test_non_json_body_is_treated_as_success(self):
        """自建 webhook 常返回纯文本，不该被误判为失败。"""
        notifier._raise_if_business_error(b"OK")
        notifier._raise_if_business_error(b"")

    def test_json_array_is_ignored(self):
        notifier._raise_if_business_error(b"[1,2,3]")


class PayloadShapeTest(unittest.TestCase):

    def test_wecom_markdown(self):
        n = notifier.WeComNotifier("https://qyapi.weixin.qq.com/x")
        p = n.payload("标题", "正文")
        self.assertEqual(p["msgtype"], "markdown")
        self.assertIn("标题", p["markdown"]["content"])
        self.assertIn("正文", p["markdown"]["content"])

    def test_dingtalk_markdown_has_title(self):
        n = notifier.DingTalkNotifier("https://oapi.dingtalk.com/x")
        p = n.payload("标题", "正文")
        self.assertEqual(p["markdown"]["title"], "标题")

    def test_generic_webhook_has_text_field(self):
        n = notifier.WebhookNotifier("https://example.com/hook")
        p = n.payload("标题", "正文")
        self.assertEqual(p["subject"], "标题")
        self.assertEqual(p["body"], "正文")
        self.assertIn("标题", p["text"])

    def test_dingtalk_signature_is_appended(self):
        n = notifier.DingTalkNotifier("https://oapi.dingtalk.com/robot/send?access_token=t",
                                      secret="SECRET")
        with mock.patch.object(notifier.time, "time", return_value=1700000000.0):
            url = n._target_url()
        self.assertIn("timestamp=1700000000000", url)
        self.assertIn("sign=", url)

    def test_dingtalk_without_secret_leaves_url_alone(self):
        n = notifier.DingTalkNotifier("https://x/y")
        self.assertEqual(n._target_url(), "https://x/y")


class EmailDefaultsTest(unittest.TestCase):

    def test_ssl_default_port(self):
        self.assertEqual(notifier.EmailNotifier("smtp.x.com").port, 465)

    def test_starttls_default_port(self):
        self.assertEqual(notifier.EmailNotifier("smtp.x.com", use_ssl=False).port, 587)

    def test_explicit_port_wins(self):
        self.assertEqual(notifier.EmailNotifier("smtp.x.com", port=2525).port, 2525)

    def test_empty_recipients_rejected(self):
        n = notifier.EmailNotifier("smtp.x.com")
        with self.assertRaises(ValueError):
            n.send("s", "b")

    def test_password_reads_env(self):
        with mock.patch.dict(os.environ, {"SMTP_P": "hunter2"}):
            n = notifier.EmailNotifier("smtp.x.com", user="a", password="env:SMTP_P")
        self.assertEqual(n.password, "hunter2")


class BuildNotifiersTest(unittest.TestCase):

    def test_aliases(self):
        cfg = {"channels": [
            {"type": "wecom", "url": "u1"},
            {"type": "wechat_work", "url": "u2"},
            {"type": "ding", "url": "u3"},
            {"type": "smtp", "host": "h"},
        ]}
        kinds = [type(n).__name__ for n in notifier.build_notifiers(cfg)]
        self.assertEqual(kinds, ["WeComNotifier", "WeComNotifier",
                                 "DingTalkNotifier", "EmailNotifier"])

    def test_disabled_channel_is_skipped(self):
        cfg = {"channels": [{"type": "wecom", "url": "u", "enabled": False}]}
        self.assertEqual(notifier.build_notifiers(cfg), [])

    def test_unknown_type_is_skipped_not_fatal(self):
        cfg = {"channels": [
            {"type": "carrier_pigeon", "url": "u"},
            {"type": "wecom", "url": "u2"},
        ]}
        out = notifier.build_notifiers(cfg)
        self.assertEqual(len(out), 1)

    def test_malformed_entries_do_not_crash(self):
        for cfg in ({}, {"channels": None}, {"channels": ["nonsense", 42]},
                    {"channels": [{}]}):
            self.assertIsInstance(notifier.build_notifiers(cfg), list)


class SendAllTest(unittest.TestCase):
    """失败隔离：一个渠道挂掉不影响其余。"""

    class _Fake(notifier.Notifier):
        def __init__(self, name, boom=False):
            self.name = name
            self.boom = boom
            self.sent = []

        def send(self, subject, body):
            if self.boom:
                raise RuntimeError("boom")
            self.sent.append((subject, body))

    def test_all_succeed(self):
        a, b = self._Fake("a"), self._Fake("b")
        results = notifier.send_all([a, b], "s", "b")
        self.assertEqual([(n, ok) for n, ok, _ in results], [("a", True), ("b", True)])
        self.assertEqual(len(a.sent), 1)

    def test_one_failure_does_not_block_others(self):
        a, bad, c = self._Fake("a"), self._Fake("bad", boom=True), self._Fake("c")
        results = notifier.send_all([a, bad, c], "s", "b")
        self.assertEqual([ok for _, ok, _ in results], [True, False, True])
        self.assertEqual(len(c.sent), 1, "失败渠道之后的渠道仍须被尝试")
        self.assertIn("boom", results[1][2])

    def test_empty_list(self):
        self.assertEqual(notifier.send_all([], "s", "b"), [])


class FormatChangeMessageTest(unittest.TestCase):

    def _change(self, ip, sev=SEVERITY_HIGH, ctype=CHANGE_NEW_DEVICE,
                host="", desc=""):
        return Change(change_type=ctype, severity=sev, description=desc,
                      ip=ip, hostname=host)

    def test_no_changes(self):
        subject, body = notifier.format_change_message([], "无变更")
        self.assertIn("[IPScanner]", subject)
        self.assertTrue(body)

    def test_subject_carries_summary(self):
        subject, _ = notifier.format_change_message(
            [self._change("10.0.0.1")], "1 严重", label="当前扫描 → 快照 #3")
        self.assertIn("1 严重", subject)
        self.assertIn("快照 #3", subject)

    def test_body_lists_each_change(self):
        changes = [self._change("10.0.0.1", host="pc1"),
                   self._change("10.0.0.2", ctype=CHANGE_DEVICE_GONE,
                                sev=SEVERITY_INFO)]
        _, body = notifier.format_change_message(changes, "1 严重 · 1 提示")
        self.assertIn("10.0.0.1", body)
        self.assertIn("pc1", body)
        self.assertIn("10.0.0.2", body)

    def test_truncation_keeps_message_deliverable(self):
        """企业微信/钉钉超长会整条拒收，因此必须截断而不是全丢。"""
        changes = [self._change(f"10.0.0.{i}") for i in range(1, 60)]
        _, body = notifier.format_change_message(changes, "x", max_items=10)
        self.assertIn("10.0.0.10", body)
        self.assertNotIn("10.0.0.11", body)
        self.assertIn("49", body, "被省略的条数要写出来")


class ConfigFileTest(unittest.TestCase):

    def test_missing_file_returns_empty(self):
        self.assertEqual(notifier.load_config("/no/such/notify.json"), {})

    def test_corrupt_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "notify.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{ not json")
            self.assertEqual(notifier.load_config(p), {})

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "sub", "notify.json")
            cfg = {"channels": [{"type": "wecom", "url": "env:X"}]}
            ok, err = notifier.save_config(cfg, p)
            self.assertTrue(ok, err)
            self.assertEqual(notifier.load_config(p), cfg)
            # 落盘内容里不应出现明文地址（这里用的是 env: 引用）
            with open(p, encoding="utf-8") as f:
                self.assertIn("env:X", f.read())

    def test_non_dict_json_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "notify.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump([1, 2], f)
            self.assertEqual(notifier.load_config(p), {})


if __name__ == "__main__":
    unittest.main()
