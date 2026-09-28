# -*- coding: utf-8 -*-
"""WMI 传输层 WinRM 回退的单元测试（不依赖真实 PowerShell / 远程主机）。

背景
----
旧实现只走 DCOM（`Get-CimInstance -ComputerName`，需 135 + 动态 RPC 端口）。
"目标启用了 WinRM、但 DCOM 被防火墙拦掉"的环境完全识别不了 —— 这在跨网段
巡检里非常常见。新增 `transport` 参数：

    auto（默认）→ 先 DCOM，快速失败再试 WinRM
    dcom        → 仅 DCOM
    winrm       → 仅 WinRM

本测试固定三件事：
1. **尝试序列**：auto 必须两种都试、单通路模式绝不多试；
2. **时间预算**：`timeout` 是单次尝试超时；auto 只在"快速失败"时换通路，
   "卡住"（耗尽预算）不换 —— 否则不可达主机要白等 2 倍超时；
3. **可操作性**：失败消息必须带上两种通路各自的原因 + 归类后的中文提示。
"""
import base64
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from scanner import wmi as wmi_mod
from scanner.wmi import (
    wmi_query, transport_label, _attempts_for, _classify_error, _full_username,
    TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM,
)

_OK_JSON = json.dumps({
    "ok": True,
    "ComputerSystem": {"Manufacturer": "Dell Inc.", "Model": "OptiPlex 7080",
                       "Domain": "CORP", "UserName": "CORP\\alice", "Name": "PC01",
                       "TotalPhysicalMemory": 17179869184},
    "BIOS": {"SerialNumber": "ABC123", "SMBIOSBIOSVersion": "1.2.3"},
    "OS": {"Caption": "Microsoft Windows 11", "Version": "10.0.22631",
           "OSArchitecture": "64-bit", "LastBootUpTime": "20260721080000.000000+480"},
    "CPU": {"Name": "Intel(R) Core(TM) i7", "NumberOfCores": 8},
})
_EMPTY_JSON = json.dumps({"ok": True, "ComputerSystem": {}, "BIOS": {},
                          "OS": {}, "CPU": {}})


class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _protocol_of(cmd):
    """从 -EncodedCommand 参数反解出本次用的是哪条 CIM 通路。

    顺带验证了脚本确实按协议预编译（而不是运行时才拼字符串）。
    """
    i = cmd.index("-EncodedCommand")
    text = base64.b64decode(cmd[i + 1]).decode("utf-16-le")
    if "$proto = 'Wsman'" in text:
        return "Wsman"
    if "$proto = 'Dcom'" in text:
        return "Dcom"
    raise AssertionError("脚本里找不到协议标记，预编译可能坏了")


class _ScriptedRunner:
    """按协议返回预设结果，并记录调用顺序。"""

    def __init__(self, by_proto):
        self.by_proto = by_proto
        self.calls = []

    def __call__(self, cmd, **_kw):
        proto = _protocol_of(cmd)
        self.calls.append(proto)
        out = self.by_proto.get(proto)
        if isinstance(out, Exception):
            raise out
        if out is None:
            raise AssertionError(f"未预设 {proto} 的返回")
        return out


class AttemptsExpansionTest(unittest.TestCase):
    def test_auto_tries_dcom_then_winrm(self):
        self.assertEqual(
            _attempts_for(TRANSPORT_AUTO),
            [("Dcom", TRANSPORT_DCOM), ("Wsman", TRANSPORT_WINRM)],
        )

    def test_dcom_only(self):
        self.assertEqual(_attempts_for(TRANSPORT_DCOM), [("Dcom", TRANSPORT_DCOM)])

    def test_winrm_only(self):
        self.assertEqual(_attempts_for(TRANSPORT_WINRM), [("Wsman", TRANSPORT_WINRM)])


class ScriptCompilationTest(unittest.TestCase):
    """脚本必须按协议预编译，且凭据绝不进脚本正文。"""

    def test_both_protocols_precompiled(self):
        for proto in ("Dcom", "Wsman"):
            with self.subTest(proto=proto):
                self.assertIn(proto, wmi_mod._PROTOCOL_SCRIPTS)
                text = base64.b64decode(
                    wmi_mod._PROTOCOL_SCRIPTS[proto]
                ).decode("utf-16-le")
                self.assertIn(f"$proto = '{proto}'", text)
                self.assertNotIn("__PROTO__", text, "占位符没被替换")

    def test_scripts_differ_and_carry_no_credentials(self):
        dcom = base64.b64decode(wmi_mod._PROTOCOL_SCRIPTS["Dcom"]).decode("utf-16-le")
        wsman = base64.b64decode(wmi_mod._PROTOCOL_SCRIPTS["Wsman"]).decode("utf-16-le")
        self.assertNotEqual(dcom, wsman)
        for text in (dcom, wsman):
            # 凭据只能走环境变量；脚本正文里不得出现密码相关字面量
            self.assertIn("$env:IPSC_WMI_PASS", text)
            self.assertNotIn("IPSC_WMI_PASS =", text)

    def test_script_forces_utf8_output_encoding(self):
        """回归守卫：必须把 `[Console]::OutputEncoding` 设为 UTF-8。

        实测（本机 Windows PowerShell）：stdout/stderr 被重定向时，PowerShell
        默认用**控制台 OEM 代码页**（简体中文 Windows 是 GBK）输出，而调用方按
        UTF-8 解码 —— 只要返回内容含中文（例如 OS Caption 里的"专业版"）就会
        `UnicodeDecodeError`。更糟的是它发生在 subprocess 的**读取线程**里，
        异常只打印一行 traceback，输出被整体丢弃，用户只看到"PowerShell 退出码 N"。
        """
        for proto in ("Dcom", "Wsman"):
            with self.subTest(proto=proto):
                text = base64.b64decode(
                    wmi_mod._PROTOCOL_SCRIPTS[proto]
                ).decode("utf-16-le")
                self.assertIn("[Console]::OutputEncoding", text)
                self.assertIn("UTF8", text)

    def test_error_is_reported_via_stdout_json_not_stderr(self):
        """回归守卫：错误走 stdout 的 JSON。

        stderr 在重定向时会被 PowerShell 序列化成 CLIXML（不可读，且编码行为
        与 console API 不一致）；stdout 才是那个已被强制为 UTF-8、
        且调用方本来就在解析的通道。
        """
        for proto in ("Dcom", "Wsman"):
            with self.subTest(proto=proto):
                text = base64.b64decode(
                    wmi_mod._PROTOCOL_SCRIPTS[proto]
                ).decode("utf-16-le")
                self.assertIn("ok = $false", text)
                self.assertNotIn("[Console]::Error.WriteLine", text)

    def test_script_does_not_assign_unsupported_cim_option_properties(self):
        """回归守卫：绝不在 `$opt` 上赋 SkipCACheck / SkipCNCheck。

        实测（Windows PowerShell 5.1）：`New-CimSessionOption -Protocol Wsman`
        返回的 `WSManSessionOptions` **没有** `SkipCACheck` / `SkipCNCheck` 属性
        （真实属性名是 `CertCACheck` / `CertCNCheck`），赋值的后果是抛
        "找不到属性"。因为它写在 `try` 里，**整条 WinRM 通路会直接失效**，
        而且报错看起来像"目标环境问题"而不是"我们写错了"。

        正确做法：WinRM 默认走 HTTP/5985，全程不涉及证书校验，本就不需要开关；
        真要跳过校验应当用 `New-CimSessionOption -SkipCACheck` 这个**开关参数**。

        断言的是"**属性访问**"（`.SkipCACheck`）而不是裸词 —— 裸词作为开关参数
        传给 `New-CimSessionOption` 是完全合法的用法，不该被禁掉。
        """
        for proto in ("Dcom", "Wsman"):
            with self.subTest(proto=proto):
                text = base64.b64decode(
                    wmi_mod._PROTOCOL_SCRIPTS[proto]
                ).decode("utf-16-le")
                for prop in (".SkipCACheck", ".SkipCNCheck", ".SkipRevocationCheck"):
                    self.assertNotIn(prop, text)


class FallbackTest(unittest.TestCase):
    """回退行为与 `wmi_transport` 记录。"""

    def test_dcom_success_does_not_try_winrm(self):
        runner = _ScriptedRunner({"Dcom": _FakeProc(stdout=_OK_JSON)})
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd")
        self.assertEqual(runner.calls, ["Dcom"])
        self.assertEqual(d["wmi_error"], "")
        self.assertEqual(d["wmi_transport"], TRANSPORT_DCOM)
        self.assertEqual(d["wmi_model"], "OptiPlex 7080")

    def test_auto_falls_back_to_winrm_when_dcom_fails(self):
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr="RPC server is unavailable", returncode=2),
            "Wsman": _FakeProc(stdout=_OK_JSON),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd")
        self.assertEqual(runner.calls, ["Dcom", "Wsman"], "auto 应先 DCOM 再 WinRM")
        self.assertEqual(d["wmi_error"], "")
        self.assertEqual(d["wmi_transport"], TRANSPORT_WINRM, "应记录实际生效的通路")
        self.assertEqual(d["wmi_manufacturer"], "Dell Inc.")

    def test_winrm_only_skips_dcom(self):
        runner = _ScriptedRunner({"Wsman": _FakeProc(stdout=_OK_JSON)})
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport=TRANSPORT_WINRM)
        self.assertEqual(runner.calls, ["Wsman"])
        self.assertEqual(d["wmi_transport"], TRANSPORT_WINRM)

    def test_dcom_only_never_tries_winrm(self):
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr="Access is denied", returncode=2),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport=TRANSPORT_DCOM)
        self.assertEqual(runner.calls, ["Dcom"])
        self.assertTrue(d["wmi_error"])
        self.assertEqual(d["wmi_transport"], "")

    def test_unknown_transport_falls_back_to_auto(self):
        runner = _ScriptedRunner({"Dcom": _FakeProc(stdout=_OK_JSON)})
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport="nonsense")
        self.assertEqual(d["wmi_error"], "")
        self.assertEqual(d["wmi_transport"], TRANSPORT_DCOM)

    def test_empty_payload_on_dcom_still_falls_back(self):
        """会话建起来但字段全空（典型权限不足）也要换通路。"""
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout=_EMPTY_JSON),
            "Wsman": _FakeProc(stdout=_OK_JSON),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd")
        self.assertEqual(runner.calls, ["Dcom", "Wsman"])
        self.assertEqual(d["wmi_transport"], TRANSPORT_WINRM)

    def test_hung_first_attempt_does_not_retry(self):
        """首次尝试"卡住"（耗尽预算）→ 不再换通路，避免白等 2 倍超时。"""
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr="timeout", returncode=2),
        })
        # 起点 0.0s，第二次判断时已过 9s（> 8 × 0.7）
        with mock.patch.object(wmi_mod.subprocess, "run", runner), \
                mock.patch.object(wmi_mod.time, "monotonic",
                                  side_effect=[0.0, 9.0]):
            d = wmi_query("10.0.0.5", "admin", "pwd", timeout=8.0)
        self.assertEqual(runner.calls, ["Dcom"], "卡住时不应再试 WinRM")
        self.assertTrue(d["wmi_error"])
        self.assertIn("跳过", d["wmi_error"])

    def test_small_budget_skips_second_attempt(self):
        """剩余预算不足 _AUTO_MIN_REMAINING 时也不换通路。"""
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr="Access is denied", returncode=2),
        })
        # timeout=3 → 0.7*3=2.1；耗时 2.0 未超比例，但剩余 1.0 < 2.0
        with mock.patch.object(wmi_mod.subprocess, "run", runner), \
                mock.patch.object(wmi_mod.time, "monotonic",
                                  side_effect=[0.0, 2.0]):
            d = wmi_query("10.0.0.5", "admin", "pwd", timeout=3.0)
        self.assertEqual(runner.calls, ["Dcom"])
        self.assertIn("剩余时间不足", d["wmi_error"])

    def test_failure_message_lists_both_transports_and_hint(self):
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr="The RPC server is unavailable", returncode=2),
            "Wsman": _FakeProc(stdout="", stderr="WinRM cannot process the request", returncode=2),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd")
        self.assertEqual(runner.calls, ["Dcom", "Wsman"])
        msg = d["wmi_error"]
        self.assertIn(transport_label(TRANSPORT_DCOM), msg)
        self.assertIn(transport_label(TRANSPORT_WINRM), msg)
        # 归类后的中文提示必须出现，否则用户只看到英文原始报错
        self.assertIn("DCOM/RPC 不可达", msg)

    def test_missing_creds_does_not_launch_anything(self):
        runner = _ScriptedRunner({})
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("", "admin", "pwd")
        self.assertEqual(runner.calls, [])
        self.assertTrue(d["wmi_error"])


class ClassifyErrorTest(unittest.TestCase):
    def test_trusted_hosts(self):
        self.assertIn("TrustedHosts",
                      _classify_error("The WinRM client cannot process the request. "
                                      "TrustedHosts list is empty"))

    def test_access_denied(self):
        self.assertIn("凭据被拒绝", _classify_error("Access is denied. (0x80070005)"))

    def test_rpc_unavailable(self):
        self.assertIn("DCOM/RPC 不可达",
                      _classify_error("The RPC server is unavailable. (0x800706BA)"))

    def test_winrm_disabled(self):
        self.assertIn("WinRM 不可用",
                      _classify_error("The WS-Management service cannot process the request"))

    def test_host_unreachable(self):
        self.assertIn("目标主机不可达",
                      _classify_error("Cannot find the computer 'PC01'"))

    def test_unknown_returns_empty(self):
        self.assertEqual(_classify_error("some brand new error"), "")
        self.assertEqual(_classify_error(""), "")


class CleanStderrTest(unittest.TestCase):
    """`_clean_stderr()`：还原 PowerShell 的 CLIXML 错误流包装。"""

    def test_unwraps_clixml_error_items(self):
        raw = ('#< CLIXML\r\n<Objs Version="1.1.0.1" '
               'xmlns="http://schemas.microsoft.com/powershell/2004/04">'
               '<S S="Error">\u6a21\u62df\u62a5\u9519_x000D__x000A_</S>'
               '<S S="Error">\u4f4d\u7f6e \u884c:2_x000D__x000A_</S></Objs>')
        out = wmi_mod._clean_stderr(raw)
        self.assertIn("模拟报错", out)
        self.assertIn("位置 行:2", out)
        self.assertNotIn("CLIXML", out)
        self.assertNotIn("_x000D_", out)

    def test_plain_text_passes_through(self):
        self.assertEqual(wmi_mod._clean_stderr("Access is denied"),
                         "Access is denied")

    def test_empty_input(self):
        self.assertEqual(wmi_mod._clean_stderr(""), "")

    def test_clixml_without_error_items_yields_empty(self):
        self.assertEqual(wmi_mod._clean_stderr("#< CLIXML\r\n<Objs/>"), "")


class ErrorChannelTest(unittest.TestCase):
    """脚本 catch 输出到 stdout 的 `{ok:false,error:...}` 必须被识别为失败。"""

    def test_error_json_on_stdout_is_failure(self):
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout=json.dumps({"ok": False, "error": "拒绝访问"}),
                              returncode=0),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport=TRANSPORT_DCOM)
        self.assertIn("拒绝访问", d["wmi_error"])
        self.assertEqual(d["wmi_transport"], "")

    def test_chinese_error_message_survives(self):
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout=json.dumps(
                {"ok": False, "error": "RPC 服务器不可用。"})),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport=TRANSPORT_DCOM)
        self.assertIn("RPC 服务器不可用", d["wmi_error"])

    def test_chinese_os_caption_survives(self):
        payload = json.dumps({
            "ok": True,
            "ComputerSystem": {"Manufacturer": "Dell Inc.", "Model": "OptiPlex"},
            "BIOS": {}, "CPU": {},
            "OS": {"Caption": "Microsoft Windows 11 专业版"},
        })
        runner = _ScriptedRunner({"Dcom": _FakeProc(stdout=payload)})
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd")
        self.assertEqual(d["wmi_os"], "Microsoft Windows 11 专业版")
        self.assertEqual(d["wmi_transport"], TRANSPORT_DCOM)


@unittest.skipUnless(sys.platform == "win32", "需要 Windows 上的 PowerShell")
class LivePowerShellScriptTest(unittest.TestCase):
    """真实跑一次脚本，验证脚本本身可执行、且失败原因是可读文本。

    这是唯一能发现下面两类缺陷的测试 —— mock 掉 subprocess 的用例全部绕过了
    真实编码与真实脚本执行：

    1. PowerShell 默认按控制台 OEM 代码页（简中 Windows 是 GBK）输出，
       调用方按 UTF-8 解码 → 读取线程 `UnicodeDecodeError`，输出整体丢失；
    2. 在 `$opt` 上赋不存在的属性（如 `SkipCACheck`）→ 整条 WinRM 通路失效。

    目标用不可能解析的主机名，所以预期就是"连不上"，但**原因必须可读**。
    """

    BOGUS_HOST = "no-such-host-xyz-12345"
    TIMEOUT = 12.0

    def test_scripts_execute_and_report_readable_errors(self):
        for proto in ("Dcom", "Wsman"):
            with self.subTest(proto=proto):
                raw, err = wmi_mod._run_powershell(
                    proto, self.BOGUS_HOST, "u", "p", self.TIMEOUT
                )
                self.assertIsNone(raw, "不存在的主机不应返回数据")
                self.assertTrue(err, "失败必须带原因，不能是空串")
                # 解码失败会产生替换字符；出现即说明编码没统一
                self.assertNotIn("\ufffd", err)
                # "退出码 N" 是丢失真实原因后的兜底文本，不应出现
                self.assertFalse(
                    err.startswith("PowerShell 退出码"),
                    f"真实错误信息丢失，只剩兜底文本: {err!r}",
                )


class ErrorTruncationTest(unittest.TestCase):
    """原始报错按展示长度截断，但归类必须用完整原文。"""

    def test_long_error_is_truncated_for_display(self):
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr="X" * 500, returncode=2),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport=TRANSPORT_DCOM)
        self.assertIn("…", d["wmi_error"])
        self.assertLess(len(d["wmi_error"]), 300)

    def test_short_text_not_truncated(self):
        self.assertEqual(wmi_mod._truncate("short"), "short")

    def test_classification_uses_full_text_not_truncated(self):
        """关键词可能落在 160 字符之后 —— 归类必须看完整原文。"""
        runner = _ScriptedRunner({
            "Dcom": _FakeProc(stdout="", stderr=("X" * 300) + " Access is denied",
                              returncode=2),
        })
        with mock.patch.object(wmi_mod.subprocess, "run", runner):
            d = wmi_query("10.0.0.5", "admin", "pwd", transport=TRANSPORT_DCOM)
        self.assertIn("凭据被拒绝", d["wmi_error"], "截断后仍应给出归类提示")


class TransportLabelTest(unittest.TestCase):
    def test_labels_are_translated_lazily(self):
        import i18n
        i18n.init("zh-CN")
        zh_auto = transport_label(TRANSPORT_AUTO)
        self.assertIn("自动", zh_auto)
        # "WinRM" 是专有名词，两种语言下都是同一个词
        self.assertEqual(transport_label(TRANSPORT_WINRM), "WinRM")

        i18n.init("en-US")
        try:
            self.assertEqual(transport_label(TRANSPORT_AUTO), "Automatic (try DCOM first, then WinRM)")
            # "WinRM" 是专有名词，两种语言一致
            self.assertEqual(transport_label(TRANSPORT_WINRM), "WinRM")
            self.assertNotEqual(transport_label(TRANSPORT_AUTO), zh_auto)
        finally:
            i18n.init("zh-CN")

    def test_unknown_value_passes_through(self):
        self.assertEqual(transport_label("weird"), "weird")


class FullUsernameTest(unittest.TestCase):
    def test_domain_prefixed(self):
        self.assertEqual(_full_username("admin", "CORP"), "CORP\\admin")

    def test_existing_separator_wins(self):
        self.assertEqual(_full_username("CORP\\admin", "OTHER"), "CORP\\admin")

    def test_no_domain(self):
        self.assertEqual(_full_username("admin", ""), "admin")


class CredStoreTransportTest(unittest.TestCase):
    def test_default_is_auto(self):
        from scanner.cred_store import WmiCredentialStore
        self.assertEqual(WmiCredentialStore().transport, TRANSPORT_AUTO)

    def test_set_stores_transport(self):
        from scanner.cred_store import WmiCredentialStore
        s = WmiCredentialStore()
        s.set("admin", "pwd", "CORP", TRANSPORT_WINRM)
        self.assertEqual(s.transport, TRANSPORT_WINRM)

    def test_invalid_transport_falls_back_to_auto(self):
        from scanner.cred_store import WmiCredentialStore
        s = WmiCredentialStore()
        s.set("admin", "pwd", "CORP", "garbage")
        self.assertEqual(s.transport, TRANSPORT_AUTO)

    def test_set_without_transport_keeps_previous(self):
        from scanner.cred_store import WmiCredentialStore
        s = WmiCredentialStore()
        s.set("admin", "pwd", "CORP", TRANSPORT_WINRM)
        s.set("admin", "pwd2", "CORP")
        self.assertEqual(s.transport, TRANSPORT_WINRM)

    def test_transport_roundtrip_via_settings(self):
        """transport 是明文偏好（非敏感），应与用户名一起持久化。"""
        import tempfile
        from PyQt5.QtCore import QSettings
        from scanner.cred_store import WmiCredentialStore
        fd, path = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        try:
            s1 = QSettings(path, QSettings.IniFormat)
            store = WmiCredentialStore()
            store.set("admin", "pwd", "CORP", TRANSPORT_WINRM)
            store.save_to(s1)
            s1.sync()

            s2 = QSettings(path, QSettings.IniFormat)
            loaded = WmiCredentialStore()
            loaded.load_from(s2)
            self.assertEqual(loaded.transport, TRANSPORT_WINRM)
        finally:
            os.remove(path)

    def test_corrupt_stored_transport_falls_back_to_auto(self):
        import tempfile
        from PyQt5.QtCore import QSettings
        from scanner.cred_store import WmiCredentialStore
        fd, path = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        try:
            s1 = QSettings(path, QSettings.IniFormat)
            s1.setValue("wmi/transport", "!!corrupt!!")
            s1.sync()
            s2 = QSettings(path, QSettings.IniFormat)
            loaded = WmiCredentialStore()
            loaded.load_from(s2)
            self.assertEqual(loaded.transport, TRANSPORT_AUTO)
        finally:
            os.remove(path)


class CredentialDialogTest(unittest.TestCase):
    """对话框要能选传输方式，且回传语言无关的规范值。"""

    def setUp(self):
        from tests._qt_app import ensure_qt_app
        ensure_qt_app()
        import i18n
        i18n.init("zh-CN")

    def test_get_credentials_returns_transport(self):
        from ui_dialogs import WmiCredentialDialog
        dlg = WmiCredentialDialog(saved_username="admin", saved_domain="CORP",
                                  saved_transport=TRANSPORT_WINRM)
        try:
            user, pwd, domain, save, transport = dlg.get_credentials()
            self.assertEqual(user, "admin")
            self.assertEqual(domain, "CORP")
            self.assertEqual(transport, TRANSPORT_WINRM)
        finally:
            dlg.deleteLater()

    def test_combo_items_use_canonical_values(self):
        from ui_dialogs import WmiCredentialDialog
        dlg = WmiCredentialDialog()
        try:
            values = [dlg.transport_combo.itemData(i)
                      for i in range(dlg.transport_combo.count())]
            self.assertEqual(values, [TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM])
        finally:
            dlg.deleteLater()

    def test_unknown_saved_transport_selects_auto(self):
        from ui_dialogs import WmiCredentialDialog
        dlg = WmiCredentialDialog(saved_transport="bogus")
        try:
            self.assertEqual(dlg.transport_combo.currentData(), TRANSPORT_AUTO)
        finally:
            dlg.deleteLater()


if __name__ == "__main__":
    unittest.main()
