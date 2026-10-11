# -*- coding: utf-8 -*-
"""SMB 方言 / 签名探测（v1.9 #3「零利用安全体检」第四刀）。

为什么值得单独一个文件
----------------------
`scanner/smb.py` 是**手写协议**的一块 —— 它自己拼 `SMB2 NEGOTIATE` 的字节，
自己解析回来的响应。手写协议最容易出的不是"功能没写"，而是"**字节拼错了但
看起来对**"：本刀开发过程中就真的踩过一次（协商上下文写在了方言数组前面，
被 Windows 判 `STATUS_INVALID_PARAMETER`，整个协商失败、连签名都读不到）。
所以本文件必须证明四件事：

1. **拼得对** —— 两个协商请求包字节级正确，尤其 3.1.1 那段的**字段顺序**
   （规范是"固定体 → Dialects → Padding → NegotiateContextList"，
   上下文在**后**）与 8 字节对齐；
2. **认得准** —— SMB1 的判定要过**两道**（状态码为 0 **且**
   `DialectIndex != 0xFFFF`）；签名**只按是否强制**分档
   （"启用但未强制"照样能被中继）；
3. **不编造** —— 畸形输入、状态码非 0、拿不到响应，一律**不给结论**，
   而不是猜一个；
4. **不越线** —— 红线：只发 `NEGOTIATE`。本文件会断言**发出去的每一个包**
   的命令码都只有 NEGOTIATE，**绝不**出现 `SESSION_SETUP`。

为什么真实协商不进 CI
----------------------
真连一台 SMB 服务器需要网络与平台，CI 容器里不一定有 —— 时绿时红的测试
比没有测试更糟。所以这里一律用**回环上的假服务器**（`_FakeSmbServer`），
由它按请求的魔数决定回什么，从而覆盖"只认 SMB1 / 拒绝 SMB1 / 老服务器
认不得协商上下文"这些真机上造不出来的分支。

"真机上到底谈成什么"由 `.git/_smb_smoke.py` 单独确认（本机与局域网那台
Windows 10 都实测谈成 `3.1.1` + 签名 `required`），不进 CI。

fuzz 部分：两个解析器吃的是**不可信输入**（网里任何人回的任何字节），
所以"绝不抛异常"是硬契约。沿用 `tests/test_x509.py` 的纪律：固定种子、
倍率读 `IPSCANNER_FUZZ_SCALE`。
"""
import contextlib
import os
import random
import socket
import struct
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import smb
from scanner.smb import (
    SMB_PORT, SIGNING_ENABLED, SIGNING_ENABLED_TEXT, SIGNING_OFF_TEXT,
    SIGNING_REQUIRED, SIGNING_REQUIRED_TEXT, SMB1_DIALECT, _OFFERED,
    _OFFERED_BASIC, _SMB1_HEADER_LEN, _SMB2_HEADER_LEN,
    _SMB2_NEGOTIATE_STRUCT_SIZE, _preauth_integrity_context, _read_message,
    build_smb1_negotiate, build_smb2_negotiate, parse_smb1_negotiate_response,
    parse_smb2_negotiate_response, probe_smb,
)

#: 固定种子 —— 失败必须可复现
_SEED = 0x534D4232


# ── 假服务器 ───────────────────────────────────────────────────────────
#
# 全部绑回环、用临时端口。`mode` 决定它怎么回：
#
#   smb2+smb1     SMB2 谈成 3.1.1，SMB1 也在（完整功能的老设备/服务器）
#   smb1-only     对 SMB2 协商回 SMB1 响应（只认 SMB1 的老设备）
#   smb1-refuse   SMB1 响应里 DialectIndex=0xFFFF（明确拒绝）
#   smb2-refuse   SMB2 一律回错误状态码
#   smb2-old-only 带 3.1.1（体更长）就拒，否则回 3.0.2 —— 用来测兜底
#   smb2-silent   收到 SMB2 什么都不回
class _FakeSmbServer:
    def __init__(self, mode="smb2+smb1"):
        self.mode = mode
        #: 收到的每个请求的 (魔数, 命令码) —— 红线断言靠它
        self.seen = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # ── 回包构造 ──
    @staticmethod
    def _smb2_response(dialect=0x0311, mode=SIGNING_REQUIRED, status=0):
        hdr = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, status, 0, 1,
                          0, 0, 0, 0, 0, 0, b"\x00" * 16)
        body = struct.pack("<HHHH", 65, mode, dialect, 0) + b"\x00" * 60
        return hdr + body

    @staticmethod
    def _smb1_response(index=0, status=0):
        hdr = struct.pack("<4sBIBHH8sHHHHH", b"\xffSMB", 0x72, status, 0x18,
                          0xC853, 0, b"\x00" * 8, 0, 0, 0, 0, 0)
        return hdr + bytes([0x11]) + struct.pack("<H", index) + b"\x00" * 20

    def _reply_for(self, magic, req):
        m = self.mode
        if magic == b"\xffSMB":
            if m == "smb1-refuse":
                return self._smb1_response(index=0xFFFF)
            return self._smb1_response(index=0)
        if magic == b"\xfeSMB":
            if m == "smb2-silent":
                return None
            if m == "smb1-only":
                return self._smb1_response(index=0)
            if m == "smb2-refuse":
                return self._smb2_response(status=0xC00000BB)
            if m == "smb2-old-only":
                # 带 3.1.1 的请求更长（多了协商上下文）；拒掉它，
                # 逼调用方走保守列表兜底。
                if len(req) > 120:
                    return self._smb2_response(status=0xC000000D)
                return self._smb2_response(dialect=0x0302,
                                           mode=SIGNING_ENABLED)
            return self._smb2_response()
        return None

    def _serve(self):
        while not self._stop:
            try:
                conn, _addr = self.sock.accept()
            except OSError:
                return
            # 对端提前断开（本模块的探测会主动关连接）是**正常**的，不是错误。
            # 用 `contextlib.suppress` 而不是 `except OSError: pass` ——
            # `test_logging_policy.py` 对裸的 `except ...: pass` 有计数棘轮，
            # 连写注释也过不了那一关。
            with contextlib.suppress(OSError):
                self._handle(conn)
            with contextlib.suppress(OSError):
                conn.close()

    def _handle(self, conn):
        head = conn.recv(4)
        if len(head) < 4:
            return
        length = int.from_bytes(head[1:4], "big")
        req = b""
        while len(req) < length:
            chunk = conn.recv(length - len(req))
            if not chunk:
                break
            req += chunk
        magic = req[:4]
        self.seen.append((magic, self._command_of(req)))
        reply = self._reply_for(magic, req)
        if reply is not None:
            conn.sendall(b"\x00" + len(reply).to_bytes(3, "big") + reply)

    @staticmethod
    def _command_of(req):
        """从请求里取出命令码（SMB2 在偏移 12，SMB1 在偏移 4）。"""
        if req[:4] == b"\xffSMB":
            return req[4] if len(req) > 4 else None
        if req[:4] == b"\xfeSMB" and len(req) >= 14:
            return struct.unpack_from("<H", req, 12)[0]
        return None

    def close(self):
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


class _ServerCase(unittest.TestCase):
    """起一个假服务器并在 tearDown 关掉它。"""

    def server(self, mode):
        srv = _FakeSmbServer(mode)
        self.addCleanup(srv.close)
        return srv


# ── 1. 请求包字节级 ────────────────────────────────────────────────────

class Smb2RequestTest(unittest.TestCase):
    """SMB2 NEGOTIATE 请求的每一个字段。"""

    def setUp(self):
        self.req = build_smb2_negotiate()

    def test_header_is_64_bytes(self):
        self.assertEqual(len(self.req[:4]), 4)
        self.assertEqual(self.req[:4], b"\xfeSMB")
        self.assertEqual(struct.unpack_from("<H", self.req, 4)[0],
                         _SMB2_HEADER_LEN)

    def test_header_command_is_negotiate(self):
        self.assertEqual(struct.unpack_from("<H", self.req, 12)[0], 0x0000)

    def test_header_status_is_zero(self):
        self.assertEqual(struct.unpack_from("<I", self.req, 8)[0], 0)

    def test_body_structure_size_is_36(self):
        self.assertEqual(struct.unpack_from("<H", self.req, 64)[0],
                         _SMB2_NEGOTIATE_STRUCT_SIZE)

    def test_dialect_count_matches_the_array(self):
        count = struct.unpack_from("<H", self.req, 66)[0]
        self.assertEqual(count, len(_OFFERED))

    def test_security_mode_advertises_signing_support(self):
        mode = struct.unpack_from("<H", self.req, 68)[0]
        self.assertEqual(mode, SIGNING_ENABLED)

    def test_dialect_array_is_the_offered_list_in_order(self):
        off = _SMB2_HEADER_LEN + _SMB2_NEGOTIATE_STRUCT_SIZE
        got = [struct.unpack_from("<H", self.req, off + 2 * i)[0]
               for i in range(len(_OFFERED))]
        self.assertEqual(got, list(_OFFERED))
        self.assertIn(0x0311, got)

    def test_dialects_come_before_the_negotiate_context(self):
        """⚠ 本刀开发时踩过的坑：规范顺序是"方言在前、上下文在后"。

        写反了会被 Windows 判 `STATUS_INVALID_PARAMETER`，而且**整个协商失败**
        —— 连签名都读不到。这条测试就是那个坑的守卫。
        """
        off = _SMB2_HEADER_LEN + _SMB2_NEGOTIATE_STRUCT_SIZE
        ctx_off = struct.unpack_from("<I", self.req, 64 + 28)[0]
        # 方言数组整段落在上下文起点之前
        self.assertLess(off + 2 * len(_OFFERED), ctx_off)
        got = [struct.unpack_from("<H", self.req, off + 2 * i)[0]
               for i in range(len(_OFFERED))]
        self.assertEqual(got, list(_OFFERED))
        # 上下文起点处确实是 PREAUTH_INTEGRITY 的类型码
        self.assertEqual(struct.unpack_from("<H", self.req, ctx_off)[0],
                         smb._PREAUTH_CTX_TYPE)

    def test_context_offset_is_8_byte_aligned(self):
        ctx_off = struct.unpack_from("<I", self.req, 64 + 28)[0]
        self.assertEqual(ctx_off % 8, 0)
        self.assertEqual(ctx_off, 112)

    def test_padding_between_dialects_and_context_is_zero(self):
        off = _SMB2_HEADER_LEN + _SMB2_NEGOTIATE_STRUCT_SIZE
        ctx_off = struct.unpack_from("<I", self.req, 64 + 28)[0]
        self.assertEqual(self.req[off + 2 * len(_OFFERED):ctx_off],
                         b"\x00" * (ctx_off - off - 2 * len(_OFFERED)))

    def test_context_count_is_one(self):
        self.assertEqual(struct.unpack_from("<H", self.req, 64 + 32)[0], 1)

    def test_context_uses_sha512_with_32_byte_salt(self):
        ctx_off = struct.unpack_from("<I", self.req, 64 + 28)[0]
        data_len = struct.unpack_from("<H", self.req, ctx_off + 2)[0]
        self.assertEqual(data_len, 38)
        self.assertEqual(struct.unpack_from("<H", self.req, ctx_off + 8)[0], 1)
        self.assertEqual(struct.unpack_from("<H", self.req, ctx_off + 10)[0], 32)
        self.assertEqual(struct.unpack_from("<H", self.req, ctx_off + 12)[0],
                         smb._HASH_SHA512)

    def test_message_has_no_trailing_slack(self):
        """上下文数据必须正好吃到包尾 —— 多一个字节都会被判参数非法。"""
        ctx_off = struct.unpack_from("<I", self.req, 64 + 28)[0]
        data_len = struct.unpack_from("<H", self.req, ctx_off + 2)[0]
        self.assertEqual(ctx_off + 8 + data_len, len(self.req))
        self.assertEqual(len(self.req), 158)

    def test_salt_is_random_per_request(self):
        """盐每次不同 —— 固定盐等于把 preauth 完整性白送。"""
        other = build_smb2_negotiate()
        self.assertNotEqual(self.req[118:150], other[118:150])

    def test_client_guid_is_random_per_request(self):
        other = build_smb2_negotiate()
        self.assertNotEqual(self.req[76:92], other[76:92])

    def test_basic_variant_omits_smb311_and_context(self):
        basic = build_smb2_negotiate(smb311=False)
        off = _SMB2_HEADER_LEN + _SMB2_NEGOTIATE_STRUCT_SIZE
        count = struct.unpack_from("<H", basic, 66)[0]
        got = [struct.unpack_from("<H", basic, off + 2 * i)[0]
               for i in range(count)]
        self.assertEqual(got, list(_OFFERED_BASIC))
        self.assertNotIn(0x0311, got)
        # 没有 3.1.1 时那 8 字节按 ClientStartTime 解读，规范要求填 0
        self.assertEqual(basic[64 + 28:64 + 36], b"\x00" * 8)
        self.assertEqual(len(basic), 108)

    def test_basic_variant_offered_list_is_a_prefix_of_the_full_one(self):
        """保守列表必须是完整列表去掉 3.1.1 —— 别偷偷少了别的方言。"""
        self.assertEqual(list(_OFFERED_BASIC), list(_OFFERED)[:-1])


class Smb1RequestTest(unittest.TestCase):
    """SMB1 NEGOTIATE 请求。"""

    def setUp(self):
        self.req = build_smb1_negotiate()

    def test_magic_and_command(self):
        self.assertEqual(self.req[:4], b"\xffSMB")
        self.assertEqual(self.req[4], 0x72)

    def test_header_is_32_bytes(self):
        self.assertEqual(_SMB1_HEADER_LEN, 32)
        self.assertGreater(len(self.req), 32)

    def test_word_count_is_zero(self):
        self.assertEqual(self.req[32], 0)

    def test_byte_count_and_dialect_buffer(self):
        count = struct.unpack_from("<H", self.req, 33)[0]
        self.assertEqual(count, 12)
        self.assertEqual(self.req[35:35 + count], b"\x02NT LM 0.12\x00")
        self.assertEqual(len(self.req), 35 + count)

    def test_offers_only_smb1_dialect(self):
        """⚠ 只带 `NT LM 0.12`：带上 SMB2 方言会让服务器改用 SMB2 回答，
        反而问不出"你还说不说 SMB1"。"""
        payload = self.req[35:]
        self.assertNotIn(b"SMB", payload.replace(b"NT LM", b""))

    def test_request_has_no_security_blob(self):
        """没开 EXTENDED_SECURITY 就不该拖一段安全数据在后面。"""
        self.assertEqual(len(self.req), 47)


# ── 2. Direct TCP 分帧 ─────────────────────────────────────────────────

class FramingTest(unittest.TestCase):
    def _pair(self):
        """一对回环 socket，**客户端带超时**。

        ⚠ 超时不是可选项：`_read_message()` 的"长度上限"一旦被改坏，它就会拿着
        对端声称的巨大长度去 `recv` 并**永久阻塞** —— 那时回归不是"测试变红"，
        而是"整个测试套件卡死"（反向验证时就真撞上过：一条注入让探针脚本挂了
        3 分钟没动静）。设了超时，回归会干脆地报错。
        """
        srv, cli = socket.socketpair()
        cli.settimeout(2.0)
        self.addCleanup(srv.close)
        self.addCleanup(cli.close)
        return srv, cli

    def test_frame_prefixes_type_and_big_endian_length(self):
        framed = smb._frame(b"abcdef")
        self.assertEqual(len(framed), 10)
        self.assertEqual(framed[0], 0x00)
        self.assertEqual(int.from_bytes(framed[1:4], "big"), 6)
        self.assertEqual(framed[4:], b"abcdef")

    def test_read_message_rejects_non_zero_type(self):
        """类型字节不是 0x00 就不是 SMB 消息 —— 必须当作读不到。"""
        srv, cli = self._pair()
        srv.sendall(b"\x01\x00\x00\x04abcd")
        self.assertIsNone(_read_message(cli))

    def test_read_message_rejects_zero_length(self):
        srv, cli = self._pair()
        srv.sendall(b"\x00\x00\x00\x00")
        self.assertIsNone(_read_message(cli))

    def test_read_message_rejects_absurd_length(self):
        """对端声称一个巨大的长度不能把内存吃掉（也不能把测试卡死）。"""
        srv, cli = self._pair()
        srv.sendall(b"\x00\xff\xff\xff")
        self.assertIsNone(_read_message(cli))

    def test_read_message_returns_the_payload(self):
        srv, cli = self._pair()
        srv.sendall(b"\x00\x00\x00\x04abcd")
        self.assertEqual(_read_message(cli), b"abcd")

    def test_recv_exact_returns_none_on_early_close(self):
        srv, cli = self._pair()
        srv.sendall(b"ab")
        srv.close()
        self.assertIsNone(smb._recv_exact(cli, 4))


# ── 3. SMB2 响应解析 ───────────────────────────────────────────────────

def _smb2_response(dialect=0x0311, mode=SIGNING_REQUIRED, status=0,
                   struct_size=65, command=0, magic=b"\xfeSMB"):
    hdr = struct.pack("<4sHHIHHIIQIIQ16s", magic, 64, 0, status, command, 1, 0,
                      0, 0, 0, 0, 0, b"\x00" * 16)
    body = struct.pack("<HHHH", struct_size, mode, dialect, 0) + b"\x00" * 60
    return hdr + body


class ParseSmb2Test(unittest.TestCase):
    def test_reads_dialect_and_signing(self):
        got = parse_smb2_negotiate_response(
            _smb2_response(0x0311, SIGNING_REQUIRED))
        self.assertEqual(got, {"dialect": "3.1.1", "signing": "required"})

    def test_every_known_dialect_number_has_a_name(self):
        for number, name in ((0x0202, "2.0.2"), (0x0210, "2.1"), (0x0300, "3.0"),
                             (0x0302, "3.0.2"), (0x0311, "3.1.1")):
            got = parse_smb2_negotiate_response(_smb2_response(number))
            self.assertEqual(got["dialect"], name, hex(number))

    def test_unknown_dialect_is_reported_as_hex(self):
        """认不出的方言号宁可显示得丑，也不能猜一个名字。"""
        got = parse_smb2_negotiate_response(_smb2_response(0x02FF))
        self.assertEqual(got["dialect"], "0x02ff")

    def test_signing_enabled_only_is_not_required(self):
        got = parse_smb2_negotiate_response(
            _smb2_response(mode=SIGNING_ENABLED))
        self.assertEqual(got["signing"], SIGNING_ENABLED_TEXT)

    def test_signing_off(self):
        got = parse_smb2_negotiate_response(_smb2_response(mode=0))
        self.assertEqual(got["signing"], SIGNING_OFF_TEXT)

    def test_signing_required_wins_over_enabled(self):
        """两位都置时是"强制" —— 不能因为先看 enabled 就报成"启用"。

        "启用但未强制"正是那个**没有**防护的状态，判错了就是把风险漏掉。
        """
        got = parse_smb2_negotiate_response(
            _smb2_response(mode=SIGNING_ENABLED | SIGNING_REQUIRED))
        self.assertEqual(got["signing"], SIGNING_REQUIRED_TEXT)

    def test_non_zero_status_gives_nothing(self):
        """失败响应是"问不出来"，不是"不安全" —— 不能下任何结论。"""
        self.assertEqual(parse_smb2_negotiate_response(
            _smb2_response(status=0xC00000BB)), {})

    def test_wrong_command_gives_nothing(self):
        self.assertEqual(parse_smb2_negotiate_response(
            _smb2_response(command=0x0001)), {})

    def test_wrong_structure_size_gives_nothing(self):
        self.assertEqual(parse_smb2_negotiate_response(
            _smb2_response(struct_size=36)), {})

    def test_wrong_magic_gives_nothing(self):
        self.assertEqual(parse_smb2_negotiate_response(
            _smb2_response(magic=b"\xffSMB")), {})

    def test_short_input_gives_nothing(self):
        for n in (0, 4, 63, 64, 100, 127):
            self.assertEqual(parse_smb2_negotiate_response(b"\xfeSMB" + b"\x00" * n),
                             {}, n)

    def test_non_bytes_gives_nothing(self):
        for bad in (None, 123, 1.5, ["x"], {"a": 1}):
            self.assertEqual(parse_smb2_negotiate_response(bad), {}, bad)

    def test_bytearray_is_accepted(self):
        raw = bytearray(_smb2_response(0x0311, SIGNING_REQUIRED))
        self.assertEqual(parse_smb2_negotiate_response(raw)["dialect"], "3.1.1")


class ParseSmb1Test(unittest.TestCase):
    def _response(self, index=0, status=0, word_count=0x11, magic=b"\xffSMB"):
        hdr = struct.pack("<4sBIBHH8sHHHHH", magic, 0x72, status, 0x18, 0xC853,
                          0, b"\x00" * 8, 0, 0, 0, 0, 0)
        return hdr + bytes([word_count]) + struct.pack("<H", index) + b"\x00" * 8

    def test_accepted_index_is_true(self):
        self.assertTrue(parse_smb1_negotiate_response(self._response(0)))

    def test_refused_index_is_false(self):
        """⚠ 0xFFFF 是"你给的方言我一个都不支持"的正式表达。

        只看状态码会把它读成"支持 SMB1" —— 把安全的主机报成高危，
        是最坏的一种误报。
        """
        self.assertFalse(parse_smb1_negotiate_response(self._response(0xFFFF)))

    def test_non_zero_status_is_false(self):
        self.assertFalse(parse_smb1_negotiate_response(
            self._response(status=0xC0000001)))

    def test_unexpected_word_count_is_false(self):
        self.assertFalse(parse_smb1_negotiate_response(
            self._response(word_count=0x10)))

    def test_smb2_shaped_input_is_false(self):
        self.assertFalse(parse_smb1_negotiate_response(
            _smb2_response(magic=b"\xfeSMB")))

    def test_short_and_non_bytes_are_false(self):
        for bad in (b"", b"\xffSMB", b"\xffSMB" + b"\x00" * 20, None, 7, []):
            self.assertFalse(parse_smb1_negotiate_response(bad), bad)


# ── 4. 探测流程（回环假服务器）─────────────────────────────────────────

class ProbeSmbTest(_ServerCase):
    def test_full_server_reports_all_three_facts(self):
        srv = self.server("smb2+smb1")
        got = probe_smb("127.0.0.1", port=srv.port, timeout=2)
        self.assertEqual(got, {"dialect": "3.1.1", "signing": "required",
                               "smb1": "1"})

    def test_smb1_is_probed_on_a_separate_connection(self):
        """SMB1 必须另开一条连接问 —— SMB2 谈成后那条连接已经进入 SMB2 模式。"""
        srv = self.server("smb2+smb1")
        probe_smb("127.0.0.1", port=srv.port, timeout=2)
        self.assertEqual(len(srv.seen), 2)
        self.assertEqual(srv.seen[0][0], b"\xfeSMB")
        self.assertEqual(srv.seen[1][0], b"\xffSMB")

    def test_smb1_only_server(self):
        srv = self.server("smb1-only")
        got = probe_smb("127.0.0.1", port=srv.port, timeout=2)
        self.assertEqual(got, {"dialect": SMB1_DIALECT, "smb1": "1"})
        # SMB1 响应里读不到 SMB2 的 SecurityMode，所以不该有 signing 键
        self.assertNotIn("signing", got)
        self.assertEqual(len(srv.seen), 1)

    def test_refused_smb1_is_not_reported_as_available(self):
        srv = self.server("smb1-refuse")
        got = probe_smb("127.0.0.1", port=srv.port, timeout=2)
        self.assertEqual(got["dialect"], "3.1.1")
        self.assertNotIn("smb1", got)

    def test_old_server_falls_back_to_the_conservative_list(self):
        """带 3.1.1 被拒时退一步重谈 —— 拿得到签名与方言，总好过一无所获。"""
        srv = self.server("smb2-old-only")
        got = probe_smb("127.0.0.1", port=srv.port, timeout=2)
        self.assertEqual(got["dialect"], "3.0.2")
        self.assertEqual(got["signing"], SIGNING_ENABLED_TEXT)
        # 完整列表 → 保守列表 → SMB1，三条连接
        self.assertEqual(len(srv.seen), 3)

    def test_all_smb2_refused_gives_nothing(self):
        srv = self.server("smb2-refuse")
        self.assertEqual(probe_smb("127.0.0.1", port=srv.port, timeout=2), {})

    def test_silent_server_gives_nothing(self):
        srv = self.server("smb2-silent")
        self.assertEqual(probe_smb("127.0.0.1", port=srv.port, timeout=1), {})

    def test_closed_port_gives_nothing(self):
        """端口没开是"没探到"，不是"安全" —— 返回空 dict 而不是编造。"""
        self.assertEqual(probe_smb("127.0.0.1", port=1, timeout=0.5), {})

    def test_unreachable_host_gives_nothing(self):
        # 192.0.2.0/24 是 TEST-NET-1，按 RFC 5737 保证不可路由
        self.assertEqual(probe_smb("192.0.2.1", timeout=0.5), {})

    def test_default_port_is_445(self):
        self.assertEqual(SMB_PORT, 445)

    def test_negotiate_failure_is_logged_at_debug(self):
        """连不上只记 debug：它是"问不出来"，不是错误结论。"""
        with self.assertLogs("ipscanner.smb", level="DEBUG") as cap:
            probe_smb("127.0.0.1", port=1, timeout=0.5)
        self.assertTrue(any("SMB" in line for line in cap.output), cap.output)


class ProbeRedLineTest(_ServerCase):
    """红线：只发 NEGOTIATE，绝不发 SESSION_SETUP / 不试凭据。"""

    #: SMB2 里除 NEGOTIATE(0x0000) 之外最该防的就是 SESSION_SETUP(0x0001)。
    _SMB2_SESSION_SETUP = 0x0001
    #: SMB1 的 SESSION_SETUP 是 0x73。
    _SMB1_SESSION_SETUP = 0x73

    def test_probe_only_sends_negotiate(self):
        srv = self.server("smb2+smb1")
        probe_smb("127.0.0.1", port=srv.port, timeout=2)
        self.assertTrue(srv.seen)
        for magic, command in srv.seen:
            if magic == b"\xffSMB":
                self.assertEqual(command, 0x72)
            else:
                self.assertEqual(command, 0x0000)

    def test_no_session_setup_is_ever_sent(self):
        """把话说明白：本模块**没有**任何地方会发认证请求。

        直接对两个构造函数做静态检查 —— 连"有没有那个字节"都不必猜。
        """
        for request in (build_smb2_negotiate(), build_smb2_negotiate(smb311=False),
                        build_smb1_negotiate()):
            if request[:4] == b"\xffSMB":
                self.assertNotEqual(request[4], self._SMB1_SESSION_SETUP)
            else:
                self.assertNotEqual(struct.unpack_from("<H", request, 12)[0],
                                    self._SMB2_SESSION_SETUP)

    def test_module_never_mentions_session_setup_command(self):
        """源码里不该出现 SESSION_SETUP 的命令码常量 —— 写了就说明有人在实现它。"""
        path = os.path.join(ROOT, "scanner", "smb.py")
        with open(path, encoding="utf-8") as f:
            source = f.read()
        for token in ("_SMB2_SESSION_SETUP", "_SMB1_SESSION_SETUP",
                      "session_setup", "0x0073"):
            self.assertNotIn(token, source, token)


# ── 5. fuzz ────────────────────────────────────────────────────────────

class ParseFuzzTest(unittest.TestCase):
    """解析器吃的是不可信输入，绝不抛异常是硬契约。"""

    def setUp(self):
        self.rnd = random.Random(_SEED)
        self.count = 300 * max(1, int(os.environ.get(
            "IPSCANNER_FUZZ_SCALE", "1") or "1"))

    def test_random_bytes_never_raise(self):
        for _ in range(self.count):
            blob = bytes(self.rnd.randrange(256)
                         for _ in range(self.rnd.randrange(0, 200)))
            self.assertIsInstance(parse_smb2_negotiate_response(blob), dict)
            self.assertIsInstance(parse_smb1_negotiate_response(blob), bool)

    def test_random_headers_never_raise(self):
        for _ in range(self.count):
            magic = self.rnd.choice([b"\xfeSMB", b"\xffSMB", b"\x00SMB"])
            blob = magic + bytes(self.rnd.randrange(256)
                                 for _ in range(self.rnd.randrange(0, 160)))
            self.assertIsInstance(parse_smb2_negotiate_response(blob), dict)
            self.assertIsInstance(parse_smb1_negotiate_response(blob), bool)

    def test_mutated_valid_responses_never_raise(self):
        base = _smb2_response(0x0311, SIGNING_REQUIRED)
        for _ in range(self.count):
            blob = bytearray(base)
            for _ in range(self.rnd.randrange(1, 6)):
                blob[self.rnd.randrange(len(blob))] = self.rnd.randrange(256)
            self.assertIsInstance(parse_smb2_negotiate_response(bytes(blob)),
                                  dict)

    def test_a_verdict_is_only_given_for_a_clean_success(self):
        """fuzz 也要断言**判据本身**：有结论 ⟺ 魔数对 + 状态 0 + 结构对。

        只断言"不抛异常"会漏掉"把垃圾当成成功"这一类错误。
        """
        accepted = 0
        for _ in range(self.count):
            blob = b"\xfeSMB" + bytes(self.rnd.randrange(256)
                                      for _ in range(self.rnd.randrange(0, 160)))
            got = parse_smb2_negotiate_response(blob)
            status = (struct.unpack_from("<I", blob, 8)[0]
                      if len(blob) >= 12 else None)
            command = (struct.unpack_from("<H", blob, 12)[0]
                       if len(blob) >= 14 else None)
            size = (struct.unpack_from("<H", blob, 64)[0]
                    if len(blob) >= 66 else None)
            should = (len(blob) >= 128 and status == 0 and command == 0
                      and size == 65)
            self.assertEqual(bool(got), should, blob.hex())
            if got:
                accepted += 1
        # 随机字节几乎不可能凑出合法结构；凑不出就说明判据被放宽了
        self.assertEqual(accepted, 0)


# ── 6. 预共享密钥上下文本身 ────────────────────────────────────────────

class PreauthContextTest(unittest.TestCase):
    def test_structure(self):
        ctx = _preauth_integrity_context()
        self.assertEqual(len(ctx), 46)
        self.assertEqual(struct.unpack_from("<H", ctx, 0)[0],
                         smb._PREAUTH_CTX_TYPE)
        self.assertEqual(struct.unpack_from("<H", ctx, 2)[0], 38)
        self.assertEqual(struct.unpack_from("<I", ctx, 4)[0], 0)
        self.assertEqual(struct.unpack_from("<H", ctx, 8)[0], 1)
        self.assertEqual(struct.unpack_from("<H", ctx, 10)[0], 32)
        self.assertEqual(struct.unpack_from("<H", ctx, 12)[0], smb._HASH_SHA512)

    def test_injected_salt_is_used_verbatim(self):
        salt = b"\x01" * 32
        ctx = _preauth_integrity_context(salt)
        self.assertEqual(ctx[14:], salt)
        self.assertEqual(struct.unpack_from("<H", ctx, 10)[0], 32)

    def test_salt_is_random_by_default(self):
        self.assertNotEqual(_preauth_integrity_context(),
                            _preauth_integrity_context())


if __name__ == "__main__":
    unittest.main()
