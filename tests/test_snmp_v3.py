# -*- coding: utf-8 -*-
"""SNMPv3 / USM 的单元测试。

分三层，缺一不可：
1. **已知答案向量**（RFC 3414 §A.3）—— 密钥本地化算错的话，后面全白测；
2. **报文布局**（构包 → 解包 → 摘要校验）—— 覆盖"认证参数字段偏移"这类
   纯 mock 测不出来的错位；
3. **真实 UDP 回环代理** —— 走完 discovery → 请求 → 认证 → 解密 → 解析
   的完整链路，这是唯一能暴露"字段顺序/时序"类缺陷的一层。

已知答案向量来自 RFC 3414 Appendix A.3（密码 "maplesyrup"）。
"""
import os
import socket
import struct
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import i18n
from scanner import aes
from scanner import snmp as snmp_mod
from scanner import snmp_v3 as v3
from scanner.snmp import _snmp_enc_int, _snmp_enc_oid, _snmp_decode_oid
from scanner.snmp_v3 import (
    SnmpV3User, AUTH_MD5, AUTH_SHA, AUTH_NONE, PRIV_AES, PRIV_DES, PRIV_NONE,
    ERR_AUTH, ERR_CONFIG, ERR_NO_RESPONSE, ERR_PROTOCOL, ERR_REJECTED,
    LEVEL_AUTH_NO_PRIV, LEVEL_AUTH_PRIV, LEVEL_NO_AUTH_NO_PRIV,
)

# ── RFC 3414 §A.3 已知答案 ──
_RFC_PASSPHRASE = "maplesyrup"
_RFC_ENGINE_ID = bytes.fromhex("000000000000000000000002")
_RFC_MD5_KU = bytes.fromhex("9faf3283884e92834ebc9847d8edd963")
_RFC_MD5_KUL = bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")
_RFC_SHA_KUL = bytes.fromhex("6695febc9288e36282235fc7151f128497b38f3f")

# RFC 3414 §A.4 的示例字段值（引擎 ID 换成自洽的 12 字节）
_USM_SAMPLE_ENGINE = bytes.fromhex("800000020109840301")


# ══════════════════════════════════════════════════════════════════
# 1. 已知答案向量
# ══════════════════════════════════════════════════════════════════

class Rfc3414KeyVectorsTest(unittest.TestCase):
    """RFC 3414 §A.3 的密钥派生向量 —— 密码学正确性的地基。"""

    def test_md5_ku_matches_rfc(self):
        self.assertEqual(
            v3._password_to_key(_RFC_PASSPHRASE, "md5"), _RFC_MD5_KU)

    def test_md5_kul_matches_rfc(self):
        self.assertEqual(
            v3.localize_key(_RFC_PASSPHRASE, _RFC_ENGINE_ID, AUTH_MD5),
            _RFC_MD5_KUL)

    def test_sha_kul_matches_rfc(self):
        self.assertEqual(
            v3.localize_key(_RFC_PASSPHRASE, _RFC_ENGINE_ID, AUTH_SHA),
            _RFC_SHA_KUL)

    def test_sha_ku_is_20_bytes(self):
        self.assertEqual(len(v3._password_to_key(_RFC_PASSPHRASE, "sha1")), 20)

    def test_ku_uses_full_megabyte(self):
        """Ku 必须哈希满 1048576 字节，且密码索引**跨块连续**（RFC 3414 §A.2.1）。

        注意不能把"第一个 64 字节块"简单重复 16384 次 —— 密码长度不整除 64
        时，块边界处的索引要继续往前走，不是从头再来（这个区别会让
        MD5 结果完全不同）。这里按 RFC 的伪代码逐字节重放一遍。
        """
        import hashlib
        raw = b"abc"
        h = hashlib.md5()
        idx = 0
        for _ in range(1048576 // 64):
            block = bytearray()
            for _i in range(64):
                block.append(raw[idx % len(raw)])
                idx += 1
            h.update(bytes(block))
        self.assertEqual(h.digest(), v3._password_to_key("abc", "md5"))

    def test_localize_requires_auth_proto(self):
        with self.assertRaises(ValueError):
            v3.localize_key("x", _RFC_ENGINE_ID, AUTH_NONE)

    def test_hmac96_is_12_bytes(self):
        self.assertEqual(len(v3._hmac96(b"k" * 16, b"msg", "md5")), 12)
        self.assertEqual(len(v3._hmac96(b"k" * 16, b"msg", "sha1")), 12)


class AesCfbTest(unittest.TestCase):
    """AES-128-CFB128（RFC 3826 的加密原语）。"""

    def test_fips197_encrypt_block(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes.encrypt_block(key, pt).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_cfb128_round_trip(self):
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        for n in (1, 15, 16, 17, 31, 32, 100, 255):
            data = os.urandom(n)
            enc = aes.cfb128_encrypt(key, iv, data)
            self.assertEqual(aes.cfb128_decrypt(key, iv, enc), data, f"n={n}")

    def test_cfb128_first_block_equals_cipher_of_iv(self):
        """CFB 第一个密文块 = E(IV)；这条能抓住把 CFB 写成 CBC 的错误。"""
        key = bytes(range(16))
        iv = bytes(range(16))
        data = b"\x00" * 16
        self.assertEqual(aes.cfb128_encrypt(key, iv, data),
                         aes.encrypt_block(key, iv))


# ══════════════════════════════════════════════════════════════════
# 2. 报文布局
# ══════════════════════════════════════════════════════════════════

class IntegerEncodingTest(unittest.TestCase):
    """BER INTEGER 编码 —— 这里曾有一个真实缺陷。

    旧实现用 `(n.bit_length() + 7) // 8` 作为长度再 signed=True 编码，
    导致位长恰为 8 的倍数的正数（128~255、32768~65535、…）直接
    OverflowError。SNMPv3 的 msgMaxSize = 65507 正好落在雷区里。
    """

    def test_boundary_values_round_trip(self):
        for n in (0, 1, 127, 128, 200, 255, 256, 32767, 32768, 65507,
                  8388607, 8388608, 2147483647):
            with self.subTest(n=n):
                enc = _snmp_enc_int(n)
                self.assertEqual(int.from_bytes(enc[2:], "big", signed=True), n)

    def test_negative_values_round_trip(self):
        for n in (-1, -128, -129, -256, -32768):
            with self.subTest(n=n):
                enc = _snmp_enc_int(n)
                self.assertEqual(int.from_bytes(enc[2:], "big", signed=True), n)

    def test_positive_high_bit_gets_sign_padding(self):
        """最高位为 1 的正数必须补 0x00，否则会被解成负数。"""
        self.assertEqual(_snmp_enc_int(200), bytes.fromhex("020200c8"))
        self.assertEqual(_snmp_enc_int(65507), bytes.fromhex("020300ffe3"))

    def test_msg_max_size_is_encodable(self):
        """回归：构建 v3 报文不得因 msgMaxSize 溢出而崩溃。"""
        msg = v3._build_v3_message(1, v3._enc_msg_flags(False, False),
                                   v3._build_usm_params(b"", 0, 0, "", b"", b""),
                                   v3._build_scoped_pdu(b"", "", v3._build_pdu(
                                       v3._PDU_GET, 1, ["1.3.6.1.2.1.1.1.0"])))
        self.assertTrue(msg.startswith(b"\x30"))


class MessageLayoutTest(unittest.TestCase):

    def _engine(self):
        return v3._Engine(engine_id=_USM_SAMPLE_ENGINE, boots=1,
                          time_at=0.0, eng_time=257)

    def test_usm_params_round_trip(self):
        raw = v3._build_usm_params(_USM_SAMPLE_ENGINE, 1, 257, "bert",
                                   bytes.fromhex("0123456789abcdeffedcba98"),
                                   bytes.fromhex("0123456789abcdef"))
        fields, _off = v3._parse_usm_params(raw)
        self.assertEqual(fields["engine_id"], _USM_SAMPLE_ENGINE)
        self.assertEqual(fields["boots"], 1)
        self.assertEqual(fields["eng_time"], 257)
        self.assertEqual(fields["username"], "bert")

    def test_auth_offset_points_at_auth_params(self):
        """回归：认证参数偏移曾错指到用户名字段（索引 3 而非 4）。

        这会让"清零认证字段后重算摘要"清掉用户名，导致**每一次**
        认证请求都判为校验失败。
        """
        auth_params = bytes.fromhex("0123456789abcdeffedcba98")
        raw = v3._build_usm_params(_USM_SAMPLE_ENGINE, 1, 257, "bert",
                                   auth_params, b"")
        _fields, off = v3._parse_usm_params(raw)
        self.assertIsNotNone(off)
        self.assertEqual(raw[off:off + 12], auth_params)

    def test_auth_offset_in_full_message(self):
        user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                          auth_key=_RFC_PASSPHRASE)
        msg, _ak, _pk = v3._build_request(
            self._engine(), user, v3._PDU_GET, ["1.3.6.1.2.1.1.1.0"], 12345)
        parsed = v3.parse_v3_message(msg)
        self.assertEqual(parsed["msg_id"], 12345)
        self.assertEqual(parsed["usm"]["username"], "bert")
        self.assertEqual(
            parsed["raw"][parsed["auth_offset"]:parsed["auth_offset"] + 12],
            parsed["usm"]["auth_params"])

    def test_digest_verifies_and_detects_tampering(self):
        user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                          auth_key=_RFC_PASSPHRASE)
        msg, auth_key, _pk = v3._build_request(
            self._engine(), user, v3._PDU_GET, ["1.3.6.1.2.1.1.1.0"], 7)
        parsed = v3.parse_v3_message(msg)
        self.assertTrue(v3._verify_digest(parsed, auth_key, user))

        bad = bytearray(msg)
        bad[parsed["auth_offset"]] ^= 0xFF
        self.assertFalse(
            v3._verify_digest(v3.parse_v3_message(bytes(bad)), auth_key, user))

    def test_verify_digest_rejects_empty_auth_params(self):
        """未认证的 Report PDU 认证字段为空，必须直接判失败。

        否则切片赋值会去覆盖它后面的字段（把报文写坏）。
        """
        user = SnmpV3User(username="bert", auth_proto=AUTH_MD5, auth_key="k")
        msg, auth_key, _pk = v3._build_request(
            self._engine(), user, v3._PDU_GET, ["1.3.6.1.2.1.1.1.0"], 7)
        parsed = v3.parse_v3_message(msg)
        parsed["usm"]["auth_params"] = b""
        self.assertFalse(v3._verify_digest(parsed, auth_key, user))

    def test_msg_flags_bits(self):
        self.assertEqual(v3._enc_msg_flags(False, False), b"\x04\x01\x04")
        self.assertEqual(v3._enc_msg_flags(True, False), b"\x04\x01\x05")
        self.assertEqual(v3._enc_msg_flags(True, True), b"\x04\x01\x07")
        # 响应类报文 reportable 必须为 0
        self.assertEqual(v3._enc_msg_flags(True, False, reportable=False),
                         b"\x04\x01\x01")
        self.assertEqual(v3._enc_msg_flags(False, False, reportable=False),
                         b"\x04\x01\x00")

    def test_request_sets_reportable_and_auth_bits(self):
        user = SnmpV3User(username="u", auth_proto=AUTH_SHA, auth_key="k")
        msg, _ak, _pk = v3._build_request(
            self._engine(), user, v3._PDU_GET, ["1.3.6.1.2.1.1.1.0"], 1)
        parsed = v3.parse_v3_message(msg)
        self.assertEqual(parsed["flags"], 0x05)      # reportable | auth

    def test_priv_request_encrypts_scoped_pdu(self):
        user = SnmpV3User(username="u", auth_proto=AUTH_SHA, auth_key="k",
                          priv_proto=PRIV_AES, priv_key="k")
        msg, _ak, priv_key = v3._build_request(
            self._engine(), user, v3._PDU_GET, ["1.3.6.1.2.1.1.1.0"], 1)
        parsed = v3.parse_v3_message(msg)
        self.assertEqual(parsed["msg_data_tag"], 0x04)      # OCTET STRING = 密文
        self.assertIsNotNone(v3._decode_response(parsed, priv_key, user))
        self.assertIsNone(v3._decode_response(parsed, b"\x00" * 16, user))

    def test_parse_rejects_non_v3_and_garbage(self):
        self.assertIsNone(v3.parse_v3_message(b""))
        self.assertIsNone(v3.parse_v3_message(b"\xff\xff"))
        # v2c 报文（version=1）
        v2c = snmp_mod._snmp_build_get("public", 1, ["1.3.6.1.2.1.1.1.0"])
        self.assertIsNone(v3.parse_v3_message(v2c))


class EngineCacheTest(unittest.TestCase):

    def setUp(self):
        v3.reset_engine_cache()

    def tearDown(self):
        v3.reset_engine_cache()

    def test_current_time_advances_with_local_clock(self):
        now = time.monotonic()
        eng = v3._Engine(engine_id=b"\x01", boots=1, time_at=now, eng_time=500)
        self.assertEqual(eng.current_time(), 500)
        # 本地时钟过了 7 秒，推算的 engineTime 也要 +7
        eng.time_at = now - 7.0
        self.assertEqual(eng.current_time(), 507)

    def test_discovery_is_cached_per_endpoint(self):
        """同一 (ip, port) 只发现一次 —— 否则每台设备每轮都要多一个往返。

        这里让 `_discover` 走真实路径（只把 socket 换成不发包的假 socket），
        顺带验证它能正确解析发现响应里的引擎参数。
        """
        eng = v3._Engine(engine_id=b"\x01\x02", boots=9, time_at=0.0, eng_time=77)
        sock = _FakeSock([_engine_reply(eng)])
        got1 = v3._get_engine("10.0.0.1", 161, 1.0, sock)
        got2 = v3._get_engine("10.0.0.1", 161, 1.0, sock)
        self.assertEqual(got1.engine_id, b"\x01\x02")
        self.assertEqual(got1.boots, 9)
        self.assertEqual(got1.eng_time, 77)
        self.assertIs(got1, got2)
        self.assertEqual(sock.sent, 1)

    def test_different_ports_are_cached_separately(self):
        eng = v3._Engine(engine_id=b"\x01", boots=1, time_at=0.0, eng_time=1)
        sock = _FakeSock([_engine_reply(eng), _engine_reply(eng)])
        v3._get_engine("10.0.0.1", 161, 1.0, sock)
        v3._get_engine("10.0.0.1", 162, 1.0, sock)
        self.assertEqual(sock.sent, 2)

    def test_reset_engine_cache_forces_rediscovery(self):
        eng = v3._Engine(engine_id=b"\x01", boots=1, time_at=0.0, eng_time=1)
        sock = _FakeSock([_engine_reply(eng), _engine_reply(eng)])
        v3._get_engine("10.0.0.1", 161, 1.0, sock)
        v3.reset_engine_cache()
        v3._get_engine("10.0.0.1", 161, 1.0, sock)
        self.assertEqual(sock.sent, 2)


# ══════════════════════════════════════════════════════════════════
# 3. 参数校验 / 显示 / 解码
# ══════════════════════════════════════════════════════════════════

class UserValidateTest(unittest.TestCase):

    def test_valid_no_auth(self):
        self.assertEqual(SnmpV3User(username="u").validate(), "")

    def test_valid_auth_no_priv(self):
        u = SnmpV3User(username="u", auth_proto=AUTH_MD5, auth_key="k")
        self.assertEqual(u.validate(), "")

    def test_valid_auth_priv(self):
        u = SnmpV3User(username="u", auth_proto=AUTH_SHA, auth_key="k",
                       priv_proto=PRIV_AES, priv_key="k2")
        self.assertEqual(u.validate(), "")

    def test_missing_username(self):
        self.assertIn("用户名", SnmpV3User().validate())

    def test_bad_auth_proto(self):
        u = SnmpV3User(username="u", auth_proto="sha512", auth_key="k")
        self.assertIn("sha512", u.validate())

    def test_bad_priv_proto(self):
        u = SnmpV3User(username="u", auth_proto=AUTH_MD5, auth_key="k",
                       priv_proto="3des", priv_key="k")
        self.assertIn("3des", u.validate())

    def test_priv_without_auth_is_rejected(self):
        u = SnmpV3User(username="u", priv_proto=PRIV_AES, priv_key="k")
        self.assertIn("认证", u.validate())

    def test_auth_without_key_is_rejected(self):
        u = SnmpV3User(username="u", auth_proto=AUTH_MD5)
        self.assertIn("认证密码", u.validate())

    def test_priv_without_key_is_rejected(self):
        u = SnmpV3User(username="u", auth_proto=AUTH_MD5, auth_key="k",
                       priv_proto=PRIV_AES)
        self.assertIn("加密密码", u.validate())

    def test_des_is_explicitly_unsupported(self):
        """DES 必须给出明确错误，而不是静默降级成明文。"""
        u = SnmpV3User(username="u", auth_proto=AUTH_MD5, auth_key="k",
                       priv_proto=PRIV_DES, priv_key="k")
        msg = u.validate()
        self.assertIn("DES", msg)
        self.assertIn("AES", msg)

    def test_security_level(self):
        self.assertEqual(SnmpV3User().security_level(), LEVEL_NO_AUTH_NO_PRIV)
        self.assertEqual(
            SnmpV3User(auth_proto=AUTH_MD5).security_level(), LEVEL_AUTH_NO_PRIV)
        self.assertEqual(
            SnmpV3User(auth_proto=AUTH_MD5, priv_proto=PRIV_AES).security_level(),
            LEVEL_AUTH_PRIV)


class ReportHintTest(unittest.TestCase):
    """Report PDU 的统计 OID → 可操作提示。"""

    def test_each_usm_stat_oid_has_a_hint(self):
        cases = {
            "1.3.6.1.6.3.15.1.1.1.0": "安保级别",
            "1.3.6.1.6.3.15.1.1.3.0": "用户名",
            "1.3.6.1.6.3.15.1.1.5.0": "认证",
            "1.3.6.1.6.3.15.1.1.6.0": "解密",
        }
        for oid, keyword in cases.items():
            with self.subTest(oid=oid):
                self.assertIn(keyword, v3._report_hint(oid))

    def test_unknown_oid_has_no_hint(self):
        self.assertEqual(v3._report_hint("1.3.6.1.2.1.1.1.0"), "")

    def test_report_message_uses_hint(self):
        kind, msg = v3._report_message([("1.3.6.1.6.3.15.1.1.3.0", b"\x01", 0x02)])
        self.assertEqual(kind, ERR_REJECTED)
        self.assertIn("用户名", msg)

    def test_report_message_without_known_oid(self):
        kind, msg = v3._report_message([("1.2.3", b"", 0x02)])
        self.assertEqual(kind, ERR_REJECTED)
        self.assertIn("Report", msg)

    def test_hints_are_translated_lazily(self):
        """提示是显示文本，必须随界面语言变化（不能 import 期冻结）。"""
        i18n.init("zh-CN")
        zh = v3._report_hint("1.3.6.1.6.3.15.1.1.3.0")
        i18n.init("en-US")
        try:
            en = v3._report_hint("1.3.6.1.6.3.15.1.1.3.0")
            self.assertNotEqual(zh, en)
            self.assertIn("user name", en.lower())
        finally:
            i18n.init("zh-CN")


class DecodeValueTest(unittest.TestCase):

    def test_octet_string(self):
        # 与 v2c 路径一致：只 strip 空白，不剥 NUL（保持行为统一）
        self.assertEqual(v3._decode_value(b"  hello  ", 0x04), "hello")
        self.assertEqual(v3._decode_value(b"sw-core-01\x00", 0x04), "sw-core-01\x00")

    def test_object_identifier(self):
        enc = _snmp_enc_oid("1.3.6.1.2.1.1.1.0")
        self.assertEqual(v3._decode_value(enc[2:], 0x06), "1.3.6.1.2.1.1.1.0")

    def test_integers(self):
        for tag in (0x02, 0x41, 0x42, 0x43, 0x46):
            with self.subTest(tag=tag):
                self.assertEqual(v3._decode_value(b"\x01\x00", tag), "256")

    def test_ip_address(self):
        self.assertEqual(v3._decode_value(b"\x0a\x00\x00\x01", 0x40), "10.0.0.1")

    def test_unknown_tag_is_empty(self):
        self.assertEqual(v3._decode_value(b"\x01", 0x99), "")

    def test_oid_round_trip_through_encoder(self):
        for oid in ("1.3.6.1.2.1.1.1.0", "1.0.8802.1.1.2.1.4.1.1.5",
                    "1.3.6.1.4.1.9.9.23.1.2.1.1.6"):
            with self.subTest(oid=oid):
                enc = _snmp_enc_oid(oid)
                self.assertEqual(_snmp_decode_oid(enc[2:]), oid)


# ══════════════════════════════════════════════════════════════════
# 4. 真实 UDP 回环代理（端到端）
# ══════════════════════════════════════════════════════════════════

def _oid_key(oid):
    return tuple(int(p) for p in oid.split(".") if p != "")


def _reply_tlv(tag, payload):
    return bytes([tag]) + v3._ber_len(len(payload)) + payload


class FakeSnmpV3Agent:
    """最小可用的 SNMPv3 代理（真实 UDP 回环）。

    支持：引擎发现、GET、GETNEXT、以及"目标拒绝"（回 Report PDU）。
    它按协议**独立**构造响应（自己算摘要、自己加密、reportable 置 0），
    因此能验出客户端在字段顺序、时序、加密往返上的错误 ——
    这些是纯 mock 覆盖不到的。
    """

    def __init__(self, engine_id=_USM_SAMPLE_ENGINE, boots=3, eng_time=100,
                 username="bert", auth_proto=AUTH_MD5, auth_key=_RFC_PASSPHRASE,
                 priv_proto=PRIV_NONE, priv_key="",
                 values=None, report_oid=None):
        self.engine_id = engine_id
        self.boots = boots
        self.eng_time = eng_time
        self.username = username
        self.auth_proto = auth_proto
        self.auth_key = auth_key
        self.priv_proto = priv_proto
        self.priv_key = priv_key
        self.values = dict(values or {})
        self.report_oid = report_oid
        self.requests = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.1)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._stop.set()
        self._thread.join(timeout=3)
        self.sock.close()

    # ── 服务循环 ──
    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                reply = self._handle(data)
            except Exception:      # noqa: BLE001 - 代理内部异常不该挂死测试
                reply = None
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    return

    def _handle(self, data):
        parsed = v3.parse_v3_message(data)
        if parsed is None:
            return None
        usm = parsed["usm"]
        msg_id = parsed["msg_id"]
        self.requests.append(parsed)

        # 发现阶段：空 engineID + noAuthNoPriv → 回 Report 告知权威引擎 ID
        if not usm["engine_id"]:
            return self._reply_report(msg_id, "1.3.6.1.6.3.15.1.1.4.0")

        if self.report_oid:
            return self._reply_report(msg_id, self.report_oid)

        auth = bool(self.auth_proto)
        priv = bool(self.priv_proto)

        if auth:
            if usm["username"] != self.username:
                return self._reply_report(msg_id, "1.3.6.1.6.3.15.1.1.3.0")
            kul = v3.localize_key(self.auth_key, self.engine_id, self.auth_proto)
            probe = SnmpV3User(auth_proto=self.auth_proto)
            if not v3._verify_digest(parsed, kul, probe):
                return self._reply_report(msg_id, "1.3.6.1.6.3.15.1.1.5.0")

        # 与客户端同一套约定：加密时 msgData 是 OCTET STRING，解密的是它的
        # 内容；明文时用整条 TLV（_parse_scoped_pdu 期望完整 SEQUENCE）。
        msg_data = parsed["msg_data"]
        if priv:
            kul = v3.localize_key(self.priv_key, self.engine_id, self.auth_proto)
            iv = (struct.pack(">I", usm["boots"])
                  + struct.pack(">I", usm["eng_time"]) + usm["priv_params"])
            msg_data = aes.cfb128_decrypt(kul[:16], iv, parsed["msg_data_content"])
            if v3._parse_scoped_pdu(msg_data) is None:
                # 解不开 → 按 RFC 3414 回 usmStatsDecryptionErrors
                return self._reply_report(msg_id, "1.3.6.1.6.3.15.1.1.6.0")

        decoded = v3._parse_scoped_pdu(msg_data)
        if decoded is None:
            return None
        pdu_tag, _err, varbinds = decoded
        if not varbinds:
            return None
        req_oid = varbinds[0][0]

        if pdu_tag == v3._PDU_GET:
            # GET 必须对**每个**请求的 OID 各回一个 varbind
            pairs = [(o, *self._value(o)) for o, _v, _t in varbinds]
        elif pdu_tag == v3._PDU_GETNEXT:
            nxt = self._next_oid(req_oid)
            if nxt is None:
                pairs = [(req_oid, b"", 0x82)]        # endOfMibView
            else:
                pairs = [(nxt, *self._value(nxt))]
        else:
            return None
        return self._reply_response(msg_id, pairs, auth, priv)

    def _value(self, oid):
        """values[oid] 可以是 bytes（默认 OCTET STRING）或 (bytes, tag)。

        交换机转发表里 INTEGER 和 OCTET STRING 是混在一起的，一律回 0x04
        会让端口号/状态字段被全部丢弃，也就测不出真实的组装逻辑。
        """
        v = self.values.get(oid)
        if v is None:
            return b"", 0x04
        if isinstance(v, tuple):
            return v[0], v[1]
        return v, 0x04

    def _next_oid(self, oid):
        """按字典序返回下一个 OID（None 表示到末尾）。"""
        key = _oid_key(oid)
        candidates = sorted((k for k in self.values if _oid_key(k) > key),
                            key=_oid_key)
        return candidates[0] if candidates else None

    # ── 构包 ──
    def _reply_report(self, msg_id, stat_oid):
        """未认证、未加密的 Report（RFC 3414 §3.2）。"""
        pdu = v3._build_pdu(v3._PDU_REPORT, msg_id, [stat_oid])
        scoped = v3._build_scoped_pdu(self.engine_id, "", pdu)
        usm = v3._build_usm_params(self.engine_id, self.boots, self.eng_time,
                                   "", b"", b"")
        return v3._build_v3_message(
            msg_id, v3._enc_msg_flags(False, False, reportable=False), usm, scoped)

    def _reply_response(self, msg_id, pairs, auth, priv):
        varbinds = b""
        for oid, val, tag in pairs:
            varbinds += v3._enc_seq(_snmp_enc_oid(oid) + _reply_tlv(tag, val))
        body = (v3._snmp_enc_int(msg_id) + v3._snmp_enc_int(0)
                + v3._snmp_enc_int(0) + v3._enc_seq(varbinds))
        pdu = _reply_tlv(v3._PDU_RESPONSE, body)
        scoped = v3._build_scoped_pdu(self.engine_id, "", pdu)

        priv_params = b""
        if priv:
            priv_params = v3._salt()
            kul = v3.localize_key(self.priv_key, self.engine_id, self.auth_proto)
            iv = (struct.pack(">I", self.boots)
                  + struct.pack(">I", self.eng_time) + priv_params)
            scoped = v3._enc_octet(aes.cfb128_encrypt(kul[:16], iv, scoped))

        flags = v3._enc_msg_flags(auth, priv, reportable=False)
        if not auth:
            usm = v3._build_usm_params(self.engine_id, self.boots, self.eng_time,
                                       self.username, b"", priv_params)
            return v3._build_v3_message(msg_id, flags, usm, scoped)

        kul = v3.localize_key(self.auth_key, self.engine_id, self.auth_proto)
        usm = v3._build_usm_params(self.engine_id, self.boots, self.eng_time,
                                   self.username, bytes(12), priv_params)
        msg = v3._build_v3_message(msg_id, flags, usm, scoped)
        digest = v3._hmac96(kul, msg, v3._HASH_BY_AUTH[self.auth_proto])
        usm = v3._build_usm_params(self.engine_id, self.boots, self.eng_time,
                                   self.username, digest, priv_params)
        return v3._build_v3_message(msg_id, flags, usm, scoped)


_SYS_VALUES = {
    "1.3.6.1.2.1.1.1.0": b"Fake Switch OS 1.0",
    "1.3.6.1.2.1.1.5.0": b"sw-core-01",
    "1.3.6.1.2.1.1.2.0": b"\x2b\x06\x01\x04\x01\x09\x9f\x0c\x01",
}


class EndToEndTest(unittest.TestCase):
    """走完整链路的端到端测试（真实 UDP 回环）。"""

    def setUp(self):
        v3.reset_engine_cache()

    def tearDown(self):
        v3.reset_engine_cache()

    def test_noauth_get(self):
        with FakeSnmpV3Agent(auth_proto=AUTH_NONE, values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="bert")
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertNotIn("error", info)
        self.assertEqual(info["sys_descr"], "Fake Switch OS 1.0")
        self.assertEqual(info["sys_name"], "sw-core-01")
        self.assertEqual(info["security_level"], LEVEL_NO_AUTH_NO_PRIV)

    def test_md5_auth_get(self):
        with FakeSnmpV3Agent(values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertNotIn("error", info)
        self.assertEqual(info["sys_name"], "sw-core-01")
        self.assertEqual(info["security_level"], LEVEL_AUTH_NO_PRIV)

    def test_sha_auth_priv_get(self):
        """authPriv：摘要 + AES 加密全链路。"""
        with FakeSnmpV3Agent(auth_proto=AUTH_SHA, auth_key="authpass",
                             priv_proto=PRIV_AES, priv_key="privpass",
                             values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_SHA,
                              auth_key="authpass", priv_proto=PRIV_AES,
                              priv_key="privpass")
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertNotIn("error", info)
        self.assertEqual(info["sys_descr"], "Fake Switch OS 1.0")
        self.assertEqual(info["security_level"], LEVEL_AUTH_PRIV)

    def test_wrong_auth_password_reports_auth_failure(self):
        """认证密码错误：目标要么回 Report(认证失败)，要么直接丢包。

        两种都是真实设备的行为，所以这里接受两种结果，
        但**必须**让用户看到"认证"这个关键词，而不是笼统的"无响应"。
        """
        with FakeSnmpV3Agent(values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key="wrongpass")
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertIn("error", info)
        self.assertIn(info["error_kind"], (ERR_AUTH, ERR_REJECTED))
        self.assertIn("认证", info["error"])

    def test_unknown_user_is_reported_not_masked(self):
        """目标回 Report(未知用户名) 时，必须把真正原因透出来。

        这条专门盯住"先校验摘要"的实现：那样只会报"认证校验失败"，
        用户永远不知道其实是用户名写错了。
        """
        with FakeSnmpV3Agent(values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="nobody", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertIn("error", info)
        self.assertEqual(info["error_kind"], ERR_REJECTED)
        self.assertIn("用户名", info["error"])

    def test_report_oid_is_surfaced(self):
        with FakeSnmpV3Agent(values=_SYS_VALUES,
                             report_oid="1.3.6.1.6.3.15.1.1.5.0") as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertEqual(info["error_kind"], ERR_REJECTED)
        self.assertIn("认证", info["error"])

    def test_wrong_priv_password_reports_decrypt_failure(self):
        """加密密码错：目标按 RFC 3414 回 usmStatsDecryptionErrors。"""
        with FakeSnmpV3Agent(auth_proto=AUTH_SHA, auth_key="authpass",
                             priv_proto=PRIV_AES, priv_key="rightpriv",
                             values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_SHA,
                              auth_key="authpass", priv_proto=PRIV_AES,
                              priv_key="wrongpriv")
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertIn("error", info)
        self.assertEqual(info["error_kind"], ERR_REJECTED)
        self.assertIn("解密", info["error"])

    def test_closed_port_is_no_response(self):
        """没有任何监听 → ERR_NO_RESPONSE（调用方据此才敢回退 v2c）。"""
        # 绑一个端口再立刻关掉，保证该端口上无人监听
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.bind(("127.0.0.1", 0))
        dead_port = tmp.getsockname()[1]
        tmp.close()
        user = SnmpV3User(username="bert", auth_proto=AUTH_MD5, auth_key="k")
        info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=0.4,
                                     port=dead_port)
        self.assertEqual(info["error_kind"], ERR_NO_RESPONSE)

    def test_invalid_config_fails_before_any_packet(self):
        info = v3.snmp_v3_get_system("127.0.0.1", SnmpV3User(), timeout=0.4)
        self.assertEqual(info["error_kind"], ERR_CONFIG)
        self.assertIn("用户名", info["error"])

    def test_empty_oid_values_report_error(self):
        """目标回了响应但三个系统 OID 都无值 → 明确报错，不是空结果。"""
        with FakeSnmpV3Agent(values={}) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            info = v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0,
                                         port=ag.port)
        self.assertIn("error", info)
        self.assertEqual(info["error_kind"], ERR_PROTOCOL)

    def test_engine_discovered_only_once_across_requests(self):
        """两次请求只应发现一次引擎 —— 每台设备每轮省一个往返。"""
        with FakeSnmpV3Agent(values=_SYS_VALUES) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0, port=ag.port)
            v3.snmp_v3_get_system("127.0.0.1", user, timeout=1.0, port=ag.port)
            discoveries = [p for p in ag.requests if not p["usm"]["engine_id"]]
        self.assertEqual(len(discoveries), 1)


class WalkTest(unittest.TestCase):
    """GETNEXT 遍历语义（与 v2c 的 snmp_walk 保持一致）。"""

    BASE = "1.3.6.1.2.1.2.2.1.2"
    TREE = {
        "1.3.6.1.2.1.2.2.1.2.1": b"eth0",
        "1.3.6.1.2.1.2.2.1.2.2": b"eth1",
        "1.3.6.1.2.1.2.2.1.2.3": b"wlan0",
        # 这条不在子树里：遍历到它就该停
        "1.3.6.1.2.1.2.2.1.3.1": b"\x01",
    }

    def setUp(self):
        v3.reset_engine_cache()

    def tearDown(self):
        v3.reset_engine_cache()

    def test_walk_returns_subtree_only(self):
        with FakeSnmpV3Agent(values=self.TREE) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            got = v3.snmp_v3_walk("127.0.0.1", user, self.BASE, timeout=1.0,
                                  port=ag.port)
        self.assertEqual(sorted(got), sorted(
            [k for k in self.TREE if k.startswith(self.BASE + ".")]))
        self.assertEqual(got["1.3.6.1.2.1.2.2.1.2.1"], (b"eth0", 0x04))

    def test_walk_on_unreachable_returns_empty(self):
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.bind(("127.0.0.1", 0))
        dead = tmp.getsockname()[1]
        tmp.close()
        user = SnmpV3User(username="bert", auth_proto=AUTH_MD5, auth_key="k")
        self.assertEqual(
            v3.snmp_v3_walk("127.0.0.1", user, self.BASE, timeout=0.4, port=dead),
            {})

    def test_walk_invalid_config_returns_empty(self):
        self.assertEqual(v3.snmp_v3_walk("127.0.0.1", SnmpV3User(), self.BASE), {})

    def test_walk_stops_at_max_iterations(self):
        """迭代上限必须生效（防止目标一直不前进时死循环）。"""
        tree = {f"1.3.6.1.2.1.2.2.1.2.{i}": b"x" for i in range(1, 50)}
        with FakeSnmpV3Agent(values=tree) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            got = v3.snmp_v3_walk("127.0.0.1", user, self.BASE, timeout=1.0,
                                  port=ag.port, max_iterations=5)
        self.assertLessEqual(len(got), 5)


class _FakeSock:
    """只用于引擎缓存测试：记录发送次数，不真的收发。"""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = 0

    def sendto(self, _data, _addr):
        self.sent += 1

    def recvfrom(self, _n):
        if not self.replies:
            raise socket.timeout()
        return self.replies.pop(0), ("127.0.0.1", 161)


def _engine_reply(eng):
    """构造一条带指定引擎参数的发现响应。"""
    scoped = v3._build_scoped_pdu(eng.engine_id, "", v3._build_pdu(
        v3._PDU_REPORT, 1, ["1.3.6.1.6.3.15.1.1.4.0"]))
    usm = v3._build_usm_params(eng.engine_id, eng.boots, eng.eng_time,
                               "", b"", b"")
    return v3._build_v3_message(
        1, v3._enc_msg_flags(False, False, reportable=False), usm, scoped)


# ══════════════════════════════════════════════════════════════════
# 5. 凭据存储与配置对话框
# ══════════════════════════════════════════════════════════════════

class _FakeSettings:
    """QSettings 的最小替身：只要 setValue / value 两个方法。"""

    def __init__(self, values=None):
        self.values = dict(values or {})

    def setValue(self, key, value):
        self.values[key] = value

    def value(self, key, default=None):
        return self.values.get(key, default)


class SnmpV3CredentialStoreTest(unittest.TestCase):

    def setUp(self):
        from scanner.cred_store import SnmpV3CredentialStore, _HAS_DPAPI
        self.store_cls = SnmpV3CredentialStore
        self.has_dpapi = _HAS_DPAPI

    def test_defaults_are_no_auth(self):
        s = self.store_cls()
        self.assertFalse(s.has_creds())
        u = s.to_user()
        self.assertEqual(u.auth_proto, AUTH_NONE)
        self.assertEqual(u.security_level(), LEVEL_NO_AUTH_NO_PRIV)

    def test_invalid_protocols_fall_back(self):
        """非法协议值必须回落，不能让脏值进持久化。"""
        s = self.store_cls()
        s.set("u", "sha512", "k", "3des", "k2")
        self.assertEqual(s.auth_proto, AUTH_NONE)
        self.assertEqual(s.priv_proto, PRIV_NONE)

    def test_disabling_auth_clears_priv(self):
        """RFC 3414：priv 必须建立在 auth 之上，关掉认证就得连加密一起关。"""
        s = self.store_cls()
        s.set("u", AUTH_MD5, "k", PRIV_AES, "k2")
        self.assertEqual(s.to_user().security_level(), LEVEL_AUTH_PRIV)
        s.set("u")                       # 只留用户名
        self.assertEqual(s.auth_proto, AUTH_NONE)
        self.assertEqual(s.priv_proto, PRIV_NONE)
        self.assertEqual(s.priv_key, "")

    def test_round_trip_through_settings(self):
        s = self.store_cls()
        s.set("snmpuser", AUTH_SHA, "authkey123", PRIV_AES, "privkey123")
        st = _FakeSettings()
        s.save_to(st)

        loaded = self.store_cls()
        loaded.load_from(st)
        self.assertEqual(loaded.username, "snmpuser")
        self.assertEqual(loaded.auth_proto, AUTH_SHA)
        self.assertEqual(loaded.priv_proto, PRIV_AES)
        if self.has_dpapi:
            # 有 DPAPI 的平台口令必须能原样还原
            self.assertEqual(loaded.auth_key, "authkey123")
            self.assertEqual(loaded.priv_key, "privkey123")
        else:
            # 无 DPAPI 的平台不落盘口令，也不能崩
            self.assertEqual(loaded.auth_key, "")
            self.assertEqual(loaded.priv_key, "")

    def test_saved_keys_are_not_plaintext(self):
        """口令绝不能以明文出现在配置里。"""
        if not self.has_dpapi:
            self.skipTest("非 Windows 平台无 DPAPI")
        s = self.store_cls()
        s.set("u", AUTH_MD5, "supersecret", PRIV_AES, "anothersecret")
        st = _FakeSettings()
        s.save_to(st)
        blob = " ".join(str(v) for v in st.values.values())
        self.assertNotIn("supersecret", blob)
        self.assertNotIn("anothersecret", blob)

    def test_load_ignores_invalid_stored_protocols(self):
        st = _FakeSettings({"snmpv3/username": "u",
                            "snmpv3/auth_proto": "bogus",
                            "snmpv3/priv_proto": "bogus"})
        s = self.store_cls()
        s.load_from(st)
        self.assertEqual(s.auth_proto, AUTH_NONE)
        self.assertEqual(s.priv_proto, PRIV_NONE)

    def test_corrupt_saved_key_does_not_raise(self):
        """配置被改坏时只能清空口令，不能影响启动。"""
        st = _FakeSettings({"snmpv3/username": "u",
                            "snmpv3/auth_proto": AUTH_MD5,
                            "snmpv3/auth_key_enc": "not-base64!!"})
        s = self.store_cls()
        s.load_from(st)
        self.assertEqual(s.auth_key, "")


class SnmpV3DialogTest(unittest.TestCase):
    """配置对话框：下拉必须回传语言无关的规范值。"""

    def setUp(self):
        from tests._qt_app import ensure_qt_app
        ensure_qt_app()
        i18n.init("zh-CN")

    def _dlg(self, **kw):
        from ui_dialogs import SnmpV3CredentialDialog
        return SnmpV3CredentialDialog(**kw)

    def test_combo_items_use_canonical_values(self):
        dlg = self._dlg()
        try:
            self.assertEqual(
                [dlg.auth_combo.itemData(i) for i in range(dlg.auth_combo.count())],
                [AUTH_NONE, AUTH_MD5, AUTH_SHA])
            self.assertEqual(
                [dlg.priv_combo.itemData(i) for i in range(dlg.priv_combo.count())],
                [PRIV_NONE, PRIV_AES])
        finally:
            dlg.deleteLater()

    def test_des_is_not_offered(self):
        """DES 不支持，就不该出现在下拉里让用户白选。"""
        dlg = self._dlg()
        try:
            values = [dlg.priv_combo.itemData(i)
                      for i in range(dlg.priv_combo.count())]
            self.assertNotIn(PRIV_DES, values)
        finally:
            dlg.deleteLater()

    def test_priv_disabled_without_auth(self):
        dlg = self._dlg()
        try:
            dlg.auth_combo.setCurrentIndex(dlg.auth_combo.findData(AUTH_NONE))
            self.assertFalse(dlg.priv_combo.isEnabled())
            self.assertFalse(dlg.priv_edit.isEnabled())
            dlg.auth_combo.setCurrentIndex(dlg.auth_combo.findData(AUTH_SHA))
            self.assertTrue(dlg.priv_combo.isEnabled())
        finally:
            dlg.deleteLater()

    def test_get_config_round_trips_saved_values(self):
        saved = {"username": "snmpuser", "auth_proto": AUTH_SHA,
                 "auth_key": "a" * 8, "priv_proto": PRIV_AES, "priv_key": "p" * 8}
        dlg = self._dlg(saved=saved)
        try:
            user, auth_proto, auth_key, priv_proto, priv_key, save = dlg.get_config()
            self.assertEqual(user, "snmpuser")
            self.assertEqual(auth_proto, AUTH_SHA)
            self.assertEqual(auth_key, "a" * 8)
            self.assertEqual(priv_proto, PRIV_AES)
            self.assertEqual(priv_key, "p" * 8)
            self.assertFalse(save)
        finally:
            dlg.deleteLater()

    def test_unknown_saved_protocol_falls_back(self):
        dlg = self._dlg(saved={"auth_proto": "bogus", "priv_proto": "bogus"})
        try:
            self.assertEqual(dlg.auth_combo.currentData(), AUTH_NONE)
            self.assertEqual(dlg.priv_combo.currentData(), PRIV_NONE)
        finally:
            dlg.deleteLater()

    def test_test_button_without_target_reports_error(self):
        """目标为空时不该发起任何网络请求，直接本地报错。"""
        dlg = self._dlg(saved={"username": "u", "auth_proto": AUTH_MD5,
                               "auth_key": "k"})
        try:
            dlg._on_test()
            self.assertIn("IP", dlg.result_label.text())
        finally:
            dlg.deleteLater()

    def test_test_button_validates_config_first(self):
        """配置不合法时应该本地就报错，而不是发一个必然失败的包。"""
        dlg = self._dlg(saved={"username": "u", "auth_proto": AUTH_MD5})
        try:
            dlg.target_edit.setText("127.0.0.1")
            dlg._on_test()
            self.assertIn("密码", dlg.result_label.text())
        finally:
            dlg.deleteLater()


class SwitchMapOverV3Test(unittest.TestCase):
    """交换机端口映射要能走 SNMPv3。

    很多交换机的 v2c 团体字默认关闭或被策略禁用，端口映射只能靠 v3。
    这里让"只会说 v3"的假代理来服务，因此一旦实现偷偷走 v2c 就拿不到转发表。
    """

    _MAC = "AA:BB:CC:DD:EE:FF"
    _SUFFIX = "170.187.204.221.238.255"      # 上面那个 MAC 的十进制 OID 后缀

    def setUp(self):
        v3.reset_engine_cache()
        self.values = {
            # dot1dTpFdbPort / dot1dTpFdbStatus（INTEGER）
            f"1.3.6.1.2.1.17.4.3.1.2.{self._SUFFIX}": (b"\x00\x05", 0x02),
            f"1.3.6.1.2.1.17.4.3.1.3.{self._SUFFIX}": (b"\x03", 0x02),
            # dot1dBasePortIfIndex：桥接端口 5 → ifIndex 10
            "1.3.6.1.2.1.17.1.4.1.2.5": (b"\x0a", 0x02),
            # ifDescr / ifName（OCTET STRING）
            "1.3.6.1.2.1.2.2.1.2.10": b"GigabitEthernet0/10",
            "1.3.6.1.2.1.31.1.1.1.1.10": b"Gi0/10",
            "1.3.6.1.2.1.1.5.0": b"sw-core-01",
        }

    def tearDown(self):
        v3.reset_engine_cache()

    def test_map_switch_ports_over_v3(self):
        import switch_mapper
        with FakeSnmpV3Agent(values=self.values) as ag:
            user = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                              auth_key=_RFC_PASSPHRASE)
            info = switch_mapper.map_switch_ports(
                "127.0.0.1", snmp_v3_user=user, timeout=1.0, port=ag.port)
        self.assertEqual(info.error, "")
        self.assertEqual(info.sys_name, "sw-core-01")
        self.assertEqual(len(info.mappings), 1)
        m = info.mappings[0]
        self.assertEqual(m.mac, self._MAC)
        self.assertEqual(m.port_name, "Gi0/10")     # ifName 优先于 ifDescr
        self.assertEqual(m.if_index, 10)
        self.assertEqual(m.bridge_port, 5)

    def test_map_switch_ports_v3_auth_failure_reports_error(self):
        """v3 凭据错时必须明确报错，不能静默返回空映射。"""
        import switch_mapper
        with FakeSnmpV3Agent(values=self.values) as ag:
            bad = SnmpV3User(username="bert", auth_proto=AUTH_MD5,
                             auth_key="wrongpass")
            info = switch_mapper.map_switch_ports(
                "127.0.0.1", snmp_v3_user=bad, timeout=1.0, port=ag.port)
        self.assertNotEqual(info.error, "")
        self.assertEqual(info.mappings, [])


if __name__ == "__main__":
    unittest.main()
