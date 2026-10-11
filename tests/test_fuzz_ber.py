# -*- coding: utf-8 -*-
"""手写 BER/DER 解析器的 fuzz 固化测试（建议书 §5.3、§10 第 5 件）。

为什么要有这个文件
------------------
`scanner/snmp.py` 与 `scanner/snmp_v3.py` 里的 BER 解析是**手写**的 ——
本项目核心零第三方依赖，SNMP 报文只能自己拆。但它拆的是**不可信输入**：
网里任何一台设备都能往 161/udp 回一个畸形报文，扫描线程直接吃下它。
所以「解析器不抛异常」是硬契约，不是"最好别抛"。

建议书附录 A 实测过「6 万随机字节 + 4 万合法响应变异，零未捕获异常」，
但那是一次性脚本，跑完就没了 —— 等于「目前没炸」而不是「保证不炸」。
本文件把它固化成回归测试，代价是每次 CI 多跑两三秒。

四个刻意的设计
--------------
1. **固定种子**。fuzz 的价值在于「失败可复现」：CI 红了必须能拿到同一串
   字节。种子固定后每次跑的都是同一批输入；要扩大覆盖就调
   `IPSCANNER_FUZZ_SCALE`（CI 用 1，本地想压满用 10）。
2. **不只看"没抛异常"**。一个「任何输入都返回 None」的解析器也能让
   "不抛异常"全绿。所以每个 fuzz 类先用一条**合法种子报文**证明解析器
   真的能解析（否则就是在 fuzz 空气），再断言返回值只能是
   「None 或约定的结构」。
3. **纯随机字节是空的，必须配"结构自洽"生成器**。实测：v2c 解析器收到
   6000 条纯随机字节时，**0 条**解析成功、平均只调 1.0 次 TLV —— 因为
   第 2 行 `tag != 0x30` 就把它们全挡回去了。所以另有 `_structured_v2c`
   生成"外层框架合法、内容随机"的报文（实测平均 8.6 次 TLV/输入、
   1970/6000 解析成功），真正压到深层的 varbind 循环。
4. **只 fuzz 有兜底的入口**。`_extract_varbinds` 这类内层辅助函数本身没有
   try/except，它是**被** `_parse_scoped_pdu` 的兜底包着的 —— 单独 fuzz 它
   只会得到一堆"不是 bug 的失败"。这里只打真正面对网络字节的那几个入口。

有效性验证（一次性，不入测试）
------------------------------
把 `_snmp_parse_response` 的 try/except 用 AST 摘掉后重跑同样的变异输入，
4000 次里有 **1434 次**抛出异常 —— 即本文件确实能抓住"兜底被删掉"这类缺陷，
而不是恒绿的摆设。
"""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import service_fingerprints as SF
from scanner import snmp as snmp2
from scanner import snmp_v3 as v3
from scanner.snmp import _ber_len, _snmp_enc_int, _snmp_enc_oid, _snmp_enc_str

#: 固定种子 —— 失败必须可复现（见模块 docstring 第 1 条）
_SEED = 0x5A172C4E

#: 迭代倍率。CI 用 1（整组 ≈ 3 秒），本地想跑满用 IPSCANNER_FUZZ_SCALE=10。
_SCALE = max(1, int(os.environ.get("IPSCANNER_FUZZ_SCALE", "1") or "1"))

#: 随机字节的长度上界。真实 SNMP 响应通常几百字节，但畸形包可能极短或极长；
#: 上界取 96 是"够覆盖长形式长度域"与"别把测试跑慢"之间的折中。
_MAX_LEN = 96


# ── 输入生成：纯随机 ──


def _random_bytes(rnd, lo=0, hi=_MAX_LEN):
    """随机长度、随机内容的字节串。"""
    return bytes(rnd.getrandbits(8) for _ in range(rnd.randint(lo, hi)))


def _mutate(rnd, data):
    """对一条合法报文做一次结构无关的破坏。

    五种手法对应真实世界里的畸形报文：位翻转（传输误码）、截断（分片丢失）、
    长度域破坏（最常见的构造错误）、插入与删除（对齐错位）。
    """
    if not data:
        return _random_bytes(rnd, 1, 8)
    buf = bytearray(data)
    kind = rnd.randrange(5)
    if kind == 0:                                   # 位翻转
        i = rnd.randrange(len(buf))
        buf[i] ^= 1 << rnd.randrange(8)
    elif kind == 1:                                 # 截断
        return bytes(buf[:rnd.randrange(len(buf) + 1)])
    elif kind == 2:                                 # 长度域改成"长形式"
        buf[rnd.randrange(len(buf))] = 0x80 | rnd.randrange(1, 5)
    elif kind == 3:                                 # 插入
        i = rnd.randrange(len(buf) + 1)
        buf[i:i] = _random_bytes(rnd, 1, 4)
    else:                                           # 删除
        i = rnd.randrange(len(buf))
        del buf[i:i + rnd.randint(1, 8)]
    return bytes(buf)


# ── 输入生成：结构自洽（框架合法、内容随机） ──


def _seq(body):
    return b"\x30" + _ber_len(len(body)) + body


def _octet(rnd, lo=0, hi=10):
    body = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(lo, hi)))
    return b"\x04" + _ber_len(len(body)) + body


def _octet_of(body):
    return b"\x04" + _ber_len(len(body)) + body


def _integer(rnd, lo=0, hi=2 ** 31):
    n = rnd.randint(lo, hi)
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:                              # DER：最高位为 1 要补 0x00
        body = b"\x00" + body
    return b"\x02" + _ber_len(len(body)) + body


def _oid(rnd):
    """随机但**编码合法**的 OID（含多字节子标识符的续位）。"""
    arcs = [rnd.randint(1, 2), rnd.randint(0, 39)]
    arcs += [rnd.randint(0, 300) for _ in range(rnd.randint(0, 6))]
    out = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunks = [arc & 0x7F]
        rest = arc >> 7
        while rest:
            chunks.append((rest & 0x7F) | 0x80)
            rest >>= 7
        out += bytes(reversed(chunks))
    return b"\x06" + _ber_len(len(out)) + out


def _any_value(rnd):
    """随机的 varbind 值：字符串 / 整数 / OID / NULL / IpAddress。"""
    kind = rnd.randrange(5)
    if kind == 0:
        return _octet(rnd)
    if kind == 1:
        return _integer(rnd, 0, 2 ** 32)
    if kind == 2:
        return _oid(rnd)
    if kind == 3:
        return b"\x05\x00"
    return b"\x40" + _ber_len(4) + bytes(rnd.getrandbits(8) for _ in range(4))


def _structured_v2c(rnd):
    """外层框架完全合法的 v2c 报文，内容随机 —— 让随机输入真的走进深层。

    强制外层是 `0x30` SEQUENCE、version 合法、PDU tag 是 `0xA2`，否则解析器
    会在头几行就 return None（纯随机字节实测 6000 条里 0 条通过）。
    """
    varbinds = b"".join(_seq(_oid(rnd) + _any_value(rnd))
                        for _ in range(rnd.randint(0, 4)))
    pdu_body = (_integer(rnd) + _integer(rnd, 0, 2)      # error-status 常为 0
                + _integer(rnd) + _seq(varbinds))
    pdu = b"\xa2" + _ber_len(len(pdu_body)) + pdu_body
    return _seq(_integer(rnd, 0, 1) + _octet(rnd) + pdu)


def _structured_v3(rnd):
    """外层框架完全合法的 v3 报文（msgVersion=3），内容随机。

    msgSecurityParameters 必须是「OCTET STRING 包着 DER 的 USM 参数」，
    所以这里也照此封装 —— 否则解析器会在 USM 那一层直接失败。
    """
    usm = _seq(_octet(rnd, 0, 16) + _integer(rnd, 0, 5) + _integer(rnd, 0, 1000)
               + _octet(rnd, 0, 8) + _octet(rnd, 0, 12) + _octet(rnd, 0, 8))
    header = _seq(_integer(rnd) + _integer(rnd, 0, 65507)
                  + _octet(rnd, 0, 1) + _integer(rnd, 0, 3))
    inner = (_integer(rnd) + _integer(rnd, 0, 2) + _integer(rnd)
             + _seq(b"".join(_seq(_oid(rnd) + _any_value(rnd))
                             for _ in range(rnd.randint(0, 3)))))
    pdu = bytes([rnd.choice((0xA0, 0xA1, 0xA2, 0xA8))]) + _ber_len(len(inner)) + inner
    scoped = _seq(_octet(rnd, 0, 16) + _octet(rnd, 0, 8) + pdu)
    return _seq(_integer(rnd, 3, 3) + header + _octet_of(usm) + scoped)


# ── 合法种子（证明解析器真的会解析） ──


def _valid_v2c_response():
    """构造一条**真能解析**的 v2c GetResponse —— 变异 fuzz 的种子。

    用被测模块自己的编码器拼，避免"测试里的手写字节"和"实现"各错一半。
    """
    oid = _snmp_enc_oid("1.3.6.1.2.1.1.1.0")
    value = b"\x04" + _ber_len(5) + b"Linux"
    varbind = _seq(oid + value)
    pdu_body = _snmp_enc_int(1) + _snmp_enc_int(0) + _snmp_enc_int(0) + _seq(varbind)
    pdu = b"\xa2" + _ber_len(len(pdu_body)) + pdu_body
    return _seq(_snmp_enc_int(1) + _snmp_enc_str("public") + pdu)


def _valid_v3_message():
    """构造一条**真能解析**的 v3 明文 ScopedPDU 报文。"""
    engine = bytes.fromhex("800000020109840301")
    usm = v3._build_usm_params(engine, 1, 257, "bert", b"\x11" * 12, b"")
    pdu = v3._build_pdu(v3._PDU_RESPONSE, 7, ["1.3.6.1.2.1.1.1.0"])
    scoped = v3._build_scoped_pdu(engine, "", pdu)
    return v3._build_v3_message(
        7, v3._enc_msg_flags(True, False, reportable=False), usm, scoped)


# ── 断言脚手架 ──


class _FuzzCase(unittest.TestCase):
    """共用的「不抛异常 + 返回值形状」断言。"""

    def _exercise(self, func, data, label, *extra):
        """调用解析器；抛异常即失败，并把输入原样打出来（可复现）。

        `extra` 用于两参数解析器（如 `_decode_value`）。
        """
        try:
            return func(data, *extra)
        except Exception as e:  # fuzz 的核心断言：任何异常都是被测缺陷
            self.fail(
                f"{label} 在 fuzz 输入上抛了 {type(e).__name__}: {e}\n"
                f"    输入 {len(data)} 字节: {data.hex()}"
            )

    def _assert_varbinds_shape(self, out, label):
        """返回值只能是 None，或 [(oid:str, value:bytes, tag:int), ...]。"""
        if out is None:
            return
        self.assertIsInstance(out, list, msg=f"{label} 返回了非 list 非 None")
        for item in out:
            self.assertIsInstance(item, tuple, msg=f"{label} 的元素不是 tuple")
            self.assertEqual(len(item), 3, msg=f"{label} 的元素不是三元组")
            oid, value, tag = item
            self.assertIsInstance(oid, str, msg=f"{label} 的 OID 不是 str")
            self.assertIsInstance(value, bytes, msg=f"{label} 的值不是 bytes")
            self.assertIsInstance(tag, int, msg=f"{label} 的 tag 不是 int")


class SnmpV2cParserFuzzTest(_FuzzCase):
    """v2c GetResponse 解析器：`scanner/snmp.py::_snmp_parse_response`。"""

    def test_valid_seed_really_parses(self):
        """先证明种子是"能解析的真报文"，否则下面的变异等于 fuzz 空气。"""
        out = snmp2._snmp_parse_response(_valid_v2c_response())
        self.assertEqual(out, [("1.3.6.1.2.1.1.1.0", b"Linux", 4)])

    def test_random_bytes_never_raise(self):
        """纯随机字节 —— 覆盖"连外层都不是 SEQUENCE"这一档。"""
        rnd = random.Random(_SEED)
        for _ in range(6000 * _SCALE):
            data = _random_bytes(rnd)
            out = self._exercise(snmp2._snmp_parse_response, data, "v2c 解析")
            self._assert_varbinds_shape(out, "v2c 解析")

    def test_structured_random_never_raise(self):
        """框架合法、内容随机 —— 真正压到 varbind 循环（见 docstring 第 3 条）。"""
        rnd = random.Random(_SEED ^ 0x10)
        for _ in range(4000 * _SCALE):
            data = _structured_v2c(rnd)
            out = self._exercise(snmp2._snmp_parse_response, data, "v2c 结构随机解析")
            self._assert_varbinds_shape(out, "v2c 结构随机解析")

    def test_mutated_response_never_raise(self):
        """合法响应的变异 —— 比纯随机字节更容易命中"半对的"解析路径。"""
        seed = _valid_v2c_response()
        rnd = random.Random(_SEED ^ 0x01)
        for _ in range(4000 * _SCALE):
            data = _mutate(rnd, seed)
            out = self._exercise(snmp2._snmp_parse_response, data, "v2c 变异解析")
            self._assert_varbinds_shape(out, "v2c 变异解析")

    def test_declared_length_beyond_payload_does_not_hang(self):
        """长形式长度域声明了远超实际内容的长度 —— 不能靠它撑出巨量内存。"""
        for declared in (0x7F, 0x80, 0xFF, 0x10000, 0xFFFFFF):
            payload = (b"\x30" + b"\x84" + declared.to_bytes(4, "big")
                       + b"\x02\x01\x01")
            out = self._exercise(snmp2._snmp_parse_response, payload, "v2c 超长长度域")
            self._assert_varbinds_shape(out, "v2c 超长长度域")


class SnmpV3ParserFuzzTest(_FuzzCase):
    """v3 报文解析器：`parse_v3_message` / `_parse_usm_params` / `_parse_scoped_pdu`。"""

    #: parse_v3_message 成功时约定的键（少一个都说明解析器把状态弄丢了）
    _KEYS = ("msg_id", "flags", "usm", "msg_data", "msg_data_content",
             "msg_data_tag", "raw", "usm_offset", "auth_offset")

    def _assert_parsed_shape(self, out, label):
        if out is None:
            return
        self.assertIsInstance(out, dict, msg=f"{label} 返回了非 dict 非 None")
        for key in self._KEYS:
            self.assertIn(key, out, msg=f"{label} 的返回缺键 {key}")

    def test_valid_seed_really_parses(self):
        parsed = v3.parse_v3_message(_valid_v3_message())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["msg_id"], 7)
        self.assertEqual(parsed["usm"]["username"], "bert")
        self._assert_parsed_shape(parsed, "v3 种子")

    def test_random_bytes_never_raise(self):
        rnd = random.Random(_SEED ^ 0x02)
        for _ in range(6000 * _SCALE):
            data = _random_bytes(rnd)
            self._assert_parsed_shape(
                self._exercise(v3.parse_v3_message, data, "v3 解析"), "v3 解析")

    def test_structured_random_never_raise(self):
        """框架合法（msgVersion=3）、内容随机 —— 压到 USM 与 ScopedPDU 内层。"""
        rnd = random.Random(_SEED ^ 0x11)
        for _ in range(4000 * _SCALE):
            data = _structured_v3(rnd)
            self._assert_parsed_shape(
                self._exercise(v3.parse_v3_message, data, "v3 结构随机解析"),
                "v3 结构随机解析")

    def test_mutated_message_never_raise(self):
        seed = _valid_v3_message()
        rnd = random.Random(_SEED ^ 0x03)
        for _ in range(4000 * _SCALE):
            data = _mutate(rnd, seed)
            self._assert_parsed_shape(
                self._exercise(v3.parse_v3_message, data, "v3 变异解析"),
                "v3 变异解析")

    def test_inner_parsers_never_raise(self):
        """USM 参数与 ScopedPDU 也直接吃网络字节，各自有兜底，单独压一遍。"""
        rnd = random.Random(_SEED ^ 0x04)
        for _ in range(4000 * _SCALE):
            data = _random_bytes(rnd, 0, 64)
            usm = self._exercise(v3._parse_usm_params, data, "USM 参数解析")
            self.assertIsInstance(usm, tuple)
            self.assertEqual(len(usm), 2)
            scoped = self._exercise(v3._parse_scoped_pdu, data, "ScopedPDU 解析")
            self.assertTrue(scoped is None or isinstance(scoped, tuple))

    def test_decode_value_never_raises(self):
        """值解码：tag 与内容长度不匹配时也不能炸（如 INTEGER 长度为 0）。"""
        rnd = random.Random(_SEED ^ 0x05)
        for _ in range(3000 * _SCALE):
            data = _random_bytes(rnd, 0, 32)
            tag = rnd.randrange(256)
            out = self._exercise(v3._decode_value, data, "值解码", tag)
            self.assertIsInstance(out, str)

    def test_decode_value_empty_payloads(self):
        """空内容是最容易漏的一条路径（`int.from_bytes(b"")` 返回 0）。"""
        for tag in (0x02, 0x04, 0x06, 0x40, 0x41, 0x42, 0x43, 0x46, 0x99):
            with self.subTest(tag=hex(tag)):
                self.assertIsInstance(v3._decode_value(b"", tag), str)


class ServiceFingerprintFuzzTest(_FuzzCase):
    """服务版本指纹的**正则**同样是手写的，同样吃不可信输入（banner）。"""

    def test_valid_banner_really_matches(self):
        """先证明指纹库真的在匹配 —— 否则下面的随机 banner 全绿毫无意义。"""
        fp = SF.fingerprint_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22)
        self.assertIsNotNone(fp, "连真实 SSH banner 都匹配不到，指纹库没加载")
        self.assertIn("OpenSSH", str(fp))

    def test_random_banner_never_raises(self):
        rnd = random.Random(_SEED ^ 0x06)
        ports = (None, 21, 22, 25, 80, 110, 143, 443, 3306, 8080)
        for _ in range(1500 * _SCALE):
            text = "".join(chr(rnd.randint(32, 126))
                           for _ in range(rnd.randint(0, 120)))
            out = self._exercise(SF.fingerprint_banner, text, "指纹匹配",
                                 rnd.choice(ports))
            self.assertTrue(out is None or hasattr(out, "service"))

    def test_highly_repetitive_banner_does_not_hang(self):
        """ReDoS 探针：高度重复的输入最容易让回溯型正则指数爆炸。"""
        probes = ("A" * 20000, "-" * 20000, "1" * 20000,
                  "Server: " + "x" * 20000, "ab" * 10000, "(" * 5000)
        for text in probes:
            with self.subTest(prefix=text[:12]):
                out = self._exercise(SF.fingerprint_banner, text, "指纹匹配(重复串)", 80)
                self.assertTrue(out is None or hasattr(out, "service"))

    def test_embedded_nul_and_control_chars_never_raise(self):
        """真实 banner 里常混进 NUL 与不可打印字符（设备固件写坏了）。"""
        rnd = random.Random(_SEED ^ 0x07)
        for _ in range(800 * _SCALE):
            text = "".join(chr(rnd.randrange(0, 128))
                           for _ in range(rnd.randint(0, 80)))
            out = self._exercise(SF.fingerprint_banner, text, "指纹匹配(控制字符)", 21)
            self.assertTrue(out is None or hasattr(out, "service"))


if __name__ == "__main__":
    unittest.main()
