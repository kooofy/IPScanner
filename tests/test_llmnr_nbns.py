# -*- coding: utf-8 -*-
"""LLMNR / NBNS 响应器探测（v1.9 #3「零利用安全体检」第二刀）。

为什么值得单独一个文件
----------------------
`scanner/llmnr_nbns.py` 往网络里**发**东西（组播 / 广播），这在被动扫描为主的
项目里是少数几个"会主动碰网络"的功能之一。它必须证明三件事：

1. **查得对** —— 两个协议的查询包字节级正确（LLMNR 的 RD 位必须为 0、
   NBNS 用 QTYPE=0x20 而不是 netbios.py 那个 NBSTAT 的 0x21）；
2. **认得准** —— 只认**肯定**应答，且应答里必须真的含我们编的那个名字。
   这两条各自对应一类真实误报：前者会把每个 WINS 服务器报成欺骗响应器
   （它会对任何不存在的名字回 RCODE=3），后者会把网络里**别人**的
   LLMNR/NBNS 流量全算到自己头上；
3. **不投毒** —— 红线。本文件里所有"响应器"都是**测试自己起的假货**，
   探测目标靠 `targets` 注入指向回环地址。测试**绝不**往真实组播/广播地址发包。

为什么全部走 `targets` 注入
---------------------------
与 `risk_rules.score_risk(now=...)` 同一个理由：让测试**脱离真实网络环境**。
组播 / 广播在 CI 容器里不一定可用，真发包的测试会时绿时红 —— 那比没有测试更糟。
"本机到底发不发得出组播/广播"这件事由 `.git/_llmnr_smoke.py` 在真机上单独确认，
不进 CI。

fuzz 部分：`is_positive_answer()` 吃的是**不可信输入**（网里任何人回的任何包），
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

from scanner import llmnr_nbns
from scanner.llmnr_nbns import (
    DEFAULT_TARGETS, LLMNR_GROUP, LLMNR_PORT, MAX_RESPONSES, NBNS_BROADCAST,
    NBNS_PORT, PROBE_PREFIX, _encode_dns_name, _nbt_name16, _wire_signature,
    apply_responders, build_llmnr_query, build_nbns_query, is_positive_answer,
    probe_responders, random_probe_name,
)

#: 固定种子 —— 失败必须可复现
_SEED = 0x4C4C4D4E

#: 迭代倍率，与 `tests/test_fuzz_ber.py` 共用同一个开关。
_SCALE = max(1, int(os.environ.get("IPSCANNER_FUZZ_SCALE", "1") or "1"))

#: 回环假响应器的等待窗口。正例会立刻收到回复但**仍要等满**整个窗口
#: （`probe_responders` 要收齐所有响应器，找到第一个不提前退出），
#: 所以这个值同时决定正例与负例的耗时 —— 压到 0.8s 兼顾速度与 CI 抖动。
_WINDOW = 0.8


# ── 假响应器 ───────────────────────────────────────────────────────────
#
# 全部绑在 127.0.0.1 的**临时端口**上，由 `targets` 注入指向它 —— 不碰组播、
# 不碰广播、不碰真实网段。三个模式对应三种真实情形。

def _dns_reply(query, mode, other_name="someone-else"):
    """把收到的查询改造成一个应答包。

    - `positive`   ：回**肯定**应答（QR=1、RCODE=0、ANCOUNT=1），问题段原样回显
                     —— 真实响应器就是这么答的，回显里自然带着我们的探测名；
    - `negative`   ：回 RCODE=3「名字不存在」（**WINS 服务器的正常行为**）；
    - `other-name` ：回一个肯定应答，但问的是**别人的名字**（模拟网络里飘着的
                     第三方 LLMNR/NBNS 流量）。
    """
    tid = struct.unpack("!H", bytes(query[:2]))[0]
    if mode == "other-name":
        return (struct.pack("!HHHHHH", tid, 0x8000, 1, 1, 0, 0)
                + _encode_dns_name(other_name) + struct.pack("!HH", 255, 1))
    if mode == "negative":
        # 回显问题段 + RCODE=3 + ANCOUNT=0
        return struct.pack("!HHHHHH", tid, 0x8003, 1, 0, 0, 0) + bytes(query[12:])
    # positive：回显问题段，声明有 1 条答案
    return struct.pack("!HHHHHH", tid, 0x8000, 1, 1, 0, 0) + bytes(query[12:])


class _FakeResponder:
    """一个只在回环上监听的假响应器，用于验证探测的收发与判定链路。"""

    def __init__(self, mode="positive"):
        self.mode = mode
        self.received = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stopped = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        # 监听套接字被 close() 之后 recvfrom 必然抛 OSError —— 那是**收尾时的
        # 正常路径**，也是这个循环唯一的退出方式。用 contextlib.suppress 而不是
        # `except OSError: pass`：后者会被 test_logging_policy 的计数棘轮抓走。
        with contextlib.suppress(OSError):
            while not self._stopped:
                data, addr = self.sock.recvfrom(65535)
                self.received += 1
                with contextlib.suppress(OSError):
                    self.sock.sendto(_dns_reply(data, self.mode), addr)

    def close(self):
        self._stopped = True
        self.sock.close()
        # 关闭之后 recvfrom 立刻抛 OSError，循环自行退出；join 只是等它跑完。
        self._thread.join(timeout=2.0)

    def target(self, proto="llmnr"):
        """本响应器的 `targets` 注入项（回环地址 + 临时端口）。"""
        return [(proto, "127.0.0.1", self.port)]


class _ResponderCase(unittest.TestCase):
    """带自动收尾的基类：假响应器必须保证关掉，否则线程会挂到测试进程结束。"""

    def responder(self, mode="positive"):
        fake = _FakeResponder(mode)
        self.addCleanup(fake.close)
        return fake


# ── 查询包字节级正确性 ─────────────────────────────────────────────────

class QueryBuildTest(unittest.TestCase):
    """两个协议的查询包必须字节级正确 —— 发错了对端直接忽略，探测静默失效。"""

    def test_llmnr_rd_bit_is_zero(self):
        """LLMNR 规定发送时 RD 位必须为 0（RFC 4795 §2.1），与普通 DNS 不同。

        这条最容易抄错：普通 DNS 查询的 flags 是 `0x0100`（RD=1），照抄过来
        虽然多数实现仍会应答，但已经不符合规范。
        """
        flags = struct.unpack("!H", build_llmnr_query("abc")[2:4])[0]
        self.assertEqual(flags, 0x0000)
        self.assertEqual(flags & 0x0100, 0, "RD 位必须为 0")

    def test_llmnr_header_counts(self):
        pkt = build_llmnr_query("abc", tid=0x1234)
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", pkt[:12])
        self.assertEqual((tid, flags, qd, an, ns, ar), (0x1234, 0, 1, 0, 0, 0))

    def test_llmnr_asks_any_type(self):
        """QTYPE=ANY(255)：问"你叫什么"而不是"A 记录是多少"，更容易被接住。"""
        pkt = build_llmnr_query("abc")
        self.assertEqual(struct.unpack("!HH", pkt[-4:]), (255, 1))

    def test_llmnr_carries_plain_dns_labels(self):
        pkt = build_llmnr_query("ipscanner-ab12c")
        self.assertIn(b"\x0fipscanner-ab12c\x00", pkt)
        self.assertEqual(pkt, build_llmnr_query("ipscanner-ab12c"),
                         "同参数必须产出同一份包（tid 之外无随机）")

    def test_nbns_flags_and_qtype(self):
        """flags=0x0110（查询 + 广播位）；QTYPE=0x20（NB），**不是** 0x21（NBSTAT）。"""
        pkt = build_nbns_query("abc", tid=0x1234)
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", pkt[:12])
        self.assertEqual((tid, flags, qd, an, ns, ar), (0x1234, 0x0110, 1, 0, 0, 0))
        self.assertEqual(struct.unpack("!HH", pkt[-4:]), (0x0020, 1))

    def test_nbns_name_is_nibble_encoded(self):
        """NBNS 的名字是 32 字节半字节编码，与 LLMNR 的标签编码完全不同形状。"""
        from scanner.netbios import _encode_nbname
        name16 = _nbt_name16("ipscanner-ab12c")
        enc = _encode_nbname(name16)
        self.assertEqual(len(enc), 32)
        pkt = build_nbns_query("ipscanner-ab12c")
        self.assertIn(enc, pkt)
        self.assertNotIn(b"ipscanner-ab12c", pkt, "不该以明文出现")

    def test_nbns_name16_is_padded_to_sixteen(self):
        raw = _nbt_name16("abc")
        self.assertEqual(len(raw), 16)
        self.assertEqual(raw[:3], b"ABC")
        self.assertEqual(raw[3:], b" " * 13)

    def test_the_two_wire_signatures_never_collide(self):
        """两个协议的线格式形状完全不同 —— 拿谁当签名都不会互相误判。

        这正是 `_wire_signature()` 敢只用"名字在报文里的样子"来认名字的前提。
        """
        name = "ipscanner-ab12c"
        self.assertNotEqual(_wire_signature("llmnr", name),
                            _wire_signature("nbns", name))
        self.assertIn(_wire_signature("llmnr", name),
                      build_llmnr_query(name).lower())
        self.assertIn(_wire_signature("nbns", name),
                      build_nbns_query(name).lower())

    def test_wire_signature_is_case_insensitive(self):
        """名字比较必须大小写不敏感：NBNS 的 16 字节名是**大写**的。"""
        self.assertEqual(_wire_signature("nbns", "ipscanner-ab12c"),
                         _wire_signature("nbns", "IPSCANNER-AB12C"))


class RandomProbeNameTest(unittest.TestCase):

    def test_fits_the_netbios_fifteen_char_limit(self):
        """⚠ 两个协议共用同一个名字，长度受 NBNS 这一侧约束（15 字符上限）。

        超了会被 `_nbt_name16()` 悄悄截断 —— 名字对不上，探测从此静默失效。
        """
        for _ in range(200):
            self.assertLessEqual(len(random_probe_name()), 15)

    def test_is_recognisable_and_ascii(self):
        name = random_probe_name()
        self.assertTrue(name.startswith(PROBE_PREFIX))
        name.encode("ascii")        # 不能抛
        self.assertEqual(len(name), len(PROBE_PREFIX) + llmnr_nbns.PROBE_SUFFIX_LEN)

    def test_suffix_is_random(self):
        """固定名字迟早会有人真的注册它，那时探测就变成永久误报。"""
        names = {random_probe_name() for _ in range(500)}
        self.assertGreater(len(names), 400, "随机后缀重复太多")


# ── 应答判定矩阵 ───────────────────────────────────────────────────────

def _reply(flags, ancount=1, qd=1):
    return struct.pack("!HHHHHH", 0x1234, flags, qd, ancount, 0, 0)


class PositiveAnswerTest(unittest.TestCase):
    """`is_positive_answer()` 的判定矩阵。每一条都对应一类真实误报或漏报。"""

    def test_positive_answer_is_accepted(self):
        self.assertTrue(is_positive_answer(_reply(0x8000)))

    def test_a_query_is_not_an_answer(self):
        """QR=0 —— 这是**别人的查询**，不是应答。"""
        self.assertFalse(is_positive_answer(_reply(0x0000)))

    def test_negative_rcode_is_rejected(self):
        """RCODE=3「名字不存在」是 WINS 服务器对任何不存在名字的正常反应。

        把它算成发现，等于把每个网段里的 WINS 服务器都报成欺骗响应器。
        """
        self.assertFalse(is_positive_answer(_reply(0x8003)))

    def test_other_rcodes_are_rejected(self):
        for rcode in (1, 2, 4, 5):
            with self.subTest(rcode=rcode):
                self.assertFalse(is_positive_answer(_reply(0x8000 | rcode)))

    def test_nonzero_opcode_is_rejected(self):
        for opcode in (1, 2, 4, 5, 15):
            with self.subTest(opcode=opcode):
                self.assertFalse(is_positive_answer(_reply(0x8000 | (opcode << 11))))

    def test_answer_without_any_record_is_rejected(self):
        """ANCOUNT=0 —— 声称是应答却一条记录都没有，不算肯定应答。"""
        self.assertFalse(is_positive_answer(_reply(0x8000, ancount=0)))

    def test_short_or_junk_input_is_rejected(self):
        for data in (b"", b"\x00", b"\x12\x34" * 5, None, 0, "text", [], {}):
            with self.subTest(data=data):
                self.assertFalse(is_positive_answer(data))

    def test_bytearray_is_accepted(self):
        self.assertTrue(is_positive_answer(bytearray(_reply(0x8000))))


# ── 收发链路（回环假响应器） ───────────────────────────────────────────

class ProbeRespondersTest(_ResponderCase):
    """三条判定链路：真响应器必须抓到，两类"看起来像应答"的必须放过。"""

    def test_a_positive_responder_is_found(self):
        fake = self.responder("positive")
        found = probe_responders(timeout=_WINDOW, name="ipscanner-ab12c",
                                 targets=fake.target())
        self.assertEqual(found, {"127.0.0.1": {"llmnr": "ipscanner-ab12c"}})
        self.assertGreaterEqual(fake.received, 1, "查询根本没送到")

    def test_a_negative_responder_is_not_found_but_was_reached(self):
        """WINS 服务器式的否定应答：**必须**放过，但包确实来回过。"""
        fake = self.responder("negative")
        found = probe_responders(timeout=_WINDOW, name="ipscanner-ab12c",
                                 targets=fake.target())
        self.assertEqual(found, {})
        self.assertGreaterEqual(fake.received, 1,
                                "包没到 —— 那这个测试什么也没证明")

    def test_a_positive_answer_for_another_name_is_ignored(self):
        """网络里随时有别人的 LLMNR/NBNS 流量在飘，只看"收到肯定应答"会全算进来。"""
        fake = self.responder("other-name")
        found = probe_responders(timeout=_WINDOW, name="ipscanner-ab12c",
                                 targets=fake.target())
        self.assertEqual(found, {})
        self.assertGreaterEqual(fake.received, 1)

    def test_both_protocols_are_probed_and_reported(self):
        """LLMNR 与 NBNS 各起一个假响应器，两个都要被抓到并分别标注协议。"""
        llmnr_fake = self.responder("positive")
        nbns_fake = self.responder("positive")
        found = probe_responders(
            timeout=_WINDOW, name="ipscanner-ab12c",
            targets=llmnr_fake.target("llmnr") + nbns_fake.target("nbns"))
        self.assertEqual(found, {"127.0.0.1": {"llmnr": "ipscanner-ab12c",
                                               "nbns": "ipscanner-ab12c"}})

    def test_no_target_answers_gives_an_empty_mapping(self):
        """干净网络（没人应答）应当得到空 dict —— 这是最常见的结果。"""
        found = probe_responders(timeout=0.3, name="ipscanner-ab12c",
                                 targets=[("llmnr", "127.0.0.1", _closed_port())])
        self.assertEqual(found, {})

    def test_empty_name_short_circuits(self):
        self.assertEqual(probe_responders(timeout=0.3, name="   "), {})
        self.assertEqual(probe_responders(timeout=0.3, name=""), {})

    def test_empty_targets_short_circuits(self):
        self.assertEqual(probe_responders(timeout=0.3, name="ipscanner-x",
                                          targets=[]), {})

    def test_unknown_protocol_is_ignored(self):
        """未知协议没有查询构造函数 —— 跳过而不是崩掉，另一个协议照常。"""
        found = probe_responders(timeout=0.3, name="ipscanner-x",
                                 targets=[("carrier-pigeon", "127.0.0.1", 1)])
        self.assertEqual(found, {})

    def test_unreachable_target_does_not_raise(self):
        """目标不可达（发不出去）只该告警，返回值仍是一个可用的 dict。"""
        found = probe_responders(timeout=0.3, name="ipscanner-x",
                                 targets=[("llmnr", "127.0.0.1", _closed_port())])
        self.assertEqual(found, {})

    def test_default_targets_are_the_standard_multicast_and_broadcast(self):
        """默认目标是 LLMNR 组播与 NBNS 广播 —— 写错地址探测就永远静默。"""
        self.assertEqual(DEFAULT_TARGETS,
                         (("llmnr", LLMNR_GROUP, LLMNR_PORT),
                          ("nbns", NBNS_BROADCAST, NBNS_PORT)))
        self.assertEqual((LLMNR_GROUP, LLMNR_PORT), ("224.0.0.252", 5355))
        self.assertEqual((NBNS_BROADCAST, NBNS_PORT), ("255.255.255.255", 137))

    def test_response_cap_is_enforced(self):
        """异常网络（或有人故意刷）里防止无限循环 —— 上限必须是个有限值。"""
        self.assertIsInstance(MAX_RESPONSES, int)
        self.assertGreater(MAX_RESPONSES, 0)
        self.assertLess(MAX_RESPONSES, 4096)


def _closed_port():
    """拿一个**确认没人监听**的回环端口（开一个再立刻关掉）。"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


# ── 结果分发 ───────────────────────────────────────────────────────────

class _Result:
    """够用的 ScanResult 替身（只用到 ip / name_responder）。"""

    def __init__(self, ip):
        self.ip = ip
        self.name_responder = {}


class ApplyRespondersTest(unittest.TestCase):

    def test_in_scope_responder_is_attached(self):
        results = [_Result("10.0.0.5"), _Result("10.0.0.6")]
        outside = apply_responders(results, {"10.0.0.5": {"llmnr": "ipscanner-a"}})
        self.assertEqual(results[0].name_responder, {"llmnr": "ipscanner-a"})
        self.assertEqual(results[1].name_responder, {})
        self.assertEqual(outside, [])

    def test_out_of_scope_responder_is_reported_not_fabricated(self):
        """不在扫描范围内的响应器**不伪造设备行** —— 快照记的是台账，
        塞一台没扫到的设备会让设备数失真。"""
        results = [_Result("10.0.0.5")]
        outside = apply_responders(results, {"10.0.0.99": {"nbns": "ipscanner-b"}})
        self.assertEqual(len(results), 1, "不能凭空多出一台设备")
        self.assertEqual(results[0].name_responder, {})
        self.assertEqual(outside, ["10.0.0.99"])

    def test_out_of_scope_list_is_sorted_and_deduplicated(self):
        results = []
        outside = apply_responders(results, {
            "10.0.0.30": {"llmnr": "x"},
            "10.0.0.10": {"llmnr": "x"},
            "10.0.0.20": {"nbns": "x"},
        })
        self.assertEqual(outside, ["10.0.0.10", "10.0.0.20", "10.0.0.30"])

    def test_nothing_found_changes_nothing(self):
        results = [_Result("10.0.0.5")]
        self.assertEqual(apply_responders(results, {}), [])
        self.assertEqual(results[0].name_responder, {})

    def test_both_protocols_are_kept_per_device(self):
        results = [_Result("10.0.0.5")]
        apply_responders(results, {"10.0.0.5": {"llmnr": "a", "nbns": "b"}})
        self.assertEqual(results[0].name_responder, {"llmnr": "a", "nbns": "b"})


# ── fuzz：判定函数吃的是不可信输入 ─────────────────────────────────────

class AnswerFuzzTest(unittest.TestCase):
    """`is_positive_answer()` 的输入来自网络里的任意主机，绝不能抛异常。"""

    def setUp(self):
        self.rnd = random.Random(_SEED)

    def test_random_bytes_never_raise(self):
        for _ in range(4000 * _SCALE):
            size = self.rnd.randrange(0, 300)
            data = bytes(self.rnd.randrange(256) for _ in range(size))
            with self.subTest(size=size):
                is_positive_answer(data)        # 不抛即通过

    def test_random_headers_never_raise_and_agree_with_the_rule(self):
        """随机 header 里也会**真的**出现肯定应答 —— 顺带验证判定与规范一致。"""
        accepted = 0
        for _ in range(4000 * _SCALE):
            tid = self.rnd.randrange(0x10000)
            flags = self.rnd.randrange(0x10000)
            qd = self.rnd.randrange(4)
            an = self.rnd.randrange(4)
            data = struct.pack("!HHHHHH", tid, flags, qd, an, 0, 0)
            got = is_positive_answer(data)
            expected = bool(flags & 0x8000) and not (flags >> 11) & 0x0F \
                and not flags & 0x000F and an >= 1
            with self.subTest(flags=flags, an=an):
                self.assertEqual(got, expected)
            accepted += got
        self.assertGreater(accepted, 0,
                           "随机 header 一个都没被判为肯定应答 —— 判定多半恒为 False")

    def test_mutated_real_answers_never_raise(self):
        """在**真实形状**的应答上做变异 —— 比纯随机字节更能进到判定深处。"""
        base = _dns_reply(build_llmnr_query("ipscanner-ab12c"), "positive")
        for _ in range(2000 * _SCALE):
            data = bytearray(base)
            for _ in range(self.rnd.randrange(1, 5)):
                pos = self.rnd.randrange(len(data))
                data[pos] = self.rnd.randrange(256)
            if self.rnd.random() < 0.3:
                data = data[:self.rnd.randrange(len(data) + 1)]
            with self.subTest(n=len(data)):
                is_positive_answer(bytes(data))


if __name__ == "__main__":
    unittest.main()
