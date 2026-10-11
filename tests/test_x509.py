# -*- coding: utf-8 -*-
"""X.509 走查 + HTTPS 证书读取（v1.9 #3「零利用安全体检」第一刀）。

为什么值得单独一个文件
----------------------
`scanner/x509.py` 是**手写**的 DER 走查 —— 本项目核心零第三方依赖（`cryptography`
没装，也不能为这一项引进来），而 `getpeercert()` 在 `CERT_NONE` 下只回一个空
dict，所以证书内容只能自己拆。它拆的是**不可信输入**：网里任何一台设备的 443
端口都能回一份畸形 DER，扫描线程直接吃下它。因此「结构不符就返回 `{}`、绝不抛
异常」是硬契约，不是"最好别抛"。

守四件事
--------
1. **解析** —— 用一份真实自签名证书的 DER（853 字节，openssl 现生成）逐字段
   核对，包括 RSA 位宽要从模数现算这件事（少走一层 SEQUENCE 会得到 0 位，
   实测踩过）；
2. **时间** —— UTCTime 的两位年用的是 **RFC 5280 §4.1.2.5.1** 规则（50–99 →
   19xx），不是 `strptime("%y")` 的 POSIX 规则（69–99 → 19xx）。两者在 **50–68**
   这段不一样，用 `%y` 会把 2068 读成 1968；
3. **判定** —— 弱签名 / 弱密钥阈值、"不认识的算法不下结论"（宁可漏报不可误报）；
4. **接线** —— `scanner.http.read_https` 真做一次 TLS 握手（**本地自签名服务端，
   不出网**），banner 里必须真的带上 CN。这正是原先 `cert["subject"]` 在
   `CERT_NONE` 下取不到、那十行**从未执行过**的死代码的回归守卫。

fuzz 部分沿用 `tests/test_fuzz_ber.py` 的三条纪律：固定种子、不只看"没抛异常"
（还要证明解析器**真的解析出了东西**）、纯随机字节是空转必须配"形状自洽"的
生成器。倍率同样读 `IPSCANNER_FUZZ_SCALE`（CI 用 1，本地想压满用 10）。
"""
import base64
import contextlib
import datetime
import io
import os
import random
import socket
import ssl
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import x509
from scanner.http import _read_https_banner, _tunnel_text, read_https
from scanner.x509 import parse_certificate

#: 固定种子 —— 失败必须可复现
_SEED = 0x584C3530

#: 迭代倍率，与 `tests/test_fuzz_ber.py` 共用同一个开关。
_SCALE = max(1, int(os.environ.get("IPSCANNER_FUZZ_SCALE", "1") or "1"))


# ── 固件 ───────────────────────────────────────────────────────────────
#
# 两份都是**现生成的一次性测试证书**，私钥只用于本文件里的本地回环 TLS 服务端，
# 没有任何真实用途、也不保护任何东西。之所以把私钥也贴进来：只有这样才能在
# **不出网**的前提下真跑一次握手（CI 跑在 GitHub runner 上，不能依赖外网）。

#: openssl req -x509 -newkey rsa:2048 -sha256 现生成的自签名证书 DER。
#: CN=ipscanner-test.local / O=IPScanner Test / 有效期 2026-10-11 → 2036-10-08
_FIXTURE_B64 = (
    "MIIDUTCCAjmgAwIBAgIUWexij4PQWUwZw1xsGYnYCsyVFIcwDQYJKoZIhvcNAQELBQAwODEdMBsG"
    "A1UEAwwUaXBzY2FubmVyLXRlc3QubG9jYWwxFzAVBgNVBAoMDklQU2Nhbm5lciBUZXN0MB4XDTI2"
    "MTAxMTA1MTYwMVoXDTM2MTAwODA1MTYwMVowODEdMBsGA1UEAwwUaXBzY2FubmVyLXRlc3QubG9j"
    "YWwxFzAVBgNVBAoMDklQU2Nhbm5lciBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"
    "AQEAozGWZQv8BdUZf7BO6xzd4cGje7rYQRz9vzL5I/1uS2QKlJhz4IeDihxE+ptE7fsDDb70zcFm"
    "lCM93S8eyLu7sjSY+AxyhKO3AFbk1GyU2MYkaI6RCc1TYEgM/lm3sxWbFuKqY974EdUL2f3Tnlht"
    "DutQkL2Nw5oLJccHB5o62D5TlO8iy1mRGt27QKiP/ShZJQoa3ZE9siNCOjcC9ySClVVC7B6z8A5z"
    "Z9Ej03+rFdBLLluAPDoTJbJLL6r35aPQ2mJWF+IBkLIv8ukdxTfypuFrmghJtPWdzZSsZhhNa/lD"
    "9lqlAS6HcdMOXUQ6eMJN+rpsByR+qqJxHfN5EWossQIDAQABo1MwUTAdBgNVHQ4EFgQUkatlNNek"
    "bqwT7uYjd36x9fldf4YwHwYDVR0jBBgwFoAUkatlNNekbqwT7uYjd36x9fldf4YwDwYDVR0TAQH/"
    "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAfTK/Xd91t5oCpQAN2LURCxyAEHShE9lX7njbLq/A"
    "bkNqi6fOHnri4hhFJD92lRkFQ7dFQKl10+awR9Wx8Kq64n2E9KwJMyP4YzvjXImI3UAyy11eRPnn"
    "S8A+TajUZ6Flrax7oisEwg9NKfTAFBrzYsUobQ6VnvmRjhv6620yovgDqhpnwA6dbQjpOCCNdSce"
    "Jot3cFLecoOpp5LJuOc7KXd5TeT0EL1dpRjRxK3R4lJVJfQMXjPnr9D7rNUxiNTim08fXTVtp0xk"
    "85qQRRuSgBgWBhtsJex7O4AWNE3Zw4hDps0zJChSiUHWWi44evBDK+aJWADe0e96NOFdzB99tA=="
)
FIXTURE_DER = base64.b64decode(_FIXTURE_B64)

#: 本地回环 TLS 服务端用的证书 / 私钥（一次性测试用，见上面的说明）。
#: CN=ipscanner-selftest.local / O=IPScanner Test / 有效期到 2126-09-17
SERVER_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDWzCCAkOgAwIBAgIUNU9XM0gQwXpZf8UkKy0Oc3EVUFUwDQYJKoZIhvcNAQEL
BQAwPDEXMBUGA1UECgwOSVBTY2FubmVyIFRlc3QxITAfBgNVBAMMGGlwc2Nhbm5l
ci1zZWxmdGVzdC5sb2NhbDAgFw0yNjEwMTEwNTIzMzhaGA8yMTI2MDkxNzA1MjMz
OFowPDEXMBUGA1UECgwOSVBTY2FubmVyIFRlc3QxITAfBgNVBAMMGGlwc2Nhbm5l
ci1zZWxmdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALmm28y7748vEyOrmb1FCmUqparCHomHWoFYcHz0iiF1T2lbK93utBE8dJMhUaWa
8w3v55dc24lRhpNaufDZf2U1oqGsDdJu/Bjzb7xTs2p6L2G5VIOd5Bq1kjA+cmnH
SIELHSOIdZbNocpPCuPkTqTsLkmtwAjffPKhIXBGquBbhn4dL9Vbz/92QKRKBQPr
nc6Mfa/KEs7dS4x3g1t4YJ/wHSEaXR8OU2r16+H3YoRfmbiqxGPsqxxPVbwE//oW
4kc2fThqPL5bp207jHwh1g37EQdKKzhXmmdaycWJCJADDj1ma/uxDrBDR+qc7gk1
OwV/Yre4IEkFbBxVYLyxOJMCAwEAAaNTMFEwHQYDVR0OBBYEFCuJDxfrnO1HiTm8
MU9hhNDjX+eTMB8GA1UdIwQYMBaAFCuJDxfrnO1HiTm8MU9hhNDjX+eTMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACKIPADU+YyiTG7baozXhF+A
QgfOvLFzKagDS7HI+hlhSUKDOL41O6dfsD7XXiXp50mvdnGaXfz8Br8PC8axuAjc
STW6MSCYWDtgYOmXcVwKPRpO3f8AcQVO4JoIuksskulWu1gYjMVOdVSljSuxKWHq
j9LfLrZVisrz6ykjtd9YCq2CHljges5C645CFxAXb8+ReJORywqUdtd3OzV1MAfp
bn+LujPJT2UyflHbuAfHhH1Y6zgjXaidOQkJORljzKWpw+j6JticP4na2yW0CKok
kaCvr1cL9FFLL+ZQysSjNfqK2WqAuL77Qa1U3HEgeriMOoi/hb6/T2qYfhPOqSc=
-----END CERTIFICATE-----
"""

SERVER_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC5ptvMu++PLxMj
q5m9RQplKqWqwh6Jh1qBWHB89IohdU9pWyvd7rQRPHSTIVGlmvMN7+eXXNuJUYaT
Wrnw2X9lNaKhrA3SbvwY82+8U7Nqei9huVSDneQatZIwPnJpx0iBCx0jiHWWzaHK
Twrj5E6k7C5JrcAI33zyoSFwRqrgW4Z+HS/VW8//dkCkSgUD653OjH2vyhLO3UuM
d4NbeGCf8B0hGl0fDlNq9evh92KEX5m4qsRj7KscT1W8BP/6FuJHNn04ajy+W6dt
O4x8IdYN+xEHSis4V5pnWsnFiQiQAw49Zmv7sQ6wQ0fqnO4JNTsFf2K3uCBJBWwc
VWC8sTiTAgMBAAECggEAFcxYvIZIj4hYd/S7HXUQzmYeg5k9WqqQ3uUSeCmCWoFa
rKUu1mUjsW5mxavA2XADH9zOVYBqqonvAjhB4ty2z5xnlxILoWy0nv1eXj95roPg
Mlo/aSDN2rD9FDsQ1gi3I6e5aSWpoOZOG+ICBlYVQdoVaUNEbAZJtndi5Lr3b1Y8
laCXkzLhHT6rX9wXyvLc+2/aBzKnRV15VZWcZaKkjx7/kdJh8xSAiBApzOAogmXD
t6COiG644HeLs5jwvpkuQGrKITpLtdsqA3aiwCl5IpQlb8F5J0bebsePE/nhiznq
RodTLNQsRrU/q2VFkRo0HcGrTB6+6zzt00ETmPzPSQKBgQDdtHRtUTxzeehbkShM
Zf8h59dvG3U91zP1FzQMQ1v4dG65Tm1aG1P6K+RhMrj+oN0I4rvXPKWOd6UzmFF7
ZGzV09TP6/ru5C/iWPaQUwN1a4Wmrgzk5tUGRRpfxda8FqlXv1Xz6n/IzigU20N1
2cPYfCB9z61RO+4dOxB6B3lz5wKBgQDWXrIReAfuGZKII3v03U+5zbpuUvg7ADhN
RihJG+98+HQGvnvIP0vpHPqGSrVHSu6mnQkJZgvzUVA0EPuqZJAJq2dyi8v95z/m
ytud84yV7cTTlGS75adAAoON6SzXkMGPWqWWb6E3rn1UG3YMWaKD1u0l2m8ckSNh
50K+Ym7AdQKBgQDRwaqpxsMv6fX5tDNxXMrvFD+SYmMhWBtTVlmrBIveXKJpdhcl
uldQiPhxMaEvX5jgkEvyDvIAAZjuYL0uxkvmXp2o/nYSURgwycS1taS/EjSIB4Ix
i2eeoACc/jv1Bme/mkpDFOlDXjEz0mNX++k8R+whvDwZcF8PjtM+8RVqnwKBgQC7
PznxMlRS8PliewRCTbHfDUmEJmr3Nmj3bomv2nvlQCww29/JeSh4dbyK4uTXYid1
V4PWNtHHdkZFRHRfULnUCGkyz9Oec4kIsjcFEADD0U10tpEK4z2lFs0MfxmRLbs0
2av77IP43CxS9C23+e+Pk4PP5a3aWRh74wIUxGwTJQKBgQCSRln4FA8ZtS6C8ZSi
0rzagr2Fa+8WfM2LIEouoMTZbMVYZLBag/z/9C/2uPrYY64NNtzmb8DFuAeIocsk
KnxiDbAh+8qaey6kqZCrBRLM6rfGNvHbcwQDTo48sTGnPNvcBZjajQV0WBgTIA3c
lmujMMfJdqtO/x6MTAai9Soqow==
-----END PRIVATE KEY-----
"""

#: `parse_certificate` 的返回键是**固定**的 —— 取不到就是 "" / 0 / False。
_KEYS = ("cn", "issuer_cn", "not_before", "not_after", "self_signed",
         "sig_alg", "key_alg", "key_bits", "curve")


# ── DER 构造小工具（只给 fuzz 用） ──────────────────────────────────────


def _len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def _oid(dotted):
    nums = [int(x) for x in dotted.split(".")]
    raw = bytearray([nums[0] * 40 + nums[1]])
    for value in nums[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append((value & 0x7F) | 0x80)
            value >>= 7
        raw += bytes(reversed(chunk))
    return _tlv(0x06, bytes(raw))


def _name(text):
    """Name = SEQ{ SET{ SEQ{ OID commonName, UTF8 text } } }"""
    return _tlv(0x30, _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, text))))


def _shaped_cert(rnd):
    """**证书形状**的随机 DER：外壳与层级都对，内容随机。

    纯随机字节与"随便嵌套的 DER"对本走查都是空转（实测非空率 **0%**）——
    走查要求一条证书形状的路径，形状不对就立刻返回 `{}`。只有把形状搭对，
    才能真正压到 validity / subject / SPKI 那几层（实测非空率 65.1%）。
    """
    sig = _oid(rnd.choice(["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.5",
                           "1.2.840.10045.4.3.2", "2.9.9.9"]))
    algid = _tlv(0x30, sig)
    cn = bytes(rnd.randrange(32, 127) for _ in range(rnd.randrange(0, 12)))
    name = _name(cn)
    t_tag = rnd.choice([0x17, 0x18])
    if t_tag == 0x17:
        stamp = b"%02d%02d%02d%02d%02d%02dZ" % (
            rnd.randrange(0, 100), rnd.randrange(1, 13), rnd.randrange(1, 29),
            rnd.randrange(0, 24), rnd.randrange(0, 60), rnd.randrange(0, 60))
    else:
        stamp = b"%04d%02d%02d%02d%02d%02dZ" % (
            rnd.randrange(1950, 2100), rnd.randrange(1, 13), rnd.randrange(1, 29),
            rnd.randrange(0, 24), rnd.randrange(0, 60), rnd.randrange(0, 60))
    validity = _tlv(0x30, _tlv(t_tag, stamp) + _tlv(t_tag, stamp))
    modulus = bytes([rnd.randrange(1, 256)]) + bytes(
        rnd.randrange(256) for _ in range(rnd.randrange(32, 256)))
    spki = _tlv(0x30, _tlv(0x30, _oid("1.2.840.113549.1.1.1")) +
                _tlv(0x03, b"\x00" + _tlv(0x30, _tlv(0x02, modulus) +
                                          _tlv(0x02, b"\x01\x00\x01"))))
    fields = [_tlv(0x02, bytes([rnd.randrange(1, 256)]))]      # serialNumber
    fields.append(algid)                                       # signature
    fields.append(name)                                        # issuer
    fields.append(validity)                                    # validity
    fields.append(name if rnd.random() < 0.4 else _name(cn))   # subject
    fields.append(spki)                                        # subjectPublicKeyInfo
    if rnd.random() < 0.8:
        fields.insert(0, _tlv(0xA0, _tlv(0x02, b"\x02")))      # [0] version
    tbs = _tlv(0x30, b"".join(fields))
    der = _tlv(0x30, tbs + algid + _tlv(0x03, b"\x00" + bytes(rnd.randrange(64))))
    if rnd.random() < 0.35:                                    # 三分之一截断
        der = der[:rnd.randrange(1, len(der) + 1)]
    return der


def _mutate(rnd, data):
    """对真实证书做一次结构无关的破坏（位翻转 / 截断 / 插入 / 删除 / 改写）。"""
    if not data:
        return bytes([rnd.randrange(256)])
    buf = bytearray(data)
    kind = rnd.randrange(5)
    if kind == 0:
        buf[rnd.randrange(len(buf))] ^= 1 << rnd.randrange(8)
    elif kind == 1:
        del buf[rnd.randrange(len(buf)):]
    elif kind == 2:
        i = rnd.randrange(len(buf))
        buf[i:i] = bytes([rnd.randrange(256)])
    elif kind == 3 and len(buf) > 2:
        del buf[rnd.randrange(len(buf))]
    else:
        buf[rnd.randrange(len(buf))] = rnd.randrange(256)
    return bytes(buf)


# ── 本地回环 TLS 服务端（不出网） ───────────────────────────────────────


class _TlsServer:
    """一个只跑在 127.0.0.1 上的自签名 TLS 服务端，可接受多次连接。

    ⚠ 收尾与"对端先走"这两条路径用的是 `contextlib.suppress` 而不是
    `except OSError: pass`：前者**具名**说出容忍的是哪个异常，后者会被
    `tests/test_logging_policy.py` 的「静默吞异常」棘轮计为新增（实测踩过）。
    """

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="ipscanner-tls-")
        cert = os.path.join(self.dir, "cert.pem")
        key = os.path.join(self.dir, "key.pem")
        # 显式 newline="\n"：Windows 下默认会写 CRLF，PEM 解析虽容忍，
        # 但保持仓库"文本文件一律 LF"的习惯。
        for path, text in ((cert, SERVER_CERT_PEM), (key, SERVER_KEY_PEM)):
            with io.open(path, "w", encoding="ascii", newline="\n") as fh:
                fh.write(text)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stopped = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        # 监听套接字被 close() 之后 accept 必然抛 OSError —— 那是**收尾时的
        # 正常路径**，也是这个循环唯一的退出方式。
        with contextlib.suppress(OSError):
            while not self._stopped:
                conn, _ = self.sock.accept()
                threading.Thread(target=self._handle, args=(conn,),
                                 daemon=True).start()

    def _handle(self, conn):
        # 客户端取完证书就走，不打招呼是常态（对端 RST / 提前 close）——
        # 这类错误对测试结论没有意义，具名吞掉。
        with contextlib.suppress(OSError, ssl.SSLError):
            with conn:
                with self.ctx.wrap_socket(conn, server_side=True) as ss:
                    while ss.recv(4096):
                        pass             # 等客户端关连接（EOF）

    def close(self):
        self._stopped = True
        # `socket.close()` 是幂等的（重复调用不抛），所以这里不需要任何保护。
        self.sock.close()
        self.thread.join(timeout=5)


def _plain_server(handle):
    """起一个**非 TLS** 的 127.0.0.1 假服务端，返回监听套接字（调用方 close）。

    `handle(conn)` 决定它像什么。里面抛的 OSError 一并吞掉 —— 客户端握手失败
    会立刻断开，"对端先走了"是测试里的正常路径（同样用具名 suppress）。
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def _serve():
        with contextlib.suppress(OSError):
            while True:
                conn, _ = srv.accept()
                with contextlib.suppress(OSError):
                    handle(conn)
                conn.close()

    threading.Thread(target=_serve, daemon=True).start()
    return srv


def _closed_port():
    """分配一个刚被关掉的本地端口 —— 连它必然 ConnectionRefused。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ── 1. 解析 ────────────────────────────────────────────────────────────


class ParseCertificateTest(unittest.TestCase):
    """用真实证书固件逐字段核对（不是"看着像对"）。"""

    def test_fixture_is_a_real_certificate(self):
        """先证明固件本身是能被解出来的真证书 —— 否则下面的断言在测空气。"""
        got = parse_certificate(FIXTURE_DER)
        self.assertTrue(got, "固件解析为空，说明走查或固件有一边坏了")

    def test_fixture_fields(self):
        got = parse_certificate(FIXTURE_DER)
        self.assertEqual(got["cn"], "ipscanner-test.local")
        self.assertEqual(got["issuer_cn"], "ipscanner-test.local")
        self.assertEqual(got["not_before"], "2026-10-11T05:16:01")
        self.assertEqual(got["not_after"], "2036-10-08T05:16:01")
        self.assertTrue(got["self_signed"])
        self.assertEqual(got["sig_alg"], "sha256_rsa")
        self.assertEqual(got["key_alg"], "rsa")
        # ⚠ RSA 的模数包在 BIT STRING 里再套一层 SEQUENCE，少走这一层会得到 0
        self.assertEqual(got["key_bits"], 2048)
        self.assertEqual(got["curve"], "")

    def test_return_keys_are_fixed(self):
        """键固定 —— 消费方（tls_cert_facts / risk_rules）按名取值。"""
        self.assertEqual(set(parse_certificate(FIXTURE_DER)), set(_KEYS))

    def test_der_length(self):
        self.assertEqual(len(FIXTURE_DER), 853)

    def test_accepts_bytearray(self):
        self.assertEqual(parse_certificate(bytearray(FIXTURE_DER)),
                         parse_certificate(FIXTURE_DER))

    def test_rejects_non_bytes(self):
        for bad in (None, "", "x" * 200, 123, [], {}, object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertEqual(parse_certificate(bad), {})

    def test_rejects_out_of_range_sizes(self):
        """太小（<32 字节）或太大（>1 MiB）直接判垃圾，连结构都不看。"""
        self.assertEqual(parse_certificate(b""), {})
        self.assertEqual(parse_certificate(b"\x30" * 31), {})
        self.assertEqual(parse_certificate(b"\x30" * ((1 << 20) + 1)), {})

    def test_rejects_non_sequence_outer(self):
        self.assertEqual(parse_certificate(b"\x02" + b"\x7e" + b"\x00" * 126), {})

    def test_every_prefix_of_the_fixture_is_safe(self):
        """853 个前缀逐个喂进去 —— 截断是最常见的畸形，且必然命中"半截 TLV"。"""
        for n in range(len(FIXTURE_DER)):
            with self.subTest(prefix=n):
                got = parse_certificate(FIXTURE_DER[:n])
                self.assertIsInstance(got, dict)
                if got:
                    self.assertEqual(set(got), set(_KEYS))

    def test_truncating_the_tail_yields_nothing(self):
        """外层长度域声明了 853 字节，一截断它就不再成立 → 整份判垃圾。

        这是**有意**的：`_read_tlv` 要求每个 TLV 完整（`stop > end` 即拒），
        所以"信封破了"给的是**空**，而不是一份来路不明的半截证书 —— 拿半截
        数据下安全结论比说"没读到"危险得多。
        """
        for cut in (1, 10, 200, 400):
            with self.subTest(cut=cut):
                self.assertEqual(parse_certificate(FIXTURE_DER[:-cut]), {})

    def test_missing_pieces_degrade_to_empty_strings(self):
        """信封完整、但某几项缺失时，**能读到多少给多少**（不整份丢弃）。

        这份手工构造的证书刻意缺三样：没有 `[0]` 版本号（v1 证书就这样）、
        validity 里只有 notBefore、公钥换成 EC。用来钉住两件事：
        版本号可缺（下标要跟着挪），以及缺项是空串而不是异常。
        """
        algid = _tlv(0x30, _oid("1.2.840.113549.1.1.11"))
        name = _name(b"degraded.local")
        validity = _tlv(0x30, _tlv(0x17, b"260101000000Z"))     # 只有 notBefore
        spki = _tlv(0x30, _tlv(0x30, _oid("1.2.840.10045.2.1") +
                               _oid("1.2.840.10045.3.1.7")) +
                    _tlv(0x03, b"\x00" + b"\x04" + b"\x00" * 64))
        fields = [_tlv(0x02, b"\x01"), algid, name, validity, name, spki]
        der = _tlv(0x30, _tlv(0x30, b"".join(fields)) +
                   algid + _tlv(0x03, b"\x00" + b"\x00" * 8))

        got = parse_certificate(der)
        self.assertEqual(set(got), set(_KEYS))
        self.assertEqual(got["cn"], "degraded.local")
        self.assertEqual(got["not_before"], "2026-01-01T00:00:00")
        self.assertEqual(got["not_after"], "", "只有 notBefore，notAfter 应是空串")
        self.assertTrue(got["self_signed"], "issuer 与 subject 是同一份 DER")
        self.assertEqual(got["sig_alg"], "sha256_rsa")
        self.assertEqual(got["key_alg"], "ec")
        self.assertEqual(got["key_bits"], 256)
        self.assertEqual(got["curve"], "prime256v1")

    def test_corrupting_the_outer_length_yields_nothing(self):
        """外层长度域被改大 → 越界 → 直接 {}（而不是读出一堆垃圾）。"""
        bad = bytearray(FIXTURE_DER)
        bad[1] = 0x84                      # 该用短形式的长度域改成长形式
        self.assertEqual(parse_certificate(bytes(bad)), {})

    def test_indefinite_length_is_rejected(self):
        """DER 不允许不定长（BER 才允许）。"""
        self.assertEqual(parse_certificate(b"\x30\x80" + b"\x00" * 64), {})


class ParseTimeTest(unittest.TestCase):
    """`_parse_time` 的两位年规则与格式校验。"""

    def _utc(self, body):
        return x509._parse_time(x509._TAG_UTC_TIME, body.encode("ascii"))

    def _gen(self, body):
        return x509._parse_time(x509._TAG_GEN_TIME, body.encode("ascii"))

    def test_utc_time_two_digit_year_boundary(self):
        """⚠ RFC 5280 的规则：50–99 → 19xx，00–49 → 20xx。

        用 `strptime("%y")` 的 POSIX 规则（69–99 → 19xx）会在 **50–68** 这段
        出错 —— 把 2050 读成 1950、把 2068 读成 1968。这里逐个钉住边界。
        """
        self.assertEqual(self._utc("490101000000Z"), "2049-01-01T00:00:00")
        self.assertEqual(self._utc("500101000000Z"), "1950-01-01T00:00:00")
        self.assertEqual(self._utc("680101000000Z"), "1968-01-01T00:00:00")
        self.assertEqual(self._utc("690101000000Z"), "1969-01-01T00:00:00")
        self.assertEqual(self._utc("990101000000Z"), "1999-01-01T00:00:00")
        self.assertEqual(self._utc("000101000000Z"), "2000-01-01T00:00:00")

    def test_utc_time_matches_the_fixture(self):
        self.assertEqual(self._utc("361008051601Z"), "2036-10-08T05:16:01")

    def test_generalized_time(self):
        self.assertEqual(self._gen("21260917052338Z"), "2126-09-17T05:23:38")
        self.assertEqual(self._gen("19991231235959Z"), "1999-12-31T23:59:59")

    def test_rejects_wrong_tag(self):
        """标签不是时间类型 → 空串（不能把任意字符串当时间读）。"""
        for tag in (x509._TAG_UTF8, x509._TAG_PRINTABLE, x509._TAG_OID, 0x02):
            with self.subTest(tag=tag):
                self.assertEqual(x509._parse_time(tag, b"361008051601Z"), "")

    def test_rejects_malformed_forms(self):
        cases = {
            "缺 Z": "361008051601",
            "不带秒": "3610080516Z",
            "多一位": "3610080516010Z",
            "少一位": "36100805160Z",
            "有非数字": "3610080516x1Z",
            "空": "Z",
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self._utc(body), "")

    def test_rejects_impossible_dates(self):
        for body in ("991301000000Z",          # 13 月
                     "990132000000Z",          # 32 日
                     "990101250000Z",          # 25 时
                     "990101006000Z"):         # 60 分
            with self.subTest(body=body):
                self.assertEqual(self._utc(body), "")

    def test_rejects_non_ascii(self):
        self.assertEqual(
            x509._parse_time(x509._TAG_UTC_TIME, b"3610080516\xff1Z"), "")

    def test_generalized_time_length_is_checked(self):
        self.assertEqual(self._gen("361008051601Z"), "")     # 12 位不是 GeneralizedTime
        self.assertEqual(self._gen("2036100805160Z"), "")


# ── 2. 判定 ────────────────────────────────────────────────────────────


class WeakPredicateTest(unittest.TestCase):

    def test_weak_signature_markers(self):
        for alg in ("md5_rsa", "sha1_rsa", "sha1_dsa", "sha1_ecdsa"):
            with self.subTest(alg=alg):
                self.assertTrue(x509.is_weak_signature(alg))
        for alg in ("sha256_rsa", "sha384_rsa", "sha512_rsa", "sha256_ecdsa",
                    "sha224_rsa", "ed25519"):
            with self.subTest(alg=alg):
                self.assertFalse(x509.is_weak_signature(alg))

    def test_unknown_algorithm_stays_silent(self):
        """不认识的 OID 不下结论 —— 宁可漏报，不可误报。"""
        for alg in ("", "2.9.9.9", "1.2.3.4.5", "1.3.6.1.4.1.99999.1"):
            with self.subTest(alg=alg):
                self.assertFalse(x509.is_weak_signature(alg))

    def test_weak_key_thresholds(self):
        self.assertTrue(x509.is_weak_key("rsa", 1024))
        self.assertTrue(x509.is_weak_key("rsa", 2047))
        self.assertFalse(x509.is_weak_key("rsa", 2048))
        self.assertFalse(x509.is_weak_key("rsa", 4096))
        self.assertTrue(x509.is_weak_key("ec", 192))
        self.assertFalse(x509.is_weak_key("ec", 256))
        self.assertTrue(x509.is_weak_key("dsa", 1024))

    def test_unknown_key_algorithm_stays_silent(self):
        self.assertFalse(x509.is_weak_key("", 512))
        self.assertFalse(x509.is_weak_key("ed25519", 255))
        self.assertFalse(x509.is_weak_key("weird", 64))

    def test_zero_bits_means_unknown_not_weak(self):
        """位数取不到（0）时不下结论 —— 否则每台读不到模数的设备都会被误报。"""
        for alg in ("rsa", "ec", "dsa", ""):
            with self.subTest(alg=alg):
                self.assertFalse(x509.is_weak_key(alg, 0))
                self.assertFalse(x509.is_weak_key(alg, None))

    def test_thresholds_are_the_documented_constants(self):
        self.assertEqual(x509.MIN_RSA_BITS, 2048)
        self.assertEqual(x509.MIN_EC_BITS, 224)


class DaysUntilTest(unittest.TestCase):

    _NOW = datetime.datetime(2026, 10, 11, 12, 0, 0)

    def test_future_and_past(self):
        self.assertEqual(x509.days_until("2026-10-21T12:00:00", now=self._NOW), 10)
        self.assertEqual(x509.days_until("2026-10-01T12:00:00", now=self._NOW), -10)
        self.assertEqual(x509.days_until("2026-10-11T12:00:00", now=self._NOW), 0)

    def test_boundary_is_floor_not_round(self):
        """差 23 小时算 0 天 —— `.days` 是向下取整，别把它当四舍五入。"""
        self.assertEqual(x509.days_until("2026-10-12T11:00:00", now=self._NOW), 0)
        self.assertEqual(x509.days_until("2026-10-12T13:00:00", now=self._NOW), 1)

    def test_unparseable_returns_none(self):
        for bad in ("", None, "2036/10/08", "2036-10-08", "not a date",
                    "2036-13-08T05:16:01", "2036-10-08T05:16:01Z"):
            with self.subTest(bad=bad):
                self.assertIsNone(x509.days_until(bad, now=self._NOW))

    def test_uses_utc_now_by_default(self):
        """不传 now 时取当前 UTC —— 给一个远期日期，结果必须是正的大数。"""
        got = x509.days_until("2999-01-01T00:00:00")
        self.assertIsNotNone(got)
        self.assertGreater(got, 300000)


# ── 3. 接线：真跑一次 TLS 握手（本地回环，不出网） ──────────────────────


class TunnelTextTest(unittest.TestCase):
    """`_tunnel_text` 是纯粹的格式化 —— 顺带钉住"没有 CN 时怎么显示"。"""

    def test_formats_version_and_cn(self):
        self.assertEqual(_tunnel_text("TLSv1.3", "*.github.com"),
                         "Tunnel is OpenSSL TLSv1.3: *.github.com")

    def test_falls_back_when_either_side_is_empty(self):
        self.assertEqual(_tunnel_text("", ""),
                         "Tunnel is OpenSSL TLS: unknown service")
        self.assertEqual(_tunnel_text("TLSv1.2", ""),
                         "Tunnel is OpenSSL TLSv1.2: unknown service")
        self.assertEqual(_tunnel_text("", "a.b"),
                         "Tunnel is OpenSSL TLS: a.b")

    def test_none_is_tolerated(self):
        self.assertEqual(_tunnel_text(None, None),
                         "Tunnel is OpenSSL TLS: unknown service")


class ReadHttpsTest(unittest.TestCase):
    """真握手。

    这是那十行**死代码**的回归守卫：`CERT_NONE` 下 `getpeercert()` 回的是**空
    dict**（不是 None、也不报错），所以旧代码读 `cert["subject"]` 永远取不到 CN，
    banner 恒为 `"...: unknown service"`。现在走 `getpeercert(binary_form=True)`
    拿 DER 自己解 —— 若哪天又退回去，下面的断言立刻红。
    """

    def setUp(self):
        self.srv = _TlsServer()
        self.addCleanup(self.srv.close)

    def test_banner_carries_the_certificate_cn(self):
        banner, facts = read_https("127.0.0.1", self.srv.port, 3.0)
        self.assertIn("ipscanner-selftest.local", banner,
                      "banner 里没有 CN —— 十行死代码又回来了：%r" % banner)
        self.assertNotIn("unknown service", banner)
        self.assertEqual(facts["cn"], "ipscanner-selftest.local")

    def test_facts_match_the_local_certificate(self):
        _banner, facts = read_https("127.0.0.1", self.srv.port, 3.0)
        self.assertEqual(set(facts), set(_KEYS))
        self.assertEqual(facts["issuer_cn"], "ipscanner-selftest.local")
        self.assertTrue(facts["self_signed"])
        self.assertEqual(facts["sig_alg"], "sha256_rsa")
        self.assertEqual(facts["key_alg"], "rsa")
        self.assertEqual(facts["key_bits"], 2048)
        self.assertEqual(facts["not_after"], "2126-09-17T05:23:38")
        self.assertGreater(x509.days_until(facts["not_after"]), 30000)

    def test_banner_starts_with_the_tunnel_prefix(self):
        banner, _facts = read_https("127.0.0.1", self.srv.port, 3.0)
        self.assertTrue(banner.startswith("Tunnel is OpenSSL "), banner)

    def test_banner_wrapper_matches_read_https(self):
        banner, _facts = read_https("127.0.0.1", self.srv.port, 3.0)
        self.assertEqual(_read_https_banner("127.0.0.1", self.srv.port, 3.0), banner)

    def test_server_accepts_repeated_connections(self):
        """服务端可复用 —— 上面几条测试都依赖它，串行读两次确认没有"只服务一次"。"""
        first, _f1 = read_https("127.0.0.1", self.srv.port, 3.0)
        second, _f2 = read_https("127.0.0.1", self.srv.port, 3.0)
        self.assertEqual(first, second)
        self.assertIn("ipscanner-selftest.local", second)

    def test_refused_connection_returns_unknown_service(self):
        banner, facts = read_https("127.0.0.1", _closed_port(), 1.0)
        self.assertEqual(banner, "unknown service")
        self.assertEqual(facts, {})
        self.assertEqual(_read_https_banner("127.0.0.1", _closed_port(), 1.0),
                         "unknown service")

    def test_plain_tcp_server_returns_unknown_service(self):
        """对端不是 TLS（回的是明文）→ 握手失败 → 如实说"不认识"，不抛异常。"""
        srv = _plain_server(lambda conn: conn.sendall(b"220 not-a-tls-server\r\n"))
        self.addCleanup(srv.close)
        banner, facts = read_https("127.0.0.1", srv.getsockname()[1], 3.0)
        self.assertEqual(banner, "unknown service")
        self.assertEqual(facts, {})

    def test_black_hole_returns_unknown_service_within_timeout(self):
        """对端接受连接但永不说话 → 由 timeout 兜底，不能挂死扫描线程。"""
        release = threading.Event()
        self.addCleanup(release.set)
        srv = _plain_server(lambda conn: release.wait(5.0))   # 拿住不放，什么都不发
        self.addCleanup(srv.close)
        banner, facts = read_https("127.0.0.1", srv.getsockname()[1], 0.5)
        self.assertEqual(banner, "unknown service")
        self.assertEqual(facts, {})


# ── 4. fuzz ────────────────────────────────────────────────────────────


class X509FuzzTest(unittest.TestCase):
    """「结构不符就返回 `{}`、绝不抛异常」是硬契约（见模块 docstring）。

    纪律与 `tests/test_fuzz_ber.py` 一致：固定种子；不只看"没抛异常"，还要证明
    解析器**真的解析出了东西**（否则等于在 fuzz 空气）；纯随机字节与形状自洽的
    生成器都要有。
    """

    def _check_shape(self, got, label, data):
        self.assertIsInstance(got, dict, msg="%s 返回了非 dict" % label)
        if got:
            self.assertEqual(set(got), set(_KEYS),
                             msg="%s 的键不对：%s" % (label, sorted(got)))

    def test_random_bytes_never_raise(self):
        """纯随机字节 —— 覆盖"连外层都不是 SEQUENCE"这一档。

        ⚠ 这一档实测**非空率 0%**（形状不对就立刻返回），所以它只证明"不炸"，
        真正压到深层的是下面两条。这里如实说明，免得后人以为 0% 是坏掉了。
        """
        rnd = random.Random(_SEED)
        nonempty = 0
        for _ in range(6000 * _SCALE):
            data = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 300)))
            got = parse_certificate(data)
            self._check_shape(got, "纯随机", data)
            nonempty += 1 if got else 0
        self.assertEqual(nonempty, 0, "纯随机字节不该解析出东西")

    def test_shaped_certificate_never_raise_and_reaches_the_deep_layers(self):
        """证书形状、内容随机 —— 实测非空率 65.1%，是真在解析而不是空转。"""
        rnd = random.Random(_SEED ^ 0x11)
        total = 4000 * _SCALE
        nonempty = with_date = with_cn = 0
        for _ in range(total):
            data = _shaped_cert(rnd)
            got = parse_certificate(data)
            self._check_shape(got, "形状自洽", data)
            if got:
                nonempty += 1
                with_date += 1 if got["not_after"] else 0
                with_cn += 1 if got["cn"] else 0
        # 固定种子 → 这些比例是确定的；阈值留足余量，只用来拦"解析器退化成恒空"。
        self.assertGreater(nonempty / total, 0.30,
                           "形状自洽的输入非空率过低，走查可能退化了")
        self.assertGreater(with_date, 0, "从没读到过日期 —— validity 那层没被走到")
        self.assertGreater(with_cn, 0, "从没读到过 CN —— subject 那层没被走到")

    def test_mutated_real_certificate_never_raise(self):
        """真实证书的变异 —— 实测非空率 28.4%，最容易命中"半对的"解析路径。"""
        rnd = random.Random(_SEED ^ 0x01)
        total = 4000 * _SCALE
        nonempty = 0
        for _ in range(total):
            data = FIXTURE_DER
            for _ in range(rnd.randrange(1, 4)):
                data = _mutate(rnd, data)
            got = parse_certificate(data)
            self._check_shape(got, "真实证书变异", data)
            nonempty += 1 if got else 0
        self.assertGreater(nonempty, 0,
                           "变异后一个都解不出，说明生成器把证书改废了")

    def test_fuzz_actually_exercises_the_parser(self):
        """反向验证：合法固件必须被解出全部字段。

        没有这一条，一个「任何输入都返回 `{}`」的实现也能让上面三个用例全绿。
        9 个键里 `curve` 对 RSA 证书本就是空串，所以非空的是 **8 项**。
        """
        got = parse_certificate(FIXTURE_DER)
        nonempty = [k for k in _KEYS if got.get(k)]
        self.assertEqual(len(nonempty), 8,
                         "固件只读出了 %s —— 走查退化了" % sorted(nonempty))
        self.assertEqual(got["curve"], "", "RSA 证书不该有曲线名")


if __name__ == "__main__":
    unittest.main()
