# -*- coding: utf-8 -*-
"""极简 X.509 证书走查（纯标准库，零第三方依赖）。

为什么需要它
------------
`ssl.SSLSocket.getpeercert()` **只在验证通过时**才返回解析好的字典。本项目为了
能连上自签名 / 已过期的证书（局域网设备管理面几乎全是自签名），握手时用的是
`verify_mode = CERT_NONE` —— 此时它返回的是**空 dict**（不是 None，也不报错）。

`scanner/http.py` 原先就在这里读 `cert["subject"]` 取 CN，因此那几行**从未执行过**
（`tests/test_x509.py::HttpBannerTest` 守着这个回归）。

要拿到证书内容只剩一条路：`getpeercert(binary_form=True)` 拿 DER 自己解。而
`cryptography` 未安装，项目身份是**零第三方依赖**，不能为这一项引进来；
`SSLContext.set_verify(CERT_NONE, cb)` 那个老办法在 Python 3.13 已被移除。

于是手写最小走查 —— 只取安全体检要用的几项，**不做完整 X.509 实现**。
结构是规整的（RFC 5280 §4.1），按顺序跳过前几项就能定位到需要的字段：

    Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    TBSCertificate  ::= SEQUENCE {
        version         [0] EXPLICIT INTEGER DEFAULT v1,   -- 通常存在
        serialNumber        INTEGER,
        signature           AlgorithmIdentifier,
        issuer              Name,
        validity            Validity,          -- SEQ{ notBefore, notAfter }
        subject             Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        ... 可选扩展 }

**不验签、不验链、不做信任判断** —— 这里只负责"读事实"。信任与否是调用方的事。
输入来自网络，一律当成垃圾处理：结构不符就返回 `{}`，**绝不抛异常**。
"""
import datetime

# ── DER 标签 ───────────────────────────────────────────────────────────

_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OID = 0x06
_TAG_UTF8 = 0x0C
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_PRINTABLE = 0x13
_TAG_T61 = 0x14
_TAG_IA5 = 0x16
_TAG_UTC_TIME = 0x17
_TAG_GEN_TIME = 0x18
_TAG_BMP = 0x1E
_TAG_CONTEXT0 = 0xA0

#: 证书本身不该超过这个大小（真实证书 1–3 KB，链也不会到 1 MiB）。
#: 超过就判为垃圾 —— 输入来自网络，给走查一个上界。
_MAX_DER = 1 << 20

#: 签名算法 OID → 规范代码。**未知 OID 原样返回点分十进制**，这样"弱算法"
#: 判断可以只对认识的算法下结论（不认识就沉默，宁可漏报不可误报）。
_SIG_ALGORITHMS = {
    "1.2.840.113549.1.1.4": "md5_rsa",
    "1.2.840.113549.1.1.5": "sha1_rsa",
    "1.2.840.113549.1.1.10": "rsassa_pss",
    "1.2.840.113549.1.1.11": "sha256_rsa",
    "1.2.840.113549.1.1.12": "sha384_rsa",
    "1.2.840.113549.1.1.13": "sha512_rsa",
    "1.2.840.113549.1.1.14": "sha224_rsa",
    "1.2.840.10040.4.3": "sha1_dsa",
    "2.16.840.1.101.3.4.3.2": "sha256_dsa",
    "1.2.840.10045.4.1": "sha1_ecdsa",
    "1.2.840.10045.4.3.1": "sha224_ecdsa",
    "1.2.840.10045.4.3.2": "sha256_ecdsa",
    "1.2.840.10045.4.3.3": "sha384_ecdsa",
    "1.2.840.10045.4.3.4": "sha512_ecdsa",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}

#: 公钥算法 OID → 规范代码
_KEY_ALGORITHMS = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.1.10": "rsa",
    "1.2.840.10045.2.1": "ec",
    "1.2.840.10040.4.1": "dsa",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}

#: 椭圆曲线 OID → (名字, 位数)
_EC_CURVES = {
    "1.2.840.10045.3.1.1": ("secp192r1", 192),
    "1.3.132.0.33": ("secp224r1", 224),
    "1.2.840.10045.3.1.7": ("prime256v1", 256),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
}

#: commonName 的 OID（RFC 5280 附录 A.1）
_OID_COMMON_NAME = "2.5.4.3"

#: 名字里可以装字符串的标签（T61String 是 80 年代的老编码，按 latin-1 兜底）
_TEXT_TAGS = (_TAG_UTF8, _TAG_PRINTABLE, _TAG_IA5, _TAG_T61, _TAG_BMP)


# ── DER 原语 ───────────────────────────────────────────────────────────

def _read_tlv(buf, i, end):
    """读一个 TLV，返回 `(tag, 内容起点, 内容长度, 下一个 TLV 的起点)`。

    不合法（越界 / 不定长 / 非最小长度编码 / 高 tag 号）返回 None。
    DER 比 BER 严：不定长与冗余长度都是非法的，这里直接拒掉 —— 越早拒掉，
    后面所有下标运算就越安全。
    """
    if i < 0 or i + 2 > end:
        return None
    tag = buf[i]
    if tag & 0x1F == 0x1F:              # 高 tag 号：本模块用不到
        return None
    j = i + 1
    first = buf[j]
    j += 1
    if first == 0x80:                   # 不定长：DER 不允许
        return None
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or j + n > end:
            return None
        length = int.from_bytes(buf[j:j + n], "big")
        j += n
        if length < 0x80:               # 该用短形式却用了长形式：DER 不允许
            return None
    else:
        length = first
    stop = j + length
    if stop > end:
        return None
    return tag, j, length, stop


def _iter_tlvs(buf, start, end):
    """把 [start, end) 切成若干 TLV，逐个 yield `(tag, 内容起点, 内容长度)`。

    遇到不合法的 TLV **就此打住**（而不是抛异常）—— 半截数据只能拿到半截事实。
    """
    i = start
    while i < end:
        got = _read_tlv(buf, i, end)
        if got is None:
            return
        tag, cstart, clen, nxt = got
        yield tag, cstart, clen
        i = nxt


def _oid_to_str(raw) -> str:
    """DER 编码的 OID → 点分十进制字符串。空 / 畸形返回空串。"""
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    started = False
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
            started = False
    if started:                          # 最后一节没结束符 → 畸形
        return ""
    return ".".join(parts)


def _decode_text(tag, raw) -> str:
    """按标签解出一个字符串。解不出就返回空串（不抛异常）。"""
    if tag == _TAG_BMP:
        try:
            return raw.decode("utf-16-be", errors="replace").strip()
        except Exception:                # noqa: BLE001 - 输入不可信，解不出就是空
            return ""
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return ""


def _parse_time(tag, raw) -> str:
    """UTCTime / GeneralizedTime → `YYYY-MM-DDTHH:MM:SS`（规范值，不做本地化）。

    ⚠ UTCTime 的两位年是 **RFC 5280 §4.1.2.5.1** 的规则（50–99 → 19xx，
    00–49 → 20xx），**不是** `strptime("%y")` 的 POSIX 规则（69–99 → 19xx）——
    两者在 50–68 这段不一样，用 `%y` 会把 2055 年读成 1955 年。
    """
    if tag not in (_TAG_UTC_TIME, _TAG_GEN_TIME):
        return ""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return ""
    if not text.endswith("Z"):           # RFC 5280 强制 Z、强制带秒
        return ""
    body = text[:-1]
    if tag == _TAG_UTC_TIME:
        if len(body) != 12 or not body.isdigit():
            return ""
        yy = int(body[:2])
        body = "%04d%s" % (1900 + yy if yy >= 50 else 2000 + yy, body[2:])
    elif len(body) != 14 or not body.isdigit():
        return ""
    try:
        dt = datetime.datetime.strptime(body, "%Y%m%d%H%M%S")
    except ValueError:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _alg_oid(buf, node) -> str:
    """从 AlgorithmIdentifier（`SEQ{ OID, 参数? }`）里取 OID 的点分十进制串。"""
    _, start, length = node
    for tag, cstart, clen in _iter_tlvs(buf, start, start + length):
        if tag == _TAG_OID:
            return _oid_to_str(buf[cstart:cstart + clen])
        break                            # 第一个孩子不是 OID → 不是合法 algid
    return ""


def _alg_param_oid(buf, node) -> str:
    """取 AlgorithmIdentifier 的**参数**（第二个孩子）若是 OID 则返回它。"""
    _, start, length = node
    kids = list(_iter_tlvs(buf, start, start + length))
    if len(kids) >= 2 and kids[1][0] == _TAG_OID:
        s, ln = kids[1][1], kids[1][2]
        return _oid_to_str(buf[s:s + ln])
    return ""


def _first_cn(buf, node) -> str:
    """从 Name（RDNSequence）里取第一个 commonName。

    Name ::= SEQUENCE OF RelativeDistinguishedName
    RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
    """
    _, start, length = node
    for tag, s, ln in _iter_tlvs(buf, start, start + length):
        if tag != _TAG_SET:
            continue
        for tag2, s2, ln2 in _iter_tlvs(buf, s, s + ln):
            if tag2 != _TAG_SEQUENCE:
                continue
            pair = list(_iter_tlvs(buf, s2, s2 + ln2))
            if len(pair) != 2 or pair[0][0] != _TAG_OID:
                continue
            os_, ol = pair[0][1], pair[0][2]
            if _oid_to_str(buf[os_:os_ + ol]) != _OID_COMMON_NAME:
                continue
            vt, vs, vl = pair[1]
            if vt not in _TEXT_TAGS:
                continue
            text = _decode_text(vt, buf[vs:vs + vl])
            if text:
                return text
    return ""


def _spki(buf, node):
    """从 SubjectPublicKeyInfo 取 `(算法代码, 位数, 曲线名)`。

    SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    RSA 的位宽要从模数 INTEGER 现算；EC 的位宽来自曲线 OID。
    """
    _, start, length = node
    kids = list(_iter_tlvs(buf, start, start + length))
    if len(kids) < 2 or kids[0][0] != _TAG_SEQUENCE:
        return "", 0, ""
    key_alg = _KEY_ALGORITHMS.get(_alg_oid(buf, kids[0]), "")
    curve = ""
    bits = 0
    if key_alg == "ec":
        curve, bits = _EC_CURVES.get(_alg_param_oid(buf, kids[0]), ("", 0))
    elif key_alg in ("ed25519", "ed448"):
        bits = 255 if key_alg == "ed25519" else 448
    if kids[1][0] != _TAG_BIT_STRING:
        return key_alg, bits, curve
    bs, bl = kids[1][1], kids[1][2]
    if bl < 2:
        return key_alg, bits, curve
    # BIT STRING 内容首字节是"未用位数"，其后才是真正的公钥。
    # ⚠ RSA 的公钥还多包一层：BIT STRING → `SEQ{ modulus INTEGER, exponent INTEGER }`，
    # 模数不是 BIT STRING 的第一个孩子 —— 少走这一层就会得到 0 位（实测踩过）。
    inner = bs + 1
    if key_alg == "rsa":
        wrapped = list(_iter_tlvs(buf, inner, bs + bl))
        if wrapped and wrapped[0][0] == _TAG_SEQUENCE:
            _, is_, il = wrapped[0]
            mod = list(_iter_tlvs(buf, is_, is_ + il))
            if mod and mod[0][0] == _TAG_INTEGER:
                s, ln = mod[0][1], mod[0][2]
                bits = int.from_bytes(buf[s:s + ln], "big").bit_length()
    elif not bits:
        bits = (bl - 1) * 8 - buf[bs]
    return key_alg, bits, curve


# ── 对外接口 ───────────────────────────────────────────────────────────

def parse_certificate(der) -> dict:
    """从 DER 证书里取出安全体检要用的事实。

    返回值**键固定**（取不到就是 `""` / `0` / `False`），且**全部是语言无关的
    规范值**（仓库铁律：存储与比较用规范值，展示时才 `tr()`）：

    ==================  ==============================================
    ``cn``              subject 的 commonName
    ``issuer_cn``       issuer 的 commonName
    ``not_before``      ``YYYY-MM-DDTHH:MM:SS``（UTC）
    ``not_after``       同上
    ``self_signed``     **启发式**：issuer 与 subject 的 DER 完全相同
    ``sig_alg``         规范代码（如 ``sha256_rsa``）；不认识的 OID 给点分十进制
    ``key_alg``         规范代码（``rsa`` / ``ec`` / ``dsa`` / ``ed25519`` …）
    ``key_bits``        公钥位数，取不到为 0
    ``curve``           EC 曲线名（非 EC 为空串）
    ==================  ==============================================

    ⚠ ``self_signed`` **不验签** —— 只比 issuer 与 subject。真自签名要验签，
    那需要密码学库（本项目零第三方依赖）。对本用途够用：局域网设备管理面的
    自签名证书 issuer 与 subject 一定相同。

    输入不是合法证书时返回 `{}`，**绝不抛异常**。
    """
    if not isinstance(der, (bytes, bytearray)):
        return {}
    if not 32 <= len(der) <= _MAX_DER:
        return {}
    buf = bytes(der)
    top = _read_tlv(buf, 0, len(buf))
    if top is None or top[0] != _TAG_SEQUENCE:
        return {}
    outer = list(_iter_tlvs(buf, top[1], top[1] + top[2]))
    if len(outer) < 3 or outer[0][0] != _TAG_SEQUENCE:
        return {}

    tbs = outer[0]
    fields = list(_iter_tlvs(buf, tbs[1], tbs[1] + tbs[2]))
    # 可选 [0] 版本号（v1 证书没有）
    idx = 1 if fields and fields[0][0] == _TAG_CONTEXT0 else 0
    # serial / signature / issuer / validity / subject / spki
    if len(fields) < idx + 6:
        return {}
    issuer = fields[idx + 2]
    validity = fields[idx + 3]
    subject = fields[idx + 4]
    spki = fields[idx + 5]
    if issuer[0] != _TAG_SEQUENCE or subject[0] != _TAG_SEQUENCE:
        return {}
    if validity[0] != _TAG_SEQUENCE:
        return {}

    times = list(_iter_tlvs(buf, validity[1], validity[1] + validity[2]))
    not_before = not_after = ""
    if len(times) >= 1:
        not_before = _parse_time(times[0][0], buf[times[0][1]:times[0][1] + times[0][2]])
    if len(times) >= 2:
        not_after = _parse_time(times[1][0], buf[times[1][1]:times[1][1] + times[1][2]])

    issuer_der = buf[issuer[1]:issuer[1] + issuer[2]]
    subject_der = buf[subject[1]:subject[1] + subject[2]]

    key_alg, key_bits, curve = ("", 0, "")
    if spki[0] == _TAG_SEQUENCE:
        key_alg, key_bits, curve = _spki(buf, spki)

    # 签名算法取**外层**第 2 个元素：RFC 5280 要求它与 TBS 里的那个一致，
    # 但外层那份才是"这份证书实际用的算法"，更可靠。
    sig_oid = _alg_oid(buf, outer[1]) if outer[1][0] == _TAG_SEQUENCE else ""

    return {
        "cn": _first_cn(buf, subject),
        "issuer_cn": _first_cn(buf, issuer),
        "not_before": not_before,
        "not_after": not_after,
        "self_signed": issuer_der == subject_der,
        "sig_alg": _SIG_ALGORITHMS.get(sig_oid, sig_oid),
        "key_alg": key_alg,
        "key_bits": key_bits,
        "curve": curve,
    }


# ── 判定 ───────────────────────────────────────────────────────────────

#: 签名算法里出现这些子串就判为弱（MD5 / SHA-1）
WEAK_SIG_MARKERS = ("md5", "sha1")

#: RSA 位数低于它判为弱（NIST SP 800-57：2048 是当前下限）
MIN_RSA_BITS = 2048

#: EC 位数低于它判为弱
MIN_EC_BITS = 224


def is_weak_signature(sig_alg: str) -> bool:
    """签名算法是否已过时（MD5 / SHA-1）。

    只对**认识**的算法下结论：不认识的 OID（点分十进制形式）返回 False ——
    宁可漏报，不可误报。

    ⚠ 已知局限：`rsassa_pss` 的哈希写在参数里，本模块不解析参数，因此
    "PSS + SHA-1" 这种情况会漏掉。设备证书里 PSS 极少见，先不为此加一层走查。
    """
    if not sig_alg or ("." in sig_alg and sig_alg[0].isdigit()):
        return False                     # 未知 OID
    return any(marker in sig_alg for marker in WEAK_SIG_MARKERS)


def is_weak_key(key_alg: str, key_bits: int) -> bool:
    """公钥是否过短。位数取不到（0）时不下结论。"""
    if not key_bits:
        return False
    if key_alg == "rsa":
        return key_bits < MIN_RSA_BITS
    if key_alg == "ec":
        return key_bits < MIN_EC_BITS
    if key_alg == "dsa":
        return key_bits < MIN_RSA_BITS
    return False


def days_until(not_after: str, now=None):
    """距 `not_after` 还有几天（负数 = 已过期）。解析不出返回 None。

    `now` 可注入（测试用），默认取当前 UTC 时间。**只做日期差**，不引入时区。

    ⚠ 必须是 **UTC**：证书里的时间是 UTC，拿本地时间比会在时区偏移处差一天。
    这里用 `timezone.utc` 再摘掉 tzinfo（与 `not_after` 解析出的裸 datetime
    对齐），刻意**不用** `utcnow()` —— 它在 3.12 起已标记弃用。
    """
    if not not_after:
        return None
    try:
        expiry = datetime.datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return None
    current = now or datetime.datetime.now(
        datetime.timezone.utc).replace(tzinfo=None)
    return (expiry - current).days
