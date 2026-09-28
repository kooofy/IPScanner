# -*- coding: utf-8 -*-
"""SNMPv3 / USM（User-based Security Model）—— 纯标准库实现。

为什么需要
----------
v1/v2c 的团体字（community）是**明文**传输的，等价于把密码写在信封外面；
v3 用 USM 做用户级认证与加密，是现在唯一被推荐的部署方式。

支持范围（**明确边界，不要含糊**）
--------------------------------
- 认证：`HMAC-MD5-96`（RFC 3414）、`HMAC-SHA-96`（RFC 3414）
- 加密：`AES-128-CFB128`（RFC 3826）
- 认证/加密都不填 → `noAuthNoPriv`（仅用户名）
- ⚠️ **不支持 DES 隐私协议**（`usmDESPrivProtocol`）：标准库没有 DES，
  且该协议已废弃、现代设备默认关闭。指定 DES 会返回明确的错误而不是静默降级。

设计要点
--------
- 依赖仅为 `hashlib` / `hmac` / `os` / `struct` 与自实现的 `scanner.aes`。
- **先发现（discovery）再请求**：v3 的认证密钥要用对端权威引擎的 engineID 做本地化，
  所以必须先发一条空引擎 ID、无认证的探测报文换取 engineID/engineBoots/engineTime。
- 认证摘要按 RFC 3414：先把认证参数字段填 12 个 0 序列化整条报文，再算 HMAC 取前 12 字节，
  最后把摘要回填进该字段（**回填不重算**）。
- 引擎参数按 (ip, port) 缓存，并用本地时钟推算 engineTime（RFC 3414 §2.3）。
- 失败结果带 `error_kind`，让调用方能区分"目标根本不回话"（可安全回退 v2c）
  与"凭据/配置不对"（不该回退，回退只会掩盖问题）。
"""
import os
import hmac
import time
import struct
import hashlib
import threading
from dataclasses import dataclass

from app_logging import get_logger
from i18n import tr

from . import aes
from .snmp import (_ber_len, _snmp_enc_int, _snmp_enc_oid,
                   _snmp_read_tlv, _snmp_decode_oid)

_log = get_logger(__name__)

# ── 认证 / 加密协议标识（语言无关规范值）──
AUTH_NONE = ""
AUTH_MD5 = "md5"
AUTH_SHA = "sha"
AUTH_PROTOS = (AUTH_NONE, AUTH_MD5, AUTH_SHA)

PRIV_NONE = ""
PRIV_AES = "aes"
PRIV_DES = "des"          # 仅用于识别并给出"不支持"提示
PRIV_PROTOS = (PRIV_NONE, PRIV_AES, PRIV_DES)

# 安保级别（语言无关规范值）
LEVEL_NO_AUTH_NO_PRIV = "noAuthNoPriv"
LEVEL_AUTH_NO_PRIV = "authNoPriv"
LEVEL_AUTH_PRIV = "authPriv"
SECURITY_LEVELS = (LEVEL_NO_AUTH_NO_PRIV, LEVEL_AUTH_NO_PRIV, LEVEL_AUTH_PRIV)

# 失败类别（语言无关规范值）——调用方据此决定是否回退到 v2c
ERR_CONFIG = "config"            # 本地参数不合法，重试无意义
ERR_NO_RESPONSE = "no_response"  # 目标不响应（可安全回退 v2c）
ERR_AUTH = "auth"                # 认证/加密凭据或算法不匹配
ERR_PROTOCOL = "protocol"        # 报文畸形或响应类型非预期
ERR_REJECTED = "rejected"        # 目标用 Report PDU 明确拒绝

_HASH_BY_AUTH = {AUTH_MD5: "md5", AUTH_SHA: "sha1"}
_AUTH_PARAM_LEN = 12       # HMAC-96 → 12 字节
_AES_KEY_LEN = 16
_DES_KEY_LEN = 8

# RFC 3414 §A.2.1：Ku = H(passphrase 重复填充到 1048576 字节)
_KU_LEN = 1048576

SECURITY_MODEL_USM = 3
MSG_VERSION_V3 = 3

# msgFlags 位
_FLAG_AUTH = 0x01
_FLAG_PRIV = 0x02
_FLAG_REPORTABLE = 0x04

# PDU 标签
_PDU_GET = 0xA0
_PDU_GETNEXT = 0xA1
_PDU_RESPONSE = 0xA2
_PDU_REPORT = 0xA8

# msgMaxSize：本实现接受的最大响应报文长度（RFC 3412 要求 >= 484）
_MSG_MAX_SIZE = 65507

# USM 统计 OID → 可操作提示（Report PDU 会带回这些 OID）。
# 这里是**显示文本**，必须惰性翻译：模块顶层调用 tr() 会在 import 期
# 被冻结成当前语言（见 tests/test_i18n_lazy.py::NoImportTimeTrTest）。
def _report_hint(oid: str) -> str:
    """USM 统计 OID → 中文提示源串的当前语言译文（未知 OID 返回空串）。"""
    if oid == "1.3.6.1.6.3.15.1.1.1.0":
        return tr("不支持的安保级别（目标不接受当前的认证/加密组合）")
    if oid == "1.3.6.1.6.3.15.1.1.2.0":
        return tr("不支持的安保模型")
    if oid == "1.3.6.1.6.3.15.1.1.3.0":
        return tr("未知用户名（目标上没有该 SNMPv3 用户）")
    if oid == "1.3.6.1.6.3.15.1.1.4.0":
        return tr("未知引擎 ID（引擎参数已过期，需重新发现）")
    if oid == "1.3.6.1.6.3.15.1.1.5.0":
        return tr("认证失败：认证密码错误或认证算法不匹配")
    if oid == "1.3.6.1.6.3.15.1.1.6.0":
        return tr("解密失败：加密密码错误或加密算法不匹配")
    return ""


@dataclass
class SnmpV3User:
    """SNMPv3 USM 用户参数（口令为明文，仅存在于内存）。"""
    username: str = ""
    auth_proto: str = AUTH_NONE
    auth_key: str = ""
    priv_proto: str = PRIV_NONE
    priv_key: str = ""

    @property
    def uses_auth(self) -> bool:
        return bool(self.auth_proto)

    @property
    def uses_priv(self) -> bool:
        return bool(self.priv_proto)

    def security_level(self) -> str:
        """返回 noAuthNoPriv / authNoPriv / authPriv（语言无关值）。"""
        if self.uses_priv:
            return LEVEL_AUTH_PRIV
        if self.uses_auth:
            return LEVEL_AUTH_NO_PRIV
        return LEVEL_NO_AUTH_NO_PRIV

    def validate(self):
        """返回错误提示；合法则返回空串。"""
        if not self.username:
            return tr("SNMPv3 需要用户名")
        if self.auth_proto and self.auth_proto not in AUTH_PROTOS:
            return tr("不支持的认证协议: %s") % self.auth_proto
        if self.priv_proto and self.priv_proto not in PRIV_PROTOS:
            return tr("不支持的加密协议: %s") % self.priv_proto
        if self.priv_proto and not self.auth_proto:
            # RFC 3414：加密必须建立在认证之上（没有认证就没有完整性保护）
            return tr("加密（priv）必须同时启用认证（auth）")
        if self.auth_proto and not self.auth_key:
            return tr("启用认证时必须提供认证密码")
        if self.priv_proto and not self.priv_key:
            return tr("启用加密时必须提供加密密码")
        if self.priv_proto == PRIV_DES:
            return tr("不支持 DES 加密协议（已废弃且标准库无 DES），请改用 AES-128")
        return ""


# ── USM 密钥本地化（RFC 3414 §2.6 / A.2）──

def _password_to_key(passphrase: str, hash_name: str) -> bytes:
    """口令 → Ku：把口令重复填充到 1 MiB 再哈希（RFC 3414 §A.2.1）。"""
    raw = passphrase.encode("utf-8", "replace")
    if not raw:
        raw = b"\x00"
    reps = _KU_LEN // len(raw) + 1
    buf = (raw * reps)[:_KU_LEN]
    h = hashlib.new(hash_name)
    h.update(buf)
    return h.digest()


def localize_key(passphrase: str, engine_id: bytes, auth_proto: str) -> bytes:
    """口令 → 本地化密钥 Kul = H(Ku || engineID || Ku)（RFC 3414 §2.6）。"""
    hash_name = _HASH_BY_AUTH.get(auth_proto)
    if hash_name is None:
        raise ValueError(f"不支持的认证协议: {auth_proto}")
    ku = _password_to_key(passphrase, hash_name)
    h = hashlib.new(hash_name)
    h.update(ku)
    h.update(engine_id)
    h.update(ku)
    return h.digest()


def _hmac96(key: bytes, msg: bytes, hash_name: str) -> bytes:
    """HMAC-96：取 HMAC 输出的前 12 字节（RFC 3414 §6）。"""
    return hmac.new(key, msg, hash_name).digest()[:_AUTH_PARAM_LEN]


# ── 报文构造 / 解析 ──

def _enc_octet(data: bytes) -> bytes:
    return b"\x04" + _ber_len(len(data)) + data


def _enc_seq(body: bytes) -> bytes:
    return b"\x30" + _ber_len(len(body)) + body


def _enc_msg_flags(auth: bool, priv: bool, reportable: bool = True) -> bytes:
    """msgFlags。

    `reportable` 只对**请求**为 True —— RFC 3412 §7.1.3 规定响应类报文
    必须把 reportableFlag 置 0，否则对端会试图为响应再发 Report。
    """
    flags = (_FLAG_REPORTABLE if reportable else 0)
    flags |= _FLAG_AUTH if auth else 0
    flags |= _FLAG_PRIV if priv else 0
    return _enc_octet(bytes([flags]))


def _build_varbinds(oids) -> bytes:
    out = b""
    for oid in oids:
        vb = _snmp_enc_oid(oid) + b"\x05\x00"
        out += _enc_seq(vb)
    return _enc_seq(out)


def _build_pdu(pdu_tag: int, req_id: int, oids) -> bytes:
    body = (_snmp_enc_int(req_id) + _snmp_enc_int(0) + _snmp_enc_int(0)
            + _build_varbinds(oids))
    return bytes([pdu_tag]) + _ber_len(len(body)) + body


def _build_scoped_pdu(engine_id: bytes, context_name: str, pdu: bytes) -> bytes:
    return _enc_seq(_enc_octet(engine_id) + _enc_octet(context_name.encode()) + pdu)


def _build_usm_params(engine_id: bytes, boots: int, eng_time: int,
                      username: str, auth_params: bytes, priv_params: bytes) -> bytes:
    return _enc_seq(
        _enc_octet(engine_id)
        + _snmp_enc_int(boots)
        + _snmp_enc_int(eng_time)
        + _enc_octet(username.encode("utf-8", "replace"))
        + _enc_octet(auth_params)
        + _enc_octet(priv_params)
    )


def _build_v3_message(msg_id: int, flags: bytes, usm_params: bytes,
                      msg_data: bytes) -> bytes:
    header = _enc_seq(
        _snmp_enc_int(msg_id)
        + _snmp_enc_int(_MSG_MAX_SIZE)
        + flags
        + _snmp_enc_int(SECURITY_MODEL_USM)
    )
    return _enc_seq(
        _snmp_enc_int(MSG_VERSION_V3)
        + header
        + _enc_octet(usm_params)
        + msg_data
    )


def _find_octet_field(seq_body: bytes, index: int) -> bytes:
    """在 SEQUENCE 体里取第 index 个字段（0 基）的原始内容字节。"""
    pos = 0
    for i in range(index + 1):
        _tag, length, pos = _snmp_read_tlv(seq_body, pos)
        if i == index:
            return seq_body[pos:pos + length]
        pos += length
    return b""


# UsmSecurityParameters 的字段顺序（RFC 3414 §2.4），顺序即协议契约
_USM_FIELDS = ("engine_id", "boots", "eng_time", "username",
               "auth_params", "priv_params")


def _parse_usm_params(raw: bytes):
    """解析 UsmSecurityParameters。

    返回 (fields, auth_offset) —— 失败时 (None, None)。
    `auth_offset` 是**认证参数字段内容**在 `raw` 中的字节偏移，
    校验摘要时要在整条报文的对应位置把它清零后重算。
    """
    try:
        _tag, _length, pos = _snmp_read_tlv(raw, 0)
        fields = {}
        auth_offset = None
        for name in _USM_FIELDS:
            _tag, length, content = _snmp_read_tlv(raw, pos)
            if name == "auth_params":
                auth_offset = content
            fields[name] = raw[content:content + length]
            pos = content + length
        return {
            "engine_id": fields["engine_id"],
            "boots": int.from_bytes(fields["boots"], "big") if fields["boots"] else 0,
            "eng_time": int.from_bytes(fields["eng_time"], "big") if fields["eng_time"] else 0,
            "username": fields["username"].decode("utf-8", "replace"),
            "auth_params": fields["auth_params"],
            "priv_params": fields["priv_params"],
        }, auth_offset
    except Exception:
        return None, None


def parse_v3_message(data: bytes):
    """解析 SNMPv3 报文外层，返回 dict（失败返回 None）。

    返回 {msg_id, flags, usm, msg_data, msg_data_tag, raw, usm_offset, auth_offset}
    其中 `raw` 是整条报文的原始字节、`auth_offset` 指向认证参数字段 ——
    校验摘要时需要在原始字节上把该字段清零后重算。
    """
    try:
        _tag, _length, pos = _snmp_read_tlv(data, 0)
        # msgVersion
        _tag, length, pos = _snmp_read_tlv(data, pos)
        version = int.from_bytes(data[pos:pos + length], "big")
        pos += length
        if version != MSG_VERSION_V3:
            return None
        # headerData
        _tag, length, hdr_pos = _snmp_read_tlv(data, pos)
        hdr_body = data[hdr_pos:hdr_pos + length]
        msg_id = int.from_bytes(_find_octet_field(hdr_body, 0), "big")
        flags = _find_octet_field(hdr_body, 2)
        pos = hdr_pos + length
        # msgSecurityParameters (OCTET STRING 包着 DER 的 USM 参数)
        _tag, length, sec_pos = _snmp_read_tlv(data, pos)
        usm_raw = data[sec_pos:sec_pos + length]
        usm, auth_in_usm = _parse_usm_params(usm_raw)
        if usm is None:
            return None
        pos = sec_pos + length
        # msgData：整条 TLV（含 tag/len）与内容分开存。
        # - 明文 ScopedPDU 要用**整条 TLV**，因为 _parse_scoped_pdu 期望
        #   一个完整的 SEQUENCE；
        # - 加密时 msgData 是 OCTET STRING，要解密的是它的**内容**（密文）。
        # 早先只存内容，明文响应永远解析失败；加密路径则因为"解密结果本身
        # 就是完整 SEQUENCE"而侥幸可用，把问题掩盖了很久。
        tag, length, data_pos = _snmp_read_tlv(data, pos)
        # 认证参数在整条报文中的绝对偏移：sec_pos + (USM 内部偏移)
        return {
            "msg_id": msg_id,
            "flags": flags[0] if flags else 0,
            "usm": usm,
            "msg_data": data[pos:data_pos + length],
            "msg_data_content": data[data_pos:data_pos + length],
            "msg_data_tag": tag,
            "raw": data,
            "usm_offset": sec_pos,
            "auth_offset": (sec_pos + auth_in_usm) if auth_in_usm is not None else None,
        }
    except Exception:
        return None


def _extract_varbinds(pdu_body: bytes):
    """从 PDU 体（已跳过 tag/len）里取 varbind 列表。"""
    pos = 0
    for _ in range(3):            # request-id, error-status, error-index
        _tag, length, pos = _snmp_read_tlv(pdu_body, pos)
        pos += length
    tag, length, vbl_pos = _snmp_read_tlv(pdu_body, pos)
    vbl_end = vbl_pos + length
    results = []
    pos = vbl_pos
    while pos < vbl_end:
        _tag, length, pos = _snmp_read_tlv(pdu_body, pos)      # varbind SEQUENCE
        vb_end = pos + length
        _tag, olength, opos = _snmp_read_tlv(pdu_body, pos)
        oid = _snmp_decode_oid(pdu_body[opos:opos + olength])
        pos = opos + olength
        vtag, vlength, vpos = _snmp_read_tlv(pdu_body, pos)
        results.append((oid, pdu_body[vpos:vpos + vlength], vtag))
        pos = vb_end
    return results


def _parse_scoped_pdu(blob: bytes):
    """解析 ScopedPDU → (pdu_tag, error_status, varbinds) 或 None。"""
    try:
        _tag, _length, pos = _snmp_read_tlv(blob, 0)
        for _ in range(2):        # contextEngineID, contextName
            _tag, length, pos = _snmp_read_tlv(blob, pos)
            pos += length
        pdu_tag, pdu_len, pdu_pos = _snmp_read_tlv(blob, pos)
        pdu_body = blob[pdu_pos:pdu_pos + pdu_len]
        # error-status
        p2 = 0
        _tag, length, p2 = _snmp_read_tlv(pdu_body, p2)
        p2 += length
        _tag, length, p2 = _snmp_read_tlv(pdu_body, p2)
        err_status = int.from_bytes(pdu_body[p2:p2 + length], "big")
        return pdu_tag, err_status, _extract_varbinds(pdu_body)
    except Exception:
        return None


# ── salt：RFC 3826 要求同一密钥下 IV 不重复 ──

_SALT_COUNTER = struct.unpack(">Q", os.urandom(8))[0]
_SALT_LOCK = threading.Lock()


def _salt() -> bytes:
    """生成 8 字节 salt（RFC 3826 §3.1.2.1，单调递增即可保证不重复）。"""
    global _SALT_COUNTER
    with _SALT_LOCK:
        _SALT_COUNTER = (_SALT_COUNTER + 1) & 0xFFFFFFFFFFFFFFFF
        val = _SALT_COUNTER
    return struct.pack(">Q", val)


# ── 引擎参数发现与缓存 ──

@dataclass
class _Engine:
    engine_id: bytes
    boots: int
    time_at: float
    eng_time: int

    def current_time(self) -> int:
        """按本地时钟推算当前 engineTime（RFC 3414 §2.3）。"""
        return self.eng_time + int(time.monotonic() - self.time_at)


_ENGINE_CACHE = {}
_ENGINE_LOCK = threading.Lock()


def reset_engine_cache():
    """清空引擎参数缓存（测试用）。"""
    with _ENGINE_LOCK:
        _ENGINE_CACHE.clear()


def _discover(ip: str, port: int, timeout: float, sock):
    """发一条空引擎 ID、无认证的探测报文，换回权威引擎参数。

    返回 _Engine 或 None。RFC 3414 §4 —— 发现阶段必须用 noAuthNoPriv。
    """
    msg_id = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    pdu = _build_pdu(_PDU_GET, msg_id, ["1.3.6.1.2.1.1.1.0"])
    scoped = _build_scoped_pdu(b"", "", pdu)
    usm = _build_usm_params(b"", 0, 0, "", b"", b"")
    msg = _build_v3_message(msg_id, _enc_msg_flags(False, False), usm, scoped)

    sock.sendto(msg, (ip, port))
    try:
        data, _addr = sock.recvfrom(65535)
    except OSError:
        return None
    parsed = parse_v3_message(data)
    if not parsed:
        return None
    usm_out = parsed["usm"]
    if not usm_out["engine_id"]:
        return None
    return _Engine(engine_id=usm_out["engine_id"], boots=usm_out["boots"],
                   time_at=time.monotonic(), eng_time=usm_out["eng_time"])


def _get_engine(ip, port, timeout, sock):
    """取缓存的引擎参数；没有则发现一次。"""
    key = (ip, port)
    with _ENGINE_LOCK:
        eng = _ENGINE_CACHE.get(key)
    if eng is not None:
        return eng
    eng = _discover(ip, port, timeout, sock)
    if eng is None:
        return None
    with _ENGINE_LOCK:
        _ENGINE_CACHE[key] = eng
    return eng


# ── 单次请求 ──

def _build_request(engine, user, pdu_tag, oids, msg_id):
    """构造一条完整的（可能已加密的）v3 请求报文。

    返回 (报文, auth_key, priv_key)；未启用认证/加密时对应 key 为 None。
    """
    auth = user.uses_auth
    priv = user.uses_priv

    pdu = _build_pdu(pdu_tag, msg_id, oids)
    scoped = _build_scoped_pdu(engine.engine_id, "", pdu)

    auth_key = b""
    priv_key = b""
    if auth:
        auth_key = localize_key(user.auth_key, engine.engine_id, user.auth_proto)
    if priv:
        # RFC 3826 §3.1.2.1：AES 用 Kul 的前 16 字节
        priv_key = localize_key(user.priv_key, engine.engine_id,
                                user.auth_proto)[:_AES_KEY_LEN]

    # engineTime 只取一次：IV 与 USM 参数里的 engineTime 必须是同一个值，
    # 否则恰好跨秒时接收方按报文里的 engineTime 推出的 IV 与发送方不一致，
    # 解密就随机失败（实测会复现）。
    eng_time = engine.current_time()

    priv_params = b""
    if priv:
        priv_params = _salt()
        iv = (struct.pack(">I", engine.boots)
              + struct.pack(">I", eng_time)
              + priv_params)
        scoped = _enc_octet(aes.cfb128_encrypt(priv_key, iv, scoped))

    flags = _enc_msg_flags(auth, priv)

    if not auth:
        usm = _build_usm_params(engine.engine_id, engine.boots, eng_time,
                                user.username, b"", priv_params)
        return _build_v3_message(msg_id, flags, usm, scoped), None, priv_key or None

    # 认证：先用 12 个 0 占位序列化，算摘要，再回填（RFC 3414 §6.3.1）
    usm = _build_usm_params(engine.engine_id, engine.boots, eng_time,
                            user.username, bytes(_AUTH_PARAM_LEN), priv_params)
    msg = _build_v3_message(msg_id, flags, usm, scoped)
    digest = _hmac96(auth_key, msg, _HASH_BY_AUTH[user.auth_proto])
    usm = _build_usm_params(engine.engine_id, engine.boots, eng_time,
                            user.username, digest, priv_params)
    return _build_v3_message(msg_id, flags, usm, scoped), auth_key, priv_key or None


def _verify_digest(parsed, auth_key, user) -> bool:
    """校验响应摘要：把原始报文里的认证字段清零后重算 HMAC。"""
    off = parsed.get("auth_offset")
    if off is None or not auth_key:
        return False
    # 认证参数字段必须是 12 字节；未认证的 Report PDU 这里是空的，
    # 直接判失败，绝不能让下面的切片赋值去覆盖后面的字段
    if len(parsed["usm"]["auth_params"]) != _AUTH_PARAM_LEN:
        return False
    raw = bytearray(parsed["raw"])
    raw[off:off + _AUTH_PARAM_LEN] = bytes(_AUTH_PARAM_LEN)
    expect = _hmac96(auth_key, bytes(raw), _HASH_BY_AUTH[user.auth_proto])
    return hmac.compare_digest(expect, parsed["usm"]["auth_params"])


def _decode_response(parsed, priv_key, user):
    """把响应的 msgData 解出 varbinds；返回 (pdu_tag, error_status, varbinds)。"""
    tag = parsed["msg_data_tag"]
    if tag == 0x04:                       # OCTET STRING → 密文，需要解密
        if not priv_key:
            return None
        usm_out = parsed["usm"]
        iv = (struct.pack(">I", usm_out["boots"])
              + struct.pack(">I", usm_out["eng_time"])
              + usm_out["priv_params"])
        blob = aes.cfb128_decrypt(priv_key, iv, parsed["msg_data_content"])
    else:                                 # 明文 ScopedPDU，直接用整条 TLV
        blob = parsed["msg_data"]
    return _parse_scoped_pdu(blob)


def _report_message(varbinds):
    """把 Report PDU 的统计 OID 翻译成可操作提示，返回 (kind, message)。"""
    for oid, _vbytes, _vtag in varbinds:
        hint = _report_hint(oid)
        if hint:
            return ERR_REJECTED, tr("SNMPv3 被目标拒绝：%s") % hint
    return ERR_REJECTED, tr("SNMPv3 被目标拒绝（收到 Report PDU）")


def _request(ip, port, timeout, user, pdu_tag, oids):
    """执行一次 v3 请求，返回 (ok, payload, kind)。

    ok=True 时 payload 为 [(oid, vbytes, vtag), ...]；
    ok=False 时 payload 为错误字符串、kind 为 ERR_* 之一。
    """
    import socket as _socket
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        engine = _get_engine(ip, port, timeout, sock)
        if engine is None:
            return False, tr("SNMPv3 引擎发现失败（目标无响应或未启用 SNMP）"), ERR_NO_RESPONSE

        msg_id = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
        msg, auth_key, priv_key = _build_request(engine, user, pdu_tag, oids, msg_id)
        sock.sendto(msg, (ip, port))
        try:
            data, _addr = sock.recvfrom(65535)
        except OSError:
            return (False,
                    tr("SNMPv3 无响应（用户名/密码错误，或目标未开放 161 端口）"),
                    ERR_NO_RESPONSE)

        parsed = parse_v3_message(data)
        if not parsed:
            return False, tr("SNMPv3 响应无法解析"), ERR_PROTOCOL

        # 先解码再校验摘要：目标拒绝请求时会回一条**未认证、未加密**的
        # Report PDU（RFC 3414 §3.2 —— 它无法认证我们，自然也无法签名回包）。
        # 若先校验摘要，就只会报"认证校验失败"，把"用户名不存在"
        # "引擎 ID 未知"这些真正可操作的原因全部盖掉。
        decoded = _decode_response(parsed, priv_key, user)
        if decoded is not None and decoded[0] == _PDU_REPORT:
            kind, message = _report_message(decoded[2])
            return False, message, kind

        if user.uses_auth and not _verify_digest(parsed, auth_key, user):
            return (False,
                    tr("SNMPv3 响应认证校验失败（认证密码错误或报文被篡改）"),
                    ERR_AUTH)

        if decoded is None:
            return False, tr("SNMPv3 响应解密失败（加密密码或算法不匹配）"), ERR_AUTH
        resp_tag, err_status, varbinds = decoded

        if resp_tag != _PDU_RESPONSE:
            return False, tr("SNMPv3 收到非预期响应类型"), ERR_PROTOCOL
        if err_status:
            return False, tr("SNMPv3 目标返回错误状态 %d") % err_status, ERR_REJECTED
        return True, varbinds, ""
    except Exception as e:  # noqa: BLE001
        # 网络异常/超时都归为"本次查询失败"，但必须留痕便于排障
        _log.debug("SNMPv3 请求失败 %s: %s", ip, e)
        return False, tr("SNMPv3 请求异常: %s") % e, ERR_PROTOCOL
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception as e:  # noqa: BLE001
                _log.debug("关闭 SNMPv3 socket 失败: %s", e)


def _decode_value(vbytes, vtag) -> str:
    """按 ASN.1 类型把 varbind 值转成字符串（与 v2c 路径保持一致）。"""
    if vtag == 0x04:                                    # OCTET STRING
        return vbytes.decode("utf-8", "replace").strip()
    if vtag == 0x06:                                    # OBJECT IDENTIFIER
        return _snmp_decode_oid(vbytes)
    if vtag in (0x02, 0x41, 0x42, 0x43, 0x46):          # INTEGER / Counter / Gauge / TimeTicks
        return str(int.from_bytes(vbytes, "big"))
    if vtag == 0x40:                                    # IpAddress
        return ".".join(str(b) for b in vbytes)
    return ""


# ── 对外接口 ──

def auth_label(value: str) -> str:
    """认证协议规范值 → 当前语言显示文本（惰性翻译，只用于显示）。"""
    if value == AUTH_MD5:
        return "HMAC-MD5-96"
    if value == AUTH_SHA:
        return "HMAC-SHA-96"
    return tr("不认证")


def priv_label(value: str) -> str:
    """加密协议规范值 → 当前语言显示文本（惰性翻译，只用于显示）。"""
    if value == PRIV_AES:
        return tr("AES-128 加密")
    if value == PRIV_DES:
        return tr("DES（不支持）")
    return tr("不加密")


def snmp_v3_get_system(ip: str, user: "SnmpV3User", timeout: float = 1.5,
                       port: int = 161) -> dict:
    """SNMPv3 GET sysDescr/sysName/sysObjectID。

    成功返回 {'sys_descr','sys_name','sys_objectid','security_level'}；
    失败返回 {'error': ..., 'error_kind': ERR_*}（便于上层把原因显示给用户，
    而不是静默无结果；error_kind 还让调用方能区分"该不该回退 v2c"）。
    """
    err = user.validate()
    if err:
        return {"error": err, "error_kind": ERR_CONFIG}

    oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.2.0"]
    ok, payload, kind = _request(ip, port, timeout, user, _PDU_GET, oids)
    if not ok:
        return {"error": payload, "error_kind": kind}

    info = {"security_level": user.security_level()}
    for oid, vbytes, vtag in payload:
        txt = _decode_value(vbytes, vtag)
        if oid == "1.3.6.1.2.1.1.1.0":
            info["sys_descr"] = txt
        elif oid == "1.3.6.1.2.1.1.5.0":
            info["sys_name"] = txt
        elif oid == "1.3.6.1.2.1.1.2.0":
            info["sys_objectid"] = txt
    if info.get("sys_descr") or info.get("sys_name"):
        return info
    return {"error": tr("SNMPv3 未返回系统信息（OID 无值）"), "error_kind": ERR_PROTOCOL}


def snmp_v3_walk(ip: str, user: "SnmpV3User", base_oid: str, timeout: float = 1.5,
                 port: int = 161, max_iterations: int = 2000) -> dict:
    """SNMPv3 GETNEXT 遍历子树，返回 {oid: (value_bytes, value_tag)}。

    语义与 v2c 的 `snmp_walk` 一致，便于上层无差别使用。
    出错时返回已取到的部分结果（并记 warning 留痕），而不是丢掉全部。
    """
    err = user.validate()
    if err:
        _log.warning("SNMPv3 walk 参数不合法 %s: %s", ip, err)
        return {}

    results = {}
    current = base_oid
    prefix = base_oid.rstrip(".") + "."
    for _ in range(max_iterations):
        ok, payload, kind = _request(ip, port, timeout, user, _PDU_GETNEXT, [current])
        if not ok:
            # 与 v2c 路径一致：中断时返回已取到的部分结果，但必须留痕
            _log.warning("SNMPv3 walk 中断（已取 %d 条，%s）: %s",
                         len(results), kind, payload)
            break
        if not payload:
            break
        oid, vbytes, vtag = payload[0]
        if not oid.startswith(prefix) or vtag == 0x82:      # 出子树 / endOfMibView
            break
        results[oid] = (vbytes, vtag)
        if oid == current:                                   # 防御：防止不前进死循环
            break
        current = oid
    return results
