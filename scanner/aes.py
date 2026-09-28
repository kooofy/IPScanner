# -*- coding: utf-8 -*-
"""AES-128 分组密码 + CFB128 模式（纯标准库实现）。

为什么手写
----------
本项目坚持**零额外依赖**（`requirements.txt` 只有 PyQt5 / openpyxl / xlrd），
而 Python 标准库不含任何分组密码。SNMPv3 的 USM 隐私协议（RFC 3826）需要
AES-128-CFB128，故在此实现。

安全性说明（务必知悉）
----------------------
- 这是**教科书实现**，未做抗侧信道加固（无查表随机化、无常数时间比较）。
  它用于 SNMPv3 的链路加密，运行在可信本机、只处理自己构造的报文，
  威胁模型与"通用密码库"不同。
- 只实现 **加密方向**：CFB128 解密同样只用分组密码的正向变换，
  因此无需逆 S 盒 / 逆 MixColumns。
- S 盒**由有限域运算推导**而不是抄写 256 字节常量表 —— 抄表极易出错，
  推导则可自证（测试断言 FIPS-197 已知向量）。

参考：FIPS-197（AES）、NIST SP 800-38A（CFB 模式）、RFC 3826（SNMPv3 AES）。
"""

# ── GF(2^8) 运算（模 AES 多项式 x^8+x^4+x^3+x+1 = 0x11B）──

def _gf_mul(a: int, b: int) -> int:
    """GF(2^8) 乘法。"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a: int) -> int:
    """GF(2^8) 乘法逆元（0 的逆元定义为 0）。"""
    if a == 0:
        return 0
    for x in range(1, 256):
        if _gf_mul(a, x) == 1:
            return x
    return 0       # pragma: no cover - 数学上不可达


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> bytes:
    """按 FIPS-197 定义推导 S 盒：先取乘法逆元，再做仿射变换。"""
    out = bytearray(256)
    for a in range(256):
        b = _gf_inv(a)
        out[a] = (b ^ _rotl8(b, 1) ^ _rotl8(b, 2)
                  ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63)
    return bytes(out)


_SBOX = _build_sbox()

# 密钥扩展轮常量
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

_BLOCK = 16
_ROUNDS = 10


def _expand_key(key: bytes):
    """AES-128 密钥扩展 → 44 个 4 字节字。"""
    if len(key) != 16:
        raise ValueError(f"AES-128 需要 16 字节密钥，收到 {len(key)}")
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 4 * (_ROUNDS + 1)):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [_SBOX[b] for b in temp]         # SubWord
            temp[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return w


def _add_round_key(s, w, rnd):
    """状态按列主序 s[r + 4c] 存放；轮密钥字 w[4*rnd + c] 的第 r 字节对应 s[r + 4c]。"""
    for c in range(4):
        word = w[4 * rnd + c]
        for r in range(4):
            s[r + 4 * c] ^= word[r]


def _shift_rows(s):
    """第 r 行循环左移 r 个字节。"""
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _mix_columns(s):
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        s[4 * c] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        s[4 * c + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        s[4 * c + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        s[4 * c + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def encrypt_block(key: bytes, block: bytes) -> bytes:
    """AES-128 单分组加密（ECB 语义，供 CFB 调用）。"""
    if len(block) != _BLOCK:
        raise ValueError(f"AES 分组必须 16 字节，收到 {len(block)}")
    w = _expand_key(key)
    s = list(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, _ROUNDS):
        s = [_SBOX[b] for b in s]
        s = _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, w, rnd)
    s = [_SBOX[b] for b in s]
    s = _shift_rows(s)
    _add_round_key(s, w, _ROUNDS)
    return bytes(s)


def _cfb128_xor(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CFB128 加密变换：反馈寄存器取**密文**。

    解密**不能**复用本函数（解密反馈的是密文输入而非运算结果），
    见 `cfb128_decrypt`。
    """
    if len(iv) != _BLOCK:
        raise ValueError(f"CFB128 初始向量必须 16 字节，收到 {len(iv)}")
    out = bytearray()
    feedback = bytes(iv)
    for i in range(0, len(data), _BLOCK):
        chunk = data[i:i + _BLOCK]
        keystream = encrypt_block(key, feedback)
        enc = bytes(a ^ b for a, b in zip(chunk, keystream))
        out += enc
        # 反馈寄存器取本段密文；末段不足 16 字节时补零（仅影响已无用的寄存器）
        feedback = (enc + bytes(_BLOCK - len(enc))) if len(enc) < _BLOCK else enc
    return bytes(out)


def cfb128_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-128-CFB128 加密。"""
    return _cfb128_xor(key, iv, plaintext)


def cfb128_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-128-CFB128 解密。

    注意：标准 CFB 解密的反馈寄存器用的是**密文**，所以这里不能用
    `_cfb128_xor`（它会反馈加密结果）。解密需自己维护寄存器。
    """
    if len(iv) != _BLOCK:
        raise ValueError(f"CFB128 初始向量必须 16 字节，收到 {len(iv)}")
    out = bytearray()
    feedback = bytes(iv)
    for i in range(0, len(ciphertext), _BLOCK):
        chunk = ciphertext[i:i + _BLOCK]
        keystream = encrypt_block(key, feedback)
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        feedback = (chunk + bytes(_BLOCK - len(chunk))) if len(chunk) < _BLOCK else chunk
    return bytes(out)
