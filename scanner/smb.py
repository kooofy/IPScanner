# -*- coding: utf-8 -*-
"""SMB 方言与签名探测（v1.9 #3 第四刀，零利用安全体检）。

红线（先讲清楚）
----------------
本模块**只发 SMB2 NEGOTIATE / SMB1 NEGOTIATE 两种协商请求**，然后读回协商结果。
**绝不**发 `SESSION_SETUP`、不试任何凭据、不做一次认证尝试、不读写任何共享。
协商是 SMB 会话的**第一步且不需要任何身份** —— 它就是客户端在问"你会说哪几种
方言、签名怎么要求"。一个连凭据都没带的数据包，谈不上"利用"。

为什么这是个真信号
------------------
SMB 的两件事决定了局域网里绝大多数横向移动能不能成功：

1. **方言**。SMB1 有已被武器化的远程代码执行漏洞（EternalBlue / WannaCry），
   微软从 Windows 10 1709 起默认不再安装 SMB1。一台**仍然开着 SMB1** 的设备
   是整张网里最容易被打穿的一台。
2. **签名**。SMB 签名**未强制**时，攻击者可以把受害者的 NTLM 认证中继到这台
   服务器上，用别人的身份登录 —— 这就是"中继攻击"，也是勒索软件在局域网里
   横向扩散的常见手法。服务器上"签名已启用但未强制"等于没设。

这两条都不需要任何凭据就能问出来，所以属于"零利用"范围内性价比最高的一类。

诚实降级（这几条决定了它不会误报）
----------------------------------
- **只认干净的协商成功**。响应状态码非 0（`STATUS_NOT_SUPPORTED` 等）一律不
  下结论 —— 报"未知"好过报一个猜的。
- **SMB1 的判定要过两道**：状态码为 0 **且** `DialectIndex != 0xFFFF`。后者是
  服务器"你给的方言我一个都不支持"的正式表达；只看状态码会把"明确拒绝"读成
  "支持"。
- **签名只按"是否强制"判定**。`SIGNING_ENABLED` 与 `SIGNING_REQUIRED` 是两位：
  服务器**启用**了签名但**不强制**时，客户端仍可协商不签名 → 中继照样成立。
  所以"未强制"才是那个发现，"未启用"是它的子集。
- 拿不到响应（端口没开 / 不是 SMB / 被防火墙拦）就是**没有结论**，不是"安全"。

已知边界（不粉饰）
------------------
- 只探 **TCP/445**（SMB over Direct TCP）。不走 139（NetBIOS over TCP），
  那条路上的 SMB1 探不到。
- **我们发** 3.1.1 必需的 `SMB2_PREAUTH_INTEGRITY_CAPABILITIES` 协商上下文
  （见 `_preauth_integrity_context`），但**不解析响应里的协商上下文** ——
  所以**不报**"是否支持加密"（那要看 `SMB2_ENCRYPTION_CAPABILITIES`，本刀不做）。
- 只报事实，不下结论：阈值与分值统一在 `risk_rules` 里（仓库铁律）。
"""
import os
import socket
import struct
import uuid
from typing import Dict

from app_logging import get_logger

_log = get_logger(__name__)

#: SMB over Direct TCP 端口
SMB_PORT = 445

#: SMB2 的协议标识（SMB 1 是 `\xffSMB`）。用它区分两类响应。
_SMB2_MAGIC = b"\xfeSMB"
_SMB1_MAGIC = b"\xffSMB"

#: SMB2 头长度。请求与响应都是 64 字节。
_SMB2_HEADER_LEN = 64
#: SMB1 头长度。
_SMB1_HEADER_LEN = 32

#: 协商响应体的**固定部分**长度（MS-SMB2 §2.2.4）。
#: 所以一份合法的 SMB2 协商响应至少 64 + 64 = 128 字节。
_SMB2_NEGOTIATE_BODY_LEN = 64

#: 协商**请求**体的固定部分长度：`StructureSize` 固定填 36（MS-SMB2 §2.2.3），
#: 与方言个数、协商上下文个数都无关。方言数组与上下文列表都排在它后面。
_SMB2_NEGOTIATE_STRUCT_SIZE = 36

#: SMB2 命令码：NEGOTIATE。**只发这一个**。
_SMB2_NEGOTIATE = 0x0000

#: SMB1 命令码：NEGOTIATE。
_SMB1_NEGOTIATE = 0x72

#: SMB2 方言号 → 规范串。**语言无关**，展示时才翻译。
_DIALECTS = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}

#: 我们愿意说的方言，**从低到高**（与 Windows 客户端同一顺序）。
#: 服务器会挑它支持的最高一个，与列表顺序无关。
_OFFERED = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)

#: 保守方言列表：去掉 3.1.1。只在完整列表谈不成时兜底用（见 `probe_smb`）。
#:
#: 为什么需要兜底：**报 3.1.1 就必须同时报那个协商上下文**（下面那段），
#: 而只认到 3.0.2 的老服务器可能压根不认识协商上下文、直接报错。那时退一步
#: 用这份列表重谈一次，至少还能拿到签名与方言 —— 总好过一无所获。
_OFFERED_BASIC = _OFFERED[:-1]

#: 协商上下文的类型：preauth 完整性（MS-SMB2 §2.2.3.1.1）。
#: **只要方言列表里有 3.1.1，这个上下文就是必带的** —— 不带会被判成
#: `STATUS_INVALID_PARAMETER`（实测），整个协商直接失败。
_PREAUTH_CTX_TYPE = 0x0001

#: 哈希算法：SHA-512。Windows **只认这一个**（实测报 SHA-256 会被拒）。
_HASH_SHA512 = 0x0001

#: SHA-512 要求的盐长度（MS-SMB2 §2.2.3.1.1）。
_PREAUTH_SALT_LEN = 32

#: `SecurityMode` 的两位（MS-SMB2 §2.2.3 / §2.2.4）。
SIGNING_ENABLED = 0x01
SIGNING_REQUIRED = 0x02

#: 签名状态的规范串。**只按"是否强制"分档**（见模块 docstring 的诚实降级）。
SIGNING_REQUIRED_TEXT = "required"
SIGNING_ENABLED_TEXT = "enabled"
SIGNING_OFF_TEXT = "off"

#: SMB1 的方言号（`NT LM 0.12` 在协商响应里回的是 `DialectIndex`，不是这个表）。
SMB1_DIALECT = "1"

#: 单次读取的上限，防止对端声称一个巨大的长度把内存吃掉。
_MAX_READ = 1 << 20


def _recv_exact(sock, count: int):
    """从 socket 精确读 `count` 字节；对端提前关闭时返回 `None`。"""
    chunks = []
    got = 0
    while got < count:
        chunk = sock.recv(count - got)
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _read_message(sock):
    """读一条 Direct TCP 传输的 SMB 消息。

    TCP/445 上每条消息前面有 4 字节的传输头（1 字节类型 + 3 字节**大端**长度），
    少了它服务器根本不会理你 —— 这是最容易漏的一步。
    """
    head = _recv_exact(sock, 4)
    if not head or head[0] != 0x00:
        return None
    length = int.from_bytes(head[1:4], "big")
    if not 0 < length <= _MAX_READ:
        return None
    return _recv_exact(sock, length)


def _frame(payload: bytes) -> bytes:
    """给 SMB 消息加 4 字节 Direct TCP 传输头。"""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command: int, message_id: int = 0, credit: int = 1,
                 flags: int = 0) -> bytes:
    """构造 64 字节的 SMB2 头（MS-SMB2 §2.2.1）。

    ⚠ 偏移 32..35 在 SMB 2.0.2 里是 `ProcessId`、在 2.1+ 里是保留字段
    （规范要求为 0）。这里按参考实现的惯例填 `0xFEFF`：它对两者都合法，
    而在只支持 SMB 2.0.2 的老设备上填 0 反而可能被拒。协商阶段这个字段
    不参与任何判定。
    """
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        _SMB2_MAGIC,       # ProtocolId
        _SMB2_HEADER_LEN,  # StructureSize
        0,                 # CreditCharge
        0,                 # Status / ChannelSequence
        command,           # Command
        credit,            # CreditRequest
        flags,             # Flags
        0,                 # NextCommand
        message_id,        # MessageId
        0x0000FEFF,        # ProcessId（见上）
        0,                 # TreeId
        0,                 # SessionId
        b"\x00" * 16,      # Signature
    )


def _preauth_integrity_context(salt: bytes = None) -> bytes:
    """构造 `SMB2_PREAUTH_INTEGRITY_CAPABILITIES` 协商上下文（MS-SMB2 §2.2.3.1.1）。

    字段顺序：`ContextType` / `DataLength` / `Reserved` 8 字节头，然后是
    `HashAlgorithmCount` / `SaltLength` / `HashAlgorithms` / `Salt`。

    ⚠ `DataLength` 只算 `Data` 部分（不含那 8 字节头）—— 写大了写小了都会被拒。
    """
    if salt is None:
        salt = os.urandom(_PREAUTH_SALT_LEN)
    data = struct.pack("<HH", 1, len(salt))
    data += struct.pack("<H", _HASH_SHA512) + salt
    return struct.pack("<HHI", _PREAUTH_CTX_TYPE, len(data), 0) + data


def build_smb2_negotiate(client_guid: bytes = None, smb311: bool = True) -> bytes:
    """构造 SMB2 NEGOTIATE 请求（MS-SMB2 §2.2.3）。

    `SecurityMode` 填 `SIGNING_ENABLED`：表示"我支持签名"，**不是**要求签名 ——
    我们本来就不认证，这个位只影响服务器对后续会话的期望。

    ⚠⚠ **字段顺序是本节最容易搞反的一处**。规范里 `Dialects` 在**前**、
    `NegotiateContextList` 在**后**，中间夹一段填充把上下文顶到 8 字节边界：

        固定体(36) → Dialects → Padding → NegotiateContextList

    把上下文写到方言前面会被判 `STATUS_INVALID_PARAMETER`，而且**整个协商失败**
    （实测：状态码 `0xC000000D`，连签名都读不到）。填充不是"可选的美化"，
    它决定了 `NegotiateContextOffset` 能不能落在 8 字节边界上。

    `smb311=False` 时不报 3.1.1、不带上下文 —— 老服务器认不得上下文时用它兜底
    （见 `_OFFERED_BASIC`）。
    """
    if client_guid is None:
        client_guid = uuid.uuid4().bytes
    dialects = _OFFERED if smb311 else _OFFERED_BASIC
    dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)

    body = struct.pack(
        "<HHHH", _SMB2_NEGOTIATE_STRUCT_SIZE, len(dialects), SIGNING_ENABLED, 0
    ) + struct.pack("<I", 0) + client_guid

    if not smb311:
        # 方言里没有 3.1.1，这 8 字节就得按 ClientStartTime 解读，规范要求填 0。
        return _smb2_header(_SMB2_NEGOTIATE) + body + struct.pack("<Q", 0) + dialect_bytes

    after_dialects = (_SMB2_HEADER_LEN + _SMB2_NEGOTIATE_STRUCT_SIZE
                      + len(dialect_bytes))
    pad = (-after_dialects) % 8          # 把上下文顶到 8 字节边界
    body += struct.pack("<IHH", after_dialects + pad, 1, 0)
    return (_smb2_header(_SMB2_NEGOTIATE) + body + dialect_bytes
            + b"\x00" * pad + _preauth_integrity_context())


def build_smb1_negotiate() -> bytes:
    """构造 SMB1 NEGOTIATE 请求，只带一个方言 `NT LM 0.12`。

    刻意**只**带这一个：我们要问的正是"你还说不说 SMB1"，带上 SMB2 方言会让
    服务器改用 SMB2 回答，反而问不出来。
    """
    dialect = b"NT LM 0.12"
    buf = b"\x02" + dialect + b"\x00"
    header = struct.pack(
        "<4sBIBHH8sHHHHH",
        _SMB1_MAGIC,  # Protocol
        _SMB1_NEGOTIATE,   # Command
        0,            # Status
        0x18,         # Flags: CASELESS | CANONICALIZED_PATHS
        0xC853,       # Flags2: UNICODE | NT_STATUS | EXTENDED_SECURITY …
        0,            # PIDHigh
        b"\x00" * 8,  # Signature
        0, 0, 0, 0, 0,   # Reserved / TID / PID / UID / MID
    )
    return header + struct.pack("<BH", 0, len(buf)) + buf


def parse_smb2_negotiate_response(data) -> Dict:
    """解析 SMB2 NEGOTIATE 响应，返回 `{"dialect":…, "signing":…}`。

    `dialect` 是规范串（`"3.1.1"` 等）；认不出的方言号返回**十六进制串**
    （`"0x02ff"`）而不是猜一个名字 —— 宁可显示得丑一点，也不能把没见过的
    东西叫成见过的。`signing` 取 `required` / `enabled` / `off`。

    结构不符、状态码非 0、长度不够一律返回 `{}`（**绝不抛异常**：输入来自网络）。
    """
    if not isinstance(data, (bytes, bytearray)):
        return {}
    data = bytes(data)
    if len(data) < _SMB2_HEADER_LEN + _SMB2_NEGOTIATE_BODY_LEN:
        return {}
    if data[:4] != _SMB2_MAGIC:
        return {}
    status = struct.unpack_from("<I", data, 8)[0]
    if status != 0:
        # 失败响应只该被记 debug：它是"问不出来"，不是"不安全"
        _log.debug("SMB2 协商失败，状态码 0x%08X", status)
        return {}
    command = struct.unpack_from("<H", data, 12)[0]
    if command != _SMB2_NEGOTIATE:
        return {}
    body = _SMB2_HEADER_LEN
    struct_size = struct.unpack_from("<H", data, body)[0]
    if struct_size != 65:
        # 协商响应的 StructureSize 固定是 65；不是就说明这不是协商响应
        return {}
    mode = struct.unpack_from("<H", data, body + 2)[0]
    revision = struct.unpack_from("<H", data, body + 4)[0]
    return {
        "dialect": _DIALECTS.get(revision, "0x%04x" % revision),
        "signing": _signing_text(mode),
    }


def _signing_text(mode: int) -> str:
    """`SecurityMode` → 签名状态规范串（**只按是否强制分档**）。"""
    if mode & SIGNING_REQUIRED:
        return SIGNING_REQUIRED_TEXT
    if mode & SIGNING_ENABLED:
        return SIGNING_ENABLED_TEXT
    return SIGNING_OFF_TEXT


def parse_smb1_negotiate_response(data) -> bool:
    """SMB1 NEGOTIATE 响应是否**真的**选中了 `NT LM 0.12`。

    两道都要过（见模块 docstring）：状态码为 0 **且** `DialectIndex != 0xFFFF`。
    后者是"你给的方言我一个都不支持"的正式表达 —— 只看状态码会把明确拒绝
    读成"支持 SMB1"，那正是最坏的一种误报（把安全的主机报成高危）。
    """
    if not isinstance(data, (bytes, bytearray)):
        return False
    data = bytes(data)
    if len(data) < _SMB1_HEADER_LEN + 3:
        return False
    if data[:4] != _SMB1_MAGIC:
        return False
    if struct.unpack_from("<I", data, 5)[0] != 0:
        return False
    if data[_SMB1_HEADER_LEN] != 0x11:
        # NEGOTIATE 响应固定 WordCount=17（0x11）；不是就别硬读参数
        return False
    index = struct.unpack_from("<H", data, _SMB1_HEADER_LEN + 1)[0]
    return index != 0xFFFF


def _negotiate(ip: str, port: int, request: bytes, timeout: float):
    """连上去、发一个协商请求、读一条响应；任何失败都返回 `None`。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_frame(request))
            return _read_message(sock)
    except Exception as e:      # noqa: BLE001
        # 端口没开 / 不是 SMB / 被拦 —— 都属于"问不出来"，不是错误结论
        _log.debug("SMB 协商请求失败 %s:%d: %s", ip, port, e)
        return None


def probe_smb(ip: str, port: int = SMB_PORT, timeout: float = 1.5) -> Dict:
    """探一台主机的 SMB 方言与签名要求，返回事实 dict。

    返回的键（拿不到就不给这个键 —— 消费方不该把"没探到"当成"探到了但为空"）：

    - `dialect`：协商出来的方言规范串（`"1"` / `"2.1"` / `"3.1.1"` …）；
    - `signing`：`"required"` / `"enabled"` / `"off"`；
    - `smb1`：`"1"` 表示**这台主机还支持 SMB1**（此时上面两条可能来自 SMB2，
      所以它是一条独立事实，不能只看 `dialect == "1"`）。

    ⚠ 这是**新探测**（新开 TCP 连接 + 发一个协商包），但与 `tls_cert` 同属
    "对已经确认开放的服务做一次握手"，不是 LLMNR/NBNS 那种主动往网段里发
    组播/广播 —— 所以它跟着既有的 445 探测一起跑，不需要单独的开关。
    """
    facts: Dict = {}

    response = _negotiate(ip, port, build_smb2_negotiate(), timeout)
    parsed = parse_smb2_negotiate_response(response)
    if not parsed and response is not None and response[:4] != _SMB1_MAGIC:
        # 连上了、回的也是 SMB2 形状，但谈不成 —— 很可能对面是只认到 3.0.2 的
        # 老服务器，不认识我们带的协商上下文。退一步用保守方言列表再谈一次：
        # 拿得到签名与方言，总好过整条探测一无所获。
        response = _negotiate(ip, port, build_smb2_negotiate(smb311=False), timeout)
        parsed = parse_smb2_negotiate_response(response)

    if response is None:
        return facts

    if response[:4] == _SMB1_MAGIC:
        # 服务器只认 SMB1：它对 SMB2 协商回的是 SMB1 协商响应，让客户端降级。
        facts["dialect"] = SMB1_DIALECT
        facts["smb1"] = "1"
        return facts

    if not parsed:
        return facts
    facts.update(parsed)

    # SMB2 谈成了，说明这条连接已经进入 SMB2 模式 —— SMB1 要另开一条连接问。
    # 只在 SMB2 谈成时才多问一次：服务器只认 SMB1 的情况上面已经报过了。
    smb1_response = _negotiate(ip, port, build_smb1_negotiate(), timeout)
    if parse_smb1_negotiate_response(smb1_response):
        facts["smb1"] = "1"
    return facts
