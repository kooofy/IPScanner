# -*- coding: utf-8 -*-
"""LLMNR / NBNS 响应器探测（v1.9 #3 第二刀，零利用安全体检）。

红线（先讲清楚）
----------------
本模块只做两件事：**构造一个查询**、**解析收到的应答**。
不注册名字、不应答别人的查询、不伪造 MAC/IP，**绝不向网络投毒**。
发出去的只有一个标准 DNS 格式的查询包 —— 和一台普通 Windows 机器在 DNS
解析失败时自动发出的那个东西**完全一样**，没有任何攻击性载荷。

为什么这是个真信号
------------------
LLMNR（UDP/5355，组播 `224.0.0.252`）与 NBNS（UDP/137，广播）是 DNS 之后的
**广播名字解析兜底**：名字在 DNS 里查不到时，Windows 会退到这两者。攻击者因此
可以跑一个「什么都答」的响应器（Responder 这类工具），把请求者引到自己身上，
骗取 NTLMv2 挑战响应，再离线爆破或中继。

本模块用的是这条攻击链的**零利用版本**：

    编一个**不可能存在**的名字（随机后缀），查一次，看谁给**肯定应答**。

干净网络里没有任何主机会应答 —— 名字根本不归它所有。一台主机若对一个刚编出来
的名字给出肯定应答，说明它**在应答它不拥有的名字**：要么是安全工具 / 蜜罐，
要么就是欺骗响应器。两种情况都值得让人知道。

诚实降级（这几条决定了它不会误报）
----------------------------------
- **只认肯定应答**。NBNS 的**否定**应答（RCODE=3「名字不存在」）是 WINS 服务器
  与代理的**正常行为** —— 它对每个不存在的名字都会这么答。把它算成发现，
  等于把每个网段里的 WINS 服务器都报成欺骗响应器，只记 debug。
- **应答里必须真的含我们编的那个名字**。网络里随时有**别人**的 LLMNR/NBNS
  流量在飘，只看「收到一个肯定应答」会把它们全算进来。
- **随机后缀**。固定名字迟早会有人真的注册它，那时探测就变成永久误报。
- 探测是**显式开关**（GUI 勾选框 / CLI `--name-responder`），**默认关**：
  它会在网络里产生组播 / 广播包，与「被动发现」的零发包原则冲突。

已知边界（不粉饰）
------------------
- 只覆盖**本链路**：LLMNR 组播与 NBNS 广播都不过路由器，跨网段扫不到。
- 结果只落到**本次扫描到的设备**上（见 `ScanResult.name_responder`）。
  不在扫描范围内的响应器会被写进日志，但不会进快照 —— 快照记的是台账，
  往台账里塞一台没扫到的设备会让设备数失真。
- 本机若配了多张网卡，组播走默认路由那张；其他网卡所在链路探不到。
- LLMNR 应答按 RFC 4795 §2.5 应当是**单播**回查询源端口，本模块也用临时源端口
  接收。若某个响应器固执地走组播回 5355，我们会漏掉它（实测 Windows 走单播）。
"""
import socket
import struct
import time
import uuid
from typing import Dict

from app_logging import get_logger

from .netbios import _encode_nbname

_log = get_logger(__name__)

#: LLMNR：组播地址与端口（RFC 4795 §2）
LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT = 5355

#: NBNS：广播地址与端口（RFC 1002）
NBNS_BROADCAST = "255.255.255.255"
NBNS_PORT = 137

#: 探测名前缀。刻意做成**一眼能认出**的形状：抓包里看到 `ipscanner-` 开头的
#: 名字就知道是 IPScanner 的体检探针，而不是某个真实主机名。
#:
#: ⚠ 总长必须 ≤ 15 字符 —— NetBIOS 名上限就是 15（第 16 字节是类型后缀）。
#: 两个协议共用同一个名字，所以长度受 NBNS 这一侧约束。
PROBE_PREFIX = "ipscanner-"

#: 探测名随机部分的十六进制位数（`PROBE_PREFIX` 9 字符 + 5 = 14，留 1 位余量）。
PROBE_SUFFIX_LEN = 5

#: 一次探测最多接受多少个应答。异常网络（或有人故意刷）里防止无限循环。
MAX_RESPONSES = 64

#: `recvfrom` 的单次等待。比整体 `timeout` 小得多，这样循环能及时检查总时限。
_POLL = 0.25

#: 默认探测目标：`(协议规范值, 地址, 端口)`。
#: LLMNR 走组播、NBNS 走广播 —— 两者都只在本链路内可达。
DEFAULT_TARGETS = (("llmnr", LLMNR_GROUP, LLMNR_PORT),
                   ("nbns", NBNS_BROADCAST, NBNS_PORT))


def random_probe_name() -> str:
    """生成一个**不可能存在**的探测名。

    随机后缀是刻意的：固定名字迟早会有人真的注册它，那时探测就变成永久误报。
    """
    return PROBE_PREFIX + uuid.uuid4().hex[:PROBE_SUFFIX_LEN]


def _encode_dns_name(name: str) -> bytes:
    """域名 → DNS 长度前缀标签（LLMNR 用，普通 DNS 编码）。"""
    out = b""
    for label in name.split("."):
        raw = label.encode("utf-8", "replace")[:63]
        if raw:
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _nbt_name16(name: str) -> bytes:
    """探测名 → NBT 的 16 字节名（15 字符 + 类型后缀 `0x00` = 工作站名）。"""
    return name.upper().encode("ascii", "replace")[:15].ljust(16, b" ")


def build_llmnr_query(name: str, tid: int = 0) -> bytes:
    """构造 LLMNR 名字查询（RFC 4795 §2.1，DNS 报文格式）。

    flags 全 0：LLMNR 规定 RD 位在发送时**必须为 0**，与普通 DNS 查询的
    `0x0100` 不同。QTYPE 用 ANY(255) —— 问「你叫什么」而不是「A 记录是多少」，
    更容易被「什么都答」的响应器接住。
    """
    header = struct.pack("!HHHHHH", tid & 0xFFFF, 0x0000, 1, 0, 0, 0)
    return header + _encode_dns_name(name) + struct.pack("!HH", 255, 0x0001)


def build_nbns_query(name: str, tid: int = 0) -> bytes:
    """构造 NBNS 名字查询（RFC 1002 §4.2.12）。

    与 `netbios.py` 的 NBSTAT 请求（QTYPE=`0x21`，问「你注册了哪些名字」）不同：
    这里问的是**单个名字的地址**（QTYPE=`0x20` = NB），因为我们要的正是
    「有没有人声称自己叫这个名字」。

    flags = `0x0110`：查询 + **广播位**（让响应者也广播一份，增大被我们收到的
    机会）。它只影响应答的投递方式，不改变查询语义。
    """
    enc = _encode_nbname(_nbt_name16(name))
    header = struct.pack("!HHHHHH", tid & 0xFFFF, 0x0110, 1, 0, 0, 0)
    return header + bytes([0x20]) + enc + struct.pack("!HH", 0x0020, 0x0001)


#: 协议规范值 → 查询包构造函数。新增协议（如 mDNS 名字冲突探测）在这里加一项
#: 即可，`probe_responders()` 的收发循环不用改。
_QUERY_BUILDERS = {"llmnr": build_llmnr_query, "nbns": build_nbns_query}


def _header(data) -> tuple:
    """返回 `(flags, qdcount, ancount)`；不足 12 字节返回 None。"""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        return None
    _tid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", bytes(data[:12]))
    return flags, qd, an


def is_positive_answer(data) -> bool:
    """是不是一个**肯定**的查询应答。

    QR=1（是应答）、OPCODE=0（标准查询）、RCODE=0（没有名字错误 / 格式错误）、
    ANCOUNT≥1（至少给了一条答案）。

    ⚠ **否定应答不算**（见模块 docstring）：NBNS 的 RCODE=3「名字不存在」是
    WINS 服务器 / 代理的正常行为，把它算成发现等于把每个网段里的 WINS 服务器
    都报成欺骗响应器。
    """
    got = _header(data)
    if got is None:
        return False
    flags, _qd, an = got
    if not flags & 0x8000:               # QR=0 → 是查询，不是应答
        return False
    if (flags >> 11) & 0x0F:             # OPCODE ≠ 0
        return False
    if flags & 0x000F:                   # RCODE ≠ 0（名字不存在 / 格式错误 / 拒绝…）
        return False
    return an >= 1


def _send(sock, packet, dest, label):
    """发一个探测包；失败只告警（该协议本次探测失效，但另一个协议仍可继续）。"""
    try:
        sock.sendto(packet, dest)
    except OSError as e:
        _log.warning("%s 探测包发送失败（目标 %s），该协议本次无法发现响应器: %s",
                     label, dest[0], e)


def _wire_signature(proto: str, name: str) -> bytes:
    """探测名在**报文线格式**里的样子（用于在应答里认名字，大小写不敏感）。

    两个协议的编码形状完全不同 —— LLMNR 是普通 DNS 标签、NBNS 是 32 字节
    半字节编码 —— 所以拿哪一个当签名都不会互相误判。
    """
    if proto == "llmnr":
        return name.lower().encode("utf-8")
    return _encode_nbname(_nbt_name16(name)).lower()


def probe_responders(timeout: float = 2.0, name: str = None,
                     targets=None) -> Dict[str, dict]:
    """查一次「不可能存在的名字」，返回给**肯定应答**的 `{ip: {协议: 名字}}`。

    协议名是规范值 `"llmnr"` / `"nbns"`（展示时再翻译）。`name` 可注入，
    测试用来固定探测名。`timeout` 是所有目标共用的总等待时长。
    `targets` 是 `[(协议, 地址, 端口), ...]`，默认 `DEFAULT_TARGETS`。

    ⚠ `targets` 这个注入点存在的理由与 `risk_rules.score_risk(now=...)` 一样：
    让测试能**脱离真实网络环境**跑。组播 / 广播在 CI 容器里不一定可用，
    真发包的测试会时绿时红，那比没有测试更糟。

    返回值只包含**真的应答了**的 IP —— 干净网络里应当是空 dict。
    任何异常都被兜住（输入来自网络），失败返回已经收到的部分。
    """
    name = (name or random_probe_name()).strip()
    if not name:
        return {}
    targets = tuple(targets if targets is not None else DEFAULT_TARGETS)
    signatures = {}
    for proto, _host, _port in targets:
        if proto in _QUERY_BUILDERS:
            signatures[proto] = _wire_signature(proto, name)
    if not signatures:
        return {}

    found: Dict[str, dict] = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 绑**临时端口**而不是 5355/137：那两个端口在本机常被系统解析器占着，
        # 而 LLMNR / NBNS 的应答按规范是单播回**查询源端口**的，临时端口一样收得到。
        sock.bind(("", 0))
        sock.settimeout(_POLL)

        for proto, host, port in targets:
            builder = _QUERY_BUILDERS.get(proto)
            if builder is None:
                continue
            _send(sock, builder(name), (host, port), proto.upper())

        end = time.time() + max(0.0, timeout)
        while time.time() < end and len(found) < MAX_RESPONSES:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data or not addr:
                continue
            if not is_positive_answer(data):
                continue
            low = bytes(data).lower()
            for proto, sig in signatures.items():
                if sig in low:
                    found.setdefault(addr[0], {})[proto] = name
                    break
    except Exception as e:  # noqa: BLE001
        # 整体失败：会让"网络里有欺骗响应器"这个结论缺失，属于用户能感知的
        # 结果缺失，必须留痕
        _log.warning("LLMNR/NBNS 响应器探测异常，结果可能不完整: %s", e,
                     exc_info=True)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError as e:
                _log.debug("关闭探测 socket 失败: %s", e)
    return found


def apply_responders(results, found) -> list:
    """把探测结果挂到对应设备上，返回**不在扫描范围内**的响应器 IP 列表。

    单独成函数是为了让 GUI（`ScanThread`）与 CLI 共用同一份分发逻辑 ——
    两边各写一遍迟早会不一致。

    `results` 是 `ScanResult` 列表（原地修改），`found` 是 `probe_responders()`
    的返回值。不在结果里的响应器**不伪造设备行**：快照记的是台账，塞一台没扫到
    的设备会让设备数失真。调用方负责把它们写进日志。
    """
    by_ip = {r.ip: r for r in results}
    outside = []
    for ip, protos in found.items():
        target = by_ip.get(ip)
        if target is None:
            outside.append(ip)
        else:
            target.name_responder = dict(protos)
    return sorted(outside)
