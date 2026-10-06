# -*- coding: utf-8 -*-
"""内网高频服务的 banner 探测（P2-2）。

与 ``http.py`` 的分工
---------------------
``http.py`` 负责 HTTP/HTTPS/FTP/SSH 这几条"带应用层交互"的探测（发 GET、
发 SSL 握手、读欢迎行）。本模块补齐**其余内网高频服务**的探测，并把结果交给
``service_fingerprints`` 指纹库解析出产品与版本：

    Telnet / SMTP / POP3 / IMAP / VNC / MySQL·MariaDB /
    Redis / PostgreSQL / MongoDB / RDP

设计约束
--------
1. **只做无凭据识别。** 不发任何需要认证的请求；拿不到版本号时只识别服务，
   绝不尝试登录（那会把"扫描"变成"入侵"）。
2. **绝不抛异常。** 每个探测失败都返回空串 —— 目标端口开放但服务不按预期
   应答是常态（蜜罐、代理、非标服务），不能让单台设备把富化流水线带崩。
3. **超时极短。** 这些探测都发生在 enrich 阶段、且只在端口确实开放时才调用，
   超时统一由调用方按 RTT 自适应给出，这里只设上限兜底。
"""
import socket
import struct

# Telnet 的 IAC 协商字节（0xFF 开头）会混进欢迎文本，先剔除再交给指纹库。
_IAC = 0xFF


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """尽量读满 n 字节（对端提前关闭时返回已读到的部分）。"""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _sanitize(text: str) -> str:
    """去掉控制字符（保留可读文本），避免二进制噪声污染指纹匹配与展示。"""
    return "".join(ch if (ch.isprintable() or ch == " ") else " " for ch in text).strip()


def _connect(ip: str, port: int, timeout: float):
    sock = socket.create_connection((ip, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def read_greeting(ip: str, port: int, timeout: float = 1.0) -> str:
    """读取"连上就主动报欢迎语"的服务的 banner（SMTP / POP3 / IMAP / Telnet）。"""
    try:
        with _connect(ip, port, timeout) as sock:
            data = sock.recv(512)
        return _sanitize(data.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return ""


def read_vnc_banner(ip: str, port: int = 5900, timeout: float = 1.0) -> str:
    """VNC 服务端在连接建立后立即发送 ``RFB 003.008\\n`` 版本行。"""
    try:
        with _connect(ip, port, timeout) as sock:
            data = sock.recv(64)
        return _sanitize(data.decode("ascii", "replace"))
    except Exception:  # noqa: BLE001
        return ""


def read_mysql_banner(ip: str, port: int = 3306, timeout: float = 1.0) -> str:
    """MySQL / MariaDB 握手包中的服务端版本串。

    包格式：3 字节长度(LE) + 1 字节序号 + 1 字节协议版本(0x0a) + NUL 结尾版本串。
    MariaDB 的版本串形如 ``5.5.5-10.6.4-MariaDB``（前导 5.5.5 是为兼容老客户端）。
    """
    try:
        with _connect(ip, port, timeout) as sock:
            data = sock.recv(128)
        if len(data) < 6 or data[4] != 0x0A:
            return ""
        end = data.find(b"\x00", 5)
        if end < 0:
            end = len(data)
        return _sanitize(data[5:end].decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return ""


def read_redis_banner(ip: str, port: int = 6379, timeout: float = 1.0) -> str:
    """Redis 不主动说话，需要发一条 ``PING``。

    未启用认证 → ``+PONG``；启用认证 → ``-NOAUTH ...``。两者都能确认"这是
    Redis"。**不发 INFO**：未认证时拿不到版本，而已认证场景需要凭据，
    与"无凭据识别"的约束冲突。
    """
    try:
        with _connect(ip, port, timeout) as sock:
            sock.sendall(b"PING\r\n")
            data = sock.recv(256)
        text = _sanitize(data.decode("utf-8", "replace"))
        # 只认 Redis 的 RESP 应答前缀，避免把任意回显当成命中
        if text.startswith(("+PONG", "-NOAUTH", "-ERR")):
            return text
        return ""
    except Exception:  # noqa: BLE001
        return ""


def read_postgresql_banner(ip: str, port: int = 5432, timeout: float = 1.0) -> str:
    """PostgreSQL 不主动发 banner，用 SSLRequest 探测。

    SSLRequest = int32(长度 8) + int32(80877103)。服务端回单字节 ``S``（支持
    SSL）或 ``N``（不支持）—— 两者都证明这是 PostgreSQL。**版本号只在认证后的
    ParameterStatus 里才有**，无凭据拿不到，因此这里只做服务识别。
    """
    try:
        with _connect(ip, port, timeout) as sock:
            sock.sendall(struct.pack("!ii", 8, 80877103))
            data = sock.recv(1)
        return "PostgreSQL" if data in (b"S", b"N") else ""
    except Exception:  # noqa: BLE001
        return ""


def _bson_is_master() -> bytes:
    """构造 BSON 文档 ``{"isMaster": 1}``。"""
    elements = b"\x10isMaster\x00" + struct.pack("<i", 1)
    return struct.pack("<i", len(elements) + 5) + elements + b"\x00"


def read_mongodb_banner(ip: str, port: int = 27017, timeout: float = 1.0) -> str:
    """MongoDB：用 legacy ``OP_QUERY`` 发一条 isMaster，按响应判定。

    无凭据下 ``buildInfo``（能拿版本）需要认证，而 isMaster 是握手阶段允许
    匿名调用的，因此只做服务识别、不取版本。
    """
    try:
        query = _bson_is_master()
        body = (struct.pack("<i", 0)                 # flags
                + b"admin.$cmd\x00"                  # fullCollectionName
                + struct.pack("<ii", 0, -1)          # numberToSkip / numberToReturn
                + query)
        header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)  # OP_QUERY
        with _connect(ip, port, timeout) as sock:
            sock.sendall(header + body)
            head = _recv_exact(sock, 4)
            if len(head) < 4:
                return ""
            total = struct.unpack("<i", head)[0]
            rest = _recv_exact(sock, max(0, min(total - 4, 4096)))
        if len(rest) < 12:
            return ""
        opcode = struct.unpack("<i", rest[8:12])[0]
        if opcode != 1:                              # OP_REPLY
            return ""
        return "MongoDB" if b"ismaster" in rest.lower() else ""
    except Exception:  # noqa: BLE001
        return ""


# 最小 RDP 连接请求：TPKT(4) + X.224 CR(7) + RDP 协商请求(8) = 19 字节
_RDP_CONNECT_REQUEST = bytes.fromhex("030000130ee00000000000010008000b000000")


def read_rdp_banner(ip: str, port: int = 3389, timeout: float = 1.0) -> str:
    """RDP：发一个最小 X.224 连接请求，服务端回连接确认（0xD0）即判定为 RDP。

    无凭据无法拿到 RDP 版本/主机名，这里只做服务识别。
    """
    try:
        with _connect(ip, port, timeout) as sock:
            sock.sendall(_RDP_CONNECT_REQUEST)
            data = sock.recv(64)
        # TPKT 头(03 00) + X.224 长度字节 + 连接确认码 0xD0
        if len(data) >= 6 and data[0] == 0x03 and data[5] == 0xD0:
            return "RDP"
        return ""
    except Exception:  # noqa: BLE001
        return ""
