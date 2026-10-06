# -*- coding: utf-8 -*-
"""服务 banner 探测测试（P2-2）。

每个探测都用**本机回环上的一次性假服务端**驱动，验证真正的二进制解析逻辑
（MySQL 握手包、MongoDB OP_REPLY、RDP X.224 确认、PostgreSQL SSLRequest …），
而不是靠 mock 掉 socket 来"假装通过"。

另一条同样重要的契约：**任何失败都必须返回空串**，绝不抛异常 ——
目标端口开着但不是该服务（代理、蜜罐、非标实现）是常态，
不能让一台设备的异常把整条富化流水线带崩。
"""
import os
import socket
import struct
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app_logging import get_logger
from scanner import banners

_log = get_logger(__name__)


class _OneShotServer:
    """回环上的单连接假服务端：accept 一次，交给 handler，然后关闭。"""

    def __init__(self, handler):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self._handler = handler
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return          # 测试结束时套接字已被关闭，属正常收尾
        try:
            with conn:
                self._handler(conn)
        except Exception:   # noqa: BLE001 - 假服务端的 handler 失败只影响该用例
            _log.warning("假服务端 handler 异常", exc_info=True)
        finally:
            self._srv.close()

    def close(self):
        # socket.close() 是幂等的：重复关闭不会抛异常，无需捕获
        self._srv.close()


class SanitizeTest(unittest.TestCase):

    def test_strips_control_chars(self):
        self.assertEqual(banners._sanitize("ab\x00\x01cd\r\n"), "ab  cd")

    def test_keeps_printable(self):
        self.assertEqual(banners._sanitize("  hello world  "), "hello world")


class GreetingTest(unittest.TestCase):

    def test_reads_smtp_greeting(self):
        srv = _OneShotServer(lambda c: c.sendall(b"220 mail.example.com ESMTP\r\n"))
        try:
            got = banners.read_greeting("127.0.0.1", srv.port, 1.0)
            self.assertIn("ESMTP", got)
        finally:
            srv.close()

    def test_returns_empty_on_connection_refused(self):
        # 找一个几乎肯定没人监听的端口：先 bind 再 close 拿到端口号
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(banners.read_greeting("127.0.0.1", port, 0.3), "")


class MysqlTest(unittest.TestCase):

    @staticmethod
    def _handshake(version: bytes) -> bytes:
        payload = b"\x0a" + version + b"\x00" + b"\x00" * 20
        return len(payload).to_bytes(3, "little") + b"\x00" + payload

    def test_parses_mysql_handshake(self):
        srv = _OneShotServer(lambda c: c.sendall(self._handshake(b"8.0.36")))
        try:
            self.assertEqual(
                banners.read_mysql_banner("127.0.0.1", srv.port, 1.0), "8.0.36")
        finally:
            srv.close()

    def test_parses_mariadb_handshake(self):
        srv = _OneShotServer(
            lambda c: c.sendall(self._handshake(b"5.5.5-10.6.4-MariaDB")))
        try:
            got = banners.read_mysql_banner("127.0.0.1", srv.port, 1.0)
            self.assertIn("MariaDB", got)
        finally:
            srv.close()

    def test_non_mysql_response_returns_empty(self):
        # 协议版本字节不是 0x0a → 不是 MySQL
        srv = _OneShotServer(lambda c: c.sendall(b"\x03\x00\x00\x00\xffhello"))
        try:
            self.assertEqual(banners.read_mysql_banner("127.0.0.1", srv.port, 1.0), "")
        finally:
            srv.close()


class RedisTest(unittest.TestCase):

    def test_pong(self):
        def handler(conn):
            conn.recv(64)
            conn.sendall(b"+PONG\r\n")
        srv = _OneShotServer(handler)
        try:
            self.assertIn("PONG", banners.read_redis_banner("127.0.0.1", srv.port, 1.0))
        finally:
            srv.close()

    def test_noauth(self):
        def handler(conn):
            conn.recv(64)
            conn.sendall(b"-NOAUTH Authentication required.\r\n")
        srv = _OneShotServer(handler)
        try:
            self.assertIn("NOAUTH",
                          banners.read_redis_banner("127.0.0.1", srv.port, 1.0))
        finally:
            srv.close()

    def test_non_redis_response_returns_empty(self):
        def handler(conn):
            conn.recv(64)
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
        srv = _OneShotServer(handler)
        try:
            self.assertEqual(banners.read_redis_banner("127.0.0.1", srv.port, 1.0), "")
        finally:
            srv.close()


class PostgresqlTest(unittest.TestCase):

    def test_ssl_supported(self):
        def handler(conn):
            conn.recv(8)
            conn.sendall(b"S")
        srv = _OneShotServer(handler)
        try:
            self.assertEqual(
                banners.read_postgresql_banner("127.0.0.1", srv.port, 1.0), "PostgreSQL")
        finally:
            srv.close()

    def test_unexpected_reply_returns_empty(self):
        srv = _OneShotServer(lambda c: c.sendall(b"X"))
        try:
            self.assertEqual(
                banners.read_postgresql_banner("127.0.0.1", srv.port, 1.0), "")
        finally:
            srv.close()


class VncTest(unittest.TestCase):

    def test_reads_rfb_version(self):
        srv = _OneShotServer(lambda c: c.sendall(b"RFB 003.008\n"))
        try:
            self.assertIn("RFB",
                          banners.read_vnc_banner("127.0.0.1", srv.port, 1.0))
        finally:
            srv.close()


class RdpTest(unittest.TestCase):

    def test_x224_connection_confirm(self):
        def handler(conn):
            conn.recv(64)
            # TPKT(03 00 ...) + X.224 长度字节 + 连接确认码 0xD0
            conn.sendall(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x00")
        srv = _OneShotServer(handler)
        try:
            self.assertEqual(banners.read_rdp_banner("127.0.0.1", srv.port, 1.0), "RDP")
        finally:
            srv.close()

    def test_non_rdp_response_returns_empty(self):
        srv = _OneShotServer(lambda c: c.sendall(b"not rdp at all"))
        try:
            self.assertEqual(banners.read_rdp_banner("127.0.0.1", srv.port, 1.0), "")
        finally:
            srv.close()


class MongodbTest(unittest.TestCase):

    @staticmethod
    def _op_reply() -> bytes:
        rest = struct.pack("<iiii", 1, 0, 1, 0) + b"\x00" * 8 + b"ismaster\x00"
        return struct.pack("<i", 4 + len(rest)) + rest

    def test_is_master_reply(self):
        def handler(conn):
            conn.recv(512)
            conn.sendall(self._op_reply())
        srv = _OneShotServer(handler)
        try:
            self.assertEqual(
                banners.read_mongodb_banner("127.0.0.1", srv.port, 1.0), "MongoDB")
        finally:
            srv.close()

    def test_wrong_opcode_returns_empty(self):
        def handler(conn):
            conn.recv(512)
            rest = struct.pack("<iiii", 1, 0, 999, 0) + b"ismaster\x00"
            conn.sendall(struct.pack("<i", 4 + len(rest)) + rest)
        srv = _OneShotServer(handler)
        try:
            self.assertEqual(
                banners.read_mongodb_banner("127.0.0.1", srv.port, 1.0), "")
        finally:
            srv.close()


class NoExceptionContractTest(unittest.TestCase):
    """所有探测对"连不上/对端立刻关闭"都必须返回空串而非抛异常。"""

    def test_all_probes_survive_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        probes = [
            banners.read_greeting, banners.read_vnc_banner, banners.read_mysql_banner,
            banners.read_redis_banner, banners.read_postgresql_banner,
            banners.read_mongodb_banner, banners.read_rdp_banner,
        ]
        for probe in probes:
            self.assertEqual(probe("127.0.0.1", port, 0.3), "",
                             msg=f"{probe.__name__} 在端口关闭时应返回空串")


if __name__ == "__main__":
    unittest.main()
