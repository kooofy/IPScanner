# -*- coding: utf-8 -*-
import concurrent.futures
import platform
import random
import re
import socket
import struct
import time
from typing import Dict

from app_logging import get_logger

from .constants import _MDNS_GROUP, _MDNS_PORT, _resolve_executor, _resolve_executor_lock
from .util import _run_cmd

_log = get_logger(__name__)


def _get_resolve_executor():
    global _resolve_executor
    if _resolve_executor is None:
        with _resolve_executor_lock:
            if _resolve_executor is None:
                _resolve_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=8, thread_name_prefix="resolve-host"
                )
    return _resolve_executor


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """反向 DNS 解析主机名（复用进程级线程池）"""
    try:
        future = _get_resolve_executor().submit(socket.gethostbyaddr, ip)
        try:
            hostname, _, _ = future.result(timeout=timeout)
            return hostname
        except concurrent.futures.TimeoutExpired:
            return ""
    except (socket.herror, socket.gaierror, Exception):
        return ""


def get_netbios_name(ip: str, timeout: float = 2.0) -> str:
    """获取 NetBIOS 名称。
    Windows: nbtstat -A。Linux/macOS: nmblookup（samba-common）。
    均不可用时返回空串。
    """
    is_win = platform.system() == "Windows"
    try:
        if is_win:
            output = _run_cmd(["nbtstat", "-A", ip], timeout=timeout)
        else:
            # Linux/macOS: nmblookup -A (samba-common 包)
            output = _run_cmd(["nmblookup", "-A", ip], timeout=timeout)

        for line in output.splitlines():
            stripped = line.strip()
            if "<00>" not in stripped:
                continue
            if re.search(r"GROUP|组", stripped, re.IGNORECASE):
                continue
            m = re.match(r"^(\S+)\s+<00>", stripped)
            if m:
                name = m.group(1)
                # nmblookup 输出格式: "COMPUTERNAME  <00> - B <ACTIVE>"
                if not name.startswith("IS~"):
                    return name
    except Exception as e:  # noqa: BLE001
        # nmblookup 未安装（Windows 上正常）或查询失败 → 主机名留空
        _log.debug("nmblookup 查询主机名失败 %s: %s", ip, e)
    return ""


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        b = label.encode("utf-8")
        out += bytes([len(b)]) + b
    out += b"\x00"
    return out


def _build_dns_query(name: str, qtype: int, req_id: int, unicast: bool = True) -> bytes:
    """构造标准 DNS 查询报文（mDNS 用，flags=0x0100）。"""
    header = struct.pack("!HHHHHH", req_id, 0x0100, 1, 0, 0, 0)
    qname = _encode_dns_name(name)
    qclass = 0x0001 | (0x8000 if unicast else 0)   # QU 位：请求单播响应
    return header + qname + struct.pack("!HH", qtype, qclass)


def _parse_dns_name(data: bytes, pos: int, depth: int = 0):
    """解析域名（支持压缩指针 0xC0），返回 (name, 新位置)。

    限制压缩指针跳转深度（默认 10 层），防止畸形 / 循环压缩指针
    （如 A -> B -> A）导致无限递归与栈溢出。
    """
    labels = []
    jumped = False
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:   # 压缩指针
            if depth >= 10:         # 超过最大嵌套层数，视为畸形报文，安全终止
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                pos += 2
            name, _ = _parse_dns_name(data, ptr, depth + 1)
            labels.append(name)
            break
        label = data[pos + 1:pos + 1 + length].decode("utf-8", "replace")
        labels.append(label)
        pos += 1 + length
    return ".".join(labels), pos


def _parse_mdns_packet(data: bytes, by_ip: dict, src_ip: str):
    """解析一条 mDNS 响应，把主机名/服务类型归入 by_ip[src_ip]。"""
    try:
        if len(data) < 12:
            return
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
        pos = 12
        for _ in range(qd):
            _, pos = _parse_dns_name(data, pos)
            pos += 4   # qtype + qclass
        entry = by_ip.setdefault(src_ip, {"names": set(), "services": set()})
        for _ in range(an + ns + ar):
            name, pos = _parse_dns_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _rclass = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            pos += 4   # TTL
            rdlen = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1:   # A 记录：name -> IPv4
                if len(rdata) >= 4:
                    ip = socket.inet_ntoa(rdata[:4])
                    entry["names"].add(name)
                    if ip != src_ip:
                        by_ip.setdefault(ip, {"names": set(), "services": set()})["names"].add(name)
            elif rtype == 12:   # PTR：DNS-SD 服务类型枚举
                low = name.lower()
                if low.endswith("_tcp.local") or low.endswith("_udp.local"):
                    label = name[:-6] if name.endswith(".local") else name
                    entry["services"].add(label)
            # SRV(33)/TXT(16)/AAAA(28) 等暂不解析（本机链路单设备响应已含自身信息）
    except Exception as e:  # noqa: BLE001
        # 畸形/截断的 mDNS 报文：网络里常有无视规范的实现，属预期情况
        _log.debug("解析 mDNS 报文失败（来自 %s，已跳过）: %s", src_ip, e)


def mdns_discover(timeout: float = 2.5,
                  listen_only: bool = False) -> Dict[str, dict]:
    """
    mDNS / DNS-SD 网络发现：向本地组播组发送浏览查询，收集所有响应。

    返回 {ip: {"names": set(host名), "services": set(服务类型)} }。
    典型可发现：打印机、NAS、路由器、Apple 设备、IoT、投屏、SMB 等。

    端口策略：
    - 优先绑定 5353 接收组播（最完整，能收到其余设备的组播广播）；
    - 若 5353 被系统 mDNS/Bonjour 占用（Windows 常见），回退到随机源端口：
      向组播组发送查询，响应设备会单播回我们的源端口，仍可被收到（仅
      失去「被动监听其他设备组播」能力，但足以发现手机等主动响应的设备）。

    ``listen_only=True`` —— **只听模式：一个包都不发**。
    绑 5353、加入组播组，然后只收（其他主机的 announcement、以及它们
    对别人查询的响应）。给「被动发现」用：零发包 → 不惊动 IDS / 流量审计。
    代价是发现能力弱于主动查询（安静网络里可能长时间收不到东西），
    且**必须**占用 5353 —— 拿不到就返回空（见下方 warning），
    因为退到随机端口在只听模式下收不到任何组播。
    """
    by_ip: Dict[str, dict] = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        _bound_5353 = False
        try:
            sock.bind(("", _MDNS_PORT))
            _bound_5353 = True
        except OSError:
            if listen_only:
                # 只听模式退到随机端口毫无意义（没人会单播给我们，我们又
                # 不发包去换响应）。静默返回空会让调用方误判成"网络里没设备"，
                # 必须留痕说明是端口被占。
                _log.warning(
                    "mDNS 只听模式无法绑定 5353（多半被系统 mDNS/Bonjour 占用），"
                    "本次收不到任何组播；如需发现设备请改用主动查询模式。")
                return by_ip
            # 5353 被系统占用：回退随机端口（仍可收单播响应）
            try:
                sock.bind(("", 0))
            except OSError:
                return by_ip

        if _bound_5353:
            try:
                mreq = socket.inet_aton(_MDNS_GROUP) + socket.inet_aton("0.0.0.0")
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                return by_ip

        sock.settimeout(0.25)

        # 主动查询：DNS-SD 服务枚举 + 通用 ANY + 手机/投屏相关服务类型。
        # 手机（iPhone/iPad）通常广播 companion-link / airdrop；Android 投屏
        # 经 googlecast；Apple TV 经 airplay/raop。主动问这些类型能显著提高
        # 手机被直接识别的概率（即便 MAC 为随机地址）。
        #
        # listen_only=True 时**整段跳过**：不发包，只靠下面的 recvfrom 收
        # 别人自发广播的内容。
        if not listen_only:
            _svc_types = [
                "_services._dns-sd._udp.local",
                "local",                      # ANY
                "_companion-link._tcp.local",
                "_airdrop._tcp.local",
                "_airplay._tcp.local",
                "_raop._tcp.local",
                "_googlecast._tcp.local",
                "_printer._tcp.local",
                "_ipp._tcp.local",
                "_homekit._tcp.local",
            ]
            for name in _svc_types:
                qtype = 255 if name == "local" else 12   # ANY / PTR
                q = _build_dns_query(name, qtype, random.randint(1, 65535))
                try:
                    sock.sendto(q, (_MDNS_GROUP, _MDNS_PORT))
                except OSError as e:
                    # 组播发送失败（无网卡 / 被防火墙拦 / 无组播路由）→ 发现会整体失效
                    _log.warning("mDNS 组播发送失败（%s），本次发现可能不完整: %s", name, e)

        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr:
                _parse_mdns_packet(data, by_ip, addr[0])
    except Exception as e:  # noqa: BLE001
        # mDNS 发现整体失败：会让"支持 mDNS 但不响应 Ping/ARP"的设备全部漏掉，
        # 属于用户能直接感知的结果缺失，必须留痕
        _log.warning("mDNS 发现过程异常，结果可能不完整: %s", e, exc_info=True)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception as e:  # noqa: BLE001
                _log.debug("关闭 mDNS socket 失败: %s", e)
    return by_ip
