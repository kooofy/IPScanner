# -*- coding: utf-8 -*-
import ctypes
import ipaddress
import os
import platform
import re
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

from app_logging import get_logger

from .constants import _LOCAL_MAC_CACHE
from .util import _inet_checksum, _run_cmd

# 探测层失败大多是"预期内"的（主机离线、无路由、arping 未安装），因此统一用
# debug 级别记录：默认 INFO 级别不会写进日志文件，需要排查时把级别调到 DEBUG
# 即可看到每一步为什么没结果。只有"整个子系统不可用"才值得 warning。
_log = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"
_IS_MAC = platform.system() == "Darwin"


# ── 原生 ICMP 存活探测 ────────────────────────────────────────────────
#
# 为什么不再默认走 `ping` 子进程
# ------------------------------
# 旧实现每个 IP 起一个 `ping` 进程：/24 是 254 次进程创建，/16（本项目上限）
# 是 65536 次。Windows 上单次进程创建约 10~20ms，这部分开销往往**比真正的
# 网络等待还大** —— 这是与 Advanced IP Scanner / nmap 最主要的体感差距。
#
# Windows：iphlpapi 的 IcmpSendEcho
#   用户态导出，**零第三方依赖、零管理员权限**，与本项目已有的 SendARP
#   （见 _arp_ping_windows）是同一套 ctypes 手法，风格保持一致。
#
# Linux / macOS：SOCK_RAW + IPPROTO_ICMP
#   需要 root 或 CAP_NET_RAW。拿不到权限时静默回退子进程 —— 功能不受影响，
#   只是慢一点，因此不值得打扰用户。
#
# 两条路都必须返回与子进程版**完全一致**的 (alive, rtt_ms, ttl) 三元组：
# TTL 是 OS 指纹（见 osfp.guess_os_from_ttl）的输入，丢了会让识别率下降。

_IP_SUCCESS = 0
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# 原生 ICMP 可用性：None=尚未探测，True/False=探测结果。
# 只在 ping.py 内部读写，因此不需要放进 constants 共享 ——
# 对比 _syn_failed 的教训：跨模块共享的可变状态必须只有一个持有者。
_native_ping_ok: Optional[bool] = None

_iphlpapi = None
_ws2_32 = None
_icmp_configured = False


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    """对应 Windows SDK 的 ICMP_ECHO_REPLY（字段顺序不可改）。

    ``Options.Ttl`` 是**回包**的 TTL —— IcmpSendEcho 会把收到的 IP 头选项
    填进这里，这正是 OS 指纹需要的信息。
    """
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IP_OPTION_INFORMATION),
    ]


def _init_icmp_windows() -> bool:
    """解析 iphlpapi/ws2_32 并声明签名。成功返回 True，不可用返回 False。"""
    global _iphlpapi, _ws2_32, _icmp_configured
    if _icmp_configured:
        return _iphlpapi is not None
    _icmp_configured = True
    try:
        _iphlpapi = ctypes.windll.iphlpapi
        _ws2_32 = ctypes.windll.ws2_32

        _ws2_32.inet_addr.argtypes = [ctypes.c_char_p]
        _ws2_32.inet_addr.restype = ctypes.c_ulong

        _iphlpapi.IcmpCreateFile.argtypes = []
        _iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p

        _iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        _iphlpapi.IcmpCloseHandle.restype = ctypes.c_int

        _iphlpapi.IcmpSendEcho.argtypes = [
            ctypes.c_void_p,        # IcmpHandle
            ctypes.c_ulong,         # DestinationAddress (IPAddr, 网络序)
            ctypes.c_char_p,        # RequestData
            ctypes.c_ushort,        # RequestSize
            ctypes.c_void_p,        # RequestOptions（可空）
            ctypes.c_void_p,        # ReplyBuffer
            ctypes.c_ulong,         # ReplySize
            ctypes.c_ulong,         # Timeout(ms)
        ]
        _iphlpapi.IcmpSendEcho.restype = ctypes.c_ulong
    except Exception as e:  # noqa: BLE001
        # 非 Windows 或 iphlpapi 不可用：属预期，上层会回退子进程 ping
        _log.debug("IcmpSendEcho 不可用，回退子进程 ping: %s", e)
        _iphlpapi = None
        _ws2_32 = None
    return _iphlpapi is not None


_ICMP_PAYLOAD = b"ipscanner-ping"


def _icmp_ping_windows(ip: str, timeout_ms: int):
    """Windows 原生 ICMP。返回 (alive, rtt_ms, ttl)；不可用返回 None。"""
    if not _init_icmp_windows():
        return None

    addr = _ws2_32.inet_addr(ip.encode("ascii", "ignore"))
    if addr == 0xFFFFFFFF:      # INADDR_NONE：不是合法的 IPv4 字面量
        return None

    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == _INVALID_HANDLE_VALUE:
        _log.debug("IcmpCreateFile 失败，回退子进程 ping")
        return None
    try:
        # 回包缓冲区至少要能放下 ICMP_ECHO_REPLY + 请求数据 + 8 字节 ICMP 头
        reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(_ICMP_PAYLOAD) + 8
        reply_buf = ctypes.create_string_buffer(reply_size)

        # 每次调用独立建/销句柄：IcmpSendEcho 不保证同一句柄跨线程安全，
        # 而本函数会被 100 个工作线程并发调用。建句柄只是用户态→内核的
        # 一次快速调用，比"起一个 ping 进程"便宜好几个数量级。
        n = _iphlpapi.IcmpSendEcho(
            handle,
            ctypes.c_ulong(addr),
            _ICMP_PAYLOAD,
            ctypes.c_ushort(len(_ICMP_PAYLOAD)),
            None,
            ctypes.cast(reply_buf, ctypes.c_void_p),
            ctypes.c_ulong(reply_size),
            ctypes.c_ulong(max(1, int(timeout_ms))),
        )
        if n == 0:
            # 超时 / 目标不可达 / 无路由：都属于"这台不在线"
            return False, 0.0, 0

        reply = ctypes.cast(reply_buf,
                            ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
        if reply.Status != _IP_SUCCESS:
            return False, 0.0, 0
        return True, float(reply.RoundTripTime), int(reply.Options.Ttl)
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


def _build_icmp_echo_request(ident: int, seq: int, payload: bytes) -> bytes:
    """构造 ICMP Echo Request（type=8），校验和已填好。

    抽成纯函数是为了可单测 —— 校验和算错是这类实现最典型的 bug，
    且表现为"永远收不到回包"，极难定位。
    """
    header = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    checksum = _inet_checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, checksum, ident & 0xFFFF, seq & 0xFFFF) + payload


def _icmp_ping_unix(ip: str, timeout_ms: int):
    """Linux/macOS 原生 ICMP。无 CAP_NET_RAW 时返回 None（上层回退）。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as e:
        _log.debug("原生 ICMP 需要 root/CAP_NET_RAW，回退子进程 ping: %s", e)
        return None

    try:
        ident = os.getpid() & 0xFFFF
        seq = 1
        packet = _build_icmp_echo_request(ident, seq, _ICMP_PAYLOAD)
        budget = max(0.05, timeout_ms / 1000.0)

        t0 = time.perf_counter()
        sock.settimeout(budget)
        sock.sendto(packet, (ip, 0))

        deadline = t0 + budget
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return False, 0.0, 0
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                return False, 0.0, 0
            except OSError as e:
                _log.debug("原生 ICMP 收包失败 %s: %s", ip, e)
                return False, 0.0, 0
            if addr[0] != ip:
                continue

            # Linux 与 BSD/macOS 的 raw socket 都会带上 IP 头（首字节高 4 位=4）；
            # 少数内核/配置下不带，因此两种形态都要能处理。
            ttl = 0
            if data and (data[0] >> 4) == 4:
                ihl = (data[0] & 0x0F) * 4
                if len(data) > 8:
                    ttl = data[8]
                icmp = data[ihl:]
            else:
                icmp = data

            if len(icmp) < 8 or icmp[0] != 0:      # 0 = Echo Reply
                continue
            r_id, _r_seq = struct.unpack("!HH", icmp[4:8])
            if r_id != ident:
                continue
            rtt_ms = (time.perf_counter() - t0) * 1000.0
            return True, rtt_ms, ttl
    finally:
        sock.close()


def _probe_native_ping() -> bool:
    """探测原生 ICMP 是否可用（只在进程内做一次）。"""
    if _IS_WINDOWS:
        return _init_icmp_windows()
    if _IS_LINUX or _IS_MAC:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            return True
        except OSError:
            _log.debug("原生 ICMP 不可用（需 root / CAP_NET_RAW），改用子进程 ping")
            return False
    return False


def _ping_subprocess(ip: str, timeout_ms: int) -> Tuple[bool, float, int]:
    """子进程 ping 回退路径（原实现，行为保持不变）。"""
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif _IS_MAC:
        # macOS: -c 1 -W timeout_ms (ms)
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    try:
        output = _run_cmd(cmd, timeout=timeout_ms / 1000 + 2)

        # Windows: "来自 192.168.1.1 的回复: 字节=32 时间=1ms TTL=64"
        # Linux/macOS: "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.123 ms"
        ttl = 0
        ttl_match = re.search(r"TTL[=:](\d+)", output, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
        if "TTL=" in output or "ttl=" in output:
            # 提取响应时间
            time_match = re.search(r"时间[=:](\d+)\s*ms", output)
            if not time_match:
                time_match = re.search(r"time[=:](\d+\.?\d*)\s*ms", output)
            if not time_match:
                time_match = re.search(r"<\s*(\d+)\s*ms", output)
            rtt = float(time_match.group(1)) if time_match else 0.0
            return True, rtt, ttl
        return False, 0.0, ttl
    except Exception:
        return False, 0.0, 0


def reset_native_ping_probe():
    """清除"原生 ICMP 可用性"缓存，供测试与权限变化后重新探测。"""
    global _native_ping_ok
    _native_ping_ok = None


def ping_ip(ip: str, timeout_ms: int = 1000) -> Tuple[bool, float, int]:
    """
    Ping 单个 IP，返回 (是否在线, 响应时间ms, TTL)。
    TTL 用于 OS 推测（Windows≈128 / Linux·macOS·BSD≈64 / 部分网络设备≈255）。

    优先走原生 ICMP（Windows IcmpSendEcho / Unix raw socket），
    不可用或调用异常时回退子进程 ping。两条路径返回结构完全一致。
    """
    global _native_ping_ok

    if _native_ping_ok is None:
        _native_ping_ok = _probe_native_ping()

    if _native_ping_ok:
        try:
            if _IS_WINDOWS:
                res = _icmp_ping_windows(ip, timeout_ms)
            else:
                res = _icmp_ping_unix(ip, timeout_ms)
        except Exception as e:  # noqa: BLE001
            # 原生路径意外失败：不放弃这台设备，退回子进程再试一次，
            # 并记 debug 便于定位（预期内失败如"无权限"在探测阶段已排除）
            _log.debug("原生 ICMP 调用异常，回退子进程 ping %s: %s", ip, e)
            res = None

        if res is not None:
            return res
        # 原生路径明确表示不可用（如中途失去权限）→ 关掉它，后续全部走子进程
        _native_ping_ok = False

    return _ping_subprocess(ip, timeout_ms)


def get_local_mac_map() -> Dict[str, str]:
    """
    获取本机所有网卡的 {ip: mac} 映射
    Windows 下使用 ipconfig /all，Linux/macOS 下使用 ip addr。
    """
    mac_map = {}

    try:
        if _IS_WINDOWS:
            output = _run_cmd(["ipconfig", "/all"], timeout=10)
            current_mac = None
            for line in output.splitlines():
                line = line.strip()
                # 匹配物理地址行
                mac_match = re.search(r"物理地址[ .]+: ([0-9a-fA-F\-]{17})", line)
                if not mac_match:
                    mac_match = re.search(r"Physical Address[ .]+: ([0-9a-fA-F\-]{17})", line)
                if mac_match:
                    current_mac = mac_match.group(1).replace("-", ":").lower()
                    continue
                # 匹配 IPv4 地址行
                ip_match = re.search(r"IPv4 地址[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
                if not ip_match:
                    ip_match = re.search(r"IPv4 Address[ .]+: (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match and current_mac:
                    mac_map[ip_match.group(1)] = current_mac
        else:
            # Linux / macOS: 使用 ip addr（macOS 也支持 ip 命令）
            try:
                output = _run_cmd(["ip", "addr"], timeout=10)
            except Exception:
                # macOS 回退到 ifconfig
                try:
                    output = _run_cmd(["ifconfig"], timeout=10)
                except Exception:
                    return mac_map

            current_mac = None
            for line in output.splitlines():
                line = line.strip()
                # MAC: "link/ether aa:bb:cc:dd:ee:ff" (ip addr) 或 "ether aa:bb:cc:dd:ee:ff" (ifconfig)
                mac_match = re.search(r"(?:link/)?ether\s+([0-9a-fA-F:]{17})", line)
                if mac_match:
                    current_mac = mac_match.group(1).lower()
                    continue
                # IP: "inet 192.168.1.1/24" (ip addr) 或 "inet 192.168.1.1 netmask ..." (ifconfig)
                if current_mac and "inet " in line:
                    ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if not ip.startswith("127."):
                            mac_map[ip] = current_mac
    except Exception as e:  # noqa: BLE001
        # 取不到本机 MAC 只影响"本机行不显示 MAC"，不影响扫描，故记 debug
        _log.debug("解析本机网卡信息失败（ipconfig /all 或 ip addr 输出异常）: %s", e)

    return mac_map


def get_local_mac_for_ip(ip: str) -> str:
    """获取本机指定IP对应的MAC地址"""
    global _LOCAL_MAC_CACHE
    if _LOCAL_MAC_CACHE is None:
        _LOCAL_MAC_CACHE = get_local_mac_map()
    return _LOCAL_MAC_CACHE.get(ip, "")


def arp_ping(ip: str) -> str:
    """
    主动 ARP 探测指定 IP 的 MAC 地址。
    
    Windows: 使用 SendARP API (iphlpapi.dll)，零管理员权限。
    Linux/macOS: 使用 arping 命令（需安装 iputils-arping 或 arping）。
    命中返回小写 MAC (aa:bb:...)，未命中/不支持返回空串。
    """
    if _IS_WINDOWS:
        return _arp_ping_windows(ip)
    else:
        return _arp_ping_unix(ip)


def _arp_ping_windows(ip: str) -> str:
    """Windows SendARP 主动 ARP 探测。"""
    try:
        ws2 = ctypes.windll.ws2_32
        iphlp = ctypes.windll.iphlpapi
        ws2.inet_addr.argtypes = [ctypes.c_char_p]
        ws2.inet_addr.restype = ctypes.c_uint32
        iphlp.SendARP.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_ubyte * 6),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        iphlp.SendARP.restype = ctypes.c_uint32

        dest = ws2.inet_addr(ip.encode("ascii"))
        src = ws2.inet_addr(b"0.0.0.0")
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        ret = iphlp.SendARP(dest, src, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if ret == 0 and mac_len.value >= 6:
            return ":".join(f"{b:02x}" for b in mac_buf[:6])
        _log.debug("SendARP 未命中 %s（返回码 %s，通常是目标不在同网段或未响应）", ip, ret)
    except Exception as e:  # noqa: BLE001
        # ctypes 调用失败（非 Windows / iphlpapi 不可用）→ 退化为"无 MAC"，属预期
        _log.debug("SendARP 调用失败 %s: %s", ip, e)
    return ""


def _arp_ping_unix(ip: str) -> str:
    """Linux/macOS 通过 arping 命令主动 ARP 探测。"""
    try:
        # arping: -c 1 = 发一次, -w 1 = 1 秒超时
        output = _run_cmd(["arping", "-c", "1", "-w", "1", ip], timeout=3)
        # 输出: "Unicast reply from 192.168.1.1 [aa:bb:cc:dd:ee:ff] 0.5ms"
        m = re.search(r"\[([0-9a-fA-F:]{17})\]", output)
        if m:
            return m.group(1).lower()
    except Exception as e:  # noqa: BLE001
        # arping 未安装是常见情况（iputils-arping 非默认包），会走下面的 arp -n 回退
        _log.debug("arping 不可用或执行失败 %s: %s", ip, e)

    # 回退: 尝试用 arp -n 读取系统 ARP 表 (Linux/macOS)
    try:
        output = _run_cmd(["arp", "-n", ip], timeout=3)
        m = re.search(r"([0-9a-fA-F:]{17})", output)
        if m and ip in output:
            return m.group(1).lower()
    except Exception as e:  # noqa: BLE001
        _log.debug("读取系统 ARP 表失败 %s: %s", ip, e)
    return ""


# ── Windows ipconfig 解析（中英双语，引擎与 UI 共用）────────────────
# 中文 Windows 输出「IPv4 地址 / 子网掩码」，英文 Windows 输出
# "IPv4 Address / Subnet Mask"。
# 历史问题：scan_mixin._get_local_subnet_windows() 只匹配中文关键词，导致
# 英文 Windows 上解析不到掩码，静默退化成 /24 猜测（可能扫错范围）。
# 这里统一为一份双语实现，两个调用点复用，不再各写一套。
_IPCONFIG_IP_RE = re.compile(r"IPv4\s*(?:地址|Address)[^\d]*(\d+\.\d+\.\d+\.\d+)", re.I)
_IPCONFIG_MASK_RE = re.compile(
    r"(?:子网掩码|Subnet\s*Mask)[^\d]*(\d+\.\d+\.\d+\.\d+)", re.I
)


def parse_windows_ipconfig(output) -> List[Tuple[str, str]]:
    """从 ipconfig 输出解析出 [(ip, 子网掩码), ...]，中英文 Windows 通用。

    按行推进、先 IP 后掩码才配对，避免多网卡场景下 IP 与掩码错位配对。
    未配成对的 IP（如只列了地址没有掩码的条目）会被丢弃。
    """
    pairs = []
    cur_ip = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        m = _IPCONFIG_IP_RE.search(line)
        if m:
            cur_ip = m.group(1)
            continue
        sm = _IPCONFIG_MASK_RE.search(line)
        if sm and cur_ip:
            pairs.append((cur_ip, sm.group(1)))
            cur_ip = None
    return pairs


def windows_ipconfig_subnets() -> List[Tuple[str, str]]:
    """执行 ipconfig 并返回 [(ip, 子网掩码), ...]（中英文 Windows 通用）。

    非 Windows 平台或命令执行失败时返回空列表。
    """
    if not _IS_WINDOWS:
        return []
    return parse_windows_ipconfig(_run_cmd(["ipconfig"], timeout=10))


def get_local_subnets() -> List:
    """
    返回本机所有直连网段 (ipaddress.IPv4Network 列表)。
    用于约束 ARP 主动探测范围（只对同网段离线 IP 探测，避免浪费时间）。
    Windows: 解析 ipconfig 输出。
    Linux/macOS: 解析 ip addr show 输出。
    """
    nets = []
    try:
        if _IS_WINDOWS:
            for ip_str, mask_str in windows_ipconfig_subnets():
                try:
                    net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                    if net not in nets and not _is_virtual_subnet(str(net)):
                        nets.append(net)
                except Exception as e:  # noqa: BLE001
                    _log.debug("忽略无法解析的 ipconfig 条目 %s/%s: %s",
                               ip_str, mask_str, e)
        else:
            # Linux / macOS: 解析 ip addr show
            try:
                output = _run_cmd(["ip", "addr", "show"], timeout=10)
            except Exception:
                output = _run_cmd(["ifconfig"], timeout=10)

            for line in output.splitlines():
                line = line.strip()
                # "inet 192.168.1.1/24 brd 192.168.1.255 scope global ..."
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if not m:
                    # ifconfig style: "inet 192.168.1.1 netmask 255.255.255.0"
                    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        ip_str, mask_str = m.group(1), m.group(2)
                        try:
                            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen
                            net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
                            if ip_str not in ("127.0.0.1",) and not _is_virtual_subnet(str(net)):
                                if net not in nets:
                                    nets.append(net)
                        except Exception as e:  # noqa: BLE001
                            _log.debug("忽略无法解析的 ifconfig 条目 %s/%s: %s",
                                       ip_str, mask_str, e)
                    continue
                ip_str, prefix_str = m.group(1), m.group(2)
                if ip_str.startswith("127."):
                    continue
                try:
                    net = ipaddress.ip_network(f"{ip_str}/{prefix_str}", strict=False)
                    if not _is_virtual_subnet(str(net)) and net not in nets:
                        nets.append(net)
                except Exception as e:  # noqa: BLE001
                    _log.debug("忽略无法解析的 ip addr 条目 %s/%s: %s",
                               ip_str, prefix_str, e)
    except Exception as e:  # noqa: BLE001
        # 整体失败会影响「本机网段」填充与 ARP 主动探测范围，值得 warning
        _log.warning("本机网段探测失败: %s", e, exc_info=True)
    return nets


def _is_virtual_subnet(net_str: str) -> bool:
    """排除常见虚拟/容器网卡网段（Docker、虚拟化、链路本地等）。"""
    virtual_prefixes = (
        "172.17.", "172.18.", "172.19.",  # Docker 默认网桥
        "169.254.",                         # 链路本地 (APIPA)
    )
    net_str_lower = net_str.lower()
    for p in virtual_prefixes:
        if net_str_lower.startswith(p):
            return True
    # 排除 docker/veth/br- 接口网段（CIDR 级）
    virtual_names = ("docker", "veth", "br-", "virbr", "vboxnet", "vmnet")
    if any(n in net_str_lower for n in virtual_names):
        return True
    return False


def get_mac_for_ip(ip: str, arp_cache: Optional[Dict[str, str]] = None) -> str:
    """获取指定 IP 的 MAC 地址。跨平台：arp 命令。"""
    # 先检查是否是本机IP
    local_mac = get_local_mac_for_ip(ip)
    if local_mac:
        return local_mac

    if arp_cache and ip in arp_cache:
        return arp_cache[ip]

    # ARP 表查询 (Windows/Linux/macOS 通用)
    try:
        output = _run_cmd(["arp", "-a", ip], timeout=5)
        for line in output.splitlines():
            match = re.search(r"([0-9a-fA-F\-:]{17})", line)
            if match and ip in line:
                return match.group(1).replace("-", ":").lower()
    except Exception as e:  # noqa: BLE001
        _log.debug("arp -a 查询失败 %s: %s", ip, e)

    # Linux/macOS: 尝试读取 /proc/net/arp
    if not _IS_WINDOWS:
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.lower()
        except Exception as e:  # noqa: BLE001
            _log.debug("读取 /proc/net/arp 失败 %s: %s", ip, e)

    return ""
