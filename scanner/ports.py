# -*- coding: utf-8 -*-
import concurrent.futures
import os
import platform
import random
import re
import socket
import struct
import threading
import time
from typing import List, Tuple

from app_logging import get_logger

from . import constants as _C
from . import throttle
from .constants import COMMON_PORTS, _SYSTEM_SHARES
from .util import _inet_checksum, _local_ip_for_dst, _run_cmd
from i18n import tr

# 端口探测是"高频、单点失败很常见"的场景（绝大多数端口本来就是关的，
# 超时属正常），因此逐端口失败一律 debug；只有整个子系统不可用才 warning。
_log = get_logger(__name__)


# ── 端口探测线程池（进程内单例、有界） ──────────────────────────────────
#
# 旧实现**每次** scan_ports() 调用都新建一个
# ``ThreadPoolExecutor(max_workers=min(64, len(ports)))``。这个池是按"单台设备
# 单次调用"建的，但端口扫描在整个流水线里是**按设备**反复调用的：
# enrich 阶段并发 50 台，每台还要为协议端口再扫一次，于是最坏组合
# （standard 档 1023 端口）≈ 50 × 64 × 2 ≈ 6400 个线程在创建/销毁中抖动。
# 线程创建本身有成本（Windows 默认保留 1MB 栈），持续的新建-销毁还会让
# 调度器与 GC 反复被唤醒 —— 而真正的资源约束其实只是"同时在飞的 socket 数"，
# 线程数只是它的表象。
#
# 因此收敛为一个**进程内单例有界池**：
#   * 线程数有硬上限，不随设备数 / 端口数放大；
#   * 一次创建、长期复用，消除创建/销毁抖动。
#
# 上限取 384 ≈ enrich 并发(50) × 每台 8 路并发。这个取值的依据是实测（见下表，
# 场景：50 台设备并发富化，每台 22 个端口）：
#
#   | 探测延迟        | 旧实现(每台各建池)      | 单例池(cap=384)        |
#   | 1ms 快 LAN      | 0.20s / 69 线程         | 0.20s / 93 线程        |
#   | 混合(多数关闭)  | 0.36~0.48s / ~200 线程  | 0.33~0.38s / ~160 线程 |
#   | 全部 150ms 超时 | 0.56s / 715 线程        | 0.60s / 436 线程       |
#
# 即：现实负载（快 LAN / 多数端口关闭）下**不劣于甚至略快于**旧实现，
# 而线程数大幅下降；只有在"整台主机端口全部被防火墙丢包"的极端场景下
# 才会有约 7% 的时延代价 —— 换来的是最坏情况从数千线程收敛到 384 的硬上限。
# 128 这类更激进的取值在极端场景下会慢 2.5 倍，故不取。
_PORT_POOL_WORKERS = 384

_port_pool = None
_port_pool_lock = threading.Lock()


def _get_port_pool() -> concurrent.futures.ThreadPoolExecutor:
    """返回进程内共享的端口探测池（首次调用时惰性创建）。"""
    global _port_pool
    if _port_pool is None:
        with _port_pool_lock:
            if _port_pool is None:
                _port_pool = concurrent.futures.ThreadPoolExecutor(
                    max_workers=_PORT_POOL_WORKERS,
                    thread_name_prefix="portprobe",
                )
    return _port_pool


def port_pool_workers() -> int:
    """共享端口池的并发上限（供测试与诊断读取）。"""
    return _PORT_POOL_WORKERS


def shutdown_port_pool() -> None:
    """关闭并丢弃共享端口池，下次调用会重新惰性创建。

    正常扫描流程**不需要**调用它 —— 池本就是设计成跨设备、跨扫描复用的。
    提供它只是为了测试隔离，以及进程收尾时显式释放。
    """
    global _port_pool
    with _port_pool_lock:
        pool, _port_pool = _port_pool, None
    if pool is not None:
        pool.shutdown(wait=False)


# ── connect 扫描引擎选择（异步优先，线程池回退） ──────────────────────────
#
# v2.1 §2.1：connect 模式的并发探测默认改走 asyncio + IOCP（见
# scanner/async_ports.py）。异步路径在 Windows 上用**一个线程**挂起上千个
# connect，实测 2000 个关闭端口比线程池快约 1 倍（2× 提速），且无需任何驱动。
#
# 三条回退护栏，确保"换引擎"是**可回滚**的（v2.1 §0 原则 5）：
#   1. 显式开关：环境变量 ``IPSCANNER_TCP_ENGINE=threaded`` 强制回退线程池；
#      ``=async`` 强制异步（不可用时抛错，供测试）；未设 = 默认 auto。
#   2. 平台能力：``ProactorEventLoop`` 不可用（非 Windows 等）→ 自动回退；
#   3. 运行期失败：异步路径抛任何异常 → 记 warning 后**本次**回退线程池，
#      并置位进程级标记，后续调用直接走线程池（避免每台设备都重试一次坏引擎）。
_ENGINE_ENV = "IPSCANNER_TCP_ENGINE"

# 进程级"异步引擎已判失败"标记：一旦异步路径在真实扫描中抛错，就永久回退，
# 不再反复尝试。用 Event 而非 bool（与 _C._syn_failed 同口径，自带同步）。
_async_engine_failed = threading.Event()


def _async_engine_preference() -> str:
    """解析引擎偏好：``auto``（默认）/ ``threaded`` / ``async``。"""
    raw = (os.environ.get(_ENGINE_ENV) or "").strip().lower()
    if raw in ("threaded", "thread", "sync"):
        return "threaded"
    if raw in ("async", "asyncio"):
        return "async"
    return "auto"


def _use_async_connect() -> bool:
    """本次 connect 扫描是否走异步路径。"""
    pref = _async_engine_preference()
    if pref == "threaded":
        return False
    if _async_engine_failed.is_set():
        return False
    from . import async_ports as _ap
    ok, _reason = _ap.requires_proactor()
    if not ok:
        return False
    if pref == "async":
        return True
    return True  # auto：能力满足即用


def tcp_engine() -> str:
    """当前 connect 扫描实际会用的引擎：``"async"`` 或 ``"threaded"``。

    供测试与诊断读取（不触发任何探测）。
    """
    return "async" if _use_async_connect() else "threaded"


def reset_async_engine_state() -> None:
    """清空"异步引擎已失败"标记（供测试隔离；正常流程不需要）。"""
    _async_engine_failed.clear()


def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """检测指定端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_shares(ip: str, timeout: float = 1.5) -> List[str]:
    """
    枚举目标的 SMB 共享文件夹，返回共享名列表。
    Windows: net view。Linux/macOS: smbclient。
    过滤 ADMIN$/IPC$/PRINT$ 及 X$ 盘符类系统隐藏共享。
    """
    if platform.system() == "Windows":
        return _scan_shares_windows(ip, timeout)
    else:
        return _scan_shares_unix(ip, timeout)


def _scan_shares_windows(ip: str, timeout: float) -> List[str]:
    """Windows: net view"""
    try:
        output = _run_cmd(["net", "view", f"\\\\{ip}"], timeout=timeout)
        shares = []
        for line in output.splitlines():
            s = line.strip()
            if not s:
                continue
            if ("----" in s
                    or s.startswith("共享名") or s.startswith("Share name")
                    or s.startswith("命令成功") or "successfully" in s.lower()
                    or "系统错误" in s
                    or "System error" in s or "The command" in s):
                continue
            m = re.match(
                r"^(\S+)\s+(Disk|Print|IPC|Device|磁盘|打印|设备)", s, re.IGNORECASE
            )
            if not m:
                continue
            name = m.group(1).strip()
            if not name:
                continue
            if _is_system_share(name):
                continue
            shares.append(name)
        return shares
    except Exception:
        return []


def _scan_shares_unix(ip: str, timeout: float) -> List[str]:
    """Linux/macOS: smbclient -L（需安装 samba-client）"""
    # 两种调用方式：先匿名（-N），再空用户名/密码（-U %）。
    # smbclient 未安装时 _run_cmd 返回空串而非抛错，因此这里除了兜异常，
    # 还要靠"输出为空"判定失败，并把原因记到 debug 供排查。
    for _args, _label in ((["-N"], "匿名"), (["-U", "%"], "空凭据")):
        try:
            output = _run_cmd(["smbclient", "-L", f"//{ip}"] + _args + ["-g"],
                              timeout=timeout)
            if output:
                return _parse_smbclient_output(output)
            _log.debug("smbclient %s 枚举无输出 %s（多半未安装 samba-client 或无权限）",
                       _label, ip)
        except Exception as e:  # noqa: BLE001
            _log.debug("smbclient %s 枚举共享失败 %s: %s", _label, ip, e)
    return []


def _parse_smbclient_output(output: str) -> List[str]:
    """解析 smbclient -L 的 grepable (-g) 输出：Disk|share_name|description"""
    shares = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("Disk|"):
            continue
        parts = line.split("|")
        if len(parts) >= 2:
            name = parts[1].strip()
            if name and not _is_system_share(name):
                shares.append(name)
    return shares


def _is_system_share(name: str) -> bool:
    """判断是否为系统隐藏共享。"""
    up = name.upper()
    if up in _SYSTEM_SHARES:
        return True
    if len(name) == 2 and name[1] == "$" and name[0].isalpha():
        return True
    return False


def scan_ports(ip: str, ports: List[int] = None, timeout: float = 0.5,
               mode: str = "connect", rtt_callback=None) -> List[int]:
    """
    扫描多个端口，返回开放端口列表。

    mode:
      "connect" 全连接 TCP 扫描（默认，无需管理员，最稳定）
      "syn"     TCP SYN 半开扫描（需管理员；Windows 还需 Npcap，否则自动回退 connect）
      "udp"     仅扫描 UDP 端口（需管理员；不可用时回退为空）

    rtt_callback: 仅 connect 模式，每当某个端口探测成功(open)时回调其 connect 耗时(秒)。
      用于上层做 RTT 自适应超时（估计网络延迟），不影响返回值。
    """
    if ports is None:
        ports = COMMON_PORTS
    if not ports:
        return []
    if mode == "syn":
        return _scan_ports_syn(ip, ports, timeout)
    if mode == "udp":
        return _scan_ports_udp(ip, ports, timeout)
    # connect：默认走异步（IOCP），不可用/失败则回退线程池
    if _use_async_connect():
        try:
            from . import async_ports as _ap
            return _ap.probe_ports_async(
                ip, ports, timeout=timeout, rtt_callback=rtt_callback,
            )
        except Exception as e:  # noqa: BLE001
            # 异步引擎在真实扫描中失败：记 warning、永久回退线程池、本次立即重试。
            # 这是"换引擎可回滚"的兜底 —— 绝不让一次引擎故障升级成扫描失败。
            _async_engine_failed.set()
            _log.warning("异步 connect 引擎失败，回退线程池并记入进程级回退标记 %s: %s",
                         ip, e)
    return _scan_ports_connect_threaded(ip, ports, timeout, rtt_callback)


def _scan_ports_connect_threaded(ip: str, ports: List[int], timeout: float,
                                 rtt_callback=None) -> List[int]:
    """connect 模式的线程池实现（异步路径的回退，也是历史实现）。

    与异步路径**结果契约完全一致**：返回排序后的开放端口列表，
    ``rtt_callback`` 仅在端口开放时回调 connect 耗时。
    """
    open_ports = []
    executor = _get_port_pool()

    def _probe(p):
        # 礼貌模式（v2.1 §2.4）：发包前过令牌桶闸门。fast 档下是 no-op
        # （只有一次全局加载 + None 判断），只有 balanced/polite 才真正阻塞。
        throttle.throttle_gate()
        # 必须用 perf_counter：Windows 上它一直是 QueryPerformanceCounter（~100ns），
        # 而 time.monotonic() 在 Python 3.12 及以前是 GetTickCount64，分辨率只有
        # 15.6ms（3.13 才改成 QPC）。局域网 connect 通常只要几百微秒，
        # 用粗时钟两次调用会落在同一 tick 上、差值为 0.0，被下面的
        # `elapsed > 0` 守卫丢掉 —— 结果 RTT 采样恒为空、自适应超时永远退回默认值。
        t0 = time.perf_counter()
        ok = scan_port(ip, p, timeout)
        return ok, (time.perf_counter() - t0) if ok else 0.0

    # 礼貌模式：投递前按当前档打乱端口顺序（固定顺序扫同一网段是 IDS 的
    # 经典特征）。fast 档 shuffle=False ⇒ 顺序与改造前完全一致。
    futures = {executor.submit(_probe, p): p for p in throttle.shuffle_for(ports)}
    for future in concurrent.futures.as_completed(futures):
        port = futures[future]
        try:
            ok, elapsed = future.result()
            if ok:
                open_ports.append(port)
                if rtt_callback is not None and elapsed > 0:
                    rtt_callback(elapsed)
        except Exception as e:  # noqa: BLE001
            # 单端口探测失败 = 视为关闭。这是端口扫描的常态（绝大多数端口
            # 本来就是关的），因此只记 debug，避免日志被刷爆。
            _log.debug("端口探测异常，按关闭处理 %s:%s: %s", ip, port, e)
    return sorted(open_ports)


def reset_raw_capability_cache():
    """清空原始套接字能力缓存，让下次 raw_capability() 重新实测。

    供引擎在每次 SYN/UDP 扫描开始前调用 —— 权限可能在两次扫描之间变化
    （例如用户改用管理员身份重启了扫描），缓存若不失效就会一直沿用
    "上次不行"的结论，与 engine 里"本次重新验证"的意图不符。
    """
    _C._raw_cap_cache = None


def raw_capability() -> Tuple[bool, str]:
    """
    检测当前进程是否能创建原始套接字（SYN/UDP 扫描前提）。
    返回 (是否可用, 不可用原因)。
    注意：Windows 上即便能创建 IPPROTO_RAW 套接字，发送 TCP 报文仍可能被系统拦截
    （返回 WSAEINVAL），真正的收发能力需在发送时验证；此处仅做"能否创建"的初步判断。
    """
    if _C._raw_cap_cache is not None:
        return _C._raw_cap_cache
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        _C._raw_cap_cache = (True, "")
    except OSError:
        _C._raw_cap_cache = (False, tr("无权限创建原始套接字（需以管理员/root 运行）"))
    except Exception as e:
        _C._raw_cap_cache = (False, f"原始套接字不可用: {e}")
    return _C._raw_cap_cache


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int, seq: int) -> bytes:
    """构造 IP(TCP) 报文（含 SYN 标志）。"""
    tcp_off = 5
    tcp_flags = 0x02  # SYN
    window = socket.htons(64240)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0,
                             (tcp_off << 4), tcp_flags, window, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip), 0, 6, len(tcp_header))
    tcp_csum = _inet_checksum(pseudo + tcp_header)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0,
                             (tcp_off << 4), tcp_flags, window,
                             socket.htons(tcp_csum), 0)

    ihl = 5
    version_ihl = (4 << 4) | ihl
    total_len = ihl * 4 + len(tcp_header)
    ip_id = random.randint(0, 65535)
    ip_header = struct.pack("!BBHHHBBH4s4s", version_ihl, 0, total_len, ip_id,
                            0, 128, 6, 0,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_csum = _inet_checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s", version_ihl, 0, total_len, ip_id,
                            0, 128, 6, socket.htons(ip_csum),
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip_header + tcp_header


def syn_scan_port(dst_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    TCP SYN 半开扫描单个端口。
    返回: "open"(收到 SYN-ACK) / "closed"(收到 RST) / "filtered"(超时无响应)
    发送阶段需要原始套接字权限；无权限时抛 OSError，由调用方回退。
    """
    src_ip = _local_ip_for_dst(dst_ip)
    if src_ip == "0.0.0.0":
        return "filtered"
    src_port = random.randint(1025, 65535)
    seq = random.randint(0, 0xffffffff)
    packet = _build_syn_packet(src_ip, dst_ip, src_port, port, seq)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    send_sock.settimeout(timeout)
    send_sock.sendto(packet, (dst_ip, 0))
    send_sock.close()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock.settimeout(timeout)
    start = time.time()
    try:
        while time.time() - start < timeout:
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            if addr[0] != dst_ip:
                continue
            ihl = (data[0] & 0x0f) * 4
            tcp = data[ihl:]
            if len(tcp) < 4:
                continue
            r_src_port, r_dst_port = struct.unpack("!HH", tcp[0:4])
            if r_dst_port != src_port or r_src_port != port:
                continue
            flags = tcp[13]
            if flags & 0x12 == 0x12:   # SYN-ACK
                return "open"
            if flags & 0x04:           # RST
                return "closed"
    finally:
        recv_sock.close()
    return "filtered"


def _scan_ports_syn(ip: str, ports: List[int], timeout: float) -> List[int]:
    if _C._syn_failed.is_set():
        return scan_ports(ip, ports, timeout, mode="connect")
    open_ports = []
    ex = _get_port_pool()
    futs = {ex.submit(_syn_one, ip, p, timeout): p for p in ports}
    for f in concurrent.futures.as_completed(futs):
        p = futs[f]
        try:
            state = f.result()
        except OSError:
            # 无原始套接字发送权限（典型 Windows）：标记失败并整体回退
            _C._syn_failed.set()
            return scan_ports(ip, ports, timeout, mode="connect")
        except Exception:
            state = "error"
        if state == "open":
            open_ports.append(p)
    return sorted(open_ports)


def _syn_one(ip: str, port: int, timeout: float) -> str:
    return syn_scan_port(ip, port, timeout)


def udp_scan_port(dst_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    UDP 端口扫描：发送空 UDP 报文，监听 ICMP 端口不可达。
    返回: "open"(无响应，open|filtered) / "closed"(收到 ICMP 端口不可达)
    需要原始套接字接收 ICMP；无权限时抛 OSError，由调用方回退。
    """
    src_ip = _local_ip_for_dst(dst_ip)
    if src_ip == "0.0.0.0":
        return "open"  # 无法判断，保守当作 open|filtered
    src_port = random.randint(1025, 65535)
    payload = b""
    udp_header = struct.pack("!HHHH", src_port, port, 8 + len(payload), 0)
    packet = udp_header + payload

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    send_sock.settimeout(timeout)
    send_sock.sendto(packet, (dst_ip, 0))
    send_sock.close()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_sock.settimeout(timeout)
    start = time.time()
    try:
        while time.time() - start < timeout:
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            if addr[0] != dst_ip:
                continue
            # ICMP 头: type(1) code(1) csum(2) ... ; 端口不可达 type=3 code=3
            if len(data) < 8:
                continue
            icmp_type, icmp_code = data[0], data[1]
            if icmp_type == 3 and icmp_code == 3:
                # 校验内部携带的原 UDP 头部源端口是否匹配
                if len(data) >= 28:
                    inner_src = struct.unpack("!H", data[24:26])[0]
                    if inner_src == src_port:
                        return "closed"
    finally:
        recv_sock.close()
    return "open"  # 超时无响应 => open|filtered


def _scan_ports_udp(ip: str, ports: List[int], timeout: float) -> List[int]:
    if not ports:
        return []
    if _C._syn_failed.is_set():
        return []  # UDP 也依赖原始套接字，失败则跳过（避免误报）
    open_ports = []
    ex = _get_port_pool()
    futs = {ex.submit(udp_scan_port, ip, p, timeout): p for p in ports}
    for f in concurrent.futures.as_completed(futs):
        p = futs[f]
        try:
            state = f.result()
        except OSError:
            _C._syn_failed.set()
            return []
        except Exception:
            state = "error"
        if state == "open":
            open_ports.append(p)
    return sorted(open_ports)
