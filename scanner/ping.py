# -*- coding: utf-8 -*-
import ctypes
import ipaddress
import platform
import re
from typing import Dict, List, Optional, Tuple

from app_logging import get_logger

from .constants import _LOCAL_MAC_CACHE
from .util import _run_cmd

# 探测层失败大多是"预期内"的（主机离线、无路由、arping 未安装），因此统一用
# debug 级别记录：默认 INFO 级别不会写进日志文件，需要排查时把级别调到 DEBUG
# 即可看到每一步为什么没结果。只有"整个子系统不可用"才值得 warning。
_log = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"
_IS_MAC = platform.system() == "Darwin"


def ping_ip(ip: str, timeout_ms: int = 1000) -> Tuple[bool, float, int]:
    """
    Ping 单个 IP，返回 (是否在线, 响应时间ms, TTL)。
    TTL 用于 OS 推测（Windows≈128 / Linux·macOS·BSD≈64 / 部分网络设备≈255）。
    """
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
