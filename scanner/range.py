# -*- coding: utf-8 -*-
"""IP 范围解析（**仅 IPv4**）。

支持格式:
    192.168.1.0/24             (CIDR)
    192.168.1.1-254            (短范围)
    192.168.1.1-192.168.1.254  (完整范围)
    192.168.1.1                (单 IP)

规模保护（P0-2）：
    解析前先计算范围包含的 IP 数，超过 MAX_IPS_PER_RANGE 时抛 RangeTooLarge，
    而不是先构建出几十亿个字符串把进程撑爆。调用方应捕获该异常并给出明确提示。
    需要"只看数量不建列表"时用 count_ip_range()，避免重复构建大列表。

IPv6（本工具不支持）：
    这里刻意**显式拒绝** IPv6 字面量，而不是让 ipaddress 放行后一路走到扫描层。
    历史缺陷：ipaddress.ip_network("2001:db8::/120") 语法完全合法，会正常解析并
    产出一串 IPv6 地址；但下游的 ARP/SendARP、NetBIOS、WMI、SNMP 全部假设 IPv4，
    结果是用户拿到一张"全部离线"的假结果表，且没有任何报错。
    需要把"暂不支持 IPv6"和"格式写错"分开提示时，用 is_ipv6_range() 判别。
"""
import ipaddress
from typing import List, Optional, Tuple

# 单个范围上限：65536 = 一个 /16。IPv4 单网段实务中很少超过 /16，
# 再大基本是误输入（如 0.0.0.0/0、10.0.0.0/8），必须拦下。
MAX_IPS_PER_RANGE = 65536

# 一次扫描所有范围合计上限：65536 = 一个 /16
# 与单范围上限取同一量级：每个 IP 都会实例化一个 ScanResult（约 1KB），
# 65536 个约 65MB，是单进程可接受的上限；再大则 ping 耗时也早已不可用。
MAX_IPS_TOTAL = 65536


class RangeTooLarge(ValueError):
    """IP 范围超出规模上限。"""

    def __init__(self, range_str: str, count: int, limit: int):
        self.range_str = range_str
        self.count = count
        self.limit = limit
        super().__init__(
            f"范围「{range_str}」包含 {count} 个 IP，超过单次上限 {limit} 个。"
        )


def _parse_spec(range_str: str) -> Optional[Tuple]:
    """把范围字符串解析为规格描述，不构建 IP 列表。

    返回 ("cidr", IPv4Network) / ("range", start_int, end_int) / ("single", ip_str)；
    无法解析**或非 IPv4** 返回 None。
    """
    if range_str is None:
        return None
    s = str(range_str).strip()
    if not s:
        return None

    # CIDR
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
        if net.version != 4:
            return None
        return ("cidr", net)

    # 范围: 192.168.1.1-254 或 192.168.1.1-192.168.1.254
    if "-" in s:
        parts = s.split("-")
        if len(parts) != 2:
            return None
        start_str, end_str = parts[0].strip(), parts[1].strip()
        if not start_str or not end_str:
            return None
        try:
            # 短格式: 192.168.1.1-254
            if "." not in end_str:
                prefix = start_str.rsplit(".", 1)[0]
                end_str = f"{prefix}.{end_str}"
            start = ipaddress.ip_address(start_str)
            end = ipaddress.ip_address(end_str)
            # 版本必须一致，否则 int() 比较会得出无意义结果
            if start.version != end.version:
                return None
            # 仅 IPv4：IPv6 区间同样会被 ipaddress 放行，必须挡在这里
            if start.version != 4:
                return None
            a, b = int(start), int(end)
            if a > b:
                a, b = b, a
            return ("range", a, b)
        except (ValueError, IndexError):
            return None

    # 单 IP
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return ("single", str(addr))


def is_ipv6_range(range_str: str) -> bool:
    """该字符串是否为**语法合法**的 IPv6 范围（单地址 / CIDR / 区间）。

    本工具只支持 IPv4（见模块 docstring）。这个函数存在的唯一目的，是让上层
    能把"暂不支持 IPv6"和"格式写错了"分开提示 —— 否则两者都表现为
    is_valid_range() 返回 False，用户会看到同一句"无法解析"而反复试错。
    """
    if range_str is None:
        return False
    s = str(range_str).strip()
    if not s:
        return False
    try:
        if "/" in s:
            return ipaddress.ip_network(s, strict=False).version == 6
        if "-" in s:
            parts = s.split("-")
            if len(parts) != 2:
                return False
            start_str, end_str = parts[0].strip(), parts[1].strip()
            if not start_str or not end_str:
                return False
            # 先判起点版本：短格式（a.b.c.d-254）只对 IPv4 有意义，此处直接排除
            if ipaddress.ip_address(start_str).version != 6:
                return False
            return ipaddress.ip_address(end_str).version == 6
        return ipaddress.ip_address(s).version == 6
    except (ValueError, IndexError):
        return False


def _count_spec(spec: Tuple) -> int:
    """计算规格包含的 IP 数（CIDR 剔除网络号/广播地址）。"""
    kind = spec[0]
    if kind == "cidr":
        net = spec[1]
        # /31、/32 无网络号/广播地址概念，全部可用
        if net.prefixlen >= 31:
            return net.num_addresses
        return max(0, net.num_addresses - 2)
    if kind == "range":
        return spec[2] - spec[1] + 1
    return 1


def count_ip_range(range_str: str) -> int:
    """不构建列表，直接返回范围包含的 IP 数；无法解析返回 0。

    用于 UI 展示规模、校验总量等场景，避免反复构建大列表。
    """
    spec = _parse_spec(range_str)
    if spec is None:
        return 0
    return _count_spec(spec)


def is_valid_range(range_str: str) -> bool:
    """是否为可解析的 **IPv4** 范围（不检查规模上限）。

    IPv6 字面量返回 False —— 本工具不支持 IPv6，见模块 docstring。
    需要区分"不支持"与"写错了"时配合 is_ipv6_range() 使用。
    """
    return _parse_spec(range_str) is not None


def parse_ip_range(range_str: str, max_ips: Optional[int] = MAX_IPS_PER_RANGE) -> List[str]:
    """解析 IP 范围字符串，返回 IP 列表。

    Args:
        range_str: 范围字符串
        max_ips:   允许的最大 IP 数；None 表示不限制（仅测试/内部使用）。
                   超出时抛 RangeTooLarge，避免无上限构建列表导致内存耗尽。

    Raises:
        RangeTooLarge: 范围包含的 IP 数超过 max_ips。
    """
    spec = _parse_spec(range_str)
    if spec is None:
        return []

    count = _count_spec(spec)
    if max_ips is not None and count > max_ips:
        raise RangeTooLarge(str(range_str).strip(), count, max_ips)

    kind = spec[0]
    if kind == "cidr":
        net = spec[1]
        if net.prefixlen >= 31:
            return [str(ip) for ip in net]
        return [str(ip) for ip in net.hosts()]
    if kind == "range":
        return [str(ipaddress.ip_address(i)) for i in range(spec[1], spec[2] + 1)]
    return [spec[1]]
