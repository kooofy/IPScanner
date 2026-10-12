# -*- coding: utf-8 -*-
"""被动 / 持续发现：不扫网段，只读本机**已经有**的信息。

与主动扫描的分工
----------------
- 主动扫描回答「这个网段里有什么」—— 要发包，快但会惊动 IDS / 流量审计；
- 被动发现回答「最近谁在我身边出现过」—— **默认零发包**，
  代价是看不到沉默设备。

两个来源
--------
1. **本机 ARP 表整表 dump**（`dump_arp_table()`）—— 零发包。
   只能看到「最近与本机有过 L2 往来」的设备，但覆盖面最广，
   连不响应任何探测的设备也在表里。
2. **mDNS 组播监听** —— 复用 `scanner/dns.py`，默认走 `listen_only=True`
   （只听不发，零发包）。需要更强发现能力时可显式开主动查询
   （`mdns_active=True`），代价是发组播包。

**只报「新出现」，不报「消失」**（`PassiveWatcher`）
---------------------------------------------------
ARP 条目会过期，设备从表里消失**不等于**它下线了 ——
报「消失」是假阳性。宁可不说，也不要给用户一份会自己造谣的台账。

**「新出现」要过两道关：IP 与指纹**
------------------------------------
只看 IP 的话，一台开了「隐私 MAC」的手机换个地址就会被当成新设备。
所以 `PassiveWatcher` 同时记「见过的 IP」与「见过的设备指纹」
（`device_fingerprint.py`，主机名 / 厂商）：IP 没见过、但指纹认得出来，
那是**老设备换了 MAC / IP**，不是新设备。

**不写快照**
------------
快照有 20 条硬上限（`history_store.prune`）。被动发现每周期写一条，
十分钟就能把真实扫描历史全冲掉，`diff` / `locate_device()` 随之失效。
所以这里只维护**内存台账**；要落库请调用方显式调
`history_store.save_snapshot()`。
"""
import platform
import re
import time
from typing import Callable, Dict, List, Optional, Set

from app_logging import get_logger

from device_fingerprint import fingerprint
from .dns import mdns_discover
from .engine import _merge_mdns
from .models import ScanResult, get_mac_vendor
from .ndp import attach_ipv6, dump_ndp_cache, ipv6_enabled, probe_all_nodes
from .util import _run_cmd

_log = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"

#: ARP 表里这些 MAC 不代表"一台设备"：广播、全零（条目未解析完成）、组播。
_UNUSABLE_MACS = frozenset({"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"})
#: IPv4 / IPv6 组播 MAC 前缀 —— 也不是单台设备。
_MULTICAST_PREFIXES = ("01:00:5e", "33:33")
#: MAC 的形状（小写冒号分隔）。各解析器的正则已经把形状卡住了，
#: 但 `/proc/net/arp` 是**按空白切列**读的，列错位时会把垃圾当 MAC ——
#: 所以这里再统一校验一次，让所有路径都吃到同一份约束。
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def _mac_usable(mac: str) -> bool:
    """这个 MAC 能不能代表一台真实设备。"""
    m = (mac or "").lower()
    if not _MAC_RE.match(m):
        return False
    if m in _UNUSABLE_MACS:
        return False
    return not m.startswith(_MULTICAST_PREFIXES)


# ── ARP 表解析（三种平台格式，各自独立函数以便喂样本单测） ──────────────

# Windows `arp -a`：
#     192.168.1.1          50-2b-73-xx-xx-xx     dynamic
_WIN_ARP_LINE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\S+")

# Linux / macOS `arp -an`：
#     ? (192.168.1.1) at 50:2b:73:xx:xx:xx [ether] on en0
#     ? (192.168.1.20) at (incomplete) on en0      ← 匹配不上，自然被跳过
_UNIX_ARP_LINE = re.compile(
    r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def parse_windows_arp(output: str) -> Dict[str, str]:
    """解析 Windows ``arp -a`` 输出 → {ip: mac}。

    多网卡时输出里有若干 `Interface: ...` 行，它们不匹配 IP+MAC 的形状，
    自然被跳过 —— 无需单独处理。
    """
    out: Dict[str, str] = {}
    for line in (output or "").splitlines():
        m = _WIN_ARP_LINE.match(line)
        if not m:
            continue
        ip = m.group(1)
        mac = m.group(2).replace("-", ":").lower()
        if _mac_usable(mac):
            out[ip] = mac
    return out


def parse_unix_arp(output: str) -> Dict[str, str]:
    """解析 Linux / macOS ``arp -an`` 输出 → {ip: mac}。"""
    out: Dict[str, str] = {}
    for line in (output or "").splitlines():
        m = _UNIX_ARP_LINE.search(line)
        if not m:
            continue
        ip = m.group(1)
        mac = m.group(2).lower()
        if _mac_usable(mac):
            out[ip] = mac
    return out


def parse_proc_net_arp(text: str) -> Dict[str, str]:
    """解析 Linux ``/proc/net/arp`` → {ip: mac}。

    格式：``IP address  HW type  Flags  HW address  Mask  Device``。
    Flags 为 ``0x0`` 表示条目尚未解析完成，MAC 无意义，跳过。
    """
    out: Dict[str, str] = {}
    for line in (text or "").splitlines()[1:]:      # 第 0 行是表头
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, flags, mac = parts[0], parts[2], parts[3].lower()
        if flags == "0x0":
            continue
        if _mac_usable(mac):
            out[ip] = mac
    return out


def dump_arp_table() -> Dict[str, str]:
    """读**本机 ARP 表整表**，返回 ``{ip: mac}``。**不发任何网络包**。

    Linux 优先直接读 ``/proc/net/arp``（不起子进程）；macOS 与回退路径走
    ``arp -an``（``-n`` 关掉反向 DNS，避免每条都去查名字、把一次读表拖成秒级）。
    Windows 走 ``arp -a``。

    表为空时**记 warning**：这既可能是"本机确实没有 L2 邻居"，
    也可能是 ``arp`` 命令不可用 —— 后者会让被动发现整体失效，
    属于用户能直接感知的结果缺失，必须留痕。
    """
    table: Dict[str, str] = {}
    if _IS_WINDOWS:
        table = parse_windows_arp(_run_cmd(["arp", "-a"], timeout=5))
    else:
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as fh:
                table = parse_proc_net_arp(fh.read())
        except OSError as e:
            # macOS 没有 /proc；Linux 上极少数受限环境也读不到。属预期分支。
            _log.debug("读 /proc/net/arp 失败（非 Linux？），改用 arp -an: %s", e)
        if not table:
            table = parse_unix_arp(_run_cmd(["arp", "-an"], timeout=5))

    if not table:
        _log.warning("ARP 表为空或读取失败 —— 本次被动发现看不到任何设备"
                     "（arp 命令不可用？或本机确实没有二层邻居）。")
    return table


# ── 一次被动发现 ──────────────────────────────────────────────────────

def _attach_ndp(results: Dict[str, ScanResult], *, probe: bool) -> int:
    """读 NDP 缓存并把 IPv6 地址挂到已有 IPv4 设备上（v2.0 §2.4）。

    返回挂上去的地址条数。任何一步失败都不抛 —— 看得见多少算多少，
    不能因为 IPv6 侧出问题把**已经读到的 ARP 结果**一起弄没。

    ``probe=True`` 时先向 `ff02::1` 发一次多播（唯一发包分支）；
    发完等一小会儿再读缓存，否则设备的邻居通告还没到。
    """
    try:
        if probe:
            if probe_all_nodes():
                # 等一拍让链路上的设备把 ICMPv6 echo reply 发回来、
                # 内核把邻居缓存建起来。0.5s 是"多数本链路设备都来得及"
                # 的经验值；不设更长是因为被动发现本身要求快。
                time.sleep(0.5)
        table = dump_ndp_cache()
    except Exception as e:  # noqa: BLE001
        _log.warning("读取 IPv6 邻居缓存失败，本次跳过 IPv6 可见性: %s", e,
                     exc_info=True)
        return 0
    if not table:
        # 空缓存分两种：本机根本没启用 IPv6（预期，不必惊动用户），
        # 与启用着却一台设备都没读到（可能只是本链路安静）。
        # 用 ipv6_enabled() 把两者分开，免得用户看到"没有设备"而反复排查。
        if not ipv6_enabled():
            _log.info("本机未启用 IPv6，本次无 IPv6 可见性可报。")
        else:
            _log.debug("NDP 缓存为空（本机启用了 IPv6，但当前无邻居条目）。")
        return 0
    return attach_ipv6(table, results.values())


def passive_discover(*, mdns: bool = True, mdns_active: bool = False,
                     mdns_timeout: float = 2.5,
                     ipv6: bool = False, ipv6_probe: bool = False,
                     library_lookup: Optional[Callable] = None
                     ) -> Dict[str, ScanResult]:
    """跑一次被动发现，返回 ``{ip: ScanResult}``。

    Args:
        mdns: 是否同时听 mDNS。关掉就只读 ARP 表（最快，~几十毫秒）。
        mdns_active: ``False``（默认）走 mDNS **只听模式，零发包**；
            ``True`` 才复用主动查询（发组播包，发现更全）。
        mdns_timeout: 听组播的时长（秒）。主动模式下也是等响应的时长。
        ipv6: 是否同时读 **NDP / IPv6 邻居缓存**并把地址挂到已有 IPv4 设备上
            （v2.0 §2.4）。**默认关**：多数排障场景只看 IPv4，读 NDP 是额外
            开销。开启后**本身零发包**（纯读本机缓存）。
        ipv6_probe: 读 NDP 缓存前先向 `ff02::1` 发**一次** ICMPv6 echo，
            促使设备回邻居通告。**这是本函数唯一会发包的分支**，默认关。
            仅在 ``ipv6=True`` 时有意义。
        library_lookup: 地址库内存匹配回调，对 ARP 新设备各调一次。

    关于 ``status``：ARP 表里有记录就标 ``online`` —— 那意味着本机最近
    确实和它有 L2 往来。但这**不等于**"此刻可达"（条目可能已过期）。
    真正的证据在 ``discovery_method``（``arp`` / ``mdns``）里，展示层据此区分。

    关于 IPv6：本函数**不新建** IPv6-only 设备行（一个 /64 有 2⁶⁴ 个地址，
    「盘点」不成立）—— 只把 NDP 里 MAC 与已有 IPv4 设备对上的地址追加到
    它的 ``ipv6_addresses`` 上（见 `scanner.ndp.attach_ipv6()`）。
    """
    results: Dict[str, ScanResult] = {}

    for ip, mac in dump_arp_table().items():
        results[ip] = ScanResult(ip=ip, status="online", mac=mac,
                                 vendor=get_mac_vendor(mac),
                                 discovery_method="arp")

    if ipv6:
        _attach_ndp(results, probe=ipv6_probe)

    if library_lookup is not None:
        for r in results.values():
            try:
                library_lookup(r)
            except Exception as e:  # noqa: BLE001
                # 地址库匹配失败只影响"位置/使用者"这类补充字段，
                # 不影响这台设备被发现了这一事实，所以只警告不中断。
                _log.warning("地址库匹配失败（被动发现）%s: %s", r.ip, e,
                             exc_info=True)

    if mdns:
        # listen_only=not mdns_active —— 默认只听，一个包都不发。
        try:
            mdns_map = mdns_discover(timeout=mdns_timeout,
                                     listen_only=not mdns_active)
        except Exception as e:  # noqa: BLE001
            # 组播出错（无组播路由 / 网卡切换 / 防火墙拦）不该把**已经读到的
            # ARP 结果**一起丢掉 —— 那才是被动发现的主来源。扫描引擎对
            # mDNS 阶段也是这个处理（见 scanner/engine.py 的 MdnsPhase）。
            _log.warning("mDNS 监听失败，本次只保留 ARP 表结果: %s", e,
                         exc_info=True)
            mdns_map = {}
        # 复用扫描引擎的合并逻辑：它已经处理好了 hostname/services 补充，
        # 以及"就地改过的对象要打 mdns_updated 标记让 UI 重渲染"的契约。
        _merge_mdns(results, mdns_map, library_lookup)

    return results


class PassiveWatcher:
    """把周期性被动发现的结果并进一份**内存台账**，并给出「新出现」的设备。

    ``known`` 是「已经见过」的 IP 集合，``known_fingerprints`` 是「已经见过」
    的**设备指纹**集合 —— 两者一起决定什么算"新"。只看 IP 的话，一台开了
    「隐私 MAC」的手机换个地址就会被重复报成新设备（路线图 §3 #11）。

    基线最自然是最近一次扫描快照的设备列表（`history_store.latest_devices()`）：
    那样报出来的就是"上次扫描之后新冒出来的设备"。不给基线的话，第一次轮询
    会把整张 ARP 表都当成新设备。
    """

    def __init__(self, known_ips: Optional[Set[str]] = None,
                 known_devices: Optional[list] = None,
                 library_lookup: Optional[Callable] = None):
        self.ledger: Dict[str, ScanResult] = {}
        self.known: Set[str] = {str(ip) for ip in (known_ips or ())}
        self.known_fingerprints: Set[str] = set()
        # 基线既能直接给 IP 集合，也能给完整设备列表（后者还能拿到指纹）。
        for d in (known_devices or ()):
            ip = (d.get("ip") if isinstance(d, dict) else getattr(d, "ip", "")) or ""
            if ip:
                self.known.add(str(ip))
            fp = fingerprint(d)
            if fp:
                self.known_fingerprints.add(fp)
        self._library_lookup = library_lookup

    def poll(self, *, mdns: bool = True, mdns_active: bool = False,
             mdns_timeout: float = 2.5, ipv6: bool = False,
             ipv6_probe: bool = False):
        """轮询一次。返回 ``(台账列表, 本次新出现的列表)``。

        台账是**累积**的：这一轮没出现的设备不会从台账里消失（见模块
        docstring —— 不报"消失"）。

        ``ipv6`` / ``ipv6_probe`` 透传给 `passive_discover`（v2.0 §2.4）。
        已经挂在设备上的 IPv6 地址**跨轮累积**：NDP 条目会过期，某一轮读不到
        不代表设备没有 IPv6 —— 与"不报消失"同一立场（宁可不说，不要造谣）。
        """
        found = passive_discover(mdns=mdns, mdns_active=mdns_active,
                                 mdns_timeout=mdns_timeout,
                                 ipv6=ipv6, ipv6_probe=ipv6_probe,
                                 library_lookup=self._library_lookup)
        # 本轮读到的 IPv6 按 MAC 累积回台账里已有的设备上：即使这一轮 ARP 表
        # 里没有它（L2 条目过期），上一轮看到的 IPv6 也不该凭空消失。
        if ipv6:
            self._accumulate_ipv6(found)
        fresh: List[ScanResult] = []
        fps = {ip: fingerprint(r) for ip, r in found.items()}
        for ip, r in found.items():
            if ip in self.known:
                continue
            # IP 没见过，但指纹认得出来 → 老设备换了 MAC / IP，不是新设备。
            fp = fps[ip]
            if fp and fp in self.known_fingerprints:
                continue
            fresh.append(r)
        # 指纹与 IP 都要跨轮累积，否则下一轮又会把同一台设备重报一次。
        # ⚠ 累积必须放在**判断之后**：同一轮里两台设备指纹相同（同一台机器的
        # 两个网卡、或快照里主机名重复）时，两台都要报出来，不能互相压制。
        for fp in fps.values():
            if fp:
                self.known_fingerprints.add(fp)
        self.ledger.update(found)
        self.known.update(found)
        return list(self.ledger.values()), fresh

    def _accumulate_ipv6(self, found: Dict[str, ScanResult]) -> None:
        """把本轮新读到的 IPv6 地址并进**台账**里对应的老设备上。

        做法：先用 MAC 建「本轮设备的 MAC → IP」索引，再把本轮设备上挂到的
        IPv6 追加到台账里同 MAC 的**老资产**上。这样即便某台设备这一轮的
        ARP 条目已过期（不在 ``found`` 里），它上一轮看到的 IPv6 也不会消失。

        **不新建**行：``found`` 里若有一台 IPv4 设备是台账里没有的（第一次
        出现），它的 ``ipv6_addresses`` 由 `passive_discover` 已经挂好，
        ``ledger.update(found)`` 会带进去，这里不需要额外处理。
        """
        # MAC → 台账里的既有结果（同一 MAC 可能对应多条历史行，全都要更新）。
        ledger_by_mac: Dict[str, list] = {}
        for r in self.ledger.values():
            mac = (r.mac or "").lower()
            if mac:
                ledger_by_mac.setdefault(mac, []).append(r)
        for r in found.values():
            if not r.ipv6_addresses:
                continue
            for old in ledger_by_mac.get((r.mac or "").lower(), ()):
                if old is r:
                    continue
                for addr in r.ipv6_addresses:
                    if addr not in old.ipv6_addresses:
                        old.ipv6_addresses.append(addr)
