# -*- coding: utf-8 -*-
import concurrent.futures
import ipaddress
import statistics
from typing import Dict, List
try:
    from oui_database import get_mac_vendor
except ImportError:
    def get_mac_vendor(mac: str) -> str:
        return ""

from . import constants as _C
from .banners import (read_greeting, read_mongodb_banner, read_mysql_banner,
                      read_postgresql_banner, read_rdp_banner, read_redis_banner,
                      read_vnc_banner)
from .classify import infer_device
from .constants import (COMMON_PORTS, PROTOCOL_PORTS, SVC_HTTP, SVC_HTTPS,
                        SVC_IMAP, SVC_MONGODB, SVC_MYSQL, SVC_POP3,
                        SVC_POSTGRESQL, SVC_RDP, SVC_REDIS, SVC_SMTP,
                        SVC_SNMP, SVC_TELNET, SVC_VNC, SVC_MDNS, SVC_SMB)
from .dns import get_netbios_name, mdns_discover, resolve_hostname
from .http import (_read_ftp_banner, _read_http, _read_ssh_banner,
                   _read_upnp_device_name, read_https)
from .models import ScanResult
from .osfp import _match_tcp_stack, _os_detail_from_banners, _tcp_stack_probe, guess_os_from_ttl
from .ping import arp_ping, get_local_subnets, get_mac_for_ip, ping_ip
from .ports import (raw_capability, reset_raw_capability_cache, scan_port,
                    scan_ports, scan_shares)
from .range import (parse_ip_range, count_ip_range, is_ipv6_range, RangeTooLarge,
                    MAX_IPS_PER_RANGE, MAX_IPS_TOTAL)
from .smb import probe_smb
from .snmp import snmp_get_system
from .snmp_v3 import snmp_v3_get_system, ERR_NO_RESPONSE
from app_logging import get_logger
from i18n import tr
from service_fingerprints import fingerprint_banner

# 扫描编排层的异常大多是"单台设备/单个环节失败"，不应影响整批扫描，
# 但必须留痕 —— 否则用户只看到"结果少了几个字段"，无从判断原因。
_log = get_logger(__name__)


def _proto_ports_already_scanned(scan_ports_flag: bool, ports, proto_ports) -> bool:
    """完整端口扫描是否已覆盖**全部**协议端口。

    协议端口（HTTP 80 / HTTPS 443 / FTP 21 / RDP 3389）本来就都在常用端口表里，
    因此"完整端口扫描 + 协议识别"同时开启时，旧实现会对同一台设备的同一批端口
    重复探测一遍 —— 多一次网络往返、多一轮线程池排队，纯属浪费。
    只有"确实覆盖了全部协议端口"时才允许复用，否则仍需补扫缺失的那些。

    ``ports`` 为 None 表示使用默认常用端口表（与 ``scan_ports`` 的语义一致）。
    """
    if not scan_ports_flag:
        return False
    scanned = set(ports or COMMON_PORTS)
    return all(p in scanned for p in proto_ports)


#: 端口 → (规范服务代码, banner 探测函数)。仅在该端口确实开放时才会调用。
#: 这些是内网高频服务，端口本身就是很强的线索；具体产品/版本交给指纹库解析。
_SERVICE_PROBES = (
    (23, SVC_TELNET, read_greeting),
    (25, SVC_SMTP, read_greeting),
    (110, SVC_POP3, read_greeting),
    (143, SVC_IMAP, read_greeting),
    (3389, SVC_RDP, read_rdp_banner),
    (3306, SVC_MYSQL, read_mysql_banner),
    (5432, SVC_POSTGRESQL, read_postgresql_banner),
    (5900, SVC_VNC, read_vnc_banner),
    (6379, SVC_REDIS, read_redis_banner),
    (27017, SVC_MONGODB, read_mongodb_banner),
)


def _probe_extra_services(result: ScanResult, ip: str, timeout: float) -> None:
    """对开放端口上的已知服务读取 banner，把识别结果并入 result。

    只在端口确实开放时探测，每种服务最多一次；探测失败静默跳过 ——
    "端口开着但不是该服务"（代理、蜜罐、非标服务）是常态，不该刷日志。
    产品与版本由 ``service_fingerprints`` 指纹库从 banner 中解析。
    """
    if not result.open_ports:
        return
    probe_timeout = max(0.5, min(1.5, timeout + 0.5))
    for port, code, probe in _SERVICE_PROBES:
        if port not in result.open_ports or code in result.services:
            continue
        try:
            banner = probe(ip, port, probe_timeout)
        except Exception as e:  # noqa: BLE001
            _log.debug("服务 banner 探测失败 %s:%s: %s", ip, port, e)
            continue
        if not banner:
            continue
        fp = fingerprint_banner(banner, port=port)
        service = (fp.service if fp and fp.service else code)
        if service in result.services:
            continue
        result.services.append(service)
        result.service_details.append({
            "proto": service,
            "port": port,
            "banner": (fp.display if fp else banner),
        })


def _identify_snmp(ip: str, snmp_v3_user=None):
    """SNMP 设备识别，返回 (info, error_message)。

    - 未配置 SNMPv3 用户 → 走 v2c 团体字探测（历史行为）；
    - 配置了 v3 用户 → **优先 v3**（明文团体字本就不该再用）。
      只有"目标根本不回话"才回退 v2c；凭据/配置类错误直接上报 ——
      回退会把"密码写错了"伪装成"这台设备不支持 SNMP"，更难排查。
    """
    if snmp_v3_user is None:
        return snmp_get_system(ip), None

    info = snmp_v3_get_system(ip, snmp_v3_user)
    if "error" not in info:
        return info, None
    if info.get("error_kind") == ERR_NO_RESPONSE:
        # 目标很可能只是没开 v3：回退到 v2c 团体字再试一次
        return snmp_get_system(ip), None
    # 凭据/配置/协议类错误：每台都失败说明是配置问题，必须留痕
    _log.warning("SNMPv3 识别失败 %s: %s", ip, info.get("error", ""))
    return None, info.get("error", "")


# ── RTT 自适应超时（仅 TCP connect 模式） ──
_RTT_WIN = 20          # 滚动窗口样本数
_RTT_FACTOR = 2.0      # 超时 = 中位数 RTT × 因子（留探测余量）
_RTT_MIN = 0.15        # 最短超时(秒)，避免局域网过激
_RTT_MAX = 1.5         # 最长超时(秒)，高延迟网也不至于太慢


def adaptive_timeout_from_samples(samples, factor=_RTT_FACTOR,
                                  min_to=_RTT_MIN, max_to=_RTT_MAX):
    """根据开放端口 connect 耗时样本，返回夹紧后的 connect 超时(秒)。

    样本为空返回默认 0.5；否则取中位数 × 因子并夹紧到 [min_to, max_to]。
    局域网(RTT 个位数 ms)会收敛到 min_to，显著快于固定 0.5s。
    """
    if not samples:
        return 0.5
    med = statistics.median(samples)
    return max(min_to, min(max_to, med * factor))


# ══════════════════════════════════════════════════════════════════════
#  扫描前置解析（纯函数，便于单测；不碰网络）
# ══════════════════════════════════════════════════════════════════════

def _resolve_tcp_mode(tcp_scan_mode: str, warnings: List[str]) -> str:
    """解析实际生效的 TCP 探测方式。

    syn/udp 需要原始套接字权限；拿不到就回退 connect 并把原因写进 warnings。
    **每次扫描都重新实测并复位"发送被拒"标记**：权限可能在两次扫描之间变化
    （例如用户提权重启），沿用上次结论会让用户永远静默回退到 connect。
    """
    if tcp_scan_mode not in ("syn", "udp"):
        return "connect"
    reset_raw_capability_cache()
    _C._syn_failed.clear()
    avail, reason = raw_capability()
    if avail:
        return tcp_scan_mode
    warnings.append(
        f"{'SYN' if tcp_scan_mode == 'syn' else tr('UDP')} 探测需要管理员权限"
        f"（Windows 还需 Npcap），已回退到 TCP 全连接扫描。{reason}"
    )
    return "connect"


def _build_proto_map(protocols):
    """把协议名列表拆成 (协议→端口 映射, 是否启用 SNMP 识别)。"""
    proto_port_map = {}
    snmp_enabled = False
    if protocols:
        for proto in protocols:
            proto_upper = proto.upper()
            if proto_upper == SVC_SNMP:
                snmp_enabled = True
            elif proto_upper in PROTOCOL_PORTS:
                proto_port_map[proto_upper] = PROTOCOL_PORTS[proto_upper]
    return proto_port_map, snmp_enabled


def _parse_ranges(ip_ranges):
    """解析并校验 IP 范围，返回 ``(all_ips, warnings, ok)``。

    含规模保护：**先只计数**，超限时在构建任何列表之前就拒绝，
    否则 ``0.0.0.0/0`` 会先 append 出 42.9 亿个字符串把进程撑爆。
    ``ok=False`` 表示调用方应中止本次扫描。
    """
    all_ips: List[str] = []
    warnings: List[str] = []
    for r in ip_ranges:
        n = count_ip_range(r)
        if n <= 0:
            # 纯非法输入与 IPv6 都落到这里。后者语法合法、只是本工具不支持，
            # 必须留痕 —— 否则用户看到"扫了但一台都没在线"会去查网络。
            # 这条兜底对"旧配置里存了 IPv6 网段"尤其必要：GUI/CLI 的输入期
            # 校验拦不住已经写进 ipscanner.ini 的历史数据。
            if is_ipv6_range(r):
                warnings.append(
                    tr("「{r}」是 IPv6 范围，本工具目前只支持 IPv4 扫描，已跳过。").format(r=r)
                )
            continue
        if n > MAX_IPS_PER_RANGE:
            warnings.append(
                f"范围「{r}」包含 {n} 个 IP，超过单次上限 {MAX_IPS_PER_RANGE} 个，已中止本次扫描。"
                f"请拆分为更小的范围（如按 /24 分批）后重试。"
            )
            return [], warnings, False
        if len(all_ips) + n > MAX_IPS_TOTAL:
            warnings.append(
                f"扫描范围合计将超过 {MAX_IPS_TOTAL} 个 IP（超出项：「{r}」），已中止本次扫描。"
                f"请缩小范围后重试。"
            )
            return [], warnings, False
        try:
            all_ips.extend(parse_ip_range(r))
        except RangeTooLarge as e:      # 兜底：与上面的计数判断保持一致
            warnings.append(str(e))
            return [], warnings, False
    return all_ips, warnings, True


# ══════════════════════════════════════════════════════════════════════
#  扫描上下文
# ══════════════════════════════════════════════════════════════════════

class ScanContext:
    """一次扫描的共享状态容器。

    原先这些状态散落在 ``scan()`` 的局部变量与四个嵌套闭包里，导致
    "想加一种新的发现方式就必须动 ``scan()`` 本身"。集中到 ctx 之后，
    各发现阶段（``DiscoveryPhase``）只依赖 ctx：**新增方式 = 新增一个类并
    登记进 ``PHASES``**，编排代码不动。
    """

    def __init__(self, scanner, all_ips, *, effective_tcp_mode: str = "connect",
                 warnings: List[str] = None, timeout_ms: int = 1000,
                 max_threads: int = 100, scan_ports_flag: bool = False,
                 protocols=None, mdns_discovery: bool = True, ports=None,
                 progress_callback=None, result_callback=None,
                 phase_callback=None,
                 library_lookup=None, snmp_v3_user=None):
        self.scanner = scanner
        self.all_ips = list(all_ips)
        self.total = len(self.all_ips)
        self.completed = 0
        self.results: Dict[str, ScanResult] = {
            ip: ScanResult(ip=ip) for ip in self.all_ips
        }
        # 与 scanner.warnings 共享同一个列表：阶段内追加的告警对外立即可见
        self.warnings: List[str] = warnings if warnings is not None else []

        self.effective_tcp_mode = effective_tcp_mode
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports_flag = scan_ports_flag
        self.ports = ports
        self.mdns_discovery = mdns_discovery
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        # 阶段回调 ``(name, index, total)``。``name`` 是**语言无关的规范值**
        # （即 ``DiscoveryPhase.name``，如 ``"ping"``），显示层再经
        # ``constants.phase_label()`` 惰性翻译 —— 回调里绝不传已翻译的文本，
        # 否则日志/审计里会出现"随界面语言变化的阶段名"。
        self.phase_callback = phase_callback
        self.library_lookup = library_lookup
        self.snmp_v3_user = snmp_v3_user

        self.proto_port_map, self.snmp_enabled = _build_proto_map(protocols)

        # RTT 自适应超时（仅 connect 模式）状态
        self.rtt_window: List[float] = []
        self.port_timeout = 0.5

        # 并发执行器：NetBIOS 解析共用池，与 DNS 解析并发而非串行等待
        self.netbios_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(10, min(50, len(self.all_ips)))
        )
        # enrich 并发度：主机名/NetBIOS/端口探测均为 I/O 密集，可安全提高到 50
        self.enrich_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(50, max(1, len(self.all_ips)))
        )
        self.enrich_futures = []

    # ── 状态访问与副作用 ──
    def is_stopped(self) -> bool:
        return bool(self.scanner._stop_flag)

    def submit_enrich(self, ip: str) -> None:
        """把一台在线设备交给富化流水线（与剩余阶段并发执行）。"""
        self.enrich_futures.append(
            self.enrich_executor.submit(_enrich_device, self, ip)
        )

    def on_rtt(self, rtt: float) -> None:
        """开放端口 connect 耗时样本回调 → 滚动估计自适应超时。"""
        if rtt <= 0:
            return
        self.rtt_window.append(rtt)
        if len(self.rtt_window) > _RTT_WIN:
            self.rtt_window.pop(0)
        self.port_timeout = adaptive_timeout_from_samples(self.rtt_window)

    def wait_enrich(self) -> None:
        """等待所有富化任务完成（停止扫描时不等待）。"""
        if self.is_stopped():
            return
        for f in self.enrich_futures:
            try:
                f.result()
            except Exception as e:  # noqa: BLE001
                # enrich 阶段单台设备失败：该设备结果字段会缺失，
                # 记 warning 便于定位是哪台、哪一步
                _log.warning("设备信息富化失败: %s", e, exc_info=True)

    def shutdown(self) -> None:
        self.enrich_executor.shutdown(wait=False)
        self.netbios_executor.shutdown(wait=False)


# ══════════════════════════════════════════════════════════════════════
#  设备富化
# ══════════════════════════════════════════════════════════════════════

def _enrich_device(ctx: ScanContext, ip: str) -> None:
    """富化单个在线设备：MAC / 厂商 / 主机名 / 端口 / 服务。"""
    if ctx.is_stopped():
        return
    result = ctx.results[ip]

    # RTT 自适应超时（仅 TCP connect 模式）：用已探设备的开放端口 connect
    # 耗时估计网络延迟，滚动窗口中位数动态夹紧 connect 超时，局域网可显著提速。
    _pto = ctx.port_timeout if ctx.effective_tcp_mode == "connect" else 0.5

    # MAC 地址：优先保留已获取的 MAC（如 ARP 主动探测所得），
    # 否则 per-IP 查询 ARP 缓存（对刚 ping 通的在线主机可靠）
    if not result.mac:
        result.mac = get_mac_for_ip(ip)
    mac = result.mac

    # 厂商识别 (通过 MAC OUI)
    if mac:
        result.vendor = get_mac_vendor(mac)

    # 端口 & 服务探测 (与本机名解析并行执行)
    if ctx.scan_ports_flag:
        result.scan_method = ctx.effective_tcp_mode
        result.open_ports = scan_ports(
            ip, ports=ctx.ports, timeout=_pto, mode=ctx.effective_tcp_mode,
            rtt_callback=ctx.on_rtt if ctx.effective_tcp_mode == "connect" else None,
        )

    # OS / 版本探测：基于 TTL 推测族 + banner 提取版本
    result.os_guess = guess_os_from_ttl(result.ttl) if result.ttl else ""
    _os_extra = {}
    if 22 in result.open_ports:
        _ssh = _read_ssh_banner(ip, 22, 1.0)
        if _ssh:
            _os_extra["ssh"] = _ssh
    if 21 in result.open_ports:
        _ftp = _read_ftp_banner(ip, 21, 1.0)
        if _ftp:
            _os_extra["ftp"] = _ftp
    result.os_detail = _os_detail_from_banners(result.service_details, _os_extra)

    # TCP 栈指纹（深度 OS 探测）：best-effort，无权限/失败自动跳过
    if result.open_ports:
        _probe_port = next(
            (p for p in (80, 443, 8080, 22, 21, 23, 135, 445, 139,
                         3389, 5900, 53) if p in result.open_ports),
            result.open_ports[0],
        )
        _sig = _tcp_stack_probe(ip, _probe_port, 1.0)
        if _sig:
            _tcp_os = _match_tcp_stack(_sig)
            # 仅在 ICMP 无结论或 TCP 识别为网络设备时覆盖，
            # 避免与已较准确的 ICMP TTL 推测冲突
            if _tcp_os and (not result.os_guess or _tcp_os == "网络设备"):
                result.os_guess = _tcp_os

    svc_list = []
    svc_details = []
    if ctx.proto_port_map:
        proto_ports = list(ctx.proto_port_map.values())
        # 复用已扫结果：完整端口扫描若已覆盖全部协议端口，就没必要再扫一遍
        # （见 _proto_ports_already_scanned 的说明）。
        if _proto_ports_already_scanned(ctx.scan_ports_flag, ctx.ports, proto_ports):
            detected_proto_ports = [p for p in proto_ports
                                    if p in result.open_ports]
        else:
            detected_proto_ports = scan_ports(
                ip, ports=proto_ports, timeout=_pto,
                rtt_callback=ctx.on_rtt if ctx.effective_tcp_mode == "connect" else None,
            )
        for proto, port in ctx.proto_port_map.items():
            if port in detected_proto_ports:
                svc_list.append(proto)
                detail = {"proto": proto, "port": port}
                if proto == SVC_HTTP:
                    # 单次 GET 同时提取 banner(标题) 与设备品牌/型号
                    # （对只开 80/443 的打印机很关键，省掉一次 TCP 往返）
                    http_banner, http_brand, http_model = _read_http(ip, port, 1.2)
                    upnp_name = _read_upnp_device_name(ip, port, 0.8)
                    result.upnp_model = upnp_name
                    result.http_brand = http_brand
                    result.http_model = http_model
                    if upnp_name:
                        # 对齐 AIP 风格: "<设备型号> <IP> (<Server头>)"
                        disp = upnp_name if ip in upnp_name else f"{upnp_name} {ip}"
                        if http_banner:
                            disp = f"{disp} ({http_banner})"
                        detail["banner"] = disp
                    else:
                        detail["banner"] = http_banner
                elif proto == SVC_HTTPS:
                    # 一次握手同时拿 banner 与证书事实（见 scanner/http.read_https）。
                    # 证书只保留第一个探到的：风险评分是"一台设备一条结论"，
                    # 每个 HTTPS 端口各留一份会让同一台设备刷出多条同义理由。
                    _banner, _cert = read_https(ip, port, 1.2)
                    detail["banner"] = _banner
                    if _cert and not result.tls_cert:
                        result.tls_cert = _cert
                svc_details.append(detail)
                # 如果没开完整端口扫描，也把协议端口加入开放端口列表
                if not ctx.scan_ports_flag and port not in result.open_ports:
                    result.open_ports.append(port)
                    result.open_ports.sort()
    result.services = svc_list
    result.service_details = svc_details

    # P2-2：对已知的高频服务端口读取 banner，由指纹库解析出产品与版本
    # （Telnet / SMTP / POP3 / IMAP / VNC / MySQL / Redis / PostgreSQL /
    #  MongoDB / RDP）。放在这里是为了让后续的设备类型推断也能用上这些服务。
    _probe_extra_services(result, ip, _pto)

    # 主机名：DNS 解析 (resolve_hostname 自带 1-worker 线程池，在设备线程内执行)
    # 与 NetBIOS 解析 (netbios_executor) 并发，任一命中即可
    hostname = resolve_hostname(ip, timeout=1.0)
    if not hostname:
        try:
            hostname = ctx.netbios_executor.submit(
                get_netbios_name, ip, 2.0
            ).result(timeout=2.0)
        except Exception as e:  # noqa: BLE001
            # 超时或 NetBIOS 不可达：主机名留空属正常结果，仅记 debug
            _log.debug("NetBIOS 主机名兜底查询失败 %s: %s", ip, e)
    result.hostname = hostname

    # SNMP 设备识别 (交换机/AP/打印机等)：取 sysDescr/sysName，
    # 作为主机名兜底，并把 "SNMP" 加入服务列表
    if ctx.snmp_enabled:
        snmp_info, _snmp_error = _identify_snmp(ip, ctx.snmp_v3_user)
        if snmp_info:
            result.snmp_sys_name = snmp_info.get("sys_name", "")
            result.snmp_sys_descr = snmp_info.get("sys_descr", "")
            if not result.hostname and result.snmp_sys_name:
                result.hostname = result.snmp_sys_name
            if SVC_SNMP not in result.services:
                result.services.append(SVC_SNMP)
            result.service_details.append({
                "proto": SVC_SNMP,
                "port": 161,
                "banner": result.snmp_sys_descr or tr("SNMP 设备信息"),
            })

    # 共享文件夹探测 (SMB / 445)：对在线设备的 SMB 服务枚举共享目录
    smb_open = 445 in result.open_ports
    if not smb_open and not ctx.scan_ports_flag:
        # 未做完整端口扫描时，快速探测 445 是否开放（仅在线设备）
        smb_open = scan_port(ip, 445, 0.4)
    if smb_open:
        shares = scan_shares(ip, timeout=1.5)
        if shares:
            result.shares = shares
            if SVC_SMB not in result.services:
                result.services.append(SVC_SMB)
            result.service_details.append({
                "proto": SVC_SMB,
                "port": 445,
                "banner": f"{len(shares)} 个共享: " + ", ".join(shares),
                "shares": shares,
            })
        # 零利用安全体检（v1.9 #3 第四刀）：只发 SMB2/SMB1 NEGOTIATE，读回方言与
        # 签名要求（`SecurityMode`）。**不**发 SESSION_SETUP、不试任何凭据 ——
        # 见 `scanner/smb.py` 开头的红线。放在这个分支里是因为 445 刚确认开着，
        # 不用再探一次端口；也刻意**不**依赖 `scan_shares()` 是否成功（它走的
        # 是另一套调用，拿不到共享不代表问不出方言）。
        result.smb = probe_smb(ip, timeout=1.5)

    # 设备指纹深度：综合厂商/端口/服务(mDNS/UPnP/SNMP)/OS 推断设备类别与型号
    result.device_class, result.device_model = infer_device(result)

    # 地址库匹配：由调用方传入的内存索引回调，在 enrich 工作线程内完成。
    # 放在最后是因为台账字段与指纹字段互不覆盖；失败不影响扫描结果。
    if ctx.library_lookup is not None:
        try:
            ctx.library_lookup(result)
        except Exception as e:  # noqa: BLE001
            # 地址库匹配失败只丢台账字段（位置/使用人/备注），不影响扫描
            _log.warning("地址库匹配失败 %s: %s", ip, e, exc_info=True)

    if ctx.result_callback:
        ctx.result_callback(result)


# ══════════════════════════════════════════════════════════════════════
#  mDNS 合并
# ══════════════════════════════════════════════════════════════════════

def _merge_mdns(results: Dict[str, ScanResult], mdns_map: dict,
                library_lookup=None) -> int:
    """把 mDNS 组播发现结果并入 results（就地修改），返回新增设备数。

    从 scan() 里抽出来是为了可单测 —— 这段逻辑有一条容易写错的契约：

    对**已存在**的结果是就地修改。而那些对象在 enrich 完成时就已经通过
    result_callback 交给 UI 渲染过一轮了，所以任何改动都必须打上
    `mdns_updated` 标记，UI 才会重渲染这一行；否则 mDNS 补上的服务/主机名
    在界面上永远看不到。

    Args:
        results: {ip: ScanResult}，原地更新
        mdns_map: {ip: {"names": set, "services": set}}
        library_lookup: 地址库内存匹配回调，仅对新增设备调用一次
    """
    added = 0
    for ip, info in mdns_map.items():
        names = sorted(info.get("names", set()))
        services = sorted(info.get("services", set()))
        if ip in results:
            r = results[ip]
            _changed = False
            if not r.hostname and names:
                r.hostname = names[0].rstrip(".")
                _changed = True
            if services and SVC_MDNS not in r.services:
                r.services.append(SVC_MDNS)
                r.service_details.append({
                    "proto": SVC_MDNS, "port": 0,
                    "banner": ", ".join(services),
                })
                _changed = True
            if r.status != "online":
                r.status = "online"
                if not r.discovery_method:
                    r.discovery_method = "mdns"
                _changed = True
            # 只有真的改过才打标记：没改也打会让 UI 做无谓的重渲染
            if _changed:
                r.mdns_updated = True
        else:
            nr = ScanResult(ip=ip, status="online",
                            discovery_method="mdns",
                            hostname=names[0].rstrip(".") if names else "")
            if services:
                nr.services.append(SVC_MDNS)
                nr.service_details.append({
                    "proto": SVC_MDNS, "port": 0,
                    "banner": ", ".join(services),
                })
            # mDNS 新发现的设备同样补一次地址库匹配（纯内存查找）
            if library_lookup is not None:
                try:
                    library_lookup(nr)
                except Exception as e:  # noqa: BLE001
                    _log.warning("地址库匹配失败（mDNS 新设备）%s: %s",
                                 ip, e, exc_info=True)
            results[ip] = nr
            added += 1
    return added


# ══════════════════════════════════════════════════════════════════════
#  发现阶段（Discovery Phase）
#
#  每个阶段只依赖 ScanContext，互不知道彼此的实现细节。
#  新增一种发现方式（LLDP / WSD …）= 新增一个 DiscoveryPhase 子类
#  并登记进 PHASES，scan() 的编排代码无需改动。
# ══════════════════════════════════════════════════════════════════════

class DiscoveryPhase:
    """发现阶段基类。"""

    name = "phase"

    def run(self, ctx: ScanContext) -> None:
        raise NotImplementedError


class PingPhase(DiscoveryPhase):
    """阶段一：ICMP 存活探测（并发）。

    在线设备一旦确认就立即交给富化流水线，与剩余 ping 并发执行 ——
    整体耗时从 "ping + enrich" 降为 "max(ping, enrich)"。
    """

    name = "ping"

    def run(self, ctx: ScanContext) -> None:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=ctx.max_threads) as ping_ex:
            futures = {}
            for ip in ctx.all_ips:
                if ctx.is_stopped():
                    break
                futures[ping_ex.submit(ping_ip, ip, ctx.timeout_ms)] = ip

            for future in concurrent.futures.as_completed(futures):
                if ctx.is_stopped():
                    break
                ip = futures[future]
                try:
                    alive, rtt, ttl = future.result()
                except Exception:  # noqa: BLE001
                    alive, rtt, ttl = False, 0.0, 0

                result = ctx.results[ip]
                result.response_time = rtt
                result.ttl = ttl
                result.status = "online" if alive else "offline"
                if alive:
                    result.discovery_method = "ping"

                ctx.completed += 1
                if ctx.progress_callback:
                    ctx.progress_callback(ctx.completed, ctx.total, ip)

                # 在线设备一旦确认，立即交给 enrich 线程池，
                # 与剩余 ping 并发执行 (流水线加速)
                if alive and not ctx.is_stopped():
                    ctx.submit_enrich(ip)


class ArpPhase(DiscoveryPhase):
    """阶段二：ARP 主动探测（仅本机直连网段）。

    发现"禁 Ping 但在线"的静默主机。SendARP 不依赖 ICMP，命中即视为在线，
    与 ping 命中的设备同样进入 enrich 流水线。
    """

    name = "arp"

    def run(self, ctx: ScanContext) -> None:
        if ctx.is_stopped():
            return
        local_subnets = get_local_subnets()
        if not local_subnets:
            return

        offline_local = []
        for ip in ctx.all_ips:
            r = ctx.results[ip]
            if r.status == "online":
                continue
            try:
                if any(ipaddress.ip_address(ip) in net for net in local_subnets):
                    offline_local.append(ip)
            except Exception as e:  # noqa: BLE001
                # 单个 IP 字面量非法（正常不会发生，范围已被校验）
                _log.debug("跳过无法解析的 IP %s: %s", ip, e)

        if not offline_local:
            return

        arp_ex = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(50, len(offline_local))
        )
        arp_futs = {arp_ex.submit(arp_ping, ip): ip for ip in offline_local}
        for f in concurrent.futures.as_completed(arp_futs):
            if ctx.is_stopped():
                break
            ip = arp_futs[f]
            try:
                mac = f.result(timeout=2.0)
            except Exception:  # noqa: BLE001
                mac = ""
            if mac:
                r = ctx.results[ip]
                r.status = "online"
                r.discovery_method = "arp"
                r.mac = mac
                r.vendor = get_mac_vendor(mac) if mac else ""
                r.response_time = 0.0
                # 进入 enrich 流水线（与 ping 命中的设备一致）
                ctx.submit_enrich(ip)
        arp_ex.shutdown(wait=False)


class MdnsPhase(DiscoveryPhase):
    """阶段三：mDNS 组播发现（本地链路）。

    发现网内"不响应 Ping/ARP"但支持 mDNS 的设备（打印机/NAS/路由器/
    Apple 设备/IoT/投屏/SMB 等）。命中设备补充主机名(mDNS 名)与服务类型，
    扫描范围之外的新设备也并入结果（标记为 mDNS 发现）。
    """

    name = "mdns"

    def run(self, ctx: ScanContext) -> None:
        if not ctx.mdns_discovery or ctx.is_stopped():
            return
        try:
            mdns_map = mdns_discover(timeout=2.5)
        except Exception as e:  # noqa: BLE001
            # 组播发现失败不影响已完成的 Ping/ARP 结果，只是少一路补充信息
            _log.debug("mDNS 组播发现失败: %s", e)
            mdns_map = {}
        _merge_mdns(ctx.results, mdns_map, ctx.library_lookup)


#: 发现阶段的执行顺序。新增发现方式只需在此登记。
PHASES = (PingPhase(), ArpPhase(), MdnsPhase())


# ══════════════════════════════════════════════════════════════════════
#  扫描器
# ══════════════════════════════════════════════════════════════════════

class NetworkScanner:
    """网络扫描器主类"""

    def __init__(self):
        self.is_scanning = False
        self._stop_flag = False

    def stop(self):
        """请求停止扫描"""
        self._stop_flag = True

    def _merge_mdns(self, results: Dict[str, ScanResult], mdns_map: dict,
                    library_lookup=None) -> int:
        """向后兼容的薄封装：真正的实现在模块级 ``_merge_mdns``。"""
        return _merge_mdns(results, mdns_map, library_lookup)

    def scan(self, ip_ranges: List[str], timeout_ms: int = 1000,
             max_threads: int = 100, scan_ports_flag: bool = False,
             protocols: List[str] = None, tcp_scan_mode: str = "connect",
             mdns_discovery: bool = True, ports: List[int] = None,
             progress_callback=None, result_callback=None,
             phase_callback=None,
             library_lookup=None, snmp_v3_user=None) -> List[ScanResult]:
        """
        扫描多个 IP 范围。

        本方法只负责**编排**：解析前置参数 → 建立 ScanContext → 依次执行
        ``PHASES`` 中的发现阶段 → 收尾。各阶段的具体行为见对应的
        ``DiscoveryPhase`` 子类。

        Args:
            ip_ranges: IP 范围字符串列表
            timeout_ms: ping 超时(毫秒)
            max_threads: 最大并发线程数
            scan_ports_flag: 是否扫描端口
            protocols: 要检测的应用层协议列表 (HTTP, HTTPS, FTP, RDP 等)
            tcp_scan_mode: 端口探测方式 connect(全连接)/syn(SYN半开)/udp(仅UDP)
            mdns_discovery: 是否在扫描末尾做 mDNS 组播发现（发现网内 IoT/打印机/NAS 等）
            progress_callback: 进度回调 (current, total, current_ip)
            result_callback: 单个结果回调 (ScanResult)
            phase_callback: 阶段切换回调 (phase_name, index, total)。在**每个阶段开始前**
                调用一次，``phase_name`` 是语言无关的规范值（如 ``"ping"``）；
                供 GUI 显示"现在在干嘛"。
            library_lookup: 地址库匹配回调 (ScanResult) -> bool，在 enrich 工作线程内
                逐台调用，用于把台账信息（位置/使用者/备注）写回结果。
                由调用方传入内存索引（见 mac_library.MacMatcher.apply_to），
                避免在 GUI 主线程逐条查 SQLite 导致大网段界面冻结。
            snmp_v3_user: SNMPv3 用户参数（scanner.snmp_v3.SnmpV3User）。
                为 None 时走 v2c 团体字探测；传入时**优先 v3**，仅在目标不响应
                时才回退 v2c。凭据/配置类错误不回退，直接留 warning 便于排查。

        Returns:
            ScanResult 列表
        """
        self.is_scanning = True
        self._stop_flag = False
        self.warnings = []  # 本次扫描的非致命告警（如 SYN 回退）

        # 解析 TCP 探测方式（syn/udp 需要原始套接字权限）
        effective_tcp_mode = _resolve_tcp_mode(tcp_scan_mode, self.warnings)

        # 解析所有 IP（含规模保护）
        all_ips, range_warnings, ok = _parse_ranges(ip_ranges)
        self.warnings.extend(range_warnings)
        if not ok or not all_ips:
            self.is_scanning = False
            return []

        ctx = ScanContext(
            self, all_ips,
            effective_tcp_mode=effective_tcp_mode,
            warnings=self.warnings,
            timeout_ms=timeout_ms,
            max_threads=max_threads,
            scan_ports_flag=scan_ports_flag,
            protocols=protocols,
            mdns_discovery=mdns_discovery,
            ports=ports,
            progress_callback=progress_callback,
            result_callback=result_callback,
            phase_callback=phase_callback,
            library_lookup=library_lookup,
            snmp_v3_user=snmp_v3_user,
        )

        try:
            _total_phases = len(PHASES)
            for _index, phase in enumerate(PHASES, start=1):
                # 阶段开始前通知一次（带 index/total，供 UI 显示"阶段 2/3"）。
                # 与 progress_callback 同属纯通知，这里不做异常隔离 —— 显示层
                # 自己的问题不该被引擎悄悄吃掉。
                if ctx.phase_callback:
                    ctx.phase_callback(phase.name, _index, _total_phases)
                phase.run(ctx)
        finally:
            # 等待所有富化完成；停止扫描时不再等待，直接返回
            ctx.wait_enrich()
            ctx.shutdown()

        # 运行时原始套接字发送被系统拒绝（如 Windows 拦截 TCP 原始发送）的回退告警
        if ctx.effective_tcp_mode in ("syn", "udp") and _C._syn_failed.is_set():
            self.warnings.append(
                tr("SYN/UDP 探测在发送阶段被系统拒绝"
                   "（Windows 需 Npcap 或以管理员运行），本次端口扫描已回退到 TCP 全连接。")
            )

        # 记录 RTT 自适应最终收敛的 connect 超时，供上层日志展示
        self.last_adaptive_timeout = ctx.port_timeout

        self.is_scanning = False
        return list(ctx.results.values())
