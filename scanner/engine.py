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

from .classify import infer_device
from .constants import (PROTOCOL_PORTS, SVC_HTTP, SVC_HTTPS, SVC_SNMP, SVC_MDNS, SVC_SMB)
from .dns import get_netbios_name, mdns_discover, resolve_hostname
from .http import _read_ftp_banner, _read_http, _read_https_banner, _read_ssh_banner, _read_upnp_device_name
from .models import ScanResult
from .osfp import _match_tcp_stack, _os_detail_from_banners, _tcp_stack_probe, guess_os_from_ttl
from .ping import arp_ping, get_local_subnets, get_mac_for_ip, ping_ip
from .ports import raw_capability, scan_port, scan_ports, scan_shares
from .range import (parse_ip_range, count_ip_range, RangeTooLarge,
                    MAX_IPS_PER_RANGE, MAX_IPS_TOTAL)
from .snmp import snmp_get_system
from .snmp_v3 import snmp_v3_get_system, ERR_NO_RESPONSE
from app_logging import get_logger
from i18n import tr

# 扫描编排层的异常大多是"单台设备/单个环节失败"，不应影响整批扫描，
# 但必须留痕 —— 否则用户只看到"结果少了几个字段"，无从判断原因。
_log = get_logger(__name__)


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

    def scan(self, ip_ranges: List[str], timeout_ms: int = 1000,
             max_threads: int = 100, scan_ports_flag: bool = False,
             protocols: List[str] = None, tcp_scan_mode: str = "connect",
             mdns_discovery: bool = True, ports: List[int] = None,
             progress_callback=None, result_callback=None,
             library_lookup=None, snmp_v3_user=None) -> List[ScanResult]:
        """
        扫描多个 IP 范围。

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
        self.warnings: List[str] = []  # 本次扫描的非致命告警（如 SYN 回退）

        # 解析 TCP 探测方式：syn/udp 需要原始套接字权限
        effective_tcp_mode = "connect"
        if tcp_scan_mode in ("syn", "udp"):
            avail, reason = raw_capability()
            if avail:
                effective_tcp_mode = tcp_scan_mode
                # 重新尝试发送（之前若失败则重置，便于本次重新验证）
                global _syn_failed
                _syn_failed = False
            else:
                self.warnings.append(
                    f"{'SYN' if tcp_scan_mode == 'syn' else tr('UDP')} 探测需要管理员权限"
                    f"（Windows 还需 Npcap），已回退到 TCP 全连接扫描。{reason}"
                )

        # 解析所有 IP（含规模保护：先只计数，超限时在构建任何列表之前就拒绝，
        # 否则 0.0.0.0/0 会先 append 出 42.9 亿个字符串把进程撑爆）
        all_ips = []
        for r in ip_ranges:
            n = count_ip_range(r)
            if n <= 0:
                continue
            if n > MAX_IPS_PER_RANGE:
                self.is_scanning = False
                self.warnings.append(
                    f"范围「{r}」包含 {n} 个 IP，超过单次上限 {MAX_IPS_PER_RANGE} 个，已中止本次扫描。"
                    f"请拆分为更小的范围（如按 /24 分批）后重试。"
                )
                return []
            if len(all_ips) + n > MAX_IPS_TOTAL:
                self.is_scanning = False
                self.warnings.append(
                    f"扫描范围合计将超过 {MAX_IPS_TOTAL} 个 IP（超出项：「{r}」），已中止本次扫描。"
                    f"请缩小范围后重试。"
                )
                return []
            try:
                all_ips.extend(parse_ip_range(r))
            except RangeTooLarge as e:      # 兜底：与上面的计数判断保持一致
                self.is_scanning = False
                self.warnings.append(str(e))
                return []

        if not all_ips:
            self.is_scanning = False
            return []

        total = len(all_ips)
        results: Dict[str, ScanResult] = {ip: ScanResult(ip=ip) for ip in all_ips}
        completed = 0

        # Phase 1 + Phase 3 流水线：ping 与在线设备的富化(enrich)并发执行。
        # 富化阶段的 DNS / NetBIOS / 端口探测都是 I/O 密集型，可完全隐藏在 ping 等待时间内，
        # 整体扫描耗时从 "ping 耗时 + enrich 耗时" 降为 "max(ping 耗时, enrich 耗时)"。
        # 构建协议端口映射 (协议名 -> 端口号)；SNMP 为 UDP 设备识别，单独开关
        proto_port_map = {}
        snmp_enabled = False
        if protocols:
            for proto in protocols:
                proto_upper = proto.upper()
                if proto_upper == SVC_SNMP:
                    snmp_enabled = True
                elif proto_upper in PROTOCOL_PORTS:
                    proto_port_map[proto_upper] = PROTOCOL_PORTS[proto_upper]

        # NetBIOS 解析共用线程池，使其与 DNS 解析并发而非串行等待
        _netbios_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(10, min(50, len(all_ips)))
        )

        # RTT 自适应超时（仅 TCP connect 模式）状态机
        _rtt_window = []
        _port_timeout = 0.5
        self.last_adaptive_timeout = 0.5

        def _on_rtt(rtt):
            if rtt <= 0:
                return
            _rtt_window.append(rtt)
            if len(_rtt_window) > _RTT_WIN:
                _rtt_window.pop(0)
            nonlocal _port_timeout
            _port_timeout = adaptive_timeout_from_samples(_rtt_window)

        def enrich_device(ip: str):
            """富化单个在线设备：MAC / 厂商 / 主机名 / 端口 / 服务。"""
            if self._stop_flag:
                return
            result = results[ip]

            # RTT 自适应超时（仅 TCP connect 模式）：用已探设备的开放端口 connect
            # 耗时估计网络延迟，滚动窗口中位数动态夹紧 connect 超时，局域网可显著提速。
            _pto = _port_timeout if effective_tcp_mode == "connect" else 0.5

            # MAC 地址：优先保留已获取的 MAC（如 ARP 主动探测所得），
            # 否则 per-IP 查询 ARP 缓存（对刚 ping 通的在线主机可靠）
            if not result.mac:
                result.mac = get_mac_for_ip(ip)
            mac = result.mac

            # 厂商识别 (通过 MAC OUI)
            if mac:
                result.vendor = get_mac_vendor(mac)

            # 端口 & 服务探测 (与本机名解析并行执行)
            if scan_ports_flag:
                result.scan_method = effective_tcp_mode
                result.open_ports = scan_ports(
                    ip, ports=ports, timeout=_pto, mode=effective_tcp_mode,
                    rtt_callback=_on_rtt if effective_tcp_mode == "connect" else None,
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
            if proto_port_map:
                proto_ports = list(proto_port_map.values())
                detected_proto_ports = scan_ports(
                    ip, ports=proto_ports, timeout=_pto,
                    rtt_callback=_on_rtt if effective_tcp_mode == "connect" else None,
                )
                for proto, port in proto_port_map.items():
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
                            detail["banner"] = _read_https_banner(ip, port, 1.2)
                        svc_details.append(detail)
                        # 如果没开完整端口扫描，也把协议端口加入开放端口列表
                        if not scan_ports_flag and port not in result.open_ports:
                            result.open_ports.append(port)
                            result.open_ports.sort()
            result.services = svc_list
            result.service_details = svc_details

            # 主机名：DNS 解析 (resolve_hostname 自带 1-worker 线程池，在设备线程内执行)
            # 与 NetBIOS 解析 (_netbios_executor) 并发，任一命中即可
            hostname = resolve_hostname(ip, timeout=1.0)
            if not hostname:
                try:
                    hostname = _netbios_executor.submit(
                        get_netbios_name, ip, 2.0
                    ).result(timeout=2.0)
                except Exception as e:  # noqa: BLE001
                    # 超时或 NetBIOS 不可达：主机名留空属正常结果，仅记 debug
                    _log.debug("NetBIOS 主机名兜底查询失败 %s: %s", ip, e)
            result.hostname = hostname

            # SNMP 设备识别 (交换机/AP/打印机等)：取 sysDescr/sysName，
            # 作为主机名兜底，并把 "SNMP" 加入服务列表
            if snmp_enabled:
                snmp_info, _snmp_error = _identify_snmp(ip, snmp_v3_user)
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
            if not smb_open and not scan_ports_flag:
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

            # 设备指纹深度：综合厂商/端口/服务(mDNS/UPnP/SNMP)/OS 推断设备类别与型号
            result.device_class, result.device_model = infer_device(result)

            # 地址库匹配：由调用方传入的内存索引回调，在 enrich 工作线程内完成。
            # 放在最后是因为台账字段与指纹字段互不覆盖；失败不影响扫描结果。
            if library_lookup is not None:
                try:
                    library_lookup(result)
                except Exception as e:  # noqa: BLE001
                    # 地址库匹配失败只丢台账字段（位置/使用人/备注），不影响扫描
                    _log.warning("地址库匹配失败 %s: %s", ip, e, exc_info=True)

            if result_callback:
                result_callback(result)

        # enrich 并发度：主机名/NetBIOS/端口探测均为 I/O 密集，可安全提高到 50
        _enrich_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(50, max(1, len(all_ips)))
        )
        _enrich_futures = []

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ping_ex:
                futures = {}
                for ip in all_ips:
                    if self._stop_flag:
                        break
                    futures[ping_ex.submit(ping_ip, ip, timeout_ms)] = ip

                for future in concurrent.futures.as_completed(futures):
                    if self._stop_flag:
                        break
                    ip = futures[future]
                    try:
                        alive, rtt, ttl = future.result()
                    except Exception:
                        alive, rtt, ttl = False, 0.0, 0

                    result = results[ip]
                    result.response_time = rtt
                    result.ttl = ttl
                    result.status = "online" if alive else "offline"
                    if alive:
                        result.discovery_method = "ping"

                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total, ip)

                    # 在线设备一旦确认，立即交给 enrich 线程池，
                    # 与剩余 ping 并发执行 (流水线加速)
                    if alive and not self._stop_flag:
                        _enrich_futures.append(
                            _enrich_executor.submit(enrich_device, ip)
                        )

            # ── Phase 2: ARP 主动探测（仅本机直连网段）──
            # 发现"禁 Ping 但在线"的静默主机。SendARP 不依赖 ICMP，
            # 命中即视为在线，与 ping 命中的设备同样进入 enrich 流水线。
            if not self._stop_flag:
                local_subnets = get_local_subnets()
                if local_subnets:
                    offline_local = []
                    for ip in all_ips:
                        r = results[ip]
                        if r.status == "online":
                            continue
                        try:
                            if any(ipaddress.ip_address(ip) in net for net in local_subnets):
                                offline_local.append(ip)
                        except Exception as e:  # noqa: BLE001
                            # 单个 IP 字面量非法（正常不会发生，范围已被校验）
                            _log.debug("跳过无法解析的 IP %s: %s", ip, e)

                    if offline_local:
                        arp_ex = concurrent.futures.ThreadPoolExecutor(
                            max_workers=min(50, len(offline_local))
                        )
                        arp_futs = {
                            arp_ex.submit(arp_ping, ip): ip for ip in offline_local
                        }
                        for f in concurrent.futures.as_completed(arp_futs):
                            if self._stop_flag:
                                break
                            ip = arp_futs[f]
                            try:
                                mac = f.result(timeout=2.0)
                            except Exception:
                                mac = ""
                            if mac:
                                r = results[ip]
                                r.status = "online"
                                r.discovery_method = "arp"
                                r.mac = mac
                                r.vendor = get_mac_vendor(mac) if mac else ""
                                r.response_time = 0.0
                                # 进入 enrich 流水线（与 ping 命中的设备一致）
                                _enrich_futures.append(
                                    _enrich_executor.submit(enrich_device, ip)
                                )
                        arp_ex.shutdown(wait=False)

            # ── Phase 3: mDNS 组播发现（本地链路）──
            # 发现网内"不响应 Ping/ARP"但支持 mDNS 的设备（打印机/NAS/路由器/
            # Apple 设备/IoT/投屏/SMB 等）。命中设备补充主机名(mDNS 名)与服务类型，
            # 扫描范围之外的新设备也并入结果（标记为 mDNS 发现）。
            if mdns_discovery and not self._stop_flag:
                try:
                    mdns_map = mdns_discover(timeout=2.5)
                except Exception as e:  # noqa: BLE001
                    # 组播发现失败不影响已完成的 Ping/ARP 结果，只是少一路补充信息
                    _log.debug("mDNS 组播发现失败: %s", e)
                    mdns_map = {}
                self._merge_mdns(results, mdns_map, library_lookup)
        finally:
            # 等待所有富化完成；停止扫描时不再等待，直接返回
            if not self._stop_flag:
                for f in _enrich_futures:
                    try:
                        f.result()
                    except Exception as e:  # noqa: BLE001
                        # enrich 阶段单台设备失败：该设备结果字段会缺失，
                        # 记 warning 便于定位是哪台、哪一步
                        _log.warning("设备信息富化失败: %s", e, exc_info=True)
            _enrich_executor.shutdown(wait=False)
            _netbios_executor.shutdown(wait=False)

        # 运行时原始套接字发送被系统拒绝（如 Windows 拦截 TCP 原始发送）的回退告警
        if effective_tcp_mode in ("syn", "udp") and _syn_failed:
            self.warnings.append(
                tr("SYN/UDP 探测在发送阶段被系统拒绝" "（Windows 需 Npcap 或以管理员运行），本次端口扫描已回退到 TCP 全连接。")
            )

        # 记录 RTT 自适应最终收敛的 connect 超时，供上层日志展示
        self.last_adaptive_timeout = _port_timeout

        self.is_scanning = False
        return list(results.values())
