# -*- coding: utf-8 -*-
"""跨网段取 MAC 的参考实现：SNMP 读三层设备的 ARP 表（ipNetToMediaTable）。

为什么需要它
------------
MAC 是二层概念，只能靠 ARP 在**同一个广播域**内学到。扫描机在
10.193.28.0/22、目标在 10.193.24.0/24 时，ICMP 能通（经网关三层转发），
但本机 ARP 表里永远只有网关的 MAC —— 目标设备的 MAC 拿不到。

出路是**换一台"看得见"这些设备的机器去读 ARP 表**：持有 10.193.24.0/24
三层接口的那台路由器 / 三层交换机（通常就是本机默认网关）。它要转发数据包，
就必须自己 ARP 出目标的 MAC，于是它的 ARP 表里有完整的 IP → MAC。

关键 OID
--------
- ipNetToMediaPhysAddress  1.3.6.1.2.1.4.22.1.2   （RFC 1213，老而广）
  值是 6 字节 OCTET STRING = MAC；**索引后缀自带 IP**：
  `<ifIndex>.<a>.<b>.<c>.<d>` ⇒ 一次 walk 就能拿到 IP→MAC，不必再走
  ipNetToMediaNetAddress 那一列。
- ipNetToPhysicalPhysAddress 1.3.6.1.2.1.4.35.1.4 （RFC 4293，新设备）
  索引为 `<ifIndex>.<addrType>.<addrLen>.<addr…>.<addressType>`，作为回退。

用法
----
    python tools/snmp_arp_probe.py 10.193.31.254
    python tools/snmp_arp_probe.py 10.193.31.254 --range 10.193.24.0/24
    python tools/snmp_arp_probe.py 10.193.31.254 -c public -c private

只读（GETNEXT），不写任何设备配置；纯标准库，复用 scanner.snmp 的 BER 编解码。
"""
import argparse
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.snmp import snmp_get_system, snmp_walk  # noqa: E402

_OID_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"
_OID_NET_TO_PHYSICAL_PHYS = "1.3.6.1.2.1.4.35.1.4"

_TAG_OCTET_STRING = 0x04


def _mac_from_bytes(vbytes) -> str:
    """6 字节 OCTET STRING → "aa:bb:cc:dd:ee:ff"；全零 / 长度不符返回空串。"""
    if len(vbytes) != 6:
        return ""
    if vbytes == b"\x00" * 6:
        return ""
    return ":".join(f"{b:02x}" for b in vbytes)


def _suffix_to_ip_v1213(suffix: str) -> str:
    """ipNetToMediaTable 索引后缀 = ``<ifIndex>.<a>.<b>.<c>.<d>``。"""
    parts = suffix.split(".")
    if len(parts) < 5:
        return ""
    try:
        octets = [int(p) for p in parts[-4:]]
    except ValueError:
        return ""
    if any(not 0 <= o < 256 for o in octets):
        return ""
    return ".".join(str(o) for o in octets)


def _suffix_to_ip_v4293(suffix: str) -> str:
    """ipNetToPhysicalTable 索引后缀里挑出 IPv4 的 InetAddress 部分。

    形如 ``<ifIndex>.1.4.<a>.<b>.<c>.<d>.<addressType>``（addrType=1 为 ipv4，
    紧跟的长度字节为 4）。这里扫描一遍而不是定长切片，容忍 ifIndex 位数变化。
    """
    parts = suffix.split(".")
    for i in range(len(parts) - 6):
        if parts[i + 1] != "1" or parts[i + 2] != "4":
            continue
        try:
            octets = [int(p) for p in parts[i + 3:i + 7]]
        except ValueError:
            continue
        if all(0 <= o < 256 for o in octets):
            return ".".join(str(o) for o in octets)
    return ""


def _walk_arp_table(host: str, community: str, timeout: float, port: int,
                    max_iterations: int = 5000):
    """返回 ``({ip: mac}, 来源 MIB 名)``；取不到时来源为空串。"""
    for base_oid, parse, label in (
        (_OID_NET_TO_MEDIA_PHYS, _suffix_to_ip_v1213, "ipNetToMediaTable (RFC 1213)"),
        (_OID_NET_TO_PHYSICAL_PHYS, _suffix_to_ip_v4293, "ipNetToPhysicalTable (RFC 4293)"),
    ):
        raw = snmp_walk(host, base_oid, community=community, timeout=timeout,
                        port=port, max_iterations=max_iterations)
        prefix = base_oid + "."
        table = {}
        for oid, (vbytes, vtag) in (raw or {}).items():
            if not oid.startswith(prefix) or vtag != _TAG_OCTET_STRING:
                continue
            ip = parse(oid[len(prefix):])
            mac = _mac_from_bytes(vbytes)
            if ip and mac:
                table[ip] = mac
        if table:
            return table, label
    return {}, ""


def _in_range(ip: str, nets) -> bool:
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="SNMP 读三层设备 ARP 表（跨网段取 MAC 的参考实现）")
    ap.add_argument("host", help="持有目标网段三层接口的设备 IP（通常=本机默认网关）")
    ap.add_argument("-c", "--community", action="append", default=None,
                    help="SNMP v2c 团体字，可重复（默认依次试 public / 空串）")
    ap.add_argument("--range", action="append", default=None, dest="ranges",
                    metavar="范围",
                    help="只显示落在该范围内的条目，如 10.193.24.0/24（可重复）")
    ap.add_argument("--timeout", type=float, default=1.5, metavar="秒")
    ap.add_argument("--port", type=int, default=161)
    args = ap.parse_args(argv)

    communities = args.community or ["public", ""]

    nets = []
    for r in (args.ranges or []):
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            print(f"[!] 无法解析范围: {r}", file=sys.stderr)
            return 2

    print(f"目标设备: {args.host}:{args.port}")
    sys_info = snmp_get_system(args.host, communities=communities,
                               timeout=args.timeout, port=args.port)
    if sys_info:
        print(f"  sysName : {sys_info.get('sys_name', '')}")
        print(f"  sysDescr: {(sys_info.get('sys_descr', '') or '').splitlines()[0][:80]}")
    else:
        print("  [!] 取不到 sysDescr/sysName（可能是团体字不对或设备未开 SNMP）")

    for community in communities:
        table, source = _walk_arp_table(args.host, community, args.timeout, args.port)
        if table:
            shown = {ip: mac for ip, mac in table.items() if _in_range(ip, nets)}
            print(f"\n[+] 团体字 {community!r} 命中，来源 {source}")
            print(f"    ARP 表共 {len(table)} 条，其中匹配本次过滤的 {len(shown)} 条：\n")
            for ip in sorted(shown, key=lambda s: tuple(int(x) for x in s.split("."))):
                print(f"    {ip:<16} {shown[ip]}")
            return 0

    print("\n[-] 所有团体字都没拿到 ARP 表。逐条排查：")
    print("    1. 设备是否开了 SNMP，且团体字正确（-c 指定）")
    print("    2. UDP 161 是否可达（本机与设备之间没有被 ACL / 防火墙拦）")
    print("    3. 该设备是否支持 ipNetToMediaTable（纯二层交换机可能只支持")
    print("       BRIDGE-MIB，那张表只有 MAC 没有 IP —— 得换成持有目标网段")
    print("       三层接口的路由器 / 三层交换机来查）")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
