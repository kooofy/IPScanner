"""资产表（assets）的四种互操作导出格式 —— v1.9 §1.2。

本模块是「资产表」的第一个消费方：**纯读（调用方传入行）+ 纯写文件**，
零网络、零新依赖、零 PyQt、零 `tr()`。

设计铁律（见 `docs/ROADMAP_V1.9.md` §1.2）：
- 导出的**值**必须是规范值（`status` → online/offline，`device_class` → 中文源串），
  **绝不落 `tr()` 之后的展示串**。导出文件会被别的系统解析，落展示串 = 静默破坏。
- 四种格式都做成**逐字节可钉死**的纯函数（golden file 测试），格式漂移会被测试抓住。
- 0 台设备时产出**合法的空文档**（合法 XML 根 / 带表头的 CSV / `{"data":[]}` /
  空 `router.db`），不是空文件、不是畸形 XML。

输入约定：每个 row 是 `history_store.list_assets()` 返回的一台设备字典，
键见 `list_assets` 文档。本模块不依赖 history_store，便于单测直接喂样例行。

格式：
- nmap      → Nmap XML（`nmap.xml`），含 `<host>/<address>/<hostnames>/<ports>`，
              `<status state="up|down"/>`。⚠ **不编 `<os>`**（只有 os_guess，无可靠指纹，
              编 `<osmatch>` 是撒谎 —— 延续「诚实降级」原则）。
- zabbix    → Zabbix LLD JSON（`zabbix_lld.json`），`{"data":[{ "{#IP}":…, … }]}`。
- netbox    → NetBox 设备 CSV importer（`netbox.csv`），表头与官方一致；
              `device_type` = "Manufacturer Model"（vendor + device_class），
              `device_role` ← device_class，`site` ← location，`status` ← Active/Offline
              （外键按名字解析，导入前在 NetBox 里建好对应对象）。
- oxidized   → Oxidized `router.db`（`name:model:group`，model ← device_class，
              group ← location）。
"""

from __future__ import annotations

import csv
import io
import json

__all__ = [
    "INTEROP_FORMATS",
    "build_interop",
    "export_interop",
    "render_nmap_xml",
    "render_zabbix_lld",
    "render_netbox_csv",
    "render_router_db",
    "parse_ports",
    "parse_services",
]

#: CLI / GUI 暴露的格式名（小写）。
INTEROP_FORMATS = ("nmap", "zabbix", "netbox", "oxidized")

#: 常见端口 → Nmap 风格服务名（用于 nmap.xml 的 `<service name>`）。
# 没命中的端口落 "unknown"（与 Nmap 未指纹时的行为一致，诚实不撒谎）。
_COMMON_PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 113: "ident", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "ms-sql-s", 1521: "oracle", 1723: "pptp",
    1812: "radius", 1813: "radius-acct", 2049: "nfs", 3128: "squid-http",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 5985: "wsman", 5986: "wsman", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

#: NetBox 设备 CSV importer 的表头（顺序即导出顺序）。
# 必填列 name/device_type/device_role/site/status 放最前，与官方一致。
NETBOX_HEADER = [
    "name", "device_type", "device_role", "site", "status",
    "serial", "asset_tag", "platform", "comments",
]


# ── 解析辅助（把落库的文本形式还原成结构）──────────────────────────────────────

def parse_ports(value) -> list:
    """open_ports 文本（逗号分隔端口号，或 ''）→ 升序整数列表。

    容错：list 输入原样转 int；非数字片段丢弃；空 → []。
    """
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        out = []
        for x in value:
            s = str(x).strip()
            if s.isdigit():
                out.append(int(s))
        return out
    s = str(value).strip()
    if not s:
        return []
    out = []
    for p in s.split(","):
        p = p.strip()
        if p.isdigit():
            out.append(int(p))
    return out


def parse_services(value) -> list:
    """services 文本（JSON 数组字符串，或 ''）→ 字符串列表。

    落库形式是 JSON（见 `history_store._services_to_text`）；这里也能吃退化形态
    （纯逗号分隔串）。空 → []。
    """
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    s = str(value).strip()
    if not s:
        return []
    try:
        arr = json.loads(s)
        if isinstance(arr, list):
            return [str(x) for x in arr]
    except (ValueError, TypeError):
        pass
    # 退化：当普通逗号分隔串处理
    return [p.strip() for p in s.split(",") if p.strip()]


# ── 小工具 ─────────────────────────────────────────────────────────────────────

def _xml_escape(s) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;"))


def _display_name(row) -> str:
    """导出里用于「设备名」的回退链：hostname → ip → identity_key。"""
    return (row.get("hostname") or row.get("ip")
            or row.get("identity_key") or "")


def _netbox_status(canonical) -> str:
    """online → Active，offline → Offline，未知/空 → Active（NetBox 默认状态）。"""
    if canonical == "offline":
        return "Offline"
    return "Active"


def _netbox_comments(row, services, ports) -> str:
    """把「没对应 NetBox 列」的信息塞进 comments，诚实且可读。"""
    parts = []
    if row.get("os_guess"):
        parts.append("OS: " + row["os_guess"])
    if services:
        parts.append("Services: " + ", ".join(services))
    if ports:
        parts.append("Ports: " + ", ".join(str(p) for p in ports))
    if row.get("user"):
        parts.append("User: " + row["user"])
    if row.get("remark"):
        parts.append(row["remark"])
    return "; ".join(parts)


# ── 渲染（纯函数，返回 str；编码在 build_interop 里统一处理）─────────────────────

def render_nmap_xml(rows) -> str:
    """渲染 Nmap XML。逐字节确定（无时间戳），便于 golden file。

    ⚠ 不编 `<os>`：我们只有 os_guess，没有可靠 OS 指纹，编 `<osmatch>` 是撒谎。
    """
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<nmaprun scanner="IPScanner" version="1.0">',
    ]
    for r in rows:
        lines.append("  <host>")
        status = r.get("status")
        state = ("up" if status == "online"
                 else "down" if status == "offline" else "unknown")
        lines.append('    <status state="%s"/>' % _xml_escape(state))

        ip = r.get("ip") or ""
        if ip:
            lines.append('    <address addr="%s" addrtype="ipv4"/>'
                         % _xml_escape(ip))
        mac = r.get("mac") or ""
        if mac:
            lines.append('    <address addr="%s" addrtype="mac"/>'
                         % _xml_escape(mac))

        host = r.get("hostname") or ""
        if host:
            lines.append('    <hostnames><hostname name="%s"/></hostnames>'
                         % _xml_escape(host))
        else:
            lines.append("    <hostnames/>")

        lines.append("    <ports>")
        for p in parse_ports(r.get("open_ports")):
            svc = _COMMON_PORT_SERVICES.get(p, "unknown")
            lines.append(
                '      <port portid="%d">'
                '<state state="open" reason="open" reason_ttl="0"/>'
                '<service name="%s"/></port>'
                % (p, _xml_escape(svc))
            )
        lines.append("    </ports>")
        # 诚实降级：故意不输出 <os> 段
        lines.append("  </host>")
    lines.append("</nmaprun>")
    return "\n".join(lines) + "\n"


def render_zabbix_lld(rows) -> str:
    """渲染 Zabbix LLD（低级别发现）JSON：`{"data":[{ "{#MACRO}":值, … }]}`。"""
    data = []
    for r in rows:
        services = parse_services(r.get("services"))
        ports = parse_ports(r.get("open_ports"))
        data.append({
            "{#IP}": r.get("ip") or "",
            "{#HOSTNAME}": _display_name(r),
            "{#MAC}": r.get("mac") or "",
            "{#DEVICE.CLASS}": r.get("device_class") or "",
            "{#VENDOR}": r.get("vendor") or "",
            "{#STATUS}": r.get("status") or "",
            "{#LOCATION}": r.get("location") or "",
            "{#OS}": r.get("os_guess") or "",
            "{#SERVICES}": ", ".join(services),
            "{#PORTS}": ", ".join(str(p) for p in ports),
        })
    # ensure_ascii=False 保留中文设备类型/厂商；indent=2 便于人工 diff。
    return json.dumps({"data": data}, ensure_ascii=False, indent=2) + "\n"


def render_netbox_csv(rows) -> str:
    """渲染 NetBox 设备 CSV importer 格式（表头与官方一致）。

    外键按名字解析（导入前在 NetBox 建好对应对象）：
    - device_type = "Manufacturer Model" → vendor + ' ' + device_class
    - device_role ← device_class
    - site        ← location
    - status      ← Active/Offline
    - platform    ← os_guess（便于映射到 NetBox platform）
    """
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(NETBOX_HEADER)
    for r in rows:
        services = parse_services(r.get("services"))
        ports = parse_ports(r.get("open_ports"))
        name = _display_name(r)
        vendor = r.get("vendor") or ""
        dclass = r.get("device_class") or ""
        # NetBox device_type 格式即 "Manufacturer Model"
        device_type = (vendor + " " + dclass).strip()
        w.writerow([
            name,
            device_type,
            dclass,                       # device_role
            r.get("location") or "",      # site（外键，按名字）
            _netbox_status(r.get("status")),
            "",                           # serial：资产表无此列
            "",                           # asset_tag：资产表无此列
            r.get("os_guess") or "",      # platform（外键，按名字）
            _netbox_comments(r, services, ports),
        ])
    return buf.getvalue()


def render_router_db(rows) -> str:
    """渲染 Oxidized `router.db`：`name:model:group` 每行。

    model ← device_class（资产表直接有，优先于拓扑节点的 model）；
    group ← location（空 → "default"，Oxidized 要求 group 非空）。
    0 行 → 空字符串（合法的空 router.db，不是畸形文件）。
    """
    lines = []
    for r in rows:
        name = _display_name(r)
        model = r.get("device_class") or "unknown"
        group = r.get("location") or "default"
        lines.append("%s:%s:%s" % (name, model, group))
    return "\n".join(lines) + ("\n" if lines else "")


# ── 分发器 ─────────────────────────────────────────────────────────────────────

def build_interop(fmt, rows) -> bytes:
    """把资产行渲染成指定格式的**字节**（编码随格式而定）。

    纯函数、无副作用，便于 golden file 测试直接比对字节。
    """
    fmt = (fmt or "").lower()
    if fmt == "nmap":
        return render_nmap_xml(rows).encode("utf-8")
    if fmt == "zabbix":
        return render_zabbix_lld(rows).encode("utf-8")
    if fmt == "netbox":
        # CSV 带 BOM，与 excel_handler.export_csv 一致（Excel 友好）。
        return render_netbox_csv(rows).encode("utf-8-sig")
    if fmt == "oxidized":
        return render_router_db(rows).encode("utf-8")
    raise ValueError(
        "不支持的导出格式：%r（可选：%s）" % (fmt, "/".join(INTEROP_FORMATS))
    )


def export_interop(fmt, rows, path) -> None:
    """渲染并写入磁盘。CLI / GUI 统一入口。"""
    data = build_interop(fmt, rows)
    with open(path, "wb") as f:
        f.write(data)
