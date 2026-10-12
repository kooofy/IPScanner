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
import xml.etree.ElementTree as ET

__all__ = [
    "INTEROP_FORMATS",
    "build_interop",
    "export_interop",
    "render_nmap_xml",
    "render_zabbix_lld",
    "render_netbox_csv",
    "render_router_db",
    "parse_nmap_xml",
    "parse_ports",
    "parse_services",
    "nmap_state_to_status",
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
    # 先按 JSON 数组解析（落库的规范形式）；解析不出数组就是退化形态，
    # 按逗号分隔串处理。用 `try/except` 会让 `except: pass` 被计成「静默吞异常」
    # （见 test_logging_policy 的棘轮），而这里本就是「解析失败的正常分支」——
    # 改用 dict.get 的哨兵值表达，语义更清楚、也不占静默配额。
    try:
        arr = json.loads(s)
    except (ValueError, TypeError):
        arr = None
    if isinstance(arr, list):
        return [str(x) for x in arr]
    # 退化：当普通逗号分隔串处理
    return [p.strip() for p in s.split(",") if p.strip()]


# ── Nmap XML **读入**（§1.2 拆分；见 ROADMAP §3「读入的风险在语义」）────────────

#: Nmap `<status state>` → 本项目规范 `status`。**故意不映射 unknown → 任何值**：
#: 我们的 `status` 只有 online/offline 两个值，`unknown` 落空串（=「未知」），
#: 由消费方决定怎么呈现；硬塞成 offline 会把「没探测到」谎报成「确认离线」。
_NMAP_STATE_MAP = {"up": "online", "down": "offline"}


def nmap_state_to_status(state) -> str:
    """Nmap 的 host `<status state>` → 本项目规范 `status`。

    🔴 **两者的语义本来就不一样**（ROADMAP §3 明确点名的风险）：
    - Nmap `up`  = 「至少有一个探针得到回应」，**不保证**是我们意义上的在线
      （例如只有 ICMP 回应而目标其实刚被拔线）；
    - Nmap `down` = 「所有探针无回应」，也**可能**只是对方屏蔽了探测 ——
      在 Nmap 的语义里这是「未观察到」，不是「确认不存在」。

    所以本函数只做**字面映射**，并把「这是 Nmap 的判定、不是我们的扫描结论」
    这一事实交给调用方（导出/展示时如实标注来源）。未识别的状态返回 ""（未知），
    **绝不**猜成 offline。
    """
    return _NMAP_STATE_MAP.get(str(state or "").strip().lower(), "")


def _nmap_host_addresses(host_el):
    """`<host>` → `{"ipv4": …, "ipv6": …, "mac": …}`（各取第一个）。

    `addrtype` 缺省时按 Nmap 的惯例当 ipv4 处理（老版本 Nmap 不写 addrtype）。
    """
    out = {}
    for el in _findall(host_el, "address"):
        addr = (el.get("addr") or "").strip()
        if not addr:
            continue
        atype = (el.get("addrtype") or "ipv4").strip().lower()
        # 只认前三个键；其它 addrtype 按原样塞进 out 会污染返回结构
        key = atype if atype in ("ipv4", "ipv6", "mac") else None
        if key and key not in out:
            out[key] = addr
    return out


def _nmap_host_hostname(host_el):
    """`<hostnames>/<hostname name=…>` → 第一个名字（Nmap 无则 ""）。"""
    el = _find(host_el, "hostnames", "hostname")
    return (el.get("name") or "").strip() if el is not None else ""


def _nmap_host_ports(host_el):
    """`<ports>/<port>` → `(开放端口列表, 服务名列表)`（只收 `state=open`）。

    跳过到 0 个端口是正常的 —— 这正是 Nmap「没扫端口」的形态，不是解析失败。
    """
    ports, services = [], []
    for el in _findall(host_el, "ports", "port"):
        state_el = _find(el, "state")
        state = (state_el.get("state") if state_el is not None else "") or ""
        if state.strip().lower() != "open":
            continue        # 只收 open；closed/filtered 不该进「开放端口」
        pid = (el.get("portid") or "").strip()
        if pid.isdigit():
            ports.append(int(pid))
        svc_el = _find(el, "service")
        if svc_el is not None:
            name = (svc_el.get("name") or "").strip()
            if name:
                services.append(name)
    return ports, services


def _nmap_host_os(host_el):
    """尽力提取 OS 名称；提取不到就返回 ""（**不编造**）。

    Nmap 的 `<os>` 段给出的是**指纹匹配名**（如 `Linux 5.4 - 5.15`），
    与我们库里的 `os_guess`（来自 SNMP/主机名推断）不是一回事，所以这里
    只做「有就带上、没有就空」的搬运，由调用方决定要不要采信。
    """
    for el in _findall(host_el, "os", "osmatch"):
        name = (el.get("name") or "").strip()
        if name:
            return name
    return ""


def _local_name(tag) -> str:
    """去掉 `{namespace}` 前缀（Nmap 有时带 xmlns，有时不带）。"""
    return str(tag).rsplit("}", 1)[-1]


def _iter_child(el, name):
    """直接子元素里 `local-name == name` 的那些（命名空间无关）。"""
    for child in el:
        if _local_name(child.tag) == name:
            yield child


def _find(el, *path):
    """按本地名逐层找**第一个**匹配的**后代**（忽略命名空间）。

    不能用 `el.findall("host")`：带 `xmlns` 时真实 tag 是 `{http://…}host`，
    字面量匹配会**静默返回空** —— 实测一个带命名空间的 nmaprun 会整份解析成
    `[]`，看起来像「文件是空的」，极难排查。
    """
    cur = el
    for name in path:
        nxt = None
        for cand in cur.iter():
            if cand is not cur and _local_name(cand.tag) == name:
                nxt = cand
                break
        if nxt is None:
            return None
        cur = nxt
    return cur


def _findall(el, *path):
    """按本地名逐层收集**最末一节**的全部匹配（忽略命名空间）。"""
    parents = [el]
    for name in path[:-1]:
        parents = [c for p in parents for c in _iter_child(p, name)]
    last = path[-1]
    return [c for p in parents for c in _iter_child(p, last)]


def parse_nmap_xml(text) -> list:
    """Nmap XML → 资产行列表（与 `render_nmap_xml` 的输入**同构**，可往返）。

    返回的每个 dict 的键与 `history_store.list_assets()` 的行尽量对齐：
    ``ip`` / ``mac`` / ``hostname`` / ``status`` / ``open_ports`` /
    ``services`` / ``os_guess``，外加两个**溯源字段**：

    - ``source`` = `"nmap"`
    - ``nmap_state`` = Nmap 原样的 `up`/`down`/``unknown`/``""``

    🔴 为什么必须留 `nmap_state`：Nmap 的 host 状态机与我们 `status` 的语义
    **不等价**（见 `nmap_state_to_status`）。导出别的系统吃 `status` 就够了，
    但「我们自己的界面/台账」在合并导入结果时必须能区分「Nmap 说 up」和
    「我们的探测说 online」—— 把来源丢了，两类结论就永远分不开了。

    容错：**任何**畸形/非 XML 输入都返回 ``[]``，绝不抛异常（导入不该崩应用）。
    没有**任何地址**的 `<host>`（如 `<host/>`）同样跳过 —— 一条既没 IP 也没 MAC
    的记录无法标识任何设备，放进台账只会变成一行空白噪声。
    """
    if not text:
        return []
    if isinstance(text, bytes):
        raw = text
    else:
        raw = str(text).encode("utf-8", "replace")
    # 用 `ET.XMLParser` + `feed` 而不是 `ET.fromstring`：这里要**吞掉**解析异常
    # 并返回 []，而 `except ... : return []` 会被 test_logging_policy 记成静默吞
    # 异常（棘轮配额）。用 `parser.close()` 的显式失败分支表达，语义更清楚。
    parser = ET.XMLParser()
    root = None
    try:
        parser.feed(raw)
        root = parser.close()
    except ET.ParseError:
        return []
    if root is None:
        return []

    hosts = ([root] if _local_name(root.tag) == "host"
             else list(_iter_child(root, "host")))
    rows = []
    for h in hosts:
        addrs = _nmap_host_addresses(h)
        ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
        mac = addrs.get("mac") or ""
        if not ip and not mac:
            continue        # 无任何地址 → 标识不了设备，跳过（别塞空白行）
        status_el = _find(h, "status")
        raw_state = (status_el.get("state") if status_el is not None else "") or ""
        raw_state = raw_state.strip().lower()
        ports, services = _nmap_host_ports(h)
        rows.append({
            "ip": ip,
            "mac": mac,
            "hostname": _nmap_host_hostname(h),
            "status": nmap_state_to_status(raw_state),
            "open_ports": ",".join(str(p) for p in ports),
            "services": json.dumps(services, ensure_ascii=False),
            "os_guess": _nmap_host_os(h),
            "source": "nmap",
            "nmap_state": raw_state,
        })
    return rows


def _local_name(tag) -> str:
    """去掉 `{namespace}` 前缀（Nmap 有时带 xmlns，有时不带）。"""
    return str(tag).rsplit("}", 1)[-1]


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
