# -*- coding: utf-8 -*-
import ctypes
import locale
import platform
import re
import threading
from i18n import tr

"""
扫描引擎常量：端口映射、扫描级别、OUI 分类提示等。
"""


_IS_WINDOWS = platform.system() == "Windows"


_CMD_ENCODING = None


if _IS_WINDOWS:
    try:
        cp = ctypes.windll.kernel32.GetConsoleOutputCP()
        _CMD_ENCODING = "utf-8" if cp == 65001 else (f"cp{cp}" if cp else "gbk")
    except Exception:
        # 回退到 locale，并把"纯 utf-8"当作 GBK（兼容 Python 3.13 UTF-8 模式）
        try:
            enc = locale.getpreferredencoding(False)
            _CMD_ENCODING = enc if enc and enc.lower() not in ("utf-8", "utf8") else "gbk"
        except Exception:
            _CMD_ENCODING = "gbk"


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]


# ── 扫描级别：端口范围（对齐 nmap 的 -F / 默认 / -p- 精神） ──
#   quick   : 当前高频服务端口（最常用 21 个），日常巡检
#   standard: 1-1023 知名端口（≈ nmap top 1000 精神）
#   all     : 1-65535 全端口（安全评估，最慢）
SCAN_LEVELS = ("quick", "standard", "all")

# 扫描级别显示名：惰性翻译。
# 旧实现用 SCAN_LEVEL_LABELS = {"quick": tr("快速 (21)"), ...}，tr() 在 import 期
# 就被求值并冻结，切换语言后菜单文字不会变（需重启进程才生效）。
_SCAN_LEVEL_TEXT = {
    "quick": "快速 (21)",
    "standard": "标准 (1023)",
    "all": "全端口 (65535)",
}


def scan_level_label(level: str) -> str:
    """扫描级别代码 -> 当前语言的显示名（惰性翻译）。"""
    text = _SCAN_LEVEL_TEXT.get(level)
    return tr(text) if text else str(level)


def get_ports_for_level(level: str):
    """按扫描级别返回端口列表（按需生成，不常驻大列表）。

    quick（默认）/ 未识别级别 -> COMMON_PORTS（向后兼容当前行为）。
    standard -> 1-1023 知名端口；all -> 1-65535 全端口。
    """
    if level == "standard":
        return list(range(1, 1024))
    if level == "all":
        return list(range(1, 65536))
    # quick 与未识别：当前高频服务端口
    return COMMON_PORTS



# ── 开放端口列显示：Top N 合并，避免漏扫目标开几百端口撑爆表格 ──
PORT_DISPLAY_TOP_N = 20


def format_ports_display(ports, top_n: int = PORT_DISPLAY_TOP_N):
    """把开放端口列表格式化为 (显示文本, 完整文本)。

    端口数 <= top_n：显示文本 == 完整文本（逗号拼接）。
    超出：显示文本截断为前 top_n 个并追加 ", +N more"，完整文本仍为全部端口。
    空列表：返回 ("—", "—")。
    """
    if not ports:
        return "—", "—"
    sorted_ports = sorted(ports)
    full = ", ".join(str(p) for p in sorted_ports)
    if len(sorted_ports) <= top_n:
        return full, full
    shown = ", ".join(str(p) for p in sorted_ports[:top_n])
    return f"{shown}, +{len(sorted_ports) - top_n} more", full


UDP_PORTS = [53, 67, 69, 123, 137, 138, 161, 500, 514, 1900, 5353]


# 端口名显示表：值同样是惰性翻译的原文（见 port_name）
_PORT_NAME_TEXT = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 500: "IKE",
    514: "Syslog", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5353: "mDNS", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def port_name(port) -> str:
    """端口号 -> 服务名（惰性翻译）。未知端口返回空串。"""
    text = _PORT_NAME_TEXT.get(port)
    return tr(text) if text else ""


# ── 服务/协议标识（语言无关的规范代码）──────────────────────────────
# 这是 P1 的核心修复之一：`services` 列表与 `service_details[].proto`
# 过去存的是 **tr() 之后的显示文本**，于是：
#   - 引擎内部用 `proto == tr("HTTP")` 比较，语言一换就可能全部失配；
#   - topology_discovery.py 却用裸字符串 "SNMP" 比较（两种写法并存）；
#   - 扫描协议配置存进 ini 的也是翻译后的文本，切语言后配置被静默丢弃。
# 现在统一：内部一律用下面的 ASCII 代码，只在**显示时**调 service_label()。
SVC_HTTP = "HTTP"
SVC_HTTPS = "HTTPS"
SVC_FTP = "FTP"
SVC_RDP = "RDP"
SVC_SNMP = "SNMP"
SVC_MDNS = "mDNS"
SVC_SMB = "SMB"

# 规范代码 -> 翻译原文（切勿在 import 期 tr()）
SERVICE_LABELS = {
    SVC_HTTP: "HTTP",
    SVC_HTTPS: "HTTPS",
    SVC_FTP: "FTP",
    SVC_RDP: "RDP",
    SVC_SNMP: "SNMP",
    SVC_MDNS: "mDNS",
    SVC_SMB: "SMB共享",
}


def service_label(code) -> str:
    """服务代码 -> 当前语言的显示名（惰性翻译，切语言立即生效）。

    未知代码原样返回，保证历史结果/第三方写入的值仍能显示。
    """
    if not code:
        return ""
    text = SERVICE_LABELS.get(code)
    return tr(text) if text else str(code)


def service_code(value) -> str:
    """把任意服务值（含历史版本翻译后的文本）归一为规范代码。

    识别顺序：规范代码 -> 源串（不区分大小写）-> 当前语言下的翻译。
    最后一步依赖 i18n.canonical() 的反查表，因此"英文环境下传 Printer"
    这类输入也能正确归一。
    """
    if not value:
        return ""
    v = str(value).strip()
    if v in SERVICE_LABELS:              # 已是规范代码
        return v
    low = v.lower()
    for code, text in SERVICE_LABELS.items():
        if low == text.lower():          # 是源串
            return code
    # 再尝试按「当前语言下的翻译」反查：翻译 -> 源串 -> 规范代码
    try:
        from i18n import canonical
        src = canonical(v)
        if src != v:
            if src in SERVICE_LABELS:
                return src
            for code, text in SERVICE_LABELS.items():
                if src == text:
                    return code
    except Exception:
        # 反查失败 → 原样返回入参。这是"查不到"而非错误：
        # 调用方拿到未识别的值时按字面量展示即可。
        pass
    return v


# 需要协议识别的协议 -> 端口（键为规范代码）
PROTOCOL_PORTS = {
    SVC_HTTP: 80,
    SVC_HTTPS: 443,
    SVC_FTP: 21,
    SVC_RDP: 3389,
}


# ── 设备类别 / 操作系统（规范值 = 中文源串，显示时惰性翻译）──────────
# 约定与上面的服务代码一致：
#   * 引擎内部（classify / osfp / wmi）产出的是**未翻译的规范值**；
#   * 只有 UI / 导出 / CLI 展示时才调 device_class_label() / os_label()。
# 这样 device_class 落库（scan_history.db）后与界面语言无关，
# 跨语言切换时历史查询与统计不会失配。
def device_class_label(value) -> str:
    """设备类别规范值 -> 当前语言的显示名（惰性翻译）。"""
    return tr(value) if value else ""


def os_label(value) -> str:
    """操作系统规范值 -> 当前语言的显示名（惰性翻译）。"""
    return tr(value) if value else ""




_LOCAL_MAC_CACHE = None


_resolve_executor = None


_resolve_executor_lock = threading.Lock()


_SNMP_GET_OIDS = [
    "1.3.6.1.2.1.1.1.0",   # sysDescr
    "1.3.6.1.2.1.1.5.0",   # sysName
    "1.3.6.1.2.1.1.2.0",   # sysObjectID
]


_SNMP_DEFAULT_COMMUNITIES = ("public", "")


_SYSTEM_SHARES = {"ADMIN$", "IPC$", "PRINT$"}


_PRINTER_BRANDS = [
    ("hp", "HP"), ("hewlett", "HP"), ("canon", "Canon"), ("epson", "Epson"),
    ("brother", "Brother"), ("xerox", "Xerox"), ("ricoh", "Ricoh"),
    ("konica", "Konica Minolta"), ("minolta", "Konica Minolta"),
    ("kyocera", "Kyocera"), ("lexmark", "Lexmark"), ("dell", "Dell"),
    ("samsung", "Samsung"), ("sharp", "Sharp"), ("toshiba", "Toshiba"),
    ("fuji", "Fuji Xerox"), ("xerox", "Fuji Xerox"), ("panasonic", "Panasonic"),
    ("oki", "OKI"), ("lenovo", "Lenovo"), ("pantum", "Pantum"),
    ("震旦", "Aurora"), ("奔图", "Pantum"), ("联想", "Lenovo"),
]


_PRINTER_MODEL_RE = re.compile(
    r"(?:hp\s+)?(laserjet\s+[^<\"]{2,40})|"
    r"(?:canon\s+)?(pixma\s+[^<\"]{2,40})|"
    r"(?:epson\s+)?(ecotank\s+[^<\"]{2,40}|workforce\s+[^<\"]{2,40})|"
    r"(?:brother\s+)?(hl-[^<\"]{2,40}|dcp-[^<\"]{2,40}|mfc-[^<\"]{2,40})|"
    r"(?:xerox\s+)?(phaser\s+[^<\"]{2,40}|versalink\s+[^<\"]{2,40})|"
    r"(?:ricoh\s+)?(mp\s+[^<\"]{2,40}|sp\s+[^<\"]{2,40})",
    re.IGNORECASE,
)


_raw_cap_cache = None


_syn_failed = False


_MDNS_GROUP = "224.0.0.251"


_MDNS_PORT = 5353


_OUI_CLASS_HINTS = [
    ("hikvision", "摄像头"),
    ("dahua", "摄像头"),
    ("axis", "摄像头"),
    ("tiandy", "摄像头"),
    ("uniview", "摄像头"),
    ("foscam", "摄像头"),
    ("reolink", "摄像头"),
    ("ezviz", "摄像头"),
    ("hi351", "摄像头"),               # 海思芯片，多见于摄像头
    ("synology", "NAS"),
    ("qnap", "NAS"),
    ("terramaster", "NAS"),
    ("western digital", "NAS/存储"),
    ("seagate", "NAS/存储"),
    ("cisco", "网络设备"),
    ("aruba", "AP/交换机"),
    ("juniper", "网络设备"),
    ("fortinet", "防火墙"),
    ("mikrotik", "路由器/防火墙"),
    ("ubiquiti", "AP/路由器"),
    ("ruijie", "路由器/交换机"),
    ("h3c", "路由器/交换机"),
    ("tp-link", "路由器"),
    ("tplink", "路由器"),
    ("netgear", "路由器"),
    ("d-link", "路由器"),
    ("dlink", "路由器"),
    ("asus", "路由器"),
    ("mercury", "路由器"),
    ("tenda", "路由器"),
    ("huawei", "路由器/手机"),
    ("xiaomi", "IoT/路由器"),
    ("apple", "手机/电脑/IoT"),
    ("samsung", "电视/手机/打印机"),
    ("lg", "电视"),
    ("sony", "电视/游戏机"),
    ("philips", "灯具/IoT"),
    ("sengled", "灯具/IoT"),
    ("yeelight", "灯具/IoT"),
    ("tuya", "IoT"),
    ("espressif", "IoT开发板"),
    ("raspberry", "开发板/IoT"),
    ("sonos", "音箱"),
    ("bose", "音箱"),
    ("google", "手机/音箱/Nest"),
    ("nest", "IoT/摄像头"),
    ("amazon", "音箱/路由器"),
    ("nintendo", "游戏机"),
    ("microsoft", "电脑/游戏机"),
    ("nvidia", "电脑/游戏机"),
    ("hp ", "打印机/电脑"),
    ("hewlett", "打印机/电脑"),
    ("canon", "打印机"),
    ("brother", "打印机"),
    ("epson", "打印机"),
    ("xerox", "打印机"),
    ("lexmark", "打印机"),
    ("intel", "电脑/网卡"),
    ("dell", "电脑"),
    ("lenovo", "电脑"),
    ("hon hai", "电脑/手机"),
    ("azurewave", "电脑/网卡"),
]

# 手机厂商 OUI 关键词：仅凭 MAC(OUI) 只能拿到厂商，无法区分手机/电脑/IoT，
# 故仅作为「多信号融合识别手机」的候选集，需结合端口/OS/主机名剔除非手机信号。
_PHONE_OUI_KEYWORDS = (
    "apple", "samsung", "xiaomi", "huawei", "oppo", "vivo", "google",
    "oneplus", "realme", "meizu", "honor", "motorola", "nokia", "lg",
    "sony", "tcl", "lenovo",
)

# 手机厂商 OUI 关键词 -> 品牌**展示名**（用于「设备类型」列型号展示）。
#
# 值是展示文本，所以只能惰性翻译：包 tr() 会在导入期被求值，
# 而语言包在 i18n.init() 时才加载 —— 结果是英文界面下型号列永远显示「三星/小米/华为」。
# 键是 `kw in vendor` 的**匹配模式**，绝不能翻译（见 _IOT_VENDOR_KEYWORDS 的同类说明）。
# 保持 _PHONE_BRAND_DISPLAY 这个名字可用，由模块 __getattr__ 惰性构造。
_PHONE_BRAND_TEXT = {
    "apple": "Apple", "samsung": "三星", "xiaomi": "小米", "huawei": "华为",
    "oppo": "OPPO", "vivo": "vivo", "google": "Google", "oneplus": "一加",
    "realme": "realme", "meizu": "魅族", "honor": "荣耀", "motorola": "Motorola",
    "nokia": "Nokia", "lg": "LG", "sony": "Sony", "tcl": "TCL", "lenovo": "Lenovo",
}


def phone_brand_display() -> dict:
    """返回 {OUI 关键词: 品牌展示名}，按**当前**界面语言翻译。"""
    return {kw: tr(text) for kw, text in _PHONE_BRAND_TEXT.items()}

# IoT / 智能家居 / 家电厂商关键字：用于 step5 OS 兜底时排除「手机/IoT」误报，
# 直接归为「智能家居/IoT」。这些厂商的设备多为无屏 IoT，不应冒认成手机。
_IOT_VENDOR_KEYWORDS = (
    "roborock", "石头", "xiaomi", "mijia", "米家", "tuya", "涂鸦",
    "espressif", "philips", "sengled", "yeelight", "sonos", "bose",
    "nest", "amazon", "ring", "ecovacs", "科沃斯", "dreame", "追觅",
    "tp-link", "tplink", "mercury", "tenda", "netgear", "d-link", "dlink",
    "asus", "ruijie", "h3c", "ubiquiti", "huawei", "rui", "mercury",
    "broadlink", "orvibo", "欧瑞博", "govee", "aqara", "绿米", "switchbot",
    "海康", "hikvision", "dahua", "大华", "yi", "小蚁", "imou", "乐橙",
    "eufy", "anko", "tplink", "klein", "wemo", "belkin", "lutron",
    "shelly", "sonoff", "gree", "格力", "midea", "美的", "haier", "海尔",
    "changhong", "长虹", "hisense", "海信", "skyworth", "创维",
)



# ── 向后兼容：旧的模块级常量改为惰性求值（PEP 562）──────────────────
# 旧代码用 SCAN_LEVEL_LABELS / PORT_NAMES 这两个在 import 期就 tr() 冻结的字典。
# 直接删掉会破坏既有调用方，因此保留同名入口，但改成**访问时**才翻译：
# 既修复了"切语言不生效"，又不必改动所有调用点。
# 新代码请优先用 scan_level_label() / port_name()。
_LAZY_ALIASES = {
    "SCAN_LEVEL_LABELS": lambda: {lv: scan_level_label(lv) for lv in SCAN_LEVELS},
    "PORT_NAMES": lambda: {p: port_name(p) for p in _PORT_NAME_TEXT},
    "_PHONE_BRAND_DISPLAY": phone_brand_display,
}


def __getattr__(name):
    factory = _LAZY_ALIASES.get(name)
    if factory is not None:
        return factory()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
