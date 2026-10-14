# -*- coding: utf-8 -*-
import ctypes
import locale
import platform
import re
import threading
from i18n import tr

# v2.2 §3.2：常用端口表（quick 级）与端口显示名已外置为顶层
# port_services.json（由顶层模块 port_services 三层加载：data_dir() →
# resource_dir() → 模块内兜底，与 service_fingerprints 同范式）。
# 这里只取加载函数；字面量默认值搬去了 port_services 的内置兜底表。
# 加载是惰性的 —— import 期不读盘、不调 tr()。
from port_services import common_ports as _common_ports
from port_services import port_names as _port_names
from port_services import raw_port_name as _raw_port_name

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


# 常用端口（quick 级）已外置到 port_services.json（见文件顶部导入说明）。
# 这个名字经文件末尾的 _LAZY_ALIASES 惰性保留，语义 = common_ports()。


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


# 扫描阶段显示名：惰性翻译。键是**语言无关的规范值**（即 `DiscoveryPhase.name`），
# 与 `scanner/engine.py` 的 `PHASES` 一一对应。
# 未知阶段名原样返回 —— 以后新增阶段忘了补词条，也只是显示英文名，不会崩。
#
# ⚠️ 措辞刻意避开已有词条：语言包里 `"mDNS 发现"` 已存在，但它的含义是
# **"该设备是通过 mDNS 发现的"**（`Found via mDNS`）。阶段名若复用它，英文界面
# 会显示成 "Found via mDNS"，意思全拧 —— 故这里用"mDNS 组播发现"。
_PHASE_TEXT = {
    "ping": "存活探测",
    "arp": "ARP 补全",
    "mdns": "mDNS 组播发现",
    # 扫描末尾按需读取交换机转发表（见 topology_discovery.collect_switch_port_maps）
    "switch_map": "读取交换机转发表",
    # 扫描末尾按需探测 LLMNR / NBNS 响应器（见 scanner/llmnr_nbns.py）。
    # 措辞与 GUI 勾选框**刻意一致**（main_window.responder_check）—— 同一个开关，
    # 摘要条上说"正在探测名字响应器"，用户能立刻对上自己勾的那个框。
    "name_responder": "探测名字响应器",
}


def phase_label(name: str) -> str:
    """扫描阶段代码 -> 当前语言的显示名（惰性翻译）。"""
    text = _PHASE_TEXT.get(name)
    return tr(text) if text else str(name)


# 「定位查询」查不到时的原因显示名：惰性翻译。
# 键是 `history_store` 里的 `LOCATE_*` **语言无关规范值**（存储层只产出规范值，
# 翻译发生在展示层 —— 仓库铁律）。取值刻意都写成"说不出位置"的口径，
# 而不是"设备不存在"：`mac_not_in_fdb` 只说明转发表里没有它，不代表这台机器不在网上。
#
# ⚠️ 这张表必须与 `history_store.LOCATE_*` 一一对应，
# `tests/test_locate.py::LocateReasonLabelTest` 会强制校验（漏一个就红）。
_LOCATE_REASON_TEXT = {
    "no_device": "没有这台设备的记录",
    "no_switch_data": "从未采集过交换机转发表",
    "switch_scan_failed": "交换机转发表读取失败",
    "mac_not_in_fdb": "交换机转发表里没有这台设备",
}


def locate_reason_label(reason: str) -> str:
    """定位查询的未知原因代码 -> 当前语言的显示名（惰性翻译）。"""
    text = _LOCATE_REASON_TEXT.get(reason)
    return tr(text) if text else str(reason)


# 「定位查询」查不到时给出的**下一步动作**。与上面的短标签分开：
# 标签回答"为什么不知道"，提示回答"那我该怎么办" —— 后者才是有用的一半。
# 没有对应提示（如 no_device 之外的未知代码）时返回空串，调用方不显示提示行。
_LOCATE_REASON_HINT = {
    "no_device": "历史库里没有这台设备的记录。先扫描一次并保存快照，再来定位。",
    "no_switch_data": "还没有采集过交换机转发表。扫描时勾选「读取交换机转发表」"
                      "（命令行加 --switch-map --save-snapshot）后重新扫描。",
    "switch_scan_failed": "交换机响应了 SNMP，但转发表读不到 —— "
                          "多数是设备不支持 BRIDGE-MIB，或团体字权限不足。",
    "mac_not_in_fdb": "交换机转发表里没有它：设备可能已离线，"
                      "或接在本次未读取转发表的交换机上。",
}


def locate_reason_hint(reason: str) -> str:
    """定位查询的未知原因代码 -> 当前语言的可操作提示（惰性翻译）。"""
    text = _LOCATE_REASON_HINT.get(reason)
    return tr(text) if text else ""


def get_ports_for_level(level: str):
    """按扫描级别返回端口列表（按需生成，不常驻大列表）。

    quick（默认）/ 未识别级别 -> COMMON_PORTS（向后兼容当前行为）。
    standard -> 1-1023 知名端口；all -> 1-65535 全端口。
    """
    if level == "standard":
        return list(range(1, 1024))
    if level == "all":
        return list(range(1, 65536))
    # quick 与未识别：当前高频服务端口（外置表，用户可在 data_dir() 覆盖）
    return _common_ports()



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


# 端口名显示表已外置到 port_services.json（见文件顶部导入说明）。
# values 是显示文本原文，只在显示时过 tr()（见 port_name）——
# 它们绝不参与比较（比较用端口号本身或 SVC_* 规范代码）。


def port_name(port) -> str:
    """端口号 -> 服务名（惰性翻译）。未知端口返回空串。"""
    text = _raw_port_name(port)
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
# P2-2 扩展服务指纹覆盖的服务（均为 ASCII 规范代码，显示走 service_label）
SVC_TELNET = "Telnet"
SVC_SMTP = "SMTP"
SVC_POP3 = "POP3"
SVC_IMAP = "IMAP"
SVC_VNC = "VNC"
SVC_MYSQL = "MySQL"
SVC_REDIS = "Redis"
SVC_POSTGRESQL = "PostgreSQL"
SVC_MONGODB = "MongoDB"

# 规范代码 -> 翻译原文（切勿在 import 期 tr()）
SERVICE_LABELS = {
    SVC_HTTP: "HTTP",
    SVC_HTTPS: "HTTPS",
    SVC_FTP: "FTP",
    SVC_RDP: "RDP",
    SVC_SNMP: "SNMP",
    SVC_MDNS: "mDNS",
    SVC_SMB: "SMB共享",
    SVC_TELNET: "Telnet",
    SVC_SMTP: "SMTP",
    SVC_POP3: "POP3",
    SVC_IMAP: "IMAP",
    SVC_VNC: "VNC",
    SVC_MYSQL: "MySQL",
    SVC_REDIS: "Redis",
    SVC_POSTGRESQL: "PostgreSQL",
    SVC_MONGODB: "MongoDB",
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


# ── 跨模块共享状态 ────────────────────────────────────────────────────
# 这两个变量被 ports.py 与 engine.py 共同读写，**必须**通过 ``constants.xxx``
# 属性访问，不能用 ``from .constants import _xxx`` 再赋值 —— 后者只会创建一份
# 本模块的副本，写不回这里（Python 的 import 是名字绑定，不是引用别名）。
# 历史缺陷：ports.py 曾经这么写，导致三份互不相干的副本：
#   · ports 的副本一旦置位就再没人复位（提权后仍静默回退 connect）
#   · engine 的副本恒为 False，使"SYN 发送被拒"的回退告警成为死代码
# _syn_failed 用 Event 而非裸 bool：它被多个探测线程并发读写，Event 自带同步。
_raw_cap_cache = None


_syn_failed = threading.Event()


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
    # v2.2 §3.2：COMMON_PORTS 从模块字面量改为惰性别名（外置表加载函数），
    # 旧调用点 `from scanner.constants import COMMON_PORTS` 语义不变。
    "COMMON_PORTS": _common_ports,
    "PORT_NAMES": lambda: {p: port_name(p) for p in _port_names()},
    "_PHONE_BRAND_DISPLAY": phone_brand_display,
}


def __getattr__(name):
    factory = _LAZY_ALIASES.get(name)
    if factory is not None:
        return factory()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
