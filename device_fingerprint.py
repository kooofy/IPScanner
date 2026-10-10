# -*- coding: utf-8 -*-
"""随机化 MAC 识别：用**设备指纹**把「换了隐私 MAC 的同一台设备」认回来。

背景（路线图 §3 耦合提示 #11）
------------------------------
iOS / Android / Windows 默认开启「私有 Wi-Fi 地址」：同一台设备每次接入
（或每个网络）用一个**随机 MAC**。只按 MAC 认设备的台账，会把同一台手机
反复报成「新设备」—— 1.2 被动发现上线后这个噪声被放大，台账可信度被吃掉。

判据：LAA 位
------------
随机 MAC 的硬信号是 **LAA 位**（第一字节的 0x02 位）= 1，即「本地管理地址」。
OUI 库里查不到厂商只是**佐证**（LAA 地址本就不在 OUI 库里），LAA 才是判据。
注意它是**必要不充分**条件：少数虚拟网卡也用 LAA —— 所以本模块从不单凭
LAA 下结论，一定还要**指纹一致**才判定「同一台」（见 `same_device`）。

指纹：只认身份锚点
------------------
指纹是一组 token：``host=<主机名>`` / ``vendor=<厂商>`` / ``model=<型号>`` /
``serial=<序列号>``，全部归一化（小写、去首尾空白、主机名去 ``.local``）。

**为什么「设备类别 / 操作系统 / 服务」不进指纹**：它们是**上下文**字段，
在整网里被大量设备共享 —— ``os=Windows``、``port=445``、``class=电脑`` 会让
两台同型号笔电全部命中，把两台并成一台。那种「错认」比「漏认」严重得多：
漏认只是多报一次新设备（诚实），错认是让台账凭空少一台、把 A 的历史挂到 B 上。
所以指纹必须有身份锚点；一个都没有时**不给指纹**，退回 MAC 身份。

（另：快照表 ``devices`` 只存 ip/status/mac/hostname/vendor/device_class/
os_guess/open_ports/…，**没有**服务字段 —— 所以「服务组合」在快照对比这条
路径上本来就取不到。这条实现约束与上面的理由方向一致。）

配对规则（`same_device`）
------------------------
1. 同类字段两边都有值却不同（``host=a`` vs ``host=b``）→ **否决**，不是同一台；
2. 交集里命中 ``host=`` 或 ``serial=`` → 同一台（强证据）；
3. 交集里命中 ``model=`` 且交集 ≥2 个 token → 同一台（同型号需再有一项佐证）；
4. 其余（只有 ``vendor=`` 相同）→ **不算**同一台（同厂商设备太多）。
"""
import re

#: LAA 位：MAC 第一字节的第 2 位（0x02）。置 1 即「本地管理地址」。
_LAA_MASK = 0x02

#: 强证据 token 前缀：主机名与序列号基本唯一。
_STRONG_PREFIXES = ("host=", "serial=")
#: 中等证据：型号（同型号可能有多台，需再有一项佐证）。
_MEDIUM_PREFIXES = ("model=",)
#: 否决前缀：同类字段两边都有值却不同 → 直接判定不是同一台。
_VETO_PREFIXES = ("host=", "vendor=", "model=", "serial=")

_NON_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def is_randomized_mac(mac: str) -> bool:
    """这台设备的 MAC **疑似随机化**（隐私 MAC / 本地管理地址）。

    判据是 LAA 位（第一字节 0x02）。它是**必要不充分**条件 —— 少数虚拟网卡
    也用 LAA，所以调用方还要 `same_device()` 一致才认定「同一台」。
    形状不对（不是 6 字节）时返回 ``False``。
    """
    hexs = _NON_HEX_RE.sub("", mac or "")
    if len(hexs) != 12:
        return False
    return bool(int(hexs[:2], 16) & _LAA_MASK)


def _field(dev, *names) -> str:
    """从 ScanResult（属性）或快照 dict（键）里取第一个非空字段。

    两条路径的字段名一致（`ui_logic.build_snapshot` 就是按属性名落库的），
    所以同一个名字列表两边通用。
    """
    for name in names:
        val = dev.get(name) if isinstance(dev, dict) else getattr(dev, name, None)
        if val:
            return str(val).strip()
    return ""


def _norm(value: str) -> str:
    """归一化：小写、去首尾空白、去掉 mDNS 全限定名的 ``.local`` 后缀与结尾的点。"""
    s = (value or "").strip().lower().rstrip(".")
    if s.endswith(".local"):
        s = s[:-len(".local")]
    return s


def fingerprint_tokens(dev) -> frozenset:
    """设备的身份 token 集合（`ScanResult` 或快照 dict 都行）。

    没有任何身份字段时返回**空集** —— 表示「信号不足，不做身份判定」。
    """
    tokens = set()
    host = _norm(_field(dev, "hostname", "netbios_name"))
    if host:
        tokens.add("host=" + host)
    vendor = _norm(_field(dev, "vendor"))
    if vendor:
        tokens.add("vendor=" + vendor)
    model = _norm(_field(dev, "device_model", "wmi_model"))
    if model:
        tokens.add("model=" + model)
    serial = _norm(_field(dev, "wmi_serial"))
    if serial:
        tokens.add("serial=" + serial)
    return frozenset(tokens)


def fingerprint(dev) -> str:
    """身份指纹的规范字符串（排序后 ``|`` 连接）；信号不足时返回 ``""``。

    只用于日志 / 调试 / 测试。判定请用 `same_device()` —— 它做的是
    「交集 + 否决」，而不是字符串全等；后者会因为一边缺字段而漏配
    （旧快照只存 hostname/vendor，新结果是完整的 ScanResult）。
    """
    return "|".join(sorted(fingerprint_tokens(dev)))


def same_device(a, b) -> bool:
    """两台设备（`ScanResult` 或快照 dict）是不是**同一台**。

    只认身份 token 的交集，并要求命中身份锚点；``vendor=`` 相同**不算**
    （同厂商设备太多）。任一侧信号不足时返回 ``False`` —— 宁可漏认，不可错认。
    """
    ta, tb = fingerprint_tokens(a), fingerprint_tokens(b)
    if not ta or not tb:
        return False
    for prefix in _VETO_PREFIXES:
        va = {t for t in ta if t.startswith(prefix)}
        vb = {t for t in tb if t.startswith(prefix)}
        if va and vb and va != vb:
            return False
    shared = ta & tb
    if not shared:
        return False
    if any(t.startswith(_STRONG_PREFIXES) for t in shared):
        return True
    if any(t.startswith(_MEDIUM_PREFIXES) for t in shared) and len(shared) >= 2:
        return True
    return False
