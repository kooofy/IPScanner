# -*- coding: utf-8 -*-
from typing import Tuple

from .constants import (_OUI_CLASS_HINTS, _PRINTER_BRANDS, _PHONE_OUI_KEYWORDS,
                         _PHONE_BRAND_DISPLAY, _IOT_VENDOR_KEYWORDS, SVC_MDNS)
from .snmp import _snmp_model

from .models import ScanResult


def infer_device(result: "ScanResult") -> Tuple[str, str]:
    """
    综合指纹推断设备类别与型号，返回 (device_class, device_model)。

    返回的是**语言无关的规范值**（中文源串），显示时才翻译
    （见 constants.device_class_label）。切勿在此处调用 tr()：
    该值会落库到 scan_history.db，一旦带上语言，切换语言后历史查询就会失配。

    纯被动：仅基于已采集数据(厂商/端口/服务/mDNS/UPnP/SNMP/OS)推断，
    不发起新连接。TCP 栈指纹由调用方单独探测后写入 result.os_guess，
    本函数复用 os_guess 作为兜底信号。
    """
    ports = set(result.open_ports)
    vendor = (result.vendor or "").lower()
    hostname = (result.hostname or "").lower()
    mdns = []
    for sd in result.service_details or []:
        if sd.get("proto") == SVC_MDNS:
            for s in (sd.get("banner") or "").split(","):
                s = s.strip()
                if s:
                    mdns.append(s)
    mdns_lower = [s.lower() for s in mdns]
    snmp_descr = result.snmp_sys_descr or ""
    upnp = result.upnp_model or ""
    http_brand = (result.http_brand or "").strip()
    http_model = (result.http_model or "").strip()
    http_is_printer = http_brand and (
        http_brand == "打印机" or
        any(display == http_brand for _, display in _PRINTER_BRANDS)
    )

    device_class = ""
    device_model = ""

    # 1) mDNS 服务类型强信号
    if any(("airplay" in s or "_raop" in s) for s in mdns_lower):
        device_class = "媒体设备"
        if "apple" in vendor or "apple" in hostname:
            device_model = "Apple TV / AirPlay"
    if any("googlecast" in s for s in mdns_lower):
        device_class = device_class or "投屏设备"
        device_model = device_model or "Chromecast"
    if any(("_printer" in s or "_ipp" in s) for s in mdns_lower):
        device_class = device_class or "打印机"
    if any("_homekit" in s for s in mdns_lower):
        device_class = device_class or "智能家居"
    if any("_adb" in s for s in mdns_lower):
        device_class = device_class or "Android/开发板"
    # Apple 移动设备（iPhone/iPad/Apple Watch）的 Continuity 信号，优先于媒体设备：
    # 投屏只是手机的一个子场景，companion-link / airdrop 才是真移动设备指纹。
    # 现代手机常用私有/随机 MAC，OUI 查不到厂商，mDNS 服务类型是可靠线索。
    if any(("_companion-link" in s or "_airdrop" in s) for s in mdns_lower):
        device_class = "手机"
        device_model = device_model or "Apple 移动设备"

    # 2) 端口组合规则
    if not device_class:
        if 554 in ports:                                   # RTSP 视频流
            device_class = "摄像头"
        elif bool({515, 631, 9100} & ports):               # 打印协议
            device_class = "打印机"
        elif (5000 in ports or 5001 in ports) or (8443 in ports and "nas" in hostname):
            device_class = "NAS"
        elif (23 in ports or 22 in ports) and 80 in ports and (53 in ports or 67 in ports):
            device_class = "路由器"
        elif 23 in ports and 161 in ports:                  # Telnet + SNMP：受管网络设备(交由 SNMP 细化)
            device_class = "网络设备"
        elif bool({5060, 5061} & ports):
            device_class = "电话/VoIP"

    # 3) SNMP sysDescr 信号（可细化端口组合得出的泛化类别）
    if snmp_descr:
        sd_low = snmp_descr.lower()
        if device_class in ("", "网络设备", "未知设备"):
            if "switch" in sd_low or ("ios" in sd_low and "cisco" in sd_low):
                device_class = "交换机"
            elif "router" in sd_low or "routeros" in sd_low:
                device_class = "路由器"
            elif "printer" in sd_low or "jetdirect" in sd_low:
                device_class = "打印机"
            elif "nas" in sd_low or "storage" in sd_low:
                device_class = "NAS"
            elif "ap" in sd_low and "aruba" in sd_low:
                device_class = "AP"
        if not device_model:
            device_model = _snmp_model(snmp_descr)

    # 4) UPnP / HTTP 型号信号
    # HTTP 页面识别出打印机品牌（对仅开 80/443 的现代网络打印机很关键）
    if http_is_printer and not device_class:
        device_class = "打印机"
        if http_model:
            device_model = f"{http_brand} {http_model}".strip()
        elif not device_model and http_brand != "打印机":
            device_model = f"{http_brand} 打印机"

    if upnp and not device_model:
        device_model = upnp
        if not device_class:
            ul = upnp.lower()
            if "print" in ul or "打印" in upnp or "laser" in ul:
                device_class = "打印机"
            elif "nas" in ul:
                device_class = "NAS"
            elif "router" in ul:
                device_class = "路由器"
            else:
                device_class = device_class or "网络设备"

    # 4.5) 手机识别：OUI 厂商 + 排除电脑/服务器/电视特征（多信号融合）
    # 关键：手机连 Wi-Fi 通常无开放端口、TTL 猜测多为 Linux/Unix，若放在 OS 兜底之后
    # 会被误标为「Linux 设备」，故必须在 OS 兜底之前、且强信号(mDNS/端口/SNMP/UPnP)之后判定。
    if not device_class:
        if any(k in vendor for k in _PHONE_OUI_KEYWORDS):
            _pc_signals = (
                bool({135, 139, 445, 3389} & ports)          # SMB/RPC/RDP：典型 Windows PC/服务器
                or result.os_guess == "Windows"
                or any(h in hostname for h in
                       ("mac", "pc", "desktop", "laptop", "server", "nas",
                        "router", "switch", "printer", "print"))
            )
            _tv_signals = any(t in hostname for t in
                              ("tv", "bravia", "webos", "tizen", "android tv", "shield"))
            if not _pc_signals and not _tv_signals:
                device_class = "手机"
                if not device_model:
                    device_model = next(
                        (disp for kw, disp in _PHONE_BRAND_DISPLAY.items()
                         if kw in vendor), vendor.split(",")[0] or "手机"
                    ).strip()

    # 4.7) 主机名含手机品牌关键字（即使 MAC 随机化、OUI 为空也能识别移动设备）
    # 须置于 OS 兜底(step 5)之前，否则会被较模糊的「手机/IoT」抢占。
    if not device_class:
        _mobile_host = ("iphone", "ipad", "android", "xiaomi", "huawei",
                        "oppo", "vivo", "oneplus", "realme", "redmi", "honor",
                        "galaxy", "pixel")
        if any(h in hostname for h in _mobile_host):
            device_class = "手机"

    # 4.8) 已知 IoT / 智能家居 / 家电厂商（vendor 非空）：直接判「智能家居/IoT」，
    # 避免 step5 OS 兜底把「无端口 Linux/Unix」误归为「手机/IoT」。
    # 注意：手机厂商(apple/samsung/...)已在 step4.5 命中；此处排除它们，
    # 仅对明确的 IoT/家电/网络厂商生效。
    if not device_class and vendor:
        if any(k in vendor for k in _IOT_VENDOR_KEYWORDS):
            device_class = "智能家居/IoT"

    # 5) 仅凭 OS 推测兜底（优先于 OUI 泛化提示，给出更具体的类别）
    if not device_class:
        if result.os_guess == "Windows":
            device_class = "电脑/服务器" if (3389 in ports or (445 in ports and 139 in ports)) \
                else "Windows 设备"
        elif result.os_guess == "Linux/Unix":
            # 现代手机（iOS/Android）常使用随机/私有 MAC，OUI 查不到厂商；
            # 且默认无开放端口、TTL 同属 Linux/Unix 类。无开放端口 + 无 PC/TV/
            # 服务器信号的主机，多为手机或 IoT，而非真正的「Linux 设备/服务器」。
            # 双保险：vendor 已知且属 IoT 厂商时（step4.8 未覆盖的边界），不标手机/IoT。
            _pc_signals = any(h in hostname for h in
                              ("mac", "pc", "desktop", "laptop", "server", "nas",
                               "router", "switch", "printer", "print"))
            _tv_signals = any(t in hostname for t in
                              ("tv", "bravia", "webos", "tizen", "android tv", "shield"))
            if (not ports and not _pc_signals and not _tv_signals
                    and not any(k in vendor for k in _IOT_VENDOR_KEYWORDS)):
                device_class = "手机/IoT"
            else:
                device_class = "Linux 设备/服务器" if 22 in ports else "Linux 设备"
        elif result.os_guess == "网络设备":
            device_class = "网络设备"
        else:
            device_class = "未知设备"

    # 6) OUI 厂商提示（弱信号，仅当上述均无结论时作为兜底）
    if not device_class:
        for key, cls in _OUI_CLASS_HINTS:
            if key in vendor:
                device_class = cls
                break
        if not device_class and any(k in hostname
                                    for k in ("apple", "iphone", "ipad", "macbook")):
            device_class = "手机/电脑/IoT"

    # 7) 型号兜底：厂商 + 类别
    if not device_model and device_class:
        if device_class == "摄像头" and "hikvision" in vendor:
            device_model = "海康威视摄像头"
        elif device_class == "摄像头" and "dahua" in vendor:
            device_model = "大华摄像头"
        elif device_class == "路由器" and "mikrotik" in vendor:
            device_model = "MikroTik 路由器"
        elif device_class == "NAS" and "synology" in vendor:
            device_model = "群晖 NAS"
        elif device_class == "NAS" and "qnap" in vendor:
            device_model = "威联通 NAS"

    return device_class, device_model
