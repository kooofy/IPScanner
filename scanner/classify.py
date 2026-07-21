# -*- coding: utf-8 -*-
import subprocess
import socket
import ssl
import struct
import threading
import concurrent.futures
import ipaddress
import re
import time
import platform
import os
import locale
import random
import ctypes
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
try:
    from oui_database import get_mac_vendor
except ImportError:
    def get_mac_vendor(mac: str) -> str:
        return ""

from .constants import _OUI_CLASS_HINTS, _PRINTER_BRANDS
from .snmp import _snmp_model

from .models import ScanResult


def infer_device(result: "ScanResult") -> Tuple[str, str]:
    """
    综合指纹推断设备类别与型号，返回 (device_class, device_model)。
    纯被动：仅基于已采集数据(厂商/端口/服务/mDNS/UPnP/SNMP/OS)推断，
    不发起新连接。TCP 栈指纹由调用方单独探测后写入 result.os_guess，
    本函数复用 os_guess 作为兜底信号。
    """
    ports = set(result.open_ports)
    vendor = (result.vendor or "").lower()
    hostname = (result.hostname or "").lower()
    mdns = []
    for sd in result.service_details or []:
        if sd.get("proto") == "mDNS":
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

    # 5) 仅凭 OS 推测兜底（优先于 OUI 泛化提示，给出更具体的类别）
    if not device_class:
        if result.os_guess == "Windows":
            device_class = "电脑/服务器" if (3389 in ports or (445 in ports and 139 in ports)) \
                else "Windows 设备"
        elif result.os_guess == "Linux/Unix":
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
