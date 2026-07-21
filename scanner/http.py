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

from .constants import _PRINTER_BRANDS, _PRINTER_MODEL_RE

from .models import ScanResult


def _read_http(ip: str, port: int, timeout: float = 1.0) -> Tuple[str, str, str]:
    """对 HTTP 端口发送单次 GET /，一次性提取 (banner, brand, model)。

    合并原 _read_http_banner 与 _read_http_brand 两次独立 TCP 连接，
    对只开 80/443 的打印机 / 路由器等可省一半往返；
    banner 取 Server 头（或 <title>），brand/model 取页面正文推断。
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: IPScanner/1.0\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode("utf-8"))
            data = b""
            while len(data) < 32768:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"</html>" in data.lower():
                        break
                except socket.timeout:
                    break
            text = data.decode("utf-8", errors="replace")
            # banner: Server 头优先，其次 <title>
            banner = ""
            m = re.search(r"Server:\s*(.+?)[\r\n]", text, re.IGNORECASE)
            if m:
                banner = m.group(1).strip()
            else:
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if m:
                    banner = re.sub(r"[\s\r\n]+", " ", m.group(1).strip())
            brand, model = _extract_http_brand(text)
            return banner, brand, model
    except Exception:
        return "", "", ""


def _extract_http_brand(text: str) -> Tuple[str, str]:
    """
    从 HTTP 页面文本（Server 头、标题、正文）中推断设备品牌和型号。
    返回 (brand, model)，命中打印机品牌时 brand 非空。
    """
    if not text:
        return "", ""
    low = text.lower()

    # 1) 品牌关键字匹配
    brand = ""
    for key, display in _PRINTER_BRANDS:
        if key in low:
            brand = display
            break

    # 2) 尝试抓型号
    model = ""
    m = _PRINTER_MODEL_RE.search(text)
    if m:
        model = next((g for g in m.groups() if g), "")
        model = re.sub(r"[\s\r\n]+", " ", model).strip()
        # 首字母大写美化
        model = " ".join(w.capitalize() for w in model.split())

    # 3) 若正文里有明显"打印机"中文信号，但没命中国际品牌，给一个通用品牌提示
    if not brand and ("打印机" in text or "printer" in low or "laser" in low or "inkjet" in low):
        brand = "打印机"

    return brand, model


def _read_https_banner(ip: str, port: int, timeout: float = 1.2) -> str:
    """对 HTTPS 端口做 SSL 握手，返回 OpenSSL 隧道风格字符串。

    成功时: "Tunnel is OpenSSL <TLS版本>: <证书CN>"
    失败时: "Tunnel is OpenSSL <TLS版本>: unknown service" 或 "unknown service"
    与 Advanced IP Scanner 的 HTTPS 子项展示风格保持一致。
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version() or "TLS"
                cert = ssock.getpeercert()
                cn = ""
                if cert:
                    subject = cert.get("subject")
                    if subject:
                        for entry in subject:
                            for key, value in entry:
                                if key == "commonName":
                                    cn = value
                                    break
                            if cn:
                                break
                result = cn if cn else "unknown service"
                return f"Tunnel is OpenSSL {version}: {result}"
    except Exception:
        # 握手失败（超时/协议不兼容等）：保留 OpenSSL 隧道风格，
        # 若无法确定版本则统一返回 unknown service，避免空串导致子项回退成 "HTTPS, port 443"。
        return "unknown service"


def _parse_upnp_name(xml_text: str) -> str:
    """从 UPnP 设备描述 XML 中提取最可读的设备型号名。

    优先 manufacturer+modelName（与 AIP 展示的设备型号一致）；
    friendlyName 常含序列号/主机名后缀，次之；再退到 modelDescription。
    """
    def grab(tag: str) -> str:
        m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml_text,
                      re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1).strip())
        return ""

    model = grab("modelName")
    manu = grab("manufacturer")
    if model and manu:
        return f"{manu} {model}"
    if model:
        return model
    friendly = grab("friendlyName")
    if friendly:
        return friendly
    desc = grab("modelDescription")
    if desc:
        return desc
    return ""


def _read_upnp_device_name(ip: str, port: int, timeout: float = 0.8) -> str:
    """尝试常见 UPnP 设备描述路径，识别打印机/NAS/路由器等设备型号名。

    仅对 HTTP 端口开放的设备调用；每个路径使用较短超时以控制整体耗时。
    返回如 "HP LaserJet M104w" 的可读名，未识别返回空串。
    """
    paths = ["/rootDesc.xml", "/DeviceDescription.xml",
             "/device.xml", "/description.xml"]
    per_req = max(0.3, min(0.5, timeout))
    for path in paths:
        try:
            with socket.create_connection((ip, port), timeout=per_req) as sock:
                sock.settimeout(per_req)
                req = (
                    f"GET {path} HTTP/1.0\r\n"
                    f"Host: {ip}\r\n"
                    f"User-Agent: IPScanner/1.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(req.encode("utf-8"))
                data = b""
                while len(data) < 16384:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        low = data.lower()
                        if b"</root>" in low or b"</device>" in low:
                            break
                    except socket.timeout:
                        break
            text = data.decode("utf-8", errors="replace")
            if "<device" not in text.lower():
                continue
            name = _parse_upnp_name(text)
            if name:
                return name
        except Exception:
            continue
    return ""


def _read_ssh_banner(ip: str, port: int = 22, timeout: float = 1.0) -> str:
    """读取 SSH 服务标识行，返回版本串如 'OpenSSH_8.9p1'（失败返回空）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            text = data.decode("utf-8", "replace").strip()
            m = re.search(r"SSH-\d\.\d-(.+)", text)
            if m:
                return m.group(1).strip()
            return text
    except Exception:
        return ""


def _read_ftp_banner(ip: str, port: int = 21, timeout: float = 1.0) -> str:
    """读取 FTP 欢迎横幅，返回原始 220 行（失败返回空）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            return data.decode("utf-8", "replace").strip()
    except Exception:
        return ""
