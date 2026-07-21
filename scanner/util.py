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

from .constants import _CMD_ENCODING

from .models import ScanResult


def _run_cmd(cmd: list, timeout: float = 10) -> str:
    """执行命令并返回输出文本，自动处理 Windows 编码"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        raw = result.stdout
        if _CMD_ENCODING:
            return raw.decode(_CMD_ENCODING, errors="replace")
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _inet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _local_ip_for_dst(dst: str) -> str:
    """获取到达 dst 时使用的本机出口 IP。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"
