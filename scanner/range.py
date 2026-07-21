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

from .models import ScanResult


def parse_ip_range(range_str: str) -> List[str]:
    """
    解析 IP 范围字符串，返回 IP 列表。
    支持:
      192.168.1.0/24          (CIDR)
      192.168.1.1-254         (范围)
      192.168.1.1-192.168.1.254 (完整范围)
      192.168.1.1             (单 IP)
    """
    range_str = range_str.strip()
    if not range_str:
        return []

    ips = []

    # CIDR
    if "/" in range_str:
        try:
            net = ipaddress.ip_network(range_str, strict=False)
            for ip in net.hosts():
                ips.append(str(ip))
            # /31 和 /32 特殊处理
            if net.prefixlen >= 31:
                ips = [str(ip) for ip in net]
            return ips
        except ValueError:
            return []

    # 范围: 192.168.1.1-254 或 192.168.1.1-192.168.1.254
    if "-" in range_str:
        parts = range_str.split("-")
        if len(parts) == 2:
            start_str = parts[0].strip()
            end_str = parts[1].strip()
            try:
                # 短格式: 192.168.1.1-254
                if "." not in end_str:
                    prefix = start_str.rsplit(".", 1)[0]
                    end_str = f"{prefix}.{end_str}"
                start = ipaddress.ip_address(start_str)
                end = ipaddress.ip_address(end_str)
                # 确保 start <= end
                if int(start) > int(end):
                    start, end = end, start
                for i in range(int(start), int(end) + 1):
                    ips.append(str(ipaddress.ip_address(i)))
                return ips
            except (ValueError, IndexError):
                return []

    # 单 IP
    try:
        ipaddress.ip_address(range_str)
        return [range_str]
    except ValueError:
        return []
