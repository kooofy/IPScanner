# -*- coding: utf-8 -*-
"""IP 扫描引擎包。
原 scanner.py 拆分而来；对外公共 API 与旧模块保持一致。
"""
from .models import ScanResult
from .constants import COMMON_PORTS, PORT_NAMES, PROTOCOL_PORTS
from .range import parse_ip_range
from .engine import NetworkScanner
from .dns import mdns_discover
from .wmi import wmi_query, merge_wmi, wmi_device_class
from .cred_store import WmiCredentialStore

__all__ = [
    'ScanResult', 'COMMON_PORTS', 'PORT_NAMES', 'PROTOCOL_PORTS',
    'parse_ip_range', 'NetworkScanner', 'mdns_discover',
    'wmi_query', 'merge_wmi', 'wmi_device_class', 'WmiCredentialStore',
]
