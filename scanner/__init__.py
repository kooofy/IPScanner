# -*- coding: utf-8 -*-
"""IP 扫描引擎包。
原 scanner.py 拆分而来；对外公共 API 与旧模块保持一致。
"""
from .models import ScanResult
from .constants import (COMMON_PORTS, PORT_NAMES, PROTOCOL_PORTS,
                       SCAN_LEVELS, SCAN_LEVEL_LABELS, get_ports_for_level,
                       PORT_DISPLAY_TOP_N, format_ports_display)
from .range import parse_ip_range
from .engine import NetworkScanner
from .dns import mdns_discover
from .wmi import wmi_query, merge_wmi, wmi_device_class
from .cred_store import WmiCredentialStore
from .netbios import netbios_query, merge_netbios
from .snmp import snmp_get_system, snmp_walk

__all__ = [
    'ScanResult', 'COMMON_PORTS', 'PORT_NAMES', 'PROTOCOL_PORTS',
    'parse_ip_range', 'NetworkScanner', 'mdns_discover',
    'wmi_query', 'merge_wmi', 'wmi_device_class', 'WmiCredentialStore',
    'netbios_query', 'merge_netbios',
    'snmp_get_system', 'snmp_walk',
    'SCAN_LEVELS', 'SCAN_LEVEL_LABELS', 'get_ports_for_level',
    'PORT_DISPLAY_TOP_N', 'format_ports_display',
]
