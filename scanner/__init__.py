# -*- coding: utf-8 -*-
"""IP 扫描引擎包。
原 scanner.py 拆分而来；对外公共 API 与旧模块保持一致。
"""
from .models import ScanResult
from .constants import (COMMON_PORTS, PORT_NAMES, PROTOCOL_PORTS,
                       SCAN_LEVELS, SCAN_LEVEL_LABELS, get_ports_for_level,
                       PORT_DISPLAY_TOP_N, format_ports_display,
                       scan_level_label, port_name, phase_label,
                       SVC_HTTP, SVC_HTTPS, SVC_FTP, SVC_RDP,
                       SVC_SNMP, SVC_MDNS, SVC_SMB,
                       SERVICE_LABELS, service_label, service_code,
                       device_class_label, os_label)
from .range import (parse_ip_range, count_ip_range, is_valid_range, is_ipv6_range,
                    RangeTooLarge, MAX_IPS_PER_RANGE, MAX_IPS_TOTAL)
from .engine import NetworkScanner
from .ping import parse_windows_ipconfig, windows_ipconfig_subnets
from .dns import mdns_discover
from .wmi import (wmi_query, merge_wmi, wmi_device_class, transport_label,
                  TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM, TRANSPORTS)
from .cred_store import WmiCredentialStore, SnmpV3CredentialStore
from .netbios import netbios_query, merge_netbios
from .passive import passive_discover, dump_arp_table, PassiveWatcher
from .snmp import snmp_get_system, snmp_walk
from .snmp_v3 import (snmp_v3_get_system, snmp_v3_walk, SnmpV3User,
                      auth_label, priv_label,
                      AUTH_NONE, AUTH_MD5, AUTH_SHA, AUTH_PROTOS,
                      PRIV_NONE, PRIV_AES, PRIV_PROTOS, PRIV_DES,
                      SECURITY_LEVELS,
                      ERR_CONFIG, ERR_NO_RESPONSE, ERR_AUTH, ERR_PROTOCOL,
                      ERR_REJECTED)

__all__ = [
    'ScanResult', 'COMMON_PORTS', 'PORT_NAMES', 'PROTOCOL_PORTS',
    'parse_ip_range', 'count_ip_range', 'is_valid_range', 'is_ipv6_range',
    'RangeTooLarge', 'MAX_IPS_PER_RANGE', 'MAX_IPS_TOTAL',
    'NetworkScanner', 'mdns_discover',
    'parse_windows_ipconfig', 'windows_ipconfig_subnets',
    'wmi_query', 'merge_wmi', 'wmi_device_class', 'WmiCredentialStore',
    'transport_label', 'TRANSPORT_AUTO', 'TRANSPORT_DCOM', 'TRANSPORT_WINRM',
    'TRANSPORTS',
    'netbios_query', 'merge_netbios',
    'passive_discover', 'dump_arp_table', 'PassiveWatcher',
    'snmp_get_system', 'snmp_walk',
    'snmp_v3_get_system', 'snmp_v3_walk', 'SnmpV3User',
    'SnmpV3CredentialStore', 'auth_label', 'priv_label',
    'AUTH_NONE', 'AUTH_MD5', 'AUTH_SHA', 'AUTH_PROTOS',
    'PRIV_NONE', 'PRIV_AES', 'PRIV_PROTOS', 'PRIV_DES',
    'SECURITY_LEVELS',
    'ERR_CONFIG', 'ERR_NO_RESPONSE', 'ERR_AUTH', 'ERR_PROTOCOL', 'ERR_REJECTED',
    'SCAN_LEVELS', 'SCAN_LEVEL_LABELS', 'get_ports_for_level',
    'PORT_DISPLAY_TOP_N', 'format_ports_display',
    'scan_level_label', 'port_name', 'phase_label',
    'SVC_HTTP', 'SVC_HTTPS', 'SVC_FTP', 'SVC_RDP',
    'SVC_SNMP', 'SVC_MDNS', 'SVC_SMB',
    'SERVICE_LABELS', 'service_label', 'service_code',
    'device_class_label', 'os_label',
]
