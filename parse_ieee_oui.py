# -*- coding: utf-8 -*-
"""
解析 IEEE 官方 OUI 数据库 (oui.txt)，生成 Python 字典格式的 MAC OUI 厂商数据库
"""

import re
import os


def parse_ieee_oui(filepath: str) -> dict:
    """
    解析 IEEE oui.txt 文件，返回 {oui: vendor} 字典
    
    Args:
        filepath: oui.txt 文件路径
        
    Returns:
        dict: {"xx:xx:xx": "厂商名称", ...}
    """
    oui_dict = {}
    
    if not os.path.exists(filepath):
        print(f"文件不存在: {filepath}")
        return oui_dict
    
    # 匹配 OUI 行的正则: "XX-XX-XX   (hex)		Company Name"
    # 注意：分隔符可能是制表符或多个空格
    pattern = re.compile(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$')
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\r\n')
            match = pattern.match(line)
            if match:
                oui_hex = match.group(1).replace('-', ':').lower()
                vendor = match.group(2).strip()
                # 清理厂商名称中的多余空白
                vendor = re.sub(r'\s+', ' ', vendor)
                if oui_hex and vendor:
                    oui_dict[oui_hex] = vendor
    
    return oui_dict


# 常见厂商名称规范化映射（小写: 显示名称）
VENDOR_NORMALIZE = {
    'tp-link technologies': 'TP-Link',
    'tp-link': 'TP-Link',
    'tp link': 'TP-Link',
    'huawei technologies': 'Huawei',
    'huawei': 'Huawei',
    'cisco systems': 'Cisco',
    'cisco': 'Cisco',
    'apple': 'Apple',
    'dell': 'Dell',
    'dell inc': 'Dell',
    'lenovo': 'Lenovo',
    'hewlett-packard': 'HP',
    'hewlett packard': 'HP',
    'hp inc': 'HP',
    'hp': 'HP',
    'xiaomi': 'Xiaomi',
    'samsung electronics': 'Samsung',
    'samsung': 'Samsung',
    'asus': 'ASUS',
    'asustek computer': 'ASUS',
    'acer': 'Acer',
    'msi': 'MSI',
    'micro-star international': 'MSI',
    'gigabyte': 'Gigabyte',
    'sony': 'Sony',
    'lg electronics': 'LG',
    'lg': 'LG',
    'microsoft': 'Microsoft',
    'intel': 'Intel',
    'amd': 'AMD',
    'nvidia': 'NVIDIA',
    'vmware': 'VMware',
    'google': 'Google',
    'amazon': 'Amazon',
    'facebook': 'Meta',
    'meta': 'Meta',
    'netgear': 'NETGEAR',
    'ubiquiti': 'Ubiquiti',
    'ubiquiti networks': 'Ubiquiti',
    'h3c': 'H3C',
    'h3c technologies': 'H3C',
    'ruijie networks': 'Ruijie',
    'ruijie': 'Ruijie',
    'mercury': 'Mercury',
    'fast': 'FAST',
    'tenda': 'Tenda',
    'zte': 'ZTE',
    'fiberhome': 'FiberHome',
    'fiberhome telecommunication technologies': 'FiberHome',
    'nokia': 'Nokia',
    'ericsson': 'Ericsson',
    'motorola': 'Motorola',
    'blackberry': 'BlackBerry',
    'oneplus': 'OnePlus',
    'oppo': 'OPPO',
    'vivo': 'vivo',
    'meizu': 'Meizu',
    'lenovo mobile': 'Lenovo',
    'lcfc(hefei) electronics technology': 'Lenovo',
    'lcfc(hefei) electronics': 'Lenovo',
    'lcfc hefei electronics': 'Lenovo',
    'lcfc electronics': 'Lenovo',
    'hon device technology': 'Honor',
    'honor': 'Honor',
    'realme': 'Realme',
    'tcl king': 'TCL',
    'tcl': 'TCL',
    'hisense': 'Hisense',
    'haier': 'Haier',
    'midea': 'Midea',
    'gree': 'Gree',
    'canon': 'Canon',
    'epson': 'Epson',
    'brother industries': 'Brother',
    'brother': 'Brother',
    'xerox': 'Xerox',
    'ricoh': 'Ricoh',
    'lexmark': 'Lexmark',
    'kyocera': 'Kyocera',
    'sharp': 'Sharp',
    'panasonic': 'Panasonic',
    'toshiba': 'Toshiba',
    'fujifilm': 'Fujifilm',
    'synology': 'Synology',
    'qnap': 'QNAP',
    'asus teck': 'ASUS',
    'buffalo': 'Buffalo',
    'seagate': 'Seagate',
    'western digital': 'WD',
    'wd': 'WD',
    'toshiba information systems': 'Toshiba',
    'advantech': 'Advantech',
    'd-link': 'D-Link',
    'd link': 'D-Link',
    'zyxel': 'Zyxel',
    'mikrotik': 'MikroTik',
    'fortinet': 'Fortinet',
    'palo alto': 'Palo Alto',
    'juniper': 'Juniper',
    'aruba': 'Aruba',
    'extreme networks': 'Extreme',
    'brocade': 'Brocade',
    'f5 networks': 'F5',
    'check point': 'Check Point',
    'sophos': 'Sophos',
    'watchguard': 'WatchGuard',
    'barracuda': 'Barracuda',
    'sonicwall': 'SonicWall',
    'ubiquiti networks inc': 'Ubiquiti',
    'arista networks': 'Arista',
    'mellanox': 'Mellanox',
    'inspur': 'Inspur',
    'inspur electronic': 'Inspur',
    'sugon': 'Sugon',
    'h3c technologies co': 'H3C',
    'new h3c technologies': 'H3C',
    'hp inc.': 'HP',
    'hewlett-packard company': 'HP',
    'hewlett packard company': 'HP',
    'dell inc.': 'Dell',
    'dell computer': 'Dell',
    'dell technologies': 'Dell',
    'ibm': 'IBM',
    'oracle': 'Oracle',
    'emc': 'EMC',
    'vmware,': 'VMware',
    'citrix': 'Citrix',
    'red hat': 'Red Hat',
    'suse': 'SUSE',
    'ubuntu': 'Ubuntu',
    'raspberry pi': 'Raspberry Pi',
    'arduino': 'Arduino',
    'espressif': 'Espressif',
    'espressif inc': 'Espressif',
    'realtek': 'Realtek',
    'broadcom': 'Broadcom',
    'qualcomm': 'Qualcomm',
    'mediatek': 'MediaTek',
    'marvell': 'Marvell',
    'texas instruments': 'TI',
    'stmicroelectronics': 'ST',
    'nordic semiconductor': 'Nordic',
    'nxp': 'NXP',
    'microchip': 'Microchip',
    'silicon labs': 'Silicon Labs',
    ' infineon': 'Infineon',
    'cypress': 'Cypress',
}


def simplify_vendor_name(vendor: str) -> str:
    """
    简化厂商名称，去除常见的公司后缀，使显示更简洁
    
    Args:
        vendor: 原始厂商名称
        
    Returns:
        简化后的厂商名称
    """
    original = vendor
    
    v = vendor.strip()
    
    # 反复去除后缀（可能有多个后缀叠加）
    changed = True
    while changed:
        changed = False
        
        # 常见公司后缀（大小写不敏感匹配，按长度从长到短排序）
        suffixes = [
            ' Co., Ltd.', ' Co., Ltd', ' Co.,Ltd.', ' Co.,Ltd',
            ' Co. Ltd.', ' Co. Ltd',
            ' Co.,LTD.', ' Co.,LTD',
            ', Inc.', ', Inc', ' Inc.', ' Inc',
            ', Ltd.', ', Ltd', ' Ltd.', ' Ltd',
            ', Limited', ' Limited',
            ' Corporation', ' Corp.', ' Corp',
            ' Incorporated',
            ' GmbH & Co. KG', ' GmbH',
            ' S.p.A.',
            ' B.V.', ' BV',
            ' S.A.', ' SA',
            ' A/S',
            ' K.K.',
            ' LLC',
            ' LLP',
            ' AB',
            ' PLC',
            ' Ltda',
            ',',
        ]
        
        v_lower = v.lower()
        for suffix in suffixes:
            suffix_lower = suffix.lower()
            if v_lower.endswith(suffix_lower):
                v = v[:-len(suffix)].strip()
                changed = True
                break
    
    # 清理多余空白
    v = re.sub(r'\s+', ' ', v).strip()
    
    # 规范化常见厂商名称
    v_lower = v.lower().strip()
    if v_lower in VENDOR_NORMALIZE:
        v = VENDOR_NORMALIZE[v_lower]
    
    return v if v else original


def generate_python_code(oui_dict: dict, output_path: str, use_simple_names: bool = True):
    """
    生成 Python 代码文件，包含 MAC_OUI_VENDORS 字典和 get_mac_vendor 函数
    
    Args:
        oui_dict: OUI 字典
        output_path: 输出文件路径
        use_simple_names: 是否使用简化的厂商名称
    """
    # 按 OUI 排序
    sorted_ouis = sorted(oui_dict.keys())
    
    lines = []
    lines.append('# -*- coding: utf-8 -*-')
    lines.append('"""')
    lines.append('MAC OUI 厂商数据库')
    lines.append(f'数据来源: IEEE 官方 OUI 数据库 (共 {len(sorted_ouis)} 条记录)')
    lines.append('"""')
    lines.append('')
    lines.append('')
    lines.append('MAC_OUI_VENDORS = {')
    
    for oui in sorted_ouis:
        vendor = oui_dict[oui]
        if use_simple_names:
            vendor = simplify_vendor_name(vendor)
        # 转义引号
        vendor_escaped = vendor.replace('"', '\\"')
        lines.append(f'    "{oui}": "{vendor_escaped}",')
    
    lines.append('}')
    lines.append('')
    lines.append('')
    lines.append('def get_mac_vendor(mac: str) -> str:')
    lines.append('    """根据 MAC 地址获取厂商名称"""')
    lines.append('    if not mac:')
    lines.append('        return ""')
    lines.append('    mac = mac.lower().replace("-", ":")')
    lines.append('    if len(mac) < 8:')
    lines.append('        return ""')
    lines.append('    oui = mac[:8]')
    lines.append('    return MAC_OUI_VENDORS.get(oui, "")')
    lines.append('')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"已生成 {output_path}，共 {len(sorted_ouis)} 条记录")


def main():
    oui_txt_path = r"C:\Users\Koofy\Desktop\oui.txt"
    output_path = r"d:\Tools\IPScanner\oui_database.py"
    
    print(f"正在解析 {oui_txt_path} ...")
    oui_dict = parse_ieee_oui(oui_txt_path)
    print(f"解析完成，共 {len(oui_dict)} 条 OUI 记录")
    
    # 打印前10条测试
    print("\n前10条记录:")
    for i, (oui, vendor) in enumerate(sorted(oui_dict.items())[:10]):
        simple = simplify_vendor_name(vendor)
        print(f"  {oui} -> {vendor} (简化: {simple})")
    
    # 生成 Python 代码文件
    print(f"\n正在生成数据库文件...")
    generate_python_code(oui_dict, output_path, use_simple_names=True)
    
    print("\n完成！")


if __name__ == '__main__':
    main()
