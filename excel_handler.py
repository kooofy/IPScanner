# -*- coding: utf-8 -*-
"""
Excel 导入/导出处理模块
支持 .xls / .xlsx、列名自动识别、多 MAC 列、IP/MAC 匹配、多文件合并、结果导出
"""

import os
import openpyxl
import xlrd
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from typing import Dict, List, Optional, Tuple
import re


# 列名别名映射 (小写精确匹配)。一个字段可对应多列 (多 MAC / 多位置列)
COLUMN_ALIASES = {
    "ip": ["ip", "ip地址", "ipaddress", "ip_address", "ip addr", "主机地址"],
    "mac": ["mac", "mac地址", "macaddress", "mac_address", "mac addr", "物理地址", "网卡地址",
            "lan-mac", "wifi-mac", "lanmac", "wifimac", "有线mac", "无线mac", "网卡mac",
            "计算机mac地址", "计算机mac", "电脑mac", "终端mac", "本机mac", "无线网卡mac"],
    "device_type": ["设备类型", "类型", "devicetype", "device_type", "设备", "device", "终端类型",
                    "功能教室", "打印机型号", "型号", "设备名称", "一体机"],
    "location": ["位置", "location", "部署位置", "机房", "房间", "楼层", "安装位置", "place",
                 "楼宇", "门牌", "门牌号", "处室名称", "处室", "房间号", "地点", "区域", "楼层位置", "部门"],
    "user": ["使用者", "用户", "user", "负责人", "使用人", "归属", "owner", "姓名", "使用教师", "使用人/部门", "使用部门"],
    "remark": ["备注", "说明", "remark", "note", "notes", "描述", "description", "comment"],
}


def _cell_to_str(val) -> str:
    """单元格值统一转字符串"""
    if val is None:
        return ""
    if isinstance(val, float):
        if val == int(val):
            return str(int(val))
        return str(val)
    if isinstance(val, int):
        return str(val)
    return str(val).strip()


def normalize_mac(mac: str) -> str:
    """统一 MAC 地址格式为 aa:bb:cc:dd:ee:ff"""
    if not mac:
        return ""
    mac = str(mac).strip().lower()
    mac = re.sub(r"[^0-9a-f]", "", mac)
    if len(mac) == 12:
        return ":".join(mac[i:i+2] for i in range(0, 12, 2))
    return mac


def detect_columns(headers: List[str]) -> Dict[str, List[int]]:
    """
    自动检测 Excel 列对应的字段。
    返回 {字段名: [列索引列表]}，一个字段可命中多列 (如 LAN-MAC + WIFI-MAC)。
    """
    mapping = {}
    for field, aliases in COLUMN_ALIASES.items():
        cols = []
        for col_idx, header in enumerate(headers):
            h = str(header).strip().lower()
            if h and h in aliases:
                cols.append(col_idx)
        if cols:
            mapping[field] = cols
    return mapping


def _read_rows(file_path: str) -> List[tuple]:
    """读取工作簿首个工作表，返回二维行数据 (含表头行)"""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".xls":
        wb = xlrd.open_workbook(file_path)
        ws = wb.sheet_by_index(0)
        rows = []
        for r in range(ws.nrows):
            rows.append(tuple(ws.cell_value(r, c) for c in range(ws.ncols)))
        return rows
    else:
        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
        ws = wb.active
        rows = list(ws.iter_rows(values_only=True))
        wb.close()
        return rows


class ExcelHandler:
    """Excel 文件处理"""

    def __init__(self):
        self.data_by_ip: Dict[str, dict] = {}
        self.data_by_mac: Dict[str, dict] = {}
        self.file_path: str = ""
        self.headers: List[str] = []
        self.column_mapping: Dict[str, List[int]] = {}
        self.row_count: int = 0
        self.source_files: List[str] = []

    def load(self, file_path: str, append: bool = False) -> Tuple[bool, str]:
        """
        加载 Excel 文件。
        append=True 时不清空已有数据 (用于多文件合并导入)。
        Returns: (是否成功, 消息)
        """
        self.file_path = file_path

        # 先读取，读取失败不影响已有数据
        try:
            rows = _read_rows(file_path)
        except Exception as e:
            return False, f"无法打开文件: {e}"

        if not rows:
            return False, "文件为空"

        if not append:
            self.data_by_ip.clear()
            self.data_by_mac.clear()
            self.row_count = 0
            self.source_files = []

        # 定位表头行：前 15 行内找第一个含已识别字段别名的行 (兼容首行是大标题的情况)
        header_row_idx = 0
        for idx in range(min(15, len(rows))):
            hdr = [str(h).strip().lower() if h is not None else "" for h in rows[idx]]
            if any(any(h in aliases for h in hdr) for aliases in COLUMN_ALIASES.values()):
                header_row_idx = idx
                break

        raw_headers = [str(h).strip() if h is not None else "" for h in rows[header_row_idx]]
        self.headers = raw_headers
        self.column_mapping = detect_columns(raw_headers)

        if "ip" not in self.column_mapping and "mac" not in self.column_mapping:
            return False, "未找到 IP/MAC 列，无法在扫描时自动匹配设备（请在清单中补充 MAC 或 IP 列后重试）"

        ip_cols = self.column_mapping.get("ip", [])
        mac_cols = self.column_mapping.get("mac", [])
        ip_col = ip_cols[0] if ip_cols else None
        added = 0

        for row in rows[header_row_idx + 1:]:
            if not row or all(c is None or str(c).strip() == "" for c in row):
                continue

            entry = {}
            for field, cols in self.column_mapping.items():
                vals = []
                for c in cols:
                    if c < len(row):
                        v = _cell_to_str(row[c])
                        if v:
                            vals.append(v)
                if vals:
                    entry[field] = " ".join(vals)

            # 取一个 MAC 原文用于显示 (不影响匹配，匹配走 data_by_mac)
            if mac_cols:
                for c in mac_cols:
                    if c < len(row):
                        m = _cell_to_str(row[c])
                        if m:
                            entry["mac"] = m
                            break

            # IP 索引
            if ip_col is not None and ip_col < len(row):
                ip_val = _cell_to_str(row[ip_col]).strip()
                if ip_val:
                    self.data_by_ip[ip_val] = entry

            # MAC 索引 (所有 MAC 列都建索引，一个设备多网卡也能匹配)
            matched_mac = False
            for c in mac_cols:
                if c < len(row):
                    m = normalize_mac(_cell_to_str(row[c]))
                    if m:
                        self.data_by_mac[m] = entry
                        matched_mac = True

            # 既没有 IP 也没有 MAC 的行无意义，跳过
            if not entry.get("ip") and not matched_mac:
                continue

            self.row_count += 1
            added += 1

        if added == 0:
            return False, "MAC/IP 数据为空，该文件无法在扫描时自动匹配设备（请检查 MAC 列是否已填写）"

        if file_path not in self.source_files:
            self.source_files.append(file_path)

        msg = f"已从 {os.path.basename(file_path)} 载入 {added} 条 (累计 {self.row_count} 条)"
        detected = list(self.column_mapping.keys())
        msg += f"\n识别字段: {', '.join(detected)}"
        return True, msg

    def match(self, ip: str, mac: str = "") -> Optional[dict]:
        """
        通过 IP 或 MAC 匹配设备信息。
        优先 IP 精确匹配，其次 MAC 匹配。
        """
        # IP 精确匹配
        if ip and ip in self.data_by_ip:
            return self.data_by_ip[ip]

        # MAC 匹配
        if mac:
            mac_norm = normalize_mac(mac)
            if mac_norm and mac_norm in self.data_by_mac:
                return self.data_by_mac[mac_norm]

        return None

    def is_loaded(self) -> bool:
        return bool(self.data_by_ip or self.data_by_mac)


def export_results(results: list, file_path: str) -> Tuple[bool, str]:
    """
    将扫描结果导出到 Excel。
    results: ScanResult 列表 (或 dict 列表)
    """
    try:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "扫描结果"

        # 表头
        headers = [
            "IP地址", "状态", "主机名", "MAC地址", "厂商",
            "设备类型", "位置", "使用者",
            "响应时间(ms)", "开放端口", "备注"
        ]

        # 样式
        header_font = Font(name="微软雅黑", size=11, bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
        header_align = Alignment(horizontal="center", vertical="center")
        thin_border = Border(
            left=Side(style="thin", color="D1D5DB"),
            right=Side(style="thin", color="D1D5DB"),
            top=Side(style="thin", color="D1D5DB"),
            bottom=Side(style="thin", color="D1D5DB"),
        )
        online_fill = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid")
        offline_fill = PatternFill(start_color="FEF2F2", end_color="FEF2F2", fill_type="solid")
        cell_font = Font(name="微软雅黑", size=10)
        cell_align = Alignment(horizontal="left", vertical="center")

        # 写表头
        for col_idx, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align
            cell.border = thin_border

        # 写数据
        for row_idx, result in enumerate(results, 2):
            if hasattr(result, "to_dict"):
                data = result.to_dict()
            elif isinstance(result, dict):
                data = result
            else:
                continue

            is_online = data.get("状态") == "在线"
            fill = online_fill if is_online else offline_fill

            for col_idx, header in enumerate(headers, 1):
                value = data.get(header, "")
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.font = cell_font
                cell.alignment = cell_align
                cell.border = thin_border
                cell.fill = fill

        # 自动列宽
        col_widths = {
            "IP地址": 16, "状态": 8, "主机名": 20, "MAC地址": 20, "厂商": 12,
            "设备类型": 12, "位置": 20, "使用者": 12,
            "响应时间(ms)": 14, "开放端口": 30, "备注": 20,
        }
        for col_idx, header in enumerate(headers, 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = col_widths.get(header, 15)

        # 冻结首行
        ws.freeze_panes = "A2"

        # 自动筛选
        ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}1"

        wb.save(file_path)
        wb.close()
        return True, f"已导出 {len(results)} 条记录到 {file_path}"
    except Exception as e:
        return False, f"导出失败: {e}"


def create_template(file_path: str) -> Tuple[bool, str]:
    """生成 Excel 模板文件"""
    try:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "设备清单"

        headers = ["IP地址", "MAC地址", "设备类型", "位置", "使用者", "备注"]
        samples = [
            ["192.168.1.1", "aa:bb:cc:dd:ee:ff", "路由器", "机房A-机柜1", "网络管理员", "主网关"],
            ["192.168.1.10", "", "PC", "3楼-301办公室", "张三", "财务部"],
            ["192.168.1.20", "", "打印机", "3楼-打印区", "公共", "HP LaserJet"],
            ["192.168.1.100", "", "服务器", "机房B-机柜2", "IT部", "文件服务器"],
            ["192.168.1.200", "", "摄像头", "1楼-大厅", "安保部", "海康威视"],
        ]

        # 样式
        header_font = Font(name="微软雅黑", size=11, bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
        header_align = Alignment(horizontal="center", vertical="center")
        thin_border = Border(
            left=Side(style="thin", color="D1D5DB"),
            right=Side(style="thin", color="D1D5DB"),
            top=Side(style="thin", color="D1D5DB"),
            bottom=Side(style="thin", color="D1D5DB"),
        )

        for col_idx, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align
            cell.border = thin_border

        cell_font = Font(name="微软雅黑", size=10)
        cell_align = Alignment(horizontal="left", vertical="center")
        for row_idx, sample in enumerate(samples, 2):
            for col_idx, value in enumerate(sample, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.font = cell_font
                cell.alignment = cell_align
                cell.border = thin_border

        col_widths = [18, 22, 12, 22, 14, 20]
        for col_idx, width in enumerate(col_widths, 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = width

        ws.freeze_panes = "A2"

        wb.save(file_path)
        wb.close()
        return True, f"模板已生成: {file_path}"
    except Exception as e:
        return False, f"生成模板失败: {e}"
