# -*- coding: utf-8 -*-
"""
Excel 导入/导出处理模块
支持 .xls / .xlsx、列名自动识别、多 MAC 列、IP/MAC 匹配、多文件合并、结果导出
"""

import os
import json
import openpyxl
import xlrd
from datetime import datetime
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from typing import Dict, List, Optional, Tuple
import re
import csv


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
            "设备类型", "设备型号", "位置", "使用者",
            "响应时间(ms)", "开放端口", "共享文件夹", "发现方式", "端口探测方式", "操作系统", "备注"
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
            "设备类型": 12, "设备型号": 22, "位置": 20, "使用者": 12,
            "响应时间(ms)": 14, "开放端口": 30, "共享文件夹": 30, "发现方式": 12, "端口探测方式": 14, "操作系统": 16, "备注": 20,
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


def _result_to_row(result) -> dict:
    """统一把 ScanResult / dict 转成导出行字典（含共享文件夹、发现方式）。"""
    if hasattr(result, "to_dict"):
        return result.to_dict()
    if isinstance(result, dict):
        return result
    return {}


def export_csv(results: list, file_path: str) -> Tuple[bool, str]:
    """
    将扫描结果导出为 CSV（UTF-8-SIG，Excel 直接打开中文不乱码）。
    """
    try:
        headers = [
            "IP地址", "状态", "主机名", "MAC地址", "厂商",
            "设备类型", "设备型号", "位置", "使用者",
            "响应时间(ms)", "开放端口", "共享文件夹", "发现方式", "端口探测方式", "操作系统", "备注"
        ]
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for result in results:
                d = _result_to_row(result)
                row = [d.get(h, "") for h in headers]
                writer.writerow(row)
        return True, f"已导出 {len(results)} 条记录到 {file_path}"
    except Exception as e:
        return False, f"导出失败: {e}"


def export_html(results: list, file_path: str) -> Tuple[bool, str]:
    """
    将扫描结果导出为带样式的 HTML 表格（在线/离线行着色）。
    """
    try:
        headers = [
            "IP地址", "状态", "主机名", "MAC地址", "厂商",
            "设备类型", "设备型号", "位置", "使用者",
            "响应时间(ms)", "开放端口", "共享文件夹", "发现方式", "端口探测方式", "操作系统", "备注"
        ]
        rows_html = []
        for result in results:
            d = _result_to_row(result)
            is_online = d.get("状态") == "在线"
            bg = "#e6f9ed" if is_online else "#fdecec"
            color = "#16713a" if is_online else "#b3261e"
            tds = []
            for h in headers:
                val = str(d.get(h, "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                if h == "状态":
                    tds.append(f'<td style="color:{color};font-weight:600;text-align:center">{val}</td>')
                else:
                    tds.append(f"<td>{val}</td>")
            rows_html.append(
                f'<tr style="background:{bg}">{"".join(tds)}</tr>'
            )
        thead = "".join(f"<th>{h}</th>" for h in headers)
        table = (
            '<table border="1" cellspacing="0" cellpadding="6" '
            'style="border-collapse:collapse;font-family:Microsoft YaHei,Segoe UI,Arial;font-size:13px">'
            f"<thead><tr style='background:#2563EB;color:#fff'>{thead}</tr></thead>"
            f"<tbody>{''.join(rows_html)}</tbody></table>"
        )
        online_count = sum(1 for r in results if _result_to_row(r).get("状态") == "在线")
        html = (
            "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<title>IPScanner 扫描结果</title></head><body>"
            f"<h2>局域网扫描结果</h2>"
            f"<p>共 {len(results)} 条记录，{online_count} 台在线，"
            f"导出时间 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
            f"{table}</body></html>"
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)
        return True, f"已导出 {len(results)} 条记录到 {file_path}"
    except Exception as e:
        return False, f"导出失败: {e}"


def export_json(results: list, file_path: str) -> Tuple[bool, str]:
    """
    将扫描结果导出为 JSON（UTF-8，保留完整字段，便于二次处理/接口对接）。
    """
    try:
        rows = []
        for result in results:
            d = _result_to_row(result)
            # 转成普通 dict（to_dict 返回的即 dict），去除空值可选保留
            rows.append(d)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
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
