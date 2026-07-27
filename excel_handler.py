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
from i18n import tr


# 列名别名映射 (小写精确匹配)。一个字段可对应多列 (多 MAC / 多位置列)
COLUMN_ALIASES = {
    "ip": ["ip", tr("ip地址"), "ipaddress", "ip_address", "ip addr", tr("主机地址")],
    "mac": ["mac", tr("mac地址"), "macaddress", "mac_address", "mac addr", tr("物理地址"), tr("网卡地址"),
            "lan-mac", "wifi-mac", "lanmac", "wifimac", tr("有线mac"), tr("无线mac"), tr("网卡mac"),
            tr("计算机mac地址"), tr("计算机mac"), tr("电脑mac"), tr("终端mac"), tr("本机mac"), tr("无线网卡mac")],
    "device_type": [tr("设备类型"), tr("类型"), "devicetype", "device_type", tr("设备"), "device", tr("终端类型"),
                    tr("功能教室"), tr("打印机型号"), tr("型号"), tr("设备名称"), tr("一体机")],
    "location": [tr("位置"), "location", tr("部署位置"), tr("机房"), tr("房间"), tr("楼层"), tr("安装位置"), "place",
                 tr("楼宇"), tr("门牌"), tr("门牌号"), tr("处室名称"), tr("处室"), tr("房间号"), tr("地点"), tr("区域"), tr("楼层位置"), tr("部门")],
    "user": [tr("使用者"), tr("用户"), "user", tr("负责人"), tr("使用人"), tr("归属"), "owner", tr("姓名"), tr("使用教师"), tr("使用人/部门"), tr("使用部门")],
    "remark": [tr("备注"), tr("说明"), "remark", "note", "notes", tr("描述"), "description", "comment"],
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
        ws.title = tr("扫描结果")

        # 表头
        headers = [
            tr("IP地址"), tr("状态"), tr("主机名"), tr("MAC地址"), tr("厂商"),
            tr("设备类型"), tr("设备型号"), tr("位置"), tr("使用者"),
            tr("响应时间(ms)"), tr("开放端口"), tr("共享文件夹"), tr("发现方式"), tr("端口探测方式"), tr("操作系统"), tr("备注")
        ]

        # 样式
        header_font = Font(name=tr("微软雅黑"), size=11, bold=True, color="FFFFFF")
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
        cell_font = Font(name=tr("微软雅黑"), size=10)
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

            is_online = data.get(tr("状态")) == tr("在线")
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
            tr("IP地址"): 16, tr("状态"): 8, tr("主机名"): 20, tr("MAC地址"): 20, tr("厂商"): 12,
            tr("设备类型"): 12, tr("设备型号"): 22, tr("位置"): 20, tr("使用者"): 12,
            tr("响应时间(ms)"): 14, tr("开放端口"): 30, tr("共享文件夹"): 30, tr("发现方式"): 12, tr("端口探测方式"): 14, tr("操作系统"): 16, tr("备注"): 20,
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
            tr("IP地址"), tr("状态"), tr("主机名"), tr("MAC地址"), tr("厂商"),
            tr("设备类型"), tr("设备型号"), tr("位置"), tr("使用者"),
            tr("响应时间(ms)"), tr("开放端口"), tr("共享文件夹"), tr("发现方式"), tr("端口探测方式"), tr("操作系统"), tr("备注")
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
            tr("IP地址"), tr("状态"), tr("主机名"), tr("MAC地址"), tr("厂商"),
            tr("设备类型"), tr("设备型号"), tr("位置"), tr("使用者"),
            tr("响应时间(ms)"), tr("开放端口"), tr("共享文件夹"), tr("发现方式"), tr("端口探测方式"), tr("操作系统"), tr("备注")
        ]
        rows_html = []
        for result in results:
            d = _result_to_row(result)
            is_online = d.get(tr("状态")) == tr("在线")
            bg = "#e6f9ed" if is_online else "#fdecec"
            color = "#16713a" if is_online else "#b3261e"
            tds = []
            for h in headers:
                val = str(d.get(h, "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                if h == tr("状态"):
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
        online_count = sum(1 for r in results if _result_to_row(r).get(tr("状态")) == tr("在线"))
        html = (
            "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>" + tr("<title>IPScanner 扫描结果</title></head><body>") + f"<h2>局域网扫描结果</h2>"
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
        ws.title = tr("设备清单")

        headers = [tr("IP地址"), tr("MAC地址"), tr("设备类型"), tr("位置"), tr("使用者"), tr("备注")]
        samples = [
            ["192.168.1.1", "aa:bb:cc:dd:ee:ff", tr("路由器"), tr("机房A-机柜1"), tr("网络管理员"), tr("主网关")],
            ["192.168.1.10", "", "PC", tr("3楼-301办公室"), tr("张三"), tr("财务部")],
            ["192.168.1.20", "", tr("打印机"), tr("3楼-打印区"), tr("公共"), "HP LaserJet"],
            ["192.168.1.100", "", tr("服务器"), tr("机房B-机柜2"), tr("IT部"), tr("文件服务器")],
            ["192.168.1.200", "", tr("摄像头"), tr("1楼-大厅"), tr("安保部"), tr("海康威视")],
        ]

        # 样式
        header_font = Font(name=tr("微软雅黑"), size=11, bold=True, color="FFFFFF")
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

        cell_font = Font(name=tr("微软雅黑"), size=10)
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
