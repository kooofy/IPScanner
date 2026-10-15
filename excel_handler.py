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
from typing import Dict, List, Tuple
import re
import csv
from i18n import tr
import i18n


# 列名别名映射：这是**匹配表**，必须语言无关，因此全部写成字面量，绝不能包 tr()。
#
# 历史缺陷：这里原本写的是 tr("ip地址")。i18n.init() 早于 excel_handler 的导入，
# 所以英文模式下这些别名在导入期就被求值成 "IP Address" —— 于是随版本内置的中文
# 模板 设备清单模板.xlsx 在英文界面下**完全无法导入**（detect_columns 返回空字典，
# 用户看到的是"未找到 IP/MAC 列"）。
# 现在中英文别名同时以字面量列出：Excel 用哪种语言写都能匹配，与界面语言彻底解耦。
#
# 匹配前统一 .strip().lower()（见 detect_columns），故这里全部小写。
COLUMN_ALIASES = {
    "ip": [
        "ip地址", "ip address", "主机地址", "host address", "ip", "ipaddress", "ip_address",
        "ip addr"
    ],
    "mac": [
        "mac地址", "mac address", "物理地址", "physical address", "网卡地址", "nic address", "有线mac",
        "wired mac", "无线mac", "wireless mac", "网卡mac", "nic mac", "计算机mac地址",
        "computer mac address", "计算机mac", "computer mac", "电脑mac", "pc mac", "终端mac",
        "terminal mac", "本机mac", "local mac", "无线网卡mac", "wireless nic mac", "mac",
        "macaddress", "mac_address", "mac addr", "lan-mac", "wifi-mac", "lanmac", "wifimac"
    ],
    "device_type": [
        "设备类型", "device type", "类型", "type", "设备", "device", "终端类型", "terminal type", "功能教室",
        "function room", "打印机型号", "printer model", "型号", "model", "设备名称", "device name", "一体机",
        "mfp", "devicetype", "device_type"
    ],
    "location": [
        "位置", "location", "部署位置", "deployment location", "机房", "server room", "房间", "room",
        "楼层", "floor", "安装位置", "install location", "楼宇", "building", "门牌", "door no.", "门牌号",
        "door plate no.", "处室名称", "office name", "处室", "office", "房间号", "room no.", "地点", "区域",
        "area", "楼层位置", "floor location", "部门", "department", "place"
    ],
    "user": [
        "使用者", "user", "用户", "负责人", "owner", "使用人", "归属", "姓名", "name", "使用教师", "teacher",
        "使用人/部门", "user/dept", "使用部门", "department"
    ],
    "remark": [
        "备注", "remark", "说明", "description", "描述", "note", "notes", "comment"
    ],
}


# ── 面向用户的提示语（v2.2 §3.4-b）──────────────────────────────────────
#
# 🔴 这些**必须**走 `tr("… {占位} …").format(...)`，不能写成裸 f-string：
# 裸 f-string 里的中文是**字面量**，AST 的 i18n 完整性测试收集不到它，
# 于是英文界面下会漏出中文（"已导出 3 条记录到 …"）而**没有任何告警**。
# 占位符用 `{n}` / `{path}` / `{err}` 命名（翻译时语序可以调整）。

def _exported_text(n: int, path: str) -> str:
    """导出成功提示：`已导出 3 条记录到 D:\\out.xlsx`。"""
    return tr("已导出 {n} 条记录到 {path}").format(n=n, path=path)


def _export_failed_text(err) -> str:
    """导出失败提示（保留原始异常文本，便于用户自查）。"""
    return tr("导出失败: {err}").format(err=err)


def _template_created_text(path: str) -> str:
    """模板生成成功提示。"""
    return tr("模板已生成: {path}").format(path=path)


def _template_failed_text(err) -> str:
    """模板生成失败提示。"""
    return tr("生成模板失败: {err}").format(err=err)


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
        return True, _exported_text(len(results), file_path)
    except Exception as e:
        return False, _export_failed_text(e)


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
        return True, _exported_text(len(results), file_path)
    except Exception as e:
        return False, _export_failed_text(e)


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
        # 🔴 标题 / 摘要行也走 tr(...).format(...)：这是**用户会打开的文件**，
        # 英文界面下导出的 HTML 里出现中文，与"导出提示"是同一类漏翻
        # （裸 f-string 是字面量，AST 完整性测试收集不到）。
        html = (
            "<!DOCTYPE html><html lang='%s'><head><meta charset='utf-8'>" % i18n.current_lang()
            + tr("<title>IPScanner 扫描结果</title></head><body>")
            + "<h2>" + tr("局域网扫描结果") + "</h2>"
            + "<p>" + tr("共 {n} 条记录，{m} 台在线，导出时间 {t}").format(
                n=len(results), m=online_count,
                t=datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "</p>"
            + table + "</body></html>"
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)
        return True, _exported_text(len(results), file_path)
    except Exception as e:
        return False, _export_failed_text(e)


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
        return True, _exported_text(len(results), file_path)
    except Exception as e:
        return False, _export_failed_text(e)


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
        return True, _template_created_text(file_path)
    except Exception as e:
        return False, _template_failed_text(e)
