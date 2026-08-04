# -*- coding: utf-8 -*-
"""导入导出与打印操作混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
import os
from datetime import datetime
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from PyQt5.QtGui import QTextDocument, QPageLayout, QPageSize
from PyQt5.QtPrintSupport import QPrinter, QPrintPreviewDialog
from excel_handler import (
    export_results, export_csv, export_html, export_json, create_template
)
import audit_log
from i18n import tr

class ExportMixin:
    def _import_excel(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, tr("选择 Excel 文件（可多选，自动合并进地址库）"), "",
            tr("Excel 文件 (*.xlsx *.xls);;所有文件 (*.*)")
        )
        if not files:
            return

        ok_files = 0
        errs = []
        for f in files:
            success, msg = self.library.merge_from_excel(f)
            if success:
                ok_files += 1
                self.status_bar.showMessage(msg)
            else:
                errs.append(f"{os.path.basename(f)}: {msg}")

        self._refresh_library_label()

        # 审计：记录地址库导入
        if ok_files:
            self._audit(
                audit_log.CAT_LIBRARY, tr("导入地址库"),
                f"合并 {ok_files} 个文件 · 地址库共 {self.library.count()} 条"
                + (f" · 失败 {len(errs)} 个" if errs else ""),
            )

        # 若已有扫描结果，按新地址库重新匹配标注
        if self.all_results:
            self._refresh_matches_from_library()

        if errs:
            QMessageBox.warning(self, tr("部分文件导入失败"), "\n".join(errs))
        elif ok_files:
            QMessageBox.information(
                self, tr("导入成功"),
                f"已合并 {ok_files} 个文件到地址库，共 {self.library.count()} 条。\n"
                f"扫描联网设备后将自动按 MAC 匹配。"
            )

    def _export_library(self):
        default_name = f"MAC地址库_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        file_path, _ = QFileDialog.getSaveFileName(
            self, tr("导出地址库"), default_name, tr("Excel 文件 (*.xlsx)")
        )
        if not file_path:
            return
        success, msg = self.library.export_to_excel(file_path)
        if success:
            self._audit(
                audit_log.CAT_EXPORT, tr("导出地址库"),
                f"{self.library.count()} 条 · {os.path.basename(file_path)}",
            )
            self.status_bar.showMessage(msg)
            QMessageBox.information(self, tr("导出成功"), msg)
        else:
            QMessageBox.warning(self, tr("导出失败"), msg)

    def _generate_template(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, tr("保存 Excel 模板"), tr("设备清单模板.xlsx"),
            tr("Excel 文件 (*.xlsx)")
        )
        if not file_path:
            return
        success, msg = create_template(file_path)
        if success:
            self._audit(
                audit_log.CAT_EXPORT, tr("生成 Excel 模板"),
                os.path.basename(file_path),
            )
            QMessageBox.information(self, tr("成功"), msg)
        else:
            QMessageBox.warning(self, tr("失败"), msg)

    def _export_results(self):
        if not self.all_results:
            QMessageBox.warning(self, tr("提示"), tr("没有可导出的结果"))
            return

        default_name = f"扫描结果_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, tr("导出扫描结果"), default_name,
            tr("Excel 文件 (*.xlsx);;CSV 文件 (*.csv);;HTML 文件 (*.html);;JSON 文件 (*.json)")
        )
        if not file_path:
            return

        # 依据过滤器/后缀决定导出格式（用户未手动加后缀时按过滤器补上）
        path = file_path
        low = path.lower()
        if not (low.endswith(".xlsx") or low.endswith(".csv")
                or low.endswith(".html") or low.endswith(".json")):
            if "CSV" in selected_filter:
                path += ".csv"
            elif "HTML" in selected_filter:
                path += ".html"
            elif "JSON" in selected_filter:
                path += ".json"
            else:
                path += ".xlsx"

        if path.lower().endswith(".csv"):
            success, msg = export_csv(self.all_results, path)
            _fmt = "CSV"
        elif path.lower().endswith(".html"):
            success, msg = export_html(self.all_results, path)
            _fmt = "HTML"
        elif path.lower().endswith(".json"):
            success, msg = export_json(self.all_results, path)
            _fmt = "JSON"
        else:
            success, msg = export_results(self.all_results, path)
            _fmt = "Excel"

        if success:
            self._audit(
                audit_log.CAT_EXPORT, tr("导出扫描结果"),
                f"{_fmt} · {len(self.all_results)} 条 · {os.path.basename(path)}",
            )
            self.status_bar.showMessage(msg)
            QMessageBox.information(self, tr("导出成功"), msg)
        else:
            QMessageBox.warning(self, tr("导出失败"), msg)

    def _print_results(self):
        """将当前扫描结果表格打印 / 导出为 PDF（先弹打印预览对话框）。"""
        if self.table.topLevelItemCount() == 0:
            QMessageBox.information(self, tr("提示"), tr("当前没有可打印的扫描结果，请先执行扫描。"))
            return

        # 仅取可见列（服务列默认隐藏，跳过），只打印设备顶层行
        cols = [c for c in range(self.table.columnCount())
                if not self.table.isColumnHidden(c)]
        headers = [self.table.headerItem().text(c) for c in cols]
        rows = []
        for r in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(r)
            if item.isHidden():   # 跳过被筛选隐藏的行（如"仅在线"下的离线设备），实现所见即所得
                continue
            rows.append([item.text(c) for c in cols])

        doc = QTextDocument()
        doc.setHtml(self._build_results_print_html(headers, rows))

        printer = QPrinter(QPrinter.HighResolution)
        printer.setPageSize(QPageSize(QPageSize.A4))
        printer.setPageOrientation(QPageLayout.Landscape)

        preview = QPrintPreviewDialog(printer, self)
        preview.setWindowTitle(tr("打印预览 - 扫描结果"))
        preview.paintRequested.connect(lambda p: doc.print_(p))
        preview.exec_()

    @staticmethod
    def _build_results_print_html(headers, rows):
        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = ""
        for i, row in enumerate(rows):
            bg = "#F2F2F2" if i % 2 else "#FFFFFF"
            tds = "".join(f"<td>{esc(c)}</td>" for c in row)
            body += f"<tr style='background:{bg};'>{tds}</tr>"
        title = f"局域网扫描结果 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        return (
            "<html><head><meta charset='utf-8'>"
            "<style>"
            "table{border-collapse:collapse;width:100%;font-size:9pt;"
            "font-family:'Microsoft YaHei',SimSun,sans-serif;}"
            "th,td{border:1px solid #999;padding:3px 5px;text-align:left;}"
            "th{background:#2C3E50;color:#FFFFFF;}"
            "</style></head><body>"
            f"<h3 style='margin:0 0 6px 0;'>{esc(title)}</h3>"
            "<table>" + f"<tr>{th}</tr>" + body + "</table></body></html>"
        )

    # --- 关于 ---

