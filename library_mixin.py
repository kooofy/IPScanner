# -*- coding: utf-8 -*-
"""MAC 地址库管理混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
import os
from datetime import datetime

from PyQt5.QtWidgets import QDialog, QFileDialog, QMessageBox
from ui_dialogs import (
    AssetEditDialog, AssetImportPreviewDialog, MacLibraryDialog, DeviceEditDialog,
)
from ui_dialogs import asset_import_preview
import asset_import
import audit_log
import history_store
from app_logging import get_logger
from ui_msg import msg_ask, msg_info, msg_warn
from i18n import tr

_log = get_logger(__name__)


class LibraryMixin:
    def _open_library_manager(self):
        dlg = MacLibraryDialog(self.library, self)
        dlg.exec_()
        self._refresh_library_label()
        if self.all_results:
            self._refresh_matches_from_library()

    def _edit_asset(self, identity_key):
        """编辑一台设备的**人工台账**字段（v2.3 §3.4）。

        对话框只负责收集与校验，**写入在这里** —— 让对话框自己开库会让"取消"
        也可能留下半截写入，而且没法单测（见 `ui_dialogs/asset_edit.py` 的注释）。

        🔴 写入走 `history_store.update_asset_lifecycle()`，它**只碰生命周期列**，
           不碰扫描写入的列 —— 例行扫描永远不会覆盖这里填的值。
        """
        key = (identity_key or "").strip()
        if not key:
            return
        try:
            asset = history_store.get_asset(key, db_path=self.history_db) or {}
        except Exception as e:  # noqa: BLE001
            # 读不到就按空台账打开 —— 用户至少还能把值填进去。
            _log.warning("读取资产台账失败（%s）: %s", key, e)
            asset = {}
        dlg = AssetEditDialog(key, asset, self)
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            changed = history_store.update_asset_lifecycle(
                key, db_path=self.history_db, **dlg.values())
        except ValueError as e:
            # 对话框已挡过一道校验，这里是**第二道** —— 库层才是权威
            # （比如将来 CLI / 其它入口也复用同一个写入函数）。
            msg_warn(self, tr("资产信息未保存"), str(e))
            return
        except Exception as e:  # noqa: BLE001
            _log.warning("写入资产台账失败（%s）: %s", key, e)
            msg_warn(self, tr("资产信息未保存"), tr("写入失败，详情见日志。"))
            return
        if not changed:
            msg_warn(self, tr("资产信息未保存"),
                     tr("没有找到这台设备的台账行（可能刚被清理）。"))
            return
        # 🔴 缓存必须清掉：`_asset_for()` 按设备键缓存，不清的话用户填完看到的
        #    还是旧值 —— 那会让人以为"没保存上"，然后反复重填。
        getattr(self, "_asset_cache", {}).clear()
        self._refresh_detail_panel(self.table.currentItem())
        self._audit(audit_log.CAT_LIBRARY, tr("编辑资产信息"), key)
        self.status_bar.showMessage(tr("资产信息已保存"))

    def _export_asset_template(self):
        """生成台账导入模板（v2.3.3）：当前资产一台一行铺出来，六个台账列留空。

        为什么默认**铺出当前资产**而不是给一张空表：身份键 `identity_key` 是
        从 MAC 派生的，用户没法自己编 —— 空表等于逼他先去命令行查一遍。
        铺出来之后，他只需要在右边六列填值。

        🔴 模板里**不放示例行**：示例一旦漏删就会跟着导入（产生 notfound），
           更糟的是有人照着示例的假数据改了真设备。说明只写在 xlsx 的第二页。
        """
        default = "资产台账模板_%s.xlsx" % datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self, tr("导出台账模板"), default,
            tr("Excel 工作簿 (*.xlsx);;CSV 文件 (*.csv)"))
        if not path:
            return
        try:
            assets = history_store.list_assets(db_path=self.history_db)
        except Exception as e:  # noqa: BLE001
            _log.warning("读取资产表失败: %s", e)
            msg_warn(self, tr("导出台账模板失败"), tr("读取资产表失败，详情见日志。"))
            return
        try:
            count = asset_import.write_template(
                path, assets=assets,
                notes=[tr(s) for s in asset_import_preview.TEMPLATE_NOTES],
                sheet_title=tr("资产台账"), notes_title=tr("说明"))
        except Exception as e:  # noqa: BLE001 - 目录不存在 / 文件被 Excel 占用
            _log.warning("生成台账模板失败（%s）: %s", path, e)
            msg_warn(self, tr("导出台账模板失败"), str(e))
            return
        self._audit(audit_log.CAT_EXPORT, tr("导出台账模板"),
                    f"{os.path.basename(path)} · {count} 台待填")
        msg_info(self, tr("模板已生成"),
                 tr("共 {n} 台设备待填。填好后用「导入资产信息...」导回。").format(
                     n=count))
        self.status_bar.showMessage(
            tr("已生成台账模板：{n} 台待填").format(n=count))

    def _import_assets(self):
        """批量导入台账字段（v2.3.1）：选文件 → 编译计划 → **预览确认** → 写入。

        为什么中间非要有「预览」这一步：批量导入一次能改几十上百台设备的
        人工台账，而且**没有撤销**。选错文件、把「位置」当成「位置树」、
        误开清空开关，都会一次改掉一大片。所以界面上**从不**选完文件直接写。

        🔴 写入只走 `history_store.update_asset_lifecycle()`（经
           `asset_import.apply_plan()`），只碰生命周期列。
        🔴 判定逻辑与 CLI `assets-import` 是**同一份** `asset_import` ——
           两处口径不一致会让「界面说 12 台、命令行说 13 台」。
        """
        path, _ = QFileDialog.getOpenFileName(
            self, tr("选择台账文件（CSV 或 Excel）"), "",
            tr("台账文件 (*.csv *.xlsx *.xls);;所有文件 (*.*)"))
        if not path:
            return
        try:
            headers, body = asset_import.read_table(path)
        except Exception as e:  # noqa: BLE001 - 缺 openpyxl / 文件被占用 / 不是工作簿
            _log.warning("读取台账文件失败（%s）: %s", path, e)
            msg_warn(self, tr("无法读取台账文件"), str(e))
            return
        try:
            assets = history_store.list_assets(db_path=self.history_db)
        except Exception as e:  # noqa: BLE001
            _log.warning("读取资产表失败: %s", e)
            msg_warn(self, tr("无法读取资产表"), tr("读取失败，详情见日志。"))
            return

        plan = asset_import.build_plan([headers] + list(body), assets)
        problem = plan.get("problem") or ""
        if problem:
            msg_warn(self, tr("这张表用不了"),
                     asset_import_preview.problem_text(problem) + "\n\n"
                     + tr("最省事的办法：先导出一次资产表"
                          "（命令行 `assets -f csv -o 台账.csv`），在它上面改。"))
            return

        name = os.path.basename(path)
        pending = asset_import.pending_count(plan)
        report = asset_import_preview.build_report(plan)
        dlg = AssetImportPreviewDialog(
            report, file_label=tr("文件：{name}").format(name=name),
            can_apply=pending > 0, parent=self)
        if dlg.exec_() != QDialog.Accepted:
            return

        try:
            result = asset_import.apply_plan(plan, db_path=self.history_db)
        except Exception as e:  # noqa: BLE001 - 库层故障：如实报，不假装写完
            _log.warning("导入台账失败（%s）: %s", name, e)
            msg_warn(self, tr("导入失败"), str(e))
            return

        written = result["written"]
        failed = result["failed"]
        # 缓存与详情面板必须刷新，否则用户导入完看到的还是旧值 ——
        # 那会让人以为"没导进去"，然后反复导（与 `_edit_asset` 同一条教训）。
        getattr(self, "_asset_cache", {}).clear()
        self._refresh_detail_panel(self.table.currentItem())
        self._audit(
            audit_log.CAT_LIBRARY, tr("导入资产信息"),
            f"{name} · 写入 {written} 台" + (f" · 失败 {len(failed)} 台"
                                             if failed else ""),
        )

        if failed:
            # 有失败行就把完整报告再摊开一次（只读、只有「关闭」）——
            # 用一句 msg_info 报"部分失败"等于把要改哪几行藏起来了。
            again = AssetImportPreviewDialog(
                asset_import_preview.build_report(plan, written=written),
                file_label=tr("文件：{name}").format(name=name),
                can_apply=False, parent=self)
            again.exec_()
            self.status_bar.showMessage(
                tr("导入完成：写入 {n} 台，{f} 台需要处理").format(
                    n=written, f=len(failed)))
            return

        msg_info(self, tr("导入完成"),
                 tr("已写入 {n} 台设备的台账字段。").format(n=written))
        self.status_bar.showMessage(
            tr("导入完成：写入 {n} 台").format(n=written))

    def _add_to_library(self, ip: str = "", mac: str = ""):
        dlg = DeviceEditDialog(self.library, parent=self, ip=ip, mac=mac)
        if dlg.exec_() == QDialog.Accepted:
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self._audit(
                audit_log.CAT_LIBRARY, tr("新增设备"),
                f"IP {ip or '—'} · MAC {mac or '—'} · 地址库共 {self.library.count()} 条",
            )
            self.status_bar.showMessage(tr("已加入地址库"))

    def _edit_library_entry(self, device_id: int):
        dlg = DeviceEditDialog(self.library, parent=self, device_id=device_id)
        if dlg.exec_() == QDialog.Accepted:
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self._audit(audit_log.CAT_LIBRARY, tr("编辑设备"), f"设备 #{device_id}")

    def _delete_library_entry(self, device_id: int):
        dev = self.library.get_by_id(device_id)
        if not dev:
            return
        label = dev.get("mac") or dev.get("ip") or f"#{device_id}"
        reply = msg_ask(
            self, tr("确认删除"),
            f"确定从地址库删除该设备吗？\n\n{label}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.library.delete(device_id)
            self._refresh_library_label()
            if self.all_results:
                self._refresh_matches_from_library()
            self._audit(
                audit_log.CAT_LIBRARY, tr("删除设备"),
                f"{label} · 地址库余 {self.library.count()} 条",
            )
            self.status_bar.showMessage(tr("已从地址库删除"))

    # --- Excel ---

    def _refresh_library_label(self):
        n = self.library.count()
        if n > 0:
            self.excel_label.setText(f"地址库: {n} 条")
            self.excel_label.setStyleSheet("color: #2E7D32; font-size: 11px; font-weight: bold;")
        else:
            self.excel_label.setText(tr("地址库: 空"))
            self.excel_label.setStyleSheet("color: #888888; font-size: 11px;")

