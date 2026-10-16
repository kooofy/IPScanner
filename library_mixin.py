# -*- coding: utf-8 -*-
"""MAC 地址库管理混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import QDialog, QMessageBox
from ui_dialogs import AssetEditDialog, MacLibraryDialog, DeviceEditDialog
import audit_log
import history_store
from app_logging import get_logger
from ui_msg import msg_ask, msg_warn
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

