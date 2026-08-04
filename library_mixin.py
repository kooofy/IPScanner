# -*- coding: utf-8 -*-
"""MAC 地址库管理混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import QDialog, QMessageBox
from ui_dialogs import MacLibraryDialog, DeviceEditDialog
import audit_log
from i18n import tr

class LibraryMixin:
    def _open_library_manager(self):
        dlg = MacLibraryDialog(self.library, self)
        dlg.exec_()
        self._refresh_library_label()
        if self.all_results:
            self._refresh_matches_from_library()

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
        reply = QMessageBox.question(
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

