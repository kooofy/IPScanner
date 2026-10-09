# -*- coding: utf-8 -*-
"""OUI 数据库更新混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import QMessageBox, QProgressDialog
from PyQt5.QtCore import Qt
from ui_msg import msg_ask, msg_info, msg_warn
from i18n import tr

class OuiMixin:
    def _update_oui_db(self):
        """从 IEEE 官网下载最新 OUI 数据库并重建 oui.db。"""
        reply = msg_ask(
            self, tr("检查 OUI 更新"),
            tr("将从 IEEE 官网下载最新的 MAC 厂商数据库（约 2MB），\n"
               "并重建本地 OUI 数据库。是否继续？"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )
        if reply != QMessageBox.Yes:
            return

        self._oui_progress = QProgressDialog(
            tr("正在更新 OUI 数据库..."), tr("取消"), 0, 100, self
        )
        self._oui_progress.setWindowTitle(tr("OUI 更新"))
        self._oui_progress.setWindowModality(Qt.WindowModal)
        self._oui_progress.setMinimumDuration(0)
        self._oui_progress.canceled.connect(self._oui_cancel_update)
        self._oui_cancelled = False

        from ui_threads import OuiUpdateThread
        self._oui_thread = OuiUpdateThread()
        self._oui_thread.log_signal.connect(self._oui_update_log)
        self._oui_thread.progress_signal.connect(self._oui_progress.setValue)
        self._oui_thread.finished_signal.connect(self._oui_update_finished)
        self._oui_thread.start()

    def _oui_cancel_update(self):
        self._oui_cancelled = True
        if hasattr(self, '_oui_thread') and self._oui_thread.isRunning():
            self._oui_thread.terminate()
            self._oui_thread.wait(2000)

    def _oui_update_log(self, msg: str):
        if hasattr(self, '_oui_progress') and self._oui_progress.isVisible():
            self._oui_progress.setLabelText(msg)

    def _oui_update_finished(self, result: dict):
        self._oui_progress.close()
        if self._oui_cancelled:
            return

        if result.get("success"):
            # 重新加载数据库连接
            from oui_database import reload_db
            reload_db()
            msg_info(
                self, tr("OUI 更新"),
                tr("OUI 数据库更新成功！\n\n")
                + f"共 {result['count']:,} 条记录\n"
                + f"保存至: {result['path']}"
            )
        else:
            msg_warn(
                self, tr("OUI 更新失败"),
                tr("更新 OUI 数据库时出错：\n") + result.get("error", tr("未知错误"))
            )

