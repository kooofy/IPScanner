# -*- coding: utf-8 -*-
"""历史快照、审计日志与拓扑视图混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import QProgressDialog
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from ui_dialogs import (
    AuditLogDialog, HistoryCompareDialog, HistoryQueryDialog, TopologyDialog
)
from ui_utils import _detect_gateway
import audit_log
import ui_logic
import history_store
from app_logging import get_logger
from ui_msg import msg_info
from i18n import tr

_log = get_logger(__name__)

class HistoryMixin:
    def _show_audit_log(self):
        """弹出审计日志查看器。"""
        dlg = AuditLogDialog(parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _audit(self, category, action, detail=""):
        """安全地记录一条审计日志：任何异常都不应中断主流程。"""
        try:
            audit_log.log_event(category, action, detail)
        except Exception as e:  # noqa: BLE001
            # 审计失败不能反过来打断用户正在做的操作；但丢审计这件事本身
            # 值得留痕（合规场景下审计缺失是需要追溯的）
            _log.warning("写入审计日志失败（分类 %s / 动作 %s）: %s", category, action, e)

    def _build_snapshot(self, results) -> dict:
        return ui_logic.build_snapshot(results)


    def _save_snapshot(self, results, max_keep: int = 20):
        try:
            snap = self._build_snapshot(results)
            history_store.save_snapshot(
                snap["devices"], ts=snap["time"], max_keep=max_keep,
                db_path=self.history_db,
            )
            # 新快照入库后，详情面板缓存的"历史轨迹"就过期了（见
            # MainWindow._device_timeline_for）。不清的话本次扫描新增的这条
            # 永远不会出现在轨迹里，直到重启程序。
            getattr(self, "_timeline_cache", {}).clear()
        except Exception as e:
            print(tr("保存历史快照失败:"), e)

    def _open_history_compare(self):
        dlg = HistoryCompareDialog(self, db_path=self.history_db)
        dlg.exec_()

    def _open_history_query(self):
        dlg = HistoryQueryDialog(self, db_path=self.history_db,
                                 dark=self.dark_mode)
        dlg.exec_()

    def _open_topology(self):
        if not self.all_results:
            msg_info(self, tr("拓扑视图"), tr("请先完成一次扫描，再查看拓扑。"))
            return
        gw_ip = _detect_gateway()

        # 尝试 LLDP/CDP 拓扑发现（后台线程，避免卡界面）
        self._topo_result = None
        self._topo_progress = QProgressDialog(
            tr("正在发现网络拓扑 (LLDP/CDP)..."), tr("跳过"), 0, 0, self
        )
        self._topo_progress.setWindowTitle(tr("拓扑发现"))
        self._topo_progress.setWindowModality(Qt.WindowModal)
        self._topo_progress.setMinimumDuration(0)

        class TopoThread(QThread):
            finished_signal = pyqtSignal(object)
            log_signal = pyqtSignal(str)

            def __init__(self, results):
                super().__init__()
                self.results = results

            def run(self):
                try:
                    from topology_discovery import discover_topology
                    topo = discover_topology(
                        self.results,
                        progress_callback=lambda p, c, t, m: self.log_signal.emit(m)
                    )
                    self.finished_signal.emit(topo)
                except Exception as e:  # noqa: BLE001
                    # 拓扑发现失败不应中断主流程，但必须留痕：此前是静默
                    # `except Exception:`，出问题只能靠用户口述现象。
                    _log.warning("拓扑发现失败: %s", e, exc_info=True)
                    self.finished_signal.emit(None)

        def on_finished(topo):
            self._topo_progress.close()
            dlg = TopologyDialog(self.all_results, gw_ip, self.dark_mode, self, topology=topo)
            dlg.exec_()

        self._topo_thread = TopoThread(self.all_results)
        self._topo_thread.log_signal.connect(lambda m: self._topo_progress.setLabelText(m))
        self._topo_thread.finished_signal.connect(on_finished)
        self._topo_progress.canceled.connect(lambda: None)  # 跳过 = 快进到显示
        self._topo_thread.start()
        self._topo_progress.exec_()  # 模态等待（跳过按钮关闭对话框，但线程继续）

    # --- 右键菜单 ---

