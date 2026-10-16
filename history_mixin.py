# -*- coding: utf-8 -*-
"""历史快照、审计日志与拓扑视图混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import QProgressDialog
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from ui_dialogs import (
    AuditActivityDialog, AuditLogDialog, HistoryCompareDialog,
    HistoryQueryDialog, LocateDeviceDialog, TopologyDialog, TrendViewDialog
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

    def _show_audit_activity(self):
        """弹出扫描活动自查（v2.2 §3.3）：按时间窗看聚合，不看流水。"""
        dlg = AuditActivityDialog(parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _show_trend_view(self):
        """弹出在线率趋势与稳定性（v2.3 §3.2）：看网络自己变成了什么样。"""
        dlg = TrendViewDialog(parent=self, dark=self.dark_mode)
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


    def _save_snapshot(self, results, max_keep: int = 20, switch_maps=None,
                       trend=None):
        """保存历史快照。`switch_maps` 非空时，把交换机端口映射一并落库。

        `switch_maps` 由 `ScanThread` 在**扫描线程内**采集（见
        `topology_discovery.collect_switch_port_maps`）；这里只负责写库 ——
        采集放在主线程会冻住界面（每台交换机 5 次 SNMP walk）。

        `trend` 是趋势观测的扫描元数据（`ranges` / `ports_scanned` /
        `duration_s` / `source`，见 `history_store._record_trend`）。
        不传也照写一行趋势（`total`/`online` 从 devices 现算），
        只是**按网段曲线没数据可画**（v2.3 §3.2 接线）。
        """
        try:
            snap = self._build_snapshot(results)
            sid = history_store.save_snapshot(
                snap["devices"], ts=snap["time"], max_keep=max_keep,
                db_path=self.history_db, trend=trend,
            )
            if switch_maps:
                # 与设备列表分开存：端口映射不是每次扫描都有（要 SNMP + BRIDGE-MIB），
                # 所以必须等拿到 snapshot_id 再单独写（见 history_store.save_port_map）
                history_store.save_port_map(
                    sid, switch_maps, db_path=self.history_db)
            # 新快照入库后，详情面板缓存的"历史轨迹"就过期了（见
            # MainWindow._device_timeline_for）。不清的话本次扫描新增的这条
            # 永远不会出现在轨迹里，直到重启程序。
            # 端口暴露（`_port_exposure_for`）读的是同一批 `asset_events`，
            # 同一时刻失效 —— 这次扫描刚开的端口必须立刻出现在详情面板里。
            getattr(self, "_timeline_cache", {}).clear()
            getattr(self, "_exposure_cache", {}).clear()
            # 台账行（`_asset_for`，v2.3 §3.4）同样失效：首次落库时
            # `_backfill_assets()` 会给"扫到但还没进过台账"的设备补出新行 ——
            # 不清的话那台设备点开还是没有「编辑资产信息…」入口。
            getattr(self, "_asset_cache", {}).clear()
        except Exception as e:
            print(tr("保存历史快照失败:"), e)

    def _open_history_compare(self):
        dlg = HistoryCompareDialog(self, db_path=self.history_db)
        dlg.exec_()

    def _open_history_query(self):
        dlg = HistoryQueryDialog(self, db_path=self.history_db,
                                 dark=self.dark_mode)
        dlg.exec_()

    def _open_locate_dialog(self):
        """「这台设备插在哪」—— 定位查询入口。"""
        self._audit(audit_log.CAT_DEVICE, tr("设备定位"), tr("打开设备定位工具"))
        dlg = LocateDeviceDialog(parent=self, db_path=self.history_db,
                                 dark=self.dark_mode)
        dlg.exec_()

    def _open_topology(self):
        if not self.all_results:
            msg_info(self, tr("拓扑视图"), tr("请先完成一次扫描，再查看拓扑。"))
            return
        gw_ip = _detect_gateway()

        # 尝试 LLDP/CDP/转发表拓扑发现（后台线程，避免卡界面）
        self._topo_result = None
        self._topo_progress = QProgressDialog(
            tr("正在发现网络拓扑 (LLDP/CDP)..."), tr("跳过"), 0, 0, self
        )
        self._topo_progress.setWindowTitle(tr("拓扑发现"))
        self._topo_progress.setWindowModality(Qt.WindowModal)
        self._topo_progress.setMinimumDuration(0)

        # SNMPv3 用户（若已配置）：拓扑发现必须和扫描走同一套凭据，
        # 否则会出现"扫描能识别、拓扑识别不了"这种自相矛盾的表现。
        snmp_v3_user = None
        try:
            creds = getattr(self, "snmp_v3_creds", None)
            if creds is not None and creds.has_creds():
                snmp_v3_user = creds.to_user()
        except Exception as e:      # noqa: BLE001 - 凭据不可用不该挡住拓扑
            _log.warning("读取 SNMPv3 凭据失败，本次拓扑发现使用 v2c: %s", e)

        class TopoThread(QThread):
            finished_signal = pyqtSignal(object)
            log_signal = pyqtSignal(str)

            def __init__(self, results, gateway_ip, v3_user):
                super().__init__()
                self.results = results
                self.gateway_ip = gateway_ip
                self.v3_user = v3_user

            def run(self):
                try:
                    from topology_discovery import discover_topology
                    topo = discover_topology(
                        self.results,
                        progress_callback=lambda p, c, t, m: self.log_signal.emit(m),
                        gateway_ip=self.gateway_ip,
                        snmp_v3_user=self.v3_user,
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

        self._topo_thread = TopoThread(self.all_results, gw_ip, snmp_v3_user)
        self._topo_thread.log_signal.connect(lambda m: self._topo_progress.setLabelText(m))
        self._topo_thread.finished_signal.connect(on_finished)
        self._topo_progress.canceled.connect(lambda: None)  # 跳过 = 快进到显示
        self._topo_thread.start()
        self._topo_progress.exec_()  # 模态等待（跳过按钮关闭对话框，但线程继续）

    # --- 右键菜单 ---

