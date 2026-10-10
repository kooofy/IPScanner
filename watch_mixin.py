# -*- coding: utf-8 -*-
"""持续发现（被动发现）的界面接线：一个定时器 + 一个后台线程。

为什么单独一个 mixin，而不是塞进 `scan_mixin`：扫描是「用户点一下、跑一遍」，
持续发现是「打开就一直转」的后台模式 —— 生命周期、线程归属、结果去向都不同。
塞在一起会让「扫描线程」和「轮询线程」两套状态互相纠缠。

**默认关**（与「读取交换机转发表」同一处理）：它会在后台占住 mDNS 的 5353
端口、并且会一直往表格里加行，不想跑被动发现的用户不该被它打扰。
"""
from PyQt5.QtCore import Qt, QTimer

from app_logging import get_logger
from i18n import tr

_log = get_logger(__name__)

#: 轮询间隔（毫秒）。30 秒是权衡：ARP 表的变化本来就以分钟计，
#: 再密只是在空转（每轮还要占 `mdns_timeout` 秒听组播）。
WATCH_INTERVAL_MS = 30_000

#: 界面里听 mDNS 的时长，比扫描末尾的 2.5 秒短 —— 后台轮询要克制，
#: 而 ARP 表才是被动发现的主来源。
WATCH_MDNS_TIMEOUT = 1.5


class WatchMixin:
    """给 MainWindow 用：`watch_check` 开关 + 定时轮询 + 新设备并入表格。"""

    def _init_watch(self):
        """在 `MainWindow.__init__` 里调用一次（须在 status_bar / history_db 就绪之后）。"""
        self._watch_watcher = None
        self._watch_thread = None
        self._watch_new_total = 0
        self._watch_timer = QTimer(self)
        self._watch_timer.setInterval(WATCH_INTERVAL_MS)
        self._watch_timer.timeout.connect(self._watch_tick)

    # ── 开关 ──

    def _on_watch_toggled(self, checked: bool):
        if checked:
            self._watch_start()
        else:
            self._watch_stop()

    def _watch_start(self):
        import history_store
        from scanner.passive import PassiveWatcher

        try:
            baseline = history_store.latest_devices(db_path=self.history_db)
        except Exception as e:  # noqa: BLE001
            # 基线读不到不该让开关点不动：退化成"没有基线"，
            # 结果偏保守（第一轮可能多报新设备），功能仍然可用。
            _log.warning("读取被动发现基线失败，本次不带基线运行: %s", e,
                         exc_info=True)
            baseline = []

        # 基线给整份设备列表（不是只有 IP）：watcher 还要靠主机名 / 厂商
        # 这些指纹把"换了随机 MAC 的老设备"从"新设备"里分出来。
        self._watch_watcher = PassiveWatcher(known_devices=baseline)
        self._watch_new_total = 0
        self._watch_timer.start()
        # 立刻跑一轮：勾上开关后不该等满一个周期才看到反应。
        self._watch_tick()
        self.status_bar.showMessage(
            tr("持续发现已开启：只读本机 ARP 表并监听 mDNS，不发任何网络包"))

    def _watch_stop(self):
        self._watch_timer.stop()
        # 不强杀在飞的线程：它最多再跑 mdns_timeout 秒自然结束，
        # 结果到了也会被 `_on_watch_done` 丢弃（那时开关已经关了）。
        self._watch_watcher = None
        self.status_bar.showMessage(tr("持续发现已关闭"))

    # ── 轮询 ──

    def _watch_tick(self):
        """定时器到点：起一个后台线程跑一轮被动发现。"""
        if self._watch_watcher is None:
            return
        if self._watch_thread is not None and self._watch_thread.isRunning():
            # 上一轮还没跑完（mDNS 收包慢 / 系统卡）：跳过这一轮。
            # 不排队堆积 —— 被动发现要的是"最近的样子"，补跑历史轮次没意义。
            return

        from ui_threads import PassiveWatchThread
        th = PassiveWatchThread(self._watch_watcher,
                                mdns_timeout=WATCH_MDNS_TIMEOUT)
        th.log_signal.connect(lambda msg: self.status_bar.showMessage(msg),
                              Qt.QueuedConnection)
        th.finished_signal.connect(self._on_watch_done, Qt.QueuedConnection)
        self._watch_thread = th
        th.start()

    def _on_watch_done(self, ledger, fresh):
        """一轮被动发现结束：把**新出现**的设备并进表格（= 当前台账）。"""
        if self._watch_watcher is None:
            return                      # 期间被关掉了，这一轮作废
        for r in fresh:
            self._upsert_table_row(r)
        if fresh:
            self._watch_new_total += len(fresh)
            self.status_bar.showMessage(
                tr("持续发现：新出现 {n} 台设备（本次累计 {total} 台）")
                .format(n=len(fresh), total=self._watch_new_total))
