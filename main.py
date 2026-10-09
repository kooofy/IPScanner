# -*- coding: utf-8 -*-
"""
局域网终端扫描工具 — 程序入口
基于 PyQt5，参考 Advanced IP Scanner / Angry IP Scanner 等工具的布局
"""
import sys
import os
import threading
from datetime import datetime
from app_paths import data_dir, resource_dir

os.environ.setdefault("QT_NO_DIRECTWRITE", "1")
os.environ.setdefault("QT_STYLE_OVERRIDE", "Fusion")

# 日志必须最先初始化：后续任何 import 失败（PyQt5 DLL 缺失、语言包损坏等）
# 都要能在 ipscanner.log 里留下痕迹，否则用户只能看到"双击没反应"。
import app_logging
app_logging.setup()
_log = app_logging.get_logger(__name__)

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QFont, QIcon, QPixmap

# i18n 必须在 import main_window 之前初始化：main_window → scanner/constants.py、
# audit_log.py、conflict_detector.py 等模块在顶层调用 tr()，若翻译表未加载，
# 这些常量会被冻结为恒等（中文），后续 i18n.init() 无法回溯重算。
import i18n
_saved_lang = QSettings("ipscanner.ini", QSettings.IniFormat).value("ui/language", "")
i18n.init(_saved_lang if _saved_lang else None)

from main_window import MainWindow, STYLE_SHEET
from ui_msg import msg_error
from i18n import tr


# ── 全局异常捕获 ──────────────────────────────────────────────

# crash.log 单文件上限；超过则轮转一代（crash.log -> crash.log.1）
_CRASH_LOG_MAX_BYTES = 5 * 1024 * 1024


def _rotate_crash_log(path: str):
    """crash.log 超过上限时轮转一代（crash.log -> crash.log.1）。

    刻意**不用** logging 的 RotatingFileHandler：crash.log 存在的意义正是
    "日志系统本身可能不可用"时的最后兜底，它不能反过来依赖 logging 模块。
    只保留一代历史即可 —— 崩溃日志是排障用的，不是需要长期留存的审计日志。

    本函数**允许抛异常**，由调用方 `_record_crash` 隔离：轮转失败最坏只是
    文件没变小，绝不能因此丢掉这次崩溃记录。
    """
    if os.path.getsize(path) < _CRASH_LOG_MAX_BYTES:
        return
    rotated = path + ".1"
    if os.path.exists(rotated):
        os.remove(rotated)
    os.replace(path, rotated)


def _record_crash(kind: str, err: str, log_level: int = 50):
    """把未捕获异常同时写进 crash.log 与统一日志。

    保留 crash.log 是有意的：日志系统本身依赖磁盘可写、依赖 data_dir() 探测，
    而这里要处理的恰恰可能是"日志/数据目录起不来"这类问题。crash.log 用最
    朴素的方式写，是最后一道保险；ipscanner.log 则便于和其它运行日志一起看。
    """
    try:
        _log.log(log_level, "%s\n%s", kind, err)
    except Exception:
        # 日志系统自身出错时无处可记，只能放弃这一路（下面还有 crash.log 兜底）
        pass
    try:
        _p = os.path.join(data_dir(), "crash.log")
        try:
            _rotate_crash_log(_p)
        except Exception as e:  # noqa: BLE001
            # 轮转只是"别让文件无限变大"的锦上添花。这里必须继续往下追加：
            # 一次轮转异常（文件被占用 / 磁盘满 / 权限不足）导致崩溃记录整个
            # 丢失，比 crash.log 变大严重得多。
            _log.debug("crash.log 轮转失败，本次直接追加: %s", e)
        with open(_p, "a", encoding="utf-8") as _f:
            _f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {kind}:\n"
                     f"{err}\n{'=' * 60}\n")
    except Exception:
        # crash.log 是最后一道保险；连它都写不了（磁盘满 / 目录不可写）时，
        # 已经没有任何可用的落盘通道，只能静默
        pass


def _global_except_hook(exc_type, exc_value, exc_tb):
    import traceback as _tb
    _err = "".join(_tb.format_exception(exc_type, exc_value, exc_tb))
    _record_crash("未捕获异常(excepthook)", _err)
    sys.stderr.write(tr(">>> [未捕获异常]\n") + _err)

sys.excepthook = _global_except_hook

_thread_hook_prev = threading.excepthook

def _thread_except_hook(args):
    import traceback as _tb
    _err = "".join(_tb.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
    _record_crash("线程未捕获异常", _err)
    sys.stderr.write(tr(">>> [线程未捕获异常]\n") + _err)
    if _thread_hook_prev:
        _thread_hook_prev(args)

threading.excepthook = _thread_except_hook


# ── SafeApp：捕获事件循环中的异常，防止 PyQt5 直接 abort ──────

class SafeApp(QApplication):
    """捕获所有事件/槽/绘制中的未处理异常，避免 PyQt5 直接 abort 导致闪退。"""

    _last_popup = 0.0

    def notify(self, receiver, event):
        try:
            return super().notify(receiver, event)
        except Exception:
            import traceback as _tb
            err = _tb.format_exc()
            _record_crash("事件循环未捕获异常", err)
            # 节流弹窗，避免高频绘制异常刷屏 (3 秒内同种不再弹)
            _now = datetime.now().timestamp()
            if _now - SafeApp._last_popup > 3:
                SafeApp._last_popup = _now
                try:
                    msg_error(
                        None, tr("运行时错误（已捕获，未崩溃）"),
                        tr("程序捕获到一个错误，已写入 crash.log：\n\n") + err[-1500:]
                    )
                except Exception:
                    # 连弹窗都失败了（极少见）：异常已记入日志，此处不再处理
                    pass
            return False


# ── 入口 ──────────────────────────────────────────────────────

def _shutdown_databases():
    """退出前关闭所有缓存连接（`db_util.shutdown()` 内部会做 WAL checkpoint）。

    `db_util` 的连接是按 db_path 永久缓存的，进程退出时不 close 就会残留
    `oui.db-wal` / `*.db-shm`，而且最后一批写入还留在 WAL 里 —— 用户直接拷走
    .db 文件会以为数据丢了。

    挂在 aboutToQuit 上而不是 closeEvent：后者只在走窗口关闭流程时触发，
    菜单退出 / 系统注销等路径不一定经过。
    """
    import db_util
    db_util.shutdown()


def main():

    # 高 DPI 必须在 QApplication 实例创建之前设置，否则 Qt 会打印警告
    # 并在某些 Windows 环境导致事件循环里 access violation 闪退。
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = SafeApp(sys.argv)
    app.aboutToQuit.connect(_shutdown_databases)
    app.setStyleSheet(STYLE_SHEET)
    app.setFont(QFont("Microsoft YaHei", 9))

    window = MainWindow()
    
    import os
    icon_path = os.path.join(resource_dir(), "assets", "app_icon.png")
    if os.path.exists(icon_path):
        pixmap = QPixmap(icon_path)
        if not pixmap.isNull():
            window.setWindowIcon(QIcon(pixmap))
            app.setWindowIcon(QIcon(pixmap))
    
    window.show()
    # 首次启动的一次性授权声明（docs/reviews/CODE_REVIEW.md P2-14）。**必须放在这里，不能放进
    # `MainWindow.__init__`**：`msg_consent()` 内部是模态 `exec_()`，会一直阻塞到
    # 用户点按钮；放进构造函数会让所有"建一个 MainWindow 看行为"的测试在无头环境
    # （没人点按钮）里永久挂死。用户未同意授权就直接退出，不进入事件循环。
    if not window.maybe_show_authorization_notice():
        _log.info("用户未确认授权声明，退出")
        sys.exit(0)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
