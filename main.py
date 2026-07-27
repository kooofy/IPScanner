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

from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon, QPixmap

from main_window import MainWindow, STYLE_SHEET
from i18n import tr


# ── 全局异常捕获 ──────────────────────────────────────────────

def _global_except_hook(exc_type, exc_value, exc_tb):
    import traceback as _tb
    _err = "".join(_tb.format_exception(exc_type, exc_value, exc_tb))
    try:
        _log = os.path.join(data_dir(), "crash.log")
        with open(_log, "a", encoding="utf-8") as _f:
            _f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 未捕获异常(excepthook):\n{_err}\n{'=' * 60}\n")
    except Exception:
        pass
    sys.stderr.write(tr(">>> [未捕获异常]\n") + _err)

sys.excepthook = _global_except_hook

_thread_hook_prev = threading.excepthook

def _thread_except_hook(args):
    import traceback as _tb
    _err = "".join(_tb.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
    try:
        _log = os.path.join(data_dir(), "crash.log")
        with open(_log, "a", encoding="utf-8") as _f:
            _f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 线程未捕获异常:\n{_err}\n{'=' * 60}\n")
    except Exception:
        pass
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
            try:
                _ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                _log = os.path.join(data_dir(), "crash.log")
                with open(_log, "a", encoding="utf-8") as _f:
                    _f.write(f"[{_ts}] 未捕获异常:\n{err}\n{'=' * 60}\n")
            except Exception:
                pass
            # 节流弹窗，避免高频绘制异常刷屏 (3 秒内同种不再弹)
            _now = datetime.now().timestamp()
            if _now - SafeApp._last_popup > 3:
                SafeApp._last_popup = _now
                try:
                    QMessageBox.critical(
                        None, tr("运行时错误（已捕获，未崩溃）"),
                        tr("程序捕获到一个错误，已写入 crash.log：\n\n") + err[-1500:]
                    )
                except Exception:
                    pass
            return False


# ── 入口 ──────────────────────────────────────────────────────

def main():
    import i18n
    # 优先读取用户保存的语言偏好，否则自动检测系统语言
    from PyQt5.QtCore import QSettings
    _settings = QSettings("ipscanner.ini", QSettings.IniFormat)
    _saved_lang = _settings.value("ui/language", "")
    i18n.init(_saved_lang if _saved_lang else None)

    # 高 DPI 必须在 QApplication 实例创建之前设置，否则 Qt 会打印警告
    # 并在某些 Windows 环境导致事件循环里 access violation 闪退。
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = SafeApp(sys.argv)
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
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
