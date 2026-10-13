# -*- mode: python ; coding: utf-8 -*-
# IPScanner GUI 版发布构建（PyInstaller 6.x / Python 3.13）。
#
# 构建：pyinstaller --noconfirm IPScanner.spec
# 产物：dist/IPScanner_<版本>/IPScanner_<版本>.exe
#
# 两个刻意的设计选择，改之前请先读完：
#
# 1) spec 文件名**不带版本号**。
#    旧方案叫 IPScanner_1.6.0.spec，每次发版都要改文件名 —— 于是 CI 只能靠
#    「按 mtime 挑最新的 IPScanner_1.*.spec」来猜当前该构建哪个，而且改完还得
#    同步 README / .gitignore / CI 三处。现在版本号唯一来源是 version.py，
#    spec 名固定，发版只需改 version.py 一处。
#
# 2) onedir 而非 onefile。
#    onefile 每次启动都要把整包解压到临时目录再执行。实测（本机 SSD / PyQt5 全量）：
#
#      onedir  磁盘占用 114 MB   压缩包 46.2 MB   启动到日志就绪 0.68~0.85s
#      onefile 磁盘占用  48 MB   单文件 46.1 MB   解压耗时 0.24s
#
#    即：**下载量基本一致**（46.2 vs 46.1 MB），代价是磁盘占用涨到 2.4 倍，
#    换来每次启动省掉 0.24s 的解压 + 一次「写出 48MB 可执行内容并立即运行」
#    的行为。后者才是选 onedir 的主因 —— 本项目用原始套接字 + WMI + net view，
#    本就是 EDR 高敏组合，onefile 的"自解压后执行"模式极易触发启发式误报。
#    另附收益：可增量更新、traceback 里是真实文件路径而非 _MEIxxxx 临时目录。
#
#    注意：onedir 下 PyInstaller 6.x 把 datas/binaries 放进 `_internal/` 子目录，
#    并把 sys._MEIPASS 指向它 —— 所以 app_paths.resource_dir() 两种模式都正确，
#    无需改动。这也意味着**发布时必须整个目录一起发**，不能只拷 exe。
#
# 关于静态检查：Analysis / PYZ / EXE / COLLECT 这几个名字是 PyInstaller 在执行
# spec 时注入的全局变量，不存在于任何 import 里。若把本文件显式传给 ruff
# （`ruff check IPScanner.spec`）会报 F821 —— 那是误报。CI 跑的是 `ruff check .`，
# 而 ruff 默认不遍历 .spec，所以不受影响。**不要**为了消掉它去加 noqa。

import os
import sys

# SPECPATH 由 PyInstaller 注入（spec 所在目录）。兜底 cwd，使本文件可被独立解析。
_spec_dir = globals().get("SPECPATH") or os.getcwd()
if _spec_dir not in sys.path:
    sys.path.insert(0, _spec_dir)

from version import EXE_BASENAME  # noqa: E402  （版本号唯一来源，见 version.py）

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('assets', 'assets'), ('oui.db', '.'), ('i18n', 'i18n'),
           ('service_fingerprints.json', '.'),
           ('cve_snapshot.json', '.')],
    hiddenimports=['scanner', 'PyQt5.QtXml', 'PyQt5.QtPrintSupport'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    # onedir 的关键：依赖不进 exe，交给下面的 COLLECT 收进 _internal/
    exclude_binaries=True,
    name=EXE_BASENAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets\\app_icon.ico'],
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name=EXE_BASENAME,
)
