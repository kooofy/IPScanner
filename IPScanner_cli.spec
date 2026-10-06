# -*- mode: python ; coding: utf-8 -*-
# IPScanner 无头 CLI 独立构建（P0-5）。
#
# 与 GUI 版（IPScanner_1.6.0.spec）**相互独立、互不影响**：
#   - 入口是 cli.py，不是 main.py；
#   - console=True，供计划任务 / SSH / 容器调用；
#   - 显式 excludes 掉 PyQt5 / 图形相关库，二进制体积远小于 GUI 版；
#   - 只需要 i18n（语言包）、oui.db（MAC 厂商库）与 service_fingerprints.json
#     （服务版本指纹规则），不需要 assets。
#
# 构建：pyinstaller IPScanner_cli.spec
# 产物：dist/IPScanner_cli.exe

a = Analysis(
    ['cli.py'],
    pathex=[],
    binaries=[],
    datas=[('oui.db', '.'), ('i18n', 'i18n'),
           ('service_fingerprints.json', '.')],
    hiddenimports=['scanner'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets',
        'tkinter', 'matplotlib', 'numpy', 'PIL',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='IPScanner_cli',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets\\app_icon.ico'],
)
