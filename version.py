# -*- coding: utf-8 -*-
"""单一版本号来源（single source of truth）。

改版本号**只改这里**。其余位置一律引用本模块，不要各写各的字面量：

- GUI「关于」对话框   → ``main_window.py``
- CLI ``--version``   → ``cli.py``
- PyInstaller spec    → ``IPScanner_*.spec``（通过 ``version_file()`` 或直接 import）
- ``pyproject.toml``  → 静态文件无法 import，由 ``tests/test_scaffolding.py``
  断言它与 ``__version__`` 一致

背景：此前 ``1.6.0`` 散落在 ``cli.py``、``main_window.py`` 的关于对话框和 spec
文件名里三处。发布时只要漏改一处，就会出现「exe 叫 1.6.0、关于对话框写着 1.5.0」
这类用户可见的不一致 —— 而且没有任何测试会发现。
"""

__version__ = "2.3.2"

# 应用显示名（关于对话框、CLI 帮助、spec 产物名共用）
APP_NAME = "IPScanner"

# spec 产物文件名统一由此派生，例如 "IPScanner_1.6.0.exe"
EXE_BASENAME = f"{APP_NAME}_{__version__}"
