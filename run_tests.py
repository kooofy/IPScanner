# -*- coding: utf-8 -*-
"""单元测试运行器（无需 pytest，纯标准库 unittest）。

用法：
    python run_tests.py
等价于：
    python -m unittest discover -s tests -t .

无显示环境下也能安全导入 PyQt5（仅 import，不创建 QApplication）。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def main():
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(ROOT, "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
