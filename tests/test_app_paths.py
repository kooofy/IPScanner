# -*- coding: utf-8 -*-
"""app_paths 数据目录探测策略测试。

覆盖 P0-1：exe 位于不可写目录（如 C:\\Program Files）时必须回退到
用户数据目录，而不是让 SQLite 建库失败导致启动崩溃。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import app_paths


class DataDirTest(unittest.TestCase):

    def setUp(self):
        self._frozen = getattr(sys, "frozen", None)
        self._argv0 = sys.argv[0]
        self._meipass = getattr(sys, "_MEIPASS", None)
        app_paths.reset_cache()

    def tearDown(self):
        # 还原解释器状态，避免污染其它测试
        if self._frozen is None:
            if hasattr(sys, "frozen"):
                del sys.frozen
        else:
            sys.frozen = self._frozen
        sys.argv[0] = self._argv0
        if self._meipass is None:
            if hasattr(sys, "_MEIPASS"):
                del sys._MEIPASS
        else:
            sys._MEIPASS = self._meipass
        app_paths.reset_cache()

    def _set_frozen(self, exe_path):
        sys.frozen = True
        sys.argv[0] = exe_path
        app_paths.reset_cache()

    @staticmethod
    def _unwritable_exe_path(parent):
        """构造一个"所在目录必定不可写"的 exe 路径。

        刻意用"路径中间隔着一个普通文件"来保证不可写，而不是依赖权限位或
        不存在的盘符：

        * 权限位（chmod）在 root 下无效，CI 容器常常就是 root；
        * Windows 的 ``os.access`` 对目录写权限判断不可靠；
        * 而 ``Z:\\...`` 这种"不存在的盘符"只在 Windows 成立 —— 在 Linux 上
          ``os.makedirs("Z:\\Program Files\\IPScanner")`` 会**真的把目录建出来**，
          测试于是从"回退到用户目录"变成"便携模式"，在非 Windows 上必挂。

        "普通文件不能当目录用"在所有平台上都是硬失败，因此最可靠。
        """
        blocker = os.path.join(parent, "not_a_dir")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        return os.path.join(blocker, "IPScanner.exe")

    def test_dev_mode_uses_source_dir(self):
        """未打包时数据目录 = 源码目录。"""
        if hasattr(sys, "frozen"):
            del sys.frozen
        app_paths.reset_cache()
        self.assertEqual(app_paths.data_dir_source(), "dev")
        self.assertEqual(app_paths.data_dir(), ROOT)

    def test_unwritable_exe_dir_falls_back_to_user_dir(self):
        """exe 所在目录不可写时回退到用户数据目录。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._set_frozen(self._unwritable_exe_path(tmp))
            self.assertEqual(app_paths.data_dir_source(), "user")
            self.assertTrue(app_paths.data_dir().startswith(
                os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
                or os.path.expanduser("~")
            ))
            self.assertFalse(app_paths.is_portable())

    def test_writable_exe_dir_keeps_portable_mode(self):
        """exe 目录可写时保持便携模式（数据随 exe 走）。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._set_frozen(os.path.join(tmp, "IPScanner.exe"))
            self.assertEqual(app_paths.data_dir_source(), "portable")
            self.assertEqual(app_paths.data_dir(), tmp)
            self.assertTrue(app_paths.is_portable())

    def test_data_dir_is_writable(self):
        """无论走哪条分支，返回的目录都必须真实可写。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._set_frozen(self._unwritable_exe_path(tmp))
            probe = os.path.join(app_paths.data_dir(), ".writable_check")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)

    def test_data_dir_is_cached(self):
        """重复调用返回同一目录（探测结果被缓存，不做重复磁盘写入）。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._set_frozen(os.path.join(tmp, "IPScanner.exe"))
            self.assertEqual(app_paths.data_dir(), app_paths.data_dir())

    def test_resource_dir_uses_meipass_when_frozen(self):
        """打包后资源目录指向 sys._MEIPASS。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._set_frozen(os.path.join(tmp, "IPScanner.exe"))
            sys._MEIPASS = tmp
            self.assertEqual(app_paths.resource_dir(), tmp)

    def test_label_is_non_empty(self):
        """data_dir_label 各分支都有可读中文说明。"""
        for src in ("dev", "portable", "user", "temp"):
            app_paths._data_dir_source = src
            self.assertTrue(app_paths.data_dir_label())
        app_paths.reset_cache()


if __name__ == "__main__":
    unittest.main()
