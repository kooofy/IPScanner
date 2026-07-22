# -*- coding: utf-8 -*-
"""运行时路径助手：同时兼容开发模式与 PyInstaller 打包（--onefile）模式。

- resource_dir()：图片等被打进 exe 内部的资源文件目录。
- data_dir()：数据库 / 配置 / 日志等需要持久化的用户数据目录。
"""
import os
import sys


def is_frozen():
    """是否处于 PyInstaller 打包后的运行环境。"""
    return getattr(sys, "frozen", False)


def resource_dir():
    """返回资源文件（图片等）所在目录。"""
    if is_frozen():
        # 单文件 exe：资源被解压到临时目录 sys._MEIPASS
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def data_dir():
    """返回用户数据（db/ini/日志）目录，保证持久化。

    打包后使用用户实际启动的 exe 所在目录（便携模式，数据随 exe 走）。
    """
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.dirname(os.path.abspath(__file__))
