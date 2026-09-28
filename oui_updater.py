# -*- coding: utf-8 -*-
"""OUI 数据库在线更新模块。

从 IEEE 官网下载最新 oui.txt，解析后重建 oui.db。
在后台线程中执行，通过信号回调汇报进度。
"""
import os
import sqlite3
import tempfile
import shutil
import urllib.request
import urllib.error

from app_paths import data_dir
from app_logging import get_logger

_log = get_logger(__name__)
from parse_ieee_oui import parse_ieee_oui, simplify_vendor_name

# IEEE OUI 数据源（也支持 MA-L / MA-M / MA-S，统一用 oui.txt）
_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
# 备用镜像（若主站不可用）
_OUI_URL_FALLBACK = "https://raw.githubusercontent.com/boundary/wireshark/master/manuf"


def _download_oui(progress_callback=None) -> str:
    """
    下载 IEEE oui.txt，返回本地临时文件路径。
    progress_callback(percent: int) 可选。
    """
    # 先试主站，再试备用
    urls = [("IEEE 官网", _OUI_URL), ("GitHub 镜像", _OUI_URL_FALLBACK)]

    for label, url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IPScanner/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                size = int(resp.headers.get("Content-Length", 0))
                tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb")
                try:
                    downloaded = 0
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        tmp.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback and size > 0:
                            progress_callback(min(int(downloaded * 100 / size), 99))
                    tmp.close()
                    if progress_callback:
                        progress_callback(100)
                    return tmp.name
                except Exception:
                    tmp.close()
                    os.unlink(tmp.name)
                    raise
        except Exception as e:
            last_error = f"{label}: {e}"
            continue

    raise RuntimeError(f"无法下载 OUI 数据：{last_error}")


def rebuild_oui_db(txt_path: str, output_path: str, progress_callback=None) -> int:
    """
    从 oui.txt 重建 oui.db。
    progress_callback(stage: str, percent: int) 可选。
    返回条目数。
    """
    if progress_callback:
        progress_callback("parsing", 0)

    oui_dict = parse_ieee_oui(txt_path)
    if not oui_dict:
        raise ValueError("oui.txt 解析结果为空，文件可能格式异常")

    if progress_callback:
        progress_callback("parsing", 100)

    # 写入临时文件再原子替换
    tmp_db = output_path + ".tmp"
    if os.path.exists(tmp_db):
        os.unlink(tmp_db)

    conn = sqlite3.connect(tmp_db)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("CREATE TABLE IF NOT EXISTS oui (prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)")
        conn.execute("DELETE FROM oui")

        count = 0
        batch = []
        total = len(oui_dict)
        for oui, vendor in sorted(oui_dict.items()):
            name = simplify_vendor_name(vendor)
            batch.append((oui, name))
            count += 1
            if len(batch) >= 5000:
                conn.executemany("INSERT OR REPLACE INTO oui VALUES (?,?)", batch)
                batch.clear()
                if progress_callback and total > 0:
                    progress_callback("building", int(count * 100 / total))

        if batch:
            conn.executemany("INSERT OR REPLACE INTO oui VALUES (?,?)", batch)

        conn.commit()
        conn.execute("ANALYZE")
    finally:
        conn.close()

    # 原子替换
    if os.path.exists(output_path):
        os.unlink(output_path)
    shutil.move(tmp_db, output_path)

    if progress_callback:
        progress_callback("building", 100)

    return count


def update_oui_db(progress_callback=None) -> dict:
    """
    一键更新 OUI 数据库。
    progress_callback(stage: str, percent: int, message: str) 可选。

    返回 dict: {"success": bool, "count": int, "path": str, "error": str}
    """
    txt_path = None
    try:
        if progress_callback:
            progress_callback("download", 0, "正在下载 IEEE OUI 数据库...")

        txt_path = _download_oui(
            progress_callback=lambda p: progress_callback("download", p, f"下载中... {p}%")
            if progress_callback else None
        )

        if progress_callback:
            progress_callback("parse", 0, "正在解析 OUI 数据...")

        output_path = os.path.join(data_dir(), "oui.db")
        count = rebuild_oui_db(
            txt_path, output_path,
            progress_callback=lambda s, p: progress_callback(s, p,
                f"{'解析' if s == 'parsing' else '建库'}中... {p}%")
            if progress_callback else None
        )

        return {"success": True, "count": count, "path": output_path, "error": ""}

    except Exception as e:
        return {"success": False, "count": 0, "path": "", "error": str(e)}
    finally:
        if txt_path and os.path.exists(txt_path):
            try:
                os.unlink(txt_path)
            except Exception as e:  # noqa: BLE001
                # 临时文件删不掉只留垃圾，不影响本次更新结果
                _log.debug("清理 OUI 临时文件失败 %s: %s", txt_path, e)
