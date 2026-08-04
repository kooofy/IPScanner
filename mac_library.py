# -*- coding: utf-8 -*-
"""
MAC 地址库 (持久化)

基于 SQLite，落盘保存，支持：
- Excel 批量合并导入 (自动识别列、按 MAC/IP 去重、空字段回填)
- 手动 增加 / 修改 / 删除 单条
- 按 IP 或 MAC 精确匹配 (扫描时自动标注设备类型/位置/使用者)
- 导出为 Excel
- 重启后自动加载 (数据库文件默认 mac_library.db)
"""
import contextlib
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from app_paths import data_dir
from i18n import tr

import db_util
from excel_handler import (
    normalize_mac,
    detect_columns,
    _read_rows,
    _cell_to_str,
    COLUMN_ALIASES,
)

DEFAULT_DB = os.path.join(data_dir(), "mac_library.db")

# 基礎表结构 + 非唯一索引；部分唯一索引在 _init_db 里于去重后创建
_SCHEMA_BASE = """
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT DEFAULT '',
    mac         TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    location    TEXT DEFAULT '',
    user        TEXT DEFAULT '',
    remark      TEXT DEFAULT '',
    vendor      TEXT DEFAULT '',
    source_file TEXT DEFAULT '',
    created_at  TEXT,
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_dev_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_dev_ip  ON devices(ip);
"""


class MacLibrary:
    """落盘的 MAC 地址库"""

    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        with self._conn():  # 触发建表
            pass

    # ---------- 底层 ----------
    @contextlib.contextmanager
    def _conn(self):
        """复用进程级单例连接（按 db_path 缓存，线程安全）。"""
        with db_util.connection(self.db_path, init_fn=self._init_db) as c:
            yield c

    def _init_db(self, conn):
        # 1) 建表与基础索引
        conn.executescript(_SCHEMA_BASE)
        # 2) 对已有非空 MAC 去重（保留最大 id 即最后写入一条），否则部分唯一索引会创建失败
        try:
            conn.execute(
                "DELETE FROM devices WHERE mac <> '' "
                "AND id NOT IN (SELECT MAX(id) FROM devices WHERE mac <> '' GROUP BY mac)"
            )
        except Exception:
            pass
        # 3) 部分唯一索引：仅对非空 MAC 约束唯一（空 MAC 允许多条，用于无 MAC 的占位设备）
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_dev_mac_uniq "
                "ON devices(mac) WHERE mac <> ''"
            )
        except Exception:
            pass
        conn.commit()

    @staticmethod
    def _norm_mac(mac: str) -> str:
        return normalize_mac(mac)

    # ---------- 增删改 ----------
    def add(self, ip="", mac="", device_type="", location="", user="",
            remark="", vendor="", source_file="") -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mac = self._norm_mac(mac)
        with self._conn() as conn:
            # 非空 MAC 已存在 → 整行更新（部分唯一索引保护，避免 IntegrityError）
            if mac:
                cur = conn.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
                if cur:
                    conn.execute(
                        "UPDATE devices SET ip=?, device_type=?, location=?, user=?, "
                        "remark=?, vendor=?, source_file=?, updated_at=? WHERE id=?",
                        (ip, device_type, location, user, remark, vendor, source_file, now, cur[0]),
                    )
                    conn.commit()
                    return cur[0]
            cur = conn.execute(
                "INSERT INTO devices "
                "(ip, mac, device_type, location, user, remark, vendor, source_file, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ip, mac, device_type, location, user, remark, vendor, source_file, now, now),
            )
            conn.commit()
            return cur.lastrowid

    _EDITABLE = {"ip", "mac", "device_type", "location", "user", "remark", "vendor", "source_file"}

    def update(self, device_id: int, **fields):
        sets, vals = [], []
        for k, v in fields.items():
            if k in self._EDITABLE:
                val = self._norm_mac(v) if k == "mac" else v
                sets.append(f"{k}=?")
                vals.append(val)
        if not sets:
            return
        sets.append("updated_at=?")
        vals.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        vals.append(device_id)
        with self._conn() as conn:
            conn.execute(f"UPDATE devices SET {', '.join(sets)} WHERE id=?", vals)
            conn.commit()

    def delete(self, device_id: int):
        with self._conn() as conn:
            conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
            conn.commit()

    # ---------- 查询 ----------
    def get_all(self) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_by_id(self, device_id: int) -> Optional[dict]:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return dict(r) if r else None

    def search(self, query: str) -> List[dict]:
        q = f"%{query.strip()}%"
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM devices WHERE ip LIKE ? OR mac LIKE ? OR device_type LIKE ? "
                "OR location LIKE ? OR user LIKE ? OR remark LIKE ? OR vendor LIKE ? "
                "ORDER BY id",
                (q, q, q, q, q, q, q),
            ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        with self._conn() as conn:
            c = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        return c

    def source_files(self) -> List[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT source_file FROM devices WHERE source_file != ''"
            ).fetchall()
        return [r["source_file"] for r in rows]

    def clear(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM devices")
            conn.commit()

    # ---------- 匹配 ----------
    def match(self, ip: str, mac: str = "") -> Optional[dict]:
        """优先 IP 精确匹配，其次 MAC 匹配。返回设备 dict 或 None。"""
        with self._conn() as conn:
            if ip:
                r = conn.execute("SELECT * FROM devices WHERE ip=?", (ip.strip(),)).fetchone()
                if r:
                    return dict(r)
            mac_norm = self._norm_mac(mac)
            if mac_norm:
                r = conn.execute("SELECT * FROM devices WHERE mac=?", (mac_norm,)).fetchone()
                if r:
                    return dict(r)
        return None

    def is_loaded(self) -> bool:
        return self.count() > 0

    # ---------- Excel 合并导入 ----------
    def merge_from_excel(self, file_path: str) -> Tuple[bool, str]:
        """
        解析 Excel 并合并进地址库。
        去重规则：按 MAC(优先) 或 IP 判断已存在；若已存在则只回填空字段，不覆盖已有值。
        """
        try:
            rows = _read_rows(file_path)
        except Exception as e:
            return False, f"无法打开文件: {e}"
        if not rows:
            return False, tr("文件为空")

        # 表头行定位 (兼容首行是大标题的情况)
        header_row_idx = 0
        for idx in range(min(15, len(rows))):
            hdr = [str(h).strip().lower() if h is not None else "" for h in rows[idx]]
            if any(any(h in aliases for h in hdr) for aliases in COLUMN_ALIASES.values()):
                header_row_idx = idx
                break

        raw_headers = [str(h).strip() if h is not None else "" for h in rows[header_row_idx]]
        mapping = detect_columns(raw_headers)
        if "ip" not in mapping and "mac" not in mapping:
            return False, tr("未找到 IP/MAC 列，无法自动匹配设备（请在清单中补充 MAC 或 IP 列后重试）")

        ip_cols = mapping.get("ip", [])
        mac_cols = mapping.get("mac", [])
        added = updated = skipped = 0

        for row in rows[header_row_idx + 1:]:
            if not row or all(c is None or str(c).strip() == "" for c in row):
                continue

            entry = {}
            for field, cols in mapping.items():
                vals = []
                for c in cols:
                    if c < len(row):
                        v = _cell_to_str(row[c])
                        if v:
                            vals.append(v)
                if vals:
                    entry[field] = " ".join(vals)

            mac_raw = ""
            for c in mac_cols:
                if c < len(row):
                    m = _cell_to_str(row[c])
                    if m:
                        mac_raw = m
                        break

            ip_val = ""
            if ip_cols and ip_cols[0] < len(row):
                ip_val = _cell_to_str(row[ip_cols[0]]).strip()

            if not ip_val and not mac_raw:
                continue

            existing = self.match(ip_val, mac_raw)
            if existing:
                fill = {}
                for f in ("ip", "device_type", "location", "user", "remark", "vendor"):
                    new_v = entry.get(f, "")
                    if new_v and not existing.get(f):
                        fill[f] = new_v
                mac_norm = self._norm_mac(mac_raw)
                if mac_norm and not existing.get("mac"):
                    fill["mac"] = mac_norm
                if fill:
                    self.update(existing["id"], **fill)
                    updated += 1
                else:
                    skipped += 1
            else:
                self.add(
                    ip=ip_val,
                    mac=mac_raw,
                    device_type=entry.get("device_type", ""),
                    location=entry.get("location", ""),
                    user=entry.get("user", ""),
                    remark=entry.get("remark", ""),
                    source_file=os.path.basename(file_path),
                )
                added += 1

        if added == 0 and updated == 0 and skipped == 0:
            return False, tr("MAC/IP 数据为空，该文件无法在扫描时自动匹配设备（请检查 MAC 列是否已填写）")

        msg = (f"已从 {os.path.basename(file_path)} 合并：新增 {added} 条，"
               f"更新已有 {updated} 条，无变化跳过 {skipped} 条")
        return True, msg

    # ---------- 导出 ----------
    def export_to_excel(self, file_path: str) -> Tuple[bool, str]:
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Alignment
            from openpyxl.utils import get_column_letter

            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = tr("MAC地址库")
            headers = ["ID", tr("IP地址"), tr("MAC地址"), tr("设备类型"), tr("位置"), tr("使用者"), tr("备注"), tr("来源文件")]
            hf = Font(name=tr("微软雅黑"), size=11, bold=True, color="FFFFFF")
            hf_fill = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
            for ci, h in enumerate(headers, 1):
                c = ws.cell(row=1, column=ci, value=h)
                c.font = hf
                c.fill = hf_fill
                c.alignment = Alignment(horizontal="center", vertical="center")

            devices = self.get_all()
            for ri, d in enumerate(devices, 2):
                vals = [d["id"], d["ip"], d["mac"], d["device_type"], d["location"],
                        d["user"], d["remark"], d["source_file"]]
                for ci, v in enumerate(vals, 1):
                    ws.cell(row=ri, column=ci, value=v)

            widths = [6, 16, 20, 14, 22, 14, 22, 30]
            for ci, w in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(ci)].width = w
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}1"
            wb.save(file_path)
            wb.close()
            return True, f"已导出 {len(devices)} 条到 {file_path}"
        except Exception as e:
            return False, f"导出失败: {e}"
