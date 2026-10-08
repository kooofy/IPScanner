# -*- coding: utf-8 -*-
"""扫描历史快照的 SQLite 存储。

取代原先基于 scan_history.json 的文件存储：
- 一条快照 = snapshots 表一行 + devices 表若干行（外键关联、级联删除）
- 支持保留上限裁剪、旧 JSON 自动迁移
- 对外返回的数据结构与旧 JSON 完全一致：
      [ {"time": float, "devices": [{ip,status,mac,...}, ...]}, ... ]
  因此 _compare_snapshots / HistoryCompareDialog 无需任何改动即可复用。

纯标准库 + sqlite3，无 PyQt 依赖，便于单元测试。
"""
import contextlib
import ipaddress
import os
import time
from app_paths import data_dir

import db_util

DB_PATH = os.path.join(data_dir(), "scan_history.db")

_PRAGMAS = ("PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON")


def _init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS snapshots (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            time         REAL NOT NULL,
            device_count INTEGER NOT NULL DEFAULT 0,
            note         TEXT
        );
        CREATE TABLE IF NOT EXISTS devices (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id  INTEGER NOT NULL,
            ip           TEXT DEFAULT '',
            status       TEXT DEFAULT '',
            mac          TEXT DEFAULT '',
            hostname     TEXT DEFAULT '',
            vendor       TEXT DEFAULT '',
            device_class TEXT DEFAULT '',
            os_guess     TEXT DEFAULT '',
            open_ports   TEXT DEFAULT '',
            location     TEXT DEFAULT '',
            user         TEXT DEFAULT '',
            remark       TEXT DEFAULT '',
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dev_snapshot ON devices(snapshot_id);
        -- device_timeline() 按 MAC/IP 查单台设备的历史轨迹，且该查询发生在
        -- "每选中一行" 的热路径上。没有索引时 SQLite 要全表扫描 devices
        -- （20 份快照 × /16 网段可达百万行），选中设备会明显卡顿。
        -- mac 用 NOCASE 索引：MAC 大小写不敏感，但写入时未做归一化。
        CREATE INDEX IF NOT EXISTS idx_dev_mac ON devices(mac COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_dev_ip ON devices(ip);
        """
    )
    conn.commit()


@contextlib.contextmanager
def _conn(db_path=None):
    """复用进程级单例连接（按 db_path 缓存，线程安全）。"""
    path = db_path or DB_PATH
    with db_util.connection(path, init_fn=_init_db, pragmas=_PRAGMAS) as c:
        yield c


def save_snapshot(devices, ts=None, note=None, max_keep=20, db_path=None) -> int:
    """保存一条快照（devices 为设备字典列表）。返回新快照 id。

    devices 中每个字典可用字段：ip/status/mac/hostname/vendor/
    device_class/os_guess/open_ports/location/user/remark（缺字段按空串处理）。
    """
    ts = time.time() if ts is None else ts
    with _conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO snapshots (time, device_count, note) VALUES (?,?,?)",
            (ts, len(devices), note),
        )
        sid = cur.lastrowid
        for d in devices:
            conn.execute(
                "INSERT INTO devices "
                "(snapshot_id, ip, status, mac, hostname, vendor, "
                "device_class, os_guess, open_ports, location, user, remark) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    sid,
                    d.get("ip", ""), d.get("status", ""), d.get("mac", ""),
                    d.get("hostname", ""), d.get("vendor", ""), d.get("device_class", ""),
                    d.get("os_guess", ""), d.get("open_ports", ""), d.get("location", ""),
                    d.get("user", ""), d.get("remark", ""),
                ),
            )
        conn.commit()
    prune(max_keep=max_keep, db_path=db_path)
    return sid


def list_snapshots(db_path=None) -> list:
    """返回快照元信息列表（id, time, device_count, note），按 id 升序（旧->新）。"""
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT id, time, device_count, note FROM snapshots ORDER BY id ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_snapshot(snapshot_id, db_path=None) -> dict:
    """返回完整快照 {"time": float, "devices": [...]}；不存在返回 None。"""
    with _conn(db_path) as conn:
        row = conn.execute(
            "SELECT id, time FROM snapshots WHERE id=?", (snapshot_id,)
        ).fetchone()
        if not row:
            return None
        devs = conn.execute(
            "SELECT ip, status, mac, hostname, vendor, device_class, os_guess, "
            "open_ports, location, user, remark FROM devices WHERE snapshot_id=? "
            "ORDER BY id ASC",
            (snapshot_id,),
        ).fetchall()
    return {"time": row["time"], "devices": [dict(d) for d in devs]}


def load_all(db_path=None) -> list:
    """返回全部快照（旧 JSON 的等价物），按时间升序，结构完全一致。"""
    out = []
    for snap in list_snapshots(db_path):
        full = get_snapshot(snap["id"], db_path)
        if full:
            out.append(full)
    return out


def device_timeline(mac="", ip="", db_path=None, limit=None) -> list:
    """返回某台设备在各次快照中的出现记录，按快照 id 升序（旧 → 新）。

    用于主界面详情面板的「历史轨迹」：把"这台机器以前在不在、在哪个 IP"
    从"翻快照"变成一眼可见（见 UI_REVIEW.md P3-1）。

    **匹配优先用 MAC**，没有 MAC 时才退回 IP。理由与收藏功能一致：IP 会被
    DHCP 回收后分配给另一台机器，按 IP 追溯会把两台设备的记录串在一起；
    MAC 才是设备身份。

    Args:
        mac:      设备 MAC（大小写不敏感）。
        ip:       设备 IP（仅当 mac 为空时使用）。
        db_path:  历史库路径；None 表示默认位置。
        limit:    只取**最近** N 条（None 表示全部）。

    Returns:
        [{"snapshot_id", "time", "status", "ip", "mac", "hostname"}, ...]
        没有任何记录时返回 []。
    """
    _mac = (mac or "").strip().upper()
    _ip = (ip or "").strip()
    if not _mac and not _ip:
        return []

    _cols = ("SELECT s.id AS snapshot_id, s.time AS time, d.status AS status, "
             "d.ip AS ip, d.mac AS mac, d.hostname AS hostname "
             "FROM snapshots s JOIN devices d ON d.snapshot_id = s.id ")
    # COLLATE NOCASE 必须显式写：devices.mac 的默认排序规则是 BINARY，
    # 只有比较式上也声明 NOCASE，才与 idx_dev_mac 的排序规则一致、索引才会被用上。
    with _conn(db_path) as conn:
        if _mac:
            rows = conn.execute(
                _cols + "WHERE d.mac = ? COLLATE NOCASE ORDER BY s.id ASC", (_mac,)
            ).fetchall()
        else:
            rows = conn.execute(
                _cols + "WHERE d.ip = ? ORDER BY s.id ASC", (_ip,)
            ).fetchall()
    out = [dict(r) for r in rows]
    if limit:
        out = out[-int(limit):]
    return out


def prune(max_keep=20, db_path=None):
    """仅保留最近 max_keep 条快照，删除更早的（含其 devices 行）。"""
    if max_keep is None or max_keep <= 0:
        return
    with _conn(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM snapshots").fetchone()["c"]
        if count > max_keep:
            excess = count - max_keep
            conn.execute(
                "DELETE FROM snapshots WHERE id IN ("
                "SELECT id FROM snapshots ORDER BY id ASC LIMIT ?)",
                (excess,),
            )
            conn.commit()


def migrate_from_json(json_path, db_path=None) -> int:
    """把旧 scan_history.json 迁入 SQLite。

    - json 不存在 / 非列表 / 已存在快照 -> 返回 0（幂等、安全，可重复调用）
    - 否则逐条写入，最后按保留上限裁剪
    返回迁移的快照条数。
    """
    if not os.path.exists(json_path):
        return 0
    try:
        import json
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return 0
    if not isinstance(data, list) or not data:
        return 0
    # 已迁移过（DB 非空）则不重复写入
    if list_snapshots(db_path):
        return 0
    migrated = 0
    for snap in data:
        devices = snap.get("devices", [])
        save_snapshot(
            devices,
            ts=snap.get("time"),
            note=snap.get("note"),
            max_keep=10 ** 9,  # 迁移阶段先不裁剪
            db_path=db_path,
        )
        migrated += 1
    prune(max_keep=20, db_path=db_path)
    return migrated


def ensure_migrated(db_path=None, json_path=None):
    """启动时调用一次：若 SQLite 为空且旧 JSON 存在，则迁移。返回迁移条数。"""
    if json_path is None:
        json_path = os.path.join(data_dir(), "scan_history.json")
    if not list_snapshots(db_path) and os.path.exists(json_path):
        return migrate_from_json(json_path, db_path)
    return 0


# --- 历史条件查询 -----------------------------------------------------------

def _canon(text):
    """把可能已翻译的文本还原为语言无关的源串（跨语言比较用）。

    i18n 未就绪时退化为原值，保证本模块可独立使用。
    """
    try:
        from i18n import canonical
        return canonical(text or "")
    except Exception:
        return text or ""


# 聚合时从快照逐条取用的设备字段（无首见时间，需推导）
_AGG_FIELDS = (
    "status", "mac", "hostname", "vendor", "device_class", "os_guess",
    "open_ports", "location", "user", "remark",
)


def _parse_network(network):
    """把 '192.168.1.0/24' / '192.168.1' 等解析为 ip_network；非法返回 None。"""
    if not network:
        return None
    try:
        return ipaddress.ip_network(str(network), strict=False)
    except (ValueError, TypeError):
        return None


def _ip_in_network(ip, net):
    """判断 ip 是否落在 net（ip_network）内；net 为空或 ip 非法返回 False。"""
    if net is None or not ip:
        return False
    try:
        return ipaddress.ip_address(str(ip)) in net
    except ValueError:
        return False


def query_history(device_class=None, network=None, first_seen_after=None,
                  first_seen_before=None, ip_substr=None, db_path=None) -> list:
    """跨快照聚合查询历史设备，支持按类型 / 网段 / 首见时间 / IP 关键字过滤。

    返回每条记录包含：ip, status, mac, hostname, vendor, device_class,
    os_guess, open_ports, location, user, remark, first_seen, last_seen。
    按 last_seen 降序（最近活跃的排在前）。

    说明：
    - devices 表无首见时间列，first/last seen 通过按快照时间升序遍历推导；
    - 同一 IP 在不同快照中的属性以「最近一次出现且非空」的值为准（展示当前状态）；
    - device_class 过滤基于最新已知类型做子串匹配。
    """
    net = _parse_network(network)

    # 单条 JOIN 取回全部设备行（按快照时间升序），再在内存里聚合。
    #
    # 旧写法是 `for snap in list_snapshots(): get_snapshot(snap["id"])` ——
    # 典型的 N+1：N 个快照就是 N+1 次查询，而且每次 get_snapshot 都会把该快照
    # 的整张设备表读回来。默认保留 20 个快照、每个几百台设备时，这里是 21 次
    # 查询 + 全量读盘。
    #
    # 按时间**升序**遍历是刻意的：这样每遇到一个更新的快照就必然满足
    # snap_time > last_seen，于是"非空即覆盖"自然等价于「最近一次出现且非空」。
    # 若改成降序，最新快照里为空的字段将永远填不上旧值 —— 与文档承诺不符。
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT s.time AS snap_time, d.ip, d.status, d.mac, d.hostname, "
            "       d.vendor, d.device_class, d.os_guess, d.open_ports, "
            "       d.location, d.user, d.remark "
            "  FROM devices d JOIN snapshots s ON s.id = d.snapshot_id "
            " WHERE d.ip IS NOT NULL AND TRIM(d.ip) <> '' "
            " ORDER BY s.time ASC, d.id ASC"
        ).fetchall()

    agg = {}  # ip -> 聚合记录
    for r in rows:
        ip = (r["ip"] or "").strip()
        if not ip:
            continue
        snap_time = r["snap_time"]
        cur = agg.get(ip)
        if cur is None:
            cur = {
                "ip": ip,
                "first_seen": snap_time,
                "last_seen": snap_time,
            }
            for f in _AGG_FIELDS:
                cur[f] = r[f] or ""
            agg[ip] = cur
        else:
            if snap_time > cur["last_seen"]:
                cur["last_seen"] = snap_time
                # 最新快照覆盖属性（仅非空，避免清空历史好值）
                for f in _AGG_FIELDS:
                    v = r[f] or ""
                    if v:
                        cur[f] = v
            if snap_time < cur["first_seen"]:
                cur["first_seen"] = snap_time

    # 过滤
    # device_class 是语言无关的规范值（见 scanner/classify.py），但用户在英文
    # 界面里输入的是 "Printer"、历史库里存的却是「打印机」。用 i18n.canonical()
    # 把两边都还原为源串再比较，跨语言查询才不会静默返回空结果。
    dc = _canon(device_class).lower()
    ipk = (ip_substr or "").strip().lower()
    results = []
    for cur in agg.values():
        if dc and dc not in _canon(cur.get("device_class", "")).lower():
            continue
        if ipk and ipk not in (cur.get("ip", "") or "").lower():
            continue
        if net is not None and not _ip_in_network(cur.get("ip", ""), net):
            continue
        fs = cur.get("first_seen")
        if first_seen_after is not None and (fs is None or fs < first_seen_after):
            continue
        if first_seen_before is not None and (fs is None or fs > first_seen_before):
            continue
        results.append(cur)

    results.sort(key=lambda r: r.get("last_seen", 0), reverse=True)
    return results
