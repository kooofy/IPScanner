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
import json
import os
import time
from typing import Optional
from alert_policy import normalize_mac
from app_paths import data_dir
from app_logging import get_logger

import db_util

_log = get_logger(__name__)

DB_PATH = os.path.join(data_dir(), "scan_history.db")

_PRAGMAS = ("PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON")

# ── locate_device() 的结果码 ──
# 存储层只产出**语言无关的规范值**，展示时再经 i18n 的 tr() 翻译（仓库铁律）。
LOCATE_NO_DEVICE = "no_device"                  # 库里压根没有这台设备
LOCATE_NO_SWITCH_DATA = "no_switch_data"        # 从未扫过交换机（或未落库）
LOCATE_SWITCH_SCAN_FAILED = "switch_scan_failed"  # 扫了交换机，但都没取到转发表
LOCATE_MAC_NOT_IN_FDB = "mac_not_in_fdb"        # 交换机正常，但转发表里没有这个 MAC

# 端口名可信度：'named' = 真实 ifName/ifDescr；'index_only' = 只有桥接端口号
PORT_SOURCE_IF_NAME = "if_name"
PORT_SOURCE_BRIDGE_PORT = "bridge_port"


# ── schema 迁移链 ──────────────────────────────────────────────────────
# 每项 = (版本号, SQL 脚本, 说明)，版本号连续且从 1 开始。`PRAGMA user_version`
# 记录库已升到哪一版；`db_util.apply_migrations()` 负责"读版本 → 补跑 > 当前版本的
# 迁移 → 写回"。
#
# 为什么要有它：加列必须写 `ALTER TABLE`，而 `CREATE TABLE IF NOT EXISTS`
# **不会补列** —— 没有版本号时，改造 schema 只能靠 `try/except` 猜"用户手里的库
# 是哪个年代的"。这是「资产表 + 观测表」改造的前置（见 docs/ROADMAP_V1.9.md）。
#
# ⚠ **迁移 1~3 用 `IF NOT EXISTS` 是刻意的**：它们是"引入 user_version 之前"
#   的那套建表语句，对老库重放必须无害（老库的版本号是**推断**出来的，万一推断偏低
#   也不能把库弄坏）。**第 4 版起不要再用 `IF NOT EXISTS`** —— 那时每个库都已有
#   版本号、迁移只会执行一次，让它在结构不符时**报错**比静默跳过好。
#
# ⚠ **已发布的迁移只增不改**：老库不会重跑它们，改了就只会让"新库"和
#   "老库升上来的库"结构不一致 —— 而且没有任何测试会发现。
_SQL_V1 = """
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

_SQL_V2 = """
        -- ── 交换机端口映射（「这台设备插在哪个口」的数据来源）──
        -- 与 devices 不同：端口映射不是每次扫描都有（要 SNMP + BRIDGE-MIB），
        -- 所以单独建表，且**允许某次快照一行都没有**（没扫交换机 / 交换机不支持）。
        -- 两张表都带 snapshot_id 外键 + CASCADE，prune() 删快照时会自动跟着清。
        CREATE TABLE IF NOT EXISTS switch_map (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            switch_ip   TEXT DEFAULT '',
            switch_name TEXT DEFAULT '',
            status      TEXT DEFAULT '',      -- 'ok' | 'error'
            error       TEXT DEFAULT '',
            mac_count   INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS port_map (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            switch_ip   TEXT DEFAULT '',
            switch_name TEXT DEFAULT '',
            mac         TEXT DEFAULT '',
            port_name   TEXT DEFAULT '',
            -- 'if_name'     = 来自真实 ifName / ifDescr，可信
            -- 'bridge_port' = if_index 解析失败，port_name 只是桥接端口号（不可信）
            port_source TEXT DEFAULT '',
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sm_snapshot ON switch_map(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_pm_snapshot ON port_map(snapshot_id);
        -- locate_device() 按 MAC 查最近端口，属交互热路径，必须走索引；
        -- 与 devices.mac 同理用 NOCASE（MAC 大小写不敏感，写入时未归一化）。
        CREATE INDEX IF NOT EXISTS idx_pm_mac ON port_map(mac COLLATE NOCASE);
"""

_SQL_V3 = """
        -- ── 零利用安全体检的事实（v1.9 #3）──────────────────────────
        -- 一行 = 一台设备的一条**事实**（不是结论）：kind 是规范代码
        -- （tls_not_after / tls_self_signed / tls_sig_alg …），value 是规范值。
        -- 「过期 / 即将过期 / 弱算法」这类**判定**统一在 risk_rules 里做 ——
        -- 阈值只写一处，历史里存的也永远是事实（以后调阈值可以重算）。
        --
        -- 为什么用"一张竖表"而不是往 devices 加列：
        --   * `CREATE TABLE IF NOT EXISTS` 对**已存在的库**直接生效；而给 devices
        --     加列必须写 ALTER TABLE 迁移（`CREATE TABLE IF NOT EXISTS` 不会补列），
        --     每加一个信号就得再来一次；
        --   * 后续切片（LLMNR/NBNS 响应器、SMB 方言与签名）都是异质的布尔/枚举，
        --     竖表天然容纳，不用再动 schema。
        -- 与 switch_map / port_map 同一惯例：允许某次快照一行都没有，
        -- 带 snapshot_id 外键 + CASCADE，prune() 删快照时自动跟着清。
        CREATE TABLE IF NOT EXISTS security_findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            ip          TEXT DEFAULT '',
            kind        TEXT DEFAULT '',
            value       TEXT DEFAULT '',
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sf_snapshot ON security_findings(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_sf_ip ON security_findings(ip);
"""

# ── v4：资产表（v1.9 1.1）──────────────────────────────────────────────
# ⚠ 这里**不用** `IF NOT EXISTS`（见上面的迁移链注释）：走到第 4 版时每个库
#   都有 `user_version` 了，迁移只会跑一次，结构不符时**报错**比静默跳过好。
#
# `devices` 一行 = 「某快照里的某台设备」—— 同一台机器扫 3 次就有 3 行。
# `assets` 一行 = **一台设备**。两者不是替换关系：快照是用户能理解的心智模型
# （「10 月 9 日那份清单」），资产表是**实现**（建议书 §5.1 第 3 条）。
#
# ⚠ **观测维度不另建 `asset_observations`**：`devices` 本身就是「每快照一条观测」
#   的表，再建一张等于把它整表复制一遍（/16 × 20 快照是百万行级）。所以只给
#   `devices` 补一个 `identity_key` 列 —— 旧数据靠 `_backfill_assets()` 填，
#   新数据由 `save_snapshot()` 写入时直接带上。
_SQL_V4 = """
        CREATE TABLE assets (
            -- 身份键：归一化 MAC（小写 `aa:bb:cc:dd:ee:ff`）；无 MAC 时 `ip:<ip>`。
            -- 见 identity_key()。做成主键 —— 「一台设备一行」靠它保证。
            identity_key TEXT PRIMARY KEY,
            mac          TEXT DEFAULT '',
            ip           TEXT DEFAULT '',
            status       TEXT DEFAULT '',
            hostname     TEXT DEFAULT '',
            vendor       TEXT DEFAULT '',
            device_class TEXT DEFAULT '',
            os_guess     TEXT DEFAULT '',
            open_ports   TEXT DEFAULT '',
            -- JSON 数组字符串（服务名里可能带逗号，不能用逗号分隔）。
            -- ⚠ 历史快照**没有**服务（devices 从来没存过），回填时留空串。
            services     TEXT DEFAULT '',
            location     TEXT DEFAULT '',
            user         TEXT DEFAULT '',
            remark       TEXT DEFAULT '',
            -- ⚠ first/last_seen / seen_count 是**单调累积**的列，不是从观测重算的：
            --   prune() 会删掉旧快照（连带 devices 行），而首见时间不该跟着被删掉。
            --   所以它们只在写入时按 MIN/MAX/自增推进，永不回退。
            first_seen   REAL NOT NULL,
            last_seen    REAL NOT NULL,
            seen_count   INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX idx_assets_last_seen ON assets(last_seen);
        CREATE INDEX idx_assets_ip ON assets(ip);
        -- 观测维度：给 devices 补上身份键（见上面 `_SQL_V4` 的说明）
        ALTER TABLE devices ADD COLUMN identity_key TEXT DEFAULT '';
        CREATE INDEX idx_dev_identity ON devices(identity_key);
"""

#: 引入资产表的那一版迁移。`_init_db()` 靠它判断"要不要回填"。
ASSETS_MIGRATION_VERSION = 4

MIGRATIONS = [
    (1, _SQL_V1, "snapshots / devices + 三个索引"),
    (2, _SQL_V2, "switch_map / port_map + 三个索引"),
    (3, _SQL_V3, "security_findings + 两个索引"),
    (4, _SQL_V4, "assets + devices.identity_key（资产表）"),
]

#: 本程序支持的 schema 版本（= 迁移链最后一版）。
SCHEMA_VERSION = MIGRATIONS[-1][0]

#: 识别"引入 user_version 之前建的库"：每张表属于引入它的那一版。
_LEGACY_TABLES = (
    ("snapshots", 1),
    ("devices", 1),
    ("switch_map", 2),
    ("port_map", 2),
    ("security_findings", 3),
    ("assets", 4),
)


def identity_key(mac="", ip="") -> str:
    """设备的身份键：**MAC 优先**，没有 MAC 才退回 ``ip:<ip>``。

    与 `device_timeline()` 的匹配规则一致（它也是 MAC 优先、无 MAC 才用 IP）——
    IP 会被 DHCP 回收后分给另一台机器，MAC 才是设备身份。

    归一化复用 `alert_policy.normalize_mac()`（小写带冒号）而不是另写一份：
    仓库里已经有 `excel_handler.normalize_mac`（绑 openpyxl）和
    `alert_policy.normalize_mac`（零依赖）两份了，第三份只会让三处漂移。

    既没有 MAC 也没有 IP 的设备**没有身份**（返回空串），不进资产表 ——
    它连"是哪台"都说不清，硬塞进去只会污染去重结果。
    （`query_history()` 也一样：它按 IP 聚合，先滤掉空 IP 的行。）
    """
    m = normalize_mac(mac)
    if m:
        return m
    _ip = (ip or "").strip()
    return ("ip:" + _ip) if _ip else ""


#: `assets` 里"随观测刷新"的属性列（身份键与时间列不在此列）。
_ASSET_COLS = (
    "mac", "ip", "status", "hostname", "vendor", "device_class", "os_guess",
    "open_ports", "services", "location", "user", "remark",
)

# 写入用 UPSERT：同一身份键第二次出现时**只推进时间、不覆盖好值**。
#
# 属性合并规则与 `query_history()` 完全一致 ——「最近一次出现且非空」才覆盖。
# 用**生成**的 SQL 而不是手写，是为了让"加列"这件事不可能忘记同步合并规则：
# 手写的话，新增一列后忘了在 DO UPDATE 里带上，表现是"这个字段永远是第一次
# 扫到的值"，非常难查。
#
# ⚠ MIN/MAX 用的是 SQLite 的**标量** min/max（两个参数的那一个），不是聚合函数。
_ASSET_UPSERT = (
    "INSERT INTO assets (identity_key, " + ", ".join(_ASSET_COLS) +
    ", first_seen, last_seen, seen_count) "
    "VALUES (?, " + ", ".join("?" * len(_ASSET_COLS)) + ", ?, ?, 1) "
    "ON CONFLICT(identity_key) DO UPDATE SET " +
    ", ".join("%s = CASE WHEN excluded.%s <> '' THEN excluded.%s ELSE assets.%s END"
              % (c, c, c, c) for c in _ASSET_COLS) +
    ", first_seen = MIN(assets.first_seen, excluded.first_seen)"
    ", last_seen  = MAX(assets.last_seen, excluded.last_seen)"
    ", seen_count = assets.seen_count + 1"
)

_UPDATE_IDENTITY_SQL = "UPDATE devices SET identity_key=? WHERE id=?"

#: 回填时一次攒多少行再提交。太小则往返多，太大则事务日志膨胀。
_BACKFILL_BATCH = 2000

#: 回填取数：按快照时间**升序**，这样"非空即覆盖"自然等价于「最近一次出现且非空」
#: —— 与 `query_history()` 里那段注释是同一个道理。
_BACKFILL_SQL = (
    "SELECT d.id AS id, d.mac AS mac, d.ip AS ip, d.status AS status, "
    "d.hostname AS hostname, d.vendor AS vendor, "
    "d.device_class AS device_class, d.os_guess AS os_guess, "
    "d.open_ports AS open_ports, d.location AS location, d.user AS user, "
    "d.remark AS remark, s.time AS snap_time "
    "FROM devices d JOIN snapshots s ON s.id = d.snapshot_id "
    "ORDER BY s.time ASC, d.id ASC"
)

#: "有没有值得回填的数据"：至少有一行能算出身份键。
_HAS_IDENTIFIABLE_SQL = (
    "SELECT 1 FROM devices WHERE TRIM(COALESCE(mac, '')) <> '' "
    "OR TRIM(COALESCE(ip, '')) <> '' LIMIT 1"
)


def _backfill_assets(conn) -> int:
    """把已有快照一次性折进 `assets`（迁移 v4 的**第二步**）。

    与"新快照入库"走**同一个** `_ASSET_UPSERT`，所以回填与在线写入不可能漂移 ——
    两套逻辑各写一遍是这类改造最容易错的地方。

    ⚠ **只在最后 commit 一次**：中途失败则什么都没改（`assets` 空、
    `devices.identity_key` 空），下次启动会**重新回填**（见 `_init_db()`）。
    这是有意的 —— 让重试天然幂等，不留半截状态。

    Returns:
        折进去的观测行数（devices 行数，不是资产数）。
    """
    keys = []      # [(identity_key, devices.id), ...]
    assets = []    # [_ASSET_UPSERT 的参数元组, ...]
    total = 0

    def _flush():
        if not keys:
            return
        conn.executemany(_UPDATE_IDENTITY_SQL, keys)
        conn.executemany(_ASSET_UPSERT, assets)
        keys.clear()
        assets.clear()

    for r in conn.execute(_BACKFILL_SQL):
        key = identity_key(r["mac"], r["ip"])
        if not key:
            continue
        keys.append((key, r["id"]))
        assets.append((
            key, r["mac"], r["ip"], r["status"], r["hostname"], r["vendor"],
            r["device_class"], r["os_guess"], r["open_ports"],
            "",  # services：历史快照从来没存过，无从回填
            r["location"], r["user"], r["remark"],
            r["snap_time"], r["snap_time"],
        ))
        total += 1
        if len(keys) >= _BACKFILL_BATCH:
            _flush()
    _flush()
    conn.commit()
    return total


def _assets_need_backfill(conn) -> bool:
    """`assets` 是空的、但库里有能算出身份键的设备行 → 需要回填。

    这个判定同时充当**重试条件**：回填失败时因为只在最后 commit，库会原样留在
    "assets 空"的状态，于是下次启动自动重试。反之若库里压根没有可识别的设备
    （比如全部没 MAC 也没 IP），这里返回 False —— 不会每次启动都空跑一遍。
    """
    if conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]:
        return False
    return conn.execute(_HAS_IDENTIFIABLE_SQL).fetchone() is not None


def _services_to_text(services) -> str:
    """服务清单 → 落库的文本形式（JSON 数组字符串）。

    为什么是 JSON 而不是像 `open_ports` 那样逗号分隔：服务名本身可能带逗号
    （`http-alt`、`microsoft-ds` 之类的别名不至于，但自定义服务名会），
    而 `open_ports` 是端口号、天然不含逗号。

    接受两种输入：list（转成 JSON）与 str（**假定已经是 JSON**，原样存）。
    后者是为了让"从 `assets.services` 读出来再写回去"这类往返不需要特判。
    """
    if not services:
        return ""
    if isinstance(services, str):
        return services
    try:
        return json.dumps(list(services), ensure_ascii=False)
    except (TypeError, ValueError) as e:
        # 服务清单是展示信息，不该因为一个不可序列化的元素把整份快照写不进去。
        _log.warning("服务清单序列化失败，本次不落库：%s", e)
        return ""


def _backup_path(db_path, version) -> str:
    """升级前备份文件的位置：`<库路径>.bak-v<升级前版本>`。"""
    return "%s.bak-v%d" % (db_path, version)


def _init_db(conn, db_path=None):
    """建库 / 升级。`db_path` 只用来算备份文件的位置。"""
    # effective_version() 含"老库推断"，所以**全新库**在这里是 0 ——
    # 没数据可丢，不备份。
    before = db_util.effective_version(conn, _LEGACY_TABLES)
    if 0 < before < SCHEMA_VERSION:
        # 升级前备份一份。失败不拦（db_util.backup_to_file 内部只记日志）。
        db_util.backup_to_file(conn, _backup_path(db_path, before))
    after = db_util.apply_migrations(conn, MIGRATIONS, legacy_tables=_LEGACY_TABLES)
    # ⚠ 上界 `<= SCHEMA_VERSION` 不能省：库比程序**新**时（`after` 更大）
    #   `assets` 这张表可能根本不存在，下面的回填一查就会抛
    #   `no such table` —— 而"新版建的库被旧版打开"必须**不报错**
    #   （见 `db_util.apply_migrations()` 里那条不降级规则）。
    if ASSETS_MIGRATION_VERSION <= after <= SCHEMA_VERSION and _assets_need_backfill(conn):
        # 回填失败**不能**让程序打不开自己的库：资产表是增强，不是前提。
        # 因为只在最后 commit，失败后库仍是"assets 空"的状态，下次启动会重试。
        try:
            n = _backfill_assets(conn)
            _log.info("资产表回填完成：%d 条观测 → %d 台设备", n,
                      conn.execute("SELECT COUNT(*) AS c FROM assets")
                          .fetchone()["c"])
        except Exception as e:  # noqa: BLE001
            _log.error("资产表回填失败，下次启动会重试（历史功能不受影响）：%s", e)


@contextlib.contextmanager
def _conn(db_path=None):
    """复用进程级单例连接（按 db_path 缓存，线程安全）。"""
    path = db_path or DB_PATH

    def _init(c):
        # 闭包而不是直接传 `_init_db`：`_init_db` 需要**库路径**来算升级前的
        # 备份文件放哪，而 `db_util` 的 init_fn 只给 conn。这样 `db_util` 不用
        # 为此多一个参数。
        _init_db(c, path)

    with db_util.connection(path, init_fn=_init, pragmas=_PRAGMAS) as c:
        yield c


def save_snapshot(devices, ts=None, note=None, max_keep=20, db_path=None) -> int:
    """保存一条快照（devices 为设备字典列表）。返回新快照 id。

    devices 中每个字典可用字段：ip/status/mac/hostname/vendor/
    device_class/os_guess/open_ports/location/user/remark（缺字段按空串处理）。

    另有一个**可选**字段 `security_findings`：`[(kind, value), ...]` 的
    `(规范代码, 规范值)` 对（见 `tls_cert_facts()`）。走这里而不是另开一个
    `save_*()`，是为了让 GUI 与 CLI 的**所有**落库路径自动带上它 ——
    单独一个函数迟早会有人忘记调。
    """
    ts = time.time() if ts is None else ts
    with _conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO snapshots (time, device_count, note) VALUES (?,?,?)",
            (ts, len(devices), note),
        )
        # lastrowid 在 typeshed 里是 `int | None` —— None 只可能意味着这次 INSERT
        # 根本没执行。此时继续下去会把所有 devices 挂在 `snapshot_id=None` 下：
        # 设备**写得进去**，却因为连不到任何快照而永远查不到 —— 那是**静默坏数据**，
        # 比当场报错难查得多。所以这里不返回 0 之类的假 id，也不用 cast 抹掉，
        # 直接响出来（本函数对外承诺 `-> int`，做不到就该让调用方看见）。
        sid = cur.lastrowid
        if sid is None:
            raise RuntimeError("快照 INSERT 未返回 rowid，拒绝继续写入 devices")
        sec_rows = []
        asset_rows = []
        for d in devices:
            key = identity_key(d.get("mac", ""), d.get("ip", ""))
            conn.execute(
                "INSERT INTO devices "
                "(snapshot_id, ip, status, mac, hostname, vendor, "
                "device_class, os_guess, open_ports, location, user, remark, "
                "identity_key) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    sid,
                    d.get("ip", ""), d.get("status", ""), d.get("mac", ""),
                    d.get("hostname", ""), d.get("vendor", ""), d.get("device_class", ""),
                    d.get("os_guess", ""), d.get("open_ports", ""), d.get("location", ""),
                    d.get("user", ""), d.get("remark", ""),
                    key,
                ),
            )
            # 双写：devices 是"这一份快照里的设备"，assets 是"这台设备"。
            # 两者口径不同，缺一不可 —— 只写前者则资产表永远停在升级那天，
            # 只写后者则快照比对 / 时间线这些"按份看"的功能没有数据。
            if key:
                asset_rows.append((
                    key,
                    d.get("mac", ""), d.get("ip", ""), d.get("status", ""),
                    d.get("hostname", ""), d.get("vendor", ""),
                    d.get("device_class", ""), d.get("os_guess", ""),
                    d.get("open_ports", ""),
                    _services_to_text(d.get("services")),
                    d.get("location", ""), d.get("user", ""), d.get("remark", ""),
                    ts, ts,
                ))
            ip = d.get("ip", "")
            for kind, value in (d.get("security_findings") or ()):
                sec_rows.append((sid, ip, kind, value))
        if asset_rows:
            # 同一份快照里出现重复身份键（例如同 MAC 两行）时，UPSERT 的
            # seen_count 会各记一次 —— 与"这台设备在这次扫描里被看到几次"一致。
            conn.executemany(_ASSET_UPSERT, asset_rows)
        if sec_rows:
            conn.executemany(
                "INSERT INTO security_findings (snapshot_id, ip, kind, value) "
                "VALUES (?,?,?,?)", sec_rows,
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


def get_snapshot(snapshot_id, db_path=None) -> Optional[dict]:
    """返回完整快照 {"time": float, "devices": [...]}；不存在返回 None。

    每台设备若在 `security_findings` 里有记录，会多出一个
    `security_findings: {kind: value}` 键（没有记录时**不**加这个键，
    免得消费方把"没探到"当成"探到但为空"）。
    """
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
    findings = get_security_findings(snapshot_id, db_path=db_path)
    devices = []
    for d in devs:
        item = dict(d)
        found = findings.get(item.get("ip", ""))
        if found:
            item["security_findings"] = found
        devices.append(item)
    return {"time": row["time"], "devices": devices}


def latest_devices(db_path=None) -> list:
    """最近一次快照里的**设备字典列表**（结构同 ``get_snapshot()["devices"]``）。

    没有任何快照时返回空列表。

    用途：被动发现（`scanner/passive.py`）的「已知设备」基线。给整份设备列表
    而不是只给 IP 集合，是因为 `PassiveWatcher` 还需要**设备指纹**
    （主机名 / 厂商）—— 同一台设备换了随机 MAC 或换了 IP 时，靠指纹把它认成
    老设备，而不是重复报一次「新设备」。
    """
    snaps = list_snapshots(db_path=db_path)
    if not snaps:
        return []
    snap = get_snapshot(snaps[-1]["id"], db_path=db_path)
    if not snap:
        return []
    return list(snap["devices"])


def latest_device_ips(db_path=None) -> set:
    """最近一次快照里的设备 IP 集合。没有任何快照时返回空集。

    用途：被动发现的「已知设备」基线 —— 有了它，`PassiveWatcher` 报出来的
    才是"上次扫描之后新冒出来的设备"，而不是把整张 ARP 表都当成新设备。
    """
    return {d["ip"] for d in latest_devices(db_path=db_path) if d.get("ip")}


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
    从"翻快照"变成一眼可见（见 docs/reviews/UI_REVIEW.md P3-1）。

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


def save_port_map(snapshot_id, switches, db_path=None) -> int:
    """把一次扫描中各交换机的端口映射写入 switch_map / port_map。

    端口映射与设备列表**分开存**：它不是每次扫描都有（需要 SNMP，且交换机得支持
    BRIDGE-MIB），所以单独建表，并允许某次快照一行都没有。

    Args:
        snapshot_id: 已保存的快照 id。
        switches:    可迭代，每项为 dict：
                     ``{"switch_ip", "switch_name", "error",
                        "mappings": [{"mac", "port_name", "port_is_real"}, ...]}``
                     `error` 非空表示这台交换机没取到转发表 —— 仍会写一条 switch_map，
                     好让 locate_device() 能区分「没扫过」与「扫了但失败」。
                     `port_is_real` 为 False 表示 `port_name` 只是桥接端口号（不是真
                     端口名），由本函数翻成 `port_source` 落库。
        db_path:     历史库路径；None 表示默认位置。

    Returns:
        写入 port_map 的行数（即 (交换机, MAC) 对总数）。

    **对同一 snapshot_id 是幂等的**：再次调用会先清掉该快照已有的
    switch_map / port_map 行再写 —— 否则「同一快照重读一次转发表」会让
    (MAC → 端口) 记录翻倍，`locate_device()` 的「上一次端口」判断就会读到
    同一时刻的重复行，得出假的「换过端口」。`switches` 为空/None 时**什么都不做**
    （那是「没找到交换机」，不是「这台交换机没有映射」，不该拿来清空已有数据）。
    """
    map_rows = []
    sw_rows = []
    for sw in switches or []:
        err = (sw.get("error") or "").strip()
        mappings = sw.get("mappings") or []
        sw_rows.append((
            snapshot_id, sw.get("switch_ip", ""), sw.get("switch_name", ""),
            "error" if err else "ok", err, len(mappings),
        ))
        if err:
            # 取不到转发表的交换机不产生端口行 —— 上面那条 switch_map 记录
            # 让 locate_device() 能说出「为什么位置未知」。
            continue
        for m in mappings:
            mac = (m.get("mac") or "").strip().upper()
            if not mac:
                continue
            # 产出方（switch_mapper）只报告「这个端口名是不是真实接口名」这个**事实**，
            # 由存储层翻成持久化的规范值 —— 避免领域层反向依赖存储层或共享常量表。
            source = (PORT_SOURCE_IF_NAME if m.get("port_is_real", True)
                      else PORT_SOURCE_BRIDGE_PORT)
            map_rows.append((
                snapshot_id, sw.get("switch_ip", ""), sw.get("switch_name", ""),
                mac, m.get("port_name", ""), source,
            ))

    if not sw_rows:
        return 0

    with _conn(db_path) as conn:
        # 先清后写：保证同一快照不会残留上一次的端口记录（见 docstring）
        conn.execute("DELETE FROM port_map WHERE snapshot_id=?", (snapshot_id,))
        conn.execute("DELETE FROM switch_map WHERE snapshot_id=?", (snapshot_id,))
        conn.executemany(
            "INSERT INTO switch_map "
            "(snapshot_id, switch_ip, switch_name, status, error, mac_count) "
            "VALUES (?,?,?,?,?,?)", sw_rows,
        )
        if map_rows:
            conn.executemany(
                "INSERT INTO port_map "
                "(snapshot_id, switch_ip, switch_name, mac, port_name, port_source) "
                "VALUES (?,?,?,?,?,?)", map_rows,
            )
        conn.commit()
    return len(map_rows)


# ── 零利用安全体检的事实（v1.9 #3）────────────────────────────────────

#: `security_findings.kind` 的规范代码。**语言无关**，展示时再翻译
#: （仓库铁律）。展示用的名字表等到第一个消费方（详情面板 / 安全视图）落地时
#: 再加，并同步登记进 `test_i18n_lazy.py::_label_tables()` —— 现在加了没人读。
SEC_TLS_CN = "tls_cn"
SEC_TLS_NOT_AFTER = "tls_not_after"
SEC_TLS_NOT_BEFORE = "tls_not_before"
SEC_TLS_SELF_SIGNED = "tls_self_signed"
SEC_TLS_SIG_ALG = "tls_sig_alg"
SEC_TLS_KEY = "tls_key"

#: LLMNR / NBNS 响应器（v1.9 #3 第二刀）。值存的是**探测名** —— 它正是"这个应答
#: 确实是在回我们那个问题"的证据（见 `scanner.llmnr_nbns` 的诚实降级一节）。
#: 探测名每次随机，所以它**不是**设备的稳定标识，只作现场证据留痕。
SEC_LLMNR_RESPONDER = "llmnr_responder"
SEC_NBNS_RESPONDER = "nbns_responder"

#: 协议规范值 → kind。新增协议在这里加一项；漏登记的协议走下面的兜底派生名，
#: 发现不会丢，只是 kind 少了这道"稳定契约"的保证。
_RESPONDER_KINDS = {"llmnr": SEC_LLMNR_RESPONDER, "nbns": SEC_NBNS_RESPONDER}

#: SMB 方言 / 签名（v1.9 #3 第四刀）。值全是语言无关的规范串：方言是
#: `"3.1.1"`，签名是 `"required"` / `"enabled"` / `"off"`，SMB1 可用是 `"1"`。
SEC_SMB_DIALECT = "smb_dialect"
SEC_SMB_SIGNING = "smb_signing"
SEC_SMB1 = "smb1"

#: `ScanResult.smb` 的事实名 → kind。与 `_RESPONDER_KINDS` 同一套规矩：
#: 漏登记的事实走兜底派生名（`encryption` → `smb_encryption`）—— 发现不能悄悄丢掉。
_SMB_KINDS = {"dialect": SEC_SMB_DIALECT, "signing": SEC_SMB_SIGNING,
              "smb1": SEC_SMB1}


def tls_cert_facts(cert) -> list:
    """把 `ScanResult.tls_cert`（一个 dict）摊成 `[(kind, value), ...]`。

    只收**非空**的项 —— 空值落库会让"没探到"与"探到了但该项为空"分不开。
    值全部是语言无关的规范串（日期是 `YYYY-MM-DDTHH:MM:SS`，布尔是 `"1"`）。
    """
    if not cert:
        return []
    out = []
    for kind, key in ((SEC_TLS_CN, "cn"),
                      (SEC_TLS_NOT_BEFORE, "not_before"),
                      (SEC_TLS_NOT_AFTER, "not_after"),
                      (SEC_TLS_SIG_ALG, "sig_alg")):
        value = str(cert.get(key) or "").strip()
        if value:
            out.append((kind, value))
    # 密钥拼成 "rsa/2048"；位数取不到时只写算法名，不要出现 "rsa/0"
    key_alg = str(cert.get("key_alg") or "").strip()
    key_bits = cert.get("key_bits") or 0
    if key_alg:
        out.append((SEC_TLS_KEY,
                    "%s/%d" % (key_alg, key_bits) if key_bits else key_alg))
    if cert.get("self_signed"):
        out.append((SEC_TLS_SELF_SIGNED, "1"))
    return out


def responder_facts(responder) -> list:
    """把 `ScanResult.name_responder`（`{协议: 探测名}`）摊成 `[(kind, value), ...]`。

    与 `tls_cert_facts()` 同一份契约：只收**非空**的项，值全是语言无关的规范串。
    未知协议走兜底派生名（`mdns` → `mdns_responder`）—— 发现不能悄悄丢掉，
    新增协议时也不用回来改这里。
    """
    if not responder:
        return []
    out = []
    for proto, name in sorted(responder.items()):
        proto = str(proto or "").strip().lower()
        value = str(name or "").strip()
        if proto and value:
            kind = _RESPONDER_KINDS.get(proto, proto + "_responder")
            out.append((kind, value))
    return out


def smb_facts(smb) -> list:
    """把 `ScanResult.smb`（`{事实名: 规范值}`）摊成 `[(kind, value), ...]`。

    与 `tls_cert_facts()` / `responder_facts()` 同一份契约：只收**非空**的项，
    值全是语言无关的规范串。未知事实名走兜底派生名（`encryption` →
    `smb_encryption`）—— 与 `responder_facts()` 同一个理由：发现不能悄悄丢掉。
    """
    if not smb:
        return []
    out = []
    for key, value in sorted(smb.items()):
        key = str(key or "").strip().lower()
        value = str(value or "").strip()
        if key and value:
            out.append((_SMB_KINDS.get(key, "smb_" + key), value))
    return out


def get_security_findings(snapshot_id, db_path=None) -> dict:
    """返回 `{ip: {kind: value}}`；该快照没有记录时返回空 dict。"""
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT ip, kind, value FROM security_findings "
            "WHERE snapshot_id=? ORDER BY id ASC", (snapshot_id,)
        ).fetchall()
    out = {}
    for row in rows:
        out.setdefault(row["ip"], {})[row["kind"]] = row["value"]
    return out


def locate_device(mac="", ip="", hostname="", db_path=None) -> dict:
    """定位一台设备接在**哪台交换机的哪个端口**，并给出与上一次的差异。

    回答的是局域网运维里被问得最多的问题：「这台机器插在哪个口？」
    数据来自各次扫描落库的交换机转发表（见 save_port_map）。

    **匹配优先用 MAC**，没有 MAC 时才退回 IP / 主机名 —— 与 device_timeline 同理：
    IP 会被 DHCP 回收后分配给另一台机器，MAC 才是设备身份。

    查不到时**如实说明是哪一种「未知」，绝不猜**（延续本项目的诚实降级原则）。
    `reason` 按下列优先级取值：

    ========================== ==============================================
    ``no_device``              压根没有这台设备：查询为空、库是空的，
                               或按 IP / 主机名反查不到设备。
    ``no_switch_data``         有快照，但从未扫过交换机（或未落库）。
    ``switch_scan_failed``     扫了交换机，但每一台都取不到转发表。
    ``mac_not_in_fdb``         交换机正常，但转发表里没有这个 MAC。
    ========================== ==============================================

    注意 ``no_switch_data`` 的**前提是至少存在一条快照**：空库里连设备都没见过，
    此时报 ``no_device``，不能拿 ``no_switch_data`` 搪塞。

    Args:
        mac:      设备 MAC（大小写不敏感）。
        ip:       设备 IP（仅当 mac 为空时使用）。
        hostname: 设备主机名（仅当 mac 与 ip 都为空时使用）。
        db_path:  历史库路径；None 表示默认位置。

    Returns:
        ``{"found", "reason", "mac", "ip", "hostname", "current", "previous",
           "moved", "switch_count", "port_confidence"}``

        - `mac` / `ip` / `hostname`：查询用的身份，**并尽量从库里补齐** ——
          只给 MAC 时会反查最近一次快照里的 IP 与主机名（给不出就是空串）。
        - `current` / `previous`：``{"snapshot_id","time","switch_ip","switch_name",
          "port_name","port_source"}``；`previous` 是**上一次端口不同**的那条记录。
        - `moved`：两次快照之间确实换了端口。
        - `port_confidence`：`'named'`（真实端口名）/ `'index_only'`（只有桥接端口号，
          展示时应标注不确定）。
    """
    _mac = (mac or "").strip().upper()
    _ip = (ip or "").strip()
    _host = (hostname or "").strip()

    result = {
        "found": False,
        "reason": LOCATE_NO_DEVICE,
        "mac": _mac, "ip": _ip, "hostname": _host,
        "current": None, "previous": None,
        "moved": False, "switch_count": 0,
        "port_confidence": "",
    }
    if not (_mac or _ip or _host):
        return result

    with _conn(db_path) as conn:
        # 1) 只给了 IP / 主机名时，先从**最近一次快照**的设备列表反查 MAC。
        if not _mac:
            if _ip:
                row = conn.execute(
                    "SELECT mac, ip, hostname FROM devices WHERE ip=? "
                    "ORDER BY snapshot_id DESC LIMIT 1", (_ip,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT mac, ip, hostname FROM devices WHERE hostname=? "
                    "ORDER BY snapshot_id DESC LIMIT 1", (_host,)).fetchone()
            if not row:
                return result                       # reason 保持 no_device
            _mac = (row["mac"] or "").strip().upper()
            result["mac"] = _mac
            result["ip"] = row["ip"] or _ip
            result["hostname"] = row["hostname"] or _host
            if not _mac:
                # 库里有这台设备但没记 MAC —— 拿不到身份，无法定位
                return result

        # 2) 补齐 IP / 主机名：只给了 MAC 时从最近一次快照反查。
        #    否则调用方拿到的 ip/hostname 只是它自己传进来的空串，
        #    而库里明明有 —— 展示层只能显示一排"—"，白丢信息。
        if not (result["ip"] and result["hostname"]):
            row = conn.execute(
                "SELECT ip, hostname FROM devices WHERE mac=? COLLATE NOCASE "
                "ORDER BY snapshot_id DESC LIMIT 1", (_mac,)).fetchone()
            if row:
                result["ip"] = result["ip"] or (row["ip"] or "")
                result["hostname"] = result["hostname"] or (row["hostname"] or "")

        # 3) 该 MAC 在各快照里的端口记录，新 → 旧。
        #    COLLATE NOCASE 必须显式写，否则比较式与 idx_pm_mac 的排序规则不一致、索引用不上。
        rows = conn.execute(
            "SELECT s.id AS snapshot_id, s.time AS time, p.switch_ip, p.switch_name, "
            "p.port_name, p.port_source "
            "FROM port_map p JOIN snapshots s ON s.id = p.snapshot_id "
            "WHERE p.mac = ? COLLATE NOCASE ORDER BY s.id DESC", (_mac,)).fetchall()

        # 4) 最近一次快照里交换机的概况 —— 用于区分「没扫过」与「扫了但没这台 MAC」
        sw_total = sw_ok = 0
        last = conn.execute(
            "SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        if last:
            for r in conn.execute(
                    "SELECT status, COUNT(*) AS c FROM switch_map "
                    "WHERE snapshot_id=? GROUP BY status", (last["id"],)).fetchall():
                sw_total += r["c"]
                if r["status"] == "ok":
                    sw_ok += r["c"]
        result["switch_count"] = sw_total

    if rows:
        result["found"] = True
        result["reason"] = ""
        result["current"] = dict(rows[0])
        result["port_confidence"] = (
            "index_only"
            if result["current"].get("port_source") == PORT_SOURCE_BRIDGE_PORT
            else "named"
        )
        cur_key = (result["current"]["switch_name"], result["current"]["port_name"])
        for r in rows[1:]:
            d = dict(r)
            if (d["switch_name"], d["port_name"]) != cur_key:
                result["previous"] = d
                break
        result["moved"] = result["previous"] is not None
        return result

    # 库里一次快照都没有（`last is None`）→ 这台设备必然未知，
    # 保持 no_device，不能降级成 no_switch_data：
    # 后者说的是「扫过设备、但没扫过交换机」，前提是**至少存在快照**。
    if last is None:
        return result

    if sw_total == 0:
        result["reason"] = LOCATE_NO_SWITCH_DATA
    elif sw_ok == 0:
        result["reason"] = LOCATE_SWITCH_SCAN_FAILED
    else:
        result["reason"] = LOCATE_MAC_NOT_IN_FDB
    return result


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

# SELECT 的列顺序必须与下面聚合循环里的**整数下标**一一对应。
# 用整数下标而不是列名取 sqlite3.Row 的字段是刻意的：按列名取值每行要做十几次
# 名字查找，8 万行就是近百万次；实测这是聚合环节最大的一笔开销。
_COL_SNAP_TIME = 0
_COL_IP = 1
_COL_FIELD0 = 2
_SELECT_COLS = "s.time AS snap_time, d.ip, " + ", ".join("d." + f for f in _AGG_FIELDS)


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


# 取消的检查间隔（行数）。太小会让每行都做一次 Event.is_set()，太大则取消
# 要等很久才生效。2 万行在 Python 侧只跑几十毫秒，取消失效的感知延迟可以忽略。
_CANCEL_CHECK_ROWS = 20000


class QueryCancelled(Exception):
    """查询被调用方主动取消（见 `query_history` 的 `cancel_event` 参数）。

    做成异常而不是"返回 None"：调用方（后台线程）必须能区分「用户点了停止」
    与「查询结果为空」—— 前者不该把空表格当成查询结果渲染出来。
    """


def _sql_like_escape(text) -> str:
    """转义 LIKE 的元字符，供过滤下推使用。

    用户输入的 `192.168.1._` 里那个 `_` 在 LIKE 里表示"任意单字符"，不转义就会
    连 `192.168.1.5` 一起匹配 —— 下推后结果与 Python 侧不一致，而这类"只在
    特定输入下才偏"的偏差是最难查的一类 bug。
    """
    return (str(text).replace("\\", "\\\\")
                     .replace("%", "\\%")
                     .replace("_", "\\_"))


def _network_like_prefix(net):
    """把 IPv4 网段转成可下推的 LIKE 前缀；无法安全表达时返回 None。

    只在**前缀长度是 8 的整数倍**时成立（/8、/16、/24 ……）：

        /24 → '192.168.1.%'      /16 → '10.0.%'      /8 → '192.%'

    末尾那个点不能省 —— 少了它，`192.168.1.%` 会错误匹配到 `192.168.10.5`。

    其余前缀长度（/22、/25 等）返回 None：交由 Python 侧过滤，**结果不变**，
    只是少了一次下推。宁可不下推，也不能下推错。
    """
    if net is None or net.version != 4:
        return None
    p = net.prefixlen
    if p < 8 or p % 8:
        return None
    octets = str(net.network_address).split(".")
    return ".".join(octets[:p // 8]) + ".%"


def query_history(device_class=None, network=None, first_seen_after=None,
                  first_seen_before=None, ip_substr=None, db_path=None,
                  limit=None, offset=0, cancel_event=None) -> list:
    """跨快照聚合查询历史设备，支持按类型 / 网段 / 首见时间 / IP 关键字过滤。

    返回每条记录包含：ip, status, mac, hostname, vendor, device_class,
    os_guess, open_ports, location, user, remark, first_seen, last_seen。
    按 last_seen 降序（最近活跃的排在前）。

    说明：
    - devices 表无首见时间列，first/last seen 通过按快照时间升序遍历推导；
    - 同一 IP 在不同快照中的属性以「最近一次出现且非空」的值为准（展示当前状态）；
    - device_class 过滤基于最新已知类型做子串匹配。

    Args:
        limit:  只返回排序后的前 N 条（None = 不限）。截取发生在**过滤与排序
                之后**，所以语义是"末见时间最近的 N 台"，而不是"任意 N 台"。
        offset: 跳过前 N 条。与 `limit` 组合即可翻页；同一份数据、同一组条件下
                翻页结果可复现（排序键相同时依赖 SQL 的 `s.time, d.id` 确定顺序
                + Python 稳定排序）。
        cancel_event: `threading.Event`；置位后抛 `QueryCancelled`。检查点落在
                读盘的循环里，因此能真正中断**查询**，而不是等整张表读完再丢结果。

    Raises:
        QueryCancelled: `cancel_event` 在取数过程中被置位。
    """
    net = _parse_network(network)

    ipk = (ip_substr or "").strip().lower()

    # ── 过滤下推 ─────────────────────────────────────────────────────────
    # 只下推**纯 ip 的函数**：`ip_substr` 与网段。这两个条件对同一个 IP 的判定
    # 与聚合结果无关，所以下推到行级与留在 Python 侧**结果完全等价**，但能把
    # 参与 Python 聚合的行数提前砍掉（/16 × 20 快照约 130 万行，这一层省的是
    # 最贵的那部分）。
    #
    # device_class **刻意不下推**：它比较的是聚合后的「最新已知类型」。若按行
    # 过滤，早于"变成打印机"之前的那些行会被丢掉，first_seen 就会从「这台设备
    # 第一次出现」悄悄变成「这台设备第一次是打印机」—— 与文档承诺不符。
    where = ["d.ip IS NOT NULL", "TRIM(d.ip) <> ''"]
    params = []
    # 用 TRIM(d.ip) 而不是裸 d.ip：聚合时 Python 侧对 ip 做了 .strip()，下推若
    # 直接比原列，一条存成 " 192.168.1.5 " 的记录会被 SQL 先滤掉、Python 却认为
    # 它该留下 —— 下推与判定口径必须对齐。
    if ipk:
        where.append("TRIM(d.ip) LIKE ? ESCAPE '\\'")
        params.append("%" + _sql_like_escape(ipk) + "%")
    prefix = _network_like_prefix(net)
    if prefix:
        where.append("TRIM(d.ip) LIKE ? ESCAPE '\\'")
        params.append(prefix)

    # 单条 JOIN 取回设备行（按快照时间升序），再在内存里聚合。
    #
    # 旧写法是 `for snap in list_snapshots(): get_snapshot(snap["id"])` ——
    # 典型的 N+1：N 个快照就是 N+1 次查询，而且每次 get_snapshot 都会把该快照
    # 的整张设备表读回来。默认保留 20 个快照、每个几百台设备时，这里是 21 次
    # 查询 + 全量读盘。
    #
    # 按时间**升序**遍历是刻意的：这样每遇到一个更新的快照就必然满足
    # snap_time > last_seen，于是"非空即覆盖"自然等价于「最近一次出现且非空」。
    # 若改成降序，最新快照里为空的字段将永远填不上旧值 —— 与文档承诺不符。
    sql = ("SELECT " + _SELECT_COLS +
           "  FROM devices d JOIN snapshots s ON s.id = d.snapshot_id "
           " WHERE " + " AND ".join(where) +
           " ORDER BY s.time ASC, d.id ASC")

    agg = {}  # ip -> 聚合记录
    with _conn(db_path) as conn:
        # 先查一次：表为空时下面的循环体一次都不执行，没有这一句"取消"就会失效。
        if cancel_event is not None and cancel_event.is_set():
            raise QueryCancelled()
        n = 0
        for r in conn.execute(sql, params):
            n += 1
            # 每 _CANCEL_CHECK_ROWS 行查一次取消 —— 检查点在读盘过程中，
            # 所以取消能真正中断查询，而不是等整张表读完再丢结果。
            if (cancel_event is not None and (n % _CANCEL_CHECK_ROWS) == 0
                    and cancel_event.is_set()):
                raise QueryCancelled()
            ip = (r[_COL_IP] or "").strip()
            if not ip:
                continue
            snap_time = r[_COL_SNAP_TIME]
            rec = agg.get(ip)
            if rec is None:
                rec = {"ip": ip, "first_seen": snap_time, "last_seen": snap_time}
                for i, f in enumerate(_AGG_FIELDS):
                    rec[f] = r[_COL_FIELD0 + i] or ""
                agg[ip] = rec
            else:
                if snap_time > rec["last_seen"]:
                    rec["last_seen"] = snap_time
                    # 最新快照覆盖属性（仅非空，避免清空历史好值）
                    for i, f in enumerate(_AGG_FIELDS):
                        v = r[_COL_FIELD0 + i] or ""
                        if v:
                            rec[f] = v
                if snap_time < rec["first_seen"]:
                    rec["first_seen"] = snap_time

    # 过滤
    # device_class 是语言无关的规范值（见 scanner/classify.py），但用户在英文
    # 界面里输入的是 "Printer"、历史库里存的却是「打印机」。用 i18n.canonical()
    # 把两边都还原为源串再比较，跨语言查询才不会静默返回空结果。
    dc = _canon(device_class).lower()
    results = []
    for rec in agg.values():
        if dc and dc not in _canon(rec.get("device_class", "")).lower():
            continue
        # ipk / net 上面已经下推给 SQL 了，这里**再判一次是刻意的**：
        # 下推只负责"少取点行"，判定权始终留在这一份 Python 逻辑上。两者若因
        # 边界情形（比如存了带空格的 IP）出现分歧，也是下推多取、这里滤掉，
        # 不会漏结果。
        if ipk and ipk not in (rec.get("ip", "") or "").lower():
            continue
        if net is not None and not _ip_in_network(rec.get("ip", ""), net):
            continue
        fs = rec.get("first_seen")
        if first_seen_after is not None and (fs is None or fs < first_seen_after):
            continue
        if first_seen_before is not None and (fs is None or fs > first_seen_before):
            continue
        results.append(rec)

    results.sort(key=lambda r: r.get("last_seen", 0), reverse=True)

    # limit / offset 在过滤与排序**之后**截取 —— 所以 limit 的语义是"末见时间
    # 最近的 N 台"，而不是"任意 N 台"（后者翻页会看到随机子集）。
    off = max(0, int(offset or 0))
    if off or limit is not None:
        end = None if limit is None else off + max(0, int(limit))
        results = results[off:end]
    return results
