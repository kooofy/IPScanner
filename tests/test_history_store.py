# -*- coding: utf-8 -*-
import contextlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history_store


def _dev(ip, **kw):
    base = {"ip": ip, "status": "online", "mac": "", "hostname": "",
            "vendor": "", "device_class": "", "os_guess": "", "open_ports": "",
            "location": "", "user": "", "remark": ""}
    base.update(kw)
    return base


class TestHistoryStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _save_two(self):
        history_store.save_snapshot([_dev("1.1.1.1", mac="AA:BB")], ts=1000.0, db_path=self.db)
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB", user="李四"), _dev("1.1.1.2")],
            ts=2000.0, db_path=self.db)

    def test_roundtrip(self):
        self._save_two()
        all_snaps = history_store.load_all(self.db)
        self.assertEqual(len(all_snaps), 2)
        self.assertEqual(all_snaps[0]["time"], 1000.0)
        self.assertEqual(len(all_snaps[1]["devices"]), 2)
        self.assertEqual(all_snaps[1]["devices"][1]["ip"], "1.1.1.2")

    def test_device_fields_preserved(self):
        history_store.save_snapshot(
            [_dev("1.1.1.1", open_ports="80,443", device_class="打印机")], db_path=self.db)
        snap = history_store.load_all(self.db)[0]
        d = snap["devices"][0]
        self.assertEqual(d["open_ports"], "80,443")
        self.assertEqual(d["device_class"], "打印机")

    def test_list_snapshots_meta(self):
        self._save_two()
        metas = history_store.list_snapshots(self.db)
        self.assertEqual([m["device_count"] for m in metas], [1, 2])
        self.assertEqual(metas[0]["time"], 1000.0)

    def test_get_snapshot(self):
        sid = history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        snap = history_store.get_snapshot(sid, self.db)
        self.assertEqual(snap["devices"][0]["ip"], "1.1.1.1")
        self.assertIsNone(history_store.get_snapshot(99999, self.db))

    def test_prune_keeps_recent(self):
        for i in range(25):
            history_store.save_snapshot([_dev("1.1.1.%d" % (i % 250))],
                                        db_path=self.db, max_keep=20)
        self.assertEqual(len(history_store.list_snapshots(self.db)), 20)

    def test_migrate_from_json_idempotent(self):
        json_path = os.path.join(self.tmp, "scan_history.json")
        data = [
            {"time": 1.0, "devices": [_dev("1.1.1.1")]},
            {"time": 2.0, "devices": [_dev("1.1.1.1", user="王五"), _dev("1.1.1.2")]},
        ]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        self.assertEqual(history_store.migrate_from_json(json_path, self.db), 2)
        self.assertEqual(len(history_store.load_all(self.db)), 2)
        # 再次迁移应为 0（已存在快照，幂等）
        self.assertEqual(history_store.migrate_from_json(json_path, self.db), 0)


class SnapshotRowidGuardTest(unittest.TestCase):
    """`save_snapshot()` 的「拿不到 rowid 就拒绝继续」守卫。

    这条守卫是 pyright 逼出来的：``cur.lastrowid`` 在 typeshed 里是
    ``int | None``，而本函数对外承诺 ``-> int``。但真正值得为它写守卫的不是
    类型，是**失败模式** —— 若 INSERT 没生效还继续往下走，所有 devices 都会挂在
    ``snapshot_id=None`` 下：设备**写得进去**，却因为连不到任何快照而永远查不到。
    那是比当场报错难查得多的**静默坏数据**，所以不返回 0 之类的假 id。

    反过来，这条守卫也不能是「写了就没人管」的代码 —— 所以它自己有测试。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "guard.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, True)

    # ── 注入方式：从 `_conn` 这层包一层 ──────────────────────────────
    # 不能直接 patch `sqlite3.Connection.execute` —— 它是**不可变的 C 类型**
    # （实测 `TypeError: cannot set 'execute' attribute of immutable type`）。
    # 于是改在 history_store 的连接工厂这层包一个代理：只把 snapshots 那条
    # INSERT 的游标换成 "lastrowid 为 None" 的版本，其余全部照旧。
    #
    # ⚠ **原函数必须在 patch 之前取**：helper 里若再调 `history_store._conn()`，
    # 拿到的已经是 patch 后的自己 → 无限递归 → 抛 `RecursionError`，
    # 而 `RecursionError` 是 `RuntimeError` 的**子类**，`assertRaises(RuntimeError)`
    # 会**误判通过**。下面用 `assertRaisesRegex` 钉住 message，并另有一断言
    # 反向确认注入真的生效了 —— 两道都要有：第一道防"没抛"，第二道防"抛错了还在红"。

    def _run_save_without_rowid(self):
        """在"拿不到 rowid"的条件下跑一次 save_snapshot，返回执行过的 SQL 列表。"""
        seen = []
        original = history_store._conn          # ⚠ 必须在 patch **之前**取

        class _CursorWithoutRowid:
            lastrowid = None

            def __init__(self, cur):
                self._cur = cur

            def __getattr__(self, name):
                return getattr(self._cur, name)

        class _Conn:
            def __init__(self, real):
                self._real = real

            def execute(self, sql, *a, **k):
                norm = " ".join(sql.split()).upper()
                seen.append(norm)
                cur = self._real.execute(sql, *a, **k)
                if norm.startswith("INSERT INTO SNAPSHOTS"):
                    return _CursorWithoutRowid(cur)
                return cur

            def __getattr__(self, name):
                return getattr(self._real, name)

        @contextlib.contextmanager
        def patched(db_path=None):
            with original(db_path) as conn:
                yield _Conn(conn)

        # 单层 with，不嵌套 —— 嵌套 patch 会打乱 start/stop，把 mock 泄漏给后续测试。
        with mock.patch.object(history_store, "_conn", patched):
            with self.assertRaisesRegex(RuntimeError, "rowid"):
                history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        return seen

    def test_missing_rowid_is_refused(self):
        """rowid 拿不到时必须抛错，而不是拿个假 id 继续写。"""
        self._run_save_without_rowid()          # 断言在 helper 里

    def test_no_orphan_devices_are_left_behind(self):
        """守卫在写 devices **之前**就退出，所以库里不会留下孤儿设备。

        这条是上面那条的行为后果，单独写是为了让它有独立的失败信息 ——
        「抛了错」和「没写脏数据」是两件事，不该共用一个断言。
        """
        seen = self._run_save_without_rowid()

        # 关键：INSERT INTO devices **一次都没执行过** —— 守卫挡在它前面。
        self.assertFalse(
            [s for s in seen if s.startswith("INSERT INTO DEVICES")],
            "守卫失效：已经往 devices 里写了数据",
        )
        # 反向确认 mock 真的生效了 —— 否则这条测试什么都没测到（空断言）。
        self.assertTrue(
            [s for s in seen if s.startswith("INSERT INTO SNAPSHOTS")],
            "注入没生效 —— 这条测试什么都没测到",
        )

    def test_normal_path_still_returns_a_real_id(self):
        """反向对照：不 mock 时一切照旧 —— 证明上面两条不是因为环境坏了才红的。"""
        sid = history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        self.assertIsInstance(sid, int)
        self.assertEqual(history_store.get_snapshot(sid, self.db)["devices"][0]["ip"],
                         "1.1.1.1")


class TlsCertFactsTest(unittest.TestCase):
    """`tls_cert_facts()` —— 把证书事实摊成 `(kind, value)` 对。

    这一层的契约是「只收非空的项」：空值落库会让"没探到"与"探到了但该项为空"
    分不开，而这两件事在安全体检里含义完全不同。
    """

    def test_empty_cert_gives_nothing(self):
        for bad in ({}, None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(history_store.tls_cert_facts(bad), [])

    def test_full_cert(self):
        got = history_store.tls_cert_facts({
            "cn": "router.local", "issuer_cn": "ca.local",
            "not_before": "2025-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",
            "self_signed": True, "sig_alg": "sha256_rsa",
            "key_alg": "rsa", "key_bits": 2048, "curve": "",
        })
        self.assertEqual(dict(got), {
            "tls_cn": "router.local",
            "tls_not_before": "2025-01-01T00:00:00",
            "tls_not_after": "2027-01-01T00:00:00",
            "tls_sig_alg": "sha256_rsa",
            "tls_key": "rsa/2048",
            "tls_self_signed": "1",
        })

    def test_blank_values_are_skipped(self):
        got = history_store.tls_cert_facts(
            {"cn": "   ", "not_after": "", "sig_alg": None, "self_signed": False})
        self.assertEqual(got, [])

    def test_key_never_renders_zero_bits(self):
        """位数取不到时只写算法名 —— `"rsa/0"` 会被读成"0 位密钥"，纯属误导。"""
        self.assertEqual(history_store.tls_cert_facts(
            {"key_alg": "rsa", "key_bits": 0}), [("tls_key", "rsa")])
        self.assertEqual(history_store.tls_cert_facts(
            {"key_alg": "rsa", "key_bits": None}), [("tls_key", "rsa")])
        self.assertEqual(history_store.tls_cert_facts({"key_alg": ""}), [])

    def test_self_signed_is_encoded_as_one(self):
        self.assertEqual(history_store.tls_cert_facts({"self_signed": True}),
                         [("tls_self_signed", "1")])

    def test_issuer_cn_is_not_stored(self):
        """issuer_cn 刻意不落库 —— 它不参与任何风险判定，存了就是死数据。"""
        got = history_store.tls_cert_facts({"issuer_cn": "ca.local"})
        self.assertEqual(got, [])

    def test_values_are_language_neutral(self):
        """仓库铁律：存储用规范值。这里不该出现任何中文字样。"""
        got = history_store.tls_cert_facts({
            "cn": "a", "not_after": "2027-01-01T00:00:00",
            "self_signed": True, "sig_alg": "sha1_rsa",
            "key_alg": "rsa", "key_bits": 1024,
        })
        for kind, value in got:
            with self.subTest(kind=kind):
                self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in value))


class ResponderFactsTest(unittest.TestCase):
    """`responder_facts()` —— 把名字响应器事实摊成 `(kind, value)` 对。

    与 `tls_cert_facts()` 同一份契约（只收非空项）。值存的是**探测名**：
    它正是"这个应答确实在回我们那个问题"的证据。
    """

    def test_empty_gives_nothing(self):
        for bad in ({}, None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(history_store.responder_facts(bad), [])

    def test_known_protocols_map_to_stable_kinds(self):
        self.assertEqual(
            history_store.responder_facts({"llmnr": "ipscanner-a"}),
            [(history_store.SEC_LLMNR_RESPONDER, "ipscanner-a")])
        self.assertEqual(
            history_store.responder_facts({"nbns": "ipscanner-b"}),
            [(history_store.SEC_NBNS_RESPONDER, "ipscanner-b")])

    def test_both_protocols_produce_two_rows(self):
        """两个协议是**两个事实**（明细留在事实层），各自落一行。

        注意这与风险评分不同：评分把两者合成**一条**结论（见
        `risk_rules.responder_reasons`），事实层则要保留协议明细。
        """
        got = history_store.responder_facts({"llmnr": "x", "nbns": "x"})
        self.assertEqual(dict(got), {
            history_store.SEC_LLMNR_RESPONDER: "x",
            history_store.SEC_NBNS_RESPONDER: "x",
        })

    def test_output_is_sorted_for_stable_diffs(self):
        """排序固定 —— 否则同一份事实两次落库的行序可能不同。"""
        got = history_store.responder_facts({"nbns": "b", "llmnr": "a"})
        self.assertEqual([k for k, _v in got],
                         [history_store.SEC_LLMNR_RESPONDER,
                          history_store.SEC_NBNS_RESPONDER])

    def test_blank_entries_are_skipped(self):
        for bad in ({"": "x"}, {"llmnr": ""}, {"llmnr": "   "}, {"": ""},
                    {"llmnr": None}, {None: "x"}):
            with self.subTest(bad=bad):
                self.assertEqual(history_store.responder_facts(bad), [])

    def test_protocol_case_is_normalised(self):
        self.assertEqual(
            history_store.responder_facts({"LLMNR": "ipscanner-a"}),
            [(history_store.SEC_LLMNR_RESPONDER, "ipscanner-a")])

    def test_unknown_protocol_degrades_instead_of_dropping_the_finding(self):
        """没登记的新协议走兜底派生名 —— 发现不能悄悄丢。"""
        got = history_store.responder_facts({"mdns": "ipscanner-a"})
        self.assertEqual(got, [("mdns_responder", "ipscanner-a")])

    def test_values_are_language_neutral(self):
        for kind, value in history_store.responder_facts(
                {"llmnr": "ipscanner-a1b2c"}):
            with self.subTest(kind=kind):
                self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in value))
                self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in kind))


class SmbFactsTest(unittest.TestCase):
    """`smb_facts()` —— 把 SMB 方言 / 签名事实摊成 `(kind, value)` 对。

    与 `tls_cert_facts()` / `responder_facts()` 同一份契约（只收非空项、
    值全是语言无关的规范串）。
    """

    def test_empty_gives_nothing(self):
        for bad in ({}, None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(history_store.smb_facts(bad), [])

    def test_known_facts_map_to_stable_kinds(self):
        self.assertEqual(
            history_store.smb_facts({"dialect": "3.1.1"}),
            [(history_store.SEC_SMB_DIALECT, "3.1.1")])
        self.assertEqual(
            history_store.smb_facts({"signing": "required"}),
            [(history_store.SEC_SMB_SIGNING, "required")])
        self.assertEqual(
            history_store.smb_facts({"smb1": "1"}),
            [(history_store.SEC_SMB1, "1")])

    def test_full_fact_set_produces_three_rows(self):
        got = history_store.smb_facts({"dialect": "3.1.1",
                                       "signing": "required", "smb1": "1"})
        self.assertEqual(dict(got), {
            history_store.SEC_SMB_DIALECT: "3.1.1",
            history_store.SEC_SMB_SIGNING: "required",
            history_store.SEC_SMB1: "1",
        })

    def test_output_is_sorted_for_stable_diffs(self):
        """排序固定 —— 否则同一份事实两次落库的行序可能不同。"""
        got = history_store.smb_facts({"signing": "off", "dialect": "2.1",
                                       "smb1": "1"})
        self.assertEqual([k for k, _v in got],
                         [history_store.SEC_SMB_DIALECT,
                          history_store.SEC_SMB_SIGNING,
                          history_store.SEC_SMB1])

    def test_blank_entries_are_skipped(self):
        for bad in ({"dialect": ""}, {"dialect": "   "}, {"dialect": None},
                    {"": "3.1.1"}, {None: "3.1.1"}):
            with self.subTest(bad=bad):
                self.assertEqual(history_store.smb_facts(bad), [])

    def test_fact_name_case_is_normalised(self):
        self.assertEqual(
            history_store.smb_facts({"Dialect": "3.1.1"}),
            [(history_store.SEC_SMB_DIALECT, "3.1.1")])

    def test_unknown_fact_degrades_instead_of_dropping_the_finding(self):
        """没登记的新事实走兜底派生名 —— 与响应器那边同一个理由：发现不能悄悄丢。"""
        got = history_store.smb_facts({"encryption": "aes-128-ccm"})
        self.assertEqual(got, [("smb_encryption", "aes-128-ccm")])

    def test_values_are_language_neutral(self):
        for kind, value in history_store.smb_facts(
                {"dialect": "3.1.1", "signing": "required", "smb1": "1"}):
            with self.subTest(kind=kind):
                self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in value))
                self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in kind))

    def test_smb1_kind_is_not_derived_from_the_dialect(self):
        """`smb1` 是一条**独立**事实：3.1.1 服务器完全可以同时支持 SMB1。

        所以 `dialect == "3.1.1"` 与 `smb1 == "1"` 会同时出现 —— 只看方言
        会漏掉这种情况。
        """
        got = dict(history_store.smb_facts({"dialect": "3.1.1", "smb1": "1"}))
        self.assertEqual(got[history_store.SEC_SMB_DIALECT], "3.1.1")
        self.assertEqual(got[history_store.SEC_SMB1], "1")


class SecurityFindingsStoreTest(unittest.TestCase):
    """`security_findings` 表：落库、读回、级联清理、老库平滑升级。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    _FACTS = [("tls_cn", "router.local"),
              ("tls_not_after", "2026-10-21T12:00:00"),
              ("tls_self_signed", "1")]

    def test_save_and_read_back(self):
        sid = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=self._FACTS)],
            ts=1000.0, db_path=self.db)
        self.assertEqual(history_store.get_security_findings(sid, db_path=self.db),
                         {"10.0.0.9": dict(self._FACTS)})

    def test_get_snapshot_attaches_the_key_only_when_present(self):
        """没记录时**不**加这个键 —— 消费方不该把"没探到"当成"探到但为空"。"""
        sid = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=self._FACTS), _dev("10.0.0.10")],
            ts=1000.0, db_path=self.db)
        got = history_store.get_snapshot(sid, db_path=self.db)
        by_ip = {d["ip"]: d for d in got["devices"]}
        self.assertEqual(by_ip["10.0.0.9"]["security_findings"], dict(self._FACTS))
        self.assertNotIn("security_findings", by_ip["10.0.0.10"])

    def test_devices_without_the_field_are_fine(self):
        """老调用方（以及所有既有测试）传的字典没有这个键，不能因此报错。"""
        sid = history_store.save_snapshot([_dev("10.0.0.1")], db_path=self.db)
        self.assertEqual(history_store.get_security_findings(sid, db_path=self.db), {})

    def test_empty_list_is_the_same_as_missing(self):
        sid = history_store.save_snapshot(
            [_dev("10.0.0.1", security_findings=[])], db_path=self.db)
        self.assertEqual(history_store.get_security_findings(sid, db_path=self.db), {})

    def test_unknown_snapshot_gives_empty_dict(self):
        self.assertEqual(history_store.get_security_findings(99999, db_path=self.db), {})

    def test_responder_facts_round_trip(self):
        """响应器事实走的是**同一张表**（kind/value 是通用的）——
        这条同时证明两个 `SEC_*_RESPONDER` 常量与 `responder_facts()` 对得上。
        """
        facts = history_store.responder_facts({"llmnr": "ipscanner-a",
                                               "nbns": "ipscanner-a"})
        sid = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=facts)],
            ts=1000.0, db_path=self.db)
        self.assertEqual(history_store.get_security_findings(sid, db_path=self.db),
                         {"10.0.0.9": dict(facts)})

    def test_smb_facts_round_trip(self):
        """SMB 事实也走**同一张表** —— 这条同时证明三个 `SEC_SMB*` 常量
        与 `smb_facts()` 对得上。
        """
        facts = history_store.smb_facts({"dialect": "3.1.1",
                                         "signing": "required", "smb1": "1"})
        sid = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=facts)],
            ts=1000.0, db_path=self.db)
        self.assertEqual(history_store.get_security_findings(sid, db_path=self.db),
                         {"10.0.0.9": dict(facts)})

    def test_two_snapshots_do_not_bleed_into_each_other(self):
        """每次快照各存一份 —— 历史对比靠的就是这个（上一份 vs 这一份）。"""
        first = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=[("tls_cn", "old.local")])],
            ts=1000.0, db_path=self.db)
        second = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=[("tls_cn", "new.local")])],
            ts=2000.0, db_path=self.db)
        self.assertEqual(history_store.get_security_findings(first, db_path=self.db),
                         {"10.0.0.9": {"tls_cn": "old.local"}})
        self.assertEqual(history_store.get_security_findings(second, db_path=self.db),
                         {"10.0.0.9": {"tls_cn": "new.local"}})

    def test_prune_cascades_to_findings(self):
        """剪掉旧快照时，事实行必须跟着走 —— 否则库里全是找不到主的孤儿行。"""
        for i in range(5):
            history_store.save_snapshot(
                [_dev("10.0.0.%d" % i, security_findings=self._FACTS)],
                ts=float(i), db_path=self.db, max_keep=2)
        with history_store._conn(self.db) as conn:
            live = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
            rows = conn.execute("SELECT COUNT(*) FROM security_findings").fetchone()[0]
        self.assertEqual(live, 2)
        self.assertEqual(rows, 2 * len(self._FACTS))

    def test_old_database_is_upgraded_in_place(self):
        """老库没有这张表 —— `CREATE TABLE IF NOT EXISTS` 要在首次打开时补上。

        这正是选"竖表"而不是给 `devices` 加列的原因：加列需要 `ALTER TABLE`
        迁移脚本，而竖表只要一条建表语句，且后续几个切片（LLMNR/NBNS、
        SMB 方言）也不用再动 schema。
        """
        old = os.path.join(self.tmp, "old.db")
        import sqlite3
        conn = sqlite3.connect(old)
        conn.executescript("""
            CREATE TABLE snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT,
                time REAL, device_count INTEGER, note TEXT);
            CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER, ip TEXT, status TEXT, mac TEXT,
                hostname TEXT, vendor TEXT, device_class TEXT, os_guess TEXT,
                open_ports TEXT, location TEXT, user TEXT, remark TEXT);
            INSERT INTO snapshots (time, device_count) VALUES (1.0, 1);
            INSERT INTO devices (snapshot_id, ip, status)
                VALUES (1, '192.168.1.5', 'online');
        """)
        conn.commit()
        conn.close()

        got = history_store.get_snapshot(1, db_path=old)
        self.assertEqual(got["devices"][0]["ip"], "192.168.1.5")
        self.assertNotIn("security_findings", got["devices"][0])
        # 升级后新表可用，且老快照照样能读
        sid = history_store.save_snapshot(
            [_dev("192.168.1.6", security_findings=self._FACTS)],
            ts=2.0, db_path=old)
        self.assertEqual(
            history_store.get_security_findings(sid, db_path=old),
            {"192.168.1.6": dict(self._FACTS)})
        import db_util
        db_util.close_connection(old)


class SchemaMigrationTest(unittest.TestCase):
    """`history_store` 的 schema 迁移链（`PRAGMA user_version`）。

    这层是「资产表 + 观测表」改造的**前置**：没有版本号，加列只能靠 `try/except`
    猜"用户手里的库是哪个年代的"。测试要证明四件事：

    1. 新库直接建到最新版；
    2. **老库（无版本号）被"盖章"而不是被重放** —— 它的版本号按已有表推断；
    3. 老库缺的表会被补齐，已有数据一行不丢；
    4. 版本比程序新的库不降级、不报错。
    """

    _TABLES = ("snapshots", "devices", "switch_map", "port_map",
               "security_findings", "assets")

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _raw(self, path, script=None, version=None):
        """直接建一个"老库"（绕开 history_store，模拟历史版本建出来的库）。"""
        import sqlite3
        c = sqlite3.connect(path)
        if script:
            c.executescript(script)
        if version is not None:
            c.execute("PRAGMA user_version = %d" % version)
        c.commit()
        c.close()

    def _inspect(self, path):
        """返回 (表名集合, user_version)。"""
        import sqlite3
        c = sqlite3.connect(path)
        self.addCleanup(c.close)
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'").fetchall()}
        return tables, int(c.execute("PRAGMA user_version").fetchone()[0])

    # ── 迁移链本身的不变量 ────────────────────────────────────────────

    def test_migrations_start_at_one_and_are_contiguous(self):
        """版本号必须连续从 1 开始 —— 中间断号意味着有一条迁移永远不会被执行。"""
        versions = [v for v, _sql, _desc in history_store.MIGRATIONS]
        self.assertEqual(versions, list(range(1, len(versions) + 1)))

    def test_schema_version_matches_the_last_migration(self):
        self.assertEqual(history_store.SCHEMA_VERSION,
                         history_store.MIGRATIONS[-1][0])

    def test_every_migration_can_be_inferred_from_a_table(self):
        """每一版都至少有一张"属于它"的表（或"属于它"的列）。

        否则老库推断出的版本会**偏低**，于是已经建过的迁移被重复执行 —— 建表
        （`IF NOT EXISTS`）恰好无害，但**只加列的迁移重放会报 `duplicate column
        name`**，库直接打不开。这条守的就是那个前提。

        标记有两种形态：``(表名, 版本)`` 与 ``(表名, 列名, 版本)``（后者给只加列
        的迁移用，见 `db_util.infer_legacy_version`）。
        """
        introduced = {m[-1] for m in history_store._LEGACY_TABLES}
        self.assertEqual(
            introduced,
            {v for v, _sql, _desc in history_store.MIGRATIONS},
            "每一版迁移都要在 _LEGACY_TABLES 里有对应的表或列，否则推断不出这个版本")

    def test_every_migration_description_is_present(self):
        """说明会进日志 —— 迁移跑起来时日志是唯一能看出"升了什么"的地方。"""
        for version, _sql, desc in history_store.MIGRATIONS:
            self.assertTrue(desc.strip(), "迁移 v%d 缺说明" % version)

    # ── 新库 ──────────────────────────────────────────────────────────

    def test_new_database_lands_on_the_latest_version(self):
        history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        _tables, version = self._inspect(self.db)
        self.assertEqual(version, history_store.SCHEMA_VERSION)

    def test_new_database_has_every_table(self):
        history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        tables, _v = self._inspect(self.db)
        self.assertEqual(tables, set(self._TABLES))

    def test_empty_file_is_treated_as_a_new_database(self):
        open(self.db, "wb").close()
        history_store.list_snapshots(self.db)
        tables, version = self._inspect(self.db)
        self.assertEqual(version, history_store.SCHEMA_VERSION)
        self.assertEqual(tables, set(self._TABLES))

    # ── 老库：盖章，不重放 ────────────────────────────────────────────

    def test_legacy_database_without_a_version_is_adopted(self):
        """v1.8.0 建出来的库：五张表都在，但版本号是 0。

        必须**按已有表推断**出它其实是 v3，直接盖章 —— 不能当成新库从 v1 重放。
        """
        history_store.save_snapshot([_dev("1.1.1.1", mac="AA:BB")],
                                    ts=1000.0, db_path=self.db)
        tables_before, _v = self._inspect(self.db)
        import db_util
        db_util.close_connection(self.db)
        # 抹掉版本号，还原成"引入 user_version 之前"的库
        self._raw(self.db, version=0)
        _t, v0 = self._inspect(self.db)
        self.assertEqual(v0, 0)

        snaps = history_store.list_snapshots(self.db)
        tables, version = self._inspect(self.db)
        self.assertEqual(version, history_store.SCHEMA_VERSION)
        self.assertEqual(tables, tables_before)
        # 数据一行没丢
        self.assertEqual(len(snaps), 1)

    def test_legacy_database_is_adopted_at_its_inferred_version(self):
        """只有 v1 两张表的老库（v1.7.6 之前）→ 推断为 v1，补跑 v2 / v3。"""
        old = os.path.join(self.tmp, "old_v1.db")
        self._raw(old, script=history_store._SQL_V1)
        tables, _v = self._inspect(old)
        self.assertEqual(tables, {"snapshots", "devices"})

        history_store.list_snapshots(old)
        tables, version = self._inspect(old)
        self.assertEqual(version, history_store.SCHEMA_VERSION)
        self.assertEqual(tables, set(self._TABLES))
        import db_util
        db_util.close_connection(old)

    def test_partial_legacy_database_gets_the_missing_tables(self):
        """v2 形态的老库 → 只补跑 v3，且 `security_findings` 立即可用。"""
        old = os.path.join(self.tmp, "old_v2.db")
        self._raw(old, script=history_store._SQL_V1 + history_store._SQL_V2)
        history_store.list_snapshots(old)
        tables, version = self._inspect(old)
        self.assertEqual(version, history_store.SCHEMA_VERSION)
        self.assertEqual(tables, set(self._TABLES))
        # 补出来的表能真的写进去
        sid = history_store.save_snapshot(
            [_dev("10.0.0.9", security_findings=[("tls_cn", "r.local")])],
            ts=1.0, db_path=old)
        self.assertEqual(
            history_store.get_security_findings(sid, db_path=old),
            {"10.0.0.9": {"tls_cn": "r.local"}})
        import db_util
        db_util.close_connection(old)

    def test_legacy_adoption_preserves_existing_rows(self):
        """盖章不能把老数据弄丢 —— 这是整个迁移链唯一不可接受的结果。"""
        old = os.path.join(self.tmp, "old_rows.db")
        self._raw(old, script=history_store._SQL_V1 + """
            INSERT INTO snapshots (time, device_count) VALUES (1.0, 1);
            INSERT INTO devices (snapshot_id, ip, status) VALUES (1,'192.168.1.5','online');
        """)
        got = history_store.get_snapshot(1, db_path=old)
        self.assertEqual(got["devices"][0]["ip"], "192.168.1.5")
        import db_util
        db_util.close_connection(old)

    # ── 幂等 / 未来库 ─────────────────────────────────────────────────

    def test_reopening_does_not_change_the_version(self):
        history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        _t, first = self._inspect(self.db)
        for _ in range(3):
            import db_util
            db_util.close_connection(self.db)
            history_store.list_snapshots(self.db)
            _t, version = self._inspect(self.db)
            self.assertEqual(version, first)

    def test_newer_database_is_not_downgraded(self):
        """用新版建的库被旧版程序打开 → 不降级、不报错，只记一条 warning。

        ⚠ 这条现在是**真会红**的：资产表落地后，曾经的写法
        「`after >= ASSETS_MIGRATION_VERSION` 就去查 assets」会在这种库上抛
        `no such table: assets` —— 因为 v99 的库里**没有** assets 表。
        那正好是"回退到旧版 exe 就打不开库"，比版本不一致严重得多。
        """
        future = os.path.join(self.tmp, "future.db")
        self._raw(future, script=history_store._SQL_V1, version=99)
        history_store.list_snapshots(future)
        _t, version = self._inspect(future)
        self.assertEqual(version, 99)
        import db_util
        db_util.close_connection(future)


class IdentityKeyTest(unittest.TestCase):
    """`identity_key()` —— 资产表的主键从哪来。

    它决定了"两台记录算不算同一台设备"，是整个资产表最基础的一个判断。
    """

    def test_mac_wins_over_ip(self):
        self.assertEqual(history_store.identity_key("AA:BB:CC:DD:EE:FF", "1.2.3.4"),
                         "aa:bb:cc:dd:ee:ff")

    def test_mac_is_normalized(self):
        """大小写与分隔符都要归一 —— 否则同一台设备会被拆成两台。"""
        self.assertEqual(history_store.identity_key("AA-BB-CC-DD-EE-FF"),
                         history_store.identity_key("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(history_store.identity_key("aabb.ccdd.eeff"),
                         history_store.identity_key("aa:bb:cc:dd:ee:ff"))

    def test_ip_is_the_fallback(self):
        """没有 MAC 才退回 IP —— 与 `device_timeline()` 的匹配规则一致。"""
        self.assertEqual(history_store.identity_key("", "1.2.3.4"), "ip:1.2.3.4")

    def test_ip_fallback_is_marked(self):
        """回退键必须带前缀，否则 IP 会和 MAC 撞进同一个命名空间。"""
        self.assertTrue(history_store.identity_key("", "1.2.3.4").startswith("ip:"))

    def test_nothing_to_identify(self):
        """既没 MAC 也没 IP → 没有身份，不该进资产表（会污染去重）。"""
        self.assertEqual(history_store.identity_key("", ""), "")
        self.assertEqual(history_store.identity_key(None, None), "")


class AssetTableTest(unittest.TestCase):
    """资产表（迁移 v4）—— v1.9 主题项 1.1 的验收。

    ⚠ **assets 与 query_history() 口径不同**，这不是 bug 而是本项要交付的改进：
      * `query_history()` 按 **IP** 聚合 —— 一台设备换过 IP 就是 N 行；
      * `assets` 按 **身份键**（MAC 优先）聚合 —— 换 IP 还是 1 行。
    所以"与 query_history 逐台一致"只在「有 MAC 且 IP 没变过」的设备上成立，
    测试就按这个口径写 —— **不假装两者永远相等**，否则这条验收会掩盖真正的差异。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    # ── 造库：一个货真价实的 v1.8.0 形态老库 ──────────────────────────

    def _legacy_v3(self, snaps, version=0):
        """手工搭一个老库：`snaps` = [(ts, [(ip, mac, ...), ...]), ...]。

        刻意**绕开** history_store 建库：这样造出来的才是"上一个版本真会写出来
        的那个形态"（五张表、没有 assets、devices 没有 identity_key）。
        `version=0` 是默认 —— v1.8.0 之前根本没有 user_version。
        """
        sql = [history_store._SQL_V1, history_store._SQL_V2, history_store._SQL_V3]
        sid = 0
        for ts, devs in snaps:
            sid += 1
            sql.append(
                "INSERT INTO snapshots (id, time, device_count) VALUES (%d, %r, %d);"
                % (sid, ts, len(devs)))
            for d in devs:
                sql.append(
                    "INSERT INTO devices (snapshot_id, ip, status, mac, hostname, "
                    "vendor, device_class, os_guess, open_ports, location, user, "
                    "remark) VALUES (%d, '%s', 'online', '%s', '%s', '', '', '', "
                    "'', '', '', '');"
                    % (sid, d.get("ip", ""), d.get("mac", ""),
                       d.get("hostname", "")))
        self._raw(self.db, script="".join(sql), version=version)
        return sid

    def _raw(self, path, script=None, version=None):
        import sqlite3
        c = sqlite3.connect(path)
        if script:
            c.executescript(script)
        if version is not None:
            c.execute("PRAGMA user_version = %d" % version)
        c.commit()
        c.close()

    def _assets(self, path=None):
        import sqlite3
        c = sqlite3.connect(path or self.db)
        self.addCleanup(c.close)
        c.row_factory = sqlite3.Row
        return {r["identity_key"]: dict(r)
                for r in c.execute("SELECT * FROM assets").fetchall()}

    # ── 回填正确性 ────────────────────────────────────────────────────

    def test_backfill_folds_every_identifiable_device(self):
        """三份快照、两台设备（其中一台只出现两次）→ 资产表两行。"""
        self._legacy_v3([
            (1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}]),
            (2000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"},
                      {"ip": "1.1.1.2", "mac": "AA:BB:CC:DD:EE:02"}]),
            (3000.0, [{"ip": "1.1.1.2", "mac": "AA:BB:CC:DD:EE:02"}]),
        ])
        history_store.list_snapshots(self.db)
        got = self._assets()
        self.assertEqual(set(got), {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
        self.assertEqual(got["aa:bb:cc:dd:ee:01"]["seen_count"], 2)
        self.assertEqual(got["aa:bb:cc:dd:ee:02"]["seen_count"], 2)
        self.assertEqual(got["aa:bb:cc:dd:ee:01"]["first_seen"], 1000.0)
        self.assertEqual(got["aa:bb:cc:dd:ee:01"]["last_seen"], 2000.0)
        self.assertEqual(got["aa:bb:cc:dd:ee:02"]["first_seen"], 2000.0)
        self.assertEqual(got["aa:bb:cc:dd:ee:02"]["last_seen"], 3000.0)

    def test_backfill_agrees_with_query_history(self):
        """**回填正确性的硬标准**：与 `query_history()` 逐台对表。

        只在「有 MAC 且 IP 没变过」的设备上比 —— 见本类 docstring。
        """
        self._legacy_v3([
            (1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"},
                      {"ip": "1.1.1.2", "mac": "AA:BB:CC:DD:EE:02"}]),
            (2500.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}]),
            (4000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"},
                      {"ip": "1.1.1.2", "mac": "AA:BB:CC:DD:EE:02"}]),
        ])
        history_store.list_snapshots(self.db)
        assets = self._assets()
        hist = {r["mac"]: r for r in history_store.query_history(db_path=self.db)}
        self.assertEqual(len(hist), 2)
        for rec in hist.values():
            key = history_store.identity_key(rec["mac"], rec["ip"])
            self.assertIn(key, assets)
            self.assertEqual(assets[key]["first_seen"], rec["first_seen"],
                             "首见时间不一致：%s" % key)
            self.assertEqual(assets[key]["last_seen"], rec["last_seen"],
                             "末见时间不一致：%s" % key)

    def test_a_device_that_roamed_is_one_asset(self):
        """换过 IP 的设备：query_history 是 N 行，assets 是 1 行 —— 这是改进。"""
        self._legacy_v3([
            (1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}]),
            (2000.0, [{"ip": "1.1.1.9", "mac": "AA:BB:CC:DD:EE:01"}]),
        ])
        history_store.list_snapshots(self.db)
        self.assertEqual(len(self._assets()), 1)
        # 对照：按 IP 聚合的历史视图确实是两行
        self.assertEqual(
            len(history_store.query_history(db_path=self.db)), 2)

    def test_devices_get_their_identity_key(self):
        """回填顺带把 `devices.identity_key` 填上 —— 观测维度靠它连回资产。"""
        self._legacy_v3([
            (1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"},
                      {"ip": "1.1.1.2"}]),      # 没有 MAC → 走 IP 回退
        ])
        history_store.list_snapshots(self.db)
        import sqlite3
        c = sqlite3.connect(self.db)
        self.addCleanup(c.close)
        got = {r[0] for r in c.execute("SELECT identity_key FROM devices")}
        self.assertEqual(got, {"aa:bb:cc:dd:ee:01", "ip:1.1.1.2"})

    def test_backfill_is_idempotent(self):
        """重开库不该再折一遍 —— seen_count 翻倍是最典型的漂移。"""
        self._legacy_v3([(1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}])])
        history_store.list_snapshots(self.db)
        first = self._assets()["aa:bb:cc:dd:ee:01"]["seen_count"]
        import db_util
        for _ in range(3):
            db_util.close_connection(self.db)
            history_store.list_snapshots(self.db)
        self.assertEqual(self._assets()["aa:bb:cc:dd:ee:01"]["seen_count"], first)

    def test_a_new_database_is_not_backfilled(self):
        """新库不该再走一遍回填 —— 否则双写 + 回填会把 seen_count 记成 2。

        （新库当然**会**有资产行：那是 `save_snapshot()` 双写出来的。）
        """
        history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        self.assertEqual(self._assets()["ip:1.1.1.1"]["seen_count"], 1)

    def test_backfill_failure_leaves_the_database_openable(self):
        """回填失败不能让程序打不开自己的库 —— 资产表是增强，不是前提。

        而且因为只在最后 commit，失败后库仍是"assets 空"的状态，
        **下次启动会自动重试** —— 这条顺带验证重试真的会发生。
        """
        self._legacy_v3([(1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}])])
        with mock.patch.object(history_store, "_backfill_assets",
                               side_effect=RuntimeError("boom")):
            with self.assertLogs("ipscanner.history_store", level="ERROR"):
                history_store.list_snapshots(self.db)
        self.assertEqual(self._assets(), {})
        # 快照本身照常可读 —— 历史功能不受影响
        self.assertEqual(len(history_store.list_snapshots(self.db)), 1)

        import db_util
        db_util.close_connection(self.db)
        history_store.list_snapshots(self.db)
        self.assertEqual(len(self._assets()), 1)

    # ── 双写 ──────────────────────────────────────────────────────────

    def test_three_scans_of_one_device(self):
        for ts in (1000.0, 2000.0, 3000.0):
            history_store.save_snapshot(
                [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=ts, db_path=self.db)
        got = self._assets()["aa:bb:cc:dd:ee:01"]
        self.assertEqual(got["seen_count"], 3)
        self.assertEqual(got["first_seen"], 1000.0)
        self.assertEqual(got["last_seen"], 3000.0)

    def test_double_write_keeps_devices_and_assets_consistent(self):
        """一次 save_snapshot 后，两边的 status / open_ports 必须一致。"""
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01", status="online",
                  open_ports="80,443")],
            ts=1000.0, db_path=self.db)
        asset = self._assets()["aa:bb:cc:dd:ee:01"]
        snap = history_store.get_snapshot(1, db_path=self.db)
        self.assertEqual(asset["status"], snap["devices"][0]["status"])
        self.assertEqual(asset["open_ports"], snap["devices"][0]["open_ports"])
        self.assertEqual(asset["ip"], "1.1.1.1")

    def test_an_empty_field_does_not_wipe_a_known_value(self):
        """属性合并规则与 query_history() 一致：「最近一次出现且非空」才覆盖。"""
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01", hostname="pc-1")],
            ts=1000.0, db_path=self.db)
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01", hostname="")],
            ts=2000.0, db_path=self.db)
        self.assertEqual(self._assets()["aa:bb:cc:dd:ee:01"]["hostname"], "pc-1")

    def test_writing_an_older_snapshot_does_not_move_the_times(self):
        """乱序写入（旧 JSON 迁移、手工导入）不能把 last_seen 拉回去。

        ⚠ 这条是**反向验证**逼出来的：把 `MAX(assets.last_seen, excluded.last_seen)`
        换成 `excluded.last_seen` 之后，测试**全绿** —— 因为回填是按时间升序跑的，
        `excluded` 永远不比已有的旧。于是那一半看似多余，
        其实它只在"乱序写入"这条路上起作用，而这条路**当时没有任何测试**。
        """
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=5000.0, db_path=self.db)
        # 补一份更早的（migrate_from_json 遇到未排序的 JSON 就是这样）
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=1000.0, db_path=self.db)
        got = self._assets()["aa:bb:cc:dd:ee:01"]
        self.assertEqual(got["first_seen"], 1000.0)
        self.assertEqual(got["last_seen"], 5000.0)
        self.assertEqual(got["seen_count"], 2)

    def test_pruning_does_not_roll_first_seen_back(self):
        """prune() 删旧快照（连带 devices 行），但首见时间**不能**跟着被删掉。

        这是 `assets` 把 first/last_seen 做成**累积列**而不是"从观测重算"的原因。
        """
        for ts in (1000.0, 2000.0, 3000.0):
            history_store.save_snapshot(
                [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=ts, db_path=self.db)
        self.assertEqual(len(history_store.list_snapshots(self.db)), 3)
        history_store.prune(max_keep=1, db_path=self.db)
        self.assertEqual(len(history_store.list_snapshots(self.db)), 1)
        got = self._assets()["aa:bb:cc:dd:ee:01"]
        self.assertEqual(got["first_seen"], 1000.0)
        self.assertEqual(got["last_seen"], 3000.0)
        self.assertEqual(got["seen_count"], 3)

    def test_services_are_stored_as_json(self):
        """服务名可能带逗号，所以用 JSON 而不是像 open_ports 那样逗号分隔。"""
        history_store.save_snapshot(
            [_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01", services=["http", "ssh"])],
            ts=1000.0, db_path=self.db)
        raw = self._assets()["aa:bb:cc:dd:ee:01"]["services"]
        self.assertEqual(json.loads(raw), ["http", "ssh"])
        self.assertEqual(history_store._services_to_text("[]"), "[]")
        self.assertEqual(history_store._services_to_text(None), "")

    def test_services_that_cannot_be_serialised_do_not_break_the_snapshot(self):
        """服务清单是展示信息 —— 不该因为一个怪元素把整份快照写不进去。"""
        with self.assertLogs("ipscanner.history_store", level="WARNING"):
            text = history_store._services_to_text([object()])
        self.assertEqual(text, "")

    # ── 升级前备份 ────────────────────────────────────────────────────

    def test_the_old_file_is_backed_up_before_the_upgrade(self):
        """升级前那份必须还在，而且**还是能被旧版程序打开**的形态。"""
        self._legacy_v3([(1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}])])
        history_store.list_snapshots(self.db)
        backup = history_store._backup_path(self.db, 3)
        self.assertTrue(os.path.exists(backup), "没有生成备份：%s" % backup)

        import sqlite3
        c = sqlite3.connect(backup)
        self.addCleanup(c.close)
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        # 旧版程序打开它：没有 assets 表、user_version 还是 0（推断值，没写进去）
        self.assertNotIn("assets", tables)
        self.assertEqual(int(c.execute("PRAGMA user_version").fetchone()[0]), 0)
        # 数据在（WAL 里的内容也一起带走了 —— 用 backup API 就是为了这个）
        self.assertEqual(
            c.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)

    def test_a_new_database_is_not_backed_up(self):
        """新库没东西可丢 —— 不该每次启动都往数据目录里扔一个备份文件。"""
        history_store.save_snapshot([_dev("1.1.1.1")], db_path=self.db)
        self.assertFalse(os.path.exists(history_store._backup_path(self.db, 3)))

    def test_a_failed_backup_does_not_block_the_upgrade(self):
        """备份是安全网不是门槛：备份失败不能反过来让库打不开。"""
        self._legacy_v3([(1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01"}])])
        with mock.patch.object(history_store.db_util, "backup_to_file",
                               return_value=False):
            history_store.list_snapshots(self.db)
        self.assertEqual(len(self._assets()), 1)

    # ── 对外行为不变 ──────────────────────────────────────────────────

    def test_upgrade_does_not_change_existing_behaviour(self):
        """老库升级后，`query_history()` / `device_timeline()` 结果不变。"""
        self._legacy_v3([
            (1000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01",
                       "hostname": "pc-1"}]),
            (2000.0, [{"ip": "1.1.1.1", "mac": "AA:BB:CC:DD:EE:01",
                       "hostname": "pc-1"}]),
        ])
        before = history_store.query_history(db_path=self.db)
        timeline = history_store.device_timeline(
            mac="AA:BB:CC:DD:EE:01", db_path=self.db)
        # 上面这句已经触发了升级；再取一次与它比对
        after = history_store.query_history(db_path=self.db)
        self.assertEqual(before, after)
        self.assertEqual(len(timeline), 2)


class AssetReadPathTest(unittest.TestCase):
    """资产表读路径（1.1-③）：把 assets 暴露给读取方。

    前 ①② 刀只写不读；这第③刀补"读"。验收要点：
      * list_assets 一行一台设备（按 identity_key），不是按 IP；
      * 过滤 / 分页口径对齐 query_history；
      * 旧库没有 assets 表时**优雅降级**（不崩、返回空）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _save(self, devs, ts):
        history_store.save_snapshot(devs, ts=ts, db_path=self.db)

    def test_list_assets_one_row_per_identity(self):
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=1000.0)
        self._save([_dev("1.1.1.2", mac="AA:BB:CC:DD:EE:02")], ts=2000.0)
        rows = history_store.list_assets(db_path=self.db)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["identity_key"] for r in rows},
                         {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})

    def test_roaming_mac_collapses_to_one_row(self):
        """换过 IP 但 MAC 没变 → 资产表 1 行；ip 取最近一次非空。"""
        self._save([_dev("1.1.1.10", mac="AA:BB:CC:DD:EE:01",
                         hostname="pc", open_ports="22")], ts=1000.0)
        self._save([_dev("1.1.1.50", mac="AA:BB:CC:DD:EE:01",
                         hostname="pc")], ts=2000.0)
        rows = history_store.list_assets(db_path=self.db)
        self.assertEqual(len(rows), 1)
        a = rows[0]
        self.assertEqual(a["identity_key"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(a["ip"], "1.1.1.50")
        self.assertEqual(a["open_ports"], "22")          # 第一次非空被保留
        self.assertEqual(a["seen_count"], 2)
        self.assertEqual(a["first_seen"], 1000.0)
        self.assertEqual(a["last_seen"], 2000.0)

    def test_seen_count_accumulates(self):
        for ts in (1000.0, 2000.0, 3000.0):
            self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=ts)
        rows = history_store.list_assets(db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["seen_count"], 3)

    def test_empty_field_does_not_wipe_known_value(self):
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01",
                        hostname="pc-1")], ts=1000.0)
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01",
                        hostname="")], ts=2000.0)
        self.assertEqual(history_store.list_assets(db_path=self.db)[0]["hostname"], "pc-1")

    def test_device_class_filter_is_canonical(self):
        """device_class 留 Python 侧、规范值子串匹配（跨语言）。"""
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01",
                        device_class="打印机")], ts=1000.0)
        self._save([_dev("1.1.1.2", mac="AA:BB:CC:DD:EE:02",
                        device_class="PC")], ts=2000.0)
        hit = history_store.list_assets(device_class="打印机", db_path=self.db)
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["identity_key"], "aa:bb:cc:dd:ee:01")

    def test_ip_substr_and_network_filters(self):
        self._save([_dev("10.0.0.1", mac="AA:BB:CC:DD:EE:01")], ts=1000.0)
        self._save([_dev("192.168.1.5", mac="AA:BB:CC:DD:EE:02")], ts=2000.0)
        self.assertEqual(len(history_store.list_assets(ip_substr="192.168",
                                                       db_path=self.db)), 1)
        self.assertEqual(len(history_store.list_assets(network="192.168.1.0/24",
                                                       db_path=self.db)), 1)
        self.assertEqual(len(history_store.list_assets(network="10.0.0.0/8",
                                                       db_path=self.db)), 1)

    def test_pagination(self):
        for i in range(3):
            self._save([_dev("1.1.1.%d" % (i + 1),
                            mac="AA:BB:CC:DD:EE:0%d" % (i + 1))],
                      ts=1000.0 + i)
        full = history_store.list_assets(db_path=self.db)
        self.assertEqual(len(full), 3)
        p1 = history_store.list_assets(limit=2, offset=0, db_path=self.db)
        p2 = history_store.list_assets(limit=2, offset=2, db_path=self.db)
        self.assertEqual(len(p1), 2)
        self.assertEqual(len(p2), 1)
        self.assertEqual({r["identity_key"] for r in p1 + p2},
                         {r["identity_key"] for r in full})

    def test_sorted_by_last_seen_desc(self):
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=1000.0)
        self._save([_dev("1.1.1.2", mac="AA:BB:CC:DD:EE:02")], ts=5000.0)
        self.assertEqual(history_store.list_assets(db_path=self.db)[0]
                         ["identity_key"], "aa:bb:cc:dd:ee:02")

    def test_get_asset(self):
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01",
                        hostname="pc")], ts=1000.0)
        a = history_store.get_asset("aa:bb:cc:dd:ee:01", db_path=self.db)
        self.assertIsNotNone(a)
        self.assertEqual(a["hostname"], "pc")
        self.assertIsNone(history_store.get_asset("nope", db_path=self.db))
        self.assertIsNone(history_store.get_asset("", db_path=self.db))
        self.assertIsNone(history_store.get_asset(None, db_path=self.db))

    def test_asset_count(self):
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=1000.0)
        self._save([_dev("1.1.1.2", mac="AA:BB:CC:DD:EE:02",
                        device_class="打印机")], ts=2000.0)
        self.assertEqual(history_store.asset_count(db_path=self.db), 2)
        self.assertEqual(history_store.asset_count(device_class="打印机",
                                                   db_path=self.db), 1)

    def test_first_seen_range_filters(self):
        """first_seen 范围下推 SQL（资产表有首见时间列，可直接比）。"""
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01")], ts=1000.0)
        self._save([_dev("1.1.1.2", mac="AA:BB:CC:DD:EE:02")], ts=5000.0)
        after = history_store.list_assets(first_seen_after=2000.0, db_path=self.db)
        self.assertEqual([r["identity_key"] for r in after],
                         ["aa:bb:cc:dd:ee:02"])
        before = history_store.list_assets(first_seen_before=2000.0, db_path=self.db)
        self.assertEqual([r["identity_key"] for r in before],
                         ["aa:bb:cc:dd:ee:01"])
        both = history_store.list_assets(first_seen_after=500.0,
                                         first_seen_before=6000.0, db_path=self.db)
        self.assertEqual(len(both), 2)

    def test_table_has_assets_helper(self):
        import sqlite3
        c = sqlite3.connect(":memory:")
        self.assertFalse(history_store._table_has_assets(c))
        c.execute("CREATE TABLE assets(x INTEGER)")
        self.assertTrue(history_store._table_has_assets(c))

    def test_graceful_degradation_without_assets_table(self):
        """v4 之前的旧库没有 assets 表 → 读路径返回空，不抛错。

        通过拦掉迁移（模拟"assets 因故缺失"）来触发降级分支：真实环境里
        `_init_db` 会建表，但这里是防御性分支，必须验证它**不崩**。
        """
        import sqlite3
        c = sqlite3.connect(self.db)
        c.executescript(history_store._SQL_V1 + history_store._SQL_V2
                        + history_store._SQL_V3)
        c.execute("INSERT INTO snapshots (id, time, device_count) VALUES (1, 1000.0, 1)")
        c.execute("INSERT INTO devices (snapshot_id, ip, status, mac, hostname, "
                  "vendor, device_class, os_guess, open_ports, location, user, "
                  "remark) VALUES (1, '1.1.1.1', 'online', 'AA:BB:CC:DD:EE:01', "
                  "'pc', '', '', '', '', '', '', '')")
        c.commit(); c.close()
        with mock.patch.object(history_store, "_init_db", lambda conn, path: None):
            self.assertEqual(history_store.list_assets(db_path=self.db), [])
            self.assertEqual(history_store.asset_count(db_path=self.db), 0)
            self.assertIsNone(history_store.get_asset("aa:bb:cc:dd:ee:01",
                                                      db_path=self.db))

    def test_read_path_does_not_alter_legacy_readers(self):
        """第③刀只新增读 assets 的函数，不能动 query_history / locate_device /
        device_timeline 的既有行为（1.1 验收红线：逐字段相同）。"""
        self._save([_dev("1.1.1.1", mac="AA:BB:CC:DD:EE:01", hostname="pc-1")],
                  ts=1000.0)
        self._save([_dev("1.1.1.9", mac="AA:BB:CC:DD:EE:01", hostname="pc-1")],
                  ts=2000.0)
        # query_history 按 IP 聚合 → 换过 IP 的设备是 2 行
        self.assertEqual(len(history_store.query_history(db_path=self.db)), 2)
        # device_timeline 按 MAC 仍给出 2 个观测
        self.assertEqual(len(history_store.device_timeline(
            mac="AA:BB:CC:DD:EE:01", db_path=self.db)), 2)
        # locate_device 仍返回结构完整的结果（不抛错）
        loc = history_store.locate_device(mac="AA:BB:CC:DD:EE:01",
                                          db_path=self.db)
        self.assertIsInstance(loc, dict)
        self.assertIn("mac", loc)


class FingerprintIdentityTest(unittest.TestCase):
    """v2.0 §2.1：指纹降级身份 —— 换随机 MAC 的设备仍只算一台。

    背景：iOS/Android/Windows 默认开「私有 Wi-Fi 地址」，同一台设备每次接入
    换一个随机 MAC（LAA）。只按 MAC 认设备的台账会把它反复报成新设备。

    本项**只对 LAA MAC 启用**指纹找回；非 LAA 的普通 MAC 行为与本项落地前
    逐字节一致（老用户零影响）。

    验收（对应 `docs/ROADMAP_V2.0.md` §3 2.1 的验收栏）：
      * 换 LAA MAC、主机名不变 → 资产数不增、seen_count+1、first_seen 保持；
      * 两台不同设备都 LAA、主机名不同 → 仍是两台（防错认）；
      * 只有 vendor 相同 → 不算同一台；
      * 非 LAA 普通 MAC → 行为不变；
      * 老库升级能正常回填、不产生重复资产。
    """

    #: 两个 LAA（随机）MAC：第一字节 0x02 位置 1。
    LAA_MAC_1 = "02:11:22:33:44:01"
    LAA_MAC_2 = "02:AA:BB:CC:DD:02"
    #: 一个普通（非 LAA）MAC。
    REAL_MAC = "00:1A:2B:3C:4D:01"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)

    def _save(self, devs, ts):
        history_store.save_snapshot(devs, ts=ts, db_path=self.db)

    def _assets(self):
        return history_store.list_assets(db_path=self.db)

    # ── 核心断言 ──────────────────────────────────────────────────────

    def test_randomized_mac_change_collapses_to_one_asset(self):
        """**核心**：同一台设备换随机 MAC -> 资产数不增、时间与计数都正确。"""
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone", vendor="Apple")], ts=1000.0)
        self._save([_dev("10.0.0.6", mac=self.LAA_MAC_2,
                         hostname="alice-iphone", vendor="Apple")], ts=2000.0)
        rows = self._assets()
        self.assertEqual(len(rows), 1, "换了随机 MAC 仍应是同一台设备")
        a = rows[0]
        self.assertEqual(a["seen_count"], 2)
        self.assertEqual(a["first_seen"], 1000.0, "首见时间不该被后一次观测顶掉")
        self.assertEqual(a["last_seen"], 2000.0)

    def test_key_stays_anchored_to_the_first_mac(self):
        """键锚定在**首次**的 MAC 上 —— 不因指纹出现与否而漂移。

        这条是「同一个东西不能有两个键」的守门测试：若首见就发 ``fp:`` 键，
        那么指纹那天拿不到时同一台设备会落到 MAC 键上 → 台账凭空多一台。
        """
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone")], ts=1000.0)
        self._save([_dev("10.0.0.6", mac=self.LAA_MAC_2,
                         hostname="alice-iphone")], ts=2000.0)
        rows = self._assets()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity_key"],
                         history_store.identity_key(self.LAA_MAC_1, ""))

    def test_fingerprint_is_recorded_for_explainability(self):
        """降级身份必须**可解释**：行上要看得出「靠指纹认回来的」。"""
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone")], ts=1000.0)
        a = self._assets()[0]
        self.assertTrue(a["fingerprint"], "指纹应被登记")
        self.assertTrue(history_store.is_fingerprint_key(a["fingerprint"]))

    def test_fingerprint_survives_an_observation_without_it(self):
        """一次「没拿到指纹」的观测不该把已记住的指纹抹掉。

        否则设备下次换 MAC 就再也认不回来了 —— 而瞬时拿不到指纹（NetBIOS 关着、
        mDNS 没响应）是常态。
        """
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone")], ts=1000.0)
        before = self._assets()[0]["fingerprint"]
        self.assertTrue(before)
        # 同一台设备、同一 MAC，但这次没有任何指纹字段
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1)], ts=2000.0)
        after = self._assets()[0]["fingerprint"]
        self.assertEqual(after, before, "空指纹不该覆盖已记住的指纹")

    # ── 防错认（比漏认严重得多）────────────────────────────────────────

    def test_two_different_devices_stay_two(self):
        """两台不同设备、都开 LAA、主机名不同 -> 仍是**两台**。"""
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone", vendor="Apple")], ts=1000.0)
        self._save([_dev("10.0.0.6", mac=self.LAA_MAC_2,
                         hostname="bob-pixel", vendor="Google")], ts=2000.0)
        self.assertEqual(len(self._assets()), 2)

    def test_vendor_only_match_is_not_the_same_device(self):
        """只有「厂商相同」不算同一台（同厂商设备太多）。"""
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1, vendor="Apple")], ts=1000.0)
        self._save([_dev("10.0.0.6", mac=self.LAA_MAC_2, vendor="Apple")], ts=2000.0)
        self.assertEqual(len(self._assets()), 2)

    def test_same_model_alone_is_not_enough(self):
        """只有型号相同（1 个 token）不够 —— 门槛与 `same_device()` 一致。"""
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         device_model="DS920+")], ts=1000.0)
        self._save([_dev("10.0.0.6", mac=self.LAA_MAC_2,
                         device_model="DS920+")], ts=2000.0)
        self.assertEqual(len(self._assets()), 2)

    # ── 老行为零影响 ──────────────────────────────────────────────────

    def test_non_laa_mac_behaviour_is_unchanged(self):
        """非 LAA 的普通 MAC：换 MAC 就是**不同设备**（与落地前一致）。"""
        self._save([_dev("10.0.0.5", mac=self.REAL_MAC, hostname="pc-1")], ts=1000.0)
        self._save([_dev("10.0.0.5", mac="00:1A:2B:3C:4D:02",
                         hostname="pc-1")], ts=2000.0)
        rows = self._assets()
        self.assertEqual(len(rows), 2, "普通 MAC 不应被指纹降级合并")
        self.assertEqual({r["identity_key"] for r in rows},
                         {"00:1a:2b:3c:4d:01", "00:1a:2b:3c:4d:02"})

    def test_stable_laa_mac_keeps_the_mac_key(self):
        """LAA MAC 但一直没变 -> 键就是那个 MAC（不因「有指纹」就改成 fp:）。"""
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone")], ts=1000.0)
        self._save([_dev("10.0.0.5", mac=self.LAA_MAC_1,
                         hostname="alice-iphone")], ts=2000.0)
        rows = self._assets()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity_key"],
                         history_store.identity_key(self.LAA_MAC_1, ""))
        self.assertEqual(rows[0]["seen_count"], 2)

    def test_no_mac_falls_back_to_ip_as_before(self):
        """没 MAC -> 仍退回 ip: 键（本项不改这条兜底）。"""
        self._save([_dev("10.0.0.5", hostname="nameless")], ts=1000.0)
        rows = self._assets()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity_key"], "ip:10.0.0.5")

    def test_snapshot_batch_finds_the_device_within_one_snapshot(self):
        """**同一份快照内**两次出现（两个随机 MAC、同一指纹）→ 认成一台。

        同一次扫描同时从 ARP 与 mDNS 看到同一台手机时，MAC 可能不同 ——
        先登记指纹的那行会成为后一行的锚点。
        """
        self._save([
            _dev("10.0.0.5", mac=self.LAA_MAC_1, hostname="alice-iphone"),
            _dev("10.0.0.6", mac=self.LAA_MAC_2, hostname="alice-iphone"),
        ], ts=1000.0)
        rows = self._assets()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["seen_count"], 2)

    # ── 迁移 v5：老库升级 ─────────────────────────────────────────────

    def test_legacy_v4_database_upgrades_and_backfills(self):
        """**老库（v4 形态、有 assets 无 fingerprint）** 升级到 v5 不报错、能回填。

        这是本项最危险的路径：`ALTER TABLE ADD COLUMN` 若被重放会直接
        `duplicate column name` 把库搞到打不开。
        """
        import sqlite3
        # 手工造一个 v4 形态的库（有 assets 表、但没有 fingerprint 列）
        c = sqlite3.connect(self.db)
        c.executescript(history_store._SQL_V1 + history_store._SQL_V2
                        + history_store._SQL_V3 + history_store._SQL_V4)
        c.execute("INSERT INTO snapshots (id, time, device_count) "
                  "VALUES (1, 1000.0, 1)")
        c.execute("INSERT INTO devices (snapshot_id, ip, status, mac, hostname) "
                  "VALUES (1, '1.1.1.1', 'online', 'AA:BB:CC:DD:EE:01', 'pc')")
        c.execute("PRAGMA user_version = 4")
        c.commit()
        c.close()

        # 打开 → 自动升到 v5 并回填
        rows = history_store.list_assets(db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identity_key"], "aa:bb:cc:dd:ee:01")
        # 回填也带上了 fingerprint 字段（可能为空 —— 老 devices 只有 hostname）
        self.assertIn("fingerprint", rows[0])

    def test_schema_version_is_five(self):
        self.assertEqual(history_store.SCHEMA_VERSION, 5)
        self.assertEqual([v for v, _s, _d in history_store.MIGRATIONS],
                         [1, 2, 3, 4, 5])

    def test_every_migration_has_a_legacy_marker(self):
        """每版迁移都要有「能推断出它」的表或列标记（见 db_util 推断规则）。"""
        introduced = {m[-1] for m in history_store._LEGACY_TABLES}
        self.assertEqual(introduced, {v for v, _s, _d in history_store.MIGRATIONS})


class FingerprintKeyUnitTest(unittest.TestCase):
    """`fingerprint_key()` / `is_fingerprint_key()` 的纯函数行为。"""

    def test_strong_anchor_gets_a_key(self):
        self.assertTrue(history_store.fingerprint_key({"hostname": "alice-iphone"}))
        self.assertTrue(history_store.fingerprint_key({"wmi_serial": "ABC123"}))

    def test_weak_signal_gets_no_key(self):
        """只有 vendor= 或只有 model= 不给键 —— 与 `same_device()` 门槛一致。"""
        self.assertEqual(history_store.fingerprint_key({"vendor": "Apple"}), "")
        self.assertEqual(history_store.fingerprint_key({"device_model": "DS920+"}), "")

    def test_model_plus_vendor_is_enough(self):
        self.assertTrue(history_store.fingerprint_key(
            {"device_model": "DS920+", "vendor": "Synology"}))

    def test_no_identity_fields_no_key(self):
        self.assertEqual(history_store.fingerprint_key({}), "")

    def test_same_tokens_same_key_regardless_of_order(self):
        a = history_store.fingerprint_key({"hostname": "h", "vendor": "v"})
        b = history_store.fingerprint_key({"vendor": "v", "hostname": "h"})
        self.assertEqual(a, b)

    def test_key_is_prefixed_and_not_plaintext(self):
        """键必须带 `fp:` 前缀（与 MAC / ip: 命名空间分开），且不含明文序列号。"""
        key = history_store.fingerprint_key({"wmi_serial": "SECRET-SERIAL"})
        self.assertTrue(key.startswith("fp:"))
        self.assertNotIn("SECRET", key)
        self.assertTrue(history_store.is_fingerprint_key(key))
        self.assertFalse(history_store.is_fingerprint_key("aa:bb:cc:dd:ee:ff"))
        self.assertFalse(history_store.is_fingerprint_key("ip:1.2.3.4"))
        self.assertFalse(history_store.is_fingerprint_key(""))


if __name__ == "__main__":
    unittest.main()
