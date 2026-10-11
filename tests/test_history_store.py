# -*- coding: utf-8 -*-
import json
import os
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
