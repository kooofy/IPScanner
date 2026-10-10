# -*- coding: utf-8 -*-
"""历史条件查询（query_history）单元测试。

覆盖：跨快照首见/末见推导、最新属性优先、类型/网段/IP/首见时间过滤、排序、组合过滤、
limit/offset 翻页、过滤下推等价性、取消（cancel_event）。
使用临时文件 DB，避免污染项目内 scan_history.db。
"""
import ipaddress
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history_store


def _dev(ip, **kw):
    base = {"ip": ip, "status": "online", "mac": "", "hostname": "",
            "vendor": "", "device_class": "", "os_guess": "", "open_ports": "",
            "location": "", "user": "", "remark": ""}
    base.update(kw)
    return base


def _save_many(snapshots, db):
    """snapshots: list of (ts, [device_dicts])；max_keep 抬高避免裁剪。"""
    for ts, devs in snapshots:
        history_store.save_snapshot(devs, ts=ts, db_path=db, max_keep=10 ** 9)


class TestHistoryQuery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import shutil
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty(self):
        self.assertEqual(history_store.query_history(db_path=self.db), [])

    def test_first_last_seen(self):
        _save_many([
            (1000.0, [_dev("192.168.1.10", device_class="PC")]),
            (2000.0, [_dev("192.168.1.10", device_class="PC")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        self.assertEqual(len(res), 1)
        self.assertAlmostEqual(res[0]["first_seen"], 1000.0)
        self.assertAlmostEqual(res[0]["last_seen"], 2000.0)

    def test_latest_nonempty_attr_wins(self):
        _save_many([
            (1000.0, [_dev("10.0.0.5", device_class="路由器", hostname="gw-old")]),
            (2000.0, [_dev("10.0.0.5", device_class="路由", hostname="gw-new", status="offline")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        self.assertEqual(res[0]["hostname"], "gw-new")
        self.assertEqual(res[0]["status"], "offline")
        self.assertEqual(res[0]["device_class"], "路由")

    def test_filter_device_class_substr(self):
        _save_many([
            (1000.0, [
                _dev("192.168.1.10", device_class="PC"),
                _dev("192.168.1.1", device_class="路由器"),
                _dev("192.168.1.20", device_class="打印机"),
            ]),
        ], self.db)
        res = history_store.query_history(device_class="路由", db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.1"])

    def test_filter_network_cidr(self):
        _save_many([
            (1000.0, [
                _dev("192.168.1.10", device_class="PC"),
                _dev("10.0.0.5", device_class="路由器"),
            ]),
        ], self.db)
        res = history_store.query_history(network="192.168.1.0/24", db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.10"])

    def test_filter_network_invalid_treated_as_no_filter(self):
        _save_many([(1000.0, [_dev("192.168.1.10")])], self.db)
        res = history_store.query_history(network="not-a-net", db_path=self.db)
        self.assertEqual(len(res), 1)

    def test_filter_ip_substr(self):
        _save_many([
            (1000.0, [
                _dev("192.168.1.10"),
                _dev("192.168.1.20"),
                _dev("10.0.0.5"),
            ]),
        ], self.db)
        res = history_store.query_history(ip_substr="192.168.1.2", db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.20"])

    def test_filter_first_seen_after(self):
        _save_many([
            (1000.0, [_dev("192.168.1.1")]),
            (5000.0, [_dev("192.168.1.2")]),
        ], self.db)
        res = history_store.query_history(first_seen_after=3000.0, db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.2"])

    def test_filter_first_seen_before(self):
        _save_many([
            (1000.0, [_dev("192.168.1.1")]),
            (5000.0, [_dev("192.168.1.2")]),
        ], self.db)
        res = history_store.query_history(first_seen_before=3000.0, db_path=self.db)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.1"])

    def test_sort_by_last_seen_desc(self):
        _save_many([
            (1000.0, [_dev("192.168.1.1")]),
            (3000.0, [_dev("192.168.1.2")]),
            (2000.0, [_dev("192.168.1.3")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        self.assertEqual(
            [r["ip"] for r in res],
            ["192.168.1.2", "192.168.1.3", "192.168.1.1"]
        )

    def test_combined_filters(self):
        _save_many([
            (1000.0, [_dev("192.168.1.10", device_class="PC")]),
            (5000.0, [_dev("192.168.1.20", device_class="路由器")]),
            (2000.0, [_dev("10.0.0.5", device_class="路由器")]),
        ], self.db)
        res = history_store.query_history(
            device_class="路由", network="192.168.1.0/24",
            first_seen_after=3000.0, db_path=self.db,
        )
        self.assertEqual([r["ip"] for r in res], ["192.168.1.20"])

    def test_disappeared_device_still_listed(self):
        # 设备只在早期快照出现，后期消失，首见/末见应锁定其活跃区间
        _save_many([
            (1000.0, [_dev("192.168.1.99", device_class="PC")]),
            (2000.0, [_dev("192.168.1.1")]),
        ], self.db)
        res = history_store.query_history(db_path=self.db)
        ips = [r["ip"] for r in res]
        self.assertIn("192.168.1.99", ips)
        rec = next(r for r in res if r["ip"] == "192.168.1.99")
        self.assertAlmostEqual(rec["first_seen"], 1000.0)
        self.assertAlmostEqual(rec["last_seen"], 1000.0)


class QueryHistoryQueryCountTest(unittest.TestCase):
    """回归守卫：query_history 不得退化成 N+1 查询。

    旧实现是 `list_snapshots()` 后对每个快照再 `get_snapshot(snap["id"])` ——
    N 个快照就是 N+1 次查询，且每次都把该快照的整张设备表读回来。默认保留 20 个
    快照时就是 21 次查询 + 全量读盘。改成单条 JOIN 后，`get_snapshot` 一次都不
    应该被调用。

    用"是否调用 get_snapshot"而不是"耗时"来断言：耗时在 CI 上不稳定，而调用次数
    是确定性的，能精确指出退化原因。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")

    def tearDown(self):
        import shutil
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_does_not_call_get_snapshot(self):
        _save_many([
            (1000.0 + i, [_dev(f"192.168.1.{i}", device_class="PC")])
            for i in range(6)
        ], self.db)

        calls = []
        orig = history_store.get_snapshot

        def _spy(*a, **kw):
            calls.append(a)
            return orig(*a, **kw)

        history_store.get_snapshot = _spy
        try:
            res = history_store.query_history(db_path=self.db)
        finally:
            history_store.get_snapshot = orig

        self.assertEqual(len(res), 6)
        self.assertEqual(
            calls, [],
            "query_history 又在逐快照调 get_snapshot 了（N+1 回归）",
        )


class QueryHistoryPagingTest(unittest.TestCase):
    """limit / offset：翻页拼起来必须与一次性取回**完全一致**。

    这一项对应 docs/ROADMAP_V1.8.md §1.3 的验收「查询带 LIMIT，翻页结果一致」。
    只断言"limit 生效"是不够的 —— 真正的风险是翻页时看到重复行或漏行，
    所以这里比的是"分页拼接 == 全量"，而不只是长度。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")
        # 每台设备一个快照时间 → last_seen 严格递减，排序完全确定
        _save_many(
            [(1000.0 + i, [_dev(f"10.0.0.{i + 1}", device_class="PC")])
             for i in range(10)],
            self.db,
        )

    def tearDown(self):
        import shutil
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pages_concatenate_to_full_result(self):
        full = [r["ip"] for r in history_store.query_history(db_path=self.db)]
        self.assertEqual(len(full), 10)
        pages = []
        for off in (0, 4, 8):
            pages += [r["ip"] for r in
                      history_store.query_history(db_path=self.db, limit=4, offset=off)]
        self.assertEqual(pages, full)

    def test_offset_beyond_end_is_empty(self):
        res = history_store.query_history(db_path=self.db, limit=4, offset=99)
        self.assertEqual(res, [])

    def test_limit_none_returns_everything(self):
        self.assertEqual(len(history_store.query_history(db_path=self.db, limit=None)), 10)

    def test_limit_zero_returns_nothing(self):
        self.assertEqual(history_store.query_history(db_path=self.db, limit=0), [])

    def test_limit_applies_after_sort_not_before(self):
        """limit 取的是**末见时间最近**的 N 台，不是"随便 N 台"。"""
        res = history_store.query_history(db_path=self.db, limit=3)
        self.assertEqual([r["ip"] for r in res], ["10.0.0.10", "10.0.0.9", "10.0.0.8"])


class QueryHistoryPushdownTest(unittest.TestCase):
    """过滤下推（SQL 侧预筛）必须与「全量取回后在 Python 过滤」结果一致。

    下推是纯粹的加速手段，**不允许**改变结果。这里用"同一份数据、两种算法
    对答案"的方式守它 —— 尤其盯住 LIKE 的两个经典坑：元字符（`_` / `%`）
    与八位组边界（`192.168.1.%` 不能匹配 `192.168.10.5`）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")
        _save_many([
            (1000.0, [
                _dev("192.168.1.10"), _dev("192.168.1.1"), _dev("192.168.10.5"),
                _dev("192.168.1.100"), _dev("10.0.0.5"), _dev("172.16.1.1"),
            ]),
        ], self.db)

    def tearDown(self):
        import shutil
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _python_only(self, **kw):
        """参照实现：不传过滤条件取全量，再在 Python 里按同一口径过滤。"""
        net = ipaddress.ip_network(kw["network"], strict=False) if kw.get("network") else None
        out = []
        for r in history_store.query_history(db_path=self.db):
            if net is not None and ipaddress.ip_address(r["ip"]) not in net:
                continue
            out.append(r["ip"])
        return sorted(out)

    def test_network_pushdown_matches_python_filter(self):
        # 含可下推的 /24 /16 /8，以及**不可**下推的 /25（应退回 Python 过滤）
        for net in ("192.168.1.0/24", "192.168.0.0/16", "10.0.0.0/8",
                    "192.168.1.0/25", "0.0.0.0/0"):
            with self.subTest(net=net):
                pushed = sorted(r["ip"] for r in
                                history_store.query_history(network=net, db_path=self.db))
                self.assertEqual(pushed, self._python_only(network=net))

    def test_network_prefix_does_not_leak_across_octets(self):
        """少了前缀末尾那个点，`192.168.1.%` 会把 `192.168.10.5` 一起匹配进来。"""
        res = history_store.query_history(network="192.168.1.0/24", db_path=self.db)
        self.assertEqual(sorted(r["ip"] for r in res),
                         ["192.168.1.1", "192.168.1.10", "192.168.1.100"])

    def test_ip_substr_pushdown_matches_python_filter(self):
        for key in ("192.168.1", "10.", "1.1", "0.0.5"):
            with self.subTest(key=key):
                pushed = sorted(r["ip"] for r in
                                history_store.query_history(ip_substr=key, db_path=self.db))
                expect = sorted(r["ip"] for r in history_store.query_history(db_path=self.db)
                                if key in r["ip"].lower())
                self.assertEqual(pushed, expect)

    def test_like_metachars_are_escaped(self):
        """`_` / `%` 是 LIKE 的元字符，不转义就会匹配到别的 IP。"""
        self.assertEqual(history_store._sql_like_escape("a%b_c\\d"), "a\\%b\\_c\\\\d")
        # 字面量 '%' 不该匹配任何 IP（不转义的话 LIKE '%%%' 会命中全部）
        self.assertEqual(history_store.query_history(ip_substr="%", db_path=self.db), [])

    def test_padded_ip_is_not_dropped_by_pushdown(self):
        """下推必须与聚合口径对齐：Python 侧对 ip 做了 strip()。

        若 SQL 直接比裸列，一条存成 `" 192.168.1.5 "` 的记录会被下推先滤掉，
        而 Python 认为它该留下 —— 这类"只有下推才漏"的偏差最难查。
        """
        other = os.path.join(self.tmp, "padded.db")
        _save_many([(1000.0, [_dev(" 192.168.1.5 ")])], other)
        try:
            res = history_store.query_history(network="192.168.1.0/24", db_path=other)
            self.assertEqual([r["ip"] for r in res], ["192.168.1.5"])
        finally:
            import db_util
            db_util.close_connection(other)

    def test_device_class_is_not_pushed_down(self):
        """device_class **不能**按行下推：那会把 first_seen 从"首次出现"改成
        "首次是打印机"。

        场景：一台设备在 t1 是 PC、t2 才被识别成打印机。按类型筛"打印机"时，
        它的首见时间必须仍是 t1 —— 这是"历史台账"与"当前快照"的区别所在。
        """
        db = os.path.join(self.tmp, "class.db")
        _save_many([
            (1000.0, [_dev("192.168.1.7", device_class="PC")]),
            (2000.0, [_dev("192.168.1.7", device_class="打印机")]),
        ], db)
        try:
            res = history_store.query_history(device_class="打印机", db_path=db)
            self.assertEqual(len(res), 1)
            self.assertAlmostEqual(res[0]["first_seen"], 1000.0,
                                   msg="首见时间被行级过滤改写了")
            self.assertAlmostEqual(res[0]["last_seen"], 2000.0)
        finally:
            import db_util
            db_util.close_connection(db)


class QueryHistoryCancelTest(unittest.TestCase):
    """cancel_event：取消必须抛出 QueryCancelled，而不是悄悄返回空列表。

    「返回空列表」会让后台线程把"用户点了停止"渲染成"查不到设备"，
    这正是要避免的误报。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "scan_history.db")
        _save_many(
            [(1000.0 + i, [_dev(f"10.0.{i // 256}.{i % 256}")]) for i in range(50)],
            self.db,
        )

    def tearDown(self):
        import shutil
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cancel_raises(self):
        ev = threading.Event()
        ev.set()
        with self.assertRaises(history_store.QueryCancelled):
            history_store.query_history(db_path=self.db, cancel_event=ev)

    def test_cancel_on_empty_db_still_raises(self):
        """空库也要抛 —— 否则"取消"在没数据时会被当成"查完了"。"""
        empty = os.path.join(self.tmp, "empty.db")
        ev = threading.Event()
        ev.set()
        try:
            with self.assertRaises(history_store.QueryCancelled):
                history_store.query_history(db_path=empty, cancel_event=ev)
        finally:
            import db_util
            db_util.close_connection(empty)

    def test_unset_cancel_event_returns_rows(self):
        ev = threading.Event()
        res = history_store.query_history(db_path=self.db, cancel_event=ev)
        self.assertEqual(len(res), 50)


if __name__ == "__main__":
    unittest.main()
