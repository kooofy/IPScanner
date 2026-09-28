# -*- coding: utf-8 -*-
"""mDNS 合并契约（P2-7 的引擎侧）。

`scan()` 末尾的 mDNS 阶段是**唯一**会在 `result_callback` 之后继续修改
已渲染结果对象的地方（Phase 2 的 ARP 只处理从未被回调过的离线主机）。
UI 依赖 `ScanResult.mdns_updated` 判断"扫描结束后要不要重渲染这一行"，
所以这个标记必须准确，两个方向都错不得：

- 真的改过 → **必须**置位，否则 mDNS 补上的服务/主机名在界面上永远看不到；
- 没改动   → **不能**置位，否则 UI 又退回 O(n) 全量重渲染（P2-7 要消除的开销）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.constants import SVC_MDNS
from scanner.engine import NetworkScanner
from scanner.models import ScanResult


def _engine():
    return NetworkScanner()


class MergeMdnsTest(unittest.TestCase):

    def test_new_device_is_added(self):
        results = {}
        n = _engine()._merge_mdns(
            results,
            {"10.0.0.9": {"names": {"printer.local"}, "services": {"ipp"}}},
        )
        self.assertEqual(n, 1)
        r = results["10.0.0.9"]
        self.assertEqual(r.status, "online")
        self.assertEqual(r.discovery_method, "mdns")
        self.assertEqual(r.hostname, "printer.local")
        self.assertIn(SVC_MDNS, r.services)
        # 新设备本来就会入表，不需要 mdns_updated 触发重渲染
        self.assertFalse(r.mdns_updated)

    def test_existing_device_gains_service_and_is_marked(self):
        r = ScanResult(ip="10.0.0.5", status="offline")
        _engine()._merge_mdns(
            {"10.0.0.5": r},
            {"10.0.0.5": {"names": {"nas.local"}, "services": {"smb"}}},
        )
        self.assertTrue(r.mdns_updated, "就地改过的结果必须打标记，否则 UI 不会重渲染")
        self.assertEqual(r.status, "online")
        self.assertEqual(r.hostname, "nas.local")
        self.assertIn(SVC_MDNS, r.services)

    def test_unchanged_existing_device_is_not_marked(self):
        """核心回归：没有任何改动时不得打标记。

        否则扫描结束时会对所有 mDNS 命中的行做无谓重渲染 ——
        这正是 P2-7 要消除的 O(n) 开销。
        """
        r = ScanResult(ip="10.0.0.5", status="online",
                       hostname="already.local", discovery_method="mdns")
        r.services.append(SVC_MDNS)
        r.service_details.append({"proto": SVC_MDNS, "port": 0, "banner": "smb"})
        before = (list(r.services), r.hostname, r.status)

        _engine()._merge_mdns(
            {"10.0.0.5": r},
            {"10.0.0.5": {"names": {"already.local"}, "services": {"smb"}}},
        )

        self.assertFalse(r.mdns_updated, "结果没有任何改动，不该打 mdns_updated")
        self.assertEqual((list(r.services), r.hostname, r.status), before)

    def test_only_hostname_filled_marks(self):
        r = ScanResult(ip="10.0.0.5", status="online", hostname="")
        _engine()._merge_mdns(
            {"10.0.0.5": r},
            {"10.0.0.5": {"names": {"new.local"}, "services": set()}},
        )
        self.assertTrue(r.mdns_updated)
        self.assertEqual(r.hostname, "new.local")

    def test_offline_host_flipped_online_marks(self):
        r = ScanResult(ip="10.0.0.5", status="offline")
        _engine()._merge_mdns(
            {"10.0.0.5": r},
            {"10.0.0.5": {"names": set(), "services": set()}},
        )
        self.assertTrue(r.mdns_updated)
        self.assertEqual(r.status, "online")
        self.assertEqual(r.discovery_method, "mdns")

    def test_library_lookup_applied_only_to_new_devices(self):
        seen = []
        results = {"10.0.0.5": ScanResult(ip="10.0.0.5", status="offline")}
        _engine()._merge_mdns(
            results,
            {"10.0.0.5": {"names": set(), "services": set()},
             "10.0.0.9": {"names": set(), "services": set()}},
            library_lookup=lambda r: seen.append(r.ip),
        )
        self.assertEqual(
            seen, ["10.0.0.9"],
            "地址库匹配只应对 mDNS 新增设备调用（已有设备在扫描阶段已匹配过）",
        )

    def test_library_lookup_failure_does_not_break_merge(self):
        def boom(_r):
            raise RuntimeError("库炸了")

        results = {}
        n = _engine()._merge_mdns(
            results, {"10.0.0.9": {"names": set(), "services": set()}},
            library_lookup=boom,
        )
        self.assertEqual(n, 1)
        self.assertIn("10.0.0.9", results)

    def test_empty_map(self):
        r = ScanResult(ip="10.0.0.5")
        self.assertEqual(_engine()._merge_mdns({"10.0.0.5": r}, {}), 0)
        self.assertFalse(r.mdns_updated)

    def test_to_dict_does_not_leak_internal_flag(self):
        """mdns_updated 是 UI 内部提示，不该混进导出字段。"""
        keys = ScanResult(ip="10.0.0.5", mdns_updated=True).to_dict().keys()
        self.assertNotIn("mdns_updated", keys)


if __name__ == "__main__":
    unittest.main()
