# -*- coding: utf-8 -*-
"""被动发现（`scanner/passive.py`）测试。

覆盖点，按重要性排序：
1. **不发包** —— 这是「被动」二字的全部意义，也是路线图 §1.2 的验收条件。
   用假 socket 断言 `sendto` 一次都没被调用（并反向验证测试本身抓得住发包）。
2. 三种平台的 ARP 表格式都能解析（喂真实格式的样本，不看网络）。
3. 只报「新出现」，不报「消失」—— ARP 条目过期不等于设备下线。
4. 表为空 / 端口被占时**优雅降级并记日志**（不静默）。

断言一律与语言无关：只比 IP / MAC / 计数 / 日志，不比界面文案。
"""
import os
import shutil
import socket
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import history_store  # noqa: E402
from scanner import passive  # noqa: E402
from scanner.dns import mdns_discover  # noqa: E402


# ── 假 socket：记录有没有发包 ──────────────────────────────────────────

class _RecordingSocket:
    """替身 socket：只记录调用，不碰网络。

    `sendto` 被调用过 = 我们主动发了包 = 「被动」不成立。
    """

    instances = []

    def __init__(self, *args, **kwargs):
        self.sent = []
        self.closed = False
        self.bound = None
        _RecordingSocket.instances.append(self)

    def setsockopt(self, *args):
        pass

    def bind(self, addr):
        self.bound = addr

    def settimeout(self, _t):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, _n):
        # 立刻超时 → 收包循环空转到 timeout 结束
        raise socket.timeout()

    def close(self):
        self.closed = True


class _BindFailsSocket(_RecordingSocket):
    """5353 绑不上的情形（Windows 上系统 mDNS/Bonjour 常占着）。"""

    def bind(self, addr):
        raise OSError("address already in use")


class ArpParseTest(unittest.TestCase):
    """三种平台的 ARP 表格式。样本照抄真实输出，含各种"不是设备"的行。"""

    WIN = """\
接口: 192.168.1.5 --- 0xb
  Internet 地址         物理地址              类型
  192.168.1.1           50-2b-73-11-22-33     动态
  192.168.1.20          aa-bb-cc-dd-ee-ff     动态
  192.168.1.255         ff-ff-ff-ff-ff-ff     静态
  224.0.0.22            01-00-5e-00-00-16     静态
  192.168.1.99          00-00-00-00-00-00     无效
"""

    UNIX = """\
? (192.168.1.1) at 50:2b:73:11:22:33 [ether] on en0
? (192.168.1.20) at aa:bb:cc:dd:ee:ff [ether] on en0
? (192.168.1.30) at (incomplete) on en0
? (192.168.1.255) at ff:ff:ff:ff:ff:ff [ether] on en0
"""

    PROC = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         50:2b:73:11:22:33     *        eth0
192.168.1.20     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.30     0x1         0x0         00:00:00:00:00:00     *        eth0
"""

    def test_windows_format(self):
        table = passive.parse_windows_arp(self.WIN)
        # 广播 / 组播 / 全零都不是"一台设备"，必须滤掉
        self.assertEqual(table, {"192.168.1.1": "50:2b:73:11:22:33",
                                 "192.168.1.20": "aa:bb:cc:dd:ee:ff"})

    def test_unix_format_skips_incomplete(self):
        table = passive.parse_unix_arp(self.UNIX)
        self.assertEqual(table, {"192.168.1.1": "50:2b:73:11:22:33",
                                 "192.168.1.20": "aa:bb:cc:dd:ee:ff"})

    def test_proc_net_arp_skips_unresolved_flag(self):
        table = passive.parse_proc_net_arp(self.PROC)
        self.assertEqual(table, {"192.168.1.1": "50:2b:73:11:22:33",
                                 "192.168.1.20": "aa:bb:cc:dd:ee:ff"})

    def test_mac_is_normalised_to_colon_lowercase(self):
        """Windows 用连字符大写，统一成小写冒号 —— 否则同台设备会被当成两台。"""
        table = passive.parse_windows_arp(
            "  10.0.0.7   AA-BB-CC-DD-EE-FF   dynamic\n")
        self.assertEqual(table, {"10.0.0.7": "aa:bb:cc:dd:ee:ff"})

    def test_empty_input_is_empty_not_error(self):
        for fn in (passive.parse_windows_arp, passive.parse_unix_arp,
                   passive.parse_proc_net_arp):
            self.assertEqual(fn(""), {}, fn.__name__)

    def test_garbage_lines_are_ignored(self):
        junk = "这不是 ARP 表\n\nInterface: something\n? (not-an-ip) at xx\n"
        self.assertEqual(passive.parse_windows_arp(junk), {})
        self.assertEqual(passive.parse_unix_arp(junk), {})
        self.assertEqual(passive.parse_proc_net_arp(junk), {})


class ArpTableDegradationTest(unittest.TestCase):
    """`dump_arp_table()` 的平台分支与降级留痕。

    显式 patch `_IS_WINDOWS` 而不是依赖跑测试的机器 —— 否则 Windows 上
    永远只走 Windows 分支，Unix 那条路径（/proc 优先 + arp -an 兜底）
    在 CI 的 ubuntu/macOS 上才会被测到，本地看不出来。
    """

    PROC = ("IP address  HW type  Flags  HW address         Mask  Device\n"
            "10.0.0.9    0x1      0x2    aa:bb:cc:dd:ee:ff  *     eth0\n")
    UNIX_OUT = "? (10.0.0.9) at aa:bb:cc:dd:ee:ff [ether] on eth0\n"
    WIN_OUT = "  10.0.0.9            aa-bb-cc-dd-ee-ff     动态\n"
    EXPECTED = {"10.0.0.9": "aa:bb:cc:dd:ee:ff"}

    def test_windows_branch_uses_arp_command(self):
        with mock.patch.object(passive, "_IS_WINDOWS", True), \
                mock.patch.object(passive, "_run_cmd", return_value=self.WIN_OUT):
            self.assertEqual(passive.dump_arp_table(), self.EXPECTED)

    def test_unix_branch_prefers_proc(self):
        with mock.patch.object(passive, "_IS_WINDOWS", False), \
                mock.patch("builtins.open", mock.mock_open(read_data=self.PROC)):
            self.assertEqual(passive.dump_arp_table(), self.EXPECTED)

    def test_unix_branch_falls_back_to_arp_command(self):
        with mock.patch.object(passive, "_IS_WINDOWS", False), \
                mock.patch("builtins.open", side_effect=OSError("no /proc")), \
                mock.patch.object(passive, "_run_cmd", return_value=self.UNIX_OUT):
            self.assertEqual(passive.dump_arp_table(), self.EXPECTED)

    def test_empty_table_logs_warning(self):
        """读不到表必须留痕 —— 静默返回空会被当成"网络里没设备"。"""
        with mock.patch.object(passive, "_IS_WINDOWS", False), \
                mock.patch("builtins.open", side_effect=OSError("no /proc")), \
                mock.patch.object(passive, "_run_cmd", return_value=""):
            with self.assertLogs("ipscanner.passive", level="WARNING") as cm:
                table = passive.dump_arp_table()
        self.assertEqual(table, {})
        self.assertTrue(any("ARP 表为空" in m for m in cm.output), cm.output)

    def test_non_empty_table_does_not_warn(self):
        with mock.patch.object(passive, "_IS_WINDOWS", False), \
                mock.patch("builtins.open", side_effect=OSError("no /proc")), \
                mock.patch.object(passive, "_run_cmd", return_value=self.UNIX_OUT):
            self.assertEqual(passive.dump_arp_table(), self.EXPECTED)


class NoPacketsTest(unittest.TestCase):
    """**路线图 §1.2 的验收条件**：被动路径不发包。"""

    def setUp(self):
        _RecordingSocket.instances = []

    def test_listen_only_never_sends(self):
        with mock.patch("scanner.dns.socket.socket", _RecordingSocket):
            mdns_discover(timeout=0.05, listen_only=True)
        self.assertTrue(_RecordingSocket.instances, "socket 都没建，测试无效")
        for s in _RecordingSocket.instances:
            self.assertEqual(s.sent, [], "只听模式下发了包")

    def test_active_mode_does_send(self):
        """反向验证：主动模式下**确实**会发包 —— 否则上面的断言是空的。"""
        with mock.patch("scanner.dns.socket.socket", _RecordingSocket):
            mdns_discover(timeout=0.05, listen_only=False)
        total = sum(len(s.sent) for s in _RecordingSocket.instances)
        self.assertGreater(total, 0, "主动模式一个包都没发？那 listen_only 断言没有意义")

    def test_listen_only_without_5353_degrades_loudly(self):
        """只听模式必须占 5353；拿不到就返回空**并留痕**，不能装作"网络里没设备"。"""
        with mock.patch("scanner.dns.socket.socket", _BindFailsSocket):
            with self.assertLogs("ipscanner.dns", level="WARNING") as cm:
                result = mdns_discover(timeout=0.05, listen_only=True)
        self.assertEqual(result, {})
        self.assertTrue(any("5353" in m for m in cm.output), cm.output)

    def test_passive_discover_does_not_touch_probe_entrypoints(self):
        """被动发现不得调用任何主动探测入口（ping / arp_ping）。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}):
            with mock.patch("scanner.ping.ping_ip") as m_ping, \
                    mock.patch("scanner.ping.arp_ping") as m_arp:
                passive.passive_discover(mdns=False)
        m_ping.assert_not_called()
        m_arp.assert_not_called()


class PassiveDiscoverTest(unittest.TestCase):

    ARP = {"10.0.0.1": "aa:bb:cc:00:00:01",
           "10.0.0.2": "aa:bb:cc:00:00:02"}

    def test_arp_entries_become_online_devices(self):
        with mock.patch.object(passive, "dump_arp_table",
                               return_value=dict(self.ARP)):
            res = passive.passive_discover(mdns=False)
        self.assertEqual(set(res), set(self.ARP))
        for r in res.values():
            self.assertEqual(r.status, "online")
            self.assertEqual(r.discovery_method, "arp")

    def test_mdns_fills_hostname_of_existing_arp_entry(self):
        """mDNS 结果要能补到 ARP 已发现的那一行上，而不是变成两台设备。"""
        mdns_map = {"10.0.0.2": {"names": {"nas.local."}, "services": set()}}
        with mock.patch.object(passive, "dump_arp_table",
                               return_value=dict(self.ARP)):
            with mock.patch.object(passive, "mdns_discover",
                                   return_value=mdns_map):
                res = passive.passive_discover(mdns=True)
        self.assertEqual(len(res), 2)
        # 主机名后缀（`.local`）由 `_merge_mdns` 决定，这里只要求"补上了名字"
        self.assertTrue(res["10.0.0.2"].hostname.startswith("nas"),
                        res["10.0.0.2"].hostname)
        # 发现方式仍是 ARP（先到先得），mDNS 只补信息不抢身份
        self.assertEqual(res["10.0.0.2"].discovery_method, "arp")

    def test_mdns_only_device_is_added(self):
        mdns_map = {"10.0.0.9": {"names": {"printer.local."}, "services": set()}}
        with mock.patch.object(passive, "dump_arp_table", return_value={}):
            with mock.patch.object(passive, "mdns_discover",
                                   return_value=mdns_map):
                res = passive.passive_discover(mdns=True)
        self.assertIn("10.0.0.9", res)
        self.assertEqual(res["10.0.0.9"].discovery_method, "mdns")

    def test_mdns_failure_keeps_arp_results(self):
        """mDNS 出错不能连带丢掉**已经读到的 ARP 结果**（那才是主来源）。"""
        with mock.patch.object(passive, "dump_arp_table",
                               return_value=dict(self.ARP)):
            with mock.patch.object(passive, "mdns_discover",
                                   side_effect=OSError("no multicast route")):
                with self.assertLogs("ipscanner.passive", level="WARNING"):
                    res = passive.passive_discover(mdns=True)
        self.assertEqual(set(res), set(self.ARP))


class PassiveWatcherTest(unittest.TestCase):
    """只报「新出现」；台账跨轮累积；不报「消失」。"""

    def setUp(self):
        self._patch = mock.patch.object(
            passive, "dump_arp_table",
            return_value={"10.0.0.1": "aa:bb:cc:00:00:01",
                          "10.0.0.2": "aa:bb:cc:00:00:02"})
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_first_poll_reports_all_without_baseline(self):
        w = passive.PassiveWatcher()
        ledger, fresh = w.poll(mdns=False)
        self.assertEqual(len(ledger), 2)
        self.assertEqual({r.ip for r in fresh}, {"10.0.0.1", "10.0.0.2"})

    def test_baseline_suppresses_known_devices(self):
        w = passive.PassiveWatcher(known_ips={"10.0.0.1"})
        _ledger, fresh = w.poll(mdns=False)
        self.assertEqual({r.ip for r in fresh}, {"10.0.0.2"})

    def test_second_poll_reports_nothing_new(self):
        w = passive.PassiveWatcher()
        w.poll(mdns=False)
        _ledger, fresh = w.poll(mdns=False)
        self.assertEqual(fresh, [], "第二轮把已知设备又报成新的了")

    def test_ledger_keeps_devices_that_disappear(self):
        """设备从 ARP 表消失 ≠ 下线 —— 台账不该把它删掉（不报"消失"）。"""
        w = passive.PassiveWatcher()
        w.poll(mdns=False)
        with mock.patch.object(passive, "dump_arp_table",
                               return_value={"10.0.0.1": "aa:bb:cc:00:00:01"}):
            ledger, fresh = w.poll(mdns=False)
        self.assertEqual(fresh, [])
        self.assertEqual({r.ip for r in ledger}, {"10.0.0.1", "10.0.0.2"})


class LatestDeviceIpsTest(unittest.TestCase):
    """被动发现的基线来源。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "h.db")

    def tearDown(self):
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_db_gives_empty_set(self):
        self.assertEqual(history_store.latest_device_ips(db_path=self.db), set())

    def test_returns_ips_of_the_newest_snapshot_only(self):
        history_store.save_snapshot(
            [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}], db_path=self.db)
        history_store.save_snapshot([{"ip": "10.0.0.3"}], db_path=self.db)
        self.assertEqual(history_store.latest_device_ips(db_path=self.db),
                         {"10.0.0.3"})


if __name__ == "__main__":
    unittest.main()
