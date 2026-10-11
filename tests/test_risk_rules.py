# -*- coding: utf-8 -*-
"""风险评分与风险列（docs/reviews/UI_REVIEW.md P3-4）。

守四件事：

1. **算法**（`risk_rules.score_risk`）—— 纯函数，逐条规则 + 标定用例；
2. **刻度与阈值** —— 等级边界、封顶、理由带分值、垃圾输入不炸；
3. **文案** —— 每个等级 / 理由代码都有显示名，且随语言切换；
4. **接线** —— 列索引与 `COLUMN_LABELS` 一致、「安全」预设含风险列、真
   `MainWindow` 的单元格文本 / 颜色 / 切主题跟随。

标定用例是这份文件里最要紧的部分：风险列的价值**不在于"能报"，而在于
"不什么都报"**。一台普通 Windows 主机（135/139/445/3389）必须得 0 分，
否则这一列对局域网资产盘点毫无用处。
"""
import datetime
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication

import i18n
import main_window
import risk_rules
from scanner import ScanResult

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


def _result(ports=(), status="online"):
    return ScanResult(ip="10.0.0.1", status=status, open_ports=list(ports))


class _FakeConflict:
    """最小冲突替身：`score_risk` 只读 `.severity` 与 `.conflict_type`。"""

    def __init__(self, conflict_type, severity):
        self.conflict_type = conflict_type
        self.severity = severity


class ScoringTest(unittest.TestCase):

    def test_clean_host_scores_zero(self):
        """🔴 标定基线：普通 Windows 主机必须 0 分。"""
        risk = risk_rules.score_risk(_result([135, 139, 445, 3389]))
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_NONE)
        self.assertEqual(risk["reasons"], [])

    def test_telnet_is_the_heaviest_single_port(self):
        risk = risk_rules.score_risk(_result([23]))
        self.assertEqual(risk["score"], 30)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_MEDIUM)

    def test_http_only_counts_when_https_is_absent(self):
        plain = risk_rules.score_risk(_result([80]))
        secure = risk_rules.score_risk(_result([80, 443]))
        self.assertEqual(plain["score"], 10)
        self.assertEqual(secure["score"], 0,
                         "同机开了 HTTPS 还报「HTTP 明文」就是噪声")

    def test_scores_add_up_and_are_capped(self):
        risk = risk_rules.score_risk(_result([21, 23, 69, 161, 5900, 80]))
        self.assertEqual(risk["score"], risk_rules.RISK_MAX,
                         "多项叠加必须封顶到 RISK_MAX")

    def test_reasons_carry_points_and_sum_to_the_score(self):
        risk = risk_rules.score_risk(_result([23, 21]))
        self.assertEqual(sum(p for _, p in risk["reasons"]), risk["score"])
        self.assertEqual([code for code, _ in risk["reasons"]],
                         ["weak_protocols"],
                         "明文一族聚合成一条理由（v1.9 #3 第三刀）")
        self.assertEqual(risk["weak_protocols"],
                         ["cleartext_telnet", "cleartext_ftp"],
                         "明细按严重度保序，tooltip 才好读")

    def test_conflict_points_follow_the_detector_severity(self):
        """冲突分值直接取严重级别 —— 不另立一套判断，避免两处漂移。"""
        high = risk_rules.score_risk(
            _result(), [_FakeConflict("duplicate_mac", "high")])
        warn = risk_rules.score_risk(
            _result(), [_FakeConflict("unknown_device", "warning")])
        self.assertEqual(high["score"], 40)
        self.assertEqual(warn["score"], 20)
        self.assertEqual(high["reasons"][0][0], "duplicate_mac")

    def test_conflict_and_ports_combine(self):
        risk = risk_rules.score_risk(
            _result([23]), [_FakeConflict("duplicate_mac", "high")])
        self.assertEqual(risk["score"], 70)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_HIGH)

    def test_none_result_scores_zero(self):
        risk = risk_rules.score_risk(None)
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_NONE)

    def test_calibration_examples(self):
        """真实端口组合的等级必须符合直觉（否则这一列会变成噪声）。"""
        cases = [
            ("普通 Windows 主机", [135, 139, 445, 3389],
             risk_rules.RISK_LEVEL_NONE),
            ("打印机", [80, 161, 9100], risk_rules.RISK_LEVEL_LOW),
            ("群晖 NAS", [80, 445, 5000], risk_rules.RISK_LEVEL_LOW),
            ("路由器", [23, 80, 161], risk_rules.RISK_LEVEL_MEDIUM),
            ("网络摄像头", [23, 80, 554], risk_rules.RISK_LEVEL_MEDIUM),
        ]
        for name, ports, want in cases:
            with self.subTest(case=name):
                got = risk_rules.score_risk(_result(ports))["level"]
                self.assertEqual(got, want, "%s 的等级判错了" % name)


class WeakProtocolAggregationTest(unittest.TestCase):
    """明文 / 无认证服务聚合成**一条**结论（v1.9 #3 第三刀）。

    为什么值得单独一段：一台老路由器 (23/80/161) 原来会刷出三行近义理由
    （Telnet 明文管理 / SNMP v2c 团体字明文 / HTTP 明文管理面），说的是**同一件事**，
    却把 tooltip 撑成一面墙。聚合后是一条结论 + 一行明细。

    🔴 本段最要紧的标定：**总分一个字都没变**。下面这张表是文档顶部那张标定表
    的翻版 —— 聚合若顺手改了分数，等于把整列风险分的可信度推翻。
    """

    def tearDown(self):
        i18n.init("zh-CN")

    #: (标签, 端口, 期望总分, 期望明细)
    CALIBRATION = (
        ("普通 Windows 主机", (135, 139, 445, 3389), 0, []),
        ("打印机", (80, 161, 9100), 25,
         ["cleartext_snmp", "cleartext_http"]),
        ("路由器", (23, 80, 161), 55,
         ["cleartext_telnet", "cleartext_snmp", "cleartext_http"]),
        ("群晖 NAS", (80, 445, 5000), 10, ["cleartext_http"]),
        ("网络摄像头", (23, 80, 554), 40,
         ["cleartext_telnet", "cleartext_http"]),
    )

    def test_calibration_table_is_unchanged(self):
        """🔴 聚合不许动分数 —— 逐个复核文档里的标定值。"""
        for label, ports, want_score, want_detail in self.CALIBRATION:
            with self.subTest(label=label):
                risk = risk_rules.score_risk(_result(ports))
                self.assertEqual(risk["score"], want_score)
                self.assertEqual(risk["weak_protocols"], want_detail)

    def test_one_reason_per_host_not_per_port(self):
        """一台设备命中三个弱协议，`reasons` 里仍然只有**一条**。"""
        risk = risk_rules.score_risk(_result([23, 80, 161]))
        weak = [c for c, _ in risk["reasons"] if c == "weak_protocols"]
        self.assertEqual(len(weak), 1)
        self.assertEqual([c for c, _ in risk["reasons"]], ["weak_protocols"])

    def test_the_aggregate_carries_the_whole_subtotal(self):
        """那一条理由的分值 = 各端口之和（30+15+10），不是其中最大的那个。"""
        risk = risk_rules.score_risk(_result([23, 80, 161]))
        self.assertEqual(dict(risk["reasons"]), {"weak_protocols": 55})

    def test_detail_is_ordered_by_severity(self):
        """明细按 `_PORT_RULES` 的严重度降序（30/25/20/20/15，HTTP 10 最后）。"""
        risk = risk_rules.score_risk(_result([80, 21, 161, 23, 5900, 69]))
        self.assertEqual(risk["weak_protocols"], [
            "cleartext_telnet", "unauthenticated_vnc", "cleartext_ftp",
            "cleartext_tftp", "cleartext_snmp", "cleartext_http"])

    def test_http_only_rule_survives_the_aggregation(self):
        """同机开了 443 说明有加密替代 —— 这时候报「HTTP 明文」就是噪声。"""
        self.assertEqual(risk_rules.score_risk(_result([80]))["weak_protocols"],
                         ["cleartext_http"])
        self.assertEqual(risk_rules.score_risk(_result([80, 443]))["weak_protocols"],
                         [])
        self.assertEqual(risk_rules.score_risk(_result([80, 443]))["score"], 0)

    def test_unlisted_ports_do_not_count(self):
        """445/3389/135/139 是普通 Windows 主机的常态，不在弱协议族里。"""
        risk = risk_rules.score_risk(_result([135, 139, 445, 3389]))
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["weak_protocols"], [])

    def test_the_key_is_always_present(self):
        """形状稳定：没命中时是空列表，消费方不用判断键在不在。"""
        for ports in ((), [443], [23]):
            with self.subTest(ports=ports):
                risk = risk_rules.score_risk(_result(ports))
                self.assertIn("weak_protocols", risk)
                self.assertIsInstance(risk["weak_protocols"], list)

    def test_result_without_open_ports_is_tolerated(self):
        class _Bare:
            ip = "10.0.0.1"
            status = "online"

        risk = risk_rules.score_risk(_Bare())
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["weak_protocols"], [])

    def test_helper_is_a_pure_function(self):
        """`weak_protocol_reasons()` 可单独用（与 `tls_reasons()` 同一待遇）。"""
        self.assertEqual(risk_rules.weak_protocol_reasons([23, 21]), (50, [
            "cleartext_telnet", "cleartext_ftp"]))
        self.assertEqual(risk_rules.weak_protocol_reasons([]), (0, []))
        for bad in (None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(risk_rules.weak_protocol_reasons(bad), (0, []))

    def test_helper_does_not_mutate_its_input(self):
        ports = [23, 21]
        risk_rules.weak_protocol_reasons(ports)
        self.assertEqual(ports, [23, 21])

    # ── tooltip ──

    def test_tooltip_gives_one_conclusion_plus_a_detail_line(self):
        """这正是本刀的目的：路由器从 3 行理由变成 1 行结论 + 1 行明细。"""
        i18n.init("zh-CN")
        risk = risk_rules.score_risk(_result([23, 80, 161]))
        tip = risk_rules.format_risk_tooltip(risk)
        lines = tip.split("\n")
        # 第 0 行是"风险评分 N/100"，之后只有一条 "· " 理由 + 一行缩进明细
        bullets = [ln for ln in lines if ln.startswith("· ")]
        self.assertEqual(len(bullets), 1, tip)
        self.assertIn(risk_rules.reason_label("weak_protocols"), bullets[0])
        self.assertIn("+55", bullets[0])
        detail = [ln for ln in lines if ln.startswith("    ")]
        self.assertEqual(len(detail), 1, tip)
        for code in risk["weak_protocols"]:
            self.assertIn(risk_rules.reason_label(code), detail[0])

    def test_tooltip_detail_uses_the_same_labels_as_before(self):
        """明细里的每个服务名仍然走 `_REASON_TEXT` —— 词条没被聚合删掉。"""
        i18n.init("zh-CN")
        for code in ("cleartext_telnet", "unauthenticated_vnc",
                     "cleartext_ftp", "cleartext_tftp", "cleartext_snmp",
                     "cleartext_http"):
            with self.subTest(code=code):
                self.assertTrue(risk_rules._REASON_TEXT.get(code))

    def test_tooltip_explains_the_cap(self):
        """🔴 各项之和 > 上限时，tooltip 必须说明白 —— 否则"100/100"底下
        加起来 120，用户会以为算错了。"""
        i18n.init("zh-CN")
        risk = risk_rules.score_risk(_result([21, 23, 69, 161, 5900, 80]))
        self.assertEqual(risk["score"], risk_rules.RISK_MAX)
        raw = sum(p for _, p in risk["reasons"])
        self.assertGreater(raw, risk["score"], "这条用例要靠封顶才成立")
        tip = risk_rules.format_risk_tooltip(risk)
        self.assertIn(
            risk_rules.tr("已达评分上限（各项合计 {n}）").format(n=raw), tip)

    def test_tooltip_has_no_cap_line_when_not_capped(self):
        i18n.init("zh-CN")
        risk = risk_rules.score_risk(_result([23, 21]))
        tip = risk_rules.format_risk_tooltip(risk)
        self.assertNotIn(risk_rules.tr("已达评分上限（各项合计 {n}）").format(n=50),
                         tip)

    def test_tooltip_for_a_clean_host_is_the_plain_message(self):
        i18n.init("zh-CN")
        risk = risk_rules.score_risk(_result([135, 139, 445, 3389]))
        self.assertEqual(risk_rules.format_risk_tooltip(risk),
                         risk_rules.tr("未发现明显的服务暴露风险"))

    def test_cell_text_is_unchanged(self):
        """单元格文案只跟分数/等级有关，聚合不该影响它。"""
        i18n.init("zh-CN")
        risk = risk_rules.score_risk(_result([23, 80, 161]))
        self.assertEqual(risk_rules.format_risk(risk), "中 55")


class TlsReasonTest(unittest.TestCase):
    """TLS 证书事实 → 风险理由（v1.9 #3 零利用安全体检）。

    这一段是那一刀里唯一会产生**用户可见结论**的部分，所以标定用例比覆盖用例
    更要紧：局域网设备管理面几乎人手一张自签名证书，若"自签名"给高分，整列
    风险分就塌成一个数 —— 那正是 `risk_rules` 反复提醒要避免的噪声。

    事实来源是 `ScanResult.tls_cert`（`scanner/x509.parse_certificate` 的产物），
    **不是新开的探测**：证书来自扫描时本就要做的那次 HTTPS 握手，没有多发包。
    """

    NOW = datetime.datetime(2026, 10, 11, 12, 0, 0)

    def _days(self, n):
        return (self.NOW + datetime.timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%S")

    def _cert(self, **kw):
        base = {"not_after": self._days(365), "sig_alg": "sha256_rsa",
                "key_alg": "rsa", "key_bits": 2048}
        base.update(kw)
        return base

    def test_no_certificate_means_no_reasons(self):
        for bad in ({}, None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(risk_rules.tls_reasons(bad, now=self.NOW), [])

    def test_healthy_certificate_scores_nothing(self):
        """🔴 标定基线：一张正常证书不能贡献任何分数。"""
        self.assertEqual(risk_rules.tls_reasons(self._cert(), now=self.NOW), [])

    def test_expired(self):
        got = dict(risk_rules.tls_reasons(self._cert(not_after=self._days(-1)),
                                          now=self.NOW))
        self.assertEqual(got, {"tls_expired": 40})

    def test_expiring_soon_boundary(self):
        """阈值边界：30 天内算"即将过期"，31 天不算 —— 差一天也要分清。"""
        for days, want in ((0, {"tls_expiring_soon": 15}),
                           (29, {"tls_expiring_soon": 15}),
                           (30, {"tls_expiring_soon": 15}),
                           (31, {})):
            with self.subTest(days=days):
                got = dict(risk_rules.tls_reasons(
                    self._cert(not_after=self._days(days)), now=self.NOW))
                self.assertEqual(got, want)

    def test_expiring_and_expired_do_not_stack(self):
        """过期就是过期，不再额外叠一条"即将过期"。"""
        codes = [c for c, _ in risk_rules.tls_reasons(
            self._cert(not_after=self._days(-5)), now=self.NOW)]
        self.assertEqual(codes, ["tls_expired"])

    def test_self_signed_is_only_five_points(self):
        """🔴 自签名只值 5 分 —— 几乎每台局域网设备都是自签，给高了整列就废了。"""
        got = dict(risk_rules.tls_reasons(self._cert(self_signed=True),
                                          now=self.NOW))
        self.assertEqual(got, {"tls_self_signed": 5})

    def test_weak_signature(self):
        for alg in ("md5_rsa", "sha1_rsa", "sha1_ecdsa"):
            with self.subTest(alg=alg):
                got = dict(risk_rules.tls_reasons(
                    self._cert(sig_alg=alg), now=self.NOW))
                self.assertEqual(got, {"tls_weak_signature": 25})

    def test_weak_key(self):
        for alg, bits in (("rsa", 1024), ("rsa", 512), ("ec", 192),
                          ("dsa", 1024)):
            with self.subTest(alg=alg, bits=bits):
                got = dict(risk_rules.tls_reasons(
                    self._cert(key_alg=alg, key_bits=bits), now=self.NOW))
                self.assertEqual(got, {"tls_weak_key": 20})

    def test_unknown_algorithms_stay_silent(self):
        """不认识的算法不下结论（宁可漏报不可误报）。"""
        cert = self._cert(sig_alg="2.9.9.9", key_alg="weird", key_bits=512)
        self.assertEqual(risk_rules.tls_reasons(cert, now=self.NOW), [])

    def test_missing_key_bits_stay_silent(self):
        """位数读不到（0）时不能报"密钥过短" —— 否则每台取不到模数的都误报。"""
        cert = self._cert(key_alg="rsa", key_bits=0)
        self.assertEqual(risk_rules.tls_reasons(cert, now=self.NOW), [])

    def test_unparseable_date_is_silent(self):
        """日期解析不出来时不猜 —— 不能因为"读不到"就说"过期了"。"""
        for bad in ("", "not a date", "2027/10/11", "2027-10-11"):
            with self.subTest(bad=bad):
                cert = self._cert(not_after=bad)
                self.assertEqual(risk_rules.tls_reasons(cert, now=self.NOW), [])

    def test_reasons_are_ordered_by_severity(self):
        """最要紧的理由永远排在最上面 —— tooltip 只给头几行也够用。"""
        cert = self._cert(not_after=self._days(-1), self_signed=True,
                          sig_alg="sha1_rsa", key_alg="rsa", key_bits=1024)
        codes = [c for c, _ in risk_rules.tls_reasons(cert, now=self.NOW)]
        self.assertEqual(codes, ["tls_expired", "tls_weak_signature",
                                 "tls_weak_key", "tls_self_signed"])

    def test_points_match_the_declared_table(self):
        """分值只有一处定义（`_TLS_POINTS`），别在别处又写一份。"""
        self.assertEqual(dict(risk_rules._TLS_POINTS), {
            "tls_expired": 40, "tls_expiring_soon": 15, "tls_self_signed": 5,
            "tls_weak_signature": 25, "tls_weak_key": 20,
        })
        self.assertEqual(risk_rules.TLS_EXPIRING_DAYS, 30)

    def test_score_risk_picks_up_the_certificate(self):
        """接线：证书事实必须真的进总分。"""
        r = _result([443])
        self.assertEqual(risk_rules.score_risk(r)["score"], 0)
        r.tls_cert = self._cert(not_after=self._days(-1))
        risk = risk_rules.score_risk(r, now=self.NOW)
        self.assertEqual(risk["score"], 40)
        self.assertEqual([c for c, _ in risk["reasons"]], ["tls_expired"])

    def test_score_risk_combines_ports_and_tls(self):
        r = _result([23, 443])
        r.tls_cert = self._cert(self_signed=True)
        risk = risk_rules.score_risk(r, now=self.NOW)
        self.assertEqual(risk["score"], 35)          # Telnet 30 + 自签名 5
        self.assertEqual([c for c, _ in risk["reasons"]],
                         ["weak_protocols", "tls_self_signed"])

    def test_score_risk_tolerates_objects_without_the_attribute(self):
        """历史库里读回来的对象没有这个属性 —— `getattr` 兜底不能炸。"""
        class _Bare:
            ip = "10.0.0.1"
            status = "online"
            open_ports = [443]

        self.assertEqual(risk_rules.score_risk(_Bare(), now=self.NOW)["score"], 0)

    def test_clean_host_with_a_good_certificate_still_scores_zero(self):
        """🔴 标定基线（带证书版）：普通主机 + 一张好证书仍然 0 分。"""
        r = _result([135, 139, 445, 3389, 443])
        r.tls_cert = self._cert()
        self.assertEqual(risk_rules.score_risk(r, now=self.NOW)["score"], 0)


class ResponderReasonTest(unittest.TestCase):
    """名字响应器事实 → 风险理由（v1.9 #3 第二刀）。

    与 TLS 那一段的关键差别：**这个探测会往网络里发包**（见
    `scanner/llmnr_nbns.py` 的红线），所以由显式开关控制、默认关。
    评分侧只负责把事实翻成结论。

    标定思路：这个发现本身是**歧义的** —— 应答不存在名字的既可能是欺骗响应器
    （攻击），也可能是安全扫描工具 / 蜜罐（防护）。所以 30 分表示"值得看一眼"，
    而不是替用户断定对方恶意。
    """

    #: 固定"今天"，与 `TlsReasonTest` 一致（`score_risk(now=...)` 需要）。
    NOW = datetime.datetime(2026, 10, 11, 12, 0, 0)

    def test_no_responder_means_no_reasons(self):
        for bad in ({}, None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(risk_rules.responder_reasons(bad), [])

    def test_a_responder_scores_thirty(self):
        got = dict(risk_rules.responder_reasons({"llmnr": "ipscanner-a1b2c"}))
        self.assertEqual(got, {"name_responder": 30})

    def test_both_protocols_are_one_conclusion(self):
        """🔴 标定：两个协议都给肯定应答是**同一个发现**，只算一次分。

        拆成两条会让风险栏里出现两条近义理由、分数还翻倍。协议明细留在
        事实层（`history_store.responder_facts` 的 llmnr/nbns 两行）。
        """
        one = risk_rules.responder_reasons({"llmnr": "x"})
        both = risk_rules.responder_reasons({"llmnr": "x", "nbns": "x"})
        self.assertEqual(one, both)
        self.assertEqual(len(both), 1)

    def test_score_risk_picks_up_the_responder(self):
        """接线：响应器事实必须真的进总分。"""
        r = _result([])
        self.assertEqual(risk_rules.score_risk(r)["score"], 0)
        r.name_responder = {"llmnr": "ipscanner-a1b2c"}
        risk = risk_rules.score_risk(r)
        self.assertEqual(risk["score"], 30)
        self.assertEqual([c for c, _ in risk["reasons"]], ["name_responder"])
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_MEDIUM)

    def test_score_risk_combines_ports_tls_and_responder(self):
        r = _result([23])
        r.name_responder = {"nbns": "ipscanner-a1b2c"}
        risk = risk_rules.score_risk(r)
        self.assertEqual(risk["score"], 60)          # Telnet 30 + 响应器 30
        self.assertEqual([c for c, _ in risk["reasons"]],
                         ["weak_protocols", "name_responder"])

    def test_responder_reason_comes_after_tls(self):
        """顺序契约：端口 → TLS → 响应器 → 冲突（见 `score_risk` 文档）。"""
        r = _result([23])
        r.tls_cert = {"not_after": "2020-01-01T00:00:00"}
        r.name_responder = {"llmnr": "x"}
        codes = [c for c, _ in risk_rules.score_risk(r, now=self.NOW)["reasons"]]
        self.assertEqual(codes, ["weak_protocols", "tls_expired",
                                 "name_responder"])

    def test_points_match_the_declared_constant(self):
        """分值只有一处定义，别在别处又写一份。"""
        self.assertEqual(risk_rules._NAME_RESPONDER_POINTS, 30)
        self.assertEqual(risk_rules._REASON_NAME_RESPONDER, "name_responder")

    def test_score_risk_tolerates_objects_without_the_attribute(self):
        """历史库里读回来的对象没有这个属性 —— `getattr` 兜底不能炸。"""
        class _Bare:
            ip = "10.0.0.1"
            status = "online"
            open_ports = []

        self.assertEqual(risk_rules.score_risk(_Bare())["score"], 0)

    def test_a_clean_host_still_scores_zero(self):
        """🔴 标定基线：普通主机（没勾这个名字响应器探测）仍然是 0 分。"""
        r = _result([135, 139, 445, 3389, 443])
        self.assertEqual(risk_rules.score_risk(r, now=self.NOW)["score"], 0)


class SmbReasonTest(unittest.TestCase):
    """SMB 方言 / 签名事实 → 风险理由（v1.9 #3 第四刀）。

    两条判定的标定（详见 `risk_rules._SMB_POINTS` 的注释）：

    - **SMB1 可用 45 分**，全表最高。SMB1 有已被武器化的远程代码执行漏洞
      （EternalBlue / WannaCry），且**不需要任何凭据** —— 这是零利用体检里
      唯一能直接通向"整台机器被打穿"的发现。
    - **签名未强制 25 分**，与 VNC / TLS 弱签名同级。签名没强制时 NTLM 认证
      可被**中继**，是勒索软件横向扩散的常见手法；但它要求攻击者已在网内。

    两条**分开算**，不聚合 —— 对策完全不同（停用 SMB1 vs 强制签名），
    而且彼此独立（现代 NAS 常见"SMB1 已关但签名没强制"）。
    """

    #: 固定"今天"，与 `TlsReasonTest` 一致（`score_risk(now=...)` 需要）。
    NOW = datetime.datetime(2026, 10, 11, 12, 0, 0)

    def test_no_smb_facts_means_no_reasons(self):
        for bad in ({}, None, 0, ""):
            with self.subTest(bad=bad):
                self.assertEqual(risk_rules.smb_reasons(bad), [])

    def test_a_modern_host_with_required_signing_scores_nothing(self):
        """🔴 标定基线：实测的 Windows 10（3.1.1 + 签名强制）**不该有分**。

        这条同时守住上面那张标定表里的"普通 Windows 主机 -> 0" ——
        445 开着但签名是强制的，依然不该报。
        """
        self.assertEqual(risk_rules.smb_reasons(
            {"dialect": "3.1.1", "signing": "required"}), [])

    def test_smb1_available_scores_forty_five(self):
        got = dict(risk_rules.smb_reasons({"dialect": "3.1.1", "smb1": "1"}))
        self.assertEqual(got, {"smb1_available": 45})

    def test_smb1_only_server_also_scores(self):
        """只认 SMB1 的设备（`dialect == "1"`）同样命中。"""
        got = dict(risk_rules.smb_reasons({"dialect": "1", "smb1": "1"}))
        self.assertEqual(got, {"smb1_available": 45})

    def test_signing_enabled_but_not_required_is_the_finding(self):
        """🔴 标定核心：**"启用但未强制"就是那个发现**。

        服务器启用了签名但不强制时，客户端照样可以谈成不签名 —— 中继照样成立。
        所以判定只按"是否强制"，`enabled` 与 `off` 都算。
        """
        for mode in ("enabled", "off"):
            with self.subTest(mode=mode):
                got = dict(risk_rules.smb_reasons({"signing": mode}))
                self.assertEqual(got, {"smb_signing_not_required": 25})

    def test_signing_case_and_whitespace_are_normalised(self):
        got = risk_rules.smb_reasons({"signing": "  REQUIRED  "})
        self.assertEqual(got, [])

    def test_missing_signing_fact_gives_no_conclusion(self):
        """⚠ `signing` 缺失是"问不出来"，**不是**"没强制" —— 不能猜。"""
        self.assertEqual(risk_rules.smb_reasons({"dialect": "2.1"}), [])
        self.assertEqual(risk_rules.smb_reasons({"dialect": "2.1",
                                                 "signing": ""}), [])

    def test_the_two_findings_are_separate_not_aggregated(self):
        """两条各有独立对策，所以是两条理由、分值相加（45 + 25）。"""
        got = dict(risk_rules.smb_reasons({"dialect": "3.1.1", "signing": "off",
                                           "smb1": "1"}))
        self.assertEqual(got, {"smb1_available": 45,
                               "smb_signing_not_required": 25})

    def test_dialect_alone_is_never_scored(self):
        """⚠ 不按方言"新旧"打分：给 2.1 / 3.0 定阈值是凭空的。"""
        for dialect in ("1", "2.0.2", "2.1", "3.0", "3.0.2", "3.1.1", "0x02ff"):
            with self.subTest(dialect=dialect):
                self.assertEqual(risk_rules.smb_reasons({"dialect": dialect}), [])

    def test_score_risk_picks_up_smb(self):
        """接线：SMB 事实必须真的进总分。"""
        r = _result([])
        self.assertEqual(risk_rules.score_risk(r)["score"], 0)
        r.smb = {"dialect": "1", "smb1": "1"}
        risk = risk_rules.score_risk(r)
        self.assertEqual(risk["score"], 45)
        self.assertEqual([c for c, _ in risk["reasons"]], ["smb1_available"])
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_MEDIUM)

    def test_score_risk_combines_ports_tls_responder_and_smb(self):
        r = _result([23])                                  # Telnet 30
        r.tls_cert = {"not_after": "2020-01-01T00:00:00"}  # 过期 40
        r.name_responder = {"llmnr": "x"}                  # 30
        r.smb = {"dialect": "3.1.1", "signing": "enabled", "smb1": "1"}  # 70
        risk = risk_rules.score_risk(r, now=self.NOW)
        self.assertEqual(risk["score"], 100)               # 170 封顶到 100
        self.assertEqual([c for c, _ in risk["reasons"]],
                         ["weak_protocols", "tls_expired", "name_responder",
                          "smb1_available", "smb_signing_not_required"])

    def test_smb_reason_comes_after_responder_and_before_conflicts(self):
        """顺序契约：端口 → TLS → 响应器 → SMB → 冲突（见 `score_risk` 文档）。"""
        r = _result([23])
        r.name_responder = {"llmnr": "x"}
        r.smb = {"dialect": "1", "smb1": "1"}
        risk = risk_rules.score_risk(
            r, conflicts=[_FakeConflict("duplicate_mac", "high")],
            now=self.NOW)
        codes = [c for c, _ in risk["reasons"]]
        self.assertEqual(codes, ["weak_protocols", "name_responder",
                                 "smb1_available", "duplicate_mac"])

    def test_points_match_the_declared_constant(self):
        """分值只有一处定义，别在别处又写一份。"""
        self.assertEqual(risk_rules._SMB_POINTS, {
            risk_rules._REASON_SMB1: 45,
            risk_rules._REASON_SMB_SIGNING: 25,
        })
        self.assertEqual(risk_rules._REASON_SMB1, "smb1_available")
        self.assertEqual(risk_rules._REASON_SMB_SIGNING,
                         "smb_signing_not_required")

    def test_smb1_outranks_every_other_single_reason(self):
        """标定断言：SMB1 是单条最高分 —— 它确实是这里最危险的一条。"""
        others = [p for _c, p in risk_rules._TLS_POINTS]
        others += [p for _c, _port, p in risk_rules._PORT_RULES]
        others += [risk_rules._HTTP_ONLY_POINTS,
                   risk_rules._NAME_RESPONDER_POINTS]
        self.assertGreater(risk_rules._SMB_POINTS[risk_rules._REASON_SMB1],
                           max(others))

    def test_score_risk_tolerates_objects_without_the_attribute(self):
        """历史库里读回来的对象没有这个属性 —— `getattr` 兜底不能炸。"""
        class _Bare:
            ip = "10.0.0.1"
            status = "online"
            open_ports = []

        self.assertEqual(risk_rules.score_risk(_Bare())["score"], 0)

    def test_a_clean_host_still_scores_zero(self):
        """🔴 标定基线：普通主机（445 开着但签名强制）仍然是 0 分。"""
        r = _result([135, 139, 445, 3389, 443])
        r.smb = {"dialect": "3.1.1", "signing": "required"}
        self.assertEqual(risk_rules.score_risk(r, now=self.NOW)["score"], 0)


class LevelThresholdTest(unittest.TestCase):

    def test_boundaries(self):
        cases = [(0, "none"), (1, "low"), (29, "low"), (30, "medium"),
                 (59, "medium"), (60, "high"), (100, "high")]
        for score, want in cases:
            with self.subTest(score=score):
                self.assertEqual(risk_rules.risk_level(score), want)

    def test_thresholds_are_descending(self):
        """`risk_level()` 顺序命中即返回，阈值不降序会命中错的一档。"""
        scores = [t for t, _ in risk_rules.RISK_THRESHOLDS]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_garbage_scores_zero(self):
        for value in (None, "", "abc", -5):
            with self.subTest(value=value):
                self.assertEqual(risk_rules.risk_level(value),
                                 risk_rules.RISK_LEVEL_NONE)


class LabelTest(unittest.TestCase):

    def tearDown(self):
        i18n.init("zh-CN")

    def test_level_labels_follow_language(self):
        i18n.init("zh-CN")
        zh = risk_rules.risk_level_label(risk_rules.RISK_LEVEL_HIGH)
        i18n.init("en-US")
        en = risk_rules.risk_level_label(risk_rules.RISK_LEVEL_HIGH)
        i18n.init("zh-CN")
        self.assertEqual(zh, "高")
        self.assertEqual(en, "High")

    def test_every_level_has_a_token_and_a_label(self):
        for level in (risk_rules.RISK_LEVEL_NONE, risk_rules.RISK_LEVEL_LOW,
                      risk_rules.RISK_LEVEL_MEDIUM, risk_rules.RISK_LEVEL_HIGH):
            with self.subTest(level=level):
                self.assertIn(level, risk_rules.RISK_LEVEL_TOKEN)
                self.assertTrue(risk_rules._RISK_LEVEL_TEXT.get(level),
                                "%s 没有显示名" % level)

    def test_every_reason_code_has_a_label(self):
        codes = {code for code, _, _ in risk_rules._PORT_RULES}
        codes.add(risk_rules._REASON_CLEARTEXT_HTTP)
        codes.update({"duplicate_mac", "duplicate_hostname", "unknown_device"})
        codes.update(code for code, _ in risk_rules._TLS_POINTS)
        codes.add(risk_rules._REASON_NAME_RESPONDER)
        codes.add(risk_rules._REASON_WEAK_PROTOCOLS)
        codes.update(risk_rules._SMB_POINTS)
        for code in codes:
            with self.subTest(code=code):
                self.assertTrue(
                    risk_rules._REASON_TEXT.get(code),
                    "%s 没有显示名 —— tooltip 会把裸代码露给用户" % code)

    def test_unknown_codes_pass_through(self):
        self.assertEqual(risk_rules.reason_label("nope"), "nope")
        self.assertEqual(risk_rules.risk_level_label("nope"), "nope")


class FormatTest(unittest.TestCase):

    def tearDown(self):
        i18n.init("zh-CN")

    def test_none_level_renders_a_dash(self):
        i18n.init("zh-CN")
        self.assertEqual(
            risk_rules.format_risk(
                {"score": 0, "level": risk_rules.RISK_LEVEL_NONE, "reasons": []}),
            "—")

    def test_medium_level_renders_label_and_score(self):
        i18n.init("zh-CN")
        self.assertEqual(
            risk_rules.format_risk(
                {"score": 55, "level": risk_rules.RISK_LEVEL_MEDIUM,
                 "reasons": []}),
            "中 55")

    def test_tooltip_splits_the_score(self):
        """tooltip 要能看出"这 50 分是哪来的"。

        明文一族聚合后，具体服务名（Telnet / FTP）出现在**明细子行**里而不是
        各占一条理由 —— 这条断言因此同时守着"聚合没把服务名弄丢"。
        """
        i18n.init("zh-CN")
        tip = risk_rules.format_risk_tooltip(risk_rules.score_risk(_result([23, 21])))
        self.assertIn("50", tip)
        self.assertIn("Telnet", tip)
        self.assertIn("FTP", tip)

    def test_tooltip_for_a_clean_host(self):
        i18n.init("zh-CN")
        tip = risk_rules.format_risk_tooltip(risk_rules.score_risk(_result([])))
        self.assertTrue(tip.strip(), "零分也要给一句解释，不能是空 tooltip")


class ColumnWiringTest(unittest.TestCase):
    """列索引 / 预设的接线（漂移了这列就会错位到别的列上）。"""

    def test_column_index_matches_the_label_table(self):
        self.assertEqual(main_window.COLUMN_LABELS[risk_rules.RISK_COLUMN],
                         "风险",
                         "RISK_COLUMN 与 COLUMN_LABELS 不同步了")

    def test_security_preset_includes_the_risk_column(self):
        presets = {key: cols for key, _, cols in main_window.COLUMN_PRESETS}
        self.assertIn(risk_rules.RISK_COLUMN, presets["security"],
                      "「安全」预设缺了风险列 —— 恰恰缺了那句结论")

    def test_every_preset_index_is_a_real_column(self):
        for key, _, cols in main_window.COLUMN_PRESETS:
            for col in cols:
                self.assertTrue(0 <= col < len(main_window.COLUMN_LABELS),
                                "%s 预设含不存在的列 %d" % (key, col))

    def test_all_preset_covers_every_column(self):
        all_cols = {key: cols for key, _, cols in main_window.COLUMN_PRESETS}["all"]
        self.assertEqual(sorted(all_cols),
                         list(range(len(main_window.COLUMN_LABELS))))

    def test_every_column_has_a_default_width(self):
        for col in range(len(main_window.COLUMN_LABELS)):
            with self.subTest(col=col):
                self.assertIn(col, main_window._BASE_COLUMN_WIDTHS,
                              "第 %d 列没有默认宽度" % col)


class RiskCellTest(unittest.TestCase):
    """真 `MainWindow`：单元格文本、颜色、切主题跟随。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_risk_")
        self._orig = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig
        i18n.init("zh-CN")

    def _add(self, ip, ports):
        self.mw._upsert_table_row(
            ScanResult(ip=ip, status="online", open_ports=list(ports)))
        return self.mw._ip_item_map[ip]

    def test_clean_host_shows_a_dash(self):
        item = self._add("10.0.0.1", [445])
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "—")

    def test_risky_host_shows_level_and_score(self):
        item = self._add("10.0.0.2", [23, 21])
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "中 50")

    def test_cell_is_coloured_by_level(self):
        clean = self._add("10.0.0.3", [445])
        risky = self._add("10.0.0.4", [23, 21, 5900])
        self.assertNotEqual(
            clean.foreground(risk_rules.RISK_COLUMN).color().name(),
            risky.foreground(risk_rules.RISK_COLUMN).color().name(),
            "风险等级不同却同色")

    def test_tooltip_explains_the_score(self):
        item = self._add("10.0.0.7", [23])
        self.assertIn("Telnet", item.toolTip(risk_rules.RISK_COLUMN))

    def test_conflict_raises_the_score(self):
        """冲突一变，风险列必须跟着变 —— 两处不同源就会出现自相矛盾的行。"""
        from conflict_detector import SEVERITY_HIGH, Conflict
        item = self._add("10.0.0.5", [])
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "—")
        self.mw._conflicts = [
            Conflict("duplicate_mac", SEVERITY_HIGH, "x", ips=["10.0.0.5"])]
        self.mw._conflict_ips = {"10.0.0.5": ["duplicate_mac"]}
        self.mw._apply_row_marks(item, "10.0.0.5")
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "中 40")

    def test_cell_colour_follows_the_theme(self):
        item = self._add("10.0.0.6", [23, 21])
        self.mw.dark_mode = False
        self.mw._refresh_theme_marks()
        light = item.foreground(risk_rules.RISK_COLUMN).color().name()
        self.mw.dark_mode = True
        self.mw._refresh_theme_marks()
        dark = item.foreground(risk_rules.RISK_COLUMN).color().name()
        self.assertNotEqual(light, dark, "风险列的颜色没有跟随主题")

    def test_cell_is_centred_like_the_other_short_columns(self):
        """短内容列（状态 / 响应时间 / 风险）一律居中 —— 与左对齐的长文本列区分开。"""
        item = self._add("10.0.0.8", [23])
        align = int(item.textAlignment(risk_rules.RISK_COLUMN))
        self.assertTrue(align & int(Qt.AlignHCenter),
                        "风险列没有水平居中（与状态、响应时间列不一致）")
        self.assertTrue(align & int(Qt.AlignVCenter),
                        "风险列没有垂直居中")


if __name__ == "__main__":
    unittest.main()
