# -*- coding: utf-8 -*-
"""CVE 快照状态露出（v2.1 §2.3 的 GUI 侧）：状态栏徽标 + 详情对话框。

为什么单独一个 Mixin
------------------
§2.3 落地时只铺了 CLI（`ipscanner cve --status` / `--product`）。但离线
CVE 数据有四个「用户必须在 GUI 里知道」的状态事实：

1. 数据**在不在**（`missing` / `empty` / `corrupt`）—— 不在的时候，
   扫描结论里的「无匹配」不是"查了、没有"，而是"根本没查"；
2. 数据**新不新**（`ok` / `stale` / `unknown-age`）—— 旧数据能查，但
   结论只覆盖到生成日；
3. 数据**从哪来**（内置种子 / 数据目录里的用户更新版）；
4. 不对的时候下一步**干什么**（重新生成 / 把文件放进数据目录）。

把这四件事压成状态栏一个小徽标 + 一个详情对话框：徽标只显示最需要担心的
那一层（状态栏塞不下更多），详情对话框给全量。徽标配色走
`theme_tokens` 语义色（ok=绿 / 旧或未知=琥珀 / 坏了=红），这样色盲之外
的用户也能从位置+文案读到状态，颜色只是加强。

本 Mixin **只读不改**：`load_snapshot()` 是纯读取，界面里没有任何
「点一下就下载」的按钮 —— 在线更新不在 v2.1 验收内，占位 URL 也还没有
真值（见 docs/CVE_SNAPSHOT_MODEL.md §9.4）。用户更新数据的路径就是
把新的 `cve_snapshot.json` 放进 `data_dir()`，然后重启（徽标在启动时刷新）。
"""
from app_logging import get_logger
from app_paths import data_dir
from i18n import tr
from scanner import cve_snapshot as _snap
from theme_tokens import token
from ui_msg import msg_info

_log = get_logger(__name__)

#: 快照状态规范值 → 状态栏徽标短文案（canonical → 显示）。
#: 🔴 字面量表 AST 收集不到 → 必须在 tests/test_i18n_lazy.py::_label_tables() 登记。
_CVE_BADGE_TEXT = {
    _snap.STATE_OK: "CVE 数据: 就绪 · {n} 条",
    _snap.STATE_STALE: "CVE 数据: 已过期 · {n} 条",
    _snap.STATE_UNKNOWN_AGE: "CVE 数据: 新鲜度未知",
    _snap.STATE_EMPTY: "CVE 数据: 无条目",
    _snap.STATE_MISSING: "CVE 数据: 未安装",
    _snap.STATE_CORRUPT: "CVE 数据: 读取失败",
}

#: 快照状态规范值 → 徽标 tooltip / 详情对话框里的「下一步」。
#: 同样必须在 test_i18n_lazy 的 `_label_tables()` 登记。
_CVE_HINT_TEXT = {
    _snap.STATE_OK: "数据 {age} 天前生成，在 {max} 天有效期内。共 {n} 条"
                    "（KEV {kev} 条 · EPSS 已评分 {epss} 条）。",
    _snap.STATE_STALE: "数据 {age} 天前生成，已超过 {max} 天有效期：仍可用于"
                       "比对，但只覆盖到生成日，建议更新。",
    _snap.STATE_UNKNOWN_AGE: "快照没有可读的 generated_at，无法判断新旧。"
                             "仍可用于比对，共 {n} 条。",
    _snap.STATE_EMPTY: "快照里没有条目，等于没有 CVE 数据可查，"
                       "扫描不会做 CVE 比对。",
    _snap.STATE_MISSING: "数据目录与程序目录下都没有 cve_snapshot.json，"
                         "扫描不会做 CVE 比对。",
    _snap.STATE_CORRUPT: "快照文件无法解析或校验不匹配，已拒绝加载，"
                         "扫描不会做 CVE 比对。",
}

#: 快照来源规范值 → 显示名（§9.4 要求 UI 显示来源）。同需登记。
_CVE_SOURCE_TEXT = {
    _snap.SOURCE_DATA: "数据目录（用户更新版）",
    _snap.SOURCE_SEED: "程序内置种子（覆盖面很窄）",
    _snap.SOURCE_NONE: "无",
}

#: 状态 → 语义色令牌名（theme_tokens.py）。🟢 ok / 🟡 旧或未知 / 🔴 坏。
_CVE_BADGE_TOKEN = {
    _snap.STATE_OK: "online",
    _snap.STATE_STALE: "warn",
    _snap.STATE_UNKNOWN_AGE: "warn",
    _snap.STATE_EMPTY: "muted",
    _snap.STATE_MISSING: "muted",
    _snap.STATE_CORRUPT: "danger",
}


def badge_text(state: str, entry_count: int) -> str:
    """徽标短文案（语言有关，运行时取）。"""
    tpl = _CVE_BADGE_TEXT.get(state)
    if tpl is None:                        # 未知状态：宁可露怯也不猜
        return tr("CVE 数据: 未知状态")
    # 🔴 表里的值是**待翻译字面量**，必须过 tr() —— 直接 return 会让英文
    # 界面显示中文（表驱动文案的盲区，见 test_i18n_lazy 的登记清单）。
    tpl = tr(tpl)
    if "{n}" in tpl:
        return tpl.format(n=entry_count)
    return tpl


def hint_text(stats: dict) -> str:
    """tooltip / 详情对话框里的「现状 + 下一步」（语言有关，运行时取）。"""
    state = str(stats.get("state", ""))
    tpl = _CVE_HINT_TEXT.get(state)
    if tpl is None:
        return tr("CVE 数据: 未知状态")
    tpl = tr(tpl)
    age = stats.get("age_days")
    return tpl.format(
        age=age if age is not None else "?",
        max=stats.get("max_age_days", _snap.DEFAULT_MAX_AGE_DAYS),
        n=stats.get("entry_count", 0),
        kev=stats.get("kev_count", 0),
        epss=stats.get("epss_scored_count", 0),
    )


def source_text(source: str) -> str:
    """来源显示名。"""
    return tr(_CVE_SOURCE_TEXT.get(source, _CVE_SOURCE_TEXT[_snap.SOURCE_NONE]))


def token_name(state: str) -> str:
    """状态 → 语义色令牌名。"""
    return _CVE_BADGE_TOKEN.get(state, "muted")


class CveStatusMixin:
    """主窗口混入：CVE 快照徽标的刷新与详情对话框。

    依赖（由 MainWindow 提供）：`cve_label`（QLabel，#cveLabel）、
    `dark_mode`、`status_bar`。
    """

    #: 当前解析后的主题（MainWindow 的属性）。显式声明是为了让 pyright 认它 ——
    #: 混入类之间靠"宿主提供属性"协作，静态检查看不见（本文件在 pyright 的
    #: 包含清单里，不能靠 `getattr` 到处绕）。
    dark_mode: bool

    def _refresh_cve_badge(self):
        """重读快照并刷新状态栏徽标（文案 / 颜色 / tooltip 三件套）。

        每次**重读文件**而不是缓存：文件是用户手动更新的，而徽标是状态机里
        唯一的外显窗口 —— 缓存会让「换文件后毫无变化」这种事无声发生。
        读一次几百 KB 的 JSON 在毫秒级，启动/切主题各跑一次，代价可忽略。
        """
        label = getattr(self, "cve_label", None)
        if label is None:                  # 无头测试里可能不建状态栏
            return
        try:
            snap = _snap.load_snapshot()
            stats = snap.stats()
        except Exception as e:  # noqa: BLE001
            # 徽标是附加信息：读失败绝不能连带把窗口起不来。
            # 但也不能无声 —— 退化成一个灰徽标并在日志里留痕。
            _log.debug("CVE 快照状态读取失败（徽标退化为不可用）: %s", e)
            label.setText(tr("CVE 数据: 状态未知"))
            label.setToolTip(tr("无法读取 CVE 快照状态，详见日志"))
            label.setStyleSheet(
                "color: %s; font-size: 11px;" % token("muted", self.dark_mode))
            return
        label.setText(badge_text(stats["state"], stats["entry_count"]))
        label.setToolTip(hint_text(stats))
        label.setStyleSheet(
            "color: %s; font-size: 11px;"
            % token(token_name(stats["state"]), self.dark_mode))

    def _show_cve_status(self):
        """CVE 快照详情对话框（徽标的「展开」）。

        全部事实一次给全：状态 / 来源 / 条目统计 / 生成时间 / 路径 /
        校验情况 / 下一步动作。刻意不用 QMessageBox 以外的自定义对话框 ——
        这就是个只读信息页，msg_info 足够了。
        """
        try:
            snap = _snap.load_snapshot()
            stats = snap.stats()
        except Exception as e:  # noqa: BLE001
            # 同上：读失败给一句实话，不编状态。
            _log.debug("CVE 快照详情读取失败: %s", e)
            msg_info(
                self, tr("CVE 数据快照"),
                tr("无法读取 CVE 快照状态（详见日志）。"),
            )
            return
        lines = [
            tr("状态") + "：" + badge_text(stats["state"], stats["entry_count"]),
            tr("来源") + "：" + source_text(stats["source"]),
            tr("条目") + "：" + tr("共 {n} 条（KEV {kev} 条 · EPSS 已评分"
                                  " {epss} 条）").format(
                n=stats["entry_count"], kev=stats["kev_count"],
                epss=stats["epss_scored_count"]),
        ]
        _gen = stats.get("generated_at")
        if _gen:
            _age = stats.get("age_days")
            lines.append(tr("生成时间") + "：" + tr("{ts} UTC（{age} 天前）").format(
                ts=str(_gen)[:10], age=_age if _age is not None else "?"))
        else:
            lines.append(tr("生成时间") + "：" + tr("（快照未提供）"))
        lines.append(tr("路径") + "：" + (stats.get("path") or "—"))
        _ck = stats.get("checksum_verified")
        lines.append(tr("摘要校验") + "：" + (
            tr("通过") if _ck is True else tr("未提供清单，未校验")))
        lines.append(tr("下一步") + "：" + hint_text(stats))
        # 「手动放置」永远是可行路径（模型文档 §9.4 配套第 1 条）：把路径
        # 直接告诉用户，省一次「去问路径在哪」。
        lines.append(tr("手动更新") + "：" + tr("把新的 cve_snapshot.json 放进"
                                               " {path} 后重启").format(
            path=data_dir()))
        msg_info(self, tr("CVE 数据快照"), "\n".join(lines))
