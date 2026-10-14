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
from ui_msg import msg_consent, msg_info, msg_warn

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

#: 在线更新的**结果**原因（`cve_updater.REASON_*`）→ 显示文案。
#: 🔴 本表在 test_i18n_lazy 的 `_label_tables()` 登记。规范值语言无关，
#: 中文只出现在**值**里；`update_result_text()` 取用时过 `tr()`。
_CVE_UPDATE_TEXT = {
    "ok": "更新完成：共 {n} 条（已校验 SHA256）。",
    "no-url": "尚未配置下载地址，无法在线更新。请手动把新的 "
              "cve_snapshot.json 放进数据目录。",
    "download-failed": "下载失败（网络不可达 / 超时 / 地址无效）。"
                       "已保留现有数据，可稍后重试或手动放置文件。",
    "too-large": "下载内容超过大小上限，已丢弃。请检查地址是否正确。",
    "checksum-failed": "下载内容的 SHA256 与清单不一致，已丢弃并保留现有"
                       "数据（可能是下载损坏或地址被改动）。",
    "invalid": "下载回来的内容不是可用的快照，已丢弃并保留现有数据。",
    "write-failed": "下载成功但写入数据目录失败（磁盘空间 / 权限），"
                    "已保留现有数据。",
    "no-manifest": "服务器上没有可用的 SHA256 清单，出于安全默认拒绝安装"
                   "（无法确认下载内容完整）。",
}

#: 在线更新的**入口**确认文案（用户点「更新」前的同意框）。
_CVE_UPDATE_CONSENT = {
    "title": "在线更新 CVE 数据快照",
    "body": "将从配置的地址下载 CVE 数据快照（约几百 KB），下载后先校验 "
            "SHA256 再安装。\n\n这是本程序**唯一**联网的 CVE 操作 —— 不点它"
            "就不会联网。\n\n是否继续？",
    "accept": "下载并更新",
    "decline": "取消",
}

#: 快照来源规范值 → 显示名（§9.4 要求 UI 显示来源）。同需登记。
_CVE_SOURCE_TEXT = {
    _snap.SOURCE_DATA: "数据目录（用户更新版）",
    _snap.SOURCE_SEED: "程序内置种子（覆盖面很窄）",
    _snap.SOURCE_ONLINE: "在线下载（已校验 SHA256）",
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


def update_result_text(result: dict) -> str:
    """在线更新的结果 dict → 一句用户可读的话（语言有关，运行时取）。

    `result` 就是 `cve_updater.update_snapshot()` 的返回值；`reason` 是
    语言无关的规范值，这里查表 + `tr()` + `format`（**不要**裸 f-string，
    否则躲过 i18n 完整性测试）。
    """
    reason = str(result.get("reason", ""))
    tpl = _CVE_UPDATE_TEXT.get(reason)
    if tpl is None:                        # 未知原因：宁可露怯也不猜
        return tr("更新结束，但结果无法识别。详情见日志。")
    tpl = tr(tpl)
    if "{n}" in tpl:
        return tpl.format(n=result.get("entry_count", 0))
    return tpl


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

    # ── 在线更新（v2.2 §3.1）─────────────────────────────────────────
    def _update_cve_snapshot(self):
        """在线更新 CVE 数据快照（用户显式触发，**唯一**联网的 CVE 动作）。

        流程：同意框（`msg_consent`，**不是** `msg_ask`）→ 后台线程下载
        （`CveUpdateThread`）→ 结果提示 → 刷新徽标。

        🔴 三条不能破的规矩：
        1. **绝不能放在 `MainWindow.__init__`**：同意类弹窗在无头测试里会
           永久挂住（TRAPS「界面」第 ③ 条）。本方法只由菜单动作触发。
        2. **失败不升级**：`cve_updater` 永不抛，这里也只提示 + 留痕，
           绝不弹 `msg_error` —— 下载失败不是"程序出错"，是"这次没更成"。
        3. 线程对象存到 `self._cve_update_thread`，否则会被 GC 提前回收
           （与 `oui_mixin` 同一个坑）。
        """
        url = _snap.DEFAULT_SNAPSHOT_URL
        reply = msg_consent(
            self,
            tr(_CVE_UPDATE_CONSENT["title"]),
            tr(_CVE_UPDATE_CONSENT["body"]),
            tr(_CVE_UPDATE_CONSENT["accept"]),
            tr(_CVE_UPDATE_CONSENT["decline"]),
        )
        if not reply:
            return

        from ui_threads import CveUpdateThread
        self._cve_update_thread = CveUpdateThread(url)
        self._cve_update_thread.finished_signal.connect(
            self._on_cve_update_finished)
        self._cve_update_thread.start()

    def _on_cve_update_finished(self, result: dict):
        """在线更新结束：提示结果 + 无论如何都刷新徽标。

        **成功与失败都刷新**：失败时数据没变，刷新只是原地重画（廉价）；
        成功时这一步才是"换完文件界面立刻反映"的关键。不刷新就会出现
        「刚说更新成功、徽标还写着未安装」这种自相矛盾的画面。
        """
        text = update_result_text(result)
        if result.get("ok"):
            msg_info(self, tr("CVE 数据快照在线更新"), text)
        else:
            msg_warn(self, tr("CVE 数据快照在线更新"), text)
        self._refresh_cve_badge()
