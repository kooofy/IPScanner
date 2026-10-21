# -*- coding: utf-8 -*-
"""台账批量导入的**预览 / 确认**对话框（v2.3.1）。

为什么要有这一步
----------------
批量导入是一次**不可撤销**的批量写入：选错文件、把「位置」当成「位置树」、
或者误开了清空开关，都会一次改掉几十上百台设备的台账。所以界面这条路的
流程是「选文件 → 编译计划 → **给人看一眼** → 才写」，而不是选完文件直接写。

对话框本身**不碰数据库**（与 `AssetEditDialog` 同一条约定）：它只把已经
编译好的报告显示出来，写入由调用方在 `accepted` 之后执行。

🔴 三张文案表（`_STATUS_TEXT` / `_REASON_TEXT` / `_PROBLEM_TEXT`）是**字面量表**，
   取用时必须过 `tr()`（模块顶层不能调 `tr()`，否则会被冻成导入期语言）。
   它们已登记进 `tests/test_i18n_lazy.py::_label_tables()` —— 漏登记就会在
   英文界面把「找不到设备」原样显示成中文。
"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QVBoxLayout,
)

import asset_import
from i18n import tr

#: 行状态 → 中文标签。
_STATUS_TEXT = {
    asset_import.ST_WRITTEN: "已写入",
    asset_import.ST_OK: "将写入",
    asset_import.ST_NOCHANGE: "无需改动",
    asset_import.ST_DUPLICATE: "重复行",
    asset_import.ST_EMPTY: "空行",
    asset_import.ST_NOTFOUND: "找不到设备",
    asset_import.ST_INVALID: "格式或身份有误",
}

#: 失败原因 → 中文说明。键是 `asset_import.REASON_*` 规范值。
_REASON_TEXT = {
    asset_import.REASON_BAD_DATE: "日期格式无效（应为 YYYY-MM-DD）",
    asset_import.REASON_BAD_JSON: "自定义字段不是合法的 JSON 对象",
    asset_import.REASON_NO_IDENTITY: "这一行没有身份键或 MAC，认不出是哪台设备",
    asset_import.REASON_UNKNOWN_DEVICE: "资产表里找不到这台设备",
    asset_import.REASON_IP_NOT_ALLOWED:
        "只有 IP 不能安全匹配（IP 会被 DHCP 换给别的设备），请加一列 MAC 或身份键",
    asset_import.REASON_DUPLICATE_ROW: "同一台设备在表里出现了多次，只取第一行",
    asset_import.REASON_NO_FIELDS: "这一行没有可写入的字段",
    asset_import.REASON_ALREADY_EQUAL: "与库里已有值一致，无需写入",
    asset_import.REASON_WRITE_FAILED: "写入被拒绝",
}

#: 计划级问题 → 中文说明。
_PROBLEM_TEXT = {
    asset_import.PROBLEM_EMPTY: "文件里连表头都没有（空文件？）",
    asset_import.PROBLEM_NO_COLUMNS: "没有识别到任何可写入的列",
    asset_import.PROBLEM_NO_IDENTITY_COLUMN: "表里既没有身份键列，也没有 MAC 列",
}

#: 报告里最多列多少条待处理行（与 CLI 的 `_IMPORT_DETAIL_LIMIT` 同口径）。
DETAIL_LIMIT = 20

#: 「需要用户处理」的状态（重复行也算 —— 它意味着表里有重复数据要清）。
_BAD_STATUSES = (asset_import.ST_NOTFOUND, asset_import.ST_INVALID,
                 asset_import.ST_DUPLICATE)


def problem_text(problem) -> str:
    """计划级问题 → 可显示的中文；`problem` 为空时返回空串。"""
    if not problem:
        return ""
    return tr(_PROBLEM_TEXT.get(problem, problem))


def line_text(item) -> str:
    """一条计划项 → 一行可读说明（含行号与身份线索）。"""
    who = item.get("identity_key") or item.get("detail") or ""
    raw_reason = item.get("reason") or ""
    reason = tr(_REASON_TEXT[raw_reason]) if raw_reason in _REASON_TEXT else raw_reason
    # 非法行要把**被拒的值**显示出来 —— 只说「日期格式无效」而不说是哪个值，
    # 用户还得自己回表里逐格找。`detail` 在这里正是那个值。
    if (item.get("status") == asset_import.ST_INVALID
            and item.get("identity_key") and item.get("detail")):
        reason = tr("{reason}：{value}").format(
            reason=reason, value=item["detail"])
    if item.get("field"):
        reason = tr("{reason}（字段 {field}）").format(
            reason=reason, field=item["field"])
    return tr("第 {line} 行 {who}：{reason}").format(
        line=item.get("line", 0), who=who, reason=reason)


def build_report(plan, written=None) -> str:
    """导入计划 → 预览/结果报告文本（多行，供只读文本框显示）。

    Args:
        plan:    `asset_import.build_plan()` 的结果。
        written: `None` 表示**还没写**（预览阶段）；给数字表示已写入的台数
                 （结果阶段，多一行「已写入 N 台」）。
    """
    lines = []
    cols = sorted((plan or {}).get("columns") or {})
    lines.append(tr("识别到 {n} 列：{cols}").format(
        n=len(cols), cols="、".join(cols) or tr("无")))
    ignored = (plan or {}).get("ignored") or []
    if ignored:
        lines.append(tr("忽略 {n} 列（不是台账字段）：{cols}").format(
            n=len(ignored), cols="、".join(ignored)))

    counts = asset_import.summarize(plan)
    parts = [
        tr("{label} {n} 台").format(label=tr(_STATUS_TEXT[st]), n=counts[st])
        for st in asset_import.ALL_STATUSES if counts.get(st)
    ]
    lines.append(tr("共 {total} 行：{parts}").format(
        total=(plan or {}).get("total", 0), parts="、".join(parts) or tr("无")))
    if written is not None:
        lines.append(tr("已写入 {n} 台设备的台账字段。").format(n=written))

    bad = [it for it in (plan or {}).get("items") or ()
           if it.get("status") in _BAD_STATUSES]
    if bad:
        lines.append("")
        lines.append(tr("需要处理的行："))
        for item in bad[:DETAIL_LIMIT]:
            lines.append("  " + line_text(item))
        if len(bad) > DETAIL_LIMIT:
            lines.append(tr("……另有 {n} 条。").format(n=len(bad) - DETAIL_LIMIT))
    return "\n".join(lines)


class AssetImportPreviewDialog(QDialog):
    """显示导入报告；`can_apply` 为真时给出「导入」按钮。

    `can_apply=False`（没有可写的行）时只剩「关闭」—— 这时点「导入」什么也不会
    发生，留一个能按的按钮只会让人以为写入成功了。
    """

    def __init__(self, report_text, file_label="", can_apply=True, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("导入资产信息"))
        self.setMinimumSize(560, 380)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._build(report_text, file_label, can_apply)

    def _build(self, report_text, file_label, can_apply):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        if file_label:
            head = QLabel(file_label)
            head.setObjectName("dialogHint")
            head.setWordWrap(True)
            layout.addWidget(head)

        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setPlainText(report_text or "")
        # 报告里全是对齐过的行号与原因，等宽字体比比例字体好读得多。
        view.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(view, 1)

        buttons = QDialogButtonBox()
        if can_apply:
            buttons.addButton(tr("导入"), QDialogButtonBox.AcceptRole)
        buttons.addButton(tr("关闭"), QDialogButtonBox.RejectRole)
        # 「关闭」在 can_apply 时是 RejectRole ⇒ rejected；不可写时点它同样关掉。
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
