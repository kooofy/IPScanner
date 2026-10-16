# -*- coding: utf-8 -*-
"""资产台账编辑对话框（v2.3 §3.4）：采购日期 / 保修到期 / 负责人 / 序列号 /
位置树 / 自定义字段。

为什么需要它
------------
`assets` 这 6 列是**人工填写的台账**，扫描永远不写（扫描仪不知道采购日期）。
CLI 侧有 `assets --set`，但"对着设备列表点一下"才是日常动作 —— 如果填一个
负责人要先去查身份键再拼命令行，这个字段最终就是空的。

🔴 三条硬约定
-------------
* **只写生命周期列**：写入走 `history_store.update_asset_lifecycle()`，它不碰
  扫描写入的列 —— 例行扫描也永远不会覆盖这里填的值。
* **非法输入当场报错、不静默存空**：校验不过就留在对话框里改，不 `accept()`。
  静默存成空串等于悄悄丢了用户刚填的东西（见 `asset_lifecycle` 的模块注释）。
* **自定义字段的键名不翻译**（§3.4 验收 2）：`{"机架": "A3"}` 原样存取。

⚠️ 本模块**不碰数据库**：它只负责收集与校验，写入由调用方
   （`main_window`）在 `accepted` 之后执行 —— 对话框里开库连接会让
   "取消"也可能留下半截写入，且难以单测。
"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QPlainTextEdit,
    QVBoxLayout,
)

import asset_lifecycle
from i18n import tr
from ui_msg import localize_buttons, msg_warn


class AssetEditDialog(QDialog):
    """编辑一台设备的台账字段。`values()` 给出**待写入**的字段字典。"""

    def __init__(self, identity_key, asset=None, parent=None):
        super().__init__(parent)
        self._key = (identity_key or "").strip()
        self._asset = dict(asset or {})
        self.setWindowTitle(tr("编辑资产信息"))
        self.setMinimumWidth(460)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._build()
        self._load()

    # ── 构建 ──────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        head = QLabel(tr("设备：{key}").format(key=self._key or "—"))
        head.setObjectName("dialogHint")
        head.setWordWrap(True)
        head.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(head)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        self.purchase_edit = QLineEdit()
        self.purchase_edit.setPlaceholderText("YYYY-MM-DD")
        self.warranty_edit = QLineEdit()
        self.warranty_edit.setPlaceholderText("YYYY-MM-DD")
        self.owner_edit = QLineEdit()
        self.serial_edit = QLineEdit()
        self.location_edit = QLineEdit()
        self.custom_edit = QPlainTextEdit()
        self.custom_edit.setPlaceholderText('{"机架": "A3"}')
        self.custom_edit.setFixedHeight(72)

        form.addRow(QLabel(tr("采购日期")), self.purchase_edit)
        form.addRow(QLabel(tr("保修到期")), self.warranty_edit)
        form.addRow(QLabel(tr("负责人")), self.owner_edit)
        form.addRow(QLabel(tr("序列号")), self.serial_edit)
        form.addRow(QLabel(tr("位置")), self.location_edit)
        form.addRow(QLabel(tr("自定义字段")), self.custom_edit)
        layout.addLayout(form)

        hint = QLabel(tr("日期格式 YYYY-MM-DD；留空表示清空该字段。"
                         "自定义字段填 JSON 对象，键名原样保存、不会被翻译。"))
        hint.setObjectName("dialogHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        localize_buttons(buttons)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load(self):
        """把库里已有的值填进输入框（缺字段按空串）。"""
        self.purchase_edit.setText(self._asset.get("purchase_date", "") or "")
        self.warranty_edit.setText(self._asset.get("warranty_end", "") or "")
        self.owner_edit.setText(self._asset.get("owner", "") or "")
        self.serial_edit.setText(self._asset.get("serial", "") or "")
        self.location_edit.setText(self._asset.get("location_tree", "") or "")
        self.custom_edit.setPlainText(self._asset.get("custom_json", "") or "")

    # ── 取值 / 校验 ───────────────────────────────────────

    def values(self) -> dict:
        """校验并返回待写入的字段字典；非法输入抛 `ValueError`。

        键名即 `asset_lifecycle.LIFECYCLE_COLUMNS` 里的列名 —— 直接喂给
        `history_store.update_asset_lifecycle(**values)`，中间不再做一次映射
        （多一层映射就多一处能拼错的地方）。

        🔴 错误文案在本模块生成、并且**经 `tr()`**：`asset_lifecycle` 是纯领域层，
          它抛的是中文源串，直接显示到英文界面就成了中英混杂。
        """
        out = {
            "purchase_date": self.purchase_edit.text().strip(),
            "warranty_end": self.warranty_edit.text().strip(),
            "owner": self.owner_edit.text().strip(),
            "serial": self.serial_edit.text().strip(),
            "location_tree": self.location_edit.text().strip(),
            "custom_json": self.custom_edit.toPlainText().strip(),
        }
        for name, label in (("purchase_date", tr("采购日期")),
                            ("warranty_end", tr("保修到期"))):
            # 用宽松解析器**只当探针**，文案由本层生成（见上面的 docstring）。
            if out[name] and asset_lifecycle.parse_date(out[name]) is None:
                raise ValueError(
                    tr("{field}格式无效：{value}（应为 YYYY-MM-DD）").format(
                        field=label, value=out[name]))
        try:
            asset_lifecycle.normalize_custom_json(out["custom_json"])
        except ValueError as exc:
            raise ValueError(
                tr('自定义字段必须是合法的 JSON 对象，例如 {"机架": "A3"}')) from exc
        return out

    def _on_accept(self):
        try:
            self.values()
        except ValueError as exc:
            # 不 accept：把用户填的内容留在对话框里改，而不是关掉再重来。
            msg_warn(self, tr("资产信息未保存"), str(exc))
            return
        self.accept()
