# -*- coding: utf-8 -*-
"""对话框包：按用途拆分（原 `ui_dialogs.py` 单文件 1995 行）。

拆分方案见 `docs/refactor/ui_dialogs_split_plan.md`。本 `__init__` 做门面
re-export，保持 `from ui_dialogs import X` 与 `ui_dialogs.X` 两种既有用法不变 ——
调用方（各 Mixin、测试）无需改动。
"""
from .audit import AuditLogDialog
from .audit_activity import AuditActivityDialog
from .credentials import SnmpV3CredentialDialog, WmiCredentialDialog
from .history import HistoryCompareDialog, HistoryQueryDialog
from .library import DeviceEditDialog, MacLibraryDialog
from .locate import LocateDeviceDialog
from .reports import (ChangeReportDialog, ConflictReportDialog,
                      SubnetUtilizationDialog)
from .switch_port import SwitchPortDialog
from .topology import TopologyDialog
from .wifi import WifiDialog

__all__ = [
    "DeviceEditDialog", "MacLibraryDialog",
    "HistoryCompareDialog", "HistoryQueryDialog",
    "TopologyDialog",
    "WmiCredentialDialog", "SnmpV3CredentialDialog",
    "ConflictReportDialog", "SubnetUtilizationDialog", "ChangeReportDialog",
    "AuditLogDialog", "AuditActivityDialog", "SwitchPortDialog",
    "LocateDeviceDialog", "WifiDialog",
]
