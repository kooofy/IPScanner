# `ui_dialogs.py` 拆分方案（CODE_REVIEW P1-4）

> 状态：**阶段 A 已落地**（2026-10-10）｜ 起草 2026-10-09 ｜ 对象：`ui_dialogs.py`（v1.7.5，**1995 行**）
> 目标：把全仓最大文件按用途拆成 `ui_dialogs/` 包，**对外行为零变化**。
> 本文是方案说明；**阶段 A 已按本文执行完毕**，阶段 B 仍为可选后续。
>
> ✅ **阶段 A 结果**：已拆为 `ui_dialogs/` 包（8 子模块 + re-export 门面），
> 实际最大文件 **484 行**（`reports.py`）；4 个 Mixin 与全部测试的导入面保持不变；
> ruff 干净、1116 测试全绿、CLI 冒烟通过。
> ⬜ **阶段 B（抽公共骨架，§7）未做**，仍是可选后续。

---

## 0. 一句话方案

`ui_dialogs.py`（1995 行 / **12** 个 `QDialog` + 3 个私有助手）
→ `ui_dialogs/` 包（8 个子模块 + `__init__.py` 做 re-export）。

- 单文件最大行数 **1995 → ≈490**。
- **4 个 mixin 的 `from ui_dialogs import …` 一行都不用改**（`__init__.py` 转出全部 12 个对话框）。
- 该结构与本仓库 `docs/reviews/CODE_REVIEW.md` P1-4 的原建议一致：
  > 按用途拆成 `ui_dialogs/` 包（`topology.py` / `credentials.py` / `history.py` / `settings.py`），
  > 保留 `ui_dialogs/__init__.py` 做 re-export 以免打断现有 import。
  > （注：原建议里的 `settings.py` 在本文件里并不存在对应对话框 —— 设置对话框不在 `ui_dialogs` 中，故不建。）

---

## 1. 现状剖析

### 1.1 文件构成（`ui_dialogs.py`，共 1995 行）

| 行区间 | 符号 | 行数 | 归属域 |
|---|---|---:|---|
| 1–39 | 文件头 / imports / `_log` | 39 | — |
| 42–52 | `_ellipsize()` | 11 | 共享助手 |
| 55–63 | `_faded()` | 9 | 共享助手 |
| 66–77 | `_theme_color()` | 12 | 共享助手 |
| 80–139 | `DeviceEditDialog` | 60 | 地址库 |
| 142–277 | `MacLibraryDialog` | 136 | 地址库 |
| 280–390 | `HistoryCompareDialog` | 111 | 历史 |
| 393–586 | `HistoryQueryDialog` | 194 | 历史 |
| 589–997 | `TopologyDialog` | 409 | 拓扑 |
| 1000–1072 | `WmiCredentialDialog` | 73 | 凭据 |
| 1075–1237 | `SnmpV3CredentialDialog` | 163 | 凭据 |
| 1240–1396 | `ConflictReportDialog` | 157 | 报告 |
| 1399–1560 | `SubnetUtilizationDialog` | 162 | 报告 |
| 1563–1696 | `AuditLogDialog` | 134 | 审计 |
| 1699–1856 | `SwitchPortDialog` | 158 | 端口映射 |
| 1859–1994 | `ChangeReportDialog` | 136 | 报告 |

### 1.2 内部耦合 —— 这决定了拆分边界

- **全文件只有一处类间引用**：`MacLibraryDialog._add()` / `._edit()` 打开 `DeviceEditDialog`（同属"地址库"，拆到同一文件即可，不产生跨文件依赖）。即 **12 个对话框里有 10 个完全独立**，可自由按域归组。
- **模块级私有助手的实际共用情况**（已逐行核对）：
  - `_theme_color()` —— **22 处调用，跨 5 个对话框**（历史查询 / 拓扑 / 冲突报告 / 子网利用率 / 变更报告）→ **必须**单独成 `_shared.py`，否则会产生"共享文件 ↔ 各子模块"的环状依赖。
  - `_ellipsize()` / `_faded()` —— 各 2 处，**仅 `TopologyDialog` 使用**。
  - 建议三者统一放 `_shared.py`（"对话框公共助手"单一出处）；若想更精简，也可把后两个并入 `topology.py`，`_shared.py` 只留 `_theme_color`。本方案取前者。

### 1.3 对外接口（拆分后必须逐字保持）

调用点（4 个 mixin）：

| 文件 | 导入的名字 |
|---|---|
| `scan_mixin.py` | `WmiCredentialDialog`、`SnmpV3CredentialDialog`、`ConflictReportDialog`、`SubnetUtilizationDialog`、`ChangeReportDialog` |
| `history_mixin.py` | `AuditLogDialog`、`HistoryCompareDialog`、`HistoryQueryDialog`、`TopologyDialog` |
| `network_tool_mixin.py` | `SwitchPortDialog` |
| `library_mixin.py` | `MacLibraryDialog`、`DeviceEditDialog` |

测试调用点：

| 文件 | 用法 |
|---|---|
| `tests/test_topology_layout.py` | `ui_dialogs.TopologyDialog._ring_layout / _MAX_* / (...)`（多处） |
| `tests/test_ui_dialogs_colors.py` | `ui_dialogs.ConflictReportDialog / ChangeReportDialog / TopologyDialog / AuditLogDialog` |
| `tests/test_snmp_v3.py` | `from ui_dialogs import SnmpV3CredentialDialog` |
| `tests/test_wmi_transport.py` | `from ui_dialogs import WmiCredentialDialog`（2 处） |
| `tests/test_scaffolding.py` | `import ui_dialogs` + `hasattr(ui_dialogs, "QGraphicsRectItem")` 等 5 个 Qt 图形类 |

> 结论：**只要 `ui_dialogs/__init__.py` 把 12 个对话框转出**，上面"按名字取类"的用法**全部无需改动**。

---

## 2. 约束：拆分时**必须同步修改**的测试（只有 2 处）

这两处是**直接读源码文本**或**检查 Qt 名是否在本模块**的测试，拆包后必然失效，必须在同一次提交里改：

| # | 测试 | 现状（为什么会坏） | 改法 |
|---|---|---|---|
| 1 | `tests/test_ui_dialogs_colors.py` | 4 处 `_src("ui_dialogs.py")` 把**单个文件**当扫描对象（禁色值字面量、查令牌名、查 `tr("<span`）。拆包后字面量散落到 `topology.py` / `reports.py` 等，只扫 `ui_dialogs.py`（会变成薄壳）等于**测试失效**。 | 把 `_src("ui_dialogs.py")` 换成一个**拼接整个包**的助手，例如 `_pkg_src()` = 读 `ui_dialogs/*.py` 全部内容再断言。断言内容不变。 |
| 2 | `tests/test_scaffolding.py::GraphicsItemImportTest` | `import ui_dialogs` 后断言 `hasattr(ui_dialogs, "QGraphicsRectItem")` 等 5 个名字。这些名字属于拓扑绘制，拆分后应在 `topology.py`。 | 改为 `import ui_dialogs.topology as _topo`，断言 `hasattr(_topo, name)`。语义更准确（守卫的本来就是拓扑绘制模块）。 |

**无需改动**（已确认）：

- `tests/test_i18n_lazy.py` 的两个检查都用 `os.walk(ROOT)` **递归遍历**全部 `.py`（`SKIP_DIRS` 只排除 `venv/build/dist/__pycache__/.git` 等），新包目录**自动被覆盖**。前提：新子模块里**不得出现模块级 `tr()`**（与现状一致，纯搬迁不会引入）。
- 4 个 mixin + `test_topology_layout` / `test_snmp_v3` / `test_wmi_transport`：都按名字取类，`__init__` 转出后照常工作。

---

## 3. 目标结构

```
ui_dialogs/
├─ __init__.py       # 门面：re-export 全部 12 个对话框（≈40 行）
├─ _shared.py        # _ellipsize / _faded / _theme_color（≈55 行）
├─ library.py        # DeviceEditDialog, MacLibraryDialog（≈230 行）
├─ credentials.py    # WmiCredentialDialog, SnmpV3CredentialDialog（≈270 行）
├─ history.py        # HistoryCompareDialog, HistoryQueryDialog（≈340 行）
├─ topology.py       # TopologyDialog（≈440 行）
├─ reports.py        # ConflictReportDialog, SubnetUtilizationDialog, ChangeReportDialog（≈490 行）
├─ audit.py          # AuditLogDialog（≈165 行）
└─ switch_port.py    # SwitchPortDialog（≈190 行）
```

行数为「搬迁内容 + 该子模块自己的 import 头（约 30 行）」的估算。**最大文件 ≈490 行**，全部低于 500 行。

### 归组理由

| 子模块 | 依据 |
|---|---|
| `_shared.py` | `_theme_color` 被 5 个对话框共用（另两个助手仅拓扑用），必须**单一来源**；零对话框依赖，处于依赖图最底层。 |
| `library.py` | `DeviceEditDialog` 与 `MacLibraryDialog` 是**唯一一对**有调用关系的类，且同属"地址库/设备"域。 |
| `credentials.py` | 两个凭据对话框共享"采集凭据 → 调用方 DPAPI 落盘"的契约，且都依赖 `scanner.wmi` / `scanner.snmp_v3`。 |
| `history.py` | 都读 `history_store`，是"历史快照"的两种视图（对比 / 查询）。 |
| `topology.py` | 409 行、自成一体的绘图逻辑（`QGraphics*`），且 `test_topology_layout` 已把它当独立单元测。 |
| `reports.py` | 三个"带严重度/利用率着色 + CSV 导出"的报表（冲突 / 子网利用率 / 变更），形态高度同构。 |
| `audit.py` | 审计日志查看器，只依赖 `audit_log`。 |
| `switch_port.py` | 交换机端口映射，依赖 `ui_threads.SwitchMapThread` + `switch_mapper`（含后台线程），独立成文件便于日后单测。 |

### 依赖图（无环）

```
        theme_tokens ─┐
                      ▼
   _shared ◄────┬── topology ◄── topology_discovery(惰性)
                ├── history  ◄── history_store / ui_utils
                ├── reports  ◄── conflict_detector / change_detector / ui_logic
                └── (library 不依赖 _shared)
   credentials ◄── scanner.wmi / scanner.snmp_v3
   audit       ◄── audit_log
   switch_port ◄── ui_threads / switch_mapper
```

`__init__.py` 只做转出，是唯一的"汇聚点"。

---

## 4. 执行步骤（机械搬迁，按序）

> 原则：**先纯搬迁、后优化**。本次提交只做"移动 + 改 import"，不改任何一行逻辑，
> 便于 reviewer 用 `git diff --color-moved` 一眼确认"没有真改动"。

1. **建包目录** `ui_dialogs/`。
2. **`_shared.py`**：搬 `_ellipsize` / `_faded` / `_theme_color`（含各自 docstring，其中"`tests/test_ui_dialogs_colors.py` 会扫描本文件"那句需改成"扫描本包"）。只 import `QColor` + `theme_tokens.token`。
3. **`library.py`**：搬 `DeviceEditDialog`、`MacLibraryDialog`。
4. **`credentials.py`**：搬 `WmiCredentialDialog`、`SnmpV3CredentialDialog`。
5. **`history.py`**：搬 `HistoryCompareDialog`、`HistoryQueryDialog`。
6. **`topology.py`**：搬 `TopologyDialog`（保持 `from topology_discovery import …` 的**函数内惰性 import** 不变）。
7. **`reports.py`**：搬 `ConflictReportDialog`、`SubnetUtilizationDialog`、`ChangeReportDialog`。
8. **`audit.py`**：搬 `AuditLogDialog`。
9. **`switch_port.py`**：搬 `SwitchPortDialog`。
10. **`__init__.py`**：`from .xxx import Yyy` 转出 12 个对话框，并写 `__all__`（见 §6 风险 3）。
11. **删除 `ui_dialogs.py`** —— ⚠️ **必须与建包在同一次提交**：同名目录（含 `__init__.py`）会**遮蔽**同名模块，两者并存时 `import ui_dialogs` 解析结果不确定。
12. **改 2 个测试**（§2 表格）。
13. **更新文档**（§5）。
14. **验证**（§6）。

每个子模块的 import 头按"该文件实际用到什么"精简，不要整段复制原文件的 39 行头（否则 ruff 的 F401 会报未使用导入）。

---

## 5. 需要同步更新的文档 / 注释

| 位置 | 现状 | 改为 |
|---|---|---|
| `README.md:345` | `├─ ui_dialogs.py  # 各类对话框（含拓扑视图）` | `ui_dialogs/` 一节（8 个子模块 + `__init__`） |
| `docs/reviews/CODE_REVIEW.md` P1-4 | 「未做；已长到 1898 行」 | 落地后标注关闭（**归档文档，按既定约定：仅在真正完成时改状态**） |
| `docs/reviews/README.md` §3 | P1-4 在「未落地」表 | 落地后移入「已落地」表 |
| `theme_tokens.py:47` | 注释「对话框（ui_dialogs）用到的语义色」 | 「对话框（`ui_dialogs/`）…」（可选，纯注释） |

> 说明：`docs/reviews/` 三份文档**已关闭**。按仓库约定，只有**真正落地后**才动它们的关闭状态；本方案阶段**不改**。

---

## 6. 验证方案

拆分是**纯结构变更**，验证目标是"导入面等价 + 行为不变"：

1. `python -m ruff check .` —— 必须干净（尤其 `__init__.py` 的 F401，见风险 3）。
2. `python run_tests.py` —— **1116 个测试全绿**（拆分前后数量应完全一致）。
3. CLI 冒烟：`python cli.py --version` / `scan -r 127.0.0.1/32 --no-ports --no-mdns --format json`（确认没有误伤 import 链）。
4. **导入面等价断言**（建议写成一次性脚本，不必入库）：
   ```python
   import ui_dialogs
   need = {"DeviceEditDialog","MacLibraryDialog","HistoryCompareDialog","HistoryQueryDialog",
           "TopologyDialog","WmiCredentialDialog","SnmpV3CredentialDialog","ConflictReportDialog",
           "SubnetUtilizationDialog","AuditLogDialog","SwitchPortDialog","ChangeReportDialog"}
   assert need <= set(dir(ui_dialogs)), need - set(dir(ui_dialogs))
   ```
5. 结构校验：`ls ui_dialogs/` 为 8 个 `.py`；`git ls-files ui_dialogs.py` 为空（旧文件确已删除）。
6. 行尾校验：新文件必须是 **LF**（本仓库 `.md`/`.py` 皆为 LF；Windows 上写文本务必显式 `newline="\n"`）。

### 风险与对策

| # | 风险 | 对策 |
|---|---|---|
| 1 | `ui_dialogs.py` 与 `ui_dialogs/` **同名并存** → 导入解析不确定 | 同一次提交内删除旧文件；验证步骤 5 兜底。 |
| 2 | 行尾漂移（CRLF）→ 整文件级 diff | 写文件一律 `newline="\n"`；提交前 `grep -qU $'\r'` 探一遍。 |
| 3 | `__init__.py` 里 `from .x import Y` 被判 **F401 未使用** | 定义 `__all__ = [...]`。**已实测**（ruff 0.16.8）：不加 `__all__` 会报 `F401 .a.A imported but unused`；加了 `__all__` 后 `All checks passed!`。另一条等价写法是显式冗余别名 `from .x import Y as Y`（ruff 的报错文案自己就推荐了这个）。 |
| 4 | 子模块误抄原 39 行 import 头 → F401 一片 | 每个子模块只写自己用到的导入。 |
| 5 | 搬迁时"手滑"改了逻辑 | `git diff --color-moved` 复核；reviewer 只应看到移动，不应看到改写。 |

**回滚**：整体是一次提交，`git revert` 即可；不涉及数据/配置迁移。

---

## 7. 可选增强（**建议另开一次提交，不与纯搬迁混在一起**）

拆分后会出现 **8 处**高度重复的"报表型对话框"骨架（`setAlternatingRowColors` 实测 8 处），可在**第二次提交**里收进 `_shared.py`：

- `make_report_table(cols, widths, dark)`：统一 `setColumnCount / 表头 / NoEditTriggers / SelectRows / AlternatingRowColors / 隐藏行号 / StretchLastSection / 列宽`。
- `export_table_csv(parent, cols, rows, default_name, title)`：统一 **4 处** `csv.writer + utf-8-sig` 导出。
- `_NoContextHelpDialog(QDialog)`：统一 **10 处** `setWindowFlags(... & ~Qt.WindowContextHelpButtonHint)`。

预计可再减 **≈150 行**。**但会触及行为细节（列宽、编码、按钮文案），必须单独验证**，因此与纯搬迁分开提交。

---

## 8. 工作量与建议顺序

| 阶段 | 内容 | 规模 |
|---|---|---|
| A（本次方案） | 纯搬迁 + 改 2 个测试 + 文档 | 1 次提交，约 9 新增文件 / 1 删除 / 2 测试改动 |
| B（可选） | `_shared.py` 抽公共骨架 | 1 次提交，纯减重 |

**建议**：先做 A（低风险、可 review、立即把 1995 行拆到 490 行），B 视精力另起。

---

## 附：与既有评审的关系

- 本方案直接关闭 `docs/reviews/CODE_REVIEW.md` 的 **P1-4**（该文档已关闭，落地后再改其状态）。
- 与之并列的还有 `topology_discovery.py`（1509 行）的拆分（把纯函数 `layout_real_topology` 拆到 `topology_layout.py`）——**不在本方案范围内**，如需另开文档。
