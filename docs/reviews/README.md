# 评审文档归档

> 这里存放 IPScanner 历次**代码 / 界面评审**与**文档复核**的历史记录。
> 四份文档**均已关闭**，只作存档，不再更新。
> 发现新问题请另开一份新文档，**不要**往这里的文件追加条目。
> （例外：条目的**落地状态**会随实现推进就地更正，逐条见 §3 / §5 的「更正 / 更新 /
> 定性」注 —— 那是状态同步，不是新意见。）

归档时间：2026-10-09 ｜ 归档时版本：v1.7.4
更正：2026-10-09（v1.7.5）修正 P2-4 的错误结论 —— 三平台 CI 实为 `db84b58` 已落地，详见 §3。
更新：2026-10-10 P1-4（`ui_dialogs.py` 拆分）落地 —— 已拆为 `ui_dialogs/` 包，详见 §3。
新增：2026-10-10 `PRODUCT_ADVISORY_REVIEW.md` —— 对 `docs/PRODUCT_ADVISORY.md`（v1.7.6 建议书）
17 项 `[实测]` 声明的逐条复核，结论 16 属实 / 1 有误。
定性：2026-10-11 CODE_REVIEW 最后 2 项（P2-3 / P2-5）改为「不按原方案做」——
P2-5 经复核无需执行、P2-3 改「声明式数据扩展」，未落地项归零，详见 §3。

---

## 1. 文档清单

| 文档 | 评审对象 | 评审日期 | 状态 | 关闭版本 |
|---|---|---|---|---|
| [`CODE_REVIEW.md`](CODE_REVIEW.md) | `f15341a`（v1.6.0） | 2026-10-06 | **已关闭** | v1.7.4 |
| [`UI_REVIEW.md`](UI_REVIEW.md) | `db84b58`（v1.6.0） | 2026-10-08 | **已关闭** | v1.7.4 |
| [`UI_REVIEW_ROUND2.md`](UI_REVIEW_ROUND2.md) | `638c462`（UI 改造 P0–P3） | 2026-10-09 | **已关闭** | v1.7.4 |
| [`PRODUCT_ADVISORY_REVIEW.md`](PRODUCT_ADVISORY_REVIEW.md) | `docs/PRODUCT_ADVISORY.md`（v1.7.6 建议书） | 2026-10-10 | **已关闭** | v1.7.6 |

第二轮界面验收的实机截图证据在同级目录 **`../ui-review-round2/`**（18 张）。

---

## 2. 为什么要归档并标注「已关闭」

这三份文档原本放在仓库根目录，且用的是「待办」口吻。问题是：

- 条目做完了，文档却还写着"建议…"，**下一个读的人（或下一轮的人）会把已定的事再争一遍**；
- 根目录躺着三份 `*_REVIEW.md`，看起来像"当前待办清单"，实际是历史。

所以本轮做了两件事：**统一加「已关闭」状态横幅** + **移入 `docs/reviews/`**。
根目录只保留 `README.md`。

---

## 3. CODE_REVIEW.md 落地对照

12 项意见中 **10 项已落地**，2 项经复核后**定性为不按原方案做**（**已确认，不要再当"遗漏"重提**）。

### 已落地（10 项）

| 编号 | 事项 | 落地位置 |
|---|---|---|
| P0-1 | `_syn_failed` / `_raw_cap_cache` 跨模块未共享 | `scanner/constants.py` 改用 `threading.Event()`；`ports.py` / `engine.py` 统一走 `_C.` 属性访问 |
| P0-2 | IPv6 被静默接受 → 假"全离线"结果 | `scanner/range.py` 显式版本闸门（`net.version != 4`），另有 `is_ipv6_range()` 供提示分流 |
| P0-3 | `requirements-dev.txt` 里 spec 文件名过期 | 已改为 `pyinstaller IPScanner.spec` |
| P1-1 | 端口扫描线程池反复新建（最坏 3200+ 线程） | `bounded_pool.py` |
| P1-2 | ping 走子进程，与竞品有速度代差 | `scanner/ping.py`（原生 ICMP） |
| P1-3 | `scan()` 400 行，扩展需改核心 | `scanner/engine.py` 重构 + `models.py` / `constants.py` 拆分 |
| P1-4 | `ui_dialogs.py` 拆分（评审时 1747 行） | 已拆为 `ui_dialogs/` 包（8 子模块 + `__init__` re-export 门面），方案见 `docs/refactor/ui_dialogs_split_plan.md` |
| P2-1 | 定时扫描 + 变更告警 | `scheduler.py` / `change_detector.py` / `notifier.py` |
| P2-2 | 服务版本指纹库 | `service_fingerprints.py` |
| P2-4 | macOS / Linux CI | `ci.yml` 的 `test-cross-platform` job（`ubuntu-latest` + `macos-latest`），由 `db84b58` 落地 |

### 未按原方案做（2 项，已定性）

| 编号 | 事项 | 现状 |
|---|---|---|
| P2-3 | 插件 / Fetcher 机制 | **改为「声明式数据扩展」** —— 不做 `plugins/` 目录与插件加载器。可扩展的部分一律收敛成**数据**：`oui.db`（OUI 库）、`mac_library.db`（地址库）、`service_fingerprints.py` 的指纹表、`risk_rules.py` 的规则表、`scan_presets`。**改数据不用改代码**，也就没有"插件 API 兼容性"这份长期负担 |
| P2-5 | `oui.db` 入 Git LFS | **经复核无需执行** —— `oui.db` 只有 **2.0 MB**。Git LFS 的代价不是存储，而是给**每一个** clone 引入 `git-lfs` 依赖（含三平台 CI 与 PyInstaller 打包流程），为一次性的 2 MB 付长期复杂度，收益与代价不成比例 |

> **更正（2026-10-09，v1.7.5）**：归档时把 **P2-4 记为「未做」是错的**。
> `ci.yml` 早已有 `test-cross-platform` job（`ubuntu-latest` + `macos-latest`），
> 由 `db84b58`（「代码评审后的一轮改进」）加入 —— 正是关闭其余 8 项的那个提交
> （`git merge-base --is-ancestor f15341a db84b58` = YES，证明它在评审之后）。
> 本次已把它移入「已落地」。其余 3 项「未做」经逐条核实属实。
>
> **更新（2026-10-10）**：**P1-4 已落地** —— `ui_dialogs.py`（1995 行）拆为
> `ui_dialogs/` 包（8 子模块 + re-export 门面，最大文件 484 行），
> 4 个 Mixin 与全部测试的导入面保持不变。方案与验证见
> `docs/refactor/ui_dialogs_split_plan.md`。未落地项从 3 → **2**（P2-3 / P2-5）。
>
> **定性（2026-10-11，v1.7.x）**：剩下的 2 项从"待办"改为"**已定性 —— 不按原方案做**"。
>
> - **P2-5 无需执行**：原建议书自己也标了「优先级低，属洁癖级优化」。2 MB 的
>   二进制在 clone 成本上可以忽略，而 LFS 会把"能直接 clone 就跑"变成
>   "先装 git-lfs"，对开源项目的采纳摩擦是**净增**。
> - **P2-3 改口径**：插件机制的护城河价值成立，但代价是**插件 API 的兼容性承诺**
>   —— 对单人维护者，这等于把"内部实现"变成"对外契约"，此后每次重构都要背。
>   本项目真正需要的是"用户能加自己的设备库 / 规则 / 指纹"，而那已经由数据文件
>   提供了（见上表）。**能力不缺，缺的只是"插件"这个名字。**
>
> 未落地项从 2 → **0**（P2-3 / P2-5 均已定性）。

---

## 4. UI_REVIEW.md 落地对照

**全部落地**：P0-1~2、P1-1~4、P2-1~4（共 10 项）+ P3 的 4 个差异化方向。

| 编号 | 事项 | 落地位置 |
|---|---|---|
| P0-1 | 详情面板（QSplitter 主从布局） | `detail_panel.py` |
| P0-2 | 空状态 + 扫描态摘要条 | `empty_state.py` / `scan_status.py` |
| P1-1 | 工具栏图标加文字 + 动作分组 | `main_window._init_toolbar()` |
| P1-2 | 13 列 → 列预设 | `main_window.COLUMN_PRESETS` |
| P1-3 | 扫描预设 + 设备收藏 | `scan_presets.py` / `favorites.py` |
| P1-4 | 筛选条常驻 + 计数 | `filter_bar.py` |
| P2-1 | 视觉令牌（圆角 / 间距 / 行高） | `theme_tokens.py` / `design_tokens.py` |
| P2-2 | 内联样式迁到 QSS | 4 个新模块零内联 `setStyleSheet`；`ui_dialogs.py` 硬编码色 20 → 5（余 5 处是拓扑绘图的半透明描边，本就与主题无关） |
| P2-3 | 右键菜单按动作语义分组 | `main_window_tree._show_context_menu()` |
| P2-4 | 高 DPI / 最小窗口 | `setDevicePixelRatio`；最小窗口 1024×640 |
| P3-1 | 变更时间线（常驻 chip + 行内角标） | `history_store.device_timeline()` + `ui_logic.build_change_index()` |
| P3-2 | 概览仪表盘 + 列表/概览视图切换 | `overview.py` + `main_window.VIEW_MODES` |
| P3-3 | 跟随系统深浅色 | `system_theme.resolve_dark()` |
| P3-4 | 风险列 / 评分 | `risk_rules.py` |

---

## 5. UI_REVIEW_ROUND2.md 落地对照

**9 项全部修复**，由 v1.7.1 → v1.7.4 四个版本关闭。

| 编号 | 事项 | 落地位置 | 回归测试 |
|---|---|---|---|
| P0-1（续） | 深色下服务子项 / 制造商列不跟随主题 | `main_window_tree._refresh_child_marks()`、`main_window._link_color()` 改走 `token()` | `test_theme_marks.py` |
| P0-4 | 93 处 `QMessageBox` 按钮仍是英文 | `ui_msg.py` 集中本地化 | `test_msg_buttons.py` |
| 新增 P1 | 切语言后列宽不重算 → 多列截断 | `table/header_lang` 语言戳 + `_COLUMN_WIDTH_OVERRIDES`（同语言不重算） | `test_column_widths.py` |
| 新增 P1 | 状态栏右侧整段漏翻 | 4 条 f-string 改带占位符的 `tr()` | — |
| P2 | 空状态页主次按钮 / 隐藏筛选条 / 概览页留白 / 默认排序 / `ui_dialogs` 硬编码色 | `empty_state.py`、`_update_result_controls()`、`overview.py` 等 | `test_result_controls.py` |

---

## 6. 引用约定（重要）

代码与测试的注释里引用本目录文档时，**一律写带路径的形式**：

```
docs/reviews/UI_REVIEW.md P3-2
docs/reviews/CODE_REVIEW.md P2-14
```

历史上存在过 `UI_REVIEW P3-2` 这种**不带路径**的短引用（评审文档还在仓库根目录时留下的）。
本次归档已把它们批量补齐路径。若你仍看到不带路径的旧引用，它指的就是本目录里的同名文档。

> 注意：`UI_REVIEW.md` 与 `UI_REVIEW_ROUND2.md` 是**两份不同**的文档 ——
> 前者是 2026-10-08 的第一轮界面评审，后者是 2026-10-09 对改造结果的第二轮验收。
> 引用时不要混用编号。
