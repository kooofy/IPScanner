# SignPath Foundation 免费代码签名 —— 申请材料

> **目的**：让发行版带上**可与仓库相互验证**的签名，消掉「Windows 已保护你的电脑 / 未知发布者」。
> **依据**：`docs/ROADMAP_V1.8.md` §1.4 第 2 项 —— 审批有**外部等待期**，必须最早启动。
> **状态**：**暂缓提交**（2026-10-10 决定）。材料已备齐、资格与前置条件也都满足，
> 但 `Reputation` 一栏拿不出使用量证据 —— 仓库 2026-10-10 才公开，
> stars / forks / 产物下载次数**全为 0**，且项目目前**只有维护者自己在用**。
> 按实提交大概率被要求补充材料或延后，故决定**先继续完善功能、积累真实反馈**再提交。
>
> **恢复提交的条件**（满足任一即可回来填表）：
> 1. 已在真实环境被使用（单位 / 公司 / 实验室 / 客户网络）—— 补上场景、规模、时长；
> 2. 公开后积累到可引用的下载量 / star / 社区讨论。
>
> **其余准备工作均已完成**：仓库已公开、Releases 有可免费下载的产物、
> `CODE_SIGNING_POLICY.md` 与 `CODE_OF_CONDUCT.md` 已入库、九个表单字段已备好（§3）。

---

## 1. 为什么现在就要提交

新版 SmartScreen 的信誉是**按「同一签名身份持续发布」累积**的，不是一次性买断。
今天开始签名，一年后才攒得出「持续发布」的历史；晚一年提交，就晚一年开始攒。
这也意味着签名身份一旦确定**不要更换** —— 换身份等于信誉清零重来。

> 这一条是本项目里少数「**早做比做得好更重要**」的事：其余三项（README / CHANGELOG /
> release 工作流）都是当天能完成的，唯独签名要等外部审批。
>
> ⚖ **但 2026-10-10 的实测数据让「立刻提交」变得不可行**：`Reputation` 一栏要求的
> 「被广泛使用或信任」的证据，本项目一条都拿不出（stars / 下载量全为 0，无媒体报道，
> 且只有维护者自己使用）。上面「越早越好」的逻辑针对的是**获批之后**的信誉累积；
> 而**获批之前**，申请材料本身得先过得了审核。两者冲突时只能先解决后者 ——
> 决定与恢复条件见本文顶部状态说明。

---

## 2. 资格自查（逐条对照）

SignPath Foundation 对开源项目的要求（来源：`signpath.org/apply.html`、`signpath.org`、
`foropensource.com`，以及一份 2026-02 的实操申请记录；核对日期 2026-10-10）：

| 要求 | IPScanner 现状 | |
|---|---|:---:|
| OSI 认可的开源许可 | GPL-3.0（[`LICENSE`](../LICENSE)） | ✅ |
| 仓库公开 | `github.com/kooofy/IPScanner` | ✅ |
| 持续开发 | `1.7.x` 发布线仍在推进（v1.7.6） | ✅ |
| 授予对象是**项目**而非个人 | 证书签发给 SignPath Foundation，项目侧只需署名 | ✅ |
| 构建可复现 | `IPScanner.spec` / `IPScanner_cli.spec` 均入库，CI 有打包验证 | ✅ |

免费档给的是 **OV 级证书**（签发主体是 SignPath Foundation，私钥存在其 HSM 上，不落本地），
支持签名 EXE / MSI / Docker 镜像 / Office 宏等，CI 侧支持 GitHub Actions / Azure DevOps / Jenkins。
本项目只需要 GitHub Actions —— 产物构建已经落在
[`.github/workflows/release.yml`](../.github/workflows/release.yml) 里了。

---

## 3. 申请时要填的表单字段（可直接粘贴）

提交入口：<https://signpath.org/apply.html>

| 字段 | 填写内容 |
|---|---|
| Homepage URL | `https://github.com/kooofy/IPScanner` |
| Project repository URL | `https://github.com/kooofy/IPScanner` |
| License | `GPL-3.0`（仓库根目录有 [`LICENSE`](../LICENSE)） |
| Download page URL | `https://github.com/kooofy/IPScanner/releases` |
| Tagline | `Open-source LAN scanner and asset inventory for Windows networks` |
| Category | `developer-tools` |
| Build System | `GitHub Actions` |
| Reputation | 见下方 §3.1 —— **本项目最弱的一栏，必须先读** |
| Description | 见下方引文 |

> ⚠ **`Homepage URL` 与 `Download page URL` 别填反**：前者是「项目主页」，
> 表单说明里明确写了「可以是专门网站，**也可以是仓库页**」—— 本项目没有独立官网，
> 填仓库页即可（同一行两栏填同一个 URL 是正常的，不是笔误）。
> 后者必须指向**能免费下载产物**的 Releases 页，别填仓库首页。

**`Tagline` 备选**（一句话、不带句号，会被展示在基金会官网上）：

1. `Open-source LAN scanner and asset inventory for Windows networks` ← 推荐，与现有项目风格一致
2. `Discover, identify and inventory every device on your local network — no cloud account required` ← 带上差异化卖点
3. `Scan your local network and inventory every device on it` ← 最短

**`Category` 的选项**（从基金会官网 `fdn-website` 的 `_data/projects.yml` 反推，332 个项目
实际用到的）：`developer-tools`（87）/ `gaming`（94）/ `productivity`（74）/ `science`（28）/
`graphics`（15）/ `audio`（11）/ `other`（10）/ `educational`（6）/ `accessibility`（6）。

选 **`developer-tools`** 的依据是**同类先例**，不是猜：

- `NETworkManager`（「A powerful tool for managing networks and troubleshoot network…」）
  —— 与 IPScanner 定位最接近，归在 `developer-tools`；
- 同档还有 `sniffnet`（流量监控）、`dnsmonster`（被动 DNS）、`Smartmontools`、
  `OpenModScan`（Modbus 工具）—— 都是面向技术用户的网络/诊断工具；
- `productivity` 那档收的偏消费级（`NetSpeedTray` 任务栏网速、条码工具、IRC 客户端）。

> IPScanner is an open-source LAN scanning and asset-inventory tool for
> Windows-centric networks, written in Python + PyQt5 and licensed under GPL-3.0.
> It ships a desktop GUI and a headless CLI from the same scanning engine.
> Distribution is two PyInstaller artifacts built on GitHub Actions: an onedir GUI
> bundle (`IPScanner_<version>-win64.zip`) and a single-file CLI
> (`IPScanner_cli_<version>.exe`).
>
> We are applying because unsigned downloads trigger SmartScreen's "Windows protected
> your PC" prompt, and because this tool legitimately sends ICMP / ARP / TCP / UDP
> probes and reads WMI over the network — behaviour that antivirus heuristics also
> flag. A signature tied to our public repository would let users verify that the
> binary they run was actually built from that repository.
>
> The build recipes (`IPScanner.spec`, `IPScanner_cli.spec`) and the release workflow
> are committed, so the release build is reproducible from the tagged source.

### 3.1 `Reputation` —— 本项目最弱的一栏（诚实评估）

**实测数据（2026-10-10，用 GitHub API 拉的，不是估计）**：

| 指标 | 值 |
|---|---|
| 仓库创建 | 2026-07-17 |
| **转为公开** | **2026-10-10（就是今天）** |
| stars / forks / watchers / subscribers | **0 / 0 / 0 / 0** |
| Releases 数量 | 9（v1.0 → v1.7.7） |
| **产物下载次数** | **0**（私有期间根本下载不了） |
| 媒体报道 / 博客 / 社区讨论 | **无**（搜过，命中的全是同名但无关的工具） |

**结论：这一栏目前拿不出任何「被广泛使用」的证据，而且原因很明确 ——
仓库今天才公开，在此之前外部根本无法使用它。** 不要试图用无关数据凑数：
审核方点开链接就能看出 stars/downloads 是 0，硬编反而更糟。

**可以如实写的（工程可信度，不是使用量 —— 但正是签名要担保的那个性质）**：

> IPScanner was developed in a private repository until 2026-10-10, when it was
> published under GPL-3.0; external usage metrics are therefore not yet meaningful.
> What the project can demonstrate is verifiable engineering provenance:
>
> - 69 commits over 84 days of continuous development (2026-07-18 → 2026-10-10),
>   with 9 tagged releases (v1.0 → v1.7.7).
> - 1,135 automated tests across 57 test files, run on every push.
> - Public CI across three platforms — Python 3.10–3.13 on ubuntu-latest and
>   macos-latest, plus Windows PyInstaller packaging verification:
>   https://github.com/kooofy/IPScanner/actions
> - Reproducible release builds: the PyInstaller recipes (`IPScanner.spec`,
>   `IPScanner_cli.spec`) and the release workflow are committed, and every release
>   publishes `SHA256SUMS.txt`:
>   https://github.com/kooofy/IPScanner/releases
> - Full public commit history from the first commit; the only maintainer is the
>   sole author of record.

**⚠ 若本项目已在真实环境里被使用**（单位 / 公司 / 实验室 / 客户网络等），
**一定要补上这一条 —— 它是目前唯一真实可用的「使用量」证据**，比上面所有工程指标
都更有说服力。写法：说明场景、规模、使用时长，并指明可核实的联系人身份。

**另一条路**：若希望这一栏更有分量，可先公开一段时间积累真实下载与反馈，再提交申请。
代价是审批本来就有的等待期还要往后推。

---

## 4. 提交前的加分准备（建议先做完再提交）

申请表单本身不难填，但**审核方要能方便地评估你的项目**。一份 2026-02 的实操记录
（同样是单人维护的 Windows 桌面项目）总结出下面这些准备，能明显提高通过率：

| 准备项 | 作用 | IPScanner 现状 |
|---|---|:---:|
| 仓库根目录有 `LICENSE` | 证明是 OSI 许可 | ✅ 已有 |
| README 讲清「是什么 / 从哪下载 / 怎么构建」 | 审核方判断产物来源 | ✅ 已有 |
| CI 工作流公开 | 证明产物确实由本仓库构建 | ✅ `release.yml` |
| GitHub Releases 有可免费下载的产物 | 程序硬性要求「发行版可免费下载」 | ⏳ 需先发一版 |
| **`CODE_SIGNING_POLICY.md`（代码签名政策）** | 说明「签什么、谁有权批准签名」 | ❌ 待建 |
| **`CODE_OF_CONDUCT.md`（行为准则）** | 证明项目按开源项目方式运营 | ❌ 待建 |
| **可收信的联系邮箱** | 审批沟通主要走邮件 | ⚠ 需确认 |

其中**代码签名政策是审核重点**：SignPath 的签名是**逐次审批**的，它必须知道在你这个
项目里**谁有权批准一次签名**。单人维护的项目，把维护者同时列进三个角色即可。

程序要求的署名声明（获批后必须原样出现）：

> Free code signing provided by SignPath.io, certificate by SignPath Foundation

---

## 5. 提交之后

1. **在 <https://signpath.org/apply.html> 提交** —— 这一步需要项目所有者操作，本文件无法代劳。
   审核期间可能收到补充提问，**保持邮箱畅通**。
2. 获批后：在 SignPath 里建项目 → 接 GitHub 集成 → 设计签名政策（逐次审批）。
3. 把签名步骤接到 `release.yml` 的**「构建」与「打包」之间**：
   必须先签 exe、再 `Compress-Archive`；顺序反了签的就是压缩包本身（无效）。
   仓库里两个产物分别对应 `IPScanner.spec` 产出的 exe 与 `IPScanner_cli.exe`。
4. 把程序要求的署名声明写进 Release 说明与下载页（`--generate-notes` 之外补一行）：
   `Free code signing provided by SignPath.io, certificate by SignPath Foundation`
5. **首个带签名的版本另起一个 `1.7.N`**，不要复用已发布的 v1.7.6。

---

## 6. 注意事项

- **不要买 EV 证书**：2024 年起微软取消了 EV 的「即时免警告」特权，SmartScreen 信誉改为
  按文件 / 下载量累积，OV 与 EV 的新签名文件都得等信誉，而 EV 价格是 OV 的数倍。
  ✅ 本条**已于 2026-10-10 联网复核**（多个独立来源结论一致），原先标注的「未复核」已解除；
  真正掏钱前仍建议自己再看一眼最新政策。
  （该结论最初来自 `docs/PRODUCT_ADVISORY.md` §1.4，勘误见
  [`docs/reviews/PRODUCT_ADVISORY_REVIEW.md`](reviews/PRODUCT_ADVISORY_REVIEW.md) §4。）
- 免费档覆盖的是 **Windows Authenticode**（EXE / MSI 等）；**macOS 公证（notarization）**
  是 Apple 的另一条路，不在本次范围内。
- 签名不改变杀软**启发式**误报的根因（本项目用原始套接字 + WMI + `net view`，本就是 EDR
  高敏组合）—— 它解决的是「未知发布者」与「来源不可验证」，不是「行为像恶意软件」。
