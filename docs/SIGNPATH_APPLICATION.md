# SignPath Foundation 免费代码签名 —— 申请材料

> **目的**：让发行版带上**可与仓库相互验证**的签名，消掉「Windows 已保护你的电脑 / 未知发布者」。
> **依据**：`docs/ROADMAP_V1.8.md` §1.4 第 2 项 —— 审批有**外部等待期**，必须最早启动。
> **状态**：**待提交**。本文件只是可直接粘贴的申请材料；提交动作需要项目所有者完成。
> 提交前的仓库侧准备清单见 §4 —— **建议先做完 §4 再提交**。

---

## 1. 为什么现在就要提交

新版 SmartScreen 的信誉是**按「同一签名身份持续发布」累积**的，不是一次性买断。
今天开始签名，一年后才攒得出「持续发布」的历史；晚一年提交，就晚一年开始攒。
这也意味着签名身份一旦确定**不要更换** —— 换身份等于信誉清零重来。

> 这一条是本项目里少数「**早做比做得好更重要**」的事：其余三项（README / CHANGELOG /
> release 工作流）都是当天能完成的，唯独签名要等外部审批。

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

## 3. 申请时要填的四个字段（可直接粘贴）

提交入口：<https://signpath.org/apply.html>

| 字段 | 填写内容 |
|---|---|
| Project repository URL | `https://github.com/kooofy/IPScanner` |
| License | `GPL-3.0`（仓库根目录有 [`LICENSE`](../LICENSE)） |
| Download page URL | `https://github.com/kooofy/IPScanner/releases` |
| Description | 见下方引文 |

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
