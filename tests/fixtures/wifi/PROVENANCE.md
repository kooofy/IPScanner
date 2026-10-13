# Wi-Fi fixture 来源

采集机：Windows 11 (10.0.26100)、简体中文系统、Intel(R) Wi-Fi 6 AX201 160MHz。
采集时间：2026-10-13（`networks_radio_off.txt` 为同日无线关闭时采的）。

| 文件 | 真机采集 | 说明 |
|---|---|---|
| `interfaces.txt` | ✅ | `netsh wlan show interfaces`，**已连接** QZTJXX / 5 GHz / 信道 157 |
| `networks_bssid.txt` | ✅ | `netsh wlan show networks mode=bssid`，5 个 SSID、多个 BSSID |
| `profiles.txt` | ✅ | `netsh wlan show profiles` |
| `drivers.txt` | ✅ | `netsh wlan show drivers` |
| `networks_radio_off.txt` | ✅ | 无线被**关闭**时的 `show networks` 报错文本（守 radio-off 路径） |
| `roaming_events.xml` | ✅ | `wevtutil qe Microsoft-Windows-WLAN-AutoConfig/Operational /f:xml`；**最新 24 条 + 1 条较早的 8002**（关联失败） |
| `ipconfig.txt` | ✅ | `ipconfig`，用来给「无线网卡 ↔ 网段」关联提供**带适配器名**的输入 |
| `interfaces_en.txt` | ❌ 构造 | 英文界面下的 `show interfaces`：本机是 zh-CN 系统，**产不出** en-US 的 netsh 文案 |
| `networks_bssid_en.txt` | ❌ 构造 | 同上（`show networks mode=bssid` 的英文形态） |
| `interfaces_wide_pad.txt` | ❌ 构造 | 由 `interfaces.txt` 改宽分隔空白 / 换成制表符，守「列宽被系统改过也不脆」 |
| `interfaces_disconnected.txt` | ❌ 构造 | 断开态：字段集合按 netsh 断开时的真实形态（无 SSID/BSSID/波段/信道/信号） |
| `ipconfig_en.txt` | ❌ 构造 | 英文界面下的 `ipconfig`（同上，产不出 en-US 文案） |

**为什么要构造那三份**：本机是简体中文系统，`netsh` 的**文案随系统语言变**，
而本项目要保证英文系统上也能解析 —— 只能按 netsh 的字段名形态构造。
构造样本**只用来验"标签表覆盖 + 形状兜底"**，真样本才是解析正确性的判据。
