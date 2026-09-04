<div align="center">

<img src="work/CodexGuardian/Assets/CeasyLogo.png" width="120" alt="Ceasy">

# Ceasy

**盯住 Codex Desktop 的每个任务，中断了按证据决定要不要替你续上**

[![Release](https://img.shields.io/github/v/release/chen0416ccc-cpu/Ceasy?style=flat-square&label=Release&color=2ea44f)](https://github.com/chen0416ccc-cpu/Ceasy/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chen0416ccc-cpu/Ceasy/total?style=flat-square&label=Downloads)](https://github.com/chen0416ccc-cpu/Ceasy/releases)
[![License](https://img.shields.io/github/license/chen0416ccc-cpu/Ceasy?style=flat-square&label=License&color=blue)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011%20x64-0078D6?style=flat-square&logo=windows&logoColor=white)](#系统要求)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=dotnet&logoColor=white)](#系统要求)

[![Download](https://img.shields.io/github/v/release/chen0416ccc-cpu/Ceasy?style=for-the-badge&label=Download&color=2ea44f&logo=windows&logoColor=white)](https://github.com/chen0416ccc-cpu/Ceasy/releases/latest)

安装包自带 .NET 8 运行时 · per-user 安装不弹 UAC · 界面中文，可切英文

</div>

---

Codex Desktop 的长任务会因为 provider 侧的 429、服务过载或网络断流而中断。人不在电脑前的时候，任务就一直停在那里，等你回来才发现要重新起一遍。

Ceasy 在后台观察每条任务的真实终态，中断后判断这次**是不是真的可以安全续上**——能续就在原任务里续，不能续就明确停下来等你处理。它不改 Codex：不替换安装包、不重签名 MSIX、不注入进程、不改 ASAR 或 JavaScript，也不写 Codex 的状态数据库和会话记录。

## 它做什么

- **按证据判断，不猜** —— 续不续取决于任务自己的终态证据：中断前有没有产生过输出、是不是 HTTP 429、原始输入能不能完整重放。证据不完整就闭锁不发。
- **在原任务里续** —— 恢复消息由 Codex Desktop 自己的窗口在原会话里发出，你在 Codex 界面看到的是同一条流式输出，不存在另一个看不见的会话抢走输出。
- **不该续的绝不续** —— 401/403、认证失败、额度不足、内容策略、上下文超限、以及你自己按的停止，一律标记待人工检查。
- **预制消息** —— 给某个任务排好几条有序消息，设定「正常完成后发」或「指定本地时间发」，每条都要通过目标任务、owner、编辑状态和 at-most-once 账本的复核。
- **默认只监测** —— 自动恢复要你自己打开，升级旧配置也会把它切回只监测。
- **本地运行** —— 不上传遥测，不保存 API 密钥，对 Codex 的会话目录只读。

<details>
<summary><b>完整的判定规则表</b></summary>

<br>

| 中断的样子 | Ceasy 的动作 |
| --- | --- |
| 中断前已经有助手回复、推理或工具输出 | 在原任务里追加一条 `continue`，把工作接下去 |
| 明确是 HTTP 429、且一点工作都没产生、原始输入可完整重放 | 按「已确认未提交」把原消息重发一次 |
| 其他「消息没有得到回应」的情况 | 归类为需要重发，但**闭锁不发** —— 当前 Desktop 没有非破坏性的原生重发通道，追加一条相同消息会变成重复发言 |
| 401/403、认证失败、额度不足、内容策略、上下文超限 | 不发，标记为需要人工检查 |
| 用户自己按了停止 | 不发 |
| 证据不完整（item 类型、输入边界或 summary 缺失） | 显示「证据不足」并闭锁，不做猜测性发送 |

</details>

## 安装

到 [Releases](https://github.com/chen0416ccc-cpu/Ceasy/releases/latest) 下载 `Ceasy-<版本>-Setup.exe`，双击运行。

装到 `%LocalAppData%\Programs\Ceasy`，**不弹 UAC**，不需要管理员账号，安装目录可以在向导里改到别的盘（自带运行时，装完约 150 MB）。卸载时会问一次要不要删掉设置和运行记录，默认保留。

装好后打开，**默认是只监测**——自动恢复需要你自己到界面里打开。

### 校验下载的文件

每个 release 都附带 `SHA256SUMS.txt`。在下载目录里跑：

```powershell
Get-FileHash .\Ceasy-2.0.0-Setup.exe -Algorithm SHA256
```

把输出的 `Hash` 和 `SHA256SUMS.txt` 里的值对一下，一致就说明文件与发布时的字节完全相同。没有 PowerShell 的话，`certutil -hashfile Ceasy-2.0.0-Setup.exe SHA256` 是等价的。这个校验和由构建脚本直接从产物算出，不是手工填的。

安装包未做代码签名，首次运行时 Windows 会弹 SmartScreen 提示，点「更多信息」→「仍要运行」继续。

## 系统要求

- Windows 10 或 Windows 11，x64
- 官方 Codex Desktop，已正常登录并注册了 `codex://` 协议（不需要对它做任何改动）
- 不需要预装 .NET——安装包自带完整的 .NET 8 运行时

Ceasy 走的是 Codex Desktop 的内部协议方法，它们不是公开 API，Codex 更新后可能改名或改结构。遇到不认识的版本时 Ceasy 保持只监测并如实显示不兼容，不会去改 Codex 来「兼容」。

## 联网行为与数据

**唯一的出站请求是版本检查**：每天最多一次 `GET https://api.github.com/repos/<owner>/<repo>/releases/latest`，只读 `tag_name`、`draft`、`prerelease` 三个字段。可在**设置 → 检查新版本**关闭，关掉之后不发出任何请求。

除此之外不上传遥测、不上报使用情况、不保存 API 密钥。对 Codex 的会话目录只读，不写 `state_5.sqlite`、不写 rollout、不改任务内容。设置、日志、恢复账本都在 `%LOCALAPPDATA%\CodexGuardian` 下。

<details>
<summary><b>版本检查请求的完整形态，以及日志里到底记了什么</b></summary>

<br>

请求头只带一个编译期常量的 User-Agent（`Ceasy/<版本> (+<仓库地址>)`，不含机器名、用户名或任何本机信息）、`Accept` 和固定的 `X-GitHub-Api-Version`，不带 cookie、不带凭据、不带请求体。响应里的 `html_url` 一律丢弃——界面上能打开的地址始终是编译期常量拼出来的，不是应答方给的。

本地日志和账本只记任务/轮次的短哈希、证据布尔值、分类和门禁阶段，**不记消息正文、标题、provider 原始错误、路径或凭据**。完整的数据位置清单见 [work/CodexGuardian/README.md](work/CodexGuardian/README.md) 的「数据位置」。

信任边界是「同一个 Windows 用户会话」：程序会校验命名管道对端的 PID、用户 SID、包族名和安装路径，但不声称能抵御管理员权限、内核级攻击或同用户下的恶意代码。

</details>

## 文档

- [work/CodexGuardian/README.md](work/CodexGuardian/README.md) —— **权威说明**。完整的行为契约、恢复规则表、事件驱动监测机制、磁盘与资源边界、安全边界都在这里。
- [CONTRIBUTING.md](CONTRIBUTING.md) —— 从源码构建、跑离线测试套件、构建安装包。

## 许可

[MIT](LICENSE)。

安装包里附带的第三方软件（.NET 8 运行时、`System.Security.Cryptography.Pkcs`、Inno Setup 6、Inno Setup 的简体中文语言文件）各自的版权与完整许可正文见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。这两个文件也会随程序装进安装目录。

---

<sub>第三方工具，与 OpenAI 无隶属关系。</sub>
