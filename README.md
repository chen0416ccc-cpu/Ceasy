# Ceasy

![许可](https://img.shields.io/badge/license-MIT-blue)
![平台](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue)
![框架](https://img.shields.io/badge/.NET-8.0--windows-blue)

**Ceasy 是面向 Windows 版 Codex Desktop 的本地多任务观察与受控恢复工具。**
它在后台盯住多个任务的真实终态，发现网络断流、服务过载、静默完成或普通中断后，
按证据决定要不要替你把那条任务续上去。

*A local watchdog for Codex Desktop on Windows: it observes real per-task terminal
state and, only with your authorization, resumes tasks that died on a transient
failure. Chinese-first UI, English available. No patching of Codex.*

它不改 Codex。不替换安装包、不重签名 MSIX、不注入进程、不修改 ASAR 或 JavaScript，
不写 Codex 的状态数据库和会话记录。所有恢复消息都由 Codex Desktop 自己的窗口在原任务里
发出，所以你在 Codex 界面看到的是同一条流式输出，不存在另一个看不见的会话抢走输出。

## 它解决什么问题

Codex Desktop 的长任务会因为 provider 侧的 429、服务过载或网络断流而中断。人不在电脑前的时候，
任务就一直停在那里，等你回来才发现要重新起一遍。Ceasy 做的是：观察到中断后，判断这次中断
**是不是真的可以安全续上**，能续就续，不能续就明确停下来等你处理。

判断的依据是任务自己的终态证据，不是猜：

| 中断的样子 | Ceasy 的动作 |
| --- | --- |
| 中断前已经有助手回复、推理或工具输出 | 在原任务里追加一条 `continue`，把工作接下去 |
| 明确是 HTTP 429、且一点工作都没产生、原始输入可完整重放 | 按「已确认未提交」把原消息重发一次 |
| 其他「消息没有得到回应」的情况 | 归类为需要重发，但**闭锁不发** —— 当前 Desktop 没有非破坏性的原生重发通道，追加一条相同消息会变成重复发言 |
| 401/403、认证失败、额度不足、内容策略、上下文超限 | 不发，标记为需要人工检查 |
| 用户自己按了停止 | 不发 |
| 证据不完整（item 类型、输入边界或 summary 缺失） | 显示「证据不足」并闭锁，不做猜测性发送 |

除此之外还有**预制消息**：给某个任务排好几条有序消息，设定「正常完成后发」或「指定本地时间发」，
每条都要通过目标任务、owner、编辑状态和 at-most-once 账本的复核才会真的发出去。

默认状态是**只监测**。自动恢复要你自己到界面里打开，升级旧配置也会把它切回只监测。
界面默认简体中文，可在设置里即时切换英文。

完整的行为契约、恢复规则表、事件驱动监测机制、磁盘与资源边界、安全边界，
都写在 [work/CodexGuardian/README.md](work/CodexGuardian/README.md) —— 那份是权威说明，
这里只是入口。

## 系统要求

- Windows 10 或 Windows 11，x64
- 官方 Codex Desktop，已正常登录并注册了 `codex://` 协议（不需要对它做任何改动）
- 不需要预装 .NET —— 安装包自带完整的 .NET 8 运行时

## 安装

到 [Releases](https://github.com/chen0416ccc-cpu/Ceasy/releases/latest) 下载
`Ceasy-<版本>-Setup.exe`，双击运行即可。

安装是 per-user 的：装到 `%LocalAppData%\Programs\Ceasy`，**不弹 UAC**，也不需要管理员账号。
安装目录可以在向导里改到别的盘（自带运行时，产物大约 150 MB，系统盘紧张时用得上）。
卸载时会问一次要不要删掉设置和运行记录，默认保留。

也可以[从源码自己构建安装包](#从源码构建)。

## 为什么会弹「未知发布者」

这个安装包**没有做代码签名**，所以 Windows 首次运行时会显示 SmartScreen 的
「Windows 已保护你的电脑」提示。要继续的话点「更多信息」→「仍要运行」。

不签名是当下的取舍，不是遗漏：

- OV 代码签名证书从 2023 年 5 月起要求私钥存在硬件（HSM 或 USB 令牌）里，第三方转售价约
  每年 216 美元起。
- 2026 年 3 月 1 日起，CA/Browser Forum 把代码签名证书的最长有效期压到 458 天；
  DigiCert 从 2026 年 2 月 15 日起只发 1 年期。也就是这笔钱每年都要付一次。
- 关键的一点：**OV 证书并不会立刻消掉 SmartScreen 警告。** SmartScreen 看的是这个签名身份
  累积的下载信誉，新证书要先攒够量。只有 EV 证书能立即通过，而它更贵。对一个刚开源、
  还没有下载量的项目来说，签了名很可能还是弹同样的框。
- [SignPath Foundation](https://signpath.org/) 给开源项目免费签名，但要求项目
  「已经发布」并具备可验证的声誉，且没有独立申诉机制 —— 现在申请几乎必被拒。
  等这个项目真的有人用了会去申请。

在那之前，用下面的办法确认你下载的文件没被动过手脚 —— 这比一个新证书能提供的保证更硬。

## 校验下载的文件

每个 release 都附带 `SHA256SUMS.txt`，里面是安装包的 SHA-256。在下载目录里跑：

```powershell
Get-FileHash .\Ceasy-2.0.0-Setup.exe -Algorithm SHA256
```

把输出的 `Hash` 和 `SHA256SUMS.txt` 里的值对一下，一致就说明文件与发布时的字节完全相同。
没有 PowerShell 的话，`certutil -hashfile Ceasy-2.0.0-Setup.exe SHA256` 是等价的。

这个校验和由 [work/build-installer.ps1](work/build-installer.ps1) 在编译安装包时直接从产物算出，
不是手工填的。

## 从源码构建

需要 **.NET SDK 8.0.418**，而且是这个精确的补丁号：`work/global.json` 里写着
`"rollForward": "disable"`，手上是 8.0.4xx 里别的补丁号也会直接报「找不到兼容的 SDK」。
钉死它是为了发布 —— `check-release-baselines.ps1` 校验的那批运行时文件会随 SDK 补丁漂移，
换个补丁号编出来的产物过不了基线校验。[.NET 8 下载页](https://dotnet.microsoft.com/download/dotnet/8.0)
按补丁号列出了历史版本。

只想编出来跑一下、不打算做发布验收的话，把 `work/global.json` 的 `rollForward` 改成
`latestPatch` 就能用手上的 SDK 编 —— 那样编出来的能跑，但别拿它当发布产物。

只想跑程序本身：

```powershell
dotnet build work\CodexGuardian\CodexGuardian.csproj -c Release -r win-x64
```

要做出安装包，还需要 Inno Setup 6：

```powershell
winget install --id JRSoftware.InnoSetup --exact
```

然后：

```powershell
pwsh -File work\build-installer.ps1 -StagingRoot D:\ceasy-build
```

`-StagingRoot` 是发布产物、TEMP 和 setup.exe 的落地根目录，指向哪个盘都行。
不传的话默认是 `D:\CodexData\CodexGuardian\installer-staging` —— 那是这个仓库自己的写策略
（构建产物不占系统盘）留下的默认值，机器上没有 D 盘时必须显式指定。
脚本跑完会打印安装包路径与 SHA-256，并在输出目录里写好 `SHA256SUMS.txt`。

### 测试

测试是一批离线契约套件，按主题分组，用一个 `--<主题>-offline-only` 开关选择要跑哪一组。
它们不联网、不启动界面、不碰真实的 Codex。

跑之前必须先指定测试数据落在哪里。这批套件不会自己挑目录，缺 `CODEX_GUARDIAN_TEST_DATA_ROOT`
会让上百个用例直接以「is required」失败：

```powershell
$env:CODEX_GUARDIAN_TEST_DATA_ROOT = 'D:\ceasy-test-data'
$env:TEMP = 'D:\ceasy-temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:CODEX_GUARDIAN_TEST_DATA_ROOT, $env:TEMP | Out-Null

dotnet build work\CodexGuardian.Tests\CodexGuardian.Tests.csproj -c Debug -r win-x64
.\work\CodexGuardian.Tests\bin\Debug\net8.0-windows\win-x64\CodexGuardian.Tests.exe --workflow-automation-offline-only
```

必须从仓库根目录启动 —— 有几个套件会读源码文件来校验静态契约。
可用的开关名列在 [work/CodexGuardian.Tests/Program.cs](work/CodexGuardian.Tests/Program.cs)；
不带任何开关就是全量运行。

**已知限制：上面那两个目录目前必须在 D 盘。** 测试基础设施里有多处断言把测试数据根钉死在
`D:\` 前缀上，几个开发期门禁工具也这样要求。它们的本意是执行本仓库「构建与测试产物不占
系统盘」的写策略，却把「非系统盘恰好叫 D」写成了硬条件，所以在没有 D 盘的机器上这批套件
起不来。这是待清理项，**只影响跑测试，不影响装好的程序** —— 运行时只要求数据目录位于本地
固定盘，不挑盘符。

**注意**：不带 `-offline-only` 后缀的那些开关（`--watcher-only`、
`--package-baseline-live-readonly` 等）会读取本机真实的 Codex 安装与会话目录。
它们仍然是只读的，但不属于离线套件。

## 联网行为与数据

**唯一的出站请求是版本检查**：每天最多一次
`GET https://api.github.com/repos/<owner>/<repo>/releases/latest`，只读其中的
`tag_name`、`draft`、`prerelease` 三个字段。请求头只带一个编译期常量的 User-Agent
（`Ceasy/<版本> (+<仓库地址>)`，不含机器名、用户名或任何本机信息）、`Accept` 和固定的
`X-GitHub-Api-Version`，不带 cookie、不带凭据、不带请求体。响应里的 `html_url` 一律丢弃 ——
界面上能打开的地址始终是编译期常量拼出来的，不是应答方给的。可在**设置 → 检查新版本**关闭，
关掉之后不发出任何请求。

除此之外：

- 不上传遥测，不上报使用情况，不写任何统计。
- 不保存 API 密钥。
- 对 Codex 的会话目录只读。不写 `state_5.sqlite`、不写 rollout、不改任务内容。
- 本地日志和账本只记任务/轮次的短哈希、证据布尔值、分类和门禁阶段，
  **不记消息正文、标题、provider 原始错误、路径或凭据**。
- 设置、日志、恢复账本都在 `%LOCALAPPDATA%\CodexGuardian` 下，完整清单见
  [work/CodexGuardian/README.md](work/CodexGuardian/README.md) 的「数据位置」。

信任边界是「同一个 Windows 用户会话」：程序会校验命名管道对端的 PID、用户 SID、
包族名和安装路径，但不声称能抵御管理员权限、内核级攻击或同用户下的恶意代码。

## 许可

[MIT](LICENSE)。

安装包里附带的第三方软件（.NET 8 运行时、`System.Security.Cryptography.Pkcs`、
Inno Setup 6、Inno Setup 的简体中文语言文件）各自的版权与完整许可正文见
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。这两个文件也会随程序装进安装目录。

## 与 OpenAI 的关系

没有关系。Ceasy 是第三方工具，与 OpenAI 无隶属，也未获其背书。

它依赖 Codex Desktop 的几个内部协议方法（`thread-follower-start-turn`、
`thread-stream-following-changed`、`thread-stream-state-changed` 等）。这些不是公开 API，
OpenAI 没有承诺过它们的稳定性 —— Codex 更新后可能改名、改版本或改结构。
遇到不认识的版本时 Ceasy 会保持只监测并如实显示不兼容，**不会去改 Codex 来「兼容」**。
