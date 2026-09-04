# 参与开发

## 从源码构建

需要 **.NET SDK 8.0.418**，而且是这个精确的补丁号：`work/global.json` 里写着 `"rollForward": "disable"`，手上是 8.0.4xx 里别的补丁号也会直接报「找不到兼容的 SDK」。

钉死它是为了发布——`check-release-baselines.ps1` 校验的那批运行时文件会随 SDK 补丁漂移，换个补丁号编出来的产物过不了基线校验。[.NET 8 下载页](https://dotnet.microsoft.com/download/dotnet/8.0)按补丁号列出了历史版本。

只想编出来跑一下、不打算做发布验收的话，把 `work/global.json` 的 `rollForward` 改成 `latestPatch` 就能用手上的 SDK 编——那样编出来的能跑，但别拿它当发布产物。

只想跑程序本身：

```powershell
dotnet build work\CodexGuardian\CodexGuardian.csproj -c Release -r win-x64
```

## 构建安装包

还需要 Inno Setup 6：

```powershell
winget install --id JRSoftware.InnoSetup --exact
```

然后：

```powershell
pwsh -File work\build-installer.ps1 -StagingRoot D:\ceasy-build
```

`-StagingRoot` 是发布产物、TEMP 和 setup.exe 的落地根目录，指向哪个盘都行。不传的话默认是 `D:\CodexData\CodexGuardian\installer-staging`——那是这个仓库自己的写策略（构建产物不占系统盘）留下的默认值，机器上没有 D 盘时必须显式指定。

脚本跑完会打印安装包路径与 SHA-256，并在输出目录里写好 `SHA256SUMS.txt`。

安装包的实机验证（装 → 启动 → 覆盖升级 → 降级拦截 → 卸载 → 清理校验，跑完恢复原状）：

```powershell
powershell -ExecutionPolicy Bypass -File work\installer\verify-installer.ps1
```

它必须在真实用户会话里跑，会短暂真正安装并启动程序，所以不要在 Ceasy 正在使用时执行。交互式向导的中文界面（含许可页排版）、向导品牌图片、以及「升级时跳过目录选择页」这三项静默安装不显示任何页面，只能人眼过。

## 测试

测试是一批离线契约套件，按主题分组，用一个 `--<主题>-offline-only` 开关选择要跑哪一组。它们不联网、不启动界面、不碰真实的 Codex。

跑之前必须先指定测试数据落在哪里。这批套件不会自己挑目录，缺 `CODEX_GUARDIAN_TEST_DATA_ROOT` 会让上百个用例直接以「is required」失败：

```powershell
$env:CODEX_GUARDIAN_TEST_DATA_ROOT = 'D:\ceasy-test-data'
$env:TEMP = 'D:\ceasy-temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:CODEX_GUARDIAN_TEST_DATA_ROOT, $env:TEMP | Out-Null

dotnet build work\CodexGuardian.Tests\CodexGuardian.Tests.csproj -c Debug -r win-x64
.\work\CodexGuardian.Tests\bin\Debug\net8.0-windows\win-x64\CodexGuardian.Tests.exe --workflow-automation-offline-only
```

必须从仓库根目录启动——有几个套件会读源码文件来校验静态契约。可用的开关名列在 [work/CodexGuardian.Tests/Program.cs](work/CodexGuardian.Tests/Program.cs)；不带任何开关就是全量运行。

**注意**：不带 `-offline-only` 后缀的那些开关（`--watcher-only`、`--package-baseline-live-readonly` 等）会读取本机真实的 Codex 安装与会话目录。它们仍然是只读的，但不属于离线套件。

### 已知限制：测试数据目录目前必须在 D 盘

上面那两个目录（`CODEX_GUARDIAN_TEST_DATA_ROOT` 和 `TEMP`）必须在 `D:\` 下。测试基础设施里有多处断言把测试数据根钉死在 `D:\` 前缀上，几个开发期门禁工具也这样要求。

它们的本意是执行本仓库「构建与测试产物不占系统盘」的写策略，却把「非系统盘恰好叫 D」写成了硬条件，所以在没有 D 盘的机器上这批套件起不来。这是待清理项，**只影响跑测试，不影响装好的程序**——运行时只要求数据目录位于本地固定盘，不挑盘符。

## 提交约定

- commit message 用英文，沿用仓库既有习惯。
- 静态契约测试断言失败时，先判断是实现违反了真实契约，还是测试必须更新到新的有意设计。**不要为了让测试通过而删断言。**
- 不要把未实现的功能写成已有功能，无论是在文档还是完成度声明里。
- 验证要分层陈述：离线测试、只读校验、实机验证各自只支撑自己那一层，没跑到的步骤要明说没跑。
