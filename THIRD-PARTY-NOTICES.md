# 第三方声明

Ceasy 自身按 [MIT 许可](LICENSE)发布。除此之外，Ceasy 的安装包与源码树包含或依赖下面这些
第三方软件。本文件列出它们各自的版权与许可，以满足这些许可对再分发的要求。

许可正文一律保留英文原文，不作翻译。法律效力在原文，任何译文只能当参考。

| 组件 | 许可 | 出现在哪里 |
| --- | --- | --- |
| [.NET 8](#net-8) | MIT | 安装目录里的运行时与 WPF 文件 |
| [System.Security.Cryptography.Pkcs 8.0.1](#systemsecuritycryptographypkcs-801) | MIT | `CodexGuardian.Control` 的唯一 NuGet 直接依赖 |
| [Inno Setup 6](#inno-setup-6) | Inno Setup License | 编译出的 `Ceasy-<版本>-Setup.exe` |
| [Inno Setup 简体中文语言文件](#inno-setup-简体中文语言文件) | MIT | `work/installer/Languages/ChineseSimplified.isl` |

## .NET 8

Ceasy 是 .NET 8 的 WPF 桌面应用。安装包由 `work/build-installer.ps1` 以 self-contained
win-x64 方式发布，所以**完整的 .NET 8 运行时与 WPF 一起装进了安装目录**（`hostfxr.dll`、
`coreclr.dll`、`PresentationNative_cor3.dll`、`wpfgfx_cor3.dll`、`System.*.dll` 等）。
用户机器上不需要预装 .NET，代价是这些文件属于随 Ceasy 一起再分发的第三方二进制。

- 项目主页：https://github.com/dotnet/runtime
- 许可：MIT

.NET 运行时自己也依赖若干第三方代码（zlib、Unicode 数据表、RFC 参考实现等），
Microsoft 把那份清单维护在
https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT ，
随运行时分发的文件同样受它约束。Ceasy 不复述那份清单的内容，以免出现失同步的第二份副本。

```
The MIT License (MIT)

Copyright (c) .NET Foundation and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## System.Security.Cryptography.Pkcs 8.0.1

`work/CodexGuardian.Control` 的唯一 NuGet 直接依赖，声明在
`work/CodexGuardian.Control/CodexGuardian.Control.csproj`。用途是解析 Authenticode 签名里的
PKCS#7 结构：`CodexPackageBaselineVerifier.cs` 用它只读判定已安装的 Codex 包是否仍是官方签名，
`PublishedRuntimeDependencyClosureVerifier.cs` 用它校验发布产物里这个包的来源没有被降级或篡改。

- 项目主页：https://github.com/dotnet/runtime
- 许可：MIT，与 .NET 8 同为 .NET Foundation and Contributors，正文见上一节。

## Inno Setup 6

`work/installer/Ceasy.iss` 由 Inno Setup 6 的命令行编译器 `ISCC.exe` 编译成
`Ceasy-<版本>-Setup.exe`。生成的 setup.exe 里含有 Inno Setup 的安装引擎代码，
所以那个文件本身就是 Inno Setup 的二进制再分发。

- 项目主页：https://jrsoftware.org/isinfo.php
- 源码：https://github.com/jrsoftware/issrc
- 许可：Inno Setup License

关于许可与商业使用，这里有两层不同的事实，都要说清楚：

1. **许可文面**（下面的正文）允许任何人把这个软件用于任何目的，包括商业应用，
   四项条件只约束「再分发 Inno Setup 自身」。其中第 2 条要求二进制再分发保留原有的
   版权声明与网址 —— Inno 编译出的 setup.exe 在 `/HELP` 与关于框里自带这些信息，
   Ceasy 没有移除或改写它们。
2. **官方政策**是另一回事：Inno Setup 6.5.0 起，jrsoftware.org 声明它
   "remains open source and free for non-commercial use"，并在购买页写明
   "we request that all commercial users of Inno Setup purchase licenses"。
   编译器自己会把这件事印在输出里 —— `ISCC.exe` 的版权抬头下面紧跟一行
   `Non-commercial use only`。

Ceasy 是免费开源产品，不销售、不收费、不含内购或商业授权，属于上述非商业使用。
如果有人以 Ceasy 为基础做商业分发，需要自行按 jrsoftware.org 的当期政策处理 Inno Setup 的授权。

```
Inno Setup License
==================

Except where otherwise noted, all of the documentation and software included in the Inno
Setup package is copyrighted by Jordan Russell.

Copyright (C) 1997-2026 Jordan Russell. All rights reserved.
Portions Copyright (C) 2000-2026 Martijn Laan. All rights reserved.

This software is provided "as-is," without any express or implied warranty. In no event shall
the author be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial
applications, and to alter and redistribute it, provided that the following conditions are met:

1. All redistributions of source code files must retain all copyright notices that are currently
   in place, and this list of conditions without modification.

2. All redistributions in binary form must retain all occurrences of the above copyright notice
   and web site addresses that are currently in place (for example, in the About boxes).

3. The origin of this software must not be misrepresented; you must not claim that you wrote
   the original software. If you use this software to distribute a product, an acknowledgment
   in the product documentation would be appreciated but is not required.

4. Modified versions in source or binary form must be plainly marked as such, and must not
   be misrepresented as being the original software.


Jordan Russell
jr-2020 AT jrsoftware.org
https://jrsoftware.org/
```

## Inno Setup 简体中文语言文件

`work/installer/Languages/ChineseSimplified.isl` 是安装向导的简体中文界面文案，
原样取自社区维护的翻译项目，未作改动。Inno Setup 官方只随包提供
`Default.isl`（英文）与 `Languages/` 下的部分语种，简体中文不在其中，所以这个文件
必须随源码树一起分发。

- 项目主页：https://github.com/kira-96/Inno-Setup-Chinese-Simplified-Translation
- 维护者：Zhenghan Yang (Kira)
- 许可：MIT

```
MIT License

Copyright (c) 2019 - 2020 kirakira

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 关于 Codex

Ceasy 观察并有限度地操作 OpenAI Codex Desktop，但**不包含、不修改、不再分发 Codex 的
任何代码或资源**。Codex 的安装包、ASAR 内容、状态数据库与会话记录全部按只读方式对待。
Ceasy 与 OpenAI 无隶属关系，也未获其背书。
