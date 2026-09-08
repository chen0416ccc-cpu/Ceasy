; Ceasy 安装程序 —— Inno Setup 6 脚本
;
; 不要直接双击编译。请通过 work\build-installer.ps1 调用，由它负责
; 发布 self-contained 产物并传入 PublishDir / OutputDir。
;
; 设计约定：
;   * per-user 安装（PrivilegesRequired=lowest），不弹 UAC。应用的开机自启写在
;     HKCU\...\Run，数据目录在 %LocalAppData%\CodexGuardian，本来就是单用户作用域，
;     装到 Program Files 反而与之不一致。
;   * 保留目录选择页，默认 %LocalAppData%\Programs\Ceasy，允许改到其他盘
;     （self-contained 产物体积较大，系统盘紧张的用户需要这个出口）。
;   * 卸载时清理 HKCU\...\Run 的死启动项，但默认保留用户数据目录。

#ifndef PublishDir
  #error 必须通过 ISCC /DPublishDir=<已发布的 self-contained 目录> 传入
#endif

#ifndef OutputDir
  #define OutputDir "."
#endif

#define AppName "Ceasy"
#define AppExeName "CodexGuardian.exe"
#define BrokerExeName "CodexGuardian.Broker.exe"
#define AppPublisher "Ceasy"
; 年份写死而不是取编译时的当前年：安装包要可复现，同一份源码在跨年后重新编译
; 不应该产出不同的二进制。
; 写 (C) 而不是直接写 © ：Inno 会把 (C) 替换成 ©，落到版本资源里是
; "Copyright © 2026 Ceasy"，同时源文件保持纯 ASCII，不依赖 .iss 的编码。
#define AppCopyright "Copyright (C) 2026 Ceasy"
; 版本号单一来源是 CodexGuardian.csproj 的 <Version>，由 build-installer.ps1 读出后
; 通过 /DAppVersion 传入。缺省时退回读 exe 的四段版本，只为让脚本能独立编译。
#ifndef AppVersion
  #define AppVersion GetVersionNumbersString(AddBackslash(PublishDir) + AppExeName)
#endif
; 应用的单实例 Mutex 定义在 CodexGuardian\App.xaml.cs 的 SingleInstanceMutexName，
; 值为 "Local\CodexGuardian.SingleInstance"。Inno 的 AppMutex 会检查裸名与
; Global\ 前缀两种形式，裸名在同一会话内与 Local\ 前缀指向同一内核对象。
#define AppMutexName "CodexGuardian.SingleInstance"
; 开机自启项：CodexGuardian\Services\StartupService.cs 的 RunKeyPath + ValueName
#define RunKeyPath "Software\Microsoft\Windows\CurrentVersion\Run"
#define RunValueName "CodexGuardian"
; 用户数据目录：CodexGuardian\Services\SettingsService.cs 的默认 dataDirectory
#define DataDirName "CodexGuardian"

[Setup]
; AppId 一旦发布就不能再改，否则升级会被识别成另一个产品，产生重复卸载项。
AppId={{8F3A1C9E-7D42-4B58-A6E1-2C5B9D0F4A73}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppCopyright={#AppCopyright}
; setup.exe 自身的文件属性。缺了这些，右键属性的「详细信息」页几乎是空的，
; 而杀软和企业软件清点工具都会读它们。
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} 安装程序
VersionInfoCopyright={#AppCopyright}
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir={#OutputDir}
OutputBaseFilename={#AppName}-{#AppVersion}-Setup
; 相对 .iss 所在目录解析，与源码树的应用图标共用一份，避免两处不同步。
SetupIconFile=..\CodexGuardian\Assets\Ceasy.ico
; self-contained win-x64 产物，不支持 32 位与 ARM 上的 x86 模拟。
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; 免 UAC 的 per-user 安装。
PrivilegesRequired=lowest
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; 向导品牌图片。由 installer\build-wizard-images.ps1 从应用 logo 和设计系统色板生成，
; 不是手工美术资产——logo 或色板改了重跑那个脚本即可。
; Inno Setup 6.6.0 起这两个指令支持 PNG（含 alpha），所以不必再转 BMP。
; 逗号分隔多档尺寸，Setup 自己挑最接近当前 DPI 的那张，高分屏上不会糊。
WizardImageFile=Assets\WizardImage-202x386.png,Assets\WizardImage-336x643.png,Assets\WizardImage-534x1022.png
WizardSmallImageFile=Assets\WizardSmallImage-58.png,Assets\WizardSmallImage-97.png,Assets\WizardSmallImage-159.png
; 大图不透明，这个色只在 Setup 缩放后可能出现的边缘缝隙里露出来，取图自身的
; 顶部背景色（设计系统的 Canvas #F2EFE7）。Inno 的颜色是 $BBGGRR 字节序。
WizardImageBackColor=$E7EFF2
; 小图故意留全透明，让 logo 与向导页自己的背景混合，所以不设
; WizardSmallImageBackColor——默认的 clWindow 跟随系统，比写死白色更稳。
; 目录选择页保留（产物体积大，需要给出改盘的出口）；程序组页无意义，去掉。
DisableDirPage=no
DisableProgramGroupPage=yes
DisableWelcomePage=no
ShowLanguageDialog=auto
; 安装/卸载前检测正在运行的实例，提示关闭而不是直接失败。
AppMutex={#AppMutexName}
; 防两个安装器同时跑。没有它，用户双击两次就会有两个进程往同一目录解压，
; 后果是文件被写坏而两边都报成功。名字的唯一性来自产品名；Inno 会同时检查裸名和
; Global\ 前缀，裸名是会话级的，所以不会让另一个登录用户装不了。
SetupMutex={#AppName}.Setup.Mutex
CloseApplications=yes
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
; per-user 安装不需要重启，别在收尾页面提示重启。
RestartIfNeededByRun=no
; setup.exe 始终把日志写到 %TEMP%\Setup Log *.txt。装失败时这是唯一的一手证据，
; 让用户重跑一次带 /LOG 参数往往已经来不及。
SetupLogging=yes
; 卸载项写到 HKCU，与 per-user 安装一致。
UsePreviousAppDir=yes
UsePreviousGroup=yes
MinVersion=10.0

[Languages]
; LicenseFile 按语言分别指定，优先于 [Setup] 的同名指令，所以中文用户看到的是中文许可页，
; 英文用户看到英文那份。两份文本都是 UTF-8 with BOM + CRLF：Inno 只在有 BOM 时才把纯文本
; 许可文件按 UTF-8 解读，没有 BOM 会退回当前语言的 ANSI 代码页，中文那份就会整页乱码。
; CRLF 由 .gitattributes 固定，理由见那里的注释。
Name: "chinesesimplified"; MessagesFile: "Languages\ChineseSimplified.isl"; LicenseFile: "License-ChineseSimplified.txt"
Name: "english"; MessagesFile: "compiler:Default.isl"; LicenseFile: "License-English.txt"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; 整个 self-contained 发布目录原样复制。ignoreversion 是必需的：产物里多数
; 运行时 DLL 版本号相同但内容可能因 SDK 补丁而变，按版本比较会漏更新。
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; 许可与第三方声明。MIT 要求「在所有副本或实质部分中」保留许可声明，安装目录就是一份副本，
; 所以这两个文件必须随产物落地，而不是只留在仓库里。源路径相对 .iss 所在目录解析，
; 直接指向仓库根的同一份文件，不经过发布目录——否则要在 csproj 里加 <None> 复制项，
; 那会让它们同时出现在开发构建的 bin 目录里。
; LICENSE 改名为 LICENSE.txt：无扩展名的文件在资源管理器里双击打不开，而这份文件的
; 全部意义就是给人读。
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Comment: "{cm:ShortcutComment}"; AppUserModelID: "Ceasy.CodexGuardian"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Comment: "{cm:ShortcutComment}"; Tasks: desktopicon; AppUserModelID: "Ceasy.CodexGuardian"

[InstallDelete]
; 旧安装器把 Broker 合并到主程序目录。只清理这四个旧入口文件，
; 共享 DLL 留给主程序，用户配置目录不在安装清理范围内。
Type: files; Name: "{app}\CodexGuardian.Broker.exe"
Type: files; Name: "{app}\CodexGuardian.Broker.dll"
Type: files; Name: "{app}\CodexGuardian.Broker.deps.json"
Type: files; Name: "{app}\CodexGuardian.Broker.runtimeconfig.json"

[Registry]
; 只在卸载时清理开机自启项。应用自己通过 StartupService 写这个值，安装器不主动创建，
; 但必须负责删除——否则卸载后会残留一个指向已删除 exe 的死启动项。
Root: HKCU; Subkey: "{#RunKeyPath}"; ValueType: none; ValueName: "{#RunValueName}"; Flags: dontcreatekey uninsdeletevalue

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[CustomMessages]
; 快捷方式的鼠标悬停提示。文案取自 CodexGuardian\README.md 的产品定义，
; 不另造一套说法。
chinesesimplified.ShortcutComment=Codex Desktop 的本地多任务观察与受控恢复工具
english.ShortcutComment=Local multi-task observation and controlled recovery for Codex Desktop
chinesesimplified.RemoveDataPrompt=是否同时删除 Ceasy 的设置和运行记录？%n%n位置：%1%n%n选「否」会保留这些数据，以后重新安装时设置还在。
english.RemoveDataPrompt=Also delete Ceasy settings and logs?%n%nLocation: %1%n%nChoose No to keep them so a future reinstall picks up your settings.
; 降级提示。%1 是已装版本，%2 是这个安装包的版本。
chinesesimplified.DowngradeWarning=这台电脑上已安装的 Ceasy %1 比当前安装包 %2 更新。%n%n继续会把它降级到旧版本，且设置文件可能已经是新版格式。%n%n确定要降级吗？
english.DowngradeWarning=Ceasy %1 is already installed and is newer than this installer (%2).%n%nContinuing will downgrade it, and your settings may already be in the newer format.%n%nDowngrade anyway?

[Code]
const
  RunKey = '{#RunKeyPath}';
  RunValue = '{#RunValueName}';
  { Inno 自己的卸载信息键。键名里的 AppId 由预处理器的 SetupSetting 函数从 [Setup]
    原样取回，所以 GUID 只在 AppId 那一处定义，不会出现第二份副本失同步。
    取回的字符串里带着 Inno 表示字面左大括号的双写转义，所以必须经过 ExpandConstant
    才变成真正的键名。
    注意：这段注释里不能出现预处理器的取值写法本身——预处理器在 Pascal 词法之前工作，
    注释里的它也会被展开，展开结果带右大括号，会把这条注释提前截断。 }
  UninstallKeyRaw = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1';

{ 判定这次是升级还是首次安装。依据取 Inno 存的 App Path 而不是 UninstallString：
  UsePreviousAppDir 读的就是 App Path，只有它存在才能保证「跳过目录页」之后
  仍然装回原目录。 }
function IsUpgrade(): Boolean;
var
  PreviousPath: String;
begin
  Result :=
    RegQueryStringValue(HKEY_CURRENT_USER, ExpandConstant(UninstallKeyRaw),
      'Inno Setup: App Path', PreviousPath) and
    (PreviousPath <> '');
end;

{ 降级保护。Inno 默认允许旧版盖新版：[Files] 用了 ignoreversion，每个文件都会被
  旧版覆盖，卸载项的 DisplayVersion 也一起回退，用户没有任何迹象能察觉自己降级了。
  更麻烦的是设置文件可能已经是新版格式，降级后由旧版读取。
  静默模式（/VERYSILENT /SUPPRESSMSGBOXES）下取 IDNO 中止：自动化流程不该悄悄降级。 }
function InitializeSetup(): Boolean;
var
  InstalledText: String;
  InstalledVer, ThisVer: Int64;
begin
  Result := True;

  if not RegQueryStringValue(HKEY_CURRENT_USER, ExpandConstant(UninstallKeyRaw),
       'DisplayVersion', InstalledText) then
    Exit;
  { 版本号解析不了就不拦。宁可放过一次降级，也不能因为注册表里有个畸形值就装不了。 }
  if not StrToVersion(InstalledText, InstalledVer) then
    Exit;
  if not StrToVersion('{#AppVersion}', ThisVer) then
    Exit;
  if ComparePackedVersion(InstalledVer, ThisVer) <= 0 then
    Exit;

  Result := SuppressibleMsgBox(
    FmtMessage(CustomMessage('DowngradeWarning'), [InstalledText, '{#AppVersion}']),
    mbError,
    MB_YESNO or MB_DEFBUTTON2,
    IDNO) = IDYES;
end;

{ 升级时不再问装到哪。UsePreviousAppDir=yes 会把目录页预填成旧路径，但那一页仍然
  可编辑；用户在升级时改了路径，Inno 会装到新目录而不清理旧目录，结果是两份 150 MB
  产物、一个只指向新目录的卸载项。首次安装仍然给出目录选择——self-contained 产物
  体积大，系统盘紧张的用户需要那个出口。 }
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = wpSelectDir) and IsUpgrade();
end;

{ 应用自己通过 StartupService 维护开机自启，值内容是 "<exe>" --background。
  换安装目录升级后那个值会指向旧路径，所以安装完成后把它重写到新路径。
  仅在该值已存在时改写——用户没开过自启就不该被安装器代劳。 }
procedure RefreshStartupEntry;
var
  Existing: String;
begin
  if RegQueryStringValue(HKEY_CURRENT_USER, RunKey, RunValue, Existing) then
  begin
    RegWriteStringValue(
      HKEY_CURRENT_USER,
      RunKey,
      RunValue,
      '"' + ExpandConstant('{app}\{#AppExeName}') + '" --background');
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RefreshStartupEntry();
end;

{ 卸载时问一次是否清理用户数据。默认保留：设置、台账、日志属于用户资产，
  不能随卸载静默消失。
  必须用 SuppressibleMsgBox 而不是 MsgBox——后者在 /VERYSILENT /SUPPRESSMSGBOXES
  下不会回退到 MB_DEFBUTTON2 指定的 No，静默卸载会把用户数据一起删掉。
  SuppressibleMsgBox 的第四个参数才是静默模式下真正采用的返回值。 }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;

  DataDir := ExpandConstant('{localappdata}\{#DataDirName}');
  if not DirExists(DataDir) then
    Exit;

  if SuppressibleMsgBox(
       FmtMessage(CustomMessage('RemoveDataPrompt'), [DataDir]),
       mbConfirmation,
       MB_YESNO or MB_DEFBUTTON2,
       IDNO) = IDYES then
  begin
    DelTree(DataDir, True, True, True);
  end;
end;
