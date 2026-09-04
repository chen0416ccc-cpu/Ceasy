# Ceasy

Ceasy 是面向 Windows 版 Codex Desktop 的本地多任务观察与受控恢复工具。它在后台观察多个任务的真实终态，发现网络断流、服务过载、静默完成或普通中断后，根据证据选择 `ResendOriginal`/`ResendContinue` 意图，或在已有真实工作后追加一条 `SendContinue`。当前安装的 Desktop 只证明了追加 continue 的通道；两个 resend 意图在缺少非破坏性原生重发契约时会安全闭锁，不会制造重复消息。

2.0 采用零手工接入架构：直接连接经过包身份校验的 stock Codex Desktop 本机 IPC，并使用 Windows 已注册的 `codex://threads/{任务 ID}` 官方任务深链建立 renderer owner。Guardian 不替换 Codex 安装包，不重签名 MSIX，不注入进程，不修改或补丁 ASAR/JavaScript，也不附带 Desktop 安装器或修改载荷。

恢复轮次由 Codex Desktop 已有 renderer 创建并持有输出流。owner 探针、内存快照和定点事实核验在用户操作电脑时仍然照常进行。Guardian 使用进程外 `SetWinEventHook + UI Automation` 做系统级增强观察：当前台 Codex composer 明确正在编辑时延后提交；明确未编辑时，用户操作其他程序不会阻止同流恢复。增强观察只有在首次及时检查成功后才显示可用；检查 gate 或 UIA 超时会立即降级并回退 Windows 连续空闲至少 15 秒，后续成功检查可自动恢复。owner 缺失且必须通过深链建立 owner 时也始终保留该全局空闲门禁。该能力零补丁、零注入，不修改 Codex，也不声称能识别后台草稿或把 composer 映射到目标任务。程序不点击输入框，不模拟鼠标或键盘，也不操作剪贴板。用户看到的是桌面端同一任务的流式输出，不存在另一个不可见 app-server 会话独占输出的问题。

界面默认使用简体中文，可在“设置”中即时切换为英文。

## 首次启用

1. 确保官方 Codex Desktop 已安装并正常登录，无需对 Codex 做任何修改。
2. 从桌面或开始菜单双击“Ceasy”。
3. 打开“自动恢复”页面，确认桌面同流通道和“系统级增强观察”状态；监测和只读核验不等待空闲，composer 正在编辑、观察不确定或需要深链导航时才使用相应安全门禁。
4. 将恢复模式从“仅监测”切换为“自动恢复”。
5. 默认会保护当前和未来新建的根任务；如果只想保护指定任务，请在“设置”中关闭“自动保护新任务”，再到“任务”页面逐个开启。
6. 主窗口可以关闭到托盘，事件监听与自动恢复会继续运行。

新配置默认从“仅监测”开始，避免第一次启动时处理不希望恢复的历史任务；任务保护策略默认覆盖当前和未来新根任务。旧配置升级时也只执行一次安全迁移：保留监测开关和各任务保护范围，把自动恢复切回“仅监测”，并保持新任务默认受保护，由用户确认原生通道和保护范围后再开启。仅监测模式不是自动恢复模式：它只分类和显示异常，不创建新轮次。

## 界面入口

| 入口 | 实际作用 | 会不会发送消息 |
| --- | --- | --- |
| **监测状态** | 应用启动后自动监听，并只读显示初始化、健康、降级或阻断状态 | 监测本身不发送 |
| **立即核对** | 人工触发一次只读状态同步 | 本按钮本身不发送 |
| **任务** | 查看多任务状态，并逐个开启或暂停保护 | 保护关闭的任务绝不自动发送 |
| **预制消息** | 为选中的任务维护多条有序消息，设置正常完成后发送或指定本地时间发送 | legacy 队列依赖队列/消息授权；工作流依赖 `UseWorkflowAutomation` 和规则授权，并共同通过目标、owner、编辑状态和 at-most-once 门禁 |
| **自动恢复** | 切换仅监测/自动恢复，设置退避和继续消息 | 仅自动恢复开启且其独立安全门禁通过后，才允许恢复写入 |
| **重新检测桌面通道** | 重新连接原版 Codex 桌面端 IPC 并检查原生方法路由 | 不安装、不修改、不重启、不发送 |
| **只读检查当前异常任务** | 最多读取近期任务的有界 summary 进行诊断 | 不发送，不读取完整 rollout |
| **设置** | 切换语言、开机启动、托盘行为、子任务范围和新任务默认保护策略 | 不发送 |

“立即核对”不是扫描周期。2.0 没有可配置的周期扫描，也不会每隔几秒重新读取所有任务。

## 恢复规则

| 最新轮次情况 | 自动动作 |
| --- | --- |
| `failed` 或 `interrupted`，且尚无助手、推理或工具输出 | 普通情况分类为 `ResendOriginal` 并闭锁；若本地终态明确为 HTTP 429、无任何工作且原始结构化输入可重放，则按“已确认未提交”规则通过 stock owner 追加原始消息，仍受 journal/owner/策略/at-most-once 门禁 |
| 本地终态确认轮次已结束，但没有最终答复或工作证据 | 分类为“消息未获回应”的 `ResendOriginal` 意图；不会追加一条相同消息冒充重发 |
| 异常结束前已有助手内容、推理结果或工具工作 | 通过 stock owner `start-turn` 追加 `SendContinue`，默认 `continue` |
| 继续消息本身在没有任何输出时再次失败 | 分类为 `ResendContinue` 意图；当前同样因 native resend 缺失而闭锁 |
| `completed` 且有明确最终答复 | 显示正常完成，不恢复 |
| item 类型、assistant phase、用户输入边界或 summary 证据不完整 | 显示“证据不足”并闭锁，不猜测性发送 |
| 429、服务过载、断流、未知失败或普通中断 | 视为可恢复异常，不要求错误必须是 429 |
| 401、403、认证失败、权限拒绝、余额/额度不足、内容策略或上下文超限 | 不自动发送，标记为人工检查 |
| `cancelled`、`canceled`、`aborted`，或本地 `turn_aborted(reason=interrupted)` | 显示用户已中断，不自动恢复；未知 abort reason 显示原因待确认并继续闭锁 |
| 最新轮次仍为 `inProgress`，或 Desktop 报告任务仍活动 | 保持处理中，不重复发送 |
| Guardian 创建的恢复轮次自身再次失败或静默结束 | 通过已确认的新 turn ID 或稳定客户端消息 ID 识别后继，保留持久墓碑并闭锁为人工检查，不自动形成恢复链 |
| 原始结构化输入无效、超限，或带附件但只能取得可见文本 | 闭锁为需要人工处理，不发送丢失附件或残缺的消息 |

## 预制消息

每个任务可以保存多条有序预制消息，并可逐条启用、停用或通过专用左侧握柄拖拽排序。单条消息最长 4000 个字符，每个任务最多 64 条；设置会把本地日期和 `HH:mm` 时间转换为明确的 UTC 时间保存，夏令时跳空或歧义时间会被拒绝。

- “正常完成后”只接受有本地终态、可靠最终答复、完整 item 证据且没有歧义活动的 `completed` 轮次。`failed`、`interrupted`、用户中止、证据不完整或仍在运行的轮次不会消耗队列项，原有恢复流程始终优先。
- “定时发送”到点后仍要求目标任务处于上述正常完成和空闲状态；到点不会越过更早的未发送消息，也不会打断正在运行的轮次。
- 一条预制消息成功创建后继轮次后，下一条必须等待该后继正常完成。已发送的前序后来被停用，仍保留这一顺序屏障；投递结果不确定时只按稳定客户端消息 ID 对账，不自动重发。
- 每次提交都重新核对目标任务、最新完成轮次、owner 快照、任务范围、队列/消息或 workflow 授权、composer 编辑状态和持久账本。精确写入开始前策略或 owner 变化会保留为可重试；写入可能已经开始后失去确认则进入 `Uncertain`。
- “仅监测”只关闭自动恢复写入，不是预制消息的总开关。预制消息仍必须通过自身的队列、消息或 workflow 授权；队列暂停、任务保护关闭或单条消息停用都保持 fail-closed。

## 原生桌面 IPC

发送链路使用 Windows 注册的 Codex 任务深链、Codex Desktop 的 `codex-ipc` 命名管道和 stock follower 方法：

1. Guardian 只读核对异常终态、最新轮次 ID 和输出类型。
2. Guardian 为 `(任务 ID, 失败轮次 ID)` 建立唯一持久操作，冻结动作和消息摘要；账本写入 `Prepared` 成功后才继续。
3. Guardian 使用本次扫描的 active/archived 快照筛选候选；真正提交前，本轮所有并发恢复共享一次新的目录刷新，确认任务仍处于 active、未归档并符合根任务/子任务范围。active 与 archived 查询冲突时按归档处理，不会为每个失败任务重复遍历完整目录。
4. Guardian 首次核对最新轮次 ID 与终态，并刷新 active/archived 目录范围。然后用 `thread-follower-edit-last-user-turn` v2 对一个随机、必不存在的 turn ID 发起无副作用探针：`no-client-found` 表示 owner 缺失；其他预期的“轮次不存在”拒绝表示目标 renderer 已接管请求。探针不会 rollback、编辑或创建轮次。
5. Guardian 先执行无副作用 owner 探针。owner 已存在时，即使用户正在操作也可继续只读核验；只有 owner 连续两次明确 `Unavailable` 且 Windows 已空闲时，才调用 `codex://threads/{任务 ID}`。transient/unknown 探针结果不会被深链导航掩盖。
6. owner 就绪后，Guardian 通过 `thread-stream-following-changed` v1 登记一个临时 follower，等待 owner 以 `thread-stream-state-changed` v11 返回内存快照。快照优先读取 canonical `turnHistory`（兼容旧 `turns` 表示），必须确认任务 runtime 为 `idle`、最新 turn ID 仍是预期失败轮次且终态符合恢复条件。取得快照后的任何状态 patch、协议版本变化或 IPC 断线都会使该快照失效。
7. 临时 follower 保持有效期间，Guardian 再核对最新轮次 ID 与终态，并对目标任务执行一次 `thread/read(includeTurns=false)`：只有返回同一任务、符合根任务/子任务范围、rollout 路径明确位于活动 `sessions` 且文件仍存在时才继续；`archived_sessions`、ephemeral、身份不符、文件已移动或路径状态不明都在 `Dispatching` 前闭锁。
8. Guardian 再次核对冻结的自动恢复策略版本、follower 快照有效性和一次有界的即时 composer 观察，再把可派发的 `SendContinue` 操作原子更新为 `Dispatching`。落盘后、真正调用 `thread-follower-start-turn` v1 前会再观察一次；前台 Codex composer 正在编辑时，未发送操作退回 `Retryable`。观察不可用、不确定、过期或 UIA 超时时，改用 Windows 连续空闲门禁。`ResendOriginal`/`ResendContinue` 另需非破坏性 native resend capability；当前包缺失时在 journal/owner/IPC 前闭锁。没有任何恢复动作调用 edit/rollback。
9. `SendContinue` 使用由任务 ID、失败轮次 ID 和动作生成的稳定客户端消息 ID。该 ID 写入账本并用于结果对账，不被宣称为 core 的持久幂等键。落盘后若监控已经停止或策略已改变，尚未发送的操作会退回 `Retryable`；一旦进入 Desktop 提交，则使用独立的 40 秒有界提交窗口，不由普通监控取消中途切断。旧 resend 账本只读保留，不补造稳定 ID 或重新派发。
10. 所有发送都由已验证的 Codex Desktop renderer 在原任务内创建轮次并持有输出流，因此 Codex 界面可直接显示同一条流式输出。
11. 每次处理最新轮次前，Guardian 在同一账本事务内用 `NewTurnId` 和用户消息 `clientId` 判断它是否由既有恢复操作创建。恢复后继仍在运行、终态未确认或再次失败时不会清理 `Dispatching`、`Uncertain`、`Accepted`、`Confirmed` 墓碑；再次失败会直接闭锁，不会把新 turn ID 当成新的失败代继续发送。只有本地终态确认恢复成功，或出现可证明无关的新轮次时，旧墓碑才转为可清理状态。

用户交互门禁与 provider 退避是两件事。provider 退避是网络恢复等待；交互门禁用于避免深链切换任务、碰上用户草稿或在用户正编辑 Codex composer 时提交新 turn。当前系统级观察只能证明“前台是否正在编辑任意 Codex composer”，不能证明目标任务是否存在后台草稿；因此明确 Clear 时允许用户操作其他程序，Unknown 时回退 15 秒 Windows 连续空闲，深链导航始终要求全局空闲。owner 探针、快照和定点读取不受该门禁阻塞。

空闲门禁、owner 探针、临时 follower 快照、失败轮次/任务范围复核和发送前失效检查用来缩小导航与提交之间的竞态窗口。stock `start-turn` 没有“比较期望失败轮次并原子创建新轮次”的跨进程事务，因此它只用于 `SendContinue`/预制消息的追加，以及显式 HTTP 429、无工作证据的“已确认未提交”原始消息重试；任何请求结果不明时，程序都只重新核对任务，不自动再发一个新请求。`ResendContinue` 和普通 `ResendOriginal` 当前不会进入该调用。追加动作只在响应返回 turn ID，或近期 summary 匹配自己的稳定 `clientId` 时确认成功；出现无法归属的新轮次时只标记为已取代，不冒充 Guardian 的发送结果。

Codex App 提供的 `send_message_to_thread` 是模型会话之间的协作工具，不是失败轮次恢复接口。实测它只会创建带 `<codex_delegation>` 来源信封的新用户轮次，不能编辑指定失败轮次，也不向调用方暴露 `expectedFailedTurnId` 或稳定 `clientUserMessageId`；同版本的 `read_thread` 摘要还可能不携带 rollout 中的 provider 终态错误。Guardian 因此不调用或伪造该工具，而是用本地新增终态字节发现真实错误，再检查 Desktop 的版本化恢复能力。若一条真实 delegation 消息自身无输出失败，Guardian 只能分类为 resend intent；当前没有合规 native resend 时保持闭锁，不追加一条相同消息。

Guardian 也不会用自己的 app-server 执行 `thread/resume + turn/start`。匹配当前 CLI 的源码表明 ThreadManager 只在单进程内去重，而 rollout writer 直接以 append 模式打开 JSONL，没有跨进程 owner 锁；独立写入会与 Desktop 形成双 writer 风险。Guardian 的 app-server 始终只读，所有恢复提交都留在 Desktop renderer 内。

当前 stock Desktop 还会把部分 provider 失败轮次暴露为 `completed/error=null`。Guardian 只在 app-server 与本地 `task_complete` 指向完全相同的轮次 ID 时合并两份证据：`inProgress` 始终优先；`completed` 则比较终止时间，本地失败与 Desktop 完成同时或更晚时采用本地真实错误，只有 Desktop 终止时间严格更新时才判定后续完成已经覆盖旧失败。提交前的两次最新轮次核验复用同一条已经确认的本地终态和时间规则，不因 app-server 再次丢失错误而误关恢复操作。

owner 内存快照若把同一轮次报告为 `completed`，也只有 owner runtime 为 `idle`，并且本地已经确认该精确 turn ID 是带错误证据的 `failed`/`interrupted`，或是“用户输入完整但没有最终答复”的静默终态时，才允许继续恢复。不同轮次 ID、未确认本地终态、证据不完整、owner 非空闲或其他 `completed` 都会闭锁。

### 兼容性与竞态边界

`codex://threads/{任务 ID}` 由当前 Windows AppxManifest 正式注册；`thread-follower-start-turn`、用于无副作用 owner 探针的 `thread-follower-edit-last-user-turn`，以及临时快照使用的 `thread-stream-following-changed` / `thread-stream-state-changed` 仍是 Desktop 内部协议，不承诺长期稳定。Microsoft Store 更新可能修改方法名、版本或请求结构。Guardian 只使用已知版本；探测不兼容时保持只监测，不会尝试修改 Codex 来“兼容”。

接收端接受稳定 `clientUserMessageId` 并可返回提交轮次 ID，但当前没有证据证明它会按该 ID 持久合并重复的 `turn/start`；因此稳定 ID 只用于对账，不作为接收端幂等保证。不确定投递采用 at-most-once，只核对 summary，不自动重发；只有显式确认请求未提交时才允许以后重试。匹配到 summary `clientId`、或收到提交轮次 ID 后即永久确认。同一个失败代不会换通道补发。owner 激活、临时 follower 快照、二次核对与任务所有权检查只能缩小竞态窗口，程序不会把这些保障包装成原子 compare-and-start 或严格 exactly-once。

## 事件驱动监测

正常运行依赖事件唤醒，不依赖高频目录扫描：

1. **一次启动基线**：启动监测时只做一次 active/archived 有界目录同步，建立任务 ID、元数据、最新轮次与状态缓存。
2. **本地文件事件**：使用 `FileSystemWatcher` 接收 rollout 的创建、重命名和追加事件。启动 watcher 不枚举历史 JSONL；追加只读新字节，单次最多 256 KiB。若一次追加超过该窗口但能从文件名确定任务 ID，只把该任务标脏并定点复核，不把“大追加”误报为全局事件丢失。
3. **Desktop 实时事件**：长期连接 stock `codex-ipc` owner/follower 通道。完整 snapshot 建立新的 host/owner revision 基线；常规 `patches` 只有在 base revision 连续，且路径涉及 runtime、resumeState、turn ID 或 turn 终态时才把目标任务标脏。文本、reasoning 和普通 item delta 不触发事实读取。revision gap 出现后不相信该 patch 携带的 idle 或 turn 状态，而是显示“状态待确认”并保持保守门禁，直到目标 `thread/read` 或新的权威 snapshot 完成核验。owner 断连和 IPC epoch reset 也会触发目标复核；`following` 仅表示订阅拓扑，不被误判为任务仍在运行。
4. **定点事实核验**：事件只负责唤醒。按任务 ID 去重的有界队列只调用 `thread/read`、最新 1 条 summary 和必要的目标 rollout 尾部核对，不重新列出所有任务。发送前仍会再次核对失败 turn、任务范围、owner 内存快照、策略和 Windows 空闲状态。
5. **长期只读状态连接**：监测启动时取得一份 monitoring lease，维持同一个独立 app-server helper 和 WebSocket；它只保留低频 task/turn 通知并执行目标读取，显式退订 item、hook、tool-progress 和文本 delta，永远不调用 `thread/resume`、`turn/start` 或 rollback。协议通知只负责唤醒，不能替代 Desktop owner stream 与文件事件；监测停止并释放 lease 后，连接进入 5 秒有界复用窗口，再由 Job Object 结束整棵进程树。
6. **有界安全校准**：健康状态下每 15 分钟进行一次低频目录 reconciliation，用于修复 OS 事件溢出、进程休眠或异常重连可能造成的缓存漂移；真实 watcher overflow、事件队列耗尽、事件无法确定任务 ID 或定点读取连续失败时也会提前请求一次。它不是高频轮询。
7. **人工同步与重连**：用户点击“立即核对”时执行一代只读目录校准，并等待自己请求的那一代完成。Desktop 管道与只读 helper 都使用 single-flight 和指数退避重连；重复连接状态不会放大为按任务数量增长的读取。

稳定终态按任务 `updatedAt` 缓存。任务元数据未变化时，即使程序长时间运行也不会再次读取该轮次。

## 磁盘与资源边界

- 常规监测、任务列表和近期对账固定使用 `itemsView=summary`；只有本地终端已匹配精确异常
  turn 且 summary 缺少用户输入或完整 item 证据时，才对该单个 turn 做一次有界
  `itemsView=full` 读取，用于恢复分类和结构化输入核验。
- 最新状态每个任务只读取 1 条 summary；自动不确定投递对账和人工诊断每个任务最多读取近期 20 条 summary。
- 生产代码不存在 `itemsView=full`、完整轮次历史 API 或完整 rollout 逐行扫描入口。
- 本地终态纠正从文件尾部 256 KiB 起读，硬上限 8 MiB，并按文件长度与修改时间缓存。
- watcher 事件会直接登记“任务 ID 到 rollout 文件”的内存映射；只有缺少映射的异常兼容路径才建立一次历史索引，不会为每个任务重复遍历会话目录。
- 实时文件监听只消费新增字节，不反复读取已经处理的历史。
- 事件稳态不会调用 `thread/list`；完整 active/archived 列表只用于启动、人工命令、15 分钟校准或明确的事件丢失恢复。
- 每个真正要发送的候选在 owner 激活前后执行两次 `thread/read(includeTurns=false)` 定向范围核验，并在提交前再次读取最新 summary；RecoveryService 不再枚举 active/archived 全目录。
- 只读 app-server helper 由 Job Object 约束进程树；监测期间复用同一 PID 和 WebSocket，停止监测后的短空闲窗口到期或进程异常时整棵 helper 树都会退出。helper 的 stdout/stderr 原始内容不写日志，只记录是否出现诊断输出。
- 恢复账本最多 256 条、主文件最多 256 KiB；`Accepted` 和 `Confirmed` 必须在观察到不同的后继轮次后才能转为 `Abandoned`，只有 `Abandoned` 可按最旧顺序清理。任务归档只暂停恢复，不会销毁 `Dispatching`、`Uncertain`、`Accepted` 或 `Confirmed` 墓碑。
- 账本只在 `Prepared`、`Dispatching`、确认、明确重试或关闭等状态转换时原子替换，不记录每次扫描、轮询或日志事件。
- 账本只保存任务/轮次/操作 UUID、动作、SHA-256 消息摘要、状态和时间，不保存原始用户消息、附件或推理内容。
- 主账本保留一份上一代文件和一个极小初始化标记；主文件损坏或缺失时先校验并恢复健康的上一代文件，其中可能已投递的 `Prepared`、`Retryable` 或 `Dispatching` 会提升为 `Uncertain`。只有主文件与上一代都不可用时才进入保守闭锁，不把缺失误判为“从未发送”。
- 守护日志上限约 4 MiB，最多保留当前日志和一份轮换日志。临时结构化诊断也只保留当前与上一代，每代最多 2 MiB；它只记录任务/轮次短哈希、证据布尔值、分类、门禁阶段、monitor cycle，以及每分钟最多一条的 WinEvent/合并/观察/超时计数，不记录消息正文、标题、provider 原始错误、路径、token 或 API 密钥。
- 程序不写入 Codex 会话文件，不保存 API 密钥，不上传遥测。
- 唯一的出站网络请求是版本检查：每天最多一次 `GET https://api.github.com/repos/<owner>/<repo>/releases/latest`，只读取其中的 `tag_name`、`draft`、`prerelease` 三个字段。请求头只带 `Ceasy/<版本> (+<仓库地址>)` 这一个 User-Agent（编译期常量，不含机器名、用户名或任何本机信息）、`Accept` 和固定的 `X-GitHub-Api-Version`；不带 cookie、不带凭据、不带任何请求体。响应最多读取 256 KiB，其中的 `html_url` 一律丢弃——界面上打开的地址始终是编译期常量拼出的仓库地址，不是应答方给的地址。检查失败只在日志里留一行状态码或超时，不记录响应正文。可在「设置 → 检查新版本」关闭，关闭后不发出任何请求。

SSD 寿命主要受写入量影响；本程序对会话目录只读。这里仍然限制读取量，是为了避免无意义的 I/O、CPU 和内存抖动，而不是把“大量重复读取”当成可接受行为。

发布验收强制包含至少三个连续的 65 秒空闲样本：预热完成后 helper 必须保持同一 PID 和连接，期间 helper 启动次数、RPC、`thread/list`、定点读取、rollout 索引刷新和账本 generation 都精确零增长。`GetProcessIoCounters` 只作为进程传输 I/O 的灾难性回归护栏，它包含管道、loopback/WebSocket、缓存和设备 I/O，不能称为物理磁盘读取。历史故障曾达到约 38 分钟读取 97 GiB、每轮约 330 MiB；任何接近这种重复读取模式的回归都视为阻断发布的问题。

## 安全边界

Guardian 在发送任何任务数据前会验证命名管道服务端：

- 服务端 PID 来自已连接管道句柄。
- 服务端与 Guardian 必须属于同一 Windows 用户 SID。
- 包族必须准确为 `OpenAI.Codex_2p2nqsd0c76g0`。
- 进程路径必须位于 Windows 登记的准确包安装目录。
- 校验前后服务端 PID 必须保持一致。

程序把“同一 Windows 用户会话”作为本机 IPC 信任边界。它不声称抵御管理员、内核级攻击、合法 Codex 进程注入或同用户恶意代码。

## 数据位置

```text
%LOCALAPPDATA%\CodexGuardian\settings.json
%LOCALAPPDATA%\CodexGuardian\guardian.log
%LOCALAPPDATA%\CodexGuardian\guardian.previous.log
%LOCALAPPDATA%\CodexGuardian\guardian-diagnostics.jsonl
%LOCALAPPDATA%\CodexGuardian\guardian-diagnostics.previous.jsonl
%LOCALAPPDATA%\CodexGuardian\recovery-operations.json
%LOCALAPPDATA%\CodexGuardian\recovery-operations.previous.json
%LOCALAPPDATA%\CodexGuardian\recovery-operations.initialized
%LOCALAPPDATA%\CodexGuardian\follow-up-operations.json
%LOCALAPPDATA%\CodexGuardian\follow-up-operations.previous.json
%LOCALAPPDATA%\CodexGuardian\follow-up-operations.initialized
```

启动基线、定点 `thread/read` 和 summary 核验复用一个独立的只读 Codex app-server helper；监测期间 monitoring lease 保持同一连接，停止监测后才进入 5 秒有界复用与进程树回收。它不执行 `resume`、`rollback` 或 `turn/start`，不创建恢复轮次，也不持有恢复输出流；所有发送都由已验证的 Codex Desktop renderer 执行。`--data-directory` 会让设置、日志、恢复账本和预制消息账本一起写入指定隔离目录。普通路径、扩展路径、设备路径、junction/symlink 和真实目标路径都会经过校验；任何解析到 `%USERPROFILE%\.codex\sessions` 或 `CODEX_HOME\sessions` 的目录都会被拒绝。

## 系统要求

- Windows 10/11 x64
- 官方 stock Codex Desktop，已正常登录并注册 `codex://` 协议；不要求用户预先安装补丁、注入组件或修改 Codex 文件
- 正式 `win-x64` 运行包已自带 .NET 8 桌面运行库，无需用户另行安装

程序会在运行时自行检测内部协议兼容性。Codex Desktop 更新后如显示不兼容，守护会保持只监测并等待新版程序，而不会对 Codex 做补丁。

## 构建与测试

```powershell
$phase = 'D:\CodexData\CodexGuardian\manual-validation'
$temp = 'D:\CodexTemp\CodexGuardian\manual-validation'

$env:WINDIR = 'C:\Windows'
$env:SystemRoot = 'C:\Windows'
$env:DOTNET_CLI_HOME = 'D:\CodexData\CodexGuardian\dotnet-home'
$env:NUGET_PACKAGES = 'D:\CodexData\CodexGuardian\nuget'
$env:TEMP = $temp
$env:TMP = $temp

New-Item -ItemType Directory -Force -Path $phase,$temp | Out-Null
dotnet build .\work\CodexGuardian.Tests\CodexGuardian.Tests.csproj `
  -c Release `
  --artifacts-path $phase `
  --nologo

$tests = Join-Path $phase 'bin\CodexGuardian.Tests\release\CodexGuardian.Tests.dll'
dotnet $tests --watcher-only
dotnet $tests --package-baseline-live-readonly
```

### 隔离的预制消息界面预览

预制消息编辑器的开发验收必须运行 fresh 构建的 `CodexGuardian.exe`，并显式使用
`D:\CodexData\CodexGuardian` 下的 phase 子目录：

```powershell
$guardian = Join-Path $phase 'bin\CodexGuardian\release\CodexGuardian.exe'
$previewData = Join-Path $phase 'preview-data'

& $guardian `
  --safe-preview `
  --follow-up-preview-fixture `
  --data-directory $previewData
```

`--follow-up-preview-fixture` 不能脱离 `--safe-preview` 使用；safe preview 也不再回退到
`TEMP` 或真实 `%LOCALAPPDATA%\CodexGuardian`。该模式只装载一个内存虚拟任务和两条
虚拟消息，用于检查增删、排序、正常完成触发、定时触发和隔离保存。它不会启动监测、
app-server、Desktop IPC、deep observation、WinEvent/UIA Hook、托盘或发送服务，自动恢复
保持关闭。此预览通过只代表 GUI 和隔离门通过，不代表 live 预制消息发送、真实恢复或发布
已经验收。

构建、测试、NuGet、CLI home 和临时文件必须从一开始就写入上述 D 盘隔离目录；
不能先在源码树或 C 盘生成再迁移。验收必须直接运行刚构建的 DLL，不能使用会在
源码树重新生成 `bin/obj` 的 `dotnet run`。任何会启动 Guardian 的开发验证还必须
提供独立的 D 盘 `--data-directory`，不得使用真实的 `%LOCALAPPDATA%\CodexGuardian`。

发布脚本的只读/离线候选验证入口：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\work\package-release.ps1 -ValidateOnly
```

脚本会自行固定 `WINDIR`、`SystemRoot`、`DOTNET_CLI_HOME`、`NUGET_PACKAGES`、
`TEMP` 和 `TMP`。默认 scratch 位于 `D:\CodexData\CodexGuardian\release-package`，
每次运行使用唯一工作目录；TEMP 使用独立的
`D:\CodexTemp\CodexGuardian\package-release\<run-id>`。可选 `-ScratchRoot` 也只能
指向 D 盘的非 reparse 目录。脚本会拒绝源码树已有或新生成的 `bin/obj`，并为其
唯一 scratch/TEMP 清理写入 JSON manifest。

运行中的 Guardian 会在任何构建或发布写入前阻断脚本；应先通过托盘“退出”正常
关闭 Guardian，不需要退出或重启 Codex Desktop。当前 r13 尚未通过真实恢复、
Guardian 内部 live observation、长时间 GUI/性能、安装、升级和卸载验收，因此不得
去掉 `-ValidateOnly` 生成或交换正式发布产物。

发布脚本不提供跳过测试参数，会强制运行构建、确定性恢复分类回归、实时监听回归、定点事件核验、65 秒空闲 CPU/I/O 门禁、版本检查和暂存包内容检查。运行目录、源码目录、两个 ZIP 和 SHA-256 都先生成 `.next` 候选并完成校验，再使用同卷 `.previous` 进行可回滚交换；交换后仍会复核必需文件、禁止 Codex 安装器/补丁器/Desktop 修改载荷、ZIP 条目和 SHA-256，全部成功后才清理上一版。
