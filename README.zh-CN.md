# Surge Guard

同一公开仓库管理三个组件：系统级网络门禁 `surge-guard`、用户级应用启动与恢复服务
`surge-gate`、SwiftBar 菜单。Swift 实现，无第三方运行时依赖。

默认行为是“Surge 增强模式就绪才允许普通联网”；也可配置“增强模式就绪，且指定域名
分流到指定策略组和允许节点才放行”。域名、策略组、节点和应用列表都属于本机配置，
公共代码不绑定某个用户、服务或网络。

Surge 增强模式接管正常应用流量，再按其规则代理或 DIRECT。本工具检查接管就绪并控制
PF；它仍是实验性外部门禁，不能证明每个数据包都不可绕过，也不能保证开机最早阶段或
守护被强杀时零泄漏。完整命令与协议以 [README.md](README.md) 为准。

新版系统守护每 30 秒在后台采样约 1 秒的 socket 活动，记录 nettop 报告的接口、进程、
本地/远端端点及本次字节增量。这些是 socket 计数，并未验证数据包实际路径，不能据此
确认绕过或确认全部经 Surge。仅接收与有发送计数分别标注；UDP 远端通配符保持未知，
不会归为公网。UDP 本地端口 5353 只提示 mDNS 常用端口，不能证明目标或路径。
系统扩展、局域网/保留地址和未知远端分别标注，不会自动批准独立网络，也不修改 PF。
重复证据五分钟内去重；同一 socket 从仅接收转为有发送，或 PF 批次/状态变化后，会重新记录。
公网发送线索优先保留。采样记录关联开始、结束门禁状态；期间发生切换时明确标为混合区间，
不会把整段字节按结束状态判作已放行或已阻断。手动或旧版记录未跟踪切换时明确显示未知。每次最多记录
20 条新证据，沿用每组件当前/上一份各 1 MiB 的日志轮转。每五分钟保留观测摘要和覆盖缺口，
普通用户 `observe-egress` 的文字与 JSON 输出都使用结构化 `flows[].candidate_domains`，
每条 socket 最多五个去重候选域名；IP 匹配规范化 IPv6 写法及 IPv4-mapped IPv6。
虚拟 IP 同时兼容原始 `d`／整数 `i` 和导出 `domain`／`IP` 格式。
`domain_queries` 分别记录 DNS 与虚拟 IP 查询的 `ok`、`empty`、`failed`（附原始错误）或
`unavailable`；后台守护标为 `not_requested`，root 不执行用户所有的 Surge CLI。
候选域名仅是缓存线索，不是该连接请求域名或实际路径的确认。
采样失败/恢复单独记录。SwiftBar 的“查看连接采样（只读）”可立即查看。
更新用户菜单只增加手动检查；后台持续记录需要安装新版系统守护。

阻断期间约每五秒、准备放行前，读取本工具 PF 阻断规则的计数，记录为 `pf_block_traffic`：
包括本次增量、当前规则累计、入站/出站包数与字节数，以及阻断批次和单调时间边界。
这能说明本规则命中了多少包，但不包含逐包的进程或目标。最后读取到清除规则之间仍可能有
未计入的命中；重载、读取失败或计数回退会明确记录缺口，不能把它们记成零包或无绕过。
不启用抓包、不改变 PF 规则；计数读取失败不改变放行条件，读取后的就绪与分流有效期会重新确认。

采样覆盖不到间隔内的所有短连接，也不具备完整的逐包审计能力；没有记录不代表确认无绕过。
日志保存毫秒时间和单调时钟；Surge 退出事件会记录“收到退出事件到 PF 阻断验证”的耗时，
该数值不等于实际退出至最后一个逃逸数据包的时间，也不承诺固定几十毫秒内完成阻断。

系统守护现在直接订阅已验证的 Surge 网络服务状态，收到“正在断开”等失效状态或进程
退出事件时，先加载阻断规则并清理旧连接状态，再进行其余条件和 PF 完整性检查。
`readiness_loss_blocked` 分别记录事件收到/发现失效、规则加载完成、阻断验证与旧状态
清理完成的时间；重新放行仍须通过全部接管和分流条件。此改动需更新系统守护才会生效。
它仍有事件通知和执行延迟，尚不能保证逐包零绕过。Surge 官方将 `include-all-networks`
列在 iOS 专用参数中，不能据此宣称 Mac 已启用系统级断开保护。

连续包级记录是单独启用的可选组件：使用系统 PKTAP 同时记录物理、隧道及回环接口，
默认 256 MB 环形抓包文件，每包保留前 256 字节及可用元数据，可能含少量应用数据。
同时在降权后的用户会话查询并保存 Surge 请求元数据，不保存 URL 参数、请求头或正文。
采集缺口、丢包、Surge 请求窗口滚动和进程变化会留痕；恢复采集不会清除历史缺口标志。
SwiftBar 单独提供状态、留存时间范围、预览、日志和启停入口，安装它不重启网络守护或修改 PF。
抓包运行与完整归属验证是两件事，未知包不能直接判为绕过；环形覆盖之前的历史不可还原。
详细安装、权限、保留范围和局限见 [包级审计说明](docs/packet-audit.md)。

## 合并诊断与短时取证

更新用户菜单后，可选“合并检查最近 20 分钟”或“120 秒 DNS／QUIC 诊断”。普通用户也可运行：

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui" diagnose
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui" diagnose --minutes 20 --watch-seconds 120 --json
```

菜单中的认证仅用于固定命令读取 root 私有事件文件；取消认证仍会生成标明缺口的部分报告。
直接命令不会弹出认证，没有可用 sudo 凭据时记录读取失败。收集与格式化始终以普通用户执行，
不修改 PF、DNS、Surge、Gate 或抓包器状态，也不发起外网连通性测试。

报告合并当前状态、两份 Guard/Gate 事件文件和最多四份 Surge 日志尾部。短时观察每两秒
查询最多 2,000 行内存日志，仅保留 DNS／QUIC／UDP socket 上下文；最多运行 300 秒。
最多保留 1,500 条最新记录、2 MiB 证据预算，序列化上限 6 MiB；文字显示最后 80 条。
`diagnostic-report.json` 及上一份 `.json.1` 保存于用户 SurgeGuard 状态目录，权限 `0600`。
尾部读取多检查一个边界字节，不占保留输入预算；完整的 1 MiB 事件文件不会误标为截断，
已知截断产生的首行残片不计为坏 JSON。memory 轮询聚合为一个来源摘要，保留采样次数
`observations` 和整体观察范围；真正不重叠的窗口仍单独记录证据缺口。
观察中每十秒写检查点，保留上一轮报告；中断可能丢失最后一个检查点后的记录。
检查点标记 `collection_finished: false`；正常完成才设为 true，该字段不代表历史覆盖完整。
报告含本机地址、路径和域名，不要公开或提交。权限不足、日志截尾、时间范围、格式损坏、
内存窗口不重叠和容量省略都保留标记；可见时间范围不证明连续覆盖。
报告不会自动宣布根因或“无逃逸”。需要包级证据时另行启用现有独立审计器，诊断不会自动开启抓包。

此功能只需 `scripts/install-user.sh --menu-only`，不替换或重启 Guard/Gate/Surge。
“准备升级 Surge”与“升级结束并恢复 Surge”继续使用已有的暂停/恢复握手；收到 Gate 确认
后才显示成功，恢复自动操作仍需等待菜单中的增强模式和 PF 验证。原有 30 秒失败退避保留。

## 可选的常驻 TCP 限制

可选的常驻 TCP 模式使用 `"persistent_tcp": true`，须先升级系统守护、专用启动器和
SurgeGate，再将该字段加入原配置，保留原有分流条件。省略或设为 `false` 保持响应式
门禁；旧版程序不认识此字段，不能先更新配置再升级。

此模式在放行状态也保留 PF 规则：普通 IPv4 TCP 只允许经已验证的 Surge VIF 和预期
源地址；Surge 专用有效组的 TCP 可以出站；其余非回环 TCP 默认拒绝，包括 IPv6。
UDP 不在此开关的常驻保护范围内，不能据此宣称所有协议零逃逸。
放行连接状态绑定接口，不允许 VIF 状态自动在物理接口匹配。当前版本不提供普通应用
IPv6 的 VIF 例外，也不提供 Tailscale、其他 VPN 或普通用户身份例外。局域网 TCP 默认
阻断，可按下文显式启用例外。就绪或分流条件失败时，执行阻断与本机旧连接状态清理，
仅保留已配置的局域网 TCP 例外。

只要求经过 Surge、允许 Surge 自己决定 DIRECT 或代理时，可明确应用
`examples/persistent-tcp.json`（`enhanced` + `persistent_tcp: true`）。
用户安装器保留现有系统策略、规则草稿和更新暂停状态，不静默取消已有分流限制。

常用局域网 TCP 直连可在原策略中加入 `"allow_lan_tcp": true`，要求同时启用
`persistent_tcp: true`。**须先升级 Guard、Gate 及其运行中的进程，以及菜单渲染器，
最后才写入新字段**；旧程序会拒绝它。保留原来的模式和域名分流条件，通过已安装的
`configure` 应用，再检查新鲜状态。省略或设为 `false` 保持原有默认限制。

例外仅允许：本机已启用的 `enN` 有线／Wi-Fi 网卡的实际私网 IPv4 地址，与
`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 对端之间的入站和出站 TCP。
规则同时限定本机地址、接口和连接状态，不放开公网、VPN／网桥、通用 IPv6
或 CGNAT。允许通过局域网路由器访问其他私网段，不限于当前直连子网；不授权本机转发流量。

同一选项也放行 **Apple USB NCM 接口上的 IPv6 链路本地 TCP**，用于 iPhone／iPad
有线开发连接。通过原生 IOKit 识别 Apple 厂商及 NCM 驱动，只接受已启用接口上的实际
`fe80::/10` 地址，规则限定接口、本机地址、对端 `fe80::/10` 和接口绑定的连接状态。
CoreDevice 创建的第二层 `utunN` 开发隧道也允许其实际 ULA 地址与自身 ULA /64 内的 TCP；
通过有界的系统 `remotectl dumpstate` 清单识别，不放行其他 VPN。新增开发隧道时保留已有
USB 承载连接；撤销例外或其他策略变化仍阻断并清理旧连接。
插拔后动态识别网卡名；枚举失败时撤销例外。不放开 Wi-Fi、公网 IPv6，
也不增加通用 iCloud 或 Apple 服务绕过。

Surge 或分流检查未就绪时仍保留局域网 TCP，方便 SSH／文件共享和本地排障。
网卡或地址变化会重载并清理对应本地地址／对端的旧连接。USB 可选枚举失败只撤销 USB
例外，保留已验证的 LAN 范围；LAN 可选枚举失败同理。`local_tcp_errors` 和菜单会显示
警告，不把有效公网策略误报成配置无效。必要的接管／地址探测失败仍整体阻断；
配置无效会撤销两类例外并阻断。
开机、升级及状态清理仍可能短暂打断局域网连接，不能将它当作独立的带外恢复通道。
此选项不增加阻断状态下的 UDP DNS／mDNS 放行，排障时可能需要直接使用 IP。
`status --json` 的 `snapshot.lan_tcp_enabled`、`lan_tcp_bindings`、`usb_tcp_bindings`
和菜单均显示有效范围。

启用后，“已阻断”指例外范围以外的网络；公网 TCP 和现有就绪／域名检查保持限制。
允许的局域网设备可能继续代理流量，因此不能声称所有连接都经过 Surge。被 Surge 接管的
局域网连接仍由 Surge 策略决定；只添加 Surge 的 DIRECT 规则，不能覆盖 Guard 对物理接口
直连 socket 的阻断。

更新 Surge 前，在菜单点“准备更新 Surge”，等 Gate 确认暂停后再启动官方更新。
暂停自动启动、身份修复和应用恢复；当前 Surge 不被该按钮退出，Guard/PF 独立运行。
更新完成或取消后点“恢复自动启动”。更新卡住不会自动解除保护、强杀更新器或自动恢复。
需要在 Surge 退出后联网的安装流程，应先在 Surge 正常时下载完整安装包。

暂停保存在私有 `update-mode.json`，跨 Gate 重启和电脑重启保留；损坏或读失败时暂停
自动操作并报告错误。确认超时仍保留请求，不能开始更新。已有退出/启动操作须完成后才
确认暂停；暂停期间拒绝有序关机请求。启动超时不会取消 NSWorkspace 请求或 launchd 提交。
`pending-launch.json` 记录 Gate 实例和请求对应的任务标识，并分开保存 launchctl 提交进程与
实际启动器／Surge 的 PID 和出生时间。仍在排队的任务、存活的提交进程、未验证的启动器或
尚未结束的回调继续阻止暂停确认；提交命令结束不代表 Surge 启动完成。Gate 重启后，须验证
对应任务进程的 Surge 身份；任务已不存在且已记录的提交进程／子进程退出或 PID 被复用时，
按失败处理并退避 30 秒后恢复。兼容旧的直接子进程记录；未决启动期间不要降级 Gate。

若 Gate 在保存子进程身份之前崩溃，或丢失了 NSWorkspace 回调，仅凭应用没有出现无法确认
请求已取消。Gate 会显示 `launch_recovery_required`，给出应用和请求 ID。独立确认旧启动
已完成、失败或取消后，可用普通用户运行：

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" status --json
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" recover-launch REQUEST_UUID --confirm-settled
```

将 `REQUEST_UUID` 换成新鲜状态中的 `pending_launch.id`。该命令依赖你的明确确认，只清除
对应的孤立请求，不会取消 LaunchServices 操作，也不会解除已有更新暂停。恢复与关机消费共用
请求锁；若取得锁时启动记录已经变化，会重新观察后再处理关机请求。无法确认时须继续
等待或重启电脑，使旧 boot 请求失效；超时和手工删除标记都不代表启动已取消。
有序关机会明确拒绝未决启动；已经排队的关机请求也会被消费并拒绝，不要求应用退出，避免
以后恢复启动时意外执行旧关机请求。若服务启动失败且请求尚未消费，则按 nonce 撤回，允许
重试；已消费的请求须查状态和日志确认结果。Gate 配置、会话和状态文件实行大小上限，拒绝
符号链接及特殊文件，要求当前用户属主且无组或其他用户访问权限（通常为 `0600`）。
配置中每个应用列表最多 256 个 Bundle ID，每个最多 255 个 ASCII 字符；`gate.json`
上限为 256 KiB。会话中的每个列表最多 1024 个 ID，允许启动列表与保存列表合并，
不静默截断；会话与 Gate 状态读取上限为 1 MiB。每次保存前按读取规则验证，超限时
报错并保留旧检查点。读取上限更小的旧版 Gate 无法读取这种较大的新检查点。

真实恢复失败执行 30 秒退避；单纯等待 Guard
确认阻断不占用退避。每次身份修复只发送一次正常退出请求，不强制终止。
`surge-gate 命令 --help`（或 `-h`）只显示帮助；未知、重复或多余参数会在取得管理锁、
执行服务操作之前被拒绝。

安装器创建无普通成员的 `_surge_guard` 组，并安装 root 所有、模式为 `2755` 的固定
`surge-guard-launch`。它设置专用 real/effective GID，不赋予 root 用户身份；验证官方 Surge 签名后执行固定路径。普通用户执行该启动器的 `--check` 可以只读核对 UID/GID 和签名。
启动器以不跟随符号链接的方式打开各级目录和可执行文件，在签名验证前后对照
`fstat` / `lstat` 等价信息中的设备、inode、属主、权限、大小及修改时间，发现替换或修改就拒绝启动。
`/Applications/Surge.app` 保留普通用户属主及原有可写权限，以兼容应用内 Sparkle 自动更新。
这些检查缩小了竞态窗口，但签名验证与按路径 `execve` 仍非原子操作；最后一次检查至执行的
窗口，以及同用户恶意进程对应用包的写入，不属于当前启动器能完全防御的边界。
SurgeGate 会在确认阻断后，以正常退出方式纠正 Surge 的错误启动身份，再调用启动器；
退出被拒绝或超时就保持错误状态，不强制终止，也不退回普通身份放行。

每次专用启动都使用当前用户 GUI 域中的独立一次性 launchd 任务，启动器和 Surge 的父进程
因此为 launchd，而不是 Gate。这避免触发某些 VPN 客户端按父 PID 处理 DNS 端口冲突的
直接终止分支，但不能阻止管理员或其他特权程序终止 Surge。任务不自动重启，进程退出后
自动移除；私有暂存 plist 放在状态目录中，不放进 `~/Library/LaunchAgents`，不会独立随登录
启动。已有的有效 Surge 继续沿用；部署新 Gate 不会改变已有进程的父进程，新路径用于下次
专用启动。
若未决启动期间把策略从 persistent TCP 切到 enhanced，同一个经过签名验证、PID 和原生
出生时间匹配的子进程可按当前策略结束等待；无关进程不能代替它完成请求。

目前专用启动器只控制经过它的启动，不能强制 Finder、Dock 或更新器独立启动的实例
从第一刻就使用专用组。检测后重启属于恢复机制；若要求所有入口、包括更新后的第一次
启动都具有该身份，还需要安装或执行前的控制，不能宣称当前实现已经满足。

状态 JSON 的 `enforcement` 应为 `persistent_tcp_egress`，放行时自身 anchor 不应为空。
守护卡住时已有规则继续保留，但状态应正常过期；开机最早阶段、接口重用、系统更新和
管理员修改 PF 等边界仍须单独验收，不能把规则存在或编译成功当成零逃逸证明。
详见 [验收步骤](docs/acceptance.md) 和 [实测记录](docs/verification.md)。

## Agent 从这里开始

1. 阅读 README 和 `AGENTS.md`，先检查已有安装、配置、服务和日志。
2. 构建并执行只读检查。`check` 成功只代表条件通过，不代表 PF 已运行。
3. 为目标机器准备明确的配置，先验证，再安装。
4. 先安装并确认 SwiftBar 离线恢复入口可用，再更新系统守护；确认系统状态后安装 SurgeGate。
5. 排障从 `doctor`、最近日志和具体原因开始；实机验收单独记录，不用构建成功代替。

### Agent 快速索引（组件职责、路径与常用操作）

| 组件 | 可执行文件 / Launchd 标签 | 状态与配置文件 | 常用命令与应急操作 |
| --- | --- | --- | --- |
| **surge-guard**（Root 防火墙门禁） | `/Library/PrivilegedHelperTools/surge-guard`<br>`system/io.github.surge-guard` | 策略：`/Library/Application Support/SurgeGuard/policy.json`<br>状态：`/Library/Application Support/SurgeGuard/status.json`<br>日志：`/private/var/db/surge-guard/events.log` | **应急暂停保护并放行网络**：`sudo /Library/PrivilegedHelperTools/surge-guard unlock`<br>**重新启用保护**：`sudo /Library/PrivilegedHelperTools/surge-guard start`<br>**只读查看非 Surge 连接与候选域名**：`surge-guard observe-egress` |
| **surge-guard-launch**（专用组启动器） | `/Library/PrivilegedHelperTools/surge-guard-launch`（`root:_surge_guard`，权限 `2755`） | 专用组记录：`/private/var/db/surge-guard/egress-group.json`（GID `60000...60999`） | **只读校验 UID/GID 与 Surge 签名**：`/Library/PrivilegedHelperTools/surge-guard-launch --check` |
| **surge-gate**（用户态伴随服务） | `~/Library/Application Support/SurgeGuard/bin/surge-gate`<br>`gui/$UID/io.github.surge-guard.gate` | 配置：`~/Library/Application Support/SurgeGuard/gate.json`<br>状态：`~/Library/Application Support/SurgeGuard/gate-status.json`<br>更新模式：`~/Library/Application Support/SurgeGuard/update-mode.json` | **手动退出或升级 Surge 前暂停自动重开**：`surge-gate update-pause`<br>**升级或维护完成后恢复**：`surge-gate update-resume`<br>**停止/启动服务（不影响当前联网与 PF）**：`surge-gate stop` / `surge-gate start`<br>**有序重启/关机（保存会话并安全断网）**：`surge-gate shutdown --action restart\|shutdown` |
| **surge-guard-audit**（按需抓包审计，默认关闭） | `/Library/PrivilegedHelperTools/surge-guard-audit`<br>`system/io.github.surge-guard.audit` | 目录：`/private/var/db/surge-guard/packet-audit/` | **临时开启连续抓包**：`sudo /Library/PrivilegedHelperTools/surge-guard-audit audit-start`<br>**停止抓包并禁用开机自启**：`sudo /Library/PrivilegedHelperTools/surge-guard-audit audit-stop` |

不要将本机配置、Surge profile、订阅、节点凭据、原始日志或诊断包提交到 GitHub。

## 构建与只读检查

需要 macOS 13+、Swift 5.9+ / Xcode Command Line Tools，以及 Network Extension 版本的
Surge Mac 增强模式。分流检查需要支持 `rule explain` 的 Surge CLI（Mac 6.9+）。

```sh
scripts/check.sh
.build/release/surge-guard check --json
.build/release/surge-guard status --json
```

构建会产生 Guard、Gate 和专用组启动器。未安装新版守护时，`status` 显示未知是合理结果。
检查脚本不加载防火墙、不退出应用，也不安装任何服务。

## 配置联网条件

仅检查增强模式，沿用原有行为：

```json
{"version":1,"mode":"enhanced","route_checks":[]}
```

默认必须通过六项：Surge 官方签名进程、主服务属于 Surge、扩展已连接、VIF 已启用且地址
正确、IPv4 默认路由指向 VIF、没有冲突的全局 IPv6 主接口。不固定 utun 编号。
只有动态存储明确返回 NoKey 才视为没有全局 IPv6 路由；读取错误、类型错误、存在但
缺少有效主接口的字典均不能放行。

需要分流条件时，复制通用示例，填写目标机器上的真实值：

```sh
cp examples/routes.json policy.local.json
.build/release/surge-guard validate policy.local.json
.build/release/surge-guard check --config policy.local.json --json
```

```json
{
  "version": 1,
  "mode": "routes",
  "route_checks": [
    {
      "url": "https://example.com",
      "required_group": "Residential"
    }
  ]
}
```

`routes` 模式要求增强模式就绪、当前为 Rule 模式、所有 URL 检查均通过。
策略组名称精确匹配并解析到代理，支持嵌套组。省略 `allowed_final_policies` 时，
组内更换代理节点不需要修改门禁配置。如果还要限制最终节点，可以额外填写
`"allowed_final_policies": ["Residential A", "Residential B"]`；已有白名单仍然有效。
显式填写空数组或 null 会被拒绝。两种配置都拒绝 DIRECT/REJECT、错误策略组、无效配置及查询失败／过期；
填写了白名单时，还会拒绝不在名单内的节点。组选择链必须连续、无环并终止于已识别的代理类型；
缺失 selected、未解析组或未知最终类型均保持阻断。
不会根据名称中“包含美国”等文字猜测节点属性，也不进行出口 IP 或网站连通性探测。
配置 URL 使用默认请求上下文；实际应用的进程、协议或 URL 特定规则可能影响结果。
状态与各 URL 查询并发执行，helper 总时限为三秒；结果仍从查询派发时起三秒过期，
不因查询慢而延长。网络事件会拒绝旧代际的在途结果，已完成结果只保留到原有效期。

本机策略和状态文件可供普通用户读取，禁止在 URL、查询参数或策略名称中放入秘密。
最多八条检查；未知配置字段、带凭据或包含原始控制字符的 URL 会被拒绝。

## 安装／升级系统守护

在本机操作。**先以普通用户安装离线恢复组件，确认菜单可用，再改系统守护：**

```sh
scripts/install-user.sh --recovery-only
```

已有控制中心时，按下文接入 `surge-guard-menu --section`；独立菜单则将
`integrations/swiftbar/surge-guard.5s.sh` 复制到 SwiftBar 插件目录。
确认“恢复与备份（离线可用）”已显示。该入口兼容旧版守护，网络断开时仍可用。
同时离线保留恢复命令：

```sh
sudo /Library/PrivilegedHelperTools/surge-guard unlock
```

```sh
sudo .build/release/surge-guard install
sudo /Library/PrivilegedHelperTools/surge-guard configure policy.local.json
```

上面是全新安装的顺序：先安装固定系统程序和启动器，再配置策略，最后才启动守护。
常驻 TCP 配置依赖已安装的启动器来准备专用组；首次 `install` 本身不会启动新守护。
升级已有守护时，先保留现有策略安装新程序，验证状态，再用新程序应用新策略：

```sh
sudo .build/release/surge-guard install
/Library/PrivilegedHelperTools/surge-guard status --json
sudo /Library/PrivilegedHelperTools/surge-guard configure policy.local.json
```

旧程序要求 `allowed_final_policies` 必填；不要在升级前给旧守护应用省略该字段的新配置，
否则它会按无效配置阻断联网。

首次不执行 `configure` 时生成 enhanced 配置；升级保留已有配置。
全新安装还需要启动：

```sh
sudo /Library/PrivilegedHelperTools/surge-guard start
/Library/PrivilegedHelperTools/surge-guard status --json
sudo /Library/PrivilegedHelperTools/surge-guard doctor
```

升级已运行服务前自动保存 root 专用备份，再正常停止旧服务，**等待防火墙锁实际释放**，
最多 20 秒。`bootout` 返回不代表旧进程已经退出。之后原子替换、启动，并等待新 PF 状态验证；
升级前就绪时，须重新达到放行。失败自动尝试恢复上一版文件并重启，恢复成功也会明确报告升级失败。
不需要先 unlock。
分流模式升级会在停止旧服务前，先用暂存的新程序验证用户会话查询通路；预检失败就中止升级，
因此升级时保持 Surge 运行。此预检不修改 PF。
可能短暂中断已有连接；若自动恢复也失败，使用菜单中的“应急解除阻断”。
系统守护以 root 运行，但执行用户所有的 Surge CLI 前，会进入登录用户会话并降低权限。

macOS 更新若移除了 PF 挂载段，新版守护或 `start` 仅在磁盘配置仍是可识别的 Apple
默认规则布局、live 过滤规则为空或仅含预期 Apple 挂载（中断后重试时可带本工具挂载）
时自动恢复。要求已有可信安装、原始安装备份和未改动的默认阻断 anchor；自定义规则、
不完整标记、顺序冲突或不安全的文件会被拒绝，应先查看 `doctor` 和日志。
恢复持有防火墙运行锁，先检查语法，将最近一次修复前的配置私密备份至
`/private/var/db/surge-guard/pf.conf.before-attachment-repair`，再仅加载含阻断规则的过滤挂载，
复核并发修改后原子补回磁盘配置。不重载 Apple 子 anchor、NAT 或 PF 选项。
PF 启用、旧连接清理及正常核验完成前，不发布已验证放行／阻断状态。
挂载准备失败时先尝试正常阻断，再报告原始错误，避免旧 live anchor 仍处于放行而直接退出；
若阻断也失败，会明确报告保护未经验证。
菜单提示磁盘挂载缺失不等于 live PF 已阻断；没有额外监视器启动已卸载或禁用的守护，
未进入系统更新维护时，手动 `unlock` 仍保持启动／下次开机恢复的语义。
旧的非回环地址保存在私有、绑定本次开机的 `addresses.json` 中，最多 512 个地址／64 KiB。
守护重启后先读取再清理旧 states；枚举或清理失败保留重试依据。记录损坏时不声称保护
已验证，仍尝试清理当前可枚举地址的 states。

上述挂载修复负责在正常已安装系统中恢复保护，与下面的系统更新维护模式分别处理，
不保证所有安装器环境兼容。系统更新在普通系统内运行时仍可能需要网络；
Gate 的 `update-pause` 本身不豁免更新流量。

### macOS 系统更新维护

使用前先升级 **Guard 和 Gate 两个组件**，并安装独立离线恢复菜单。
在 SwiftBar 点击 **「准备更新 macOS」**，或运行：

```sh
sudo /Library/PrivilegedHelperTools/surge-guard os-update-begin
```

这是管理员明确授权的 **跨重启暂停全部应用的 SurgeGuard 网络保护**。
所有应用都可能直接访问公网，并非仅放行 Apple 更新。操作不会退出 Surge，
也不保证网络一定可用；建议先关闭无关的敏感应用。菜单持续显示橙色和维护时长。

准备阶段先保存私密版本／配置备份，再等待当前桌面用户的新版 Gate 以本次请求编号、
当前开机和进程绑定的新鲜状态确认暂停。未结束的启动、待确认的遗留启动、排队或进行中的
电源操作、旧版或已停止的 Gate 都会阻止确认；处理后重试，或用 `os-update-end` 取消准备。
确认前不会解除保护。确认后，Gate 暂停自动重开 Surge、身份修复、应用恢复和周期会话快照；
已有会话和独立的 Surge `update-pause` 偏好保留。

仅清空本工具的磁盘 anchor 与 live 规则，保留其他 PF anchor、NAT、PF 全局启用状态和
原策略配置。守护继续核验自身规则为空，重启后也遵守维护状态；`status --json` 返回
`maintenance`，不显示已验证放行／阻断，也不宣称保护生效。
维护快照使用版本 2，旧读取器会显示待验证，避免误报阻断；正常保护仍使用版本 1。
root 所有的 `/Library/Application Support/SurgeGuard/system-update.json` 记录
`preparing`、`active` 或 `restoring`。请求已保存不代表解除或恢复已经成功；
必须看到 **VERIFIED MAINTENANCE** 后再用 macOS 自身入口开始更新，
不要用 Gate 的有序关机／重启替代安装器的重启流程。

维护 **不会因超时、守护重启或电脑重启自动结束**。更新完成或取消后，点击
**「结束维护并恢复保护」**，或运行：

```sh
sudo /Library/PrivilegedHelperTools/surge-guard os-update-end
/Library/PrivilegedHelperTools/surge-guard status --json
```

结束操作也能取消未完成的准备。它恢复开机阻断 anchor，按已有严格条件修复缺失挂载、
清理旧连接，并等待新鲜的正常 PF 保护核验通过，再删除维护记录，让 Gate 恢复工作。
`blocked` 代表阻断保护恢复成功，不代表已经联网；仍须通过 Surge 和所有原策略检查。
原有 Surge 更新暂停偏好仍保持暂停，须单独执行 `update-resume`。
恢复保护时已有连接可能重置。

失败会保留记录，应重试，不要通过删除记录强行结束。准备／维护阶段可重试
`os-update-begin`，或结束／取消；恢复一旦开始则重试 `os-update-end`。
记录存在时拒绝 Guard 的普通启动、重启、安装、改配置和回滚，避免绕开维护状态。
结束维护先无锁读取记录、停止守护，再持有运行锁复查并保存恢复状态；没有记录时不动服务。
记录变化、损坏或无法写入时，会在锁内尝试阻断并报错，不能冒充维护结束。
Gate 发现维护期间的排队电源请求会撤销并记录 `shutdown_declined`，不留到结束维护后重放。
状态、日志和独立应急解除规则仍可离线使用。应急解除不会清除维护记录，
之后仍须 `os-update-end`，电脑重启也不会代为结束。
菜单渲染器损坏时保留结束维护入口；特权程序损坏时仍可使用独立应急解除规则入口。
维护记录损坏时，守护启动和 `os-update-end` 会先尝试恢复阻断启动 anchor、修复支持的
attachment 并阻断，再报告原始错误。损坏记录保留待管理员修复，阻断成功不等于维护
已结束。CLI `unlock` 在记录存在或不可读时仍可显式使用。

更新后复查 Guard/Gate 新鲜状态、菜单及 SwiftBar 登录启动。
单元测试不能证明真实安装、固件／个性化阶段、恢复系统兼容性或开机早期覆盖，
相关场景须按验收文档另行授权测试。

“恢复与备份”提供：正常重启并等待验证、启动／恢复保护、备份当前版本与配置、恢复上一版、
恢复上一次规则，以及应急解除阻断。管理员操作在终端显示影响、授权和结果，不再使用
`kickstart -k` 强杀。应急入口独立于守护程序和策略，先等待旧 PID 退出，再清除此工具的
anchor；不会全局关闭 PF。**应急解除会关闭本工具的保护；普通状态下启动守护或下次开机恢复，
系统更新维护期间则必须显式结束维护。**

```sh
sudo /Library/PrivilegedHelperTools/surge-guard backup
sudo /Library/PrivilegedHelperTools/surge-guard rollback
sudo /Library/PrivilegedHelperTools/surge-guard restore-policy
```

若系统程序不可用，在本地终端以普通用户运行独立恢复入口：

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-action" unlock
# 已安装入口缺失时，可使用经过审查的仓库副本：
# /bin/bash integrations/swiftbar/surge-guard-action.sh unlock
```

该脚本验证服务状态与 PID，等待旧进程退出并再次确认服务已卸载，再清空自身 anchor。
清空操作持有管理锁和运行锁，避免与并发启动或守护最终阻断竞争，并记录 macOS 系统
日志。独立入口不发布 CLI 的 unlocked 标记；菜单 stopped／unknown 不代表实时 PF 结论。
不能把 `bootout` 返回视为进程退出；查询失败时会中止，不执行清空规则。

系统备份位于 `/private/var/db/surge-guard/backups/<id>`，仅 root 可读。
升级／手工备份与规则变更前的备份分开保存，保留历史，不整份覆盖其他服务修改过的 `pf.conf`。
恢复旧版可能减少保护条件，尤其旧版仅检查增强模式，需明确核对。首次安装没有上一版可恢复。

## 安装 SurgeGate 和 SwiftBar

安装插件不等于设置 SwiftBar 登录自启。请启用 SwiftBar 的 **Launch at Login**，
或将应用加入 macOS **登录项**，并在重新登录后验收。只确认当前菜单能显示不算自启验收。

新版系统守护安装完成后，以普通用户执行：

```sh
scripts/install-user.sh
```

自动读取 SwiftBar 插件目录，也可显式传入目录。已有单一控制中心时使用：

```sh
scripts/install-user.sh --menu-only
```

`--menu-only` 与 `--recovery-only` 都只更新独立菜单文件，不查询或重启 Guard/Gate，
也不替换 Gate 可执行文件。需要安装／升级伴随服务时，另行执行
`.build/release/surge-gate install`，该命令会重启用户服务。
再将控制中心中旧的 Surge 渲染逻辑替换为：

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-menu" --section
```

菜单区分放行、阻断、手动解除、停止和未知；展示检查时间、规则结果、具体原因、SurgeGate
状态，并提供日志、诊断、规则草稿、重启和临时恢复入口。
守护停止不代表遗留 PF 规则已清除；抓包状态缺失、过期或不完整时显示不确定，服务可能仍在运行时
保留停止入口，不推断“已关闭、零内存”。采用系统文字颜色和明暗双配色。
菜单显示名为 `surge-guard` 和 `surge-gate`。surge-gate 只有在服务运行、状态新鲜、已就绪、无待恢复应用且系统门禁
已验证放行时才显示绿色；等待／过期为橙色，错误为红色。

SurgeGate 本轮已改为同包 Swift 程序，无需 Python。它只相信近期有效的系统守护状态，
不会使用“代理端口通＋任意 utun”的备用判定。启动 Surge 后等待就绪，不自动更改增强模式偏好或分流选择。

每次新启动 Surge 前，Gate 会等待 macOS 发布 IPv4 主网络，并确认对应接口已启用且具有非回环 IPv4 地址。
仅拿到 DHCP 地址还不够：开机联网认证检测可能暂不发布主网络，导致 NetworkExtension 以
`No network available` 拒绝启动。此时状态为 `waiting_network`，菜单显示“等待 macOS 主网络就绪”；
Gate 按正常循环复查，不加固定延时、不探测互联网，也不计入启动失败的 30 秒退避。暂停和有序关机仍可处理。
已有的有效 Surge 实例会保留，不会仅因门禁未就绪就重启它或强制打开增强模式。
主网络检查只决定何时启动 Surge；PF 放行和应用恢复仍须通过原有系统守护验证。

应用设置位于 `~/Library/Application Support/SurgeGuard/gate.json`，参照 `examples/gate.json`：

- `startup_apps`：每次就绪后启动的应用 Bundle ID。
- `priority_order`：恢复／启动的优先顺序。
- `excluded_apps`：不参与会话恢复和有序退出的应用。
- `restore_session`：是否恢复上次应用列表。
- `delay_between_apps_seconds`：成功启动间隔，0–30 秒。
- `quit_timeout_seconds`：正常退出等待时间，5–300 秒，超时中止关机。

应用必须用 Bundle ID，避免中英文名称差异。失败应用保留待重试，不直接丢弃。
每 30 秒原子保存一次应用列表和待恢复项，断电时尽量恢复最近记录；不能保证最后一次落盘之后
的变化，也不负责恢复应用文档或窗口。其他登录项仍可能自行启动，流量阻断由系统守护负责。

安装时迁移 `~/.surge_gate` 中可识别的旧配置／会话，保留原文件；停用旧登录任务并将旧 plist
改名保存。无法识别的应用名称写入迁移日志，供手动补全。

## 有序关机／重启

SwiftBar → **SurgeGate** 菜单最上方是电源操作：蓝色“有序重启电脑”和红色“有序关机”；
下方分隔线之后是日志和服务管理。

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" shutdown --action restart
# 或 --action shutdown
```

请求先在锁内写入，再启动尚未运行的服务，避免服务先恢复应用再看到关机请求；并发请求不会相互覆盖。
服务查询失败按错误处理，不视为“未安装”。请求交由独立的用户服务处理，退出调用终端不会截断流程。
先保存会话，正常请求应用退出，确认后最后退出 Surge，验证 PF 已阻断，再请求 macOS 关机。
有未保存内容时由应用显示正常提示，拒绝／超时就中止；不使用 SIGKILL、宽泛 pkill，
也不修改系统全局恢复设置。最后一步可能需要系统自动化权限。
它不拦截所有 Apple 菜单关机、断电或内核故障。
macOS 接受 Apple event 只表示已提交，系统或其他应用仍可能取消关机。提交后及中止后都保留会话，
暂停快照与自动恢复；可以再次显式发起有序关机／重启，已退出应用仍保留在会话中，
也可重启 Gate 恢复自动运行。应用仍在退出阶段时拒绝重复请求。

关机后再开机，系统级守护由 LaunchDaemon 自动加载；登录用户账户后，SurgeGate 的
`RunAtLoad`／`KeepAlive` LaunchAgent 自动运行，启动 Surge，等待系统门禁放行后恢复应用。
其他登录项可能自行启动，其网络由系统守护控制。断电恢复基于最近一次约 30 秒间隔的应用快照，
应用文档／窗口恢复由各应用负责；开机最早阶段的限制仍见 README 的 Limits。

## 排查与管理

```sh
/Library/PrivilegedHelperTools/surge-guard doctor
sudo /Library/PrivilegedHelperTools/surge-guard doctor
sudo /Library/PrivilegedHelperTools/surge-guard logs
sudo /Library/PrivilegedHelperTools/surge-guard logs --follow
# agent 或脚本需要原始结构时：
sudo /Library/PrivilegedHelperTools/surge-guard logs --json
```

普通用户诊断无需授权；sudo doctor 增加实时 PF 检查。
日志默认按本地时间、级别、放行／阻断结果、中文原因、预期和实际分流组、最终策略分行显示，
先显示最近 200 条，再按需持续跟踪。每条标明 SurgeGuard／SurgeGate、当前状态、原因、影响和恢复进度。
默认省去 PID、run/event 标识和冗长的 OS UserInfo；`--json` 完整保留供 agent 读取的原始 JSON Lines。
SurgeGate 区分“应用原本已运行”和“发送了启动请求”，并分别记录“状态暂不可读”和“状态已恢复”。
一次状态文件读取失败会暂停应用恢复，不能单凭这一条认定整机断网。

Gate 为一次性专用启动任务记录 `surge_job_submitted`、`surge_job_process_observed` 和
`surge_job_process_exited`，保留启动 ID、实际进程 PID、原生出生时间、是否验证过 Surge 身份、
以及收到退出回调的墙钟／单调时间。Gate 不再是父进程，只能观察退出，无法取得该进程的
退出码、终止信号或发送者。launchctl 提交命令结束不等于 Surge 退出。历史直接启动产生的
`surge_child_started`／`surge_child_exited` 仍按原始退出码／信号显示；启动器早期失败不冒充
已验证的 Surge 退出。Gate 事件同时保留本轮运行 ID 和毫秒时间。
`surge_quit_requested` 在正常退出调用前记录身份修复、有序关机或重启的原因；
`surge_quit_result` 只表示请求是否接受，不能据此认定进程已经退出。

这些记录沿用私有轮转日志，用 `surge-gate logs --json` 读取。退出码 0 不证明是用户主动退出，
终止信号也不包含发送者；回调时间不是精确退出时间或网络保护耗时。
`surge_exit_observation_scope` 提示覆盖缺口：Gate 启动前已有且无未决任务记录的 Surge、
NSWorkspace 启动的进程以及 Gate 停止后的退出，不在本观察器的覆盖范围。仅更新源码或菜单
不会改变运行中的服务，需在维护窗口部署 Gate 新二进制，并验收下次专用启动。

SwiftBar 的系统日志入口只用 sudo 读取固定日志文件，再交给普通用户的 `format-logs` 格式化；
旧记录也能按新格式显示，不放宽原日志权限，也不以 root 执行用户目录中的渲染程序。
状态文件先在临时文件上设置好最终权限，再原子替换，消除重写时短暂不可读的权限窗口。
`status --json` 正常生成报告时退出码为 0，要读取 `state`，不能只看退出码。
`check --json` 的退出码 0 表示条件通过，1 表示未通过／错误。
JSON 使用 snake_case，状态有 allowed、blocked、unlocked、stopped、unknown、maintenance。
维护记录在可选 `system_update` 字段中；`maintenance` 只确认主动暂停保护，不代表保护生效。

状态绑定本次开机和 PID，检查及 PF 审计超过 8 秒过期；分流结果从查询开始计时，3 秒过期。
守护约每 0.5 秒检查增强模式、1 秒查询分流、5 秒审计 PF；这些不是断网延迟上限。
菜单分别显示状态发布的具体时间和 PF 验证距今时间；状态每秒发布，出现“不到 1 秒前”正常。
这些时间是菜单生成时的记录，展开菜单后不会逐秒计时。
日志包含状态变化、策略变化、查询错误、配置加载和管理操作；不为未变化的每次轮询重复写日志。
每个组件只保留当前文件和一份 `.1` 上轮文件，每份最多 1 MiB，即每组件最多 2 MiB。
写入前检查容量并轮转，拒绝超大记录和不安全权限；不会无限保留旧轮次。
SurgeGate 的 launchd 标准输出／错误改为 `/dev/null`，日志写入故障进入 macOS 自行管理的系统日志。
已有 `service.log` 保留但不再写入。
系统私有日志保留 root 权限，不为了菜单展示放宽访问。

[故障排查](docs/troubleshooting.md)提供按原因定位的步骤；
[实机验收](docs/acceptance.md)区分新增连接、已有连接、IPv6、重启和睡眠唤醒；
[验证记录](docs/verification.md)只记录实际完成的项目。

## 卸载与保留数据

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" uninstall
sudo /Library/PrivilegedHelperTools/surge-guard uninstall
```

再移除独立 SwiftBar 插件或组合菜单中的调用。卸载保留配置、会话、日志与原始 PF 备份，
只删除自己的 PF 配置段，不覆盖其他服务的配置。
Gate 的 `stop` 和 `uninstall` 会取消尚未消费的有序关机请求，避免之后启动或重装时重放；
取消失败会报错。已经提交给 macOS 的电源请求无法通过这项清理撤回。

此项目与 Surge 官方无关联，MIT 许可证。

## Surge 启动和更新

常驻 TCP 模式固定使用 `_surge_guard` 专用组，重启和更新均沿用原有组 ID，绝不根据当前 Surge 的组身份扩大 PF 放行范围。Surge 保留原安装及更新方式；本工具不修改 Surge.app，不需要 App 管理权限。

Finder、Dock 或更新器可能先启动普通组实例。这个实例没有专用组的对外 TCP 放行资格；SurgeGate 等到系统守护确认阻断后，正常退出它，再通过固定启动器恢复专用组实例。身份错误、退出失败或恢复失败均保持阻断，不提供普通组放行的兜底。

恢复可能造成短暂断网；普通 TCP 出口的阻断规则已常驻 PF，不依赖 Gate 恢复的速度。本方案不保证所有独立启动入口的第一个实例就具有专用组，已执行与未执行的网络验证见 [验证记录](docs/verification.md)。
