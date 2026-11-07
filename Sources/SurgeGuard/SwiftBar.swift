import Foundation
import SurgeGuardCore

enum SwiftBar {
    static func clean(_ text: String) -> String {
        text.replacingOccurrences(of: "|", with: "¦").components(separatedBy: .newlines).joined(separator: " ")
    }
    static func parameter(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
    static func render(sectionOnly: Bool) -> String {
        let status = StatusReport.read()
        let installedHelp = (try? Command.checked(Paths.binary, ["--help"])) ?? ""
        let modern = installedHelp.contains("restore-policy")
        let maintenance = status.systemUpdate
        let state = ["allowed", "blocked"].contains(status.state) && !status.firewallVerified ? "unknown" : status.state
        let icon = maintenance != nil ? "🟠" : state == "allowed" ? "🟢" : state == "blocked" ? "🔴" : "🟠"
        let attachmentFailure = status.reason.hasPrefix("pf_attachment_missing:") || status.reason.hasPrefix("pf_attachment_invalid:")
        let title = maintenance.map { record in
            record.phase == .preparing ? "系统更新维护准备中 · 尚未解除保护" :
                record.phase == .restoring ? "系统更新维护结束中 · 保护恢复待确认" :
                status.maintenanceVerified ? "系统更新维护中 · 保护已暂停" : "系统更新维护请求 · PF 状态未验证"
        } ?? (attachmentFailure ? "PF 挂载配置异常 · 保护待验证" : !modern && status.daemonRunning ? "旧版运行 · PF 待验证" : ["allowed": "PF 已验证放行", "blocked": "PF 已验证阻断", "stopped": "守护已停止", "unknown": "状态未知", "unlocked": "已手动解除保护"][state] ?? "状态未知")
        var lines = sectionOnly ? [] : ["\(icon) | size=13", "---"]
        // SwiftBar 2.1.1 clears submenu actions during live updates; a color preserves the action.
        let parentStyle = " | color=#1F2937,#F2F2F7"
        let infoStyle = " | color=#1F2937,#F2F2F7"
        let noteStyle = " | color=#374151,#E5E7EB size=12"
        lines.append("surge-guard · \(icon) \(title)" + parentStyle)
        if let maintenance {
            let elapsed = SystemClock.elapsedSeconds(since: maintenance.startedAt.timeIntervalSince1970, now: Date().timeIntervalSince1970)
                .map { "\($0 / 60) 分钟" } ?? "时间未知"
            lines.append("-- ⚠️ 系统更新维护：已持续 \(elapsed)，跨重启保留，不会自动到期 | color=#B45309,#FCD34D")
            lines.append("-- 维护期间全部应用均可能直连；仅解除本工具限制，不保证网络可用" + noteStyle)
            lines.append("-- 更新完成或取消后，请点击「结束维护并恢复保护」；原策略与 Surge 更新暂停偏好保留" + noteStyle)
        }
        if attachmentFailure {
            lines.append("-- 系统升级后配置可能被重置；请查看完整诊断。当前未确认保护生效" + noteStyle)
        }
        if let snapshot = status.snapshot, snapshot.enforcement != "os_update_maintenance" {
            let current = status.firewallVerified
            let modeText = snapshot.configurationMode == "routes" ? "增强模式 + 分流检查" : "增强模式"
            let enforcementText = snapshot.enforcement == "persistent_tcp_egress" ? "TCP 常驻规则（Surge 专用组）" : "响应式门禁"
            lines.append("-- 模式：\(modeText) · \(enforcementText)" + infoStyle)
            if snapshot.enforcement == "persistent_tcp_egress" {
                lines.append("-- 保护范围：常驻限制覆盖 TCP；UDP 不在本模式的保护承诺内" + noteStyle)
            }
            if snapshot.lanTcpEnabled == true {
                let bindings = snapshot.lanTcpBindings ?? []
                let scope = bindings.map { "\($0.interface):\($0.address)" }.joined(separator: ", ")
                lines.append("-- 局域网 TCP 例外：\(current ? "" : "历史记录，")\(bindings.isEmpty ? "暂无匹配网卡" : clean(scope))" + noteStyle)
                lines.append("-- 策略范围：10/8、172.16/12、192.168/16；不受 Surge 就绪条件限制" + noteStyle)
                let usb = (snapshot.usbTcpBindings ?? []).map { "\($0.interface):\($0.address)" }.joined(separator: ", ")
                lines.append("-- Apple USB／开发隧道 TCP 例外：\(current ? "" : "历史记录，")\(usb.isEmpty ? "暂无匹配网卡" : clean(usb))" + noteStyle)
                lines.append("-- 范围：NCM 链路本地 IPv6、CoreDevice 隧道本地 ULA /64；仅 TCP" + noteStyle)
            }
            let formatter = DateFormatter(); formatter.dateFormat = "HH:mm:ss"
            let age = SystemClock.elapsedSeconds(since: snapshot.checkedUptime, now: SystemClock.seconds)
                .map { $0 == 0 ? "不到 1 秒前" : "\($0) 秒前" } ?? "时间无效"
            let pfAge = SystemClock.elapsedSeconds(since: snapshot.firewallVerifiedUptime, now: SystemClock.seconds)
                .map { $0 == 0 ? "不到 1 秒前" : "\($0) 秒前" } ?? "时间无效"
            let readyText = current ? (snapshot.readiness?.ready == true ? "就绪" : "未就绪") : "历史结果，待重新验证"
            lines.append("-- 检查：\(readyText) · PF 校验：\(pfAge)（发布于 \(formatter.string(from: snapshot.checkedAt))，\(age)）" + infoStyle)
            for route in snapshot.session?.routes ?? [] {
                let rMark = current ? (route.ready ? "✓" : "✗") : "?"
                lines.append("-- 分流\(current ? "规则" : "历史记录") [\(rMark)]：\(clean(route.url)) → \(clean(route.finalPolicy ?? "未知"))" + infoStyle)
            }
            if snapshot.configurationMode == "routes" { lines.append("-- 说明：只查询规则策略，不向目标发起网络请求" + noteStyle) }
            for error in snapshot.localTcpErrors ?? [] {
                lines.append("-- ⚠️ 对应本地 TCP 例外已撤销：\(clean(error)) | color=#92400E,#FCD34D size=12")
            }
        }
        if !modern, status.daemonRunning {
            lines.append("-- 旧版守护正在运行，PF 状态尚未验证 | color=#92400E,#FCD34D size=12")
        } else if !status.reason.isEmpty {
            lines.append("-- 原因：\(clean(status.reason)) | color=#B91C1C,#FF6961 size=12")
        }
        let actionHelper = CLI.userDirectory.appendingPathComponent("bin/surge-guard-action").path
        let renderer = CLI.userDirectory.appendingPathComponent("bin/surge-guard-ui").path
        let normalBinary = FileManager.default.isExecutableFile(atPath: renderer) ? renderer : Paths.binary
        func command(_ title: String, _ args: [String], root: Bool = false, depth: String = "--") {
            let recoverable = root && args.count == 1 && ["start", "restart", "unlock", "backup", "rollback", "restore-policy", "logs", "follow-logs", "doctor", "audit-logs", "audit-requests", "os-update-begin", "os-update-end"].contains(args[0]) && FileManager.default.isExecutableFile(atPath: actionHelper)
            let diagnostic = args.count == 1 && ["diagnose", "diagnose-watch"].contains(args[0]) && FileManager.default.isExecutableFile(atPath: actionHelper)
            let executable = recoverable || diagnostic ? actionHelper : root ? "/usr/bin/sudo" : normalBinary
            let rootBinary = args.first?.hasPrefix("audit-") == true ? PacketAudit.binary : Paths.binary
            let parameters = (root && !recoverable ? [rootBinary] : []) + args
            lines.append("\(depth) \(title) | bash=\(parameter(executable)) " + parameters.enumerated().map { "param\($0.offset + 1)=\(parameter($0.element))" }.joined(separator: " ") + " terminal=true refresh=true")
        }
        lines.append("-----")
        if installedHelp.contains("os-update-begin") {
            if maintenance != nil {
                command("✅ 结束维护并恢复保护（更新已完成或取消）", ["os-update-end"], root: true)
                if maintenance?.phase != .restoring && !status.maintenanceVerified {
                    command("🔄 重试进入系统更新维护", ["os-update-begin"], root: true)
                }
            } else {
                command("🛠️ 准备更新 macOS（跨重启暂停全部应用保护）", ["os-update-begin"], root: true)
            }
            lines.append("-----")
        }
        if maintenance != nil {
            command("🔓 应急解除本工具规则（维护状态仍保留）", ["unlock"], root: true)
        } else if state == "stopped" || state == "unlocked" {
            command("▶️ 启动并恢复防火墙保护", ["start"], root: true)
            lines.append("-- ℹ️ \(status.stoppedExplanation)" + noteStyle)
        } else {
            command("🔄 重启防火墙保护（连接可能短暂重连）", ["restart"], root: true)
            command("🔓 暂停保护并放行网络（应急退出，下次启动或开机恢复）", ["unlock"], root: true)
        }
        lines.append("-----")
        command("🔍 重新检查放行条件", ["check"])
        command("🧾 合并检查最近 20 分钟（只读，保存私有报告）", ["diagnose"])
        if FileManager.default.isExecutableFile(atPath: actionHelper) {
            command("⏱️ 开始 120 秒 DNS／QUIC 诊断（自动结束）", ["diagnose-watch"])
        } else {
            command("⏱️ 开始 120 秒 DNS／QUIC 诊断（自动结束）", ["diagnose", "--watch-seconds", "120"])
        }
        command("🌐 查看非 Surge 连接与候选域名（只读采样）", ["observe-egress"])
        command("🩺 查看完整诊断 (doctor)", ["doctor"], root: true)
        command("📄 查看最近 200 条日志", ["logs"], root: true)
        if FileManager.default.isExecutableFile(atPath: actionHelper) { command("📺 实时跟踪日志", ["follow-logs"], root: true) }
        else if modern { command("📺 实时跟踪日志", ["logs", "--follow"], root: true) }
        lines.append("-----")
        lines.append("-- ⚙️ 策略配置与版本备份（离线可用）" + parentStyle)
        command("📝 编辑规则草稿", ["edit-config"], depth: "----")
        if modern && maintenance == nil {
            command("✅ 验证并应用规则草稿", ["configure", CLI.draft], root: true, depth: "----")
            lines.append("-------")
            command("💾 备份当前版本与配置", ["backup"], root: true, depth: "----")
            command("⏪ 恢复上一版与配置（rollback）", ["rollback"], root: true, depth: "----")
            command("↩️ 恢复上一次规则配置", ["restore-policy"], root: true, depth: "----")
        } else if !modern {
            lines.append("---- 当前为旧版系统守护：分流门禁及备份命令尚未启用 | color=#92400E,#FCD34D size=12")
        }
        for kind in ["update", "policy"] {
            let path = BackupManifest.pointer(kind)
            if (try? RootFiles.verify(path)) != nil,
               let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
               let saved = try? JSON.decode(BackupManifest.self, from: data), (try? saved.validate()) != nil {
                let formatter = DateFormatter(); formatter.dateStyle = .short; formatter.timeStyle = .short
                lines.append("---- \(kind == "update" ? "最近版本" : "最近规则")备份：\(formatter.string(from: saved.createdAt))" + noteStyle)
            }
        }
        if FileManager.default.isExecutableFile(atPath: PacketAudit.binary) {
            let service = try? Command.run("/bin/launchctl", ["print", "system/" + PacketAudit.label])
            let audit = service.flatMap { PacketAuditSnapshot.read(service: $0) }
            let auditMenu = PacketAuditMenu(service: service, snapshot: audit)
            lines.append("-- 📦 抓包审计工具（\(auditMenu.title)）" + parentStyle)
            lines.append("---- 当前状态：\(auditMenu.title)" + infoStyle)
            if let audit {
                lines.append("---- 抓包环形容量：\(audit.capacityMegabytes) MB；Surge 请求记录：\(clean(audit.surgeRequestsState))" + noteStyle)
                for description in audit.historyDescriptions { lines.append("---- \(description)" + noteStyle) }
                lines.append("---- 历史缺口不会因恢复记录而清除；无缺口标记不等于完整覆盖" + noteStyle)
            }
            lines.append("---- 抓包运行不代表全部流量经 Surge；未知归属与丢包须核对" + noteStyle)
            if auditMenu.canStop {
                command("⏹️ 停止连续抓包并关闭自启（保留历史）", ["audit-stop"], root: true, depth: "----")
            } else {
                command("▶️ 开始连续抓包（临时验证时开启）", ["audit-start"], root: true, depth: "----")
            }
            command("📊 查看抓包审计状态", ["audit-status"], depth: "----")
            command("⏱️ 查看留存包的实际时间范围", ["audit-coverage"], root: true, depth: "----")
            command("🔎 查看抓包元数据预览（非完整列表）", ["audit-preview"], root: true, depth: "----")
            if FileManager.default.isExecutableFile(atPath: actionHelper) {
                command("📄 查看包级审计事件", ["audit-logs"], root: true, depth: "----")
                command("📋 查看 Surge 请求记录", ["audit-requests"], root: true, depth: "----")
            }
        }
        if FileManager.default.isExecutableFile(atPath: CLI.gateBinary) {
            let gateReport = (try? Command.checked(CLI.gateBinary, ["status", "--json"], timeout: 3))
                .flatMap { try? JSON.decode(GateStatusReport.self, from: Data($0.utf8)) }
            let gateTitle = gateReport?.menuTitle(guardAllowed: status.state == "allowed" && status.firewallVerified) ?? "🟠 状态待验证"
            let helperAvailable = FileManager.default.isExecutableFile(atPath: actionHelper)
            lines.append("surge-gate · \(gateTitle)" + parentStyle)
            if let report = gateReport, report.running, report.fresh {
                if let identity = report.status.surge,
                   SystemClock.seconds >= identity.checkedUptime, SystemClock.seconds - identity.checkedUptime < 15 {
                    let formatter = DateFormatter(); formatter.dateFormat = "HH:mm:ss"
                    lines.append("-- Surge 进程：PID \(identity.pid.map(String.init) ?? "未确认") · 专用组 \(identity.expectedGroup.map(String.init) ?? "未启用")（\(identity.verified ? "已验证" : "未验证")，\(formatter.string(from: identity.checkedAt))）" + infoStyle)
                    if !identity.verified { lines.append("-- 身份原因：\(clean(identity.reason)) | color=#92400E,#FCD34D size=12") }
                } else { lines.append("-- Surge 身份：待重新验证" + infoStyle) }
                if ["os_update_paused", "os_update_waiting"].contains(report.status.state) {
                    lines.append("-- \(clean(report.status.message ?? "系统更新维护"))" + noteStyle)
                    if report.status.update?.paused == true {
                        lines.append("-- 原有 Surge 更新暂停偏好仍保留；结束系统维护不会自动取消它" + noteStyle)
                    }
                } else if let update = report.status.update, update.paused {
                    let elapsed = SystemClock.elapsedSeconds(since: update.changedAt.timeIntervalSince1970, now: Date().timeIntervalSince1970)
                        .map { "\($0 / 60) 分 \($0 % 60) 秒" } ?? "时间无效"
                    lines.append("-- 当前模式：\(report.status.state == "update_paused" ? "已暂停自动重开 Surge" : "请求暂停，等待确认")（已持续 \(elapsed)） | color=#92400E,#FCD34D size=12")
                    if report.status.state == "update_paused" {
                        lines.append("-- 说明：已确认暂停，可手动退出或升级 Surge；完成后点击「升级结束并恢复 Surge」" + noteStyle)
                    } else {
                        lines.append("-- 暂停请求尚未确认，暂勿开始升级：\(clean(report.status.message ?? "等待在途操作结束"))" + noteStyle)
                    }
                } else if ["waiting_network", "waiting_identity", "recovery_failed", "error", "launch_pending", "launch_recovery_required"].contains(report.status.state),
                          let message = report.status.message {
                    lines.append("-- 原因：\(clean(message)) | color=#92400E,#FCD34D size=12")
                }
            } else if gateReport?.running == false {
                lines.append("-- 状态：服务已停止（不影响当前网络连接和 PF 防火墙）" + infoStyle)
            } else {
                lines.append("-- 状态：Gate 状态待验证" + infoStyle)
            }
            lines.append("-----")
            if maintenance == nil {
                if let report = gateReport, report.running, report.fresh,
                   report.status.capabilities?.contains("update_pause_v1") == true {
                    if report.status.update?.paused == true {
                        lines.append("-- ▶️ 升级结束并恢复 Surge（官方升级已完成或取消） | bash=\(parameter(helperAvailable ? actionHelper : CLI.gateBinary)) param1=\(helperAvailable ? "gate-update-resume" : "update-resume") terminal=true refresh=true color=#B45309,#FCD34D")
                    } else {
                        lines.append("-- ⏸️ 准备升级 Surge（暂停自动恢复，保留 PF 保护） | bash=\(parameter(helperAvailable ? actionHelper : CLI.gateBinary)) param1=\(helperAvailable ? "gate-update-pause" : "update-pause") terminal=true refresh=true")
                    }
                    lines.append("-- 等待 Gate 确认暂停后再退出或升级；也适用于手动维护 Surge" + noteStyle)
                    lines.append("-----")
                }
                lines.append("-- ⚡ 安全电源操作 · 先保存会话并关闭应用再断网" + parentStyle + " size=13")
                for (title, action, color, symbol) in [("有序重启电脑（保存会话并安全断网）", "restart", "#1D4ED8,#93C5FD", "arrow.clockwise"),
                                                       ("有序关机（保存会话并安全断网）", "shutdown", "#B91C1C,#FCA5A5", "power")] {
                    lines.append("-- \(title) | bash=\(parameter(CLI.gateBinary)) param1=shutdown param2=--action param3=\(action) terminal=true refresh=true color=\(color) size=14 sfimage=\(symbol) width=16 height=16")
                }
                lines.append("-- 说明：正常退出应用后验证阻断；未保存文档超时会中止，不保证开机早期零漏流" + noteStyle)
            } else {
                lines.append("-- 系统更新请使用 macOS 自己的重启入口；维护期间 Gate 自动启动与会话快照暂停" + noteStyle)
            }
            lines.append("-----")
            if gateReport?.running == false {
                lines.append("-- ▶️ 启动 surge-gate 服务 | bash=\(parameter(helperAvailable ? actionHelper : CLI.gateBinary)) param1=\(helperAvailable ? "gate-start" : "start") terminal=true refresh=true")
            } else {
                lines.append("-- 🔄 重启 surge-gate 服务 | bash=\(parameter(CLI.gateBinary)) param1=restart terminal=true refresh=true")
                lines.append("-- ⏹️ 停止 surge-gate 服务（不影响当前联网） | bash=\(parameter(helperAvailable ? actionHelper : CLI.gateBinary)) param1=\(helperAvailable ? "gate-stop" : "stop") terminal=true refresh=true")
            }
            for (title, args) in [("📄 查看 surge-gate 日志", ["logs"]), ("📺 实时跟踪 surge-gate 日志", ["logs", "--follow"]), ("⚙️ 编辑应用自启与恢复配置", ["edit-config"])] {
                lines.append("-- \(title) | bash=\(parameter(CLI.gateBinary)) " + args.enumerated().map { "param\($0.offset + 1)=\(parameter($0.element))" }.joined(separator: " ") + " terminal=true refresh=true")
            }
        } else {
            let legacyGate = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".surge_gate/surge_gate.py").path
            let gateTitle = FileManager.default.fileExists(atPath: legacyGate) ? "旧版待迁移，运行状态未验证" : "未安装"
            lines.append("surge-gate · \(gateTitle) | color=#374151,#E5E7EB")
            lines.append("-- 有序重启 / 关机：需先安装 surge-gate" + noteStyle)
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
