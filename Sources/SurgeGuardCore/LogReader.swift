import Foundation

public enum LogReader {
    private static func reason(_ message: String) -> String {
        let labels = ["route_policy_mismatch": "分流策略与配置不一致", "rule_probe_failed": "无法查询 Surge 分流",
                      "rule_probe_expired": "分流结果已过期，等待重新验证", "rule_probe_pending": "等待第一次分流检查",
                      "configuration_invalid": "联网规则配置无效", "enhanced_mode_disabled": "增强模式已关闭",
                      "outbound_mode_is_direct": "Surge 当前为 Direct 模式，需要 Rule 模式",
                      "outbound_mode_is_proxy": "Surge 当前为 Global Proxy 模式，需要 Rule 模式",
                      "readiness_probe_failed": "无法确认增强模式接管状态",
                      "incomplete_route_results": "分流检查结果不完整", "rule_probe_configuration_changed": "分流查询期间配置已变化，等待重新检查",
                      "signed Surge process missing": "未找到签名有效的 Surge 进程",
                      "Surge network extension is not connected": "Surge 网络扩展未连接",
                      "primary network service is not Surge": "主网络服务不属于 Surge",
                      "Surge VIF is not up with its expected IPv4 address": "Surge 虚拟网卡或地址未就绪",
                      "Surge does not own the IPv4 default route": "IPv4 默认路由未由 Surge 接管",
                      "the global IPv6 route is not owned by Surge": "IPv6 主路由未由 Surge 接管",
                      "surge_tunnel_disconnecting": "增强模式正在断开，提前阻断",
                      "surge_tunnel_disconnected": "增强模式已断开",
                      "surge_tunnel_connecting": "增强模式正在连接，保持阻断",
                      "surge_tunnel_status_unknown": "增强模式连接状态未知",
                      "surge_process_exited": "Surge 进程已退出",
                      "persistent_tcp_not_ready": "常驻 TCP 出口条件未通过，保持阻断"]
        return message.components(separatedBy: "; ").map { part in
            guard let key = labels.keys.first(where: { part == $0 || part.hasPrefix($0 + ":") }) else { return text(part) }
            if key == "rule_probe_failed" {
                let cause: String
                if part.contains("Surge isn't running on the local machine") { cause = "Surge CLI 暂时无法连接本机 Surge" }
                else if part.contains("timed out") { cause = "Surge CLI 查询超时" }
                else {
                    let last = part.components(separatedBy: .newlines).last ?? part
                    let brief = last.replacingOccurrences(of: "surge-guard: ", with: "")
                        .components(separatedBy: " UserInfo=")[0]
                    cause = String(text(brief).prefix(240)) + "（完整错误见 --json）"
                }
                return labels[key]! + " [\(key)]：" + cause
            }
            return labels[key]! + " [\(key)]" + text(String(part.dropFirst(key.count)))
        }.joined(separator: "; ")
    }

    private static func text(_ value: Any?) -> String {
        guard let value else { return "—" }
        return String(String(describing: value).unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
    }

    public static func format(_ line: String, json: Bool = false) -> String {
        let record = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
        if json {
            let object = record ?? ["event": "legacy_text", "message": line]
            guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) else { return "{}" }
            return String(decoding: data, as: UTF8.self)
        }
        guard let record else { return text(line) }
        let event = record["event"] as? String ?? "event"
        let message = record["message"] as? String ?? ""
        let details = record["details"] as? [String: Any] ?? [:]
        let legacyProgress = event == "gate_state" && message.hasSuffix(" application(s) pending") ? Int(message.split(separator: " ").first ?? "") : nil
        let unavailable = event == "gate_status_unavailable" || (event == "gate_state" && message.hasPrefix("unknown:"))
        let permissionDenied = (details["reason"] as? String ?? message).contains("Permission denied") ||
            (details["reason"] as? String ?? message).contains("permission to view")
        let titles = ["daemon_started": "守护启动", "daemon_stopped": "守护停止，保留阻断",
                      "system_update_preparing": "准备系统更新维护，等待 Gate 确认",
                      "system_update_active": "系统更新维护已验证，全部应用保护暂停",
                      "system_update_restoring": "正在结束系统更新维护并恢复保护",
                      "system_update_completed": "系统更新维护结束，保护已验证恢复",
                      "system_update_unverified": "系统更新维护解除规则尚未验证",
                      "system_update_daemon_stopped": "守护退出，跨重启系统更新维护继续",
                      "system_update_paused": "系统更新维护：Gate 自动操作已暂停",
                      "route_decision_changed": "分流结果变化", "configuration_loaded": "配置已加载",
                      "local_tcp_inventory_failed": "本地 TCP 例外枚举失败",
                      "local_tcp_inventory_recovered": "本地 TCP 例外枚举已恢复",
                      "configuration_installed": "配置已应用", "rule_probe_failed": "分流查询失败",
                      "pf_reconciled": "PF 规则已重新校验", "pf_unverified": "无法确认防火墙保护",
                      "manual_unlock": "已手动解除保护", "restart_requested": "已请求正常重启",
                      "backup_created": "恢复备份已保存", "backup_restored": "已恢复上一次备份",
                      "upgrade_failed": "升级失败", "rollback_completed": "升级失败，上一版已恢复",
                      "rollback_failed": "自动恢复失败，请使用离线恢复入口",
                      "installation_updated": "系统守护升级完成", "installation_created": "系统守护安装完成",
                      "upgrade_probe_verified": "升级前的用户会话检查通过", "command_failed": "操作失败",
                      "reconciliation_failed": "守护检查失败，正在尝试阻断并重启", "fail_closed": "已验证阻断，等待守护恢复",
                      "gate_started": "应用恢复服务启动", "application_restored": "应用启动请求已完成",
                      "application_already_running": "应用已在运行，无需重新启动", "surge_launch_requested": "已请求启动 Surge",
                      "surge_child_started": "专用 Surge 启动器子进程已创建",
                      "surge_child_exited": "专用 Surge 子进程已退出",
                      "surge_job_submitted": "已提交一次性 Surge 启动任务",
                      "surge_job_process_observed": "已观察到 launchd 启动的 Surge／启动器进程",
                      "surge_job_process_exited": "launchd 启动的 Surge／启动器进程已退出",
                      "surge_quit_requested": "Gate 请求 Surge 正常退出", "surge_quit_result": "Surge 退出请求返回",
                      "surge_exit_observation_scope": "Surge 退出状态的记录范围",
                      "gate_state": "应用门禁状态变化", "gate_ready": "应用门禁已就绪",
                      "gate_restore_progress": "正在恢复应用", "gate_waiting": "等待系统门禁放行",
                      "gate_waiting_network": "等待 macOS 主网络后启动 Surge",
                      "gate_status_unavailable": "系统门禁状态暂不可读", "gate_status_recovered": "系统门禁状态读取已恢复",
                      "gate_error": "应用门禁异常", "readiness_loss_blocked": "接管失效，优先阻断已验证",
                      "update_paused": "Surge 更新暂停：自动启动、身份修复和应用恢复已暂停",
                      "update_resumed": "Surge 更新模式结束：自动恢复已启用",
                      "update_pause_requested": "已请求暂停，须等待 Gate 确认后再更新",
                      "update_resume_requested": "已请求恢复自动启动，等待 Gate 确认",
                      "surge_recovery_failed": "Surge 恢复失败：30 秒后重试",
                      "launch_pending": "应用启动尚在进行，暂停更新未确认",
                      "launch_recovery_required": "启动结果未知，需要人工确认恢复",
                      "launch_recovery_confirmed": "用户已确认旧启动结束，解除等待",
                      "launch_failed_after_restart": "旧启动器已退出，等待退避后恢复",
                      "egress_path_observed": "socket 采样记录（实际路径未验证）",
                      "egress_observation_failed": "出口观测暂不可用", "egress_observation_recovered": "出口观测已恢复",
                      "egress_observation_summary": "出口观测摘要",
                      "pf_block_traffic": "PF 阻断命中计数", "pf_block_observation_failed": "PF 阻断流量证据暂不可用",
                      "pf_block_observation_gap": "PF 阻断计数记录不完整",
                      "audit_capture_started": "包级记录开始启动", "audit_capture_ready": "包级采集接口已打开",
                      "audit_capture_failed": "包级记录失败", "audit_capture_stopped": "包级记录已停止",
                      "audit_capture_gap": "包级记录会话之间有缺口", "audit_capture_drops": "包级记录发生丢包",
                      "audit_stop_requested": "已请求停止包级记录",
                      "audit_capture_statistics_reset": "抓包统计回退或回绕，继续保留数据包",
                      "audit_state_changed": "包级记录状态变化", "audit_capture_diagnostic": "抓包工具诊断",
                      "audit_guard_state": "采集时观察到门禁状态变化", "audit_surge_request": "Surge 请求元数据",
                      "audit_surge_unavailable": "Surge 请求记录暂不可用", "audit_surge_recovered": "Surge 请求记录已恢复",
                      "audit_surge_history_gap": "Surge 请求历史可能不完整",
                      "application_restore_failed": "应用启动失败，保留待重试", "shutdown_started": "开始有序退出",
                      "shutdown_aborted": "关机已中止，会话已保留", "shutdown_requested": "已请求系统关机",
                      "shutdown_declined": "关机请求已拒绝，应用未被要求退出",
                      "legacy_migrated": "旧配置已迁移", "migration_app_unresolved": "旧应用名称需要补全 Bundle ID"]
        let title = unavailable ? "系统门禁状态暂不可读" : legacyProgress.map { $0 == 0 ? "应用门禁已就绪" : "正在恢复应用" } ??
            (event == "gate_changed" ? (message == "allowed" ? "ALLOWED / 已放行" : "BLOCKED / 已阻断") : titles[event] ?? event)
        var timestamp = record["time"] as? String ?? "—"
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: timestamp) ?? ISO8601DateFormatter().date(from: timestamp) {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS XXXXX"
            if let identifier = record["display_time_zone"] as? String, let zone = TimeZone(identifier: identifier) { formatter.timeZone = zone }
            timestamp = formatter.string(from: date)
        }
        let level = unavailable ? "WARNING" : (record["level"] as? String ?? "info").uppercased()
        let component = record["component"] as? String ?? (record["app"] != nil || event.hasPrefix("application_") || event == "gate_state" ? "SurgeGate" : "SurgeGuard")
        var lines = ["\(text(timestamp))  [\(text(level))] \(text(component)) · \(text(title))"]
        let pending = (details["pending_count"] as? Int) ?? legacyProgress
        if unavailable {
            let serviceQueryFailed = (details["reason"] as? String ?? message).contains("service_query_failed")
            lines.append(permissionDenied ? "  原因：读取 status.json 时权限被拒绝（EACCES/13）" : serviceQueryFailed ? "  原因：无法查询系统守护进程状态" : "  原因：无法取得近期有效的系统门禁状态")
            lines.append("  影响：应用恢复暂停；这条日志本身不能判定网络已断开")
            lines.append("  处理：待读取恢复后继续；持续出现时查看完整诊断")
        } else if event == "local_tcp_inventory_failed" || event == "local_tcp_inventory_recovered" {
            lines.append(event == "local_tcp_inventory_failed" ? "  影响：已撤销枚举失败的本地 TCP 例外；公网放行仍由原有 Surge 与分流检查决定" : "  状态：本地 TCP 例外已按当前接口重新计算")
            if event == "local_tcp_inventory_failed" {
                lines.append("  原因：\(text(message))")
                lines.append("  处理：自动重试接口枚举；持续失败时查看诊断")
            }
        } else if event == "gate_waiting_network" {
            lines.append("  原因：macOS 尚未发布可用的 IPv4 主网络，可能仍在等待 DHCP 或联网认证检测")
            lines.append("  影响：暂不启动 Surge，应用恢复暂停；主网络就绪不代表系统门禁已放行")
            lines.append("  处理：主网络就绪后自动启动 Surge；持续等待时检查 Wi-Fi／以太网连接")
        } else if event == "gate_status_recovered" {
            lines.append(details["guard_state"] as? String == "allowed" ? "  状态：系统门禁读取已恢复，可以继续恢复应用" : "  状态：系统门禁读取已恢复，当前未放行，应用恢复仍暂停")
        } else if event == "gate_waiting" || (event == "gate_state" && ["blocked:", "stopped:", "unlocked:"].contains(where: { message.hasPrefix($0) })) {
            let state = details["guard_state"] as? String ?? String(message.prefix(while: { $0 != ":" }))
            let cause = details["reason"] as? String ?? message.split(separator: ":", maxSplits: 1).dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces)
            let states = ["blocked": "系统门禁已阻断", "stopped": "未验证到运行中的系统守护", "unlocked": "系统保护已手动解除"]
            lines.append("  状态：\(states[state] ?? "等待系统门禁")，应用恢复暂停")
            if !cause.isEmpty { lines.append("  原因：\(reason(cause))") }
        } else if event == "gate_ready" || legacyProgress == 0 {
            lines.append("  状态：应用恢复完成，等待后续状态变化")
        } else if event == "gate_restore_progress" || legacyProgress != nil {
            lines.append("  状态：按配置顺序恢复应用")
        } else if event == "application_already_running" {
            lines.append("  结果：沿用正在运行的应用，本次没有发送启动请求")
        } else if event == "application_restored" {
            lines.append(record["component"] == nil ? "  结果：应用恢复步骤已完成（旧版事件不能区分原本已运行的应用）" : "  结果：已完成应用启动请求")
        } else if event == "surge_job_submitted" {
            lines.append("  状态：已提交用户级一次性任务，尚未验证 Surge 身份或联网条件；提交命令结束不代表应用启动结束")
        } else if event == "surge_job_process_observed" || event == "surge_job_process_exited" {
            lines.append("  进程：PID \(text(details["child_pid"]))；父进程为 launchd，非 Gate 子进程")
            if event == "surge_job_process_exited" {
                lines.append(details["startup_verified"] as? Bool == true ? "  阶段：Gate 曾验证此进程的 Surge 启动身份" : "  阶段：尚未验证 Surge 启动身份，可能仍是启动器")
                lines.append("  退出方式：非子进程，Gate 无法取得退出码、终止信号或发送者；观察时间不代表精确退出时间或网络状态")
            } else { lines.append("  状态：已开始跟踪退出，尚未验证 Surge 启动身份或联网条件") }
        } else if event == "surge_child_exited" {
            lines.append("  进程：PID \(text(details["child_pid"]))")
            lines.append(details["startup_verified"] as? Bool == true ? "  阶段：Gate 曾验证此子进程为就绪的 Surge 启动身份" :
                "  阶段：尚未验证此子进程的 Surge 启动身份，可能仍是启动器")
            switch details["termination_reason"] as? String {
            case "exit": lines.append("  退出方式：退出码 \(text(details["exit_code"]))；不能据此判定是用户退出或内部错误")
            case "uncaught_signal": lines.append("  退出方式：未处理的信号 \(text(details["signal"]))（9=SIGKILL，15=SIGTERM）；不能据此确定发送者")
            default: lines.append("  退出方式：未知；原始状态见 --json")
            }
            lines.append("  范围：观察时间是 Gate 收到回调的时间；关联 Gate 的退出请求另查日志，不能由本事件确认发起者或网络状态")
        } else if event == "surge_quit_requested" || event == "surge_quit_result" {
            let causes = ["identity_repair": "修复专用组启动身份", "ordered_restart": "有序重启电脑", "ordered_shutdown": "有序关闭电脑"]
            let cause = details["reason"] as? String ?? "unknown"
            lines.append("  原因：\(causes[cause] ?? text(cause))；目标 PID \(text(details["surge_pid"]))")
            if event == "surge_quit_result" {
                switch details["accepted"] as? Bool {
                case true: lines.append("  结果：请求已接受，但尚不能确认进程退出")
                case false: lines.append("  结果：请求未被接受，不能确认进程退出")
                default: lines.append("  结果：未知，不能确认进程退出")
                }
            } else { lines.append("  操作：即将发送正常退出请求，不使用强制终止") }
        } else if event == "surge_child_started" {
            lines.append("  进程：PID \(text(details["child_pid"]))；已挂接退出回调，尚未验证 Surge 启动身份或联网条件")
        } else if event == "surge_exit_observation_scope" {
            lines.append(details["launch_method"] as? String == "launchd_once" ?
                "  范围：跟踪本轮观察到的一次性 launchd 启动进程退出，无法取得退出码或信号" :
                "  范围：仅记录本轮 Gate 通过专用启动器创建的子进程退出状态（旧版直接启动）")
            lines.append("  缺口：Gate 启动前已存在的 Surge、NSWorkspace 启动及 Gate 停止后的退出，不在此范围内")
        } else if event == "readiness_loss_blocked" {
            lines.append("  原因：\(reason(message))")
            lines.append("  结果：阻断规则与旧连接状态清理已完成；后续条件检查仍在阻断下进行")
            if let elapsed = details["event_to_rules_loaded_ms"] as? Double {
                lines.append("  收到失效事件 / 本次发现失效 → 阻断规则加载完成：\(String(format: "%.1f", elapsed)) 毫秒")
            }
            if let elapsed = details["event_to_block_verified_ms"] as? Double {
                lines.append("  收到失效事件 / 本次发现失效 → 阻断验证及旧状态清理完成：\(String(format: "%.1f", elapsed)) 毫秒")
            }
            lines.append("  范围：这是守护处理耗时；未测量实际断开至事件收到的时间，也未验证逐包零绕过")
        } else if event == "audit_surge_request" {
            let request = details["request"] as? [String: Any] ?? [:]
            lines.append("  应用：\(text(request["process_path"]))（PID \(text(request["pid"]))）")
            lines.append("  端点：\(text(request["source_address"])):\(text(request["source_port"])) → \(text(request["remote_host"]))")
            lines.append("  Surge 策略：\(text(request["original_policy_name"])) → \(text(request["policy_name"]))")
            lines.append("  状态：完成=\(text(request["completed"]))；失败=\(text(request["failed"]))；拒绝=\(text(request["rejected"]))")
            lines.append("  观测时累计：发送 \(text(request["out_bytes"])) 字节；接收 \(text(request["in_bytes"])) 字节（不是本次增量）")
            lines.append("  范围：这是 Surge 自己提供的请求记录；DIRECT 也可能由 Surge 处理，尚未与抓包逐包匹配")
        } else if event.hasPrefix("audit_") {
            let descriptions = ["capture_statistics_unavailable": "尚未取得近期抓包统计，无法核对记录状态",
                "waiting_for_pktap_capture": "正在等待 PKTAP 采集接口就绪",
                "capture_running; packet_path_attribution_unverified": "采集正在运行，数据包是否经过 Surge 仍待核对",
                "capture_drops_reported": "抓包计数报告过丢失，对应区间记录不完整",
                "capture_stopped; subsequent_traffic_not_recorded": "采集已停止，后续流量未记录",
                "capture_exited_or_failed": "采集进程退出或发生故障，后续记录不可确认",
                "missing; possible_request_history_gap": "Surge 两次最近请求列表没有重叠，期间可能有未保存的短请求",
                "surge_process_changed": "Surge 进程已变化，新旧请求历史之间的连续性不可确认",
                "PKTAP capture opened; attribution and end-to-end completeness remain unverified": "PKTAP 采集接口已打开；流量归属和整体记录完整性仍待核对",
                "Surge request queries recovered; prior gaps remain unverified": "Surge 请求查询已恢复；之前的缺口仍未补齐"]
            if !message.isEmpty { lines.append("  说明：\(descriptions[message] ?? String(text(message).prefix(480)))") }
            if let state = details["state"] { lines.append("  采集状态：\(text(state))") }
            if let packets = details["dropped_by_kernel"] { lines.append("  内核抓包丢失：\(text(packets)) 包；对应区间不能认定为完整") }
            if let packets = details["dropped_by_interface"] { lines.append("  接口报告丢失：\(text(packets)) 包；对应区间不能认定为完整") }
            if let state = details["guard_state"] { lines.append("  当时读取的门禁状态：\(text(state))（不是逐包判定）") }
            lines.append("  范围：没有记录到绕过不代表确认无绕过；停机、丢包、请求窗口滚动和旧文件覆盖均会限制追溯")
        } else if event == "egress_path_observed" {
            lines.append("  观测：nettop 报告以下 socket 的字节计数增加；接口字段是工具报告值，计数不作为链路总流量合计")
            lines.append("  结论：未验证数据包实际路径，不能据此确认绕过或确认全部经 Surge")
            lines.append("  影响：仅记录，不改变防火墙或联网状态")
            if let started = details["sample_started_uptime"] as? Double, let ended = details["sample_completed_uptime"] as? Double {
                lines.append("  采样命令耗时：\(String(format: "%.3f", max(0, ended - started))) 秒；字节增量取第二帧约 1 秒")
            }
            let states = ["allowed": "放行", "blocked": "阻断", "changed": "采样关联窗口发生切换", "unknown": "未跟踪切换"]
            let during = details["guard_state_during_sample"] as? String ?? "unknown"
            lines.append("  门禁关联：\(states[during] ?? "未知")（守护状态，不能据此认定采样字节已放行或已阻断）")
            if during == "changed" {
                lines.append("    开始：\(text(details["guard_state_at_start"])) → 结束：\(text(details["guard_state_at_end"]))；不按结束状态归因整段流量")
                lines.append("    关联窗口包含后台任务排队与回调时间，可能比采样命令覆盖的时间更长")
            }
            for flow in details["flows"] as? [[String: Any]] ?? [] {
                let kinds = ["system_extension": "系统扩展", "application_or_service": "应用/服务", "unresolved": "身份待确认"]
                let scopes = ["public": "远端为公网地址", "local_or_reserved": "远端为局域网/保留地址", "unresolved": "远端未知"]
                let scope = flow["destination_scope"] as? String ?? "unresolved"
                let sent = flow["sent_bytes"] as? UInt64, received = flow["received_bytes"] as? UInt64
                let direction = sent == 0 && (received ?? 0) > 0 ? "仅有接收计数" : (sent ?? 0) > 0 ? "有发送计数" : "方向未确认"
                let category = EgressFlow.category(kind: flow["process_kind"] as? String ?? "unresolved", scope: scope, sent: sent ?? 0)
                let assessments = ["public_send_review": "公网发送线索，优先核对；尚未验证绕过",
                                   "public_receive_only": "公网远端，仅接收；没有本次向外发送的计数证据",
                                   "system_extension": "系统扩展活动，需结合独立网络判断；不等同普通应用绕过",
                                   "local_or_reserved": "远端为局域网/保留地址，不作为公网绕过证据",
                                   "unresolved_peer": "远端未知，保留原始线索，无法判断公网绕过"]
                lines.append("  \(text(flow["process"]))（PID \(text(flow["pid"]))） · \(kinds[flow["process_kind"] as? String ?? ""] ?? "身份待确认") · \(scopes[scope] ?? "远端未知") · \(direction)")
                lines.append("    分类：\(assessments[category]!)")
                lines.append("    nettop 报告接口：\(text(flow["interface"]))  协议：\(text(flow["transport"]))")
                lines.append("    本地端点：\(text(flow["local_endpoint"]))  远端原始值：\(text(flow["remote_endpoint"]))")
                if let domains = flow["candidate_domains"] as? [String], !domains.isEmpty {
                    lines.append("    Surge DNS 缓存候选域名：\(domains.map { text($0) }.joined(separator: ", "))（仅按远端 IP 关联缓存，不代表已确认该连接请求的域名）")
                }
                lines.append("    本次采样发送：\(text(flow["sent_bytes"])) 字节  接收：\(text(flow["received_bytes"])) 字节")
                if scope == "unresolved" {
                    lines.append("    判断：远端地址未提供，无法区分局域网与公网")
                }
                if let transport = flow["transport"] as? String, ["udp4", "udp6"].contains(transport),
                   let local = flow["local_endpoint"] as? String, local.hasSuffix(":5353") || local.hasSuffix(".5353") {
                    lines.append("    线索：本地 UDP 5353 是 mDNS 常用端口；端口本身不能确认目标或路径")
                }
            }
            if let limited = details["limited_flows"] as? Int, limited > 0 {
                lines.append("  记录上限：本次另有 \(limited) 条新记录未展开；不能视为已检查或没有活动")
            }
        } else if event == "pf_block_traffic" {
            let totals = details["totals"] as? [String: Any] ?? [:]
            let delta = details["delta"] as? [String: Any] ?? [:]
            lines.append("  证据：本工具 PF 阻断规则的命中计数，入站与出站分别统计")
            let deltaTitle = details["delta_has_baseline"] as? Bool == false ? "本次读数（基线未知，不能作为增量）" : "本次增量"
            lines.append("  \(deltaTitle)：\(text(delta["packets"])) 包 / \(text(delta["bytes"])) 字节；入站 \(text(delta["in_packets"])) 包，出站 \(text(delta["out_packets"])) 包")
            lines.append("  当前规则累计：\(text(totals["packets"])) 包 / \(text(totals["bytes"])) 字节；入站 \(text(totals["in_packets"])) 包，出站 \(text(totals["out_packets"])) 包")
            lines.append("  阻断批次：\(text(details["block_id"]))；读取阶段：\(text(details["phase"]))")
            if details["counter_continuity"] as? Bool == false {
                lines.append("  连续性：本批次曾读取失败或计数回退；增量基线已重建，不能累加成完整历史")
            }
            if details["phase"] as? String == "before_allow" {
                lines.append("  时间边界：这是准备放行前的读取；到实际切换放行规则之间仍可能有未计入的命中。是否放行见后续门禁日志")
            }
            lines.append("  范围：没有逐包进程、目标或内容；不能与 socket 采样逐条配对，零计数也不能证明没有绕过")
        } else if event == "pf_block_observation_failed" || event == "pf_block_observation_gap" {
            let causes = ["Rules reloaded before final counter read": "先加载阻断规则，未在重载前完成旧计数的最后读取",
                          "Missing or ambiguous PF block counters": "未找到唯一的本工具 PF 阻断计数",
                          "Malformed PF block counters": "PF 阻断计数字段无法解析",
                          "Inconsistent PF block counters": "PF 入站、出站与总计数不一致",
                          "PF block counters decreased; observation continuity lost": "PF 计数回退，可能被清零或规则被重载，连续性无法确认"]
            lines.append("  原因：\(causes[message] ?? text(message))")
            lines.append("  阻断批次：\(text(details["block_id"]))")
            lines.append("  影响：阻断流量记录不完整；不能据此判断没有拦截或发生绕过，原有防火墙策略不变")
        } else if event == "egress_observation_failed" {
            lines.append("  原因：\(text(message))")
            lines.append("  影响：这段时间缺少出口观测证据；现有防火墙判断继续运行")
        } else if event == "egress_observation_summary" {
            lines.append("  状态：后台每 \(text(details["sample_interval_seconds"])) 秒采样 \(text(details["sample_seconds"])) 秒")
            lines.append("  本次其他接口 socket 记录：\(text(details["observed_flows"])) 条；远端未解析的活动 socket：\(text(details["unresolved_active_sockets"])) 个")
            lines.append("  覆盖缺口：接口未知 \(text(details["unattributed_active_sockets"])) 个；无字节计数 \(text(details["unmeasured_sockets"])) 个")
            if let counts = details["category_counts"] as? [String: Any] {
                lines.append("  分类：公网发送待核对 \(text(counts["public_send_review"]))；公网仅接收 \(text(counts["public_receive_only"]))；系统扩展 \(text(counts["system_extension"]))；局域网/保留 \(text(counts["local_or_reserved"]))；远端未知 \(text(counts["unresolved_peer"]))")
                lines.append("  本次去重 \(text(details["deduplicated_flows"])) 条；超过展开上限 \(text(details["limited_flows"])) 条（均不是整个五分钟的累计）")
            }
            lines.append("  范围：TCP / UDP socket 计数与工具报告接口；未验证逐包路径，未发现记录不代表确认无绕过")
        } else if event == "gate_changed" {
            lines.append(message == "allowed" ? "  状态：普通联网已放行，配置条件与 PF 检查通过" : "  状态：普通联网已阻断，条件通过后自动恢复")
            if message != "allowed" { lines.append("  原因：\(reason(message))") }
        } else if !message.isEmpty && message != "allowed" { lines.append("  说明：\(reason(message))") }
        if details["allow_lan_tcp"] as? Bool == true {
            lines.append("  例外：已配置的私网 TCP 仍可经匹配的 Wi-Fi／有线网卡直连；Apple USB 链路本地 IPv6 TCP 也在本地例外范围内")
        }
        if let pending { lines.append("  恢复进度：剩余 \(pending) 个应用") }
        if let elapsed = details["exit_event_to_block_verified_ms"] as? Double {
            lines.append("  Surge 退出事件收到至 PF 阻断验证：\(String(format: "%.1f", elapsed)) 毫秒（不是实际退出至逐包阻断延迟）")
        }
        if let routes = details["routes"] as? [[String: Any]] {
            for route in routes {
                lines.append("  \((route["ready"] as? Bool) == true ? "✓" : "✗") \(text(route["url"]))")
                lines.append("    预期分流组：\(text(route["expected_group"]))")
                lines.append("    实际分流组：\(text(route["actual_group"]))\n    最终策略：\(text(route["final_policy"]))")
            }
        }
        if let app = record["app"] as? String, !app.isEmpty { lines.append("  应用: \(text(app))") }
        let metadata = [details["mode"].map { "配置=\(text($0))" }, details["pf"].map { "PF=\(text($0))" },
                        details["outbound_mode"].map { "出站模式=\(text($0))" }, details["duration_ms"].map { "耗时=\(text($0))ms" },
                        details["guard_state"].map { "系统门禁=\(text($0))" },
                        details["backup_id"].map { "备份=\(text($0))" }, details["kind"].map { "备份类型=\(text($0))" }].compactMap { $0 }
        if !metadata.isEmpty { lines.append("  " + metadata.joined(separator: "  ")) }
        return lines.joined(separator: "\n")
    }

    public static func show(path: String, follow: Bool, json: Bool) throws {
        let task = Process(), pipe = Pipe()
        defer { try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close() }
        task.executableURL = URL(fileURLWithPath: "/usr/bin/tail")
        task.arguments = ["-n", "200"] + (follow ? ["-F"] : []) + [path]
        task.standardOutput = pipe
        try task.run()
        defer { if task.isRunning { task.terminate() } }
        pipe.fileHandleForWriting.closeFile()
        try render(pipe.fileHandleForReading, json: json)
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw GuardError("Log reader exited with status \(task.terminationStatus)") }
    }

    public static func render(_ input: FileHandle, json: Bool = false) throws {
        var pending = Data()
        while true {
            let chunk = input.availableData
            if chunk.isEmpty { break }
            pending.append(chunk)
            guard pending.count <= 2_097_152 else { throw GuardError("Log line exceeded limits") }
            while let newline = pending.firstIndex(of: 10) {
                let line = String(decoding: pending[..<newline], as: UTF8.self)
                let rendered = format(line, json: json) + "\n"
                try FileHandle.standardOutput.write(contentsOf: Data(rendered.utf8))
                pending.removeSubrange(...newline)
            }
        }
        if !pending.isEmpty { print(format(String(decoding: pending, as: UTF8.self), json: json)) }
    }
}
