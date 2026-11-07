import Foundation
import Darwin
import SurgeGuardCore

enum CLI {
    static let usage = """
    Surge Guard — Surge Enhanced Mode gate with optional routing conditions

      check [--json] [--config FILE]   Probe conditions; does not prove PF is active
      status [--json]                  Read the daemon's recent verified status
      doctor                          Explain conditions, configuration and service status
      diagnose [--minutes 1...120] [--watch-seconds 1...300] [--json]
                                      User-only merged evidence; default 20m; bounded private report
      observe-egress [--json]          Read-only socket/interface sample; not a no-bypass certificate
      audit-status [--json]            Independent packet recorder status; never proof of no bypass
      audit-request-sample             Normal-user read-only Surge request metadata snapshot (JSON)
      sudo audit-install [--megabytes 256|1024|4096] [--timezone AREA/CITY]
                                      Install/start independent bounded PKTAP recorder; no PF changes
      sudo audit-start / audit-stop    Enable recording / stop and disable automatic startup; retain captures
      sudo audit-preview               Limited metadata preview of retained captures
      sudo audit-coverage              Scan actual retained packet timestamps (JSON; may be partial)
      sudo audit-uninstall             Stop recorder/remove its service; retain private captures
      validate FILE                   Validate a policy without network changes
      rules                           Preview default blocked PF rules (no LAN exception)
      swiftbar [--section]             Render the portable SwiftBar menu
      edit-config                     Open a user-owned policy draft
      sudo configure FILE             Validate and atomically install a policy
      sudo install                    Install/update; a running gate stays blocked during update
      sudo start                      Load the installed system service
      sudo restart                    Ask the service to block and restart normally
      sudo backup                     Save installed binary, service and policy for recovery
      sudo rollback                   Restore the last update backup and restart the service
      sudo restore-policy             Restore the policy saved before the last configure
      sudo logs [--follow] [--json]    Readable recent events; optional follow or JSON Lines
      format-logs [--json]             Render log records from stdin without privileges
      sudo unlock                     Stop and remove this gate; reboot/start re-arms it
      sudo os-update-begin            Pause protection for ALL apps across reboots; verify Gate first
      sudo os-update-end              Finish/cancel macOS maintenance and verify restored protection
      sudo uninstall                  Remove installed system components; retain configuration/logs

    Enhanced mode preserves Surge routing and DIRECT policies. This is a reactive
    readiness gate by default. Optional persistent_tcp keeps TCP egress rules loaded;
    neither mode certifies complete packet coverage or boot-time protection.
    """

    struct CheckReport: Encodable {
        let version = 1
        var ready: Bool
        let mode: String
        let readiness: Readiness
        var session: SessionObservation?
        var reasons: [String]
        var usbTcpBindings: [USBTCPBinding]?
        var localTcpErrors: [String]?
    }

    static func policy(_ args: [String]) throws -> Configuration {
        if let position = args.firstIndex(of: "--config") {
            guard args.indices.contains(position + 1) else { throw GuardError("--config requires a file") }
            return try Configuration.decode(Data(contentsOf: URL(fileURLWithPath: args[position + 1])))
        }
        if FileManager.default.fileExists(atPath: Paths.configuration) || FileManager.default.fileExists(atPath: Paths.publicState) {
            return try Configuration.load()
        }
        return .enhanced
    }

    static func check(_ args: [String] = ["check"], helperPath: String = Paths.binary) throws -> CheckReport {
        try check(configuration: policy(args), helperPath: helperPath)
    }

    static func check(configuration: Configuration, helperPath: String = Paths.binary) throws -> CheckReport {
        let readiness = try Probe.readiness()
        var report = CheckReport(ready: readiness.ready, mode: configuration.mode,
                                 readiness: readiness, reasons: readiness.reasons)
        if configuration.allowsLANTCP {
            let inventory = LocalTCPInventory()
            report.usbTcpBindings = inventory.usb
            report.localTcpErrors = inventory.errors.isEmpty ? nil : inventory.errors
        }
        if configuration.mode == "routes" {
            do {
                let session = try geteuid() == 0 ? Probe.privilegedSession(configuration: configuration, helperPath: helperPath) : Probe.session(configuration: configuration)
                report.session = session
                if !session.ready {
                    if session.mode != "rule" { report.reasons.append("outbound_mode_is_\(session.mode)") }
                    if !session.enhancedMode { report.reasons.append("enhanced_mode_disabled") }
                    report.reasons += session.routes.filter { !$0.ready }.map { "\($0.reason): \($0.url)" }
                }
                report.ready = readiness.ready && session.ready
            } catch {
                report.ready = false
                report.reasons.append("rule_probe_failed: \(error)")
            }
        }
        if configuration.usesPersistentTCP {
            do {
                let group = try DedicatedEgress.group()
                guard let pid = try Probe.trustedSurgePID(),
                      try DedicatedEgress.identityMatches(pid: pid, uid: Probe.consoleUID(), group: group) else {
                    throw GuardError("surge_egress_identity_mismatch")
                }
                _ = try Probe.surgeInterface()
            } catch {
                report.ready = false
                report.reasons.append("persistent_tcp_not_ready: \(error)")
            }
        }
        return report
    }

    static var userDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/SurgeGuard")
    }
    static var draft: String { userDirectory.appendingPathComponent("policy-draft.json").path }
    static var gateBinary: String { userDirectory.appendingPathComponent("bin/surge-gate").path }

    static func run(_ args: [String]) throws {
        guard let action = args.first else { print(usage); return }
        if ["help", "--help", "-h"].contains(action) || args.contains("--help") || args.contains("-h") { print(usage); return }
        if action == "diagnose" {
            try DiagnosticCommand.run(Array(args.dropFirst()))
            return
        }
        if action == "session-probe" {
            guard args.count == 2, let uid = UInt32(args[1]) else { throw GuardError("Invalid internal session probe") }
            try Probe.dropPrivileges(to: uid)
            let observation = try Probe.session(configuration: Configuration.load())
            print(try JSON.encode(observation))
            return
        }
        if action == "os-update-gate-probe" {
            guard args.count == 3, let uid = UInt32(args[1]), let id = UUID(uuidString: args[2]) else {
                throw GuardError("Invalid internal maintenance probe")
            }
            try Probe.dropPrivileges(to: uid)
            let service = try Command.run("/bin/launchctl", ["print", "gui/\(uid)/\(UserPaths.label)"])
            guard let account = getpwuid(uid) else { throw GuardError("Cannot resolve Gate state owner") }
            let path = String(cString: account.pointee.pw_dir) + "/Library/Application Support/SurgeGuard/gate-status.json"
            let data = try UserPaths.readPrivate(path, maximumBytes: GateSession.maximumBytes)
            let acknowledged = try data.map { try SystemUpdate.gateAcknowledged($0, service: service, id: id) } ?? false
            print(try JSON.encode(["acknowledged": acknowledged]))
            return
        }
        if action == "audit-request-probe" {
            guard args.count == 2, let uid = UInt32(args[1]) else { throw GuardError("Invalid internal request audit") }
            try Probe.dropPrivileges(to: uid)
            print(try JSON.encode(SurgeRequestAuditBatch.collect()))
            return
        }
        if action.hasPrefix("audit-") {
            try PacketAuditAdmin.command(args)
            return
        }
        if ["check", "doctor"].contains(action) {
            var index = 1
            var seen = Set<String>()
            while index < args.count {
                let option = args[index]
                guard seen.insert(option).inserted else { throw GuardError("Duplicate option: \(option)") }
                if option == "--config", args.indices.contains(index + 1) { index += 2 }
                else if option == "--json", action == "check" { index += 1 }
                else { throw GuardError("Unknown or incomplete option: \(option)") }
            }
        } else if ["status", "swiftbar", "format-logs", "observe-egress"].contains(action) {
            let optional = ["status": "--json", "swiftbar": "--section", "format-logs": "--json", "observe-egress": "--json"][action]!
            guard args.count == 1 || (args.count == 2 && args[1] == optional) else { throw GuardError("Unexpected options for \(action)") }
        } else if action == "logs" {
            let flags = Array(args.dropFirst())
            guard Set(flags).count == flags.count, flags.allSatisfy({ ["--json", "--follow"].contains($0) }) else { throw GuardError("Usage: logs [--follow] [--json]") }
        } else if !["validate", "configure"].contains(action), args.count != 1 {
            throw GuardError("Unexpected arguments for \(action)")
        }
        switch action {
        case "rules": print(Policy.blocked, terminator: "")
        case "check":
            let report = try check(args)
            print(try JSON.encode(report, pretty: !args.contains("--json")))
            if !args.contains("--json") { print(report.ready ? "READY (conditions only; inspect status for PF)" : "NOT READY") }
            exit(report.ready ? 0 : 1)
        case "status":
            let report = StatusReport.read()
            print(try JSON.encode(report, pretty: !args.contains("--json")))
        case "observe-egress":
            var report = try EgressObservation.collect()
            report.querySurgeDomains()
            if args.contains("--json") { print(try JSON.encode(report)) }
            else {
                if report.flows.isEmpty { print("本次采样没有可展示的其他接口 socket 记录；覆盖缺口见下方。这不能确认历史或采样间隔内是否绕过。") }
                else {
                    let details = try JSONSerialization.jsonObject(with: Data(JSON.encode(report).utf8))
                    let timestamp = ISO8601DateFormatter()
                    timestamp.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                    let event: [String: Any] = ["event": "egress_path_observed", "component": "SurgeGuard", "details": details,
                                              "time": timestamp.string(from: report.sampledAt)]
                    print(LogReader.format(String(decoding: try JSONSerialization.data(withJSONObject: event), as: UTF8.self)))
                }
                for source in ["dns", "virtual_ip"] {
                    if let query = report.domainQueries?[source] {
                        print("候选域名查询 \(source)：\(query.status)\(query.error.map { " · " + $0 } ?? "")")
                    }
                }
                print("采样缺口：目标未知 \(report.unresolvedActiveSockets)，接口未知 \(report.unattributedActiveSockets)，无计数 \(report.unmeasuredSockets)。只读，不修改防火墙。")
            }
        case "validate":
            guard args.count == 2 else { throw GuardError("Usage: validate FILE") }
            let config = try Configuration.decode(Data(contentsOf: URL(fileURLWithPath: args[1])))
            print("Valid version \(config.version), mode \(config.mode), \(config.routeChecks.count) route check(s)")
        case "doctor":
            print("=== Service and recent PF verification ===")
            print(try JSON.encode(StatusReport.read(), pretty: true))
            print("=== Fresh condition probe (no firewall changes) ===")
            print(try JSON.encode(check(args), pretty: true))
            print("=== Paths ===\nPolicy: \(Paths.configuration)\nPrivate events: \(Paths.eventsLog)")
            if geteuid() == 0 {
                let firewall = Firewall()
                print("PF enabled: \(try firewall.enabled()); anchor first: \(try firewall.attached())")
                print("Live anchor:\n\(try firewall.readRules())")
            } else { print("For live PF and private logs: sudo \(Paths.binary) doctor / logs") }
            print("This diagnoses readiness gating; it is not proof of zero leakage or packet-by-packet enforcement.")
        case "swiftbar": print(SwiftBar.render(sectionOnly: args.contains("--section")), terminator: "")
        case "format-logs": try LogReader.render(.standardInput, json: args.contains("--json"))
        case "edit-config":
            guard geteuid() != 0 else { throw GuardError("Edit the draft as your normal user, then use sudo configure FILE") }
            try FileManager.default.createDirectory(at: userDirectory, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            if !FileManager.default.fileExists(atPath: draft) {
                try policy([]).encoded().write(toFile: draft, atomically: true, encoding: .utf8)
            }
            try Command.checked("/usr/bin/open", ["-a", "TextEdit", draft])
        default:
            guard ["install", "start", "restart", "backup", "rollback", "restore-policy", "run", "unlock", "uninstall", "configure", "logs", "os-update-begin", "os-update-end"].contains(action) else {
                throw GuardError("Unknown command: \(action)")
            }
            guard geteuid() == 0 else { throw GuardError("\(action) requires administrator privileges") }
            let management = !["run", "logs"].contains(action) ? try RuntimeLock(management: true) : nil
            defer { withExtendedLifetime(management) {} }
            if !["run", "logs", "unlock", "os-update-begin", "os-update-end"].contains(action) { try SystemUpdate.requireNormalOperation() }
            if action.hasPrefix("os-update-") {
                guard URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path == Paths.binary else {
                    throw GuardError("Use the installed root-owned guard for system update maintenance")
                }
                try RootFiles.verify(Paths.binary)
            }
            switch action {
            case "os-update-begin": try SystemUpdateAdmin.begin()
            case "os-update-end": try SystemUpdateAdmin.end()
            case "install": try Admin.install()
            case "start":
                try Admin.start()
                try Admin.waitForStatus()
            case "restart": try Admin.restart()
            case "backup":
                let saved = try Recovery.save(kind: "update")
                print("Backup saved: \(Paths.backups)/\(saved.id)")
            case "rollback": try Admin.restore(Recovery.latest("update"))
            case "restore-policy":
                try Recovery.restore(Recovery.latest("policy"))
                print("Previous policy restored. Inspect status; the daemon reloads it automatically.")
            case "unlock": try Admin.unlock()
            case "uninstall": try Admin.uninstall()
            case "configure":
                guard args.count == 2 else { throw GuardError("Usage: sudo configure FILE") }
                let config = try Configuration.decode(Data(contentsOf: URL(fileURLWithPath: args[1])))
                let encoded = try config.encoded()
                if config.usesPersistentTCP { try Admin.prepareDedicatedGroup() }
                try RootFiles.preparePublicState()
                try Recovery.save(kind: "policy")
                try RootFiles.write(encoded, to: Paths.configuration, mode: 0o644)
                EventLog.write("configuration_installed", message: "Policy validated and installed", details: ["mode": config.mode])
                print("Policy installed. A running daemon reloads it automatically; inspect status.")
            case "logs":
                try RootFiles.verify(Paths.eventsLog)
                try LogReader.show(path: Paths.eventsLog, follow: args.contains("--follow"), json: args.contains("--json"))
            case "run": try Daemon().run()
            default: break
            }
        }
    }
}
