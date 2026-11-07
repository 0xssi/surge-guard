import Foundation
import Darwin

public enum Paths {
    public static let label = "io.github.surge-guard"
    public static let binary = "/Library/PrivilegedHelperTools/surge-guard"
    public static let plist = "/Library/LaunchDaemons/\(label).plist"
    public static let runtime = "/private/var/db/surge-guard"
    public static let eventsLog = runtime + "/events.log"
    public static let pfConfig = "/private/etc/pf.conf"
    public static let publicState = "/Library/Application Support/SurgeGuard"
    public static let configuration = publicState + "/policy.json"
    public static let snapshot = publicState + "/status.json"
    public static let unlockMarker = publicState + "/unlocked.json"
    public static let addressHistory = runtime + "/addresses.json"
    public static let backups = runtime + "/backups"
}

public enum RootFiles {
    public static func preparePublicState() throws {
        try verify("/Library/Application Support", directory: true)
        if !FileManager.default.fileExists(atPath: Paths.publicState) {
            try FileManager.default.createDirectory(atPath: Paths.publicState, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o755])
        }
        try verify(Paths.publicState, directory: true)
    }
    public static func verify(_ path: String, directory: Bool = false) throws {
        var info = stat()
        guard lstat(path, &info) == 0,
              info.st_uid == 0, info.st_mode & 0o022 == 0,
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) else {
            throw GuardError("Expected a root-owned, non-writable-by-others \(directory ? "directory" : "file"): \(path)")
        }
    }

    public static func write(_ value: String, to path: String, mode: mode_t = 0o600) throws {
        // The parent is root-owned, so atomic replacement cannot be redirected
        // by an unprivileged process. Existing symlinks are always refused.
        try verify(URL(fileURLWithPath: path).deletingLastPathComponent().path, directory: true)
        if FileManager.default.fileExists(atPath: path) { try verify(path) }
        var info = stat()
        if lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFLNK {
            throw GuardError("Refusing symbolic link: \(path)")
        }
        try AtomicFile.write(value, to: path, mode: mode)
    }

    public static func prepareRuntime() throws {
        // macOS /var/run can be group-writable by daemon. Use a root-only
        // parent; persisted PF tokens are checked against live references.
        try verify(URL(fileURLWithPath: Paths.runtime).deletingLastPathComponent().path, directory: true)
        if !FileManager.default.fileExists(atPath: Paths.runtime) {
            try FileManager.default.createDirectory(atPath: Paths.runtime, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        }
        try verify(Paths.runtime, directory: true)
    }
}

public final class RuntimeLock {
    private let descriptor: Int32
    public convenience init(timeout: TimeInterval = 0, management: Bool = false) throws {
        try RootFiles.prepareRuntime()
        let fd = open(Paths.runtime + (management ? "/management.lock" : "/lock"), O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try self.init(taking: fd, timeout: timeout)
    }
    // Takes ownership on both success and failure; deinit must not close a failed initializer's FD again.
    public init(taking fd: Int32, timeout: TimeInterval = 0) throws {
        guard fd >= 0 else { throw GuardError("Cannot open service lock") }
        do { try Self.acquire(fd, timeout: timeout) }
        catch { close(fd); throw error }
        descriptor = fd
    }
    public static func acquire(_ descriptor: Int32, timeout: TimeInterval) throws {
        let deadline = SystemClock.seconds + max(0, timeout)
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EAGAIN else { throw GuardError("Cannot acquire firewall lock: errno \(errno)") }
            guard SystemClock.seconds < deadline else {
                throw GuardError("Timed out waiting for the previous surge-guard process to release the firewall lock")
            }
            usleep(50_000)
        }
    }
    deinit { close(descriptor) }
}

public struct PFBlockCounters: Codable, Equatable {
    public let packets: UInt64
    public let bytes: UInt64
    public let inPackets: UInt64
    public let inBytes: UInt64
    public let outPackets: UInt64
    public let outBytes: UInt64

    public static func parse(_ output: String) throws -> PFBlockCounters {
        // macOS pfctl -s labels: label, evaluations, total packets/bytes, in packets/bytes, out packets/bytes.
        let rows = output.split(separator: "\n").map { $0.split(whereSeparator: { $0.isWhitespace }) }
            .filter { $0.first == "surge-guard-block" }
        guard rows.count == 1, rows[0].count == 8 else { throw GuardError("Missing or ambiguous PF block counters") }
        let numbers = rows[0].dropFirst().compactMap { UInt64($0) }
        guard numbers.count == 7 else { throw GuardError("Malformed PF block counters") }
        let packets = numbers[3].addingReportingOverflow(numbers[5])
        let bytes = numbers[4].addingReportingOverflow(numbers[6])
        guard !packets.overflow, !bytes.overflow, packets.partialValue == numbers[1], bytes.partialValue == numbers[2] else {
            throw GuardError("Inconsistent PF block counters")
        }
        return PFBlockCounters(packets: numbers[1], bytes: numbers[2], inPackets: numbers[3], inBytes: numbers[4],
                               outPackets: numbers[5], outBytes: numbers[6])
    }

    public func delta(since previous: PFBlockCounters?) throws -> PFBlockCounters {
        guard let previous else { return self }
        guard packets >= previous.packets, bytes >= previous.bytes, inPackets >= previous.inPackets,
              inBytes >= previous.inBytes, outPackets >= previous.outPackets, outBytes >= previous.outBytes else {
            throw GuardError("PF block counters decreased; observation continuity lost")
        }
        return PFBlockCounters(packets: packets - previous.packets, bytes: bytes - previous.bytes,
                               inPackets: inPackets - previous.inPackets, inBytes: inBytes - previous.inBytes,
                               outPackets: outPackets - previous.outPackets, outBytes: outBytes - previous.outBytes)
    }
}

public final class Firewall {
    public private(set) var lanTCPBindings: [LANTCPBinding] = []
    public private(set) var usbTCPBindings: [USBTCPBinding] = []
    private var knownAddresses = Set<String>()
    private let historyPath: String?
    private var historyLoaded = false
    private var revokedLocalStates = Set<[String]>()
    private var expectedRules: String?
    private let tokenPath = Paths.runtime + "/pf-token"
    public private(set) var revision = 0
    public private(set) var blockID: String?
    private var blockStarted: Double = 0
    private var blockCounters: PFBlockCounters?
    private var blockCountersSampled: Double?
    private var blockCounterFailure = ""
    private var blockCounterContinuity = true
    private var nextBlockCounterSample: Double = 0

    public init(historyPath: String? = Paths.addressHistory) { self.historyPath = historyPath }

    private struct AddressHistory: Codable {
        let version: Int
        let bootId: String
        let addresses: [String]

        func validate() throws {
            guard version == 1, !bootId.isEmpty, bootId.utf8.count <= 128, addresses.count <= 512,
                  Set(addresses).count == addresses.count, addresses.allSatisfy({ address in
                      var ipv4 = in_addr(), ipv6 = in6_addr()
                      return address.utf8.count <= 45 && !address.utf8.contains(0) &&
                          (inet_pton(AF_INET, address, &ipv4) == 1 || inet_pton(AF_INET6, address, &ipv6) == 1)
                  }) else { throw GuardError("Invalid PF address history") }
        }
    }

    private func loadAddressHistory() throws {
        guard !historyLoaded else { return }
        if let historyPath, let data = try UserPaths.readPrivate(historyPath, maximumBytes: 65_536) {
            guard let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(fields.keys) == ["version", "boot_id", "addresses"] else { throw GuardError("Invalid PF address history fields") }
            let history = try JSON.decode(AddressHistory.self, from: data)
            try history.validate()
            if history.bootId == SystemClock.bootID { knownAddresses.formUnion(history.addresses) }
        }
        historyLoaded = true
    }

    private func saveAddressHistory() throws {
        guard let historyPath else { return }
        let history = AddressHistory(version: 1, bootId: SystemClock.bootID, addresses: knownAddresses.sorted())
        try history.validate()
        let encoded = try JSON.encode(history)
        guard encoded.utf8.count <= 65_536 else { throw GuardError("PF address history exceeds its size limit") }
        try RootFiles.write(encoded, to: historyPath)
    }

    @discardableResult
    public func setLANTCP(_ bindings: [LANTCPBinding]) throws -> Bool {
        _ = try LANTCP.rules(bindings: bindings)
        guard bindings != lanTCPBindings else { return false }
        for binding in lanTCPBindings where !bindings.contains(binding) {
            for peer in LANTCP.networks { rememberLocalStateCleanup(address: binding.address, peer: peer) }
        }
        lanTCPBindings = bindings
        return true
    }

    @discardableResult
    public func setUSBTCP(_ bindings: [USBTCPBinding]) throws -> Bool {
        _ = try USBTCP.rules(bindings: bindings)
        guard bindings != usbTCPBindings else { return false }
        for binding in usbTCPBindings where !bindings.contains(binding) {
            let peer = binding.interface.hasPrefix("utun") ? USBTCP.tunnelNetwork(binding.address)! : "fe80::/10"
            rememberLocalStateCleanup(address: binding.address, peer: peer)
        }
        usbTCPBindings = bindings
        return true
    }

    private func rememberLocalStateCleanup(address: String, peer: String) {
        revokedLocalStates.insert(["-k", address, "-k", peer])
        revokedLocalStates.insert(["-k", peer, "-k", address])
    }

    public func clearRevokedLocalStates(clear: ([String]) throws -> Void = {
        try Command.checked("/sbin/pfctl", $0, timeout: 5)
    }) throws {
        for arguments in revokedLocalStates.sorted(by: { $0.lexicographicallyPrecedes($1) }) { try clear(arguments) }
        revokedLocalStates.removeAll()
    }

    public func attached() throws -> Bool {
        Policy.attachedFirst(try Command.checked("/sbin/pfctl", ["-sr"]))
    }

    public func prepareAttachment() throws {
        try Self.preparingAttachment({ try prepareAttachmentRules() }, blockOnFailure: { _ = try block() })
    }

    public func prepareBlocking() throws {
        try Self.preparingAttachment({
            try RootFiles.verify(Policy.anchorPath)
            if try String(contentsOfFile: Policy.anchorPath) == SystemUpdate.suspendedAnchor {
                try RootFiles.write(Policy.blocked, to: Policy.anchorPath, mode: 0o644)
            }
            try prepareAttachment()
        }, blockOnFailure: { _ = try block() })
        try block()
    }

    public static func preparingAttachment(_ prepare: () throws -> Void, blockOnFailure: () throws -> Void) throws {
        do { try prepare() }
        catch {
            let failure = String(describing: error)
            // An old live attachment may still allow traffic even when disk recovery cannot proceed.
            do { try blockOnFailure() }
            catch { throw GuardError("PF attachment preparation failed: \(failure); blocking could not be verified: \(error)") }
            throw GuardError("PF attachment preparation failed: \(failure); blocking verified, repair is still required")
        }
    }

    private func prepareAttachmentRules() throws {
        let live = try Command.checked("/sbin/pfctl", ["-sr"])
        try RootFiles.verify(Paths.pfConfig)
        try RootFiles.verify(Policy.anchorPath)
        let config = try String(contentsOfFile: Paths.pfConfig)
        _ = try Policy.removingAttachment(from: config)
        if !config.contains(Policy.configBlock) {
            let restored = try Policy.restoringDefaultAttachment(config, liveRules: live)
            try restoreDefaultAttachment(config: config, restored: restored, live: live)
            return
        }
        if Policy.attachedFirst(live) { return }
        guard !live.contains(Policy.attachment) else {
            throw GuardError("Another filter precedes Surge Guard; review PF ordering")
        }
        // The daemon must not depend on com.apple.pfctl running first at boot.
        try Command.checked("/sbin/pfctl", ["-n", "-f", Paths.pfConfig])
        try Command.checked("/sbin/pfctl", ["-f", Paths.pfConfig], timeout: 5)
        try requireAttachment()
    }

    // Caller holds the runtime lock, including start before it bootstraps the daemon.
    private func restoreDefaultAttachment(config: String, restored: String, live: String) throws {
        for path in [Paths.binary, Paths.plist, Paths.configuration, Paths.pfConfig + ".surge-guard.backup"] {
            try RootFiles.verify(path)
        }
        let job = try PropertyListSerialization.propertyList(from: Data(contentsOf: URL(fileURLWithPath: Paths.plist)), options: [], format: nil) as? [String: Any]
        guard job?["Label"] as? String == Paths.label,
              job?["ProgramArguments"] as? [String] == [Paths.binary, "run"],
              try String(contentsOfFile: Policy.anchorPath) == Policy.blocked else {
            throw GuardError("PF attachment recovery requires the installed Guard job and default blocking anchor")
        }
        try Command.checked("/sbin/pfctl", ["-n", "-f", "-"], input: Policy.installationPreview(restored))
        try Command.checked("/sbin/pfctl", ["-n", "-R", "-o", "none", "-f", "-"], input: Policy.restoredDefaultFilters)
        try RootFiles.prepareRuntime()
        let backup = Paths.runtime + "/pf.conf.before-attachment-repair"
        if config != restored { try RootFiles.write(config, to: backup) }
        try RootFiles.verify(Paths.pfConfig)
        guard try String(contentsOfFile: Paths.pfConfig) == config,
              try Command.checked("/sbin/pfctl", ["-sr"]) == live else {
            throw GuardError("PF configuration changed during attachment recovery; retry after reviewing changes")
        }
        // -R excludes tables; the default optimizer can otherwise silently omit rules needing generated tables.
        try Command.checked("/sbin/pfctl", ["-R", "-o", "none", "-f", "-"], input: Policy.restoredDefaultFilters, timeout: 5)
        try requireAttachment()
        guard try readRules().contains("label \"surge-guard-block\"") else {
            throw GuardError("Restored attachment lacks verified blocking rules; disk configuration not changed")
        }
        try RootFiles.verify(Paths.pfConfig)
        guard try String(contentsOfFile: Paths.pfConfig) == config else {
            throw GuardError("PF configuration changed during attachment recovery; blocking rules retained, disk not overwritten")
        }
        if config != restored { try RootFiles.write(restored, to: Paths.pfConfig, mode: 0o644) }
        EventLog.write("pf_attachment_restored", message: "Default PF attachment restored with blocking rules; enable/state-cleanup verification is still pending",
                       details: ["configuration_repaired": config != restored, "backup_path": backup])
    }

    private func requireAttachment() throws {
        guard try attached() else { throw GuardError("Surge Guard must be the first live PF filter rule; run start after reviewing pf.conf") }
    }

    public func enabled() throws -> Bool {
        try Command.checked("/sbin/pfctl", ["-s", "info"]).contains("Status: Enabled")
    }

    public func ensureEnabled() throws {
        try requireAttachment()
        let references = try Command.checked("/sbin/pfctl", ["-s", "References"])
        var ownsReference = false
        if FileManager.default.fileExists(atPath: tokenPath) {
            try RootFiles.verify(tokenPath)
            let token = try String(contentsOfFile: tokenPath).trimmingCharacters(in: .whitespacesAndNewlines)
            ownsReference = !token.isEmpty && token.allSatisfy(\.isNumber) &&
                references.split(whereSeparator: { !$0.isNumber }).contains(Substring(token))
        }
        if !ownsReference {
            let result = try Command.run("/sbin/pfctl", ["-E"], timeout: 5)
            guard result.status == 0 else { throw GuardError("Cannot acquire PF reference: \(result.combined)") }
            // pfctl writes the enable-reference token to stderr on macOS.
            guard let line = result.combined.split(separator: "\n").first(where: { $0.contains("Token") }),
                  let token = line.split(whereSeparator: { !$0.isNumber }).last else {
                throw GuardError("PF did not return an enable-reference token")
            }
            try RootFiles.write(String(token) + "\n", to: tokenPath)
        }
        if try !enabled() {
            try Command.checked("/sbin/pfctl", ["-e"], timeout: 5)
            guard try enabled() else { throw GuardError("PF is not enabled") }
        }
    }

    public func rememberAddresses() throws {
        try loadAddressHistory()
        let previous = knownAddresses
        knownAddresses.formUnion(try Probe.addresses().filter { !$0.loopback }.map(\.address))
        if knownAddresses != previous { try saveAddressHistory() }
    }

    public func clearStates(addresses: () throws -> Set<String>, clear: (String) throws -> Void) throws {
        let loaded = Result { try loadAddressHistory() }
        let current = Result { try addresses() }
        if case .success(let addresses) = current { knownAddresses.formUnion(addresses) }
        let saved = Result { try loaded.get(); try saveAddressHistory() }
        // Enumeration failure must not skip cleanup of addresses already observed while allowed.
        for address in knownAddresses.sorted() { try clear(address) }
        try saved.get()
        knownAddresses = try current.get()
        try saveAddressHistory()
    }

    public func readRules() throws -> String {
        try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-sr"])
    }

    public func unchanged() throws -> Bool {
        guard try attached(), try enabled(), let expectedRules else { return false }
        return try readRules() == expectedRules
    }

    public func systemUpdateSuspended() throws -> Bool {
        try RootFiles.verify(Policy.anchorPath)
        return try String(contentsOfFile: Policy.anchorPath) == SystemUpdate.suspendedAnchor &&
            readRules().trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    public func suspendForSystemUpdate() throws {
        try RootFiles.verify(Policy.anchorPath)
        let disk = try String(contentsOfFile: Policy.anchorPath)
        guard disk == Policy.blocked || disk == SystemUpdate.suspendedAnchor else {
            throw GuardError("Unexpected managed anchor contents; refusing system update maintenance")
        }
        try SystemUpdate.suspend(writeAnchor: {
            try RootFiles.write(SystemUpdate.suspendedAnchor, to: Policy.anchorPath, mode: 0o644)
        }, clearRules: {
            try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-F", "rules"], timeout: 5)
        }, verify: { try self.systemUpdateSuspended() })
        revision += 1
        expectedRules = nil
    }

    @discardableResult
    public func block(clearExistingStates: Bool = true) throws -> (rulesLoadedUptime: Double, statesClearedUptime: Double) {
        // Load fail-closed rules before slower integrity checks. If the anchor
        // was detached, ensureEnabled still rejects the transition.
        try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-f", "-"],
                            input: Policy.blockedRules(lanTCPBindings: lanTCPBindings, usbTCPBindings: usbTCPBindings), timeout: 5)
        let rulesLoaded = SystemClock.seconds
        revision += 1
        try ensureEnabled()
        let actual = try readRules()
        guard actual.contains("surge-guard-block") else { throw GuardError("Block rule did not load") }
        try verifyLANTCP(actual)
        try verifyUSBTCP(actual)
        // States precede PF rule evaluation. Terminate states involving this
        // Mac, including old interface addresses; never flush all PF state.
        if clearExistingStates {
            try clearStates(addresses: { Set(try Probe.addresses().filter { !$0.loopback }.map(\.address)) }) { address in
                try Command.checked("/sbin/pfctl", ["-k", address], timeout: 5)
                try Command.checked("/sbin/pfctl", ["-k", address.contains(":") ? "::/0" : "0.0.0.0/0", "-k", address], timeout: 5)
            }
            revokedLocalStates.removeAll()
        } else { try clearRevokedLocalStates() }
        expectedRules = actual
        let cleared = SystemClock.seconds
        if let blockID {
            EventLog.write("pf_block_observation_gap", level: "warning", message: "Rules reloaded before final counter read",
                           details: ["block_id": blockID, "reason": "rules_reloaded", "last_totals_only": true])
        }
        blockID = UUID().uuidString
        blockStarted = rulesLoaded
        blockCounters = nil
        blockCountersSampled = nil
        blockCounterFailure = ""
        blockCounterContinuity = true
        nextBlockCounterSample = 0
        return (rulesLoaded, cleared)
    }

    public func allow(group: UInt32? = nil, interface: String? = nil) throws {
        guard group != nil || (lanTCPBindings.isEmpty && usbTCPBindings.isEmpty) else { throw GuardError("Local TCP exceptions require persistent TCP enforcement") }
        try ensureEnabled()
        if let group {
            guard let interface else { throw GuardError("Persistent TCP policy needs a verified Surge interface") }
            let rules = try Policy.persistentTCP(group: group, interface: interface, lanTCPBindings: lanTCPBindings, usbTCPBindings: usbTCPBindings)
            try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-f", "-"], input: rules, timeout: 5)
        } else {
            try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-F", "rules"], timeout: 5)
        }
        revision += 1
        let actual = try readRules()
        if group != nil {
            guard actual.contains("surge-guard-tcp-block"),
                  actual.contains("surge-guard-egress"), actual.contains("surge-guard-vif"),
                  actual.contains("if-bound") else {
                throw GuardError("Persistent TCP rules were not verified")
            }
            try verifyLANTCP(actual)
            try verifyUSBTCP(actual)
        } else if !actual.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw GuardError("Surge Guard rules were not cleared")
        }
        try clearRevokedLocalStates()
        expectedRules = actual
        blockID = nil
    }

    private func verifyLANTCP(_ rules: String) throws {
        let actual = Set(rules.split(separator: "\n").map(String.init))
        let expected = try LANTCP.rules(bindings: lanTCPBindings).split(separator: "\n").map(String.init)
        guard expected.allSatisfy(actual.contains),
              actual.filter({ $0.contains("label \"surge-guard-lan-") }).count == expected.count else {
            throw GuardError("LAN TCP rules were not verified")
        }
    }

    private func verifyUSBTCP(_ rules: String) throws {
        let actual = Set(rules.split(separator: "\n").map(String.init))
        let expected = try USBTCP.rules(bindings: usbTCPBindings).split(separator: "\n").map(String.init)
        guard expected.allSatisfy(actual.contains),
              actual.filter({ $0.contains("label \"surge-guard-usb-") }).count == expected.count else {
            throw GuardError("USB TCP rules were not verified")
        }
    }

    public func recordBlockedTraffic(phase: String = "periodic") {
        guard let blockID else { return }
        let now = SystemClock.seconds
        guard phase != "periodic" || now >= nextBlockCounterSample else { return }
        nextBlockCounterSample = now + 5
        do {
            let output = try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-s", "labels"], timeout: 1)
            let counters = try PFBlockCounters.parse(output)
            let delta = try counters.delta(since: blockCounters)
            let baseline = blockCountersSampled ?? (blockCounterContinuity ? blockStarted : nil)
            let recovered = !blockCounterFailure.isEmpty
            blockCounterFailure = ""
            blockCounters = counters
            blockCountersSampled = SystemClock.seconds
            guard delta.packets > 0 || phase != "periodic" || recovered else { return }
            let totals = try JSONSerialization.jsonObject(with: Data(JSON.encode(counters).utf8))
            let changes = try JSONSerialization.jsonObject(with: Data(JSON.encode(delta).utf8))
            var details: [String: Any] = ["block_id": blockID, "block_started_uptime": blockStarted,
                                     "counter_sampled_uptime": blockCountersSampled!, "phase": phase,
                                     "anchor": Policy.anchor, "label": "surge-guard-block", "totals": totals, "delta": changes,
                                     "delta_has_baseline": baseline != nil,
                                     "counter_continuity": blockCounterContinuity, "scope": "own_pf_block_rule_counters"]
            details["delta_baseline_uptime"] = baseline
            EventLog.write("pf_block_traffic", message: "PF block rule packet counters; endpoints and processes not captured", details: details)
        } catch {
            let reason = String(describing: error)
            if reason != blockCounterFailure || phase != "periodic" {
                EventLog.write("pf_block_observation_failed", level: "warning", message: reason,
                               details: ["block_id": blockID, "phase": phase, "impact": "traffic_evidence_unavailable; firewall_policy_unchanged"])
            }
            blockCounterFailure = reason
            blockCounterContinuity = false
            blockCounters = nil
            blockCountersSampled = nil
        }
    }

    public func unlock() throws {
        // Only the caller's anchor/reference is removed, including during recovery.
        try Command.checked("/sbin/pfctl", ["-a", Policy.anchor, "-F", "rules"], timeout: 5)
        if FileManager.default.fileExists(atPath: tokenPath) {
            try RootFiles.verify(tokenPath)
            let token = try String(contentsOfFile: tokenPath).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !token.isEmpty, token.allSatisfy(\.isNumber) else { throw GuardError("Invalid PF reference file") }
            let references = try Command.checked("/sbin/pfctl", ["-s", "References"])
            if references.split(whereSeparator: { !$0.isNumber }).contains(Substring(token)) {
                try Command.checked("/sbin/pfctl", ["-X", token], timeout: 5)
            }
            try FileManager.default.removeItem(atPath: tokenPath)
        }
    }
}
