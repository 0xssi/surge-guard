import Darwin
import Foundation
import SystemConfiguration
import SurgeGuardCore

func protectionTests() throws {
    let key = "State:/Network/Global/IPv6"
    let missing = try Probe.networkDictionary(key, read: { nil }, error: { Int32(kSCStatusNoKey) })
    try check(missing == nil && Policy.ipv6Safe(primaryInterface: missing?["PrimaryInterface"] as? String, surgeInterface: "utun9"),
              "An explicitly absent IPv6 key must remain supported")
    for status in [kSCStatusFailed, kSCStatusNoStoreSession, kSCStatusOK] {
        try rejects { _ = try Probe.networkDictionary(key, read: { nil }, error: { Int32(status) }) }
    }
    for value in ["invalid" as Any, NSNull(), ["PrimaryInterface": 9]] {
        if value is [String: Any] {
            let dictionary = try Probe.networkDictionary(key, read: { value })
            try check(!Policy.ipv6Safe(primaryInterface: dictionary.map { $0["PrimaryInterface"] as? String ?? "" }, surgeInterface: "utun9"),
                      "Malformed IPv6 primary interface became absent")
        } else { try rejects { _ = try Probe.networkDictionary(key, read: { value }) } }
    }
    let empty = try Probe.networkDictionary(key, read: { [:] as [String: Any] })
    try check(!Policy.ipv6Safe(primaryInterface: empty.map { $0["PrimaryInterface"] as? String ?? "" }, surgeInterface: "utun9"),
              "Present empty IPv6 state became a missing route")
    print("PASS: IPv6 store errors and malformed values fail closed; only NoKey means absent")

    for phase in [SystemUpdate.Phase.preparing, .active, .restoring] {
        var record = SystemUpdate(userID: 501, backupID: UUID().uuidString); record.phase = phase
        try check(try SystemUpdate.loadProtectingOnFailure(read: { record }, protect: {
            throw GuardError("Valid maintenance unexpectedly re-armed protection")
        }) == record, "Valid maintenance did not preserve its phase")
    }
    for blockFails in [false, true] {
        var steps: [String] = []
        do {
            _ = try SystemUpdate.loadProtectingOnFailure(read: { throw GuardError("corrupt checkpoint") }, protect: {
                steps.append("restore_boot_anchor"); steps.append("repair_attachment"); steps.append("block")
                if blockFails { throw GuardError("attachment unavailable") }
            })
            throw GuardError("Invalid checkpoint was silently discarded")
        } catch {
            let message = String(describing: error)
            try check(steps == ["restore_boot_anchor", "repair_attachment", "block"] && message.contains("corrupt checkpoint") &&
                      message.contains(blockFails ? "blocking could not be verified: attachment unavailable" : "blocking verified"),
                      "Invalid maintenance skipped repair, lost its error or claimed unverified blocking")
        }
    }
    print("PASS: invalid maintenance attempts attachment repair and blocking without re-arming valid active maintenance")

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("pf-history-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("addresses.json").path
    func fixture(_ addresses: [String], boot: String = SystemClock.bootID) throws {
        let object: [String: Any] = ["version": 1, "boot_id": boot, "addresses": addresses]
        try AtomicFile.write(String(decoding: JSONSerialization.data(withJSONObject: object), as: UTF8.self), to: path, mode: 0o600)
    }
    for _ in 0..<2 {
        try fixture(["192.0.2.10", "2001:db8::1"])
        let firewall = Firewall(historyPath: path)
        var cleared: [String] = []
        try rejects {
            try firewall.clearStates(addresses: { throw GuardError("inventory failed") }) { cleared.append($0) }
        }
        try check(cleared == ["192.0.2.10", "2001:db8::1"], "Replacement firewall forgot boot-bound historical addresses")
    }
    try fixture(["192.0.2.10"], boot: "previous-boot")
    var previousBoot: [String] = []
    try rejects { try Firewall(historyPath: path).clearStates(addresses: { [] }) { previousBoot.append($0) } }
    try check(previousBoot.isEmpty, "Previous-boot addresses became current state cleanup dependencies")
    for addresses in [["192.0.2.1/24"], ["192.0.2.1\u{0}ignored"], ["192.0.2.1", "192.0.2.1"], Array(repeating: "::1", count: 513)] {
        try fixture(addresses)
        var cleared: [String] = []
        try rejects { try Firewall(historyPath: path).clearStates(addresses: { ["192.0.2.20"] }) { cleared.append($0) } }
        try check(cleared == ["192.0.2.20"], "Invalid history skipped current address cleanup or supplied unsafe pfctl arguments")
    }
    try check(try String(contentsOfFile: path).contains("addresses"), "Failed cleanup discarded its checkpoint")
    print("PASS: replacement firewalls consume bounded boot-bound history; invalid history still permits current-address cleanup")

    let local = Firewall(historyPath: nil)
    try local.setLANTCP([LANTCPBinding(interface: "en0", address: "192.168.1.2")])
    try local.setUSBTCP([USBTCPBinding(interface: "en11", address: "fe80::1234")])
    try local.setUSBTCP([])
    var arguments: [[String]] = []
    try rejects { try local.clearRevokedLocalStates { arguments.append($0); throw GuardError("cleanup failed") } }
    arguments = []
    try local.clearRevokedLocalStates { arguments.append($0) }
    try check(Set(arguments) == [["-k", "fe80::1234", "-k", "fe80::/10"], ["-k", "fe80::/10", "-k", "fe80::1234"]] &&
              local.lanTCPBindings.count == 1, "USB revocation forgot retry state, revoked LAN or cleared unrelated endpoints")
    arguments = []
    try local.clearRevokedLocalStates { arguments.append($0) }
    try check(arguments.isEmpty, "Successful local cleanup replayed pending removals")
    try local.setLANTCP([])
    try local.clearRevokedLocalStates { arguments.append($0) }
    try check(arguments.count == 6 && arguments.allSatisfy { $0.count == 4 && $0.contains("192.168.1.2") && !$0.contains("0.0.0.0/0") },
              "LAN revocation broadened to public peers or lost a direction")
    print("PASS: local exception removal clears only corresponding peer pairs and retains failed cleanup for retry")

    let lan = LANTCPBinding(interface: "en0", address: "192.168.1.2")
    let usb = USBTCPBinding(interface: "en11", address: "fe80::1234")
    let usbFailure = LocalTCPInventory(addresses: { [] }, lan: { _ in [lan] }, usb: { _ in throw GuardError("USB unavailable") })
    try check(usbFailure.lan == [lan] && usbFailure.usb.isEmpty && usbFailure.errors == ["usb_tcp_inventory_failed: USB unavailable"],
              "USB inventory failure revoked the valid LAN scope")
    let lanFailure = LocalTCPInventory(addresses: { [] }, lan: { _ in throw GuardError("LAN unavailable") }, usb: { _ in [usb] })
    try check(lanFailure.lan.isEmpty && lanFailure.usb == [usb] && lanFailure.errors.count == 1,
              "LAN inventory failure revoked the verified USB scope")
    let missingInventory = LocalTCPInventory(addresses: { throw GuardError("interfaces unavailable") },
                                            lan: { _ in throw GuardError("should not query") }, usb: { _ in throw GuardError("should not query") })
    try check(missingInventory.lan.isEmpty && missingInventory.usb.isEmpty && missingInventory.errors == ["interface_inventory_failed: interfaces unavailable"],
              "Failed address enumeration retained a local exception or queried incomplete inventory")
    let warningSnapshot = GuardSnapshot(runId: "fixture", firewallVerifiedUptime: SystemClock.seconds, allowed: true,
                                        configurationMode: "enhanced", readiness: nil, session: nil, reasons: [], localTcpErrors: usbFailure.errors)
    try check(try JSON.decode(GuardSnapshot.self, from: Data(JSON.encode(warningSnapshot).utf8)).localTcpErrors == usbFailure.errors,
              "Local inventory errors disappeared from machine-readable status")
    let localLog = "{\"event\":\"local_tcp_inventory_failed\",\"message\":\"USB unavailable\"}"
    try check(LogReader.format(localLog).contains("公网放行仍由原有 Surge") && LogReader.format(localLog, json: true).contains("USB unavailable"),
              "Local inventory log claimed a public outage or lost the raw error")
    print("PASS: optional LAN/USB failures revoke only their own scope and retain JSON errors")

    let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let recovery = try String(contentsOf: project.appendingPathComponent("integrations/swiftbar/surge-guard-action.sh"))
    var program = recovery.components(separatedBy: "recovery_lock_program='\n")[1].components(separatedBy: "\n'\n")[0]
    let managementPath = directory.appendingPathComponent("management.lock").path
    let lockPath = directory.appendingPathComponent("lock").path
    let marker = directory.appendingPathComponent("must-not-run").path
    let service = directory.appendingPathComponent("launchctl").path
    let pf = directory.appendingPathComponent("pfctl").path
    try "#!/bin/sh\necho 'Could not find service'\nexit 113\n".write(toFile: service, atomically: true, encoding: .utf8)
    try "#!/bin/sh\nif [ \"$3\" = -F ]; then /usr/bin/touch '\(marker)'; fi\n".write(toFile: pf, atomically: true, encoding: .utf8)
    chmod(service, 0o700); chmod(pf, 0o700)
    program = program.replacingOccurrences(of: "/private/var/db/surge-guard", with: directory.path)
        .replacingOccurrences(of: "$> == 0", with: "$> == \(geteuid())")
        .replacingOccurrences(of: "$info[4] == 0", with: "$info[4] == \(geteuid())")
        .replacingOccurrences(of: "+ 20;", with: "+ 0.1;")
        .replacingOccurrences(of: "/bin/launchctl", with: service)
        .replacingOccurrences(of: "/sbin/pfctl", with: pf)
    let recoveryArguments = ["-T", "-MConfig", "-MFcntl=:flock,:DEFAULT,:mode", "-MTime::HiRes=clock_gettime,CLOCK_MONOTONIC,sleep", "-e", program]
    for path in [managementPath, lockPath] {
        let held = try RuntimeLock(taking: open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600))
        defer { withExtendedLifetime(held) {} }
        let refused = try Command.run("/usr/bin/perl", recoveryArguments)
        try check(refused.status != 0 && !FileManager.default.fileExists(atPath: marker),
                  "System Perl bypassed a native management/runtime flock and executed a recovery mutation")
    }
    let before = try FileManager.default.attributesOfItem(atPath: managementPath)[.systemFileNumber] as? NSNumber
    _ = try Command.checked("/usr/bin/perl", recoveryArguments)
    let after = try FileManager.default.attributesOfItem(atPath: managementPath)[.systemFileNumber] as? NSNumber
    try check(FileManager.default.fileExists(atPath: marker) && before == after,
              "Independent recovery replaced its lock inode or could not recover after release")
    try FileManager.default.removeItem(atPath: marker)
    chmod(managementPath, 0o644)
    try check(try Command.run("/usr/bin/perl", recoveryArguments).status != 0 && !FileManager.default.fileExists(atPath: marker),
              "Recovery trusted a non-private lock file")
    try FileManager.default.removeItem(atPath: managementPath)
    try FileManager.default.createSymbolicLink(atPath: managementPath, withDestinationPath: lockPath)
    try check(try Command.run("/usr/bin/perl", recoveryArguments).status != 0 && !FileManager.default.fileExists(atPath: marker),
              "Recovery followed a substituted lock symlink")
    print("PASS: system Perl native flock serializes both daemon/management locks, retains inodes and rejects unsafe files")

    let routes = (0..<8).map { RouteCheck(url: "https://example.com/\($0)", requiredGroup: "Proxy") }
    let configuration = Configuration(version: 1, mode: "routes", routeChecks: routes)
    let status = "{\"mode\":\"rule\",\"features\":{\"enhanced-mode\":true}}"
    let route = "{\"rule-policy\":\"Proxy\",\"final\":\"Node\",\"final-type\":\"ss\",\"steps\":[{\"group\":\"Proxy\",\"selected\":\"Node\"}]}"
    let lock = NSLock()
    var active = 0, peak = 0, calls = 0
    let observation = try SessionObservation.collect(configuration: configuration) { arguments in
        lock.lock(); active += 1; calls += 1; peak = max(peak, active); lock.unlock()
        Thread.sleep(forTimeInterval: 0.05)
        lock.lock(); active -= 1; lock.unlock()
        return arguments == ["--raw", "status"] ? status : route
    }
    try check(calls == 9 && peak > 1 && observation.ready && observation.routes.map(\.url) == routes.map(\.url),
              "Route probes ran serially, lost their configured order or changed policy evaluation")
    try rejects {
        _ = try SessionObservation.collect(configuration: configuration) { arguments in
            if arguments.last == routes[3].url { throw GuardError("injected query failure") }
            return arguments == ["--raw", "status"] ? status : route
        }
    }
    try rejects { _ = try SessionObservation.collect(configuration: configuration) { _ in "{}" } }
    print("PASS: bounded concurrent rule queries preserve URL order, configuration binding and fail-closed errors")

    try check(Policy.blocked.contains("from (self) port 68 to any port 67 user root tag SG_LINK no state") &&
              !Policy.blocked.contains("port 53"), "DHCP renewal widened into an ordinary-user or DNS exception")
    _ = try Command.checked("/sbin/pfctl", ["-n", "-f", "-"], input: Policy.blocked)
    print("PASS: native PF parses root-owned local-source DHCPv4 renewal without opening DNS")
}
