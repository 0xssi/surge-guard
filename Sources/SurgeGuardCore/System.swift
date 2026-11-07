import Foundation
import Darwin
import Security
import SystemConfiguration

public struct CommandResult {
    public let status: Int32
    public let outputData: Data
    public var output: String { String(decoding: outputData, as: UTF8.self) }
    public let diagnostics: String
    public var combined: String { output + diagnostics }
}

public enum Command {
    // Own the child group and keep its leader unreaped until cleanup, so its PID cannot be reused.
    public static func run(_ executable: String, _ arguments: [String],
                           input: String? = nil, timeout: TimeInterval = 2) throws -> CommandResult {
        guard !([executable] + arguments).contains(where: { $0.utf8.contains(0) }) else {
            throw GuardError("Command executable and arguments must not contain NUL characters")
        }
        guard (input?.utf8.count ?? 0) < 16_384, timeout.isFinite, timeout > 0 else {
            throw GuardError("Invalid command input or timeout")
        }
        let invocation = ([executable] + arguments).joined(separator: " ")
        let output = Pipe(), errors = Pipe(), stdin = Pipe()
        let handles = [output.fileHandleForReading, output.fileHandleForWriting,
                       errors.fileHandleForReading, errors.fileHandleForWriting,
                       stdin.fileHandleForReading, stdin.fileHandleForWriting]
        defer { handles.forEach { try? $0.close() } }
        let outFD = output.fileHandleForReading.fileDescriptor
        let errFD = errors.fileHandleForReading.fileDescriptor
        let inFD = stdin.fileHandleForWriting.fileDescriptor
        for fd in [outFD, errFD, inFD] {
            guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0 else {
                throw GuardError("Cannot configure command pipe")
            }
        }
        guard fcntl(inFD, F_SETNOSIGPIPE, 1) == 0 else { throw GuardError("Cannot protect command stdin") }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw GuardError("Cannot prepare command file actions") }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw GuardError("Cannot prepare command attributes") }
        defer { posix_spawnattr_destroy(&attributes) }
        func require(_ code: Int32) throws {
            guard code == 0 else { throw GuardError("Cannot prepare command: errno \(code)") }
        }
        var mask = sigset_t(), defaults = sigset_t()
        sigemptyset(&mask)
        sigfillset(&defaults)
        sigdelset(&defaults, SIGKILL); sigdelset(&defaults, SIGSTOP)
        try require(posix_spawnattr_setsigmask(&attributes, &mask))
        try require(posix_spawnattr_setsigdefault(&attributes, &defaults))
        try require(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)))
        try require(posix_spawnattr_setpgroup(&attributes, 0))
        if input != nil {
            try require(posix_spawn_file_actions_adddup2(&actions, stdin.fileHandleForReading.fileDescriptor, STDIN_FILENO))
        } else { try require(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)) }
        try require(posix_spawn_file_actions_adddup2(&actions, output.fileHandleForWriting.fileDescriptor, STDOUT_FILENO))
        try require(posix_spawn_file_actions_adddup2(&actions, errors.fileHandleForWriting.fileDescriptor, STDERR_FILENO))
        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        let environment: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C"]
        let env = environment.map { strdup($0) } + [nil]
        defer { (argv + env).forEach { free($0) } }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, executable, &actions, &attributes, argv, env)
        guard spawned == 0 else { throw GuardError("Cannot launch \(invocation): errno \(spawned)") }
        defer {
            kill(-pid, SIGKILL)
            kill(pid, SIGKILL)
            var status: Int32 = 0
            let deadline = SystemClock.seconds + 1
            var reaped = false
            repeat {
                let result = waitpid(pid, &status, WNOHANG)
                if result == pid || (result < 0 && errno == ECHILD) { reaped = true; break }
                usleep(1_000)
            } while SystemClock.seconds < deadline
            if !reaped {
                // A kernel-stalled child must not hold command pipes or the caller indefinitely.
                let child = pid
                DispatchQueue.global(qos: .utility).async {
                    var status: Int32 = 0
                    while waitpid(child, &status, 0) < 0 && errno == EINTR {}
                }
            }
        }
        try output.fileHandleForWriting.close()
        try errors.fileHandleForWriting.close()
        try stdin.fileHandleForReading.close()
        let inputBytes = Data((input ?? "").utf8)
        var written = 0, inputClosed = false
        var captures = [Data(), Data()], eof = [false, false]
        var buffer = [UInt8](repeating: 0, count: 8192)
        let deadline = SystemClock.seconds + timeout
        var exitedAt: Double?
        var exitStatus: Int32?
        while true {
            for (index, fd) in [outFD, errFD].enumerated() where !eof[index] {
                for _ in 0..<8 {
                    let count = Darwin.read(fd, &buffer, buffer.count)
                    if count == 0 { eof[index] = true; break }
                    if count < 0 {
                        if errno == EINTR { continue }
                        guard errno == EAGAIN || errno == EWOULDBLOCK else { throw GuardError("Cannot read \(invocation) output: errno \(errno)") }
                        break
                    }
                    // One boundary byte distinguishes a complete 1 MiB log from a truncated tail.
                    guard captures[index].count + count <= 1_048_577 else { throw GuardError("\(invocation) output exceeded limits") }
                    captures[index].append(contentsOf: buffer.prefix(count))
                }
            }
            if !inputClosed {
                if written < inputBytes.count {
                    let count = inputBytes.withUnsafeBytes { Darwin.write(inFD, $0.baseAddress!.advanced(by: written), inputBytes.count - written) }
                    if count > 0 { written += count }
                    else if count < 0, errno != EAGAIN, errno != EWOULDBLOCK, errno != EINTR {
                        throw GuardError("Cannot write \(invocation) input: errno \(errno)")
                    }
                }
                if written == inputBytes.count { try stdin.fileHandleForWriting.close(); inputClosed = true }
            }
            if exitStatus == nil {
                var info = siginfo_t()
                let result = waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT)
                guard result == 0 || errno == EINTR else { throw GuardError("Cannot inspect \(invocation) child: errno \(errno)") }
                if result == 0, info.si_pid == pid {
                    exitedAt = SystemClock.seconds
                    exitStatus = info.si_code == CLD_EXITED ? info.si_status : 128 + info.si_status
                }
            }
            if let exitStatus, eof.allSatisfy({ $0 }) {
                return CommandResult(status: exitStatus, outputData: captures[0],
                                     diagnostics: String(decoding: captures[1], as: UTF8.self))
            }
            let now = SystemClock.seconds
            guard now < deadline else { throw GuardError("\(invocation) timed out after \(timeout)s") }
            if let exitedAt, now - exitedAt >= 1 { throw GuardError("\(invocation) output pipes did not close") }
            var descriptors = [pollfd(fd: eof[0] ? -1 : outFD, events: Int16(POLLIN), revents: 0),
                               pollfd(fd: eof[1] ? -1 : errFD, events: Int16(POLLIN), revents: 0),
                               pollfd(fd: inputClosed ? -1 : inFD, events: Int16(POLLOUT), revents: 0)]
            _ = poll(&descriptors, nfds_t(descriptors.count), 10)
        }
    }

    @discardableResult
    public static func checked(_ executable: String, _ arguments: [String],
                               input: String? = nil, timeout: TimeInterval = 2) throws -> String {
        let result = try run(executable, arguments, input: input, timeout: timeout)
        let invocation = ([executable] + arguments).joined(separator: " ")
        guard result.status == 0 else { throw GuardError("\(invocation) failed: \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))") }
        return result.output
    }
}

public struct InterfaceAddress {
    public let name: String
    public let address: String
    public let up: Bool
    public let loopback: Bool

    public init(name: String, address: String, up: Bool, loopback: Bool) {
        self.name = name
        self.address = address
        self.up = up
        self.loopback = loopback
    }
}

public enum Probe {
    public static let surgeCLI = "/Applications/Surge.app/Contents/Applications/surge-cli"

    public static func consoleUID() throws -> uid_t {
        var uid: uid_t = 0
        guard SCDynamicStoreCopyConsoleUser(nil, &uid, nil) != nil, uid >= 501 else {
            throw GuardError("No interactive user session; waiting for login")
        }
        return uid
    }

    public static func dropPrivileges(to uid: uid_t) throws {
        guard geteuid() == 0, uid == (try consoleUID()), let account = getpwuid(uid) else {
            throw GuardError("Cannot resolve the console user for privilege drop")
        }
        let name = String(cString: account.pointee.pw_name)
        let gid = account.pointee.pw_gid
        guard initgroups(name, Int32(gid)) == 0,
              setgid(gid) == 0, setuid(uid) == 0,
              getuid() == uid, geteuid() == uid else {
            throw GuardError("Cannot enter the console user's unprivileged session")
        }
    }

    public static func session(configuration: Configuration) throws -> SessionObservation {
        guard geteuid() != 0, getuid() == (try consoleUID()) else {
            throw GuardError("Surge CLI queries must run as the console user")
        }
        return try SessionObservation.collect(configuration: configuration) { arguments in
            try Command.checked(surgeCLI, arguments)
        }
    }

    public static func privilegedSession(configuration: Configuration, helperPath: String = Paths.binary) throws -> SessionObservation {
        let uid = try consoleUID()
        try RootFiles.verify(helperPath)
        // Enter the user's bootstrap namespace, then drop UID/GID inside our
        // root-owned helper before executing any user-owned Surge code.
        let response = try Command.checked("/bin/launchctl", ["asuser", String(uid), helperPath, "session-probe", String(uid)],
                                           timeout: 3)
        guard uid == (try consoleUID()) else { throw GuardError("Console user changed during rule probe") }
        let observation = try JSON.decode(SessionObservation.self, from: Data(response.utf8))
        guard observation.policyFingerprint == (try configuration.fingerprint()) else {
            throw GuardError("Policy changed during query; run candidate --config checks as the normal user")
        }
        return observation
    }

    public static func addresses(query: (UnsafeMutablePointer<UnsafeMutablePointer<ifaddrs>?>) -> Int32 = getifaddrs) throws -> [InterfaceAddress] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard query(&first) == 0 else { throw GuardError("Cannot enumerate interface addresses: errno \(errno)") }
        defer { freeifaddrs(first) }
        var result: [InterfaceAddress] = []
        var current = first
        while let item = current {
            defer { current = item.pointee.ifa_next }
            let info = item.pointee
            guard let address = info.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET) || address.pointee.sa_family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host,
                              socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { throw GuardError("Cannot decode interface address") }
            result.append(InterfaceAddress(name: String(cString: info.ifa_name),
                                           address: String(cString: host).components(separatedBy: "%")[0],
                                           up: info.ifa_flags & UInt32(IFF_UP) != 0,
                                           loopback: info.ifa_flags & UInt32(IFF_LOOPBACK) != 0))
        }
        return result
    }

    public static func trustedSurgePID() throws -> pid_t? {
        let candidates = try surgeCandidates()
        var trust = SurgeProcessTrust()
        return try trust.trustedPID(candidates: candidates, validate: surgeSignatureValid, recheck: surgeCandidates)
    }

    public static func surgeCandidates() throws -> [SurgeProcess] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        for _ in 0..<3 {
            var size = 0
            guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0, size <= 16 * 1024 * 1024 else {
                throw GuardError("Cannot size native process inventory: errno \(errno)")
            }
            var records = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride + 64)
            size = records.count * MemoryLayout<kinfo_proc>.stride
            let result = records.withUnsafeMutableBytes { sysctl(&mib, 3, $0.baseAddress, &size, nil, 0) }
            if result != 0, errno == ENOMEM { continue }
            guard result == 0, size > 0, size % MemoryLayout<kinfo_proc>.stride == 0,
                  size <= records.count * MemoryLayout<kinfo_proc>.stride else {
                throw GuardError("Cannot read complete native process inventory: errno \(errno)")
            }
            return records.prefix(size / MemoryLayout<kinfo_proc>.stride).compactMap { info in
                let name = withUnsafeBytes(of: info.kp_proc.p_comm) {
                    String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self)
                }
                guard name == "Surge" else { return nil }
                let started = info.kp_proc.p_un.__p_starttime
                return SurgeProcess(pid: info.kp_proc.p_pid, startedSeconds: Int(started.tv_sec),
                                    startedMicroseconds: Int(started.tv_usec))
            }.sorted { $0.pid < $1.pid }
        }
        throw GuardError("Native process inventory changed repeatedly")
    }

    public static func surgeSignatureValid(_ pid: pid_t) -> Bool {
        var requirement: SecRequirement?
        let identity = "anchor apple generic and identifier \"com.nssurge.surge-mac\" and certificate leaf[subject.OU] = \"YCKFLA6N72\""
        guard SecRequirementCreateWithString(identity as CFString, SecCSFlags(rawValue: 0), &requirement) == errSecSuccess,
              let requirement else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        return SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(rawValue: 0), &code) == errSecSuccess &&
            code.map { SecCodeCheckValidity($0, SecCSFlags(rawValue: 0), requirement) == errSecSuccess } == true
    }

    public static func trustedSurgeRunning() throws -> Bool {
        try trustedSurgePID() != nil
    }

    public static func startupNetworkReady(primaryInterface: String?, addresses: [InterfaceAddress]) -> Bool {
        guard let primaryInterface, !primaryInterface.isEmpty else { return false }
        return addresses.contains { address in
            var ipv4 = in_addr()
            return address.name == primaryInterface && address.up && !address.loopback &&
                !address.address.utf8.contains(0) && inet_pton(AF_INET, address.address, &ipv4) == 1
        }
    }

    public static func startupNetworkReady() throws -> Bool {
        guard let store = SCDynamicStoreCreate(nil, "surge-gate.startup-network" as CFString, nil, nil) else {
            throw GuardError("Cannot open SystemConfiguration store for Surge startup")
        }
        let primary = try networkDictionary("State:/Network/Global/IPv4", read: {
            SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString)
        })
        // A DHCP address alone is insufficient while captive evaluation withholds the primary network.
        return startupNetworkReady(primaryInterface: primary?["PrimaryInterface"] as? String, addresses: try addresses())
    }

    public static func surgeInterface() throws -> String {
        guard let store = SCDynamicStoreCreate(nil, "surge-guard.interface" as CFString, nil, nil),
              let primary = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let service = primary["PrimaryService"] as? String, isSurgeService(service, store: store),
              let interface = primary["PrimaryInterface"] as? String,
              try addresses().contains(where: { $0.name == interface && $0.up && $0.address == "198.18.0.1" }) else {
            throw GuardError("Verified Surge interface is unavailable")
        }
        return interface
    }

    public static func isSurgeService(_ service: String, store: SCDynamicStore) -> Bool {
        guard !service.isEmpty,
              let vpn = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(service)/VPN" as CFString) as? [String: Any] else { return false }
        return vpn["NEProviderBundleIdentifier"] as? String == "com.nssurge.surge-mac.ne"
    }

    public static func connectionLossReason(_ status: SCNetworkConnectionStatus) -> String? {
        switch status {
        case .connected: return nil
        case .disconnecting: return "surge_tunnel_disconnecting"
        case .disconnected: return "surge_tunnel_disconnected"
        case .connecting: return "surge_tunnel_connecting"
        default: return "surge_tunnel_status_unknown"
        }
    }

    public static func networkDictionary(_ key: String, read: () -> Any?, error: () -> Int32 = SCError) throws -> [String: Any]? {
        guard let value = read() else {
            let status = error()
            guard status == kSCStatusNoKey else { throw GuardError("Cannot read network state \(key): \(status)") }
            return nil
        }
        guard let dictionary = value as? [String: Any] else { throw GuardError("Invalid network state dictionary: \(key)") }
        return dictionary
    }

    public static func readiness(trustedProcess: Bool? = nil) throws -> Readiness {
        guard let store = SCDynamicStoreCreate(nil, "surge-guard.probe" as CFString, nil, nil) else {
            throw GuardError("Cannot open SystemConfiguration store")
        }
        func dictionary(_ key: String) throws -> [String: Any]? {
            try networkDictionary(key, read: { SCDynamicStoreCopyValue(store, key as CFString) })
        }
        let primary = try dictionary("State:/Network/Global/IPv4") ?? [:]
        let globalIPv6 = try dictionary("State:/Network/Global/IPv6")
        let service = primary["PrimaryService"] as? String ?? ""
        let interface = primary["PrimaryInterface"] as? String ?? ""
        let ipv6Interface = globalIPv6.map { $0["PrimaryInterface"] as? String ?? "" }
        let surgeService = isSurgeService(service, store: store)
        let connection = surgeService ? SCNetworkConnectionCreateWithServiceID(nil, service as CFString, nil, nil) : nil
        let connected = connection.map { SCNetworkConnectionGetStatus($0) == .connected } ?? false
        let vifUp = try interface.hasPrefix("utun") && addresses().contains {
            $0.name == interface && $0.up && $0.address == "198.18.0.1"
        }
        let route = try Command.checked("/sbin/route", ["-n", "get", "default"])
        return Readiness(trustedProcess: try trustedProcess ?? trustedSurgeRunning(), surgeService: surgeService,
                         connected: connected, vifUp: vifUp,
                         ownsDefaultRoute: !interface.isEmpty && Policy.defaultInterface(route) == interface,
                         ipv6Safe: Policy.ipv6Safe(primaryInterface: ipv6Interface, surgeInterface: interface))
    }
}
