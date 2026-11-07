import Darwin
import Foundation

// Kernel socket attribution is independent of SCPreferences and VPN status numbers.
// Never infer a utun owner from its address, display name or another running VPN.
public struct NativeTunnelBinding: Equatable {
    public let provider: SurgeProcess
    public let descriptor: Int32
    public let interface: String
    public let socket: UInt64

    public init(provider: SurgeProcess, descriptor: Int32, interface: String, socket: UInt64) {
        self.provider = provider
        self.descriptor = descriptor
        self.interface = interface
        self.socket = socket
    }

    public static func interface(kind: Int32, family: Int32, protocolNumber: Int32,
                                 controller: String, unit: UInt32, state: Int16) -> String? {
        let refused = SOI_S_NOFDREF | SOI_S_ISCONNECTING | SOI_S_ISDISCONNECTING |
            SOI_S_CANTSENDMORE | SOI_S_CANTRCVMORE | SOI_S_ISDISCONNECTED
        guard kind == SOCKINFO_KERN_CTL, family == AF_SYSTEM, protocolNumber == SYSPROTO_CONTROL,
              controller == "com.apple.net.utun_control", unit > 0,
              Int32(state) & SOI_S_ISCONNECTED != 0, Int32(state) & refused == 0 else { return nil }
        // XNU utun_ctl_connect assigns the interface unit from sc_unit - 1.
        return "utun\(unit - 1)"
    }

    public static func read(provider: SurgeProcess, interface: String) throws -> NativeTunnelBinding? {
        guard geteuid() == 0 else {
            throw GuardError("Native tunnel ownership inspection requires administrator access; run sudo \(Paths.binary) doctor")
        }
        return try read(provider: provider, interface: interface,
                        identity: { try SurgeProcess.read(pid: provider.pid) },
                        descriptors: { try descriptors(pid: provider.pid) },
                        socket: { try socket(pid: provider.pid, descriptor: $0) })
    }

    public static func read(provider: SurgeProcess, interface: String,
                            identity: () throws -> SurgeProcess?, descriptors: () throws -> [Int32],
                            socket: (Int32) throws -> socket_info?) throws -> NativeTunnelBinding? {
        for _ in 0..<3 {
            guard try identity() == provider else { return nil }
            let fds = try descriptors()
            var matches: [NativeTunnelBinding] = []
            var changed = false
            for fd in fds {
                guard let value = try socket(fd) else { changed = true; break }
                guard let binding = binding(value, provider: provider, descriptor: fd),
                      binding.interface == interface else { continue }
                matches.append(binding)
            }
            if changed { continue }
            guard try identity() == provider else { return nil }
            guard matches.count == 1, let match = matches.first else { return nil }
            // Re-read the actual FD after enumeration: a reused FD is not the same socket.
            guard let current = try socket(match.descriptor),
                  binding(current, provider: provider, descriptor: match.descriptor) == match,
                  try identity() == provider else { continue }
            return match
        }
        throw GuardError("Native tunnel socket inventory changed repeatedly")
    }

    private static func binding(_ info: socket_info, provider: SurgeProcess, descriptor: Int32) -> NativeTunnelBinding? {
        let control = info.soi_proto.pri_kern_ctl
        let name = withUnsafeBytes(of: control.kcsi_name) { bytes -> String? in
            guard let end = bytes.firstIndex(of: 0) else { return nil }
            return String(bytes: bytes[..<end], encoding: .utf8)
        }
        guard info.soi_so != 0, control.kcsi_id != 0, let name,
              let interface = interface(kind: info.soi_kind, family: info.soi_family,
                                        protocolNumber: info.soi_protocol, controller: name,
                                        unit: control.kcsi_unit, state: info.soi_state) else { return nil }
        return NativeTunnelBinding(provider: provider, descriptor: descriptor, interface: interface, socket: info.soi_so)
    }

    private static func socket(pid: pid_t, descriptor: Int32) throws -> socket_info? {
        var value = socket_fdinfo()
        let size = proc_pidfdinfo(pid, descriptor, PROC_PIDFDSOCKETINFO,
                                 &value, Int32(MemoryLayout<socket_fdinfo>.size))
        if size == 0, errno == EBADF || errno == ENOENT { return nil }
        guard size == MemoryLayout<socket_fdinfo>.size else {
            throw GuardError("Cannot inspect native tunnel socket: errno \(errno), size \(size)")
        }
        return value.psi
    }

    private static func descriptors(pid: pid_t) throws -> [Int32] {
        let required = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        let stride = MemoryLayout<proc_fdinfo>.stride
        guard required > 0, required <= 1_048_576, Int(required) % stride == 0 else {
            throw GuardError("Cannot size native tunnel descriptors: errno \(errno), size \(required)")
        }
        var values = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(required) / stride + 128)
        let capacity = values.count * stride
        let size = values.withUnsafeMutableBytes {
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count))
        }
        guard size > 0, size < capacity, Int(size) % stride == 0 else {
            throw GuardError("Cannot read complete native tunnel descriptors: errno \(errno), size \(size)")
        }
        return values.prefix(Int(size) / stride).filter { $0.proc_fdtype == PROX_FDTYPE_SOCKET }.map(\.proc_fd)
    }
}

public enum SurgeServiceConnection: Equatable {
    case configured
    case kernel(NativeTunnelBinding)
}
