import Darwin
import Foundation
import SystemConfiguration
import SurgeGuardCore

func nativeTunnelTests() throws {
    func interface(kind: Int32 = Int32(SOCKINFO_KERN_CTL), family: Int32 = AF_SYSTEM,
                   proto: Int32 = SYSPROTO_CONTROL, controller: String = "com.apple.net.utun_control",
                   unit: UInt32 = 43, state: Int16 = Int16(SOI_S_ISCONNECTED)) -> String? {
        NativeTunnelBinding.interface(kind: kind, family: family, protocolNumber: proto,
                                     controller: controller, unit: unit, state: state)
    }
    try check(interface() == "utun42", "Kernel control unit did not identify its actual utun")
    try check(interface(unit: 1) == "utun0" && interface(unit: 0) == nil, "Invalid zero unit was accepted")
    try check(interface(kind: Int32(SOCKINFO_TCP)) == nil && interface(family: AF_INET) == nil &&
              interface(proto: 0) == nil && interface(controller: "other.controller") == nil,
              "An unrelated socket was treated as a Surge tunnel")
    for bit in [SOI_S_NOFDREF, SOI_S_ISCONNECTING, SOI_S_ISDISCONNECTING,
                SOI_S_CANTSENDMORE, SOI_S_CANTRCVMORE, SOI_S_ISDISCONNECTED] {
        try check(interface(state: Int16(SOI_S_ISCONNECTED | bit)) == nil,
                  "A closing or nonfunctional native socket permitted readiness")
    }
    try check(interface(state: 0) == nil &&
              interface(state: Int16(SOI_S_ISCONNECTED | SOI_S_PRIV | SOI_S_NBIO)) == "utun42",
              "Connected native state or harmless flags were misclassified")
    print("PASS: kernel tunnel identity requires exact controller, unit, family, protocol and usable connected socket")

    let provider = SurgeProcess(pid: 1234, startedSeconds: 10, startedMicroseconds: 20)
    let binding = NativeTunnelBinding(provider: provider, descriptor: 6, interface: "utun42", socket: 123)
    func socket(handle: UInt64 = 123) -> socket_info {
        var info = socket_info(), control = kern_ctl_info()
        info.soi_so = handle
        info.soi_kind = Int32(SOCKINFO_KERN_CTL)
        info.soi_family = AF_SYSTEM
        info.soi_protocol = SYSPROTO_CONTROL
        info.soi_state = Int16(SOI_S_ISCONNECTED)
        control.kcsi_id = 1
        control.kcsi_unit = 43
        withUnsafeMutableBytes(of: &control.kcsi_name) {
            $0.copyBytes(from: Array("com.apple.net.utun_control".utf8) + [0])
        }
        info.soi_proto.pri_kern_ctl = control
        return info
    }
    try check(try NativeTunnelBinding.read(provider: provider, interface: "utun42", identity: { provider },
                                           descriptors: { [6] }, socket: { _ in socket() }) == binding,
              "Stable native ownership was rejected")
    try check(try NativeTunnelBinding.read(provider: provider, interface: "utun42", identity: { provider },
                                           descriptors: { [6, 7] }, socket: { _ in socket() }) == nil,
              "Ambiguous matching socket descriptors were accepted")
    var observations = 0
    try check(try NativeTunnelBinding.read(provider: provider, interface: "utun42", identity: {
        observations += 1
        return observations == 1 ? provider : SurgeProcess(pid: 1234, startedSeconds: 99, startedMicroseconds: 0)
    }, descriptors: { [6] }, socket: { _ in socket() }) == nil, "PID reuse during enumeration was accepted")
    observations = 0
    try rejects {
        _ = try NativeTunnelBinding.read(provider: provider, interface: "utun42", identity: { provider },
                                         descriptors: { [6] }, socket: { _ in
            observations += 1
            return socket(handle: observations % 2 == 1 ? 123 : 456)
        })
    }
    try check(observations == 6, "FD reuse was accepted or retried without a bound")
    observations = 0
    try rejects {
        _ = try NativeTunnelBinding.read(provider: provider, interface: "utun42", identity: { provider },
                                         descriptors: { [6] }, socket: { _ in observations += 1; return nil })
    }
    try check(observations == 3, "Disappearing FDs were treated as successful complete inventory")
    do {
        _ = try NativeTunnelBinding.read(provider: provider, interface: "utun42", identity: { provider },
                                         descriptors: { [6] }, socket: { _ in throw GuardError("short native socket result") })
        throw GuardError("Socket query error was hidden")
    } catch {
        try check(String(describing: error).contains("short native socket result"), "Original socket query error was lost")
    }
    print("PASS: native ownership rechecks process birth, FD/socket identity, ambiguity and bounded inventory races")

    let primary: [String: Any] = ["PrimaryService": "fixture-service", "PrimaryInterface": "utun42"]
    var kernelCalls = 0
    func resolve(setup: [String: Any]?, current: [String: Any]? = primary,
                 candidate: NativeTunnelBinding? = binding) throws -> SurgeServiceConnection? {
        try Probe.serviceConnection("fixture-service", interface: "utun42", read: { key in
            key.hasPrefix("Setup:") ? setup : current
        }, kernel: { _ in kernelCalls += 1; return candidate })
    }
    try check(try resolve(setup: nil) == .kernel(binding), "Absent Setup could not use verified kernel ownership")
    kernelCalls = 0
    try check(try resolve(setup: ["NEProviderBundleIdentifier": "com.nssurge.surge-mac.ne"]) == .configured,
              "Configured official service lost its SCNetworkConnection path")
    for setup: [String: Any] in [[:], ["NEProviderBundleIdentifier": "other.provider"], ["NEProviderBundleIdentifier": 7]] {
        try check(try resolve(setup: setup) == nil, "An explicit Setup service entered the kernel path")
    }
    try check(kernelCalls == 0, "Explicit Setup was overridden by an unrelated connected kernel socket")
    try check(try resolve(setup: nil, candidate: nil) == nil, "Missing kernel ownership permitted readiness")
    for changed: [String: Any]? in [nil, [:], ["PrimaryService": "other", "PrimaryInterface": "utun42"],
                                    ["PrimaryService": "fixture-service", "PrimaryInterface": "utun43"]] {
        try check(try resolve(setup: nil, current: changed) == nil, "Changed primary binding was accepted")
    }
    let wrong = NativeTunnelBinding(provider: provider, descriptor: 6, interface: "utun43", socket: 123)
    try check(try resolve(setup: nil, candidate: wrong) == nil, "Kernel ownership of a different VIF was accepted")
    var setupReads = 0
    let changedSetup = try Probe.serviceConnection("fixture-service", interface: "utun42", read: { key in
        if key.hasPrefix("Setup:") {
            setupReads += 1
            return setupReads == 1 ? nil : ["NEProviderBundleIdentifier": "other.provider"]
        }
        return primary
    }, kernel: { _ in binding })
    try check(changedSetup == nil, "A newly configured different provider was overridden after socket inspection")
    for error in [kSCStatusFailed, kSCStatusNoStoreSession, kSCStatusOK] {
        kernelCalls = 0
        try rejects {
            _ = try Probe.serviceConnection("fixture-service", interface: "utun42", read: { key in
                try Probe.networkDictionary(key, read: { nil }, error: { Int32(error) })
            }, kernel: { _ in kernelCalls += 1; return binding })
        }
        try check(kernelCalls == 0, "A failed Setup read became an absent Setup service")
    }
    try rejects {
        _ = try Probe.serviceConnection("fixture-service", interface: "utun42", read: { key in
            try Probe.networkDictionary(key, read: { "malformed" })
        }, kernel: { _ in binding })
    }
    if geteuid() != 0 {
        try rejects { _ = try NativeTunnelBinding.read(provider: provider, interface: "utun42") }
    }
    print("PASS: native service selection rejects explicit wrong providers, read errors, missing ownership and changed primary bindings")
}
