import Foundation

public struct Readiness: Codable, Equatable {
    public var trustedProcess: Bool
    public var surgeService: Bool
    public var connected: Bool
    public var vifUp: Bool
    public var ownsDefaultRoute: Bool
    public var ipv6Safe: Bool

    public init(trustedProcess: Bool, surgeService: Bool, connected: Bool,
                vifUp: Bool, ownsDefaultRoute: Bool, ipv6Safe: Bool) {
        self.trustedProcess = trustedProcess
        self.surgeService = surgeService
        self.connected = connected
        self.vifUp = vifUp
        self.ownsDefaultRoute = ownsDefaultRoute
        self.ipv6Safe = ipv6Safe
    }

    public var ready: Bool {
        trustedProcess && surgeService && connected && vifUp && ownsDefaultRoute && ipv6Safe
    }

    public var reasons: [String] {
        [(trustedProcess, "signed Surge process missing"),
         (surgeService, "primary network service is not Surge"),
         (connected, "Surge network extension is not connected"),
         (vifUp, "Surge VIF is not up with its expected IPv4 address"),
         (ownsDefaultRoute, "Surge does not own the IPv4 default route"),
         (ipv6Safe, "the global IPv6 route is not owned by Surge")]
            .filter { !$0.0 }.map { $0.1 }
    }
}

public enum Policy {
    public static let anchor = "io.github.surge-guard"
    public static let anchorPath = "/etc/pf.anchors/" + anchor
    public static let begin = "# BEGIN surge-guard (managed)"
    public static let end = "# END surge-guard (managed)"
    public static let attachment = "anchor \"\(anchor)\""
    public static let configBlock = """
    \(begin)
    \(attachment)
    load anchor "\(anchor)" from "\(anchorPath)"
    \(end)

    """

    // Only local link configuration is exempt. No DNS, APNs, VPN endpoint,
    // captive-portal, general LAN, or general ICMP exception is granted.
    public static let blocked = """
    pass out on ! lo0 inet proto udp from any port 68 to 255.255.255.255 port 67 tag SG_LINK no state
    pass out on ! lo0 inet proto udp from (self) port 68 to any port 67 user root tag SG_LINK no state
    pass in on ! lo0 inet proto udp from any port 67 to any port 68 tag SG_LINK no state
    pass out on ! lo0 inet6 proto udp from fe80::/10 port 546 to ff02::1:2 port 547 tag SG_LINK no state
    pass in on ! lo0 inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546 tag SG_LINK no state
    pass out on ! lo0 inet6 proto icmp6 from fe80::/10 to ff02::2 icmp6-type 133 code 0 tag SG_LINK no state
    pass in on ! lo0 inet6 proto icmp6 from fe80::/10 to any icmp6-type 134 code 0 tag SG_LINK no state
    pass out on ! lo0 inet6 proto icmp6 from { ::/128, fe80::/10 } to ff02::1:ff00:0/104 icmp6-type 135 code 0 tag SG_LINK no state
    pass out on ! lo0 inet6 proto icmp6 from fe80::/10 to fe80::/10 icmp6-type 135 code 0 tag SG_LINK no state
    pass out on ! lo0 inet6 proto icmp6 from fe80::/10 to fe80::/10 icmp6-type 136 code 0 tag SG_LINK no state
    pass out on ! lo0 inet6 proto icmp6 from fe80::/10 to ff02::1 icmp6-type 136 code 0 tag SG_LINK no state
    pass in on ! lo0 inet6 proto icmp6 from { ::/128, fe80::/10 } to any icmp6-type 135 code 0 tag SG_LINK no state
    pass in on ! lo0 inet6 proto icmp6 from fe80::/10 to any icmp6-type 136 code 0 tag SG_LINK no state
    block drop quick on ! lo0 all ! tagged SG_LINK label "surge-guard-block"

    """

    public static func blockedRules(lanTCPBindings: [LANTCPBinding] = [], usbTCPBindings: [USBTCPBinding] = []) throws -> String {
        try LANTCP.rules(bindings: lanTCPBindings) + USBTCP.rules(bindings: usbTCPBindings) + blocked
    }

    public static func persistentTCP(group: UInt32, interface: String, lanTCPBindings: [LANTCPBinding] = [], usbTCPBindings: [USBTCPBinding] = []) throws -> String {
        guard (60_000...60_999).contains(group), interface.hasPrefix("utun"),
              interface.count > 4, interface.count < 16,
              interface.dropFirst(4).allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw GuardError("Invalid dedicated egress group or verified Surge interface")
        }
        // Bind VIF states to that interface; they must not authorize physical egress after route changes.
        return try LANTCP.rules(bindings: lanTCPBindings) + USBTCP.rules(bindings: usbTCPBindings) + """
        pass out quick on \(interface) inet proto tcp from 198.18.0.1 to any keep state (if-bound) label "surge-guard-vif"
        pass out quick on ! lo0 proto tcp all group \(group) keep state (if-bound) label "surge-guard-egress"
        block drop quick on ! lo0 proto tcp all label "surge-guard-tcp-block"

        """
    }

    public static func removingAttachment(from config: String) throws -> String {
        let lines = config.components(separatedBy: "\n")
        let begins = lines.indices.filter { lines[$0] == begin }
        let ends = lines.indices.filter { lines[$0] == end }
        if begins.isEmpty && ends.isEmpty { return config }
        guard begins.count == 1, ends.count == 1, begins[0] < ends[0] else {
            throw GuardError("Malformed surge-guard markers in pf.conf; refusing to edit")
        }
        let start = begins[0], finish = ends[0]
        // Do not delete user edits inserted between our markers.
        guard lines[start...finish].joined(separator: "\n") + "\n" == configBlock else {
            throw GuardError("Managed PF attachment was edited; refusing to overwrite it")
        }
        return (Array(lines[..<start]) + Array(lines[(finish + 1)...])).joined(separator: "\n")
    }

    public static func attaching(to config: String) throws -> String {
        let base = try removingAttachment(from: config)
        guard !base.contains(anchor) else {
            throw GuardError("Unmanaged surge-guard reference already exists in pf.conf")
        }
        // Restrict automatic installation to a recognizable Apple filter anchor.
        // Live rule ordering is checked separately before allowing any traffic.
        let lines = base.components(separatedBy: "\n")
        let positions = lines.indices.filter { lines[$0].trimmingCharacters(in: .whitespaces) == "anchor \"com.apple/*\"" }
        guard positions.count == 1 else {
            throw GuardError("Expected one Apple filter anchor; custom pf.conf needs manual integration")
        }
        var result = lines
        result.insert(configBlock.trimmingCharacters(in: .newlines), at: positions[0])
        return result.joined(separator: "\n")
    }

    public static func attachedFirst(_ rules: String) -> Bool {
        // macOS -sr also lists normalization rules. They are not packet-filter
        // allow/block rules and may correctly precede our filter anchor.
        let lines = rules.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = lines.first(where: {
            !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix("scrub-anchor ") && !$0.hasPrefix("scrub ")
        }) else { return false }
        return first == attachment || first == attachment + " all"
    }

    // Only restore a known default layout; custom rules require an administrator's review.
    public static func restoringDefaultAttachment(_ config: String, liveRules: String) throws -> String {
        func lines(_ text: String) -> [String] {
            text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        }
        let base = try removingAttachment(from: config)
        guard base.utf8.count <= 65_536, !base.contains(anchor), lines(base) == [
            "scrub-anchor \"com.apple/*\"", "nat-anchor \"com.apple/*\"",
            "rdr-anchor \"com.apple/*\"", "dummynet-anchor \"com.apple/*\"",
            "anchor \"com.apple/*\"", "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\""
        ] else { throw GuardError("PF attachment recovery requires an unmodified Apple default rule layout") }
        let live = lines(liveRules)
        let apple = "anchor \"com.apple/*\" all"
        let filters = live.first == "scrub-anchor \"com.apple/*\" all fragment reassemble" ? Array(live.dropFirst()) : live
        guard live.isEmpty || filters == [apple] || filters == [attachment + " all", apple] else {
            throw GuardError("PF attachment recovery refused unfamiliar live rules; review PF ordering")
        }
        return try attaching(to: config)
    }

    // Filter-only loading preserves NAT, options and existing Apple/third-party anchor contents.
    public static var restoredDefaultFilters: String {
        "scrub-anchor \"com.apple/*\"\n" + attachment + " {\n" + blocked + "}\nanchor \"com.apple/*\"\n"
    }

    public static func installationPreview(_ config: String) throws -> String {
        guard config.components(separatedBy: configBlock).count == 2 else {
            throw GuardError("Expected one managed attachment for PF installation preflight")
        }
        // The new anchor file may not exist yet; parse its planned contents inline.
        return config.replacingOccurrences(of: configBlock, with: attachment + " {\n" + blocked + "}\n")
    }

    public static func defaultInterface(_ output: String) -> String? {
        output.split(separator: "\n").compactMap { line -> String? in
            let fields = line.split(whereSeparator: { $0.isWhitespace })
            return fields.count == 2 && fields[0] == "interface:" ? String(fields[1]) : nil
        }.first
    }

    public static func ipv6Safe(primaryInterface: String?, surgeInterface: String) -> Bool {
        primaryInterface == nil || (!surgeInterface.isEmpty && primaryInterface == surgeInterface)
    }
}

public struct GuardError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}
