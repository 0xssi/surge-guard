import Foundation
import CryptoKit
import Darwin

public struct RouteCheck: Codable, Equatable {
    public var url: String
    public var requiredGroup: String
    public var allowedFinalPolicies: [String]?

    public init(url: String, requiredGroup: String, allowedFinalPolicies: [String]? = nil) {
        self.url = url
        self.requiredGroup = requiredGroup
        self.allowedFinalPolicies = allowedFinalPolicies
    }

    public func allowsFinalPolicy(_ policy: String?) -> Bool {
        guard let policy, !policy.isEmpty,
              !["DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF"].contains(policy.uppercased()) else { return false }
        return allowedFinalPolicies?.contains(policy) ?? true
    }
}

public struct Configuration: Codable, Equatable {
    public var version: Int
    public var mode: String
    public var routeChecks: [RouteCheck]
    public var persistentTCP: Bool?
    public var allowLANTCP: Bool?
    public var usesPersistentTCP: Bool { persistentTCP == true }
    public var allowsLANTCP: Bool { allowLANTCP == true }
    public var enforcement: String { usesPersistentTCP ? "persistent_tcp_egress" : "surge_readiness_gate" }
    enum CodingKeys: String, CodingKey {
        case version, mode, routeChecks
        case persistentTCP = "persistentTcp"
        case allowLANTCP = "allowLanTcp"
    }

    public static let enhanced = Configuration(version: 1, mode: "enhanced", routeChecks: [])

    public init(version: Int, mode: String, routeChecks: [RouteCheck], persistentTCP: Bool? = nil, allowLANTCP: Bool? = nil) {
        self.version = version
        self.mode = mode
        self.routeChecks = routeChecks
        self.persistentTCP = persistentTCP
        self.allowLANTCP = allowLANTCP
    }

    public func validate() throws {
        guard !allowsLANTCP || usesPersistentTCP else { throw GuardError("allow_lan_tcp requires persistent_tcp") }
        guard version == 1, ["enhanced", "routes"].contains(mode), routeChecks.count <= 8 else {
            throw GuardError("Configuration requires version 1, mode enhanced/routes, and at most eight route checks")
        }
        guard (mode == "enhanced" && routeChecks.isEmpty) || (mode == "routes" && !routeChecks.isEmpty) else {
            throw GuardError("enhanced mode requires no route checks; routes mode requires at least one")
        }
        var urls = Set<String>()
        for check in routeChecks {
            guard let url = URLComponents(string: check.url),
                  ["https", "http"].contains(url.scheme), url.host?.isEmpty == false,
                  url.user == nil, url.password == nil, url.fragment == nil,
                  !check.url.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  check.url.count <= 2048, urls.insert(check.url).inserted,
                  validName(check.requiredGroup) else {
                throw GuardError("Each route check needs a unique HTTP(S) URL without credentials or control characters and an exact group")
            }
            if let allowed = check.allowedFinalPolicies {
                guard !allowed.isEmpty, allowed.count <= 128, Set(allowed).count == allowed.count,
                      allowed.allSatisfy({ validName($0) && check.allowsFinalPolicy($0) }) else {
                    throw GuardError("Optional allowed_final_policies must contain unique nonempty proxy names; omit it for group-only matching")
                }
            }
        }
    }

    private func validName(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 512 && value == value.trimmingCharacters(in: .whitespacesAndNewlines) &&
            !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    }

    public static func decode(_ data: Data) throws -> Configuration {
        guard data.count <= 65_536,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: ["version", "mode", "route_checks", "persistent_tcp", "allow_lan_tcp"]),
              Set(object.keys).isSuperset(of: ["version", "mode", "route_checks"]),
              (object["persistent_tcp"] == nil || object["persistent_tcp"] is Bool),
              (object["allow_lan_tcp"] == nil || object["allow_lan_tcp"] is Bool),
              let routes = object["route_checks"] as? [[String: Any]],
              routes.allSatisfy({ route in
                  let keys = Set(route.keys)
                  return (keys == ["url", "required_group"] || keys == ["url", "required_group", "allowed_final_policies"]) &&
                      (route["allowed_final_policies"] == nil || route["allowed_final_policies"] is [String])
              }) else {
            throw GuardError("Invalid or unknown configuration fields")
        }
        let result = try JSON.decode(Configuration.self, from: data)
        try result.validate()
        return result
    }

    public static func load() throws -> Configuration {
        try RootFiles.verify(Paths.configuration)
        return try decode(Data(contentsOf: URL(fileURLWithPath: Paths.configuration)))
    }

    public func encoded() throws -> String {
        var text = try JSON.encode(self, pretty: true)
        if text.utf8.count > 65_536 { text = try JSON.encode(self) }
        _ = try Self.decode(Data(text.utf8))
        return text
    }

    // Only installation may supply a missing policy after creating the state directory.
    public static func forInstallation(path: String = Paths.configuration) throws -> Configuration {
        var info = stat()
        if lstat(path, &info) != 0, errno == ENOENT { return .enhanced }
        try RootFiles.verify(path)
        return try decode(Data(contentsOf: URL(fileURLWithPath: path)))
    }

    public func fingerprint() throws -> String {
        SHA256.hash(data: Data(try JSON.encode(self).utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public enum JSON {
    public static func encode<T: Encodable>(_ value: T, pretty: Bool = false) throws -> String {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = pretty ? [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes] : [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .secondsSince1970
        return try decoder.decode(type, from: data)
    }
}

public struct RouteResult: Codable, Equatable {
    public var url: String
    public var expectedGroup: String
    public var actualGroup: String?
    public var finalPolicy: String?
    public var ready: Bool
    public var reason: String

    public static func evaluate(_ data: Data, check: RouteCheck) throws -> RouteResult {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let group = object["rule-policy"] as? String,
              let final = object["final"] as? String,
              let type = object["final-type"] as? String,
              let steps = object["steps"] as? [[String: Any]],
              !group.isEmpty, !final.isEmpty, !type.isEmpty else {
            throw GuardError("Surge returned an incomplete rule explanation")
        }
        let proxy = ["http", "https", "socks5", "socks5-tls", "ss", "shadowsocks", "snell", "vmess", "trojan",
                     "wireguard", "hysteria2", "tuic", "tuic-v5", "ssh", "tailscale"].contains(type.lowercased())
        var selected = group
        var visited = Set<String>()
        var resolved = !steps.isEmpty && steps.count <= 128
        for step in steps {
            guard let name = step["group"] as? String, name == selected, visited.insert(name).inserted,
                  let next = step["selected"] as? String, !next.isEmpty else { resolved = false; break }
            selected = next
        }
        let groupMatches = group == check.requiredGroup && resolved && selected == final && !visited.contains(final)
        let ready = groupMatches && proxy && check.allowsFinalPolicy(final)
        return RouteResult(url: check.url, expectedGroup: check.requiredGroup, actualGroup: group,
                           finalPolicy: final, ready: ready,
                           reason: ready ? "route_matched" : "route_policy_mismatch")
    }
}

public struct SessionObservation: Codable {
    public var policyFingerprint: String
    public var mode: String
    public var enhancedMode: Bool
    public var routes: [RouteResult]
    public var ready: Bool { mode == "rule" && enhancedMode && !routes.isEmpty && routes.allSatisfy(\.ready) }

    public static func collect(configuration: Configuration, query: ([String]) throws -> String) throws -> SessionObservation {
        try configuration.validate()
        let arguments = [["--raw", "status"]] + configuration.routeChecks.map { ["--raw", "rule", "explain", $0.url] }
        let lock = NSLock()
        var responses = [Result<String, Error>?](repeating: nil, count: arguments.count)
        // Independent CLI reads share one freshness budget rather than accumulating per-URL timeouts.
        DispatchQueue.concurrentPerform(iterations: arguments.count) { index in
            let result = Result { try query(arguments[index]) }
            lock.lock(); responses[index] = result; lock.unlock()
        }
        let status = try responses[0]!.get()
        guard let object = try JSONSerialization.jsonObject(with: Data(status.utf8)) as? [String: Any],
              let mode = object["mode"] as? String,
              let features = object["features"] as? [String: Any],
              let enhanced = features["enhanced-mode"] as? Bool else {
            throw GuardError("Surge returned incomplete mode/feature status")
        }
        var routes: [RouteResult] = []
        for (index, check) in configuration.routeChecks.enumerated() {
            // shortcut: URL default context only; add request overrides when gating process/protocol-specific rules.
            let response = try responses[index + 1]!.get()
            routes.append(try RouteResult.evaluate(Data(response.utf8), check: check))
        }
        return SessionObservation(policyFingerprint: try configuration.fingerprint(), mode: mode, enhancedMode: enhanced, routes: routes)
    }
}
