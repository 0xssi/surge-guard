import Darwin

public struct LocalTCPInventory {
    public private(set) var lan: [LANTCPBinding] = []
    public private(set) var usb: [USBTCPBinding] = []
    public private(set) var errors: [String] = []

    public init(addresses: () throws -> [InterfaceAddress] = { try Probe.addresses() },
                lan: ([InterfaceAddress]) throws -> [LANTCPBinding] = LANTCP.bindings,
                usb: ([InterfaceAddress]) throws -> [USBTCPBinding] = USBTCP.bindings) {
        let current: [InterfaceAddress]
        do { current = try addresses() }
        catch { errors = ["interface_inventory_failed: \(error)"]; return }
        do { self.lan = try lan(current) }
        catch { errors.append("lan_tcp_inventory_failed: \(error)") }
        do { self.usb = try usb(current) }
        catch { errors.append("usb_tcp_inventory_failed: \(error)") }
    }
}

public struct LANTCPBinding: Codable, Equatable, Hashable {
    public let interface: String
    public let address: String

    public init(interface: String, address: String) {
        self.interface = interface
        self.address = address
    }
}

public enum LANTCP {
    public static let networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    public static func privateIPv4(_ address: String) -> Bool {
        var value = in_addr()
        guard !address.utf8.contains(0), inet_pton(AF_INET, address, &value) == 1 else { return false }
        let host = UInt32(bigEndian: value.s_addr)
        // Darwin accepts leading zeroes; PF must see the same unambiguous decimal address.
        guard address == [24, 16, 8, 0].map({ String((host >> $0) & 255) }).joined(separator: ".") else { return false }
        return host & 0xff00_0000 == 0x0a00_0000 || host & 0xfff0_0000 == 0xac10_0000 || host & 0xffff_0000 == 0xc0a8_0000
    }

    private static func ethernetInterface(_ name: String) -> Bool {
        name.hasPrefix("en") && name.count > 2 && name.count < 16 &&
            name.dropFirst(2).allSatisfy { $0.isASCII && $0.isNumber }
    }

    public static func bindings(addresses: [InterfaceAddress]) throws -> [LANTCPBinding] {
        let result = Set(addresses.filter { $0.up && !$0.loopback && ethernetInterface($0.name) && privateIPv4($0.address) }
            .map { LANTCPBinding(interface: $0.name, address: $0.address) })
            .sorted { ($0.interface, $0.address) < ($1.interface, $1.address) }
        guard result.count <= 64 else { throw GuardError("Too many LAN TCP interface addresses") }
        return result
    }

    public static func rules(bindings: [LANTCPBinding]) throws -> String {
        guard bindings.count <= 64, Set(bindings).count == bindings.count,
              bindings.allSatisfy({ ethernetInterface($0.interface) && privateIPv4($0.address) }) else {
            throw GuardError("LAN TCP rules require unique private IPv4 addresses on Ethernet/Wi-Fi en interfaces")
        }
        return bindings.flatMap { binding in
            networks.flatMap { network in
                ["pass in quick on \(binding.interface) inet proto tcp from \(network) to \(binding.address) flags S/SA keep state (if-bound) label \"surge-guard-lan-in\"",
                 "pass out quick on \(binding.interface) inet proto tcp from \(binding.address) to \(network) flags S/SA keep state (if-bound) label \"surge-guard-lan-out\""]
            }
        }.map { $0 + "\n" }.joined()
    }
}
