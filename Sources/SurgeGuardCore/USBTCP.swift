import Darwin
import Foundation
import IOKit

public struct USBTCPBinding: Codable, Equatable, Hashable {
    public let interface: String
    public let address: String

    public init(interface: String, address: String) {
        self.interface = interface
        self.address = address
    }
}

public enum USBTCP {
    public static func interfaces() throws -> Set<String> {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AppleUSBNCMData"), &iterator) == KERN_SUCCESS else {
            throw GuardError("Cannot enumerate USB NCM interfaces")
        }
        // IOKit returns a null iterator on success when no services match.
        guard iterator != 0 else { return [] }
        defer { IOObjectRelease(iterator) }
        var names = Set<String>()
        while case let device = IOIteratorNext(iterator), device != 0 {
            defer { IOObjectRelease(device) }
            guard let vendor = IORegistryEntrySearchCFProperty(device, kIOServicePlane, "idVendor" as CFString,
                                                               nil, IOOptionBits(kIORegistryIterateRecursively | kIORegistryIterateParents)) as? NSNumber else {
                throw GuardError("Cannot identify USB NCM vendor")
            }
            guard vendor.intValue == 0x05ac else { continue }
            var children: io_iterator_t = 0
            guard IORegistryEntryGetChildIterator(device, kIOServicePlane, &children) == KERN_SUCCESS else {
                throw GuardError("Cannot enumerate Apple USB NCM network interfaces")
            }
            defer { IOObjectRelease(children) }
            while case let child = IOIteratorNext(children), child != 0 {
                defer { IOObjectRelease(child) }
                guard IOObjectConformsTo(child, "IOEthernetInterface") != 0 else { continue }
                guard let name = IORegistryEntryCreateCFProperty(child, "BSD Name" as CFString, nil, 0)?.takeRetainedValue() as? String,
                      name.hasPrefix("en"), validInterface(name) else { throw GuardError("Invalid Apple USB NCM interface name") }
                names.insert(name)
                guard names.count <= 64 else { throw GuardError("Too many Apple USB NCM interfaces") }
            }
            guard IOIteratorIsValid(children) != 0 else { throw GuardError("USB NCM interfaces changed during enumeration") }
        }
        guard IOIteratorIsValid(iterator) != 0 else { throw GuardError("USB NCM devices changed during enumeration") }
        return names
    }

    private static func validInterface(_ name: String) -> Bool {
        let prefix = name.hasPrefix("utun") ? 4 : 2
        return (name.hasPrefix("en") || name.hasPrefix("utun")) && name.count > prefix && name.count < 16 &&
            name.dropFirst(prefix).allSatisfy { $0.isASCII && $0.isNumber }
    }

    private static func ipv6(_ address: String) -> in6_addr? {
        var value = in6_addr()
        guard address.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) || $0 == 58 }),
              inet_pton(AF_INET6, address, &value) == 1 else { return nil }
        return value
    }

    public static func linkLocalIPv6(_ address: String) -> Bool {
        guard let value = ipv6(address) else { return false }
        let bytes = withUnsafeBytes(of: value) { Array($0) }
        return bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
    }

    public static func tunnelNetwork(_ address: String) -> String? {
        guard var value = ipv6(address), withUnsafeBytes(of: value, { $0[0] & 0xfe == 0xfc }) else { return nil }
        withUnsafeMutableBytes(of: &value) { bytes in
            for index in 8..<16 { bytes[index] = 0 }
        }
        var host = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &value, &host, socklen_t(host.count)) != nil else { return nil }
        return String(cString: host) + "/64"
    }

    public static func tunnelInterfaces(_ output: String) throws -> Set<String> {
        guard output.utf8.count <= 1_048_576, output.hasPrefix("Local device\n") else {
            throw GuardError("Invalid CoreDevice interface inventory")
        }
        var tunnel = false
        var names = Set<String>()
        for line in output.components(separatedBy: "\n") {
            if line.hasPrefix("Found ") {
                tunnel = line.range(of: "^Found coredevice-[0-9]+ \\(coredevice-device\\)$", options: .regularExpression) != nil
            }
            if tunnel, line.hasPrefix("\t\tInterfaceName => ") {
                let name = String(line.dropFirst("\t\tInterfaceName => ".count))
                guard name.hasPrefix("utun"), validInterface(name), names.insert(name).inserted, names.count <= 64 else {
                    throw GuardError("Invalid or ambiguous CoreDevice tunnel interface")
                }
            }
        }
        return names
    }

    public static func bindings(addresses: [InterfaceAddress]) throws -> [USBTCPBinding] {
        var names = try interfaces()
        if !names.isEmpty, addresses.contains(where: { $0.up && $0.name.hasPrefix("utun") && tunnelNetwork($0.address) != nil }) {
            // shortcut: remotectl diagnostic format; replace this parser if Apple changes its CoreDevice inventory.
            let output = try Command.checked("/usr/libexec/remotectl", ["dumpstate"], timeout: 2)
            names.formUnion(try tunnelInterfaces(output))
        }
        return try bindings(addresses: addresses, interfaces: names)
    }

    public static func bindings(addresses: [InterfaceAddress], interfaces: Set<String>) throws -> [USBTCPBinding] {
        guard interfaces.count <= 64, interfaces.allSatisfy(validInterface) else { throw GuardError("Invalid USB NCM interface inventory") }
        let bindings = Set(addresses.filter { $0.up && !$0.loopback && interfaces.contains($0.name) &&
            ($0.name.hasPrefix("utun") ? tunnelNetwork($0.address) != nil : linkLocalIPv6($0.address)) }
            .map { USBTCPBinding(interface: $0.name, address: $0.address) })
            .sorted { ($0.interface, $0.address) < ($1.interface, $1.address) }
        _ = try rules(bindings: bindings)
        return bindings
    }

    public static func rules(bindings: [USBTCPBinding]) throws -> String {
        guard bindings.count <= 64, Set(bindings).count == bindings.count,
              bindings.allSatisfy({ validInterface($0.interface) &&
                  ($0.interface.hasPrefix("utun") ? tunnelNetwork($0.address) != nil : linkLocalIPv6($0.address)) }) else {
            throw GuardError("Device TCP rules require unique local IPv6 addresses on Apple USB NCM or CoreDevice interfaces")
        }
        return bindings.flatMap { binding in
            let peer = binding.interface.hasPrefix("utun") ? tunnelNetwork(binding.address)! : "fe80::/10"
            return ["pass in quick on \(binding.interface) inet6 proto tcp from \(peer) to \(binding.address) flags S/SA keep state (if-bound) label \"surge-guard-usb-in\"",
                    "pass out quick on \(binding.interface) inet6 proto tcp from \(binding.address) to \(peer) flags S/SA keep state (if-bound) label \"surge-guard-usb-out\""]
        }.map { $0 + "\n" }.joined()
    }
}
