import Foundation
import SurgeGuardCore

func usbTCPTests() throws {
    try check(try USBTCP.bindings(addresses: []).isEmpty,
              "Native USB inventory must accept no matching devices without creating exceptions")
    let address = "fe80::1234"
    let binding = USBTCPBinding(interface: "en11", address: address)
    for valid in [address, "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"] {
        try check(USBTCP.linkLocalIPv6(valid), "USB link-local boundary rejected")
    }
    for invalid in ["fec0::1", "fe7f::1", "::1", "2001:4860::1", "fd00::1", "192.168.1.1",
                    "fe80::1%en11", "fe80::1/64", "fe80::1\npass all", "fe80::1\0pass all"] {
        try check(!USBTCP.linkLocalIPv6(invalid), "USB exception accepted non-link-local or malformed IPv6: \(invalid)")
    }
    let addresses = [InterfaceAddress(name: "en11", address: address, up: true, loopback: false),
                     InterfaceAddress(name: "en11", address: "2001:4860::1", up: true, loopback: false),
                     InterfaceAddress(name: "en11", address: "169.254.1.1", up: true, loopback: false),
                     InterfaceAddress(name: "en0", address: address, up: true, loopback: false),
                     InterfaceAddress(name: "en12", address: address, up: false, loopback: false),
                     InterfaceAddress(name: "en13", address: address, up: true, loopback: true)]
    try check(try USBTCP.bindings(addresses: addresses + addresses, interfaces: ["en11", "en12", "en13"]) == [binding],
              "USB inventory included Wi-Fi, public, IPv4, down or loopback addresses, or duplicates")
    try check(try USBTCP.bindings(addresses: addresses, interfaces: []) == [], "USB unplug retained an exception")
    for interface in ["en", "utun", "lo0", "en１", "en11\npass all", "en0000000000000000"] {
        try rejects { _ = try USBTCP.bindings(addresses: addresses, interfaces: [interface]) }
        try rejects { _ = try USBTCP.rules(bindings: [USBTCPBinding(interface: interface, address: address)]) }
    }
    try rejects { _ = try USBTCP.rules(bindings: [binding, binding]) }
    try rejects { _ = try USBTCP.rules(bindings: [USBTCPBinding(interface: "en11", address: "2001:4860::1")]) }
    let many = (0..<65).map { USBTCPBinding(interface: "en11", address: "fe80::\(String($0, radix: 16))") }
    try rejects { _ = try USBTCP.rules(bindings: many) }
    let rules = try USBTCP.rules(bindings: [binding])
    try check(rules.split(separator: "\n").count == 2 && rules.contains("from fe80::/10 to \(address)") &&
              rules.contains("from \(address) to fe80::/10") && rules.split(separator: "\n").allSatisfy {
                  $0.contains("quick on en11 inet6 proto tcp") && $0.contains("keep state (if-bound)") && !$0.contains("any")
              }, "USB rules widened interface, protocol, address or state scope")
    try check(try Policy.blockedRules(usbTCPBindings: [binding]) == rules + Policy.blocked &&
              Policy.persistentTCP(group: 60000, interface: "utun42", usbTCPBindings: [binding]) ==
              rules + Policy.persistentTCP(group: 60000, interface: "utun42"), "USB rules displaced existing restrictions")
    try check(try USBTCP.rules(bindings: []).isEmpty, "Empty USB inventory changed default rules")
    let firewall = Firewall(historyPath: nil)
    try check(try firewall.setUSBTCP([binding]) && !firewall.setUSBTCP([binding]) &&
              firewall.setUSBTCP([]) && firewall.usbTCPBindings.isEmpty, "USB interface removal/change was not tracked")
    let snapshot = GuardSnapshot(runId: "usb-test", firewallVerifiedUptime: SystemClock.seconds, allowed: true,
                                 configurationMode: "routes", readiness: nil, session: nil, reasons: [], usbTcpBindings: [binding])
    let json = try JSON.encode(snapshot)
    try check(try JSON.decode(GuardSnapshot.self, from: Data(json.utf8)).usbTcpBindings == [binding] &&
              json.contains("\"usb_tcp_bindings\""), "USB scope missing from status JSON")
    let parsed = try Command.run("/sbin/pfctl", ["-n", "-f", "-"], input: rules + Policy.blocked)
    try check(parsed.status == 0, "macOS rejected USB IPv6 PF syntax: \(parsed.combined)")
    let dump = "Local device\n\tProperties: {\n\t\tInterfaceName => en7\n\t}\n\nFound coredevice-4 (coredevice-device)\n\tState: attached\n\tProperties: {\n\t\tInterfaceName => utun12\n\t}\n\nFound ncm-1 (ncm-device)\n\tProperties: {\n\t\tInterfaceName => en11\n\t}\n"
    try check(try USBTCP.tunnelInterfaces(dump) == ["utun12"], "CoreDevice inventory included another device or interface")
    for invalid in ["", "permission denied", dump.replacingOccurrences(of: "utun12", with: "en7"),
                    dump.replacingOccurrences(of: "utun12", with: "utun12;pass all"),
                    dump + "Found coredevice-5 (coredevice-device)\n\t\tInterfaceName => utun12\n"] {
        try rejects { _ = try USBTCP.tunnelInterfaces(invalid) }
    }
    let tunnel = USBTCPBinding(interface: "utun12", address: "fd12:3456:789a::2")
    let tunnelAddresses = [InterfaceAddress(name: "utun12", address: tunnel.address, up: true, loopback: false),
                           InterfaceAddress(name: "utun12", address: address, up: true, loopback: false),
                           InterfaceAddress(name: "utun12", address: "2001:4860::1", up: true, loopback: false),
                           InterfaceAddress(name: "utun10", address: "fd7a:115c:a1e0::1", up: true, loopback: false)]
    try check(try USBTCP.bindings(addresses: tunnelAddresses, interfaces: USBTCP.tunnelInterfaces(dump)) == [tunnel],
              "CoreDevice exception included another VPN, link-local or global address")
    let tunnelRules = try USBTCP.rules(bindings: [tunnel])
    try check(tunnelRules.contains("from fd12:3456:789a::/64 to \(tunnel.address)") &&
              tunnelRules.contains("from \(tunnel.address) to fd12:3456:789a::/64") && !tunnelRules.contains("fc00::/7"),
              "CoreDevice TCP exception escaped the device's local subnet")
    try check(try Command.run("/sbin/pfctl", ["-n", "-f", "-"], input: tunnelRules + rules + Policy.blocked).status == 0,
              "macOS rejected CoreDevice tunnel PF syntax")
    try rejects { _ = try USBTCP.rules(bindings: [USBTCPBinding(interface: "en11", address: tunnel.address)]) }
    try rejects { _ = try USBTCP.rules(bindings: [USBTCPBinding(interface: "utun12", address: address)]) }
    print("PASS: USB TCP is limited to active Apple NCM link-local IPv6, revokes on unplug, and preserves existing PF rules")
}
