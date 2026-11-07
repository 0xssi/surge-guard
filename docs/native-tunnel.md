# Native tunnel ownership

This local repository starts from upstream `51c5b19e8bed8800510742ef74443cfdb895d742`.
It adds a kernel ownership backend for a primary tunnel that has no
SystemConfiguration Setup VPN dictionary. It does not use an older installed
binary, a VPN display name, an observed VPN status number or a VIF address as
provider identity.

## Provider and connection evidence

An existing Setup VPN dictionary keeps the upstream path: its exact official
provider identifier and a connected `SCNetworkConnection` are required. A present
empty/wrong dictionary cannot select another backend. Read/type errors throw;
only an explicit missing key can select kernel attribution.

The kernel backend requires exactly one native process candidate with the
official Network Extension code identifier and developer signature. Native PID
birth identity is checked before and after attribution, and the candidate set
is checked again after signature validation and socket inspection.

Bounded `proc_pidinfo` / `proc_pidfdinfo` queries inspect that process's socket
descriptors. A match requires an AF_SYSTEM / SYSPROTO_CONTROL socket belonging
to `com.apple.net.utun_control`, a usable connected socket state and a nonzero
controller/unit/socket identity. The current primary interface must equal the
interface assigned by the kernel control unit. The final FD and opaque socket
identity are re-read to reject FD reuse; ambiguous or incomplete observations
cannot permit readiness.

This follows the SDK's `sys/proc_info.h` definitions and XNU's assignment of
the utun interface number from `sc_unit - 1` in `utun_ctl_connect`:
[Apple XNU source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c),
[native process/socket structures](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h).
No kernel socket is opened, connected, duplicated or modified by this probe.

The primary service/interface is rechecked after attribution. The main Surge
signature, actual VIF address/up state, default route, IPv6 safety and configured
URL routing conditions remain independently required. Ownership is evidence
about the local packet tunnel, not remote endpoint health or packet coverage.

## Events and privilege

Configured services retain the upstream SCNetworkConnection subscription. The
kernel backend watches the verified provider's exit with a PID/birth-bound
generation, observes native service/interface/Setup changes, and checks the
connected socket again on the existing 0.5-second fallback. Replacing a socket,
provider or backend invalidates route evidence and passes through blocking.
Obsolete callbacks cannot act as the current provider's callback.

There is no subscription to another process's individual FD. FD closure may
therefore be detected by a network event or the fallback poll. These paths do
not promise a fixed packet-block latency. Read errors continue to fail closed.

On the target system, inspecting the root-owned NE's descriptors requires
administrator access. The system daemon already has this privilege; no new
privileged service or control socket is added. Use the installed administrator
read-only `doctor` for a fresh complete condition probe. Unprivileged `check`
must report the access limitation rather than borrow a cached green result.
The ordinary menu/Gate still consume fresh root-published verified status.

## Validation scope

Unit checks cover socket/controller/state selection and fail-closed backend
selection. Target-machine read-only verification is recorded separately in
`verification.md`. Actual provider loss, socket closure, network changes,
sleep/wake, boot ordering and packet-level enforcement require separate live
acceptance. No system preference or PF permission is relaxed by this backend.
