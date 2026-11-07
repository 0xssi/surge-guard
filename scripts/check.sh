#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
swift run surge-guard-tests
launch_test_dir=$(mktemp -d /tmp/surge-launch-check.XXXXXX)
trap 'rm -rf "$launch_test_dir"' EXIT HUP INT TERM
/usr/bin/clang -Wall -Wextra -Werror -I Sources/SurgeLaunch Tests/SurgeLaunchTests/main.c -o "$launch_test_dir/check"
"$launch_test_dir/check"
swift build -c release -Xswiftc -warnings-as-errors
.build/debug/surge-guard-tests --gate-lock-check "$project_dir/.build/release/surge-gate"
.build/debug/surge-guard-tests --diagnostic-lock-check "$project_dir/.build/release/surge-guard"
if .build/release/surge-guard-launch --invalid; then
    printf '%s\n' 'Dedicated launcher accepted arbitrary arguments' >&2
    exit 1
fi
if .build/release/surge-guard-launch --check; then
    printf '%s\n' 'Uninstalled launcher unexpectedly granted a dedicated group' >&2
    exit 1
fi
.build/release/surge-guard validate examples/enhanced.json
.build/release/surge-guard validate examples/routes.json
.build/release/surge-guard validate examples/persistent-tcp.json
.build/release/surge-guard --help
.build/release/surge-guard install --help
.build/release/surge-guard diagnose --help
if .build/release/surge-guard diagnose --minutes 0 --json; then
    printf '%s\n' 'Diagnostics accepted an invalid history window' >&2
    exit 1
fi
.build/release/surge-gate --help
printf '%s\n' '{"event":"gate_state","app":"","message":"1 application(s) pending"}' | .build/release/surge-guard format-logs | /usr/bin/grep -q '剩余 1 个应用'
sh -n scripts/install-user.sh
sh -n integrations/swiftbar/surge-guard.5s.sh
sh -n integrations/swiftbar/surge-guard-action.sh
/bin/bash integrations/swiftbar/surge-guard-action.sh check-recovery
sh integrations/swiftbar/surge-guard-action.sh --help
git diff --check
