#!/bin/sh
# <xbar.title>surge-guard</xbar.title>
# <xbar.desc>Surge readiness, routing policy, firewall and application startup.</xbar.desc>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>

user_bin="$HOME/Library/Application Support/SurgeGuard/bin"
if [ -x "$user_bin/surge-guard-ui" ] && "$user_bin/surge-guard-ui" swiftbar "$@"; then exit 0; fi
# Keep an escape hatch even when the privileged binary or renderer is broken.
if [ "${1:-}" != --section ]; then printf '%s\n' '🟠 | size=13' '---'; fi
printf '%s\n' 'surge-guard · 🟠 状态不可用' \
    "-- 应急解除阻断（关闭保护） | bash=\"$user_bin/surge-guard-action\" param1=unlock terminal=true refresh=true" \
    "-- 重启守护并等待验证 | bash=\"$user_bin/surge-guard-action\" param1=restart terminal=true refresh=true" \
    "-- 结束系统更新维护并恢复保护 | bash=\"$user_bin/surge-guard-action\" param1=os-update-end terminal=true refresh=true" \
    "-- 查看最近日志 | bash=\"$user_bin/surge-guard-action\" param1=logs terminal=true"
