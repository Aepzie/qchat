#!/bin/sh
# Create the unprivileged system user and group that run qchat-server and
# the configuration directory, or check existing ones. Existing directories
# and files are never changed, so upgrades keep their data; lax permissions
# only produce a warning.
#
# Intended layout (packaging/README.md, "Linux packages"):
#
#   /etc/qchat               root:qchat   0750  read-only for the server
#   /etc/qchat/server.toml   root:qchat   0640
#   /etc/qchat/server.crt    root:qchat   0640
#   /etc/qchat/server.key    qchat:qchat  0600  only the server reads it
#   /var/lib/qchat           qchat:qchat  0700  database (StateDirectory)
#
# /var/lib/qchat is not created here: "qchat-server init", run as root,
# creates it together with the database, and systemd creates it for the
# unit's StateDirectory= otherwise.
set -e

warn() {
    echo "qchat-server: warning: $*" >&2
}

fail() {
    echo "qchat-server: error: $*" >&2
    exit 1
}

# mode_allows MODE MASK: whether the octal permission MODE has any bit of
# the octal MASK set.
mode_allows() {
    [ $((0$1 & 0$2)) -ne 0 ]
}

sys_uid_max=999
if [ -r /etc/login.defs ]; then
    value=$(awk '$1 == "SYS_UID_MAX" { print $2; exit }' /etc/login.defs)
    case "$value" in
        '' | *[!0-9]*) ;;
        *) sys_uid_max=$value ;;
    esac
fi

if ! getent group qchat >/dev/null 2>&1; then
    groupadd --system qchat
fi

if entry=$(getent passwd qchat); then
    uid=$(printf '%s\n' "$entry" | cut -d: -f3)
    shell=$(printf '%s\n' "$entry" | cut -d: -f7)
    case "$uid" in
        '' | *[!0-9]*) fail "cannot read the UID of the existing user qchat" ;;
    esac
    if [ "$uid" -eq 0 ] || [ "$uid" -gt "$sys_uid_max" ]; then
        fail "a user named qchat already exists with UID $uid, which is not a system account (1-$sys_uid_max). qchat-server would run as that user and could read its files. Rename or remove that user, or create the system user yourself (useradd --system --shell /usr/sbin/nologin qchat), then install again."
    fi
    case "$shell" in
        */nologin | */false) ;;
        *) fail "the existing user qchat has the login shell '$shell'. The service account must not be able to log in; run 'usermod --shell /usr/sbin/nologin qchat' if that account is meant for qchat-server, then install again." ;;
    esac
else
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --gid qchat --no-create-home \
        --home-dir /var/lib/qchat --shell "$nologin" \
        --comment "qchat relay server" qchat
fi

# check_path PATH OWNERS FORBIDDEN: warn if PATH exists and is owned by none
# of the space-separated user:group pairs in OWNERS, or its mode has any of
# the octal FORBIDDEN bits set.
check_path() {
    [ -e "$1" ] || return 0
    owner=$(stat -c '%U:%G' "$1")
    mode=$(stat -c '%a' "$1")
    case " $2 " in
        *" $owner "*) ;;
        *) warn "$1 is owned by $owner; expected one of: $2" ;;
    esac
    if mode_allows "$mode" "$3"; then
        warn "$1 has mode $mode, which grants more access than intended (the bits $3 should be clear)"
    fi
}

if [ ! -d /etc/qchat ]; then
    install -d -o root -g qchat -m 0750 /etc/qchat
fi
check_path /etc/qchat "root:qchat qchat:qchat root:root" 027
check_path /etc/qchat/server.toml "root:qchat qchat:qchat root:root" 037
check_path /etc/qchat/server.crt "root:qchat qchat:qchat root:root" 033
check_path /etc/qchat/server.key "qchat:qchat" 077
check_path /var/lib/qchat "qchat:qchat" 077
exit 0
