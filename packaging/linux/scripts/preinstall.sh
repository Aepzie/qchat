#!/bin/sh
# Create the unprivileged system user and group that run qchat-server, and
# the directories for the identity and the database. An existing user and
# existing directories are left alone, so upgrades keep their data.
set -e

if ! getent group qchat >/dev/null 2>&1; then
    groupadd --system qchat
fi
if ! getent passwd qchat >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --gid qchat --no-create-home \
        --home-dir /var/lib/qchat --shell "$nologin" \
        --comment "qchat relay server" qchat
fi

for dir in /etc/qchat /var/lib/qchat; do
    if [ ! -d "$dir" ]; then
        install -d -o qchat -g qchat -m 0700 "$dir"
    fi
done
exit 0
