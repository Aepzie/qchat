#!/bin/sh
# Reload systemd after the unit file is gone. The qchat user, the server
# identity in /etc/qchat and the database in /var/lib/qchat are kept: they
# hold the key clients are pinned to and every registered identity. Delete
# them by hand when they are no longer needed.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
