#!/bin/sh
# Stop and disable the service when the package is removed, but not when it
# is upgraded. dpkg passes "remove" or "purge" on removal and "upgrade" on
# upgrade; rpm passes the number of versions left installed, 0 on removal.
set -e

case "$1" in
    remove|purge|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now qchat-server.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
