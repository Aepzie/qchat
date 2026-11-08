#!/bin/sh
# Make systemd see the new or updated unit. The service is not enabled
# automatically, because it cannot start before "qchat-server init" has
# created the identity. A running server is restarted on upgrade.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl is-active --quiet qchat-server.service; then
        systemctl restart qchat-server.service || true
    fi
fi

if [ ! -f /etc/qchat/server.toml ]; then
    cat <<'MSG'
qchat-server is installed. As root, create the server identity, give the
qchat user access to it, then start the service:

  qchat-server init --data-dir /etc/qchat \
      --database /var/lib/qchat/qchat.db --host chat.example.org
  chown root:qchat /etc/qchat/server.toml /etc/qchat/server.crt
  chmod 0640 /etc/qchat/server.toml /etc/qchat/server.crt
  chown qchat:qchat /etc/qchat/server.key
  chown -R qchat:qchat /var/lib/qchat
  systemctl enable --now qchat-server

init warns that /etc/qchat is accessible to other users: that is the qchat
group, as intended. See /usr/share/doc/qchat-server/README.systemd.md.
MSG
fi
exit 0
