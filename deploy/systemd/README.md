# Running qchat-server with systemd

`qchat-server.service` runs the server as the unprivileged user `qchat`
with `ProtectSystem=strict`: the whole file system, `/etc` included, is
read-only for the server except its state directory `/var/lib/qchat`. The
key and configuration live in `/etc/qchat`, so even a compromised server
process cannot alter them. The database of identity bundles and invite code
hashes and undelivered ciphertext must be writable, together with the `-wal` and
`-shm` files SQLite creates next to it, so it lives in `/var/lib/qchat`.

All commands run as root.

## 1. Install the binary and the unit

```sh
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o qchat-server ./cmd/server
install -m 0755 qchat-server /usr/local/bin/qchat-server
install -m 0644 deploy/systemd/qchat-server.service /etc/systemd/system/qchat-server.service
useradd --system --no-create-home --shell /usr/sbin/nologin qchat
```

## 2. Create the directories

Both directories must be owned by `qchat`, because `init` runs as that user
and refuses directories owned by somebody else:

```sh
install -d -o qchat -g qchat -m 0700 /etc/qchat /var/lib/qchat
```

## 3. Create the identity, configuration and database

```sh
runuser -u qchat -- /usr/local/bin/qchat-server init \
  --data-dir /etc/qchat --database /var/lib/qchat/qchat.db --host chat.example.org
```

`--database /var/lib/qchat/qchat.db` is required here. It writes
`database = '/var/lib/qchat/qchat.db'` into `/etc/qchat/server.toml`; with
the default `db/qchat.db` the database would be below `/etc/qchat`, which
the unit makes read-only, and the server would not start. For a data
directory created without the flag, move `/etc/qchat/db/qchat.db` to
`/var/lib/qchat/qchat.db` (owned by `qchat`, mode 0600) and change the
`database` line accordingly.

`init` prints the fingerprint users must pin; print it again at any time
with `qchat-server fingerprint --config /etc/qchat/server.toml`.

## 4. Start

```sh
systemctl daemon-reload
systemctl enable --now qchat-server
journalctl -u qchat-server
```

Invite codes are created with
`runuser -u qchat -- qchat-server invite create --config /etc/qchat/server.toml`.
The log never contains client IP addresses, identity IDs or message data.
