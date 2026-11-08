# Running qchat-server as a Tor onion service

`qchat-server` has no code dependency on Tor. To offer it as an onion
service, run the tor daemon next to it and let tor forward the onion
service's port to the server, which listens on the loopback interface only.
Clients then connect with `qchat --tor`.

What this gives you:

- Clients do not reveal their IP address to the relay or to anyone watching
  the relay's network. Every connection arrives from `127.0.0.1`.
- The relay's own IP address and location are hidden from clients and from
  the network, as long as it is not also reachable directly (see step 3).
- No DNS: the onion address is resolved inside Tor, never by a DNS server.

What it does not change: TLS with key pinning still runs end to end on top
of Tor (see [TLS pinning on top of Tor](#tls-pinning-on-top-of-tor)), and
the end-to-end encryption of messages is the same as without Tor.

The commands below assume the systemd setup from
[../systemd/README.md](../systemd/README.md) on Debian or Ubuntu; adapt
paths for other systems. All commands run as root.

## 1. Install tor and create the onion service

```sh
apt install tor
```

Add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/qchat/
HiddenServicePort 7443 127.0.0.1:7443
```

`HiddenServicePort 7443 127.0.0.1:7443` publishes virtual port 7443 of the
onion service and forwards it to `127.0.0.1:7443`, where `qchat-server`
listens. Onion services are version 3 by default; do not enable
`HiddenServiceSingleHopMode` or `HiddenServiceNonAnonymousMode`, which give
up the relay's location for lower latency.

```sh
systemctl restart tor
cat /var/lib/tor/qchat/hostname
```

The `hostname` file holds the onion address: 56 base32 characters followed
by `.onion`. The service's private key `hs_ed25519_secret_key` lives in the
same directory. Back it up as carefully as the server key: if it is lost,
the onion address changes and every client has to be told the new one; if
it is stolen, someone else can publish the same address (clients still
refuse that impostor, because its TLS key does not match their pin).

## 2. Create the server identity for the onion address

For a new server, pass the onion address as `--host` and bind the listener
to the loopback interface:

```sh
runuser -u qchat -- /usr/local/bin/qchat-server init \
  --data-dir /etc/qchat --database /var/lib/qchat/qchat.db \
  --host <onion>.onion --listen 127.0.0.1:7443
```

`init` prints the fingerprint and the command clients use; they add `--tor`
(step 5). The certificate
name is informational only: clients authenticate the server by its pinned
key, never by host name, so an existing server can be moved behind Tor
without a new identity and without changing its fingerprint. In that case
only change the listen address (step 3).

## 3. Listen on localhost only

`/etc/qchat/server.toml` must contain

```toml
listen = '127.0.0.1:7443'
```

The default `0.0.0.0:7443` would also accept connections from the internet,
which makes the relay reachable, and its IP address discoverable, without
Tor. With a loopback address only tor can reach the server. Do not open
port 7443 in the firewall (skip step 5 of the systemd guide), and check
after starting:

```sh
systemctl restart qchat-server
ss -ltn 'sport = :7443'
```

The only listener must be `127.0.0.1:7443`. If you deliberately want to
serve both directly and over Tor, keep a public listen address instead; the
relay is then not hidden, but clients who use Tor still hide theirs.

## 4. Adjust the per-address connection limit

Behind an onion service every connection comes from `127.0.0.1`, so the
per-address limit `limits.max_connections_per_ip` (default 16) would cap
the number of connected clients for the whole server. Set it to the same
value as `limits.max_connections` in `/etc/qchat/server.toml`:

```toml
[limits]
max_connections = 1000
max_connections_per_ip = 1000
# Shared by all onion clients: size them for all users together.
sealed_recipients_per_minute_per_ip = 120000
anonymous_lookups_per_hour_per_ip = 24000
```

The sealed-sender budgets per address also become global limits. Only
sealed entries and anonymous lookups whose access proof the relay accepts
spend them; refused ones spend only their own connection's refusal budget,
so clients without valid access keys cannot exhaust them for everybody.
Clients holding a valid key still can, up to the per-connection limits per
connection, which is why the tor-side defences below matter:

```
HiddenServicePoWDefensesEnabled 1
HiddenServiceMaxStreams 64
HiddenServiceMaxStreamsCloseCircuit 1
```

Put these lines into the same `torrc` section as `HiddenServiceDir`
(`HiddenServicePoWDefensesEnabled` needs Tor 0.4.8 or later).

`limits.max_connections` and `limits.max_pending_handshakes` still bound the
server's resources. Against denial of service from the Tor side, tor itself
offers `HiddenServiceMaxStreams`, `HiddenServiceMaxStreamsCloseCircuit` and,
in recent versions, `HiddenServicePoWDefensesEnabled 1` in the same torrc
section.

## 5. Connect clients

Clients need a running Tor client (the tor daemon, SOCKS port
`127.0.0.1:9050`, or Tor Browser, SOCKS port `127.0.0.1:9150`):

```sh
qchat --tor --server <onion>.onion:7443 --pin sha256:<fingerprint>
qchat --socks5 127.0.0.1:9150 --server <onion>.onion:7443 --pin sha256:<fingerprint>
```

With `--tor` or `--socks5` the client connects only through the proxy and
never falls back to a direct connection; the status bar shows `Tor: on`.
The server name is passed to the proxy unresolved, and each run uses a
fresh SOCKS user name so that Tor keeps qchat on circuits of its own. The
first connection to an onion service can take tens of seconds while Tor
builds the circuits; the client retries on its own.

## TLS pinning on top of Tor

The onion address already authenticates the onion service's key, and Tor
encrypts the connection end to end to it. qchat keeps its own TLS 1.3
connection with X25519MLKEM768 and SPKI pinning inside the Tor stream
anyway:

- Pinning does not depend on the onion service key. A leaked or copied
  `hs_ed25519_secret_key` lets an attacker publish the address, but not
  impersonate the relay: clients refuse any server whose TLS key does not
  match their pin.
- Tor's onion service encryption is classical. The inner TLS layer adds the
  post-quantum hybrid key exchange against "harvest now, decrypt later"
  attackers.
- The same pin works with and without Tor, so moving a server behind Tor,
  or offering both, needs no change on the clients except the address.
