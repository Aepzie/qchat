# Phase 5 design: metadata protection

Status: in progress. Each section below is self-contained.

## Tor

Goal: let a client hide its IP address from the relay and from the network,
and let an operator hide the relay's location, without making Tor a
dependency of either binary. Tor is optional; without it nothing changes.

### Client: SOCKS5 dialer (`internal/transport/socks5.go`)

```go
func SOCKS5Dialer(proxyAddr, isolation string) func(ctx context.Context, network, addr string) (net.Conn, error)
var ErrSOCKS5 error
type SOCKS5ReplyError struct{ Code byte }
```

The returned function plugs into `transport.DialOptions.NetDialContext` and
`client.Options.Dialer`. TLS 1.3 with X25519MLKEM768 and SPKI pinning runs
unchanged on top of the proxied TCP stream. It is a minimal SOCKS5 client
(RFC 1928, CONNECT only) written for qchat, with no new module dependency:

- **No local name resolution.** Host names are sent as `ATYP 0x03` (domain
  name) and resolved by the proxy; only IP literals are sent as addresses.
  No DNS query reveals the server's name, and `.onion` names work.
  `http.Transport` passes the name unresolved to the dial function, and its
  `Proxy` field stays nil, so environment proxies cannot interfere.
- **Stream isolation.** A non-empty `isolation` token is sent as both user
  name and password of RFC 1929 username/password authentication, and only
  that method is offered: a proxy that does not accept it is refused rather
  than used without isolation. Tor's `IsolateSOCKSAuth` (on by default) puts
  streams with different credentials on different circuits. The client
  draws a fresh random 128-bit token per run, so qchat shares no circuit
  with other applications or with earlier runs, while its reconnects within
  one run reuse circuits.
- **Bounded time.** Connecting to the proxy is limited to 30 s and the SOCKS
  handshake to 120 s (onion circuits are slow to build); the caller's
  context cancels either at any time, and context errors are returned as
  such. The deadline is cleared once the tunnel is up. The session's own
  45 s dial timeout and its reconnect back-off apply on top.
- **Strict parsing.** Every reply field is checked: version bytes, the
  selected method (must be the one offered), the RFC 1929 status, the
  reserved byte, the address type and the exact length of the bound address.
  The reply is consumed byte for byte without buffering, so the first byte
  from the server is never lost or misread. Any violation fails the dial
  with an error wrapping `ErrSOCKS5`; failure codes are returned as
  `*SOCKS5ReplyError`, with Tor's onion service codes `0xF0`-`0xF7` named.
  Invalid input (non-TCP network, missing or zero port, empty or over-long
  host, IPv6 zone, token over 255 bytes) fails before any connection.

### Client: flags (`cmd/client`)

- `--tor` uses Tor's default SOCKS port `127.0.0.1:9050`.
- `--socks5 HOST:PORT` uses another proxy, for example Tor Browser at
  `127.0.0.1:9150`, and overrides `--tor`'s address. An explicitly given
  value must pass `transport.ValidateHostPort`, even an empty one.
- With either flag, every connection the client makes (the chat session and
  the profile recovery lookup) is dialed through the proxy. There is no
  fallback: if the proxy is down or refuses, the client does not connect.
- The status bar's `Tor:` segment (`tui.Config.Tor`) shows `on` whenever a
  proxy is configured.
- Locked builds keep their embedded server and pin; the proxy flags still
  apply.
- `transport.ValidateHostPort` already accepts v3 onion host names (56
  base32 characters plus `.onion`); tests cover them, and
  `qchat-server init --host <onion>.onion` accepts them for the certificate.

### Server: onion service

The server has no Tor code. The operator runs tor with
`HiddenServiceDir` / `HiddenServicePort 7443 127.0.0.1:7443` and binds
`qchat-server` to `127.0.0.1:7443` so that it is not also reachable
directly. Because all onion connections arrive from `127.0.0.1`,
`limits.max_connections_per_ip` must be raised to `limits.max_connections`.
Step-by-step instructions are in
[deploy/tor/README.md](../../deploy/tor/README.md).

### Security notes

- TLS pinning stays mandatory over Tor. A stolen onion service key lets an
  attacker publish the onion address but not pass the client's pin check,
  and the inner TLS adds a post-quantum key exchange that Tor's onion
  service protocol lacks.
- Tor hides network addresses, not identities: the relay still sees which
  identity authenticates and, for queued messages, the sender and recipient
  IDs. Sealed sender and padding address those separately.
- The proxy sees only the destination name and port and an opaque TLS
  stream. A non-Tor SOCKS5 proxy given with `--socks5` learns the server
  name and the client's address; the status bar still says `Tor: on`, since
  the client cannot tell what the proxy is.
- Timing correlation by an adversary who watches both the client's and the
  relay's network is outside Tor's threat model and outside this phase.
