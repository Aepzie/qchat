# Running qchat-server as a Windows service

`qchat-server run` detects when the Windows service control manager started
it and runs as a service. A Stop or Shutdown request triggers the same
graceful shutdown as Ctrl+C in a console: new connections are refused and
open sessions are closed with WebSocket status 1001 (going away) before the
process exits, which takes at most about 15 seconds.

All commands below run in an elevated PowerShell (Run as administrator).

## 1. Install the binary

Build on any machine with Go installed:

```powershell
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o qchat-server.exe ./cmd/server
```

Copy it to a directory only administrators can write to:

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\qchat"
Copy-Item .\qchat-server.exe "C:\Program Files\qchat\qchat-server.exe"
```

## 2. Create the data directory

```powershell
& "C:\Program Files\qchat\qchat-server.exe" init --data-dir C:\ProgramData\qchat --host chat.example.org
```

This writes `server.key` (the private key), `server.crt` and `server.toml`,
and prints the fingerprint users must pin. Keep the data directory outside
any user profile. Running `init` again refuses to overwrite the identity;
`--force` creates a new key, which changes the fingerprint and locks out
every client pinned to the old one.

Before installing the service, run the server once in the foreground to
check the configuration (stop it with Ctrl+C):

```powershell
& "C:\Program Files\qchat\qchat-server.exe" run --config C:\ProgramData\qchat\server.toml
```

## 3. Register the service

Run the service under its own virtual service account
(`NT SERVICE\qchat-server`). Windows manages this account automatically: it
has no password, cannot log on interactively and has no rights beyond what
you grant it, unlike `LocalSystem`.

```powershell
sc.exe --% create qchat-server binPath= "\"C:\Program Files\qchat\qchat-server.exe\" run --config C:\ProgramData\qchat\server.toml" start= auto obj= "NT SERVICE\qchat-server"
sc.exe description qchat-server "qchat relay server"
sc.exe failure qchat-server reset= 86400 actions= restart/5000/restart/5000/restart/60000
sc.exe failureflag qchat-server 1
```

Notes on the `create` line:

- The space after each `name=` is required by `sc.exe`.
- Keep the escaped quotes (`\"`) around the executable path inside
  `binPath=`. Without them Windows splits the unquoted path at the space and
  tries `C:\Program.exe` first, a classic privilege-escalation hole.
- `--%` makes PowerShell pass the rest of the line to `sc.exe` unchanged;
  Windows PowerShell 5.1 otherwise mangles embedded quotes. In `cmd.exe`,
  drop the `--%`.

`failureflag 1` makes the restart actions apply also when the server stops
with an error (for example because the port is in use), not only when the
process crashes.

## 4. Restrict access to the data directory

The private key must be readable by the service and administrators only.
Replace the inherited permissions of the data directory (the virtual account
exists only after step 3):

```powershell
icacls C:\ProgramData\qchat /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\qchat-server:(OI)(CI)RX"
icacls C:\ProgramData\qchat
```

`S-1-5-18` is SYSTEM and `S-1-5-32-544` is the Administrators group; the
SIDs work on every Windows language. The service needs read access only, so
a compromised server process cannot alter its key or configuration. On
Windows, the Unix file modes requested by `init` (0700/0600) are
best-effort, and these ACLs are what actually protects the key.

## 5. Open the firewall and start

```powershell
New-NetFirewallRule -DisplayName "qchat-server" -Direction Inbound -Protocol TCP -LocalPort 7443 -Action Allow -Program "C:\Program Files\qchat\qchat-server.exe"
sc.exe start qchat-server
sc.exe query qchat-server
```

Print the fingerprint again at any time:

```powershell
& "C:\Program Files\qchat\qchat-server.exe" fingerprint --data-dir C:\ProgramData\qchat
```

## Logs

A service has no console, and the server currently writes its log to
standard error only, so log output is discarded while it runs as a service.
Use a foreground run (step 2) to troubleshoot. The log never contains client
IP addresses or message data in either case.

## Updating and removing

```powershell
sc.exe stop qchat-server
Copy-Item .\qchat-server.exe "C:\Program Files\qchat\qchat-server.exe"
sc.exe start qchat-server
```

To remove the service:

```powershell
sc.exe stop qchat-server
sc.exe delete qchat-server
Remove-NetFirewallRule -DisplayName "qchat-server"
```

Delete `C:\ProgramData\qchat` only if you also want to destroy the server
identity; a new one has a different fingerprint.
