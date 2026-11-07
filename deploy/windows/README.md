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

## 2. Register the service

Register the service before creating the data directory: `init` grants the
service account read access, and that account exists only once the service
is registered. Do not start the service yet.

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

## 3. Create the data directory

```powershell
& "C:\Program Files\qchat\qchat-server.exe" init --data-dir C:\ProgramData\qchat --host chat.example.org --service-account "NT SERVICE\qchat-server"
```

This writes `server.key` (the private key), `server.crt` and `server.toml`,
creates the database `db\qchat.db` (registered identity bundles and invite
code hashes, never messages), and prints the fingerprint users must pin. Keep the data directory outside
any user profile. Running `init` again refuses to overwrite the identity;
`--force` creates a new key, which changes the fingerprint and locks out
every client pinned to the old one.

`init` creates the directory and every file in it with an explicit access
control list that does not inherit from `C:\ProgramData` (which lets every
local user read new subdirectories):

- SYSTEM, the Administrators group and the owner of each object (the
  Administrators group when `init` runs elevated) have full control;
- `NT SERVICE\qchat-server` may read, but not change, the key and
  configuration, so a compromised server process cannot alter them;
- `NT SERVICE\qchat-server` may modify (read, write, create and delete
  files, but not change permissions in) the `db` subdirectory, inherited by
  every file in it: SQLite writes `qchat.db` and creates and deletes
  `qchat.db-wal` and `qchat.db-shm` next to it while the server runs;
- nobody else has access.

This is why the database lives in a directory of its own: the service needs
write access to the database directory, never to the directory holding the
key. `--database PATH` puts it elsewhere (a relative path resolves against
the data directory); with `--service-account` it must not be directly in the
data directory.

The files are created with this ACL, so at no point can other users read the
key. `--service-account` also accepts a SID (`S-1-5-...`), which avoids
localized account names on non-English Windows. On Windows, the Unix file
modes 0700/0600 are meaningless; the ACL is what protects the key.

`init` refuses to use a data directory that already exists unless it is owned
by SYSTEM, Administrators or the account running `init`, and grants no access
to Everyone, Authenticated Users, INTERACTIVE or Users. Any local user can
create a directory under `C:\ProgramData`; if such a pre-created directory
were used, its owner could change its permissions later and read or replace
the key. If `init` refuses, delete the directory (after checking who created
it and why) and run `init` again. Junctions and symbolic links are refused
as well.

## 4. Verify the permissions and test the configuration

Check that the ACL looks as described above:

```powershell
icacls C:\ProgramData\qchat
icacls C:\ProgramData\qchat\server.key
icacls C:\ProgramData\qchat\db
```

Expect entries for SYSTEM (`S-1-5-18`), Administrators (`S-1-5-32-544`),
OWNER RIGHTS (`S-1-3-4`) with `(F)` and `NT SERVICE\qchat-server` with `(RX)`
only, except on `db` and the files in it, where `NT SERVICE\qchat-server` has
`(M)` (modify; `(OI)(CI)(M)` on the directory itself); names are localized, for example `VORDEFINIERT\Administratoren` on
German Windows. There must be no entry for `Users`, `Authenticated Users` or
`Everyone`, and none marked `(I)` (inherited).

If you created the data directory with an older version of `init` or without
`--service-account`, either recreate it (which changes the fingerprint), or
fix the ACL by hand with these SIDs, which work on every Windows language:

```powershell
icacls C:\ProgramData\qchat /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\qchat-server:(OI)(CI)RX" /T
```

`/inheritance:r` removes the entries inherited from `C:\ProgramData`, and
`/T` applies the change to the files already in the directory.

A data directory created before the database moved to `db\` has
`database = 'qchat.db'` in `server.toml`, and the service cannot write it.
Stop the service, then move the database into its own directory and grant
the service account modify access there:

```powershell
New-Item -ItemType Directory C:\ProgramData\qchat\db
Move-Item C:\ProgramData\qchat\qchat.db C:\ProgramData\qchat\db\qchat.db
icacls C:\ProgramData\qchat\db /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\qchat-server:(OI)(CI)M" /T
```

and change the line in `server.toml` to `database = 'db/qchat.db'`. Move
`qchat.db-wal` and `qchat.db-shm` along if they exist (they do only after an
unclean stop).

Then run the server once in the foreground to check the configuration (stop
it with Ctrl+C):

```powershell
& "C:\Program Files\qchat\qchat-server.exe" run --config C:\ProgramData\qchat\server.toml
```

At startup, `run` logs a warning if the ACL of the private key grants access
to Everyone, Authenticated Users, INTERACTIVE or Users.

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
Use a foreground run (step 4) to troubleshoot. The log never contains client
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
