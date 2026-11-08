# Packaging and distribution

This directory holds what is needed to turn qchat binaries into installers:

| File | Purpose |
| --- | --- |
| [`../.goreleaser.yaml`](../.goreleaser.yaml) | Release builds of server and client, archives, checksums, cosign signature, SBOMs, server `.deb`/`.rpm` |
| [`linux/qchat-server.service`](linux/qchat-server.service) | systemd unit shipped in the server packages (binary in `/usr/bin`) |
| [`linux/scripts/`](linux/scripts) | Package scripts: create the `qchat` system user and directories, reload systemd, stop the service on removal |
| [`linux/nfpm-client.yaml`](linux/nfpm-client.yaml) | `.deb`/`.rpm` of a pinned client |
| [`windows/qchat.iss`](windows/qchat.iss) | Inno Setup installer of a pinned client |

There are two kinds of client binaries:

- **Release clients** from the GitHub release are generic. Users pass
  `--server` and `--pin` themselves.
- **Pinned clients** are built by a server operator with
  `qchat-server build-client`. They carry the server address and the
  fingerprint of the server's public key, connect only to that server, and
  reject any other `--server` or `--pin` (see `internal/buildcfg`). This is
  what you hand to people who should not have to type or check a
  fingerprint.

## Building a pinned client

You need the qchat source tree of the version you want to ship and the Go
toolchain named in its `go.mod` (`go version` must match exactly for
reproducible results). Get the source with `git checkout v0.5.0` in a clone,
or unpack `qchat_<version>_source.tar.gz` from the release after verifying it
(see [Verifying a release](#verifying-a-release)).

`build-client` reads `server.toml` and the certificate named in it. It never
opens the private key, so it can run on a separate build machine that has
only `server.toml` and `server.crt`. Never copy `server.key` anywhere.

```sh
cd qchat                      # the source tree; or pass --source DIR
qchat-server build-client --config /etc/qchat/server.toml \
  --server chat.example.org:7443 --version v0.5.0 --out ./qchat-clients
```

- `--server` is the address clients dial. Without it, the first host name of
  the certificate and the port of `listen` are used; give it explicitly when
  the server is behind NAT or a port forward. `build-client` warns when the
  address is `localhost` or a loopback IP.
- `--targets` limits the platforms, for example `--targets windows/amd64,darwin/arm64`.
  The default is `linux`, `windows` and `darwin` on `amd64` and `arm64`.
- `--version` goes into `qchat --version` and the file names.

The result is `qchat_<version>_<os>_<arch>[.exe]` for each platform and a
`SHA256SUMS` file in the format of `sha256sum`. The binaries embed only the
address, the public key fingerprint and the version; nothing secret. Check a
binary with `qchat --version`, which prints `(locked to chat.example.org:7443)`.

### Reproducible builds

`build-client` builds with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`
and `-ldflags "-s -w -buildid= ..."`, sets `GOWORK=off` and ignores
`GOFLAGS`, `GOEXPERIMENT` and the `GOAMD64`/`GOARM`/`GOARM64`/`GO386` level
variables of the calling environment. The binaries therefore depend only on:

1. the source tree,
2. the exact Go toolchain version,
3. the server address, fingerprint and version passed to `build-client`.

Anyone with the same three inputs gets byte-identical binaries, which lets a
second person confirm that the installer you distribute was built from the
published source: they run the same `build-client` command (with the public
`server.crt` and a `server.toml` pointing to it) and compare `SHA256SUMS`.
The test `TestBuildClientReproducible` in `cmd/server` builds the client
twice and compares the results.

Code signing (below) changes the binary. Record `SHA256SUMS` before signing
and publish both the unsigned hashes and the signed files.

## Windows installer (Inno Setup)

Install [Inno Setup](https://jrsoftware.org/isinfo.php) 6.3 or later, then:

```bat
iscc /DClientExe=C:\build\qchat-clients\qchat_v0.5.0_windows_amd64.exe ^
     /DAppVersion=0.5.0 /DArch=x64 /DAppName="qchat (Example Org)" ^
     /DAppId={{1C2D...your own GUID...} packaging\windows\qchat.iss
```

Use `/DArch=arm64` with the `windows_arm64` binary. The installer goes to
`packaging\windows\Output\qchat-setup-<version>-<arch>.exe` (change with
`/DOutputDir=`). It installs `qchat.exe` to Program Files (or, if the user
chooses, to their per-user programs folder), adds a Start menu entry that
opens a terminal running qchat, and registers an uninstaller. Uninstalling
keeps the user's qchat profile with their identity keys and messages.

Give every server its own `AppName` and `AppId` (a fresh GUID, written with
a doubled opening brace on the command line) if one person may install
clients for several servers; installers with the same `AppId` replace each
other.

### Authenticode signing

Unsigned installers and executables trigger Microsoft Defender SmartScreen
("Windows protected your PC"), and many users stop there. To avoid it,
sign both `qchat.exe` and the installer with an Authenticode code signing
certificate from a certificate authority (OV or EV; since 2023 the private
key must live on a hardware token or in a cloud HSM, for example Azure
Trusted Signing). SmartScreen reputation builds up over downloads for OV
certificates.

1. Sign the client before packaging it:

   ```bat
   signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a qchat_v0.5.0_windows_amd64.exe
   ```

2. Let Inno Setup sign the installer and uninstaller by defining a sign tool:

   ```bat
   iscc "/Ssigntool=signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $f" ^
        /DSignTool=signtool /DClientExe=... packaging\windows\qchat.iss
   ```

Always timestamp (`/tr`), so signatures stay valid after the certificate
expires. Check with `signtool verify /pa /v qchat-setup-0.5.0-x64.exe`.

## macOS: Developer ID and notarization

Gatekeeper blocks unsigned, un-notarized binaries that were downloaded with
a browser. Telling users to bypass it (`xattr -d com.apple.quarantine`) is
exactly the habit attackers exploit, so sign and notarize what you
distribute. This needs a membership in the Apple Developer Program and two
certificates: *Developer ID Application* (for the binary) and *Developer ID
Installer* (for a `.pkg`).

```sh
codesign --sign "Developer ID Application: Example Org (TEAMID)" \
  --options runtime --timestamp qchat_v0.5.0_darwin_arm64
mkdir -p pkgroot/usr/local/bin
cp qchat_v0.5.0_darwin_arm64 pkgroot/usr/local/bin/qchat
pkgbuild --root pkgroot --identifier org.example.qchat --version 0.5.0 \
  --sign "Developer ID Installer: Example Org (TEAMID)" qchat-0.5.0-arm64.pkg
xcrun notarytool submit qchat-0.5.0-arm64.pkg --keychain-profile notary --wait
xcrun stapler staple qchat-0.5.0-arm64.pkg
spctl --assess --type install -v qchat-0.5.0-arm64.pkg
```

A bare binary cannot carry a stapled notarization ticket; the `.pkg` can,
so it also installs offline without warnings. Build one package per
architecture, or combine both binaries with `lipo -create` first.

## Linux packages

### Server

The release contains `qchat-server_<version>_<arch>.deb` and `.rpm`, built by
GoReleaser with nfpm. They install `/usr/bin/qchat-server`, the systemd unit,
create the system user and group `qchat` and the directories `/etc/qchat`
and `/var/lib/qchat` (mode 0700, owned by `qchat`). The service is not
enabled until the identity exists:

```sh
sudo apt install ./qchat-server_0.5.0_amd64.deb      # or: sudo dnf install ./qchat-server-0.5.0-1.x86_64.rpm
sudo runuser -u qchat -- qchat-server init --data-dir /etc/qchat \
  --database /var/lib/qchat/qchat.db --host chat.example.org
sudo systemctl enable --now qchat-server
```

Removing the package stops the service and keeps the user, the identity and
the database. Build the packages locally, without signing, with
`goreleaser release --snapshot --clean --skip=sign,sbom` (output in `dist/`).

### Pinned client

Distribute the binary with `SHA256SUMS`, or wrap it with
[nfpm](https://nfpm.goreleaser.com):

```sh
QCHAT_BINARY=qchat-clients/qchat_v0.5.0_linux_amd64 QCHAT_VERSION=0.5.0 QCHAT_ARCH=amd64 \
  nfpm package --config packaging/linux/nfpm-client.yaml --packager deb --target qchat-clients/
```

Use `--packager rpm` for an `.rpm`, and `QCHAT_ARCH=arm64` with the arm64
binary.

## Verifying a release

Every release has `qchat_<version>_checksums.txt` and a cosign bundle
`qchat_<version>_checksums.txt.sigstore.json`. The bundle is a keyless
signature: Sigstore issued a short-lived certificate to the GitHub Actions
workflow `.github/workflows/release.yml` of this repository at the release
tag, and the signature is recorded in the public Rekor transparency log. No
long-lived signing key exists that could leak.

1. Verify the signature of the checksum file with
   [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.x
   or later:

   ```sh
   cosign verify-blob qchat_0.5.0_checksums.txt \
     --bundle qchat_0.5.0_checksums.txt.sigstore.json \
     --certificate-identity "https://github.com/craguS/qchat/.github/workflows/release.yml@refs/tags/v0.5.0" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

   It must print `Verified OK`. Any other identity, issuer or tag means the
   file was not produced by this repository's release workflow.

2. Verify the downloads against the checksum file:

   ```sh
   sha256sum --ignore-missing -c qchat_0.5.0_checksums.txt
   ```

   On macOS use `shasum -a 256 -c` (it also reports the files you did not
   download as missing). On Windows compare
   `Get-FileHash -Algorithm SHA256 qchat_0.5.0_windows_amd64.zip` with the
   line in the checksum file.

For pinned clients, the operator publishes `SHA256SUMS` over a channel users
already trust (for example next to the fingerprint), and users or a second
operator check it with `sha256sum -c SHA256SUMS` or by rebuilding as
described under [Reproducible builds](#reproducible-builds).
