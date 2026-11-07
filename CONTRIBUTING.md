# Contributing to qchat

Thank you for your interest. qchat is a security-sensitive project, so the rules below are stricter than in a typical application.

## Workflow

- Branch names: `feature/phase-N-topic` (for example `feature/phase-2-identity-keys`). Fixes may use `fix/short-topic`.
- Make small, logical commits. Every commit must build and pass the tests.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/). Allowed types:
  `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `build`, `perf`, `security`.
  Example: `feat(transport): pin server SPKI hash in client`.
- Open a pull request against `main` and describe what changed and why.

## Checks to run before opening a pull request

```sh
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

`gofmt -l .` must print nothing. CI runs the same checks.

Any code that parses untrusted input (wire frames, config files, network data) must come with a fuzz test, and the fuzz target should run cleanly for a reasonable time before you submit.

## Rules

- No home-grown cryptography. Use the Go standard library or well-established, maintained libraries. Do not invent primitives, modes or protocols.
- Changes to cryptographic code require tests (including known-answer or interoperability tests where available) and a written rationale in the pull request.
- Never commit secrets, private keys, certificates, databases or real server configuration. Use `*.example.toml` files for examples.
- Code must not panic on untrusted input. Return errors instead and test the failure paths.
- Never write secrets, keys, plaintext messages or IP addresses to logs or error messages.
- Keep dependencies minimal and justify each new one.

## Licensing

By contributing, you agree that your contributions are licensed under the GNU Affero General Public License v3.0 (AGPL-3.0), the same license as the project, and that you have the right to submit them. Sign off your commits (`git commit -s`) to indicate this.

## Reporting security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
