# Contributing to Tessera

Thank you for taking the time to contribute.

## Prerequisites

| Tool | Version |
|------|---------|
| Go | 1.22+ |
| Node | 20+ |
| pnpm | 9+ |
| Rust | stable |
| Xcode Command Line Tools | latest (macOS) |

Install Xcode CLT: `xcode-select --install`

## Building

```bash
# Build tessera daemon + tessera-cli
make build

# Build Tauri sidecar binary for the desktop UI
make sidecar
```

## Running Tests

```bash
# Go unit + integration tests (race detector on)
go test ./... -race -count=1

# UI unit tests
cd ui && pnpm test

# Rust (Tauri) tests
cd ui/src-tauri && cargo test
```

All three suites must pass before opening a PR.

## Running the Desktop UI in Dev Mode

```bash
cd ui && pnpm tauri dev
```

The daemon must be running and the keystore unlocked for the UI to be useful.

## Commit Style

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add rate-limit option to token mint
fix: zero DEK on Lock
chore: bump golangci-lint to 1.59
docs: document audit log rotation
test: add edge cases for token expiry boundary
```

Breaking changes: append `!` after the type (`feat!:`) and add a `BREAKING CHANGE:` footer.

## Pull Request Checklist

Before submitting a PR, verify:

- [ ] `go test ./... -race -count=1` passes
- [ ] `go vet ./...` is clean
- [ ] `gofmt -l .` produces no output
- [ ] `cd ui && pnpm test` passes (if UI files changed)
- [ ] `cd ui/src-tauri && cargo test` passes (if Tauri files changed)
- [ ] README updated if observable behavior changed
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No secrets, credentials, or real keystore files committed

## Branch Model

`main` is always shippable. Work in short-lived feature branches and open a PR against `main`. Force-push to `main` is disabled.

## License Grant

By contributing to Tessera you agree that your contributions will be released under the [MIT License](LICENSE).
