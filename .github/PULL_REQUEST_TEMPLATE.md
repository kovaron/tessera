<!-- Thanks for opening a PR. Fill in the sections below. -->

## Summary

<!-- What does this change do and why. 1-3 bullets. -->

## Related

<!-- Closes #123, refs #456. Or "n/a" for unrelated work. -->

## Test plan

<!-- Commands you ran, manual steps, screenshots if UI. -->

- [ ] `go test ./... -race -count=1` passes
- [ ] `go vet ./...` clean
- [ ] `gofmt -l .` empty
- [ ] `pnpm test` passes (if UI changed)
- [ ] `cargo test` passes (if Tauri Rust changed)

## Checklist

- [ ] README updated if user-visible behaviour changed
- [ ] CHANGELOG.md updated under `## [Unreleased]`
- [ ] No real secrets, tokens, or `.db` files committed
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
