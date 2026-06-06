.PHONY: build test lint clean smoke

build:
	go build -o tessera ./cmd/tessera
	go build -o tessera-cli ./cmd/tessera-cli

test:
	go test ./... -race -count=1

lint:
	go vet ./...

clean:
	rm -f tessera tessera-cli coverage.out

smoke:
	@./scripts/smoke.sh

.PHONY: sidecar
sidecar:
	mkdir -p ui/src-tauri/binaries
	GOOS=darwin GOARCH=arm64 go build -o ui/src-tauri/binaries/tessera-cli-aarch64-apple-darwin ./cmd/tessera-cli
	GOOS=darwin GOARCH=amd64 go build -o ui/src-tauri/binaries/tessera-cli-x86_64-apple-darwin ./cmd/tessera-cli
