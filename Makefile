.PHONY: build test lint clean

build:
	go build -o proxyd ./cmd/proxyd
	go build -o proxyctl ./cmd/proxyctl

test:
	go test ./... -race -count=1

lint:
	go vet ./...

clean:
	rm -f proxyd proxyctl coverage.out

.PHONY: sidecar
sidecar:
	mkdir -p ui/src-tauri/binaries
	GOOS=darwin GOARCH=arm64 go build -o ui/src-tauri/binaries/proxyctl-aarch64-apple-darwin ./cmd/proxyctl
	GOOS=darwin GOARCH=amd64 go build -o ui/src-tauri/binaries/proxyctl-x86_64-apple-darwin ./cmd/proxyctl
