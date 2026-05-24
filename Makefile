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
