BINARY_NAME := da-resourced
MODULE      := github.com/shostwp-byte/da-resourcelimiter
CONF_VER    := $(shell awk -F= '/^version=/{print "v"$$2}' plugin/plugin.conf 2>/dev/null || echo "v1.0.4.2")
VERSION     ?= $(CONF_VER)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME  ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")

LDFLAGS := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)'

.PHONY: all build build-linux-amd64 build-linux-arm64 test vet fmt-check clean

all: fmt-check vet test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/da-resourced

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/da-resourced

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/da-resourced

test:
	go test -v -race ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "Unformatted Go files:"; gofmt -l .; exit 1)

clean:
	rm -rf bin/ dist/
