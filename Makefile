VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/tinybrickboy/router/internal/version.Version=$(VERSION)
ARCHS   := amd64 arm64 arm
GO      ?= go

.PHONY: build dist test clean

# Binaries für die aktuelle Architektur
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/bgp-router ./cmd/bgp-router
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/bgp-agent ./cmd/bgp-agent

# Alle Architekturen + SHA256SUMS (für Releases und den Upload im Webinterface)
dist:
	@mkdir -p dist
	@for arch in $(ARCHS); do \
		for app in bgp-router bgp-agent; do \
			echo "build $$app-linux-$$arch"; \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch GOARM=7 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$app-linux-$$arch ./cmd/$$app || exit 1; \
		done; \
	done
	cd dist && sha256sum bgp-* > SHA256SUMS

test:
	$(GO) vet ./...
	$(GO) test ./...

clean:
	rm -rf bin dist
