BINARY := sipcurious
PKG    := ./cmd/sipcurious
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
DIST      := dist

.PHONY: all build test vet fmt cover bench build-linux dist clean

all: vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

cover:
	go test -coverprofile=cover.out ./...
	go tool cover -func=cover.out

bench:
	go test -run '^$$' -bench . ./...

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)_linux_amd64 $(PKG)

# dist builds the release artifacts into ./dist (what the release workflow
# publishes): sipcurious_<version>_<os>_<arch>.tar.gz (.zip for windows) with
# the binary, LICENSE and README.md, plus SHA256SUMS. Narrow it with e.g.
# make dist PLATFORMS="linux/amd64 darwin/arm64" VERSION=v2.0.0
dist:
	rm -rf $(DIST)
	mkdir -p $(DIST)
	set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		name=$(BINARY)_$(VERSION)_$${os}_$${arch}; \
		exe=$(BINARY); [ $$os = windows ] && exe=$(BINARY).exe; \
		mkdir -p $(DIST)/$$name; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$$name/$$exe $(PKG); \
		cp LICENSE README.md $(DIST)/$$name/; \
		if [ $$os = windows ]; then \
			(cd $(DIST) && zip -q -r $$name.zip $$name); \
		else \
			tar -C $(DIST) -czf $(DIST)/$$name.tar.gz $$name; \
		fi; \
		rm -rf $(DIST)/$$name; \
	done
	cd $(DIST) && { sha256sum $(BINARY)_* 2>/dev/null || shasum -a 256 $(BINARY)_*; } > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

clean:
	go clean
	rm -rf $(DIST)
	rm -f $(BINARY) $(BINARY)_linux_amd64 cover.out
