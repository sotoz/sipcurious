# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=sipcurious
BINARY_UNIX=$(BINARY_NAME)_unix
PROJECT=github.com/sotoz/sipcurious/cmd/sipcurious
DEP_VERSION=0.4.1
all: test build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v $(PROJECT)
test:
	$(GOTEST) -coverprofile=cover.out -v ./...
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./...
	./$(BINARY_NAME)
deps:
	curl -L -s https://github.com/golang/dep/releases/download/v$(DEP_VERSION)/dep-linux-amd64 -o $GOPATH/bin/dep
	dep ensure

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v