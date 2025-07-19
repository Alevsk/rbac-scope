# Build variables
BINARY_NAME=rbac-scope
VERSION?=0.1.0 # This will be overridden by git tags in CI
BUILD_DIR=bin
DOCKER_OWNER=alevsk
DOCKER_REGISTRY?=docker.io
DOCKER_IMAGE_BASE?=$(BINARY_NAME)
DOCKER_IMAGE?=$(DOCKER_REGISTRY)/$(DOCKER_OWNER)/$(DOCKER_IMAGE_BASE)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Target platforms for cross-compilation
TARGET_PLATFORMS := \
    linux/amd64 \
    linux/arm \
    linux/arm64 \
    darwin/amd64 \
    darwin/arm64 \
    windows/amd64

# Build flags
VERSION?=$(shell git describe --tags --always --dirty)
COMMIT_HASH?=$(shell git rev-parse --short HEAD)
BUILD_TIMESTAMP?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH) -X main.date=$(BUILD_TIMESTAMP)"

.PHONY: all build build-cross clean test cover fmt lint docker install-deps

all: clean install-deps fmt lint test build

# Usage: make build [GOOS=linux] [GOARCH=amd64] [OUTPUT_SUFFIX=-linux-amd64] [EXE_EXT=]
build:
	mkdir -p $(BUILD_DIR)
	@echo "Building for GOOS=$(GOOS) GOARCH=$(GOARCH) VERSION=$(VERSION)"
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)$(OUTPUT_SUFFIX)$(EXE_EXT) ./cmd/rbac-scope

build-cross:
	@echo "Starting cross-compilation for version $(VERSION)..."
	$(foreach platform,$(TARGET_PLATFORMS), \
		$(eval GOOS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval GOARCH := $(word 2,$(subst /, ,$(platform)))) \
		$(eval OUTPUT_SUFFIX := -$(GOOS)-$(GOARCH)) \
		$(eval EXE_EXT := $(if $(findstring windows,$(GOOS)),.exe,)) \
		make build GOOS=$(GOOS) GOARCH=$(GOARCH) OUTPUT_SUFFIX=$(OUTPUT_SUFFIX) EXE_EXT=$(EXE_EXT) VERSION=$(VERSION) || exit 1; \
	)
	@echo "Cross-compilation finished."

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.txt coverage.html

test:
	$(GOTEST) -v ./... -coverprofile=coverage.txt

cover: test
	$(GOCMD) tool cover -html=coverage.txt -o coverage.html

fmt:
	$(GOFMT) ./...

lint:
	golangci-lint run --timeout=5m ./...

docker:
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
	docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest

install-deps:
	$(GOMOD) download
	$(GOMOD) verify
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
