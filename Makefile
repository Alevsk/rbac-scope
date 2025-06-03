# Build variables
BINARY_NAME=rbac-ops
VERSION?=0.1.0
BUILD_DIR=bin
DOCKER_REGISTRY=docker.io
DOCKER_IMAGE=$(DOCKER_REGISTRY)/$(BINARY_NAME)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

.PHONY: all build clean test cover fmt lint docker install-deps

all: clean install-deps fmt lint test build

build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/rbac-ops

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
