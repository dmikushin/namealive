# Makefile for NameAlive
# Network Host Discovery Tool

.PHONY: all build clean test install uninstall fmt vet lint run help build-all

# Variables
BINARY_NAME = namealive
GO = go
GOFLAGS = -v
LDFLAGS = -s -w
INSTALL_PATH = /usr/local/bin

# Get version from git
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Build flags with version info
BUILD_FLAGS = -ldflags "$(LDFLAGS) -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Default target
all: build

## help: Display this help message
help:
	@echo "Available targets:"
	@grep -E '^##' Makefile | sed 's/## /  /'

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) .

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@rm -rf dist/
	@$(GO) clean

## test: Run tests
test:
	@echo "Running tests..."
	$(GO) test $(GOFLAGS) ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

## lint: Run golangci-lint (requires golangci-lint installed)
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

## install: Install the binary system-wide
install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	@sudo cp $(BINARY_NAME) $(INSTALL_PATH)/
	@echo "Installation complete!"

## uninstall: Remove the installed binary
uninstall:
	@echo "Uninstalling $(BINARY_NAME) from $(INSTALL_PATH)..."
	@sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Uninstallation complete!"

## run: Build and run with default parameters
run: build
	@echo "Running $(BINARY_NAME)..."
	@sudo ./$(BINARY_NAME)

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

## update: Update dependencies
update:
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy

## build-all: Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p dist

	# Linux AMD64
	GOOS=linux GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)_linux_amd64 .

	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GO) build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)_linux_arm64 .

	# Linux ARM
	GOOS=linux GOARCH=arm GOARM=7 $(GO) build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)_linux_armv7 .

	# Darwin AMD64
	GOOS=darwin GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)_darwin_amd64 .

	# Darwin ARM64 (M1/M2)
	GOOS=darwin GOARCH=arm64 $(GO) build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)_darwin_arm64 .

	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)_windows_amd64.exe .

	@echo "Build complete! Binaries are in dist/"

## release: Create release archives
release: build-all
	@echo "Creating release archives..."
	@cd dist && \
	tar czf $(BINARY_NAME)_linux_amd64.tar.gz $(BINARY_NAME)_linux_amd64 && \
	tar czf $(BINARY_NAME)_linux_arm64.tar.gz $(BINARY_NAME)_linux_arm64 && \
	tar czf $(BINARY_NAME)_linux_armv7.tar.gz $(BINARY_NAME)_linux_armv7 && \
	tar czf $(BINARY_NAME)_darwin_amd64.tar.gz $(BINARY_NAME)_darwin_amd64 && \
	tar czf $(BINARY_NAME)_darwin_arm64.tar.gz $(BINARY_NAME)_darwin_arm64 && \
	zip $(BINARY_NAME)_windows_amd64.zip $(BINARY_NAME)_windows_amd64.exe
	@echo "Release archives created in dist/"

## docker: Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .

## check: Run all checks (fmt, vet, test)
check: fmt vet test
	@echo "All checks passed!"