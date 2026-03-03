# Build settings for AWS Lambda (ARM64)
GOOS := linux
GOARCH := arm64
LDFLAGS := -s -w

.PHONY: build

# Output directory
BIN_DIR := bin

# Package directory
PACKAGE_DIR := dist

# Build handler for Lambda
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/bootstrap ./cmd

package: build
	mkdir -p $(PACKAGE_DIR)
	cd $(BIN_DIR) && zip ../$(PACKAGE_DIR)/alerter.zip bootstrap

# Lint all Go code
lint:
	golangci-lint run ./...

# Format all Go code
format:
	golangci-lint fmt ./...

clean:
	rm -rf $(BIN_DIR)